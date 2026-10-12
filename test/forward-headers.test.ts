import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  resolveForwardHeadersConfig,
  shouldForwardHeader,
  FORWARD_HEADERS_DEFAULT_DENY,
} from "../src/forward-headers.ts";

const SECRET = "relay-secret";
const OUTBOUND_SECRET = "relay-outbound-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "forward-headers" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(BODY);
  });
}

describe("WR-69 forward-headers module", () => {
  it("rejects invalid configs with RangeError", () => {
    assert.throws(() => resolveForwardHeadersConfig("nope" as never), RangeError);
    assert.throws(() => resolveForwardHeadersConfig([] as never), RangeError);
    assert.throws(() => resolveForwardHeadersConfig({ "http://x/": null as never }), RangeError);
    assert.throws(
      () => resolveForwardHeadersConfig({ "http://x/": { allow: ["("] } }),
      /invalid header pattern/
    );
    assert.throws(
      () => resolveForwardHeadersConfig({ "http://x/": { allow: [123] as never } }),
      /must be strings or RegExp/
    );
    assert.throws(
      () => resolveForwardHeadersConfig({ "http://x/": { deny: "x-a" as never } }),
      /must be an array/
    );
  });

  it("accepts an empty rule object (means default-deny only)", () => {
    const rules = resolveForwardHeadersConfig({ "http://x/": {} });
    const rule = rules.get("http://x/")!;
    assert.equal(rule.allow, undefined);
    assert.deepEqual(rule.deny, []);
  });

  it("never forwards authorization/cookie by default when a rule exists", () => {
    const rule = resolveForwardHeadersConfig({ "http://x/": {} }).get("http://x/")!;
    assert.deepEqual([...FORWARD_HEADERS_DEFAULT_DENY], ["authorization", "cookie"]);
    assert.equal(shouldForwardHeader(rule, "authorization"), false);
    assert.equal(shouldForwardHeader(rule, "cookie"), false);
    assert.equal(shouldForwardHeader(rule, "Authorization"), false, "case-insensitive");
    assert.equal(shouldForwardHeader(rule, "x-custom-id"), true);
  });

  it("explicit allow overrides the default deny, never an explicit deny", () => {
    const allowAuth = resolveForwardHeadersConfig({
      "http://x/": { allow: ["authorization"] },
    }).get("http://x/")!;
    assert.equal(shouldForwardHeader(allowAuth, "authorization"), true);
    assert.equal(shouldForwardHeader(allowAuth, "cookie"), false);

    const denyWins = resolveForwardHeadersConfig({
      "http://x/": { allow: ["x-custom-id"], deny: [/^x-/] },
    }).get("http://x/")!;
    assert.equal(shouldForwardHeader(denyWins, "x-custom-id"), false, "deny wins over allow");
    assert.equal(shouldForwardHeader(denyWins, "x-other"), false);
  });

  it("allow: [] forwards nothing; allow patterns support regex families", () => {
    const none = resolveForwardHeadersConfig({ "http://x/": { allow: [] } }).get("http://x/")!;
    assert.equal(shouldForwardHeader(none, "x-anything"), false);

    const prefixed = resolveForwardHeadersConfig({ "http://x/": { allow: ["^x-"] } }).get("http://x/")!;
    assert.equal(shouldForwardHeader(prefixed, "x-custom-id"), true);
    assert.equal(shouldForwardHeader(prefixed, "content-type"), false);
  });

  it("RegExp patterns are deterministic even with stateful flags", () => {
    const rule = resolveForwardHeadersConfig({ "http://x/": { allow: [/^x-/g] } }).get("http://x/")!;
    assert.equal(shouldForwardHeader(rule, "x-a"), true);
    assert.equal(shouldForwardHeader(rule, "x-a"), true, "no lastIndex flakiness");
  });
});

describe("WR-69 server wiring", () => {
  let stub: Server;
  let stubPort: number;
  let seen: Array<Record<string, unknown>>;

  before(async () => {
    seen = [];
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ ...req.headers });
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "fwd-headers-"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    return relay;
  }

  function inboundHeaders(): Record<string, string> {
    return {
      "content-type": "application/json",
      "x-signature": signSha256(BODY, SECRET),
      authorization: "Bearer caller-credential",
      cookie: "session=abc",
      "x-custom-id": "evt-1",
    };
  }

  async function postAndWait(port: number) {
    seen.length = 0;
    const res = await post(port, inboundHeaders());
    assert.equal(res.status, 202);
    const deadline = Date.now() + 5000;
    while (seen.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(seen.length, 1, "stub received the delivery");
    return seen[0];
  }

  async function withRelay(extra: Record<string, unknown>, fn: (port: number) => Promise<void>) {
    const relay = makeRelay(extra);
    const port = await listen(relay);
    try {
      await fn(port);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  }

  it("without a rule: current pass-through behavior is preserved byte-for-byte", async () => {
    await withRelay({}, async (port) => {
      const got = await postAndWait(port);
      assert.equal(got["authorization"], "Bearer caller-credential");
      assert.equal(got["cookie"], "session=abc");
      assert.equal(got["x-custom-id"], "evt-1");
    });
  });

  it("with a rule: authorization/cookie are stripped by default, others pass", async () => {
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    await withRelay({ forwardHeaders: { [forwardUrl]: {} } }, async (port) => {
      const got = await postAndWait(port);
      assert.equal(got["authorization"], undefined);
      assert.equal(got["cookie"], undefined);
      assert.equal(got["x-custom-id"], "evt-1");
    });
  });

  it("explicit allow re-enables a default-denied header; explicit deny always wins", async () => {
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    await withRelay(
      { forwardHeaders: { [forwardUrl]: { allow: ["authorization", "x-custom-id"], deny: ["x-custom-id"] } } },
      async (port) => {
        const got = await postAndWait(port);
        assert.equal(got["authorization"], "Bearer caller-credential", "explicit allow overrides default deny");
        assert.equal(got["x-custom-id"], undefined, "explicit deny wins over explicit allow");
        assert.equal(got["cookie"], undefined);
      }
    );
  });

  it("rules are per endpoint: other targets are unaffected", async () => {
    await withRelay(
      { forwardHeaders: { "http://other.example/hook": {} } },
      async (port) => {
        const got = await postAndWait(port);
        assert.equal(got["authorization"], "Bearer caller-credential");
        assert.equal(got["cookie"], "session=abc");
      }
    );
  });

  it("relay-forced headers are stamped after the gate and always survive", async () => {
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    await withRelay(
      {
        forwardHeaders: { [forwardUrl]: { allow: [] } },
        outboundSigning: { secret: OUTBOUND_SECRET },
      },
      async (port) => {
        const got = await postAndWait(port);
        assert.equal(got["x-custom-id"], undefined, "allow: [] drops everything");
        assert.ok(got["x-relay-signature"], "the relay signature is stamped after the gate");
        assert.ok(got["x-trace-id"], "the trace id is stamped after the gate");
      }
    );
  });

  it("invalid forwardHeaders throws RangeError at startup", () => {
    assert.throws(
      () => makeRelay({ forwardHeaders: { "http://x/": { allow: ["("] } } }),
      /invalid forwardHeaders config/
    );
  });
});
