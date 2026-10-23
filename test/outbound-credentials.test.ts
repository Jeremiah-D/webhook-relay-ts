import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  applyOutboundCredentials,
  CredentialSecretUnavailableError,
  resolveOutboundCredentialsConfig,
} from "../src/outbound-credentials.ts";
import type { RetryItem } from "../src/retry.ts";

const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const REF = "WR192_TEST_SECRET_REF";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

/** A stub downstream that records every request's headers. */
async function stubDownstream() {
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
      res.writeHead(200).end("ok");
    });
  });
  const port = await listen(server);
  return { server, seen, url: `http://127.0.0.1:${port}/hook` };
}

/** Minimal token endpoint for the oauth2 coexistence test. */
async function stubTokenEndpoint() {
  let hits = 0;
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      hits += 1;
      res
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ access_token: "coex-tok", token_type: "Bearer", expires_in: 3600 }));
    });
  });
  const port = await listen(server);
  return { server, url: `http://127.0.0.1:${port}/oauth/token`, get hits() { return hits; } };
}

const PARAM_COUNT = 43; // outboundCredentials is the last createDefaultSender parameter

function senderWithCredentials(record: Parameters<typeof createDefaultSender>[42]) {
  const args = Array(PARAM_COUNT).fill(undefined) as Parameters<typeof createDefaultSender>;
  args[42] = record;
  return createDefaultSender(...args);
}

describe("WR-192 outbound static credentials — config validation", () => {
  const ok = () => ({
    id: "partner-key",
    header: "x-api-key",
    secretRef: REF,
    secretResolver: () => "resolved-secret",
  });

  it("accepts a well-formed record", () => {
    const map = resolveOutboundCredentialsConfig({ "https://x.test/hook": [ok()] });
    const creds = map.get("https://x.test/hook");
    assert.ok(creds !== undefined && creds.length === 1);
    assert.equal(creds[0].id, "partner-key");
    assert.equal(creds[0].header, "x-api-key");
    assert.equal(creds[0].headerLower, "x-api-key");
    assert.equal(creds[0].secretRef, REF);
  });

  it("throws RangeError on every bad shape", () => {
    const bad: Array<[string, unknown]> = [
      ["non-object record", []],
      ["non-array list", { "https://x.test/hook": {} }],
      ["empty array", { "https://x.test/hook": [] }],
      ["missing id", { "https://x.test/hook": [{ ...ok(), id: undefined }] }],
      ["empty id", { "https://x.test/hook": [{ ...ok(), id: "" }] }],
      ["missing header", { "https://x.test/hook": [{ ...ok(), header: undefined }] }],
      ["blank header", { "https://x.test/hook": [{ ...ok(), header: "  " }] }],
      ["missing secretRef", { "https://x.test/hook": [{ ...ok(), secretRef: undefined }] }],
      ["empty secretRef", { "https://x.test/hook": [{ ...ok(), secretRef: "" }] }],
      ["non-function secretResolver", { "https://x.test/hook": [{ ...ok(), secretResolver: "env" }] }],
      ["duplicate id", { "https://x.test/hook": [ok(), { ...ok(), header: "x-other" }] }],
      [
        "duplicate header (case-insensitive)",
        { "https://x.test/hook": [ok(), { ...ok(), id: "other", header: "X-API-KEY" }] },
      ],
    ];
    for (const [name, record] of bad) {
      assert.throws(
        () => resolveOutboundCredentialsConfig(record as never),
        RangeError,
        `expected RangeError for ${name}`
      );
    }
  });

  it("throws RangeError at startup when the secretRef does not resolve (fail-fast)", () => {
    // Neither an env var nor the injected resolver yields a value.
    delete process.env[REF];
    assert.throws(
      () =>
        resolveOutboundCredentialsConfig({
          "https://x.test/hook": [{ id: "k", header: "x-api-key", secretRef: REF }],
        }),
      RangeError,
      "missing env secret must refuse to boot"
    );
    assert.throws(
      () =>
        resolveOutboundCredentialsConfig({
          "https://x.test/hook": [{ ...ok(), secretResolver: () => "" }],
        }),
      RangeError,
      "empty-string secret must refuse to boot"
    );
  });

  it("resolves via the default env resolver at startup", () => {
    process.env[REF] = "env-secret";
    try {
      const map = resolveOutboundCredentialsConfig({
        "https://x.test/hook": [{ id: "k", header: "x-api-key", secretRef: REF }],
      });
      assert.equal(map.get("https://x.test/hook")?.[0].secretResolver(REF), "env-secret");
    } finally {
      delete process.env[REF];
    }
  });
});

describe("WR-192 applyOutboundCredentials", () => {
  const compiled = (overrides: Record<string, unknown> = {}) => ({
    id: "k1",
    header: "x-api-key",
    headerLower: "x-api-key",
    secretRef: REF,
    secretResolver: () => "s3cr3t",
    ...overrides,
  });

  it("stamps the resolved value", () => {
    const headers: Record<string, string | string[]> = {};
    applyOutboundCredentials(headers, "https://x.test/hook", [compiled()]);
    assert.equal(headers["x-api-key"], "s3cr3t");
  });

  it("strips a forged inbound header with the same name (case-insensitive)", () => {
    const headers: Record<string, string | string[]> = {
      "X-API-KEY": "forged",
      "x-trace-custom": "keep",
    };
    applyOutboundCredentials(headers, "https://x.test/hook", [compiled()]);
    assert.equal(headers["x-api-key"], "s3cr3t");
    assert.equal(headers["X-API-KEY"], undefined);
    assert.equal(headers["x-trace-custom"], "keep");
  });

  it("is a no-op without credentials", () => {
    const headers: Record<string, string | string[]> = { a: "b" };
    applyOutboundCredentials(headers, "https://x.test/hook", undefined);
    assert.deepEqual(headers, { a: "b" });
  });

  it("throws CredentialSecretUnavailableError when the resolver breaks mid-run", () => {
    const headers: Record<string, string | string[]> = {};
    assert.throws(
      () =>
        applyOutboundCredentials(headers, "https://x.test/hook", [
          compiled({ secretResolver: () => undefined }),
        ]),
      (err) =>
        err instanceof CredentialSecretUnavailableError &&
        err.credentialId === "k1" &&
        err.secretRef === REF &&
        /did not resolve/.test(err.message)
    );
  });
});

describe("WR-192 delivery path", () => {
  let downstream: Awaited<ReturnType<typeof stubDownstream>>;

  before(async () => {
    downstream = await stubDownstream();
  });

  after(async () => {
    downstream.server.close();
    await new Promise((r) => downstream.server.once("close", r));
  });

  function item(headers: Record<string, string> = {}): RetryItem {
    return {
      id: "item-1",
      traceId: "trace-1",
      payload: BODY,
      targetUrl: downstream.url,
      headers,
    };
  }

  async function deliver(sender: { (i: RetryItem): Promise<unknown>; destroy(): void }, it: RetryItem) {
    downstream.seen.length = 0;
    try {
      await sender(it);
    } finally {
      sender.destroy();
    }
    assert.equal(downstream.seen.length, 1);
    return downstream.seen[0];
  }

  it("injects the configured credential into the outbound request", async () => {
    const sender = senderWithCredentials({
      [downstream.url]: [
        { id: "partner-key", header: "x-api-key", secretRef: REF, secretResolver: () => "injected-1" },
      ],
    });
    const got = await deliver(sender, item());
    assert.equal(got.headers["x-api-key"], "injected-1");
  });

  it("injects multiple credentials for one endpoint", async () => {
    const sender = senderWithCredentials({
      [downstream.url]: [
        { id: "k1", header: "x-api-key", secretRef: REF, secretResolver: () => "v1" },
        { id: "k2", header: "Authorization", secretRef: REF, secretResolver: () => "Token v2" },
      ],
    });
    const got = await deliver(sender, item());
    assert.equal(got.headers["x-api-key"], "v1");
    assert.equal(got.headers["authorization"], "Token v2");
  });

  it("strips a forged inbound credential header and stamps the relay value", async () => {
    const sender = senderWithCredentials({
      [downstream.url]: [
        { id: "partner-key", header: "x-api-key", secretRef: REF, secretResolver: () => "real" },
      ],
    });
    const got = await deliver(sender, item({ "x-api-key": "forged", "X-Custom": "pass" }));
    assert.equal(got.headers["x-api-key"], "real");
    assert.equal(got.headers["x-custom"], "pass");
  });

  it("refuses to boot createDefaultSender with an unresolvable secretRef", () => {
    delete process.env[REF];
    assert.throws(
      () =>
        senderWithCredentials({
          [downstream.url]: [{ id: "k", header: "x-api-key", secretRef: REF }],
        }),
      RangeError
    );
  });

  it("resolves the secret per delivery attempt (rotation takes effect without restart)", async () => {
    let value = "first";
    const sender = senderWithCredentials({
      [downstream.url]: [
        { id: "rotating", header: "x-api-key", secretRef: REF, secretResolver: () => value },
      ],
    });
    try {
      downstream.seen.length = 0;
      await sender(item());
      value = "second";
      await sender(item());
      assert.equal(downstream.seen.length, 2);
      assert.equal(downstream.seen[0].headers["x-api-key"], "first");
      assert.equal(downstream.seen[1].headers["x-api-key"], "second");
    } finally {
      sender.destroy();
    }
  });

  it("coexists with WR-129 oauth2: bearer token and static credential on one delivery", async () => {
    const tokenEp = await stubTokenEndpoint();
    try {
      const args = Array(PARAM_COUNT).fill(undefined) as Parameters<typeof createDefaultSender>;
      args[31] = {
        [downstream.url]: {
          token_endpoint: tokenEp.url,
          client_id: "relay",
          client_secret: "oauth-secret",
        },
      };
      args[42] = {
        [downstream.url]: [
          { id: "static-1", header: "x-api-key", secretRef: REF, secretResolver: () => "static-v" },
        ],
      };
      const sender = createDefaultSender(...args);
      const got = await deliver(sender, item());
      assert.equal(got.headers["authorization"], "Bearer coex-tok");
      assert.equal(got.headers["x-api-key"], "static-v");
    } finally {
      tokenEp.server.close();
    }
  });

  it("static credential wins deterministically over the oauth2 bearer token on the same header", async () => {
    const tokenEp = await stubTokenEndpoint();
    try {
      const args = Array(PARAM_COUNT).fill(undefined) as Parameters<typeof createDefaultSender>;
      args[31] = {
        [downstream.url]: {
          token_endpoint: tokenEp.url,
          client_id: "relay",
          client_secret: "oauth-secret",
        },
      };
      args[42] = {
        [downstream.url]: [
          { id: "static-auth", header: "Authorization", secretRef: REF, secretResolver: () => "ApiKey static" },
        ],
      };
      const sender = createDefaultSender(...args);
      const got = await deliver(sender, item());
      assert.equal(got.headers["authorization"], "ApiKey static");
    } finally {
      tokenEp.server.close();
    }
  });

  it("survives a WR-69 forwardHeaders deny on the credential header (relay-forced stamp)", async () => {
    const args = Array(PARAM_COUNT).fill(undefined) as Parameters<typeof createDefaultSender>;
    args[12] = { [downstream.url]: { deny: ["x-api-key"] } };
    args[42] = {
      [downstream.url]: [
        { id: "k", header: "x-api-key", secretRef: REF, secretResolver: () => "forced" },
      ],
    };
    const sender = createDefaultSender(...args);
    const got = await deliver(sender, item({ "x-api-key": "forged", "x-trace-custom": "pass" }));
    // The deny blocks the passthrough, but the relay-forced stamp lands anyway.
    assert.equal(got.headers["x-api-key"], "forced");
    assert.equal(got.headers["x-trace-custom"], "pass");
  });
});

describe("WR-192 accepted audit", () => {
  it("carries credentialIds and never the secret value", async () => {
    const downstream = await stubDownstream();
    const dir = mkdtempSync(join(tmpdir(), "wr192-"));
    const auditPath = join(dir, "audit.jsonl");
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: downstream.url,
      auditLog: new AuditLog(auditPath),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      outboundCredentials: {
        [downstream.url]: [
          {
            id: "partner-key",
            header: "x-api-key",
            secretRef: REF,
            secretResolver: () => "audit-test-secret-value",
          },
        ],
      },
    });
    const port = await listen(relay);
    try {
      downstream.seen.length = 0;
      await new Promise<void>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: {
              "x-signature": signSha256(BODY, SECRET),
              "x-api-key": "forged-inbound",
            },
          },
          (res) => {
            res.resume();
            res.on("end", resolve);
          }
        );
        r.on("error", reject);
        r.end(BODY);
      });
      // Wait for the delivery to land so the audit trail is complete.
      const deadline = Date.now() + 5000;
      while (downstream.seen.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(downstream.seen.length, 1);
      assert.equal(downstream.seen[0].headers["x-api-key"], "audit-test-secret-value");
      // The forged inbound value never reached the downstream.
      assert.notEqual(downstream.seen[0].headers["x-api-key"], "forged-inbound");

      const lines = readFileSync(auditPath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      const accepted = lines.find((e) => e.event === "accepted");
      assert.ok(accepted, "expected an accepted audit event");
      assert.deepEqual(accepted.credentialIds, ["partner-key"]);
      const raw = readFileSync(auditPath, "utf8");
      assert.ok(!raw.includes("audit-test-secret-value"), "secret value must never reach the audit log");
      assert.ok(!raw.includes("forged-inbound"), "forged inbound value must never reach the audit log");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      downstream.server.close();
      await new Promise((r) => downstream.server.once("close", r));
    }
  });

  it("omits credentialIds when no credentials are configured", async () => {
    const downstream = await stubDownstream();
    const dir = mkdtempSync(join(tmpdir(), "wr192-no-"));
    const auditPath = join(dir, "audit.jsonl");
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: downstream.url,
      auditLog: new AuditLog(auditPath),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(relay);
    try {
      await new Promise<void>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: { "x-signature": signSha256(BODY, SECRET) },
          },
          (res) => {
            res.resume();
            res.on("end", resolve);
          }
        );
        r.on("error", reject);
        r.end(BODY);
      });
      const deadline = Date.now() + 5000;
      while (downstream.seen.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      const lines = readFileSync(auditPath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      const accepted = lines.find((e) => e.event === "accepted");
      assert.ok(accepted, "expected an accepted audit event");
      assert.equal(accepted.credentialIds, undefined);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      downstream.server.close();
      await new Promise((r) => downstream.server.once("close", r));
    }
  });

  it("refuses to boot createRelayServer with an unresolvable secretRef", async () => {
    const downstream = await stubDownstream();
    const dir = mkdtempSync(join(tmpdir(), "wr192-boot-"));
    delete process.env[REF];
    assert.throws(
      () =>
        createRelayServer({
          secret: SECRET,
          forwardUrl: downstream.url,
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
          outboundCredentials: {
            [downstream.url]: [{ id: "k", header: "x-api-key", secretRef: REF }],
          },
        }),
      RangeError,
      "relay must refuse to boot with a missing credential secret"
    );
    downstream.server.close();
    await new Promise((r) => downstream.server.once("close", r));
  });
});
