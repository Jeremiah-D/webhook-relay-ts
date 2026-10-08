import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import {
  Ed25519Verifier,
  HmacSha256Verifier,
  assertValidEndpointVerifierRules,
  selectEndpointVerifier,
  signEd25519,
  signSha256,
  type Verifier,
} from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const GLOBAL_SECRET = "global-secret";
const PATH_SECRET = "path-secret";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));

const hmacGlobal = new HmacSha256Verifier(GLOBAL_SECRET);

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

describe("selectEndpointVerifier", () => {
  const ed: Verifier = new Ed25519Verifier(
    generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString()
  );

  it("matches exact paths", () => {
    const rules = [{ pattern: "/hooks/stripe", verifier: ed }];
    assert.equal(selectEndpointVerifier("/hooks/stripe", rules), ed);
    assert.equal(selectEndpointVerifier("/hooks/stripe/", rules), undefined);
    assert.equal(selectEndpointVerifier("/hooks/stripe/x", rules), undefined);
  });

  it("matches prefix patterns, including the bare prefix", () => {
    const rules = [{ pattern: "/hooks/*", verifier: ed }];
    assert.equal(selectEndpointVerifier("/hooks/stripe", rules), ed);
    assert.equal(selectEndpointVerifier("/hooks", rules), ed);
    assert.equal(selectEndpointVerifier("/hooksx", rules), undefined);
    assert.equal(selectEndpointVerifier("/other", rules), undefined);
  });

  it("first matching rule wins", () => {
    const rules = [
      { pattern: "/hooks/*", verifier: ed },
      { pattern: "/hooks/stripe", verifier: hmacGlobal },
    ];
    assert.equal(selectEndpointVerifier("/hooks/stripe", rules), ed);
  });

  it("returns undefined when nothing matches or no rules are configured", () => {
    const rules = [{ pattern: "/hooks/stripe", verifier: ed }];
    assert.equal(selectEndpointVerifier("/hooks/other", rules), undefined);
    assert.equal(selectEndpointVerifier("/hooks/stripe", undefined), undefined);
    assert.equal(selectEndpointVerifier("/hooks/stripe", []), undefined);
  });

  it("a /* rule matches every path", () => {
    const rules = [{ pattern: "/*", verifier: ed }];
    assert.equal(selectEndpointVerifier("/anything/at/all", rules), ed);
  });
});

describe("assertValidEndpointVerifierRules", () => {
  it("accepts undefined and valid rules", () => {
    assertValidEndpointVerifierRules(undefined);
    assertValidEndpointVerifierRules([
      { pattern: "/hooks/stripe", verifier: hmacGlobal },
      { pattern: "/hooks/*", verifier: hmacGlobal },
    ]);
  });

  it("rejects non-arrays, bad patterns, and bad verifiers", () => {
    assert.throws(() => assertValidEndpointVerifierRules("nope" as never), RangeError);
    assert.throws(
      () => assertValidEndpointVerifierRules([{ pattern: "no-leading-slash", verifier: hmacGlobal }]),
      RangeError
    );
    assert.throws(() => assertValidEndpointVerifierRules([{ pattern: "", verifier: hmacGlobal }]), RangeError);
    assert.throws(
      () =>
        assertValidEndpointVerifierRules([
          { pattern: "/hooks/x", verifier: { name: "", verify: () => true } as Verifier },
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidEndpointVerifierRules([{ pattern: "/hooks/x", verifier: { name: "x" } as Verifier }]),
      RangeError
    );
  });
});

describe("server per-endpoint verifier selection", () => {
  let stub: Server;
  let stubPort: number;
  let received: number;

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const edVerifier = new Ed25519Verifier(pubPem);
  const pathHmac = new HmacSha256Verifier(PATH_SECRET);

  before(async () => {
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        received++;
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function makeRelay() {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: GLOBAL_SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      endpointVerifiers: [
        { pattern: "/hooks/ed", verifier: edVerifier },
        { pattern: "/hooks/hmac", verifier: pathHmac },
      ],
    });
    return { relay, audit };
  }

  it("uses the per-endpoint verifier: Ed25519 path accepts ed25519, rejects HMAC", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      received = 0;
      const ok = await post(port, "/hooks/ed", BODY, { "x-signature": signEd25519(BODY, privPem) });
      assert.equal(ok.status, 202);

      // The global HMAC secret must NOT verify on the Ed25519 endpoint.
      const wrong = await post(port, "/hooks/ed", BODY, { "x-signature": signSha256(BODY, GLOBAL_SECRET) });
      assert.equal(wrong.status, 401);

      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].verifier, "ed25519");
      const rejected = events.filter((e) => e.event === "rejected");
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason, "invalid_signature");
      assert.equal(rejected[0].verifier, "ed25519");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("supports a per-path HMAC secret distinct from the global one", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    try {
      const ok = await post(port, "/hooks/hmac", BODY, { "x-signature": signSha256(BODY, PATH_SECRET) });
      assert.equal(ok.status, 202);
      const wrong = await post(port, "/hooks/hmac", BODY, { "x-signature": signSha256(BODY, GLOBAL_SECRET) });
      assert.equal(wrong.status, 401);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("falls back to the global verifier on unmatched paths", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      const ok = await post(port, "/", BODY, { "x-signature": signSha256(BODY, GLOBAL_SECRET) });
      assert.equal(ok.status, 202);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      // No per-endpoint rule fired, so no verifier attribution is added.
      assert.equal(accepted[0].verifier, undefined);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("signature mismatches never touch the circuit breaker", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      // Hammer the per-endpoint path with bad signatures.
      for (let i = 0; i < 5; i++) {
        const res = await post(port, "/hooks/ed", BODY, { "x-signature": "sha256=00" });
        assert.equal(res.status, 401);
      }
      const events = audit.readAll() as Array<Record<string, unknown>>;
      assert.ok(!events.some((e) => e.event === "circuit_open" || e.event === "circuit_half_open"));

      // The endpoint still delivers immediately after: nothing tripped.
      received = 0;
      const ok = await post(port, "/", BODY, { "x-signature": signSha256(BODY, GLOBAL_SECRET) });
      assert.equal(ok.status, 202);
      const deadline = Date.now() + 5000;
      while (received === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.ok(received > 0);
      const fresh = audit.readAll() as Array<Record<string, unknown>>;
      assert.ok(fresh.some((e) => e.event === "delivered"));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("rejects invalid endpointVerifiers at startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          secret: GLOBAL_SECRET,
          forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
          auditLog: audit,
          endpointVerifiers: [{ pattern: "no-slash", verifier: hmacGlobal }],
        }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          secret: GLOBAL_SECRET,
          forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
          auditLog: audit,
          endpointVerifiers: [{ pattern: "/hooks/x", verifier: { name: "bogus" } as Verifier }],
        }),
      RangeError
    );
  });
});
