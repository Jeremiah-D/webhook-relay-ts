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
  signEd25519,
  signSha256,
  type EndpointVerifierRule,
  type Verifier,
} from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// WR-442: live revision of the per-endpoint inbound verifier rules.
// The global verifier is passed as a `verifier` object (never a raw
// key in the options), and each pinned path gets its own verifier so a
// key rollover is a new verifier object under the same scheme name.
const GLOBAL_KEY = "test-global-key-please-change";
const PATH_KEY = "test-path-key-please-change";
const BATCH_KEY = "test-batch-key-please-change";
const BATCH_KEY_2 = "test-batch-key-2-please-change";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));

const hmacGlobal = new HmacSha256Verifier(GLOBAL_KEY);
const hmacPath = new HmacSha256Verifier(PATH_KEY);
const hmacBatch = new HmacSha256Verifier(BATCH_KEY);
const hmacBatch2 = new HmacSha256Verifier(BATCH_KEY_2);

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

async function closeRelay(relay: Server): Promise<void> {
  relay.close();
  await new Promise<void>((r) => relay.once("close", r));
}

/** One signed batch item, signed with the given key. */
function batchItem(payload: unknown, signingKey: string) {
  const raw = Buffer.from(JSON.stringify(payload));
  return {
    payload: raw.toString("base64"),
    headers: { "x-signature": signSha256(raw, signingKey) },
  };
}

/** POST a batch envelope + items, all signed with the given key. */
async function postBatch(port: number, signingKey: string) {
  const envelope = Buffer.from(JSON.stringify({ events: [batchItem({ n: 1 }, signingKey)] }));
  const res = await post(port, "/ingest/batch", envelope, {
    "x-signature": signSha256(envelope, signingKey),
  });
  // A rejected envelope answers 401 with a plain-text body, not JSON.
  return { status: res.status, text: res.text, body: res.status === 401 ? null : JSON.parse(res.text) };
}

describe("live endpoint verifier revision (WR-442)", () => {
  let stub: Server;
  let stubPort: number;
  let received: number;

  const oldKeys = generateKeyPairSync("ed25519");
  const newKeys = generateKeyPairSync("ed25519");
  const edOld = new Ed25519Verifier(
    oldKeys.publicKey.export({ type: "spki", format: "pem" }).toString()
  );
  const edNew = new Ed25519Verifier(
    newKeys.publicKey.export({ type: "spki", format: "pem" }).toString()
  );
  const oldPrivPem = oldKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const newPrivPem = newKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  const initialRules: EndpointVerifierRule[] = [
    { pattern: "/hooks/ed", verifier: edOld },
    { pattern: "/hooks/hmac", verifier: hmacPath },
  ];

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

  function makeRelay(endpointVerifiers?: EndpointVerifierRule[]) {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      verifier: hmacGlobal,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      ...(endpointVerifiers !== undefined ? { endpointVerifiers } : {}),
    });
    return { relay, audit };
  }

  function revisions(audit: AuditLog) {
    return audit.query({ event: "endpoint_verifiers_revised" }) as Array<Record<string, unknown>>;
  }

  it("rotates a pinned path's verifier: the new key verifies, the old key 401s", async () => {
    const { relay, audit } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      const ok = await post(port, "/hooks/ed", BODY, { "x-signature": signEd25519(BODY, oldPrivPem) });
      assert.equal(ok.status, 202);

      // Key rollover: a new Ed25519 verifier object under the same
      // scheme name ("ed25519") — this must be a real revision, never
      // a silent no-op.
      relay.reviseEndpointVerifiers!([{ pattern: "/hooks/ed", verifier: edNew }]);

      const rotated = await post(port, "/hooks/ed", BODY, {
        "x-signature": signEd25519(BODY, newPrivPem),
      });
      assert.equal(rotated.status, 202);
      const stale = await post(port, "/hooks/ed", BODY, {
        "x-signature": signEd25519(BODY, oldPrivPem),
      });
      assert.equal(stale.status, 401);

      const events = revisions(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { pattern: "/hooks/ed", verifier: "ed25519" },
        { pattern: "/hooks/hmac", verifier: "hmac-sha256" },
      ]);
      assert.deepEqual(events[0].current, [{ pattern: "/hooks/ed", verifier: "ed25519" }]);
    } finally {
      await closeRelay(relay);
    }
  });

  it("adds a new path rule live, including from unconfigured", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    try {
      assert.equal(relay.getEndpointVerifiers!(), undefined);
      const before = await post(port, "/hooks/hmac", BODY, {
        "x-signature": signSha256(BODY, PATH_KEY),
      });
      assert.equal(before.status, 401); // falls back to the global verifier

      relay.reviseEndpointVerifiers!([{ pattern: "/hooks/hmac", verifier: hmacPath }]);

      const ok = await post(port, "/hooks/hmac", BODY, {
        "x-signature": signSha256(BODY, PATH_KEY),
      });
      assert.equal(ok.status, 202);
      const wrong = await post(port, "/hooks/hmac", BODY, {
        "x-signature": signSha256(BODY, GLOBAL_KEY),
      });
      assert.equal(wrong.status, 401);
      assert.deepEqual(relay.getEndpointVerifiers!(), [
        { pattern: "/hooks/hmac", verifier: "hmac-sha256" },
      ]);
    } finally {
      await closeRelay(relay);
    }
  });

  it("removing a rule falls back to the global verifier", async () => {
    const { relay } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      relay.reviseEndpointVerifiers!([{ pattern: "/hooks/ed", verifier: edOld }]);
      const ok = await post(port, "/hooks/hmac", BODY, {
        "x-signature": signSha256(BODY, GLOBAL_KEY),
      });
      assert.equal(ok.status, 202);
      const stale = await post(port, "/hooks/hmac", BODY, {
        "x-signature": signSha256(BODY, PATH_KEY),
      });
      assert.equal(stale.status, 401);
    } finally {
      await closeRelay(relay);
    }
  });

  it("null clears all rules back to the global verifier", async () => {
    const { relay, audit } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      relay.reviseEndpointVerifiers!(null);
      assert.equal(relay.getEndpointVerifiers!(), undefined);
      const ok = await post(port, "/hooks/ed", BODY, {
        "x-signature": signSha256(BODY, GLOBAL_KEY),
      });
      assert.equal(ok.status, 202);
      const stale = await post(port, "/hooks/ed", BODY, {
        "x-signature": signEd25519(BODY, oldPrivPem),
      });
      assert.equal(stale.status, 401);
      const events = revisions(audit);
      assert.equal(events.length, 1);
      assert.equal(events[0].current, null);
    } finally {
      await closeRelay(relay);
    }
  });

  it("[] clears all rules back to the global verifier, like null", async () => {
    const { relay } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      relay.reviseEndpointVerifiers!([]);
      assert.equal(relay.getEndpointVerifiers!(), undefined);
      const ok = await post(port, "/hooks/hmac", BODY, {
        "x-signature": signSha256(BODY, GLOBAL_KEY),
      });
      assert.equal(ok.status, 202);
    } finally {
      await closeRelay(relay);
    }
  });

  it("an illegal pattern throws RangeError and the live rules are untouched", async () => {
    const { relay, audit } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      assert.throws(
        () => relay.reviseEndpointVerifiers!([{ pattern: "no-slash", verifier: hmacPath }]),
        RangeError
      );
      assert.throws(
        () => relay.reviseEndpointVerifiers!([{ pattern: "", verifier: hmacPath }]),
        RangeError
      );
      assert.equal(revisions(audit).length, 0);
      assert.deepEqual(relay.getEndpointVerifiers!(), [
        { pattern: "/hooks/ed", verifier: "ed25519" },
        { pattern: "/hooks/hmac", verifier: "hmac-sha256" },
      ]);
      const ok = await post(port, "/hooks/ed", BODY, {
        "x-signature": signEd25519(BODY, oldPrivPem),
      });
      assert.equal(ok.status, 202);
    } finally {
      await closeRelay(relay);
    }
  });

  it("a verifier without a name or verify method throws RangeError and the live rules are untouched", async () => {
    const { relay, audit } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      assert.throws(
        () =>
          relay.reviseEndpointVerifiers!([
            { pattern: "/hooks/x", verifier: { name: "", verify: () => true } as Verifier },
          ]),
        RangeError
      );
      assert.throws(
        () =>
          relay.reviseEndpointVerifiers!([
            { pattern: "/hooks/x", verifier: { name: "x" } as Verifier },
          ]),
        RangeError
      );
      assert.throws(
        () => relay.reviseEndpointVerifiers!("nope" as never),
        RangeError
      );
      assert.equal(revisions(audit).length, 0);
      const ok = await post(port, "/hooks/hmac", BODY, {
        "x-signature": signSha256(BODY, PATH_KEY),
      });
      assert.equal(ok.status, 202);
    } finally {
      await closeRelay(relay);
    }
  });

  it("a same-rules revision is a silent no-op with no audit event", async () => {
    const { relay, audit } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      // Same patterns in the same order, same verifier objects.
      relay.reviseEndpointVerifiers!([
        { pattern: "/hooks/ed", verifier: edOld },
        { pattern: "/hooks/hmac", verifier: hmacPath },
      ]);
      assert.equal(revisions(audit).length, 0);

      // Clearing an already-empty table is a no-op too.
      relay.reviseEndpointVerifiers!(null);
      assert.equal(revisions(audit).length, 1);
      relay.reviseEndpointVerifiers!(null);
      relay.reviseEndpointVerifiers!([]);
      assert.equal(revisions(audit).length, 1);
    } finally {
      await closeRelay(relay);
    }
  });

  it("the batch envelope uses the revised rules", async () => {
    const { relay } = makeRelay([{ pattern: "/ingest/batch", verifier: hmacBatch }]);
    const port = await listen(relay);
    try {
      const ok = await postBatch(port, BATCH_KEY);
      assert.equal(ok.status, 202);
      assert.equal(ok.body.results[0].status, 202);

      relay.reviseEndpointVerifiers!([{ pattern: "/ingest/batch", verifier: hmacBatch2 }]);

      const stale = await postBatch(port, BATCH_KEY);
      assert.equal(stale.status, 401);
      const rotated = await postBatch(port, BATCH_KEY_2);
      assert.equal(rotated.status, 202);
      assert.equal(rotated.body.results[0].status, 202);
    } finally {
      await closeRelay(relay);
    }
  });

  it("a request verified before the revision is unaffected", async () => {
    const { relay, audit } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      received = 0;
      const ok = await post(port, "/hooks/ed", BODY, {
        "x-signature": signEd25519(BODY, oldPrivPem),
      });
      assert.equal(ok.status, 202);

      // Rotate the trust anchor after admission: the queued event
      // must still deliver under the verifier it started with.
      relay.reviseEndpointVerifiers!([{ pattern: "/hooks/ed", verifier: edNew }]);
      const deadline = Date.now() + 5000;
      while (received === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.ok(received > 0);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].verifier, "ed25519");
    } finally {
      await closeRelay(relay);
    }
  });

  it("the audit records only pattern + verifier name, never key material", async () => {
    const { relay, audit } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      relay.reviseEndpointVerifiers!([{ pattern: "/hooks/ed", verifier: edNew }]);
      const events = revisions(audit);
      assert.equal(events.length, 1);
      // Only the revision payload plus the audit chain's own fields
      // (hash-chained tamper evidence) — no verifier object, no key.
      const allowed = new Set([
        "current",
        "event",
        "previous",
        "ts",
        "hash",
        "hmac",
        "hmacKeyId",
        "hmacPrev",
        "prevHash",
      ]);
      assert.ok(Object.keys(events[0]).every((k) => allowed.has(k)));
      const raw = JSON.stringify(events[0]);
      assert.ok(!raw.includes(GLOBAL_KEY));
      assert.ok(!raw.includes(PATH_KEY));
      assert.ok(!raw.includes(oldPrivPem));
      assert.ok(!raw.includes(newPrivPem));
      assert.ok(!raw.includes("function"));
      assert.ok(!raw.includes("verify"));
    } finally {
      await closeRelay(relay);
    }
  });

  it("getEndpointVerifiers returns an exact snapshot; mutating it leaves the live rules alone", async () => {
    const { relay } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      const snapshot = relay.getEndpointVerifiers!()!;
      assert.deepEqual(snapshot, [
        { pattern: "/hooks/ed", verifier: "ed25519" },
        { pattern: "/hooks/hmac", verifier: "hmac-sha256" },
      ]);
      // Mutate the snapshot: push a bogus rule and rewrite a pattern.
      snapshot.push({ pattern: "/hooks/pwned", verifier: "hmac-sha256" });
      snapshot[0].pattern = "/hooks/other";
      assert.deepEqual(relay.getEndpointVerifiers!(), [
        { pattern: "/hooks/ed", verifier: "ed25519" },
        { pattern: "/hooks/hmac", verifier: "hmac-sha256" },
      ]);
      const ok = await post(port, "/hooks/ed", BODY, {
        "x-signature": signEd25519(BODY, oldPrivPem),
      });
      assert.equal(ok.status, 202);
    } finally {
      await closeRelay(relay);
    }
  });

  it("unmatched paths still fall back to the global verifier after a revision", async () => {
    const { relay } = makeRelay(initialRules);
    const port = await listen(relay);
    try {
      relay.reviseEndpointVerifiers!([{ pattern: "/hooks/ed", verifier: edNew }]);
      const ok = await post(port, "/", BODY, { "x-signature": signSha256(BODY, GLOBAL_KEY) });
      assert.equal(ok.status, 202);
    } finally {
      await closeRelay(relay);
    }
  });
});
