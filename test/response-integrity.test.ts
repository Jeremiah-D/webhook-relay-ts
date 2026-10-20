import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  parseContentDigest,
  verifyContentDigest,
  IntegrityMismatchError,
} from "../src/response-integrity.ts";
import {
  assertValidResponseGuardConfig,
  DEFAULT_MAX_RESPONSE_BYTES,
} from "../src/response-limit.ts";

// NOTE: intentionally not named SECRET — the runner's secret redaction
// rewrites `secret: SECRET` occurrences in test sources.
const SIGNING_SECRET = "integrity-test-secret";

function sha256Digest(body: Buffer): string {
  return `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
}

function sha512Digest(body: Buffer): string {
  return `sha-512=:${createHash("sha512").update(body).digest("base64")}:`;
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
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
    r.end(body);
  });
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

type AuditEvent = Record<string, unknown>;

function events(audit: AuditLog, event: string): AuditEvent[] {
  return audit.query({ event }) as AuditEvent[];
}

/** Stub whose 200 response body / Content-Digest behavior is scriptable. */
function digestStub(respond: (body: Buffer) => { body: Buffer; digest?: string }) {
  const hits: number[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      hits.push(Date.now());
      const { body, digest } = respond(Buffer.from("ignored"));
      const headers: Record<string, string> = {};
      if (digest !== undefined) headers["content-digest"] = digest;
      res.writeHead(200, headers).end(body);
    });
  });
  return { server, hits };
}

describe("WR-168 Content-Digest parsing and verification", () => {
  it("parses a single sha-256 member", () => {
    const body = Buffer.from("hello");
    const members = parseContentDigest(sha256Digest(body));
    assert.equal(members.length, 1);
    assert.equal(members[0]?.algorithm, "sha-256");
    assert.ok(members[0]?.digest.equals(createHash("sha256").update(body).digest()));
  });

  it("parses a multi-member dictionary in order", () => {
    const body = Buffer.from("hello");
    const members = parseContentDigest(`${sha256Digest(body)}, ${sha512Digest(body)}`);
    assert.deepEqual(
      members.map((m) => m.algorithm),
      ["sha-256", "sha-512"]
    );
  });

  it("rejects malformed headers", () => {
    for (const bad of ["", "sha-256=abc", "sha-256=:not base64!!!:", "sha-256=:e30=:;p=1", "=::"]) {
      assert.throws(() => parseContentDigest(bad), RangeError, JSON.stringify(bad));
    }
  });

  it("verifies a matching sha-256 digest", () => {
    const body = Buffer.from("payload-bytes");
    const verdict = verifyContentDigest(body, sha256Digest(body));
    assert.equal(verdict.verified, true);
    assert.equal(verdict.algorithm, "sha-256");
  });

  it("verifies a matching sha-512 digest", () => {
    const body = Buffer.from("payload-bytes");
    const verdict = verifyContentDigest(body, sha512Digest(body));
    assert.equal(verdict.verified, true);
    assert.equal(verdict.algorithm, "sha-512");
  });

  it("prefers sha-512 when both are listed", () => {
    const body = Buffer.from("payload-bytes");
    // Corrupt the sha-256 member only: the sha-512 verdict must still pass.
    const badSha256 = `sha-256=:${Buffer.from("wrongwrongwrongwrongwrongwrong12").toString("base64")}:`;
    const verdict = verifyContentDigest(body, `${badSha256}, ${sha512Digest(body)}`);
    assert.equal(verdict.verified, true);
    assert.equal(verdict.algorithm, "sha-512");
  });

  it("fails a tampered body", () => {
    const verdict = verifyContentDigest(Buffer.from("tampered"), sha256Digest(Buffer.from("original")));
    assert.equal(verdict.verified, false);
    assert.equal(verdict.algorithm, "sha-256");
    assert.match(String(verdict.reason), /does not match/);
  });

  it("has no opinion when the header is absent", () => {
    assert.deepEqual(verifyContentDigest(Buffer.from("x"), undefined), { verified: true });
    assert.deepEqual(verifyContentDigest(Buffer.from("x"), ""), { verified: true });
  });

  it("fails closed on unsupported-only algorithms", () => {
    const verdict = verifyContentDigest(Buffer.from("x"), "md5=:e30=:");
    assert.equal(verdict.verified, false);
    assert.equal(verdict.algorithm, "unsupported");
    assert.match(String(verdict.reason), /no supported digest algorithm/);
  });

  it("fails closed on a malformed header", () => {
    const verdict = verifyContentDigest(Buffer.from("x"), "sha-256=garbage");
    assert.equal(verdict.verified, false);
    assert.match(String(verdict.reason), /unparseable/);
  });

  it("IntegrityMismatchError carries the audit token", () => {
    const err = new IntegrityMismatchError("http://x/hook", "sha-256", "nope", 200);
    assert.match(err.message, /integrity_mismatch/);
    assert.equal(err.name, "IntegrityMismatchError");
    assert.equal(err.statusCode, 200);
  });

  it("rejects illegal guard configs at startup", () => {
    assert.throws(
      () => assertValidResponseGuardConfig({ "http://x/": { maxResponseBytes: 0 } }),
      RangeError
    );
    assert.throws(
      () => assertValidResponseGuardConfig({ "http://x/": { maxResponseBytes: -5 } }),
      RangeError
    );
    assert.throws(
      () => assertValidResponseGuardConfig({ "http://x/": { maxResponseBytes: 1.5 } }),
      RangeError
    );
    assert.throws(
      () => assertValidResponseGuardConfig({ "http://x/": { verifyContentDigest: "yes" } }),
      RangeError
    );
    assert.throws(() => assertValidResponseGuardConfig({ "": { verifyContentDigest: true } }), RangeError);
    // Sane configs pass.
    assertValidResponseGuardConfig({
      "http://x/": { verifyContentDigest: true },
      "http://y/": { maxResponseBytes: 1024 },
    });
    assert.equal(DEFAULT_MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
  });
});

describe("WR-168 end-to-end Content-Digest verification", () => {
  const BODY = Buffer.from(JSON.stringify({ order: "ord_9", amount: 100 }));

  function relay(
    stubPort: number,
    guard: Record<string, { verifyContentDigest?: boolean; maxResponseBytes?: number }>,
    maxAttempts: number
  ) {
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "respint-")), "audit.jsonl"));
    const targetUrl = `http://127.0.0.1:${stubPort}/hook`;
    const server = createRelayServer({
      secret: SIGNING_SECRET,
      forwardUrl: targetUrl,
      auditLog: audit,
      responseGuard: { [targetUrl]: guard },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts },
    });
    return { server, audit, targetUrl };
  }

  it("delivers when the downstream Content-Digest matches", async () => {
    const { server: stub } = digestStub(() => {
      const body = Buffer.from("ack-ok");
      return { body, digest: sha256Digest(body) };
    });
    const stubPort = await listen(stub);
    const { server: relayServer, audit } = relay(stubPort, { verifyContentDigest: true }, 3);
    const relayPort = await listen(relayServer);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SIGNING_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "integrity_mismatch").length, 0);
      assert.equal(events(audit, "dead_letter").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("retries then dead-letters on digest mismatch, auditing integrity_mismatch", async () => {
    const { server: stub, hits } = digestStub(() => {
      const body = Buffer.from("actual-bytes");
      // Digest of *different* bytes — the tampered/mismatched case.
      return { body, digest: sha256Digest(Buffer.from("claimed-bytes")) };
    });
    const stubPort = await listen(stub);
    const { server: relayServer, audit } = relay(stubPort, { verifyContentDigest: true }, 3);
    const relayPort = await listen(relayServer);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SIGNING_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => hits.length >= 3, 15000, "3 downstream attempts");
      assert.equal(hits.length, 3);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      const dead = events(audit, "dead_letter");
      assert.equal(dead.length, 1);
      assert.match(String(dead[0]?.error), /integrity_mismatch/);
      assert.equal(dead[0]?.failure_class, "retryable");
      const mismatches = events(audit, "integrity_mismatch");
      assert.equal(mismatches.length, 1);
      assert.equal(mismatches[0]?.algorithm, "sha-256");
      assert.match(String(mismatches[0]?.error), /integrity_mismatch/);
      assert.equal(mismatches[0]?.targetUrl, `http://127.0.0.1:${stubPort}/hook`);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("delivers unchanged when the downstream sends no Content-Digest", async () => {
    const { server: stub } = digestStub(() => ({ body: Buffer.from("no-digest") }));
    const stubPort = await listen(stub);
    const { server: relayServer, audit } = relay(stubPort, { verifyContentDigest: true }, 1);
    const relayPort = await listen(relayServer);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SIGNING_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "integrity_mismatch").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("fails closed when only unsupported digest algorithms are listed", async () => {
    const { server: stub, hits } = digestStub(() => ({
      body: Buffer.from("x"),
      digest: "md5=:e30=:",
    }));
    const stubPort = await listen(stub);
    const { server: relayServer, audit } = relay(stubPort, { verifyContentDigest: true }, 2);
    const relayPort = await listen(relayServer);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SIGNING_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => hits.length >= 2, 15000, "2 downstream attempts");
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      const mismatches = events(audit, "integrity_mismatch");
      assert.equal(mismatches.length, 1);
      assert.equal(mismatches[0]?.algorithm, "unsupported");
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("verifies a body larger than the legacy 64 KiB capture under the default 4 MiB cap", async () => {
    // Proves the guard read cap (default 4 MiB) replaced the legacy 64 KiB
    // truncated capture: a 200 KiB body with a valid digest can only
    // verify when the sender actually read all 200 KiB.
    const big = Buffer.alloc(200 * 1024, "b");
    const { server: stub } = digestStub(() => ({ body: big, digest: sha512Digest(big) }));
    const stubPort = await listen(stub);
    const { server: relayServer, audit } = relay(stubPort, { verifyContentDigest: true }, 1);
    const relayPort = await listen(relayServer);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SIGNING_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "integrity_mismatch").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });
});
