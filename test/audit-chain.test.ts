import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { AuditLog } from "../src/audit.ts";
import { AesGcmEncryptor, randomAes256Key } from "../src/encrypt.ts";
import { createRelayServer } from "../src/server.ts";

const genesis = "00".repeat(32);
const hashRe = /^[0-9a-f]{64}$/;
const opToken = "op-chain-test-token";
const relaySecret = "chain-test-relay-secret";

function tmpLog(): { audit: AuditLog; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "audit-chain-"));
  const path = join(dir, "audit.jsonl");
  return { audit: new AuditLog(path), path };
}

function rawLines(path: string): string[] {
  return readFileSync(path, "utf8").trimEnd().split("\n");
}

/** Parse a raw line, mutate the object, write it back (key order preserved). */
function rewriteLine(path: string, lineNo: number, mutate: (rec: Record<string, unknown>) => void): void {
  const segments = readFileSync(path, "utf8").split("\n");
  const rec = JSON.parse(segments[lineNo - 1]) as Record<string, unknown>;
  mutate(rec);
  segments[lineNo - 1] = JSON.stringify(rec);
  writeFileSync(path, segments.join("\n"));
}

async function listenOn(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "GET", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end();
  });
}

describe("audit hash chain (WR-77)", () => {
  it("chains appended lines: prevHash links, first link from genesis", () => {
    const { audit, path } = tmpLog();
    audit.append({ event: "accepted", id: "a1" });
    audit.append({ event: "delivered", id: "a1" });
    audit.append({ event: "dead_letter", id: "a2" });

    const lines = rawLines(path).map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.equal(lines.length, 3);
    for (const rec of lines) {
      assert.match(rec.prevHash as string, hashRe);
      assert.match(rec.hash as string, hashRe);
    }
    assert.equal(lines[0].prevHash, genesis);
    assert.equal(lines[1].prevHash, lines[0].hash);
    assert.equal(lines[2].prevHash, lines[1].hash);

    // The chain lives in its own fields; the event body is untouched.
    assert.equal(lines[0].event, "accepted");
    assert.equal(lines[0].id, "a1");

    const v = audit.verifyChain();
    assert.equal(v.ok, true);
    assert.equal(v.lines, 3);
    assert.equal(v.checked, 3);
    assert.deepEqual(v.corruptLines, []);
    assert.equal(v.firstBreak, undefined);
    assert.equal(v.head, lines[2].hash);
  });

  it("detects a rewritten line and reports its line number", () => {
    const { audit, path } = tmpLog();
    audit.append({ event: "accepted", id: "a1" });
    audit.append({ event: "delivered", id: "a1" });
    audit.append({ event: "dead_letter", id: "a2" });

    rewriteLine(path, 2, (rec) => {
      rec.event = "forged";
    });

    const v = audit.verifyChain();
    assert.equal(v.ok, false);
    assert.deepEqual(v.firstBreak, { line: 2, reason: "hash_mismatch" });
    assert.equal(v.checked, 1); // trusted prefix is line 1 only
  });

  it("detects a deleted line via the dangling prevHash", () => {
    const { audit, path } = tmpLog();
    audit.append({ event: "a" });
    audit.append({ event: "b" });
    audit.append({ event: "c" });

    const segments = readFileSync(path, "utf8").split("\n");
    writeFileSync(path, [segments[0], segments[2], segments[3]].join("\n"));

    const v = audit.verifyChain();
    assert.equal(v.ok, false);
    assert.deepEqual(v.firstBreak, { line: 2, reason: "prev_mismatch" });
  });

  it("detects spliced foreign lines", () => {
    const a = tmpLog();
    const b = tmpLog();
    a.audit.append({ event: "a1" });
    a.audit.append({ event: "a2" });
    b.audit.append({ event: "b1" });
    b.audit.append({ event: "b2" });

    writeFileSync(a.path, readFileSync(a.path, "utf8") + readFileSync(b.path, "utf8"));

    const v = a.audit.verifyChain();
    assert.equal(v.ok, false);
    assert.deepEqual(v.firstBreak, { line: 3, reason: "prev_mismatch" });
  });

  it("hashes the sealed ciphertext envelope, never plaintext (WR-11)", () => {
    const enc = new AesGcmEncryptor(randomAes256Key());
    const dir = mkdtempSync(join(tmpdir(), "audit-chain-"));
    const path = join(dir, "audit.jsonl");
    const audit = new AuditLog(path, { payloadEncryptor: enc });

    audit.append({ event: "accepted", payload: "card=4111111111111111" });
    const rec = JSON.parse(rawLines(path)[0]) as Record<string, unknown>;
    assert.equal(rec.payloadEncrypted, true);
    assert.equal((rec.payload as Record<string, unknown>).alg, "aes-256-gcm");
    assert.ok(!JSON.stringify(rec.payload).includes("4111111111111111"));
    assert.equal(audit.verifyChain().ok, true);

    // Plaintext still round-trips through the sealed envelope.
    const readBack = audit.readAll()[0] as Record<string, unknown>;
    assert.equal(readBack.payload, "card=4111111111111111");

    // Tampering with the ciphertext breaks the chain exactly like a rewrite.
    rewriteLine(path, 1, (r) => {
      (r.payload as Record<string, unknown>).data = "AAAA";
    });
    const v = audit.verifyChain();
    assert.equal(v.ok, false);
    assert.deepEqual(v.firstBreak, { line: 1, reason: "hash_mismatch" });
  });

  it("reports corrupt lines without breaking chain continuity", () => {
    const { audit, path } = tmpLog();
    audit.append({ event: "a" });
    audit.append({ event: "b" });

    const segments = readFileSync(path, "utf8").split("\n");
    writeFileSync(path, [segments[0], "this is not json", "{truncated", segments[1], ""].join("\n"));

    const v = audit.verifyChain();
    assert.equal(v.ok, true);
    assert.deepEqual(v.corruptLines, [2, 3]);
    assert.equal(v.lines, 4);
    assert.equal(v.checked, 2);
    // Query (WR-04 index) still skips the bad lines, orthogonally.
    assert.equal(audit.query({}).length, 2);
  });

  it("flags pre-chain legacy lines as missing_chain_fields", () => {
    const { path } = tmpLog();
    writeFileSync(
      path,
      JSON.stringify({ ts: "2026-10-01T00:00:00.000Z", event: "legacy" }) + "\n"
    );
    const audit = new AuditLog(path);
    // The chain restarts at genesis when the newest line predates the chain.
    audit.append({ event: "new" });
    const rec = JSON.parse(rawLines(path)[1]) as Record<string, unknown>;
    assert.equal(rec.prevHash, genesis);

    const v = audit.verifyChain();
    assert.equal(v.ok, false);
    assert.deepEqual(v.firstBreak, { line: 1, reason: "missing_chain_fields" });
  });

  it("continues the chain when another instance appends to the same file", () => {
    const { audit, path } = tmpLog();
    audit.append({ event: "a" });
    const other = new AuditLog(path);
    other.append({ event: "b" });
    audit.append({ event: "c" });

    const v = audit.verifyChain();
    assert.equal(v.ok, true);
    assert.equal(v.checked, 3);
  });

  it("restarts from genesis after the file is truncated/rotated", () => {
    const { audit, path } = tmpLog();
    audit.append({ event: "a" });
    writeFileSync(path, ""); // rotation
    audit.append({ event: "b" });

    const rec = JSON.parse(rawLines(path)[0]) as Record<string, unknown>;
    assert.equal(rec.prevHash, genesis);
    const v = audit.verifyChain();
    assert.equal(v.ok, true);
    assert.equal(v.checked, 1);
  });

  it("reports an empty (or missing) log as a clean genesis chain", () => {
    const { audit } = tmpLog();
    const v = audit.verifyChain();
    assert.equal(v.ok, true);
    assert.equal(v.lines, 0);
    assert.equal(v.checked, 0);
    assert.equal(v.head, genesis);
  });
});

describe("GET /audit/verify operator endpoint (WR-77)", () => {
  function makeRelay(audit: AuditLog, withToken: boolean) {
    return createRelayServer({
      secret: relaySecret,
      forwardUrl: "http://127.0.0.1:1/hook",
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...(withToken ? { operatorToken: opToken } : {}),
    });
  }

  async function closeRelay(relay: { close(): void; once(e: string, cb: () => void): void }) {
    relay.close();
    await new Promise<void>((r) => relay.once("close", r));
  }

  it("404s when no operatorToken is configured (fail closed)", async () => {
    const { audit } = tmpLog();
    audit.append({ event: "accepted", id: "e1" });
    const relay = makeRelay(audit, false);
    const port = await listenOn(relay);
    try {
      assert.equal((await get(port, "/audit/verify")).status, 404);
      // Even a well-formed token cannot conjure the endpoint.
      assert.equal((await get(port, "/audit/verify", { authorization: "Bearer x" })).status, 404);
    } finally {
      await closeRelay(relay);
    }
  });

  it("403s on a bad token, 405s on POST, 200s with the verification report", async () => {
    const { audit, path } = tmpLog();
    audit.append({ event: "accepted", id: "e1" });
    audit.append({ event: "delivered", id: "e1" });
    const relay = makeRelay(audit, true);
    const port = await listenOn(relay);
    const auth = { authorization: `Bearer ${opToken}` };
    try {
      assert.equal((await get(port, "/audit/verify")).status, 403);
      assert.equal((await get(port, "/audit/verify", { authorization: "Bearer wrong" })).status, 403);

      const okRes = await get(port, "/audit/verify", auth);
      assert.equal(okRes.status, 200);
      const okBody = JSON.parse(okRes.text) as Record<string, unknown>;
      assert.equal(okBody.ok, true);
      assert.equal(okBody.checked, 2);

      // POST is not allowed on the read-only endpoint.
      const postRes = await new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          { host: "127.0.0.1", port, path: "/audit/verify", method: "POST", headers: auth },
          (res) => {
            res.resume();
            res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end();
      });
      assert.equal(postRes.status, 405);

      // Tamper with the log file; the endpoint reports the break.
      rewriteLine(path, 1, (rec) => {
        rec.id = "forged";
      });
      const badRes = await get(port, "/audit/verify", auth);
      assert.equal(badRes.status, 200);
      const badBody = JSON.parse(badRes.text) as {
        ok: boolean;
        firstBreak?: { line: number; reason: string };
      };
      assert.equal(badBody.ok, false);
      assert.deepEqual(badBody.firstBreak, { line: 1, reason: "hash_mismatch" });
    } finally {
      await closeRelay(relay);
    }
  });
});
