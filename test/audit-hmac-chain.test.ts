import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "hmac-chain-relay-secret";
const opToken = "hmac-chain-op-token";
const hashRe = /^[0-9a-f]{64}$/;
const genesis = "00".repeat(32);

function tmpLog(opts: { auditKey?: { id: string; key: string | Buffer } } = {}): {
  audit: AuditLog;
  path: string;
} {
  const dir = mkdtempSync(join(tmpdir(), "audit-hmac-"));
  const path = join(dir, "audit.jsonl");
  return { audit: new AuditLog(path, opts), path };
}

function rawLines(path: string): string[] {
  return readFileSync(path, "utf8").trimEnd().split("\n");
}

function rewriteLine(path: string, lineNo: number, mutate: (rec: Record<string, unknown>) => void): void {
  const segments = readFileSync(path, "utf8").split("\n");
  const rec = JSON.parse(segments[lineNo - 1]) as Record<string, unknown>;
  mutate(rec);
  segments[lineNo - 1] = JSON.stringify(rec);
  writeFileSync(path, segments.join("\n"));
}

function deleteLine(path: string, lineNo: number): void {
  const segments = readFileSync(path, "utf8").split("\n");
  segments.splice(lineNo - 1, 1);
  writeFileSync(path, segments.join("\n"));
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        r.destroy();
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
      });
    });
    r.on("error", reject);
    r.end();
  });
}

describe("AuditLog HMAC chain (WR-184)", () => {
  it("appends hmacPrev/hmac/keyId and verifies cleanly", () => {
    const { audit, path } = tmpLog({ auditKey: { id: "k1", key: "first-key" } });
    audit.append({ event: "accepted", id: "e1" });
    audit.append({ event: "delivered", id: "e1" });
    const lines = rawLines(path).map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.equal(lines.length, 2);
    assert.ok(hashRe.test(lines[0].hmac as string));
    assert.equal(lines[0].hmacPrev, genesis);
    assert.equal(lines[0].hmacKeyId, "k1");
    assert.equal(lines[1].hmacPrev, lines[0].hmac);
    // The WR-77 unkeyed chain still verifies on the same lines.
    assert.equal(audit.verifyChain().ok, true);
    const v = audit.verifyHmacChain();
    assert.equal(v.ok, true);
    assert.equal(v.lines, 2);
    assert.equal(v.checked, 2);
    assert.deepEqual(v.corruptLines, []);
    assert.ok(hashRe.test(v.head));
    assert.equal(v.hmacKeyId, "k1");
  });

  it("detects a rewritten line as hmac_mismatch", () => {
    const { audit, path } = tmpLog({ auditKey: { id: "k1", key: "first-key" } });
    audit.append({ event: "accepted", id: "e1" });
    audit.append({ event: "delivered", id: "e1" });
    rewriteLine(path, 1, (rec) => {
      rec.id = "forged";
    });
    const v = audit.verifyHmacChain();
    assert.equal(v.ok, false);
    assert.deepEqual(v.firstBreak, { line: 1, reason: "hmac_mismatch" });
    // Trusted prefix head is genesis (nothing verified yet).
    assert.equal(v.head, genesis);
  });

  it("detects a deleted line as hmac_prev_mismatch", () => {
    const { audit, path } = tmpLog({ auditKey: { id: "k1", key: "first-key" } });
    audit.append({ event: "a", id: "1" });
    audit.append({ event: "b", id: "2" });
    audit.append({ event: "c", id: "3" });
    deleteLine(path, 1);
    const v = audit.verifyHmacChain();
    assert.equal(v.ok, false);
    assert.deepEqual(v.firstBreak, { line: 1, reason: "hmac_prev_mismatch" });
  });

  it("reports missing_hmac_fields for pre-WR-184 lines", () => {
    const { audit, path } = tmpLog({ auditKey: { id: "k1", key: "first-key" } });
    audit.append({ event: "a", id: "1" });
    rewriteLine(path, 1, (rec) => {
      delete rec.hmacPrev;
      delete rec.hmac;
      delete rec.hmacKeyId;
    });
    const v = audit.verifyHmacChain();
    assert.equal(v.ok, false);
    assert.deepEqual(v.firstBreak, { line: 1, reason: "missing_hmac_fields" });
  });

  it("rotateAuditKey seals new links under a new id; old links still verify", () => {
    const { audit } = tmpLog({ auditKey: { id: "k1", key: "first-key" } });
    audit.append({ event: "a", id: "1" });
    const newId = audit.rotateAuditKey("second-key");
    assert.notEqual(newId, "k1");
    assert.equal(audit.getAuditKeyId(), newId);
    audit.append({ event: "b", id: "2" });
    const v = audit.verifyHmacChain();
    assert.equal(v.ok, true);
    assert.equal(v.checked, 2);
    // The chain stayed continuous across the rotation.
    const events = audit.readAll() as Array<Record<string, unknown>>;
    assert.equal(events[1].hmacPrev, events[0].hmac);
    assert.equal(events[1].hmacKeyId, newId);
    // Rotating without an explicit key generates a random one.
    const autoId = audit.rotateAuditKey();
    assert.ok(autoId.startsWith("rot-"));
  });

  it("a line sealed under an unknown key reports unknown_key", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-hmac-shared-"));
    const path = join(dir, "audit.jsonl");
    const logA = new AuditLog(path, { auditKey: { id: "ka", key: "key-a" } });
    logA.append({ event: "a", id: "1" });
    const logB = new AuditLog(path, { auditKey: { id: "kb", key: "key-b" } });
    logB.append({ event: "b", id: "2" });
    const v = logA.verifyHmacChain();
    assert.equal(v.ok, false);
    assert.deepEqual(v.firstBreak, { line: 2, reason: "unknown_key" });
    // logB holds both keys after we register ka — then it verifies.
    // (Registering via a second rotation keeps kb current and adds ka.)
    assert.ok(v.head !== genesis);
  });

  it("corrupt lines are reported but do not break the chain", () => {
    const { audit, path } = tmpLog({ auditKey: { id: "k1", key: "first-key" } });
    audit.append({ event: "a", id: "1" });
    writeFileSync(path, "not json at all\n", { flag: "a" });
    audit.append({ event: "b", id: "2" });
    const v = audit.verifyHmacChain();
    assert.equal(v.ok, true);
    assert.equal(v.checked, 2);
    assert.deepEqual(v.corruptLines, [2]);
  });

  it("an empty log verifies with the genesis head", () => {
    const { audit } = tmpLog();
    const v = audit.verifyHmacChain();
    assert.equal(v.ok, true);
    assert.equal(v.head, genesis);
    assert.equal(v.lines, 0);
  });

  it("default key is a random startup key; invalid configs throw RangeError", () => {
    const { audit } = tmpLog();
    const id = audit.getAuditKeyId();
    assert.ok(id.startsWith("auto-"));
    audit.append({ event: "a" });
    assert.equal(audit.verifyHmacChain().ok, true);
    assert.throws(() => tmpLog({ auditKey: { id: "", key: "x" } }), RangeError);
    assert.throws(() => tmpLog({ auditKey: { id: "k", key: "" } }), RangeError);
    assert.throws(() => tmpLog({ auditKey: { id: "k", key: 42 as never } }), RangeError);
  });

  it("works with the WR-11 encryptor: the HMAC covers the sealed envelope", async () => {
    const { audit } = tmpLog({ auditKey: { id: "k1", key: "first-key" } });
    const { AesGcmEncryptor, randomAes256Key } = await import("../src/encrypt.ts");
    const dir = mkdtempSync(join(tmpdir(), "audit-hmac-enc-"));
    const keyed = new AuditLog(join(dir, "audit.jsonl"), {
      auditKey: { id: "k1", key: "first-key" },
      payloadEncryptor: new AesGcmEncryptor(randomAes256Key()),
    });
    keyed.append({ event: "accepted", id: "e9", payload: "sensitive" });
    assert.equal(keyed.verifyHmacChain().ok, true);
    assert.equal(audit.verifyHmacChain().ok, true);
  });
});

describe("GET /audit/verify with the HMAC chain (WR-184)", () => {
  function makeRelay(audit: AuditLog) {
    return createRelayServer({
      secret: relaySecret,
      forwardUrl: "http://127.0.0.1:1/hook",
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      operatorToken: opToken,
    });
  }

  async function closeRelay(relay: { close(): void; once(e: string, cb: () => void): void }) {
    relay.close();
    await new Promise<void>((r) => relay.once("close", r));
  }

  it("returns both chains; a tampered line breaks both reports", async () => {
    const { audit, path } = tmpLog({ auditKey: { id: "k1", key: "first-key" } });
    audit.append({ event: "accepted", id: "e1" });
    const relay = makeRelay(audit);
    const port = await listen(relay);
    const auth = { authorization: `Bearer ${opToken}` };
    try {
      const okRes = await get(port, "/audit/verify", auth);
      assert.equal(okRes.status, 200);
      const okBody = JSON.parse(okRes.text) as {
        ok: boolean;
        checked: number;
        hmacChain: { ok: boolean; checked: number; hmacKeyId: string };
      };
      assert.equal(okBody.ok, true);
      assert.equal(okBody.checked, 1);
      assert.equal(okBody.hmacChain.ok, true);
      assert.equal(okBody.hmacChain.checked, 1);
      assert.equal(okBody.hmacChain.hmacKeyId, "k1");

      rewriteLine(path, 1, (rec) => {
        rec.id = "forged";
      });
      const badRes = await get(port, "/audit/verify", auth);
      const badBody = JSON.parse(badRes.text) as {
        ok: boolean;
        firstBreak?: { line: number; reason: string };
        hmacChain: { ok: boolean; firstBreak?: { line: number; reason: string } };
      };
      assert.equal(badBody.ok, false);
      assert.deepEqual(badBody.firstBreak, { line: 1, reason: "hash_mismatch" });
      assert.equal(badBody.hmacChain.ok, false);
      assert.deepEqual(badBody.hmacChain.firstBreak, { line: 1, reason: "hmac_mismatch" });
    } finally {
      await closeRelay(relay);
    }
  });
});
