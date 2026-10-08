import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { AesGcmEncryptor, randomAes256Key } from "../src/encrypt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "batch-replay" }));
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

interface SeededItem {
  id: string;
  targetUrl: string;
}

/** Build a running queue whose sender always fails, pre-filled with dead letters. */
function seedDeadLetters(items: SeededItem[], extraOpts: Record<string, unknown> = {}) {
  const timer = manualTimer();
  const q = new RetryQueue({
    sender: async () => {
      throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 2,
    jitterMs: 0,
    setTimer: timer.setTimer,
    ...extraOpts,
  });
  q.start();
  for (const item of items) {
    q.enqueue({
      id: item.id,
      payload: Buffer.from(`payload-${item.id}`),
      targetUrl: item.targetUrl,
      headers: {},
    });
  }
  return { q, timer };
}

async function listen(server: Server): Promise<number> {
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

function postBatch(port: number, body: unknown, token?: string) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
    const r = httpRequest({ host: "127.0.0.1", port, path: "/dead-letter/replay", method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end(raw);
  });
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end(body);
  });
}

describe("dead-letter batch replay", () => {
  it("dry-run returns metadata only and has zero side effects", async () => {
    const { q, timer } = seedDeadLetters([
      { id: "a", targetUrl: EP_A },
      { id: "b", targetUrl: EP_A },
      { id: "c", targetUrl: EP_B },
    ]);
    await timer.run();
    assert.equal(q.getDeadLetter().length, 3);

    const preview = q.replayDeadLetters({}, { dryRun: true });
    assert.equal(preview.length, 3);
    for (const p of preview) {
      assert.deepEqual(Object.keys(p).sort(), [
        "attempts",
        "deadLetteredAt",
        "endpoint",
        "id",
        "lastError",
        "payloadBytes",
      ]);
    }
    assert.ok(!("payload" in preview[0]), "dry-run must not leak the payload");
    assert.ok(!("encryptedPayload" in preview[0]), "dry-run must not leak the sealed envelope");
    assert.equal(preview[0].endpoint, EP_A);
    assert.equal(preview[0].attempts, 2);
    assert.equal(preview[0].lastError, "downstream 500");
    assert.ok(!Number.isNaN(Date.parse(preview[0].deadLetteredAt)));
    assert.equal(preview[0].payloadBytes, Buffer.from("payload-a").length);

    // Zero side effects: nothing re-queued, nothing removed.
    assert.equal(q.getDeadLetter().length, 3, "dry-run must not remove dead letters");
    assert.equal(q.pendingCount(), 0, "dry-run must not re-queue anything");

    // Filters also apply to the preview.
    const byEndpoint = q.replayDeadLetters({ endpoint: EP_B }, { dryRun: true });
    assert.equal(byEndpoint.length, 1);
    assert.equal(byEndpoint[0].id, "c");
    const byIds = q.replayDeadLetters({ ids: ["a", "c"] }, { dryRun: true });
    assert.deepEqual(byIds.map((p) => p.id), ["a", "c"]);
  });

  it("dry-run never touches payloads, not even decrypting them", async () => {
    const { q, timer } = seedDeadLetters([{ id: "x", targetUrl: EP_A }], {
      payloadEncryptor: new AesGcmEncryptor(randomAes256Key()),
    });
    await timer.run();
    assert.equal(q.getDeadLetter().length, 1);
    assert.ok(q.getDeadLetter()[0].encryptedPayload, "dead letter should be sealed");
    // Corrupt the sealed envelope: a real replay would now fail to decrypt.
    q.getDeadLetter()[0].encryptedPayload!.tag = Buffer.alloc(16).toString("base64");
    const preview = q.replayDeadLetters({ ids: ["x"] }, { dryRun: true });
    assert.equal(preview.length, 1);
    assert.equal(preview[0].id, "x");
  });

  it("replays by endpoint, leaving other endpoints' dead letters alone", async () => {
    const { q, timer } = seedDeadLetters([
      { id: "a1", targetUrl: EP_A },
      { id: "b1", targetUrl: EP_B },
      { id: "a2", targetUrl: EP_A },
    ]);
    await timer.run();
    const result = q.replayDeadLetters({ endpoint: EP_A });
    assert.deepEqual(result.replayed, ["a1", "a2"]);
    assert.deepEqual(result.failed, []);
    assert.deepEqual(
      q.getDeadLetter().map((e) => e.id),
      ["b1"],
      "only the other endpoint's entries stay dead-lettered"
    );
    assert.equal(q.pendingCount(), 2);
  });

  it("replays an ids subset", async () => {
    const { q, timer } = seedDeadLetters([
      { id: "a", targetUrl: EP_A },
      { id: "b", targetUrl: EP_A },
      { id: "c", targetUrl: EP_A },
    ]);
    await timer.run();
    const result = q.replayDeadLetters({ ids: ["a", "c"] });
    assert.deepEqual(result.replayed, ["a", "c"]);
    assert.deepEqual(result.failed, []);
    assert.deepEqual(q.getDeadLetter().map((e) => e.id), ["b"]);
    // Unknown ids are reported as failures, not crashes — like the
    // single-item endpoint's 404, a typo should be visible, not invisible.
    const missing = q.replayDeadLetters({ ids: ["nope"] });
    assert.deepEqual(missing.replayed, []);
    assert.equal(missing.failed.length, 1);
    assert.equal(missing.failed[0].id, "nope");
    assert.match(missing.failed[0].error, /unknown dead-letter id/);
  });

  it("a failed replay stays in the dead-letter list and is reported with its error", async () => {
    const { q, timer } = seedDeadLetters(
      [
        { id: "good", targetUrl: EP_A },
        { id: "bad", targetUrl: EP_A },
      ],
      { payloadEncryptor: new AesGcmEncryptor(randomAes256Key()) }
    );
    await timer.run();
    // Corrupt the sealed envelope of one entry (at-rest corruption): its
    // replay fails to decrypt, the other one replays fine.
    const bad = q.getDeadLetter().find((e) => e.id === "bad")!;
    bad.encryptedPayload!.tag = Buffer.alloc(16).toString("base64");

    const result = q.replayDeadLetters();
    assert.deepEqual(result.replayed, ["good"]);
    assert.equal(result.failed.length, 1);
    assert.equal(result.failed[0].id, "bad");
    assert.match(result.failed[0].error, /decrypt failed/);

    // The failed entry stays dead-lettered; the success left the list.
    assert.deepEqual(q.getDeadLetter().map((e) => e.id), ["bad"]);
    assert.equal(q.pendingCount(), 1);
  });

  it("returns empty results when nothing matches", async () => {
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }]);
    await timer.run();
    assert.deepEqual(q.replayDeadLetters({ endpoint: EP_B }), { replayed: [], failed: [] });
    assert.deepEqual(q.replayDeadLetters({ ids: [] }), { replayed: [], failed: [] });
    assert.deepEqual(q.replayDeadLetters({}, { dryRun: true }).length, 1);
  });

  it("single replay is failure-atomic: a decrypt failure keeps the dead letter", async () => {
    const { q, timer } = seedDeadLetters([{ id: "x", targetUrl: EP_A }], {
      payloadEncryptor: new AesGcmEncryptor(randomAes256Key()),
    });
    await timer.run();
    q.getDeadLetter()[0].encryptedPayload!.tag = Buffer.alloc(16).toString("base64");
    assert.throws(() => q.replayDeadLetter("x"), /decrypt failed/);
    assert.equal(q.getDeadLetter().length, 1, "failed single replay must not lose the entry");
  });
});

describe("POST /dead-letter/replay operator endpoint", () => {
  it("dry-run has no side effects and never leaks payloads", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      sender: async () => {
        throw new Error("downstream 500");
      },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      operatorToken: "op-secret",
    });
    const port = await listen(relay);
    const auth = "op-secret";
    try {
      assert.equal((await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) })).status, 202);
      const listed = await getDeadLetterEntries(port, auth);
      assert.equal(listed.length, 1);
      const id = listed[0].id;

      const auditBefore = audit.readAll().length;
      const res = await postBatch(port, { dryRun: true }, auth);
      assert.equal(res.status, 200);
      const body = JSON.parse(res.text) as Record<string, unknown>;
      assert.equal(body.dryRun, true);
      const entries = body.entries as Array<Record<string, unknown>>;
      assert.equal(entries.length, 1);
      assert.equal(entries[0].id, id);
      assert.equal(entries[0].endpoint, "http://127.0.0.1:1/unused");
      assert.equal(entries[0].attempts, 2);
      assert.equal(entries[0].lastError, "downstream 500");
      assert.ok(!("payload" in entries[0]), "dry-run must not leak the payload");

      // Zero side effects.
      assert.equal((await getDeadLetterEntries(port, auth)).length, 1, "dead-letter count unchanged");
      assert.equal(audit.readAll().length, auditBefore, "no audit events from a dry run");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("replays matching entries and audits dead_letter_batch_replayed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const forwardUrl = "http://127.0.0.1:1/unused";
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl,
      auditLog: audit,
      sender: async () => {
        throw new Error("downstream 500");
      },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      operatorToken: "op-secret",
    });
    const port = await listen(relay);
    const auth = "op-secret";
    try {
      const sig = { "x-signature": signSha256(BODY, SECRET) };
      assert.equal((await post(port, "/", BODY, sig)).status, 202);
      assert.equal((await post(port, "/", BODY, sig)).status, 202);
      let listed = await getDeadLetterEntries(port, auth);
      assert.equal(listed.length, 2);
      const ids = listed.map((e) => e.id);

      // ids subset: only the first entry is replayed.
      const subset = await postBatch(port, { ids: [ids[0]] }, auth);
      assert.equal(subset.status, 200);
      const subsetBody = JSON.parse(subset.text) as Record<string, unknown>;
      assert.deepEqual(subsetBody.replayed, [ids[0]]);
      assert.deepEqual(subsetBody.failed, []);

      // The replayed entry re-enters delivering and, with the sender still
      // failing, comes back to the dead-letter list with a fresh budget.
      listed = await getDeadLetterEntries(port, auth, 2);
      assert.equal(listed.length, 2);
      const back = listed.find((e) => e.id === ids[0])!;
      assert.equal(back.attempts, 2);

      // Full batch replay by endpoint filter.
      const full = await postBatch(port, { endpoint: forwardUrl }, auth);
      assert.equal(full.status, 200);
      const fullBody = JSON.parse(full.text) as Record<string, unknown>;
      assert.deepEqual((fullBody.replayed as string[]).sort(), [...ids].sort());
      assert.deepEqual(fullBody.failed, []);

      const events = audit.readAll() as Array<Record<string, unknown>>;
      const batched = events.filter((e) => e.event === "dead_letter_batch_replayed");
      assert.equal(batched.length, 2);
      assert.deepEqual(batched[0].replayed, [ids[0]]);
      assert.deepEqual(batched[1].endpoint, forwardUrl);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("is 404 fail-closed without operatorToken and 403 with a wrong token", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listen(relay);
    try {
      assert.equal((await postBatch(port, { dryRun: true })).status, 404);
      assert.equal((await postBatch(port, { dryRun: true }, "some-token")).status, 404);
      assert.equal((await get(port, "/dead-letter/replay", { authorization: "Bearer x" })).status, 404);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("requires the bearer token and a valid JSON body when configured", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      operatorToken: "op-secret",
    });
    const port = await listen(relay);
    try {
      assert.equal((await postBatch(port, { dryRun: true })).status, 403);
      assert.equal((await postBatch(port, { dryRun: true }, "wrong")).status, 403);
      // Malformed body and bad field types are 400, not crashes.
      assert.equal((await postBatch(port, "not json", "op-secret")).status, 400);
      assert.equal((await postBatch(port, { endpoint: 42 }, "op-secret")).status, 400);
      assert.equal((await postBatch(port, { ids: "x" }, "op-secret")).status, 400);
      assert.equal((await postBatch(port, { dryRun: "yes" }, "op-secret")).status, 400);
      // GET is not allowed on the replay endpoint.
      assert.equal(
        (await get(port, "/dead-letter/replay", { authorization: "Bearer op-secret" })).status,
        405
      );
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});

async function getDeadLetterEntries(
  port: number,
  token: string,
  expected = 1
): Promise<Array<{ id: string; attempts: number }>> {
  const deadline = Date.now() + 5000;
  for (;;) {
    const res = await get(port, "/dead-letter", { authorization: `Bearer ${token}` });
    assert.equal(res.status, 200);
    const entries = JSON.parse(res.text) as Array<{ id: string; attempts: number }>;
    if (entries.length >= expected) return entries;
    if (Date.now() >= deadline) throw new Error("timed out waiting for dead letters");
    await new Promise((r) => setTimeout(r, 25));
  }
}
