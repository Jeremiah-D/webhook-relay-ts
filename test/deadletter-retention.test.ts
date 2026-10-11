import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { AesGcmEncryptor, randomAes256Key, type PayloadEncryptor } from "../src/encrypt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import type {
  DeadLetterPurgeResult,
  DeadLetterPurgedEvent,
} from "../src/deadletter-retention.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const INGEST_KEY = "relay-secret";
const OPERATOR_TOKEN = "op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "retention" }));
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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
  tenantId?: string;
}

/** Build a queue whose sender always fails, pre-filled with dead letters. */
function seedDeadLetters(items: SeededItem[], extraOpts: Record<string, unknown> = {}) {
  const timer = manualTimer();
  const q = new RetryQueue({
    sender: async () => {
      throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 1,
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
      ...(item.tenantId !== undefined ? { tenantId: item.tenantId } : {}),
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

describe("dead-letter retention validation", () => {
  it("rejects illegal retention values with RangeError", () => {
    const bad: unknown[] = [
      { retentionMs: 0 },
      { retentionMs: -100 },
      { retentionMs: NaN },
      { retentionMs: Infinity },
      { retentionMs: "60000" },
      { retentionMs: [1000] },
      { retentionMs: { [EP_A]: 0 } },
      { retentionMs: { [EP_A]: -1 } },
      { retentionMs: { [EP_A]: NaN } },
      { retentionMs: { [EP_A]: Infinity } },
      { retentionMs: { "": 1000 } },
      { retentionMs: 1000, sweepIntervalMs: 0 },
      { retentionMs: 1000, sweepIntervalMs: -1 },
      { retentionMs: 1000, sweepIntervalMs: NaN },
    ];
    for (const opts of bad) {
      assert.throws(
        () => new RetryQueue({ deadLetterRetention: opts as Record<string, unknown> as never }),
        RangeError,
        `expected RangeError for ${JSON.stringify(opts)}`
      );
    }
  });

  it("accepts a missing or TTL-less retention object (inert, no purge)", () => {
    const q = new RetryQueue({});
    assert.deepEqual(q.purgeExpiredDeadLetters(), { purged: [], skipped: [] });
    assert.equal(q.getRetentionSweeper(), undefined);

    const inert = new RetryQueue({ deadLetterRetention: {} });
    assert.equal(inert.getRetentionSweeper()?.isEnabled(), false);
    assert.deepEqual(inert.purgeExpiredDeadLetters(), { purged: [], skipped: [] });
  });

  it("rejects illegal retention values at the server layer", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    assert.throws(
      () =>
        createRelayServer({
          secret: INGEST_KEY,
          forwardUrl: "http://127.0.0.1:1/unused",
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          deadLetterRetention: { retentionMs: 0 },
        }),
      RangeError
    );
  });
});

describe("purgeExpiredDeadLetters", () => {
  it("purges expired entries and reports them without payloads", async () => {
    const { q, timer } = seedDeadLetters(
      [
        { id: "a", targetUrl: EP_A },
        { id: "b", targetUrl: EP_B },
      ],
      { deadLetterRetention: { retentionMs: 1 } }
    );
    await timer.run();
    assert.equal(q.getDeadLetter().length, 2);
    // Let the 1ms TTL expire.
    await sleep(30);

    const result = q.purgeExpiredDeadLetters();
    assert.deepEqual(
      result.purged.map((p) => p.id),
      ["a", "b"]
    );
    assert.deepEqual(result.skipped, []);
    for (const p of result.purged) {
      assert.deepEqual(Object.keys(p).sort(), ["attempts", "deadLetteredAt", "endpoint", "id"]);
      assert.ok(!("payload" in p), "purge report must not leak the payload");
    }
    assert.equal(q.getDeadLetter().length, 0, "purged entries leave the dead-letter list");
  });

  it("keeps entries whose TTL has not expired", async () => {
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: 3_600_000 },
    });
    await timer.run();
    await sleep(20);
    assert.deepEqual(q.purgeExpiredDeadLetters(), { purged: [], skipped: [] });
    assert.equal(q.getDeadLetter().length, 1);
    assert.deepEqual(q.getDeadLetterStats(), { total: 1, purged: 0, byEndpoint: [{ endpoint: EP_A, count: 1 }] });
  });

  it("per-endpoint record only purges opted-in endpoints", async () => {
    const { q, timer } = seedDeadLetters(
      [
        { id: "a1", targetUrl: EP_A },
        { id: "a2", targetUrl: EP_A },
        { id: "b1", targetUrl: EP_B },
      ],
      { deadLetterRetention: { retentionMs: { [EP_A]: 1 } } }
    );
    await timer.run();
    await sleep(30);
    const result = q.purgeExpiredDeadLetters();
    assert.deepEqual(result.purged.map((p) => p.id), ["a1", "a2"]);
    assert.deepEqual(
      q.getDeadLetter().map((e) => e.id),
      ["b1"],
      "the non-opted-in endpoint keeps its dead letters"
    );
    assert.deepEqual(q.getDeadLetterStats(), {
      total: 1,
      purged: 2,
      byEndpoint: [{ endpoint: EP_B, count: 1 }],
    });
  });

  it("purges sealed entries without ever exposing their payload", async () => {
    const events: DeadLetterPurgedEvent[] = [];
    const { q, timer } = seedDeadLetters([{ id: "s", targetUrl: EP_A, tenantId: "t1" }], {
      payloadEncryptor: new AesGcmEncryptor(randomAes256Key()),
      deadLetterRetention: { retentionMs: 1 },
      onDeadLetterPurged: (e) => events.push(e),
    });
    await timer.run();
    assert.ok(q.getDeadLetter()[0].encryptedPayload, "dead letter should be sealed");
    await sleep(30);

    const result = q.purgeExpiredDeadLetters();
    assert.equal(result.purged.length, 1);
    assert.equal(events.length, 1);
    const [e] = events;
    assert.deepEqual(Object.keys(e).sort(), [
      "attempts",
      "deadLetteredAt",
      "endpoint",
      "event",
      "id",
      "tenant",
      "traceId",
    ]);
    assert.equal(e.event, "dead_letter_purged");
    assert.equal(e.id, "s");
    assert.equal(e.endpoint, EP_A);
    assert.equal(e.attempts, 1);
    assert.equal(e.tenant, "t1");
    assert.ok(e.traceId.length > 0);
    assert.ok(!Number.isNaN(Date.parse(e.deadLetteredAt)));
    assert.ok(!("payload" in e), "purge audit must not leak the payload");
    assert.ok(!("encryptedPayload" in e), "purge audit must not leak the sealed envelope");
  });

  it("skips entries claimed by an in-progress WR-23 batch replay", async () => {
    const base = new AesGcmEncryptor(randomAes256Key());
    let inner: DeadLetterPurgeResult | undefined;
    let queue!: RetryQueue;
    const hookEncryptor: PayloadEncryptor = {
      name: base.name,
      encrypt: (p) => base.encrypt(p),
      decrypt: (env) => {
        // Reentrant sweep, fired from inside the batch replay's decrypt:
        // the batch claims every matched id for its whole run.
        inner ??= queue.purgeExpiredDeadLetters();
        return base.decrypt(env);
      },
    };
    queue = new RetryQueue({
      sender: async () => {
        throw new Error("downstream 500");
      },
      baseDelayMs: 1,
      maxAttempts: 1,
      jitterMs: 0,
      payloadEncryptor: hookEncryptor,
      deadLetterRetention: { retentionMs: 1 },
    });
    queue.start();
    queue.enqueue({ id: "r1", payload: Buffer.from("p1"), targetUrl: EP_A, headers: {} });
    queue.enqueue({ id: "r2", payload: Buffer.from("p2"), targetUrl: EP_A, headers: {} });
    // Real timers: let both deliveries fail into the dead letter, then let
    // the 1ms TTL expire.
    await sleep(50);
    assert.equal(queue.getDeadLetter().length, 2);

    const result = queue.replayDeadLetters();
    assert.deepEqual(result.replayed.sort(), ["r1", "r2"]);
    assert.ok(inner !== undefined, "the reentrant sweep should have run inside decrypt");
    // r1 was mid-replay (already spliced out); r2 was still listed but
    // claimed by the batch — it must be skipped, not purged.
    assert.deepEqual(inner.skipped, ["r2"]);
    assert.deepEqual(inner.purged, []);
    queue.stop();
  });

  it("skips entries claimed by a WR-31 auto-replay round", async () => {
    const base = new AesGcmEncryptor(randomAes256Key());
    let inner: DeadLetterPurgeResult | undefined;
    let queue!: RetryQueue;
    const hookEncryptor: PayloadEncryptor = {
      name: base.name,
      encrypt: (p) => base.encrypt(p),
      decrypt: (env) => {
        inner ??= queue.purgeExpiredDeadLetters();
        return base.decrypt(env);
      },
    };
    queue = new RetryQueue({
      sender: async () => {
        throw new Error("downstream 500");
      },
      baseDelayMs: 1,
      maxAttempts: 1,
      jitterMs: 0,
      payloadEncryptor: hookEncryptor,
      deadLetterRetention: { retentionMs: 1 },
      // Top-level, like the server passes it; the schedule itself is
      // driven manually via triggerOnce so no timer fires mid-test.
      autoReplay: { enabled: true, intervalMs: 60_000, maxRounds: 10 },
    });
    queue.start();
    queue.enqueue({ id: "w1", payload: Buffer.from("p1"), targetUrl: EP_A, headers: {} });
    queue.enqueue({ id: "w2", payload: Buffer.from("p2"), targetUrl: EP_A, headers: {} });
    await sleep(50);
    assert.equal(queue.getDeadLetter().length, 2);

    const round = queue.getAutoReplayer()!.triggerOnce();
    assert.deepEqual(round.replayed.sort(), ["w1", "w2"]);
    assert.ok(inner !== undefined, "the reentrant sweep should have run inside the auto-replay round");
    assert.deepEqual(inner.skipped, ["w2"]);
    assert.deepEqual(inner.purged, []);
    queue.stop();
  });

  it("a purged entry never resurrects after a journal recovery", async () => {
    const dir = mkdtempSync(join(tmpdir(), "durable-"));
    const mk = () =>
      new RetryQueue({
        sender: async () => {
          throw new Error("downstream 500");
        },
        baseDelayMs: 1,
        maxAttempts: 1,
        jitterMs: 0,
        durableQueueDir: dir,
        deadLetterRetention: { retentionMs: 1 },
      });
    const q1 = mk();
    q1.start();
    q1.enqueue({ id: "d1", payload: Buffer.from("p1"), targetUrl: EP_A, headers: {} });
    // Real timers: the delivery fails into the dead letter, then the 1ms
    // TTL expires.
    await sleep(80);
    assert.equal(q1.getDeadLetter().length, 1);
    const r = q1.purgeExpiredDeadLetters();
    assert.equal(r.purged.length, 1);
    q1.stop();

    // A restarted process replays the journal: the `purged` line
    // supersedes the `dead_letter` line, so the entry stays gone.
    const q2 = mk();
    assert.equal(q2.getDeadLetter().length, 0, "purged entry must not resurrect after recovery");
    q2.stop();
  });

  it("getDeadLetterStats exposes the purged count", async () => {
    const { q, timer } = seedDeadLetters(
      [
        { id: "a1", targetUrl: EP_A },
        { id: "a2", targetUrl: EP_A },
        { id: "b1", targetUrl: EP_B },
      ],
      { deadLetterRetention: { retentionMs: { [EP_A]: 1 } } }
    );
    await timer.run();
    assert.deepEqual(q.getDeadLetterStats(), {
      total: 3,
      purged: 0,
      byEndpoint: [
        { endpoint: EP_A, count: 2 },
        { endpoint: EP_B, count: 1 },
      ],
    });
    await sleep(30);
    q.purgeExpiredDeadLetters();
    assert.deepEqual(q.getDeadLetterStats(), {
      total: 1,
      purged: 2,
      byEndpoint: [{ endpoint: EP_B, count: 1 }],
    });
  });
});

describe("server wiring", () => {
  it("audits dead_letter_purged and serves GET /dead-letter/stats", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const forwardUrl = "http://127.0.0.1:1/unused";
    const relay = createRelayServer({
      secret: INGEST_KEY,
      forwardUrl,
      auditLog: audit,
      sender: async () => {
        throw new Error("downstream 500");
      },
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
      deadLetterRetention: { retentionMs: 1, sweepIntervalMs: 25 },
      operatorToken: OPERATOR_TOKEN,
    });
    const port = await listen(relay);
    const auth = { authorization: `Bearer ${OPERATOR_TOKEN}` };
    try {
      assert.equal(
        (await post(port, "/", BODY, { "x-signature": signSha256(BODY, INGEST_KEY) })).status,
        202
      );
      // Wait for the delivery to fail into the dead letter and for a
      // couple of sweep intervals to purge it.
      await sleep(300);

      const stats = await get(port, "/dead-letter/stats", auth);
      assert.equal(stats.status, 200);
      const s = JSON.parse(stats.text) as { total: number; purged: number; byEndpoint: unknown[] };
      assert.equal(s.total, 0);
      assert.equal(s.purged, 1);
      assert.deepEqual(s.byEndpoint, []);

      const purgedEvents = audit.readAll().filter((e) => e.event === "dead_letter_purged");
      assert.equal(purgedEvents.length, 1);
      const [ev] = purgedEvents as Array<Record<string, unknown>>;
      assert.equal(ev["endpoint"], forwardUrl);
      assert.equal(typeof ev["id"], "string");
      assert.equal(typeof ev["attempts"], "number");
      assert.ok(!Number.isNaN(Date.parse(ev["deadLetteredAt"] as string)));
      assert.ok(!("payload" in ev), "purge audit must not leak the payload");

      // The stats endpoint sits behind the operator token like the rest.
      assert.equal((await get(port, "/dead-letter/stats")).status, 403);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
