import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, appendFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type RetryItem,
  type Sender,
  type QueueRestoredInfo,
} from "../src/retry.ts";
import { QueueJournal } from "../src/durable-queue.ts";
import { AesGcmEncryptor, randomAes256Key } from "../src/encrypt.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

/** Deterministic clock + timer; delays are captured for assertions. */
function controlledEnv(startMs = 1_000_000) {
  let now = startMs;
  const pending: Array<{ fn: () => void }> = [];
  const delays: number[] = [];
  const setTimer = (fn: () => void, ms: number) => {
    delays.push(ms);
    const rec = { fn };
    pending.push(rec);
    return {
      clear: () => {
        const i = pending.indexOf(rec);
        if (i >= 0) pending.splice(i, 1);
      },
    };
  };
  const clearTimer = (h: { clear(): void }) => h.clear();
  const settle = () => new Promise((r) => setImmediate(r));
  return {
    now: () => now,
    advance: (ms: number) => {
      now += ms;
    },
    setTimer,
    clearTimer,
    delays,
    pendingCount: () => pending.length,
    async fireNext() {
      const rec = pending.shift();
      assert.ok(rec, "expected a pending timer");
      rec.fn();
      await settle();
      await settle();
    },
    async drain() {
      let guard = 10000;
      while (pending.length > 0) {
        if (--guard <= 0) throw new Error("drain did not terminate");
        const rec = pending.shift()!;
        rec.fn();
        await settle();
        await settle();
      }
    },
  };
}

const ITEM: RetryItem = {
  id: "dq-item-1",
  payload: Buffer.from("durable-payload"),
  targetUrl: "http://localhost:9999/hook",
  headers: { "content-type": "application/json" },
};

function freshDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

function baseOpts(env: ReturnType<typeof controlledEnv>, dir: string, sender: Sender) {
  return {
    sender,
    baseDelayMs: 1000,
    maxDelayMs: 60000,
    maxAttempts: 3,
    jitterMs: 0,
    setTimer: env.setTimer,
    clearTimer: env.clearTimer,
    durableQueueDir: dir,
    durableQueueNow: env.now,
  };
}

describe("durable-queue", () => {
  it("restores a pending item and delivers it after restart", async () => {
    const dir = freshDir("dq-");
    const env1 = controlledEnv();
    const q1 = new RetryQueue(baseOpts(env1, dir, async () => {}));
    // Enqueued while stopped: journaled, never scheduled.
    q1.enqueue({ ...ITEM });
    assert.ok(existsSync(join(dir, "queue.jsonl")));

    let restored: QueueRestoredInfo | undefined;
    const delivered: Buffer[] = [];
    const env2 = controlledEnv();
    const q2 = new RetryQueue({
      ...baseOpts(env2, dir, async (item) => {
        delivered.push(item.payload);
      }),
      onQueueRestored: (info) => {
        restored = info;
      },
    });
    assert.deepEqual(restored, {
      dir,
      restoredItems: 1,
      restoredDeadLetters: 0,
      restoredRetries: 0,
      skippedLines: 0,
    });
    q2.start();
    await env2.drain();
    assert.equal(delivered.length, 1);
    assert.deepEqual(delivered[0], ITEM.payload);
    assert.equal(q2.pendingCount(), 0);

    // Delivered items are terminal: a third boot restores nothing.
    const env3 = controlledEnv();
    let restored3: QueueRestoredInfo | undefined;
    const q3 = new RetryQueue({
      ...baseOpts(env3, dir, async () => {}),
      onQueueRestored: (info) => {
        restored3 = info;
      },
    });
    assert.equal(restored3!.restoredItems, 0);
    assert.equal(q3.pendingCount(), 0);
  });

  it("retry resumes with remaining backoff and attempts are not reset", async () => {
    const dir = freshDir("dq-");
    const env1 = controlledEnv();
    const q1 = new RetryQueue(
      baseOpts(env1, dir, async () => {
        throw new Error("down");
      })
    );
    q1.start();
    q1.enqueue({ ...ITEM });
    await env1.fireNext(); // attempt 1 fails -> backoff 2000ms journaled
    assert.deepEqual(env1.delays, [0, 2000]);

    // "Restart" 500ms into the backoff: the retry must resume with the
    // remaining 1500ms, not the full 2000ms.
    const env2 = controlledEnv();
    env2.advance(500);
    let restored: QueueRestoredInfo | undefined;
    const q2 = new RetryQueue({
      ...baseOpts(env2, dir, async () => {
        throw new Error("still down");
      }),
      onQueueRestored: (info) => {
        restored = info;
      },
    });
    assert.equal(restored!.restoredItems, 1);
    assert.equal(restored!.restoredRetries, 1);
    q2.start();
    assert.deepEqual(env2.delays, [1500]);

    await env2.fireNext(); // attempt 2 fails -> backoff for attempt 2
    // attempt was preserved (1, not reset to 0): next backoff is
    // base*2^2 = 4000, not 2000.
    assert.deepEqual(env2.delays, [1500, 4000]);
    await env2.fireNext(); // attempt 3 fails -> maxAttempts reached
    assert.equal(q2.getDeadLetter().length, 1);
    assert.equal(q2.getDeadLetter()[0].attempts, 3);
    assert.equal(q2.getDeadLetter()[0].id, ITEM.id);

    // The dead letter survives another restart with its payload intact.
    const env3 = controlledEnv();
    const q3 = new RetryQueue(baseOpts(env3, dir, async () => {}));
    const dead = q3.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.deepEqual(dead[0].payload, ITEM.payload);
    assert.equal(q3.pendingCount(), 0);
  });

  it("seals payloads with the WR-11 encryptor and restores dead letters sealed", async () => {
    const dir = freshDir("dq-");
    const key = randomAes256Key();
    const encryptor = new AesGcmEncryptor(key);
    const env1 = controlledEnv();
    const secretPayload = Buffer.from("secret-payload-bytes");
    const q1 = new RetryQueue({
      ...baseOpts(env1, dir, async () => {
        throw new Error("down");
      }),
      maxAttempts: 1,
      payloadEncryptor: encryptor,
    });
    q1.start();
    q1.enqueue({ ...ITEM, payload: secretPayload });
    await env1.drain();
    assert.equal(q1.getDeadLetter().length, 1);
    // No plaintext payload on disk.
    const journal = readFileSync(join(dir, "queue.jsonl"), "utf8");
    assert.ok(!journal.includes("secret-payload-bytes"));

    // Restore with the same encryptor: the dead letter comes back sealed
    // and replays to the original bytes.
    const env2 = controlledEnv();
    const delivered: Buffer[] = [];
    const q2 = new RetryQueue({
      ...baseOpts(env2, dir, async (item) => {
        delivered.push(item.payload);
      }),
      payloadEncryptor: encryptor,
    });
    assert.equal(q2.getDeadLetter().length, 1);
    assert.equal(q2.getDeadLetter()[0].payload.length, 0); // sealed placeholder
    assert.ok(q2.getDeadLetter()[0].encryptedPayload);
    assert.ok(q2.replayDeadLetter(ITEM.id));
    q2.start();
    await env2.drain();
    assert.equal(delivered.length, 1);
    assert.deepEqual(delivered[0], secretPayload);
  });

  it("restores sealed dead letters without an encryptor; replay then fails loudly and keeps the entry", async () => {
    const dir = freshDir("dq-");
    const encryptor = new AesGcmEncryptor(randomAes256Key());
    const env1 = controlledEnv();
    const q1 = new RetryQueue({
      ...baseOpts(env1, dir, async () => {
        throw new Error("down");
      }),
      maxAttempts: 1,
      payloadEncryptor: encryptor,
    });
    q1.start();
    q1.enqueue({ ...ITEM });
    await env1.drain();
    assert.equal(q1.getDeadLetter().length, 1);

    // A restart without the encryptor still recovers the sealed entry —
    // decryption waits for replay, like the live dead-letter list.
    const env2 = controlledEnv();
    const q2 = new RetryQueue(baseOpts(env2, dir, async () => {}));
    assert.equal(q2.getDeadLetter().length, 1);
    assert.throws(() => q2.replayDeadLetter(ITEM.id), /no payloadEncryptor/);
    // Failed replay never loses the dead letter.
    assert.equal(q2.getDeadLetter().length, 1);
  });

  it("a replayed dead letter restores as live, not dead", async () => {
    const dir = freshDir("dq-");
    const env1 = controlledEnv();
    const q1 = new RetryQueue(
      baseOpts(env1, dir, async () => {
        throw new Error("down");
      })
    );
    q1.start();
    // Exhaust all 3 attempts quickly: the sender always fails.
    q1.enqueue({ ...ITEM });
    await env1.drain();
    assert.equal(q1.getDeadLetter().length, 1);
    assert.ok(q1.replayDeadLetter(ITEM.id));
    assert.equal(q1.getDeadLetter().length, 0);
    assert.equal(q1.pendingCount(), 1);
    // Restart before the replayed item delivers: it must come back live.
    const env2 = controlledEnv();
    let restored: QueueRestoredInfo | undefined;
    const q2 = new RetryQueue({
      ...baseOpts(env2, dir, async () => {}),
      onQueueRestored: (info) => {
        restored = info;
      },
    });
    assert.equal(restored!.restoredItems, 1);
    assert.equal(restored!.restoredDeadLetters, 0);
    assert.equal(q2.pendingCount(), 1);
  });

  it("skips corrupt journal lines and counts them", async () => {
    const dir = freshDir("dq-");
    const env1 = controlledEnv();
    const q1 = new RetryQueue(baseOpts(env1, dir, async () => {}));
    q1.enqueue({ ...ITEM });
    const path = join(dir, "queue.jsonl");
    appendFileSync(path, "\nthis is not json\n");
    appendFileSync(path, JSON.stringify({ v: 1, op: "bogus", id: "x" }) + "\n");
    appendFileSync(path, JSON.stringify({ v: 1, op: "retry", id: "ghost" }) + "\n"); // unknown id

    const env2 = controlledEnv();
    let restored: QueueRestoredInfo | undefined;
    const q2 = new RetryQueue({
      ...baseOpts(env2, dir, async () => {}),
      onQueueRestored: (info) => {
        restored = info;
      },
    });
    assert.equal(restored!.restoredItems, 1);
    assert.equal(restored!.skippedLines, 3);
    assert.equal(q2.getDurableQueueStats().skippedLines, 3);
  });

  it("is disabled by default and rejects invalid configuration", () => {
    const env = controlledEnv();
    const q = new RetryQueue({ sender: async () => {}, setTimer: env.setTimer });
    assert.equal(q.getDurableQueueStats().enabled, false);
    assert.throws(() => new RetryQueue({ durableQueueDir: "" }), RangeError);
    assert.throws(() => new RetryQueue({ durableQueueDir: 123 as unknown as string }), RangeError);
  });

  it("compacts superseded lines while keeping live state", async () => {
    const dir = freshDir("dq-");
    const journal = new QueueJournal(dir);
    const item = (id: string): RetryItem & { attempt: number } => ({
      id,
      payload: Buffer.from(id),
      targetUrl: "http://x/hook",
      headers: {},
      attempt: 0,
    });
    journal.appendEnqueue(item("a"));
    journal.appendEnqueue(item("b"));
    journal.appendEnqueue(item("c"));
    journal.appendRetry("b", 2, 1_002_000);
    journal.appendDelivered("a");
    // Live: b (attempt 2, retry pending), c (fresh).
    journal.compact(
      [
        { ...item("b"), attempt: 2, nextAt: 1_002_000 },
        { ...item("c"), attempt: 0 },
      ],
      [],
      true
    );
    const rec = journal.recover();
    assert.equal(rec.items.length, 2);
    const b = rec.items.find((i) => i.id === "b")!;
    assert.equal(b.attempt, 2);
    assert.equal(b.nextAt, 1_002_000);
    assert.deepEqual(b.payload, Buffer.from("b"));
    const lines = readFileSync(join(dir, "queue.jsonl"), "utf8")
      .split("\n")
      .filter((l) => l.trim() !== "");
    // 2 enqueue + 1 retry; the delivered/superseded lines are gone.
    assert.equal(lines.length, 3);
  });

  it("emits queue_restored to the audit log on server boot", async () => {
    const dir = freshDir("dq-");
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "dq-secret",
      forwardUrl: "http://127.0.0.1:9/hook",
      auditLog: audit,
      durableQueueDir: join(dir, "queue"),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    try {
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const restored = events.find((e) => e.event === "queue_restored");
      assert.ok(restored, "expected a queue_restored audit event");
      assert.equal(restored!.restoredItems, 0);
      assert.equal(restored!.restoredDeadLetters, 0);
      assert.equal(restored!.skippedLines, 0);
    } finally {
      relay.close();
    }
  });

  it("exposes durable stats via getDurableQueueStats", async () => {
    const dir = freshDir("dq-");
    const env = controlledEnv();
    const q = new RetryQueue(baseOpts(env, dir, async () => {}));
    q.enqueue({ ...ITEM });
    const stats = q.getDurableQueueStats();
    assert.equal(stats.enabled, true);
    assert.equal(stats.dir, dir);
    assert.equal(stats.liveItems, 1);
    assert.equal(stats.deadLetters, 0);
    assert.ok(stats.journalAppends >= 1);
    assert.equal(stats.journalWriteErrors, 0);
  });
});
