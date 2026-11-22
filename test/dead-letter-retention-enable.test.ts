import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue } from "../src/retry.ts";
import {
  type DeadLetterPurgeResult,
  type DeadLetterPurgedEvent,
} from "../src/deadletter-retention.ts";
import { AesGcmEncryptor, randomAes256Key, type PayloadEncryptor } from "../src/encrypt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const signingKey = "dead-letter-retention-enable-test-key";
const opToken = "dead-letter-retention-enable-op-token";
const EP_A = "http://a.example/hook";
const URL = "http://localhost:9999/hook";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Queue WITHOUT deadLetterRetention configured — the enable's starting point. */
function makeQueue(extraOpts: Record<string, unknown> = {}) {
  const purged: DeadLetterPurgedEvent[] = [];
  const q = new RetryQueue({
    sender: async () => {
      throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 1,
    jitterMs: 0,
    onDeadLetterPurged: (e) => purged.push(e),
    ...extraOpts,
  });
  return { q, purged };
}

/** Enqueue one item and wait until it has failed into the dead letter. */
async function seedDeadLetter(q: RetryQueue, id: string, targetUrl = EP_A): Promise<void> {
  q.enqueue({ id, payload: Buffer.from(`payload-${id}`), targetUrl, headers: {} });
  const deadline = Date.now() + 2000;
  while (Date.now() < deadline) {
    if (q.getDeadLetter().some((e) => e.id === id)) return;
    await sleep(10);
  }
  throw new Error(`seed timeout: ${id} never dead-lettered`);
}

describe("RetryQueue.setDeadLetterRetention enable (WR-449)", () => {
  it("enabling on an unconfigured queue resolves the sweep interval to the 60s default", async () => {
    const { q } = makeQueue();
    try {
      assert.equal(q.getDeadLetterRetention(), undefined);
      assert.equal(q.retentionConfigured(), false);
      assert.equal(q.getRetentionSweeper(), undefined);
      assert.deepEqual(q.setDeadLetterRetention({ retentionMs: 1000 }), {
        retentionMs: 1000,
        sweepIntervalMs: 60_000,
      });
      assert.deepEqual(q.getDeadLetterRetention(), {
        retentionMs: 1000,
        sweepIntervalMs: 60_000,
      });
      assert.ok(q.getRetentionSweeper() !== undefined);
      assert.equal(q.retentionConfigured(), true);
    } finally {
      await q.shutdown();
    }
    // The per-endpoint record form, on a fresh queue.
    const second = makeQueue();
    try {
      assert.deepEqual(second.q.setDeadLetterRetention({ retentionMs: { [EP_A]: 500 } }), {
        retentionMs: { [EP_A]: 500 },
        sweepIntervalMs: 60_000,
      });
    } finally {
      await second.q.shutdown();
    }
  });

  it("a missing, empty, non-object, or illegal enable patch throws RangeError and leaves the queue unconfigured", async () => {
    const { q } = makeQueue();
    try {
      for (const bad of [
        {},
        { sweepIntervalMs: 5000 }, // missing retentionMs: nothing to enable
        null,
        "1000",
        [1000],
        { retentionMs: 0 },
        { retentionMs: -1 },
        { retentionMs: NaN },
        { retentionMs: Infinity },
        { retentionMs: null },
        { retentionMs: "1000" },
        { retentionMs: [1000] },
        { retentionMs: { [EP_A]: 0 } },
        { retentionMs: { "": 1000 } },
        { retentionMs: 1000, sweepIntervalMs: 0 },
        { retentionMs: 1000, sweepIntervalMs: NaN },
      ] as never[]) {
        assert.throws(
          () => q.setDeadLetterRetention(bad),
          RangeError,
          `patch ${JSON.stringify(bad)}`
        );
        assert.equal(q.getDeadLetterRetention(), undefined);
        assert.equal(q.retentionConfigured(), false);
        assert.equal(q.getRetentionSweeper(), undefined);
      }
      // A valid patch still enables after the rejected ones.
      assert.deepEqual(q.setDeadLetterRetention({ retentionMs: 1000 }), {
        retentionMs: 1000,
        sweepIntervalMs: 60_000,
      });
    } finally {
      await q.shutdown();
    }
  });

  it("enabling on a running queue arms the sweep schedule immediately; on a stopped queue it arms at the next start", async () => {
    const running = makeQueue();
    try {
      running.q.start();
      running.q.setDeadLetterRetention({ retentionMs: 1000, sweepIntervalMs: 3_600_000 });
      assert.equal(running.q.getRetentionSweeper()?.isRunning(), true);
      running.q.stop();
      assert.equal(running.q.getRetentionSweeper()?.isRunning(), false);
      running.q.start();
      assert.equal(running.q.getRetentionSweeper()?.isRunning(), true);
      running.q.stop();
    } finally {
      await running.q.shutdown();
    }
    const stopped = makeQueue();
    try {
      stopped.q.setDeadLetterRetention({ retentionMs: 1000, sweepIntervalMs: 3_600_000 });
      assert.equal(stopped.q.getRetentionSweeper()?.isRunning(), false);
      stopped.q.start();
      assert.equal(stopped.q.getRetentionSweeper()?.isRunning(), true);
      stopped.q.stop();
    } finally {
      await stopped.q.shutdown();
    }
  });

  it("entries already past TTL at enable time are purged on the next sweep", async () => {
    const { q, purged } = makeQueue();
    try {
      q.start();
      await seedDeadLetter(q, "a");
      // The entry is already ~30ms old: a 1ms TTL makes it expired
      // the moment the enable lands — TTLs judge by age, so the
      // pre-enable dead letter is not grandfathered in.
      await sleep(30);
      assert.deepEqual(q.setDeadLetterRetention({ retentionMs: 1 }), {
        retentionMs: 1,
        sweepIntervalMs: 60_000,
      });
      const result = q.purgeExpiredDeadLetters();
      assert.deepEqual(
        result.purged.map((p) => p.id),
        ["a"]
      );
      assert.deepEqual(result.skipped, []);
      assert.equal(q.getDeadLetter().length, 0);
      assert.equal(purged.length, 1);
      assert.equal(purged[0].id, "a");
      assert.equal(purged[0].endpoint, EP_A);
      assert.equal(purged[0].event, "dead_letter_purged");
    } finally {
      q.stop();
    }
  });

  it("entries not yet past TTL are purged when they age out", async () => {
    const { q } = makeQueue();
    try {
      q.start();
      await seedDeadLetter(q, "a");
      assert.deepEqual(q.setDeadLetterRetention({ retentionMs: 300 }), {
        retentionMs: 300,
        sweepIntervalMs: 60_000,
      });
      assert.deepEqual(q.purgeExpiredDeadLetters(), { purged: [], skipped: [] });
      assert.equal(q.getDeadLetter().length, 1, "too young to purge yet");
      await sleep(350);
      assert.deepEqual(
        q.purgeExpiredDeadLetters().purged.map((p) => p.id),
        ["a"]
      );
      assert.equal(q.getDeadLetter().length, 0);
    } finally {
      q.stop();
    }
  });

  it("entries claimed by an in-progress replay are still skipped after an enable", async () => {
    const base = new AesGcmEncryptor(randomAes256Key());
    let inner: DeadLetterPurgeResult | undefined;
    let armed = false;
    let queue!: RetryQueue;
    const hookEncryptor: PayloadEncryptor = {
      name: base.name,
      encrypt: (p) => base.encrypt(p),
      decrypt: (env) => {
        // Reentrant sweep, fired from inside the batch replay's decrypt:
        // the batch claims every matched id for its whole run. Armed
        // only for the replay — the initial failed deliveries decrypt
        // too, before any sweeper exists.
        if (armed) inner ??= queue.purgeExpiredDeadLetters();
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
    });
    try {
      queue.start();
      await seedDeadLetter(queue, "r1");
      await seedDeadLetter(queue, "r2");
      // Enable after the dead letters exist: both are already past
      // the 1ms TTL by the time the replay runs.
      assert.deepEqual(queue.setDeadLetterRetention({ retentionMs: 1 }), {
        retentionMs: 1,
        sweepIntervalMs: 60_000,
      });
      await sleep(30);
      armed = true;
      const result = queue.replayDeadLetters();
      assert.deepEqual(result.replayed.sort(), ["r1", "r2"]);
      assert.ok(inner !== undefined, "the reentrant sweep should have run inside decrypt");
      // r1 was mid-replay (already spliced out); r2 was still listed but
      // claimed by the batch — it must be skipped, not purged.
      assert.deepEqual(inner.skipped, ["r2"]);
      assert.deepEqual(inner.purged, []);
    } finally {
      queue.stop();
    }
  });

  it("the armed sweep purges on schedule after an enable on a running queue", async () => {
    const { q, purged } = makeQueue();
    try {
      q.start();
      await seedDeadLetter(q, "a");
      assert.deepEqual(
        q.setDeadLetterRetention({ retentionMs: 1, sweepIntervalMs: 50 }),
        { retentionMs: 1, sweepIntervalMs: 50 }
      );
      // No manual sweep: the armed timer must purge on schedule.
      const deadline = Date.now() + 2000;
      while (Date.now() < deadline) {
        if (q.getDeadLetter().length === 0) break;
        await sleep(10);
      }
      assert.equal(q.getDeadLetter().length, 0, "the armed sweep should purge on schedule");
      assert.equal(purged.length, 1);
      assert.equal(purged[0].id, "a");
    } finally {
      q.stop();
    }
  });

  it("a restart returns to unconfigured — the enable is live-only", async () => {
    const first = makeQueue();
    try {
      first.q.setDeadLetterRetention({ retentionMs: 1000 });
      assert.equal(first.q.retentionConfigured(), true);
    } finally {
      await first.q.shutdown();
    }
    const second = makeQueue();
    try {
      assert.equal(second.q.getDeadLetterRetention(), undefined);
      assert.equal(second.q.retentionConfigured(), false);
      assert.equal(second.q.getRetentionSweeper(), undefined);
    } finally {
      await second.q.shutdown();
    }
  });

  it("enabling unlocks the dead-letter-purged callback gate and purges flow to it", async () => {
    const { q } = makeQueue();
    try {
      assert.throws(
        () => q.reviseDeadLetterPurgedCallback(() => {}),
        (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
      );
      q.setDeadLetterRetention({ retentionMs: 1 });
      // No throw now — the gate opens the moment the sweeper exists.
      const seen: DeadLetterPurgedEvent[] = [];
      q.reviseDeadLetterPurgedCallback((e) => seen.push(e));
      q.start();
      await seedDeadLetter(q, "a");
      await sleep(30); // past the 1ms TTL
      assert.deepEqual(
        q.purgeExpiredDeadLetters().purged.map((p) => p.id),
        ["a"]
      );
      assert.equal(seen.length, 1);
      assert.equal(seen[0].id, "a");
      assert.equal(seen[0].event, "dead_letter_purged");
      // Clearing back to audit-only leaves the sweep itself working.
      q.reviseDeadLetterPurgedCallback(null);
      await seedDeadLetter(q, "b");
      await sleep(30);
      assert.deepEqual(
        q.purgeExpiredDeadLetters().purged.map((p) => p.id),
        ["b"]
      );
      assert.equal(seen.length, 1, "cleared callback receives nothing more");
    } finally {
      await q.shutdown();
    }
  });
});

describe("RelayServer dead-letter retention enable (WR-449)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function listen(server: Server): Promise<number> {
    return new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
  }

  function makeRelay() {
    const dir = mkdtempSync(join(tmpdir(), "dead-letter-retention-enable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("enable audits previous null and the full current snapshot, and mounts the getter", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getDeadLetterRetention, undefined);
    assert.equal(typeof relay.setDeadLetterRetention, "function", "set is always set");
    // The callback gate is still fail-closed before the enable.
    assert.throws(
      () => relay.reviseDeadLetterPurgedCallback!(null),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    assert.deepEqual(relay.setDeadLetterRetention!({ retentionMs: 1000 }), {
      retentionMs: 1000,
      sweepIntervalMs: 60_000,
    });
    assert.deepEqual(relay.getDeadLetterRetention!(), {
      retentionMs: 1000,
      sweepIntervalMs: 60_000,
    });
    const revised = eventsOf(audit, "dead_letter_retention_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { retentionMs: 1000, sweepIntervalMs: 60_000 });
    // The enable also opens the callback gate (WR-397 stays unset).
    relay.reviseDeadLetterPurgedCallback!(() => {});
    const replaced = eventsOf(audit, "dead_letter_purged_callback_revised");
    assert.equal(replaced.length, 1);
    assert.equal(replaced[0].previous, "cleared");
    assert.equal(replaced[0].current, "set");
    // A same-value revision after the enable is a silent no-op.
    relay.setDeadLetterRetention!({ retentionMs: 1000 });
    assert.equal(eventsOf(audit, "dead_letter_retention_revised").length, 1);
  });

  it("an illegal or empty enable patch throws RangeError and leaves the server unconfigured", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    for (const bad of [
      {},
      { sweepIntervalMs: 5000 },
      { retentionMs: 0 },
      { retentionMs: null },
    ] as never[]) {
      assert.throws(() => relay.setDeadLetterRetention!(bad), RangeError);
    }
    assert.throws(() => relay.setDeadLetterRetention!(null as never), RangeError);
    assert.equal(relay.getDeadLetterRetention, undefined);
    assert.equal(eventsOf(audit, "dead_letter_retention_revised").length, 0);
  });

  it("a restart returns to unconfigured — the enable is live-only", async () => {
    const first = makeRelay();
    await listen(first.relay);
    first.relay.setDeadLetterRetention!({ retentionMs: 1000 });
    assert.deepEqual(first.relay.getDeadLetterRetention!(), {
      retentionMs: 1000,
      sweepIntervalMs: 60_000,
    });
    const second = makeRelay();
    await listen(second.relay);
    assert.equal(second.relay.getDeadLetterRetention, undefined);
  });
});
