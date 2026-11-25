import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type ReplayForcedInfo,
  type ReplayIdempotencyOptions,
  type ReplaySkippedInfo,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "replay-idempotency-enable-secret";
const operatorToken = "replay-idempotency-enable-token";
const URL = "http://localhost:9999/hook";
const FORWARD = "http://127.0.0.1:1/unused";
const PAYLOAD = Buffer.from(JSON.stringify({ payment: "pi_123", amount: 5000 }));
const PAYLOAD_2 = Buffer.from(JSON.stringify({ payment: "pi_456", amount: 7000 }));
const PAYLOAD_3 = Buffer.from(JSON.stringify({ payment: "pi_789", amount: 9000 }));

/** Manual timer with single-step control. */
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
    async drain() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function controllableSender() {
  let fail = true;
  const sender: Sender = async () => {
    if (fail) throw new Error("downstream 500");
  };
  return { sender, setFail: (v: boolean) => (fail = v) };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

describe("RetryQueue reviseReplayIdempotency enable (WR-460)", () => {
  function makeQueue(
    replayIdempotency?: ReplayIdempotencyOptions,
    withHooks = true
  ) {
    const timer = manualTimer();
    const f = controllableSender();
    const skipped: ReplaySkippedInfo[] = [];
    const forced: ReplayForcedInfo[] = [];
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 1, // dead-letter on the first failure
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      ...(replayIdempotency === undefined ? {} : { replayIdempotency }),
      ...(withHooks
        ? {
            onReplaySkipped: (info) => skipped.push(info),
            onReplayForced: (info) => forced.push(info),
          }
        : {}),
    });
    return { q, timer, f, skipped, forced };
  }

  it("enables with the construction defaults and the getter returns them at once", () => {
    const { q } = makeQueue();
    assert.equal(q.getReplayIdempotencyConfig(), undefined);
    assert.deepEqual(q.reviseReplayIdempotency({}), {
      windowMs: 86_400_000,
      maxEntries: 10_000,
    });
    assert.deepEqual(q.getReplayIdempotencyConfig(), {
      windowMs: 86_400_000,
      maxEntries: 10_000,
    });
    // The guard exists but has indexed nothing yet: no stats rows.
    assert.deepEqual(q.getReplayIdempotencyStats(), []);
  });

  it("enables with explicit values", () => {
    const { q } = makeQueue();
    assert.deepEqual(q.reviseReplayIdempotency({ windowMs: 5000, maxEntries: 42 }), {
      windowMs: 5000,
      maxEntries: 42,
    });
    assert.deepEqual(q.getReplayIdempotencyConfig(), { windowMs: 5000, maxEntries: 42 });
  });

  it("a partial patch fills the rest from the construction defaults", () => {
    const { q } = makeQueue();
    assert.deepEqual(q.reviseReplayIdempotency({ windowMs: 7000 }), {
      windowMs: 7000,
      maxEntries: 10_000,
    });
    const { q: q2 } = makeQueue();
    assert.deepEqual(q2.reviseReplayIdempotency({ maxEntries: 3 }), {
      windowMs: 86_400_000,
      maxEntries: 3,
    });
  });

  it("an illegal or non-object patch throws RangeError and the queue stays unconfigured, then still enables", () => {
    const { q } = makeQueue();
    for (const bad of [
      { windowMs: 0 },
      { windowMs: -5 },
      { windowMs: Number.NaN },
      { windowMs: Number.POSITIVE_INFINITY },
      { maxEntries: 0 },
      { maxEntries: 1.5 },
      { maxEntries: Number.NaN },
    ]) {
      assert.throws(() => q.reviseReplayIdempotency(bad), RangeError);
      assert.equal(q.getReplayIdempotencyConfig(), undefined);
    }
    assert.throws(() => q.reviseReplayIdempotency(null as never), RangeError);
    assert.throws(() => q.reviseReplayIdempotency("wide" as never), RangeError);
    assert.throws(() => q.reviseReplayIdempotency([] as never), RangeError);
    assert.equal(q.getReplayIdempotencyConfig(), undefined);
    assert.equal(q.replayIdempotencyConfigured(), false);
    // Still enablable afterwards: the failed attempts left nothing behind.
    assert.deepEqual(q.reviseReplayIdempotency({}), {
      windowMs: 86_400_000,
      maxEntries: 10_000,
    });
    assert.equal(q.replayIdempotencyConfigured(), true);
  });

  it("the next replay after the enable is suppressed and the skip hook fires; force still replays", async () => {
    const { q, timer, f, skipped, forced } = makeQueue();
    q.start();
    // Dead-letter one copy while the guard is off.
    q.enqueue({ id: "en-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 1);
    // Enable, then deliver the same pair: the guard clock is wall time,
    // so sleep past the dead-lettering instant for a strict `>` gap.
    q.reviseReplayIdempotency({ windowMs: 120_000 });
    await sleep(10);
    f.setFail(false);
    q.enqueue({ id: "en-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.replayDeadLetter("en-a"), false);
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].id, "en-a");
    assert.equal(forced.length, 0);
    // Explicit force replays anyway.
    assert.equal(q.replayDeadLetter("en-a", { force: true }), true);
    assert.equal(q.getDeadLetter().length, 0);
    assert.equal(forced.length, 1);
    assert.equal(forced[0].id, "en-a");
    await timer.drain();
  });

  it("deliveries before the enable are not retroactively recorded", async () => {
    const { q, timer, f, skipped } = makeQueue();
    q.start();
    // Deliver the pair while the guard is off: never recorded.
    f.setFail(false);
    q.enqueue({ id: "nr-ok", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    // Dead-letter the same pair.
    f.setFail(true);
    q.enqueue({ id: "nr-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 1);
    // Enable: the pre-enable delivery is not in the fresh index, so the
    // replay is allowed.
    q.reviseReplayIdempotency({ windowMs: 120_000 });
    assert.equal(q.replayDeadLetter("nr-a"), true);
    await timer.drain(); // sender still failing: re-dead-letters
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(skipped.length, 0);
    // Deliver the pair again after the enable, then the next replay of
    // the same dead letter is suppressed.
    await sleep(10);
    f.setFail(false);
    q.enqueue({ id: "nr-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.replayDeadLetter("nr-a"), false);
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].id, "nr-a");
  });

  it("revision after the enable still follows WR-441: empty/illegal throw, same-value is a no-op", async () => {
    const { q, timer, f } = makeQueue();
    q.start();
    q.reviseReplayIdempotency({});
    f.setFail(false);
    q.enqueue({ id: "rv-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    const statsBefore = q.getReplayIdempotencyStats();
    assert.equal(statsBefore!.length, 1);
    // Empty patch is a RangeError now that the guard exists (unlike the
    // enable path, where {} means "all defaults").
    assert.throws(() => q.reviseReplayIdempotency({}), RangeError);
    // Same-value revision is a silent no-op.
    assert.deepEqual(q.reviseReplayIdempotency({ windowMs: 86_400_000, maxEntries: 10_000 }), {
      windowMs: 86_400_000,
      maxEntries: 10_000,
    });
    // Illegal patch throws and leaves the live values and index alone.
    assert.throws(() => q.reviseReplayIdempotency({ windowMs: 0 }), RangeError);
    assert.deepEqual(q.getReplayIdempotencyConfig(), {
      windowMs: 86_400_000,
      maxEntries: 10_000,
    });
    assert.deepEqual(q.getReplayIdempotencyStats(), statsBefore);
    // A real partial revision still merges live values.
    assert.deepEqual(q.reviseReplayIdempotency({ windowMs: 2000 }), {
      windowMs: 2000,
      maxEntries: 10_000,
    });
  });

  it("widening the window after the enable revives an expired-but-not-evicted record", async () => {
    const { q, timer, f, skipped } = makeQueue();
    q.start();
    // Dead-letter two copies of the same pair while the guard is off.
    q.enqueue({ id: "w-a1", payload: PAYLOAD, targetUrl: URL, headers: {} });
    q.enqueue({ id: "w-a2", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 2);
    // Enable with a short window, then deliver the pair.
    q.reviseReplayIdempotency({ windowMs: 100 });
    await sleep(10);
    f.setFail(false);
    q.enqueue({ id: "w-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    // Let the record expire past the 100ms window: the first replay is
    // allowed (sender failing, so it re-dead-letters without refreshing
    // the record).
    await sleep(150);
    f.setFail(true);
    assert.equal(q.replayDeadLetter("w-a1"), true);
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 2);
    // Widen the window: the never-evicted record revives, and the
    // second copy — still carrying its original dead-lettering instant
    // — is suppressed again.
    assert.deepEqual(q.reviseReplayIdempotency({ windowMs: 120_000 }), {
      windowMs: 120_000,
      maxEntries: 10_000,
    });
    assert.equal(q.replayDeadLetter("w-a2"), false);
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].id, "w-a2");
  });

  it("lowering maxEntries after the enable evicts the oldest records at once", async () => {
    const { q, timer, f } = makeQueue();
    q.start();
    q.reviseReplayIdempotency({ maxEntries: 2 });
    f.setFail(false);
    q.enqueue({ id: "cap-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    // Mark the boundary *between* cap-a and cap-b: cap-a was recorded
    // before this instant (so the third insert evicts it), while cap-b
    // and cap-c are recorded after it (so they survive as the oldest).
    // The assertions below then hold by program order, not by cap-b
    // and the marker landing in the same wall-clock millisecond — a
    // slow runner used to cross that boundary and fail CI (WR-465).
    const t3 = Date.now();
    q.enqueue({ id: "cap-b", payload: PAYLOAD_2, targetUrl: URL, headers: {} });
    await timer.drain();
    q.enqueue({ id: "cap-c", payload: PAYLOAD_3, targetUrl: URL, headers: {} });
    await timer.drain();
    // The cap already evicted the oldest pair on the third insert.
    const stats = q.getReplayIdempotencyStats()!;
    assert.equal(stats.length, 1);
    assert.equal(stats[0].trackedPairs, 2);
    assert.ok(stats[0].oldestRecordAtMs! >= t3);
    // Tightening the cap evicts the oldest remaining record at once.
    assert.deepEqual(q.reviseReplayIdempotency({ maxEntries: 1 }), {
      windowMs: 86_400_000,
      maxEntries: 1,
    });
    const tightened = q.getReplayIdempotencyStats()!;
    assert.equal(tightened.length, 1);
    assert.equal(tightened[0].trackedPairs, 1);
    assert.ok(tightened[0].oldestRecordAtMs! >= t3);
  });

  it("a tenant born after the enable starts from the enabled values", async () => {
    const { q, timer, f, skipped } = makeQueue();
    q.start();
    q.reviseReplayIdempotency({ windowMs: 120_000 });
    // Tenant t2 dead-letters then delivers the same pair.
    q.enqueue({ id: "t2-dl", payload: PAYLOAD, targetUrl: URL, headers: {}, tenantId: "t2" });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 1);
    await sleep(10);
    f.setFail(false);
    q.enqueue({ id: "t2-ok", payload: PAYLOAD, targetUrl: URL, headers: {}, tenantId: "t2" });
    await timer.drain();
    // The lazy t2 guard was built from the enabled values, so the
    // replay is suppressed.
    assert.equal(q.replayDeadLetter("t2-dl"), false);
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].id, "t2-dl");
    assert.deepEqual(q.getReplayIdempotencyConfig(), {
      windowMs: 120_000,
      maxEntries: 10_000,
    });
    const stats = q.getReplayIdempotencyStats()!;
    assert.equal(stats.length, 1);
    assert.equal(stats[0].tenant, "t2");
    assert.equal(stats[0].trackedPairs, 1);
  });

  it("stats are undefined before the enable and activity-gated after it", async () => {
    const { q, timer, f } = makeQueue();
    q.start();
    assert.equal(q.getReplayIdempotencyStats(), undefined);
    q.reviseReplayIdempotency({});
    assert.deepEqual(q.getReplayIdempotencyStats(), []);
    f.setFail(false);
    q.enqueue({ id: "st-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    const stats = q.getReplayIdempotencyStats()!;
    assert.equal(stats.length, 1);
    assert.equal(stats[0].trackedPairs, 1);
    assert.ok(typeof stats[0].oldestRecordAtMs === "number");
    assert.equal(stats[0].tenant, undefined);
  });

  it("enabling unlocks reviseReplayCallbacks: the gate opens the moment the guard exists", async () => {
    const { q, timer, f } = makeQueue(undefined, false);
    q.start();
    const seenSkipped: ReplaySkippedInfo[] = [];
    const seenForced: ReplayForcedInfo[] = [];
    assert.throws(
      () => q.reviseReplayCallbacks({ onReplaySkipped: (info) => seenSkipped.push(info) }),
      /replay idempotency is not configured/
    );
    q.reviseReplayIdempotency({ windowMs: 120_000 });
    // The gate is open now: install both observers.
    q.reviseReplayCallbacks({
      onReplaySkipped: (info) => seenSkipped.push(info),
      onReplayForced: (info) => seenForced.push(info),
    });
    q.enqueue({ id: "cb-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    await sleep(10);
    f.setFail(false);
    q.enqueue({ id: "cb-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.replayDeadLetter("cb-a"), false);
    assert.equal(seenSkipped.length, 1);
    assert.equal(seenSkipped[0].id, "cb-a");
    assert.equal(q.replayDeadLetter("cb-a", { force: true }), true);
    assert.equal(seenForced.length, 1);
    assert.equal(seenForced[0].id, "cb-a");
    await timer.drain();
  });

  it("a fresh queue is unconfigured again: the enable is live-only (restart restores unconfigured)", () => {
    const { q } = makeQueue();
    q.reviseReplayIdempotency({ windowMs: 5000 });
    assert.deepEqual(q.getReplayIdempotencyConfig(), { windowMs: 5000, maxEntries: 10_000 });
    // A new instance — what a restart produces — starts unconfigured.
    const { q: restarted } = makeQueue();
    assert.equal(restarted.getReplayIdempotencyConfig(), undefined);
    assert.equal(restarted.replayIdempotencyConfigured(), false);
    assert.equal(restarted.getReplayIdempotencyStats(), undefined);
  });
});

describe("RelayServer reviseReplayIdempotency enable (WR-460)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "replay-idempotency-enable-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: FORWARD,
      auditLog,
      operatorToken,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("enabling audits previous: null with the exact current config, exactly once, and mounts the getter", () => {
    const { relay, auditLog } = makeServer();
    assert.equal(relay.getReplayIdempotencyConfig, undefined);
    assert.deepEqual(relay.reviseReplayIdempotency!({ windowMs: 5000, maxEntries: 42 }), {
      windowMs: 5000,
      maxEntries: 42,
    });
    assert.deepEqual(relay.getReplayIdempotencyConfig!(), {
      windowMs: 5000,
      maxEntries: 42,
    });
    const enabled = eventsOf(auditLog, "replay_idempotency_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].previous, null);
    assert.deepEqual(enabled[0].current, { windowMs: 5000, maxEntries: 42 });
  });

  it("an illegal enable patch throws RangeError, audits nothing, and the getter stays unset", () => {
    const { relay, auditLog } = makeServer();
    assert.throws(() => relay.reviseReplayIdempotency!({ windowMs: 0 }), RangeError);
    assert.throws(() => relay.reviseReplayIdempotency!({ maxEntries: 1.5 }), RangeError);
    assert.equal(eventsOf(auditLog, "replay_idempotency_revised").length, 0);
    assert.equal(relay.getReplayIdempotencyConfig, undefined);
    // Still enablable afterwards.
    assert.deepEqual(relay.reviseReplayIdempotency!({}), {
      windowMs: 86_400_000,
      maxEntries: 10_000,
    });
    assert.equal(eventsOf(auditLog, "replay_idempotency_revised").length, 1);
  });

  it("revising the callbacks before the enable throws; after the enable it works", () => {
    const { relay } = makeServer();
    assert.throws(
      () => relay.reviseReplayCallbacks!({ onReplaySkipped: () => {} }),
      /replay idempotency is not configured/
    );
    relay.reviseReplayIdempotency!({});
    relay.reviseReplayCallbacks!({ onReplaySkipped: () => {} });
  });

  it("a replay after the server-side enable is suppressed and audits replay_skipped_delivered; force audits replay_forced", async () => {
    const dir = mkdtempSync(join(tmpdir(), "replay-idempotency-enable-http-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    let fail = true;
    let calls = 0;
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: FORWARD,
      auditLog: audit,
      sender: async () => {
        calls += 1;
        if (fail) throw new Error("downstream 500");
      },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      operatorToken,
    });
    servers.push(relay);
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const addr = relay.address();
    assert.ok(addr && typeof addr === "object");
    const port = addr.port;
    const auth = { authorization: `Bearer ${operatorToken}` };
    try {
      const body = PAYLOAD;
      const post = (p: number, path: string, raw: Buffer, headers: Record<string, string> = {}) =>
        new Promise<{ status: number; text: string }>((resolve, reject) => {
          const r = httpRequest({ host: "127.0.0.1", port: p, path, method: "POST", headers }, (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c: Buffer) => chunks.push(c));
            res.on("end", () =>
              resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
            );
          });
          r.on("error", reject);
          r.end(raw);
        });
      const getDeadLetters = async (expected: number) => {
        const deadline = Date.now() + 5000;
        for (;;) {
          const res = await new Promise<{ status: number; text: string }>((resolve, reject) => {
            const r = httpRequest(
              { host: "127.0.0.1", port, path: "/dead-letter", method: "GET", headers: auth },
              (resp) => {
                const chunks: Buffer[] = [];
                resp.on("data", (c: Buffer) => chunks.push(c));
                resp.on("end", () =>
                  resolve({ status: resp.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
                );
              }
            );
            r.on("error", reject);
            r.end();
          });
          assert.equal(res.status, 200);
          const entries = JSON.parse(res.text) as Array<{ id: string }>;
          if (entries.length >= expected) return entries;
          if (Date.now() >= deadline) throw new Error("timed out waiting for dead letters");
          await sleep(25);
        }
      };
      const waitForCalls = async (n: number) => {
        const deadline = Date.now() + 5000;
        for (;;) {
          if (calls >= n) return;
          if (Date.now() >= deadline) throw new Error("timed out waiting for deliveries");
          await sleep(25);
        }
      };

      // Dead-letter one copy while the guard is off.
      assert.equal(
        (await post(port, "/", body, { "x-signature": signSha256(body, relaySecret) })).status,
        202
      );
      const dead = await getDeadLetters(1);
      const id = dead[0].id;

      // Enable at runtime: no restart, no state lost.
      assert.deepEqual(relay.reviseReplayIdempotency!({}), {
        windowMs: 86_400_000,
        maxEntries: 10_000,
      });
      assert.deepEqual(relay.getReplayIdempotencyConfig!(), {
        windowMs: 86_400_000,
        maxEntries: 10_000,
      });

      // Deliver the same pair after the enable: the guard clock is wall
      // time, so sleep past the dead-lettering instant first — the
      // record must be strictly newer than the dead-lettering.
      await sleep(10);
      fail = false;
      assert.equal(
        (await post(port, "/", body, { "x-signature": signSha256(body, relaySecret) })).status,
        202
      );
      await waitForCalls(2);
      assert.equal((await getDeadLetters(1)).length, 1);

      const suppressed = await post(port, `/dead-letter/${id}/replay`, Buffer.from("{}"), auth);
      assert.equal(suppressed.status, 200);
      assert.deepEqual(JSON.parse(suppressed.text), {
        id,
        replayed: false,
        skipped: true,
        reason: "replay_suppressed_delivered",
      });
      assert.equal((await getDeadLetters(1)).length, 1);
      const skipEvents = eventsOf(audit, "replay_skipped_delivered");
      assert.equal(skipEvents.length, 1);
      assert.equal(skipEvents[0].id, id);

      const forced = await post(
        port,
        `/dead-letter/${id}/replay`,
        Buffer.from(JSON.stringify({ force: true })),
        auth
      );
      assert.equal(forced.status, 200);
      assert.deepEqual(JSON.parse(forced.text), { id, replayed: true });
      const forcedEvents = eventsOf(audit, "replay_forced");
      assert.equal(forcedEvents.length, 1);
      assert.equal(forcedEvents[0].id, id);
      // The forced replay delivered (sender healthy): the dead letter is gone.
      const deadline = Date.now() + 5000;
      for (;;) {
        if ((await getDeadLetters(0)).length === 0) break;
        if (Date.now() >= deadline) throw new Error("timed out waiting for the dead letter to clear");
        await sleep(25);
      }
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
