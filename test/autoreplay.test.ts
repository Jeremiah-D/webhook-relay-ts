import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type RetryItem } from "../src/retry.ts";
import { DeadLetterAutoReplayer, type AutoReplayOptions, type DeadLetterAutoReplayAuditEvent } from "../src/autoreplay.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "auto-replay" }));
const EP = "http://a.example/hook";

/**
 * Deterministic timer: callbacks fire only via `run()`; the scheduled
 * delays are observable via `waits()`.
 */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pending,
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    clearTimer: (h: { clear(): void }) => h.clear(),
    waits(): number[] {
      return pending.map((p) => p.ms);
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f.fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

interface Setup {
  q: RetryQueue;
  /** Queue's own delivery timer. */
  timer: ReturnType<typeof manualTimer>;
  /** The replayer's private timer (rounds never fire unless driven). */
  replayTimer: ReturnType<typeof manualTimer>;
  replayer: DeadLetterAutoReplayer;
  audits: DeadLetterAutoReplayAuditEvent[];
  sender: { fail: boolean };
}

/**
 * Queue with a toggleable sender and an enabled auto-replay scheduler.
 * The replayer gets its own manual timer so scheduled rounds never fire
 * as a side effect of draining the queue's delivery timer.
 */
function setupAutoReplay(
  extraQueueOpts: Record<string, unknown> = {},
  autoReplay: Record<string, unknown> = {}
): Setup {
  const timer = manualTimer();
  const replayTimer = manualTimer();
  const state = { fail: true };
  const audits: DeadLetterAutoReplayAuditEvent[] = [];
  const q = new RetryQueue({
    sender: async () => {
      if (state.fail) throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 2,
    jitterMs: 0,
    setTimer: timer.setTimer,
    clearTimer: timer.clearTimer,
    onAutoReplayAudit: (event) => audits.push(event),
    autoReplay: {
      enabled: true,
      intervalMs: 1000,
      maxRounds: 3,
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
      ...autoReplay,
    },
    ...extraQueueOpts,
  });
  const replayer = q.getAutoReplayer();
  assert.ok(replayer, "auto-replay scheduler must exist when configured");
  return { q, timer, replayTimer, replayer, audits, sender: state };
}

async function seedDeadLetter(s: Setup, id: string) {
  s.q.start();
  s.q.enqueue({ id, payload: Buffer.from(`payload-${id}`), targetUrl: EP, headers: {} });
  await s.timer.run();
  const dl = s.q.getDeadLetter();
  assert.equal(dl.length, 1, "item should be dead-lettered");
  assert.equal(dl[0].attempts, 2, "entry consumed its full attempt budget");
}

describe("dead-letter auto-replay", () => {
  it("triggerOnce replays dead letters and removes successes", async () => {
    const delivered: Array<{ id: string; attempts: number }> = [];
    const s = setupAutoReplay({
      onDelivered: (item: RetryItem, attempts: number) => delivered.push({ id: item.id, attempts }),
    });
    await seedDeadLetter(s, "dl-1");

    const round = s.replayer.triggerOnce();
    assert.deepEqual(round.replayed, ["dl-1"]);
    assert.deepEqual(round.failed, []);
    assert.equal(round.consecutiveEmptyRounds, 0);
    assert.equal(round.stopped, false);
    assert.equal(s.q.getDeadLetter().length, 0, "replayed item leaves the dead letter");
    assert.equal(s.q.pendingCount(), 1, "replayed item is back in the queue");

    // Fresh-budget semantics: the entry had burned 2 attempts, but the
    // replay delivers on attempt 1.
    s.sender.fail = false;
    await s.timer.run();
    assert.deepEqual(delivered, [{ id: "dl-1", attempts: 1 }]);
    assert.equal(s.q.getDeadLetter().length, 0);
    assert.equal(s.replayer.status().totalReplayed, 1);
    await s.q.shutdown(1000);
  });

  it("counts consecutive empty rounds, backs off exponentially, and stops at maxRounds with an audit", () => {
    const replayTimer = manualTimer();
    const nowMs = 1_000_000;
    const audits: DeadLetterAutoReplayAuditEvent[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      onAutoReplayAudit: (e) => audits.push(e),
      autoReplay: {
        enabled: true,
        intervalMs: 1000,
        maxRounds: 3,
        maxIntervalMs: 3000,
        now: () => nowMs,
        setTimer: replayTimer.setTimer,
        clearTimer: replayTimer.clearTimer,
      },
    });
    const replayer = q.getAutoReplayer()!;
    q.start();

    assert.deepEqual(replayTimer.waits(), [1000], "first round at the base interval");

    const r1 = replayer.triggerOnce();
    assert.equal(r1.consecutiveEmptyRounds, 1);
    assert.equal(r1.stopped, false);
    assert.deepEqual(replayTimer.waits(), [2000], "backoff: intervalMs * 2^1");

    const r2 = replayer.triggerOnce();
    assert.equal(r2.consecutiveEmptyRounds, 2);
    assert.deepEqual(replayTimer.waits(), [3000], "capped: 1000 * 2^2 = 4000 > maxIntervalMs 3000");

    const r3 = replayer.triggerOnce();
    assert.equal(r3.consecutiveEmptyRounds, 3);
    assert.equal(r3.stopped, true);
    assert.deepEqual(replayTimer.waits(), [], "no round scheduled after the stop");

    assert.equal(audits.length, 1);
    assert.deepEqual(audits[0], {
      event: "dead_letter_auto_replay",
      reason: "rounds_exhausted",
      consecutiveEmptyRounds: 3,
      totalReplayed: 0,
      lastRunAt: new Date(nowMs).toISOString(),
    });

    // A stopped scheduler ignores further triggers — the audit fires once.
    const r4 = replayer.triggerOnce();
    assert.deepEqual(r4.replayed, []);
    assert.equal(r4.stopped, true);
    assert.equal(audits.length, 1);

    // Resume is the operator's explicit "try again": counter resets,
    // schedule restarts at the base interval.
    const { restarted } = replayer.resume();
    assert.equal(restarted, true);
    assert.equal(replayer.status().consecutiveEmptyRounds, 0);
    assert.equal(replayer.status().stopped, false);
    assert.deepEqual(replayTimer.waits(), [1000]);
  });

  it("a successful round resets the consecutive-empty counter", async () => {
    const s = setupAutoReplay();
    s.q.start();

    assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 1);
    assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 2);

    await seedDeadLetter(s, "dl-reset");
    s.sender.fail = false;
    const round = s.replayer.triggerOnce();
    assert.deepEqual(round.replayed, ["dl-reset"]);
    assert.equal(round.consecutiveEmptyRounds, 0, "success resets the counter");
    assert.equal(round.stopped, false);

    // Two more empty rounds do not stop the scheduler: maxRounds is 3.
    assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 1);
    assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 2);
    assert.equal(s.replayer.status().stopped, false);
    assert.equal(s.audits.length, 0);
    await s.q.shutdown(1000);
  });

  it("entries that fail to re-queue do not count as successes", () => {
    const replayTimer = manualTimer();
    const replayer = new DeadLetterAutoReplayer({
      enabled: true,
      intervalMs: 1000,
      maxRounds: 2,
      // e.g. a sealed payload with no decryptor: nothing re-queues, the
      // entry stays dead-lettered and the round counts as empty.
      replayAll: () => ({ replayed: [], failed: [{ id: "x", error: "no decryptor" }] }),
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
    });
    replayer.start();
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 1, "failed re-queues are not successes");
    assert.equal(replayer.triggerOnce().stopped, true, "two failed rounds exhaust maxRounds");
  });

  it("RangeError on invalid auto-replay values", () => {
    const replayAll = () => ({ replayed: [] as string[], failed: [] as never[] });
    assert.throws(() => new RetryQueue({ autoReplay: { enabled: true, intervalMs: 0 } }), RangeError);
    assert.throws(() => new RetryQueue({ autoReplay: { enabled: true, maxRounds: 0 } }), RangeError);
    assert.throws(() => new RetryQueue({ autoReplay: { enabled: true, maxRounds: 1.5 } }), RangeError);
    assert.throws(
      () => new RetryQueue({ autoReplay: { enabled: true, intervalMs: 5000, maxIntervalMs: 1000 } }),
      RangeError
    );
    assert.throws(() => new DeadLetterAutoReplayer({ replayAll, intervalMs: -1 }), RangeError);
    assert.throws(() => new DeadLetterAutoReplayer({ replayAll, maxRounds: 0 }), RangeError);
    // Default: no scheduler at all. Configured-but-disabled: exists, never ticks.
    assert.equal(new RetryQueue().getAutoReplayer(), undefined);
    const q = new RetryQueue({ autoReplay: { enabled: false } });
    assert.equal(q.getAutoReplayer()?.isEnabled(), false);
    assert.equal(q.getAutoReplayer()?.isRunning(), false);
  });

  it("shutdown stops the auto-replay timer", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      autoReplay: {
        enabled: true,
        intervalMs: 5000,
        maxRounds: 10,
        setTimer: timer.setTimer,
        clearTimer: timer.clearTimer,
      },
    });
    q.start();
    assert.ok(timer.pending.length >= 1, "a round is scheduled");
    await q.shutdown(1000);
    assert.equal(timer.pending.length, 0, "shutdown clears the pending round timer");
  });

  it("pause freezes the schedule with state retained; resume continues", () => {
    const s = setupAutoReplay();
    s.q.start();
    assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 1);

    s.replayer.pause();
    assert.equal(s.replayer.status().paused, true);
    assert.equal(s.replayer.isRunning(), false);
    assert.deepEqual(s.replayTimer.waits(), [], "no round scheduled while paused");

    const { restarted } = s.replayer.resume();
    assert.equal(restarted, false);
    assert.equal(s.replayer.status().paused, false);
    assert.equal(s.replayer.status().consecutiveEmptyRounds, 1, "counter retained across pause");
    assert.deepEqual(s.replayTimer.waits(), [2000], "schedule resumes from the retained counter");
  });

  it("nextRunAt is observable in the status", () => {
    const replayTimer = manualTimer();
    const nowMs = 2_000_000;
    const q = new RetryQueue({
      sender: async () => {},
      autoReplay: {
        enabled: true,
        intervalMs: 60_000,
        maxRounds: 5,
        now: () => nowMs,
        setTimer: replayTimer.setTimer,
        clearTimer: replayTimer.clearTimer,
      },
    });
    const replayer = q.getAutoReplayer()!;
    assert.equal(replayer.status().nextRunAt, null, "nothing scheduled before start");
    q.start();
    assert.equal(replayer.status().nextRunAt, new Date(nowMs + 60_000).toISOString());
  });
});

describe("auto-replay operator endpoints", () => {
  const TOKEN = "operator-token";
  let servers: Server[] = [];

  after(async () => {
    for (const s of servers) {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
    servers = [];
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function request(
    port: number,
    path: string,
    method: string,
    token?: string
  ): Promise<{ status: number; body: any }> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {};
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString()) })
        );
      });
      r.on("error", reject);
      r.end();
    });
  }

  function makeServer(autoReplay?: AutoReplayOptions, operatorToken: string | null = TOKEN) {
    const dir = mkdtempSync(join(tmpdir(), "autoreplay-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const server = createRelayServer({
      secret: SECRET,
      forwardUrl: EP,
      auditLog,
      operatorToken: operatorToken ?? undefined,
      sender: async () => {},
      autoReplay,
    });
    return { server, auditLog };
  }

  it("status / pause / resume / trigger with the operator Bearer <redacted>", async () => {
    const { server } = makeServer({ enabled: true, intervalMs: 60_000, maxRounds: 3 });
    servers.push(server);
    const port = await listen(server);
    const auth = (p: string, m: string) => request(port, p, m, TOKEN);

    const status = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.equal(status.enabled, true);
    assert.equal(status.paused, false);
    assert.equal(status.stopped, false);
    assert.equal(status.consecutiveEmptyRounds, 0);
    assert.equal(status.totalReplayed, 0);
    assert.equal(status.lastRunAt, null);
    assert.ok(typeof status.nextRunAt === "string", "a round is scheduled");

    const pause = await auth("/dead-letter/auto-replay/pause", "POST");
    assert.equal(pause.status, 200);
    assert.deepEqual(pause.body, { paused: true });
    const pausedStatus = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.equal(pausedStatus.paused, true);
    assert.equal(pausedStatus.nextRunAt, null);

    // A trigger still runs one round outside the paused schedule.
    const trigger = await auth("/dead-letter/auto-replay/trigger", "POST");
    assert.equal(trigger.status, 200);
    assert.deepEqual(trigger.body.replayed, []);
    assert.equal(trigger.body.consecutiveEmptyRounds, 1, "empty trigger counts like a scheduled round");
    assert.equal(trigger.body.stopped, false);
    const stillPaused = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.equal(stillPaused.paused, true, "trigger does not unpause");

    const resume = await auth("/dead-letter/auto-replay/resume", "POST");
    assert.equal(resume.status, 200);
    assert.deepEqual(resume.body, { paused: false, restarted: false });
    const resumed = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.equal(resumed.paused, false);
    assert.equal(resumed.consecutiveEmptyRounds, 1, "counter retained across pause");

    // Exhaust the rounds through the endpoint, then resume restarts it.
    await auth("/dead-letter/auto-replay/trigger", "POST");
    const last = await auth("/dead-letter/auto-replay/trigger", "POST");
    assert.equal(last.body.stopped, true);
    const exhausted = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.equal(exhausted.stopped, true);
    const restart = await auth("/dead-letter/auto-replay/resume", "POST");
    assert.deepEqual(restart.body, { paused: false, restarted: true });
    const restarted = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.equal(restarted.stopped, false);
    assert.equal(restarted.consecutiveEmptyRounds, 0);
  });

  it("status reports enabled:false when unconfigured; controls 404", async () => {
    const { server } = makeServer(undefined);
    servers.push(server);
    const port = await listen(server);

    const status = await request(port, "/dead-letter/auto-replay/status", "GET", TOKEN);
    assert.equal(status.status, 200);
    assert.deepEqual(status.body, {
      enabled: false,
      paused: false,
      stopped: false,
      consecutiveEmptyRounds: 0,
      totalReplayed: 0,
      lastRunAt: null,
      nextRunAt: null,
    });
    for (const path of [
      "/dead-letter/auto-replay/pause",
      "/dead-letter/auto-replay/resume",
      "/dead-letter/auto-replay/trigger",
    ]) {
      const r = await request(port, path, "POST", TOKEN);
      assert.equal(r.status, 404);
      assert.equal(r.body.error, "dead-letter auto-replay is not configured");
    }
  });

  it("fail-closed without operatorToken: 404 on all four endpoints", async () => {
    const { server } = makeServer({ enabled: true, intervalMs: 60_000, maxRounds: 3 }, null);
    servers.push(server);
    const port = await listen(server);
    const status = await request(port, "/dead-letter/auto-replay/status", "GET");
    assert.equal(status.status, 404);
    for (const path of [
      "/dead-letter/auto-replay/pause",
      "/dead-letter/auto-replay/resume",
      "/dead-letter/auto-replay/trigger",
    ]) {
      assert.equal((await request(port, path, "POST")).status, 404);
    }
  });

  it("wrong Bearer <redacted> answers 403", async () => {
    const { server } = makeServer({ enabled: true, intervalMs: 60_000, maxRounds: 3 });
    servers.push(server);
    const port = await listen(server);
    const r = await request(port, "/dead-letter/auto-replay/status", "GET", "wrong-token");
    assert.equal(r.status, 403);
  });

  it("method mismatch answers 405", async () => {
    const { server } = makeServer({ enabled: true, intervalMs: 60_000, maxRounds: 3 });
    servers.push(server);
    const port = await listen(server);
    assert.equal((await request(port, "/dead-letter/auto-replay/pause", "GET", TOKEN)).status, 405);
  });

  it("trigger replays a real dead letter through the server and audits exhaustion", async () => {
    const dir = mkdtempSync(join(tmpdir(), "autoreplay-e2e-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    let fail = true;
    const server = createRelayServer({
      secret: SECRET,
      forwardUrl: EP,
      auditLog,
      operatorToken: TOKEN,
      sender: async () => {
        if (fail) throw new Error("downstream 500");
      },
      retry: { baseDelayMs: 1, maxAttempts: 1, jitterMs: 0 },
      autoReplay: { enabled: true, intervalMs: 60_000, maxRounds: 2 },
    });
    servers.push(server);
    const port = await listen(server);
    const auth = (p: string, m: string) => request(port, p, m, TOKEN);

    // Produce a dead letter through the real inbound path.
    const accepted = await new Promise<{ status: number }>((resolve, reject) => {
      const headers: Record<string, string> = {
        "content-type": "application/json",
        "x-signature": signSha256(BODY, SECRET),
      };
      const r = httpRequest({ host: "127.0.0.1", port, path: "/", method: "POST", headers }, (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
      });
      r.on("error", reject);
      r.end(BODY);
    });
    assert.equal(accepted.status, 202);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal((await auth("/dead-letter", "GET")).body.length, 1, "one dead letter");

    // Operator trigger replays it; the replayed delivery succeeds now.
    fail = false;
    const trigger = await auth("/dead-letter/auto-replay/trigger", "POST");
    assert.equal(trigger.status, 200);
    assert.equal(trigger.body.replayed.length, 1);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal((await auth("/dead-letter", "GET")).body.length, 0, "replayed success leaves the dead letter");
    const status = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.equal(status.totalReplayed, 1);
    assert.equal(status.consecutiveEmptyRounds, 0);

    // Exhaustion audits `dead_letter_auto_replay` to the audit log.
    await auth("/dead-letter/auto-replay/trigger", "POST");
    const last = await auth("/dead-letter/auto-replay/trigger", "POST");
    assert.equal(last.body.stopped, true);
    const events = auditLog.query({ event: "dead_letter_auto_replay" });
    assert.equal(events.length, 1);
    const evt = events[0] as Record<string, unknown>;
    assert.equal(evt["reason"], "rounds_exhausted");
    assert.equal(evt["consecutiveEmptyRounds"], 2);
    assert.equal(evt["totalReplayed"], 1);
  });
});
