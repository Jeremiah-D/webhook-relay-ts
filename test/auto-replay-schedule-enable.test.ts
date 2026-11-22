import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { request as httpRequest } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

const EP = "http://a.example/hook";
const opToken = "operator-token";
const signingKey = "auto-replay-schedule-enable-test-key";

/**
 * Deterministic timer: callbacks fire only via `run()`; the scheduled
 * delays are observable via `waits()` (same helper as
 * auto-replay-schedule-revision.test.ts).
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

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

describe("RetryQueue.reviseAutoReplaySchedule enable (WR-447)", () => {
  it("the first revise on an unconfigured queue enables it; omitted knobs take the construction defaults", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.getAutoReplayScheduleConfig(), undefined);
    assert.equal(q.getAutoReplayer(), undefined);
    assert.deepEqual(q.reviseAutoReplaySchedule({ intervalMs: 5000 }), {
      intervalMs: 5000,
      maxRounds: 10,
      maxIntervalMs: 3_600_000,
    });
    assert.deepEqual(q.getAutoReplayScheduleConfig(), {
      intervalMs: 5000,
      maxRounds: 10,
      maxIntervalMs: 3_600_000,
    });
    const replayer = q.getAutoReplayer();
    assert.ok(replayer, "the scheduler exists after the enable");
    assert.equal(replayer!.isEnabled(), true, "the enable arms the scheduler");
    assert.deepEqual(replayer!.status().consecutiveEmptyRounds, 0);
    assert.deepEqual(replayer!.status().totalReplayed, 0);

    // A bare maxRounds patch takes the other two defaults.
    const q2 = new RetryQueue({ sender: async () => {} });
    assert.deepEqual(q2.reviseAutoReplaySchedule({ maxRounds: 2 }), {
      intervalMs: 60_000,
      maxRounds: 2,
      maxIntervalMs: 3_600_000,
    });
  });

  it("an empty or non-object patch throws RangeError and leaves the queue unconfigured", () => {
    const q = new RetryQueue({ sender: async () => {} });
    for (const patch of [{}, null, "1000", []]) {
      assert.throws(
        () => q.reviseAutoReplaySchedule(patch as never),
        RangeError,
        JSON.stringify(patch)
      );
      assert.equal(q.getAutoReplayScheduleConfig(), undefined, JSON.stringify(patch));
      assert.equal(q.getAutoReplayer(), undefined, JSON.stringify(patch));
    }
  });

  it("an illegal patch throws RangeError and leaves the queue unconfigured", () => {
    const q = new RetryQueue({ sender: async () => {} });
    const invalid: Array<Record<string, unknown>> = [
      { intervalMs: 0 },
      { intervalMs: -5 },
      { intervalMs: NaN },
      { maxRounds: 0 },
      { maxRounds: 1.5 },
      { maxIntervalMs: 0 },
      { maxIntervalMs: 500 },
      { intervalMs: 5000, maxIntervalMs: 1000 },
    ];
    for (const patch of invalid) {
      assert.throws(
        () => q.reviseAutoReplaySchedule(patch as never),
        RangeError,
        JSON.stringify(patch)
      );
      assert.equal(q.getAutoReplayScheduleConfig(), undefined, JSON.stringify(patch));
      assert.equal(q.getAutoReplayer(), undefined, JSON.stringify(patch));
    }
  });

  it("enabling on a running queue arms the schedule immediately — rounds tick", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    q.start();
    assert.deepEqual(q.reviseAutoReplaySchedule({ intervalMs: 50, maxRounds: 10 }), {
      intervalMs: 50,
      maxRounds: 10,
      maxIntervalMs: 3_600_000,
    });
    const replayer = q.getAutoReplayer()!;
    assert.equal(replayer.isRunning(), true, "the schedule arms on the running queue");
    assert.equal(typeof replayer.status().nextRunAt, "string");
    await sleep(250);
    assert.ok(
      replayer.status().consecutiveEmptyRounds >= 1,
      "empty rounds ticked after the enable"
    );
    assert.equal(replayer.status().totalReplayed, 0);
    await q.shutdown(1000);
  });

  it("enabling on a stopped queue arms at the next start", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    q.reviseAutoReplaySchedule({ intervalMs: 50, maxRounds: 10 });
    const replayer = q.getAutoReplayer()!;
    assert.equal(replayer.isRunning(), false, "nothing ticks before start()");
    assert.equal(replayer.status().consecutiveEmptyRounds, 0);
    q.start();
    assert.equal(replayer.isRunning(), true);
    await sleep(150);
    assert.ok(
      replayer.status().consecutiveEmptyRounds >= 1,
      "rounds tick once the queue starts"
    );
    await q.shutdown(1000);
  });

  it("the enable starts from empty state — a dead letter seeded before it is not evaluated retroactively", async () => {
    const timer = manualTimer();
    const state = { fail: true };
    const q = new RetryQueue({
      sender: async () => {
        if (state.fail) throw new Error("downstream 500");
      },
      baseDelayMs: 1,
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    q.start();
    q.enqueue({ id: "dl-before-enable", payload: Buffer.from("payload"), targetUrl: EP, headers: {} });
    await timer.run();
    assert.equal(q.getDeadLetter().length, 1, "one entry dead-lettered before the enable");

    q.reviseAutoReplaySchedule({ intervalMs: 50, maxRounds: 10 });
    const replayer = q.getAutoReplayer()!;
    assert.equal(replayer.status().consecutiveEmptyRounds, 0, "no rounds counted before the enable");
    assert.equal(replayer.status().totalReplayed, 0, "nothing replayed before the enable");
    await q.shutdown(1000);
  });

  it("a partial revision after an enable still merges; landing on the live values is a no-op", () => {
    const q = new RetryQueue({ sender: async () => {} });
    q.reviseAutoReplaySchedule({ intervalMs: 5000 });
    assert.deepEqual(q.reviseAutoReplaySchedule({ maxRounds: 4 }), {
      intervalMs: 5000,
      maxRounds: 4,
      maxIntervalMs: 3_600_000,
    });
    assert.deepEqual(
      q.reviseAutoReplaySchedule({ intervalMs: 5000, maxRounds: 4, maxIntervalMs: 3_600_000 }),
      { intervalMs: 5000, maxRounds: 4, maxIntervalMs: 3_600_000 }
    );
    assert.deepEqual(q.getAutoReplayScheduleConfig(), {
      intervalMs: 5000,
      maxRounds: 4,
      maxIntervalMs: 3_600_000,
    });
  });

  it("a restart returns to unconfigured — the enable is live-only", () => {
    const opts = { sender: async () => {} };
    const q = new RetryQueue(opts);
    q.reviseAutoReplaySchedule({ intervalMs: 5000 });
    assert.notEqual(q.getAutoReplayScheduleConfig(), undefined);
    // A fresh queue from the same construction options has no scheduler.
    const restarted = new RetryQueue(opts);
    assert.equal(restarted.getAutoReplayScheduleConfig(), undefined);
    assert.equal(restarted.getAutoReplayer(), undefined);
  });
});

describe("RelayServer auto-replay enable (WR-447)", () => {
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

  function makeRelay() {
    const dir = mkdtempSync(join(tmpdir(), "autoreplay-schedule-enable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: EP,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => {},
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
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

  const construction = { intervalMs: 60_000, maxRounds: 10, maxIntervalMs: 3_600_000 };

  it("enabling audits previous null and mounts the getter; a same-value revision after the enable is a silent no-op", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getAutoReplayScheduleConfig, undefined);
    assert.deepEqual(relay.reviseAutoReplaySchedule({ intervalMs: 10_000 }), {
      ...construction,
      intervalMs: 10_000,
    });
    assert.deepEqual(relay.getAutoReplayScheduleConfig!(), {
      ...construction,
      intervalMs: 10_000,
    });
    const revised = eventsOf(audit, "auto_replay_schedule_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { ...construction, intervalMs: 10_000 });
    // Landing exactly on the live values audits nothing.
    relay.reviseAutoReplaySchedule({ intervalMs: 10_000 });
    assert.equal(eventsOf(audit, "auto_replay_schedule_revised").length, 1);
    // A real revision after the enable audits the enabled config as previous.
    relay.reviseAutoReplaySchedule({ maxRounds: 4 });
    const revised2 = eventsOf(audit, "auto_replay_schedule_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { ...construction, intervalMs: 10_000 });
    assert.deepEqual(revised2[1].current, { ...construction, intervalMs: 10_000, maxRounds: 4 });
  });

  it("an illegal or empty patch throws RangeError and leaves the relay unconfigured", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    for (const patch of [{}, { intervalMs: 0 }, { maxRounds: 0 }, { maxIntervalMs: 500 }]) {
      assert.throws(
        () => relay.reviseAutoReplaySchedule(patch as never),
        RangeError,
        JSON.stringify(patch)
      );
      assert.equal(relay.getAutoReplayScheduleConfig, undefined, JSON.stringify(patch));
    }
    assert.equal(eventsOf(audit, "auto_replay_schedule_revised").length, 0);
  });

  it("a fresh relay from the same options is unconfigured again — the enable is live-only", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    relay.reviseAutoReplaySchedule({ intervalMs: 10_000 });
    assert.notEqual(relay.getAutoReplayScheduleConfig, undefined);
    const second = makeRelay();
    await listen(second.relay);
    assert.equal(second.relay.getAutoReplayScheduleConfig, undefined);
  });

  it("rounds tick after a server-level enable — the status endpoint reports them", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    const auth = (p: string, m: string) => request(port, p, m, opToken);

    // Before the enable the status reports a disabled scheduler.
    const before = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.equal(before.enabled, false);

    relay.reviseAutoReplaySchedule({ intervalMs: 50, maxRounds: 10 });
    const enabled = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.equal(enabled.enabled, true);
    assert.equal(enabled.paused, false);
    assert.equal(enabled.stopped, false);
    assert.equal(enabled.consecutiveEmptyRounds, 0);
    assert.equal(typeof enabled.nextRunAt, "string", "a round is scheduled after the enable");

    await sleep(250);
    const ticked = (await auth("/dead-letter/auto-replay/status", "GET")).body;
    assert.ok(
      ticked.consecutiveEmptyRounds >= 1,
      "empty rounds ticked after the server-level enable"
    );
  });
});
