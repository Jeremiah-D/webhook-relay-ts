import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type StaleEndpointPausedEvent } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "stale-pause-enable-test-key";
const opToken = "stale-pause-enable-op-token";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Let the deliver() promise chain settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Manual timer that records every armed interval, so a retune's
 * re-arm is observable: the old pending fn must be cleared and a new
 * fn armed at the revised interval.
 */
function recordingTimer() {
  const pending: Array<() => void> = [];
  const intervals: number[] = [];
  return {
    intervals,
    pendingCount: () => pending.length,
    setTimer: (fn: () => void, ms: number) => {
      intervals.push(ms);
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await flush();
    },
  };
}

function item(id: string, targetUrl: string = URL) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

/** Queue WITHOUT stalePause configured — the enable's starting point. */
function makeQueue() {
  const queueTimer = recordingTimer();
  const autoPaused: StaleEndpointPausedEvent[] = [];
  const q = new RetryQueue({
    sender: async () => {},
    setTimer: queueTimer.setTimer,
    clearTimer: queueTimer.clearTimer,
    jitterMs: 0,
    onStalePauseAudit: (e) => autoPaused.push(e),
  });
  return { q, queueTimer, autoPaused };
}

describe("RetryQueue.reviseStalePause enable (WR-445)", () => {
  it("enabling on an unconfigured queue resolves missing fields to the defaults", async () => {
    const { q } = makeQueue();
    try {
      assert.equal(q.getStalePauseConfig(), undefined);
      assert.equal(q.stalePauseConfigured(), false);
      assert.equal(q.getStalePauseSweeper(), undefined);
      assert.deepEqual(q.reviseStalePause({ staleAfterDays: 7 }), {
        staleAfterDays: 7,
        sweepIntervalMs: 60_000,
      });
      assert.deepEqual(q.getStalePauseConfig(), { staleAfterDays: 7, sweepIntervalMs: 60_000 });
      assert.ok(q.getStalePauseSweeper() !== undefined);
      assert.equal(q.stalePauseConfigured(), true);
    } finally {
      await q.shutdown();
    }
    // The other knob's default, on a fresh queue.
    const second = makeQueue();
    try {
      assert.deepEqual(second.q.reviseStalePause({ sweepIntervalMs: 5000 }), {
        staleAfterDays: 30,
        sweepIntervalMs: 5000,
      });
    } finally {
      await second.q.shutdown();
    }
  });

  it("an illegal or empty enable patch throws RangeError and leaves the queue unconfigured", async () => {
    const { q } = makeQueue();
    try {
      for (const staleAfterDays of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, "7"]) {
        assert.throws(
          () => q.reviseStalePause({ staleAfterDays: staleAfterDays as number }),
          (err: unknown) =>
            err instanceof RangeError &&
            err.message ===
              `stalePause.staleAfterDays must be a finite number > 0, got ${String(staleAfterDays)}`,
          `staleAfterDays=${String(staleAfterDays)}`
        );
        assert.equal(q.getStalePauseConfig(), undefined);
        assert.equal(q.stalePauseConfigured(), false);
      }
      for (const sweepIntervalMs of [0, -100, Number.NaN, Number.POSITIVE_INFINITY, "1000"]) {
        assert.throws(
          () => q.reviseStalePause({ sweepIntervalMs: sweepIntervalMs as number }),
          (err: unknown) =>
            err instanceof RangeError &&
            err.message ===
              `stalePause.sweepIntervalMs must be a finite number > 0, got ${String(sweepIntervalMs)}`,
          `sweepIntervalMs=${String(sweepIntervalMs)}`
        );
        assert.equal(q.getStalePauseConfig(), undefined);
      }
      for (const bad of [{}, null, "7", [7]] as never[]) {
        assert.throws(() => q.reviseStalePause(bad), RangeError);
        assert.equal(q.getStalePauseConfig(), undefined);
        assert.equal(q.stalePauseConfigured(), false);
      }
      // A valid patch still enables after the rejected ones.
      assert.deepEqual(q.reviseStalePause({ staleAfterDays: 7 }), {
        staleAfterDays: 7,
        sweepIntervalMs: 60_000,
      });
    } finally {
      await q.shutdown();
    }
  });

  it("pre-enable activity is never evaluated: no baseline, no pause on the next sweep", async () => {
    const { q, queueTimer, autoPaused } = makeQueue();
    try {
      q.enqueue(item("a"));
      q.start();
      await queueTimer.step(); // delivered at T0 — before the enable
      q.stop();
      // Enable with a sub-second threshold: had the pre-enable
      // delivery been stamped, the endpoint would be past it already.
      assert.deepEqual(q.reviseStalePause({ staleAfterDays: 0.00001 }), {
        staleAfterDays: 0.00001,
        sweepIntervalMs: 60_000,
      });
      assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
      assert.deepEqual(q.getStalePauseStats(), []);
      assert.equal(autoPaused.length, 0);
      assert.equal(q.isEndpointPaused(URL), false);
    } finally {
      await q.shutdown();
    }
  });

  it("an endpoint first seen after the enable pauses on the next sweep once past the threshold", async () => {
    const { q, queueTimer, autoPaused } = makeQueue();
    try {
      // ~0.86 s threshold: the endpoint crosses it after a short real sleep.
      assert.deepEqual(
        q.reviseStalePause({ staleAfterDays: 0.00001, sweepIntervalMs: 3_600_000 }),
        { staleAfterDays: 0.00001, sweepIntervalMs: 3_600_000 }
      );
      q.enqueue(item("a"));
      q.start();
      await queueTimer.step(); // delivered — stamps the success baseline
      assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
      await sleep(2000);
      const res = q.sweepStaleEndpoints();
      assert.equal(res.paused.length, 1);
      assert.equal(res.paused[0].endpoint, URL);
      assert.equal(q.isEndpointPaused(URL), true);
      assert.equal(autoPaused.length, 1);
      assert.equal(autoPaused[0].endpoint, URL);
      assert.equal(autoPaused[0].staleAfterDays, 0.00001);
      assert.equal(q.getStalePauseStats()[0].paused, true);
      q.stop();
    } finally {
      await q.shutdown();
    }
  });

  it("enabling on a running queue arms the sweep schedule immediately; on a stopped queue it arms at the next start", async () => {
    const running = makeQueue();
    try {
      running.q.start();
      running.q.reviseStalePause({ staleAfterDays: 7, sweepIntervalMs: 3_600_000 });
      assert.equal(running.q.getStalePauseSweeper()?.isRunning(), true);
      running.q.stop();
      assert.equal(running.q.getStalePauseSweeper()?.isRunning(), false);
      running.q.start();
      assert.equal(running.q.getStalePauseSweeper()?.isRunning(), true);
      running.q.stop();
    } finally {
      await running.q.shutdown();
    }
    const stopped = makeQueue();
    try {
      stopped.q.reviseStalePause({ staleAfterDays: 7, sweepIntervalMs: 3_600_000 });
      assert.equal(stopped.q.getStalePauseSweeper()?.isRunning(), false);
      stopped.q.start();
      assert.equal(stopped.q.getStalePauseSweeper()?.isRunning(), true);
      stopped.q.stop();
    } finally {
      await stopped.q.shutdown();
    }
  });

  it("a restart returns to unconfigured — the enable is live-only", async () => {
    const first = makeQueue();
    try {
      first.q.reviseStalePause({ staleAfterDays: 7 });
      assert.equal(first.q.stalePauseConfigured(), true);
    } finally {
      await first.q.shutdown();
    }
    const second = makeQueue();
    try {
      assert.equal(second.q.getStalePauseConfig(), undefined);
      assert.equal(second.q.stalePauseConfigured(), false);
      assert.equal(second.q.getStalePauseSweeper(), undefined);
    } finally {
      await second.q.shutdown();
    }
  });

  it("enabling unlocks the stale-pause audit callback gate", async () => {
    const { q } = makeQueue();
    try {
      assert.throws(
        () => q.reviseStalePauseAuditCallback(() => {}),
        (err: unknown) =>
          err instanceof Error && /requires a restart/.test(err.message)
      );
      q.reviseStalePause({ staleAfterDays: 7 });
      // No throw now — the gate opens the moment the sweeper exists.
      // The enable itself installs no callback (WR-402 stays separate).
      q.reviseStalePauseAuditCallback(() => {});
      q.reviseStalePauseAuditCallback(null);
    } finally {
      await q.shutdown();
    }
  });
});

describe("RelayServer stale-pause enable (WR-445)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "stale-pause-enable-"));
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

  it("enable audits previous null and the full current config, and mounts the getter", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getStalePauseConfig, undefined);
    assert.equal(typeof relay.reviseStalePause, "function", "revise is always set");
    // The callback gate is still fail-closed before the enable.
    assert.throws(
      () => relay.reviseStalePauseAuditCallback!(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    assert.deepEqual(relay.reviseStalePause!({ staleAfterDays: 7 }), {
      staleAfterDays: 7,
      sweepIntervalMs: 60_000,
    });
    assert.deepEqual(relay.getStalePauseConfig!(), { staleAfterDays: 7, sweepIntervalMs: 60_000 });
    const revised = eventsOf(audit, "stale_pause_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { staleAfterDays: 7, sweepIntervalMs: 60_000 });
    // The enable also opens the callback gate (WR-402 stays unset).
    relay.reviseStalePauseAuditCallback!(() => {});
    const replaced = eventsOf(audit, "stale_pause_audit_callback_revised");
    assert.equal(replaced.length, 1);
    assert.equal(replaced[0].previous, "cleared");
    assert.equal(replaced[0].current, "set");
    // A same-value revision after the enable is a silent no-op.
    relay.reviseStalePause!({ staleAfterDays: 7 });
    assert.equal(eventsOf(audit, "stale_pause_revised").length, 1);
  });

  it("an illegal or empty enable patch throws RangeError and leaves the server unconfigured", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    for (const bad of [{ staleAfterDays: 0 }, { sweepIntervalMs: 0 }, {}]) {
      assert.throws(() => relay.reviseStalePause!(bad), RangeError);
    }
    assert.throws(() => relay.reviseStalePause!(null as never), RangeError);
    assert.equal(relay.getStalePauseConfig, undefined);
    assert.equal(eventsOf(audit, "stale_pause_revised").length, 0);
  });

  it("a restart returns to unconfigured — the enable is live-only", async () => {
    const first = makeRelay();
    await listen(first.relay);
    first.relay.reviseStalePause!({ staleAfterDays: 7 });
    assert.deepEqual(first.relay.getStalePauseConfig!(), { staleAfterDays: 7, sweepIntervalMs: 60_000 });
    const second = makeRelay();
    await listen(second.relay);
    assert.equal(second.relay.getStalePauseConfig, undefined);
  });
});
