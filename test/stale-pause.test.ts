import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type Sender,
  type StaleEndpointPausedEvent,
} from "../src/retry.ts";
import { StalePauseSweeper } from "../src/stale-pause.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { HttpDeliveryError } from "../src/failure.ts";

const URL = "http://localhost:9999/hook";
const HOOK_KEY = "hook-key";
const OP_TOKEN = "op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const DAY_MS = 86_400_000;

/**
 * Manual timer with single-step control: parking re-arms timers, so the
 * tests advance one wave at a time instead of draining everything.
 */
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
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await flush();
    },
  };
}

/** Let the deliver() promise chain (turn -> limiter -> sender) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string = URL) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

/** Controllable clock shared by the queue stamps and the sweep. */
function clock() {
  let nowMs = 1_700_000_000_000;
  return {
    now: () => nowMs,
    advance: (ms: number) => {
      nowMs += ms;
    },
  };
}

function makeQueue(opts: Record<string, unknown> = {}) {
  const c = clock();
  const timer = manualTimer();
  const autoPaused: StaleEndpointPausedEvent[] = [];
  const pauseCauses: Array<string | undefined> = [];
  const q = new RetryQueue({
    sender: async () => {},
    setTimer: timer.setTimer,
    clearTimer: timer.clearTimer,
    jitterMs: 0,
    stalePause: { staleAfterDays: 30, now: c.now },
    onStalePauseAudit: (e) => autoPaused.push(e),
    onEndpointPaused: (i) => pauseCauses.push(i.cause),
    ...opts,
  } as ConstructorParameters<typeof RetryQueue>[0]);
  return { q, c, timer, autoPaused, pauseCauses };
}

describe("stalePause option validation", () => {
  it("throws RangeError on illegal values, at construction", () => {
    for (const staleAfterDays of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, "30"]) {
      assert.throws(
        () => new RetryQueue({ stalePause: { staleAfterDays: staleAfterDays as number } }),
        RangeError,
        `staleAfterDays=${String(staleAfterDays)}`
      );
    }
    for (const sweepIntervalMs of [0, -100, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(
        () => new RetryQueue({ stalePause: { sweepIntervalMs } }),
        RangeError,
        `sweepIntervalMs=${String(sweepIntervalMs)}`
      );
    }
    // A present-but-empty object enables the feature with defaults.
    const q = new RetryQueue({ stalePause: {} });
    assert.ok(q.getStalePauseSweeper()?.isEnabled());
    q.stop();
  });

  it("is disabled by default: no tracking, no sweeper, no pause", () => {
    const { q, c } = makeQueue({ stalePause: undefined });
    assert.equal(q.getStalePauseSweeper(), undefined);
    assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
    assert.deepEqual(q.getStalePauseStats(), []);
    q.enqueue(item("a"));
    c.advance(60 * DAY_MS);
    assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
    assert.equal(q.isEndpointPaused(URL), false);
    assert.ok(!q.renderMetrics().includes("relay_endpoint_auto_pauses_total"));
  });
});

describe("StalePauseSweeper", () => {
  it("auto-pauses an idle endpoint after the threshold", async () => {
    const { q, c, timer, autoPaused, pauseCauses } = makeQueue();
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // delivered
    assert.equal(q.getStalePauseStats()[0]?.idleDays, 0);
    c.advance(29 * DAY_MS);
    assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
    c.advance(2 * DAY_MS); // 31 days idle
    const res = q.sweepStaleEndpoints();
    assert.equal(res.paused.length, 1);
    assert.equal(res.paused[0].endpoint, URL);
    assert.ok(res.paused[0].idleMs >= 31 * DAY_MS);
    assert.equal(q.isEndpointPaused(URL), true);
    // Audit event: the operator alert channel, edge-triggered.
    assert.equal(autoPaused.length, 1);
    const ev = autoPaused[0];
    assert.equal(ev.event, "endpoint_auto_paused");
    assert.equal(ev.endpoint, URL);
    assert.equal(ev.idleDays, 31);
    assert.equal(ev.staleAfterDays, 30);
    assert.ok(ev.lastSuccessfulDeliveryAt !== undefined);
    assert.ok(typeof ev.at === "string");
    // Same WR-50 mechanics, cause-distinguished.
    assert.deepEqual(pauseCauses, ["auto"]);
    // Stats + metrics observability.
    const stats = q.getStalePauseStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].paused, true);
    assert.equal(stats[0].autoPauses, 1);
    assert.equal(stats[0].pending, 0);
    assert.ok(
      q.renderMetrics().includes(`relay_endpoint_auto_pauses_total{endpoint="${URL}"} 1`)
    );
    q.stop();
  });

  it("never auto-pauses while anything is pending", async () => {
    let releaseSender!: () => void;
    const sender: Sender = async () => {
      await new Promise<void>((r) => {
        releaseSender = r;
      });
    };
    const { q, c, timer, autoPaused } = makeQueue({ sender });
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // sender invoked, promise pending
    c.advance(60 * DAY_MS);
    assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
    assert.equal(q.isEndpointPaused(URL), false);
    releaseSender(); // settles -> delivered
    await flush();
    c.advance(31 * DAY_MS);
    const res = q.sweepStaleEndpoints();
    assert.equal(res.paused.length, 1);
    assert.equal(autoPaused.length, 1);
    q.stop();
  });

  it("a successful delivery refreshes the idle clock", async () => {
    const { q, c, timer } = makeQueue();
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // delivered at T0
    c.advance(29 * DAY_MS);
    q.enqueue(item("b"));
    await timer.step(); // delivered at T0+29d: clock restarts
    c.advance(29 * DAY_MS);
    assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] }); // only 29d idle
    c.advance(2 * DAY_MS);
    assert.equal(q.sweepStaleEndpoints().paused.length, 1);
    q.stop();
  });

  it("semantic failures do not count as success", async () => {
    const { q, c, timer, autoPaused } = makeQueue({
      sender: async () => ({
        statusCode: 200,
        body: Buffer.from(JSON.stringify({ ok: false })),
        truncated: false,
      }),
      responseValidators: { [URL]: () => false },
      maxAttempts: 1,
    });
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // validator rejects -> dead-lettered, never "delivered"
    c.advance(31 * DAY_MS);
    const res = q.sweepStaleEndpoints();
    assert.equal(res.paused.length, 1);
    // No success ever stamped: the audit event says so honestly.
    assert.equal(autoPaused.length, 1);
    assert.equal(autoPaused[0].lastSuccessfulDeliveryAt, undefined);
    assert.equal(autoPaused[0].idleDays, 31); // measured from first sighting
    q.stop();
  });

  it("non-retryable (4xx) outcomes do not count as success", async () => {
    const { q, c, timer, autoPaused } = makeQueue({
      sender: async () => {
        throw new HttpDeliveryError(400);
      },
      maxAttempts: 5,
    });
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // 400 -> dead-lettered immediately, not delivered
    c.advance(31 * DAY_MS);
    const res = q.sweepStaleEndpoints();
    assert.equal(res.paused.length, 1);
    assert.equal(autoPaused[0].lastSuccessfulDeliveryAt, undefined);
    q.stop();
  });

  it("a manual pause is never re-processed; resume restarts the clock", async () => {
    const { q, c, timer, autoPaused, pauseCauses } = makeQueue();
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // delivered at T0
    c.advance(31 * DAY_MS);
    assert.equal(q.pauseEndpoint(URL), true); // manual hold first
    assert.deepEqual(pauseCauses, ["manual"]);
    assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] }); // sweep skips it
    assert.equal(autoPaused.length, 0); // no auto event, no double audit
    assert.equal(q.resumeEndpoint(URL), true); // ordinary WR-50 resume path
    assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] }); // clock restarted
    c.advance(29 * DAY_MS);
    assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
    c.advance(2 * DAY_MS);
    const res = q.sweepStaleEndpoints();
    assert.equal(res.paused.length, 1);
    assert.deepEqual(pauseCauses, ["manual", "auto"]);
    q.stop();
  });

  it("an auto-paused endpoint still accepts inbound but stops delivering", async () => {
    let calls = 0;
    const { q, c, timer } = makeQueue({
      sender: async () => {
        calls += 1;
      },
    });
    q.enqueue(item("a"));
    q.start();
    await timer.step();
    assert.equal(calls, 1);
    c.advance(31 * DAY_MS);
    q.sweepStaleEndpoints();
    assert.equal(q.isEndpointPaused(URL), true);
    q.enqueue(item("b")); // inbound still received...
    await timer.step();
    assert.equal(calls, 1); // ...but not delivered: parked, not discarded
    assert.equal(q.pendingCount(), 1);
    assert.equal(q.resumeEndpoint(URL), true); // manual resume recovers
    await timer.step();
    assert.equal(calls, 2); // parked item resumes with its lifecycle intact
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });

  it("start/stop arm and disarm the sweep; the armed sweep pauses on schedule", async () => {
    let sweepFn: (() => void) | undefined;
    let cleared = 0;
    const c = clock();
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      stalePause: {
        staleAfterDays: 30,
        now: c.now,
        setTimer: (fn: () => void, _ms: number) => {
          sweepFn = fn;
          return {
            clear: () => {
              cleared += 1;
              sweepFn = undefined;
            },
          };
        },
        clearTimer: (h: { clear(): void }) => h.clear(),
      },
    });
    const sweeper = q.getStalePauseSweeper();
    assert.ok(sweeper instanceof StalePauseSweeper);
    assert.equal(sweeper.isRunning(), false);
    q.enqueue(item("a"));
    q.start();
    assert.equal(sweeper.isRunning(), true);
    assert.ok(sweepFn !== undefined);
    await timer.step(); // delivered at T0
    c.advance(31 * DAY_MS);
    sweepFn!(); // the armed sweep fires on its schedule
    assert.equal(q.isEndpointPaused(URL), true);
    q.stop();
    assert.equal(sweeper.isRunning(), false);
    assert.equal(cleared, 1);
  });

  it("batch-buffered and deliver_at-parked items count as pending", async () => {
    const { q, c, timer } = makeQueue({
      batch: { windowMs: 60_000, maxBatchSize: 100 },
    });
    q.enqueue(item("a")); // sits in the batch window: buffered, not queued
    q.start();
    c.advance(31 * DAY_MS);
    assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
    await timer.step(); // window elapses -> flush -> queued
    await timer.step(); // delivery attempt -> delivered
    c.advance(31 * DAY_MS);
    assert.equal(q.sweepStaleEndpoints().paused.length, 1);
    q.stop();
  });
});

describe("server wiring for stale-endpoint auto-pause", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function postWebhook(port: number) {
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: {
            "x-signature": signSha256(BODY, HOOK_KEY),
            "content-type": "application/json",
            "content-length": String(BODY.length),
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
  }

  function getText(port: number, path: string, token?: string) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const headers: Record<string, string> = {};
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      });
      r.on("error", reject);
      r.end();
    });
  }

  it("audits endpoint_auto_paused (not endpoint_paused) and exposes the metric", async () => {
    const dir = mkdtempSync(join(tmpdir(), "stale-pause-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const c = clock();
    let sweepFn: (() => void) | undefined;
    const relay = createRelayServer({
      secret: HOOK_KEY,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: OP_TOKEN,
      sender: async () => {},
      stalePause: {
        staleAfterDays: 30,
        now: c.now,
        setTimer: (fn: () => void, _ms: number) => {
          sweepFn = fn;
          return { clear: () => {} };
        },
        clearTimer: (h: { clear(): void }) => h.clear(),
      },
    });
    servers.push(relay);
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await flush(20); // let the delivery settle before advancing the clock
    c.advance(31 * DAY_MS);
    assert.ok(sweepFn !== undefined);
    sweepFn!();
    const autoEvents = audit.query({ event: "endpoint_auto_paused" }) as Array<{
      endpoint: string;
      idleDays: number;
    }>;
    assert.equal(autoEvents.length, 1);
    assert.equal(autoEvents[0].endpoint, URL);
    assert.equal(autoEvents[0].idleDays, 31);
    // One transition, one audit event: no `endpoint_paused` for the auto path.
    assert.equal(audit.query({ event: "endpoint_paused" }).length, 0);
    const metrics = await getText(port, "/metrics", OP_TOKEN);
    assert.equal(metrics.status, 200);
    assert.ok(metrics.text.includes(`relay_endpoint_auto_pauses_total{endpoint="${URL}"} 1`));
  });
});
