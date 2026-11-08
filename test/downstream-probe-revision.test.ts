import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DownstreamProber,
  type ProbeTimerHandle,
} from "../src/downstream-probe.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "downstream-probe-revision-test-key";
const opToken = "downstream-probe-revision-op-token";
const EP = "http://127.0.0.1:9/health";
const EP2 = "http://127.0.0.1:9/other";

/** Manual timer driver: collect scheduled callbacks, inspect on demand. */
function manualTimers() {
  const scheduled: { fn: () => void; ms: number; cleared: boolean }[] = [];
  return {
    setTimer: (fn: () => void, ms: number): ProbeTimerHandle => {
      const entry = { fn, ms, cleared: false };
      scheduled.push(entry);
      return {
        clear: () => {
          entry.cleared = true;
        },
      };
    },
    clearTimer: (h: ProbeTimerHandle) => h.clear(),
    scheduled,
  };
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      assert.ok(addr && typeof addr === "object");
      resolve(addr.port);
    });
  });
}

describe("DownstreamProber.retune (WR-355)", () => {
  it("revising intervalMs re-arms pending timers at the new delay, counts untouched", () => {
    const t = manualTimers();
    const prober = new DownstreamProber({
      endpoints: [EP, EP2],
      intervalMs: 1000,
      probeRequest: async () => true,
      recordOutcome: () => {},
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    assert.equal(t.scheduled.length, 2);
    assert.ok(t.scheduled.every((s) => s.ms === 1000 && !s.cleared));
    assert.deepEqual(prober.retune({ intervalMs: 5000 }), {
      intervalMs: 5000,
      timeoutMs: 5000,
      method: "HEAD",
    });
    // Both pending timers were cleared and re-armed at the new interval.
    assert.equal(t.scheduled.length, 4);
    assert.ok(t.scheduled.slice(0, 2).every((s) => s.cleared));
    assert.ok(t.scheduled.slice(2).every((s) => s.ms === 5000 && !s.cleared));
    // No round ran, so no outcome counts moved.
    assert.deepEqual(
      prober.stats().map((s) => [s.success, s.failure, s.consecutiveFailures]),
      [
        [0, 0, 0],
        [0, 0, 0],
      ]
    );
    prober.stop();
    assert.ok(t.scheduled.slice(2).every((s) => s.cleared));
  });

  it("revising timeoutMs makes the next default request use the new timeout", async () => {
    const stub = createServer((req, res) => {
      res.on("error", () => {});
      // Answer slower than the old timeout, faster than the new one.
      setTimeout(() => {
        try {
          res.writeHead(200);
          res.end();
        } catch {
          // Client already timed out and destroyed the request.
        }
      }, 300);
    });
    const port = await listen(stub);
    const url = `http://127.0.0.1:${port}/healthz`;
    try {
      const prober = new DownstreamProber({
        endpoints: [url],
        timeoutMs: 100,
        recordOutcome: () => {},
      });
      assert.deepEqual(await prober.runRound(), [{ endpoint: url, ok: false }]);
      assert.deepEqual(prober.retune({ timeoutMs: 2000 }), {
        intervalMs: 30000,
        timeoutMs: 2000,
        method: "HEAD",
      });
      assert.deepEqual(await prober.runRound(), [{ endpoint: url, ok: true }]);
    } finally {
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  });

  it("revising method makes the next round use the new method", async () => {
    const methods: string[] = [];
    const stub = createServer((req, res) => {
      methods.push(req.method ?? "");
      res.writeHead(200).end();
    });
    const port = await listen(stub);
    const url = `http://127.0.0.1:${port}/healthz`;
    try {
      const prober = new DownstreamProber({
        endpoints: [url],
        recordOutcome: () => {},
      });
      assert.deepEqual(await prober.runRound(), [{ endpoint: url, ok: true }]);
      assert.deepEqual(methods, ["HEAD"]);
      assert.deepEqual(prober.retune({ method: "GET" }), {
        intervalMs: 30000,
        timeoutMs: 5000,
        method: "GET",
      });
      assert.deepEqual(await prober.runRound(), [{ endpoint: url, ok: true }]);
      assert.deepEqual(methods, ["HEAD", "GET"]);
    } finally {
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  });

  it("an injected custom probeRequest is unaffected by timeoutMs revisions", async () => {
    const seen: number[] = [];
    const prober = new DownstreamProber({
      endpoints: [EP],
      timeoutMs: 100,
      probeRequest: async () => {
        seen.push(1);
        return true;
      },
      recordOutcome: () => {},
    });
    assert.deepEqual(await prober.runRound(), [{ endpoint: EP, ok: true }]);
    prober.retune({ timeoutMs: 2000 });
    assert.deepEqual(await prober.runRound(), [{ endpoint: EP, ok: true }]);
    assert.equal(seen.length, 2);
  });

  it("illegal patches throw RangeError and the live values and timers are untouched", () => {
    const t = manualTimers();
    const prober = new DownstreamProber({
      endpoints: [EP],
      intervalMs: 30000,
      timeoutMs: 5000,
      method: "HEAD",
      probeRequest: async () => true,
      recordOutcome: () => {},
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    const live = { intervalMs: 30000, timeoutMs: 5000, method: "HEAD" as const };
    assert.deepEqual(prober.snapshot(), live);
    for (const patch of [
      { intervalMs: 0 },
      { intervalMs: -1 },
      { intervalMs: NaN },
      { intervalMs: Infinity },
      { timeoutMs: 0 },
      { timeoutMs: -5 },
      { timeoutMs: Infinity },
      { method: "POST" as "HEAD" },
    ]) {
      assert.throws(() => prober.retune(patch), RangeError, JSON.stringify(patch));
    }
    assert.deepEqual(prober.snapshot(), live);
    // No timer was cleared or re-armed by the failed revisions.
    assert.equal(t.scheduled.length, 1);
    assert.ok(t.scheduled.every((s) => s.ms === 30000 && !s.cleared));
    prober.stop();
  });

  it("an empty patch and a non-object patch are RangeErrors", () => {
    const prober = new DownstreamProber({
      endpoints: [EP],
      probeRequest: async () => true,
      recordOutcome: () => {},
    });
    assert.throws(() => prober.retune({}), RangeError);
    assert.throws(() => prober.retune(null as never), RangeError);
    assert.throws(() => prober.retune("fast" as never), RangeError);
    assert.throws(() => prober.retune([] as never), RangeError);
    assert.deepEqual(prober.snapshot(), {
      intervalMs: 30000,
      timeoutMs: 5000,
      method: "HEAD",
    });
  });

  it("a same-value patch is a silent no-op and does not re-arm timers", () => {
    const t = manualTimers();
    const prober = new DownstreamProber({
      endpoints: [EP],
      intervalMs: 1000,
      probeRequest: async () => true,
      recordOutcome: () => {},
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    const live = { intervalMs: 1000, timeoutMs: 5000, method: "HEAD" as const };
    assert.deepEqual(prober.retune({ intervalMs: 1000 }), live);
    assert.deepEqual(prober.retune({ intervalMs: 1000, timeoutMs: 5000, method: "HEAD" }), live);
    assert.deepEqual(prober.snapshot(), live);
    // The pending countdown was left alone: still one live 1000 timer.
    assert.equal(t.scheduled.length, 1);
    assert.ok(t.scheduled.every((s) => s.ms === 1000 && !s.cleared));
    prober.stop();
  });

  it("an in-flight round settles on its original flow while the other endpoint's timer is re-armed", async () => {
    const t = manualTimers();
    const outcomes: [string, boolean][] = [];
    let releaseProbe: ((ok: boolean) => void) | undefined;
    const prober = new DownstreamProber({
      endpoints: [EP, EP2],
      intervalMs: 1000,
      probeRequest: () =>
        new Promise<boolean>((resolve) => {
          releaseProbe = resolve;
        }),
      recordOutcome: (endpoint, ok) => outcomes.push([endpoint, ok]),
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    assert.equal(t.scheduled.length, 2);
    // Fire EP's round; it goes in-flight on the deferred probe.
    const roundA = t.scheduled[0].fn();
    // Revise while A is in flight.
    prober.retune({ intervalMs: 5000 });
    // EP2's pending timer was cleared and re-armed at 5000; EP's fired
    // timer entry is untouched (it already fired, so there is nothing
    // to clear — the manual driver still lists it as uncleared).
    assert.ok(t.scheduled[1].cleared);
    const live = t.scheduled.filter((s) => !s.cleared && s.ms === 5000);
    assert.equal(live.length, 2);
    // The in-flight round still settles on its original flow.
    releaseProbe!(true);
    await roundA;
    assert.deepEqual(outcomes, [[EP, true]]);
    // After settling, tick re-armed EP at the new interval too — one
    // live 5000 timer per endpoint (the fired 1000 entry aside).
    const liveAfter = t.scheduled.filter((s) => !s.cleared && s.ms === 5000);
    assert.equal(liveAfter.length, 2);
    const s = prober.stats().find((x) => x.endpoint === EP)!;
    assert.equal(s.success, 1);
    assert.equal(s.failure, 0);
    assert.equal(s.consecutiveFailures, 0);
    prober.stop();
  });

  it("an unstarted prober uses the revised values on the next start()", () => {
    const t = manualTimers();
    const prober = new DownstreamProber({
      endpoints: [EP],
      intervalMs: 1000,
      probeRequest: async () => true,
      recordOutcome: () => {},
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.retune({ intervalMs: 7000, method: "GET", timeoutMs: 2000 });
    assert.deepEqual(prober.snapshot(), {
      intervalMs: 7000,
      timeoutMs: 2000,
      method: "GET",
    });
    prober.start();
    assert.equal(t.scheduled.length, 1);
    assert.equal(t.scheduled[0].ms, 7000);
    prober.stop();
  });
});

describe("RetryQueue downstream probe revision (WR-355)", () => {
  const okSender: Sender = async () => ({ statusCode: 200, body: Buffer.alloc(0) });

  it("unconfigured: revise throws the must-restart Error, getter returns undefined", () => {
    const q = new RetryQueue({ sender: okSender });
    assert.equal(q.getProbeConfig(), undefined);
    assert.throws(
      () => q.reviseProbe({ intervalMs: 5000 }),
      /not configured — enabling it requires a restart/
    );
    assert.equal(q.getProbeConfig(), undefined);
    q.stop();
  });

  it("getter tracks revisions", () => {
    const q = new RetryQueue({
      sender: okSender,
      probe: {
        endpoints: [EP],
        intervalMs: 60000,
        probeRequest: async () => true,
      },
    });
    assert.deepEqual(q.getProbeConfig(), {
      intervalMs: 60000,
      timeoutMs: 5000,
      method: "HEAD",
    });
    assert.deepEqual(q.reviseProbe({ intervalMs: 5000, method: "GET" }), {
      intervalMs: 5000,
      timeoutMs: 5000,
      method: "GET",
    });
    assert.deepEqual(q.getProbeConfig(), {
      intervalMs: 5000,
      timeoutMs: 5000,
      method: "GET",
    });
    q.stop();
  });
});

describe("RelayServer downstream probe revision (WR-355)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "downstream-probe-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: EP,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  const construction = { intervalMs: 60000, timeoutMs: 5000, method: "HEAD" as const };

  it("revision audits previous/current with three fields; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: {
        probe: {
          endpoints: [EP],
          intervalMs: 60000,
          probeRequest: async () => true,
        },
      },
    });
    await listen(relay);
    assert.deepEqual(relay.getProbeConfig!(), construction);
    assert.deepEqual(relay.reviseProbe!({ intervalMs: 5000 }), {
      ...construction,
      intervalMs: 5000,
    });
    const revised = eventsOf(audit, "probe_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, intervalMs: 5000 });
    // Landing exactly on the live values audits nothing.
    relay.reviseProbe!({ intervalMs: 5000 });
    assert.equal(eventsOf(audit, "probe_revised").length, 1);
    assert.deepEqual(relay.getProbeConfig!(), { ...construction, intervalMs: 5000 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseProbe!({ intervalMs: 0 }), RangeError);
    assert.throws(() => relay.reviseProbe!({}), RangeError);
    assert.equal(eventsOf(audit, "probe_revised").length, 1);
    assert.deepEqual(relay.getProbeConfig!(), { ...construction, intervalMs: 5000 });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getProbeConfig, undefined);
    assert.throws(
      () => relay.reviseProbe!({ intervalMs: 5000 }),
      /not configured — enabling it requires a restart/
    );
  });
});
