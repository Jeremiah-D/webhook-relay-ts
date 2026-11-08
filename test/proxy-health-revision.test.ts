import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { Socket } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ProxyHealthMonitor,
  type ProxyHealthAuditEvent,
  type ProxyHealthConfig,
  type ProxyHealthTimerHandle,
} from "../src/proxy-health.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "proxy-health-revision-test-key";
const opToken = "proxy-health-revision-op-token";
const deadProxy = "http://127.0.0.1:1/sick";
const EP = "http://127.0.0.1:9/health";

/** A fake successful CONNECT: no network, just a destroyable handle. */
function fakeSocket(): Socket {
  return { destroy: () => undefined } as unknown as Socket;
}

function failingConnect(): Promise<Socket> {
  return Promise.reject(new Error("TCP connect to proxy failed: ECONNREFUSED"));
}

function okConnect(): Promise<Socket> {
  return Promise.resolve(fakeSocket());
}

/** Manual timer driver: collect scheduled callbacks, inspect on demand. */
function manualTimers() {
  const scheduled: { fn: () => void; ms: number; cleared: boolean }[] = [];
  return {
    setTimer: (fn: () => void, ms: number): ProxyHealthTimerHandle => {
      const entry = {
        fn: () => {
          // A fired timer is consumed: it no longer counts as pending.
          entry.cleared = true;
          return fn();
        },
        ms,
        cleared: false,
      };
      scheduled.push(entry);
      return {
        clear: () => {
          entry.cleared = true;
        },
      };
    },
    clearTimer: (h: ProxyHealthTimerHandle) => h.clear(),
    scheduled,
    live(): { fn: () => void; ms: number; cleared: boolean }[] {
      return scheduled.filter((e) => !e.cleared);
    },
  };
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr !== null && typeof addr === "object") resolve(addr.port);
      else reject(new Error("no address"));
    });
  });
}

describe("ProxyHealthMonitor.retune (WR-358)", () => {
  it("tightening intervalMs re-arms the pending timer at the new delay, counts untouched", () => {
    const t = manualTimers();
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      intervalMs: 60000,
      connect: okConnect,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    m.start();
    assert.equal(t.live().length, 1);
    assert.equal(t.live()[0].ms, 60000);
    const next = m.retune({ intervalMs: 5000 });
    assert.deepEqual(next, { intervalMs: 5000, probeTimeoutMs: 10000, failureThreshold: 3 });
    assert.equal(t.scheduled[0].cleared, true);
    assert.equal(t.live().length, 1);
    assert.equal(t.live()[0].ms, 5000);
    const s = m.stats()[0];
    assert.equal(s.success, 0);
    assert.equal(s.failure, 0);
    assert.equal(s.consecutiveFailures, 0);
    assert.equal(s.healthy, true);
    m.stop();
  });

  it("loosening intervalMs triggers no extra round", async () => {
    const t = manualTimers();
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      intervalMs: 60000,
      connect: okConnect,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    m.start();
    m.retune({ intervalMs: 120000 });
    assert.equal(t.live().length, 1);
    assert.equal(t.live()[0].ms, 120000);
    // Fire the one pending round: exactly one probe runs, then re-arms.
    await t.live()[0].fn();
    assert.equal(m.stats()[0].success, 1);
    assert.equal(t.live().length, 1);
    assert.equal(t.live()[0].ms, 120000);
    m.stop();
  });

  it("probeTimeoutMs is read live: the next probe handshakes with the new timeout", async () => {
    const seen: number[] = [];
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      probeTimeoutMs: 10000,
      connect: (_proxyUrl, _host, _port, opts) => {
        seen.push(opts.connectTimeoutMs);
        return okConnect();
      },
    });
    await m.runRound();
    assert.deepEqual(seen, [10000]);
    m.retune({ probeTimeoutMs: 2500 });
    await m.runRound();
    assert.deepEqual(seen, [10000, 2500]);
  });

  it("lowering failureThreshold marks the proxy unhealthy on the next failure", async () => {
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      failureThreshold: 3,
      connect: failingConnect,
    });
    await m.runRound();
    await m.runRound();
    assert.equal(m.stats()[0].consecutiveFailures, 2);
    assert.equal(m.stats()[0].healthy, true);
    m.retune({ failureThreshold: 2 });
    await m.runRound();
    assert.equal(m.stats()[0].consecutiveFailures, 3);
    assert.equal(m.stats()[0].healthy, false);
  });

  it("raising failureThreshold does not retroactively re-admit an unhealthy proxy", async () => {
    const audits: ProxyHealthAuditEvent[] = [];
    let fail = true;
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      failureThreshold: 1,
      connect: () => (fail ? failingConnect() : okConnect()),
      onAudit: (e) => audits.push(e),
    });
    await m.runRound();
    assert.equal(m.stats()[0].healthy, false);
    m.retune({ failureThreshold: 5 });
    assert.equal(m.stats()[0].healthy, false);
    assert.equal(
      audits.filter((e) => e.event === "proxy_recovered").length,
      0
    );
    // Recovery still needs a successful scheduled probe, not the revision.
    fail = false;
    await m.runRound();
    assert.equal(m.stats()[0].healthy, true);
    assert.equal(
      audits.filter((e) => e.event === "proxy_recovered").length,
      1
    );
  });

  it("illegal patches throw RangeError and leave the live values untouched", () => {
    const m = new ProxyHealthMonitor({
      intervalMs: 60000,
      probeTimeoutMs: 8000,
      failureThreshold: 2,
    });
    const before = m.snapshot();
    for (const intervalMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(() => m.retune({ intervalMs }), RangeError);
    }
    for (const probeTimeoutMs of [0, -1, Number.NaN]) {
      assert.throws(() => m.retune({ probeTimeoutMs }), RangeError);
    }
    for (const failureThreshold of [0, -1, 1.5, Number.NaN]) {
      assert.throws(() => m.retune({ failureThreshold }), RangeError);
    }
    assert.throws(() => m.retune(null as unknown as { intervalMs: number }), RangeError);
    assert.throws(() => m.retune("fast" as unknown as { intervalMs: number }), RangeError);
    assert.throws(() => m.retune([] as unknown as { intervalMs: number }), RangeError);
    assert.deepEqual(m.snapshot(), before);
  });

  it("an empty patch is a RangeError", () => {
    const m = new ProxyHealthMonitor({ intervalMs: 60000 });
    assert.throws(() => m.retune({}), RangeError);
    assert.equal(m.snapshot().intervalMs, 60000);
  });

  it("a same-value patch is a silent no-op with no audit", () => {
    const audits: ProxyHealthAuditEvent[] = [];
    const m = new ProxyHealthMonitor({
      intervalMs: 60000,
      probeTimeoutMs: 8000,
      failureThreshold: 2,
      onAudit: (e) => audits.push(e),
    });
    assert.deepEqual(m.retune({ intervalMs: 60000 }), {
      intervalMs: 60000,
      probeTimeoutMs: 8000,
      failureThreshold: 2,
    });
    assert.deepEqual(m.retune({ intervalMs: 60000, probeTimeoutMs: 8000, failureThreshold: 2 }), {
      intervalMs: 60000,
      probeTimeoutMs: 8000,
      failureThreshold: 2,
    });
    assert.equal(audits.length, 0);
  });

  it("a real revision audits previous/current with the three knobs", () => {
    const audits: ProxyHealthAuditEvent[] = [];
    const m = new ProxyHealthMonitor({
      intervalMs: 60000,
      probeTimeoutMs: 8000,
      failureThreshold: 2,
      onAudit: (e) => audits.push(e),
    });
    const construction: ProxyHealthConfig = {
      intervalMs: 60000,
      probeTimeoutMs: 8000,
      failureThreshold: 2,
    };
    const next = m.retune({ intervalMs: 5000, failureThreshold: 5 });
    assert.deepEqual(next, { ...construction, intervalMs: 5000, failureThreshold: 5 });
    assert.equal(audits.length, 1);
    assert.equal(audits[0].event, "proxy_health_revised");
    assert.deepEqual(
      (audits[0] as { previous: ProxyHealthConfig }).previous,
      construction
    );
    assert.deepEqual(
      (audits[0] as { current: ProxyHealthConfig }).current,
      { ...construction, intervalMs: 5000, failureThreshold: 5 }
    );
  });

  it("an unstarted monitor picks the new values up on start()", () => {
    const t = manualTimers();
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      intervalMs: 60000,
      connect: okConnect,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    m.retune({ intervalMs: 7000, probeTimeoutMs: 1234 });
    m.start();
    assert.equal(t.live().length, 1);
    assert.equal(t.live()[0].ms, 7000);
    assert.equal(m.snapshot().probeTimeoutMs, 1234);
    m.stop();
  });

  it("revision leaves already-recorded health state and counters untouched", async () => {
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      intervalMs: 60000,
      failureThreshold: 3,
      connect: failingConnect,
    });
    await m.runRound();
    await m.runRound();
    m.retune({ intervalMs: 5000 });
    const s = m.stats()[0];
    assert.equal(s.consecutiveFailures, 2);
    assert.equal(s.failure, 2);
    assert.equal(s.healthy, true);
    // Same for an already-unhealthy proxy: the revision moves no verdict.
    const m2 = new ProxyHealthMonitor({
      proxies: [deadProxy],
      intervalMs: 60000,
      failureThreshold: 1,
      connect: failingConnect,
    });
    await m2.runRound();
    assert.equal(m2.stats()[0].healthy, false);
    m2.retune({ probeTimeoutMs: 2500 });
    assert.equal(m2.stats()[0].healthy, false);
    assert.equal(m2.stats()[0].consecutiveFailures, 1);
  });
});

describe("RelayServer proxy health revision (WR-358)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "proxy-health-revision-"));
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

  const construction: ProxyHealthConfig = {
    intervalMs: 60000,
    probeTimeoutMs: 10000,
    failureThreshold: 3,
  };

  it("revision audits previous/current with three fields; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      proxyHealth: { ...construction, connect: okConnect },
    });
    await listen(relay);
    assert.deepEqual(relay.getProxyHealthConfig!(), construction);
    assert.deepEqual(relay.reviseProxyHealth!({ intervalMs: 5000 }), {
      ...construction,
      intervalMs: 5000,
    });
    const revised = eventsOf(audit, "proxy_health_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, intervalMs: 5000 });
    // Landing exactly on the live values audits nothing.
    relay.reviseProxyHealth!({ intervalMs: 5000 });
    assert.equal(eventsOf(audit, "proxy_health_revised").length, 1);
    assert.deepEqual(relay.getProxyHealthConfig!(), { ...construction, intervalMs: 5000 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseProxyHealth!({ intervalMs: 0 }), RangeError);
    assert.throws(() => relay.reviseProxyHealth!({}), RangeError);
    assert.equal(eventsOf(audit, "proxy_health_revised").length, 1);
    assert.deepEqual(relay.getProxyHealthConfig!(), { ...construction, intervalMs: 5000 });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getProxyHealthConfig, undefined);
    assert.throws(
      () => relay.reviseProxyHealth!({ intervalMs: 5000 }),
      (err: unknown) =>
        err instanceof Error && /requires a restart/.test((err as Error).message)
    );
  });
});
