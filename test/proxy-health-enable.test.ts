import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEFAULT_PROXY_HEALTH_CONFIG,
  type ProxyHealthConfig,
} from "../src/proxy-health.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "proxy-health-enable-test-key";
const opToken = "proxy-health-enable-op-token";
const deadProxy = "http://127.0.0.1:1/sick";
const EP = "http://127.0.0.1:9/health";

// Port 1 refuses connections: the CONNECT probe fails fast and
// deterministically, with no stubbed connect (the enable path takes
// the construction defaults, including the real connectViaProxy).
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
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

describe("RelayServer proxy health live enable (WR-479)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "proxy-health-enable-"));
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

  async function waitForAudit(
    audit: AuditLog,
    event: string,
    min: number,
    timeoutMs = 5000
  ): Promise<Record<string, unknown>[]> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = eventsOf(audit, event);
      if (found.length >= min) return found;
      if (Date.now() >= deadline) throw new Error(`timed out waiting for ${min}x ${event}`);
      await sleep(25);
    }
  }

  async function closeRelay(relay: Server): Promise<void> {
    relay.close();
    await new Promise((r) => relay.once("close", r));
  }

  it("first revise enables probing, mounts both getters, audits previous null once, and the first probe round marks the dead proxy unhealthy", async () => {
    const { relay, audit } = makeRelay({ proxies: { [EP]: deadProxy } });
    await listen(relay);
    try {
      assert.equal(relay.getProxyHealthConfig, undefined);
      assert.equal(relay.getProxyHealthStats, undefined);
      // A short interval and threshold 1: the first scheduled round
      // (one interval after the enable, no burst) proves the dead
      // proxy sick. Omitted probeTimeoutMs takes the default.
      const enabled: ProxyHealthConfig = {
        intervalMs: 50,
        probeTimeoutMs: 10000,
        failureThreshold: 1,
      };
      assert.deepEqual(relay.reviseProxyHealth!({ intervalMs: 50, failureThreshold: 1 }), enabled);
      assert.deepEqual(relay.getProxyHealthConfig!(), enabled);
      // The seed list comes from the `proxies` record, exactly as at
      // startup: the dead proxy is tracked with empty counters, and
      // nothing has been probed yet.
      assert.deepEqual(relay.getProxyHealthStats!(), [
        {
          proxyUrl: deadProxy,
          healthy: true,
          success: 0,
          failure: 0,
          consecutiveFailures: 0,
        },
      ]);
      const revised = eventsOf(audit, "proxy_health_revised");
      assert.equal(revised.length, 1, "the enable is audited exactly once");
      assert.equal(revised[0].previous, null);
      assert.deepEqual(revised[0].current, enabled);
      // The first scheduled round fails against the dead proxy and
      // trips the threshold-1 verdict.
      const unhealthy = await waitForAudit(audit, "proxy_unhealthy", 1);
      assert.equal(unhealthy.length, 1);
      assert.equal(unhealthy[0].proxyUrl, deadProxy);
      assert.equal(unhealthy[0].consecutiveFailures, 1);
      const stats = relay.getProxyHealthStats!();
      assert.equal(stats.length, 1);
      assert.equal(stats[0].healthy, false);
      assert.ok(stats[0].failure >= 1);
      assert.ok(stats[0].consecutiveFailures >= 1);
      assert.equal(typeof stats[0].lastProbeAtMs, "number");
      // A later revision merges against the live enabled values
      // (WR-358 chain) and audits with the enabled config as previous.
      assert.deepEqual(relay.reviseProxyHealth!({ intervalMs: 5000 }), {
        ...enabled,
        intervalMs: 5000,
      });
      assert.equal(eventsOf(audit, "proxy_health_revised").length, 2);
      assert.deepEqual(eventsOf(audit, "proxy_health_revised")[1].previous, enabled);
      assert.deepEqual(eventsOf(audit, "proxy_health_revised")[1].current, {
        ...enabled,
        intervalMs: 5000,
      });
    } finally {
      await closeRelay(relay);
    }
  });

  it("illegal and non-object patches throw RangeError, stay unconfigured, and a later legal patch still enables", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    try {
      const bad: unknown[] = [
        { intervalMs: 0 },
        { intervalMs: -1 },
        { intervalMs: Number.NaN },
        { probeTimeoutMs: 0 },
        { failureThreshold: 0 },
        { failureThreshold: 1.5 },
        null,
        "fast",
        [],
      ];
      for (const patch of bad) {
        assert.throws(
          () => relay.reviseProxyHealth!(patch as never),
          RangeError,
          JSON.stringify(patch)
        );
        assert.equal(relay.getProxyHealthConfig, undefined, JSON.stringify(patch));
        assert.equal(relay.getProxyHealthStats, undefined, JSON.stringify(patch));
      }
      assert.equal(eventsOf(audit, "proxy_health_revised").length, 0);
      // A failed enable leaves nothing behind: a legal patch still enables.
      const enabled: ProxyHealthConfig = {
        intervalMs: 5000,
        probeTimeoutMs: 10000,
        failureThreshold: 3,
      };
      assert.deepEqual(relay.reviseProxyHealth!({ intervalMs: 5000 }), enabled);
      assert.deepEqual(relay.getProxyHealthConfig!(), enabled);
      const revised = eventsOf(audit, "proxy_health_revised");
      assert.equal(revised.length, 1);
      assert.equal(revised[0].previous, null);
    } finally {
      await closeRelay(relay);
    }
  });

  it("a same-value patch after enable is a silent no-op; an empty patch is a RangeError again once enabled", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    try {
      const enabled: ProxyHealthConfig = {
        intervalMs: 5000,
        probeTimeoutMs: 10000,
        failureThreshold: 3,
      };
      assert.deepEqual(relay.reviseProxyHealth!({ intervalMs: 5000 }), enabled);
      assert.equal(eventsOf(audit, "proxy_health_revised").length, 1);
      // Landing exactly on the live values audits nothing.
      assert.deepEqual(relay.reviseProxyHealth!({ intervalMs: 5000 }), enabled);
      assert.deepEqual(
        relay.reviseProxyHealth!({ intervalMs: 5000, probeTimeoutMs: 10000, failureThreshold: 3 }),
        enabled
      );
      assert.equal(eventsOf(audit, "proxy_health_revised").length, 1);
      // The empty-patch no-op applies only while unconfigured: once
      // enabled, an empty patch is a RangeError again (WR-358).
      assert.throws(() => relay.reviseProxyHealth!({}), RangeError);
      assert.equal(eventsOf(audit, "proxy_health_revised").length, 1);
      assert.deepEqual(relay.getProxyHealthConfig!(), enabled);
    } finally {
      await closeRelay(relay);
    }
  });

  it("an empty patch on an unconfigured relay is a silent no-op reporting the defaults, and the relay can still be enabled afterwards", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    try {
      assert.equal(relay.getProxyHealthConfig, undefined);
      assert.deepEqual(relay.reviseProxyHealth!({}), { ...DEFAULT_PROXY_HEALTH_CONFIG });
      // Nothing was enabled: no getter, no audit, no probing.
      assert.equal(relay.getProxyHealthConfig, undefined);
      assert.equal(relay.getProxyHealthStats, undefined);
      assert.equal(eventsOf(audit, "proxy_health_revised").length, 0);
      // The no-op left no state: a real patch still enables.
      const enabled: ProxyHealthConfig = {
        intervalMs: 5000,
        probeTimeoutMs: 10000,
        failureThreshold: 3,
      };
      assert.deepEqual(relay.reviseProxyHealth!({ intervalMs: 5000 }), enabled);
      assert.deepEqual(relay.getProxyHealthConfig!(), enabled);
      const revised = eventsOf(audit, "proxy_health_revised");
      assert.equal(revised.length, 1);
      assert.equal(revised[0].previous, null);
    } finally {
      await closeRelay(relay);
    }
  });

  it("a fresh relay (restart) is unconfigured again", async () => {
    const first = makeRelay();
    await listen(first.relay);
    try {
      first.relay.reviseProxyHealth!({ intervalMs: 5000 });
      assert.deepEqual(first.relay.getProxyHealthConfig!(), {
        intervalMs: 5000,
        probeTimeoutMs: 10000,
        failureThreshold: 3,
      });
    } finally {
      await closeRelay(first.relay);
    }
    const restarted = makeRelay();
    await listen(restarted.relay);
    try {
      assert.equal(restarted.relay.getProxyHealthConfig, undefined);
      assert.equal(restarted.relay.getProxyHealthStats, undefined);
    } finally {
      await closeRelay(restarted.relay);
    }
  });
});
