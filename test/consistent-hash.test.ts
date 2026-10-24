import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  type Sender,
} from "../src/retry.ts";
import {
  ConsistentHashDispatcher,
  assertValidConsistentHashConfig,
  assertValidConsistentHashTargets,
  DEFAULT_VIRTUAL_NODES,
} from "../src/consistent-hash.ts";

const endpointUrl = "http://127.0.0.1:9931/hook";
const targetA = "http://127.0.0.1:9932/a";
const targetB = "http://127.0.0.1:9933/b";
const targetC = "http://127.0.0.1:9934/c";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
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
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function item(id: string, targetUrl: string = endpointUrl, tenantId?: string) {
  return { id, payload: Buffer.from("hello"), targetUrl, headers: {}, ...(tenantId === undefined ? {} : { tenantId }) };
}

function cfgABC(extra: Record<string, unknown> = {}) {
  return {
    [endpointUrl]: {
      targets: [{ targetUrl: targetA }, { targetUrl: targetB }, { targetUrl: targetC }],
      ...extra,
    },
  };
}

describe("consistent-hash config validation", () => {
  it("accepts a minimal valid config", () => {
    assertValidConsistentHashConfig({
      [endpointUrl]: { targets: [{ targetUrl: targetA }] },
    });
  });

  it("rejects a non-record config", () => {
    assert.throws(() => assertValidConsistentHashConfig(null as never), RangeError);
    assert.throws(() => assertValidConsistentHashConfig([] as never), RangeError);
    assert.throws(() => assertValidConsistentHashConfig("x" as never), RangeError);
  });

  it("rejects an empty endpoint key", () => {
    assert.throws(
      () => assertValidConsistentHashConfig({ "": { targets: [{ targetUrl: targetA }] } }),
      RangeError
    );
  });

  it("rejects empty / non-array / duplicate / empty-url target lists", () => {
    assert.throws(() => assertValidConsistentHashTargets([]), RangeError);
    assert.throws(() => assertValidConsistentHashTargets("nope"), RangeError);
    assert.throws(
      () => assertValidConsistentHashTargets([{ targetUrl: targetA }, { targetUrl: targetA }]),
      RangeError
    );
    assert.throws(() => assertValidConsistentHashTargets([{ targetUrl: "" }]), RangeError);
    assert.throws(() => assertValidConsistentHashTargets([{ targetUrl: 42 }]), RangeError);
  });

  it("rejects illegal virtualNodes, accepts the bounds", () => {
    for (const bad of [0, -1, 1.5, 4097, NaN, Infinity]) {
      assert.throws(
        () => assertValidConsistentHashConfig(cfgABC({ virtualNodes: bad })),
        RangeError,
        `virtualNodes=${String(bad)}`
      );
    }
    assertValidConsistentHashConfig(cfgABC({ virtualNodes: 1 }));
    assertValidConsistentHashConfig(cfgABC({ virtualNodes: 4096 }));
  });

  it("rejects illegal stickyKey, accepts tenant/endpoint/event", () => {
    for (const bad of [[], ["bogus"], ["tenant", "tenant"], "tenant", [42]]) {
      assert.throws(
        () => assertValidConsistentHashConfig(cfgABC({ stickyKey: bad })),
        RangeError,
        `stickyKey=${JSON.stringify(bad)}`
      );
    }
    assertValidConsistentHashConfig(cfgABC({ stickyKey: ["event"] }));
    assertValidConsistentHashConfig(cfgABC({ stickyKey: ["tenant", "endpoint", "event"] }));
  });

  it("rejects illegal failureThreshold / recoveryIntervalMs", () => {
    assert.throws(
      () => assertValidConsistentHashConfig(cfgABC({ failureThreshold: 0 })),
      RangeError
    );
    assert.throws(
      () => assertValidConsistentHashConfig(cfgABC({ failureThreshold: 1.5 })),
      RangeError
    );
    assert.throws(
      () => assertValidConsistentHashConfig(cfgABC({ recoveryIntervalMs: 0 })),
      RangeError
    );
    assert.throws(
      () => assertValidConsistentHashConfig(cfgABC({ recoveryIntervalMs: -10 })),
      RangeError
    );
  });
});

describe("consistent-hash stickiness", () => {
  it("routes the same (tenant, endpoint) key to the same target every time", () => {
    const d = new ConsistentHashDispatcher(cfgABC());
    const first = d.resolveTarget(endpointUrl, { tenant: "acme", eventId: "e-1" });
    for (let i = 0; i < 50; i++) {
      assert.equal(
        d.resolveTarget(endpointUrl, { tenant: "acme", eventId: `e-${i}` }),
        first,
        "default stickyKey ignores the event id"
      );
    }
  });

  it("spreads distinct tenants across targets and is deterministic across dispatchers", () => {
    const d1 = new ConsistentHashDispatcher(cfgABC());
    const d2 = new ConsistentHashDispatcher(cfgABC());
    const owners = new Map<string, number>();
    for (let i = 0; i < 60; i++) {
      const tenant = `tenant-${i}`;
      const t1 = d1.resolveTarget(endpointUrl, { tenant, eventId: "x" });
      const t2 = d2.resolveTarget(endpointUrl, { tenant, eventId: "x" });
      assert.equal(t1, t2, "same key must resolve identically on a fresh ring");
      owners.set(t1!, (owners.get(t1!) ?? 0) + 1);
    }
    // 60 keys over 3 targets with 128 vnodes each: every target owns some.
    assert.equal(owners.size, 3);
    for (const [, n] of owners) assert.ok(n >= 5, `every target should own several keys, got ${n}`);
  });

  it("the default tenant hashes as a stable key too", () => {
    const d = new ConsistentHashDispatcher(cfgABC());
    const a = d.resolveTarget(endpointUrl, { eventId: "e-1" });
    const b = d.resolveTarget(endpointUrl, { eventId: "e-2" });
    assert.equal(a, b);
  });

  it("stickyKey ['event'] keys on the event id: same event sticks, different events spread", () => {
    const d = new ConsistentHashDispatcher(cfgABC({ stickyKey: ["event"] }));
    const first = d.resolveTarget(endpointUrl, { tenant: "t-a", eventId: "evt-1" });
    const again = d.resolveTarget(endpointUrl, { tenant: "t-b", eventId: "evt-1" });
    assert.equal(first, again, "tenant must not affect an event-only key");
    const owners = new Set<string>();
    for (let i = 0; i < 60; i++) {
      owners.add(d.resolveTarget(endpointUrl, { eventId: `evt-${i}` })!);
    }
    assert.equal(owners.size, 3);
  });

  it("returns undefined for an unconfigured endpoint", () => {
    const d = new ConsistentHashDispatcher(cfgABC());
    assert.equal(d.resolveTarget("http://127.0.0.1:9999/other", { tenant: "t", eventId: "e" }), undefined);
  });

  it("hasEndpoint reflects the config", () => {
    const d = new ConsistentHashDispatcher(cfgABC());
    assert.ok(d.hasEndpoint(endpointUrl));
    assert.ok(!d.hasEndpoint("http://127.0.0.1:9999/other"));
  });
});

describe("consistent-hash minimal migration", () => {
  it("removing a target only remigrates that target's keys", () => {
    const d = new ConsistentHashDispatcher(cfgABC());
    const before = new Map<string, string>();
    for (let i = 0; i < 2000; i++) {
      before.set(`t-${i}`, d.resolveTarget(endpointUrl, { tenant: `t-${i}`, eventId: "e" })!);
    }
    const ownedByC = [...before.values()].filter((t) => t === targetC).length;
    assert.ok(ownedByC > 0, "sanity: C must own some keys before removal");

    d.setTargets(endpointUrl, [{ targetUrl: targetA }, { targetUrl: targetB }]);
    let changed = 0;
    for (const [tenant, oldTarget] of before) {
      const now = d.resolveTarget(endpointUrl, { tenant, eventId: "e" })!;
      if (now !== oldTarget) {
        changed++;
        // Only C's keys may move — A and B keep every key they owned.
        assert.equal(oldTarget, targetC, `key ${tenant} migrated off a surviving target`);
      } else {
        assert.ok(now === targetA || now === targetB);
      }
    }
    assert.equal(changed, ownedByC, "exactly C's keys remigrate — nothing else moves");

    const stats = d.getConsistentHashStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].ringVersion, 2);
    assert.equal(stats[0].migrations, 1);
  });

  it("adding a target only steals keys from its ring arcs", () => {
    const d = new ConsistentHashDispatcher({
      [endpointUrl]: { targets: [{ targetUrl: targetA }, { targetUrl: targetB }] },
    });
    const before = new Map<string, string>();
    for (let i = 0; i < 2000; i++) {
      before.set(`t-${i}`, d.resolveTarget(endpointUrl, { tenant: `t-${i}`, eventId: "e" })!);
    }
    d.setTargets(endpointUrl, [
      { targetUrl: targetA },
      { targetUrl: targetB },
      { targetUrl: targetC },
    ]);
    let changed = 0;
    for (const [tenant, oldTarget] of before) {
      const now = d.resolveTarget(endpointUrl, { tenant, eventId: "e" })!;
      if (now !== oldTarget) {
        changed++;
        assert.equal(now, targetC, "only C may steal keys on add");
      }
    }
    assert.ok(changed > 0 && changed < 2000, `adding C must move some but not all keys, moved ${changed}`);
    assert.equal(d.getConsistentHashStats()[0].migrations, 1);
  });

  it("a no-op membership change bumps the version but not the migration count", () => {
    const d = new ConsistentHashDispatcher(cfgABC());
    d.resolveTarget(endpointUrl, { tenant: "t", eventId: "e" });
    d.setTargets(endpointUrl, [
      { targetUrl: targetA },
      { targetUrl: targetB },
      { targetUrl: targetC },
    ]);
    const stats = d.getConsistentHashStats()[0];
    assert.equal(stats.ringVersion, 2);
    assert.equal(stats.migrations, 0);
  });

  it("setTargets validates before applying and rejects unknown endpoints", () => {
    const d = new ConsistentHashDispatcher(cfgABC());
    assert.throws(() => d.setTargets(endpointUrl, []), RangeError);
    assert.throws(
      () => d.setTargets(endpointUrl, [{ targetUrl: targetA }, { targetUrl: targetA }]),
      RangeError
    );
    // The failed applies left the ring untouched.
    assert.equal(d.getConsistentHashStats()[0].ringVersion, 1);
    assert.throws(() => d.setTargets("http://127.0.0.1:9999/nope", [{ targetUrl: targetA }]), RangeError);
  });
});

describe("consistent-hash health filtering", () => {
  it("excludes breaker-open targets and retains half_open ones", () => {
    const states = new Map<string, "closed" | "open" | "half_open">();
    const d = new ConsistentHashDispatcher(cfgABC(), {
      circuitState: (t) => states.get(t) ?? "closed",
    });
    // Find a key owned by A, then open A's breaker.
    let key: string | undefined;
    for (let i = 0; i < 500; i++) {
      const t = `k-${i}`;
      if (d.resolveTarget(endpointUrl, { tenant: t, eventId: "e" }) === targetA) {
        key = t;
        break;
      }
    }
    assert.ok(key !== undefined);
    states.set(targetA, "open");
    const rerouted = d.resolveTarget(endpointUrl, { tenant: key, eventId: "e" });
    assert.ok(rerouted === targetB || rerouted === targetC, "open target must not serve its keys");
    // Half-open is retained: the breaker's probe delivery must run.
    states.set(targetA, "half_open");
    assert.equal(d.resolveTarget(endpointUrl, { tenant: key, eventId: "e" }), targetA);
  });

  it("excludes targets after failureThreshold consecutive failures, recovers after the interval", () => {
    let now = 1_000_000;
    const d = new ConsistentHashDispatcher(cfgABC({ failureThreshold: 2, recoveryIntervalMs: 30_000 }), {
      now: () => now,
    });
    let key: string | undefined;
    for (let i = 0; i < 500; i++) {
      const t = `k-${i}`;
      if (d.resolveTarget(endpointUrl, { tenant: t, eventId: "e" }) === targetB) {
        key = t;
        break;
      }
    }
    assert.ok(key !== undefined);
    d.recordOutcome(endpointUrl, targetB, false);
    assert.equal(d.resolveTarget(endpointUrl, { tenant: key, eventId: "e" }), targetB, "one failure is below threshold");
    d.recordOutcome(endpointUrl, targetB, false);
    const rerouted = d.resolveTarget(endpointUrl, { tenant: key, eventId: "e" });
    assert.ok(rerouted !== targetB, "threshold reached: target leaves the ring");
    // Still out before the recovery interval elapses.
    now += 29_999;
    assert.notEqual(d.resolveTarget(endpointUrl, { tenant: key, eventId: "e" }), targetB);
    // The recovery canary: eligible again after the interval.
    now += 1;
    assert.equal(d.resolveTarget(endpointUrl, { tenant: key, eventId: "e" }), targetB);
    // A success resets the counter.
    d.recordOutcome(endpointUrl, targetB, true);
    const stats = d.getConsistentHashStats()[0];
    assert.equal(stats.targets.find((t) => t.targetUrl === targetB)!.consecutiveFailures, 0);
  });

  it("pins to the first target when every target is unhealthy", () => {
    const d = new ConsistentHashDispatcher(cfgABC({ failureThreshold: 1 }), { now: () => 0 });
    for (const t of [targetA, targetB, targetC]) d.recordOutcome(endpointUrl, t, false);
    const stats = d.getConsistentHashStats()[0];
    assert.ok(stats.targets.every((t) => !t.healthy));
    for (let i = 0; i < 20; i++) {
      assert.equal(d.resolveTarget(endpointUrl, { tenant: `t-${i}`, eventId: "e" }), targetA);
    }
  });

  it("ignores outcomes for unknown endpoints or removed targets", () => {
    const d = new ConsistentHashDispatcher(cfgABC());
    d.recordOutcome("http://127.0.0.1:9999/nope", targetA, false);
    d.recordOutcome(endpointUrl, "http://127.0.0.1:9999/gone", false);
    d.setTargets(endpointUrl, [{ targetUrl: targetA }]);
    d.recordOutcome(endpointUrl, targetB, false); // removed target: ignored
    const stats = d.getConsistentHashStats()[0];
    assert.equal(stats.targets.length, 1);
    assert.equal(stats.targets[0].consecutiveFailures, 0);
  });
});

describe("RetryQueue consistent-hash integration", () => {
  it("routes sticky per tenant, reports stats and metrics", async () => {
    const timer = manualTimer();
    const seen: Array<{ id: string; target: string }> = [];
    const sender: Sender = async (item) => {
      seen.push({ id: item.id, target: item.targetUrl });
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      setTimer: timer.setTimer,
      consistentHash: cfgABC(),
      consistentHashNow: () => 0,
    });
    q.start();
    // Two deliveries for tenant "acme" must land on the same target;
    // other tenants spread.
    q.enqueue(item("acme-1", endpointUrl, "acme"));
    q.enqueue(item("acme-2", endpointUrl, "acme"));
    for (let i = 0; i < 12; i++) q.enqueue(item(`t-${i}`, endpointUrl, `tenant-${i}`));
    await timer.run();

    const byId = new Map(seen.map((s) => [s.id, s.target]));
    assert.equal(byId.get("acme-1"), byId.get("acme-2"), "same tenant must be sticky");
    const stats = q.getConsistentHashStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, endpointUrl);
    assert.equal(stats[0].ringVersion, 1);
    assert.equal(stats[0].migrations, 0);
    const total = stats[0].targets.reduce((n, t) => n + t.dispatched, 0);
    assert.equal(total, seen.length);
    const exposition = q.renderMetrics();
    for (const t of stats[0].targets) {
      if (t.dispatched > 0) {
        assert.match(
          exposition,
          new RegExp(
            `relay_consistent_hash_dispatch_total\\{endpoint="${endpointUrl}",target="${t.targetUrl}"\\} ${t.dispatched}`
          )
        );
      }
    }
    q.stop();
  });

  it("omits relay_consistent_hash_dispatch_total when the mode is not in use", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.ok(!q.renderMetrics().includes("relay_consistent_hash_dispatch_total"));
    assert.deepEqual(q.getConsistentHashStats(), []);
  });

  it("rejects mixing consistent-hash with weighted / failover / weightTuning", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          consistentHash: cfgABC(),
          weighted: { [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 1 }] } },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          consistentHash: cfgABC(),
          failover: { [endpointUrl]: { standbys: [targetA, targetB] } },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          consistentHash: cfgABC(),
          weighted: { [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 1 }] } },
          weightTuning: { retuneIntervalMs: 1000 },
        }),
      RangeError
    );
    // Different endpoints may still use different modes.
    const q = new RetryQueue({
      sender: async () => {},
      consistentHash: cfgABC(),
      weighted: { "http://127.0.0.1:9939/other": { targets: [{ targetUrl: targetA, weight: 1 }] } },
    });
    assert.equal(q.getConsistentHashStats().length, 1);
    q.stop();
  });

  it("rejects an invalid consistent-hash config at construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          consistentHash: cfgABC({ virtualNodes: 0 }),
        }),
      RangeError
    );
  });

  it("updateEndpointConfig replaces the ring membership at runtime", () => {
    const q = new RetryQueue({
      sender: async () => {},
      consistentHash: cfgABC(),
    });
    q.updateEndpointConfig(endpointUrl, {
      consistentHash: { targets: [{ targetUrl: targetA }, { targetUrl: targetB }] },
    });
    const stats = q.getConsistentHashStats()[0];
    assert.equal(stats.ringVersion, 2);
    assert.equal(stats.migrations, 1);
    assert.deepEqual(
      stats.targets.map((t) => t.targetUrl),
      [targetA, targetB]
    );
    // Patching an endpoint without consistent-hash routing fails fast.
    assert.throws(
      () =>
        q.updateEndpointConfig("http://127.0.0.1:9939/other", {
          consistentHash: { targets: [{ targetUrl: targetA }] },
        }),
      RangeError
    );
    // An invalid patch leaves the running ring untouched.
    assert.throws(
      () =>
        q.updateEndpointConfig(endpointUrl, {
          consistentHash: { targets: [] },
        }),
      RangeError
    );
    assert.equal(q.getConsistentHashStats()[0].ringVersion, 2);
    q.stop();
  });

  it("reports a failed target's outcome back to the ring", async () => {
    const timer = manualTimer();
    let failA = true;
    const sender: Sender = async (item) => {
      // A plain thrown Error classifies as a retryable delivery failure.
      if (item.targetUrl === targetA && failA) throw new Error("boom");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 5,
      setTimer: timer.setTimer,
      consistentHash: cfgABC({ failureThreshold: 1 }),
      consistentHashNow: () => 0,
    });
    q.start();
    // Find a tenant owned by A; its delivery fails once, then the ring
    // must route the retry away from A.
    const probe = new ConsistentHashDispatcher(cfgABC());
    let key: string | undefined;
    for (let i = 0; i < 200; i++) {
      const t = `fail-${i}`;
      if (probe.resolveTarget(endpointUrl, { tenant: t, eventId: "e" }) === targetA) {
        key = t;
        break;
      }
    }
    assert.ok(key !== undefined);
    q.enqueue(item("retry-1", endpointUrl, key));
    await timer.run();
    const stats = q.getConsistentHashStats()[0];
    const a = stats.targets.find((t) => t.targetUrl === targetA)!;
    assert.ok(a.consecutiveFailures >= 1, "the failed delivery must feed the ring's health counter");
    assert.ok(!a.healthy, "A must be out of the ring after one failure at threshold 1");
    q.stop();
  });
});

describe("consistent-hash defaults", () => {
  it("defaults to 128 virtual nodes per target", () => {
    const d = new ConsistentHashDispatcher(cfgABC());
    const stats = d.getConsistentHashStats()[0];
    assert.ok(stats.targets.every((t) => t.virtualNodes === DEFAULT_VIRTUAL_NODES));
    assert.equal(DEFAULT_VIRTUAL_NODES, 128);
  });
});
