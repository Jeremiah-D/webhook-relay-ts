import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { InboundRateLimiter } from "../src/ratelimit.ts";
import { buildHealthSummary } from "../src/health-summary.ts";

// WR-136: adaptive inbound rate limiting. The full per-endpoint budget is 4
// req/s, the floor is 1 req/s, the throttle engages at depth 20 and
// releases below depth 10.
const FULL = 4;
const MIN = 1;
const LOW = 10;
const HIGH = 20;
const ADAPTIVE = {
  minPerEndpointPerSecond: MIN,
  queueDepthHigh: HIGH,
  queueDepthLow: LOW,
};

/** A limiter with a mutable depth source and a controllable clock. */
function adaptiveLimiter(state: { depth: number }, nowRef?: { now: number }) {
  return new InboundRateLimiter(
    {
      perEndpointPerSecond: FULL,
      now: nowRef !== undefined ? () => nowRef.now : undefined,
      adaptiveInbound: ADAPTIVE,
    },
    () => state.depth
  );
}

describe("inbound-adaptive: disabled by default", () => {
  it("behaves exactly like the WR-22 original when adaptiveInbound is unset", () => {
    let now = 0;
    const rl = new InboundRateLimiter({ perEndpointPerSecond: FULL, now: () => now });
    for (let i = 0; i < FULL; i++) assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
    const v = rl.take("1.1.1.1", "ep");
    assert.equal(v.ok, false);
    if (!v.ok) {
      assert.equal(v.dimension, "endpoint");
      assert.equal(v.retryAfterMs, 250); // 1 token short at 4/sec
    }
    assert.deepEqual(rl.adaptiveStats(), { enabled: false, throttled: false });
  });

  it("never calls a depthProvider when adaptive is off", () => {
    const rl = new InboundRateLimiter({ perEndpointPerSecond: FULL }, () => {
      throw new Error("must not be called");
    });
    assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
    assert.deepEqual(rl.adaptiveStats(), { enabled: false, throttled: false });
  });

  it("a missing depthProvider with adaptive on reads depth as 0 (no throttle)", () => {
    const rl = new InboundRateLimiter({ perEndpointPerSecond: FULL, adaptiveInbound: ADAPTIVE });
    const s = rl.adaptiveStats();
    assert.equal(s.enabled, true);
    assert.equal(s.throttled, false);
    assert.equal(s.effectivePerEndpointPerSecond, FULL);
    assert.equal(s.pendingDepth, 0);
  });
});

describe("inbound-adaptive: throttle engagement", () => {
  it("keeps the full budget below the low mark", () => {
    const state = { depth: 0 };
    const rl = adaptiveLimiter(state);
    const s = rl.adaptiveStats();
    assert.equal(s.enabled, true);
    assert.equal(s.throttled, false);
    assert.equal(s.effectivePerEndpointPerSecond, FULL);
    assert.equal(s.pendingDepth, 0);
    for (let i = 0; i < FULL; i++) assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
    assert.equal(rl.take("1.1.1.1", "ep").ok, false);
  });

  it("engages at queueDepthHigh and pins the floor at/above it", () => {
    const state = { depth: HIGH };
    const rl = adaptiveLimiter(state);
    const s = rl.adaptiveStats();
    assert.equal(s.throttled, true);
    assert.equal(s.effectivePerEndpointPerSecond, MIN);
    assert.equal(s.pendingDepth, HIGH);
    // Depth far past high stays pinned at the floor, never below it.
    state.depth = 1000;
    assert.equal(rl.adaptiveStats().effectivePerEndpointPerSecond, MIN);
  });

  it("scales the effective budget linearly between low and high while throttled", () => {
    const state = { depth: HIGH };
    const rl = adaptiveLimiter(state);
    assert.equal(rl.adaptiveStats().throttled, true);
    // Mid-band: 4 - (4-1) * (15-10)/(20-10) = 2.5.
    state.depth = 15;
    assert.equal(rl.adaptiveStats().effectivePerEndpointPerSecond, 2.5);
    // A fresh endpoint key gets exactly 2.5 tokens of budget.
    assert.deepEqual(rl.take("1.1.1.1", "ep2"), { ok: true });
    assert.deepEqual(rl.take("1.1.1.1", "ep2"), { ok: true });
    const v = rl.take("1.1.1.1", "ep2");
    assert.equal(v.ok, false);
    if (!v.ok) {
      assert.equal(v.dimension, "endpoint");
      assert.equal(v.retryAfterMs, 200); // 0.5 tokens short at 2.5/sec
    }
  });

  it("releases the full budget only below queueDepthLow (hysteresis)", () => {
    const state = { depth: HIGH };
    const rl = adaptiveLimiter(state);
    assert.equal(rl.adaptiveStats().throttled, true);
    // Falling into the band keeps the throttle: no flap at the threshold.
    state.depth = 15;
    let s = rl.adaptiveStats();
    assert.equal(s.throttled, true);
    assert.equal(s.effectivePerEndpointPerSecond, 2.5);
    // Exactly at the low mark is still throttled — release needs *below*.
    state.depth = LOW;
    s = rl.adaptiveStats();
    assert.equal(s.throttled, true);
    assert.equal(s.effectivePerEndpointPerSecond, FULL);
    // Below the low mark the full budget is back.
    state.depth = LOW - 1;
    s = rl.adaptiveStats();
    assert.equal(s.throttled, false);
    assert.equal(s.effectivePerEndpointPerSecond, FULL);
    assert.equal(s.pendingDepth, LOW - 1);
  });

  it("rising through the band keeps the full budget until the high mark", () => {
    const state = { depth: 0 };
    const rl = adaptiveLimiter(state);
    state.depth = 15;
    const s = rl.adaptiveStats();
    assert.equal(s.throttled, false);
    assert.equal(s.effectivePerEndpointPerSecond, FULL);
    // A mid-band arrival still gets the full budget (no premature cut).
    for (let i = 0; i < FULL; i++) assert.deepEqual(rl.take("2.2.2.2", "ep"), { ok: true });
    assert.equal(rl.take("2.2.2.2", "ep").ok, false);
    // Touching the high mark engages.
    state.depth = HIGH;
    assert.equal(rl.adaptiveStats().throttled, true);
  });
});

describe("inbound-adaptive: retry-after stays honest", () => {
  it("computes retryAfterMs against the effective (throttled) budget", () => {
    const state = { depth: HIGH };
    const nowRef = { now: 0 };
    const rl = adaptiveLimiter(state, nowRef);
    assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true }); // the single token at 1/sec
    const v = rl.take("1.1.1.1", "ep");
    assert.equal(v.ok, false);
    if (!v.ok) {
      assert.equal(v.dimension, "endpoint");
      assert.equal(v.retryAfterMs, 1000); // 1 token short at the throttled 1/sec
    }
    // And the budget really is 1/sec: the token returns after a second.
    nowRef.now += 1000;
    assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
  });
});

describe("inbound-adaptive: config validation", () => {
  const good = { perEndpointPerSecond: FULL, adaptiveInbound: ADAPTIVE };

  it("rejects a non-positive floor", () => {
    assert.throws(
      () => new InboundRateLimiter({ ...good, adaptiveInbound: { ...ADAPTIVE, minPerEndpointPerSecond: 0 } }),
      RangeError
    );
    assert.throws(
      () => new InboundRateLimiter({ ...good, adaptiveInbound: { ...ADAPTIVE, minPerEndpointPerSecond: -2 } }),
      RangeError
    );
  });

  it("rejects a floor above the configured per-endpoint budget", () => {
    assert.throws(
      () =>
        new InboundRateLimiter({
          ...good,
          adaptiveInbound: { ...ADAPTIVE, minPerEndpointPerSecond: FULL + 1 },
        }),
      RangeError
    );
  });

  it("rejects a high mark that is not strictly above the low mark", () => {
    assert.throws(
      () => new InboundRateLimiter({ ...good, adaptiveInbound: { ...ADAPTIVE, queueDepthHigh: LOW } }),
      RangeError
    );
    assert.throws(
      () =>
        new InboundRateLimiter({
          ...good,
          adaptiveInbound: { ...ADAPTIVE, queueDepthHigh: LOW - 1 },
        }),
      RangeError
    );
  });

  it("rejects a negative low mark and non-finite marks", () => {
    assert.throws(
      () => new InboundRateLimiter({ ...good, adaptiveInbound: { ...ADAPTIVE, queueDepthLow: -1 } }),
      RangeError
    );
    assert.throws(
      () =>
        new InboundRateLimiter({
          ...good,
          adaptiveInbound: { ...ADAPTIVE, queueDepthHigh: Number.POSITIVE_INFINITY },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new InboundRateLimiter({
          ...good,
          adaptiveInbound: { ...ADAPTIVE, queueDepthLow: Number.NaN },
        }),
      RangeError
    );
  });

  it("rejects adaptive config without a per-endpoint budget to adapt", () => {
    assert.throws(
      () => new InboundRateLimiter({ perIpPerSecond: 10, adaptiveInbound: ADAPTIVE }),
      /perEndpointPerSecond/
    );
  });
});

describe("inbound-adaptive: operator observability", () => {
  it("health summary omits inboundRateLimit when the adaptive limiter is off", () => {
    const summary = buildHealthSummary({ circuits: [], quotas: [], probes: [] });
    assert.equal("inboundRateLimit" in summary, false);
  });

  it("health summary carries the throttle snapshot when enabled", () => {
    const summary = buildHealthSummary({
      circuits: [],
      quotas: [],
      probes: [],
      inboundRateLimit: { throttled: true, effectivePerEndpointPerSecond: 1, pendingDepth: 20 },
    });
    assert.deepEqual(summary.inboundRateLimit, {
      throttled: true,
      effectivePerEndpointPerSecond: 1,
      pendingDepth: 20,
    });
  });
});
