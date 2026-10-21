import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  LatencyChangepointDetector,
  LatencyChangepointMonitor,
  type LatencyRegimeChange,
} from "../src/changepoint.ts";

// Deterministic clock: tests set `now` explicitly.
let now = 5_000_000;
const nowMs = () => now;

function feed(d: LatencyChangepointDetector, values: number[]): LatencyRegimeChange[] {
  const events: LatencyRegimeChange[] = [];
  for (const v of values) {
    const e = d.observe(v);
    if (e) events.push(e);
  }
  return events;
}

const repeat = (n: number, v: number): number[] => Array.from({ length: n }, () => v);

describe("LatencyChangepointDetector", () => {
  it("detects a sudden latency increase with before/after snapshots", () => {
    const d = new LatencyChangepointDetector("ep-a", { nowMs });
    now = 5_000_001;
    assert.equal(feed(d, repeat(20, 100)).length, 0);
    const events = feed(d, repeat(30, 500));
    assert.equal(events.length, 1);
    const e = events[0];
    assert.equal(e.endpoint, "ep-a");
    assert.equal(e.direction, "increase");
    assert.equal(e.detectedAtMs, 5_000_001);
    assert.equal(e.before.p50, 100);
    assert.equal(e.before.p95, 100);
    assert.equal(e.after.p50, 500);
    assert.equal(e.after.p95, 500);
  });

  it("detects a sudden latency decrease", () => {
    const d = new LatencyChangepointDetector("ep-b", { nowMs });
    assert.equal(feed(d, repeat(20, 500)).length, 0);
    const events = feed(d, repeat(30, 100));
    assert.equal(events.length, 1);
    assert.equal(events[0].direction, "decrease");
    assert.equal(events[0].before.p50, 500);
    assert.equal(events[0].after.p50, 100);
  });

  it("does not alarm on a stable baseline", () => {
    const d = new LatencyChangepointDetector("ep-c", { nowMs });
    // Small deterministic jitter around the baseline.
    const jittered = Array.from({ length: 300 }, (_, i) => 100 + (i % 3));
    assert.equal(feed(d, jittered).length, 0);
  });

  it("catches a gradual ramp that stays below a fixed SLO threshold", () => {
    // A fixed 400ms SLO alert would never fire on a 100->340 ramp; the
    // changepoint detector fires while after.p95 is still far below it.
    const d = new LatencyChangepointDetector("ep-d", { nowMs });
    assert.equal(feed(d, repeat(15, 100)).length, 0);
    const ramp = Array.from({ length: 40 }, (_, i) => 100 + 6 * (i + 1));
    const events = feed(d, ramp);
    assert.equal(events.length, 1);
    assert.equal(events[0].direction, "increase");
    assert.equal(events[0].before.p50, 100);
    assert.ok(events[0].after.p95 < 400, "alarm fires before any fixed 400ms threshold");
    assert.ok(events[0].after.p50 > events[0].before.p50);
  });

  it("catches a moderate persistent shift below a fixed SLO line", () => {
    const d = new LatencyChangepointDetector("ep-e", { nowMs });
    assert.equal(feed(d, repeat(15, 100)).length, 0);
    const events = feed(d, repeat(60, 250));
    assert.equal(events.length, 1);
    assert.equal(events[0].direction, "increase");
    assert.equal(events[0].before.p50, 100);
    assert.equal(events[0].after.p50, 250);
    assert.ok(events[0].after.p95 < 400);
  });

  it("re-baselines after an alarm and detects a second shift", () => {
    const d = new LatencyChangepointDetector("ep-f", { nowMs });
    assert.equal(feed(d, repeat(20, 100)).length, 0);
    const first = feed(d, repeat(60, 500));
    assert.equal(first.length, 1);
    // New regime is stable: no immediate second alarm.
    assert.equal(feed(d, repeat(60, 500)).length, 0);
    const second = feed(d, repeat(30, 900));
    assert.equal(second.length, 1);
    // The second alarm is measured against the NEW normal (500), not 100.
    assert.equal(second[0].before.p50, 500);
    assert.equal(second[0].after.p50, 900);
  });

  it("warmup baseline uses the median, so one outlier cannot poison it", () => {
    const d = new LatencyChangepointDetector("ep-g", { warmupSamples: 10, nowMs });
    const warmup = [...repeat(9, 100), 10000];
    assert.equal(feed(d, warmup).length, 0);
    // Baseline is 100 (median), not ~1090 (mean): the 100s are normal.
    assert.equal(feed(d, repeat(30, 100)).length, 0);
  });

  it("fires the onLatencyRegimeChange callback with the same event", () => {
    const seen: LatencyRegimeChange[] = [];
    const d = new LatencyChangepointDetector("ep-h", {
      nowMs,
      onLatencyRegimeChange: (e) => seen.push(e),
    });
    feed(d, repeat(20, 100));
    const returned = feed(d, repeat(30, 500));
    assert.equal(seen.length, 1);
    assert.deepEqual(seen[0], returned[0]);
  });

  it("rejects invalid config and samples", () => {
    assert.throws(() => new LatencyChangepointDetector("", { nowMs }), /endpoint/);
    assert.throws(() => new LatencyChangepointDetector("x", { deltaMs: 0 }), /deltaMs/);
    assert.throws(() => new LatencyChangepointDetector("x", { deltaMs: NaN }), /deltaMs/);
    assert.throws(() => new LatencyChangepointDetector("x", { lambda: -1 }), /lambda/);
    assert.throws(() => new LatencyChangepointDetector("x", { warmupSamples: 0 }), /warmupSamples/);
    assert.throws(() => new LatencyChangepointDetector("x", { windowSamples: 1 }), /windowSamples/);
    assert.throws(
      () => new LatencyChangepointDetector("x", { onLatencyRegimeChange: 42 as never }),
      /onLatencyRegimeChange/
    );
    const d = new LatencyChangepointDetector("x", { nowMs });
    assert.throws(() => d.observe(-1), /latencyMs/);
    assert.throws(() => d.observe(NaN), /latencyMs/);
  });

  it("keeps memory bounded (2 * windowSamples samples)", () => {
    const d = new LatencyChangepointDetector("ep-i", { windowSamples: 8, nowMs });
    assert.equal(feed(d, repeat(1000, 100)).length, 0);
    const internals = d as unknown as { samples: unknown[] };
    assert.ok(internals.samples.length <= 16);
  });
});

describe("LatencyChangepointMonitor", () => {
  it("isolates endpoints: a shift on one never alarms another", () => {
    const m = new LatencyChangepointMonitor({ nowMs });
    assert.deepEqual(m.endpoints(), []);
    for (let i = 0; i < 20; i++) {
      assert.equal(m.observe("a", 100), undefined);
      assert.equal(m.observe("b", 100), undefined);
    }
    let aEvents = 0;
    for (let i = 0; i < 30; i++) {
      if (m.observe("a", 500)) aEvents++;
      assert.equal(m.observe("b", 100), undefined);
    }
    assert.equal(aEvents, 1);
    assert.deepEqual(m.endpoints().sort(), ["a", "b"]);
  });
});
