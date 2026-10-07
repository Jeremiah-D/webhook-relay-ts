import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ReplayGuard } from "../src/replay.ts";

/** A manually advanced clock for deterministic window tests. */
function fakeClock(startMs: number): { now: () => number; advance: (ms: number) => void } {
  let t = startMs;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

describe("replay guard", () => {
  it("accepts a fresh nonce and rejects its replay", () => {
    const guard = new ReplayGuard();
    assert.deepEqual(guard.check("n1"), { ok: true });
    assert.deepEqual(guard.check("n1"), { ok: false, reason: "duplicate_nonce" });
    assert.deepEqual(guard.check("n2"), { ok: true });
  });

  it("rejects a missing or empty nonce", () => {
    const guard = new ReplayGuard();
    assert.deepEqual(guard.check(undefined), { ok: false, reason: "missing_nonce" });
    assert.deepEqual(guard.check(""), { ok: false, reason: "missing_nonce" });
    // A missing nonce is never recorded, so the next valid check is unaffected.
    assert.deepEqual(guard.check("n1"), { ok: true });
  });

  it("rejects timestamps outside the window on both sides", () => {
    const clock = fakeClock(1_700_000_000_000);
    const guard = new ReplayGuard({ windowSec: 60, nowMs: clock.now });
    assert.deepEqual(guard.check("old", clock.now() - 61_000), {
      ok: false,
      reason: "expired_timestamp",
    });
    assert.deepEqual(guard.check("future", clock.now() + 61_000), {
      ok: false,
      reason: "future_timestamp",
    });
    assert.deepEqual(guard.check("edge-old", clock.now() - 60_000), { ok: true });
    assert.deepEqual(guard.check("edge-future", clock.now() + 60_000), { ok: true });
  });

  it("treats a non-numeric timestamp as out of window", () => {
    const guard = new ReplayGuard();
    assert.deepEqual(guard.check("n1", NaN), { ok: false, reason: "expired_timestamp" });
  });

  it("forgets a nonce once the window passes", () => {
    const clock = fakeClock(1_700_000_000_000);
    const guard = new ReplayGuard({ windowSec: 60, nowMs: clock.now });
    assert.deepEqual(guard.check("n1"), { ok: true });
    assert.deepEqual(guard.check("n1"), { ok: false, reason: "duplicate_nonce" });
    clock.advance(61_000);
    assert.equal(guard.size(), 0);
    // Same nonce is a fresh delivery again after expiry.
    assert.deepEqual(guard.check("n1"), { ok: true });
  });

  it("evicts the oldest nonces beyond maxEntries", () => {
    const guard = new ReplayGuard({ maxEntries: 2 });
    assert.deepEqual(guard.check("a"), { ok: true });
    assert.deepEqual(guard.check("b"), { ok: true });
    assert.equal(guard.size(), 2);
    assert.deepEqual(guard.check("c"), { ok: true });
    assert.equal(guard.size(), 2);
    // "a" was evicted, so it is no longer a duplicate.
    assert.deepEqual(guard.check("a"), { ok: true });
    assert.deepEqual(guard.check("c"), { ok: false, reason: "duplicate_nonce" });
  });

  it("validates its configuration", () => {
    assert.throws(() => new ReplayGuard({ windowSec: 0 }), RangeError);
    assert.throws(() => new ReplayGuard({ windowSec: -5 }), RangeError);
    assert.throws(() => new ReplayGuard({ maxEntries: 0 }), RangeError);
    assert.throws(() => new ReplayGuard({ maxEntries: 1.5 }), RangeError);
  });
});
