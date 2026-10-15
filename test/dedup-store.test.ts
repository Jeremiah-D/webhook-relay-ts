import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DeliveryDeduplicator,
  InMemoryDedupStore,
  type DedupStore,
} from "../src/dedup.ts";

const URL = "http://localhost:9999/hook";
const HASH = DeliveryDeduplicator.hashPayload(
  Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_1" }))
);

/**
 * Redis-style async store: every op defers a macrotask, like a network
 * hop. Honors the caller-supplied clock — never Date.now().
 */
function makeAsyncStore(backing = new Map<string, number>()): DedupStore {
  return {
    async checkAndRemember(key: string, nowMs: number, windowMs: number): Promise<boolean> {
      await new Promise((r) => setTimeout(r, 0));
      const firstSeen = backing.get(key);
      if (firstSeen !== undefined && nowMs - firstSeen < windowMs) return true;
      await new Promise((r) => setTimeout(r, 0));
      backing.set(key, nowMs);
      return false;
    },
    async size(): Promise<number> {
      await new Promise((r) => setTimeout(r, 0));
      return backing.size;
    },
  };
}

describe("DeliveryDeduplicator with a custom async DedupStore (WR-108)", () => {
  it("suppresses duplicates inside the window and redelivers after expiry", async () => {
    let now = 1_000_000;
    const d = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, store: makeAsyncStore() });
    assert.equal(await d.check(URL, HASH), false);
    assert.equal(await d.check(URL, HASH), true);
    now += 59_999;
    assert.equal(await d.check(URL, HASH), true); // still inside the window
    now += 1; // exactly 60_000 elapsed
    assert.equal(await d.check(URL, HASH), false); // expired: redeliver
    assert.equal(await d.check(URL, HASH), true); // new window suppresses
    const s = await d.stats();
    assert.equal(s.checked, 5);
    assert.equal(s.suppressed, 3);
    assert.equal(s.tracked, 1);
  });

  it("keeps endpoints and payloads isolated", async () => {
    const d = new DeliveryDeduplicator({ windowMs: 60_000, store: makeAsyncStore() });
    const otherHash = DeliveryDeduplicator.hashPayload(Buffer.from("other"));
    assert.equal(await d.check(URL, HASH), false);
    assert.equal(await d.check(URL + "/b", HASH), false); // different endpoint
    assert.equal(await d.check(URL, otherHash), false); // different payload
    assert.equal(await d.check(URL, HASH), true); // original pair still suppressed
    assert.equal((await d.stats()).tracked, 3);
  });

  it("also works with a synchronous custom store", async () => {
    const backing = new Map<string, number>();
    const store: DedupStore = {
      checkAndRemember(key, nowMs, windowMs) {
        const firstSeen = backing.get(key);
        if (firstSeen !== undefined && nowMs - firstSeen < windowMs) return true;
        backing.set(key, nowMs);
        return false;
      },
      size: () => backing.size,
    };
    const d = new DeliveryDeduplicator({ windowMs: 60_000, store });
    assert.equal(await d.check(URL, HASH), false);
    assert.equal(await d.check(URL, HASH), true);
    assert.equal((await d.stats()).tracked, 1);
  });

  it("passes the injected clock through; the store never needs wall-clock", async () => {
    const calls: Array<[nowMs: number, windowMs: number]> = [];
    const store: DedupStore = {
      checkAndRemember(_key, nowMs, windowMs) {
        calls.push([nowMs, windowMs]);
        return false;
      },
      size: () => 0,
    };
    let now = 123_456_789;
    const d = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, store });
    await d.check(URL, HASH);
    now = 987_654_321;
    await d.check(URL, HASH);
    // The exact injected values reach the store — no wall-clock consulted.
    assert.deepEqual(calls, [
      [123_456_789, 60_000],
      [987_654_321, 60_000],
    ]);
  });

  it("a custom store writes no journal files", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-store-nojournal-"));
    const d = new DeliveryDeduplicator({ windowMs: 60_000, store: makeAsyncStore() });
    assert.equal(await d.check(URL, HASH), false);
    assert.equal((await d.stats()).journal, undefined);
    assert.deepEqual(readdirSync(dir), []);
  });

  it("two store instances over one shared backing map suppress across instances", async () => {
    // The multi-instance Redis story: separate deduplicator objects, one
    // shared remote state.
    const shared = new Map<string, number>();
    let now = 0;
    const d1 = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, store: makeAsyncStore(shared) });
    const d2 = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, store: makeAsyncStore(shared) });
    assert.equal(await d1.check(URL, HASH), false); // instance 1 sees it first
    assert.equal(await d2.check(URL, HASH), true); // instance 2 suppresses: shared state
    now = 60_000;
    assert.equal(await d2.check(URL, HASH), false); // window expired for both
    assert.equal(await d1.check(URL, HASH), true); // …and the new window is shared too
  });

  it("rejects store + journalDir together and invalid stores", () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-store-conflict-"));
    assert.throws(
      () => new DeliveryDeduplicator({ store: makeAsyncStore(), journalDir: dir }),
      RangeError
    );
    assert.throws(
      () => new DeliveryDeduplicator({ store: null as unknown as DedupStore }),
      TypeError
    );
    assert.throws(
      () => new DeliveryDeduplicator({ store: "redis://localhost" as unknown as DedupStore }),
      TypeError
    );
    assert.throws(
      () => new DeliveryDeduplicator({ store: 42 as unknown as DedupStore }),
      TypeError
    );
    assert.throws(() => new DeliveryDeduplicator({ store: {} as DedupStore }), TypeError);
    // maxEntries validation still applies with a custom store.
    assert.throws(
      () => new DeliveryDeduplicator({ store: makeAsyncStore(), maxEntries: 0 }),
      RangeError
    );
  });

  it("the default path still journals across restarts", async () => {
    // One small round-trip; deeper journal coverage lives in
    // test/dedup.test.ts ("DeliveryDeduplicator journal (WR-79)").
    const dir = mkdtempSync(join(tmpdir(), "dedup-store-default-journal-"));
    let now = 5_000_000;
    const d1 = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, journalDir: dir });
    assert.equal(await d1.check(URL, HASH), false);
    const d2 = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, journalDir: dir });
    assert.equal((await d2.stats()).journal?.recovered, 1);
    assert.equal(await d2.check(URL, HASH), true);
  });
});

describe("InMemoryDedupStore", () => {
  it("rejects invalid maxEntries like the deduplicator always did", () => {
    assert.throws(() => new InMemoryDedupStore({ maxEntries: 0 }), RangeError);
    assert.throws(() => new InMemoryDedupStore({ maxEntries: 1.5 }), RangeError);
    assert.throws(() => new InMemoryDedupStore({ maxEntries: NaN }), RangeError);
  });

  it("keeps WR-14 semantics: window, oldest-eviction, order refresh", () => {
    const s = new InMemoryDedupStore({ maxEntries: 2 });
    assert.equal(s.checkAndRemember("a", 0, 60_000), false);
    assert.equal(s.checkAndRemember("b", 0, 60_000), false);
    assert.equal(s.checkAndRemember("c", 0, 60_000), false); // evicts "a"
    assert.equal(s.size(), 2);
    assert.equal(s.checkAndRemember("b", 0, 60_000), true); // "b" still tracked
    assert.equal(s.checkAndRemember("a", 0, 60_000), false); // "a" was evicted
    assert.equal(s.checkAndRemember("a", 59_999, 60_000), true); // inside window
    assert.equal(s.checkAndRemember("a", 60_000, 60_000), false); // expired: new window
    assert.equal(s.size(), 1); // lazy expiry also dropped "c" (seen at t=0)
  });
});
