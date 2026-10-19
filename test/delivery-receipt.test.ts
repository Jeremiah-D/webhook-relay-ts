import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import {
  DeliveryReceiptStore,
  type DeliveryReceipt,
} from "../src/delivery-receipt.ts";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function freshDir(): string {
  const d = mkdtempSync(join(tmpdir(), "receipt-test-"));
  tmpDirs.push(d);
  return d;
}

/** Manual timer with single-step control (same harness as the other queue tests). */
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
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, targetUrl: string, extra: Record<string, unknown> = {}) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {}, ...extra };
}

describe("DeliveryReceiptStore", () => {
  it("rejects invalid configuration", () => {
    assert.throws(() => new DeliveryReceiptStore({ maxEntries: 0 }), RangeError);
    assert.throws(() => new DeliveryReceiptStore({ maxEntries: -1 }), RangeError);
    assert.throws(() => new DeliveryReceiptStore({ maxEntries: 1.5 }), RangeError);
    assert.throws(() => new DeliveryReceiptStore({ journalDir: "" }), RangeError);
  });

  it("queries newest-first with endpoint/outcome/time/limit filters", () => {
    let now = 1000;
    const s = new DeliveryReceiptStore({ now: () => now });
    s.record({ deliveryId: "d1", endpoint: URL_A, attempt: 1, latencyMs: 5, outcome: "delivered" });
    now = 2000;
    s.record({ deliveryId: "d2", endpoint: URL_B, attempt: 2, latencyMs: 7, outcome: "dead_letter" });
    now = 3000;
    s.record({ deliveryId: "d3", endpoint: URL_A, attempt: 1, latencyMs: 9, outcome: "delivered" });

    assert.deepEqual(s.query().map((r) => r.deliveryId), ["d3", "d2", "d1"]);
    assert.deepEqual(s.query({ endpoint: URL_A }).map((r) => r.deliveryId), ["d3", "d1"]);
    assert.deepEqual(s.query({ outcome: "dead_letter" }).map((r) => r.deliveryId), ["d2"]);
    assert.deepEqual(s.query({ since: 2000, until: 2000 }).map((r) => r.deliveryId), ["d2"]);
    assert.deepEqual(s.query({ limit: 2 }).map((r) => r.deliveryId), ["d3", "d2"]);
    // Query results are copies: mutating one must not corrupt the store.
    const q = s.query({ limit: 1 });
    q[0].deliveryId = "tampered";
    assert.equal(s.query({ limit: 1 })[0].deliveryId, "d3");
  });

  it("evicts the oldest past maxEntries and counts drops", () => {
    const s = new DeliveryReceiptStore({ maxEntries: 2 });
    for (let i = 0; i < 5; i++) {
      s.record({ deliveryId: `d${i}`, endpoint: URL_A, attempt: 1, latencyMs: 1, outcome: "delivered" });
    }
    assert.deepEqual(s.query().map((r) => r.deliveryId), ["d4", "d3"]);
    assert.deepEqual(s.stats(), { stored: 2, dropped: 3, journalEnabled: false });
  });

  it("exports the ring as JSONL", () => {
    const s = new DeliveryReceiptStore();
    s.record({ deliveryId: "d1", endpoint: URL_A, attempt: 1, latencyMs: 1, outcome: "delivered" });
    s.record({ deliveryId: "d2", endpoint: URL_B, attempt: 3, latencyMs: 2, outcome: "dead_letter" });
    const lines = s.exportJsonl().trim().split("\n");
    assert.equal(lines.length, 2);
    assert.equal((JSON.parse(lines[0]) as DeliveryReceipt).deliveryId, "d1");
    assert.equal((JSON.parse(lines[1]) as DeliveryReceipt).outcome, "dead_letter");
    assert.equal(new DeliveryReceiptStore().exportJsonl(), "");
  });

  it("appends to the JSONL journal and recovers its tail on construction", () => {
    const dir = freshDir();
    let now = 1000;
    const s1 = new DeliveryReceiptStore({ journalDir: dir, maxEntries: 2, now: () => now });
    s1.record({ deliveryId: "d1", endpoint: URL_A, attempt: 1, latencyMs: 1, outcome: "delivered" });
    now = 2000;
    s1.record({ deliveryId: "d2", endpoint: URL_A, attempt: 1, latencyMs: 1, outcome: "delivered" });
    now = 3000;
    s1.record({ deliveryId: "d3", endpoint: URL_A, attempt: 1, latencyMs: 1, outcome: "delivered" });
    const journal = readFileSync(join(dir, "delivery-receipts.jsonl"), "utf8").trim().split("\n");
    assert.equal(journal.length, 3);
    assert.equal((JSON.parse(journal[2]) as DeliveryReceipt).deliveryId, "d3");

    // A new store recovers the journal tail into its ring.
    const s2 = new DeliveryReceiptStore({ journalDir: dir, maxEntries: 2 });
    assert.deepEqual(s2.query().map((r) => r.deliveryId), ["d3", "d2"]);
    assert.equal(s2.stats().journalEnabled, true);
  });

  it("skips corrupt journal lines on recovery", () => {
    const dir = freshDir();
    writeFileSync(
      join(dir, "delivery-receipts.jsonl"),
      `{"deliveryId":"ok","endpoint":"${URL_A}","attempt":1,"latencyMs":1,"outcome":"delivered","at":1}\n` +
        `not json at all\n` +
        `{"deliveryId":123,"outcome":"bogus"}\n`
    );
    const s = new DeliveryReceiptStore({ journalDir: dir });
    assert.deepEqual(s.query().map((r) => r.deliveryId), ["ok"]);
  });
});

describe("RetryQueue delivery receipts", () => {
  it("emits a delivered receipt with attempt, latency, statusCode, trace correlation", async () => {
    let now = 5000;
    const t = manualTimer();
    const seen: DeliveryReceipt[] = [];
    const sender: Sender = async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false });
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryReceipts: {
        now: () => now,
        onDelivered: (r) => seen.push(r),
        onFailed: () => {
          throw new Error("onFailed must not fire for a delivery");
        },
      },
    });
    q.enqueue(item("d1", URL_A, { enqueuedAt: 4000, traceId: "trace-1", tenantId: "acme" }));
    q.start();
    await t.step();
    assert.equal(seen.length, 1);
    const r = seen[0];
    assert.equal(r.deliveryId, "d1");
    assert.equal(r.endpoint, URL_A);
    assert.equal(r.attempt, 1);
    assert.equal(r.latencyMs, 1000); // enqueuedAt=4000 -> terminal at 5000
    assert.equal(r.statusCode, 200);
    assert.equal(r.outcome, "delivered");
    assert.equal(r.at, 5000);
    assert.equal(r.traceId, "trace-1");
    assert.equal(r.tenant, "acme");
    // The receipt is also in the queryable log.
    const logged = q.getDeliveryReceipts();
    assert.equal(logged?.length, 1);
    assert.equal(logged?.[0].deliveryId, "d1");
    q.stop();
  });

  it("emits a dead_letter receipt with the failed attempt's status code", async () => {
    let now = 9000;
    const t = manualTimer();
    const failed: DeliveryReceipt[] = [];
    const sender: Sender = async () => {
      throw Object.assign(new Error("downstream 503"), { statusCode: 503 });
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 1,
      deliveryReceipts: { now: () => now, onFailed: (r) => failed.push(r) },
    });
    q.enqueue(item("f1", URL_B, { enqueuedAt: 8000 }));
    q.start();
    await t.step();
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(failed.length, 1);
    const r = failed[0];
    assert.equal(r.outcome, "dead_letter");
    assert.equal(r.attempt, 1);
    assert.equal(r.statusCode, 503);
    assert.equal(r.latencyMs, 1000);
    assert.equal(r.endpoint, URL_B);
    assert.deepEqual(q.getDeliveryReceipts({ outcome: "dead_letter" })?.length, 1);
    q.stop();
  });

  it("a throwing receipt callback never breaks the delivery path", async () => {
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryReceipts: {
        onDelivered: () => {
          throw new Error("callback bug");
        },
      },
    });
    q.enqueue(item("d1", URL_A));
    q.start();
    await t.step();
    assert.equal(calls, 1); // the delivery still went through
    assert.equal(q.getDeliveryReceipts()?.length, 1); // and was still recorded
    q.stop();
  });

  it("omits statusCode when the sender saw no response", async () => {
    const t = manualTimer();
    const seen: DeliveryReceipt[] = [];
    const sender: Sender = async () => {}; // void: no response to summarize
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryReceipts: { onDelivered: (r) => seen.push(r) },
    });
    q.enqueue(item("d1", URL_A));
    q.start();
    await t.step();
    assert.equal(seen.length, 1);
    assert.ok(!("statusCode" in seen[0]));
    assert.equal(seen[0].outcome, "delivered");
    q.stop();
  });

  it("disabled by default: no receipts, no callbacks, zero overhead", async () => {
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({ sender, setTimer: t.setTimer });
    q.enqueue(item("d1", URL_A));
    q.start();
    await t.step();
    assert.equal(calls, 1);
    assert.equal(q.getDeliveryReceipts(), undefined);
    assert.equal(q.exportDeliveryReceipts(), undefined);
    q.stop();
  });

  it("exports receipts as JSONL", async () => {
    const t = manualTimer();
    const sender: Sender = async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false });
    const q = new RetryQueue({ sender, setTimer: t.setTimer, deliveryReceipts: {} });
    q.enqueue(item("d1", URL_A));
    q.enqueue(item("d2", URL_B));
    q.start();
    await t.step();
    const lines = q.exportDeliveryReceipts()?.trim().split("\n") ?? [];
    assert.equal(lines.length, 2);
    const ids = lines.map((l) => (JSON.parse(l) as DeliveryReceipt).deliveryId).sort();
    assert.deepEqual(ids, ["d1", "d2"]);
    q.stop();
  });
});
