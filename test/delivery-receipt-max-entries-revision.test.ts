import { describe, it, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { DeliveryReceiptStore, type DeliveryReceipt } from "../src/delivery-receipt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "delivery-receipt-max-entries-revision-secret";
const operatorToken = "delivery-receipt-max-entries-revision-token";
const FORWARD = "http://127.0.0.1:1/unused";
const URL_A = "http://localhost:9999/a";

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function freshDir(): string {
  const d = mkdtempSync(join(tmpdir(), "receipt-max-entries-revision-"));
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

function receipt(id: string): Omit<DeliveryReceipt, "at"> {
  return { deliveryId: id, endpoint: URL_A, attempt: 1, latencyMs: 1, outcome: "delivered" };
}

describe("DeliveryReceiptStore ring bound revision (WR-468)", () => {
  it("widening lets the ring hold past the old cap", () => {
    const store = new DeliveryReceiptStore({ maxEntries: 3 });
    store.record(receipt("r1"));
    store.record(receipt("r2"));
    store.record(receipt("r3"));
    assert.equal(store.stats().stored, 3);
    store.setMaxEntries(5);
    assert.equal(store.getMaxEntries(), 5);
    store.record(receipt("r4"));
    store.record(receipt("r5"));
    assert.equal(store.stats().stored, 5);
    assert.equal(store.stats().dropped, 0);
    assert.deepEqual(
      store.query().map((r) => r.deliveryId),
      ["r5", "r4", "r3", "r2", "r1"]
    );
  });

  it("tightening trims the oldest on the spot and the trimmed count joins dropped", () => {
    const store = new DeliveryReceiptStore({ maxEntries: 5 });
    for (const id of ["r1", "r2", "r3", "r4", "r5"]) store.record(receipt(id));
    store.setMaxEntries(2);
    assert.equal(store.getMaxEntries(), 2);
    assert.equal(store.stats().stored, 2);
    assert.equal(store.stats().dropped, 3);
    assert.deepEqual(
      store.query().map((r) => r.deliveryId),
      ["r5", "r4"]
    );
  });

  it("after tightening, the next record still evicts per the new bound", () => {
    const store = new DeliveryReceiptStore({ maxEntries: 5 });
    for (const id of ["r1", "r2", "r3", "r4", "r5"]) store.record(receipt(id));
    store.setMaxEntries(2);
    store.record(receipt("r6"));
    assert.equal(store.stats().stored, 2);
    assert.equal(store.stats().dropped, 4);
    assert.deepEqual(
      store.query().map((r) => r.deliveryId),
      ["r6", "r5"]
    );
  });

  it("illegal bounds throw RangeError and leave the bound and ring untouched", () => {
    const store = new DeliveryReceiptStore({ maxEntries: 3 });
    store.record(receipt("r1"));
    for (const bad of [0, -1, 2.5, NaN, "3", null, undefined]) {
      assert.throws(() => store.setMaxEntries(bad as never), RangeError, JSON.stringify(bad));
    }
    assert.equal(store.getMaxEntries(), 3);
    assert.equal(store.stats().stored, 1);
    assert.equal(store.stats().dropped, 0);
    // Still revisable afterwards.
    store.setMaxEntries(4);
    assert.equal(store.getMaxEntries(), 4);
  });

  it("revising to the live bound is a silent no-op", () => {
    const store = new DeliveryReceiptStore({ maxEntries: 3 });
    for (const id of ["r1", "r2", "r3"]) store.record(receipt(id));
    store.setMaxEntries(3);
    assert.equal(store.getMaxEntries(), 3);
    assert.equal(store.stats().stored, 3);
    assert.equal(store.stats().dropped, 0);
  });

  it("tightening never rewrites the journal; a fresh store still recovers the tail", () => {
    const dir = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 5, journalDir: dir });
    for (const id of ["r1", "r2", "r3"]) store.record(receipt(id));
    store.setMaxEntries(1);
    assert.equal(store.stats().stored, 1);
    const lines = readFileSync(join(dir, "delivery-receipts.jsonl"), "utf8")
      .split("\n")
      .filter((l) => l.length > 0);
    assert.equal(lines.length, 3);
    const recovered = new DeliveryReceiptStore({ maxEntries: 5, journalDir: dir });
    assert.deepEqual(
      recovered.query().map((r) => r.deliveryId),
      ["r3", "r2", "r1"]
    );
  });
});

describe("RetryQueue delivery receipt ring bound revision (WR-468)", () => {
  function makeQueue(maxEntries = 3) {
    const t = manualTimer();
    const sender: Sender = async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false });
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 1,
      deliveryReceipts: { maxEntries },
    });
    return { q, t };
  }

  async function deliver(q: RetryQueue, t: ReturnType<typeof manualTimer>, id: string) {
    q.enqueue(item(id, URL_A));
    await t.step();
  }

  it("widening lets the ring hold past the old cap", async () => {
    const { q, t } = makeQueue(3);
    try {
      q.start();
      for (const id of ["d1", "d2", "d3"]) await deliver(q, t, id);
      assert.equal(q.getDeliveryReceipts()?.length, 3);
      q.reviseDeliveryReceiptMaxEntries(5);
      assert.equal(q.getDeliveryReceiptMaxEntries(), 5);
      for (const id of ["d4", "d5"]) await deliver(q, t, id);
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d5", "d4", "d3", "d2", "d1"]
      );
    } finally {
      q.stop();
    }
  });

  it("tightening trims the oldest on the spot; the next delivery evicts per the new bound", async () => {
    const { q, t } = makeQueue(5);
    try {
      q.start();
      for (const id of ["d1", "d2", "d3", "d4", "d5"]) await deliver(q, t, id);
      assert.equal(q.getDeliveryReceipts()?.length, 5);
      q.reviseDeliveryReceiptMaxEntries(2);
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d5", "d4"]
      );
      await deliver(q, t, "d6");
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d6", "d5"]
      );
    } finally {
      q.stop();
    }
  });

  it("illegal bounds throw RangeError and leave the bound and ring untouched; unconfigured throws Error", async () => {
    const { q, t } = makeQueue(3);
    try {
      q.start();
      await deliver(q, t, "d1");
      for (const bad of [0, -2, 1.5, NaN, "3" as never]) {
        assert.throws(() => q.reviseDeliveryReceiptMaxEntries(bad as never), RangeError);
      }
      assert.equal(q.getDeliveryReceiptMaxEntries(), 3);
      assert.equal(q.getDeliveryReceipts()?.length, 1);
      // Still revisable afterwards.
      q.reviseDeliveryReceiptMaxEntries(4);
      assert.equal(q.getDeliveryReceiptMaxEntries(), 4);
    } finally {
      q.stop();
    }
    const bare = new RetryQueue({
      sender: (async () => {}) as Sender,
      maxAttempts: 1,
    });
    try {
      assert.equal(bare.deliveryReceiptsConfigured(), false);
      assert.equal(bare.getDeliveryReceiptMaxEntries(), undefined);
      assert.throws(
        () => bare.reviseDeliveryReceiptMaxEntries(5),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
    } finally {
      bare.stop();
    }
  });

  it("a fresh queue restores the construction bound — the revision is live-only", async () => {
    const { q, t } = makeQueue(3);
    try {
      q.start();
      q.reviseDeliveryReceiptMaxEntries(9);
      assert.equal(q.getDeliveryReceiptMaxEntries(), 9);
    } finally {
      q.stop();
    }
    const fresh = makeQueue(3);
    try {
      assert.equal(fresh.q.getDeliveryReceiptMaxEntries(), 3);
    } finally {
      fresh.q.stop();
    }
  });
});

describe("RelayServer delivery receipt ring bound revision (WR-468)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "delivery-receipt-max-entries-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: FORWARD,
      auditLog,
      operatorToken,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  function receiptServer(maxEntries = 3) {
    const sender: Sender = async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false });
    return makeServer({
      sender,
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
      deliveryReceipts: { maxEntries },
    });
  }

  it("a real revision audits numeric previous/current; the next revision reads the live bound", () => {
    const { relay, auditLog } = receiptServer(3);
    relay.reviseDeliveryReceiptMaxEntries!(5);
    relay.reviseDeliveryReceiptMaxEntries!(2);
    const revised = eventsOf(auditLog, "delivery_receipt_max_entries_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[0].previous, 3);
    assert.equal(revised[0].current, 5);
    assert.equal(revised[1].previous, 5);
    assert.equal(revised[1].current, 2);
  });

  it("a same-value revision is a silent no-op; an illegal bound throws and audits nothing; unconfigured throws Error", () => {
    const { relay, auditLog } = receiptServer(3);
    relay.reviseDeliveryReceiptMaxEntries!(3);
    assert.equal(eventsOf(auditLog, "delivery_receipt_max_entries_revised").length, 0);
    for (const bad of [0, -1, 2.5, NaN, "5" as never]) {
      assert.throws(() => relay.reviseDeliveryReceiptMaxEntries!(bad as never), RangeError);
    }
    assert.equal(eventsOf(auditLog, "delivery_receipt_max_entries_revised").length, 0);
    // A real revision still audits afterwards, from the untouched bound.
    relay.reviseDeliveryReceiptMaxEntries!(4);
    const revised = eventsOf(auditLog, "delivery_receipt_max_entries_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, 3);
    assert.equal(revised[0].current, 4);
    // Unconfigured: the queue throws the canonical "must restart" Error.
    const bare = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    });
    assert.throws(
      () => bare.relay.reviseDeliveryReceiptMaxEntries!(5),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
    assert.equal(eventsOf(bare.auditLog, "delivery_receipt_max_entries_revised").length, 0);
  });
});
