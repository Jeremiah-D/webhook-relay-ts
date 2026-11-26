import { describe, it, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync } from "node:fs";
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
const relaySecret = "delivery-receipt-journal-dir-enable-secret";
const operatorToken = "delivery-receipt-journal-dir-enable-token";
const FORWARD = "http://127.0.0.1:1/unused";
const URL_A = "http://localhost:9999/a";
const JOURNAL_FILE = "delivery-receipts.jsonl";

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function freshDir(): string {
  const d = mkdtempSync(join(tmpdir(), "receipt-journal-dir-enable-"));
  tmpDirs.push(d);
  return d;
}

function journalLines(dir: string): string[] {
  return readFileSync(join(dir, JOURNAL_FILE), "utf8")
    .split("\n")
    .filter((l) => l.length > 0);
}

function journalIds(dir: string): string[] {
  return journalLines(dir).map((l) => (JSON.parse(l) as { deliveryId: string }).deliveryId);
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

function journalLine(id: string, at: number): string {
  return JSON.stringify({ deliveryId: id, endpoint: URL_A, attempt: 1, latencyMs: 1, outcome: "delivered", at });
}

describe("DeliveryReceiptStore journal enable (WR-470)", () => {
  it("enabling writes the next record to the new file; earlier in-memory receipts stay in the ring", () => {
    const dir = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 5 });
    assert.equal(store.getJournalDir(), undefined);
    assert.equal(store.stats().journalEnabled, false);
    store.record(receipt("r0"));
    assert.equal(existsSync(join(dir, JOURNAL_FILE)), false);
    store.setJournalDir(dir);
    assert.equal(store.getJournalDir(), dir);
    assert.equal(store.stats().journalEnabled, true);
    store.record(receipt("r1"));
    assert.deepEqual(journalIds(dir), ["r1"]);
    assert.deepEqual(
      store.query().map((r) => r.deliveryId),
      ["r1", "r0"]
    );
  });

  it("an existing journal tail is recovered into the ring on enable; corrupt lines are skipped", () => {
    const dir = freshDir();
    writeFileSync(
      join(dir, JOURNAL_FILE),
      [journalLine("j1", 1000), "not-json", journalLine("j2", 2000)].join("\n") + "\n"
    );
    const store = new DeliveryReceiptStore({ maxEntries: 5 });
    store.record(receipt("r0"));
    store.setJournalDir(dir);
    assert.deepEqual(
      store.query().map((r) => r.deliveryId),
      ["j2", "j1", "r0"]
    );
    // The recovered receipts are live: they export with the ring.
    assert.equal(store.stats().stored, 3);
  });

  it("enable respects maxEntries: the recovered tail evicts the oldest and dropped counts it", () => {
    const dir = freshDir();
    writeFileSync(
      join(dir, JOURNAL_FILE),
      [journalLine("j1", 1000), journalLine("j2", 2000)].join("\n") + "\n"
    );
    const store = new DeliveryReceiptStore({ maxEntries: 3 });
    for (const id of ["r1", "r2", "r3"]) store.record(receipt(id));
    assert.equal(store.stats().stored, 3);
    assert.equal(store.stats().dropped, 0);
    store.setJournalDir(dir);
    // Ring was [r1, r2, r3]; recover pushes j1, j2; the two oldest
    // (r1, r2) are evicted to re-assert the bound.
    assert.equal(store.stats().stored, 3);
    assert.equal(store.stats().dropped, 2);
    assert.deepEqual(
      store.query().map((r) => r.deliveryId),
      ["j2", "j1", "r3"]
    );
  });

  it("illegal directories throw RangeError and the store stays journal-less, still enableable afterwards", () => {
    const dir = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 5 });
    store.record(receipt("r0"));
    for (const bad of ["", 123, null, undefined]) {
      assert.throws(() => store.setJournalDir(bad as never), RangeError, JSON.stringify(bad));
    }
    assert.equal(store.getJournalDir(), undefined);
    assert.equal(store.stats().journalEnabled, false);
    // Still enableable afterwards, with the live ring intact.
    store.setJournalDir(dir);
    assert.equal(store.getJournalDir(), dir);
    store.record(receipt("r1"));
    assert.deepEqual(journalIds(dir), ["r1"]);
    assert.deepEqual(
      store.query().map((r) => r.deliveryId),
      ["r1", "r0"]
    );
  });

  it("a restart restores the journal-less construction state; the journal file stays on disk as the archive", () => {
    const dir = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 5 });
    store.setJournalDir(dir);
    store.record(receipt("r1"));
    const restarted = new DeliveryReceiptStore({ maxEntries: 5 });
    assert.equal(restarted.getJournalDir(), undefined);
    assert.equal(restarted.stats().journalEnabled, false);
    assert.deepEqual(restarted.query(), []);
    // The enable was live-only — but the journal file survives.
    assert.deepEqual(journalIds(dir), ["r1"]);
  });
});

describe("RetryQueue delivery receipt journal enable (WR-470)", () => {
  function makeQueue() {
    const t = manualTimer();
    const sender: Sender = async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false });
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 1,
      deliveryReceipts: { maxEntries: 5 },
    });
    return { q, t };
  }

  async function deliver(q: RetryQueue, t: ReturnType<typeof manualTimer>, id: string) {
    q.enqueue(item(id, URL_A));
    await t.step();
  }

  it("a journal-less queue enables and the next live delivery is journaled; earlier receipts stay queryable", async () => {
    const dir = freshDir();
    const { q, t } = makeQueue();
    try {
      q.start();
      assert.equal(q.deliveryReceiptsConfigured(), true);
      assert.equal(q.getDeliveryReceiptJournalDir(), undefined);
      await deliver(q, t, "d1");
      assert.equal(existsSync(join(dir, JOURNAL_FILE)), false);
      q.reviseDeliveryReceiptJournalDir(dir);
      assert.equal(q.getDeliveryReceiptJournalDir(), dir);
      await deliver(q, t, "d2");
      assert.deepEqual(journalIds(dir), ["d2"]);
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d2", "d1"]
      );
    } finally {
      q.stop();
    }
  });

  it("a journal-less queue rejects illegal dirs and stays enableable; a store-less queue still throws Error", async () => {
    const dir = freshDir();
    const { q, t } = makeQueue();
    try {
      q.start();
      for (const bad of ["", 123 as never, null as never]) {
        assert.throws(() => q.reviseDeliveryReceiptJournalDir(bad as never), RangeError);
      }
      assert.equal(q.getDeliveryReceiptJournalDir(), undefined);
      q.reviseDeliveryReceiptJournalDir(dir);
      assert.equal(q.getDeliveryReceiptJournalDir(), dir);
    } finally {
      q.stop();
    }
    const bare = new RetryQueue({
      sender: (async () => {}) as Sender,
      maxAttempts: 1,
    });
    try {
      assert.equal(bare.deliveryReceiptsConfigured(), false);
      assert.throws(
        () => bare.reviseDeliveryReceiptJournalDir(dir),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
    } finally {
      bare.stop();
    }
  });
});

describe("RelayServer delivery receipt journal enable (WR-470)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "delivery-receipt-journal-dir-enable-"));
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

  it("the server enables a journal-less relay and audits previous: null; a same-directory call afterwards is a silent no-op", () => {
    const dir = freshDir();
    const { relay, auditLog } = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
      deliveryReceipts: { maxEntries: 5 },
    });
    relay.reviseDeliveryReceiptJournalDir!(dir);
    const enabled = eventsOf(auditLog, "delivery_receipt_journal_dir_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].previous, null);
    assert.equal(enabled[0].current, dir);
    // Same directory afterwards: silent no-op, nothing more audited.
    relay.reviseDeliveryReceiptJournalDir!(dir);
    relay.reviseDeliveryReceiptJournalDir!(join(dir, "."));
    assert.equal(eventsOf(auditLog, "delivery_receipt_journal_dir_revised").length, 1);
  });

  it("an illegal dir throws RangeError and audits nothing; a real revision after the enable audits string previous/current", () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const { relay, auditLog } = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
      deliveryReceipts: { maxEntries: 5 },
    });
    for (const bad of ["", 123 as never]) {
      assert.throws(() => relay.reviseDeliveryReceiptJournalDir!(bad as never), RangeError);
    }
    assert.equal(eventsOf(auditLog, "delivery_receipt_journal_dir_revised").length, 0);
    relay.reviseDeliveryReceiptJournalDir!(dir1);
    relay.reviseDeliveryReceiptJournalDir!(dir2);
    const revised = eventsOf(auditLog, "delivery_receipt_journal_dir_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[0].previous, null);
    assert.equal(revised[0].current, dir1);
    assert.equal(revised[1].previous, dir1);
    assert.equal(revised[1].current, dir2);
  });
});
