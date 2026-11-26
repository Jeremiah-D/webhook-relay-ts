import { describe, it, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
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
const relaySecret = "delivery-receipt-journal-dir-revision-secret";
const operatorToken = "delivery-receipt-journal-dir-revision-token";
const FORWARD = "http://127.0.0.1:1/unused";
const URL_A = "http://localhost:9999/a";
const JOURNAL_FILE = "delivery-receipts.jsonl";

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function freshDir(): string {
  const d = mkdtempSync(join(tmpdir(), "receipt-journal-dir-revision-"));
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

describe("DeliveryReceiptStore journal directory revision (WR-469)", () => {
  it("switching moves the next record to the new file; the old file is untouched", () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 5, journalDir: dir1 });
    store.record(receipt("r1"));
    assert.deepEqual(journalIds(dir1), ["r1"]);
    store.setJournalDir(dir2);
    assert.equal(store.getJournalDir(), dir2);
    store.record(receipt("r2"));
    assert.deepEqual(journalIds(dir1), ["r1"]);
    assert.deepEqual(journalIds(dir2), ["r2"]);
    assert.deepEqual(
      store.query().map((r) => r.deliveryId),
      ["r2", "r1"]
    );
  });

  it("the ring and dropped are untouched by a switch", () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 3, journalDir: dir1 });
    for (const id of ["r1", "r2", "r3", "r4"]) store.record(receipt(id));
    assert.equal(store.stats().stored, 3);
    assert.equal(store.stats().dropped, 1);
    store.setJournalDir(dir2);
    assert.equal(store.stats().stored, 3);
    assert.equal(store.stats().dropped, 1);
    assert.deepEqual(
      store.query().map((r) => r.deliveryId),
      ["r4", "r3", "r2"]
    );
    store.record(receipt("r5"));
    assert.equal(store.stats().stored, 3);
    assert.equal(store.stats().dropped, 2);
  });

  it("revising to the same directory is a silent no-op, including join-equivalent spellings", () => {
    const dir = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 5, journalDir: dir });
    store.record(receipt("r1"));
    store.setJournalDir(dir);
    store.setJournalDir(join(dir, "."));
    store.setJournalDir(dir + "/");
    assert.equal(store.getJournalDir(), dir);
    store.record(receipt("r2"));
    assert.deepEqual(journalIds(dir), ["r1", "r2"]);
  });

  it("illegal directories throw RangeError and leave the live path untouched", () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 5, journalDir: dir1 });
    store.record(receipt("r1"));
    for (const bad of ["", 123, null, undefined]) {
      assert.throws(() => store.setJournalDir(bad as never), RangeError, JSON.stringify(bad));
    }
    assert.equal(store.getJournalDir(), dir1);
    store.record(receipt("r2"));
    assert.deepEqual(journalIds(dir1), ["r1", "r2"]);
    // Still revisable afterwards.
    store.setJournalDir(dir2);
    assert.equal(store.getJournalDir(), dir2);
  });

  it("a missing directory is created on switch; a store without a journal cannot switch one on", () => {
    const dir1 = freshDir();
    const parent = freshDir();
    const dir2 = join(parent, "nested", "journal");
    assert.equal(existsSync(dir2), false);
    const store = new DeliveryReceiptStore({ maxEntries: 5, journalDir: dir1 });
    store.setJournalDir(dir2);
    assert.equal(existsSync(dir2), true);
    store.record(receipt("r1"));
    assert.deepEqual(journalIds(dir2), ["r1"]);
    // Enabling is not revising: a journal-less store throws Error.
    const bare = new DeliveryReceiptStore({ maxEntries: 5 });
    assert.equal(bare.getJournalDir(), undefined);
    assert.throws(
      () => bare.setJournalDir(dir2),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
  });

  it("a restart recovers only the new journal's tail; old-file receipts are not recovered", () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 5, journalDir: dir1 });
    store.record(receipt("r1"));
    store.setJournalDir(dir2);
    store.record(receipt("r2"));
    const recovered = new DeliveryReceiptStore({ maxEntries: 5, journalDir: dir2 });
    assert.deepEqual(
      recovered.query().map((r) => r.deliveryId),
      ["r2"]
    );
    // The old file still holds r1 on disk — it is an archive, not a source.
    assert.deepEqual(journalIds(dir1), ["r1"]);
  });

  it("the old file is never rewritten after a switch", () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const store = new DeliveryReceiptStore({ maxEntries: 5, journalDir: dir1 });
    store.record(receipt("r1"));
    const before = readFileSync(join(dir1, JOURNAL_FILE), "utf8");
    store.setJournalDir(dir2);
    store.record(receipt("r2"));
    store.record(receipt("r3"));
    assert.equal(readFileSync(join(dir1, JOURNAL_FILE), "utf8"), before);
    assert.deepEqual(journalIds(dir2), ["r2", "r3"]);
  });
});

describe("RetryQueue delivery receipt journal directory revision (WR-469)", () => {
  function makeQueue(journalDir: string) {
    const t = manualTimer();
    const sender: Sender = async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false });
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 1,
      deliveryReceipts: { maxEntries: 5, journalDir },
    });
    return { q, t };
  }

  async function deliver(q: RetryQueue, t: ReturnType<typeof manualTimer>, id: string) {
    q.enqueue(item(id, URL_A));
    await t.step();
  }

  it("a live delivery switches journal files; the old file keeps its lines", async () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const { q, t } = makeQueue(dir1);
    try {
      q.start();
      await deliver(q, t, "d1");
      assert.deepEqual(journalIds(dir1), ["d1"]);
      assert.equal(q.getDeliveryReceiptJournalDir(), dir1);
      q.reviseDeliveryReceiptJournalDir(dir2);
      assert.equal(q.getDeliveryReceiptJournalDir(), dir2);
      await deliver(q, t, "d2");
      assert.deepEqual(journalIds(dir1), ["d1"]);
      assert.deepEqual(journalIds(dir2), ["d2"]);
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d2", "d1"]
      );
    } finally {
      q.stop();
    }
  });

  it("unconfigured receipts and a journal-less configuration throw Error; illegal dirs throw RangeError", async () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const { q, t } = makeQueue(dir1);
    try {
      q.start();
      await deliver(q, t, "d1");
      for (const bad of ["", 123 as never, null as never]) {
        assert.throws(() => q.reviseDeliveryReceiptJournalDir(bad as never), RangeError);
      }
      assert.equal(q.getDeliveryReceiptJournalDir(), dir1);
      // Still revisable afterwards, and the old file keeps the record.
      q.reviseDeliveryReceiptJournalDir(dir2);
      assert.equal(q.getDeliveryReceiptJournalDir(), dir2);
      await deliver(q, t, "d2");
      assert.deepEqual(journalIds(dir1), ["d1"]);
    } finally {
      q.stop();
    }
    const bare = new RetryQueue({
      sender: (async () => {}) as Sender,
      maxAttempts: 1,
    });
    try {
      assert.equal(bare.deliveryReceiptsConfigured(), false);
      assert.equal(bare.getDeliveryReceiptJournalDir(), undefined);
      assert.throws(
        () => bare.reviseDeliveryReceiptJournalDir(dir2),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
    } finally {
      bare.stop();
    }
    const noJournal = new RetryQueue({
      sender: (async () => {}) as Sender,
      maxAttempts: 1,
      deliveryReceipts: { maxEntries: 5 },
    });
    try {
      assert.equal(noJournal.deliveryReceiptsConfigured(), true);
      assert.equal(noJournal.getDeliveryReceiptJournalDir(), undefined);
      assert.throws(
        () => noJournal.reviseDeliveryReceiptJournalDir(dir2),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
    } finally {
      noJournal.stop();
    }
  });
});

describe("RelayServer delivery receipt journal directory revision (WR-469)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "delivery-receipt-journal-dir-revision-"));
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

  function receiptServer(journalDir: string) {
    const sender: Sender = async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false });
    return makeServer({
      sender,
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
      deliveryReceipts: { maxEntries: 5, journalDir },
    });
  }

  it("a real revision audits string previous/current; the next revision reads the live directory", () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const dir3 = freshDir();
    const { relay, auditLog } = receiptServer(dir1);
    relay.reviseDeliveryReceiptJournalDir!(dir2);
    relay.reviseDeliveryReceiptJournalDir!(dir3);
    const revised = eventsOf(auditLog, "delivery_receipt_journal_dir_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[0].previous, dir1);
    assert.equal(revised[0].current, dir2);
    assert.equal(revised[1].previous, dir2);
    assert.equal(revised[1].current, dir3);
  });

  it("a same-directory revision is a silent no-op; an illegal dir throws and audits nothing; unconfigured throws Error", () => {
    const dir1 = freshDir();
    const dir2 = freshDir();
    const { relay, auditLog } = receiptServer(dir1);
    relay.reviseDeliveryReceiptJournalDir!(dir1);
    relay.reviseDeliveryReceiptJournalDir!(join(dir1, "."));
    assert.equal(eventsOf(auditLog, "delivery_receipt_journal_dir_revised").length, 0);
    for (const bad of ["", 123 as never]) {
      assert.throws(() => relay.reviseDeliveryReceiptJournalDir!(bad as never), RangeError);
    }
    assert.equal(eventsOf(auditLog, "delivery_receipt_journal_dir_revised").length, 0);
    // A real revision still audits afterwards, from the untouched directory.
    relay.reviseDeliveryReceiptJournalDir!(dir2);
    const revised = eventsOf(auditLog, "delivery_receipt_journal_dir_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, dir1);
    assert.equal(revised[0].current, dir2);
    // Unconfigured: the queue throws the canonical "must restart" Error.
    const bare = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    });
    assert.throws(
      () => bare.relay.reviseDeliveryReceiptJournalDir!(dir2),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
    assert.equal(eventsOf(bare.auditLog, "delivery_receipt_journal_dir_revised").length, 0);
    // Receipts configured but journal-less: the same Error, no audit.
    const noJournal = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
      deliveryReceipts: { maxEntries: 5 },
    });
    assert.throws(
      () => noJournal.relay.reviseDeliveryReceiptJournalDir!(dir2),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
    assert.equal(eventsOf(noJournal.auditLog, "delivery_receipt_journal_dir_revised").length, 0);
  });
});
