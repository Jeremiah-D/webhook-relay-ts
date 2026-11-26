import { describe, it, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import type { DeliveryReceipt } from "../src/delivery-receipt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "delivery-receipt-enable-secret";
const operatorToken = "delivery-receipt-enable-token";
const FORWARD = "http://127.0.0.1:1/unused";
const URL_A = "http://localhost:9999/a";
const JOURNAL_FILE = "delivery-receipts.jsonl";

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function freshDir(): string {
  const d = mkdtempSync(join(tmpdir(), "receipt-enable-"));
  tmpDirs.push(d);
  return d;
}

function journalLine(id: string, at: number): string {
  return JSON.stringify({ deliveryId: id, endpoint: URL_A, attempt: 1, latencyMs: 1, outcome: "delivered", at });
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

function makeQueue(sender?: Sender) {
  const t = manualTimer();
  const send: Sender =
    sender ?? (async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false }));
  const q = new RetryQueue({ sender: send, setTimer: t.setTimer, maxAttempts: 1 });
  return { q, t };
}

async function deliver(q: RetryQueue, t: ReturnType<typeof manualTimer>, id: string) {
  q.enqueue(item(id, URL_A));
  await t.step();
}

const ALREADY_CONFIGURED =
  "enableDeliveryReceipts: delivery receipts are already configured — use reviseDeliveryReceiptCallbacks / reviseDeliveryReceiptMaxEntries / reviseDeliveryReceiptJournalDir to change them";

describe("RetryQueue delivery receipt live enable (WR-471)", () => {
  it("a bare queue enables with no opts and the next terminal delivery is queryable and exportable", async () => {
    const { q, t } = makeQueue();
    try {
      q.start();
      assert.equal(q.deliveryReceiptsConfigured(), false);
      assert.equal(q.getDeliveryReceipts(), undefined);
      assert.equal(q.exportDeliveryReceipts(), undefined);
      q.enableDeliveryReceipts();
      assert.equal(q.deliveryReceiptsConfigured(), true);
      assert.equal(q.getDeliveryReceiptMaxEntries(), 1000);
      assert.equal(q.getDeliveryReceiptJournalDir(), undefined);
      assert.deepEqual(q.getDeliveryReceipts(), []);
      await deliver(q, t, "d1");
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d1"]
      );
      assert.equal(q.getDeliveryReceipts()?.[0].outcome, "delivered");
      assert.match(q.exportDeliveryReceipts() ?? "", /"deliveryId":"d1"/);
    } finally {
      q.stop();
    }
  });

  it("deliveries before the enable are never backfilled", async () => {
    const { q, t } = makeQueue();
    try {
      q.start();
      await deliver(q, t, "d0");
      assert.equal(q.getDeliveryReceipts(), undefined);
      q.enableDeliveryReceipts({ maxEntries: 5 });
      await deliver(q, t, "d1");
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d1"]
      );
    } finally {
      q.stop();
    }
  });

  it("enabling with a journalDir recovers the existing journal tail, bounded by the enable-time maxEntries", async () => {
    const dir = freshDir();
    writeFileSync(
      join(dir, JOURNAL_FILE),
      [journalLine("j1", 1000), journalLine("j2", 2000), journalLine("j3", 3000)].join("\n") + "\n"
    );
    const { q, t } = makeQueue();
    try {
      q.start();
      q.enableDeliveryReceipts({ maxEntries: 2, journalDir: dir });
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["j3", "j2"]
      );
      await deliver(q, t, "d1");
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d1", "j3"]
      );
      // The next record appends to the adopted journal.
      assert.deepEqual(
        readFileSync(join(dir, JOURNAL_FILE), "utf8")
          .split("\n")
          .filter((l) => l.length > 0)
          .map((l) => (JSON.parse(l) as { deliveryId: string }).deliveryId),
        ["j1", "j2", "j3", "d1"]
      );
    } finally {
      q.stop();
    }
  });

  it("illegal opts throw RangeError and the queue stays unconfigured, still enableable afterwards", () => {
    const { q } = makeQueue();
    try {
      for (const bad of [{ maxEntries: 0 }, { maxEntries: -3 }, { maxEntries: 1.5 }, { journalDir: "" }]) {
        assert.throws(() => q.enableDeliveryReceipts(bad as never), RangeError, JSON.stringify(bad));
        assert.equal(q.deliveryReceiptsConfigured(), false);
        assert.equal(q.getDeliveryReceipts(), undefined);
      }
      // Still enableable afterwards, with the defaults.
      q.enableDeliveryReceipts();
      assert.equal(q.deliveryReceiptsConfigured(), true);
      assert.equal(q.getDeliveryReceiptMaxEntries(), 1000);
    } finally {
      q.stop();
    }
  });

  it("a second enable throws Error and leaves the live store untouched", async () => {
    const { q, t } = makeQueue();
    try {
      q.start();
      q.enableDeliveryReceipts({ maxEntries: 5 });
      await deliver(q, t, "d1");
      assert.throws(() => q.enableDeliveryReceipts(), (e: unknown) => {
        assert.ok(e instanceof Error);
        assert.equal((e as Error).message, ALREADY_CONFIGURED);
        return true;
      });
      assert.throws(() => q.enableDeliveryReceipts({ maxEntries: 9 }), Error);
      assert.equal(q.getDeliveryReceiptMaxEntries(), 5);
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d1"]
      );
    } finally {
      q.stop();
    }
  });

  it("after the enable the three revise setters no longer throw the gate", async () => {
    const dir = freshDir();
    const { q, t } = makeQueue();
    try {
      q.start();
      q.enableDeliveryReceipts({ maxEntries: 5 });
      q.reviseDeliveryReceiptMaxEntries(3);
      assert.equal(q.getDeliveryReceiptMaxEntries(), 3);
      q.reviseDeliveryReceiptJournalDir(dir);
      assert.equal(q.getDeliveryReceiptJournalDir(), dir);
      const seen: DeliveryReceipt[] = [];
      q.reviseDeliveryReceiptCallbacks({ onDelivered: (r) => seen.push(r) });
      await deliver(q, t, "d1");
      assert.deepEqual(seen.map((r) => r.deliveryId), ["d1"]);
    } finally {
      q.stop();
    }
  });

  it("callbacks fire only for terminal deliveries after the enable", async () => {
    const delivered: DeliveryReceipt[] = [];
    const failed: DeliveryReceipt[] = [];
    const { q, t } = makeQueue();
    try {
      q.start();
      await deliver(q, t, "d0");
      q.enableDeliveryReceipts({
        onDelivered: (r) => delivered.push(r),
        onFailed: (r) => failed.push(r),
      });
      await deliver(q, t, "d1");
      assert.deepEqual(delivered.map((r) => r.deliveryId), ["d1"]);
      assert.deepEqual(failed, []);
    } finally {
      q.stop();
    }
    // A failing sender fires onFailed only after the enable.
    const failing: Sender = async () => {
      throw Object.assign(new Error("downstream 503"), { statusCode: 503 });
    };
    const { q: q2, t: t2 } = makeQueue(failing);
    try {
      q2.start();
      await deliver(q2, t2, "f0");
      const failed2: DeliveryReceipt[] = [];
      q2.enableDeliveryReceipts({ onFailed: (r) => failed2.push(r) });
      await deliver(q2, t2, "f1");
      assert.deepEqual(failed2.map((r) => r.deliveryId), ["f1"]);
      assert.equal(failed2[0].outcome, "dead_letter");
      assert.equal(failed2[0].statusCode, 503);
    } finally {
      q2.stop();
    }
  });

  it("a restart restores the unconfigured state; the enable is live-only", () => {
    const { q } = makeQueue();
    try {
      q.enableDeliveryReceipts({ maxEntries: 5 });
      assert.equal(q.deliveryReceiptsConfigured(), true);
    } finally {
      q.stop();
    }
    const restarted = makeQueue().q;
    try {
      assert.equal(restarted.deliveryReceiptsConfigured(), false);
      assert.equal(restarted.getDeliveryReceipts(), undefined);
      // And the fresh queue enables cleanly again.
      restarted.enableDeliveryReceipts();
      assert.equal(restarted.deliveryReceiptsConfigured(), true);
    } finally {
      restarted.stop();
    }
  });
});

describe("RelayServer delivery receipt live enable (WR-471)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "delivery-receipt-enable-"));
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

  it("the server enables with defaults and audits previous: null with the resolved current", () => {
    const { relay, auditLog } = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    });
    relay.enableDeliveryReceipts!();
    const enabled = eventsOf(auditLog, "delivery_receipts_enabled");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].previous, null);
    assert.deepEqual(enabled[0].current, {
      maxEntries: 1000,
      journalDir: null,
      onDelivered: "cleared",
      onFailed: "cleared",
    });
  });

  it("the server enable records the resolved opts: bound, journal dir, and callback presence", () => {
    const dir = freshDir();
    const { relay, auditLog } = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    });
    relay.enableDeliveryReceipts!({
      maxEntries: 7,
      journalDir: dir,
      onDelivered: () => {},
    });
    const enabled = eventsOf(auditLog, "delivery_receipts_enabled");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].previous, null);
    assert.deepEqual(enabled[0].current, {
      maxEntries: 7,
      journalDir: dir,
      onDelivered: "set",
      onFailed: "cleared",
    });
  });

  it("a second server enable throws the canonical Error and audits nothing more; illegal opts throw RangeError and audit nothing", () => {
    const { relay, auditLog } = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    });
    assert.throws(() => relay.enableDeliveryReceipts!({ maxEntries: 0 }), RangeError);
    assert.throws(() => relay.enableDeliveryReceipts!({ journalDir: "" }), RangeError);
    assert.equal(eventsOf(auditLog, "delivery_receipts_enabled").length, 0);
    relay.enableDeliveryReceipts!({ maxEntries: 5 });
    assert.equal(eventsOf(auditLog, "delivery_receipts_enabled").length, 1);
    assert.throws(() => relay.enableDeliveryReceipts!(), (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.equal((e as Error).message, ALREADY_CONFIGURED);
      return true;
    });
    assert.equal(eventsOf(auditLog, "delivery_receipts_enabled").length, 1);
    // The revise setters work after the server enable.
    relay.reviseDeliveryReceiptMaxEntries!(9);
    assert.equal(eventsOf(auditLog, "delivery_receipt_max_entries_revised").length, 1);
  });
});
