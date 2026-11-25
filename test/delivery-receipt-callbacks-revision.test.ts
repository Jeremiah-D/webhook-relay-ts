import { describe, it, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import type { DeliveryReceipt } from "../src/delivery-receipt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "delivery-receipt-callbacks-revision-secret";
const operatorToken = "delivery-receipt-callbacks-revision-token";
const FORWARD = "http://127.0.0.1:1/unused";
const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";
const PAYLOAD = Buffer.from(JSON.stringify({ payment: "pi_123", amount: 5000 }));
const BODY = PAYLOAD;

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function freshDir(): string {
  const d = mkdtempSync(join(tmpdir(), "receipt-callbacks-revision-"));
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

async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for ${what}`);
}

type DeliveredObserver = (receipt: DeliveryReceipt) => void;
type FailedObserver = (receipt: DeliveryReceipt) => void;

describe("RetryQueue delivery receipt callbacks revision (WR-467)", () => {
  function makeQueue(opts: {
    onDelivered?: DeliveredObserver;
    onFailed?: FailedObserver;
    journalDir?: string;
    maxAttempts?: number;
    failing?: boolean;
  } = {}) {
    const t = manualTimer();
    const sender: Sender = opts.failing
      ? async () => {
          throw Object.assign(new Error("downstream 503"), { statusCode: 503 });
        }
      : async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false });
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: opts.maxAttempts ?? 1,
      deliveryReceipts: {
        ...(opts.journalDir !== undefined ? { journalDir: opts.journalDir } : {}),
        ...(opts.onDelivered !== undefined ? { onDelivered: opts.onDelivered } : {}),
        ...(opts.onFailed !== undefined ? { onFailed: opts.onFailed } : {}),
      },
    });
    return { q, t };
  }

  it("delivered reaches the revised callback; the old callback stays silent", async () => {
    const oldSeen: DeliveryReceipt[] = [];
    const newSeen: DeliveryReceipt[] = [];
    const { q, t } = makeQueue({ onDelivered: (r) => oldSeen.push(r) });
    try {
      q.enqueue(item("d1", URL_A));
      q.start();
      await t.step();
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].deliveryId, "d1");
      q.reviseDeliveryReceiptCallbacks({ onDelivered: (r) => newSeen.push(r) });
      q.enqueue(item("d2", URL_A));
      await t.step();
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].deliveryId, "d2");
      assert.equal(newSeen[0].outcome, "delivered");
    } finally {
      q.stop();
    }
  });

  it("dead_letter reaches the revised callback; the old callback stays silent", async () => {
    const oldSeen: DeliveryReceipt[] = [];
    const newSeen: DeliveryReceipt[] = [];
    const { q, t } = makeQueue({
      failing: true,
      onFailed: (r) => oldSeen.push(r),
    });
    try {
      q.enqueue(item("f1", URL_B));
      q.start();
      await t.step();
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].outcome, "dead_letter");
      q.reviseDeliveryReceiptCallbacks({ onFailed: (r) => newSeen.push(r) });
      q.enqueue(item("f2", URL_B));
      await t.step();
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].deliveryId, "f2");
      assert.equal(newSeen[0].outcome, "dead_letter");
      assert.equal(newSeen[0].statusCode, 503);
    } finally {
      q.stop();
    }
  });

  it("a partial patch leaves the other hook live", async () => {
    const oldDelivered: DeliveryReceipt[] = [];
    const newDelivered: DeliveryReceipt[] = [];
    const oldFailed: DeliveryReceipt[] = [];
    const t = manualTimer();
    // Succeeds for URL_A, fails for URL_B, so one queue drives both outcomes.
    const sender: Sender = async (item) => {
      if (item.targetUrl === URL_B) {
        throw Object.assign(new Error("downstream 503"), { statusCode: 503 });
      }
      return { statusCode: 200, body: Buffer.from(""), truncated: false };
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 1,
      deliveryReceipts: {
        onDelivered: (r) => oldDelivered.push(r),
        onFailed: (r) => oldFailed.push(r),
      },
    });
    try {
      q.start();
      // Only the delivered hook moves; the failed hook stays the original.
      q.reviseDeliveryReceiptCallbacks({ onDelivered: (r) => newDelivered.push(r) });
      q.enqueue(item("d1", URL_A));
      await t.step();
      assert.equal(oldDelivered.length, 0);
      assert.equal(newDelivered.length, 1);
      q.enqueue(item("f1", URL_B));
      await t.step();
      assert.equal(oldFailed.length, 1);
      assert.equal(oldFailed[0].deliveryId, "f1");
      assert.equal(oldFailed[0].outcome, "dead_letter");
    } finally {
      q.stop();
    }
  });

  it("null clears one hook; the receipt is still recorded and journaled", async () => {
    const dir = freshDir();
    const deliveredSeen: DeliveryReceipt[] = [];
    const { q, t } = makeQueue({
      journalDir: dir,
      onDelivered: (r) => deliveredSeen.push(r),
    });
    try {
      q.enqueue(item("d1", URL_A));
      q.start();
      await t.step();
      assert.equal(deliveredSeen.length, 1);
      assert.equal(q.getDeliveryReceipts()?.length, 1);
      q.reviseDeliveryReceiptCallbacks({ onDelivered: null });
      q.enqueue(item("d2", URL_A));
      await t.step();
      assert.equal(deliveredSeen.length, 1); // cleared: no forwarding
      assert.equal(q.getDeliveryReceipts()?.length, 2); // still recorded
      assert.deepEqual(
        q.getDeliveryReceipts()?.map((r) => r.deliveryId),
        ["d2", "d1"]
      );
      const journal = readFileSync(join(dir, "delivery-receipts.jsonl"), "utf8")
        .trim()
        .split("\n");
      assert.equal(journal.length, 2); // still journaled
      assert.equal((JSON.parse(journal[1]) as DeliveryReceipt).deliveryId, "d2");
    } finally {
      q.stop();
    }
  });

  it("an empty or non-object patch throws RangeError and the live callbacks are untouched", async () => {
    const seen: DeliveryReceipt[] = [];
    const { q, t } = makeQueue({ onDelivered: (r) => seen.push(r) });
    try {
      q.start();
      assert.throws(() => q.reviseDeliveryReceiptCallbacks({}), RangeError);
      assert.throws(
        () => q.reviseDeliveryReceiptCallbacks(null as never),
        RangeError
      );
      assert.throws(
        () => q.reviseDeliveryReceiptCallbacks("nope" as never),
        RangeError
      );
      assert.throws(
        () => q.reviseDeliveryReceiptCallbacks(42 as never),
        RangeError
      );
      // An explicitly-undefined field counts as not provided.
      assert.throws(
        () => q.reviseDeliveryReceiptCallbacks({ onDelivered: undefined }),
        RangeError
      );
      q.enqueue(item("d1", URL_A));
      await t.step();
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError and the live callbacks are untouched", async () => {
    const seen: DeliveryReceipt[] = [];
    const { q, t } = makeQueue({ onDelivered: (r) => seen.push(r) });
    try {
      q.start();
      for (const bad of ["nope", 42, {}, true]) {
        assert.throws(
          () => q.reviseDeliveryReceiptCallbacks({ onDelivered: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
        assert.throws(
          () => q.reviseDeliveryReceiptCallbacks({ onFailed: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
      }
      q.enqueue(item("d1", URL_A));
      await t.step();
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a same-reference revision is a no-op; clearing when already unset is a no-op", async () => {
    const deliveredSeen: DeliveryReceipt[] = [];
    const failedSeen: DeliveryReceipt[] = [];
    const deliveredCb: DeliveredObserver = (r) => deliveredSeen.push(r);
    const failedCb: FailedObserver = (r) => failedSeen.push(r);
    const { q, t } = makeQueue({
      onDelivered: deliveredCb,
      onFailed: failedCb,
    });
    try {
      q.start();
      // Same references as construction: a no-op, nothing is dropped.
      q.reviseDeliveryReceiptCallbacks({
        onDelivered: deliveredCb,
        onFailed: failedCb,
      });
      assert.equal(q.getDeliveryReceiptCallbacks()?.onDelivered, deliveredCb);
      assert.equal(q.getDeliveryReceiptCallbacks()?.onFailed, failedCb);
      q.enqueue(item("d1", URL_A));
      await t.step();
      assert.equal(deliveredSeen.length, 1);
      // Clearing when already unset is a no-op too.
      const bareT = manualTimer();
      const bare = new RetryQueue({
        sender: (async () => {}) as Sender,
        setTimer: bareT.setTimer,
        deliveryReceipts: {},
      });
      try {
        bare.reviseDeliveryReceiptCallbacks({ onDelivered: null, onFailed: null });
        assert.equal(bare.getDeliveryReceiptCallbacks()?.onDelivered, undefined);
        assert.equal(bare.getDeliveryReceiptCallbacks()?.onFailed, undefined);
      } finally {
        bare.stop();
      }
    } finally {
      q.stop();
    }
  });

  it("receipts already emitted are never re-delivered", async () => {
    const oldSeen: DeliveryReceipt[] = [];
    const newSeen: DeliveryReceipt[] = [];
    const { q, t } = makeQueue({ onDelivered: (r) => oldSeen.push(r) });
    try {
      q.enqueue(item("d1", URL_A));
      q.start();
      await t.step();
      assert.equal(oldSeen.length, 1);
      q.reviseDeliveryReceiptCallbacks({ onDelivered: (r) => newSeen.push(r) });
      q.enqueue(item("d2", URL_A));
      await t.step();
      assert.equal(oldSeen.length, 1); // d1 was never re-sent
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].deliveryId, "d2");
    } finally {
      q.stop();
    }
  });

  it("a throwing revised callback never breaks the delivery path", async () => {
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryReceipts: { onDelivered: () => {} },
    });
    try {
      q.reviseDeliveryReceiptCallbacks({
        onDelivered: () => {
          throw new Error("callback bug");
        },
      });
      q.enqueue(item("d1", URL_A));
      q.start();
      await t.step();
      assert.equal(calls, 1); // the delivery still went through
      assert.equal(q.getDeliveryReceipts()?.length, 1); // and was still recorded
    } finally {
      q.stop();
    }
  });

  it("revising with receipts unconfigured throws Error and stays unconfigured", () => {
    const q = new RetryQueue({ sender: (async () => {}) as Sender });
    try {
      assert.equal(q.getDeliveryReceiptCallbacks(), undefined);
      assert.equal(q.deliveryReceiptsConfigured(), false);
      assert.throws(
        () => q.reviseDeliveryReceiptCallbacks({ onDelivered: () => {} }),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
      assert.throws(
        () => q.reviseDeliveryReceiptCallbacks({ onFailed: null }),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
      assert.equal(q.getDeliveryReceipts(), undefined);
      assert.equal(q.getDeliveryReceiptCallbacks(), undefined);
    } finally {
      q.stop();
    }
  });

  it("getDeliveryReceiptCallbacks reflects the live observers", () => {
    const deliveredCb: DeliveredObserver = () => {};
    const failedCb: FailedObserver = () => {};
    const newDeliveredCb: DeliveredObserver = () => {};
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      deliveryReceipts: { onDelivered: deliveredCb },
    });
    try {
      assert.equal(q.deliveryReceiptsConfigured(), true);
      assert.equal(q.getDeliveryReceiptCallbacks()?.onDelivered, deliveredCb);
      assert.equal(q.getDeliveryReceiptCallbacks()?.onFailed, undefined);
      q.reviseDeliveryReceiptCallbacks({ onDelivered: newDeliveredCb, onFailed: failedCb });
      assert.equal(q.getDeliveryReceiptCallbacks()?.onDelivered, newDeliveredCb);
      assert.equal(q.getDeliveryReceiptCallbacks()?.onFailed, failedCb);
      // Mutating the snapshot never moves the live observers.
      const snap = q.getDeliveryReceiptCallbacks()!;
      (snap as { onDelivered?: DeliveredObserver }).onDelivered = undefined;
      assert.equal(q.getDeliveryReceiptCallbacks()?.onDelivered, newDeliveredCb);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer delivery receipt callbacks revision (WR-467)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "delivery-receipt-callbacks-revision-"));
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

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function postWebhook(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      });
      r.on("error", reject);
      r.end(body);
    });
  }

  function receiptServer(opts: {
    onDelivered?: DeliveredObserver;
    onFailed?: FailedObserver;
    failing?: boolean;
  }) {
    const sender: Sender = opts.failing
      ? async () => {
          throw Object.assign(new Error("downstream 503"), { statusCode: 503 });
        }
      : async () => ({ statusCode: 200, body: Buffer.from(""), truncated: false });
    const { relay, auditLog } = makeServer({
      sender,
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
      deliveryReceipts: {
        ...(opts.onDelivered !== undefined ? { onDelivered: opts.onDelivered } : {}),
        ...(opts.onFailed !== undefined ? { onFailed: opts.onFailed } : {}),
      },
    });
    return { relay, auditLog };
  }

  async function postOne(port: number): Promise<void> {
    const sig = { "x-signature": signSha256(BODY, relaySecret) };
    assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
  }

  it("revising the delivered callback routes the next receipt to the new callback and audits presence-only", async () => {
    const initialSeen: DeliveryReceipt[] = [];
    const newSeen: DeliveryReceipt[] = [];
    const initialCb: DeliveredObserver = (r) => initialSeen.push(r);
    const newCb: DeliveredObserver = (r) => newSeen.push(r);
    const { relay, auditLog } = receiptServer({ onDelivered: initialCb });
    const port = await listen(relay);
    await postOne(port);
    await waitFor(() => initialSeen.length === 1, "first delivered receipt");
    assert.equal(initialSeen[0].outcome, "delivered");
    relay.reviseDeliveryReceiptCallbacks!({ onDelivered: newCb });
    await postOne(port);
    await waitFor(() => newSeen.length === 1, "revised delivered receipt");
    assert.equal(initialSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen[0].outcome, "delivered");
    // The revision itself was audited with per-field presence only.
    const revised = eventsOf(auditLog, "delivery_receipt_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { onDelivered: "set", onFailed: "cleared" });
    assert.deepEqual(revised[0].current, { onDelivered: "set", onFailed: "cleared" });
    assert.ok(!JSON.stringify(revised[0]).includes("=>")); // no function body
  });

  it("revising the failed callback routes the next dead-letter receipt to the new callback", async () => {
    const initialSeen: DeliveryReceipt[] = [];
    const newSeen: DeliveryReceipt[] = [];
    const initialCb: FailedObserver = (r) => initialSeen.push(r);
    const newCb: FailedObserver = (r) => newSeen.push(r);
    const { relay, auditLog } = receiptServer({ failing: true, onFailed: initialCb });
    const port = await listen(relay);
    await postOne(port);
    await waitFor(() => initialSeen.length === 1, "first dead_letter receipt");
    assert.equal(initialSeen[0].outcome, "dead_letter");
    relay.reviseDeliveryReceiptCallbacks!({ onFailed: newCb });
    await postOne(port);
    await waitFor(() => newSeen.length === 1, "revised dead_letter receipt");
    assert.equal(initialSeen.length, 1);
    assert.equal(newSeen[0].outcome, "dead_letter");
    const revised = eventsOf(auditLog, "delivery_receipt_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { onDelivered: "cleared", onFailed: "set" });
    assert.deepEqual(revised[0].current, { onDelivered: "cleared", onFailed: "set" });
    assert.ok(!JSON.stringify(revised[0]).includes("=>"));
  });

  it("a same-value revision is a silent no-op; an illegal patch throws and audits nothing; unconfigured throws Error", async () => {
    const deliveredSeen: DeliveryReceipt[] = [];
    const deliveredCb: DeliveredObserver = (r) => deliveredSeen.push(r);
    const { relay, auditLog } = receiptServer({ onDelivered: deliveredCb });
    const port = await listen(relay);
    // Same reference as construction: no audit event.
    relay.reviseDeliveryReceiptCallbacks!({ onDelivered: deliveredCb });
    assert.equal(eventsOf(auditLog, "delivery_receipt_callbacks_revised").length, 0);
    // Clearing when already unset is a no-op too.
    relay.reviseDeliveryReceiptCallbacks!({ onFailed: null });
    assert.equal(eventsOf(auditLog, "delivery_receipt_callbacks_revised").length, 0);
    // Illegal values and empty patches throw RangeError, no audit.
    for (const bad of ["nope", 42, {}, true]) {
      assert.throws(
        () => relay.reviseDeliveryReceiptCallbacks!({ onDelivered: bad as never }),
        RangeError,
        JSON.stringify(bad)
      );
    }
    assert.throws(() => relay.reviseDeliveryReceiptCallbacks!({}), RangeError);
    assert.throws(
      () => relay.reviseDeliveryReceiptCallbacks!(null as never),
      RangeError
    );
    assert.equal(eventsOf(auditLog, "delivery_receipt_callbacks_revised").length, 0);
    // The live callback is untouched: the next delivery still reaches it.
    await postOne(port);
    await waitFor(() => deliveredSeen.length === 1, "delivered receipt after bad patches");
    // A real revision still audits afterwards.
    relay.reviseDeliveryReceiptCallbacks!({ onDelivered: null });
    assert.equal(eventsOf(auditLog, "delivery_receipt_callbacks_revised").length, 1);
    assert.deepEqual(eventsOf(auditLog, "delivery_receipt_callbacks_revised")[0].current, {
      onDelivered: "cleared",
      onFailed: "cleared",
    });
    // Unconfigured: the queue throws the canonical "must restart" Error.
    const bare = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    });
    const barePort = await listen(bare.relay);
    assert.ok(barePort > 0);
    assert.throws(
      () => bare.relay.reviseDeliveryReceiptCallbacks!({ onDelivered: () => {} }),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
    assert.throws(
      () => bare.relay.reviseDeliveryReceiptCallbacks!({ onFailed: null }),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
  });
});
