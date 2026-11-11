import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type DeliveryDeadlineExceededInfo,
  type RetryItem,
  type Sender,
  type SloMissInfo,
} from "../src/retry.ts";
import { DeadlineBudgetTimeoutError } from "../src/deadline-budget.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "delivery-deadline-exceeded-callback-revision-secret";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Steppable timer: each `step()` runs the currently pending callbacks once. */
function stepTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return { clear: () => { const i = pending.indexOf(fn); if (i >= 0) pending.splice(i, 1); } };
    },
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const fn of fns) fn();
      // One macrotask flushes the whole deliver() microtask chain
      // (lane turn, limiter, global gate, sender, catch, reschedule).
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string): RetryItem {
  return { id, targetUrl: URL, payload: Buffer.from("{}"), headers: {} };
}

function baseOpts(
  t: ReturnType<typeof stepTimer>,
  now: () => number,
  sender: Sender,
  extra: Record<string, unknown> = {}
) {
  return {
    sender,
    baseDelayMs: 100,
    maxDelayMs: 10_000,
    maxAttempts: 5,
    jitterMs: 0,
    setTimer: t.setTimer,
    clearTimer: t.clearTimer,
    deliveryDeadline: { deadlines: { [URL]: 250 }, now },
    ...extra,
  };
}

describe("RetryQueue delivery-deadline-exceeded callback revision (WR-391)", () => {
  it("revise swaps the live callback: the next pre-dispatch expiry enters the new callback with exact elapsedMs/deadlineMs/attempts, already-reported expirations are never re-delivered", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const oldSeen: DeliveryDeadlineExceededInfo[] = [];
    const newSeen: DeliveryDeadlineExceededInfo[] = [];
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => { throw new Error("boom"); }, {
        onDeliveryDeadlineExceeded: (info: DeliveryDeadlineExceededInfo) => oldSeen.push(info),
      })
    );
    q.start();
    try {
      q.enqueue(item("swap-1"));
      await t.step(); // attempt 1 at t=0 fails, retry scheduled
      assert.equal(oldSeen.length, 0);
      nowMs = 300; // past the 250ms deadline before the next dispatch
      await t.step(); // dispatch expires instead of attempting
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0]?.id, "swap-1");
      assert.equal(oldSeen[0]?.endpoint, URL);
      assert.equal(oldSeen[0]?.attempts, 1);
      assert.equal(oldSeen[0]?.elapsedMs, 300);
      assert.equal(oldSeen[0]?.deadlineMs, 250);
      assert.match(oldSeen[0]?.traceId ?? "", /^[0-9a-f]{32}$/);
      assert.equal(q.getDeadLetter().length, 1);
      assert.deepEqual(newSeen, []);
      // Swap mid-stream: the old callback never hears another expiry,
      // and the already-reported expiry is never re-delivered.
      const newCb = (info: DeliveryDeadlineExceededInfo) => newSeen.push(info);
      q.reviseDeliveryDeadlineExceededCallback(newCb);
      nowMs = 1000;
      q.enqueue(item("swap-2"));
      await t.step(); // attempt 1 at t=1000 fails
      nowMs = 1300;
      await t.step(); // dispatch expires
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0]?.id, "swap-2");
      assert.equal(newSeen[0]?.attempts, 1);
      assert.equal(newSeen[0]?.elapsedMs, 300);
      assert.equal(newSeen[0]?.deadlineMs, 250);
      assert.equal(q.getDeadLetter().length, 2);
      assert.ok(
        q.renderMetrics().includes(`relay_delivery_deadline_exceeded_total{endpoint="${URL}"} 2`)
      );
    } finally {
      q.stop();
    }
  });

  it("a post-attempt budget exhaustion also enters the new callback with the actual attempt count", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const oldSeen: DeliveryDeadlineExceededInfo[] = [];
    const newSeen: DeliveryDeadlineExceededInfo[] = [];
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => { throw new DeadlineBudgetTimeoutError(URL, 0); }, {
        onDeliveryDeadlineExceeded: (info: DeliveryDeadlineExceededInfo) => oldSeen.push(info),
      })
    );
    q.start();
    try {
      q.reviseDeliveryDeadlineExceededCallback((info) => newSeen.push(info));
      q.enqueue(item("budget-1"));
      nowMs = 100; // the attempt runs 100ms into the delivery's life
      await t.step(); // the stamped budget fires mid-call
      assert.deepEqual(oldSeen, []);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0]?.id, "budget-1");
      assert.equal(newSeen[0]?.attempts, 1);
      assert.equal(newSeen[0]?.elapsedMs, 100);
      assert.equal(newSeen[0]?.deadlineMs, 250);
      const dead = q.getDeadLetter();
      assert.equal(dead.length, 1);
      assert.equal(dead[0]?.attempts, 1);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer: expirations keep dead-lettering immediately and counting, and the WR-99 slo_missed attribution still fires", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const seen: DeliveryDeadlineExceededInfo[] = [];
    const sloMissSeen: SloMissInfo[] = [];
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => { throw new Error("boom"); }, {
        onDeliveryDeadlineExceeded: (info: DeliveryDeadlineExceededInfo) => seen.push(info),
        latency: { sloMs: 5000, now: () => nowMs, onSloMiss: (info) => sloMissSeen.push(info) },
      })
    );
    q.start();
    try {
      q.enqueue(item("clear-1"));
      await t.step(); // attempt 1 fails
      nowMs = 300;
      await t.step(); // expires
      assert.equal(seen.length, 1);
      assert.equal(sloMissSeen.length, 1);
      assert.equal(sloMissSeen[0]?.deadlineBudgetExhausted, true);
      q.reviseDeliveryDeadlineExceededCallback(null);
      nowMs = 1000;
      q.enqueue(item("clear-2"));
      await t.step(); // attempt 1 fails
      nowMs = 1300;
      await t.step(); // expires
      assert.equal(seen.length, 1); // the operator hears nothing more
      assert.equal(sloMissSeen.length, 2); // WR-99 attribution untouched
      assert.equal(q.getDeadLetter().length, 2);
      assert.equal(q.getDeadLetter()[1]?.attempts, 1);
      assert.ok(
        q.renderMetrics().includes(`relay_delivery_deadline_exceeded_total{endpoint="${URL}"} 2`)
      );
    } finally {
      q.stop();
    }
  });

  it("a queue without delivery deadlines cannot gain an observer at runtime — must restart", async () => {
    const t = stepTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: t.setTimer,
    });
    assert.throws(
      () => q.reviseDeliveryDeadlineExceededCallback(() => {}),
      /requires a restart/
    );
    assert.throws(
      () => q.reviseDeliveryDeadlineExceededCallback(null),
      /requires a restart/
    );
    q.stop();
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const seen: DeliveryDeadlineExceededInfo[] = [];
    const live = (info: DeliveryDeadlineExceededInfo) => seen.push(info);
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => { throw new Error("boom"); }, {
        onDeliveryDeadlineExceeded: live,
      })
    );
    q.start();
    try {
      assert.throws(
        () => q.reviseDeliveryDeadlineExceededCallback(42 as never),
        RangeError
      );
      assert.throws(
        () => q.reviseDeliveryDeadlineExceededCallback("nope" as never),
        RangeError
      );
      q.enqueue(item("bad-1"));
      await t.step(); // attempt 1 fails
      nowMs = 300;
      await t.step(); // expires
      assert.equal(seen.length, 1);
      assert.equal(seen[0]?.id, "bad-1");
    } finally {
      q.stop();
    }
  });

  it("same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const seen: DeliveryDeadlineExceededInfo[] = [];
    const live = (info: DeliveryDeadlineExceededInfo) => seen.push(info);
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => { throw new Error("boom"); }, {
        onDeliveryDeadlineExceeded: live,
      })
    );
    q.start();
    try {
      q.reviseDeliveryDeadlineExceededCallback(live); // no-op, no throw
      q.enqueue(item("noop-1"));
      await t.step();
      nowMs = 300;
      await t.step();
      assert.equal(seen.length, 1);
      q.reviseDeliveryDeadlineExceededCallback(null);
      q.reviseDeliveryDeadlineExceededCallback(null); // clearing when unset: no-op
      nowMs = 1000;
      q.enqueue(item("noop-2"));
      await t.step();
      nowMs = 1300;
      await t.step();
      assert.equal(seen.length, 1);
      assert.equal(q.getDeadLetter().length, 2);
    } finally {
      q.stop();
    }
  });

  it("a WR-341 deadline revision is visible to the new callback: it receives the revised deadlineMs", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const seen: DeliveryDeadlineExceededInfo[] = [];
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => { throw new Error("boom"); })
    );
    q.start();
    try {
      q.enqueue(item("retune-1"));
      await t.step(); // attempt 1 at t=0 fails
      q.reviseDeliveryDeadlineExceededCallback((info) => seen.push(info));
      // Lengthen the deadline: the 300ms mark is now inside the budget.
      q.reviseDeliveryDeadline({ deadlines: { [URL]: 500 } });
      nowMs = 300;
      await t.step(); // attempt 2 runs (inside the new deadline)
      assert.equal(seen.length, 0);
      assert.equal(q.getDeadLetter().length, 0);
      nowMs = 600; // past the revised 500ms deadline
      await t.step(); // dispatch expires
      assert.equal(seen.length, 1);
      assert.equal(seen[0]?.attempts, 2);
      assert.equal(seen[0]?.elapsedMs, 600);
      assert.equal(seen[0]?.deadlineMs, 500); // the revised value, not 250
    } finally {
      q.stop();
    }
  });

  it("a dead-letter replay starts a fresh deadline cycle, unaffected by a callback revision", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const seen: DeliveryDeadlineExceededInfo[] = [];
    let fail = true;
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => {
        if (fail) throw new Error("boom");
      }, {
        onDeliveryDeadlineExceeded: (info: DeliveryDeadlineExceededInfo) => seen.push(info),
      })
    );
    q.start();
    try {
      q.enqueue(item("replay-1"));
      await t.step(); // attempt 1 fails at t=0
      nowMs = 600;
      await t.step(); // expired -> dead letter
      assert.equal(q.getDeadLetter().length, 1);
      assert.equal(seen.length, 1);
      // Swap the observer, then replay: the replayed delivery gets a
      // fresh admission instant and must not instantly expire.
      q.reviseDeliveryDeadlineExceededCallback((info) => seen.push(info));
      nowMs = 1000;
      fail = false;
      assert.equal(q.replayDeadLetter("replay-1"), true);
      await t.step();
      assert.equal(seen.length, 1); // no second expiry
      assert.equal(q.getDeadLetter().length, 0);
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer delivery-deadline-exceeded callback revision (WR-391)", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  async function drainUntil(cond: () => boolean, ms = 8000): Promise<void> {
    const deadline = Date.now() + ms;
    while (!cond()) {
      if (Date.now() > deadline) throw new Error("timed out waiting for condition");
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  function postWebhook(port: number) {
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: {
            "x-signature": signSha256(BODY, relaySecret),
            "content-type": "application/json",
            "content-length": String(BODY.length),
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
  }

  function exceededEvents(audit: AuditLog) {
    return audit.query({ event: "delivery_deadline_exceeded" }) as Array<{
      attempts: number;
      elapsedMs: number;
      deadlineMs: number;
    }>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "delivery_deadline_exceeded_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server whose downstream takes ~80ms then fails, against a 50ms deadline. */
  function expiringServer(onDeliveryDeadlineExceeded?: (info: DeliveryDeadlineExceededInfo) => void) {
    const dir = mkdtempSync(join(tmpdir(), "dlexceeded-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const slowFailing: Sender = async () => {
      await sleep(80);
      throw new Error("downstream down");
    };
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: slowFailing,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 5,
        jitterMs: 0,
        deliveryDeadline: { deadlines: { [URL]: 50 } },
        ...(onDeliveryDeadlineExceeded !== undefined ? { onDeliveryDeadlineExceeded } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  it("replacing the operator callback routes the next expiry to the new callback and the delivery_deadline_exceeded audit still lands", async () => {
    const oldSeen: DeliveryDeadlineExceededInfo[] = [];
    const newSeen: DeliveryDeadlineExceededInfo[] = [];
    const { relay, audit } = expiringServer((info) => oldSeen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => exceededEvents(audit).length >= 1);
    assert.equal(oldSeen[0]?.deadlineMs, 50);
    assert.ok((oldSeen[0]?.elapsedMs ?? 0) >= 50);
    assert.equal(exceededEvents(audit)[0]?.deadlineMs, 50);
    assert.deepEqual(newSeen, []);
    const newCb = (info: DeliveryDeadlineExceededInfo) => newSeen.push(info);
    relay.reviseDeliveryDeadlineExceededCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => exceededEvents(audit).length >= 2);
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen[0]?.deadlineMs, 50);
    assert.ok((newSeen[0]?.elapsedMs ?? 0) >= 50);
    assert.equal(exceededEvents(audit)[1]?.deadlineMs, 50);
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = expiringServer((_info) => {});
    await listen(relay);
    const newCb = (_info: DeliveryDeadlineExceededInfo) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseDeliveryDeadlineExceededCallback!(newCb);
    // set -> cleared.
    relay.reviseDeliveryDeadlineExceededCallback!(null);
    // cleared -> set.
    relay.reviseDeliveryDeadlineExceededCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseDeliveryDeadlineExceededCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseDeliveryDeadlineExceededCallback!(null);
    relay.reviseDeliveryDeadlineExceededCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [
        ["set", "set"],
        ["set", "cleared"],
        ["cleared", "set"],
        ["set", "cleared"],
      ]
    );
    // A server born without a callback: clearing when unset is a no-op,
    // and the first set audits cleared -> set. (Deadlines are configured,
    // only the observer is absent.)
    const { relay: bare, audit: bareAudit } = expiringServer();
    await listen(bare);
    bare.reviseDeliveryDeadlineExceededCallback!(null);
    bare.reviseDeliveryDeadlineExceededCallback!(newCb);
    assert.deepEqual(
      (bareAudit.query({ event: "delivery_deadline_exceeded_callback_revised" }) as Array<{
        previous: string;
        current: string;
      }>).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("a server without delivery deadlines cannot gain an observer at runtime — must restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dlexceeded-nodeadline-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: async () => { throw new Error("down"); },
      retry: {
        baseDelayMs: 10,
        maxAttempts: 2,
        jitterMs: 0,
      },
    });
    servers.push(relay);
    await listen(relay);
    assert.throws(
      () => relay.reviseDeliveryDeadlineExceededCallback!(() => {}),
      /requires a restart/
    );
    assert.equal(revisedEvents(audit).length, 0);
  });
});
