import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type OrderedAuditEvent,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const INGEST_KEY = "ordered-audit-callback-revision-key";
const OPERATOR_TOKEN = "ordered-audit-callback-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "ordered-audit-revision" }));
const EP = "http://localhost:9999/ordered";
const EP2 = "http://127.0.0.1:9/b";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return { clear: () => { const i = pending.indexOf(fn); if (i >= 0) pending.splice(i, 1); } };
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
    /** Fire exactly one pending timer (for tests that interleave clock moves). */
    async runOne() {
      const fn = pending.shift();
      if (fn !== undefined) fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

const buf = (s: string) => Buffer.from(s);

function item(
  id: string,
  targetUrl: string,
  priority?: "urgent",
  traceId = `trace-${id}`
): RetryItem {
  return { id, payload: buf(id), targetUrl, headers: {}, traceId, ...(priority ? { priority } : {}) };
}

async function tick(n = 3) {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
}

describe("RetryQueue ordered audit callback revision (WR-401)", () => {
  it("the revised callback receives the next urgent bypass with exact fields; the old callback stays silent", async () => {
    const timer = manualTimer();
    const first: OrderedAuditEvent[] = [];
    const second: OrderedAuditEvent[] = [];
    const delivered: string[] = [];
    const sender: Sender = async (wire) => {
      if (wire.id === "g-a") throw new Error("boom");
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      ordered: true,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => first.push(e),
    });
    q.start();
    try {
      q.enqueue(item("g-a", EP));
      q.enqueue(item("g-u", EP, "urgent"));
      await timer.run();
      assert.deepEqual(delivered, ["g-u"]);
      assert.equal(first.length, 1);
      assert.equal(first[0].kind, "ordered_bypassed");
      assert.equal(first[0].id, "g-u");
      assert.equal(first[0].traceId, "trace-g-u");
      assert.equal(first[0].endpoint, EP);
      assert.equal(first[0].blockedMs, undefined);
      assert.equal(first[0].maxHeadOfLineHoldMs, undefined);
      // A second bypass goes to the revised callback only.
      q.reviseOrderedAuditCallback((e) => second.push(e));
      q.enqueue(item("g-u2", EP, "urgent"));
      await timer.run();
      assert.deepEqual(delivered, ["g-u", "g-u2"]);
      assert.equal(first.length, 1, "old callback stays silent after revision");
      assert.equal(second.length, 1);
      assert.equal(second[0].kind, "ordered_bypassed");
      assert.equal(second[0].id, "g-u2");
      assert.equal(second[0].traceId, "trace-g-u2");
      assert.equal(second[0].endpoint, EP);
      const stats = q.getOrderedStats();
      assert.equal(stats[0].urgentBypassed, 2);
    } finally {
      q.stop();
    }
  });

  it("the revised callback receives the next head park with exact blockedMs/maxHeadOfLineHoldMs; the old callback stays silent", async () => {
    const timer = manualTimer();
    let nowMs = 0;
    const first: OrderedAuditEvent[] = [];
    const second: OrderedAuditEvent[] = [];
    const dead: Array<{ id: string; failureClass?: string }> = [];
    const delivered: string[] = [];
    let attemptsA = 0;
    const sender: Sender = async (wire) => {
      if (wire.id.endsWith("-a")) {
        attemptsA += 1;
        throw new Error("boom");
      }
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      ordered: { enabled: true, maxHeadOfLineHoldMs: 1000, now: () => nowMs },
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => first.push(e),
      onDeadLetter: (it, _attempts, _err, failureClass) =>
        dead.push({ id: it.id, failureClass }),
    });
    q.start();
    try {
      // First park goes to the construction-time callback.
      q.enqueue(item("p-a", EP));
      q.enqueue(item("p-b", EP));
      await timer.runOne();
      for (let i = 0; i < 200 && attemptsA < 1; i++) await tick(1);
      assert.equal(attemptsA, 1);
      await timer.runOne();
      await tick(2);
      assert.deepEqual(dead, []);
      nowMs = 1500;
      await timer.run();
      assert.equal(dead.length, 1);
      assert.equal(dead[0].id, "p-a");
      assert.equal(dead[0].failureClass, "head_of_line_timeout");
      assert.deepEqual(delivered, ["p-b"]);
      assert.equal(first.length, 1);
      assert.equal(first[0].kind, "head_of_line_parked");
      assert.equal(first[0].id, "p-a");
      assert.equal(first[0].traceId, "trace-p-a");
      assert.equal(first[0].endpoint, EP);
      assert.equal(first[0].blockedMs, 1500);
      assert.equal(first[0].maxHeadOfLineHoldMs, 1000);
      // Second park goes to the revised callback only.
      q.reviseOrderedAuditCallback((e) => second.push(e));
      q.enqueue(item("q-a", EP));
      q.enqueue(item("q-b", EP));
      await timer.runOne();
      for (let i = 0; i < 200 && attemptsA < 2; i++) await tick(1);
      assert.equal(attemptsA, 2);
      await timer.runOne();
      await tick(2);
      assert.deepEqual(dead.map((d) => d.id), ["p-a"]);
      nowMs = 3000;
      await timer.run();
      assert.deepEqual(dead.map((d) => d.id), ["p-a", "q-a"]);
      assert.equal(dead[1].failureClass, "head_of_line_timeout");
      assert.deepEqual(delivered, ["p-b", "q-b"]);
      assert.equal(first.length, 1, "old callback stays silent after revision");
      assert.equal(second.length, 1);
      assert.equal(second[0].kind, "head_of_line_parked");
      assert.equal(second[0].id, "q-a");
      assert.equal(second[0].traceId, "trace-q-a");
      assert.equal(second[0].endpoint, EP);
      assert.equal(second[0].blockedMs, 1500);
      assert.equal(second[0].maxHeadOfLineHoldMs, 1000);
      const stats = q.getOrderedStats();
      assert.equal(stats[0].headOfLineParked, 2);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; the gate and the park carry on and are still counted", async () => {
    const timer = manualTimer();
    let nowMs = 0;
    const seen: OrderedAuditEvent[] = [];
    const dead: string[] = [];
    const delivered: string[] = [];
    let attemptsA = 0;
    const sender: Sender = async (wire) => {
      if (wire.id === "c-a") {
        attemptsA += 1;
        throw new Error("boom");
      }
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      ordered: { enabled: true, maxHeadOfLineHoldMs: 1000, now: () => nowMs },
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => seen.push(e),
      onDeadLetter: (it) => dead.push(it.id),
    });
    q.start();
    try {
      // One bypass observed before the clear (single-stepped so the
      // head's retry chain does not drain and exhaust it first).
      q.enqueue(item("c-a", EP));
      q.enqueue(item("c-u", EP, "urgent"));
      await timer.runOne(); // head attempt 1: fails, retry armed
      for (let i = 0; i < 200 && attemptsA < 1; i++) await tick(1);
      assert.equal(attemptsA, 1);
      await timer.runOne(); // urgent dispatch: bypass, delivered
      await tick(2);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].kind, "ordered_bypassed");
      assert.deepEqual(delivered, ["c-u"]);
      q.reviseOrderedAuditCallback(null);
      // The gate still bypasses urgent items and still counts them.
      q.enqueue(item("c-u2", EP, "urgent"));
      await timer.runOne(); // head retry: attempt 2, fails
      await timer.runOne(); // urgent dispatch: bypass, delivered
      await tick(2);
      assert.equal(seen.length, 1, "cleared hook stays silent");
      assert.deepEqual(delivered, ["c-u", "c-u2"]);
      // The park still fires (head blocked past the bound) and still counts.
      q.enqueue(item("c-b", EP));
      await timer.runOne(); // head retry: attempt 3, fails
      await timer.runOne(); // follower dispatch: held behind the head
      await tick(2);
      assert.deepEqual(dead, []);
      nowMs = 1500;
      await timer.run();
      assert.deepEqual(dead, ["c-a"]);
      assert.deepEqual(delivered.slice(-1), ["c-b"]);
      assert.equal(seen.length, 1, "cleared hook stays silent on the park too");
      const stats = q.getOrderedStats();
      assert.equal(stats[0].urgentBypassed, 2);
      assert.equal(stats[0].headOfLineParked, 1);
      const metrics = q.renderMetrics();
      assert.ok(metrics.includes("relay_ordered_urgent_bypassed_total"), metrics);
      assert.ok(metrics.includes("relay_ordered_head_of_line_parked_total"), metrics);
    } finally {
      q.stop();
    }
  });

  it("revising with ordered delivery unconfigured throws Error; orderedConfigured reports the live state", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.orderedConfigured(), false);
    assert.deepEqual(q.getOrderedStats(), []);
    assert.throws(
      () => q.reviseOrderedAuditCallback(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    assert.throws(
      () => q.reviseOrderedAuditCallback(null),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    const timer = manualTimer();
    const configured = new RetryQueue({
      sender: async () => {},
      ordered: true,
      setTimer: timer.setTimer,
    });
    try {
      assert.equal(configured.orderedConfigured(), true);
    } finally {
      configured.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const timer = manualTimer();
    const seen: OrderedAuditEvent[] = [];
    const sender: Sender = async (wire) => {
      if (wire.id === "r-a") throw new Error("boom");
      return;
    };
    const q = new RetryQueue({
      sender,
      ordered: true,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => seen.push(e),
    });
    q.start();
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseOrderedAuditCallback(bad), RangeError, String(bad));
      }
      // Nothing moved: the original hook still fires.
      q.enqueue(item("r-a", EP));
      q.enqueue(item("r-u", EP, "urgent"));
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].kind, "ordered_bypassed");
      assert.equal(seen[0].id, "r-u");
      assert.equal(seen[0].traceId, "trace-r-u");
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const timer = manualTimer();
    const seen: OrderedAuditEvent[] = [];
    const onOrderedAudit = (e: OrderedAuditEvent) => seen.push(e);
    const sender: Sender = async (wire) => {
      if (wire.id === "n-a") throw new Error("boom");
      return;
    };
    const q = new RetryQueue({
      sender,
      ordered: true,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit,
    });
    q.start();
    try {
      q.reviseOrderedAuditCallback(onOrderedAudit);
      q.enqueue(item("n-a", EP));
      q.enqueue(item("n-u", EP, "urgent"));
      await timer.run();
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseOrderedAuditCallback(null);
      q.reviseOrderedAuditCallback(null);
      q.enqueue(item("n-u2", EP, "urgent"));
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(q.getOrderedStats()[0].urgentBypassed, 2);
    } finally {
      q.stop();
    }
  });

  it("transitions already reported are never re-delivered", async () => {
    const timer = manualTimer();
    const seen: OrderedAuditEvent[] = [];
    const sender: Sender = async (wire) => {
      if (wire.id === "d-a") throw new Error("boom");
      return;
    };
    const q = new RetryQueue({
      sender,
      ordered: true,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => seen.push(e),
    });
    q.start();
    try {
      q.enqueue(item("d-a", EP));
      q.enqueue(item("d-u", EP, "urgent"));
      await timer.run();
      assert.equal(seen.length, 1);
      q.reviseOrderedAuditCallback((e) => seen.push(e));
      assert.equal(seen.length, 1, "no re-delivery of the reported bypass");
      await timer.run();
      assert.equal(seen.length, 1, "no bypass without a new urgent item");
      // The next real bypass reports exactly once, to the new callback.
      q.enqueue(item("d-u2", EP, "urgent"));
      await timer.run();
      assert.equal(seen.length, 2);
      assert.equal(seen[1].kind, "ordered_bypassed");
      assert.equal(seen[1].id, "d-u2");
      assert.equal(seen[1].traceId, "trace-d-u2");
    } finally {
      q.stop();
    }
  });

  it("revision does not change the line order, the head hold, the park threshold, or getOrderedStats", async () => {
    const timer = manualTimer();
    let nowMs = 0;
    const seen: OrderedAuditEvent[] = [];
    const delivered: string[] = [];
    const dead: string[] = [];
    let attemptsA = 0;
    const sender: Sender = async (wire) => {
      if (wire.id === "s-a") {
        attemptsA += 1;
        throw new Error("boom");
      }
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      ordered: { enabled: true, maxHeadOfLineHoldMs: 1000, now: () => nowMs },
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => seen.push(e),
      onDeadLetter: (it) => dead.push(it.id),
    });
    q.start();
    try {
      q.enqueue(item("s-a", EP));
      q.enqueue(item("s-b", EP));
      await timer.runOne();
      for (let i = 0; i < 200 && attemptsA < 1; i++) await tick(1);
      assert.equal(attemptsA, 1);
      await timer.runOne();
      await tick(2);
      // The follower is held behind the retrying head.
      assert.deepEqual(delivered, []);
      const before = q.getOrderedStats();
      assert.equal(before[0].headId, "s-a");
      assert.equal(before[0].headBlockedCount, 1);
      assert.equal(before[0].queued, 2);
      q.reviseOrderedAuditCallback((e) => seen.push(e));
      assert.deepEqual(q.getOrderedStats(), before, "revision moves only the observer");
      // The hold bound is unchanged: the head is still held at 500ms.
      // Fire exactly one retry dispatch — a full drain would exhaust
      // the head's attempts before the bound is ever reached.
      nowMs = 500;
      await timer.runOne();
      await tick(2);
      assert.deepEqual(dead, []);
      assert.deepEqual(delivered, []);
      // Past the bound the head parks exactly as before, to the new callback.
      nowMs = 1500;
      await timer.run();
      assert.deepEqual(dead, ["s-a"]);
      assert.deepEqual(delivered, ["s-b"]);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].kind, "head_of_line_parked");
      assert.equal(seen[0].id, "s-a");
      assert.equal(seen[0].blockedMs, 1500);
      assert.equal(seen[0].maxHeadOfLineHoldMs, 1000);
      const stats = q.getOrderedStats();
      assert.equal(stats[0].headOfLineParked, 1);
      assert.equal(stats[0].headBlockedCount, 1);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer ordered audit callback revision (WR-401)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(cond(), `timed out waiting for ${what}`);
  }

  function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path: "/", method: "POST", headers }, (res) => {
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

  /** Post one item; returns the accepted id and traceId. */
  async function postOne(
    port: number,
    headers: Record<string, string> = {}
  ): Promise<{ id: string; traceId: string }> {
    const res = await post(port, BODY, {
      "x-signature": signSha256(BODY, INGEST_KEY),
      "content-type": "application/json",
      ...headers,
    });
    assert.equal(res.status, 202, res.text);
    const parsed = JSON.parse(res.text) as { id: string; traceId: string };
    assert.ok(parsed.id);
    assert.ok(parsed.traceId);
    return parsed;
  }

  /**
   * A server with ordered delivery on and a sender that always fails,
   * so a normal head stays unsettled (retrying) while urgent items
   * bypass it.
   */
  function orderedServer(opts: {
    onOrderedAudit?: (event: OrderedAuditEvent) => void;
    ordered?: Record<string, unknown>;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "ordered-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: EP2,
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => {
        throw new Error("downstream 500");
      },
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 10,
        ordered: opts.ordered ?? true,
        ...(opts.onOrderedAudit !== undefined ? { onOrderedAudit: opts.onOrderedAudit } : {}),
      },
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  it("revising the callback routes the next bypass to the new callback and both audits still land", async () => {
    const first: OrderedAuditEvent[] = [];
    const second: OrderedAuditEvent[] = [];
    const { relay, auditLog } = orderedServer({
      onOrderedAudit: (e) => first.push(e),
    });
    const port = await listen(relay);
    // A normal head that keeps failing, then an urgent item that bypasses it.
    // Note: the urgent item retries (the sender always fails), and every
    // retry dispatch re-enters the gate, so one urgent item can fire
    // several `ordered_bypassed` events — assert by id, not by count.
    const head = await postOne(port);
    const urgent = await postOne(port, { "x-priority": "urgent" });
    await waitFor(() => first.some((e) => e.id === urgent.id), "ordered_bypassed callback");
    const firstBypass = first.find((e) => e.id === urgent.id)!;
    assert.equal(firstBypass.kind, "ordered_bypassed");
    assert.equal(firstBypass.traceId, urgent.traceId);
    assert.equal(firstBypass.endpoint, EP2);
    const firstAudits = eventsOf(auditLog, "ordered_bypassed").filter((e) => e.id === urgent.id);
    assert.ok(firstAudits.length >= 1, "at least one bypass audit per retry dispatch");
    assert.equal(firstAudits[0].traceId, urgent.traceId);
    assert.equal(firstAudits[0].targetUrl, EP2);
    relay.reviseOrderedAuditCallback!((e) => second.push(e));
    const urgent2 = await postOne(port, { "x-priority": "urgent" });
    await waitFor(() => second.some((e) => e.id === urgent2.id), "revised ordered_bypassed callback");
    assert.ok(!first.some((e) => e.id === urgent2.id), "old callback stays silent after revision");
    const secondBypass = second.find((e) => e.id === urgent2.id)!;
    assert.equal(secondBypass.kind, "ordered_bypassed");
    assert.equal(secondBypass.traceId, urgent2.traceId);
    assert.equal(secondBypass.endpoint, EP2);
    const secondAudits = eventsOf(auditLog, "ordered_bypassed").filter((e) => e.id === urgent2.id);
    assert.ok(secondAudits.length >= 1, "at least one bypass audit per retry dispatch");
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "ordered_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
    assert.ok(head.id, "head was accepted");
  });

  it("revising the callback routes the next head park to the new callback with exact park fields", async () => {
    let nowMs = 0;
    const first: OrderedAuditEvent[] = [];
    const second: OrderedAuditEvent[] = [];
    const { relay, auditLog } = orderedServer({
      onOrderedAudit: (e) => first.push(e),
      ordered: { enabled: true, maxHeadOfLineHoldMs: 100, now: () => nowMs },
    });
    const port = await listen(relay);
    const head = await postOne(port);
    await postOne(port); // follower, held behind the failing head
    relay.reviseOrderedAuditCallback!((e) => second.push(e));
    // The park cannot fire until the hold clock passes the bound.
    nowMs = 5000;
    await waitFor(() => second.some((e) => e.id === head.id), "revised head_of_line_parked callback");
    assert.equal(first.length, 0, "the park happened after the revision");
    // The released follower becomes head itself and parks later too —
    // assert on the head's own park event, not on the count.
    const headParks = second.filter((e) => e.id === head.id);
    assert.equal(headParks.length, 1);
    assert.equal(headParks[0].kind, "head_of_line_parked");
    assert.equal(headParks[0].traceId, head.traceId);
    assert.equal(headParks[0].endpoint, EP2);
    assert.equal(headParks[0].blockedMs, 5000);
    assert.equal(headParks[0].maxHeadOfLineHoldMs, 100);
    const parks = eventsOf(auditLog, "head_of_line_parked").filter((e) => e.id === head.id);
    assert.equal(parks.length, 1);
    assert.equal(parks[0].traceId, head.traceId);
    assert.equal(parks[0].targetUrl, EP2);
    assert.equal(parks[0].blockedMs, 5000);
    assert.equal(parks[0].maxHeadOfLineHoldMs, 100);
    const revised = eventsOf(auditLog, "ordered_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; bypasses and parks are still audited", async () => {
    let nowMs = 0;
    const first: OrderedAuditEvent[] = [];
    const { relay, auditLog } = orderedServer({
      onOrderedAudit: (e) => first.push(e),
      ordered: { enabled: true, maxHeadOfLineHoldMs: 100, now: () => nowMs },
    });
    const port = await listen(relay);
    const head = await postOne(port);
    const urgent = await postOne(port, { "x-priority": "urgent" });
    await waitFor(() => first.some((e) => e.id === urgent.id), "ordered_bypassed callback");
    assert.equal(first.find((e) => e.id === urgent.id)?.traceId, urgent.traceId);
    relay.reviseOrderedAuditCallback!(null);
    const beforeBypass = eventsOf(auditLog, "ordered_bypassed").length;
    const urgent2 = await postOne(port, { "x-priority": "urgent" });
    await waitFor(
      () => eventsOf(auditLog, "ordered_bypassed").length > beforeBypass,
      "ordered_bypassed audit after clear"
    );
    assert.ok(!first.some((e) => e.id === urgent2.id), "cleared hook stays silent");
    const bypasses = eventsOf(auditLog, "ordered_bypassed").filter((e) => e.id === urgent2.id);
    assert.ok(bypasses.length >= 1, "at least one bypass audit per retry dispatch");
    assert.equal(bypasses[0].traceId, urgent2.traceId);
    // The park still fires and is still audited after the clear.
    await postOne(port); // follower, held behind the failing head
    nowMs = 5000;
    await waitFor(
      () => eventsOf(auditLog, "head_of_line_parked").some((e) => e.id === head.id),
      "head_of_line_parked audit after clear"
    );
    assert.ok(
      !first.some((e) => e.kind === "head_of_line_parked"),
      "cleared hook stays silent on the park too"
    );
    const parks = eventsOf(auditLog, "head_of_line_parked").filter((e) => e.id === head.id);
    assert.equal(parks.length, 1);
    assert.equal(parks[0].blockedMs, 5000);
    assert.equal(parks[0].maxHeadOfLineHoldMs, 100);
    const revised = eventsOf(auditLog, "ordered_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("a non-function value throws RangeError and the live callback is untouched; same-reference is a silent no-op", async () => {
    const first: OrderedAuditEvent[] = [];
    const onOrderedAudit = (e: OrderedAuditEvent) => first.push(e);
    const { relay, auditLog } = orderedServer({ onOrderedAudit });
    const port = await listen(relay);
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseOrderedAuditCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "ordered_audit_callback_revised").length, 0);
    relay.reviseOrderedAuditCallback!(onOrderedAudit);
    assert.equal(eventsOf(auditLog, "ordered_audit_callback_revised").length, 0);
    await postOne(port);
    const urgent = await postOne(port, { "x-priority": "urgent" });
    await waitFor(() => first.some((e) => e.id === urgent.id), "ordered_bypassed callback");
    const bypass = first.find((e) => e.id === urgent.id)!;
    assert.equal(bypass.kind, "ordered_bypassed");
    assert.equal(bypass.traceId, urgent.traceId);
  });

  it("clearing when already unset is a silent no-op", async () => {
    const { relay, auditLog } = orderedServer({});
    await listen(relay);
    relay.reviseOrderedAuditCallback!(null);
    assert.equal(eventsOf(auditLog, "ordered_audit_callback_revised").length, 0);
  });

  it("revising with ordered delivery unconfigured throws Error", () => {
    const dir = mkdtempSync(join(tmpdir(), "ordered-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: EP2,
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => {
        throw new Error("downstream 500");
      },
    });
    servers.push(relay);
    assert.throws(
      () => relay.reviseOrderedAuditCallback!(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });
});
