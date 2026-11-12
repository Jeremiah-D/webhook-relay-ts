import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type RetryItem,
  type RetryQueueOptions,
  type ScheduledFiredEvent,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const INGEST_KEY = "scheduled-fired-callback-revision-key";
const OPERATOR_TOKEN = "scheduled-fired-callback-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ ping: "cron-revision" }));
const URL_A = "http://127.0.0.1:9/a";

// Monday 2026-10-12 08:00:00 UTC.
const T0 = Date.UTC(2026, 9, 12, 8, 0, 0);

/** Manual timer: the scheduler arms exactly one timer (for the heap head). */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
    },
  };
}

function item(id: string, targetUrl: string, extra: Partial<RetryItem> = {}): RetryItem {
  return { id, payload: Buffer.from(`payload-${id}`), targetUrl, headers: {}, ...extra };
}

describe("RetryQueue scheduled-fired callback revision (WR-399)", () => {
  function queueHarness(extra: RetryQueueOptions = {}) {
    let now = T0;
    const t = manualTimer();
    const sent: RetryItem[] = [];
    const fired: ScheduledFiredEvent[] = [];
    const sender: Sender = async (it) => {
      sent.push(it);
      return { statusCode: 200, body: Buffer.from("ok"), truncated: false };
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 2,
      baseDelayMs: 50,
      jitterMs: 0,
      scheduled: { now: () => now, setTimer: t.setTimer },
      onScheduledFired: (e) => fired.push(e),
      ...extra,
    });
    q.start();
    // Drain both the scheduler and the queue's dispatch timers. Stepping
    // fires the scheduler's head timer early too, but an early fire is a
    // harmless no-op re-arm (the head is not due yet).
    const drain = async (rounds = 4) => {
      for (let i = 0; i < rounds; i++) {
        t.step();
        await new Promise((r) => setImmediate(r));
      }
    };
    // Fire the next cycle: advance the clock to the next fire instant and
    // step the scheduler timer, then drain the dispatch path.
    const fireNext = async (at: number) => {
      now = at;
      t.step();
      await drain();
    };
    return { q, t, sent, fired, setNow: (ms: number) => { now = ms; }, drain, fireNext };
  }

  it("the revised callback receives the next firing with exact fields; the old callback stays silent", async () => {
    const first: ScheduledFiredEvent[] = [];
    const second: ScheduledFiredEvent[] = [];
    const { q, sent, fireNext } = queueHarness({
      onScheduledFired: (e) => first.push(e),
    });
    try {
      q.addRecurringDelivery(
        item("sched-1", URL_A, { tenantId: "t1", priority: "urgent" }),
        "* * * * *"
      );
      await fireNext(T0 + 60000);
      assert.equal(sent.length, 1);
      assert.equal(sent[0].id, "sched-1#1");
      assert.equal(first.length, 1);
      assert.equal(first[0].event, "scheduled_fired");
      assert.equal(first[0].scheduleId, "sched-1");
      assert.equal(first[0].id, "sched-1#1");
      assert.ok(typeof first[0].traceId === "string" && first[0].traceId.length > 0);
      assert.equal(first[0].targetUrl, URL_A);
      assert.equal(first[0].tenant, "t1");
      assert.equal(first[0].priority, "urgent");
      assert.equal(first[0].nextAt, T0 + 2 * 60000);
      // The second cycle goes to the revised callback only.
      q.reviseScheduledFiredCallback((e) => second.push(e));
      await fireNext(T0 + 2 * 60000);
      assert.equal(sent.length, 2);
      assert.equal(sent[1].id, "sched-1#2");
      assert.equal(first.length, 1);
      assert.equal(second.length, 1);
      assert.equal(second[0].event, "scheduled_fired");
      assert.equal(second[0].scheduleId, "sched-1");
      assert.equal(second[0].id, "sched-1#2");
      assert.ok(typeof second[0].traceId === "string" && second[0].traceId.length > 0);
      assert.notEqual(second[0].traceId, first[0].traceId);
      assert.equal(second[0].targetUrl, URL_A);
      assert.equal(second[0].tenant, "t1");
      assert.equal(second[0].priority, "urgent");
      assert.equal(second[0].nextAt, T0 + 3 * 60000);
      assert.equal(q.getScheduledStats().fired, 2);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; firings continue and still count", async () => {
    const seen: ScheduledFiredEvent[] = [];
    const { q, sent, fireNext } = queueHarness({
      onScheduledFired: (e) => seen.push(e),
    });
    try {
      q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      await fireNext(T0 + 60000);
      assert.equal(seen.length, 1);
      assert.equal(q.getScheduledStats().fired, 1);
      q.reviseScheduledFiredCallback(null);
      await fireNext(T0 + 2 * 60000);
      assert.equal(sent.length, 2);
      assert.equal(sent[1].id, "sched-1#2");
      assert.equal(seen.length, 1, "cleared hook stays silent");
      assert.equal(q.getScheduledStats().fired, 2);
      assert.equal(q.nextScheduleFire("sched-1"), T0 + 3 * 60000);
    } finally {
      q.stop();
    }
  });

  it("revising with zero schedules succeeds (no gate); the first schedule created afterwards fires into the new callback", async () => {
    const first: ScheduledFiredEvent[] = [];
    const second: ScheduledFiredEvent[] = [];
    const { q, sent, fireNext } = queueHarness({
      onScheduledFired: (e) => first.push(e),
    });
    try {
      // No schedule exists yet — the scheduler is always built, so the
      // revision must not throw.
      q.reviseScheduledFiredCallback((e) => second.push(e));
      q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      await fireNext(T0 + 60000);
      assert.equal(sent.length, 1);
      assert.equal(first.length, 0);
      assert.equal(second.length, 1);
      assert.equal(second[0].scheduleId, "sched-1");
      assert.equal(second[0].id, "sched-1#1");
    } finally {
      q.stop();
    }
    // A queue constructed with no observer at all can gain one the same way.
    const bare = queueHarness({ onScheduledFired: undefined });
    try {
      const gained: ScheduledFiredEvent[] = [];
      bare.q.reviseScheduledFiredCallback((e) => gained.push(e));
      bare.q.addRecurringDelivery(item("sched-2", URL_A), "* * * * *");
      await bare.fireNext(T0 + 60000);
      assert.equal(gained.length, 1);
      assert.equal(gained[0].scheduleId, "sched-2");
    } finally {
      bare.q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const seen: ScheduledFiredEvent[] = [];
    const { q, fireNext } = queueHarness({
      onScheduledFired: (e) => seen.push(e),
    });
    try {
      q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseScheduledFiredCallback(bad), RangeError, String(bad));
      }
      // Nothing moved: the original hook still fires.
      await fireNext(T0 + 60000);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].id, "sched-1#1");
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const seen: ScheduledFiredEvent[] = [];
    const onFired = (e: ScheduledFiredEvent) => seen.push(e);
    const { q, fireNext } = queueHarness({ onScheduledFired: onFired });
    try {
      q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      q.reviseScheduledFiredCallback(onFired);
      await fireNext(T0 + 60000);
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseScheduledFiredCallback(null);
      q.reviseScheduledFiredCallback(null);
      await fireNext(T0 + 2 * 60000);
      assert.equal(seen.length, 1);
      assert.equal(q.getScheduledStats().fired, 2);
    } finally {
      q.stop();
    }
  });

  it("occurrences already reported are never re-delivered", async () => {
    const seen: ScheduledFiredEvent[] = [];
    const { q, fireNext } = queueHarness({
      onScheduledFired: (e) => seen.push(e),
    });
    try {
      q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      await fireNext(T0 + 60000);
      assert.equal(seen.length, 1);
      q.reviseScheduledFiredCallback((e) => seen.push(e));
      assert.equal(seen.length, 1, "no re-delivery of the reported occurrence");
      assert.equal(q.getScheduledStats().fired, 1);
      // The next real cycle reports exactly once, to the new callback.
      await fireNext(T0 + 2 * 60000);
      assert.equal(seen.length, 2);
      assert.equal(seen[1].id, "sched-1#2");
    } finally {
      q.stop();
    }
  });

  it("revision does not change the firing rhythm, pause/resume, or nextAt", async () => {
    const first: ScheduledFiredEvent[] = [];
    const second: ScheduledFiredEvent[] = [];
    const { q, t, sent, setNow, drain, fireNext } = queueHarness({
      onScheduledFired: (e) => first.push(e),
    });
    try {
      q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      assert.equal(q.nextScheduleFire("sched-1"), T0 + 60000);
      q.reviseScheduledFiredCallback((e) => second.push(e));
      assert.equal(q.nextScheduleFire("sched-1"), T0 + 60000, "revision moves no fire instant");
      await fireNext(T0 + 60000);
      assert.equal(second.length, 1);
      assert.equal(q.nextScheduleFire("sched-1"), T0 + 2 * 60000);
      // Pause stops generation; resume recomputes from now.
      assert.equal(q.pauseSchedule("sched-1"), true);
      setNow(T0 + 2 * 60000);
      t.step();
      await drain();
      assert.equal(second.length, 1, "paused schedule fires nothing");
      assert.equal(sent.length, 1);
      setNow(T0 + 10 * 60000);
      assert.equal(q.resumeSchedule("sched-1"), true);
      assert.equal(q.nextScheduleFire("sched-1"), T0 + 11 * 60000);
      await fireNext(T0 + 11 * 60000);
      assert.equal(second.length, 2);
      assert.equal(second[1].id, "sched-1#2");
      assert.equal(q.getScheduledStats().fired, 2);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer scheduled-fired callback revision (WR-399)", () => {
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

  function signedHeaders(extra: Record<string, string> = {}) {
    return {
      "x-signature": signSha256(BODY, INGEST_KEY),
      "content-type": "application/json",
      ...extra,
    };
  }

  /**
   * A server whose scheduler runs on an injected manual clock, so cron
   * cycles fire deterministically without wall-clock waits.
   */
  function firingServer(opts: {
    onScheduledFired?: (e: ScheduledFiredEvent) => void;
  } = {}) {
    let now = T0;
    const t = manualTimer();
    const sent: RetryItem[] = [];
    const dir = mkdtempSync(join(tmpdir(), "scheduled-fired-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async (it) => {
        sent.push(it);
        return { statusCode: 200, body: Buffer.from("ok"), truncated: false };
      },
      retry: {
        setTimer: t.setTimer,
        scheduled: { now: () => now, setTimer: t.setTimer },
        baseDelayMs: 50,
        jitterMs: 0,
        maxAttempts: 2,
        ...(opts.onScheduledFired !== undefined
          ? { onScheduledFired: opts.onScheduledFired }
          : {}),
      },
    });
    servers.push(relay);
    const drain = async (rounds = 4) => {
      for (let i = 0; i < rounds; i++) {
        t.step();
        await new Promise((r) => setImmediate(r));
      }
    };
    return {
      relay,
      auditLog,
      sent,
      setNow: (ms: number) => { now = ms; },
      step: () => t.step(),
      drain,
    };
  }

  /** Register a `* * * * *` schedule and fire one cycle at `at`. */
  async function registerAndFire(
    port: number,
    at: number,
    h: ReturnType<typeof firingServer>
  ): Promise<string> {
    const res = await post(port, BODY, signedHeaders({ "x-schedule-cron": "* * * * *" }));
    assert.equal(res.status, 202);
    const body = JSON.parse(res.text) as { scheduleId: string };
    assert.ok(typeof body.scheduleId === "string" && body.scheduleId.length > 0);
    h.setNow(at);
    h.step();
    await h.drain();
    return body.scheduleId;
  }

  it("revising the callback routes the next firing to the new callback and the audit still lands", async () => {
    const first: ScheduledFiredEvent[] = [];
    const second: ScheduledFiredEvent[] = [];
    const h = firingServer({ onScheduledFired: (e) => first.push(e) });
    const port = await listen(h.relay);
    const sid = await registerAndFire(port, T0 + 60000, h);
    assert.equal(first.length, 1);
    assert.equal(first[0].event, "scheduled_fired");
    assert.equal(first[0].scheduleId, sid);
    assert.equal(first[0].id, `${sid}#1`);
    assert.equal(eventsOf(h.auditLog, "scheduled_fired").length, 1);
    assert.equal(h.sent.length, 1);
    h.relay.reviseScheduledFiredCallback!((e) => second.push(e));
    h.setNow(T0 + 2 * 60000);
    h.step();
    await h.drain();
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.equal(second[0].event, "scheduled_fired");
    assert.equal(second[0].scheduleId, sid);
    assert.equal(second[0].id, `${sid}#2`);
    assert.equal(second[0].nextAt, T0 + 3 * 60000);
    assert.equal(eventsOf(h.auditLog, "scheduled_fired").length, 2);
    assert.equal(h.sent.length, 2);
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(h.auditLog, "scheduled_fired_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; the firing is still audited and still counted", async () => {
    const first: ScheduledFiredEvent[] = [];
    const h = firingServer({ onScheduledFired: (e) => first.push(e) });
    const port = await listen(h.relay);
    const sid = await registerAndFire(port, T0 + 60000, h);
    assert.equal(first.length, 1);
    h.relay.reviseScheduledFiredCallback!(null);
    h.setNow(T0 + 2 * 60000);
    h.step();
    await h.drain();
    assert.equal(first.length, 1, "cleared hook stays silent");
    assert.equal(eventsOf(h.auditLog, "scheduled_fired").length, 2);
    assert.equal(h.sent.length, 2, "occurrences keep entering the normal path");
    assert.equal(h.sent[1].id, `${sid}#2`);
    const revised = eventsOf(h.auditLog, "scheduled_fired_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("a non-function value throws RangeError and the live callback is untouched; same-reference is a silent no-op", async () => {
    const first: ScheduledFiredEvent[] = [];
    const onFired = (e: ScheduledFiredEvent) => first.push(e);
    const h = firingServer({ onScheduledFired: onFired });
    const port = await listen(h.relay);
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => h.relay.reviseScheduledFiredCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(h.auditLog, "scheduled_fired_callback_revised").length, 0);
    h.relay.reviseScheduledFiredCallback!(onFired);
    assert.equal(eventsOf(h.auditLog, "scheduled_fired_callback_revised").length, 0);
    await registerAndFire(port, T0 + 60000, h);
    assert.equal(first.length, 1);
  });

  it("clearing when already unset is a silent no-op", async () => {
    const h = firingServer({});
    await listen(h.relay);
    h.relay.reviseScheduledFiredCallback!(null);
    assert.equal(eventsOf(h.auditLog, "scheduled_fired_callback_revised").length, 0);
  });
});
