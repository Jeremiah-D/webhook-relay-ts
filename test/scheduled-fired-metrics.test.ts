import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  type RetryItem,
  type RetryQueueOptions,
  type ScheduledFiredEvent,
  type Sender,
} from "../src/retry.ts";

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

describe("WR-405 relay_scheduled_fired_total Prometheus counter", () => {
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
    // Fire the next cron cycle: advance the clock to the next fire instant
    // and step the scheduler timer, then drain the dispatch path.
    const fireNext = async (at: number) => {
      now = at;
      t.step();
      await drain();
    };
    return {
      q,
      t,
      sent,
      fired,
      now: () => now,
      setNow: (ms: number) => {
        now = ms;
      },
      drain,
      fireNext,
    };
  }

  it("after two cron firings the exposition carries relay_scheduled_fired_total 2, matching getScheduledStats().fired", async () => {
    const { q, sent, fired, fireNext } = queueHarness();
    try {
      q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      await fireNext(T0 + 60000);
      await fireNext(T0 + 2 * 60000);
      assert.equal(sent.length, 2);
      assert.equal(fired.length, 2);
      assert.equal(q.getScheduledStats().fired, 2);
      const exposition = q.renderMetrics();
      assert.match(exposition, /relay_scheduled_fired_total 2\n/);
    } finally {
      q.stop();
    }
  });

  it("a pure-cron relay (zero deliver_at parked) exposes the series on its first firing — the WR-405 gate widening", async () => {
    const { q, fireNext } = queueHarness();
    try {
      q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      // Nothing parked and nothing fired yet: no scheduled block at all.
      assert.ok(!q.renderMetrics().includes("relay_scheduled_"));
      await fireNext(T0 + 60000);
      assert.equal(q.getScheduledStats().fired, 1);
      assert.equal(q.getScheduledStats().scheduled, 0);
      const exposition = q.renderMetrics();
      assert.match(exposition, /relay_scheduled_fired_total 1\n/);
    } finally {
      q.stop();
    }
  });

  it("an untouched relay exposes no relay_scheduled_ series at all", async () => {
    const { q } = queueHarness();
    try {
      assert.ok(!q.renderMetrics().includes("relay_scheduled_"));
    } finally {
      q.stop();
    }
  });

  it("clearing the WR-399 observer (null) still counts firings in the counter", async () => {
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
      assert.equal(seen.length, 1, "cleared hook stays silent");
      assert.equal(q.getScheduledStats().fired, 2);
      assert.match(q.renderMetrics(), /relay_scheduled_fired_total 2\n/);
    } finally {
      q.stop();
    }
  });

  it("a restart resets the counter to zero (in-memory; documented limitation)", async () => {
    const first = queueHarness();
    try {
      first.q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      await first.fireNext(T0 + 60000);
      await first.fireNext(T0 + 2 * 60000);
      assert.match(first.q.renderMetrics(), /relay_scheduled_fired_total 2\n/);
    } finally {
      first.q.stop();
    }
    // A fresh queue is a fresh relay: no history survives the restart.
    const second = queueHarness();
    try {
      assert.equal(second.q.getScheduledStats().fired, 0);
      assert.ok(!second.q.renderMetrics().includes("relay_scheduled_"));
    } finally {
      second.q.stop();
    }
  });

  it("fired renders as 0, not missing, while the scheduled block is present", async () => {
    const { q, now } = queueHarness();
    try {
      // Parking one deliver_at opens the block; no cron schedule exists,
      // so nothing has ever fired.
      q.enqueue(item("c1", URL_A, { deliverAt: now() + 1000 }));
      const exposition = q.renderMetrics();
      assert.match(exposition, /relay_scheduled_total 1\n/);
      assert.match(exposition, /relay_scheduled_fired_total 0\n/);
    } finally {
      q.stop();
    }
  });

  it("the existing three series keep their values alongside fired", async () => {
    const { q, sent, now, setNow, drain, t } = queueHarness();
    try {
      q.enqueue(item("c1", URL_A, { deliverAt: now() + 1000 }));
      q.enqueue(item("c2", URL_A, { deliverAt: now() + 2000 }));
      assert.equal(q.cancelScheduled("c2"), true);
      setNow(now() + 1000);
      t.step(); // c1 due
      await drain();
      assert.equal(sent.length, 1);
      assert.equal(sent[0].id, "c1");
      const exposition = q.renderMetrics();
      assert.match(exposition, /relay_scheduled_total 2\n/);
      assert.match(exposition, /relay_scheduled_due_total 1\n/);
      assert.match(exposition, /relay_scheduled_canceled_total 1\n/);
      assert.match(exposition, /relay_scheduled_fired_total 0\n/);
    } finally {
      q.stop();
    }
  });

  it("the fired series renders after the canceled series, in fixed order", async () => {
    const { q, fireNext } = queueHarness();
    try {
      q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
      await fireNext(T0 + 60000);
      const exposition = q.renderMetrics();
      const canceledAt = exposition.indexOf("relay_scheduled_canceled_total 0\n");
      const firedAt = exposition.indexOf("relay_scheduled_fired_total 1\n");
      assert.ok(canceledAt >= 0, "canceled series present");
      assert.ok(firedAt > canceledAt, "fired series follows canceled");
    } finally {
      q.stop();
    }
  });
});
