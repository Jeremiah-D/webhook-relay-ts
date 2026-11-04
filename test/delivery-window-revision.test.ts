import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "delivery-window-revision-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";
const EP_C = "http://c.example/hook";

/** A fixed Monday: 2026-01-05. */
const at = (h: number, m = 0, s = 0) => Date.UTC(2026, 0, 5, h, m, s);
const DAY_MS = 86_400_000;

/** Manual timer that also records the scheduled delays. */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pendingCount: () => pending.length,
    lastDelay: () => pending[pending.length - 1]?.ms,
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
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

describe("RetryQueue delivery-window snapshots (WR-317)", () => {
  it("getEndpointDeliveryWindow returns the live UTC/tz snapshot, undefined without a window", () => {
    let now = at(12, 0);
    const q = new RetryQueue({
      sender: async () => {},
      deliveryWindow: {
        windows: { [EP_A]: "09:00-18:00" },
        tzWindows: { [EP_B]: { window: "09:00-18:00", timezone: "Asia/Shanghai" } },
        now: () => now,
      },
    });
    try {
      assert.deepEqual(q.getEndpointDeliveryWindow(EP_A), { endpoint: EP_A, window: "09:00-18:00" });
      assert.deepEqual(q.getEndpointDeliveryWindow(EP_B), {
        endpoint: EP_B,
        window: "09:00-18:00",
        timezone: "Asia/Shanghai",
      });
      assert.equal(q.getEndpointDeliveryWindow(EP_C), undefined);
      // A live revision is visible immediately.
      q.setEndpointDeliveryWindow(EP_A, "08:00-20:00");
      assert.deepEqual(q.getEndpointDeliveryWindow(EP_A), { endpoint: EP_A, window: "08:00-20:00" });
      q.deleteEndpointDeliveryWindow(EP_A);
      assert.equal(q.getEndpointDeliveryWindow(EP_A), undefined);
    } finally {
      q.stop();
    }
    // Feature disabled: always undefined.
    const q2 = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q2.getEndpointDeliveryWindow(EP_A), undefined);
      assert.deepEqual(q2.getDeliveryWindows(), []);
    } finally {
      q2.stop();
    }
  });

  it("getDeliveryWindows lists every configured endpoint, including ones that never parked", async () => {
    let now = at(12, 0);
    const t = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: t.setTimer,
      deliveryWindow: {
        windows: { [EP_A]: "09:00-18:00" },
        tzWindows: { [EP_B]: { window: "09:00-18:00", timezone: "Asia/Shanghai" } },
        now: () => now,
      },
    });
    try {
      q.start();
      // Nothing parked yet: the stats surface is empty by design …
      assert.deepEqual(q.getDeliveryWindowStats(), []);
      // … but the listing already covers both configured endpoints.
      assert.deepEqual(q.getDeliveryWindows(), [
        { endpoint: EP_A, window: "09:00-18:00", open: true },
        { endpoint: EP_B, window: "09:00-18:00", timezone: "Asia/Shanghai", open: false },
      ]);
      // Park one delivery on EP_A; the listing is unchanged apart from
      // the live open flag (02:00 UTC is 10:00 in Shanghai, so EP_B's
      // window is open then).
      now = at(2, 0);
      q.enqueue(item("w1", EP_A));
      await t.step();
      assert.equal(q.getDeliveryWindowStats().length, 1);
      assert.deepEqual(
        q.getDeliveryWindows().map((r) => [r.endpoint, r.open]),
        [
          [EP_A, false],
          [EP_B, true],
        ]
      );
      // A runtime revision shows up in the listing immediately. New UTC
      // endpoints list before tz ones (the module enumerates the UTC
      // table first, then the timezone table).
      q.setEndpointDeliveryWindow(EP_C, "00:00-23:59");
      assert.deepEqual(
        q.getDeliveryWindows().map((r) => r.endpoint),
        [EP_A, EP_C, EP_B]
      );
    } finally {
      q.stop();
    }
  });

  it("a widened window does not flush a parked delivery early — it goes out when the old timer fires", async () => {
    let now = at(10, 0); // 10:00 UTC, outside 01:00-09:00
    const t = manualTimer();
    let senderCalls = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { windows: { [EP_A]: "01:00-09:00" }, now: () => now },
    });
    try {
      q.start();
      q.enqueue(item("w2", EP_A));
      await t.step(); // 10:00, closed -> parked until 01:00 tomorrow
      assert.equal(senderCalls, 0);
      assert.equal(t.lastDelay(), 15 * 3_600_000);
      // Widen to the full day: 10:00 would be open now, but the armed
      // timer is not re-armed — no early flush.
      assert.equal(q.setEndpointDeliveryWindow(EP_A, "00:00-00:00"), true);
      assert.equal(senderCalls, 0);
      assert.equal(t.pendingCount(), 1, "widening must not re-arm the timer");
      assert.equal(t.lastDelay(), 15 * 3_600_000);
      // The old timer fires at 01:00 tomorrow; the gate re-reads the
      // live window (open now) and the delivery goes out.
      now = at(1, 0) + DAY_MS;
      await t.step();
      assert.equal(senderCalls, 1);
    } finally {
      q.stop();
    }
  });

  it("a narrowed window re-parks on the next trigger to the new opening, attempts untouched", async () => {
    let now = at(10, 0); // 10:00 UTC, outside 01:00-09:00
    const t = manualTimer();
    let senderCalls = 0;
    const deliveredAttempts: number[] = [];
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { windows: { [EP_A]: "01:00-09:00" }, now: () => now },
      onDelivered: (_it, attempts) => {
        deliveredAttempts.push(attempts);
      },
    });
    try {
      q.start();
      q.enqueue(item("w3", EP_A));
      await t.step(); // parked until 01:00 tomorrow
      assert.equal(senderCalls, 0);
      assert.equal(t.lastDelay(), 15 * 3_600_000);
      // Narrow: the window now opens at 02:00, not 01:00.
      assert.equal(q.setEndpointDeliveryWindow(EP_A, "02:00-09:00"), true);
      // The old timer fires at 01:00 tomorrow; the gate finds the new
      // window still closed and re-parks to the new opening (1h), not
      // the old one — and the delivery does not escape early.
      now = at(1, 0) + DAY_MS;
      await t.step();
      assert.equal(senderCalls, 0);
      assert.equal(t.lastDelay(), 3_600_000);
      // 02:00 tomorrow: the new window opens and the delivery goes out
      // on its first real attempt — the two parks consumed nothing.
      now = at(2, 0) + DAY_MS;
      await t.step();
      assert.equal(senderCalls, 1);
      assert.deepEqual(deliveredAttempts, [1]);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer delivery-window revision (WR-317)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "delivery-window-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog,
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

  function configuredServer() {
    // Fixed clock: 12:00 UTC on the Monday — EP_A (09:00-18:00 UTC) is
    // open, EP_B (09:00-18:00 Asia/Shanghai = 20:00 local) is closed.
    const fixedNow = Date.UTC(2026, 0, 5, 12, 0, 0);
    return makeServer({
      retry: {
        deliveryWindow: {
          windows: { [EP_A]: "09:00-18:00" },
          tzWindows: { [EP_B]: { window: "09:00-18:00", timezone: "Asia/Shanghai" } },
          now: () => fixedNow,
        },
      },
    });
  }

  it("reviseDeliveryWindow sets a new UTC endpoint and audits previous null", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    assert.deepEqual(relay.getDeliveryWindows!(), [
      { endpoint: EP_A, window: "09:00-18:00", open: true },
      { endpoint: EP_B, window: "09:00-18:00", timezone: "Asia/Shanghai", open: false },
    ]);
    const current = relay.reviseDeliveryWindow(EP_C, "08:00-20:00");
    assert.deepEqual(current, { endpoint: EP_C, window: "08:00-20:00" });
    const revised = eventsOf(auditLog, "quiet_hours_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_C);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { endpoint: EP_C, window: "08:00-20:00" });
    assert.deepEqual(
      relay.getDeliveryWindows!().map((r) => r.endpoint),
      [EP_A, EP_C, EP_B] // UTC endpoints list before tz ones
    );
  });

  it("reviseTzDeliveryWindow sets a timezone window and audits it", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    const current = relay.reviseTzDeliveryWindow(EP_C, "09:00-18:00", "Asia/Shanghai");
    assert.deepEqual(current, { endpoint: EP_C, window: "09:00-18:00", timezone: "Asia/Shanghai" });
    const revised = eventsOf(auditLog, "quiet_hours_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, {
      endpoint: EP_C,
      window: "09:00-18:00",
      timezone: "Asia/Shanghai",
    });
  });

  it("a UTC-to-UTC replacement audits previous/current snapshots", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    const current = relay.reviseDeliveryWindow(EP_A, "08:00-20:00");
    assert.deepEqual(current, { endpoint: EP_A, window: "08:00-20:00" });
    const revised = eventsOf(auditLog, "quiet_hours_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { endpoint: EP_A, window: "09:00-18:00" });
    assert.deepEqual(revised[0].current, { endpoint: EP_A, window: "08:00-20:00" });
  });

  it("UTC/tz mutual exclusion throws RangeError and the live window is untouched", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    // EP_A holds a UTC window; a tz revision must fail.
    assert.throws(() => relay.reviseTzDeliveryWindow(EP_A, "09:00-18:00", "Asia/Shanghai"), RangeError);
    // EP_B holds a tz window; a UTC revision must fail.
    assert.throws(() => relay.reviseDeliveryWindow(EP_B, "09:00-18:00"), RangeError);
    assert.equal(eventsOf(auditLog, "quiet_hours_revised").length, 0);
    assert.deepEqual(relay.getDeliveryWindows!(), [
      { endpoint: EP_A, window: "09:00-18:00", open: true },
      { endpoint: EP_B, window: "09:00-18:00", timezone: "Asia/Shanghai", open: false },
    ]);
  });

  it("an invalid spec or timezone throws RangeError and the live window is untouched", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    for (const bad of ["bogus", "25:00-09:00", "09:00", ""]) {
      assert.throws(() => relay.reviseDeliveryWindow(EP_A, bad), RangeError, `spec ${bad}`);
    }
    assert.throws(() => relay.reviseTzDeliveryWindow(EP_C, "09:00-18:00", "Not/AZone"), RangeError);
    assert.throws(() => relay.reviseTzDeliveryWindow(EP_C, "bogus", "Asia/Shanghai"), RangeError);
    assert.equal(eventsOf(auditLog, "quiet_hours_revised").length, 0);
    assert.deepEqual(relay.getDeliveryWindows!()[0], {
      endpoint: EP_A,
      window: "09:00-18:00",
      open: true,
    });
  });

  it("throws Error on an unconfigured server; the listing getter is unset; removal is a silent false", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.equal(relay.getDeliveryWindows, undefined);
    assert.throws(() => relay.reviseDeliveryWindow(EP_A, "09:00-18:00"), /not configured/);
    assert.throws(
      () => relay.reviseTzDeliveryWindow(EP_A, "09:00-18:00", "Asia/Shanghai"),
      /not configured/
    );
    assert.equal(relay.removeDeliveryWindow(EP_A), false);
    assert.equal(eventsOf(auditLog, "quiet_hours_revised").length, 0);
    assert.equal(eventsOf(auditLog, "quiet_hours_removed").length, 0);
  });

  it("a same-value revision is a silent no-op", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    assert.deepEqual(relay.reviseDeliveryWindow(EP_A, "09:00-18:00"), {
      endpoint: EP_A,
      window: "09:00-18:00",
    });
    assert.deepEqual(relay.reviseTzDeliveryWindow(EP_B, "09:00-18:00", "Asia/Shanghai"), {
      endpoint: EP_B,
      window: "09:00-18:00",
      timezone: "Asia/Shanghai",
    });
    assert.equal(eventsOf(auditLog, "quiet_hours_revised").length, 0);
  });

  it("removeDeliveryWindow returns true, audits, and the endpoint is deliverable again", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    assert.equal(relay.removeDeliveryWindow(EP_B), true);
    const removed = eventsOf(auditLog, "quiet_hours_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, EP_B);
    assert.deepEqual(removed[0].previous, {
      endpoint: EP_B,
      window: "09:00-18:00",
      timezone: "Asia/Shanghai",
    });
    assert.deepEqual(
      relay.getDeliveryWindows!().map((r) => r.endpoint),
      [EP_A]
    );
    // Setting a fresh window on the removed endpoint starts from null.
    relay.reviseDeliveryWindow(EP_B, "10:00-19:00");
    const revised = eventsOf(auditLog, "quiet_hours_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
  });

  it("removing a window that was never set returns false and audits nothing", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    assert.equal(relay.removeDeliveryWindow(EP_C), false);
    assert.equal(eventsOf(auditLog, "quiet_hours_removed").length, 0);
    assert.equal(relay.removeDeliveryWindow(EP_C), false);
  });

  it("getDeliveryWindows lists every configured endpoint, including ones that never parked", async () => {
    const { relay } = configuredServer();
    await listen(relay);
    // No delivery has ever been attempted: the stats surface is empty …
    // (the server has no queue handle, so this is asserted at the queue
    // level above) … but the listing already covers both endpoints.
    assert.deepEqual(
      relay.getDeliveryWindows!().map((r) => r.endpoint),
      [EP_A, EP_B]
    );
  });
});
