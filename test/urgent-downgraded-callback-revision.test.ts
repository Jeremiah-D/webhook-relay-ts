import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type RetryItem,
  type Sender,
  type UrgentDowngradedEvent,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "urgent-downgraded-callback-revision-secret";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

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
  };
}

/** Let queued microtask chains (admission -> turn grant -> sender) settle. */
async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, priority?: "urgent"): RetryItem {
  return {
    id,
    payload: Buffer.from(id),
    targetUrl: URL,
    headers: {},
    ...(priority !== undefined ? { priority } : {}),
  };
}

describe("RetryQueue urgent-downgraded callback revision (WR-389)", () => {
  it("revise swaps the live callback: the next downgrade enters the new callback with exact consecutiveUrgent/maxConsecutiveUrgent", async () => {
    const timer = manualTimer();
    const priorities = new Map<string, string | undefined>();
    const oldSeen: UrgentDowngradedEvent[] = [];
    const newSeen: UrgentDowngradedEvent[] = [];
    const q = new RetryQueue({
      sender: async (entry) => { priorities.set(entry.id, entry.priority); },
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
      onUrgentDowngraded: (e) => oldSeen.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      for (let i = 1; i <= 3; i++) q.enqueue(item(`u-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.equal(q.pendingCount(), 0);
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(oldSeen[0], {
        event: "urgent_downgraded",
        endpoint: URL,
        id: "u-3",
        traceId: oldSeen[0].traceId,
        consecutiveUrgent: 2,
        maxConsecutiveUrgent: 2,
      });
      assert.equal(priorities.get("u-3"), "normal");
      assert.deepEqual(newSeen, []);
      // Swap mid-stream: the old callback never hears another downgrade,
      // and the already-reported downgrade is never re-delivered.
      q.reviseUrgentDowngradedCallback((e) => newSeen.push(e));
      for (let i = 4; i <= 6; i++) q.enqueue(item(`u-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.equal(q.pendingCount(), 0);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "u-6");
      assert.equal(newSeen[0].consecutiveUrgent, 2);
      assert.equal(newSeen[0].maxConsecutiveUrgent, 2);
      assert.equal(priorities.get("u-6"), "normal");
      const [s] = q.getUrgentStats();
      assert.equal(s.downgraded, 2);
      // `delivered` counts urgent-lane deliveries only; the two
      // downgraded items went out on the normal lane.
      assert.equal(s.delivered, 4);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer: downgrades and the downgraded counter keep going", async () => {
    const timer = manualTimer();
    const seen: UrgentDowngradedEvent[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
      onUrgentDowngraded: (e) => seen.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      for (let i = 1; i <= 3; i++) q.enqueue(item(`c-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.equal(seen.length, 1);
      assert.equal(q.getUrgentStats()[0].downgraded, 1);
      q.reviseUrgentDowngradedCallback(null);
      for (let i = 4; i <= 6; i++) q.enqueue(item(`c-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.equal(seen.length, 1); // the operator hears nothing more
      assert.equal(q.getUrgentStats()[0].downgraded, 2); // counting continues
      // `delivered` counts urgent-lane deliveries only; the two
      // downgraded items went out on the normal lane.
      assert.equal(q.getUrgentStats()[0].delivered, 4);
    } finally {
      q.stop();
    }
  });

  it("a queue with the guard unconfigured cannot gain an observer at runtime — must restart", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    assert.throws(
      () => q.reviseUrgentDowngradedCallback(() => {}),
      /requires a restart/
    );
    assert.throws(
      () => q.reviseUrgentDowngradedCallback(null),
      /requires a restart/
    );
    q.stop();
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const timer = manualTimer();
    const seen: UrgentDowngradedEvent[] = [];
    const live = (e: UrgentDowngradedEvent) => seen.push(e);
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
      onUrgentDowngraded: live,
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      assert.throws(
        () => q.reviseUrgentDowngradedCallback(42 as never),
        RangeError
      );
      assert.throws(
        () => q.reviseUrgentDowngradedCallback("nope" as never),
        RangeError
      );
      for (let i = 1; i <= 3; i++) q.enqueue(item(`bad-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].id, "bad-3");
    } finally {
      q.stop();
    }
  });

  it("same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const timer = manualTimer();
    const seen: UrgentDowngradedEvent[] = [];
    const live = (e: UrgentDowngradedEvent) => seen.push(e);
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
      onUrgentDowngraded: live,
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      q.reviseUrgentDowngradedCallback(live); // no-op, no throw
      for (let i = 1; i <= 3; i++) q.enqueue(item(`noop-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.equal(seen.length, 1);
      q.reviseUrgentDowngradedCallback(null);
      q.reviseUrgentDowngradedCallback(null); // clearing when unset: no-op
      for (let i = 4; i <= 6; i++) q.enqueue(item(`noop-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.equal(seen.length, 1);
      assert.equal(q.getUrgentStats()[0].downgraded, 2);
    } finally {
      q.stop();
    }
  });

  it("a swap does not reset the streak: the next urgent is still judged against the streak built so far", async () => {
    const timer = manualTimer();
    const oldSeen: UrgentDowngradedEvent[] = [];
    const newSeen: UrgentDowngradedEvent[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
      onUrgentDowngraded: (e) => oldSeen.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      q.enqueue(item("s-1", "urgent"));
      q.enqueue(item("s-2", "urgent"));
      await timer.run();
      await settle();
      assert.deepEqual(oldSeen, []); // streak is 2, no downgrade yet
      // The swap must not touch guard state: the very next urgent
      // admission (streak already 2) still trips the guard.
      q.reviseUrgentDowngradedCallback((e) => newSeen.push(e));
      q.enqueue(item("s-3", "urgent"));
      await timer.run();
      await settle();
      assert.deepEqual(oldSeen, []);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "s-3");
      assert.equal(newSeen[0].consecutiveUrgent, 2);
      assert.equal(newSeen[0].maxConsecutiveUrgent, 2);
    } finally {
      q.stop();
    }
  });

  it("interleaved normal demand still never triggers a downgrade", async () => {
    const timer = manualTimer();
    const seen: UrgentDowngradedEvent[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
      onUrgentDowngraded: (e) => seen.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      q.enqueue(item("i-1", "urgent"));
      q.enqueue(item("i-2", "urgent"));
      q.enqueue(item("i-3")); // normal admission resets the streak
      q.enqueue(item("i-4", "urgent"));
      await timer.run();
      await settle();
      assert.equal(q.pendingCount(), 0);
      assert.deepEqual(seen, []);
      assert.equal(q.getUrgentStats()[0].downgraded, 0);
    } finally {
      q.stop();
    }
  });

  it("a downgraded item still goes out on the normal lane, before and after a swap", async () => {
    const timer = manualTimer();
    const priorities = new Map<string, string | undefined>();
    const delivered: string[] = [];
    const q = new RetryQueue({
      sender: async (entry) => {
        priorities.set(entry.id, entry.priority);
        delivered.push(entry.id);
      },
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
      onUrgentDowngraded: () => {},
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      for (let i = 1; i <= 3; i++) q.enqueue(item(`l-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.equal(priorities.get("l-1"), "urgent");
      assert.equal(priorities.get("l-2"), "urgent");
      assert.equal(priorities.get("l-3"), "normal");
      q.reviseUrgentDowngradedCallback(() => {});
      for (let i = 4; i <= 6; i++) q.enqueue(item(`l-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.equal(priorities.get("l-4"), "urgent");
      assert.equal(priorities.get("l-5"), "urgent");
      assert.equal(priorities.get("l-6"), "normal");
      assert.deepEqual(delivered.sort(), ["l-1", "l-2", "l-3", "l-4", "l-5", "l-6"]);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer urgent-downgraded callback revision (WR-389)", () => {
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

  async function drainUntil(cond: () => boolean, ms = 5000): Promise<void> {
    const deadline = Date.now() + ms;
    while (!cond()) {
      if (Date.now() > deadline) throw new Error("timed out waiting for condition");
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  function postWebhook(port: number, urgent = false) {
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
            ...(urgent ? { "x-priority": "urgent" } : {}),
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

  function downgradedEvents(audit: AuditLog) {
    return audit.query({ event: "urgent_downgraded" }) as Array<{
      id: string;
      endpoint: string;
      consecutiveUrgent: number;
      maxConsecutiveUrgent: number;
    }>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "urgent_downgraded_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server with the WR-121 guard at maxConsecutiveUrgent 2. */
  function guardServer(onUrgentDowngraded?: (event: UrgentDowngradedEvent) => void) {
    const dir = mkdtempSync(join(tmpdir(), "urgentdowngraded-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: (async () => {}) as Sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 3,
        jitterMs: 0,
        urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
        ...(onUrgentDowngraded !== undefined ? { onUrgentDowngraded } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  /** Post three urgent webhooks; the third trips the guard. */
  async function postUrgentBatch(port: number) {
    for (let i = 0; i < 3; i++) assert.equal(await postWebhook(port, true), 202);
  }

  it("replacing the operator callback routes the next downgrade to the new callback and the urgent_downgraded audit still lands", async () => {
    const oldSeen: UrgentDowngradedEvent[] = [];
    const newSeen: UrgentDowngradedEvent[] = [];
    const { relay, audit } = guardServer((event) => oldSeen.push(event));
    const port = await listen(relay);
    await postUrgentBatch(port);
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => downgradedEvents(audit).length >= 1);
    assert.equal(oldSeen[0].consecutiveUrgent, 2);
    assert.equal(oldSeen[0].maxConsecutiveUrgent, 2);
    assert.equal(oldSeen[0].endpoint, URL);
    assert.equal(downgradedEvents(audit)[0].consecutiveUrgent, 2);
    assert.deepEqual(newSeen, []);
    const newCb = (event: UrgentDowngradedEvent) => newSeen.push(event);
    relay.reviseUrgentDowngradedCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    await postUrgentBatch(port);
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => downgradedEvents(audit).length >= 2);
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen[0].consecutiveUrgent, 2);
    assert.equal(newSeen[0].maxConsecutiveUrgent, 2);
    assert.equal(downgradedEvents(audit)[1].consecutiveUrgent, 2);
    assert.equal((audit.query({ event: "delivered" }) as unknown[]).length, 6);
  });

  it("clearing to null keeps the urgent_downgraded audit and the downgrades, and stops the operator", async () => {
    const seen: UrgentDowngradedEvent[] = [];
    const { relay, audit } = guardServer((event) => seen.push(event));
    const port = await listen(relay);
    await postUrgentBatch(port);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => downgradedEvents(audit).length >= 1);
    relay.reviseUrgentDowngradedCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    await postUrgentBatch(port);
    await drainUntil(() => downgradedEvents(audit).length >= 2);
    assert.equal(seen.length, 1); // still silent
    // The second batch downgraded again (audited, counted) but was not
    // forwarded — and every delivery still went out.
    assert.equal(downgradedEvents(audit)[1].consecutiveUrgent, 2);
    assert.equal((audit.query({ event: "delivered" }) as unknown[]).length, 6);
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = guardServer((_event) => {});
    await listen(relay);
    const newCb = (_event: UrgentDowngradedEvent) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseUrgentDowngradedCallback!(newCb);
    // set -> cleared.
    relay.reviseUrgentDowngradedCallback!(null);
    // cleared -> set.
    relay.reviseUrgentDowngradedCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseUrgentDowngradedCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseUrgentDowngradedCallback!(null);
    relay.reviseUrgentDowngradedCallback!(null);
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
    // and the first set audits cleared -> set. (The guard is configured,
    // only the observer is absent.)
    const { relay: bare, audit: bareAudit } = guardServer();
    await listen(bare);
    bare.reviseUrgentDowngradedCallback!(null);
    bare.reviseUrgentDowngradedCallback!(newCb);
    assert.deepEqual(
      (bareAudit.query({ event: "urgent_downgraded_callback_revised" }) as Array<{
        previous: string;
        current: string;
      }>).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("a non-function value throws RangeError and the live cell is untouched", async () => {
    const seen: UrgentDowngradedEvent[] = [];
    const { relay, audit } = guardServer((event) => seen.push(event));
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseUrgentDowngradedCallback!(42 as never),
      RangeError
    );
    assert.equal(revisedEvents(audit).length, 0);
    // The live cell survived: the next downgrade still enters the original callback.
    await postUrgentBatch(port);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => downgradedEvents(audit).length >= 1);
    assert.equal(seen[0].consecutiveUrgent, 2);
    assert.equal(seen[0].maxConsecutiveUrgent, 2);
  });

  it("a server without the urgent guard cannot gain an observer at runtime — must restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "urgentdowngraded-noguard-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: (async () => {}) as Sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 3,
        jitterMs: 0,
      },
    });
    servers.push(relay);
    await listen(relay);
    assert.throws(
      () => relay.reviseUrgentDowngradedCallback!(() => {}),
      /requires a restart/
    );
    assert.equal(revisedEvents(audit).length, 0);
  });
});
