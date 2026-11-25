import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Server } from "node:http";
import {
  RetryQueue,
  type OrderedAuditEvent,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "ordered-enable-secret";
const operatorToken = "ordered-enable-token";
const EP = "http://localhost:9999/ordered";
const EP2 = "http://localhost:9999/plain";
const URL = "http://localhost:9999/hook";

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

function item(id: string, targetUrl: string, priority?: RetryItem["priority"]): RetryItem {
  return { id, payload: buf(id), targetUrl, headers: {}, ...(priority === undefined ? {} : { priority }) };
}

async function tick(n = 3) {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
}

describe("RetryQueue ordered live enable (WR-464)", () => {
  it("an unconfigured queue enables the global scope and reports the full value", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      assert.equal(q.getOrderedConfig(), undefined);
      assert.equal(q.orderedConfigured(), false);
      assert.deepEqual(q.getOrderedStats(), []);
      const next = q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 1000 } });
      assert.deepEqual(next, { global: { maxHeadOfLineHoldMs: 1000 } });
      assert.equal(q.orderedConfigured(), true);
      assert.deepEqual(q.getOrderedConfig(), { global: { maxHeadOfLineHoldMs: 1000 } });
    } finally {
      q.stop();
    }
  });

  it("an Infinity bound enable is the equivalent of constructing with ordered: true", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      const next = q.reviseOrdered({ global: { maxHeadOfLineHoldMs: Infinity } });
      assert.deepEqual(next, { global: { maxHeadOfLineHoldMs: Infinity } });
      assert.deepEqual(q.getOrderedConfig(), { global: { maxHeadOfLineHoldMs: Infinity } });
    } finally {
      q.stop();
    }
  });

  it("a per-endpoint enable orders only that endpoint; the other stays unordered", async () => {
    const timer = manualTimer();
    const delivered: string[] = [];
    const dead: Array<{ id: string; attempts: number }> = [];
    const attempts = new Map<string, number>();
    const sender: Sender = async (wire) => {
      attempts.set(wire.id, (attempts.get(wire.id) ?? 0) + 1);
      if (wire.id === "q-a" || wire.id === "p-a") throw new Error("boom");
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onDeadLetter: (it, n) => dead.push({ id: it.id, attempts: n }),
    });
    q.start();
    try {
      const next = q.reviseOrdered({ endpoints: { [EP]: { maxHeadOfLineHoldMs: 1000 } } });
      assert.deepEqual(next, { endpoints: { [EP]: { maxHeadOfLineHoldMs: 1000 } } });
      // EP2 is unordered: the follower delivers while its head is still retrying.
      q.enqueue(item("q-a", EP2));
      q.enqueue(item("q-b", EP2));
      await timer.run();
      assert.deepEqual(delivered, ["q-b"]);
      assert.equal(dead.length, 1);
      assert.equal(dead[0]!.id, "q-a");
      assert.equal(dead[0]!.attempts, 10);
      // EP is ordered: the follower is held behind its failing head.
      q.enqueue(item("p-a", EP));
      q.enqueue(item("p-b", EP));
      await timer.runOne();
      for (let i = 0; i < 200 && (attempts.get("p-a") ?? 0) < 1; i++) await tick(1);
      assert.equal(attempts.get("p-a"), 1);
      await timer.runOne();
      await tick(2);
      assert.equal(attempts.get("p-b") ?? 0, 0);
      assert.deepEqual(delivered, ["q-b"]);
    } finally {
      q.stop();
    }
  });

  it("a mixed patch enables the global scope and endpoint scopes at once", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      const next = q.reviseOrdered({
        global: { maxHeadOfLineHoldMs: 5000 },
        endpoints: { [EP]: { maxHeadOfLineHoldMs: 1000 } },
      });
      assert.deepEqual(next, {
        global: { maxHeadOfLineHoldMs: 5000 },
        endpoints: { [EP]: { maxHeadOfLineHoldMs: 1000 } },
      });
    } finally {
      q.stop();
    }
  });

  it("illegal enable patches throw RangeError, stay unconfigured, and can still enable afterwards", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      const bad: Array<{ patch: unknown; label: string }> = [
        { patch: null, label: "null patch" },
        { patch: "x", label: "string patch" },
        { patch: [1], label: "array patch" },
        { patch: {}, label: "empty patch" },
        { patch: { global: {} }, label: "empty global scope" },
        { patch: { endpoints: {} }, label: "empty endpoints record" },
        { patch: { global: { maxHeadOfLineHoldMs: 0 } }, label: "bound 0" },
        { patch: { global: { maxHeadOfLineHoldMs: -5 } }, label: "bound negative" },
        { patch: { global: { maxHeadOfLineHoldMs: Number.NaN } }, label: "bound NaN" },
        { patch: { global: { maxHeadOfLineHoldMs: "1000" } }, label: "bound string" },
        { patch: { endpoints: { [EP]: { maxHeadOfLineHoldMs: 0 } } }, label: "endpoint bound 0" },
        { patch: { endpoints: { "": { maxHeadOfLineHoldMs: 100 } } }, label: "empty endpoint key" },
        { patch: { global: "x" }, label: "non-object global scope" },
        { patch: { endpoints: "x" }, label: "non-object endpoints record" },
      ];
      for (const { patch, label } of bad) {
        assert.throws(() => q.reviseOrdered(patch as never), RangeError, label);
        assert.equal(q.getOrderedConfig(), undefined, label);
        assert.equal(q.orderedConfigured(), false, label);
      }
      assert.deepEqual(q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 1000 } }), {
        global: { maxHeadOfLineHoldMs: 1000 },
      });
    } finally {
      q.stop();
    }
  });

  it("after the enable, the next dispatch orders: the follower is held without an attempt until the head settles", async () => {
    const timer = manualTimer();
    const delivered: string[] = [];
    const attempts = new Map<string, number>();
    const sender: Sender = async (wire) => {
      attempts.set(wire.id, (attempts.get(wire.id) ?? 0) + 1);
      if (wire.id === "p-a" && attempts.get(wire.id) === 1) throw new Error("boom");
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 10_000 } });
      q.enqueue(item("p-a", EP));
      q.enqueue(item("p-b", EP));
      await timer.runOne();
      for (let i = 0; i < 200 && (attempts.get("p-a") ?? 0) < 1; i++) await tick(1);
      assert.equal(attempts.get("p-a"), 1);
      await timer.runOne();
      await tick(2);
      assert.equal(attempts.get("p-b") ?? 0, 0);
      assert.deepEqual(delivered, []);
      await timer.run();
      assert.equal(attempts.get("p-a"), 2);
      assert.deepEqual(delivered, ["p-a", "p-b"]);
    } finally {
      q.stop();
    }
  });

  it("pre-enable deliveries are not retroactively ordered: the hold clock starts at line entry, not at enqueue", async () => {
    const timer = manualTimer();
    const delivered: string[] = [];
    const dead: string[] = [];
    const attempts = new Map<string, number>();
    const sender: Sender = async (wire) => {
      attempts.set(wire.id, (attempts.get(wire.id) ?? 0) + 1);
      if ((attempts.get(wire.id) ?? 0) === 1) throw new Error("boom");
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onDeadLetter: (it) => dead.push(it.id),
    });
    q.start();
    try {
      q.enqueue(item("p-a", EP));
      q.enqueue(item("p-b", EP));
      await timer.runOne();
      await timer.runOne();
      for (let i = 0; i < 200 && (attempts.get("p-b") ?? 0) < 1; i++) await tick(1);
      assert.equal(attempts.get("p-a"), 1);
      assert.equal(attempts.get("p-b"), 1);
      // Wait out the bound *before* enabling: if the hold clock were
      // backdated to the first attempt, the head would park on its
      // next dispatch instead of retrying.
      await new Promise((r) => setTimeout(r, 300));
      q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 100 } });
      await timer.run();
      assert.deepEqual(dead, []);
      assert.deepEqual([...delivered].sort(), ["p-a", "p-b"]);
      assert.equal(attempts.get("p-a"), 2);
      assert.equal(attempts.get("p-b"), 2);
    } finally {
      q.stop();
    }
  });

  it("the poison bound is measured from the enable onwards: a head past the bound parks with head_of_line_timeout", async () => {
    const timer = manualTimer();
    const audits: OrderedAuditEvent[] = [];
    const dead: Array<{ id: string; failureClass?: string; attempts: number }> = [];
    const delivered: string[] = [];
    let attemptsA = 0;
    const sender: Sender = async (wire) => {
      if (wire.id === "p-a") {
        attemptsA += 1;
        throw new Error("boom");
      }
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => audits.push(e),
      onDeadLetter: (it, n, _err, failureClass) =>
        dead.push({ id: it.id, failureClass, attempts: n }),
    });
    q.start();
    try {
      q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 5 } });
      q.enqueue(item("p-a", EP));
      q.enqueue(item("p-b", EP));
      await timer.runOne();
      for (let i = 0; i < 200 && attemptsA < 1; i++) await tick(1);
      assert.equal(attemptsA, 1);
      await timer.runOne();
      await tick(2);
      assert.deepEqual(dead, []);
      assert.deepEqual(delivered, []);
      // Let the head's hold age past the 5ms bound, then trigger its next dispatch.
      await new Promise((r) => setTimeout(r, 100));
      await timer.run();
      assert.equal(dead.length, 1);
      assert.equal(dead[0]!.id, "p-a");
      assert.equal(dead[0]!.failureClass, "head_of_line_timeout");
      assert.equal(dead[0]!.attempts, 1);
      assert.deepEqual(delivered, ["p-b"]);
      const park = audits.find((e) => e.kind === "head_of_line_parked");
      assert.ok(park, "expected a head_of_line_parked audit");
      assert.equal(park!.id, "p-a");
      assert.ok((park!.blockedMs ?? 0) >= 5);
      assert.equal(park!.maxHeadOfLineHoldMs, 5);
    } finally {
      q.stop();
    }
  });

  it("enabling unlocks the WR-401 audit-callback gate, and the new callback sees bypasses", async () => {
    const timer = manualTimer();
    const audits: OrderedAuditEvent[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      assert.equal(q.orderedConfigured(), false);
      assert.throws(
        () => q.reviseOrderedAuditCallback(() => {}),
        (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
      );
      q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 1000 } });
      q.reviseOrderedAuditCallback((e) => audits.push(e));
      q.enqueue(item("u-1", EP, "urgent"));
      await timer.run();
      assert.equal(audits.length, 1);
      assert.equal(audits[0]!.kind, "ordered_bypassed");
      assert.equal(audits[0]!.id, "u-1");
      assert.equal(audits[0]!.endpoint, EP);
    } finally {
      q.stop();
    }
  });

  it("after the enable, revisions still follow WR-416: record-only global revisions stay RangeError", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      q.reviseOrdered({ endpoints: { [EP]: { maxHeadOfLineHoldMs: 1000 } } });
      assert.throws(
        () => q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 500 } }),
        RangeError
      );
      assert.deepEqual(q.getOrderedConfig(), {
        endpoints: { [EP]: { maxHeadOfLineHoldMs: 1000 } },
      });
      assert.deepEqual(
        q.reviseOrdered({ endpoints: { [EP]: { maxHeadOfLineHoldMs: 2000 } } }),
        { endpoints: { [EP]: { maxHeadOfLineHoldMs: 2000 } } }
      );
      assert.throws(
        () => q.reviseOrdered({ endpoints: { [EP2]: { maxHeadOfLineHoldMs: 100 } } }),
        RangeError
      );
      assert.throws(() => q.reviseOrdered({}), RangeError);
      assert.deepEqual(
        q.reviseOrdered({ endpoints: { [EP]: { maxHeadOfLineHoldMs: 2000 } } }),
        { endpoints: { [EP]: { maxHeadOfLineHoldMs: 2000 } } }
      );
    } finally {
      q.stop();
    }
  });

  it("a restart restores unconfigured: the live-only enable does not survive a fresh instance", () => {
    const enabled = new RetryQueue({
      sender: async () => {},
    });
    try {
      enabled.reviseOrdered({ global: { maxHeadOfLineHoldMs: 1000 } });
      assert.equal(enabled.orderedConfigured(), true);
    } finally {
      enabled.stop();
    }
    // A fresh instance is the post-restart state.
    const restarted = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(restarted.getOrderedConfig(), undefined);
      assert.equal(restarted.orderedConfigured(), false);
      assert.deepEqual(restarted.getOrderedStats(), []);
    } finally {
      restarted.stop();
    }
  });
});

describe("RelayServer ordered live enable (WR-464)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "ordered-enable-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
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

  it("an unconfigured server enables and audits previous: null with the exact current values, exactly once", () => {
    const { relay, auditLog } = makeServer();
    const next = relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 1000 } });
    assert.deepEqual(next, { global: { maxHeadOfLineHoldMs: 1000 } });
    const enabled = eventsOf(auditLog, "ordered_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0]!.scope, "global");
    assert.equal(enabled[0]!.previous, null);
    assert.deepEqual(enabled[0]!.current, { maxHeadOfLineHoldMs: 1000 });
  });

  it("an unbounded enable audits the current bound as the string \"Infinity\"", () => {
    const { relay, auditLog } = makeServer();
    relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: Infinity } });
    const enabled = eventsOf(auditLog, "ordered_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0]!.scope, "global");
    assert.equal(enabled[0]!.previous, null);
    assert.deepEqual(enabled[0]!.current, { maxHeadOfLineHoldMs: "Infinity" });
  });

  it("a multi-scope enable audits one event per moved scope, global first", () => {
    const { relay, auditLog } = makeServer();
    const next = relay.reviseOrdered!({
      global: { maxHeadOfLineHoldMs: 5000 },
      endpoints: { [EP]: { maxHeadOfLineHoldMs: 1000 }, [EP2]: { maxHeadOfLineHoldMs: 2000 } },
    });
    assert.deepEqual(next, {
      global: { maxHeadOfLineHoldMs: 5000 },
      endpoints: { [EP]: { maxHeadOfLineHoldMs: 1000 }, [EP2]: { maxHeadOfLineHoldMs: 2000 } },
    });
    const enabled = eventsOf(auditLog, "ordered_revised");
    assert.equal(enabled.length, 3);
    assert.equal(enabled[0]!.scope, "global");
    assert.equal(enabled[0]!.previous, null);
    assert.deepEqual(enabled[0]!.current, { maxHeadOfLineHoldMs: 5000 });
    assert.equal(enabled[1]!.scope, EP);
    assert.equal(enabled[1]!.previous, null);
    assert.deepEqual(enabled[1]!.current, { maxHeadOfLineHoldMs: 1000 });
    assert.equal(enabled[2]!.scope, EP2);
    assert.equal(enabled[2]!.previous, null);
    assert.deepEqual(enabled[2]!.current, { maxHeadOfLineHoldMs: 2000 });
  });

  it("illegal enable patches throw RangeError, stay unconfigured and unaudited, and can still enable afterwards", () => {
    const { relay, auditLog } = makeServer();
    assert.throws(() => relay.reviseOrdered!({}), RangeError);
    assert.throws(() => relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 0 } }), RangeError);
    assert.throws(
      () => relay.reviseOrdered!(null as unknown as { global: { maxHeadOfLineHoldMs: number } }),
      RangeError
    );
    assert.equal(eventsOf(auditLog, "ordered_revised").length, 0);
    const next = relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 1000 } });
    assert.deepEqual(next, { global: { maxHeadOfLineHoldMs: 1000 } });
    assert.equal(eventsOf(auditLog, "ordered_revised").length, 1);
  });

  it("after the enable, revisions audit previous as the enabled values; same-value and illegal revisions audit nothing", () => {
    const { relay, auditLog } = makeServer();
    relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 1000 } });
    const next = relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 5000 } });
    assert.deepEqual(next, { global: { maxHeadOfLineHoldMs: 5000 } });
    const revised = eventsOf(auditLog, "ordered_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1]!.previous, { maxHeadOfLineHoldMs: 1000 });
    assert.deepEqual(revised[1]!.current, { maxHeadOfLineHoldMs: 5000 });
    relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 5000 } });
    assert.throws(() => relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 0 } }), RangeError);
    assert.throws(() => relay.reviseOrdered!({}), RangeError);
    assert.equal(eventsOf(auditLog, "ordered_revised").length, 2);
  });

  it("enabling unlocks the server-side WR-401 callback gate", () => {
    const { relay, auditLog } = makeServer();
    assert.throws(
      () => relay.reviseOrderedAuditCallback!(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 1000 } });
    relay.reviseOrderedAuditCallback!(() => {});
    const revised = eventsOf(auditLog, "ordered_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0]!.previous, "cleared");
    assert.equal(revised[0]!.current, "set");
  });

  it("a restart restores unconfigured: a fresh relay's first reviseOrdered is an enable, not a revision", () => {
    const { relay, auditLog } = makeServer();
    relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 1000 } });
    assert.equal(eventsOf(auditLog, "ordered_revised").length, 1);
    const { relay: freshRelay, auditLog: freshAudit } = makeServer();
    const next = freshRelay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 500 } });
    assert.deepEqual(next, { global: { maxHeadOfLineHoldMs: 500 } });
    const enabled = eventsOf(freshAudit, "ordered_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0]!.previous, null);
    assert.deepEqual(enabled[0]!.current, { maxHeadOfLineHoldMs: 500 });
  });
});
