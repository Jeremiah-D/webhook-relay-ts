import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import {
  RetryQueue,
  type OrderedAuditEvent,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "ordered-revision-secret";
const operatorToken = "ordered-revision-token";
const EP = "http://localhost:9999/ordered";
const EP2 = "http://localhost:9999/plain";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

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

function item(id: string, targetUrl: string): RetryItem {
  return { id, payload: buf(id), targetUrl, headers: {} };
}

async function tick(n = 3) {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
}

interface StuckHead {
  q: RetryQueue;
  timer: ReturnType<typeof manualTimer>;
  audits: OrderedAuditEvent[];
  dead: Array<{ id: string; failureClass?: string; attempts: number }>;
  delivered: string[];
  attempts: () => number;
}

/** A queue whose head `p-a` fails every attempt; `p-b` waits behind it. */
function stuckHeadQueue(bound: number, clock: { now: number }): StuckHead {
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
    ordered: { enabled: true, maxHeadOfLineHoldMs: bound, now: () => clock.now },
    baseDelayMs: 10,
    maxDelayMs: 50,
    maxAttempts: 10,
    jitterMs: 0,
    setTimer: timer.setTimer,
    onOrderedAudit: (e) => audits.push(e),
    onDeadLetter: (it, attempts, _err, failureClass) =>
      dead.push({ id: it.id, failureClass, attempts }),
  });
  q.start();
  return { q, timer, audits, dead, delivered, attempts: () => attemptsA };
}

/** Enqueue head + follower; the head fails once, the follower is held. */
async function armHead(s: StuckHead): Promise<void> {
  s.q.enqueue(item("p-a", EP));
  s.q.enqueue(item("p-b", EP));
  await s.timer.runOne();
  for (let i = 0; i < 200 && s.attempts() < 1; i++) await tick(1);
  assert.equal(s.attempts(), 1);
  await s.timer.runOne();
  await tick(2);
  assert.deepEqual(s.dead, []);
  assert.deepEqual(s.delivered, []);
}

describe("RetryQueue ordered hold-bound revision (WR-416)", () => {
  it("unconfigured queue throws the must-restart Error and reports no config", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      assert.equal(q.getOrderedConfig(), undefined);
      assert.throws(
        () => q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 1000 } }),
        (err: unknown) =>
          err instanceof Error &&
          /requires a restart/.test(err.message) &&
          /reviseOrdered/.test(err.message)
      );
    } finally {
      q.stop();
    }
  });

  it("illegal patches throw RangeError and the live config is untouched", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      ordered: { enabled: true, maxHeadOfLineHoldMs: 1000 },
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      const before = { global: { maxHeadOfLineHoldMs: 1000 } };
      assert.deepEqual(q.getOrderedConfig(), before);
      const bad: Array<{ patch: unknown; label: string }> = [
        { patch: { global: { maxHeadOfLineHoldMs: 0 } }, label: "bound 0" },
        { patch: { global: { maxHeadOfLineHoldMs: -5 } }, label: "bound negative" },
        { patch: { global: { maxHeadOfLineHoldMs: Number.NaN } }, label: "bound NaN" },
        { patch: { global: { maxHeadOfLineHoldMs: "1000" } }, label: "bound string" },
        { patch: null, label: "null patch" },
        { patch: "x", label: "string patch" },
        { patch: [1], label: "array patch" },
        { patch: {}, label: "empty patch" },
        { patch: { global: {} }, label: "empty global scope" },
        { patch: { endpoints: {} }, label: "empty endpoints record" },
        {
          patch: {
            global: { maxHeadOfLineHoldMs: 500 },
            endpoints: { [EP2]: { maxHeadOfLineHoldMs: 100 } },
          },
          label: "unknown endpoint fails closed (global must not move)",
        },
        { patch: { endpoints: { [EP2]: { maxHeadOfLineHoldMs: 100 } } }, label: "unknown endpoint" },
      ];
      for (const { patch, label } of bad) {
        assert.throws(() => q.reviseOrdered(patch as never), RangeError, label);
        assert.deepEqual(q.getOrderedConfig(), before, label);
      }
    } finally {
      q.stop();
    }
  });

  it("a global revision on a record-only config throws RangeError", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      ordered: { [EP]: true },
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      assert.deepEqual(q.getOrderedConfig(), {
        endpoints: { [EP]: { maxHeadOfLineHoldMs: Infinity } },
      });
      assert.throws(
        () => q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 500 } }),
        RangeError
      );
      assert.deepEqual(q.getOrderedConfig(), {
        endpoints: { [EP]: { maxHeadOfLineHoldMs: Infinity } },
      });
    } finally {
      q.stop();
    }
  });

  it("lowering the global bound parks an already-over-bound head on its next evaluation", async () => {
    const clock = { now: 0 };
    const s = stuckHeadQueue(10_000, clock);
    try {
      await armHead(s);
      clock.now = 1500;
      const revised = s.q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 1000 } });
      assert.deepEqual(revised, { global: { maxHeadOfLineHoldMs: 1000 } });
      await s.timer.run();
      assert.equal(s.dead.length, 1);
      assert.equal(s.dead[0]!.id, "p-a");
      assert.equal(s.dead[0]!.failureClass, "head_of_line_timeout");
      assert.equal(s.dead[0]!.attempts, 1);
      assert.deepEqual(s.delivered, ["p-b"]);
      const park = s.audits.find((e) => e.kind === "head_of_line_parked");
      assert.ok(park, "expected a head_of_line_parked audit");
      assert.equal(park!.id, "p-a");
      assert.equal(park!.endpoint, EP);
      assert.equal(park!.blockedMs, 1500);
      assert.equal(park!.maxHeadOfLineHoldMs, 1000);
      const stats = s.q.getOrderedStats();
      assert.equal(stats[0]!.headOfLineParked, 1);
    } finally {
      s.q.stop();
    }
  });

  it("raising the global bound keeps the head holding until the new bound", async () => {
    const clock = { now: 0 };
    const s = stuckHeadQueue(1000, clock);
    try {
      await armHead(s);
      clock.now = 1500;
      const revised = s.q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 5000 } });
      assert.deepEqual(revised, { global: { maxHeadOfLineHoldMs: 5000 } });
      // The head's next dispatch retries instead of parking (1500 < 5000).
      await s.timer.runOne();
      for (let i = 0; i < 200 && s.attempts() < 2; i++) await tick(1);
      assert.equal(s.attempts(), 2);
      assert.deepEqual(s.dead, []);
      assert.deepEqual(s.delivered, []);
      // Past the new bound, the next dispatch parks it.
      clock.now = 6000;
      await s.timer.runOne();
      await tick(2);
      await s.timer.run();
      assert.equal(s.dead.length, 1);
      assert.equal(s.dead[0]!.id, "p-a");
      assert.equal(s.dead[0]!.failureClass, "head_of_line_timeout");
      assert.equal(s.dead[0]!.attempts, 2);
      assert.deepEqual(s.delivered, ["p-b"]);
      const park = s.audits.find((e) => e.kind === "head_of_line_parked");
      assert.ok(park, "expected a head_of_line_parked audit");
      assert.equal(park!.blockedMs, 6000);
      assert.equal(park!.maxHeadOfLineHoldMs, 5000);
    } finally {
      s.q.stop();
    }
  });

  it("a per-endpoint revision moves only that endpoint's bound", async () => {
    const clock = { now: 0 };
    const timer = manualTimer();
    const audits: OrderedAuditEvent[] = [];
    const dead: Array<{ id: string; failureClass?: string; attempts: number }> = [];
    const delivered: string[] = [];
    let attemptsA = 0;
    let attemptsC = 0;
    const sender: Sender = async (wire) => {
      if (wire.id === "p-a") {
        attemptsA += 1;
        throw new Error("boom");
      }
      if (wire.id === "q-a") {
        attemptsC += 1;
        throw new Error("boom");
      }
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      ordered: {
        [EP]: { maxHeadOfLineHoldMs: 10_000, now: () => clock.now },
        [EP2]: { maxHeadOfLineHoldMs: 10_000 },
      },
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => audits.push(e),
      onDeadLetter: (it, attempts, _err, failureClass) =>
        dead.push({ id: it.id, failureClass, attempts }),
    });
    q.start();
    try {
      q.enqueue(item("p-a", EP));
      q.enqueue(item("p-b", EP));
      q.enqueue(item("q-a", EP2));
      q.enqueue(item("q-b", EP2));
      await timer.runOne(); // p-a attempt 1
      for (let i = 0; i < 200 && attemptsA < 1; i++) await tick(1);
      await timer.runOne(); // p-b held
      await timer.runOne(); // q-a attempt 1
      for (let i = 0; i < 200 && attemptsC < 1; i++) await tick(1);
      await timer.runOne(); // q-b held
      await tick(2);
      assert.deepEqual(dead, []);
      assert.deepEqual(delivered, []);
      clock.now = 1500;
      const revised = q.reviseOrdered({ endpoints: { [EP]: { maxHeadOfLineHoldMs: 1000 } } });
      assert.deepEqual(revised, {
        endpoints: {
          [EP]: { maxHeadOfLineHoldMs: 1000 },
          [EP2]: { maxHeadOfLineHoldMs: 10_000 },
        },
      });
      // EP's head parks (1500 > 1000); EP2's head retries (1500 < 10000).
      await timer.runOne(); // p-a dispatch: parks
      await tick(2);
      assert.equal(dead.length, 1);
      assert.equal(dead[0]!.id, "p-a");
      assert.equal(dead[0]!.failureClass, "head_of_line_timeout");
      await timer.runOne(); // q-a dispatch: retries, still holding
      for (let i = 0; i < 200 && attemptsC < 2; i++) await tick(1);
      assert.equal(attemptsC, 2);
      assert.equal(dead.length, 1);
      assert.equal(delivered.length, 0);
      const stats = q.getOrderedStats();
      const epStats = stats.find((r) => r.endpoint === EP)!;
      const ep2Stats = stats.find((r) => r.endpoint === EP2)!;
      assert.equal(epStats.headOfLineParked, 1);
      assert.equal(ep2Stats.headOfLineParked, 0);
    } finally {
      q.stop();
    }
  });

  it("an already-parked head stays dead-lettered after revision; line order and stats are untouched", async () => {
    const clock = { now: 0 };
    const s = stuckHeadQueue(1000, clock);
    try {
      await armHead(s);
      clock.now = 1500;
      await s.timer.run();
      assert.equal(s.dead.length, 1);
      assert.deepEqual(s.delivered, ["p-b"]);
      assert.equal(s.audits.filter((e) => e.kind === "head_of_line_parked").length, 1);
      const revised = s.q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 5000 } });
      assert.deepEqual(revised, { global: { maxHeadOfLineHoldMs: 5000 } });
      assert.equal(s.dead.length, 1);
      assert.deepEqual(s.delivered, ["p-b"]);
      assert.equal(s.audits.filter((e) => e.kind === "head_of_line_parked").length, 1);
      const stats = s.q.getOrderedStats();
      assert.equal(stats.length, 1);
      assert.equal(stats[0]!.headOfLineParked, 1);
      assert.equal(stats[0]!.queued, 0);
    } finally {
      s.q.stop();
    }
  });

  it("a same-value revision changes nothing", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      ordered: { enabled: true, maxHeadOfLineHoldMs: 1000 },
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      assert.deepEqual(q.reviseOrdered({ global: { maxHeadOfLineHoldMs: 1000 } }), {
        global: { maxHeadOfLineHoldMs: 1000 },
      });
      assert.deepEqual(q.getOrderedConfig(), { global: { maxHeadOfLineHoldMs: 1000 } });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer ordered hold-bound revision (WR-416)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "ordered-revision-"));
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

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
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

  async function waitEvents(auditLog: AuditLog, name: string, target: number) {
    const deadline = Date.now() + 5000;
    while (eventsOf(auditLog, name).length < target && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(eventsOf(auditLog, name).length, target);
  }

  it("unconfigured server throws the must-restart Error", () => {
    const { relay } = makeServer();
    assert.throws(
      () => relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 1000 } }),
      (err: unknown) =>
        err instanceof Error &&
        /requires a restart/.test(err.message) &&
        /reviseOrdered/.test(err.message)
    );
  });

  it("a real global revision audits ordered_revised with exact previous/current", () => {
    const { relay, auditLog } = makeServer({
      retry: { ordered: { enabled: true, maxHeadOfLineHoldMs: 1000 } },
    });
    const next = relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 5000 } });
    assert.deepEqual(next, { global: { maxHeadOfLineHoldMs: 5000 } });
    const revised = eventsOf(auditLog, "ordered_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0]!.scope, "global");
    assert.deepEqual(revised[0]!.previous, { maxHeadOfLineHoldMs: 1000 });
    assert.deepEqual(revised[0]!.current, { maxHeadOfLineHoldMs: 5000 });
  });

  it("same-value, empty, and illegal revisions audit nothing", () => {
    const { relay, auditLog } = makeServer({
      retry: { ordered: { enabled: true, maxHeadOfLineHoldMs: 1000 } },
    });
    relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 5000 } });
    assert.equal(eventsOf(auditLog, "ordered_revised").length, 1);
    assert.deepEqual(relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 5000 } }), {
      global: { maxHeadOfLineHoldMs: 5000 },
    });
    assert.throws(() => relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 0 } }), RangeError);
    assert.throws(() => relay.reviseOrdered!({}), RangeError);
    assert.equal(eventsOf(auditLog, "ordered_revised").length, 1);
  });

  it("a multi-scope revision audits one event per moved scope", () => {
    const { relay, auditLog } = makeServer({
      retry: {
        ordered: {
          [EP]: { maxHeadOfLineHoldMs: 1000 },
          [EP2]: { maxHeadOfLineHoldMs: 2000 },
        },
      },
    });
    const next = relay.reviseOrdered!({
      endpoints: { [EP]: { maxHeadOfLineHoldMs: 500 }, [EP2]: { maxHeadOfLineHoldMs: 4000 } },
    });
    assert.deepEqual(next, {
      endpoints: {
        [EP]: { maxHeadOfLineHoldMs: 500 },
        [EP2]: { maxHeadOfLineHoldMs: 4000 },
      },
    });
    const revised = eventsOf(auditLog, "ordered_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[0]!.scope, EP);
    assert.deepEqual(revised[0]!.previous, { maxHeadOfLineHoldMs: 1000 });
    assert.deepEqual(revised[0]!.current, { maxHeadOfLineHoldMs: 500 });
    assert.equal(revised[1]!.scope, EP2);
    assert.deepEqual(revised[1]!.previous, { maxHeadOfLineHoldMs: 2000 });
    assert.deepEqual(revised[1]!.current, { maxHeadOfLineHoldMs: 4000 });
  });

  it("revision keeps the earlier head_of_line_parked audit row", async () => {
    const clock = { now: 0 };
    const { relay, auditLog } = makeServer({
      sender: async () => {
        throw new Error("downstream down");
      },
      retry: {
        baseDelayMs: 10,
        maxDelayMs: 50,
        maxAttempts: 50,
        jitterMs: 0,
        ordered: { enabled: true, maxHeadOfLineHoldMs: 1000, now: () => clock.now },
      },
    });
    const port = await listen(relay);
    await postWebhook(port);
    await postWebhook(port);
    // Let the head fail its first attempt, then push the clock past the
    // bound so a retry dispatch parks it (the attempt budget is wide
    // enough that the park lands before exhaustion).
    await new Promise((r) => setTimeout(r, 50));
    clock.now = 1500;
    await waitEvents(auditLog, "head_of_line_parked", 1);
    const next = relay.reviseOrdered!({ global: { maxHeadOfLineHoldMs: 5000 } });
    assert.deepEqual(next, { global: { maxHeadOfLineHoldMs: 5000 } });
    assert.equal(eventsOf(auditLog, "head_of_line_parked").length, 1);
    const revised = eventsOf(auditLog, "ordered_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0]!.scope, "global");
    assert.deepEqual(revised[0]!.previous, { maxHeadOfLineHoldMs: 1000 });
    assert.deepEqual(revised[0]!.current, { maxHeadOfLineHoldMs: 5000 });
  });
});
