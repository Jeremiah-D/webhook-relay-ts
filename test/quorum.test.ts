import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import {
  HttpDeliveryError,
  RetryQueue,
  assertValidQuorumConfig,
  type QuorumAcknowledgedInfo,
  type QuorumDispatchedInfo,
  type QuorumFailedInfo,
  type QuorumSatisfiedInfo,
  type QuorumTargetDeadLetteredInfo,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const LOGICAL = "http://127.0.0.1:9920/hook";
const T1 = "http://127.0.0.1:9921/one";
const T2 = "http://127.0.0.1:9922/two";
const T3 = "http://127.0.0.1:9923/three";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
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
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function item(id: string, priority?: RetryItem["priority"]): RetryItem {
  return {
    id,
    payload: Buffer.from(`payload-${id}`),
    targetUrl: LOGICAL,
    headers: {},
    ...(priority === undefined ? {} : { priority }),
  };
}

interface QuorumHooks {
  dispatched: QuorumDispatchedInfo[];
  acknowledged: QuorumAcknowledgedInfo[];
  satisfied: QuorumSatisfiedInfo[];
  failed: QuorumFailedInfo[];
  targetDeadLettered: QuorumTargetDeadLetteredInfo[];
}

function hookBucket(): QuorumHooks & {
  onQuorumDispatched: (i: QuorumDispatchedInfo) => void;
  onQuorumAcknowledged: (i: QuorumAcknowledgedInfo) => void;
  onQuorumSatisfied: (i: QuorumSatisfiedInfo) => void;
  onQuorumFailed: (i: QuorumFailedInfo) => void;
  onQuorumTargetDeadLettered: (i: QuorumTargetDeadLetteredInfo) => void;
} {
  const b: QuorumHooks = {
    dispatched: [],
    acknowledged: [],
    satisfied: [],
    failed: [],
    targetDeadLettered: [],
  };
  return {
    ...b,
    onQuorumDispatched: (i) => b.dispatched.push(i),
    onQuorumAcknowledged: (i) => b.acknowledged.push(i),
    onQuorumSatisfied: (i) => b.satisfied.push(i),
    onQuorumFailed: (i) => b.failed.push(i),
    onQuorumTargetDeadLettered: (i) => b.targetDeadLettered.push(i),
  };
}

/** Sender that routes by targetUrl to per-target scripted behaviors. */
function scriptedSender(
  scripts: Record<string, Array<"ok" | number | Error>>,
  calls: Record<string, number>,
  seen?: RetryItem[]
): Sender {
  return async (it: RetryItem) => {
    calls[it.targetUrl] = (calls[it.targetUrl] ?? 0) + 1;
    seen?.push(it);
    const script = scripts[it.targetUrl] ?? ["ok"];
    const step = script[Math.min(calls[it.targetUrl] - 1, script.length - 1)];
    if (step === "ok") return;
    if (typeof step === "number") throw new HttpDeliveryError(step);
    throw step;
  };
}

function makeQueue(
  sender: Sender,
  hooks: ReturnType<typeof hookBucket>,
  quorum: { targets: string[]; quorum: number } = { targets: [T1, T2, T3], quorum: 2 },
  extra: Record<string, unknown> = {}
) {
  const timer = manualTimer();
  const q = new RetryQueue({
    sender,
    baseDelayMs: 10,
    maxDelayMs: 10,
    jitterMs: 0,
    maxAttempts: 3,
    setTimer: timer.setTimer,
    quorum: { [LOGICAL]: quorum },
    onQuorumDispatched: hooks.onQuorumDispatched,
    onQuorumAcknowledged: hooks.onQuorumAcknowledged,
    onQuorumSatisfied: hooks.onQuorumSatisfied,
    onQuorumFailed: hooks.onQuorumFailed,
    onQuorumTargetDeadLettered: hooks.onQuorumTargetDeadLettered,
    ...extra,
  });
  return { q, timer };
}

describe("quorum config validation", () => {
  it("accepts a minimal valid config", () => {
    assertValidQuorumConfig({ [LOGICAL]: { targets: [T1, T2], quorum: 1 } });
    assertValidQuorumConfig({ [LOGICAL]: { targets: [T1, T2], quorum: 2 } });
    assertValidQuorumConfig(undefined);
  });

  it("rejects malformed configs", () => {
    for (const bad of [null, [], "x", 42]) {
      assert.throws(() => assertValidQuorumConfig(bad as never), RangeError, String(bad));
    }
    assert.throws(() => assertValidQuorumConfig({ "": { targets: [T1], quorum: 1 } }), RangeError);
    assert.throws(
      () => assertValidQuorumConfig({ [LOGICAL]: { targets: [], quorum: 1 } }),
      RangeError
    );
    assert.throws(
      () => assertValidQuorumConfig({ [LOGICAL]: { targets: [T1], quorum: 0 } }),
      RangeError
    );
    assert.throws(
      () => assertValidQuorumConfig({ [LOGICAL]: { targets: [T1], quorum: 2 } }),
      RangeError
    );
    assert.throws(
      () => assertValidQuorumConfig({ [LOGICAL]: { targets: [T1, T1], quorum: 1 } }),
      RangeError,
      "duplicate target"
    );
    assert.throws(
      () => assertValidQuorumConfig({ [LOGICAL]: { targets: [LOGICAL], quorum: 1 } }),
      RangeError,
      "self fan-out"
    );
    assert.throws(
      () => assertValidQuorumConfig({ [LOGICAL]: { targets: ["not-a-url"], quorum: 1 } }),
      RangeError
    );
    assert.throws(
      () => assertValidQuorumConfig({ [LOGICAL]: { targets: ["ftp://x/y"], quorum: 1 } }),
      RangeError
    );
  });

  it("rejects an invalid quorum config at queue construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          quorum: { [LOGICAL]: { targets: [T1], quorum: 5 } },
        }),
      RangeError
    );
  });

  it("enqueueFanout throws without a config for the endpoint", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.hasQuorumConfig(LOGICAL), false);
    assert.throws(() => q.enqueueFanout(item("nope")), /no quorum fan-out configured/);
  });
});

describe("quorum fan-out dispatch", () => {
  it("dispatches one member per target with the admitted id as fan-out id", async () => {
    const hooks = hookBucket();
    const seen: RetryItem[] = [];
    const calls: Record<string, number> = {};
    const { q, timer } = makeQueue(scriptedSender({}, calls, seen), hooks);
    q.start();
    try {
      q.enqueueFanout(item("f1"));
      await timer.run();
      assert.deepEqual(
        seen.map((s) => s.targetUrl).sort(),
        [T1, T2, T3]
      );
      assert.deepEqual(
        seen.map((s) => s.id).sort(),
        ["f1:quorum:0", "f1:quorum:1", "f1:quorum:2"]
      );
      // Same payload, shared trace id across members.
      for (const s of seen) assert.deepEqual(s.payload, Buffer.from("payload-f1"));
      const traceIds = new Set(seen.map((s) => s.traceId));
      assert.equal(traceIds.size, 1);
      assert.equal(hooks.dispatched.length, 1);
      assert.equal(hooks.dispatched[0].event, "quorum_dispatched");
      assert.equal(hooks.dispatched[0].fanoutId, "f1");
      assert.deepEqual(hooks.dispatched[0].targets, [T1, T2, T3]);
      assert.equal(hooks.dispatched[0].quorum, 2);
    } finally {
      q.stop();
    }
  });

  it("M-of-N satisfied: two acks settle the fan-out while the loser keeps its own retries", async () => {
    const hooks = hookBucket();
    const calls: Record<string, number> = {};
    // T1 fails once then acks; T2 acks immediately; T3 always fails.
    const { q, timer } = makeQueue(
      scriptedSender({ [T1]: [500, "ok"], [T3]: [500, 500, 500, 500] }, calls),
      hooks
    );
    q.start();
    try {
      q.enqueueFanout(item("f2"));
      await timer.run();
      // Quorum met exactly once, at the second ack.
      assert.equal(hooks.satisfied.length, 1);
      assert.equal(hooks.satisfied[0].event, "quorum_satisfied");
      assert.equal(hooks.satisfied[0].acked, 2);
      assert.equal(hooks.satisfied[0].targets, 3);
      assert.deepEqual(
        hooks.acknowledged.map((a) => a.targetUrl).sort(),
        [T1, T2]
      );
      // The loser was retried on its own budget (3 attempts), not abandoned.
      assert.equal(calls[T3], 3);
      // Each ack fired quorum_acknowledged with the running count.
      assert.deepEqual(
        hooks.acknowledged.map((a) => a.acked),
        [1, 2]
      );
      const [row] = q.getQuorumStats();
      assert.equal(row.fanoutId, "f2");
      assert.equal(row.endpoint, LOGICAL);
      assert.equal(row.targets, 3);
      assert.equal(row.acked, 2);
      assert.equal(row.status, "satisfied");
      assert.ok(row.settledAt !== undefined);
    } finally {
      q.stop();
    }
  });

  it("an acknowledged target is never re-delivered", async () => {
    const hooks = hookBucket();
    const calls: Record<string, number> = {};
    // T1 acks on attempt 1; T2 fails twice then acks; quorum 2 of 2.
    const { q, timer } = makeQueue(
      scriptedSender({ [T2]: [500, 500, "ok"] }, calls),
      hooks,
      { targets: [T1, T2], quorum: 2 }
    );
    q.start();
    try {
      q.enqueueFanout(item("f3"));
      await timer.run();
      assert.equal(calls[T1], 1); // acked once, never touched again
      assert.equal(calls[T2], 3); // its own retries only
      assert.equal(hooks.satisfied.length, 1);
      assert.equal(q.getQuorumStats()[0].status, "satisfied");
    } finally {
      q.stop();
    }
  });
});

describe("quorum loss handling", () => {
  it("a target that exhausts its budget degrades the fan-out to partial (quorum still reachable)", async () => {
    const hooks2 = hookBucket();
    const calls: Record<string, number> = {};
    const timer2 = manualTimer();
    const q2 = new RetryQueue({
      sender: async (it: RetryItem) => {
        // T3's sender hangs: still live, so M stays reachable -> partial, not failed.
        if (it.targetUrl === T3) await new Promise(() => {});
        return scriptedSender({ [T1]: [500, 500, 500], [T2]: ["ok"] }, calls)(it);
      },
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 3,
      setTimer: timer2.setTimer,
      quorum: { [LOGICAL]: { targets: [T1, T2, T3], quorum: 2 } },
      onQuorumTargetDeadLettered: hooks2.onQuorumTargetDeadLettered,
      onQuorumFailed: hooks2.onQuorumFailed,
      onQuorumSatisfied: hooks2.onQuorumSatisfied,
    });
    q2.start();
    try {
      q2.enqueueFanout(item("f4"));
      await timer2.run();
      await new Promise((r) => setImmediate(r));
      assert.equal(hooks2.targetDeadLettered.length, 1);
      const loss = hooks2.targetDeadLettered[0];
      assert.equal(loss.event, "quorum_target_dead_lettered");
      assert.equal(loss.targetUrl, T1);
      assert.equal(loss.failureClass, "retryable");
      assert.equal(hooks2.failed.length, 0); // T3 still live: quorum reachable
      assert.equal(hooks2.satisfied.length, 0);
      const [row] = q2.getQuorumStats();
      assert.equal(row.status, "partial");
      assert.equal(row.acked, 1);
      assert.equal(row.targets, 3);
      assert.equal(row.deadLettered.length, 1);
      assert.equal(row.deadLettered[0].targetUrl, T1);
    } finally {
      q2.stop();
    }
  });

  it("quorum becomes failed when M is unreachable", async () => {
    const h2 = hookBucket();
    const calls: Record<string, number> = {};
    const t2 = manualTimer();
    const q2 = new RetryQueue({
      sender: scriptedSender({ [T1]: [500], [T2]: [500], [T3]: ["ok"] }, calls),
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      setTimer: t2.setTimer,
      // T3 first: its ack banks before the two losses, so the verdict
      // fires with one acknowledgement already recorded.
      quorum: { [LOGICAL]: { targets: [T3, T1, T2], quorum: 2 } },
      onQuorumTargetDeadLettered: h2.onQuorumTargetDeadLettered,
      onQuorumFailed: h2.onQuorumFailed,
      onQuorumSatisfied: h2.onQuorumSatisfied,
    });
    q2.start();
    try {
      q2.enqueueFanout(item("f5"));
      await t2.run();
      assert.equal(h2.targetDeadLettered.length, 2);
      assert.equal(h2.failed.length, 1);
      assert.equal(h2.failed[0].event, "quorum_failed");
      assert.equal(h2.failed[0].acked, 1);
      assert.match(h2.failed[0].reason, /unreachable/);
      assert.equal(h2.satisfied.length, 0);
      const [row] = q2.getQuorumStats();
      assert.equal(row.status, "failed");
      assert.ok(row.settledAt !== undefined);
    } finally {
      q2.stop();
    }
  });
});

describe("quorum composes with WR-30 failure classification", () => {
  it("non-retryable target dead-letters on the first attempt; retryable keeps retrying", async () => {
    const hooks = hookBucket();
    const calls: Record<string, number> = {};
    const { q, timer } = makeQueue(
      scriptedSender({ [T1]: [400], [T2]: [503, 503, "ok"] }, calls),
      hooks,
      { targets: [T1, T2], quorum: 2 }
    );
    q.start();
    try {
      q.enqueueFanout(item("f6"));
      await timer.run();
      // 400 = poison: one attempt, straight to the loss record.
      assert.equal(calls[T1], 1);
      assert.equal(hooks.targetDeadLettered.length, 1);
      assert.equal(hooks.targetDeadLettered[0].failureClass, "non_retryable");
      assert.equal(hooks.targetDeadLettered[0].targetUrl, T1);
      // 503 = transient: the member burned its own retry budget, then acked.
      assert.equal(calls[T2], 3);
      // Only one ack banked and one target lost: quorum 2 of 2 unreachable.
      assert.equal(hooks.failed.length, 1);
      assert.equal(hooks.satisfied.length, 0);
      const [row] = q.getQuorumStats();
      assert.equal(row.status, "failed");
      assert.deepEqual(
        row.deadLettered.map((d) => [d.targetUrl, d.failureClass]),
        [[T1, "non_retryable"]]
      );
    } finally {
      q.stop();
    }
  });
});

describe("quorum composes with the WR-12 urgent lane", () => {
  it("an urgent admission puts every member on the fast lane", async () => {
    const hooks = hookBucket();
    const calls: Record<string, number> = {};
    const delays: number[] = [];
    const seen: RetryItem[] = [];
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: scriptedSender({ [T1]: [500, 500, "ok"] }, calls, seen),
      baseDelayMs: 100,
      maxDelayMs: 10000,
      jitterMs: 0,
      maxAttempts: 4,
      setTimer: (fn, ms) => {
        delays.push(ms);
        return timer.setTimer(fn, ms);
      },
      urgent: { retryDelayMs: 25 },
      quorum: { [LOGICAL]: { targets: [T1, T2], quorum: 2 } },
      onQuorumSatisfied: hooks.onQuorumSatisfied,
    });
    q.start();
    try {
      q.enqueueFanout(item("f7", "urgent"));
      await timer.run();
      // Every member kept the urgent priority...
      assert.ok(seen.length > 0);
      for (const s of seen) assert.equal(s.priority, "urgent");
      // ...and the flaky member retried on the fixed fast-lane delay,
      // not the exponential grid (both members dispatch at 0, then T1's
      // two urgent retries at 25ms).
      assert.deepEqual([...delays].sort((a, b) => a - b), [0, 0, 25, 25]);
      assert.equal(hooks.satisfied.length, 1);
      const urgentRows = q.getUrgentStats();
      assert.ok(urgentRows.some((r) => r.endpoint === T1 && r.delivered === 1));
    } finally {
      q.stop();
    }
  });
});

describe("quorum observability", () => {
  it("getQuorumStats tracks progress per fan-out", async () => {
    const hooks = hookBucket();
    const calls: Record<string, number> = {};
    const { q, timer } = makeQueue(scriptedSender({}, calls), hooks);
    q.start();
    try {
      assert.deepEqual(q.getQuorumStats(), []);
      q.enqueueFanout(item("f8"));
      const [before] = q.getQuorumStats();
      assert.equal(before.targets, 3);
      assert.equal(before.acked, 0);
      assert.equal(before.status, "in_progress");
      assert.deepEqual(before.deadLettered, []);
      await timer.run();
      const [after] = q.getQuorumStats();
      assert.equal(after.acked, 3);
      assert.equal(after.status, "satisfied");
    } finally {
      q.stop();
    }
  });

  it("renderMetrics exposes relay_quorum_* only once there is activity", async () => {
    const hooks = hookBucket();
    const calls: Record<string, number> = {};
    const { q, timer } = makeQueue(
      scriptedSender({ [T1]: [500, 500, 500] }, calls),
      hooks
    );
    q.start();
    try {
      q.enqueueFanout(item("f9"));
      await timer.run();
      const exposition = q.renderMetrics();
      const endpoint = LOGICAL.replace(/"/g, "");
      assert.match(
        exposition,
        new RegExp(`relay_quorum_total\\{endpoint="${endpoint}",status="satisfied"\\} 1`)
      );
      assert.match(
        exposition,
        new RegExp(`relay_quorum_acknowledged_total\\{endpoint="${endpoint}"\\} 2`)
      );
      assert.match(
        exposition,
        new RegExp(`relay_quorum_target_dead_letters_total\\{endpoint="${endpoint}"\\} 1`)
      );
    } finally {
      q.stop();
    }
    // A queue without quorum configured exposes no relay_quorum_* series.
    const plain = new RetryQueue({ sender: async () => {} });
    assert.ok(!plain.renderMetrics().includes("relay_quorum_"));
  });
});

describe("quorum server wiring", () => {
  it("fans out on admission, audits quorum events, and serves GET /quorum", async () => {
    const dir = mkdtempSync(join(tmpdir(), "quorum-server-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const opToken = "op-token";
    const calls: Record<string, number> = {};
    const payload = Buffer.from(JSON.stringify({ n: 1 }));
    const server = createRelayServer({
      secret: "test-secret",
      forwardUrl: LOGICAL,
      auditLog: audit,
      operatorToken: opToken,
      sender: scriptedSender({}, calls),
      quorum: { [LOGICAL]: { targets: [T1, T2], quorum: 2 } },
      retry: { baseDelayMs: 5, maxDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const post = (path: string, headers: Record<string, string>, body?: Buffer) =>
        new Promise<{ status: number; body: string }>((resolve, reject) => {
          const req = httpRequest(
            { port, method: body === undefined ? "GET" : "POST", path, headers },
            (res) => {
              const chunks: Buffer[] = [];
              res.on("data", (c: Buffer) => chunks.push(c));
              res.on("end", () =>
                resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") })
              );
            }
          );
          req.on("error", reject);
          req.end(body);
        });
      const accepted = await post(
        "/hook",
        { "content-type": "application/json", "x-signature": signSha256(payload, "test-secret") },
        payload
      );
      assert.equal(accepted.status, 202);
      await new Promise((r) => setTimeout(r, 300));
      // Both targets received the event through the queue's sender.
      assert.equal(calls[T1], 1);
      assert.equal(calls[T2], 1);
      // The logical endpoint itself was never sent to directly.
      assert.equal(calls[LOGICAL] ?? 0, 0);
      const quorumRes = await post("/quorum", { authorization: `Bearer ${opToken}` });
      assert.equal(quorumRes.status, 200);
      const rows = JSON.parse(quorumRes.body) as Array<Record<string, unknown>>;
      assert.equal(rows.length, 1);
      assert.equal(rows[0].endpoint, LOGICAL);
      assert.equal(rows[0].targets, 2);
      assert.equal(rows[0].acked, 2);
      assert.equal(rows[0].status, "satisfied");
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const names = events.map((e) => e.event);
      assert.ok(names.includes("quorum_dispatched"), "audits quorum_dispatched");
      assert.ok(names.includes("quorum_satisfied"), "audits quorum_satisfied");
      const acked = events.filter((e) => e.event === "quorum_acknowledged");
      assert.equal(acked.length, 2);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("rejects an invalid server-level quorum config at startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "quorum-server-"));
    assert.throws(
      () =>
        createRelayServer({
          secret: "test-secret",
          forwardUrl: LOGICAL,
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          quorum: { [LOGICAL]: { targets: [T1], quorum: 2 } },
        }),
      RangeError
    );
  });
});
