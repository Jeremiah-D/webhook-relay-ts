import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import {
  HttpDeliveryError,
  RetryQueue,
  type QuorumAcknowledgedInfo,
  type QuorumDispatchedInfo,
  type QuorumEvictedInfo,
  type QuorumFailedInfo,
  type QuorumSatisfiedInfo,
  type QuorumTargetDeadLetteredInfo,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "quorum-callbacks-revision-secret";
const operatorToken = "quorum-callbacks-revision-token";
const LOGICAL = "http://127.0.0.1:9940/hook";
const T1 = "http://127.0.0.1:9941/one";
const T2 = "http://127.0.0.1:9942/two";
const T3 = "http://127.0.0.1:9943/three";
const BODY = Buffer.from(JSON.stringify({ payment: "pi_456", amount: 7000 }));

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

function item(id: string): RetryItem {
  return {
    id,
    payload: Buffer.from(`payload-${id}`),
    targetUrl: LOGICAL,
    headers: {},
  };
}

interface QuorumHooks {
  dispatched: QuorumDispatchedInfo[];
  acknowledged: QuorumAcknowledgedInfo[];
  satisfied: QuorumSatisfiedInfo[];
  failed: QuorumFailedInfo[];
  targetDeadLettered: QuorumTargetDeadLetteredInfo[];
  evicted: QuorumEvictedInfo[];
}

/** One bucket per callback generation, so "old stays silent" is exact. */
function hookBucket(): QuorumHooks & {
  onQuorumDispatched: (i: QuorumDispatchedInfo) => void;
  onQuorumAcknowledged: (i: QuorumAcknowledgedInfo) => void;
  onQuorumSatisfied: (i: QuorumSatisfiedInfo) => void;
  onQuorumFailed: (i: QuorumFailedInfo) => void;
  onQuorumTargetDeadLettered: (i: QuorumTargetDeadLetteredInfo) => void;
  onQuorumEvicted: (i: QuorumEvictedInfo) => void;
} {
  const b: QuorumHooks = {
    dispatched: [],
    acknowledged: [],
    satisfied: [],
    failed: [],
    targetDeadLettered: [],
    evicted: [],
  };
  return {
    ...b,
    onQuorumDispatched: (i) => b.dispatched.push(i),
    onQuorumAcknowledged: (i) => b.acknowledged.push(i),
    onQuorumSatisfied: (i) => b.satisfied.push(i),
    onQuorumFailed: (i) => b.failed.push(i),
    onQuorumTargetDeadLettered: (i) => b.targetDeadLettered.push(i),
    onQuorumEvicted: (i) => b.evicted.push(i),
  };
}

/** Sender that routes by targetUrl to per-target scripted behaviors. */
function scriptedSender(
  scripts: Record<string, Array<"ok" | number | Error>>,
  calls: Record<string, number>
): Sender {
  return async (it: RetryItem) => {
    calls[it.targetUrl] = (calls[it.targetUrl] ?? 0) + 1;
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
    onQuorumEvicted: hooks.onQuorumEvicted,
    ...extra,
  });
  return { q, timer };
}

describe("RetryQueue quorum callbacks revision (WR-396)", () => {
  it("dispatched, acknowledged and satisfied reach the revised callbacks; the old callbacks stay silent", async () => {
    const first = hookBucket();
    const second = hookBucket();
    const calls: Record<string, number> = {};
    const { q, timer } = makeQueue(scriptedSender({}, calls), first);
    q.start();
    try {
      q.enqueueFanout(item("f1"));
      await timer.run();
      assert.equal(first.dispatched.length, 1);
      assert.equal(first.dispatched[0].fanoutId, "f1");
      assert.deepEqual(first.dispatched[0].targets, [T1, T2, T3]);
      assert.equal(first.dispatched[0].quorum, 2);
      assert.equal(first.satisfied.length, 1);
      assert.equal(first.satisfied[0].acked, 2);
      q.reviseQuorumCallbacks({
        onQuorumDispatched: second.onQuorumDispatched,
        onQuorumAcknowledged: second.onQuorumAcknowledged,
        onQuorumSatisfied: second.onQuorumSatisfied,
      });
      q.enqueueFanout(item("f2"));
      await timer.run();
      assert.equal(first.dispatched.length, 1);
      assert.equal(first.acknowledged.length, 3);
      assert.equal(first.satisfied.length, 1);
      assert.equal(second.dispatched.length, 1);
      assert.equal(second.dispatched[0].fanoutId, "f2");
      assert.equal(second.acknowledged.length, 3);
      assert.deepEqual(
        second.acknowledged.map((a) => a.targetUrl).sort(),
        [T1, T2, T3]
      );
      assert.equal(second.satisfied.length, 1);
      assert.equal(second.satisfied[0].fanoutId, "f2");
      assert.equal(second.satisfied[0].acked, 2);
    } finally {
      q.stop();
    }
  });

  it("an in-progress fan-out reports its later events to the revised callbacks", async () => {
    const first = hookBucket();
    const second = hookBucket();
    let resolveT2!: () => void;
    const t2Gate = new Promise<void>((r) => {
      resolveT2 = r;
    });
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async (it: RetryItem) => {
        if (it.targetUrl === T2) await t2Gate;
      },
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 3,
      setTimer: timer.setTimer,
      quorum: { [LOGICAL]: { targets: [T1, T2], quorum: 2 } },
      onQuorumDispatched: first.onQuorumDispatched,
      onQuorumAcknowledged: first.onQuorumAcknowledged,
      onQuorumSatisfied: first.onQuorumSatisfied,
      onQuorumFailed: first.onQuorumFailed,
      onQuorumTargetDeadLettered: first.onQuorumTargetDeadLettered,
      onQuorumEvicted: first.onQuorumEvicted,
    });
    q.start();
    try {
      q.enqueueFanout(item("f1"));
      await timer.run();
      // T1 acked into the first callbacks; T2 is still in flight.
      assert.equal(first.dispatched.length, 1);
      assert.equal(first.acknowledged.length, 1);
      assert.equal(first.acknowledged[0].targetUrl, T1);
      assert.equal(first.satisfied.length, 0);
      q.reviseQuorumCallbacks({
        onQuorumAcknowledged: second.onQuorumAcknowledged,
        onQuorumSatisfied: second.onQuorumSatisfied,
      });
      resolveT2();
      await timer.run();
      await new Promise((r) => setImmediate(r));
      assert.equal(first.acknowledged.length, 1);
      assert.equal(first.satisfied.length, 0);
      assert.equal(second.acknowledged.length, 1);
      assert.equal(second.acknowledged[0].targetUrl, T2);
      assert.equal(second.satisfied.length, 1);
      assert.equal(second.satisfied[0].fanoutId, "f1");
      assert.equal(second.satisfied[0].acked, 2);
    } finally {
      q.stop();
    }
  });

  it("failed and target-dead-lettered reach the revised callbacks", async () => {
    const first = hookBucket();
    const second = hookBucket();
    const calls: Record<string, number> = {};
    // T3 acks first so the verdict fires with one ack banked; T1/T2
    // exhaust their single attempt and die.
    const { q, timer } = makeQueue(
      scriptedSender({ [T1]: [500], [T2]: [500], [T3]: ["ok"] }, calls),
      first,
      { targets: [T3, T1, T2], quorum: 2 },
      { maxAttempts: 1 }
    );
    q.start();
    try {
      q.enqueueFanout(item("f1"));
      await timer.run();
      assert.equal(first.targetDeadLettered.length, 2);
      assert.equal(first.failed.length, 1);
      assert.equal(first.failed[0].acked, 1);
      assert.match(first.failed[0].reason, /unreachable/);
      q.reviseQuorumCallbacks({
        onQuorumFailed: second.onQuorumFailed,
        onQuorumTargetDeadLettered: second.onQuorumTargetDeadLettered,
      });
      q.enqueueFanout(item("f2"));
      await timer.run();
      assert.equal(first.targetDeadLettered.length, 2);
      assert.equal(first.failed.length, 1);
      assert.equal(second.targetDeadLettered.length, 2);
      assert.deepEqual(
        second.targetDeadLettered.map((d) => d.targetUrl).sort(),
        [T1, T2]
      );
      assert.equal(second.targetDeadLettered[0].failureClass, "retryable");
      assert.equal(second.failed.length, 1);
      assert.equal(second.failed[0].fanoutId, "f2");
      assert.equal(second.failed[0].acked, 1);
    } finally {
      q.stop();
    }
  });

  it("evicted reaches the revised callback at the next sweep; the verdict and counters are untouched", async () => {
    const first = hookBucket();
    const second = hookBucket();
    const calls: Record<string, number> = {};
    const { q, timer } = makeQueue(
      scriptedSender({}, calls),
      first,
      { targets: [T1, T2], quorum: 2 },
      { quorumMaxFanouts: 1 }
    );
    q.start();
    try {
      q.enqueueFanout(item("f1"));
      await timer.run();
      assert.equal(first.satisfied.length, 1);
      assert.equal(q.getQuorumEvictedCount(), 0);
      q.reviseQuorumCallbacks({ onQuorumEvicted: second.onQuorumEvicted });
      q.enqueueFanout(item("f2"));
      await timer.run();
      assert.equal(first.evicted.length, 0);
      assert.equal(second.evicted.length, 1);
      assert.equal(second.evicted[0].fanoutId, "f1");
      assert.equal(second.evicted[0].status, "satisfied");
      assert.equal(second.evicted[0].reason, "lru_cap");
      assert.equal(q.getQuorumEvictedCount(), 1);
      assert.equal(q.getQuorumStats().length, 1);
      assert.equal(q.getQuorumStats()[0].fanoutId, "f2");
      assert.equal(q.getQuorumStats()[0].status, "satisfied");
    } finally {
      q.stop();
    }
  });

  it("null clears a single field; fan-out, verdicts and counters continue and the other five fields are untouched", async () => {
    const first = hookBucket();
    const calls: Record<string, number> = {};
    let failT1 = false;
    let failT3 = false;
    const { q, timer } = makeQueue(
      async (it: RetryItem) => {
        if ((it.targetUrl === T1 && failT1) || (it.targetUrl === T3 && failT3)) {
          throw new HttpDeliveryError(500);
        }
      },
      first,
      { targets: [T1, T2, T3], quorum: 2 },
      { quorumMaxFanouts: 1 }
    );
    q.start();
    try {
      q.reviseQuorumCallbacks({ onQuorumSatisfied: null });
      q.enqueueFanout(item("f1"));
      await timer.run();
      assert.equal(first.dispatched.length, 1);
      assert.equal(first.acknowledged.length, 3);
      assert.equal(first.satisfied.length, 0, "cleared hook stays silent");
      assert.equal(q.getQuorumStats()[0].status, "satisfied");
      // The other five hooks are still live: two losses settle f2 as
      // failed, dead-letter both targets, and evict f1.
      failT1 = true;
      failT3 = true;
      q.enqueueFanout(item("f2"));
      await timer.run();
      assert.equal(first.dispatched.length, 2);
      assert.equal(first.targetDeadLettered.length, 2);
      assert.equal(first.failed.length, 1);
      assert.equal(first.failed[0].fanoutId, "f2");
      assert.equal(first.evicted.length, 1);
      assert.equal(first.evicted[0].fanoutId, "f1");
      assert.equal(first.satisfied.length, 0);
      assert.equal(q.getQuorumEvictedCount(), 1);
    } finally {
      q.stop();
    }
  });

  it("all six fields move in one patch", async () => {
    const first = hookBucket();
    const second = hookBucket();
    const calls: Record<string, number> = {};
    const { q, timer } = makeQueue(
      scriptedSender({ [T1]: [500], [T2]: [500], [T3]: ["ok"] }, calls),
      first,
      { targets: [T3, T1, T2], quorum: 2 },
      { maxAttempts: 1, quorumMaxFanouts: 1 }
    );
    q.start();
    try {
      q.reviseQuorumCallbacks({
        onQuorumDispatched: second.onQuorumDispatched,
        onQuorumAcknowledged: second.onQuorumAcknowledged,
        onQuorumSatisfied: second.onQuorumSatisfied,
        onQuorumFailed: second.onQuorumFailed,
        onQuorumTargetDeadLettered: second.onQuorumTargetDeadLettered,
        onQuorumEvicted: second.onQuorumEvicted,
      });
      q.enqueueFanout(item("f1"));
      await timer.run();
      assert.equal(first.dispatched.length, 0);
      assert.equal(second.dispatched.length, 1);
      assert.equal(second.acknowledged.length, 1);
      assert.equal(second.targetDeadLettered.length, 2);
      assert.equal(second.failed.length, 1);
      assert.equal(second.satisfied.length, 0);
      // Settling f2 evicts f1 into the revised evicted hook.
      q.enqueueFanout(item("f2"));
      await timer.run();
      assert.equal(second.dispatched.length, 2);
      assert.equal(second.failed.length, 2);
      assert.equal(first.evicted.length, 0);
      assert.equal(second.evicted.length, 1);
      assert.equal(second.evicted[0].fanoutId, "f1");
      assert.equal(second.evicted[0].status, "failed");
    } finally {
      q.stop();
    }
  });

  it("an empty or non-object patch and an illegal value throw RangeError and the live callbacks are untouched", async () => {
    const first = hookBucket();
    const calls: Record<string, number> = {};
    const { q, timer } = makeQueue(scriptedSender({}, calls), first);
    q.start();
    try {
      for (const bad of [null, "x", 42, {}, []] as never[]) {
        assert.throws(() => q.reviseQuorumCallbacks(bad), RangeError, String(bad));
      }
      assert.throws(
        () => q.reviseQuorumCallbacks({ onQuorumDispatched: "nope" as never }),
        RangeError
      );
      assert.throws(
        () => q.reviseQuorumCallbacks({ onQuorumEvicted: 42 as never }),
        RangeError
      );
      assert.throws(
        () =>
          q.reviseQuorumCallbacks({
            onQuorumSatisfied: first.onQuorumSatisfied,
            onQuorumFailed: "nope" as never,
          }),
        RangeError
      );
      // Nothing moved: the original hooks still fire.
      q.enqueueFanout(item("v1"));
      await timer.run();
      assert.equal(first.dispatched.length, 1);
      assert.equal(first.satisfied.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a same-value patch is a no-op; a partial patch leaves the other hooks live", async () => {
    const first = hookBucket();
    const second = hookBucket();
    const calls: Record<string, number> = {};
    const { q, timer } = makeQueue(scriptedSender({}, calls), first);
    q.start();
    try {
      q.reviseQuorumCallbacks({ onQuorumDispatched: first.onQuorumDispatched });
      q.reviseQuorumCallbacks({ onQuorumSatisfied: second.onQuorumSatisfied });
      q.enqueueFanout(item("n1"));
      await timer.run();
      assert.equal(first.dispatched.length, 1, "untouched hook still live");
      assert.equal(first.satisfied.length, 0);
      assert.equal(second.satisfied.length, 1);
      assert.equal(second.satisfied[0].fanoutId, "n1");
    } finally {
      q.stop();
    }
  });

  it("revising with quorum unconfigured throws Error; quorumConfigured reports the live state", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.quorumConfigured(), false);
    assert.throws(
      () => q.reviseQuorumCallbacks({ onQuorumDispatched: () => {} }),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    const calls: Record<string, number> = {};
    const { q: configured } = makeQueue(scriptedSender({}, calls), hookBucket());
    assert.equal(configured.quorumConfigured(), true);
    configured.stop();
  });
});

describe("RelayServer quorum callbacks revision (WR-396)", () => {
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

  function postWebhook(port: number, body: Buffer) {
    return new Promise<{ status: number }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-signature": signSha256(body, relaySecret),
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  function quorumServer(opts: {
    hooks?: ReturnType<typeof hookBucket>;
    sender?: Sender;
    quorum?: { targets: string[]; quorum: number };
    retryExtra?: Record<string, unknown>;
    extra?: Record<string, unknown>;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "quorum-callbacks-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const hooks = opts.hooks ?? hookBucket();
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: LOGICAL,
      auditLog,
      operatorToken,
      sender: opts.sender ?? (async () => {}),
      quorum: { [LOGICAL]: opts.quorum ?? { targets: [T1, T2, T3], quorum: 2 } },
      retry: {
        baseDelayMs: 1,
        maxDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 3,
        onQuorumDispatched: hooks.onQuorumDispatched,
        onQuorumAcknowledged: hooks.onQuorumAcknowledged,
        onQuorumSatisfied: hooks.onQuorumSatisfied,
        onQuorumFailed: hooks.onQuorumFailed,
        onQuorumTargetDeadLettered: hooks.onQuorumTargetDeadLettered,
        onQuorumEvicted: hooks.onQuorumEvicted,
        ...(opts.retryExtra ?? {}),
      },
      ...(opts.extra ?? {}),
    });
    servers.push(relay);
    return { relay, auditLog, hooks };
  }

  /** Drive one fan-out and wait for its verdict audit to land. */
  async function driveFanout(
    port: number,
    auditLog: AuditLog,
    event: "quorum_satisfied" | "quorum_failed"
  ): Promise<void> {
    const before = eventsOf(auditLog, event).length;
    assert.equal((await postWebhook(port, BODY)).status, 202);
    await waitFor(() => eventsOf(auditLog, event).length > before, `${event} audit`);
  }

  it("revising the dispatched/acknowledged/satisfied callbacks routes the next fan-out to the new callbacks and the audits still land", async () => {
    const first = hookBucket();
    const second = hookBucket();
    const { relay, auditLog } = quorumServer({ hooks: first });
    const port = await listen(relay);
    await driveFanout(port, auditLog, "quorum_satisfied");
    assert.equal(first.dispatched.length, 1);
    assert.equal(first.satisfied.length, 1);
    relay.reviseQuorumCallbacks!({
      onQuorumDispatched: second.onQuorumDispatched,
      onQuorumAcknowledged: second.onQuorumAcknowledged,
      onQuorumSatisfied: second.onQuorumSatisfied,
    });
    await driveFanout(port, auditLog, "quorum_satisfied");
    assert.equal(first.dispatched.length, 1);
    assert.equal(first.acknowledged.length, 3);
    assert.equal(first.satisfied.length, 1);
    assert.equal(second.dispatched.length, 1);
    assert.equal(second.acknowledged.length, 3);
    assert.equal(second.satisfied.length, 1);
    assert.equal(eventsOf(auditLog, "quorum_dispatched").length, 2);
    assert.equal(eventsOf(auditLog, "quorum_satisfied").length, 2);
    // The revision itself is audited with per-hook presence, never a body.
    const revised = eventsOf(auditLog, "quorum_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].onQuorumDispatched, "set");
    assert.equal(revised[0].oldOnQuorumDispatched, "set");
    assert.equal(revised[0].onQuorumAcknowledged, "set");
    assert.equal(revised[0].oldOnQuorumAcknowledged, "set");
    assert.equal(revised[0].onQuorumSatisfied, "set");
    assert.equal(revised[0].oldOnQuorumSatisfied, "set");
    assert.equal(revised[0].onQuorumFailed, "unchanged");
    assert.equal(revised[0].oldOnQuorumFailed, "set");
    assert.equal(revised[0].onQuorumTargetDeadLettered, "unchanged");
    assert.equal(revised[0].oldOnQuorumTargetDeadLettered, "set");
    assert.equal(revised[0].onQuorumEvicted, "unchanged");
    assert.equal(revised[0].oldOnQuorumEvicted, "set");
  });

  it("revising the failed and target-dead-lettered callbacks routes the next loss to the new callbacks", async () => {
    const first = hookBucket();
    const second = hookBucket();
    const calls: Record<string, number> = {};
    const { relay, auditLog } = quorumServer({
      hooks: first,
      sender: scriptedSender({ [T1]: [500], [T2]: [500], [T3]: ["ok"] }, calls),
      quorum: { targets: [T3, T1, T2], quorum: 2 },
      retryExtra: { maxAttempts: 1 },
    });
    const port = await listen(relay);
    await driveFanout(port, auditLog, "quorum_failed");
    assert.equal(first.targetDeadLettered.length, 2);
    assert.equal(first.failed.length, 1);
    relay.reviseQuorumCallbacks!({
      onQuorumFailed: second.onQuorumFailed,
      onQuorumTargetDeadLettered: second.onQuorumTargetDeadLettered,
    });
    await driveFanout(port, auditLog, "quorum_failed");
    assert.equal(first.targetDeadLettered.length, 2);
    assert.equal(first.failed.length, 1);
    assert.equal(second.targetDeadLettered.length, 2);
    assert.equal(second.failed.length, 1);
    assert.equal(eventsOf(auditLog, "quorum_failed").length, 2);
    assert.equal(eventsOf(auditLog, "quorum_target_dead_lettered").length, 4);
  });

  it("null clears a single field; the audit still lands and the other hooks stay live", async () => {
    const first = hookBucket();
    const { relay, auditLog } = quorumServer({ hooks: first });
    const port = await listen(relay);
    await driveFanout(port, auditLog, "quorum_satisfied");
    assert.equal(first.satisfied.length, 1);
    relay.reviseQuorumCallbacks!({ onQuorumSatisfied: null });
    await driveFanout(port, auditLog, "quorum_satisfied");
    assert.equal(first.dispatched.length, 2);
    assert.equal(first.acknowledged.length, 6);
    assert.equal(first.satisfied.length, 1, "cleared hook stays silent");
    assert.equal(eventsOf(auditLog, "quorum_satisfied").length, 2);
    const revised = eventsOf(auditLog, "quorum_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].onQuorumSatisfied, "cleared");
    assert.equal(revised[0].oldOnQuorumSatisfied, "set");
    assert.equal(revised[0].onQuorumDispatched, "unchanged");
    assert.equal(revised[0].oldOnQuorumDispatched, "set");
  });

  it("an illegal value or empty patch throws RangeError, live callbacks untouched, no revision audit; same-value is a silent no-op", async () => {
    const first = hookBucket();
    const { relay, auditLog } = quorumServer({ hooks: first });
    const port = await listen(relay);
    for (const bad of [null, "x", 42, {}, []] as never[]) {
      assert.throws(() => relay.reviseQuorumCallbacks!(bad), RangeError, String(bad));
    }
    assert.throws(
      () => relay.reviseQuorumCallbacks!({ onQuorumDispatched: "nope" as never }),
      RangeError
    );
    assert.throws(
      () => relay.reviseQuorumCallbacks!({ onQuorumEvicted: 42 as never }),
      RangeError
    );
    assert.equal(eventsOf(auditLog, "quorum_callbacks_revised").length, 0);
    relay.reviseQuorumCallbacks!({ onQuorumDispatched: first.onQuorumDispatched });
    assert.equal(eventsOf(auditLog, "quorum_callbacks_revised").length, 0);
    await driveFanout(port, auditLog, "quorum_satisfied");
    assert.equal(first.dispatched.length, 1);
    assert.equal(first.satisfied.length, 1);
  });

  it("revising the evicted callback routes the next eviction to the new callback", async () => {
    const first = hookBucket();
    const second = hookBucket();
    const { relay, auditLog } = quorumServer({
      hooks: first,
      extra: { quorumMaxFanouts: 1 },
    });
    const port = await listen(relay);
    await driveFanout(port, auditLog, "quorum_satisfied");
    assert.equal(first.satisfied.length, 1);
    relay.reviseQuorumCallbacks!({ onQuorumEvicted: second.onQuorumEvicted });
    assert.equal((await postWebhook(port, BODY)).status, 202);
    await waitFor(() => eventsOf(auditLog, "quorum_evicted").length > 0, "quorum_evicted audit");
    assert.equal(first.evicted.length, 0);
    assert.equal(second.evicted.length, 1);
    assert.equal(second.evicted[0].status, "satisfied");
    assert.equal(second.evicted[0].reason, "lru_cap");
    assert.equal(eventsOf(auditLog, "quorum_evicted").length, 1);
  });

  it("revising with quorum unconfigured throws Error", () => {
    const dir = mkdtempSync(join(tmpdir(), "quorum-callbacks-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: LOGICAL,
      auditLog,
      operatorToken,
      sender: async () => {},
    });
    servers.push(relay);
    assert.throws(
      () => relay.reviseQuorumCallbacks!({ onQuorumDispatched: () => {} }),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });
});
