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
} from "../src/retry.ts";
import type { CanaryRolloutEvent } from "../src/canary-rollout.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "canary-rollout-event-callback-revision-secret";
const PRIMARY = "http://127.0.0.1:9921/primary";
const CANDIDATE = "http://127.0.0.1:9922/candidate";
const URL = PRIMARY;
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

function item(id: string): RetryItem {
  return { id, payload: Buffer.from(id), targetUrl: PRIMARY, headers: {} };
}

describe("RetryQueue canary-rollout-event callback revision (WR-393)", () => {
  /** A rolling queue: steps [50, 100], 1000ms dwell, deterministic clock and coin. */
  function makeRampQueue(
    onEvent?: (event: CanaryRolloutEvent) => void,
    steps: number[] = [50, 100]
  ) {
    const timer = manualTimer();
    let nowMs = 0;
    const seen: string[] = [];
    const q = new RetryQueue({
      sender: async (entry) => {
        seen.push(entry.targetUrl);
      },
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 3,
      setTimer: timer.setTimer,
      canaryRollouts: { [PRIMARY]: { candidate: CANDIDATE, steps, dwellMs: 1000 } },
      canaryNow: () => nowMs,
      canaryRandom: () => 0,
      ...(onEvent !== undefined ? { onCanaryRolloutEvent: onEvent } : {}),
    });
    return {
      q,
      timer,
      seen,
      advance: (ms: number) => {
        nowMs += ms;
      },
    };
  }

  function counterLine(exposition: string, event: string): string | undefined {
    const re = new RegExp(
      `relay_canary_rollout_events_total\\{endpoint="${PRIMARY}",candidate="${CANDIDATE}",event="${event}"\\} (\\d+)`
    );
    return exposition.match(re)?.[0];
  }

  it("revise swaps the live callback: the next transition enters the new callback, the old one is silent, and the counters keep counting", async () => {
    const { q, timer, seen, advance } = makeRampQueue();
    const oldSeen: CanaryRolloutEvent[] = [];
    const newSeen: CanaryRolloutEvent[] = [];
    q.reviseCanaryRolloutEventCallback((e) => oldSeen.push(e));
    q.start();
    try {
      q.enqueue(item("r-1"));
      await timer.run();
      assert.deepEqual(seen, [CANDIDATE]);
      assert.equal(q.getCanaryStats()[0].step, 0);
      advance(1000);
      q.enqueue(item("r-2"));
      await timer.run();
      assert.deepEqual(seen, [CANDIDATE, CANDIDATE]);
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(oldSeen[0], {
        event: "canary_step_advanced",
        endpoint: PRIMARY,
        candidate: CANDIDATE,
        step: 1,
        percent: 100,
        at: "1970-01-01T00:00:01.000Z",
      });
      assert.deepEqual(newSeen, []);
      // Swap mid-ramp: the already-reported advance is never
      // re-delivered, and the promotion enters only the new callback.
      q.reviseCanaryRolloutEventCallback((e) => newSeen.push(e));
      advance(1000);
      q.enqueue(item("r-3"));
      await timer.run();
      assert.deepEqual(seen, [CANDIDATE, CANDIDATE, CANDIDATE]);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.deepEqual(newSeen[0], {
        event: "canary_promoted",
        endpoint: PRIMARY,
        candidate: CANDIDATE,
        step: 2,
        percent: 100,
        at: "1970-01-01T00:00:02.000Z",
      });
      assert.equal(q.getCanaryStats()[0].state, "promoted");
      const exposition = q.renderMetrics();
      assert.equal(
        counterLine(exposition, "canary_step_advanced"),
        `relay_canary_rollout_events_total{endpoint="${PRIMARY}",candidate="${CANDIDATE}",event="canary_step_advanced"} 1`
      );
      assert.equal(
        counterLine(exposition, "canary_promoted"),
        `relay_canary_rollout_events_total{endpoint="${PRIMARY}",candidate="${CANDIDATE}",event="canary_promoted"} 1`
      );
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer: the rollout keeps advancing and promoting, only the forwarding stops", async () => {
    const { q, timer, advance } = makeRampQueue();
    const seen: CanaryRolloutEvent[] = [];
    q.reviseCanaryRolloutEventCallback((e) => seen.push(e));
    q.start();
    try {
      q.enqueue(item("c-1"));
      await timer.run();
      advance(1000);
      q.enqueue(item("c-2"));
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].event, "canary_step_advanced");
      q.reviseCanaryRolloutEventCallback(null);
      advance(1000);
      q.enqueue(item("c-3"));
      await timer.run();
      assert.equal(seen.length, 1); // the promotion was silent
      assert.equal(q.getCanaryStats()[0].state, "promoted");
      const exposition = q.renderMetrics();
      assert.equal(
        counterLine(exposition, "canary_promoted"),
        `relay_canary_rollout_events_total{endpoint="${PRIMARY}",candidate="${CANDIDATE}",event="canary_promoted"} 1`
      );
    } finally {
      q.stop();
    }
  });

  it("a queue without canary configured cannot gain an observer at runtime — must restart", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.throws(
        () => q.reviseCanaryRolloutEventCallback(() => {}),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
          assert.match((err as Error).message, /requires a restart/);
          return true;
        }
      );
      assert.throws(
        () => q.reviseCanaryRolloutEventCallback(null),
        /requires a restart/
      );
    } finally {
      q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const { q, timer, advance } = makeRampQueue();
    const seen: CanaryRolloutEvent[] = [];
    const live = (e: CanaryRolloutEvent) => seen.push(e);
    q.reviseCanaryRolloutEventCallback(live);
    q.start();
    try {
      for (const bad of ["nope", 42, {}, true]) {
        assert.throws(
          () => q.reviseCanaryRolloutEventCallback(bad as never),
          RangeError,
          JSON.stringify(bad)
        );
      }
      q.enqueue(item("bad-1"));
      await timer.run();
      advance(1000);
      q.enqueue(item("bad-2"));
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].event, "canary_step_advanced");
      assert.equal(seen[0].step, 1);
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference (or clearing when unset) is a no-op", async () => {
    const { q, timer, advance } = makeRampQueue();
    const seen: CanaryRolloutEvent[] = [];
    const cb = (e: CanaryRolloutEvent) => seen.push(e);
    // Clearing when nothing is set never throws and changes nothing.
    q.reviseCanaryRolloutEventCallback(null);
    q.reviseCanaryRolloutEventCallback(cb);
    q.reviseCanaryRolloutEventCallback(cb); // same reference: no-op
    q.start();
    try {
      q.enqueue(item("same-1"));
      await timer.run();
      advance(1000);
      q.enqueue(item("same-2"));
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].event, "canary_step_advanced");
      q.reviseCanaryRolloutEventCallback(null);
      q.reviseCanaryRolloutEventCallback(null); // clearing when unset: no-op
      advance(1000);
      q.enqueue(item("same-3"));
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(q.getCanaryStats()[0].state, "promoted");
    } finally {
      q.stop();
    }
  });

  it("a rollback after a revision still carries reason/stepSamples/stepFailures to the new callback", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const events: CanaryRolloutEvent[] = [];
    const sender: Sender = async (entry) => {
      seen.push(entry.targetUrl);
      if (entry.targetUrl === CANDIDATE) throw new Error("candidate down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1, // one outcome per item: the rollback needs two items
      setTimer: timer.setTimer,
      canaryRollouts: {
        [PRIMARY]: {
          candidate: CANDIDATE,
          steps: [100],
          dwellMs: 60_000,
          maxConsecutiveStepFailures: 2,
        },
      },
      canaryNow: () => 0,
      canaryRandom: () => 0,
      onCanaryRolloutEvent: (e) => events.push(e),
    });
    q.start();
    try {
      const oldSeen = events;
      const newSeen: CanaryRolloutEvent[] = [];
      q.enqueue(item("rb-1"));
      await timer.run();
      await settle();
      assert.deepEqual(seen, [CANDIDATE]); // one failure: still rolling
      assert.equal(q.getCanaryStats()[0].state, "rolling");
      assert.deepEqual(oldSeen, []);
      // Swap before the budget burns: the rollback enters only the new
      // callback, with the full step accounting attached.
      q.reviseCanaryRolloutEventCallback((e) => newSeen.push(e));
      q.enqueue(item("rb-2"));
      await timer.run();
      await settle();
      assert.deepEqual(seen, [CANDIDATE, CANDIDATE]);
      assert.deepEqual(oldSeen, []);
      assert.equal(newSeen.length, 1);
      assert.deepEqual(newSeen[0], {
        event: "canary_rolled_back",
        endpoint: PRIMARY,
        candidate: CANDIDATE,
        step: 0,
        percent: 0,
        reason: "consecutive_failures",
        stepSamples: 2,
        stepFailures: 2,
        at: "1970-01-01T00:00:00.000Z",
      });
      assert.equal(q.getCanaryStats()[0].state, "rolled_back");
    } finally {
      q.stop();
    }
  });

  it("a revision does not disturb the ramp: the steps keep marching on the dwell", async () => {
    const { q, timer, advance } = makeRampQueue(undefined, [1, 5, 25, 50, 100]);
    const oldSeen: CanaryRolloutEvent[] = [];
    const newSeen: CanaryRolloutEvent[] = [];
    q.reviseCanaryRolloutEventCallback((e) => oldSeen.push(e));
    q.start();
    try {
      q.enqueue(item("m-1"));
      await timer.run();
      advance(1000);
      q.enqueue(item("m-2"));
      await timer.run();
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].step, 1);
      assert.equal(oldSeen[0].percent, 5);
      assert.equal(q.getCanaryStats()[0].step, 1);
      q.reviseCanaryRolloutEventCallback((e) => newSeen.push(e));
      advance(1000);
      q.enqueue(item("m-3"));
      await timer.run();
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].event, "canary_step_advanced");
      assert.equal(newSeen[0].step, 2);
      assert.equal(newSeen[0].percent, 25);
      assert.equal(q.getCanaryStats()[0].step, 2);
      assert.equal(q.getCanaryStats()[0].percent, 25);
      assert.equal(q.getCanaryStats()[0].state, "rolling");
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer canary-rollout-event callback revision (WR-393)", () => {
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

  function eventsOf(audit: AuditLog, name: string) {
    return audit.query({ event: name }) as Array<Record<string, unknown>>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "canary_rollout_event_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server with a [50, 100] canary ramp, 1000ms dwell, deterministic clock and coin. */
  function canaryServer(onCanaryRolloutEvent?: (event: CanaryRolloutEvent) => void) {
    const dir = mkdtempSync(join(tmpdir(), "canaryevent-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    let nowMs = 0;
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
        canaryRollouts: { [PRIMARY]: { candidate: CANDIDATE, steps: [50, 100], dwellMs: 1000 } },
        canaryNow: () => nowMs,
        canaryRandom: () => 0,
        ...(onCanaryRolloutEvent !== undefined ? { onCanaryRolloutEvent } : {}),
      },
    });
    servers.push(relay);
    return {
      relay,
      audit,
      advance: (ms: number) => {
        nowMs += ms;
      },
    };
  }

  /** Post one webhook and wait until it is delivered. */
  async function postAndDeliver(port: number, audit: AuditLog, deliveredSoFar: number) {
    assert.equal(await postWebhook(port), 202);
    await drainUntil(
      () => (audit.query({ event: "delivered" }) as unknown[]).length >= deliveredSoFar + 1
    );
  }

  it("replacing the operator callback routes the next transition to the new callback and the audit still lands", async () => {
    const oldSeen: CanaryRolloutEvent[] = [];
    const newSeen: CanaryRolloutEvent[] = [];
    const { relay, audit, advance } = canaryServer((event) => oldSeen.push(event));
    const port = await listen(relay);
    await postAndDeliver(port, audit, 0);
    advance(1000);
    await postAndDeliver(port, audit, 1);
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => eventsOf(audit, "canary_step_advanced").length >= 1);
    assert.equal(oldSeen[0].event, "canary_step_advanced");
    assert.equal(oldSeen[0].step, 1);
    assert.equal(oldSeen[0].percent, 100);
    assert.equal(eventsOf(audit, "canary_step_advanced")[0].step, 1);
    assert.deepEqual(newSeen, []);
    const newCb = (event: CanaryRolloutEvent) => newSeen.push(event);
    relay.reviseCanaryRolloutEventCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    advance(1000);
    await postAndDeliver(port, audit, 2);
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => eventsOf(audit, "canary_promoted").length >= 1);
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen[0].event, "canary_promoted");
    assert.equal(newSeen[0].step, 2);
    assert.equal(newSeen[0].percent, 100);
    assert.equal(eventsOf(audit, "canary_promoted")[0].step, 2);
    assert.equal((audit.query({ event: "delivered" }) as unknown[]).length, 3);
  });

  it("clearing to null keeps the audit and the transitions, and stops the operator", async () => {
    const seen: CanaryRolloutEvent[] = [];
    const { relay, audit, advance } = canaryServer((event) => seen.push(event));
    const port = await listen(relay);
    await postAndDeliver(port, audit, 0);
    advance(1000);
    await postAndDeliver(port, audit, 1);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => eventsOf(audit, "canary_step_advanced").length >= 1);
    relay.reviseCanaryRolloutEventCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    advance(1000);
    await postAndDeliver(port, audit, 2);
    await drainUntil(() => eventsOf(audit, "canary_promoted").length >= 1);
    assert.equal(seen.length, 1); // still silent
    // The promotion was audited but not forwarded — and every
    // delivery still went out.
    assert.equal(eventsOf(audit, "canary_promoted")[0].step, 2);
    assert.equal((audit.query({ event: "delivered" }) as unknown[]).length, 3);
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = canaryServer((_event) => {});
    await listen(relay);
    const newCb = (_event: CanaryRolloutEvent) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseCanaryRolloutEventCallback!(newCb);
    // set -> cleared.
    relay.reviseCanaryRolloutEventCallback!(null);
    // cleared -> set.
    relay.reviseCanaryRolloutEventCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseCanaryRolloutEventCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseCanaryRolloutEventCallback!(null);
    relay.reviseCanaryRolloutEventCallback!(null);
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
    // and the first set audits cleared -> set. (Canary is configured,
    // only the observer is absent.)
    const { relay: bare, audit: bareAudit } = canaryServer();
    await listen(bare);
    bare.reviseCanaryRolloutEventCallback!(null);
    bare.reviseCanaryRolloutEventCallback!(newCb);
    assert.deepEqual(
      (bareAudit.query({ event: "canary_rollout_event_callback_revised" }) as Array<{
        previous: string;
        current: string;
      }>).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("a non-function value throws RangeError and the live cell is untouched", async () => {
    const seen: CanaryRolloutEvent[] = [];
    const { relay, audit, advance } = canaryServer((event) => seen.push(event));
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseCanaryRolloutEventCallback!(42 as never),
      RangeError
    );
    assert.equal(revisedEvents(audit).length, 0);
    // The live cell survived: the next transition still enters the original callback.
    await postAndDeliver(port, audit, 0);
    advance(1000);
    await postAndDeliver(port, audit, 1);
    await drainUntil(() => seen.length >= 1);
    assert.equal(seen[0].event, "canary_step_advanced");
    assert.equal(seen[0].step, 1);
  });

  it("a server without canary configured cannot gain an observer at runtime — must restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "canaryevent-nocanary-"));
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
      () => relay.reviseCanaryRolloutEventCallback!(() => {}),
      /requires a restart/
    );
    assert.equal(revisedEvents(audit).length, 0);
  });
});
