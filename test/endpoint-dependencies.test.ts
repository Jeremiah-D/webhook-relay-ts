import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  type Sender,
  type EndpointDependencyTransitionInfo,
} from "../src/retry.ts";
import { EndpointDependencyGraph } from "../src/endpoint-dependencies.ts";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";
const URL_C = "http://localhost:9999/c";
const URL_D = "http://localhost:9999/d";

/**
 * Manual timer with single-step control: dependency parking re-arms
 * timers, so the tests advance one wave at a time instead of draining
 * everything.
 */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    pendingCount: () => pending.length,
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    },
  };
}

/** Fake sender with per-URL failure control and per-URL call counts. */
function perUrlSender() {
  const calls = new Map<string, number>();
  const failing = new Set<string>();
  const sender: Sender = async (item) => {
    calls.set(item.targetUrl, (calls.get(item.targetUrl) ?? 0) + 1);
    if (failing.has(item.targetUrl)) throw new Error("downstream down");
  };
  return {
    sender,
    callsFor: (url: string) => calls.get(url) ?? 0,
    setFailing: (url: string, v: boolean) => {
      if (v) failing.add(url);
      else failing.delete(url);
    },
  };
}

function makeQueue(deps: Record<string, string | string[]>) {
  let now = 0;
  const timer = manualTimer();
  const f = perUrlSender();
  const blocked: EndpointDependencyTransitionInfo[] = [];
  const unblocked: EndpointDependencyTransitionInfo[] = [];
  const delivered: Array<{ id: string; attempts: number }> = [];
  const q = new RetryQueue({
    sender: f.sender,
    baseDelayMs: 10,
    maxAttempts: 5,
    jitterMs: 0,
    random: () => 0, // deterministic parking delay
    setTimer: timer.setTimer,
    circuitBreaker: { failureThreshold: 1, cooldownMs: 100, nowMs: () => now },
    endpointDependencies: { dependsOn: deps },
    dependencyRecheckMs: 30,
    onEndpointDependencyBlocked: (info) => blocked.push(info),
    onEndpointDependencyUnblocked: (info) => unblocked.push(info),
    onDelivered: (item, attempts) => delivered.push({ id: item.id, attempts }),
  });
  return { q, timer, f, blocked, unblocked, delivered, advance: (ms: number) => (now += ms) };
}

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

describe("EndpointDependencyGraph", () => {
  it("accepts a single string and arrays, deduplicating", () => {
    const g = new EndpointDependencyGraph({ [URL_A]: URL_B, [URL_B]: [URL_C, URL_C, URL_D] });
    assert.deepEqual(g.dependenciesOf(URL_A), [URL_B]);
    assert.deepEqual(g.dependenciesOf(URL_B), [URL_C, URL_D]);
    assert.deepEqual(g.dependenciesOf(URL_C), []);
    assert.ok(g.hasDependencies(URL_A));
    assert.ok(!g.hasDependencies(URL_C));
    assert.deepEqual(g.configuredEndpoints().sort(), [URL_A, URL_B].sort());
  });

  it("walks transitive dependencies depth-first, deduplicated", () => {
    const g = new EndpointDependencyGraph({ [URL_A]: [URL_B, URL_C], [URL_B]: [URL_C, URL_D] });
    assert.deepEqual(g.allDependencies(URL_A), [URL_B, URL_C, URL_D]);
  });

  it("rejects self-dependency with RangeError", () => {
    assert.throws(() => new EndpointDependencyGraph({ [URL_A]: URL_A }), RangeError);
    assert.throws(() => new EndpointDependencyGraph({ [URL_A]: [URL_B, URL_A] }), RangeError);
  });

  it("rejects direct and indirect cycles with RangeError naming the cycle", () => {
    assert.throws(
      () => new EndpointDependencyGraph({ [URL_A]: URL_B, [URL_B]: URL_A }),
      /cycle: .* -> .*/
    );
    assert.throws(
      () =>
        new EndpointDependencyGraph({
          [URL_A]: URL_B,
          [URL_B]: URL_C,
          [URL_C]: URL_A,
        }),
      RangeError
    );
  });

  it("rejects malformed shapes", () => {
    assert.throws(() => new EndpointDependencyGraph(null as never), TypeError);
    assert.throws(() => new EndpointDependencyGraph([] as never), TypeError);
    assert.throws(() => new EndpointDependencyGraph({ [URL_A]: 42 as never }), TypeError);
    assert.throws(() => new EndpointDependencyGraph({ [URL_A]: "" }), RangeError);
    assert.throws(() => new EndpointDependencyGraph({ [URL_A]: [""] }), RangeError);
  });
});

describe("RetryQueue endpoint dependencies (WR-199)", () => {
  it("fail-fast: a dependency cycle throws RangeError at construction", () => {
    const f = perUrlSender();
    assert.throws(
      () =>
        new RetryQueue({
          sender: f.sender,
          endpointDependencies: { dependsOn: { [URL_A]: URL_B, [URL_B]: URL_A } },
        }),
      RangeError
    );
  });

  it("fail-fast: illegal dependencyRecheckMs throws RangeError at construction", () => {
    const f = perUrlSender();
    assert.throws(
      () => new RetryQueue({ sender: f.sender, dependencyRecheckMs: 0 }),
      RangeError
    );
  });

  it("parks a dependent while the dependency circuit is open; resumes on recovery", async () => {
    const { q, timer, f, blocked, unblocked, delivered, advance } = makeQueue({
      [URL_A]: URL_B,
    });
    q.start();
    try {
      // B fails once -> failureThreshold 1 trips its circuit open.
      f.setFailing(URL_B, true);
      q.enqueue(item("b1", URL_B));
      await timer.step();
      assert.equal(f.callsFor(URL_B), 1);
      assert.equal(q.getCircuitStats().find((s) => s.endpoint === URL_B)?.state, "open");

      // A depends on B: parked, never dispatched, blocked fires once.
      q.enqueue(item("a1", URL_A));
      await timer.step();
      assert.equal(f.callsFor(URL_A), 0);
      assert.equal(blocked.length, 1);
      assert.deepEqual(
        { endpoint: blocked[0].endpoint, dependency: blocked[0].dependency },
        { endpoint: URL_A, dependency: URL_B }
      );
      const stats = q.getEndpointDependencyStats();
      assert.equal(stats.length, 1);
      assert.equal(stats[0].endpoint, URL_A);
      assert.equal(stats[0].blockedBy, URL_B);
      assert.ok(stats[0].parked >= 1);
      assert.equal(stats[0].transitions, 1);

      // Still cooling: re-parked, still no dispatch, no second blocked event.
      await timer.step();
      assert.equal(f.callsFor(URL_A), 0);
      assert.equal(blocked.length, 1);

      // B recovers: cooldown elapses, probe succeeds, B closes.
      f.setFailing(URL_B, false);
      advance(100);
      await timer.step(); // B's parked retry runs the half-open probe
      await timer.step(); // A's recheck sees B closed -> unblock + dispatch
      assert.equal(q.getCircuitStats().find((s) => s.endpoint === URL_B)?.state, "closed");
      assert.equal(f.callsFor(URL_A), 1);
      assert.equal(unblocked.length, 1);
      assert.equal(unblocked[0].endpoint, URL_A);
      assert.equal(unblocked[0].dependency, URL_B);
      // No attempt was burned while parked: the delivery succeeded on
      // its first real attempt. (b1's probe also delivered, with its
      // earlier failed attempt counted — that is the dependency's own
      // retry lifecycle, not the dependent's.)
      assert.deepEqual(
        delivered.find((d) => d.id === "a1"),
        { id: "a1", attempts: 1 }
      );
      assert.equal(q.getEndpointDependencyStats().length, 0);
      assert.equal(q.getDeadLetter().length, 0);
    } finally {
      q.stop();
    }
  });

  it("an independent endpoint is unaffected by another's dependency block", async () => {
    const { q, timer, f, advance } = makeQueue({ [URL_A]: URL_B });
    q.start();
    try {
      f.setFailing(URL_B, true);
      q.enqueue(item("b1", URL_B));
      await timer.step();
      assert.equal(q.getCircuitStats().find((s) => s.endpoint === URL_B)?.state, "open");

      q.enqueue(item("c1", URL_C));
      await timer.step();
      assert.equal(f.callsFor(URL_C), 1, "C has no dependencies and must dispatch");
      assert.equal(q.getEndpointDependencyStats().length, 0);
      advance(0);
    } finally {
      q.stop();
    }
  });

  it("a transitive dependency blocks the dependent", async () => {
    const { q, timer, f, blocked } = makeQueue({ [URL_A]: URL_B, [URL_B]: URL_C });
    q.start();
    try {
      // C down -> C open. A depends on B, B depends on C: A blocked via
      // the transitive edge, naming C.
      f.setFailing(URL_C, true);
      q.enqueue(item("c1", URL_C));
      await timer.step();
      assert.equal(q.getCircuitStats().find((s) => s.endpoint === URL_C)?.state, "open");

      q.enqueue(item("a1", URL_A));
      await timer.step();
      assert.equal(f.callsFor(URL_A), 0);
      assert.equal(blocked.length, 1);
      assert.equal(blocked[0].dependency, URL_C);
    } finally {
      q.stop();
    }
  });

  it("without the option the relay behaves exactly as before", async () => {
    let now = 0;
    const timer = manualTimer();
    const f = perUrlSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      circuitBreaker: { failureThreshold: 1, cooldownMs: 100, nowMs: () => now },
    });
    q.start();
    try {
      f.setFailing(URL_B, true);
      q.enqueue(item("b1", URL_B));
      await timer.step();
      q.enqueue(item("a1", URL_A));
      await timer.step();
      assert.equal(f.callsFor(URL_A), 1, "no dependency config -> A dispatches normally");
      assert.deepEqual(q.getEndpointDependencyStats(), []);
    } finally {
      q.stop();
    }
  });
});
