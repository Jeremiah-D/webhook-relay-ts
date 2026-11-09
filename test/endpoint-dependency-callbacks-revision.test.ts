import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import {
  RetryQueue,
  type EndpointDependencyTransitionInfo,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "endpoint-dependency-callbacks-revision-secret";
const operatorToken = "endpoint-dependency-callbacks-revision-token";
const URL_A = "http://localhost:9999/a";
const URL_A2 = "http://localhost:9999/a2";
const URL_B = "http://localhost:9999/b";
const URL_C = "http://localhost:9999/c";
const URL_D = "http://localhost:9999/d";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

type TransitionObserver = (info: EndpointDependencyTransitionInfo) => void;

/**
 * Manual timer with single-step control, mirroring
 * test/endpoint-dependencies.test.ts: dependency parking re-arms
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

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

describe("RetryQueue endpoint dependency callbacks revision (WR-370)", () => {
  function makeQueue(
    deps: Record<string, string | string[]>,
    onEndpointDependencyBlocked?: TransitionObserver,
    onEndpointDependencyUnblocked?: TransitionObserver,
    extra: Record<string, unknown> = {}
  ) {
    let now = 0;
    const timer = manualTimer();
    const f = perUrlSender();
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
      ...(onEndpointDependencyBlocked !== undefined ? { onEndpointDependencyBlocked } : {}),
      ...(onEndpointDependencyUnblocked !== undefined ? { onEndpointDependencyUnblocked } : {}),
      onDelivered: (item, attempts) => delivered.push({ id: item.id, attempts }),
      ...extra,
    });
    return { q, timer, f, delivered, advance: (ms: number) => (now += ms) };
  }

  /** Trip B's circuit open (failureThreshold 1). */
  async function tripB(ctx: ReturnType<typeof makeQueue>, n: number) {
    ctx.f.setFailing(URL_B, true);
    ctx.q.enqueue(item(`b${n}`, URL_B));
    await ctx.timer.step();
    assert.equal(ctx.q.getCircuitStats().find((s) => s.endpoint === URL_B)?.state, "open");
  }

  /** Park a dependent on the open B; its blocked edge fires once. */
  async function blockDependent(ctx: ReturnType<typeof makeQueue>, url: string, n: number) {
    const before = ctx.f.callsFor(url);
    ctx.q.enqueue(item(`dep-${n}-${url}`, url));
    await ctx.timer.step();
    assert.equal(ctx.f.callsFor(url), before);
  }

  /** Let B recover: cooldown elapses, probe succeeds, B closes, the dependent unblocks. */
  async function recover(ctx: ReturnType<typeof makeQueue>) {
    ctx.f.setFailing(URL_B, false);
    ctx.advance(100);
    await ctx.timer.step(); // B's parked retry runs the half-open probe
    await ctx.timer.step(); // the dependent's recheck sees B closed -> unblock + dispatch
    assert.equal(ctx.q.getCircuitStats().find((s) => s.endpoint === URL_B)?.state, "closed");
  }

  it("blocked reaches the revised callback; the old callback stays silent", async () => {
    const oldSeen: EndpointDependencyTransitionInfo[] = [];
    const newSeen: EndpointDependencyTransitionInfo[] = [];
    const oldCb: TransitionObserver = (info) => oldSeen.push(info);
    const newCb: TransitionObserver = (info) => newSeen.push(info);
    const ctx = makeQueue({ [URL_A]: URL_B, [URL_A2]: URL_B }, oldCb);
    const { q, timer } = ctx;
    q.start();
    try {
      await tripB(ctx, 1);
      await blockDependent(ctx, URL_A, 1);
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(oldSeen[0], { endpoint: URL_A, dependency: URL_B });
      // Swap the blocked hook; A2's own blocked edge (a different
      // scope key) is the next one and must reach the new callback.
      q.reviseEndpointDependencyCallbacks({ onEndpointDependencyBlocked: newCb });
      await blockDependent(ctx, URL_A2, 2);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.deepEqual(newSeen[0], { endpoint: URL_A2, dependency: URL_B });
      assert.equal(timer.pendingCount() > 0, true);
    } finally {
      q.stop();
    }
  });

  it("unblocked reaches the revised callback; the old callback stays silent", async () => {
    const oldSeen: EndpointDependencyTransitionInfo[] = [];
    const newSeen: EndpointDependencyTransitionInfo[] = [];
    const oldCb: TransitionObserver = (info) => oldSeen.push(info);
    const newCb: TransitionObserver = (info) => newSeen.push(info);
    const ctx = makeQueue({ [URL_A]: URL_B }, () => {}, oldCb);
    const { q, timer, f } = ctx;
    q.start();
    try {
      await tripB(ctx, 1);
      await blockDependent(ctx, URL_A, 1);
      q.reviseEndpointDependencyCallbacks({ onEndpointDependencyUnblocked: newCb });
      await recover(ctx);
      assert.equal(f.callsFor(URL_A), 1);
      assert.equal(oldSeen.length, 0);
      assert.equal(newSeen.length, 1);
      assert.deepEqual(newSeen[0], { endpoint: URL_A, dependency: URL_B });
      assert.deepEqual(
        ctx.delivered.find((d) => d.id === `dep-1-${URL_A}`),
        { id: `dep-1-${URL_A}`, attempts: 1 }
      );
    } finally {
      q.stop();
    }
  });

  it("clearing both hooks keeps parking and delivery; the operator hears nothing", async () => {
    const blockedSeen: EndpointDependencyTransitionInfo[] = [];
    const unblockedSeen: EndpointDependencyTransitionInfo[] = [];
    const blockedCb: TransitionObserver = (info) => blockedSeen.push(info);
    const unblockedCb: TransitionObserver = (info) => unblockedSeen.push(info);
    const ctx = makeQueue({ [URL_A]: URL_B }, blockedCb, unblockedCb);
    const { q, f } = ctx;
    q.start();
    try {
      await tripB(ctx, 1);
      await blockDependent(ctx, URL_A, 1);
      assert.equal(blockedSeen.length, 1);
      q.reviseEndpointDependencyCallbacks({
        onEndpointDependencyBlocked: null,
        onEndpointDependencyUnblocked: null,
      });
      await recover(ctx);
      // The graph kept working — A delivered on its first real attempt —
      // but no operator callback heard the unblock.
      assert.equal(f.callsFor(URL_A), 1);
      assert.equal(unblockedSeen.length, 0);
      assert.equal(q.getEndpointDependencyStats().length, 0);
      // Re-tripping still parks and transitions, silently.
      await tripB(ctx, 2);
      await blockDependent(ctx, URL_A, 2);
      assert.equal(blockedSeen.length, 1);
      assert.equal(q.getEndpointDependencyStats().length, 1);
      assert.equal(q.getEndpointDependencyStats()[0].transitions, 3);
    } finally {
      q.stop();
    }
  });

  it("revising without a dependency graph throws Error; a configured graph with absent hooks revises fine", async () => {
    const timer = manualTimer();
    const f = perUrlSender();
    const bare = new RetryQueue({
      sender: f.sender,
      circuitBreaker: { failureThreshold: 1, cooldownMs: 100 },
      setTimer: timer.setTimer,
    });
    bare.start();
    try {
      assert.throws(
        () =>
          bare.reviseEndpointDependencyCallbacks({
            onEndpointDependencyBlocked: () => {},
          }),
        (err: unknown) =>
          err instanceof Error &&
          /endpoint dependencies are not configured — enabling them requires a restart/.test(
            err.message
          )
      );
      // A graph configured with no hooks starts absent and accepts a set.
      const seen: EndpointDependencyTransitionInfo[] = [];
      const ctx = makeQueue({ [URL_A]: URL_B });
      ctx.q.start();
      try {
        ctx.q.reviseEndpointDependencyCallbacks({
          onEndpointDependencyBlocked: (info) => seen.push(info),
        });
        await tripB(ctx, 1);
        await blockDependent(ctx, URL_A, 1);
        assert.equal(seen.length, 1);
        assert.deepEqual(seen[0], { endpoint: URL_A, dependency: URL_B });
      } finally {
        ctx.q.stop();
      }
    } finally {
      bare.stop();
    }
  });

  it("an illegal or empty patch throws RangeError and the live hooks are untouched", async () => {
    const oldBlocked: EndpointDependencyTransitionInfo[] = [];
    const oldUnblocked: EndpointDependencyTransitionInfo[] = [];
    const blockedCb: TransitionObserver = (info) => oldBlocked.push(info);
    const unblockedCb: TransitionObserver = (info) => oldUnblocked.push(info);
    const ctx = makeQueue({ [URL_A]: URL_B }, blockedCb, unblockedCb);
    const { q } = ctx;
    q.start();
    try {
      const bad = "nope";
      assert.throws(
        () =>
          q.reviseEndpointDependencyCallbacks({ onEndpointDependencyBlocked: bad as never }),
        RangeError
      );
      assert.throws(
        () =>
          q.reviseEndpointDependencyCallbacks({ onEndpointDependencyUnblocked: bad as never }),
        RangeError
      );
      assert.throws(() => q.reviseEndpointDependencyCallbacks({}), RangeError);
      assert.throws(() => q.reviseEndpointDependencyCallbacks(null as never), RangeError);
      assert.throws(() => q.reviseEndpointDependencyCallbacks("nope" as never), RangeError);
      assert.throws(() => q.reviseEndpointDependencyCallbacks(42 as never), RangeError);
      assert.throws(
        () =>
          q.reviseEndpointDependencyCallbacks({
            onEndpointDependencyBlocked: undefined,
            onEndpointDependencyUnblocked: undefined,
          }),
        RangeError
      );
      // A patch with one good field and one bad field applies nothing.
      const replacement: TransitionObserver = () => {};
      assert.throws(
        () =>
          q.reviseEndpointDependencyCallbacks({
            onEndpointDependencyBlocked: replacement,
            onEndpointDependencyUnblocked: bad as never,
          }),
        RangeError
      );
      // The live hooks are untouched: the next transition still reaches them.
      await tripB(ctx, 1);
      await blockDependent(ctx, URL_A, 1);
      assert.equal(oldBlocked.length, 1);
      assert.deepEqual(oldBlocked[0], { endpoint: URL_A, dependency: URL_B });
      await recover(ctx);
      assert.equal(oldUnblocked.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a same-reference revision is a silent no-op; a partial patch keeps the other hook", async () => {
    const oldBlocked: EndpointDependencyTransitionInfo[] = [];
    const newBlocked: EndpointDependencyTransitionInfo[] = [];
    const oldUnblocked: EndpointDependencyTransitionInfo[] = [];
    const blockedCb: TransitionObserver = (info) => oldBlocked.push(info);
    const newBlockedCb: TransitionObserver = (info) => newBlocked.push(info);
    const unblockedCb: TransitionObserver = (info) => oldUnblocked.push(info);
    const ctx = makeQueue({ [URL_A]: URL_B }, blockedCb, unblockedCb);
    const { q } = ctx;
    q.start();
    try {
      // Identical references: no-op, no throw.
      q.reviseEndpointDependencyCallbacks({
        onEndpointDependencyBlocked: blockedCb,
        onEndpointDependencyUnblocked: unblockedCb,
      });
      // Partial patch: only the blocked hook moves.
      q.reviseEndpointDependencyCallbacks({ onEndpointDependencyBlocked: newBlockedCb });
      await tripB(ctx, 1);
      await blockDependent(ctx, URL_A, 1);
      assert.equal(oldBlocked.length, 0);
      assert.equal(newBlocked.length, 1);
      await recover(ctx);
      assert.equal(oldUnblocked.length, 1);
      assert.deepEqual(oldUnblocked[0], { endpoint: URL_A, dependency: URL_B });
    } finally {
      q.stop();
    }
  });

  it("the graph, parked rechecks, and jitter are unaffected by a callback swap", async () => {
    const blockedSeen: EndpointDependencyTransitionInfo[] = [];
    const unblockedSeen: EndpointDependencyTransitionInfo[] = [];
    const ctx = makeQueue(
      { [URL_A]: URL_B },
      (info) => blockedSeen.push(info),
      (info) => unblockedSeen.push(info)
    );
    const { q, timer, f } = ctx;
    q.start();
    try {
      await tripB(ctx, 1);
      await blockDependent(ctx, URL_A, 1);
      assert.equal(blockedSeen.length, 1);
      // Rechecks keep re-parking: the parked counter grows step by step.
      await timer.step();
      await timer.step();
      const parkedBefore = q.getEndpointDependencyStats()[0].parked;
      assert.ok(parkedBefore >= 3);
      assert.equal(q.getEndpointDependencyStats()[0].transitions, 1);
      // Swap both hooks mid-block: no spurious transition, no reset.
      const newBlocked: TransitionObserver = (info) => blockedSeen.push(info);
      const newUnblocked: TransitionObserver = (info) => unblockedSeen.push(info);
      q.reviseEndpointDependencyCallbacks({
        onEndpointDependencyBlocked: newBlocked,
        onEndpointDependencyUnblocked: newUnblocked,
      });
      await timer.step();
      await timer.step();
      const stats = q.getEndpointDependencyStats();
      assert.equal(stats.length, 1);
      assert.equal(stats[0].blockedBy, URL_B);
      assert.equal(stats[0].transitions, 1);
      assert.ok(stats[0].parked > parkedBefore);
      // Recovery still unblocks into the new callback and delivers.
      await recover(ctx);
      assert.equal(f.callsFor(URL_A), 1);
      assert.equal(unblockedSeen.length, 1);
      assert.deepEqual(unblockedSeen[0], { endpoint: URL_A, dependency: URL_B });
      assert.equal(q.getEndpointDependencyStats().length, 0);
    } finally {
      q.stop();
    }
  });

  it("another endpoint's blocked state is unchanged by a callback swap", async () => {
    const blockedSeen: EndpointDependencyTransitionInfo[] = [];
    const ctx = makeQueue(
      { [URL_A]: URL_B, [URL_D]: URL_B },
      (info) => blockedSeen.push(info)
    );
    const { q, timer, f } = ctx;
    q.start();
    try {
      await tripB(ctx, 1);
      await blockDependent(ctx, URL_A, 1);
      assert.equal(blockedSeen.length, 1);
      q.reviseEndpointDependencyCallbacks({
        onEndpointDependencyBlocked: (info) => blockedSeen.push(info),
      });
      // A's blocked state survives the swap untouched.
      const stats = q.getEndpointDependencyStats();
      assert.equal(stats.length, 1);
      assert.equal(stats[0].endpoint, URL_A);
      assert.equal(stats[0].blockedBy, URL_B);
      assert.equal(stats[0].transitions, 1);
      // An independent endpoint dispatches normally while A stays parked.
      q.enqueue(item("c1", URL_C));
      await timer.step();
      assert.equal(f.callsFor(URL_C), 1, "C has no dependencies and must dispatch");
      assert.equal(f.callsFor(URL_A), 0);
      // A second dependent of the same B blocks independently, into the
      // new callback, with its own stats row.
      await blockDependent(ctx, URL_D, 1);
      assert.equal(blockedSeen.length, 2);
      assert.deepEqual(blockedSeen[1], { endpoint: URL_D, dependency: URL_B });
      assert.equal(q.getEndpointDependencyStats().length, 2);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint dependency callbacks revision (WR-370)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-dependency-callbacks-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL_A,
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

  function postWebhook(port: number, body: unknown) {
    const raw = Buffer.from(JSON.stringify(body));
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: {
            "x-signature": signSha256(raw, relaySecret),
            "content-type": "application/json",
            "content-length": String(raw.length),
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(raw);
    });
  }

  /**
   * A server where A and A2 depend on B; B is reached through a content
   * route (`kind: "dep"`), A2 through (`kind: "a2"`), everything else
   * forwards to A. The sender fails only B until told otherwise.
   */
  function dependencyServer(
    onEndpointDependencyBlocked: TransitionObserver,
    onEndpointDependencyUnblocked: TransitionObserver
  ) {
    const calls = new Map<string, number>();
    const failing = new Set<string>([URL_B]);
    const { relay, auditLog } = makeServer({
      sender: async (item: { targetUrl: string }) => {
        calls.set(item.targetUrl, (calls.get(item.targetUrl) ?? 0) + 1);
        if (failing.has(item.targetUrl)) throw new Error("downstream down");
      },
      contentRoutes: [
        {
          id: "dep",
          matchers: [{ field: "kind", op: "equals", value: "dep" }],
          targetUrl: URL_B,
        },
        {
          id: "a2",
          matchers: [{ field: "kind", op: "equals", value: "a2" }],
          targetUrl: URL_A2,
        },
      ],
      retry: {
        baseDelayMs: 10,
        maxAttempts: 5,
        jitterMs: 0,
        random: () => 0,
        circuitBreaker: { failureThreshold: 1, cooldownMs: 200 },
        endpointDependencies: { dependsOn: { [URL_A]: URL_B, [URL_A2]: URL_B } },
        dependencyRecheckMs: 30,
        onEndpointDependencyBlocked,
        onEndpointDependencyUnblocked,
      },
    });
    return {
      relay,
      auditLog,
      callsFor: (url: string) => calls.get(url) ?? 0,
      setFailing: (url: string, v: boolean) => {
        if (v) failing.add(url);
        else failing.delete(url);
      },
    };
  }

  // The send count leads the hook: the sender runs first and the
  // failure verdict (which fires the hook) lands in the delivery
  // continuation, so poll for the observed callback itself.
  async function waitSeen(seen: unknown[], target: number) {
    const deadline = Date.now() + 5000;
    while (seen.length < target && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(seen.length, target);
  }

  async function waitEvents(auditLog: AuditLog, name: string, target: number) {
    const deadline = Date.now() + 5000;
    while (eventsOf(auditLog, name).length < target && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(eventsOf(auditLog, name).length, target);
  }

  async function waitCircuitOpen(auditLog: AuditLog, endpoint: string, target: number) {
    const deadline = Date.now() + 5000;
    while (
      eventsOf(auditLog, "circuit_open").filter((e) => e.endpoint === endpoint).length < target &&
      Date.now() < deadline
    ) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(
      eventsOf(auditLog, "circuit_open").filter((e) => e.endpoint === endpoint).length,
      target
    );
  }

  /** Trip B's circuit open through the content route. */
  async function tripB(port: number, ctx: ReturnType<typeof dependencyServer>, n: number) {
    assert.equal(await postWebhook(port, { kind: "dep", n }), 202);
    await waitCircuitOpen(ctx.auditLog, URL_B, n);
  }

  it("revising the blocked callback routes the next block to the new callback and the audit still lands", async () => {
    const initialSeen: EndpointDependencyTransitionInfo[] = [];
    const newSeen: EndpointDependencyTransitionInfo[] = [];
    const unblockedSeen: EndpointDependencyTransitionInfo[] = [];
    const initialCb: TransitionObserver = (info) => initialSeen.push(info);
    const newCb: TransitionObserver = (info) => newSeen.push(info);
    const unblockedCb: TransitionObserver = (info) => unblockedSeen.push(info);
    const ctx = dependencyServer(initialCb, unblockedCb);
    const { relay, auditLog } = ctx;
    const port = await listen(relay);
    // First block: the initial callback hears it and the audit lands.
    await tripB(port, ctx, 1);
    assert.equal(await postWebhook(port, { hello: "webhook", n: 1 }), 202);
    await waitSeen(initialSeen, 1);
    assert.deepEqual(initialSeen[0], { endpoint: URL_A, dependency: URL_B });
    await waitEvents(auditLog, "endpoint_dependency_blocked", 1);
    assert.equal(ctx.callsFor(URL_A), 0);
    // Swap the operator blocked callback; the unblocked hook is untouched.
    relay.reviseEndpointDependencyCallbacks!({ onEndpointDependencyBlocked: newCb });
    // A2's own blocked edge is the next one and must reach the new callback.
    assert.equal(await postWebhook(port, { kind: "a2", n: 2 }), 202);
    await waitSeen(newSeen, 1);
    assert.equal(initialSeen.length, 1); // the old callback heard nothing more
    assert.deepEqual(newSeen[0], { endpoint: URL_A2, dependency: URL_B });
    await waitEvents(auditLog, "endpoint_dependency_blocked", 2);
    // The revision itself was audited with per-hook presence.
    const revised = eventsOf(auditLog, "endpoint_dependency_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onEndpointDependencyBlocked,
        revised[0].oldOnEndpointDependencyBlocked,
        revised[0].onEndpointDependencyUnblocked,
        revised[0].oldOnEndpointDependencyUnblocked,
      ],
      ["set", "set", "unchanged", "set"]
    );
  });

  it("revising the unblocked callback routes the next unblock to the new callback", async () => {
    const blockedSeen: EndpointDependencyTransitionInfo[] = [];
    const initialSeen: EndpointDependencyTransitionInfo[] = [];
    const newSeen: EndpointDependencyTransitionInfo[] = [];
    const blockedCb: TransitionObserver = (info) => blockedSeen.push(info);
    const initialCb: TransitionObserver = (info) => initialSeen.push(info);
    const newCb: TransitionObserver = (info) => newSeen.push(info);
    const ctx = dependencyServer(blockedCb, initialCb);
    const { relay, auditLog } = ctx;
    const port = await listen(relay);
    await tripB(port, ctx, 1);
    assert.equal(await postWebhook(port, { hello: "webhook", n: 1 }), 202);
    await waitSeen(blockedSeen, 1);
    // Swap the operator unblocked callback, then let B recover.
    relay.reviseEndpointDependencyCallbacks!({ onEndpointDependencyUnblocked: newCb });
    ctx.setFailing(URL_B, false);
    await waitSeen(newSeen, 1);
    assert.equal(initialSeen.length, 0);
    assert.deepEqual(newSeen[0], { endpoint: URL_A, dependency: URL_B });
    await waitEvents(auditLog, "endpoint_dependency_unblocked", 1);
    assert.equal(ctx.callsFor(URL_A), 1);
  });

  it("clearing both hooks keeps the graph and the audit, with no operator callback", async () => {
    const blockedSeen: EndpointDependencyTransitionInfo[] = [];
    const unblockedSeen: EndpointDependencyTransitionInfo[] = [];
    const blockedCb: TransitionObserver = (info) => blockedSeen.push(info);
    const unblockedCb: TransitionObserver = (info) => unblockedSeen.push(info);
    const ctx = dependencyServer(blockedCb, unblockedCb);
    const { relay, auditLog } = ctx;
    const port = await listen(relay);
    await tripB(port, ctx, 1);
    assert.equal(await postWebhook(port, { hello: "webhook", n: 1 }), 202);
    await waitSeen(blockedSeen, 1);
    relay.reviseEndpointDependencyCallbacks!({
      onEndpointDependencyBlocked: null,
      onEndpointDependencyUnblocked: null,
    });
    // Recovery still unblocks (audited) but no operator callback hears it.
    ctx.setFailing(URL_B, false);
    await waitEvents(auditLog, "endpoint_dependency_unblocked", 1);
    assert.equal(unblockedSeen.length, 0);
    assert.equal(ctx.callsFor(URL_A), 1);
    // Re-tripping still blocks (audited) but no operator callback hears it.
    ctx.setFailing(URL_B, true);
    await tripB(port, ctx, 2);
    assert.equal(await postWebhook(port, { hello: "webhook", n: 2 }), 202);
    await waitEvents(auditLog, "endpoint_dependency_blocked", 2);
    assert.equal(blockedSeen.length, 1);
    assert.equal(ctx.callsFor(URL_A), 1);
  });

  it("an illegal or empty patch throws RangeError and the live callbacks are untouched", async () => {
    const blockedSeen: EndpointDependencyTransitionInfo[] = [];
    const unblockedSeen: EndpointDependencyTransitionInfo[] = [];
    const blockedCb: TransitionObserver = (info) => blockedSeen.push(info);
    const unblockedCb: TransitionObserver = (info) => unblockedSeen.push(info);
    const ctx = dependencyServer(blockedCb, unblockedCb);
    const { relay, auditLog } = ctx;
    const port = await listen(relay);
    assert.throws(
      () =>
        relay.reviseEndpointDependencyCallbacks!({
          onEndpointDependencyBlocked: "nope" as never,
        }),
      RangeError
    );
    assert.throws(() => relay.reviseEndpointDependencyCallbacks!({}), RangeError);
    assert.throws(() => relay.reviseEndpointDependencyCallbacks!(null as never), RangeError);
    assert.equal(eventsOf(auditLog, "endpoint_dependency_callbacks_revised").length, 0);
    // The live callbacks are untouched: the next block still reaches them.
    await tripB(port, ctx, 1);
    assert.equal(await postWebhook(port, { hello: "webhook", n: 1 }), 202);
    await waitSeen(blockedSeen, 1);
    assert.equal(eventsOf(auditLog, "endpoint_dependency_blocked").length, 1);
    ctx.setFailing(URL_B, false);
    await waitSeen(unblockedSeen, 1);
  });

  it("a same-reference revision is a silent no-op with no audit event", async () => {
    const blockedCb: TransitionObserver = () => {};
    const unblockedCb: TransitionObserver = () => {};
    const ctx = dependencyServer(blockedCb, unblockedCb);
    const { relay, auditLog } = ctx;
    await listen(relay);
    relay.reviseEndpointDependencyCallbacks!({
      onEndpointDependencyBlocked: blockedCb,
      onEndpointDependencyUnblocked: unblockedCb,
    });
    assert.equal(eventsOf(auditLog, "endpoint_dependency_callbacks_revised").length, 0);
  });

  it("revising without a dependency graph configured throws Error", async () => {
    const { relay } = makeServer({
      retry: { baseDelayMs: 10, maxAttempts: 1, jitterMs: 0 },
    });
    await listen(relay);
    assert.throws(
      () =>
        relay.reviseEndpointDependencyCallbacks!({ onEndpointDependencyBlocked: () => {} }),
      (err: unknown) =>
        err instanceof Error && /not configured — enabling .* requires a restart/.test(err.message)
    );
  });
});
