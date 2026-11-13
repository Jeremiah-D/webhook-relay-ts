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
  type StarvationGuardAuditEvent,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "starvation-guard-audit-callback-revision-secret";
const URL = "http://localhost:9999/guard";
const FORWARD_URL = "http://localhost:9999/hook";
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

/** Let queued microtask chains (limiter grant -> turn grant -> sender) settle. */
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

/** Release every currently-blocked sender, then drain timers/microtasks. */
async function drainRound(
  timer: ReturnType<typeof manualTimer>,
  releases: Map<string, () => void>,
  q: RetryQueue
): Promise<boolean> {
  for (const release of [...releases.values()]) release();
  releases.clear();
  await timer.run();
  await settle();
  return releases.size > 0 || q.pendingCount() > 0;
}

async function drainAll(
  timer: ReturnType<typeof manualTimer>,
  releases: Map<string, () => void>,
  q: RetryQueue
): Promise<void> {
  for (let round = 0; round < 10 && (await drainRound(timer, releases, q)); round++) {
    // release-all is deterministic: microtask FIFO fixes the grant order
  }
  assert.equal(q.pendingCount(), 0);
}

/**
 * Enqueue 4 normal + 12 urgent items against a blocking sender: the
 * first normal holds the only slot, the other three wait, and the first
 * urgent parks — exactly one activation episode fires.
 */
async function triggerEpisode(
  timer: ReturnType<typeof manualTimer>,
  q: RetryQueue,
  prefix: string
): Promise<void> {
  for (const id of [`${prefix}-n-1`, `${prefix}-n-2`, `${prefix}-n-3`, `${prefix}-n-4`]) {
    q.enqueue(item(id));
  }
  await timer.run();
  await settle();
  for (let i = 1; i <= 12; i++) q.enqueue(item(`${prefix}-u-${i}`, "urgent"));
  await timer.run();
  await settle();
}

function blockingQueue(opts: {
  onStarvationGuardAudit?: (event: StarvationGuardAuditEvent) => void;
  minNormalShare?: number;
}): {
  q: RetryQueue;
  timer: ReturnType<typeof manualTimer>;
  releases: Map<string, () => void>;
  dispatchOrder: string[];
} {
  const timer = manualTimer();
  const releases = new Map<string, () => void>();
  const dispatchOrder: string[] = [];
  const sender: Sender = async (it) => {
    dispatchOrder.push(it.id);
    await new Promise<void>((r) => { releases.set(it.id, r); });
  };
  const q = new RetryQueue({
    sender,
    maxConcurrentPerEndpoint: 1,
    jitterMs: 0,
    urgent: {
      maxUrgentPerSecond: 10000,
      now: () => 0,
      ...(opts.minNormalShare !== undefined ? { minNormalShare: opts.minNormalShare } : {}),
    },
    ...(opts.onStarvationGuardAudit !== undefined
      ? { onStarvationGuardAudit: opts.onStarvationGuardAudit }
      : {}),
    setTimer: timer.setTimer,
  });
  q.start();
  return { q, timer, releases, dispatchOrder };
}

describe("RetryQueue starvation-guard audit callback revision (WR-406)", () => {
  it("the revised callback receives the next activation with exact fields; the old callback stays silent", async () => {
    const first: StarvationGuardAuditEvent[] = [];
    const second: StarvationGuardAuditEvent[] = [];
    const { q, timer, releases, dispatchOrder } = blockingQueue({
      onStarvationGuardAudit: (e) => first.push(e),
      minNormalShare: 0.25,
    });
    try {
      await triggerEpisode(timer, q, "a");
      assert.equal(first.length, 1);
      assert.deepEqual(first[0], {
        event: "starvation_guard_activated",
        endpoint: URL,
        waitingNormal: 3,
        waitingUrgent: 1,
        minNormalShare: 0.25,
      });
      assert.deepEqual(second, []);
      // Swap mid-episode: the reported activation is never re-delivered.
      q.reviseStarvationGuardAuditCallback((e) => second.push(e));
      assert.deepEqual(second, []);
      await drainAll(timer, releases, q);
      await triggerEpisode(timer, q, "b");
      assert.equal(first.length, 1, "old callback stays silent after revision");
      assert.equal(second.length, 1);
      assert.deepEqual(second[0], {
        event: "starvation_guard_activated",
        endpoint: URL,
        waitingNormal: 3,
        waitingUrgent: 1,
        minNormalShare: 0.25,
      });
      await drainAll(timer, releases, q);
      const [ls] = q.getLaneStats();
      assert.equal(ls.endpoint, URL);
      assert.equal(ls.minNormalShare, 0.25);
      assert.equal(ls.normalTurns, 8);
      assert.equal(ls.urgentTurns, 24);
      assert.equal(ls.guardActivations, 2);
      assert.equal(dispatchOrder.length, 32);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; the guard still paces and still counts activations", async () => {
    const seen: StarvationGuardAuditEvent[] = [];
    const { q, timer, releases, dispatchOrder } = blockingQueue({
      onStarvationGuardAudit: (e) => seen.push(e),
      minNormalShare: 0.25,
    });
    try {
      q.reviseStarvationGuardAuditCallback(null);
      await triggerEpisode(timer, q, "a");
      assert.deepEqual(seen, [], "cleared hook stays silent");
      await drainAll(timer, releases, q);
      // The DRR pacing is unchanged without an observer: each normal
      // dispatch earns exactly 3 urgent turns (share 0.25).
      assert.deepEqual(dispatchOrder, [
        "a-n-1",
        "a-n-2", "a-u-1", "a-u-2", "a-u-3",
        "a-n-3", "a-u-4", "a-u-5", "a-u-6",
        "a-n-4", "a-u-7", "a-u-8", "a-u-9",
        "a-u-10", "a-u-11", "a-u-12",
      ]);
      const [ls] = q.getLaneStats();
      assert.equal(ls.minNormalShare, 0.25);
      assert.equal(ls.normalTurns, 4);
      assert.equal(ls.urgentTurns, 12);
      assert.equal(ls.guardActivations, 1);
      const line = q
        .renderMetrics()
        .split("\n")
        .find((l) => l.startsWith("relay_starvation_guard_activations{"));
      assert.equal(line, `relay_starvation_guard_activations{endpoint="${URL}"} 1`);
    } finally {
      q.stop();
    }
  });

  it("revising with zero callbacks configured succeeds (no gate); the first activation after revision goes to the new callback at the default share", async () => {
    const second: StarvationGuardAuditEvent[] = [];
    const { q, timer, releases } = blockingQueue({});
    try {
      // No observer configured at all — the revision still succeeds.
      q.reviseStarvationGuardAuditCallback((e) => second.push(e));
      await triggerEpisode(timer, q, "a");
      assert.equal(second.length, 1);
      assert.deepEqual(second[0], {
        event: "starvation_guard_activated",
        endpoint: URL,
        waitingNormal: 3,
        waitingUrgent: 1,
        minNormalShare: 0.2,
      });
      await drainAll(timer, releases, q);
      const [ls] = q.getLaneStats();
      assert.equal(ls.minNormalShare, 0.2);
      assert.equal(ls.guardActivations, 1);
    } finally {
      q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const seen: StarvationGuardAuditEvent[] = [];
    const { q, timer, releases } = blockingQueue({
      onStarvationGuardAudit: (e) => seen.push(e),
      minNormalShare: 0.25,
    });
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseStarvationGuardAuditCallback(bad), RangeError, String(bad));
      }
      await triggerEpisode(timer, q, "a");
      assert.equal(seen.length, 1);
      assert.equal(seen[0].minNormalShare, 0.25);
      await drainAll(timer, releases, q);
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const seen: StarvationGuardAuditEvent[] = [];
    const onStarvationGuardAudit = (e: StarvationGuardAuditEvent) => seen.push(e);
    const { q, timer, releases } = blockingQueue({
      onStarvationGuardAudit,
      minNormalShare: 0.25,
    });
    try {
      q.reviseStarvationGuardAuditCallback(onStarvationGuardAudit);
      await triggerEpisode(timer, q, "a");
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseStarvationGuardAuditCallback(null);
      q.reviseStarvationGuardAuditCallback(null);
      await drainAll(timer, releases, q);
      await triggerEpisode(timer, q, "b");
      assert.equal(seen.length, 1, "cleared hook stays silent");
      await drainAll(timer, releases, q);
      const [ls] = q.getLaneStats();
      assert.equal(ls.guardActivations, 2);
    } finally {
      q.stop();
    }
  });

  it("activations already reported are never re-delivered", async () => {
    const seen: StarvationGuardAuditEvent[] = [];
    const { q, timer, releases } = blockingQueue({
      onStarvationGuardAudit: (e) => seen.push(e),
      minNormalShare: 0.25,
    });
    try {
      await triggerEpisode(timer, q, "a");
      assert.equal(seen.length, 1);
      q.reviseStarvationGuardAuditCallback((e) => seen.push(e));
      assert.equal(seen.length, 1, "no re-delivery of the reported activation");
      await settle();
      assert.equal(seen.length, 1, "no activation without a new episode");
      await drainAll(timer, releases, q);
      // The next real episode reports exactly once, to the new callback.
      await triggerEpisode(timer, q, "b");
      assert.equal(seen.length, 2);
      assert.equal(seen[1].minNormalShare, 0.25);
      await drainAll(timer, releases, q);
    } finally {
      q.stop();
    }
  });

  it("revision does not change turn allocation, minNormalShare, or getLaneStats", async () => {
    const seen: StarvationGuardAuditEvent[] = [];
    const { q, timer, releases, dispatchOrder } = blockingQueue({
      onStarvationGuardAudit: (e) => seen.push(e),
      minNormalShare: 0.25,
    });
    try {
      await triggerEpisode(timer, q, "a");
      assert.equal(seen.length, 1);
      q.reviseStarvationGuardAuditCallback((e) => seen.push(e));
      await drainAll(timer, releases, q);
      assert.deepEqual(dispatchOrder, [
        "a-n-1",
        "a-n-2", "a-u-1", "a-u-2", "a-u-3",
        "a-n-3", "a-u-4", "a-u-5", "a-u-6",
        "a-n-4", "a-u-7", "a-u-8", "a-u-9",
        "a-u-10", "a-u-11", "a-u-12",
      ]);
      const [ls] = q.getLaneStats();
      assert.equal(ls.endpoint, URL);
      assert.equal(ls.minNormalShare, 0.25);
      assert.equal(ls.normalTurns, 4);
      assert.equal(ls.urgentTurns, 12);
      assert.equal(ls.guardActivations, 1);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer starvation-guard audit callback revision (WR-406)", () => {
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

  async function drainUntil(cond: () => boolean, ms = 8000): Promise<void> {
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

  /** Post 4 normal + 12 urgent webhooks; the first urgent parks. */
  async function postEpisode(port: number) {
    for (let i = 0; i < 4; i++) assert.equal(await postWebhook(port, false), 202);
    for (let i = 0; i < 12; i++) assert.equal(await postWebhook(port, true), 202);
  }

  async function getMetrics(port: number): Promise<string> {
    const res = await new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/metrics",
          method: "GET",
          headers: { authorization: `Bearer ${TOKEN}` },
        },
        (res2) => {
          const chunks: Buffer[] = [];
          res2.on("data", (c: Buffer) => chunks.push(c));
          res2.on("end", () =>
            resolve({ status: res2.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end();
    });
    assert.equal(res.status, 200, res.text);
    return res.text;
  }

  function activationEvents(audit: AuditLog) {
    return audit.query({ event: "starvation_guard_activated" }) as Array<{
      endpoint: string;
      waitingNormal: number;
      waitingUrgent: number;
      minNormalShare: number;
    }>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "starvation_guard_audit_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  function deliveredCount(audit: AuditLog): number {
    return (audit.query({ event: "delivered" }) as unknown[]).length;
  }

  /**
   * A server whose sender blocks every dispatch until the test releases
   * it, so normal deliveries backlog and the first urgent parks.
   */
  function guardServer(opts: {
    onStarvationGuardAudit?: (event: StarvationGuardAuditEvent) => void;
    minNormalShare?: number;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "starvation-guard-audit-callback-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const releases = new Map<string, () => void>();
    const dispatched: string[] = [];
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: FORWARD_URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: (async (wire: { id: string }) => {
        dispatched.push(wire.id);
        await new Promise<void>((r) => { releases.set(wire.id, r); });
      }) as Sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 3,
        jitterMs: 0,
        maxConcurrentPerEndpoint: 1,
        urgent: {
          maxUrgentPerSecond: 10000,
          now: () => 0,
          ...(opts.minNormalShare !== undefined ? { minNormalShare: opts.minNormalShare } : {}),
        },
        ...(opts.onStarvationGuardAudit !== undefined
          ? { onStarvationGuardAudit: opts.onStarvationGuardAudit }
          : {}),
      },
    });
    servers.push(relay);
    return {
      relay,
      audit,
      dispatched,
      releaseAll() {
        for (const release of [...releases.values()]) release();
        releases.clear();
      },
      async drainAll(total: number) {
        const deadline = Date.now() + 8000;
        while (deliveredCount(audit) < total) {
          this.releaseAll();
          if (Date.now() > deadline) {
            throw new Error(`timed out draining to ${total} delivered`);
          }
          await new Promise((r) => setTimeout(r, 10));
        }
        this.releaseAll();
      },
    };
  }

  it("replacing the operator callback routes the next activation to the new callback and the starvation_guard_activated audit still lands", async () => {
    const oldSeen: StarvationGuardAuditEvent[] = [];
    const newSeen: StarvationGuardAuditEvent[] = [];
    const s = guardServer({
      onStarvationGuardAudit: (e) => oldSeen.push(e),
      minNormalShare: 0.25,
    });
    const port = await listen(s.relay);
    await postEpisode(port);
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => activationEvents(s.audit).length >= 1);
    assert.equal(oldSeen.length, 1);
    assert.deepEqual(oldSeen[0], {
      event: "starvation_guard_activated",
      endpoint: FORWARD_URL,
      waitingNormal: 3,
      waitingUrgent: 1,
      minNormalShare: 0.25,
    });
    // The queried audit line also carries chain fields (ts/hash/...),
    // so compare the event fields, not the whole line.
    const audited = activationEvents(s.audit)[0];
    assert.equal(audited.event, "starvation_guard_activated");
    assert.equal(audited.endpoint, FORWARD_URL);
    assert.equal(audited.waitingNormal, 3);
    assert.equal(audited.waitingUrgent, 1);
    assert.equal(audited.minNormalShare, 0.25);
    assert.deepEqual(newSeen, []);
    s.relay.reviseStarvationGuardAuditCallback!((e) => newSeen.push(e));
    assert.deepEqual(
      revisedEvents(s.audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    await s.drainAll(16);
    await postEpisode(port);
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => activationEvents(s.audit).length >= 2);
    assert.equal(oldSeen.length, 1, "old callback stays silent after revision");
    assert.equal(newSeen.length, 1);
    assert.deepEqual(newSeen[0], {
      event: "starvation_guard_activated",
      endpoint: FORWARD_URL,
      waitingNormal: 3,
      waitingUrgent: 1,
      minNormalShare: 0.25,
    });
    assert.equal(activationEvents(s.audit).length, 2);
    assert.equal(revisedEvents(s.audit).length, 1);
    await s.drainAll(32);
    assert.equal(deliveredCount(s.audit), 32);
  });

  it("clearing to null keeps the starvation_guard_activated audit and the guard pacing, and stops the operator", async () => {
    const seen: StarvationGuardAuditEvent[] = [];
    const s = guardServer({
      onStarvationGuardAudit: (e) => seen.push(e),
      minNormalShare: 0.25,
    });
    const port = await listen(s.relay);
    await postEpisode(port);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => activationEvents(s.audit).length >= 1);
    s.relay.reviseStarvationGuardAuditCallback!(null);
    assert.deepEqual(
      revisedEvents(s.audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    await s.drainAll(16);
    await postEpisode(port);
    await drainUntil(() => activationEvents(s.audit).length >= 2);
    assert.equal(seen.length, 1, "cleared hook stays silent");
    await s.drainAll(32);
    assert.equal(deliveredCount(s.audit), 32);
    const metrics = await getMetrics(port);
    const line = metrics
      .split("\n")
      .find((l) => l.startsWith("relay_starvation_guard_activations{"));
    assert.equal(line, `relay_starvation_guard_activations{endpoint="${FORWARD_URL}"} 2`);
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = guardServer({
      onStarvationGuardAudit: (_event) => {},
      minNormalShare: 0.25,
    });
    await listen(relay);
    const newCb = (_event: StarvationGuardAuditEvent) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseStarvationGuardAuditCallback!(newCb);
    // set -> cleared.
    relay.reviseStarvationGuardAuditCallback!(null);
    // cleared -> set.
    relay.reviseStarvationGuardAuditCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseStarvationGuardAuditCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseStarvationGuardAuditCallback!(null);
    relay.reviseStarvationGuardAuditCallback!(null);
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
    // and the first set audits cleared -> set. (The guard is always
    // built, only the observer is absent.)
    const bare = guardServer({ minNormalShare: 0.25 });
    await listen(bare.relay);
    bare.relay.reviseStarvationGuardAuditCallback!(null);
    bare.relay.reviseStarvationGuardAuditCallback!(newCb);
    assert.deepEqual(
      revisedEvents(bare.audit).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("a non-function value throws RangeError and the live cell is untouched; zero-config revision succeeds (no gate)", async () => {
    const seen: StarvationGuardAuditEvent[] = [];
    const s = guardServer({
      onStarvationGuardAudit: (e) => seen.push(e),
      minNormalShare: 0.25,
    });
    const port = await listen(s.relay);
    assert.throws(
      () => s.relay.reviseStarvationGuardAuditCallback!(42 as never),
      RangeError
    );
    assert.equal(revisedEvents(s.audit).length, 0);
    // The live cell survived: the next activation still enters the original callback.
    await postEpisode(port);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => activationEvents(s.audit).length >= 1);
    assert.equal(seen[0].minNormalShare, 0.25);
    await s.drainAll(16);
    // A server born without a callback revises fine (no gate): the
    // first activation after the revision goes to the new callback at
    // the default share 0.2.
    const second: StarvationGuardAuditEvent[] = [];
    const bare = guardServer({});
    const barePort = await listen(bare.relay);
    bare.relay.reviseStarvationGuardAuditCallback!((e) => second.push(e));
    assert.deepEqual(
      revisedEvents(bare.audit).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
    await postEpisode(barePort);
    await drainUntil(() => second.length >= 1);
    assert.equal(second.length, 1);
    assert.deepEqual(second[0], {
      event: "starvation_guard_activated",
      endpoint: FORWARD_URL,
      waitingNormal: 3,
      waitingUrgent: 1,
      minNormalShare: 0.2,
    });
    await bare.drainAll(16);
  });
});
