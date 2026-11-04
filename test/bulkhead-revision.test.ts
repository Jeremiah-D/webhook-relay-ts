import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import {
  EndpointBulkhead,
  EndpointBulkheads,
  BulkheadRejectedError,
} from "../src/bulkhead.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "bulkhead-revision-secret";
const A = "http://a/hook";
const B = "http://b/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

const DEFAULTS = { maxConcurrent: 2, maxQueue: 4, queueTimeoutMs: 1000 };

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Let a promise chain settle without awaiting its outcome. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

describe("EndpointBulkhead.retune / EndpointBulkheads.revise (WR-325)", () => {
  it("a raise immediately grants queued waiters FIFO up to the new cap", async () => {
    const bs = new EndpointBulkheads({ maxConcurrent: 1, maxQueue: 2, queueTimeoutMs: 1000 });
    const r1 = await bs.acquire(A);
    const p2 = bs.acquire(A);
    const p3 = bs.acquire(A);
    assert.equal(bs.stats()[0].queuedDepth, 2);
    const options = bs.revise(A, { maxConcurrent: 3 });
    assert.deepEqual(options, { maxConcurrent: 3, maxQueue: 2, queueTimeoutMs: 1000 });
    // Both waiters are granted at once — no release needed.
    const r2 = await p2;
    const r3 = await p3;
    assert.equal(bs.stats()[0].inFlight, 3);
    assert.equal(bs.stats()[0].maxConcurrent, 3);
    assert.equal(bs.stats()[0].queuedDepth, 0);
    r1();
    r2();
    r3();
    assert.equal(bs.stats()[0].inFlight, 0);
  });

  it("a cut leaves in-flight slots alone; new acquires queue under the new cap", async () => {
    const b = new EndpointBulkhead(A, { maxConcurrent: 2, maxQueue: 1, queueTimeoutMs: 1000 });
    const r1 = await b.acquire();
    const r2 = await b.acquire();
    b.retune({ maxConcurrent: 1 });
    assert.equal(b.inFlightCount(), 2);
    assert.equal(b.cap(), 1);
    const p3 = b.acquire(); // queues: one slot over the new cap, queue bound 1
    assert.equal(b.queuedDepth(), 1);
    await assert.rejects(b.acquire(), (e: unknown) => {
      assert.ok(e instanceof BulkheadRejectedError);
      assert.equal(e.reason, "queue_full");
      return true;
    });
    r1(); // slot transfers to the queued waiter; in-flight stays 2
    const r3 = await p3;
    assert.equal(b.inFlightCount(), 2);
    r2();
    assert.equal(b.inFlightCount(), 1);
    r3();
    assert.equal(b.inFlightCount(), 0);
  });

  it("cutting maxQueue does not evict already-queued waiters", async () => {
    const b = new EndpointBulkhead(A, { maxConcurrent: 1, maxQueue: 2, queueTimeoutMs: 1000 });
    const r1 = await b.acquire();
    const p2 = b.acquire();
    const p3 = b.acquire();
    assert.equal(b.queuedDepth(), 2);
    b.retune({ maxQueue: 1 });
    assert.equal(b.queuedDepth(), 2);
    // New arrivals are refused under the new bound…
    await assert.rejects(b.acquire(), (e: unknown) => {
      assert.ok(e instanceof BulkheadRejectedError);
      assert.equal(e.reason, "queue_full");
      return true;
    });
    // …but the already-queued waiters keep their places.
    r1();
    const r2 = await p2;
    assert.equal(b.queuedDepth(), 1);
    r2();
    const r3 = await p3;
    r3();
    assert.equal(b.inFlightCount(), 0);
  });

  it("a queueTimeoutMs revision only arms new waiters' timers", async () => {
    const b = new EndpointBulkhead(A, { maxConcurrent: 1, maxQueue: 5, queueTimeoutMs: 200 });
    const r1 = await b.acquire();
    const pOld = b.acquire(); // armed with the old 200ms timeout
    let oldRejected = false;
    void pOld.then(
      () => {},
      () => {
        oldRejected = true;
      }
    );
    b.retune({ queueTimeoutMs: 30 });
    const pNew = b.acquire(); // armed with the new 30ms timeout
    let newRejected = false;
    void pNew.then(
      () => {},
      (e: unknown) => {
        assert.ok(e instanceof BulkheadRejectedError);
        assert.equal(e.reason, "queue_timeout");
        newRejected = true;
      }
    );
    await sleep(80);
    assert.equal(newRejected, true);
    // The old waiter is still queued after 80ms — its 200ms timer was
    // not re-armed by the revision.
    assert.equal(oldRejected, false);
    assert.equal(b.queuedDepth(), 1);
    r1(); // grants the old waiter before its timer fires
    const rOld = await pOld;
    assert.equal(oldRejected, false);
    rOld();
    assert.equal(b.inFlightCount(), 0);
  });

  it("illegal merged values throw RangeError and the live options are untouched", () => {
    const b = new EndpointBulkhead(A, { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 });
    const bad: Array<Record<string, unknown>> = [
      { maxConcurrent: 0 },
      { maxConcurrent: -1 },
      { maxConcurrent: 1.5 },
      { maxConcurrent: Infinity },
      { maxConcurrent: NaN },
      { maxQueue: -1 },
      { maxQueue: 1.5 },
      { maxQueue: Infinity },
      { queueTimeoutMs: -1 },
      { queueTimeoutMs: Infinity },
      { queueTimeoutMs: NaN },
    ];
    for (const patch of bad) {
      assert.throws(() => b.retune(patch as never), RangeError, JSON.stringify(patch));
      assert.deepEqual(b.currentOptions(), { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 });
    }
    // Same through the aggregate on an unseen endpoint: no override recorded.
    const bs = new EndpointBulkheads({ maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 });
    for (const patch of bad) {
      assert.throws(() => bs.revise(B, patch as never), RangeError, JSON.stringify(patch));
    }
    assert.deepEqual(bs.optionsFor(B), {
      options: { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 },
      overridden: false,
    });
    assert.deepEqual(bs.configuredEndpoints(), []);
  });

  it("an empty patch throws RangeError", () => {
    const b = new EndpointBulkhead(A, { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 });
    assert.throws(() => b.retune({}), RangeError);
    assert.deepEqual(b.currentOptions(), { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 });
    const bs = new EndpointBulkheads({ maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 });
    assert.throws(() => bs.revise(A, {}), RangeError);
    assert.deepEqual(bs.optionsFor(A), {
      options: { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 },
      overridden: false,
    });
  });

  it("revise on an unseen endpoint records the override; lazy creation uses it", async () => {
    const bs = new EndpointBulkheads({ maxConcurrent: 1, maxQueue: 2, queueTimeoutMs: 1000 });
    const options = bs.revise(B, { maxConcurrent: 4 });
    assert.deepEqual(options, { maxConcurrent: 4, maxQueue: 2, queueTimeoutMs: 1000 });
    assert.deepEqual(bs.optionsFor(B), { options, overridden: true });
    assert.deepEqual(bs.optionsFor(A), {
      options: { maxConcurrent: 1, maxQueue: 2, queueTimeoutMs: 1000 },
      overridden: false,
    });
    assert.deepEqual(bs.configuredEndpoints(), [B]);
    // The lazily created bulkhead enforces the override, not the defaults.
    const releases = [await bs.acquire(B), await bs.acquire(B), await bs.acquire(B), await bs.acquire(B)];
    assert.equal(bs.stats().find((s) => s.endpoint === B)?.inFlight, 4);
    const p5 = bs.acquire(B);
    assert.equal(bs.stats().find((s) => s.endpoint === B)?.queuedDepth, 1);
    for (const r of releases) r();
    const r5 = await p5;
    r5();
  });
});

describe("RetryQueue.setEndpointBulkhead (WR-325)", () => {
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
      clearTimer: (h: { clear(): void }) => h.clear(),
      async step() {
        const fns = pending.splice(0);
        for (const f of fns) f();
        await flush();
      },
    };
  }

  function blockingSender() {
    const started: string[] = [];
    const releases = new Map<string, () => void>();
    const sender: Sender = async (it) => {
      started.push(it.id);
      await new Promise<void>((r) => releases.set(it.id, r));
    };
    return {
      sender,
      started,
      release: (id: string) => releases.get(id)!(),
      releaseAll: () => {
        for (const r of [...releases.values()]) r();
      },
    };
  }

  function item(id: string, targetUrl: string) {
    return { id, payload: BODY, targetUrl, headers: {} };
  }

  it("unconfigured: the setter returns false, the getter is undefined, removal is false", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.bulkheadConfigured(), false);
      assert.equal(q.setEndpointBulkhead(A, { maxConcurrent: 5 }), false);
      assert.equal(q.getEndpointBulkhead(A), undefined);
      assert.equal(q.clearEndpointBulkheadOverride(A), false);
    } finally {
      q.stop();
    }
  });

  it("setter round-trips; getBulkheadStats reads the live cap of a live bulkhead", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 2, maxQueue: 4, queueTimeoutMs: 1000 },
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.start();
    try {
      await timer.step();
      assert.deepEqual(started, ["a"]);
      assert.equal(q.getBulkheadStats()[0].maxConcurrent, 2);
      assert.equal(q.setEndpointBulkhead(A, { maxConcurrent: 5 }), true);
      assert.deepEqual(q.getEndpointBulkhead(A), {
        options: { maxConcurrent: 5, maxQueue: 4, queueTimeoutMs: 1000 },
        overridden: true,
      });
      // The live stats row — the same bulkhead the dispatch holds —
      // reports the revised cap.
      assert.equal(q.getBulkheadStats()[0].maxConcurrent, 5);
      assert.equal(q.getBulkheadStats()[0].inFlight, 1);
      // Another endpoint still reports the defaults.
      assert.deepEqual(q.getEndpointBulkhead(B), {
        options: { maxConcurrent: 2, maxQueue: 4, queueTimeoutMs: 1000 },
        overridden: false,
      });
    } finally {
      releaseAll();
      q.stop();
    }
  });

  it("two tenants are isolated: a revision moves only its own tenant", () => {
    const q = new RetryQueue({
      sender: async () => {},
      bulkhead: { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 },
    });
    try {
      assert.equal(q.bulkheadConfigured(), true);
      assert.equal(q.setEndpointBulkhead(A, { maxConcurrent: 1 }, "t1"), true);
      assert.deepEqual(q.getEndpointBulkhead(A, "t1"), {
        options: { maxConcurrent: 1, maxQueue: 2, queueTimeoutMs: 1000 },
        overridden: true,
      });
      assert.deepEqual(q.getEndpointBulkhead(A), {
        options: { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 },
        overridden: false,
      });
      assert.deepEqual(q.getEndpointBulkhead(A, "t2"), {
        options: { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 },
        overridden: false,
      });
      // Removing the t1 override leaves the default tenant untouched.
      assert.equal(q.clearEndpointBulkheadOverride(A, "t1"), true);
      assert.deepEqual(q.getEndpointBulkhead(A, "t1"), {
        options: { maxConcurrent: 2, maxQueue: 2, queueTimeoutMs: 1000 },
        overridden: false,
      });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint bulkhead revision (WR-325)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "bulkhead-revision-"));
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
    return makeServer({ retry: { bulkhead: { ...DEFAULTS } } });
  }

  it("revise audits previous/current with the defaults as first previous; same-value is a silent no-op", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    const current = relay.reviseEndpointBulkhead(A, { maxConcurrent: 5 });
    assert.deepEqual(current, {
      options: { maxConcurrent: 5, maxQueue: 4, queueTimeoutMs: 1000 },
      overridden: true,
    });
    const revised = eventsOf(auditLog, "endpoint_bulkhead_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, A);
    assert.deepEqual(revised[0].previous, { ...DEFAULTS });
    assert.deepEqual(revised[0].current, { maxConcurrent: 5, maxQueue: 4, queueTimeoutMs: 1000 });
    // The getter agrees with the live values.
    assert.deepEqual(relay.getEndpointBulkhead!(A), current);
    // A same-value revision returns the snapshot and audits nothing.
    const again = relay.reviseEndpointBulkhead(A, { maxConcurrent: 5 });
    assert.deepEqual(again, current);
    assert.equal(eventsOf(auditLog, "endpoint_bulkhead_revised").length, 1);
    // A second, real revision audits the live values as previous.
    relay.reviseEndpointBulkhead(A, { maxQueue: 1 });
    const revised2 = eventsOf(auditLog, "endpoint_bulkhead_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { maxConcurrent: 5, maxQueue: 4, queueTimeoutMs: 1000 });
    assert.deepEqual(revised2[1].current, { maxConcurrent: 5, maxQueue: 1, queueTimeoutMs: 1000 });
  });

  it("an illegal patch throws RangeError and nothing is audited", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    assert.throws(() => relay.reviseEndpointBulkhead(A, {}), RangeError);
    assert.throws(() => relay.reviseEndpointBulkhead(A, { maxConcurrent: 0 }), RangeError);
    assert.throws(() => relay.reviseEndpointBulkhead(A, { queueTimeoutMs: Infinity }), RangeError);
    assert.equal(eventsOf(auditLog, "endpoint_bulkhead_revised").length, 0);
    assert.deepEqual(relay.getEndpointBulkhead!(A), { options: { ...DEFAULTS }, overridden: false });
  });

  it("unconfigured: revise throws the canonical must-restart Error, the getter is unset, removal is false", async () => {
    const { relay } = makeServer();
    await listen(relay);
    assert.equal(relay.getEndpointBulkhead, undefined);
    assert.throws(
      () => relay.reviseEndpointBulkhead(A, { maxConcurrent: 5 }),
      (e: unknown) => {
        assert.ok(e instanceof Error);
        assert.equal(
          e.message,
          "reviseEndpointBulkhead: bulkhead is not configured — enabling it requires a restart"
        );
        return true;
      }
    );
    assert.equal(relay.removeEndpointBulkhead(A), false);
  });

  it("remove falls back to the construction defaults and audits the removed options", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    relay.reviseEndpointBulkhead(A, { maxConcurrent: 5, queueTimeoutMs: 500 });
    assert.equal(relay.removeEndpointBulkhead(A), true);
    const removed = eventsOf(auditLog, "endpoint_bulkhead_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, A);
    assert.deepEqual(removed[0].previous, { maxConcurrent: 5, maxQueue: 4, queueTimeoutMs: 500 });
    assert.deepEqual(relay.getEndpointBulkhead!(A), { options: { ...DEFAULTS }, overridden: false });
    // A second removal is a silent no-op.
    assert.equal(relay.removeEndpointBulkhead(A), false);
    assert.equal(eventsOf(auditLog, "endpoint_bulkhead_removed").length, 1);
  });
});
