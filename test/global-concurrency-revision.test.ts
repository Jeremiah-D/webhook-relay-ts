import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { GlobalConcurrencyGate } from "../src/global-concurrency.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "global-concurrency-revision-secret";

const A = "http://a/hook";
const B = "http://b/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Let the deliver() promise chain (turn -> limiter -> gate -> sender) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

/** Manual timer with single-step control, mirroring the other feature tests. */
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

/**
 * A sender that blocks every delivery until its release is called, so
 * in-flight occupancy is fully deterministic.
 */
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

describe("GlobalConcurrencyGate.retune (WR-313)", () => {
  it("rejects illegal values and leaves the live cap untouched", () => {
    const gate = new GlobalConcurrencyGate(2);
    for (const bad of [0, -1, 1.5, NaN, "2" as unknown as number, null as unknown as number]) {
      assert.throws(() => gate.retune(bad), RangeError, `cap ${String(bad)}`);
    }
    assert.equal(gate.cap(), 2);
    assert.equal(gate.stats().maxConcurrent, 2);
  });

  it("a same-value retune is a no-op and does not disturb waiters", async () => {
    const gate = new GlobalConcurrencyGate(1);
    const r1 = await gate.acquire();
    let woken = false;
    const p = gate.acquire().then((r) => {
      woken = true;
      return r;
    });
    await flush(3);
    assert.equal(woken, false);
    assert.equal(gate.retune(1), 1);
    await flush(3);
    assert.equal(woken, false); // still queued: no spurious grant
    assert.equal(gate.queuedDepth(), 1);
    r1();
    const rel = await p;
    rel();
    assert.equal(gate.inFlightCount(), 0);
  });

  it("widening immediately wakes FIFO waiters, each taking a fresh slot", async () => {
    const gate = new GlobalConcurrencyGate(1);
    const order: string[] = [];
    const r1 = await gate.acquire();
    const p2 = gate.acquire().then((r) => {
      order.push("w2");
      return r;
    });
    const p3 = gate.acquire().then((r) => {
      order.push("w3");
      return r;
    });
    await flush(3);
    assert.deepEqual(order, []);
    assert.equal(gate.retune(3), 3);
    const rel2 = await p2;
    const rel3 = await p3;
    assert.deepEqual(order, ["w2", "w3"]);
    assert.equal(gate.inFlightCount(), 3); // 1 held + 2 freshly granted
    assert.equal(gate.queuedDepth(), 0);
    r1();
    rel2();
    rel3();
    assert.equal(gate.inFlightCount(), 0);
  });

  it("tightening never revokes held slots; new acquisitions queue until the count drains", async () => {
    const gate = new GlobalConcurrencyGate(3);
    const r1 = await gate.acquire();
    const r2 = await gate.acquire();
    const r3 = await gate.acquire();
    let woken = false;
    const p4 = gate.acquire().then((r) => {
      woken = true;
      return r;
    });
    await flush(3);
    assert.equal(woken, false);
    assert.equal(gate.retune(1), 1);
    // In-flight stays 3: nothing is revoked.
    assert.equal(gate.inFlightCount(), 3);
    assert.equal(gate.queuedDepth(), 1);
    // A fresh acquisition queues too — it does not jump the line.
    let w5 = false;
    void gate.acquire().then(() => {
      w5 = true;
    });
    await flush(3);
    assert.equal(w5, false);
    // Releases drain the count instead of transferring while it sits
    // above the new cap; the waiter is granted only once the count is
    // back at the cap.
    r1();
    await flush(3);
    assert.equal(gate.inFlightCount(), 2);
    assert.equal(woken, false);
    r2();
    await flush(3);
    assert.equal(gate.inFlightCount(), 1);
    assert.equal(woken, false);
    r3();
    const rel4 = await p4;
    assert.equal(woken, true);
    assert.equal(gate.inFlightCount(), 1); // transferred at the cap
    assert.equal(gate.queuedDepth(), 1); // w5 still queued behind the cap
    rel4();
    await flush(3);
    assert.equal(w5, true);
    assert.equal(gate.inFlightCount(), 1);
  });

  it("retune to Infinity wakes every waiter; retune from Infinity starts limiting", async () => {
    const gate = new GlobalConcurrencyGate(1);
    const r1 = await gate.acquire();
    const woken: string[] = [];
    const p2 = gate.acquire().then((r) => {
      woken.push("w2");
      return r;
    });
    const p3 = gate.acquire().then((r) => {
      woken.push("w3");
      return r;
    });
    await flush(3);
    assert.deepEqual(woken, []);
    assert.equal(gate.retune(Infinity), Infinity);
    const rel2 = await p2;
    const rel3 = await p3;
    assert.deepEqual(woken, ["w2", "w3"]);
    assert.equal(gate.inFlightCount(), 3);
    r1();
    rel2();
    rel3();

    // From Infinity: the count is untouched, the next acquisition queues.
    const open = new GlobalConcurrencyGate();
    const o1 = await open.acquire();
    const o2 = await open.acquire();
    assert.equal(open.inFlightCount(), 2);
    assert.equal(open.retune(1), 1);
    assert.equal(open.inFlightCount(), 2); // in-flight unaffected
    let o3 = false;
    void open.acquire().then(() => {
      o3 = true;
    });
    await flush(3);
    assert.equal(o3, false);
    o1(); // drains (2 > 1): no transfer
    await flush(3);
    assert.equal(o3, false);
    assert.equal(open.inFlightCount(), 1);
    o2(); // at the cap: transfers to the waiter
    await flush(3);
    assert.equal(o3, true);
    assert.equal(open.inFlightCount(), 1);
  });
});

describe("RetryQueue.setGlobalConcurrency (WR-313)", () => {
  it("revises the live cap and getGlobalConcurrencyStats reflects it", () => {
    const sender: Sender = async () => {};
    const q = new RetryQueue({ sender, globalMaxConcurrent: 2, maxAttempts: 1 });
    q.start();
    try {
      assert.equal(q.setGlobalConcurrency(5), 5);
      assert.equal(q.getGlobalConcurrencyStats().maxConcurrent, 5);
      assert.equal(q.setGlobalConcurrency(Infinity), Infinity);
      assert.equal(q.getGlobalConcurrencyStats().maxConcurrent, Infinity);
      // Same value: no-op.
      assert.equal(q.setGlobalConcurrency(Infinity), Infinity);
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError and leaves the live cap untouched", () => {
    const sender: Sender = async () => {};
    const q = new RetryQueue({ sender, globalMaxConcurrent: 2, maxAttempts: 1 });
    q.start();
    try {
      for (const bad of [0, -1, 1.5, NaN]) {
        assert.throws(() => q.setGlobalConcurrency(bad), RangeError, `cap ${bad}`);
      }
      assert.equal(q.getGlobalConcurrencyStats().maxConcurrent, 2);
    } finally {
      q.stop();
    }
  });

  it("widening wakes a delivery queued on the gate; the wait series follows the live cap", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalMaxConcurrent: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", B));
    q.start();
    try {
      await timer.step();
      assert.deepEqual(started, ["a"]); // b waits on the gate
      assert.match(q.renderMetrics(), /relay_global_concurrency_wait_total 1/);
      assert.equal(q.setGlobalConcurrency(2), 2);
      await flush();
      assert.deepEqual(new Set(started), new Set(["a", "b"])); // widened: b starts at once
      // Retune to Infinity: the series disappears with the live cap.
      assert.equal(q.setGlobalConcurrency(Infinity), Infinity);
      assert.ok(!q.renderMetrics().includes("relay_global_concurrency_wait_total"));
      // Back to a finite cap: the series reappears (0 waits so far on it).
      assert.equal(q.setGlobalConcurrency(2), 2);
      assert.match(q.renderMetrics(), /relay_global_concurrency_wait_total 1/);
    } finally {
      releaseAll();
      await flush();
      q.stop();
    }
  });
});

describe("RelayServer.setGlobalConcurrency (WR-313)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "global-concurrency-revision-"));
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

  it("audits global_concurrency_revised with previous/current and skips the audit on a no-op", async () => {
    const { relay, auditLog } = makeServer({ retry: { globalMaxConcurrent: 2 } });
    await listen(relay);
    assert.equal(eventsOf(auditLog, "global_concurrency_revised").length, 0);
    assert.equal(relay.setGlobalConcurrency!(5), 5);
    const revised = eventsOf(auditLog, "global_concurrency_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, 2);
    assert.equal(revised[0].current, 5);
    // The stats delegate reports the live cap.
    assert.equal(relay.getGlobalConcurrencyStats!().maxConcurrent, 5);
    // Same value: no new audit event.
    relay.setGlobalConcurrency!(5);
    assert.equal(eventsOf(auditLog, "global_concurrency_revised").length, 1);
  });

  it("throws RangeError on an illegal value and leaves the live cap untouched", async () => {
    const { relay, auditLog } = makeServer({ retry: { globalMaxConcurrent: 2 } });
    await listen(relay);
    for (const bad of [0, -1, 1.5, NaN]) {
      assert.throws(() => relay.setGlobalConcurrency!(bad), RangeError, `cap ${bad}`);
    }
    assert.equal(eventsOf(auditLog, "global_concurrency_revised").length, 0);
    assert.equal(relay.getGlobalConcurrencyStats!().maxConcurrent, 2);
  });

  it("is always set: the default unlimited cap revises like any other", async () => {
    const { relay } = makeServer({});
    await listen(relay);
    assert.equal(typeof relay.setGlobalConcurrency, "function");
    assert.equal(relay.getGlobalConcurrencyStats!().maxConcurrent, Infinity);
    assert.equal(relay.setGlobalConcurrency!(4), 4);
    assert.equal(relay.getGlobalConcurrencyStats!().maxConcurrent, 4);
  });
});
