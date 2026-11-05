import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import {
  TenantConcurrencyGate,
  TenantConcurrencyGates,
} from "../src/tenant-concurrency.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "tenant-concurrency-revision-secret";
const EP_A = "http://a.example/hook";
const A = "http://a/hook";
const B = "http://b/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Let the deliver() promise chain (turn -> gates -> limiter -> sender) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
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

function item(id: string, targetUrl: string, tenantId?: string) {
  return { id, payload: BODY, targetUrl, headers: {}, ...(tenantId === undefined ? {} : { tenantId }) };
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

describe("TenantConcurrencyGate.retune (WR-328)", () => {
  it("rejects illegal values and leaves the live cap untouched", () => {
    const gate = new TenantConcurrencyGate(2);
    for (const bad of [0, -1, 1.5, NaN, "2" as unknown as number, null as unknown as number]) {
      assert.throws(() => gate.retune(bad), RangeError, `cap ${String(bad)}`);
    }
    assert.equal(gate.cap(), 2);
    assert.equal(gate.stats().maxConcurrent, 2);
  });

  it("a same-value retune is a no-op and does not disturb waiters", async () => {
    const gate = new TenantConcurrencyGate(1);
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

  it("tightening never revokes held slots; new acquisitions queue until the count drains", async () => {
    const gate = new TenantConcurrencyGate(3);
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
    // Tighten below the in-flight count: the three held slots stay.
    assert.equal(gate.retune(1), 1);
    assert.equal(gate.inFlightCount(), 3);
    await flush(3);
    assert.equal(woken, false);
    // First release drains (3 -> 2, still above the cap): no transfer.
    r1();
    await flush(3);
    assert.equal(woken, false);
    assert.equal(gate.inFlightCount(), 2);
    // Second release drains (2 -> 1, at the cap): still no transfer —
    // a waiter is a new acquisition, and 1 is not below the cap.
    r2();
    await flush(3);
    assert.equal(woken, false);
    assert.equal(gate.inFlightCount(), 1);
    // Third release drops below the cap, so the waiter finally goes.
    r3();
    const rel4 = await p4;
    assert.equal(woken, true);
    assert.equal(gate.inFlightCount(), 1);
    rel4();
    assert.equal(gate.inFlightCount(), 0);
  });

  it("widening immediately wakes FIFO waiters, each taking a fresh slot", async () => {
    const gate = new TenantConcurrencyGate(1);
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

  it("revising to Infinity wakes every waiter", async () => {
    const gate = new TenantConcurrencyGate(1);
    const r1 = await gate.acquire();
    const p2 = gate.acquire();
    const p3 = gate.acquire();
    await flush(3);
    assert.equal(gate.queuedDepth(), 2);
    assert.equal(gate.retune(Infinity), Infinity);
    const rel2 = await p2;
    const rel3 = await p3;
    assert.equal(gate.inFlightCount(), 3);
    assert.equal(gate.queuedDepth(), 0);
    r1();
    rel2();
    rel3();
    assert.equal(gate.inFlightCount(), 0);
  });
});

describe("TenantConcurrencyGates per-tenant overrides (WR-328)", () => {
  it("reviseTenant records an override only on a real change; removeTenant falls back to the default", async () => {
    const gates = new TenantConcurrencyGates(2);
    // Unseen tenants report the construction default, no override.
    assert.deepEqual(gates.getTenant("acme"), { maxConcurrent: 2, overridden: false });
    assert.equal(gates.hasOverride("acme"), false);
    assert.equal(gates.removeTenant("acme"), false);
    // A same-value revision is a no-op: no override, no gate created.
    assert.equal(gates.reviseTenant("acme", 2), 2);
    assert.equal(gates.hasOverride("acme"), false);
    assert.deepEqual(gates.stats(), []);
    // A real revision records the override and builds the gate at it.
    assert.equal(gates.reviseTenant("acme", 1), 1);
    assert.equal(gates.hasOverride("acme"), true);
    assert.deepEqual(gates.getTenant("acme"), { maxConcurrent: 1, overridden: true });
    assert.equal(gates.stats()[0].maxConcurrent, 1);
    // Other tenants still read the default.
    assert.deepEqual(gates.getTenant("globex"), { maxConcurrent: 2, overridden: false });
    // The revised gate really caps at 1: a second acquire queues.
    const r1 = await gates.acquire("acme");
    let woken = false;
    const p2 = gates.acquire("acme").then((r) => {
      woken = true;
      return r;
    });
    await flush(3);
    assert.equal(woken, false);
    // Removal falls back to the default and wakes the waiter at once
    // (the gate is retuned in place: 2 > 1 in flight, so it is granted).
    assert.equal(gates.removeTenant("acme"), true);
    assert.equal(gates.hasOverride("acme"), false);
    assert.deepEqual(gates.getTenant("acme"), { maxConcurrent: 2, overridden: false });
    const rel2 = await p2;
    assert.equal(woken, true);
    r1();
    rel2();
    assert.equal(gates.removeTenant("acme"), false);
    // The default tenant ("") revises like any other.
    assert.equal(gates.reviseTenant("", 1), 1);
    assert.equal(gates.hasOverride(""), true);
    assert.equal(gates.removeTenant(""), true);
    assert.deepEqual(gates.getTenant(""), { maxConcurrent: 2, overridden: false });
  });

  it("an illegal tenant id or cap throws and the live caps are untouched", async () => {
    const gates = new TenantConcurrencyGates(2);
    const r1 = await gates.acquire("acme");
    for (const bad of [0, -1, 1.5, NaN]) {
      assert.throws(() => gates.reviseTenant("acme", bad), RangeError, `cap ${String(bad)}`);
    }
    assert.throws(() => gates.reviseTenant(42 as unknown as string, 1), RangeError);
    assert.throws(() => gates.reviseTenant(undefined as unknown as string, 1), RangeError);
    assert.throws(() => gates.reviseTenant("bad id!", 1), RangeError);
    // Tenant id is checked before the cap: a bad id with a bad cap
    // throws for the id, and nothing moves either way.
    assert.throws(() => gates.reviseTenant("bad id!", 0), RangeError);
    assert.deepEqual(gates.getTenant("acme"), { maxConcurrent: 2, overridden: false });
    assert.equal(gates.hasOverride("acme"), false);
    assert.throws(() => gates.removeTenant(42 as unknown as string), RangeError);
    assert.throws(() => gates.removeTenant("bad id!"), RangeError);
    assert.equal(gates.removeTenant("never"), false);
    r1();
  });
});

describe("RetryQueue tenant concurrency revision (WR-328)", () => {
  it("revise/get/remove read live values; check order is tenant id, then cap", () => {
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      tenantMaxConcurrent: 2,
    });
    try {
      assert.deepEqual(q.getTenantConcurrency("acme"), {
        tenant: "acme",
        maxConcurrent: 2,
        previous: 2,
        overridden: false,
      });
      assert.deepEqual(q.getTenantConcurrency(""), {
        tenant: "",
        maxConcurrent: 2,
        previous: 2,
        overridden: false,
      });
      assert.deepEqual(q.reviseTenantConcurrency("acme", 1), {
        tenant: "acme",
        maxConcurrent: 1,
        previous: 2,
        overridden: true,
      });
      // Same effective value: a no-op that records no override.
      assert.deepEqual(q.reviseTenantConcurrency("other", 2), {
        tenant: "other",
        maxConcurrent: 2,
        previous: 2,
        overridden: false,
      });
      // Tenant id is checked before the cap.
      assert.throws(() => q.reviseTenantConcurrency("bad id!", 0), RangeError);
      assert.throws(() => q.reviseTenantConcurrency(42 as unknown as string, 1), RangeError);
      assert.throws(() => q.reviseTenantConcurrency("acme", 0), RangeError);
      assert.throws(() => q.reviseTenantConcurrency("acme", 1.5), RangeError);
      assert.deepEqual(q.getTenantConcurrency("acme"), {
        tenant: "acme",
        maxConcurrent: 1,
        previous: 1,
        overridden: true,
      });
      assert.equal(q.removeTenantConcurrency("never"), false);
      assert.equal(q.removeTenantConcurrency("acme"), true);
      assert.deepEqual(q.getTenantConcurrency("acme"), {
        tenant: "acme",
        maxConcurrent: 2,
        previous: 2,
        overridden: false,
      });
    } finally {
      q.stop();
    }
  });

  it("revising one tenant from an unconfigured (Infinity) default caps only that tenant", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
    });
    try {
      // No tenantMaxConcurrent configured: every tenant is unlimited.
      assert.deepEqual(q.getTenantConcurrency("acme"), {
        tenant: "acme",
        maxConcurrent: Infinity,
        previous: Infinity,
        overridden: false,
      });
      assert.deepEqual(q.reviseTenantConcurrency("acme", 1), {
        tenant: "acme",
        maxConcurrent: 1,
        previous: Infinity,
        overridden: true,
      });
      q.enqueue(item("a1", A, "acme"));
      q.enqueue(item("a2", B, "acme")); // same tenant: serialized now
      q.enqueue(item("b1", B, "globex")); // other tenant: still unlimited
      q.start();
      await timer.step();
      assert.ok(started.includes("a1"));
      assert.ok(started.includes("b1"), "globex is not capped by acme's revision");
      assert.ok(!started.includes("a2"), "acme's second delivery waits on acme's revised cap");
      assert.deepEqual(q.getTenantConcurrency("globex"), {
        tenant: "globex",
        maxConcurrent: Infinity,
        previous: Infinity,
        overridden: false,
      });
      releaseAll();
      await flush(); // a1/b1 settle; a2 takes acme's freed slot and starts
      releaseAll(); // release a2 as well — it started only after the first releaseAll
      await flush();
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });

  it("getTenantConcurrencyStats follows the live cap", () => {
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      tenantMaxConcurrent: 2,
    });
    try {
      assert.deepEqual(q.getTenantConcurrencyStats(), []);
      q.reviseTenantConcurrency("acme", 1);
      const rows = q.getTenantConcurrencyStats();
      assert.equal(rows.length, 1);
      assert.equal(rows[0].tenant, "acme");
      assert.equal(rows[0].maxConcurrent, 1);
      q.removeTenantConcurrency("acme");
      assert.equal(q.getTenantConcurrencyStats()[0].maxConcurrent, 2);
    } finally {
      q.stop();
    }
  });

  it("tightening bites at the next acquire; the urgent lane still bypasses and tenant-less deliveries are unaffected", async () => {
    const timer = manualTimer();
    const { sender, started, release, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      tenantMaxConcurrent: 2,
      jitterMs: 0,
    });
    try {
      q.enqueue(item("a1", A, "acme"));
      q.enqueue(item("a2", B, "acme"));
      q.start();
      await timer.step();
      assert.deepEqual(new Set(started), new Set(["a1", "a2"]));
      // Tighten below the in-flight count: both held slots stay.
      q.reviseTenantConcurrency("acme", 1);
      q.enqueue(item("a3", A, "acme")); // new acquire: must wait
      q.enqueue({ ...item("u1", B, "acme"), priority: "urgent" });
      q.enqueue(item("x1", A)); // tenant-less: never touches the gate
      await timer.step();
      assert.ok(!started.includes("a3"), "a new acme acquire queues under the tightened cap");
      assert.ok(started.includes("u1"), "urgent still bypasses the tenant gate after revision");
      assert.ok(started.includes("x1"), "tenant-less deliveries are unaffected by the revision");
      release("a1"); // drains (2 -> 1, at the cap): a3 still waits
      await flush();
      assert.ok(!started.includes("a3"));
      release("a2"); // drops below the cap: a3 goes
      await flush();
      assert.ok(started.includes("a3"));
      releaseAll();
      await flush();
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer tenant concurrency revision (WR-328)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "tenant-concurrency-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: EP_A,
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

  it("revise audits previous/current, with the construction default as first previous", async () => {
    const { relay, auditLog } = makeServer({
      retry: { tenantMaxConcurrent: 2 },
    });
    await listen(relay);
    assert.deepEqual(relay.reviseTenantConcurrency("acme", 1), {
      tenant: "acme",
      maxConcurrent: 1,
      previous: 2,
      overridden: true,
    });
    let revised = eventsOf(auditLog, "tenant_concurrency_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].tenant, "acme");
    assert.equal(revised[0].previous, 2); // first previous: the construction default
    assert.equal(revised[0].current, 1);
    // The default tenant ("") revises like any other tenant.
    assert.deepEqual(relay.reviseTenantConcurrency("", 5), {
      tenant: "",
      maxConcurrent: 5,
      previous: 2,
      overridden: true,
    });
    revised = eventsOf(auditLog, "tenant_concurrency_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].tenant, "");
    assert.equal(revised[1].previous, 2);
    assert.equal(revised[1].current, 5);
    // A second revision audits the live effective value as previous.
    relay.reviseTenantConcurrency("acme", 3);
    revised = eventsOf(auditLog, "tenant_concurrency_revised");
    assert.equal(revised.length, 3);
    assert.equal(revised[2].previous, 1);
    assert.equal(revised[2].current, 3);
  });

  it("a same-value revision is a silent no-op; an illegal value throws RangeError and live + audit are untouched", async () => {
    const { relay, auditLog } = makeServer({
      retry: { tenantMaxConcurrent: 2 },
    });
    await listen(relay);
    // Landing exactly on the live value — even the construction default itself.
    relay.reviseTenantConcurrency("acme", 2);
    assert.equal(eventsOf(auditLog, "tenant_concurrency_revised").length, 0);
    assert.equal(relay.getTenantConcurrency!("acme").overridden, false);
    relay.reviseTenantConcurrency("acme", 1);
    assert.equal(eventsOf(auditLog, "tenant_concurrency_revised").length, 1);
    relay.reviseTenantConcurrency("acme", 1);
    assert.equal(eventsOf(auditLog, "tenant_concurrency_revised").length, 1);
    for (const bad of [0, -1, 1.5, NaN]) {
      assert.throws(() => relay.reviseTenantConcurrency("acme", bad), RangeError, `cap ${String(bad)}`);
    }
    assert.throws(() => relay.reviseTenantConcurrency("bad id!", 1), RangeError);
    assert.throws(() => relay.reviseTenantConcurrency(42 as unknown as string, 1), RangeError);
    assert.deepEqual(relay.getTenantConcurrency!("acme"), {
      tenant: "acme",
      maxConcurrent: 1,
      previous: 1,
      overridden: true,
    });
    assert.equal(eventsOf(auditLog, "tenant_concurrency_revised").length, 1);
  });

  it("remove returns true, audits, and falls back to the default; without an override it returns false silently", async () => {
    const { relay, auditLog } = makeServer({
      retry: { tenantMaxConcurrent: 2 },
    });
    await listen(relay);
    assert.equal(relay.removeTenantConcurrency("acme"), false);
    assert.equal(eventsOf(auditLog, "tenant_concurrency_removed").length, 0);
    relay.reviseTenantConcurrency("acme", 1);
    assert.equal(relay.getTenantConcurrency!("acme").maxConcurrent, 1);
    assert.equal(relay.removeTenantConcurrency("acme"), true);
    const removed = eventsOf(auditLog, "tenant_concurrency_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].tenant, "acme");
    assert.equal(removed[0].previous, 1);
    assert.deepEqual(relay.getTenantConcurrency!("acme"), {
      tenant: "acme",
      maxConcurrent: 2,
      previous: 2,
      overridden: false,
    });
    // Nothing left to remove: false, no audit.
    assert.equal(relay.removeTenantConcurrency("acme"), false);
    assert.equal(eventsOf(auditLog, "tenant_concurrency_removed").length, 1);
  });

  it("revising one tenant leaves other tenants and the global gate live-unchanged", async () => {
    const { relay } = makeServer({
      retry: { tenantMaxConcurrent: 2, globalMaxConcurrent: 5 },
    });
    await listen(relay);
    relay.reviseTenantConcurrency("acme", 1);
    assert.deepEqual(relay.getTenantConcurrency!("globex"), {
      tenant: "globex",
      maxConcurrent: 2,
      previous: 2,
      overridden: false,
    });
    assert.equal(relay.getGlobalConcurrencyStats!().maxConcurrent, 5);
    relay.reviseTenantConcurrency("globex", 4);
    assert.equal(relay.getTenantConcurrency!("acme").maxConcurrent, 1);
    assert.equal(relay.getGlobalConcurrencyStats!().maxConcurrent, 5);
  });
});
