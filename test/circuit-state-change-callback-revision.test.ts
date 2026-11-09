import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { RetryQueue, type CircuitStateChangeCallback, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "circuit-state-change-callback-revision-secret";
const EP_A = "http://a.example/hook";
const BODY = Buffer.from(JSON.stringify({ event: "ping", n: 1 }));

type Transition = { endpoint: string; from: string; to: string; tenant?: string };

/**
 * Manual timer that also records the scheduled delays — the cooldown
 * tests assert on the delay a parked attempt was scheduled with, so a
 * plain fire-list is not enough.
 */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pendingCount: () => pending.length,
    lastDelay: () => pending[pending.length - 1]?.ms,
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function failingSender() {
  let calls = 0;
  let fail = true;
  const sender: Sender = async () => {
    calls += 1;
    if (fail) throw new Error("downstream down");
  };
  return { sender, calls: () => calls, setFail: (v: boolean) => (fail = v) };
}

function item(id: string, targetUrl: string, tenantId?: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {}, ...(tenantId !== undefined ? { tenantId } : {}) };
}

describe("RetryQueue circuit state-change callback revision (WR-365)", () => {
  function makeQueue() {
    const timer = manualTimer();
    let now = 0;
    const f = failingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0, // deterministic parking delay
      setTimer: timer.setTimer,
      circuitBreaker: { failureThreshold: 1, cooldownMs: 5000, nowMs: () => now },
    });
    return { q, timer, f, advance: (ms: number) => (now += ms) };
  }

  it("revise swaps the live callback: the next trip enters the new callback, the old one is silent", async () => {
    const { q, timer, f, advance } = makeQueue();
    const oldSeen: Transition[] = [];
    const newSeen: Transition[] = [];
    const oldCb: CircuitStateChangeCallback = (endpoint, from, to, tenant) =>
      oldSeen.push({ endpoint, from, to, ...(tenant !== undefined ? { tenant } : {}) });
    const newCb: CircuitStateChangeCallback = (endpoint, from, to, tenant) =>
      newSeen.push({ endpoint, from, to, ...(tenant !== undefined ? { tenant } : {}) });
    q.reviseCircuitStateChangeCallback(oldCb);
    q.start();
    try {
      q.enqueue(item("cb-swap-a", EP_A));
      await timer.step(); // attempt 1 fails -> trips open
      assert.equal(f.calls(), 1);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.deepEqual(oldSeen, [{ endpoint: EP_A, from: "closed", to: "open" }]);
      assert.deepEqual(newSeen, []);
      // Swap mid-flight: the old callback never hears another transition.
      q.reviseCircuitStateChangeCallback(newCb);
      f.setFail(false);
      advance(5000);
      await timer.step(); // backoff fires -> parked, delay = cooldown
      await timer.step(); // park fires -> probe succeeds -> closes
      assert.equal(f.calls(), 2);
      assert.equal(q.getCircuitStats()[0].state, "closed");
      assert.deepEqual(oldSeen, [{ endpoint: EP_A, from: "closed", to: "open" }]);
      assert.deepEqual(newSeen, [
        { endpoint: EP_A, from: "open", to: "half_open" },
        { endpoint: EP_A, from: "half_open", to: "closed" },
      ]);
      // A fresh trip after the close still enters only the new callback.
      f.setFail(true);
      q.enqueue(item("cb-swap-b", EP_A));
      await timer.step(); // attempt 1 fails -> trips open again
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(newSeen[2], { endpoint: EP_A, from: "closed", to: "open" });
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; the breaker keeps tripping and recovering", async () => {
    const { q, timer, f, advance } = makeQueue();
    const seen: Transition[] = [];
    const cb: CircuitStateChangeCallback = (endpoint, from, to) =>
      seen.push({ endpoint, from, to });
    q.reviseCircuitStateChangeCallback(cb);
    q.start();
    try {
      q.enqueue(item("cb-clear-a", EP_A));
      await timer.step(); // trips open
      assert.equal(seen.length, 1);
      q.reviseCircuitStateChangeCallback(null);
      f.setFail(false);
      advance(5000);
      await timer.step(); // backoff fires -> parked
      await timer.step(); // probe succeeds -> closes, silently
      assert.equal(q.getCircuitStats()[0].state, "closed");
      assert.equal(seen.length, 1);
      // And a fresh trip after the clear is silent too.
      f.setFail(true);
      q.enqueue(item("cb-clear-b", EP_A));
      await timer.step(); // trips open again
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("revise throws must-restart Error when the breaker was never configured", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.throws(
        () => q.reviseCircuitStateChangeCallback(() => {}),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
          assert.match((err as Error).message, /requires a restart/);
          return true;
        }
      );
      assert.throws(() => q.reviseCircuitStateChangeCallback(null), /requires a restart/);
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const { q, timer, f } = makeQueue();
    const seen: Transition[] = [];
    const cb: CircuitStateChangeCallback = (endpoint, from, to) =>
      seen.push({ endpoint, from, to });
    q.reviseCircuitStateChangeCallback(cb);
    q.start();
    try {
      for (const bad of ["nope", 42, {}, true]) {
        assert.throws(
          () => q.reviseCircuitStateChangeCallback(bad as never),
          RangeError,
          JSON.stringify(bad)
        );
      }
      q.enqueue(item("cb-illegal-a", EP_A));
      await timer.step(); // trips open -> the live callback still hears it
      assert.equal(f.calls(), 1);
      assert.deepEqual(seen, [{ endpoint: EP_A, from: "closed", to: "open" }]);
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference (or clearing when unset) is a no-op", async () => {
    const { q, timer, f } = makeQueue();
    const seen: Transition[] = [];
    const cb: CircuitStateChangeCallback = (endpoint, from, to) =>
      seen.push({ endpoint, from, to });
    // Clearing when nothing is set never throws and changes nothing.
    q.reviseCircuitStateChangeCallback(null);
    q.reviseCircuitStateChangeCallback(cb);
    q.reviseCircuitStateChangeCallback(cb); // same reference: no-op
    q.start();
    try {
      q.enqueue(item("cb-same-a", EP_A));
      await timer.step(); // trips open
      assert.equal(seen.length, 1);
      assert.deepEqual(seen, [{ endpoint: EP_A, from: "closed", to: "open" }]);
    } finally {
      q.stop();
    }
  });

  it("a named tenant's transition passes the tenant to the callback; the default tenant passes none", async () => {
    const { q, timer, f } = makeQueue();
    const seen: Transition[] = [];
    const cb: CircuitStateChangeCallback = (endpoint, from, to, tenant) =>
      seen.push({ endpoint, from, to, ...(tenant !== undefined ? { tenant } : {}) });
    q.reviseCircuitStateChangeCallback(cb);
    q.start();
    try {
      q.enqueue(item("cb-tenant-a", EP_A, "acme"));
      await timer.step(); // trips open for acme
      assert.deepEqual(seen, [{ endpoint: EP_A, from: "closed", to: "open", tenant: "acme" }]);
      q.enqueue(item("cb-tenant-b", EP_A));
      await timer.step(); // trips open for the default tenant
      assert.equal(seen.length, 2);
      assert.deepEqual(seen[1], { endpoint: EP_A, from: "closed", to: "open" });
      assert.equal("tenant" in seen[1], false);
    } finally {
      q.stop();
    }
  });

  it("the half-open slow-start hook still runs after a callback swap", async () => {
    // The slow-start hook lives in the breaker's own onStateChange
    // closure ahead of the operator callback (WR-148); swapping the
    // operator callback must not disturb the close path itself.
    const { q, timer, f, advance } = makeQueue();
    q.reviseCircuitStateChangeCallback(() => {});
    q.start();
    try {
      q.enqueue(item("cb-slow-a", EP_A));
      await timer.step(); // trips open
      assert.equal(q.getCircuitStats()[0].state, "open");
      f.setFail(false);
      advance(5000);
      await timer.step(); // backoff fires -> parked
      await timer.step(); // probe succeeds -> closed
      assert.equal(q.getCircuitStats()[0].state, "closed");
      assert.equal(q.getCircuitStats()[0].trips, 1);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer circuit state-change callback revision (WR-365)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "circuit-state-change-callback-revision-"));
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

  function ingest(port: number, body: Buffer = BODY): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-signature": signSha256(body, relaySecret),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(cond(), `timed out waiting for: ${what}`);
  }

  /** A server whose sender fails until told otherwise, tripping on first failure. */
  function trippingServer(onCircuitStateChange: CircuitStateChangeCallback) {
    const f = failingSender();
    const { relay, auditLog } = makeServer({
      retry: {
        sender: f.sender,
        baseDelayMs: 10,
        maxAttempts: 5,
        jitterMs: 0,
        random: () => 0,
        circuitBreaker: { failureThreshold: 1, cooldownMs: 200 },
        onCircuitStateChange,
      },
    });
    return { relay, auditLog, f };
  }

  it("replacing the operator callback routes the next trip to the new callback and the audit still lands", async () => {
    const initialSeen: Transition[] = [];
    const newSeen: Transition[] = [];
    const initialCb: CircuitStateChangeCallback = (endpoint, from, to, tenant) =>
      initialSeen.push({ endpoint, from, to, ...(tenant !== undefined ? { tenant } : {}) });
    const newCb: CircuitStateChangeCallback = (endpoint, from, to, tenant) =>
      newSeen.push({ endpoint, from, to, ...(tenant !== undefined ? { tenant } : {}) });
    const { relay, auditLog, f } = trippingServer(initialCb);
    const port = await listen(relay);
    // First trip: the initial callback hears it and the audit lands.
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "circuit_open").length >= 1, 5000, "first circuit_open");
    await waitFor(() => initialSeen.length >= 1, 5000, "initial callback on first trip");
    assert.equal(initialSeen.length, 1);
    assert.equal(initialSeen[0].to, "open");
    assert.deepEqual(newSeen, []);
    // Swap the operator callback while open.
    relay.reviseCircuitStateChangeCallback!(newCb);
    // Let the parked item recover: the probe succeeds and closes.
    f.setFail(false);
    await waitFor(() => eventsOf(auditLog, "circuit_closed").length >= 1, 5000, "circuit_closed");
    assert.equal(newSeen.length, 2); // open->half_open, half_open->closed
    assert.equal(initialSeen.length, 1); // the old callback heard nothing more
    // A fresh trip enters only the new callback, and the audit lands again.
    f.setFail(true);
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "circuit_open").length >= 2, 5000, "second circuit_open");
    await waitFor(() => newSeen.length >= 3, 5000, "new callback on second trip");
    assert.equal(newSeen[2].to, "open");
    assert.equal(initialSeen.length, 1);
  });

  it("clearing to null keeps the audit and stops the operator", async () => {
    const initialSeen: Transition[] = [];
    const initialCb: CircuitStateChangeCallback = (endpoint, from, to) =>
      initialSeen.push({ endpoint, from, to });
    const { relay, auditLog, f } = trippingServer(initialCb);
    const port = await listen(relay);
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "circuit_open").length >= 1, 5000, "first circuit_open");
    assert.equal(initialSeen.length, 1);
    // Clear back to audit-only, then recover and trip again.
    relay.reviseCircuitStateChangeCallback!(null);
    f.setFail(false);
    await waitFor(() => eventsOf(auditLog, "circuit_closed").length >= 1, 5000, "circuit_closed");
    assert.equal(initialSeen.length, 1); // the close was audit-only
    f.setFail(true);
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "circuit_open").length >= 2, 5000, "second circuit_open");
    assert.equal(initialSeen.length, 1); // still silent
  });

  it("revise audits previous/current presence; a same-reference revision is a silent no-op", async () => {
    const initialSeen: Transition[] = [];
    const initialCb: CircuitStateChangeCallback = () => {
      initialSeen.push({ endpoint: EP_A, from: "closed", to: "open" });
    };
    const { relay, auditLog } = trippingServer(initialCb);
    await listen(relay);
    const newCb: CircuitStateChangeCallback = () => {};
    // set -> set (the constructor callback was already set).
    relay.reviseCircuitStateChangeCallback!(newCb);
    // set -> cleared.
    relay.reviseCircuitStateChangeCallback!(null);
    // cleared -> set.
    relay.reviseCircuitStateChangeCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseCircuitStateChangeCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseCircuitStateChangeCallback!(null);
    relay.reviseCircuitStateChangeCallback!(null);
    const revised = eventsOf(auditLog, "circuit_state_change_callback_revised");
    assert.equal(revised.length, 4);
    assert.deepEqual(
      revised.map((e) => [e.previous, e.current]),
      [
        ["set", "set"],
        ["set", "cleared"],
        ["cleared", "set"],
        ["set", "cleared"],
      ]
    );
  });

  it("an unconfigured breaker throws Error on revise", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.throws(
      () => relay.reviseCircuitStateChangeCallback!(() => {}),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
        assert.match((err as Error).message, /requires a restart/);
        return true;
      }
    );
    assert.equal(eventsOf(auditLog, "circuit_state_change_callback_revised").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const initialSeen: Transition[] = [];
    const initialCb: CircuitStateChangeCallback = (endpoint, from, to) =>
      initialSeen.push({ endpoint, from, to });
    const { relay, auditLog, f } = trippingServer(initialCb);
    const port = await listen(relay);
    for (const bad of ["nope", 42, {}, true]) {
      assert.throws(
        () => relay.reviseCircuitStateChangeCallback!(bad as never),
        RangeError,
        JSON.stringify(bad)
      );
    }
    assert.equal(eventsOf(auditLog, "circuit_state_change_callback_revised").length, 0);
    // The live callback is untouched: a trip still reaches it.
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "circuit_open").length >= 1, 5000, "circuit_open");
    await waitFor(() => initialSeen.length >= 1, 5000, "initial callback after illegal revise");
    assert.equal(initialSeen.length, 1);
    assert.equal(f.calls(), 1);
  });
});
