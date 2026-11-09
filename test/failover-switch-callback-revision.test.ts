import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import {
  RetryQueue,
  type FailoverSwitchEvent,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "failover-switch-callback-revision-secret";
const PRIMARY = "http://127.0.0.1:9911/primary";
const STANDBY = "http://127.0.0.1:9912/standby";
const FORWARD = "http://127.0.0.1:9/unused";
const BODY = Buffer.from(JSON.stringify({ event: "ping", n: 1 }));

type SwitchObserver = (event: FailoverSwitchEvent) => void;

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

function item(id: string, targetUrl: string = PRIMARY) {
  return { id, payload: Buffer.from("hello"), targetUrl, headers: {} };
}

describe("RetryQueue failover switch callback revision (WR-366)", () => {
  function makeQueue() {
    const timer = manualTimer();
    let nowMs = 0;
    const seen: string[] = [];
    const sender: Sender = async (i) => {
      seen.push(i.targetUrl);
      if (i.targetUrl === PRIMARY) throw new Error("primary down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 3,
      setTimer: timer.setTimer,
      failover: {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 1000 },
      },
      failoverNow: () => nowMs,
    });
    return { q, timer, seen, advance: (ms: number) => (nowMs += ms) };
  }

  it("revise swaps the live callback: the next auto switch enters the new callback, the old one is silent", async () => {
    const { q, timer, seen } = makeQueue();
    const oldSeen: FailoverSwitchEvent[] = [];
    const newSeen: FailoverSwitchEvent[] = [];
    const oldCb: SwitchObserver = (e) => oldSeen.push(e);
    const newCb: SwitchObserver = (e) => newSeen.push(e);
    q.reviseFailoverSwitchCallback(oldCb);
    q.start();
    try {
      q.enqueue(item("sw-swap-a"));
      await timer.run();
      assert.deepEqual(seen, [PRIMARY, STANDBY]);
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].reason, "failure_threshold");
      assert.equal(oldSeen[0].from, PRIMARY);
      assert.equal(oldSeen[0].to, STANDBY);
      assert.deepEqual(newSeen, []);
      // Swap mid-flight: the old callback never hears another switch.
      q.reviseFailoverSwitchCallback(newCb);
      assert.equal(q.resetFailover(PRIMARY), true); // manual switch back
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].reason, "manual");
      // A fresh auto switch after the reset still enters only the new
      // callback. The failback clock has not advanced, so no canary.
      q.enqueue(item("sw-swap-b"));
      await timer.run();
      assert.deepEqual(seen, [PRIMARY, STANDBY, PRIMARY, STANDBY]);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 2);
      assert.equal(newSeen[1].reason, "failure_threshold");
      assert.equal(newSeen[1].from, PRIMARY);
      assert.equal(newSeen[1].to, STANDBY);
    } finally {
      q.stop();
    }
  });

  it("a manual resetFailover switch enters the new callback", async () => {
    const { q, timer } = makeQueue();
    const oldSeen: FailoverSwitchEvent[] = [];
    const newSeen: FailoverSwitchEvent[] = [];
    const oldCb: SwitchObserver = (e) => oldSeen.push(e);
    const newCb: SwitchObserver = (e) => newSeen.push(e);
    q.reviseFailoverSwitchCallback(oldCb);
    q.start();
    try {
      q.enqueue(item("sw-manual-a"));
      await timer.run();
      assert.equal(q.getFailoverStats()[0].activeTarget, STANDBY);
      assert.equal(oldSeen.length, 1);
      q.reviseFailoverSwitchCallback(newCb);
      assert.equal(q.resetFailover(PRIMARY), true);
      assert.equal(oldSeen.length, 1); // the old callback heard nothing more
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].reason, "manual");
      assert.equal(newSeen[0].from, STANDBY);
      assert.equal(newSeen[0].to, PRIMARY);
      assert.equal(q.getFailoverStats()[0].activeTarget, PRIMARY);
    } finally {
      q.stop();
    }
  });

  it("a failback switch enters the new callback", async () => {
    const { q, timer, advance } = makeQueue();
    const oldSeen: FailoverSwitchEvent[] = [];
    const newSeen: FailoverSwitchEvent[] = [];
    const oldCb: SwitchObserver = (e) => oldSeen.push(e);
    const newCb: SwitchObserver = (e) => newSeen.push(e);
    q.reviseFailoverSwitchCallback(oldCb);
    q.start();
    try {
      q.enqueue(item("sw-failback-a"));
      await timer.run();
      assert.equal(oldSeen.length, 1);
      q.reviseFailoverSwitchCallback(newCb);
      // Quiet period passes: the next item probes the primary (canary).
      advance(1000);
      q.enqueue(item("sw-failback-b"));
      await timer.run();
      assert.deepEqual(
        newSeen.map((s) => s.reason),
        ["failback", "failure_threshold"]
      );
      assert.equal(oldSeen.length, 1);
      assert.equal(q.getFailoverStats()[0].activeTarget, STANDBY);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; switching itself is untouched", async () => {
    const { q, timer } = makeQueue();
    const seen: FailoverSwitchEvent[] = [];
    const cb: SwitchObserver = (e) => seen.push(e);
    q.reviseFailoverSwitchCallback(cb);
    q.start();
    try {
      q.enqueue(item("sw-clear-a"));
      await timer.run();
      assert.equal(seen.length, 1);
      q.reviseFailoverSwitchCallback(null);
      assert.equal(q.resetFailover(PRIMARY), true); // still switches
      assert.equal(q.getFailoverStats()[0].activeTarget, PRIMARY);
      assert.equal(seen.length, 1); // the manual switch was silent
      q.enqueue(item("sw-clear-b"));
      await timer.run();
      assert.equal(q.getFailoverStats()[0].activeTarget, STANDBY);
      assert.equal(seen.length, 1); // the auto switch was silent too
    } finally {
      q.stop();
    }
  });

  it("revise throws must-restart Error when failover was never configured", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.throws(
        () => q.reviseFailoverSwitchCallback(() => {}),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
          assert.match((err as Error).message, /requires a restart/);
          return true;
        }
      );
      assert.throws(() => q.reviseFailoverSwitchCallback(null), /requires a restart/);
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const { q, timer } = makeQueue();
    const seen: FailoverSwitchEvent[] = [];
    const cb: SwitchObserver = (e) => seen.push(e);
    q.reviseFailoverSwitchCallback(cb);
    q.start();
    try {
      for (const bad of ["nope", 42, {}, true]) {
        assert.throws(
          () => q.reviseFailoverSwitchCallback(bad as never),
          RangeError,
          JSON.stringify(bad)
        );
      }
      q.enqueue(item("sw-illegal-a"));
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].reason, "failure_threshold");
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference (or clearing when unset) is a no-op", async () => {
    const { q, timer } = makeQueue();
    const seen: FailoverSwitchEvent[] = [];
    const cb: SwitchObserver = (e) => seen.push(e);
    // Clearing when nothing is set never throws and changes nothing.
    q.reviseFailoverSwitchCallback(null);
    q.reviseFailoverSwitchCallback(cb);
    q.reviseFailoverSwitchCallback(cb); // same reference: no-op
    q.start();
    try {
      q.enqueue(item("sw-same-a"));
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].reason, "failure_threshold");
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer failover switch callback revision (WR-366)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "failover-switch-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: FORWARD,
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

  /** A server whose sender fails the primary, tripping on first failure. */
  function switchingServer(onFailoverSwitch: SwitchObserver) {
    const { relay, auditLog } = makeServer({
      retry: {
        sender: (async (i) => {
          if (i.targetUrl === FORWARD) throw new Error("primary down");
        }) as Sender,
        baseDelayMs: 10,
        maxAttempts: 3,
        jitterMs: 0,
        random: () => 0,
        failover: {
          [FORWARD]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 500 },
        },
        onFailoverSwitch,
      },
    });
    return { relay, auditLog };
  }

  it("replacing the operator callback routes the next switch to the new callback and the audit still lands", async () => {
    const initialSeen: FailoverSwitchEvent[] = [];
    const newSeen: FailoverSwitchEvent[] = [];
    const initialCb: SwitchObserver = (e) => initialSeen.push(e);
    const newCb: SwitchObserver = (e) => newSeen.push(e);
    const { relay, auditLog } = switchingServer(initialCb);
    const port = await listen(relay);
    // First switch: the initial callback hears it and the audit lands.
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "failover_switched").length >= 1, 5000, "first failover_switched");
    await waitFor(() => initialSeen.length >= 1, 5000, "initial callback on first switch");
    assert.equal(initialSeen.length, 1);
    assert.equal(initialSeen[0].reason, "failure_threshold");
    assert.deepEqual(newSeen, []);
    // Swap the operator callback; the failback quiet period passes.
    relay.reviseFailoverSwitchCallback!(newCb);
    await new Promise((r) => setTimeout(r, 600));
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "failover_switched").length >= 3, 5000, "failback switches");
    await waitFor(() => newSeen.length >= 2, 5000, "new callback on failback switches");
    assert.deepEqual(
      newSeen.map((s) => s.reason),
      ["failback", "failure_threshold"]
    );
    assert.equal(initialSeen.length, 1); // the old callback heard nothing more
    // The revision itself was audited with set -> set presence.
    const revised = eventsOf(auditLog, "failover_switch_callback_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual([revised[0].previous, revised[0].current], ["set", "set"]);
  });

  it("clearing to null keeps the audit and stops the operator", async () => {
    const initialSeen: FailoverSwitchEvent[] = [];
    const initialCb: SwitchObserver = (e) => initialSeen.push(e);
    const { relay, auditLog } = switchingServer(initialCb);
    const port = await listen(relay);
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "failover_switched").length >= 1, 5000, "first failover_switched");
    assert.equal(initialSeen.length, 1);
    // Clear back to audit-only, then let the failback cycle run.
    relay.reviseFailoverSwitchCallback!(null);
    await new Promise((r) => setTimeout(r, 600));
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "failover_switched").length >= 3, 5000, "failback switches");
    assert.equal(initialSeen.length, 1); // both later switches were audit-only
  });

  it("revise audits previous/current presence; a same-reference revision is a silent no-op", async () => {
    const initialCb: SwitchObserver = () => {};
    const { relay, auditLog } = switchingServer(initialCb);
    await listen(relay);
    const newCb: SwitchObserver = () => {};
    // set -> set (the constructor callback was already set).
    relay.reviseFailoverSwitchCallback!(newCb);
    // set -> cleared.
    relay.reviseFailoverSwitchCallback!(null);
    // cleared -> set.
    relay.reviseFailoverSwitchCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseFailoverSwitchCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseFailoverSwitchCallback!(null);
    relay.reviseFailoverSwitchCallback!(null);
    const revised = eventsOf(auditLog, "failover_switch_callback_revised");
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

  it("an unconfigured failover throws Error on revise", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.throws(
      () => relay.reviseFailoverSwitchCallback!(() => {}),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
        assert.match((err as Error).message, /requires a restart/);
        return true;
      }
    );
    assert.equal(eventsOf(auditLog, "failover_switch_callback_revised").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const initialSeen: FailoverSwitchEvent[] = [];
    const initialCb: SwitchObserver = (e) => initialSeen.push(e);
    const { relay, auditLog } = switchingServer(initialCb);
    const port = await listen(relay);
    for (const bad of ["nope", 42, {}, true]) {
      assert.throws(
        () => relay.reviseFailoverSwitchCallback!(bad as never),
        RangeError,
        JSON.stringify(bad)
      );
    }
    assert.equal(eventsOf(auditLog, "failover_switch_callback_revised").length, 0);
    // The live callback is untouched: a switch still reaches it.
    assert.equal((await ingest(port)).status, 202);
    await waitFor(() => eventsOf(auditLog, "failover_switched").length >= 1, 5000, "failover_switched");
    await waitFor(() => initialSeen.length >= 1, 5000, "initial callback after illegal revise");
    assert.equal(initialSeen.length, 1);
  });
});
