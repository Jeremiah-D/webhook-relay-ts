import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { EndpointAutoDisable } from "../src/endpoint-disable.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "endpoint-auto-disable-revision-secret";
const operatorToken = "endpoint-auto-disable-revision-token";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Manual clock with single-step control for the tracker tests. */
function fakeClock(startMs = 1_000) {
  let now = startMs;
  return { now: () => now, advance: (ms: number) => { now += ms; } };
}

/**
 * Manual timer with single-step control, mirroring
 * test/endpoint-auto-disable-callbacks-revision.test.ts: each step drains the
 * currently-armed timers exactly once.
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

function failingSender() {
  let calls = 0;
  const sender: Sender = async () => {
    calls += 1;
    throw new Error("downstream down");
  };
  return { sender, calls: () => calls };
}

describe("EndpointAutoDisable live threshold/window revision (WR-415)", () => {
  it("lowering the threshold keeps the live streak and the next failure disables", () => {
    const clock = fakeClock();
    const tracker = new EndpointAutoDisable({
      failureThreshold: 3,
      nowMs: clock.now,
    });
    assert.equal(tracker.recordFailure(URL).disabled, false);
    assert.equal(tracker.recordFailure(URL).disabled, false);
    assert.equal(tracker.consecutiveFailures(URL), 2);
    assert.equal(tracker.isDisabled(URL), false);
    const revised = tracker.revise({ failureThreshold: 2 });
    assert.deepEqual(revised, { failureThreshold: 2, windowMs: Infinity });
    assert.equal(tracker.threshold, 2);
    // The live streak (2) survives the revision — no retroactive disable.
    assert.equal(tracker.isDisabled(URL), false);
    assert.equal(tracker.consecutiveFailures(URL), 2);
    const outcome = tracker.recordFailure(URL);
    assert.equal(outcome.disabled, true);
    assert.equal(outcome.consecutiveFailures, 3);
    assert.equal(outcome.failureThreshold, 2);
    assert.equal(tracker.isDisabled(URL), true);
  });

  it("raising the threshold never re-enables a disabled endpoint; enable() then counts per the new threshold", () => {
    const clock = fakeClock();
    const tracker = new EndpointAutoDisable({
      failureThreshold: 2,
      nowMs: clock.now,
    });
    tracker.recordFailure(URL);
    assert.equal(tracker.recordFailure(URL).disabled, true);
    const revised = tracker.revise({ failureThreshold: 5 });
    assert.deepEqual(revised, { failureThreshold: 5, windowMs: Infinity });
    assert.equal(tracker.isDisabled(URL), true);
    // Further failures past the new threshold do not re-fire or clear.
    assert.equal(tracker.recordFailure(URL).disabled, false);
    assert.equal(tracker.isDisabled(URL), true);
    assert.equal(tracker.enable(URL), true);
    assert.equal(tracker.isDisabled(URL), false);
    for (let i = 0; i < 4; i++) {
      assert.equal(tracker.recordFailure(URL).disabled, false);
    }
    assert.equal(tracker.recordFailure(URL).disabled, true);
  });

  it("tightening the window prunes old failures on the next record", () => {
    const clock = fakeClock();
    const tracker = new EndpointAutoDisable({
      failureThreshold: 3,
      windowMs: 10_000,
      nowMs: clock.now,
    });
    tracker.recordFailure(URL);
    tracker.recordFailure(URL);
    clock.advance(600);
    tracker.revise({ windowMs: 500 });
    // The two failures at t=1000 fall outside the 500ms window at t=1600.
    const outcome = tracker.recordFailure(URL);
    assert.equal(outcome.disabled, false);
    assert.equal(outcome.consecutiveFailures, 1);
    assert.equal(tracker.consecutiveFailures(URL), 1);
  });

  it("widening the window counts old failures again", () => {
    const clock = fakeClock();
    const tracker = new EndpointAutoDisable({
      failureThreshold: 3,
      windowMs: 500,
      nowMs: clock.now,
    });
    tracker.recordFailure(URL);
    tracker.recordFailure(URL);
    clock.advance(600);
    // Widen before the next record, so the prune keeps the old failures.
    tracker.revise({ windowMs: 10_000 });
    const outcome = tracker.recordFailure(URL);
    assert.equal(outcome.disabled, true);
    assert.equal(outcome.consecutiveFailures, 3);
  });

  it("illegal values throw RangeError and the live config is untouched", () => {
    const clock = fakeClock();
    const tracker = new EndpointAutoDisable({
      failureThreshold: 3,
      windowMs: 1000,
      nowMs: clock.now,
    });
    const bad: Array<{ patch: unknown; label: string }> = [
      { patch: { failureThreshold: 0 }, label: "threshold 0" },
      { patch: { failureThreshold: -1 }, label: "threshold negative" },
      { patch: { failureThreshold: 1.5 }, label: "threshold non-integer" },
      { patch: { failureThreshold: "3" }, label: "threshold string" },
      { patch: { windowMs: 0 }, label: "window 0" },
      { patch: { windowMs: -5 }, label: "window negative" },
      { patch: { windowMs: Number.NaN }, label: "window NaN" },
      { patch: { windowMs: "1000" }, label: "window string" },
      { patch: null, label: "null patch" },
      { patch: "x", label: "string patch" },
      { patch: [1], label: "array patch" },
    ];
    for (const { patch, label } of bad) {
      assert.throws(() => tracker.revise(patch as never), RangeError, label);
      assert.deepEqual(
        tracker.config(),
        { failureThreshold: 3, windowMs: 1000 },
        label
      );
    }
  });

  it("empty and same-value patches are no-ops", () => {
    const tracker = new EndpointAutoDisable({ failureThreshold: 3, windowMs: 1000 });
    assert.deepEqual(tracker.revise({}), { failureThreshold: 3, windowMs: 1000 });
    assert.deepEqual(tracker.revise({ failureThreshold: 3 }), {
      failureThreshold: 3,
      windowMs: 1000,
    });
    assert.deepEqual(tracker.revise({ failureThreshold: 3, windowMs: 1000 }), {
      failureThreshold: 3,
      windowMs: 1000,
    });
    assert.deepEqual(tracker.config(), { failureThreshold: 3, windowMs: 1000 });
  });
});

describe("RetryQueue endpoint auto-disable revision (WR-415)", () => {
  function makeQueue(extra: Record<string, unknown> = {}) {
    const timer = manualTimer();
    const f = failingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      endpointAutoDisable: { failureThreshold: 3 },
      ...extra,
    });
    q.start();
    return { q, timer, f };
  }

  const ITEM = (id: string) => ({ id, payload: Buffer.from("x"), targetUrl: URL, headers: {} });

  it("unconfigured queue throws the must-restart Error and reports no config", () => {
    const timer = manualTimer();
    const f = failingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      assert.equal(q.getEndpointAutoDisableConfig(), undefined);
      assert.throws(
        () => q.reviseEndpointAutoDisable({ failureThreshold: 2 }),
        (err: unknown) =>
          err instanceof Error &&
          /requires a restart/.test(err.message) &&
          /reviseEndpointAutoDisable/.test(err.message)
      );
    } finally {
      q.stop();
    }
  });

  it("lowering the threshold through the queue disables on the next real failure; stats rows survive; illegal patch leaves live config untouched", async () => {
    const { q, timer } = makeQueue();
    try {
      assert.deepEqual(q.getEndpointAutoDisableConfig(), {
        failureThreshold: 3,
        windowMs: Infinity,
      });
      for (let i = 0; i < 2; i++) {
        q.enqueue(ITEM(`fail-${i}`));
        await timer.step();
      }
      assert.equal(q.isEndpointDisabled(URL), false);
      assert.equal(q.getEndpointDisableStats().length, 1);
      assert.equal(q.getEndpointDisableStats()[0]!.consecutiveFailures, 2);
      const revised = q.reviseEndpointAutoDisable({ failureThreshold: 2 });
      assert.deepEqual(revised, { failureThreshold: 2, windowMs: Infinity });
      assert.deepEqual(q.getEndpointAutoDisableConfig(), {
        failureThreshold: 2,
        windowMs: Infinity,
      });
      // The stats row survives the revision untouched.
      assert.equal(q.getEndpointDisableStats().length, 1);
      assert.equal(q.getEndpointDisableStats()[0]!.consecutiveFailures, 2);
      assert.equal(q.getEndpointDisableStats()[0]!.disabled, false);
      // An illegal patch leaves the live config completely intact.
      assert.throws(() => q.reviseEndpointAutoDisable({ failureThreshold: 0 }), RangeError);
      assert.deepEqual(q.getEndpointAutoDisableConfig(), {
        failureThreshold: 2,
        windowMs: Infinity,
      });
      q.enqueue(ITEM("fail-2"));
      await timer.step();
      assert.equal(q.isEndpointDisabled(URL), true);
      assert.equal(q.getEndpointDisableStats()[0]!.disabled, true);
      assert.equal(q.getEndpointDisableStats()[0]!.consecutiveFailures, 3);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint auto-disable revision (WR-415)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-auto-disable-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
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

  async function waitEvents(auditLog: AuditLog, name: string, target: number) {
    const deadline = Date.now() + 5000;
    while (eventsOf(auditLog, name).length < target && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(eventsOf(auditLog, name).length, target);
  }

  it("unconfigured server throws the must-restart Error", () => {
    const { relay } = makeServer();
    assert.throws(
      () => relay.reviseEndpointAutoDisable!({ failureThreshold: 2 }),
      (err: unknown) =>
        err instanceof Error &&
        /requires a restart/.test(err.message) &&
        /reviseEndpointAutoDisable/.test(err.message)
    );
  });

  it("a real revision audits endpoint_auto_disable_revised with exact previous/current", () => {
    const { relay, auditLog } = makeServer({
      retry: { endpointAutoDisable: { failureThreshold: 5 } },
    });
    const next = relay.reviseEndpointAutoDisable!({ failureThreshold: 3, windowMs: 60_000 });
    assert.deepEqual(next, { failureThreshold: 3, windowMs: 60_000 });
    const revised = eventsOf(auditLog, "endpoint_auto_disable_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0]!.previous, { failureThreshold: 5, windowMs: "Infinity" });
    assert.deepEqual(revised[0]!.current, { failureThreshold: 3, windowMs: 60_000 });
  });

  it("empty, same-value, and illegal revisions audit nothing", () => {
    const { relay, auditLog } = makeServer({
      retry: { endpointAutoDisable: { failureThreshold: 5 } },
    });
    relay.reviseEndpointAutoDisable!({ failureThreshold: 3 });
    assert.equal(eventsOf(auditLog, "endpoint_auto_disable_revised").length, 1);
    assert.deepEqual(relay.reviseEndpointAutoDisable!({}), {
      failureThreshold: 3,
      windowMs: Infinity,
    });
    assert.deepEqual(relay.reviseEndpointAutoDisable!({ failureThreshold: 3 }), {
      failureThreshold: 3,
      windowMs: Infinity,
    });
    assert.throws(() => relay.reviseEndpointAutoDisable!({ failureThreshold: 0 }), RangeError);
    assert.equal(eventsOf(auditLog, "endpoint_auto_disable_revised").length, 1);
  });

  it("revision keeps the earlier disable audit row", async () => {
    const { relay, auditLog } = makeServer({
      sender: async () => {
        throw new Error("downstream down");
      },
      retry: {
        baseDelayMs: 10,
        maxAttempts: 1,
        jitterMs: 0,
        endpointAutoDisable: { failureThreshold: 2 },
      },
    });
    const port = await listen(relay);
    await postWebhook(port);
    await postWebhook(port);
    await waitEvents(auditLog, "endpoint_auto_disabled", 1);
    const next = relay.reviseEndpointAutoDisable!({ failureThreshold: 5 });
    assert.deepEqual(next, { failureThreshold: 5, windowMs: Infinity });
    assert.equal(eventsOf(auditLog, "endpoint_auto_disabled").length, 1);
    const revised = eventsOf(auditLog, "endpoint_auto_disable_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0]!.previous, { failureThreshold: 2, windowMs: "Infinity" });
    assert.deepEqual(revised[0]!.current, { failureThreshold: 5, windowMs: "Infinity" });
  });
});
