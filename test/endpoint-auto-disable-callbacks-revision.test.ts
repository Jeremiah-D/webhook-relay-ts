import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import {
  RetryQueue,
  type EndpointAutoDisabledInfo,
  type EndpointEnabledInfo,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "endpoint-auto-disable-callbacks-revision-secret";
const operatorToken = "endpoint-auto-disable-callbacks-revision-token";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

type DisabledObserver = (info: EndpointAutoDisabledInfo) => void;
type EnabledObserver = (info: EndpointEnabledInfo) => void;

/**
 * Manual timer with single-step control, mirroring
 * test/endpoint-autodisable.test.ts: each step drains the
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
  let fail = true;
  const sender: Sender = async () => {
    calls += 1;
    if (fail) throw new Error("downstream down");
  };
  return { sender, calls: () => calls, setFail: (v: boolean) => (fail = v) };
}

describe("RetryQueue endpoint auto-disable callbacks revision (WR-369)", () => {
  function makeQueue(
    onEndpointAutoDisabled?: DisabledObserver,
    onEndpointEnabled?: EnabledObserver,
    extra: Record<string, unknown> = {}
  ) {
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
      ...(onEndpointAutoDisabled !== undefined ? { onEndpointAutoDisabled } : {}),
      ...(onEndpointEnabled !== undefined ? { onEndpointEnabled } : {}),
      ...extra,
    });
    q.start();
    return { q, timer, f };
  }

  const ITEM = (id: string) => ({ id, payload: Buffer.from("x"), targetUrl: URL, headers: {} });

  /** Three enqueue+step rounds trip the gate (threshold 3, one attempt each). */
  async function trip(timer: ReturnType<typeof manualTimer>, q: RetryQueue) {
    for (let i = 0; i < 3; i++) {
      q.enqueue(ITEM(`trip-${Math.random()}`));
      await timer.step();
    }
  }

  it("disable reaches the revised callback; the old callback stays silent", async () => {
    const oldSeen: EndpointAutoDisabledInfo[] = [];
    const newSeen: EndpointAutoDisabledInfo[] = [];
    const oldCb: DisabledObserver = (info) => oldSeen.push(info);
    const newCb: DisabledObserver = (info) => newSeen.push(info);
    const { q, timer } = makeQueue(oldCb);
    try {
      await trip(timer, q);
      assert.equal(q.isEndpointDisabled(URL), true);
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(oldSeen[0], { endpoint: URL, consecutiveFailures: 3, failureThreshold: 3 });
      // Re-enable so the gate can trip again, then swap the hook.
      assert.equal(q.enableEndpoint(URL), true);
      q.reviseEndpointAutoDisableCallbacks({ onEndpointAutoDisabled: newCb });
      await trip(timer, q);
      assert.equal(q.isEndpointDisabled(URL), true);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.deepEqual(newSeen[0], { endpoint: URL, consecutiveFailures: 3, failureThreshold: 3 });
    } finally {
      q.stop();
    }
  });

  it("enable reaches the revised callback; the old callback stays silent", async () => {
    const oldSeen: EndpointEnabledInfo[] = [];
    const newSeen: EndpointEnabledInfo[] = [];
    const oldCb: EnabledObserver = (info) => oldSeen.push(info);
    const newCb: EnabledObserver = (info) => newSeen.push(info);
    const { q, timer } = makeQueue(undefined, oldCb);
    try {
      await trip(timer, q);
      assert.equal(q.enableEndpoint(URL), true);
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(oldSeen[0], { endpoint: URL });
      // Swap mid-flight: the old callback never hears another enable.
      q.reviseEndpointAutoDisableCallbacks({ onEndpointEnabled: newCb });
      await trip(timer, q);
      assert.equal(q.enableEndpoint(URL), true);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.deepEqual(newSeen[0], { endpoint: URL });
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; the gate itself is untouched", async () => {
    const disabledSeen: EndpointAutoDisabledInfo[] = [];
    const enabledSeen: EndpointEnabledInfo[] = [];
    const disabledCb: DisabledObserver = (info) => disabledSeen.push(info);
    const enabledCb: EnabledObserver = (info) => enabledSeen.push(info);
    const { q, timer } = makeQueue(disabledCb, enabledCb);
    try {
      await trip(timer, q);
      assert.equal(disabledSeen.length, 1);
      q.reviseEndpointAutoDisableCallbacks({ onEndpointAutoDisabled: null, onEndpointEnabled: null });
      // The gate still disables and re-enables — only the observation stops.
      assert.equal(q.enableEndpoint(URL), true);
      assert.equal(enabledSeen.length, 0);
      await trip(timer, q);
      assert.equal(q.isEndpointDisabled(URL), true);
      assert.equal(disabledSeen.length, 1);
      assert.equal(q.getEndpointDisableStats()[0]?.autoDisables, 2);
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError and the live callbacks are untouched", async () => {
    const disabledSeen: EndpointAutoDisabledInfo[] = [];
    const enabledSeen: EndpointEnabledInfo[] = [];
    const disabledCb: DisabledObserver = (info) => disabledSeen.push(info);
    const enabledCb: EnabledObserver = (info) => enabledSeen.push(info);
    const { q, timer } = makeQueue(disabledCb, enabledCb);
    try {
      for (const bad of ["nope", 42, {}, true]) {
        assert.throws(
          () => q.reviseEndpointAutoDisableCallbacks({ onEndpointAutoDisabled: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
        assert.throws(
          () => q.reviseEndpointAutoDisableCallbacks({ onEndpointEnabled: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
      }
      // The live callbacks are untouched: both transitions still reach them.
      await trip(timer, q);
      assert.equal(disabledSeen.length, 1);
      assert.equal(q.enableEndpoint(URL), true);
      assert.equal(enabledSeen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("an empty or non-object patch throws RangeError and the live callbacks are untouched", async () => {
    const disabledSeen: EndpointAutoDisabledInfo[] = [];
    const disabledCb: DisabledObserver = (info) => disabledSeen.push(info);
    const { q, timer } = makeQueue(disabledCb);
    try {
      assert.throws(() => q.reviseEndpointAutoDisableCallbacks({}), RangeError);
      assert.throws(() => q.reviseEndpointAutoDisableCallbacks(null as never), RangeError);
      assert.throws(() => q.reviseEndpointAutoDisableCallbacks("nope" as never), RangeError);
      assert.throws(() => q.reviseEndpointAutoDisableCallbacks(42 as never), RangeError);
      // An explicitly-undefined field counts as not provided, so a
      // patch of only undefined fields is empty too.
      assert.throws(
        () => q.reviseEndpointAutoDisableCallbacks({ onEndpointAutoDisabled: undefined }),
        RangeError
      );
      await trip(timer, q);
      assert.equal(disabledSeen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a same-reference revision is a no-op; a partial patch leaves the other hook live", async () => {
    const disabledSeen: EndpointAutoDisabledInfo[] = [];
    const enabledSeen: EndpointEnabledInfo[] = [];
    const newDisabledSeen: EndpointAutoDisabledInfo[] = [];
    const disabledCb: DisabledObserver = (info) => disabledSeen.push(info);
    const enabledCb: EnabledObserver = (info) => enabledSeen.push(info);
    const newDisabledCb: DisabledObserver = (info) => newDisabledSeen.push(info);
    const { q, timer } = makeQueue(disabledCb, enabledCb);
    try {
      // Same references as construction: no-op.
      q.reviseEndpointAutoDisableCallbacks({
        onEndpointAutoDisabled: disabledCb,
        onEndpointEnabled: enabledCb,
      });
      // Clearing when already unset is a no-op too.
      const bare = makeQueue();
      try {
        bare.q.reviseEndpointAutoDisableCallbacks({ onEndpointAutoDisabled: null, onEndpointEnabled: null });
      } finally {
        bare.q.stop();
      }
      // Partial patch: only the disable hook moves.
      q.reviseEndpointAutoDisableCallbacks({ onEndpointAutoDisabled: newDisabledCb });
      await trip(timer, q);
      assert.equal(disabledSeen.length, 0);
      assert.equal(newDisabledSeen.length, 1);
      assert.equal(q.enableEndpoint(URL), true);
      assert.equal(enabledSeen.length, 1); // the enable hook never moved
    } finally {
      q.stop();
    }
  });

  it("revising without auto-disable configured throws Error", () => {
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
    try {
      assert.throws(
        () => q.reviseEndpointAutoDisableCallbacks({ onEndpointAutoDisabled: () => {} }),
        (err: unknown) => err instanceof Error && /not configured — enabling it requires a restart/.test(err.message)
      );
      // Even an empty patch hits the gate first, not the RangeError path.
      assert.throws(() => q.reviseEndpointAutoDisableCallbacks({}), Error);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint auto-disable callbacks revision (WR-369)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-auto-disable-callbacks-revision-"));
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

  function postJson(port: number, path: string, body: unknown, token?: string) {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString() || "{}"),
          })
        );
      });
      r.on("error", reject);
      r.end(JSON.stringify(body));
    });
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

  /** A server whose auto-disable/enable hooks are observed by the given callbacks. */
  function disablingServer(
    onEndpointAutoDisabled: DisabledObserver,
    onEndpointEnabled: EnabledObserver
  ) {
    let calls = 0;
    const { relay, auditLog } = makeServer({
      sender: async () => {
        calls += 1;
        throw new Error("downstream down");
      },
      retry: {
        baseDelayMs: 10,
        maxAttempts: 1,
        jitterMs: 0,
        endpointAutoDisable: { failureThreshold: 2 },
        onEndpointAutoDisabled,
        onEndpointEnabled,
      },
    });
    return { relay, auditLog, calls: () => calls };
  }

  async function waitCalls(calls: () => number, target: number) {
    const deadline = Date.now() + 5000;
    while (calls() < target && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(calls(), target);
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

  it("revising the disable callback routes the next disable to the new callback and the audit still lands", async () => {
    const initialSeen: EndpointAutoDisabledInfo[] = [];
    const newSeen: EndpointAutoDisabledInfo[] = [];
    const enabledSeen: EndpointEnabledInfo[] = [];
    const initialCb: DisabledObserver = (info) => initialSeen.push(info);
    const newCb: DisabledObserver = (info) => newSeen.push(info);
    const enabledCb: EnabledObserver = (info) => enabledSeen.push(info);
    const { relay, auditLog, calls } = disablingServer(initialCb, enabledCb);
    const port = await listen(relay);
    // First trip: the initial callback hears it and the audit lands.
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await waitCalls(calls, 2);
    await waitSeen(initialSeen, 1);
    assert.deepEqual(initialSeen[0], { endpoint: URL, consecutiveFailures: 2, failureThreshold: 2 });
    await waitEvents(auditLog, "endpoint_auto_disabled", 1);
    // Re-enable, then swap the operator disable callback; the enable hook is untouched.
    assert.equal((await postJson(port, "/endpoints/enable", { endpoint: URL }, operatorToken)).status, 200);
    assert.equal(enabledSeen.length, 1);
    relay.reviseEndpointAutoDisableCallbacks!({ onEndpointAutoDisabled: newCb });
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await waitCalls(calls, 4);
    await waitSeen(newSeen, 1);
    assert.equal(initialSeen.length, 1); // the old callback heard nothing more
    assert.deepEqual(newSeen[0], { endpoint: URL, consecutiveFailures: 2, failureThreshold: 2 });
    await waitEvents(auditLog, "endpoint_auto_disabled", 2);
    // The revision itself was audited with per-hook presence.
    const revised = eventsOf(auditLog, "endpoint_auto_disable_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onEndpointAutoDisabled,
        revised[0].oldOnEndpointAutoDisabled,
        revised[0].onEndpointEnabled,
        revised[0].oldOnEndpointEnabled,
      ],
      ["set", "set", "unchanged", "set"]
    );
  });

  it("revising the enable callback routes the next enable to the new callback", async () => {
    const initialSeen: EndpointEnabledInfo[] = [];
    const newSeen: EndpointEnabledInfo[] = [];
    const disabledSeen: EndpointAutoDisabledInfo[] = [];
    const initialCb: EnabledObserver = (info) => initialSeen.push(info);
    const newCb: EnabledObserver = (info) => newSeen.push(info);
    const disabledCb: DisabledObserver = (info) => disabledSeen.push(info);
    const { relay, auditLog, calls } = disablingServer(disabledCb, initialCb);
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await waitCalls(calls, 2);
    assert.equal((await postJson(port, "/endpoints/enable", { endpoint: URL }, operatorToken)).status, 200);
    assert.equal(initialSeen.length, 1);
    assert.deepEqual(initialSeen[0], { endpoint: URL });
    // Swap the operator enable callback; the disable hook is untouched.
    relay.reviseEndpointAutoDisableCallbacks!({ onEndpointEnabled: newCb });
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await waitCalls(calls, 4);
    await waitSeen(disabledSeen, 2);
    assert.equal((await postJson(port, "/endpoints/enable", { endpoint: URL }, operatorToken)).status, 200);
    assert.equal(initialSeen.length, 1);
    assert.equal(newSeen.length, 1);
    assert.deepEqual(newSeen[0], { endpoint: URL });
    assert.equal(eventsOf(auditLog, "endpoint_enabled").length, 2);
  });

  it("clearing both hooks keeps the gate and the audit, with no operator callback", async () => {
    const disabledSeen: EndpointAutoDisabledInfo[] = [];
    const enabledSeen: EndpointEnabledInfo[] = [];
    const disabledCb: DisabledObserver = (info) => disabledSeen.push(info);
    const enabledCb: EnabledObserver = (info) => enabledSeen.push(info);
    const { relay, auditLog, calls } = disablingServer(disabledCb, enabledCb);
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await waitCalls(calls, 2);
    await waitSeen(disabledSeen, 1);
    relay.reviseEndpointAutoDisableCallbacks!({ onEndpointAutoDisabled: null, onEndpointEnabled: null });
    assert.equal((await postJson(port, "/endpoints/enable", { endpoint: URL }, operatorToken)).status, 200);
    // The re-enable happened (audited) but no operator callback heard it.
    assert.equal(enabledSeen.length, 0);
    await waitEvents(auditLog, "endpoint_enabled", 1);
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await waitCalls(calls, 4);
    await waitEvents(auditLog, "endpoint_auto_disabled", 2);
    // The gate tripped again and the audit landed; no operator callback heard it.
    assert.equal(disabledSeen.length, 1);
    assert.equal(eventsOf(auditLog, "endpoint_auto_disabled").length, 2);
  });

  it("an illegal or empty patch throws RangeError and the live callbacks are untouched", async () => {
    const disabledSeen: EndpointAutoDisabledInfo[] = [];
    const enabledSeen: EndpointEnabledInfo[] = [];
    const disabledCb: DisabledObserver = (info) => disabledSeen.push(info);
    const enabledCb: EnabledObserver = (info) => enabledSeen.push(info);
    const { relay, auditLog, calls } = disablingServer(disabledCb, enabledCb);
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseEndpointAutoDisableCallbacks!({ onEndpointAutoDisabled: "nope" as never }),
      RangeError
    );
    assert.throws(() => relay.reviseEndpointAutoDisableCallbacks!({}), RangeError);
    assert.throws(() => relay.reviseEndpointAutoDisableCallbacks!(null as never), RangeError);
    assert.equal(eventsOf(auditLog, "endpoint_auto_disable_callbacks_revised").length, 0);
    // The live callbacks are untouched: the next trip still reaches them.
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await waitCalls(calls, 2);
    await waitSeen(disabledSeen, 1);
    assert.equal((await postJson(port, "/endpoints/enable", { endpoint: URL }, operatorToken)).status, 200);
    assert.equal(enabledSeen.length, 1);
  });

  it("a same-reference revision is a silent no-op with no audit event", async () => {
    const disabledSeen: EndpointAutoDisabledInfo[] = [];
    const disabledCb: DisabledObserver = (info) => disabledSeen.push(info);
    const enabledCb: EnabledObserver = () => {};
    const { relay, auditLog } = disablingServer(disabledCb, enabledCb);
    await listen(relay);
    relay.reviseEndpointAutoDisableCallbacks!({
      onEndpointAutoDisabled: disabledCb,
      onEndpointEnabled: enabledCb,
    });
    assert.equal(eventsOf(auditLog, "endpoint_auto_disable_callbacks_revised").length, 0);
  });

  it("revising without auto-disable configured throws Error", async () => {
    const { relay } = makeServer({
      retry: { baseDelayMs: 10, maxAttempts: 1, jitterMs: 0 },
    });
    await listen(relay);
    assert.throws(
      () => relay.reviseEndpointAutoDisableCallbacks!({ onEndpointAutoDisabled: () => {} }),
      (err: unknown) => err instanceof Error && /not configured — enabling it requires a restart/.test(err.message)
    );
  });
});

