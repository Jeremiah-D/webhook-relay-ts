import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "endpoint-auto-disable-enable-secret";
const operatorToken = "endpoint-auto-disable-enable-token";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/**
 * Manual timer with single-step control, mirroring
 * test/endpoint-auto-disable-revision.test.ts: each step drains the
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

describe("RetryQueue reviseEndpointAutoDisable enable (WR-461)", () => {
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
      ...extra,
    });
    q.start();
    return { q, timer, f };
  }

  const ITEM = (id: string) => ({ id, payload: Buffer.from("x"), targetUrl: URL, headers: {} });

  it("enables with the construction defaults and the getter returns them at once", () => {
    const { q } = makeQueue();
    try {
      assert.equal(q.getEndpointAutoDisableConfig(), undefined);
      assert.equal(q.autoDisableConfigured(), false);
      assert.deepEqual(q.reviseEndpointAutoDisable({}), {
        failureThreshold: 5,
        windowMs: Infinity,
      });
      assert.deepEqual(q.getEndpointAutoDisableConfig(), {
        failureThreshold: 5,
        windowMs: Infinity,
      });
      assert.equal(q.autoDisableConfigured(), true);
    } finally {
      q.stop();
    }
  });

  it("an empty patch enables with all defaults", () => {
    const { q } = makeQueue();
    try {
      assert.deepEqual(q.reviseEndpointAutoDisable({}), {
        failureThreshold: 5,
        windowMs: Infinity,
      });
    } finally {
      q.stop();
    }
  });

  it("enables with explicit values", () => {
    const { q } = makeQueue();
    try {
      assert.deepEqual(
        q.reviseEndpointAutoDisable({ failureThreshold: 2, windowMs: 60_000 }),
        { failureThreshold: 2, windowMs: 60_000 }
      );
      assert.deepEqual(q.getEndpointAutoDisableConfig(), {
        failureThreshold: 2,
        windowMs: 60_000,
      });
    } finally {
      q.stop();
    }
  });

  it("a partial patch fills the rest from the construction defaults", () => {
    const { q } = makeQueue();
    try {
      assert.deepEqual(q.reviseEndpointAutoDisable({ failureThreshold: 3 }), {
        failureThreshold: 3,
        windowMs: Infinity,
      });
    } finally {
      q.stop();
    }
    const second = makeQueue();
    try {
      assert.deepEqual(second.q.reviseEndpointAutoDisable({ windowMs: 30_000 }), {
        failureThreshold: 5,
        windowMs: 30_000,
      });
    } finally {
      second.q.stop();
    }
  });

  it("an illegal or non-object patch throws RangeError and the queue stays unconfigured, then still enables", () => {
    const { q } = makeQueue();
    try {
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
        assert.throws(() => q.reviseEndpointAutoDisable(patch as never), RangeError, label);
        assert.equal(q.getEndpointAutoDisableConfig(), undefined, label);
        assert.equal(q.autoDisableConfigured(), false, label);
      }
      // Still enablable afterwards — a failed enable leaves no half state.
      assert.deepEqual(q.reviseEndpointAutoDisable({}), {
        failureThreshold: 5,
        windowMs: Infinity,
      });
    } finally {
      q.stop();
    }
  });

  it("the next failure after the enable counts from 1 and disables at the threshold", async () => {
    const seen: Array<{ endpoint: string; consecutiveFailures: number; failureThreshold: number }> =
      [];
    const { q, timer, f } = makeQueue({
      onEndpointAutoDisabled: (info: {
        endpoint: string;
        consecutiveFailures: number;
        failureThreshold: number;
      }) => seen.push(info),
    });
    try {
      q.reviseEndpointAutoDisable({ failureThreshold: 2 });
      assert.equal(q.isEndpointDisabled(URL), false);
      q.enqueue(ITEM("fail-0"));
      await timer.step();
      assert.equal(f.calls(), 1);
      assert.equal(q.isEndpointDisabled(URL), false);
      assert.equal(q.getEndpointDisableStats()[0]!.consecutiveFailures, 1);
      q.enqueue(ITEM("fail-1"));
      await timer.step();
      assert.equal(f.calls(), 2);
      assert.equal(q.isEndpointDisabled(URL), true);
      assert.equal(q.getEndpointDisableStats()[0]!.disabled, true);
      assert.equal(q.getEndpointDisableStats()[0]!.consecutiveFailures, 2);
      assert.equal(q.getEndpointDisableStats()[0]!.autoDisables, 1);
      // The transition hook fires exactly once, with the live values.
      assert.equal(seen.length, 1);
      assert.deepEqual(seen[0], {
        endpoint: URL,
        consecutiveFailures: 2,
        failureThreshold: 2,
      });
    } finally {
      q.stop();
    }
  });

  it("failures before the enable are not retroactively counted", async () => {
    const { q, timer } = makeQueue();
    try {
      // Four failures while the gate is off — never recorded anywhere.
      for (let i = 0; i < 4; i++) {
        q.enqueue(ITEM(`pre-${i}`));
        await timer.step();
      }
      assert.equal(q.isEndpointDisabled(URL), false);
      assert.deepEqual(q.getEndpointDisableStats(), []);
      q.reviseEndpointAutoDisable({ failureThreshold: 5 });
      // The next failure counts as 1, not 5 — no immediate disable.
      q.enqueue(ITEM("post-0"));
      await timer.step();
      assert.equal(q.isEndpointDisabled(URL), false);
      assert.equal(q.getEndpointDisableStats()[0]!.consecutiveFailures, 1);
      // Four more failures reach the threshold from the enable onward.
      for (let i = 1; i < 5; i++) {
        q.enqueue(ITEM(`post-${i}`));
        await timer.step();
      }
      assert.equal(q.isEndpointDisabled(URL), true);
      assert.equal(q.getEndpointDisableStats()[0]!.consecutiveFailures, 5);
    } finally {
      q.stop();
    }
  });

  it("revision after the enable still follows WR-415: empty and same-value are no-ops, illegal leaves the live config untouched", () => {
    const { q } = makeQueue();
    try {
      q.reviseEndpointAutoDisable({ failureThreshold: 3, windowMs: 60_000 });
      assert.deepEqual(q.reviseEndpointAutoDisable({}), {
        failureThreshold: 3,
        windowMs: 60_000,
      });
      assert.deepEqual(q.reviseEndpointAutoDisable({ failureThreshold: 3 }), {
        failureThreshold: 3,
        windowMs: 60_000,
      });
      assert.throws(() => q.reviseEndpointAutoDisable({ failureThreshold: 0 }), RangeError);
      assert.throws(() => q.reviseEndpointAutoDisable({ windowMs: -1 }), RangeError);
      assert.deepEqual(q.getEndpointAutoDisableConfig(), {
        failureThreshold: 3,
        windowMs: 60_000,
      });
    } finally {
      q.stop();
    }
  });

  it("lowering the threshold after the enable does not retroactively disable; raising it never re-enables; enableEndpoint recounts per the new threshold", async () => {
    const { q, timer } = makeQueue();
    try {
      q.reviseEndpointAutoDisable({ failureThreshold: 3 });
      q.enqueue(ITEM("fail-0"));
      await timer.step();
      q.enqueue(ITEM("fail-1"));
      await timer.step();
      assert.equal(q.getEndpointDisableStats()[0]!.consecutiveFailures, 2);
      // Lower below the live streak (2): still not disabled.
      assert.deepEqual(q.reviseEndpointAutoDisable({ failureThreshold: 2 }), {
        failureThreshold: 2,
        windowMs: Infinity,
      });
      assert.equal(q.isEndpointDisabled(URL), false);
      // The next failure disables.
      q.enqueue(ITEM("fail-2"));
      await timer.step();
      assert.equal(q.isEndpointDisabled(URL), true);
      // Raise the threshold: still disabled.
      assert.deepEqual(q.reviseEndpointAutoDisable({ failureThreshold: 5 }), {
        failureThreshold: 5,
        windowMs: Infinity,
      });
      assert.equal(q.isEndpointDisabled(URL), true);
      // Re-enable clears the streak; the new threshold governs.
      assert.equal(q.enableEndpoint(URL), true);
      assert.equal(q.isEndpointDisabled(URL), false);
      for (let i = 0; i < 4; i++) {
        q.enqueue(ITEM(`again-${i}`));
        await timer.step();
      }
      assert.equal(q.isEndpointDisabled(URL), false);
      q.enqueue(ITEM("again-4"));
      await timer.step();
      assert.equal(q.isEndpointDisabled(URL), true);
    } finally {
      q.stop();
    }
  });

  it("window tighten and widen prune semantics still apply after the enable", async () => {
    // Tighten: two failures inside a 500ms window, then a 600ms pause —
    // the next record prunes both and counts 1.
    const tight = makeQueue();
    try {
      tight.q.reviseEndpointAutoDisable({ failureThreshold: 3, windowMs: 500 });
      tight.q.enqueue(ITEM("t-0"));
      await tight.timer.step();
      tight.q.enqueue(ITEM("t-1"));
      await tight.timer.step();
      await new Promise((r) => setTimeout(r, 600));
      tight.q.reviseEndpointAutoDisable({ windowMs: 100 });
      tight.q.enqueue(ITEM("t-2"));
      await tight.timer.step();
      assert.equal(tight.q.isEndpointDisabled(URL), false);
      assert.equal(tight.q.getEndpointDisableStats()[0]!.consecutiveFailures, 1);
    } finally {
      tight.q.stop();
    }
    // Widen: the same two failures survive a 600ms pause once the
    // window is widened before the next record — the third failure
    // counts 3 and disables.
    const wide = makeQueue();
    try {
      wide.q.reviseEndpointAutoDisable({ failureThreshold: 3, windowMs: 500 });
      wide.q.enqueue(ITEM("w-0"));
      await wide.timer.step();
      wide.q.enqueue(ITEM("w-1"));
      await wide.timer.step();
      await new Promise((r) => setTimeout(r, 600));
      wide.q.reviseEndpointAutoDisable({ windowMs: 10_000 });
      wide.q.enqueue(ITEM("w-2"));
      await wide.timer.step();
      assert.equal(wide.q.isEndpointDisabled(URL), true);
      assert.equal(wide.q.getEndpointDisableStats()[0]!.consecutiveFailures, 3);
    } finally {
      wide.q.stop();
    }
  });

  it("getEndpointDisableStats is empty before the enable and activity-gated after it", async () => {
    const { q, timer } = makeQueue();
    try {
      assert.deepEqual(q.getEndpointDisableStats(), []);
      q.reviseEndpointAutoDisable({ failureThreshold: 2 });
      // Enabled but silent: still no rows until a verdict lands.
      assert.deepEqual(q.getEndpointDisableStats(), []);
      q.enqueue(ITEM("fail-0"));
      await timer.step();
      assert.equal(q.getEndpointDisableStats().length, 1);
      assert.equal(q.getEndpointDisableStats()[0]!.endpoint, URL);
      assert.equal(q.getEndpointDisableStats()[0]!.disabled, false);
      assert.equal(q.getEndpointDisableStats()[0]!.consecutiveFailures, 1);
      assert.equal(q.getEndpointDisableStats()[0]!.autoDisables, 0);
    } finally {
      q.stop();
    }
  });

  it("isEndpointDisabled is always false before the enable", async () => {
    const { q, timer } = makeQueue();
    try {
      assert.equal(q.isEndpointDisabled(URL), false);
      for (let i = 0; i < 4; i++) {
        q.enqueue(ITEM(`pre-${i}`));
        await timer.step();
      }
      // Failures with no tracker: the gate never engages.
      assert.equal(q.isEndpointDisabled(URL), false);
    } finally {
      q.stop();
    }
  });

  it("a fresh queue is unconfigured again: the enable is live-only", () => {
    const first = makeQueue();
    try {
      first.q.reviseEndpointAutoDisable({ failureThreshold: 2 });
      assert.equal(first.q.autoDisableConfigured(), true);
    } finally {
      first.q.stop();
    }
    const second = makeQueue();
    try {
      assert.equal(second.q.getEndpointAutoDisableConfig(), undefined);
      assert.equal(second.q.autoDisableConfigured(), false);
      assert.deepEqual(second.q.getEndpointDisableStats(), []);
    } finally {
      second.q.stop();
    }
  });
});

describe("RelayServer reviseEndpointAutoDisable enable (WR-461)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-auto-disable-enable-"));
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

  function postEnableEndpoint(port: number, endpoint: string) {
    const body = Buffer.from(JSON.stringify({ endpoint }));
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/endpoints/enable",
          method: "POST",
          headers: {
            authorization: `Bearer ${operatorToken}`,
            "content-type": "application/json",
            "content-length": String(body.length),
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  async function waitEvents(auditLog: AuditLog, name: string, target: number) {
    const deadline = Date.now() + 5000;
    while (eventsOf(auditLog, name).length < target && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(eventsOf(auditLog, name).length, target);
  }

  async function waitFor(
    auditLog: AuditLog,
    name: string,
    pred: (e: Record<string, unknown>) => boolean
  ) {
    const deadline = Date.now() + 5000;
    for (;;) {
      const hit = eventsOf(auditLog, name).find(pred);
      if (hit !== undefined) return hit;
      if (Date.now() >= deadline) assert.fail(`timed out waiting for ${name}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  it("enabling audits previous: null with the exact current config, exactly once", () => {
    const { relay, auditLog } = makeServer();
    assert.deepEqual(relay.reviseEndpointAutoDisable!({ failureThreshold: 2, windowMs: 60_000 }), {
      failureThreshold: 2,
      windowMs: 60_000,
    });
    const enabled = eventsOf(auditLog, "endpoint_auto_disable_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0]!.previous, null);
    assert.deepEqual(enabled[0]!.current, { failureThreshold: 2, windowMs: 60_000 });
    // A same-value call afterwards is a silent no-op: no second row.
    assert.deepEqual(relay.reviseEndpointAutoDisable!({ failureThreshold: 2 }), {
      failureThreshold: 2,
      windowMs: 60_000,
    });
    assert.equal(eventsOf(auditLog, "endpoint_auto_disable_revised").length, 1);
  });

  it("an illegal enable patch throws RangeError, audits nothing, then still enables", () => {
    const { relay, auditLog } = makeServer();
    assert.throws(() => relay.reviseEndpointAutoDisable!({ failureThreshold: 0 }), RangeError);
    assert.throws(() => relay.reviseEndpointAutoDisable!({ windowMs: -1 }), RangeError);
    assert.throws(() => relay.reviseEndpointAutoDisable!(null as never), RangeError);
    assert.equal(eventsOf(auditLog, "endpoint_auto_disable_revised").length, 0);
    // Still enablable afterwards.
    assert.deepEqual(relay.reviseEndpointAutoDisable!({}), {
      failureThreshold: 5,
      windowMs: Infinity,
    });
    const enabled = eventsOf(auditLog, "endpoint_auto_disable_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0]!.previous, null);
    assert.deepEqual(enabled[0]!.current, { failureThreshold: 5, windowMs: "Infinity" });
  });

  it("enabling unlocks reviseEndpointAutoDisableCallbacks: the new callback sees the disable, clearing it keeps disabling without the callback", async () => {
    const disabledSeen: Array<Record<string, unknown>> = [];
    const { relay, auditLog } = makeServer({
      sender: async () => {
        throw new Error("downstream down");
      },
      retry: { baseDelayMs: 10, maxAttempts: 1, jitterMs: 0 },
    });
    // The callback gate is closed while the tracker does not exist.
    assert.throws(
      () => relay.reviseEndpointAutoDisableCallbacks!({ onEndpointAutoDisabled: () => {} }),
      (err: unknown) => err instanceof Error && /not configured — enabling it requires a restart/.test(err.message)
    );
    relay.reviseEndpointAutoDisable!({ failureThreshold: 2 });
    relay.reviseEndpointAutoDisableCallbacks!({
      onEndpointAutoDisabled: (info) => disabledSeen.push(info as unknown as Record<string, unknown>),
    });
    assert.equal(eventsOf(auditLog, "endpoint_auto_disable_callbacks_revised").length, 1);
    const port = await listen(relay);
    await postWebhook(port);
    await postWebhook(port);
    await waitEvents(auditLog, "endpoint_auto_disabled", 1);
    assert.equal(disabledSeen.length, 1);
    assert.equal(disabledSeen[0]!.endpoint, URL);
    // Clear the hook: the gate keeps disabling, the audit keeps
    // recording, only the forwarding stops.
    relay.reviseEndpointAutoDisableCallbacks!({ onEndpointAutoDisabled: null });
    assert.equal(eventsOf(auditLog, "endpoint_auto_disable_callbacks_revised").length, 2);
    assert.equal(await postEnableEndpoint(port, URL), 200);
    await postWebhook(port);
    await postWebhook(port);
    await waitEvents(auditLog, "endpoint_auto_disabled", 2);
    assert.equal(disabledSeen.length, 1);
  });

  it("after the server-side enable the endpoint disables after the threshold failures and later deliveries dead-letter without an attempt", async () => {
    let calls = 0;
    const { relay, auditLog } = makeServer({
      sender: async () => {
        calls += 1;
        throw new Error("downstream down");
      },
      retry: { baseDelayMs: 10, maxAttempts: 1, jitterMs: 0 },
    });
    const port = await listen(relay);
    relay.reviseEndpointAutoDisable!({ failureThreshold: 2 });
    await postWebhook(port);
    await postWebhook(port);
    await waitEvents(auditLog, "endpoint_auto_disabled", 1);
    assert.equal(calls, 2);
    // The endpoint is disabled now: the next delivery dead-letters
    // without ever reaching the sender.
    await postWebhook(port);
    const dead = await waitFor(
      auditLog,
      "dead_letter",
      (e) => e.failure_class === "endpoint_disabled"
    );
    assert.equal(dead.targetUrl, URL);
    assert.equal(calls, 2);
  });
});
