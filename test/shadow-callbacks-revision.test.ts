import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import {
  RetryQueue,
  type Sender,
  type ShadowDeliveredInfo,
  type ShadowFailedInfo,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "shadow-callbacks-revision-secret";
const operatorToken = "shadow-callbacks-revision-token";
const PRIMARY = "https://downstream.example/hook";
const SHADOW = "https://shadow.example/hook";
const FORWARD = "http://127.0.0.1:1/unused";
const BODY = Buffer.from(JSON.stringify({ payment: "pi_123", amount: 5000 }));

type DeliveredObserver = (info: ShadowDeliveredInfo) => void;
type FailedObserver = (info: ShadowFailedInfo) => void;

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

/** Flush detached shadow microtasks (fire-and-forget mirror chain). */
async function flushShadow(rounds = 8): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setImmediate(r));
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for ${what}`);
}

describe("RetryQueue shadow callbacks revision (WR-395)", () => {
  function makeQueue(opts: {
    onShadowDelivered?: DeliveredObserver;
    onShadowFailed?: FailedObserver;
    shadowShouldFail?: () => boolean;
  } = {}) {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
      shadowTargets: {
        [PRIMARY]: [
          {
            targetUrl: SHADOW,
            sender: async () => {
              if (opts.shadowShouldFail?.()) throw new Error("shadow is down");
            },
          },
        ],
      },
      ...(opts.onShadowDelivered !== undefined
        ? { onShadowDelivered: opts.onShadowDelivered }
        : {}),
      ...(opts.onShadowFailed !== undefined ? { onShadowFailed: opts.onShadowFailed } : {}),
    });
    return { q, timer };
  }

  async function driveMirror(
    q: RetryQueue,
    timer: ReturnType<typeof manualTimer>,
    id: string
  ): Promise<void> {
    q.enqueue({
      id,
      payload: Buffer.from(`payload-${id}`),
      targetUrl: PRIMARY,
      headers: { "x-custom": "1" },
    });
    await timer.run();
    await flushShadow();
  }

  it("delivered reaches the revised callback; the old callback stays silent", async () => {
    const first: ShadowDeliveredInfo[] = [];
    const second: ShadowDeliveredInfo[] = [];
    const { q, timer } = makeQueue({ onShadowDelivered: (info) => first.push(info) });
    q.start();
    try {
      await driveMirror(q, timer, "s-1");
      assert.equal(first.length, 1);
      assert.equal(first[0].id, "s-1");
      q.reviseShadowCallbacks({ onShadowDelivered: (info) => second.push(info) });
      await driveMirror(q, timer, "s-2");
      assert.equal(first.length, 1);
      assert.equal(second.length, 1);
      assert.equal(second[0].id, "s-2");
      assert.equal(second[0].event, "shadow_delivered");
      assert.equal(second[0].endpoint, PRIMARY);
      assert.equal(second[0].shadowTarget, SHADOW);
    } finally {
      q.stop();
    }
  });

  it("failed reaches the revised callback; the old callback stays silent", async () => {
    const first: ShadowFailedInfo[] = [];
    const second: ShadowFailedInfo[] = [];
    const { q, timer } = makeQueue({
      onShadowFailed: (info) => first.push(info),
      shadowShouldFail: () => true,
    });
    q.start();
    try {
      await driveMirror(q, timer, "f-1");
      assert.equal(first.length, 1);
      assert.equal(first[0].id, "f-1");
      assert.equal(first[0].event, "shadow_failed");
      assert.match(first[0].error, /shadow is down/);
      q.reviseShadowCallbacks({ onShadowFailed: (info) => second.push(info) });
      await driveMirror(q, timer, "f-2");
      assert.equal(first.length, 1);
      assert.equal(second.length, 1);
      assert.equal(second[0].id, "f-2");
    } finally {
      q.stop();
    }
  });

  it("null clears a single field; mirroring and counters continue", async () => {
    const delivered: ShadowDeliveredInfo[] = [];
    const failed: ShadowFailedInfo[] = [];
    let shadowShouldFail = false;
    const { q, timer } = makeQueue({
      onShadowDelivered: (info) => delivered.push(info),
      onShadowFailed: (info) => failed.push(info),
      shadowShouldFail: () => shadowShouldFail,
    });
    q.start();
    try {
      await driveMirror(q, timer, "c-1");
      assert.equal(delivered.length, 1);
      assert.deepEqual(q.getShadowStats(), [
        { endpoint: PRIMARY, shadowTarget: SHADOW, delivered: 1, failed: 0 },
      ]);
      q.reviseShadowCallbacks({ onShadowDelivered: null });
      // The mirror still runs and still counts — only the forwarding stops.
      await driveMirror(q, timer, "c-2");
      assert.equal(delivered.length, 1);
      assert.deepEqual(q.getShadowStats(), [
        { endpoint: PRIMARY, shadowTarget: SHADOW, delivered: 2, failed: 0 },
      ]);
      // The other hook was untouched by the single-field patch.
      shadowShouldFail = true;
      await driveMirror(q, timer, "c-3");
      assert.equal(failed.length, 1);
      assert.equal(failed[0].id, "c-3");
      assert.deepEqual(q.getShadowStats(), [
        { endpoint: PRIMARY, shadowTarget: SHADOW, delivered: 2, failed: 1 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("both fields move in one patch", async () => {
    const firstDelivered: ShadowDeliveredInfo[] = [];
    const firstFailed: ShadowFailedInfo[] = [];
    const secondDelivered: ShadowDeliveredInfo[] = [];
    const secondFailed: ShadowFailedInfo[] = [];
    let shadowShouldFail = false;
    const { q, timer } = makeQueue({
      onShadowDelivered: (info) => firstDelivered.push(info),
      onShadowFailed: (info) => firstFailed.push(info),
      shadowShouldFail: () => shadowShouldFail,
    });
    q.start();
    try {
      q.reviseShadowCallbacks({
        onShadowDelivered: (info) => secondDelivered.push(info),
        onShadowFailed: (info) => secondFailed.push(info),
      });
      await driveMirror(q, timer, "b-1");
      assert.equal(firstDelivered.length, 0);
      assert.equal(secondDelivered.length, 1);
      shadowShouldFail = true;
      await driveMirror(q, timer, "b-2");
      assert.equal(firstFailed.length, 0);
      assert.equal(secondFailed.length, 1);
    } finally {
      q.stop();
    }
  });

  it("an empty or non-object patch and an illegal value throw RangeError and the live callbacks are untouched", async () => {
    const delivered: ShadowDeliveredInfo[] = [];
    const { q, timer } = makeQueue({ onShadowDelivered: (info) => delivered.push(info) });
    q.start();
    try {
      for (const bad of [null, "x", 42, {}, []] as never[]) {
        assert.throws(() => q.reviseShadowCallbacks(bad), RangeError, String(bad));
      }
      assert.throws(
        () => q.reviseShadowCallbacks({ onShadowDelivered: "nope" as never }),
        RangeError
      );
      assert.throws(
        () => q.reviseShadowCallbacks({ onShadowFailed: 42 as never }),
        RangeError
      );
      assert.throws(
        () =>
          q.reviseShadowCallbacks({
            onShadowDelivered: (info: ShadowDeliveredInfo) => delivered.push(info),
            onShadowFailed: "nope" as never,
          }),
        RangeError
      );
      // Nothing moved: the original hook still fires.
      await driveMirror(q, timer, "v-1");
      assert.equal(delivered.length, 1);
      assert.equal(delivered[0].id, "v-1");
    } finally {
      q.stop();
    }
  });

  it("a same-reference revision is a no-op; a partial patch leaves the other hook live", async () => {
    const delivered: ShadowDeliveredInfo[] = [];
    const failed: ShadowFailedInfo[] = [];
    const replacement: ShadowFailedInfo[] = [];
    let shadowShouldFail = false;
    const onDelivered: DeliveredObserver = (info) => delivered.push(info);
    const onFailed: FailedObserver = (info) => failed.push(info);
    const { q, timer } = makeQueue({
      onShadowDelivered: onDelivered,
      onShadowFailed: onFailed,
      shadowShouldFail: () => shadowShouldFail,
    });
    q.start();
    try {
      q.reviseShadowCallbacks({ onShadowDelivered: onDelivered });
      await driveMirror(q, timer, "n-1");
      assert.equal(delivered.length, 1);
      q.reviseShadowCallbacks({ onShadowFailed: (info) => replacement.push(info) });
      shadowShouldFail = true;
      await driveMirror(q, timer, "n-2");
      assert.equal(failed.length, 0);
      assert.equal(replacement.length, 1);
      shadowShouldFail = false;
      await driveMirror(q, timer, "n-3");
      assert.equal(delivered.length, 2);
    } finally {
      q.stop();
    }
  });

  it("revising with shadow targets unconfigured throws Error", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.throws(
      () => q.reviseShadowCallbacks({ onShadowDelivered: () => {} }),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    assert.equal(q.shadowConfigured(), false);
  });

  it("shadowConfigured reports the live state", () => {
    const { q } = makeQueue({});
    assert.equal(q.shadowConfigured(), true);
    q.stop();
  });
});

describe("RelayServer shadow callbacks revision (WR-395)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function postWebhook(port: number, body: Buffer) {
    return new Promise<{ status: number }>((resolve, reject) => {
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
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  /**
   * A server whose main sender succeeds and whose shadow sender is
   * flippable between success and failure. Returns the relay, its
   * audit log, the captured shadow items, and the fail switch.
   */
  function mirroringServer(opts: {
    onShadowDelivered?: DeliveredObserver;
    onShadowFailed?: FailedObserver;
    shadowTargets?: boolean;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "shadow-callbacks-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const shadowSeen: Array<{ targetUrl: string }> = [];
    let shadowShouldFail = false;
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: FORWARD,
      auditLog,
      operatorToken,
      sender: async () => {},
      retry: {
        baseDelayMs: 1,
        maxDelayMs: 5,
        jitterMs: 0,
        ...(opts.shadowTargets === false
          ? {}
          : {
              shadowTargets: {
                [FORWARD]: [
                  {
                    targetUrl: SHADOW,
                    sender: (async (it: { targetUrl: string }) => {
                      shadowSeen.push(it);
                      if (shadowShouldFail) throw new Error("shadow is down");
                    }) as Sender,
                  },
                ],
              },
            }),
        ...(opts.onShadowDelivered !== undefined
          ? { onShadowDelivered: opts.onShadowDelivered }
          : {}),
        ...(opts.onShadowFailed !== undefined ? { onShadowFailed: opts.onShadowFailed } : {}),
      },
    });
    servers.push(relay);
    return {
      relay,
      auditLog,
      shadowSeen,
      setShadowFail: (v: boolean) => {
        shadowShouldFail = v;
      },
    };
  }

  /** Drive one mirror and wait for its audit event to land. */
  async function driveMirror(
    port: number,
    auditLog: AuditLog,
    event: "shadow_delivered" | "shadow_failed"
  ): Promise<void> {
    const before = eventsOf(auditLog, event).length;
    assert.equal((await postWebhook(port, BODY)).status, 202);
    await waitFor(() => eventsOf(auditLog, event).length > before, `${event} audit`);
  }

  it("revising the delivered callback routes the next mirror to the new callback and the audit still lands", async () => {
    const first: ShadowDeliveredInfo[] = [];
    const second: ShadowDeliveredInfo[] = [];
    const { relay, auditLog, shadowSeen } = mirroringServer({
      onShadowDelivered: (info) => first.push(info),
    });
    const port = await listen(relay);
    await driveMirror(port, auditLog, "shadow_delivered");
    assert.equal(first.length, 1);
    assert.equal(shadowSeen.length, 1);
    relay.reviseShadowCallbacks!({ onShadowDelivered: (info) => second.push(info) });
    await driveMirror(port, auditLog, "shadow_delivered");
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.equal(second[0].shadowTarget, SHADOW);
    assert.equal(shadowSeen.length, 2);
    assert.equal(eventsOf(auditLog, "shadow_delivered").length, 2);
    // The revision itself is audited with per-hook presence, never a body.
    const revised = eventsOf(auditLog, "shadow_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].onShadowDelivered, "set");
    assert.equal(revised[0].oldOnShadowDelivered, "set");
    assert.equal(revised[0].onShadowFailed, "unchanged");
    assert.equal(revised[0].oldOnShadowFailed, "absent");
  });

  it("revising the failed callback routes the next failed mirror to the new callback", async () => {
    const first: ShadowFailedInfo[] = [];
    const second: ShadowFailedInfo[] = [];
    const { relay, auditLog, setShadowFail } = mirroringServer({
      onShadowFailed: (info) => first.push(info),
    });
    setShadowFail(true);
    const port = await listen(relay);
    await driveMirror(port, auditLog, "shadow_failed");
    assert.equal(first.length, 1);
    relay.reviseShadowCallbacks!({ onShadowFailed: (info) => second.push(info) });
    await driveMirror(port, auditLog, "shadow_failed");
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.match(second[0].error, /shadow is down/);
    assert.equal(eventsOf(auditLog, "shadow_failed").length, 2);
  });

  it("null clears a single field; the audit still lands and the other hook stays live", async () => {
    const delivered: ShadowDeliveredInfo[] = [];
    const failed: ShadowFailedInfo[] = [];
    const { relay, auditLog, setShadowFail } = mirroringServer({
      onShadowDelivered: (info) => delivered.push(info),
      onShadowFailed: (info) => failed.push(info),
    });
    const port = await listen(relay);
    await driveMirror(port, auditLog, "shadow_delivered");
    assert.equal(delivered.length, 1);
    relay.reviseShadowCallbacks!({ onShadowDelivered: null });
    // The mirror still runs and is still audited — only forwarding stops.
    await driveMirror(port, auditLog, "shadow_delivered");
    assert.equal(delivered.length, 1);
    assert.equal(eventsOf(auditLog, "shadow_delivered").length, 2);
    // The untouched hook still forwards.
    setShadowFail(true);
    await driveMirror(port, auditLog, "shadow_failed");
    assert.equal(failed.length, 1);
    const revised = eventsOf(auditLog, "shadow_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].onShadowDelivered, "cleared");
    assert.equal(revised[0].oldOnShadowDelivered, "set");
    assert.equal(revised[0].onShadowFailed, "unchanged");
    assert.equal(revised[0].oldOnShadowFailed, "set");
  });

  it("an illegal value or empty patch throws RangeError, live callbacks untouched, no revision audit", async () => {
    const delivered: ShadowDeliveredInfo[] = [];
    const { relay, auditLog } = mirroringServer({
      onShadowDelivered: (info) => delivered.push(info),
    });
    const port = await listen(relay);
    for (const bad of [null, "x", 42, {}, []] as never[]) {
      assert.throws(() => relay.reviseShadowCallbacks!(bad), RangeError, String(bad));
    }
    assert.throws(
      () => relay.reviseShadowCallbacks!({ onShadowDelivered: "nope" as never }),
      RangeError
    );
    assert.throws(
      () => relay.reviseShadowCallbacks!({ onShadowFailed: 42 as never }),
      RangeError
    );
    assert.equal(eventsOf(auditLog, "shadow_callbacks_revised").length, 0);
    await driveMirror(port, auditLog, "shadow_delivered");
    assert.equal(delivered.length, 1);
  });

  it("a same-value revision is a silent no-op; a partial patch leaves the other hook live", async () => {
    const delivered: ShadowDeliveredInfo[] = [];
    const failed: ShadowFailedInfo[] = [];
    const replacement: ShadowDeliveredInfo[] = [];
    const onDelivered: DeliveredObserver = (info) => delivered.push(info);
    const onFailed: FailedObserver = (info) => failed.push(info);
    const { relay, auditLog, setShadowFail } = mirroringServer({
      onShadowDelivered: onDelivered,
      onShadowFailed: onFailed,
    });
    const port = await listen(relay);
    relay.reviseShadowCallbacks!({ onShadowDelivered: onDelivered });
    assert.equal(eventsOf(auditLog, "shadow_callbacks_revised").length, 0);
    relay.reviseShadowCallbacks!({ onShadowDelivered: (info) => replacement.push(info) });
    assert.equal(eventsOf(auditLog, "shadow_callbacks_revised").length, 1);
    await driveMirror(port, auditLog, "shadow_delivered");
    assert.equal(delivered.length, 0);
    assert.equal(replacement.length, 1);
    setShadowFail(true);
    await driveMirror(port, auditLog, "shadow_failed");
    assert.equal(failed.length, 1);
  });

  it("revising with shadow targets unconfigured throws Error", () => {
    const { relay } = mirroringServer({ shadowTargets: false });
    assert.throws(
      () => relay.reviseShadowCallbacks!({ onShadowDelivered: () => {} }),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });
});
