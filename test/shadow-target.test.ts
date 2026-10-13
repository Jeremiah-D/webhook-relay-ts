import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import {
  HttpDeliveryError,
  RetryQueue,
  type RetryItem,
  type Sender,
  type ShadowDeliveredInfo,
  type ShadowFailedInfo,
} from "../src/retry.ts";
import { ShadowDispatcher, assertValidShadowTargets } from "../src/shadow.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const PRIMARY = "http://127.0.0.1:9911/hook";
const SHADOW = "http://127.0.0.1:9912/shadow";
const SHADOW2 = "http://127.0.0.1:9913/shadow2";

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

function item(id: string, targetUrl: string = PRIMARY): RetryItem {
  return { id, payload: Buffer.from(`payload-${id}`), targetUrl, headers: { "x-custom": "1" } };
}

describe("shadow config validation", () => {
  it("accepts a minimal valid config", () => {
    assertValidShadowTargets({ [PRIMARY]: [{ targetUrl: SHADOW }] });
    new ShadowDispatcher({ [PRIMARY]: [{ targetUrl: SHADOW }] }, { sender: async () => {} });
  });

  it("accepts multiple targets per endpoint", () => {
    assertValidShadowTargets({
      [PRIMARY]: [{ targetUrl: SHADOW }, { targetUrl: SHADOW2, sender: async () => {} }],
    });
  });

  it("treats undefined as disabled (valid)", () => {
    assertValidShadowTargets(undefined);
  });

  it("rejects non-record configs", () => {
    for (const bad of [null, [], "x", 42]) {
      assert.throws(() => assertValidShadowTargets(bad as never), RangeError, String(bad));
    }
  });

  it("rejects empty endpoint keys, non-array values, and empty lists", () => {
    assert.throws(() => assertValidShadowTargets({ "": [{ targetUrl: SHADOW }] }), RangeError);
    assert.throws(
      () => assertValidShadowTargets({ [PRIMARY]: { targetUrl: SHADOW } as never }),
      RangeError
    );
    assert.throws(() => assertValidShadowTargets({ [PRIMARY]: [] }), RangeError);
  });

  it("rejects a shadow target equal to the endpoint it shadows", () => {
    assert.throws(
      () => assertValidShadowTargets({ [PRIMARY]: [{ targetUrl: PRIMARY }] }),
      RangeError
    );
  });

  it("rejects duplicate shadow targets for one endpoint", () => {
    assert.throws(
      () =>
        assertValidShadowTargets({ [PRIMARY]: [{ targetUrl: SHADOW }, { targetUrl: SHADOW }] }),
      RangeError
    );
  });

  it("rejects malformed target URLs", () => {
    for (const bad of ["", "not-a-url", "ftp://example.com/x", "ws://example.com/x"]) {
      assert.throws(
        () => assertValidShadowTargets({ [PRIMARY]: [{ targetUrl: bad }] }),
        RangeError,
        bad
      );
    }
  });

  it("rejects non-object entries and non-function senders", () => {
    assert.throws(
      () => assertValidShadowTargets({ [PRIMARY]: [null as never] }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidShadowTargets({
          [PRIMARY]: [{ targetUrl: SHADOW, sender: "nope" as never }],
        }),
      RangeError
    );
  });

  it("RetryQueue construction throws RangeError on invalid shadowTargets", () => {
    assert.throws(
      () => new RetryQueue({ shadowTargets: { [PRIMARY]: [{ targetUrl: PRIMARY }] } }),
      RangeError
    );
    assert.throws(
      () => new RetryQueue({ shadowTargets: { [PRIMARY]: [] } }),
      RangeError
    );
  });
});

describe("shadow mirroring", () => {
  it("mirrors the identical wire request after a successful main attempt", async () => {
    const timer = manualTimer();
    const order: string[] = [];
    const mainSeen: RetryItem[] = [];
    const shadowSeen: RetryItem[] = [];
    const mainSender: Sender = async (it) => {
      order.push("main");
      mainSeen.push(it);
    };
    const shadowSender: Sender = async (it) => {
      order.push("shadow");
      shadowSeen.push(it);
    };
    const delivered: ShadowDeliveredInfo[] = [];
    let mainDelivered = 0;
    const q = new RetryQueue({
      sender: mainSender,
      jitterMs: 0,
      setTimer: timer.setTimer,
      shadowTargets: { [PRIMARY]: [{ targetUrl: SHADOW, sender: shadowSender }] },
      onDelivered: () => {
        mainDelivered += 1;
      },
      onShadowDelivered: (info) => {
        delivered.push(info);
      },
    });
    q.start();
    q.enqueue(item("s-1"));
    await timer.run();
    await flushShadow();

    // The shadow copy is the exact wire request: same id, payload,
    // headers, 0-based attempt index, and traceId — only the targetUrl
    // is swapped to the shadow downstream.
    assert.equal(shadowSeen.length, 1);
    const [shadowItem] = shadowSeen;
    assert.equal(shadowItem.targetUrl, SHADOW);
    assert.equal(shadowItem.id, "s-1");
    assert.deepEqual(shadowItem.payload, Buffer.from("payload-s-1"));
    assert.deepEqual(shadowItem.headers, { "x-custom": "1" });
    assert.equal(shadowItem.attempt, 0);
    assert.equal(shadowItem.traceId, mainSeen[0].traceId);
    // Fire-and-forget: the main attempt's sender ran first, and the main
    // delivery completed exactly once.
    assert.deepEqual(order, ["main", "shadow"]);
    assert.equal(mainDelivered, 1);

    // Audit hook shape.
    assert.equal(delivered.length, 1);
    const [info] = delivered;
    assert.equal(info.event, "shadow_delivered");
    assert.equal(info.id, "s-1");
    assert.equal(info.traceId, mainSeen[0].traceId);
    assert.equal(info.endpoint, PRIMARY);
    assert.equal(info.shadowTarget, SHADOW);
    assert.equal(info.attempts, 1);
    assert.equal(info.tenant, undefined);

    // Metrics: shadow outcomes live in relay_shadow_total only — the
    // main delivery counters are untouched by the mirror.
    const exposition = q.renderMetrics();
    assert.match(
      exposition,
      new RegExp(
        `relay_shadow_total\\{endpoint="${PRIMARY}",shadow_target="${SHADOW}",result="delivered"\\} 1`
      )
    );
    assert.match(exposition, new RegExp(`relay_deliveries_total\\{endpoint="${PRIMARY}",status="delivered"\\} 1`));
    // The mirror never pollutes the main counters: no failures, no
    // retries, no dead letters recorded for the main endpoint.
    assert.match(exposition, new RegExp(`relay_deliveries_total\\{endpoint="${PRIMARY}",status="failed"\\} 0`));
    assert.match(exposition, new RegExp(`relay_deliveries_total\\{endpoint="${PRIMARY}",status="retried"\\} 0`));
    assert.match(exposition, new RegExp(`relay_deliveries_total\\{endpoint="${PRIMARY}",status="dead_letter"\\} 0`));
    assert.deepEqual(q.getShadowStats(), [
      { endpoint: PRIMARY, shadowTarget: SHADOW, delivered: 1, failed: 0 },
    ]);
    q.stop();
  });

  it("falls back to the main sender when a target carries no dedicated sender", async () => {
    const timer = manualTimer();
    const calls: string[] = [];
    const sender: Sender = async (it) => {
      calls.push(it.targetUrl);
    };
    const q = new RetryQueue({
      sender,
      jitterMs: 0,
      setTimer: timer.setTimer,
      shadowTargets: { [PRIMARY]: [{ targetUrl: SHADOW }] },
    });
    q.start();
    q.enqueue(item("s-2"));
    await timer.run();
    await flushShadow();
    // Main attempt first, then the mirrored copy through the same sender.
    assert.deepEqual(calls, [PRIMARY, SHADOW]);
    assert.deepEqual(q.getShadowStats(), [
      { endpoint: PRIMARY, shadowTarget: SHADOW, delivered: 1, failed: 0 },
    ]);
    q.stop();
  });

  it("mirrors every attempt, including failed ones, without disturbing the retry trajectory", async () => {
    const timer = manualTimer();
    let mainCalls = 0;
    let shadowCalls = 0;
    const mainSender: Sender = async () => {
      mainCalls += 1;
      if (mainCalls < 3) throw new Error("boom");
    };
    const shadowSender: Sender = async () => {
      shadowCalls += 1;
      throw new Error("shadow down");
    };
    const failed: ShadowFailedInfo[] = [];
    const delivered: ShadowDeliveredInfo[] = [];
    const q = new RetryQueue({
      sender: mainSender,
      baseDelayMs: 10,
      maxDelayMs: 100,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      shadowTargets: { [PRIMARY]: [{ targetUrl: SHADOW, sender: shadowSender }] },
      onShadowDelivered: (info) => delivered.push(info),
      onShadowFailed: (info) => failed.push(info),
    });
    q.start();
    q.enqueue(item("s-3"));
    await timer.run();
    await flushShadow();

    // Three main attempts (two failures, one success) and one shadow
    // mirror per attempt — the shadow failures never scheduled a main
    // retry and never dead-lettered anything.
    assert.equal(mainCalls, 3);
    assert.equal(shadowCalls, 3);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetterStats().total, 0);
    assert.equal(failed.length, 3);
    assert.equal(delivered.length, 0);
    assert.ok(failed.every((f) => f.event === "shadow_failed" && f.error === "shadow down"));
    assert.ok(failed.every((f) => f.endpoint === PRIMARY && f.shadowTarget === SHADOW));
    assert.deepEqual(
      failed.map((f) => f.attempts),
      [1, 2, 3]
    );
    // The mirrored attempt number follows the main attempt, 1-based.
    const exposition = q.renderMetrics();
    assert.match(
      exposition,
      new RegExp(
        `relay_shadow_total\\{endpoint="${PRIMARY}",shadow_target="${SHADOW}",result="failed"\\} 3`
      )
    );
    assert.match(exposition, new RegExp(`relay_deliveries_total\\{endpoint="${PRIMARY}",status="delivered"\\} 1`));
    assert.match(exposition, new RegExp(`relay_deliveries_total\\{endpoint="${PRIMARY}",status="failed"\\} 2`));
    assert.deepEqual(q.getShadowStats(), [
      { endpoint: PRIMARY, shadowTarget: SHADOW, delivered: 0, failed: 3 },
    ]);
    q.stop();
  });

  it("a failing shadow never trips the circuit breaker or consumes quota", async () => {
    const timer = manualTimer();
    let nowMs = 1_000_000;
    const mainSender: Sender = async () => {};
    const shadowSender: Sender = async () => {
      throw new Error("shadow down");
    };
    const q = new RetryQueue({
      sender: mainSender,
      jitterMs: 0,
      setTimer: timer.setTimer,
      circuitBreaker: { failureThreshold: 5, cooldownMs: 60_000 },
      quota: { deliveriesPerMinute: 2, now: () => nowMs },
      shadowTargets: { [PRIMARY]: [{ targetUrl: SHADOW, sender: shadowSender }] },
    });
    q.start();
    // Two main deliveries inside the same quota minute: both must go
    // through immediately — the two shadow mirrors consume no tokens.
    q.enqueue(item("s-4a"));
    q.enqueue(item("s-4b"));
    await timer.run();
    await flushShadow();
    const [breaker] = q.getCircuitStats();
    assert.equal(breaker.endpoint, PRIMARY);
    assert.equal(breaker.state, "closed");
    assert.equal(breaker.consecutiveFailures, 0);
    const exposition = q.renderMetrics();
    assert.match(exposition, new RegExp(`relay_deliveries_total\\{endpoint="${PRIMARY}",status="delivered"\\} 2`));
    assert.match(
      exposition,
      new RegExp(
        `relay_shadow_total\\{endpoint="${PRIMARY}",shadow_target="${SHADOW}",result="failed"\\} 2`
      )
    );
    q.stop();
  });

  it("mirrors poison (non-retryable) attempts without resurrecting the dead letter", async () => {
    const timer = manualTimer();
    let mainCalls = 0;
    let shadowCalls = 0;
    const mainSender: Sender = async () => {
      mainCalls += 1;
      throw new HttpDeliveryError(400);
    };
    const shadowSender: Sender = async () => {
      shadowCalls += 1;
    };
    const delivered: ShadowDeliveredInfo[] = [];
    const q = new RetryQueue({
      sender: mainSender,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      shadowTargets: { [PRIMARY]: [{ targetUrl: SHADOW, sender: shadowSender }] },
      onShadowDelivered: (info) => delivered.push(info),
    });
    q.start();
    q.enqueue(item("s-5"));
    await timer.run();
    await flushShadow();
    // Poison: exactly one main attempt, immediately dead-lettered — and
    // that attempt was still mirrored to the shadow target.
    assert.equal(mainCalls, 1);
    assert.equal(shadowCalls, 1);
    assert.equal(delivered.length, 1);
    assert.equal(q.getDeadLetterStats().total, 1);
    const exposition = q.renderMetrics();
    assert.match(exposition, new RegExp(`relay_deliveries_total\\{endpoint="${PRIMARY}",status="dead_letter"\\} 1`));
    q.stop();
  });

  it("carries the tenant through shadow audit events, stats, and metrics", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
      shadowTargets: { [PRIMARY]: [{ targetUrl: SHADOW, sender: async () => {} }] },
    });
    q.start();
    q.enqueue({ ...item("s-6"), tenantId: "acme" });
    await timer.run();
    await flushShadow();
    const [row] = q.getShadowStats();
    assert.equal(row.tenant, "acme");
    assert.equal(row.delivered, 1);
    const exposition = q.renderMetrics();
    assert.match(
      exposition,
      new RegExp(
        `relay_shadow_total\\{endpoint="${PRIMARY}",tenant="acme",shadow_target="${SHADOW}",result="delivered"\\} 1`
      )
    );
    q.stop();
  });

  it("disabled by default: zero behavior change", async () => {
    const timer = manualTimer();
    let calls = 0;
    const q = new RetryQueue({
      sender: async () => {
        calls += 1;
      },
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(item("s-7"));
    await timer.run();
    await flushShadow();
    assert.equal(calls, 1);
    assert.deepEqual(q.getShadowStats(), []);
    assert.ok(!q.renderMetrics().includes("relay_shadow"));
    q.stop();
  });

  it("mirrors exactly once when semantic validation fails the attempt", async () => {
    const timer = manualTimer();
    let shadowCalls = 0;
    const mainSender: Sender = async () => ({
      statusCode: 200,
      body: Buffer.from('{"ok":false}'),
      truncated: false,
    });
    const shadowSender: Sender = async () => {
      shadowCalls += 1;
    };
    const q = new RetryQueue({
      sender: mainSender,
      maxAttempts: 1,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseValidators: () => false,
      shadowTargets: { [PRIMARY]: [{ targetUrl: SHADOW, sender: shadowSender }] },
    });
    q.start();
    q.enqueue(item("s-9"));
    await timer.run();
    await flushShadow();
    // The transport succeeded but the validator failed: the attempt is
    // one failure (dead-lettered), and the shadow copy went out exactly
    // once — not once for the "success" and once for the failure.
    assert.equal(shadowCalls, 1);
    assert.equal(q.getDeadLetterStats().total, 1);
    assert.deepEqual(q.getShadowStats(), [
      { endpoint: PRIMARY, shadowTarget: SHADOW, delivered: 1, failed: 0 },
    ]);
    q.stop();
  });

  it("multiple shadow targets each get their own copy", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const mkSender = (name: string): Sender => async (it) => {
      seen.push(`${name}:${it.targetUrl}`);
    };
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
      shadowTargets: {
        [PRIMARY]: [
          { targetUrl: SHADOW, sender: mkSender("a") },
          { targetUrl: SHADOW2, sender: mkSender("b") },
        ],
      },
    });
    q.start();
    q.enqueue(item("s-8"));
    await timer.run();
    await flushShadow();
    assert.ok(seen.includes(`a:${SHADOW}`));
    assert.ok(seen.includes(`b:${SHADOW2}`));
    assert.equal(q.getShadowStats().length, 2);
    q.stop();
  });
});

describe("shadow server wiring", () => {
  it("audits shadow_delivered through the relay server", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shadow-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const secret = "test-secret";
    const payload = Buffer.from(JSON.stringify({ n: 1 }));
    const shadowSeen: RetryItem[] = [];
    const server = createRelayServer({
      secret,
      forwardUrl: PRIMARY,
      auditLog: audit,
      sender: async () => {},
      retry: {
        baseDelayMs: 5,
        maxDelayMs: 5,
        jitterMs: 0,
        shadowTargets: {
          [PRIMARY]: [
            {
              targetUrl: SHADOW,
              sender: async (it) => {
                shadowSeen.push(it);
              },
            },
          ],
        },
      },
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const status = await new Promise<number>((resolve, reject) => {
        const req = httpRequest(
          {
            port,
            method: "POST",
            path: "/hook",
            headers: {
              "content-type": "application/json",
              "x-signature": signSha256(payload, secret),
            },
          },
          (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode ?? 0));
          }
        );
        req.on("error", reject);
        req.end(payload);
      });
      assert.equal(status, 202);
      await new Promise((r) => setTimeout(r, 300));
      // The main delivery went to the primary, the mirror to the shadow.
      assert.equal(shadowSeen.length, 1);
      assert.equal(shadowSeen[0].targetUrl, SHADOW);
      assert.deepEqual(shadowSeen[0].payload, payload);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const mirrored = events.filter((e) => e.event === "shadow_delivered");
      assert.equal(mirrored.length, 1);
      assert.equal(mirrored[0].targetUrl, PRIMARY);
      assert.equal(mirrored[0].shadowTarget, SHADOW);
      assert.equal(mirrored[0].attempts, 1);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("rejects an invalid server-level shadowTargets config at startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "shadow-audit-"));
    assert.throws(
      () =>
        createRelayServer({
          secret: "test-secret",
          forwardUrl: PRIMARY,
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          shadowTargets: { [PRIMARY]: [{ targetUrl: PRIMARY }] },
        }),
      RangeError
    );
  });
});
