import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { HmacSha256Verifier, signSha256 } from "../src/verify.ts";
import {
  DeadLetterStormEscalator,
  isSelfEscalationTarget,
  resolveDeadLetterEscalationConfig,
  DEFAULT_ESCALATION_WINDOW_MS,
  DEFAULT_ESCALATION_THRESHOLD,
  DEFAULT_ESCALATION_COOLDOWN_MS,
  DEFAULT_ESCALATION_MAX_ATTEMPTS,
  type DeadLetterEscalatedInfo,
  type DeadLetterEscalationFailedInfo,
  type EscalationPostResult,
} from "../src/escalation.ts";

const SIGNING_SECRET = "operator-alert-secret";
const OPERATOR_URL = "https://ops.example.com/alerts/dead-letter";
const ENDPOINT = "https://downstream.example/hook";

interface CapturedPost {
  url: string;
  body: Buffer;
  headers: Record<string, string>;
}

/** Captures alert POSTs without touching the network. */
function stubTransport(statusCode = 200) {
  const posts: CapturedPost[] = [];
  return {
    posts,
    post: async (url: string, body: Buffer, headers: Record<string, string>): Promise<EscalationPostResult> => {
      posts.push({ url, body, headers });
      return { statusCode };
    },
  };
}

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
    clearTimer: (h: { clear(): void }) => h.clear(),
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function escalatorHarness(overrides: Record<string, unknown> = {}) {
  const transport = stubTransport();
  const timer = manualTimer();
  let nowMs = 0;
  const escalated: DeadLetterEscalatedInfo[] = [];
  const failed: DeadLetterEscalationFailedInfo[] = [];
  const config = resolveDeadLetterEscalationConfig({
    url: OPERATOR_URL,
    signingSecret: SIGNING_SECRET,
    threshold: 2,
    windowMs: 3_600_000,
    cooldownMs: 60_000,
    post: transport.post,
    now: () => nowMs,
    setTimer: timer.setTimer,
    clearTimer: timer.clearTimer,
    ...overrides,
  })!;
  const escalator = new DeadLetterStormEscalator(config, {
    onEscalated: (info) => escalated.push(info),
    onFailed: (info) => failed.push(info),
  });
  return {
    transport,
    timer,
    escalated,
    failed,
    escalator,
    setNow: (ms: number) => {
      nowMs = ms;
    },
  };
}

/** Flush microtasks so fire-and-forget alert POSTs settle. */
async function flushAlert() {
  for (let i = 0; i < 10; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for ${what}`);
}

describe("WR-93 resolveDeadLetterEscalationConfig", () => {
  it("is off by default (undefined when unset)", () => {
    assert.equal(resolveDeadLetterEscalationConfig(undefined), undefined);
  });

  it("applies documented defaults", () => {
    const c = resolveDeadLetterEscalationConfig({ url: OPERATOR_URL, signingSecret: SIGNING_SECRET })!;
    assert.equal(c.windowMs, DEFAULT_ESCALATION_WINDOW_MS);
    assert.equal(c.windowMs, 600_000);
    assert.equal(c.threshold, DEFAULT_ESCALATION_THRESHOLD);
    assert.equal(c.threshold, 20);
    assert.equal(c.cooldownMs, DEFAULT_ESCALATION_COOLDOWN_MS);
    assert.equal(c.cooldownMs, 3_600_000);
    assert.equal(c.maxAttempts, DEFAULT_ESCALATION_MAX_ATTEMPTS);
    assert.equal(c.maxAttempts, 2);
    assert.equal(c.backoffMs, 1000);
    assert.equal(c.timeoutMs, 5000);
  });

  it("rejects a missing or invalid url", () => {
    assert.throws(() => resolveDeadLetterEscalationConfig({ url: "", signingSecret: SIGNING_SECRET }), RangeError);
    assert.throws(
      () => resolveDeadLetterEscalationConfig({ url: "not a url", signingSecret: SIGNING_SECRET }),
      RangeError
    );
    assert.throws(
      () => resolveDeadLetterEscalationConfig({ url: "ftp://ops.example.com/x", signingSecret: SIGNING_SECRET }),
      RangeError
    );
  });

  it("requires a non-empty signingSecret", () => {
    assert.throws(
      () => resolveDeadLetterEscalationConfig({ url: OPERATOR_URL, signingSecret: "" }),
      RangeError
    );
    assert.throws(
      // @ts-expect-error: runtime validation must catch a missing secret
      () => resolveDeadLetterEscalationConfig({ url: OPERATOR_URL }),
      RangeError
    );
  });

  it("rejects a self-target at configuration time", () => {
    assert.throws(
      () =>
        resolveDeadLetterEscalationConfig({
          url: "http://127.0.0.1:8080/intake",
          signingSecret: SIGNING_SECRET,
          selfOrigins: ["http://127.0.0.1:8080"],
        }),
      RangeError
    );
  });

  it("rejects invalid numeric tuning", () => {
    const bad = [
      { windowMs: 0 },
      { windowMs: -5 },
      { threshold: 0 },
      { threshold: 1.5 },
      { cooldownMs: -1 },
      { maxAttempts: 0 },
      { maxAttempts: 4 },
      { backoffMs: -1 },
      { timeoutMs: 0 },
    ];
    for (const b of bad) {
      assert.throws(
        () => resolveDeadLetterEscalationConfig({ url: OPERATOR_URL, signingSecret: SIGNING_SECRET, ...b }),
        RangeError,
        JSON.stringify(b)
      );
    }
  });
});

describe("WR-93 isSelfEscalationTarget", () => {
  it("matches on origin, ignoring the path", () => {
    assert.equal(isSelfEscalationTarget("http://127.0.0.1:8080/hook", ["http://127.0.0.1:8080"]), true);
    assert.equal(isSelfEscalationTarget("http://127.0.0.1:8080/a/b?c=d", ["http://127.0.0.1:8080/x"]), true);
  });

  it("does not match a different port or an invalid url", () => {
    assert.equal(isSelfEscalationTarget("http://127.0.0.1:9090/hook", ["http://127.0.0.1:8080"]), false);
    assert.equal(isSelfEscalationTarget("not a url", ["http://127.0.0.1:8080"]), false);
  });
});

describe("WR-93 storm detection", () => {
  it("fires exactly one alert at the threshold crossing", async () => {
    const h = escalatorHarness();
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 0);
    assert.equal(h.escalated.length, 0);

    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);
    assert.equal(h.escalated.length, 1);

    const alert = JSON.parse(h.transport.posts[0].body.toString("utf8"));
    assert.equal(alert.event, "dead_letter_escalation");
    assert.equal(alert.endpoint, ENDPOINT);
    assert.equal(alert.deadLetters, 2);
    assert.equal(alert.threshold, 2);
    assert.equal(alert.windowMs, 3_600_000);
    assert.equal(typeof alert.alertedAt, "string");
    assert.equal("tenant" in h.escalated[0], false);
    assert.equal(h.transport.posts[0].url, OPERATOR_URL);
    assert.equal(h.transport.posts[0].headers["content-type"], "application/json");
  });

  it("is edge-triggered: a continuing storm does not re-alert", async () => {
    const h = escalatorHarness();
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);

    // The storm keeps going — no new alert for the same episode.
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);
    assert.equal(h.escalated.length, 1);

    const stats = h.escalator.stats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].alerted, true);
    assert.equal(stats[0].escalations, 1);
    assert.equal(stats[0].windowDeadLetters, 5);
    assert.equal(typeof stats[0].lastAlertAt, "string");
  });

  it("manual acknowledge rearms the edge: a new episode alerts again after the cooldown", async () => {
    const h = escalatorHarness();
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);

    h.escalator.acknowledge(undefined, ENDPOINT);
    assert.equal(h.escalator.stats()[0].alerted, false);

    // Past the cooldown: the next threshold crossing is a new episode.
    h.setNow(61_000);
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 2);
    assert.equal(h.escalated.length, 2);
    assert.equal(h.escalator.stats()[0].escalations, 2);
  });

  it("without an acknowledge, a later crossing stays silent even after the cooldown", async () => {
    const h = escalatorHarness();
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);

    // The edge is still fired for this episode — time alone does not rearm it
    // (120s is past the 60s cooldown but inside the 1h window, so the
    // scope's count is still at threshold and the episode is the same).
    h.setNow(120_000);
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);
    assert.equal(h.escalator.stats()[0].alerted, true);
  });

  it("the cooldown suppresses an episode that starts too soon after an acknowledge", async () => {
    const h = escalatorHarness();
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);

    h.escalator.acknowledge(undefined, ENDPOINT);
    // 30s later — inside the 60s cooldown: the new episode stays silent.
    h.setNow(30_000);
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);
    assert.equal(h.escalated.length, 1);
  });

  it("auto-resets when the window count falls back below the threshold", async () => {
    const h = escalatorHarness({ windowMs: 1000, cooldownMs: 0 });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);
    assert.equal(h.escalator.stats()[0].alerted, true);

    // The window drains: both t=0 entries expire, one new arrival stays.
    h.setNow(1500);
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);
    const rearmed = h.escalator.stats()[0];
    assert.equal(rearmed.alerted, false);
    assert.equal(rearmed.windowDeadLetters, 1);

    // Rearmed: the next crossing fires again.
    h.setNow(1600);
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 2);
    assert.equal(h.escalated.length, 2);
  });

  it("scopes independently per (tenant, endpoint)", async () => {
    const h = escalatorHarness();
    h.escalator.recordDeadLetter({ tenant: "acme", endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ tenant: "acme", endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);

    // Another tenant on the same endpoint is its own scope: one dead
    // letter is not enough.
    h.escalator.recordDeadLetter({ tenant: "globex", endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);

    h.escalator.recordDeadLetter({ tenant: "globex", endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 2);

    const globexAlert = JSON.parse(h.transport.posts[1].body.toString("utf8"));
    assert.equal(globexAlert.tenant, "globex");
    assert.equal(globexAlert.endpoint, ENDPOINT);

    const rows = h.escalator.stats();
    assert.equal(rows.length, 2);
    const byTenant = new Map(rows.map((r) => [r.tenant, r]));
    assert.equal(byTenant.get("acme")!.escalations, 1);
    assert.equal(byTenant.get("globex")!.escalations, 1);
  });

  it("acknowledge targets one scope only", async () => {
    const h = escalatorHarness({ cooldownMs: 0 });
    h.escalator.recordDeadLetter({ tenant: "acme", endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ tenant: "acme", endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ tenant: "globex", endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ tenant: "globex", endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 2);

    h.escalator.acknowledge("acme", ENDPOINT);
    const rows = h.escalator.stats();
    const byTenant = new Map(rows.map((r) => [r.tenant, r]));
    assert.equal(byTenant.get("acme")!.alerted, false);
    assert.equal(byTenant.get("globex")!.alerted, true);

    // Unknown scopes are a no-op, not an error.
    h.escalator.acknowledge("nobody", ENDPOINT);
    h.escalator.acknowledge(undefined, "https://other.example/hook");
  });
});

describe("WR-93 alert signing (WR-26 style)", () => {
  it("signs the body with x-relay-signature and verifies with HmacSha256Verifier", async () => {
    const h = escalatorHarness({ keyId: "ops-key-1" });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);

    const post = h.transport.posts[0];
    const sig = post.headers["x-relay-signature"];
    assert.ok(sig.startsWith("sha256="));
    assert.equal(post.headers["x-relay-key-id"], "ops-key-1");

    // The operator side verifies with the shared secret.
    const verifier = new HmacSha256Verifier(SIGNING_SECRET);
    assert.equal(verifier.verify(post.body, sig), true);
    // A wrong secret does not verify — the signature is real.
    assert.equal(new HmacSha256Verifier("wrong-secret").verify(post.body, sig), false);
  });

  it("omits x-relay-key-id when no keyId is configured", async () => {
    const h = escalatorHarness();
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(h.transport.posts.length, 1);
    assert.equal("x-relay-key-id" in h.transport.posts[0].headers, false);
    const sig = h.transport.posts[0].headers["x-relay-signature"];
    assert.equal(new HmacSha256Verifier(SIGNING_SECRET).verify(h.transport.posts[0].body, sig), true);
  });
});

describe("WR-93 loop protection", () => {
  it("refuses to POST to the relay's own origin and reports the failure", async () => {
    const h = escalatorHarness();
    h.escalator.setSelfCheck(() => true); // the operator URL resolves to us
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    h.escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();

    assert.equal(h.transport.posts.length, 0);
    assert.equal(h.escalated.length, 0);
    assert.equal(h.failed.length, 1);
    assert.equal(h.failed[0].attempts, 0);
    assert.match(h.failed[0].error, /loop detected/);
    // The scope still records that the storm fired (edge consumed).
    assert.equal(h.escalator.stats()[0].escalations, 1);
  });
});

describe("WR-93 alert delivery failure", () => {
  it("reports through onFailed after attempts are exhausted", async () => {
    const transport = stubTransport(500);
    const timer = manualTimer();
    const escalated: DeadLetterEscalatedInfo[] = [];
    const failed: DeadLetterEscalationFailedInfo[] = [];
    const config = resolveDeadLetterEscalationConfig({
      url: OPERATOR_URL,
      signingSecret: SIGNING_SECRET,
      threshold: 1,
      maxAttempts: 1,
      post: transport.post,
      now: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    })!;
    const escalator = new DeadLetterStormEscalator(config, {
      onEscalated: (info) => escalated.push(info),
      onFailed: (info) => failed.push(info),
    });
    escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    await timer.run();

    assert.equal(transport.posts.length, 1);
    assert.equal(escalated.length, 0);
    assert.equal(failed.length, 1);
    assert.equal(failed[0].attempts, 1);
    assert.equal(failed[0].endpoint, ENDPOINT);
    assert.match(failed[0].error, /500/);
  });

  it("retries a failed alert and reports success on the retry", async () => {
    let calls = 0;
    const posts: CapturedPost[] = [];
    const timer = manualTimer();
    const escalated: DeadLetterEscalatedInfo[] = [];
    const failed: DeadLetterEscalationFailedInfo[] = [];
    const config = resolveDeadLetterEscalationConfig({
      url: OPERATOR_URL,
      signingSecret: SIGNING_SECRET,
      threshold: 1,
      maxAttempts: 2,
      backoffMs: 10,
      post: async (url, body, headers): Promise<EscalationPostResult> => {
        calls += 1;
        posts.push({ url, body, headers });
        return { statusCode: calls === 1 ? 500 : 200 };
      },
      now: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    })!;
    const escalator = new DeadLetterStormEscalator(config, {
      onEscalated: (info) => escalated.push(info),
      onFailed: (info) => failed.push(info),
    });
    escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(posts.length, 1);
    assert.equal(escalated.length, 0);

    // The retry timer fires: the second attempt lands.
    await timer.run();
    await flushAlert();
    assert.equal(posts.length, 2);
    assert.equal(escalated.length, 1);
    assert.equal(failed.length, 0);
  });

  it("stop() cancels a pending alert retry", async () => {
    const transport = stubTransport(500);
    const timer = manualTimer();
    const escalated: DeadLetterEscalatedInfo[] = [];
    const failed: DeadLetterEscalationFailedInfo[] = [];
    const config = resolveDeadLetterEscalationConfig({
      url: OPERATOR_URL,
      signingSecret: SIGNING_SECRET,
      threshold: 1,
      maxAttempts: 3,
      backoffMs: 10,
      post: transport.post,
      now: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    })!;
    const escalator = new DeadLetterStormEscalator(config, {
      onEscalated: (info) => escalated.push(info),
      onFailed: (info) => failed.push(info),
    });
    escalator.recordDeadLetter({ endpoint: ENDPOINT });
    await flushAlert();
    assert.equal(transport.posts.length, 1);

    escalator.stop();
    await timer.run();
    await flushAlert();
    // No retry fired after stop.
    assert.equal(transport.posts.length, 1);
    assert.equal(escalated.length, 0);
    assert.equal(failed.length, 0);
  });
});

describe("WR-93 RetryQueue integration", () => {
  it("feeds dead letters into the escalator and exposes stats + metrics", async () => {
    const transport = stubTransport();
    const escalated: DeadLetterEscalatedInfo[] = [];
    const failed: DeadLetterEscalationFailedInfo[] = [];
    const failing: Sender = async () => {
      throw new Error("downstream is down");
    };
    const q = new RetryQueue({
      sender: failing,
      baseDelayMs: 1,
      maxDelayMs: 5,
      maxAttempts: 1,
      jitterMs: 0,
      escalation: {
        url: OPERATOR_URL,
        signingSecret: SIGNING_SECRET,
        keyId: "ops-key-1",
        threshold: 2,
        windowMs: 600_000,
        cooldownMs: 0,
        post: transport.post,
        now: Date.now,
      },
      onDeadLetterEscalated: (info) => escalated.push(info),
      onDeadLetterEscalationFailed: (info) => failed.push(info),
    });
    q.start();
    q.enqueue({
      id: "dl-1",
      payload: Buffer.from("{}"),
      targetUrl: ENDPOINT,
      headers: {},
    });
    q.enqueue({
      id: "dl-2",
      payload: Buffer.from("{}"),
      targetUrl: ENDPOINT,
      headers: {},
    });
    // Wait for both dead letters and the dispatched alert to settle.
    const deadline = Date.now() + 5000;
    while ((q.getDeadLetter().length < 2 || escalated.length < 1) && Date.now() < deadline) {
      await new Promise((r) => setImmediate(r));
    }
    q.stop();

    assert.equal(q.getDeadLetter().length, 2);
    assert.equal(transport.posts.length, 1);
    assert.equal(escalated.length, 1);
    assert.equal(failed.length, 0);
    assert.equal(escalated[0].endpoint, ENDPOINT);
    assert.equal(escalated[0].deadLetters, 2);

    // The operator side verifies the queue-sent alert.
    const post = transport.posts[0];
    assert.equal(
      new HmacSha256Verifier(SIGNING_SECRET).verify(post.body, post.headers["x-relay-signature"]),
      true
    );
    assert.equal(post.headers["x-relay-key-id"], "ops-key-1");

    // Observability: stats row + Prometheus counter.
    const stats = q.getEscalationStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, ENDPOINT);
    assert.equal(stats[0].alerted, true);
    assert.equal(stats[0].escalations, 1);

    const exposition = q.renderMetrics();
    assert.match(exposition, /relay_dead_letter_escalations_total/);
    assert.match(exposition, new RegExp(`relay_dead_letter_escalations_total\\{endpoint="${ENDPOINT}"\\} 1`));

    // Manual acknowledge rearms the scope.
    q.acknowledgeDeadLetterEscalation(undefined, ENDPOINT);
    assert.equal(q.getEscalationStats()[0].alerted, false);
  });

  it("is off by default: no posts, no stats, no series", async () => {
    const failing: Sender = async () => {
      throw new Error("downstream is down");
    };
    const q = new RetryQueue({
      sender: failing,
      baseDelayMs: 1,
      maxDelayMs: 5,
      maxAttempts: 1,
      jitterMs: 0,
    });
    q.start();
    q.enqueue({ id: "dl-1", payload: Buffer.from("{}"), targetUrl: ENDPOINT, headers: {} });
    const offDeadline = Date.now() + 5000;
    while (q.getDeadLetter().length < 1 && Date.now() < offDeadline) {
      await new Promise((r) => setImmediate(r));
    }
    q.stop();

    assert.equal(q.getDeadLetter().length, 1);
    assert.deepEqual(q.getEscalationStats(), []);
    assert.ok(!q.renderMetrics().includes("relay_dead_letter_escalations_total"));
  });

  it("carries the tenant label through to the alert and the metrics", async () => {
    const transport = stubTransport();
    const failing: Sender = async () => {
      throw new Error("downstream is down");
    };
    const q = new RetryQueue({
      sender: failing,
      baseDelayMs: 1,
      maxDelayMs: 5,
      maxAttempts: 1,
      jitterMs: 0,
      escalation: {
        url: OPERATOR_URL,
        signingSecret: SIGNING_SECRET,
        threshold: 1,
        cooldownMs: 0,
        post: transport.post,
      },
    });
    q.start();
    q.enqueue({ id: "dl-t1", payload: Buffer.from("{}"), targetUrl: ENDPOINT, headers: {}, tenantId: "acme" });
    const tenantDeadline = Date.now() + 5000;
    while (transport.posts.length < 1 && Date.now() < tenantDeadline) {
      await new Promise((r) => setImmediate(r));
    }
    q.stop();

    assert.equal(transport.posts.length, 1);
    const alert = JSON.parse(transport.posts[0].body.toString("utf8"));
    assert.equal(alert.tenant, "acme");

    const stats = q.getEscalationStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].tenant, "acme");

    const exposition = q.renderMetrics();
    assert.match(
      exposition,
      new RegExp(`relay_dead_letter_escalations_total\\{endpoint="${ENDPOINT}",tenant="acme"\\} 1`)
    );
  });
});

describe("WR-93 server wiring", () => {
  it("audits dead_letter_escalated when a scope crosses the threshold", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wr93-srv-"));
    const log = new AuditLog(join(dir, "audit.jsonl"));
    const transport = stubTransport();
    const relay = createRelayServer({
      secret: "inbound-secret",
      forwardUrl: "http://127.0.0.1:1/hook",
      sender: async () => {
        throw new Error("downstream is down");
      },
      auditLog: log,
      operatorToken: "op",
      retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0 },
      deadLetterEscalation: {
        url: OPERATOR_URL,
        signingSecret: SIGNING_SECRET,
        threshold: 1,
        cooldownMs: 0,
        post: transport.post,
      },
    });
    const port = await listen(relay);
    try {
      const { request } = await import("node:http");
      const payload = JSON.stringify({ x: 1 });
      const sig = signSha256(Buffer.from(payload), "inbound-secret");
      await new Promise<void>((resolve, reject) => {
        const req = request(
          {
            method: "POST",
            hostname: "127.0.0.1",
            port,
            path: "/",
            headers: { "content-type": "application/json", "x-signature": sig },
          },
          (res) => {
            res.resume();
            res.on("end", () =>
              res.statusCode === 202 ? resolve() : reject(new Error(`status ${res.statusCode}`))
            );
          }
        );
        req.on("error", reject);
        req.end(payload);
      });
      await waitFor(
        () => log.query({ event: "dead_letter_escalated" }).length === 1,
        "dead_letter_escalated audit"
      );
      const [ev] = log.query({ event: "dead_letter_escalated" }) as Array<Record<string, unknown>>;
      assert.equal(ev.endpoint, "http://127.0.0.1:1/hook");
      assert.equal(ev.deadLetters, 1);
      assert.equal(ev.threshold, 1);
      assert.equal(typeof ev.alertedAt, "string");
      // The delivery itself dead-lettered exactly once: one per-delivery
      // event, one aggregate alert.
      assert.equal(log.query({ event: "dead_letter" }).length, 1);
      // The alert that went out is verifiable by the operator.
      assert.equal(transport.posts.length, 1);
      assert.equal(
        new HmacSha256Verifier(SIGNING_SECRET).verify(
          transport.posts[0].body,
          transport.posts[0].headers["x-relay-signature"]
        ),
        true
      );
    } finally {
      await new Promise<void>((r) => relay.close(() => r()));
    }
  });

  it("rejects a self-targeting escalation URL at server construction (config-time)", () => {
    const dir = mkdtempSync(join(tmpdir(), "wr93-self-"));
    const log = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          secret: "inbound-secret",
          forwardUrl: "http://127.0.0.1:9/hook",
          auditLog: log,
          deadLetterEscalation: {
            url: "http://127.0.0.1:8080/alerts",
            signingSecret: SIGNING_SECRET,
            selfOrigins: ["http://127.0.0.1:8080"],
          },
        }),
      /own inbound origin/
    );
  });
});
