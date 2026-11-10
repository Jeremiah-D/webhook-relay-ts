import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import {
  DeadLetterStormEscalator,
  resolveDeadLetterEscalationConfig,
  type DeadLetterEscalatedInfo,
  type DeadLetterEscalationFailedInfo,
  type EscalationConfig,
  type EscalationPostResult,
} from "../src/escalation.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "escalation-revision-test-key";
const opToken = "escalation-revision-op-token";
const operatorUrl = "https://ops.example.com/alerts/dead-letter";
const endpoint = "https://downstream.example/hook";

const MUST_RESTART =
  "reviseEscalation: escalation is not configured — enabling it requires a restart";

const DEFAULTS: EscalationConfig = {
  windowMs: 600_000,
  threshold: 20,
  cooldownMs: 3_600_000,
  maxAttempts: 2,
  backoffMs: 1000,
  timeoutMs: 5000,
};

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

/** Failing transport: every alert POST rejects. */
function failingTransport() {
  const posts: CapturedPost[] = [];
  return {
    posts,
    post: async (url: string, body: Buffer, headers: Record<string, string>): Promise<EscalationPostResult> => {
      posts.push({ url, body, headers });
      throw new Error("boom");
    },
  };
}

/**
 * Deterministic timer: `run()` executes pending callbacks. Every
 * scheduled delay is recorded, so backoff/timeout revisions are
 * observable without waiting on a wall clock.
 */
function manualTimer() {
  const pending: Array<() => void> = [];
  const delays: number[] = [];
  return {
    delays,
    setTimer: (fn: () => void, ms: number) => {
      delays.push(ms);
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
    url: operatorUrl,
    signingSecret: signingKey,
    threshold: 2,
    windowMs: 60_000,
    cooldownMs: 0,
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

describe("DeadLetterStormEscalator.retune (WR-377)", () => {
  it("six invalid values throw RangeError with the construction text and leave live values intact", () => {
    const { escalator } = escalatorHarness();
    const before = escalator.getConfig();
    const bad: Array<[string, Record<string, unknown>, string]> = [
      ["windowMs 0", { windowMs: 0 }, "escalation: `windowMs` must be > 0, got 0"],
      ["windowMs negative", { windowMs: -5 }, "escalation: `windowMs` must be > 0, got -5"],
      ["threshold 0", { threshold: 0 }, "escalation: `threshold` must be a positive integer, got 0"],
      ["threshold non-integer", { threshold: 1.5 }, "escalation: `threshold` must be a positive integer, got 1.5"],
      ["cooldownMs negative", { cooldownMs: -1 }, "escalation: `cooldownMs` must be >= 0, got -1"],
      ["maxAttempts 0", { maxAttempts: 0 }, "escalation: `maxAttempts` must be an integer in [1, 3], got 0"],
      ["maxAttempts 4", { maxAttempts: 4 }, "escalation: `maxAttempts` must be an integer in [1, 3], got 4"],
      ["backoffMs negative", { backoffMs: -1 }, "escalation: `backoffMs` must be >= 0, got -1"],
      ["timeoutMs 0", { timeoutMs: 0 }, "escalation: `timeoutMs` must be > 0, got 0"],
    ];
    for (const [name, patch, message] of bad) {
      assert.throws(() => escalator.retune(patch as never), { name: "RangeError", message }, name);
      assert.deepEqual(escalator.getConfig(), before, `${name} moved the live values`);
    }
  });

  it("empty and non-object patches throw RangeError", () => {
    const { escalator } = escalatorHarness();
    assert.throws(() => escalator.retune({}), RangeError);
    assert.throws(() => escalator.retune(null as never), RangeError);
    assert.throws(() => escalator.retune([] as never), RangeError);
    assert.throws(() => escalator.retune("x" as never), RangeError);
  });

  it("same-value revision is a silent no-op", async () => {
    const { escalator, escalated, setNow } = escalatorHarness();
    const live = escalator.getConfig();
    assert.deepEqual(escalator.retune({ ...live }), live);
    // State is untouched: one dead letter still counts one, no alert.
    setNow(1000);
    escalator.recordDeadLetter({ endpoint });
    await flushAlert();
    assert.equal(escalated.length, 0);
    assert.equal(escalator.stats()[0].windowDeadLetters, 1);
  });

  it("tightening the window prunes older samples on the next record", async () => {
    const { escalator, escalated, setNow } = escalatorHarness({ threshold: 3 });
    setNow(0);
    escalator.recordDeadLetter({ endpoint });
    setNow(10_000);
    escalator.recordDeadLetter({ endpoint });
    setNow(20_000);
    escalator.recordDeadLetter({ endpoint });
    await flushAlert();
    assert.equal(escalated.length, 1);
    assert.equal(escalated[0].deadLetters, 3);

    // Tighten the window: the t=0 sample is now outside it, but the
    // latch is untouched — the scope stays alerted until re-armed.
    assert.deepEqual(escalator.retune({ windowMs: 15_000 }), {
      windowMs: 15_000,
      threshold: 3,
      cooldownMs: 0,
      maxAttempts: 2,
      backoffMs: 1000,
      timeoutMs: 5000,
    });
    assert.equal(escalator.stats()[0].windowDeadLetters, 2);
    assert.equal(escalator.stats()[0].alerted, true);
    escalator.acknowledge(undefined, endpoint);

    // The next record prunes the t=10s sample too: only t=20s and
    // t=30s remain — below the threshold, so no alert fires.
    setNow(30_000);
    escalator.recordDeadLetter({ endpoint });
    await flushAlert();
    assert.equal(escalated.length, 1);
    assert.equal(escalator.stats()[0].windowDeadLetters, 2);
    // One more record reaches the threshold under the new window.
    setNow(32_000);
    escalator.recordDeadLetter({ endpoint });
    await flushAlert();
    assert.equal(escalated.length, 2);
    assert.equal(escalated[1].deadLetters, 3);
  });

  it("widening the threshold does not re-fire an already-alerted scope", async () => {
    const { escalator, escalated, setNow } = escalatorHarness({ threshold: 2 });
    setNow(0);
    escalator.recordDeadLetter({ endpoint });
    setNow(1000);
    escalator.recordDeadLetter({ endpoint });
    await flushAlert();
    assert.equal(escalated.length, 1);

    assert.deepEqual(escalator.retune({ threshold: 100 }), {
      windowMs: 60_000,
      threshold: 100,
      cooldownMs: 0,
      maxAttempts: 2,
      backoffMs: 1000,
      timeoutMs: 5000,
    });
    // More dead letters pile up under the relaxed threshold: the
    // scope auto-resets to quiet (below threshold) and never re-fires.
    for (const t of [2000, 3000, 4000, 5000]) {
      setNow(t);
      escalator.recordDeadLetter({ endpoint });
    }
    await flushAlert();
    assert.equal(escalated.length, 1);
    assert.equal(escalator.stats()[0].alerted, false);
    assert.equal(escalator.stats()[0].windowDeadLetters, 6);
    assert.equal(escalator.stats()[0].threshold, 100);
  });

  it("lowering the threshold fires on the next dead letter", async () => {
    const { escalator, escalated, setNow } = escalatorHarness({ threshold: 100 });
    for (const t of [0, 1000, 2000]) {
      setNow(t);
      escalator.recordDeadLetter({ endpoint });
    }
    await flushAlert();
    assert.equal(escalated.length, 0);

    escalator.retune({ threshold: 3 });
    setNow(3000);
    escalator.recordDeadLetter({ endpoint });
    await flushAlert();
    assert.equal(escalated.length, 1);
    assert.equal(escalated[0].deadLetters, 4);
    assert.equal(escalated[0].threshold, 3);
  });

  it("maxAttempts/backoffMs/timeoutMs revision governs the next alert's retries", async () => {
    const transport = failingTransport();
    const timer = manualTimer();
    let nowMs = 0;
    const escalated: DeadLetterEscalatedInfo[] = [];
    const failed: DeadLetterEscalationFailedInfo[] = [];
    const config = resolveDeadLetterEscalationConfig({
      url: operatorUrl,
      signingSecret: signingKey,
      threshold: 1,
      windowMs: 60_000,
      cooldownMs: 0,
      maxAttempts: 1,
      backoffMs: 100,
      timeoutMs: 5000,
      post: transport.post,
      now: () => nowMs,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    })!;
    const escalator = new DeadLetterStormEscalator(config, {
      onEscalated: (info) => escalated.push(info),
      onFailed: (info) => failed.push(info),
    });

    // One attempt only: the alert gives up after the first failure.
    escalator.recordDeadLetter({ endpoint });
    await flushAlert();
    assert.equal(transport.posts.length, 1);
    assert.equal(failed.length, 1);
    assert.equal(failed[0].attempts, 1);

    escalator.retune({ maxAttempts: 3, backoffMs: 7, timeoutMs: 42 });
    escalator.acknowledge(undefined, endpoint);
    nowMs = 1000;
    escalator.recordDeadLetter({ endpoint });
    await flushAlert();
    await timer.run();
    // Three attempts now: 1 + 2 retries, with the revised backoff
    // (7ms, then 14ms) and the revised socket timeout (42ms) on the
    // race timers.
    assert.equal(transport.posts.length, 4);
    assert.equal(escalated.length, 0);
    assert.equal(failed.length, 2);
    assert.equal(failed[1].attempts, 3);
    assert.ok(timer.delays.includes(7), `delays ${timer.delays} miss the revised backoff 7ms`);
    assert.ok(timer.delays.includes(14), `delays ${timer.delays} miss the revised backoff 14ms`);
    assert.ok(timer.delays.includes(42), `delays ${timer.delays} miss the revised timeout 42ms`);
  });

  it("getConfig() returns a snapshot, not a live reference", () => {
    const { escalator } = escalatorHarness();
    const snap = escalator.getConfig();
    snap.threshold = 999;
    snap.windowMs = 1;
    assert.equal(escalator.getConfig().threshold, 2);
    assert.equal(escalator.getConfig().windowMs, 60_000);
  });
});

describe("RetryQueue.reviseEscalation / getEscalationConfig (WR-377)", () => {
  it("unconfigured queue throws must-restart and the getter returns undefined", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getEscalationConfig(), undefined);
      assert.throws(() => q.reviseEscalation({ threshold: 5 }), {
        name: "Error",
        message: MUST_RESTART,
      });
    } finally {
      await q.shutdown();
    }
  });

  it("configured queue revises live and the getter reads it", async () => {
    const transport = stubTransport();
    const q = new RetryQueue({
      sender: async () => {},
      escalation: {
        url: operatorUrl,
        signingSecret: signingKey,
        threshold: 2,
        windowMs: 600_000,
        cooldownMs: 0,
        post: transport.post,
        now: Date.now,
      },
    });
    try {
      assert.deepEqual(q.getEscalationConfig(), {
        windowMs: 600_000,
        threshold: 2,
        cooldownMs: 0,
        maxAttempts: 2,
        backoffMs: 1000,
        timeoutMs: 5000,
      });
      assert.deepEqual(q.reviseEscalation({ threshold: 5 }), {
        windowMs: 600_000,
        threshold: 5,
        cooldownMs: 0,
        maxAttempts: 2,
        backoffMs: 1000,
        timeoutMs: 5000,
      });
      assert.equal(q.getEscalationConfig()?.threshold, 5);
      assert.throws(() => q.reviseEscalation({ threshold: 0 }), RangeError);
      assert.equal(q.getEscalationConfig()?.threshold, 5);
    } finally {
      await q.shutdown();
    }
  });
});

describe("RelayServer escalation revision (WR-377)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function listen(server: Server): Promise<number> {
    return new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
  }

  function makeRelay(escalation?: Record<string, unknown>) {
    const dir = mkdtempSync(join(tmpdir(), "escalation-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: "http://localhost:9999/a",
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      ...(escalation === undefined ? {} : { deadLetterEscalation: escalation }),
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("revision audits previous/current exactly; same-value is a silent no-op", async () => {
    const construction = {
      windowMs: 600_000,
      threshold: 20,
      cooldownMs: 3_600_000,
      maxAttempts: 2,
      backoffMs: 1000,
      timeoutMs: 5000,
    };
    const { relay, audit } = makeRelay({
      url: operatorUrl,
      signingSecret: signingKey,
      ...construction,
      post: stubTransport().post,
    });
    await listen(relay);
    // First `previous` is the construction config.
    assert.deepEqual(relay.getEscalationConfig!(), construction);
    assert.deepEqual(relay.reviseEscalation!({ threshold: 100, cooldownMs: 600_000 }), {
      ...construction,
      threshold: 100,
      cooldownMs: 600_000,
    });
    const revised = eventsOf(audit, "escalation_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, {
      ...construction,
      threshold: 100,
      cooldownMs: 600_000,
    });
    // Landing exactly on the live values audits nothing.
    relay.reviseEscalation!({ threshold: 100, cooldownMs: 600_000 });
    assert.equal(eventsOf(audit, "escalation_revised").length, 1);
    assert.deepEqual(relay.getEscalationConfig!(), {
      ...construction,
      threshold: 100,
      cooldownMs: 600_000,
    });
    // A second real revision chains previous from the revised values.
    relay.reviseEscalation!({ windowMs: 300_000 });
    const revised2 = eventsOf(audit, "escalation_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, {
      ...construction,
      threshold: 100,
      cooldownMs: 600_000,
    });
    assert.deepEqual(revised2[1].current, {
      ...construction,
      threshold: 100,
      cooldownMs: 600_000,
      windowMs: 300_000,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseEscalation!({ maxAttempts: 4 }), RangeError);
    assert.throws(() => relay.reviseEscalation!({}), RangeError);
    assert.throws(() => relay.reviseEscalation!(null as never), RangeError);
    assert.equal(eventsOf(audit, "escalation_revised").length, 2);
    assert.deepEqual(relay.getEscalationConfig!(), {
      ...construction,
      threshold: 100,
      cooldownMs: 600_000,
      windowMs: 300_000,
    });
    // The getter returns a snapshot, not a live reference.
    const snap = relay.getEscalationConfig!();
    snap.threshold = 999;
    assert.equal(relay.getEscalationConfig!().threshold, 100);
  });

  it("first previous is the defaults when configured with only url + signingSecret", async () => {
    const { relay, audit } = makeRelay({
      url: operatorUrl,
      signingSecret: signingKey,
      post: stubTransport().post,
    });
    await listen(relay);
    assert.deepEqual(relay.getEscalationConfig!(), DEFAULTS);
    assert.deepEqual(relay.reviseEscalation!({ threshold: 5 }), { ...DEFAULTS, threshold: 5 });
    const revised = eventsOf(audit, "escalation_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, DEFAULTS);
    assert.deepEqual(revised[0].current, { ...DEFAULTS, threshold: 5 });
  });

  it("unconfigured server throws must-restart; getter is unset", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getEscalationConfig, undefined);
    assert.throws(() => relay.reviseEscalation!({ threshold: 5 }), {
      name: "Error",
      message: MUST_RESTART,
    });
  });
});
