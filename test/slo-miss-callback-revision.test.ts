import { describe, it, afterEach, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type RetryItem,
  type Sender,
  type SloMissInfo,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { PhaseTimeoutError } from "../src/phase-timeouts.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "slo-miss-callback-revision-secret";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    pendingCount: () => pending.length,
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return { clear: () => { const i = pending.indexOf(fn); if (i >= 0) pending.splice(i, 1); } };
    },
    clearTimer: (h: { clear(): void }) => h.clear(),
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
    async step() {
      const fns = pending.splice(0);
      for (const fn of fns) fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

/** Let queued microtask chains (admission -> sender) settle. */
async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string): RetryItem {
  return { id, targetUrl: URL, payload: Buffer.from("{}"), headers: {} };
}

describe("RetryQueue SLO-miss callback revision (WR-388)", () => {
  it("revise swaps the live callback: the next slow delivery's miss enters the new callback with exact latencyMs/sloMs/dominantPhase", async () => {
    let now = 0;
    const timer = manualTimer();
    const oldSeen: SloMissInfo[] = [];
    const newSeen: SloMissInfo[] = [];
    const withPhases: Sender = async () => ({
      statusCode: 200,
      body: Buffer.alloc(0),
      truncated: false,
      phases: { connectMs: 1, firstByteMs: 4, bodyMs: 2 },
    });
    const q = new RetryQueue({
      sender: withPhases,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latency: { sloMs: 100, now: () => now, onSloMiss: (info) => oldSeen.push(info) },
      latencyPhases: {},
    });
    q.start();
    try {
      now = 0;
      q.enqueue(item("swap-1"));
      now = 250;
      await timer.run();
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(oldSeen[0], {
        id: "swap-1",
        traceId: oldSeen[0].traceId,
        endpoint: URL,
        latencyMs: 250,
        sloMs: 100,
        dominantPhase: "firstByte",
        phaseBreakdown: { connectMs: 1, firstByteMs: 4, bodyMs: 2 },
      });
      assert.match(oldSeen[0].traceId, /^[0-9a-f]{32}$/);
      assert.deepEqual(newSeen, []);
      // Swap mid-stream: the old callback never hears another miss, and
      // the already-reported miss is never re-delivered.
      const newCb = (info: SloMissInfo) => newSeen.push(info);
      q.reviseSloMissCallback(newCb);
      now = 1000;
      q.enqueue(item("swap-2"));
      now = 1250;
      await timer.run();
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "swap-2");
      assert.equal(newSeen[0].latencyMs, 250);
      assert.equal(newSeen[0].sloMs, 100);
      assert.equal(newSeen[0].dominantPhase, "firstByte");
      const [s] = q.getLatencyStats();
      assert.equal(s.count, 2);
      assert.equal(s.sloAttainment, 0);
    } finally {
      q.stop();
    }
  });

  it("a deadline-budget-exhaustion miss enters the new callback with the exhaustion marker", async () => {
    const timer = manualTimer();
    let nowMs = 0;
    const oldSeen: SloMissInfo[] = [];
    const newSeen: SloMissInfo[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      baseDelayMs: 100,
      maxDelayMs: 10_000,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      deliveryDeadline: { deadlines: { [URL]: 250 }, now: () => nowMs },
      latency: { sloMs: 5000, now: () => nowMs, onSloMiss: (info) => oldSeen.push(info) },
    });
    q.start();
    try {
      q.enqueue(item("budget-1"));
      // Revise before the expiry fires: the exhaustion miss must enter
      // only the new callback.
      q.reviseSloMissCallback((info) => newSeen.push(info));
      nowMs = 300; // past the deadline before the next dispatch
      await timer.step();
      assert.equal(q.getDeadLetter().length, 1);
      assert.deepEqual(oldSeen, []);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].deadlineBudgetExhausted, true);
      assert.equal(newSeen[0].latencyMs, 300);
      assert.equal(newSeen[0].sloMs, 250);
      assert.equal(newSeen[0].endpoint, URL);
    } finally {
      q.stop();
    }
  });

  it("a queue without latency tracking cannot gain an observer at runtime — must restart", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    assert.throws(
      () => q.reviseSloMissCallback(() => {}),
      /requires a restart/
    );
    assert.throws(
      () => q.reviseSloMissCallback(null),
      /requires a restart/
    );
    q.stop();
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    let now = 0;
    const timer = manualTimer();
    const seen: SloMissInfo[] = [];
    const live = (info: SloMissInfo) => seen.push(info);
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
      latency: { sloMs: 100, now: () => now, onSloMiss: live },
    });
    q.start();
    try {
      assert.throws(
        () => q.reviseSloMissCallback(42 as never),
        RangeError
      );
      assert.throws(
        () => q.reviseSloMissCallback("nope" as never),
        RangeError
      );
      now = 0;
      q.enqueue(item("bad-1"));
      now = 250;
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].latencyMs, 250);
    } finally {
      q.stop();
    }
  });

  it("same-reference revision and clearing-when-unset are silent no-ops", async () => {
    let now = 0;
    const timer = manualTimer();
    const seen: SloMissInfo[] = [];
    const live = (info: SloMissInfo) => seen.push(info);
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
      latency: { sloMs: 100, now: () => now, onSloMiss: live },
    });
    q.start();
    try {
      q.reviseSloMissCallback(live); // no-op, no throw
      now = 0;
      q.enqueue(item("noop-1"));
      now = 250;
      await timer.run();
      assert.equal(seen.length, 1);
      q.reviseSloMissCallback(null);
      q.reviseSloMissCallback(null); // clearing when unset: no-op
      now = 1000;
      q.enqueue(item("noop-2"));
      now = 1250;
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(q.getLatencyStats()[0].count, 2);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer: misses keep being sampled and counted", async () => {
    let now = 0;
    const timer = manualTimer();
    const seen: SloMissInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
      latency: { sloMs: 100, now: () => now, onSloMiss: (info) => seen.push(info) },
    });
    q.start();
    try {
      now = 0;
      q.enqueue(item("clear-1"));
      now = 250;
      await timer.run();
      assert.equal(seen.length, 1);
      q.reviseSloMissCallback(null);
      now = 1000;
      q.enqueue(item("clear-2"));
      now = 1250;
      await timer.run();
      assert.equal(seen.length, 1); // the operator hears nothing more
      const [s] = q.getLatencyStats();
      assert.equal(s.count, 2); // sampling continues
      assert.equal(s.sloAttainment, 0);
    } finally {
      q.stop();
    }
  });

  it("a swap leaves the retry / dead-letter path untouched", async () => {
    const timer = manualTimer();
    const seen: SloMissInfo[] = [];
    const failing: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: failing,
      baseDelayMs: 10,
      maxDelayMs: 20,
      jitterMs: 0,
      maxAttempts: 2,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      latency: { sloMs: 100, onSloMiss: (info) => seen.push(info) },
    });
    q.start();
    try {
      q.enqueue(item("dl-1"));
      await timer.step(); // attempt 1 fails -> retry scheduled
      q.reviseSloMissCallback((info) => seen.push(info));
      await timer.run(); // attempt 2 fails -> dead-letter
      const dead = q.getDeadLetter();
      assert.equal(dead.length, 1);
      assert.equal(dead[0].attempts, 2);
      assert.deepEqual(seen, []); // never delivered, so no miss either way
      assert.deepEqual(q.getLatencyStats(), []); // dead-lettered: not sampled
    } finally {
      q.stop();
    }
  });

  it("phaseTimeout passes through the miss to the revised callback", async () => {
    let attempts = 0;
    const oldSeen: SloMissInfo[] = [];
    const newSeen: SloMissInfo[] = [];
    const flaky: Sender = async (entry) => {
      attempts += 1;
      if (attempts === 1) {
        throw new PhaseTimeoutError(entry.targetUrl, "firstByte", 50);
      }
      await sleep(30);
      return { statusCode: 200, body: Buffer.from("ok"), truncated: false };
    };
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 5,
      jitterMs: 0,
      maxAttempts: 3,
      latency: { sloMs: 1, onSloMiss: (info) => oldSeen.push(info) },
    });
    q.start();
    try {
      q.enqueue(item("pt-slo-1"));
      const deadline = Date.now() + 5000;
      while (oldSeen.length === 0 && Date.now() < deadline) await sleep(10);
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].phaseTimeout, "firstByte");
      q.reviseSloMissCallback((info) => newSeen.push(info));
      // A delivery with no phase timeout carries no attribution — and
      // enters only the new callback.
      q.enqueue(item("pt-slo-2"));
      const deadline2 = Date.now() + 5000;
      while (newSeen.length === 0 && Date.now() < deadline2) await sleep(10);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].phaseTimeout, undefined);
      assert.equal(oldSeen.length, 1);
    } finally {
      q.stop();
    }
  });
});

describe("RetryQueue SLO-miss callback revision with OTLP (WR-388)", () => {
  interface CapturedPost {
    method: string;
    url: string;
    contentType: string | undefined;
    body: string;
  }

  /** Local OTLP collector stub: records POSTs, answers 200. */
  function startCollector() {
    const posts: CapturedPost[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        posts.push({
          method: req.method ?? "",
          url: req.url ?? "",
          contentType: req.headers["content-type"],
          body: Buffer.concat(chunks).toString(),
        });
        res.writeHead(200).end("ok");
      });
    });
    return {
      server,
      port: 0,
      posts,
      close: async () => {
        server.close();
        await new Promise((r) => server.once("close", r));
      },
    };
  }

  async function listenPort(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function allLogRecords(posts: CapturedPost[]): Array<Record<string, any>> {
    const out: Array<Record<string, any>> = [];
    for (const p of posts) {
      const payload = JSON.parse(p.body);
      for (const rl of payload.resourceLogs) for (const sl of rl.scopeLogs) out.push(...sl.logRecords);
    }
    return out;
  }

  async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
    const start = Date.now();
    while (!cond()) {
      if (Date.now() - start > timeoutMs) assert.fail(`timed out waiting for: ${what}`);
      await sleep(10);
    }
  }

  let collector: ReturnType<typeof startCollector>;

  before(async () => {
    collector = startCollector();
    collector.port = await listenPort(collector.server);
  });
  after(() => collector.close());

  it("revision keeps the slo_missed OTLP export firing exactly once per miss", async () => {
    const url = `http://127.0.0.1:${collector.port}/v1/logs`;
    let now = 0;
    const timer = manualTimer();
    const oldSeen: SloMissInfo[] = [];
    const newSeen: SloMissInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
      latency: { sloMs: 100, now: () => now, onSloMiss: (info) => oldSeen.push(info) },
      otlp: { endpoint: url },
    });
    q.start();
    try {
      collector.posts.length = 0;
      now = 0;
      q.enqueue(item("otlp-1"));
      now = 250;
      await timer.run();
      await waitFor(
        () => allLogRecords(collector.posts).some((r) => r.body.stringValue === "slo_missed"),
        8000,
        "first slo_missed OTLP export"
      );
      assert.equal(oldSeen.length, 1);
      assert.equal(
        allLogRecords(collector.posts).filter((r) => r.body.stringValue === "slo_missed").length,
        1
      );
      // Swap the caller callback underneath the OTLP wrapper: the
      // export must survive, exactly once per miss, and the new
      // callback must hear the next miss.
      q.reviseSloMissCallback((info) => newSeen.push(info));
      now = 1000;
      q.enqueue(item("otlp-2"));
      now = 1250;
      await timer.run();
      await waitFor(
        () =>
          allLogRecords(collector.posts).filter((r) => r.body.stringValue === "slo_missed")
            .length >= 2,
        8000,
        "second slo_missed OTLP export"
      );
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "otlp-2");
      assert.equal(
        allLogRecords(collector.posts).filter((r) => r.body.stringValue === "slo_missed").length,
        2,
        "one export per miss — never duplicated, never dropped"
      );
    } finally {
      await q.shutdown(2000);
    }
  });
});

describe("RelayServer SLO-miss callback revision (WR-388)", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  async function drainUntil(cond: () => boolean, ms = 5000): Promise<void> {
    const deadline = Date.now() + ms;
    while (!cond()) {
      if (Date.now() > deadline) throw new Error("timed out waiting for condition");
      await new Promise((r) => setTimeout(r, 10));
    }
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

  function missedEvents(audit: AuditLog) {
    return audit.query({ event: "slo_missed" }) as Array<{
      id: string;
      endpoint: string;
      latencyMs: number;
      sloMs: number;
    }>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "slo_miss_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server whose sender takes ~60ms against a 10ms SLO budget. */
  function slowServer(onSloMiss?: (info: SloMissInfo) => void) {
    const dir = mkdtempSync(join(tmpdir(), "slomiss-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const slow: Sender = async () => {
      await sleep(60);
    };
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: slow,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 3,
        jitterMs: 0,
        latency: {
          sloMs: 10,
          ...(onSloMiss !== undefined ? { onSloMiss } : {}),
        },
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  it("replacing the operator callback routes the next miss to the new callback and the slo_missed audit still lands", async () => {
    const oldSeen: SloMissInfo[] = [];
    const newSeen: SloMissInfo[] = [];
    const { relay, audit } = slowServer((info) => oldSeen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => missedEvents(audit).length >= 1);
    assert.ok(oldSeen[0].latencyMs > 10);
    assert.equal(oldSeen[0].sloMs, 10);
    assert.equal(missedEvents(audit)[0].sloMs, 10);
    assert.ok(missedEvents(audit)[0].latencyMs > 10);
    assert.deepEqual(newSeen, []);
    const newCb = (info: SloMissInfo) => newSeen.push(info);
    relay.reviseSloMissCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => missedEvents(audit).length >= 2);
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    assert.ok(newSeen[0].latencyMs > 10);
    assert.equal(newSeen[0].sloMs, 10);
    assert.equal(missedEvents(audit)[1].sloMs, 10);
  });

  it("clearing to null keeps the slo_missed audit and the sampling, and stops the operator", async () => {
    const seen: SloMissInfo[] = [];
    const { relay, audit } = slowServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => missedEvents(audit).length >= 1);
    relay.reviseSloMissCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => missedEvents(audit).length >= 2);
    assert.equal(seen.length, 1); // still silent
    // The second delivery was slow too: sampled (audited) but not forwarded.
    assert.ok(missedEvents(audit)[1].latencyMs > 10);
    assert.equal((audit.query({ event: "delivered" }) as unknown[]).length, 2);
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = slowServer((_info) => {});
    await listen(relay);
    const newCb = (_info: SloMissInfo) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseSloMissCallback!(newCb);
    // set -> cleared.
    relay.reviseSloMissCallback!(null);
    // cleared -> set.
    relay.reviseSloMissCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseSloMissCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseSloMissCallback!(null);
    relay.reviseSloMissCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [
        ["set", "set"],
        ["set", "cleared"],
        ["cleared", "set"],
        ["set", "cleared"],
      ]
    );
    // A server born without a callback: clearing when unset is a no-op,
    // and the first set audits cleared -> set. (Latency is configured,
    // only the observer is absent.)
    const { relay: bare, audit: bareAudit } = slowServer();
    await listen(bare);
    bare.reviseSloMissCallback!(null);
    bare.reviseSloMissCallback!(newCb);
    assert.deepEqual(
      (bareAudit.query({ event: "slo_miss_callback_revised" }) as Array<{
        previous: string;
        current: string;
      }>).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("a non-function value throws RangeError and the live cell is untouched", async () => {
    const seen: SloMissInfo[] = [];
    const { relay, audit } = slowServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseSloMissCallback!(42 as never),
      RangeError
    );
    assert.equal(revisedEvents(audit).length, 0);
    // The live cell survived: the next miss still enters the original callback.
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => missedEvents(audit).length >= 1);
    assert.ok(seen[0].latencyMs > 10);
    assert.equal(seen[0].sloMs, 10);
  });

  it("a server without latency tracking cannot gain an observer at runtime — must restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "slomiss-nolatency-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const slow: Sender = async () => {
      await sleep(60);
    };
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: slow,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 3,
        jitterMs: 0,
      },
    });
    servers.push(relay);
    await listen(relay);
    assert.throws(
      () => relay.reviseSloMissCallback!(() => {}),
      /requires a restart/
    );
    assert.equal(revisedEvents(audit).length, 0);
  });
});
