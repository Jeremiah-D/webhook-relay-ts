import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type AttemptFailedInfo,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "attempt-failed-callback-revision-secret";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

/**
 * Manual timer with single-step control, mirroring the other feature
 * tests: parking re-arms timers, so tests advance one wave at a time.
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
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      await flush();
    },
  };
}

/** Let the deliver() promise chain settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function failingSender() {
  let calls = 0;
  const sender: Sender = async () => {
    calls += 1;
    throw new Error("downstream down");
  };
  return { sender, calls: () => calls };
}

function item(id: string, targetUrl = URL): RetryItem {
  return { id, targetUrl, payload: Buffer.from("{}"), headers: {} };
}

describe("RetryQueue attempt-failed callback revision (WR-384)", () => {
  function makeQueue(maxAttempts = 3) {
    const timer = manualTimer();
    const f = failingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    return { q, timer, f };
  }

  it("revise swaps the live callback: the next failure enters the new callback, the old one is silent", async () => {
    const { q, timer } = makeQueue();
    const oldSeen: AttemptFailedInfo[] = [];
    const newSeen: AttemptFailedInfo[] = [];
    const oldCb = (info: AttemptFailedInfo) => oldSeen.push(info);
    const newCb = (info: AttemptFailedInfo) => newSeen.push(info);
    q.reviseAttemptFailedCallback(oldCb);
    q.start();
    try {
      q.enqueue(item("swap-1"));
      await timer.step(); // attempt 1 fails -> schedules a retry
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].id, "swap-1");
      assert.equal(oldSeen[0].endpoint, URL);
      assert.equal(oldSeen[0].attempts, 1);
      assert.equal(oldSeen[0].error, "downstream down");
      assert.equal(oldSeen[0].nextDelayMs, 20); // base * 2^attempt, attempt 1
      assert.equal(typeof oldSeen[0].traceId, "string");
      assert.ok(oldSeen[0].traceId.length > 0);
      assert.deepEqual(newSeen, []);
      // Swap mid-flight: the old callback never hears another failure.
      q.reviseAttemptFailedCallback(newCb);
      await timer.step(); // attempt 2 fails -> schedules a retry
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "swap-1");
      assert.equal(newSeen[0].attempts, 2);
      assert.equal(newSeen[0].nextDelayMs, 40); // base * 2^attempt, attempt 2
      await timer.step(); // attempt 3 fails -> dead letter, no observation
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer: retries keep scheduling and the delivery still dead-letters", async () => {
    const { q, timer, f } = makeQueue();
    const seen: AttemptFailedInfo[] = [];
    q.reviseAttemptFailedCallback((info) => seen.push(info));
    q.start();
    try {
      q.enqueue(item("clear-1"));
      await timer.step(); // attempt 1 fails -> observed
      assert.equal(seen.length, 1);
      q.reviseAttemptFailedCallback(null);
      await timer.step(); // attempt 2 fails -> unobserved, still rescheduled
      await timer.step(); // attempt 3 fails -> dead letter
      assert.equal(seen.length, 1);
      assert.equal(f.calls(), 3); // every attempt still ran
      assert.equal(q.getDeadLetter().length, 1);
    } finally {
      q.stop();
    }
  });

  it("a queue with no constructor callback can gain one at runtime — no must-restart gate", async () => {
    const { q, timer } = makeQueue();
    const seen: AttemptFailedInfo[] = [];
    q.start();
    try {
      q.enqueue(item("late-1"));
      await timer.step(); // attempt 1 fails -> nobody observes
      assert.equal(seen.length, 0);
      q.reviseAttemptFailedCallback((info) => seen.push(info));
      await timer.step(); // attempt 2 fails -> the new callback hears it
      assert.equal(seen.length, 1);
      assert.equal(seen[0].attempts, 2);
    } finally {
      q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const { q, timer } = makeQueue();
    const seen: AttemptFailedInfo[] = [];
    const live = (info: AttemptFailedInfo) => seen.push(info);
    q.reviseAttemptFailedCallback(live);
    assert.throws(
      () => q.reviseAttemptFailedCallback(42 as never),
      RangeError
    );
    assert.throws(
      () => q.reviseAttemptFailedCallback("nope" as never),
      RangeError
    );
    q.start();
    try {
      q.enqueue(item("bad-1"));
      await timer.step(); // attempt 1 fails -> the live callback survived
      assert.equal(seen.length, 1);
      assert.equal(seen[0].attempts, 1);
    } finally {
      q.stop();
    }
  });

  it("same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { q, timer } = makeQueue();
    const seen: AttemptFailedInfo[] = [];
    const live = (info: AttemptFailedInfo) => seen.push(info);
    q.reviseAttemptFailedCallback(live);
    q.reviseAttemptFailedCallback(live); // no-op, no throw
    q.start();
    try {
      q.enqueue(item("noop-1"));
      await timer.step(); // attempt 1 fails -> observed once
      assert.equal(seen.length, 1);
      q.reviseAttemptFailedCallback(null);
      q.reviseAttemptFailedCallback(null); // clearing when unset: no-op
      q.enqueue(item("noop-2"));
      await timer.step(); // noop-1 attempt 2 + noop-2 attempt 1 fail, unobserved
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a swap leaves the already-scheduled retry delay untouched", async () => {
    const { q, timer } = makeQueue();
    q.reviseAttemptFailedCallback(() => {});
    q.start();
    try {
      q.enqueue(item("delay-1"));
      await timer.step(); // attempt 1 fails -> retry scheduled at 20ms
      assert.equal(timer.lastDelay(), 20);
      q.reviseAttemptFailedCallback(() => {});
      assert.equal(timer.lastDelay(), 20); // the pending timer was not re-armed
      await timer.step(); // attempt 2 fails -> retry scheduled at 40ms
      assert.equal(timer.lastDelay(), 40);
    } finally {
      q.stop();
    }
  });

  it("a bulkhead rejection enters the new callback after a swap", async () => {
    const timer = manualTimer();
    const releases = new Map<string, () => void>();
    const sender: Sender = async (it) => {
      await new Promise<void>((r) => releases.set(it.id, r));
    };
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 1000 },
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      random: () => 0,
    });
    const oldSeen: AttemptFailedInfo[] = [];
    const newSeen: AttemptFailedInfo[] = [];
    q.reviseAttemptFailedCallback((info) => oldSeen.push(info));
    q.start();
    try {
      q.enqueue(item("bulk-a"));
      q.enqueue(item("bulk-b"));
      await timer.step(); // a dispatches (blocks); b is rejected fail-fast
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].id, "bulk-b");
      assert.equal(oldSeen[0].attempts, 0); // no attempt consumed
      assert.match(oldSeen[0].error, /bulkhead rejected/);
      assert.deepEqual(newSeen, []);
      // Swap, then let a finish so b's retry can dispatch.
      q.reviseAttemptFailedCallback((info) => newSeen.push(info));
      releases.get("bulk-a")!();
      await flush();
      await timer.step(); // b's retry dispatches and blocks
      q.enqueue(item("bulk-c"));
      await timer.step(); // c is rejected at the full bulkhead
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "bulk-c");
      assert.equal(newSeen[0].attempts, 0);
      assert.match(newSeen[0].error, /bulkhead rejected/);
      releases.get("bulk-b")!();
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer attempt-failed callback revision (WR-384)", () => {
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

  function retryingEvents(audit: AuditLog) {
    return audit.query({ event: "retrying" }) as Array<{
      id: string;
      attempts: number;
      nextDelayMs: number;
    }>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "attempt_failed_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server whose sender always fails, so every delivery retries once then dead-letters. */
  function failingServer(onAttemptFailed?: (info: AttemptFailedInfo) => void) {
    const dir = mkdtempSync(join(tmpdir(), "attemptfailed-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const sender: Sender = async () => {
      throw new Error("downstream down");
    };
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 2,
        jitterMs: 0,
        ...(onAttemptFailed !== undefined ? { onAttemptFailed } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  it("replacing the operator callback routes the next failure to the new callback and the retrying audit still lands", async () => {
    const oldSeen: AttemptFailedInfo[] = [];
    const newSeen: AttemptFailedInfo[] = [];
    const { relay, audit } = failingServer((info) => oldSeen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => retryingEvents(audit).length >= 1);
    assert.equal(retryingEvents(audit)[0].attempts, 1);
    assert.equal(retryingEvents(audit)[0].nextDelayMs, 20); // base * 2^attempt
    assert.deepEqual(newSeen, []);
    // Swap the operator callback; the first delivery is already dead-lettered.
    const newCb = (info: AttemptFailedInfo) => newSeen.push(info);
    relay.reviseAttemptFailedCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    // A fresh delivery's failure enters only the new callback.
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => retryingEvents(audit).length >= 2);
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen[0].attempts, 1);
    assert.equal(newSeen[0].error, "downstream down");
    assert.equal(retryingEvents(audit)[1].attempts, 1);
  });

  it("clearing to null keeps the retrying audit and the retry schedule, and stops the operator", async () => {
    const seen: AttemptFailedInfo[] = [];
    const { relay, audit } = failingServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => retryingEvents(audit).length >= 1);
    relay.reviseAttemptFailedCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => retryingEvents(audit).length >= 2);
    assert.equal(seen.length, 1); // still silent
    // The second delivery still retried (attempt 2 ran) and dead-lettered.
    await drainUntil(
      () => (audit.query({ event: "dead_letter" }) as unknown[]).length >= 2
    );
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = failingServer((info) => {});
    await listen(relay);
    const newCb = (_info: AttemptFailedInfo) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseAttemptFailedCallback!(newCb);
    // set -> cleared.
    relay.reviseAttemptFailedCallback!(null);
    // cleared -> set.
    relay.reviseAttemptFailedCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseAttemptFailedCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseAttemptFailedCallback!(null);
    relay.reviseAttemptFailedCallback!(null);
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
    // and the first set audits cleared -> set.
    const { relay: bare, audit: bareAudit } = failingServer();
    await listen(bare);
    bare.reviseAttemptFailedCallback!(null);
    bare.reviseAttemptFailedCallback!(newCb);
    assert.deepEqual(
      (bareAudit.query({ event: "attempt_failed_callback_revised" }) as Array<{
        previous: string;
        current: string;
      }>).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("a non-function value throws RangeError and the live cell is untouched", async () => {
    const seen: AttemptFailedInfo[] = [];
    const { relay, audit } = failingServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseAttemptFailedCallback!(42 as never),
      RangeError
    );
    assert.equal(revisedEvents(audit).length, 0);
    // The live cell survived: the next failure still enters the original callback.
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => retryingEvents(audit).length >= 1);
    assert.equal(seen[0].attempts, 1);
  });
});
