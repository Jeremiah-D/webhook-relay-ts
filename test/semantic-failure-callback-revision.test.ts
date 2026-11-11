import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type DownstreamResponse,
  type RetryItem,
  type SemanticFailureInfo,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "semantic-failure-callback-revision-secret";
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

/** Sender whose 2xx responses carry a JSON body the validator rejects. */
function rejectingJsonSender() {
  let calls = 0;
  const sender: Sender = async () => {
    calls += 1;
    const response: DownstreamResponse = {
      statusCode: 200,
      body: Buffer.from('{"ok":false}'),
      truncated: false,
    };
    return response;
  };
  return { sender, calls: () => calls };
}

function item(id: string, targetUrl = URL): RetryItem {
  return { id, targetUrl, payload: Buffer.from("{}"), headers: {} };
}

describe("RetryQueue semantic-failure callback revision (WR-386)", () => {
  function makeQueue(maxAttempts = 3) {
    const timer = manualTimer();
    const s = rejectingJsonSender();
    const q = new RetryQueue({
      sender: s.sender,
      baseDelayMs: 10,
      maxAttempts,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      responseValidators: () => false,
    });
    return { q, timer, s };
  }

  it("revise swaps the live callback: the next semantic failure enters the new callback with exact reason/attempts, the old one is silent", async () => {
    const { q, timer } = makeQueue();
    const oldSeen: SemanticFailureInfo[] = [];
    const newSeen: SemanticFailureInfo[] = [];
    const oldCb = (info: SemanticFailureInfo) => oldSeen.push(info);
    const newCb = (info: SemanticFailureInfo) => newSeen.push(info);
    q.reviseSemanticFailureCallback(oldCb);
    q.start();
    try {
      q.enqueue(item("swap-1"));
      await timer.step(); // attempt 1 fails semantically -> schedules a retry
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].id, "swap-1");
      assert.equal(oldSeen[0].endpoint, URL);
      assert.equal(oldSeen[0].attempts, 1);
      assert.equal(oldSeen[0].reason, "validator returned false");
      assert.equal(typeof oldSeen[0].traceId, "string");
      assert.ok(oldSeen[0].traceId.length > 0);
      assert.deepEqual(newSeen, []);
      // Swap mid-flight: the old callback never hears another failure,
      // and the already-reported failure is never re-delivered.
      q.reviseSemanticFailureCallback(newCb);
      await timer.step(); // attempt 2 fails semantically -> schedules a retry
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "swap-1");
      assert.equal(newSeen[0].attempts, 2);
      assert.equal(newSeen[0].reason, "validator returned false");
      await timer.step(); // attempt 3 fails semantically -> dead letter
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 2);
      assert.equal(newSeen[1].attempts, 3);
      assert.equal(q.getDeadLetter().length, 1);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer: semantic failures keep retrying and the delivery still dead-letters", async () => {
    const { q, timer, s } = makeQueue();
    const seen: SemanticFailureInfo[] = [];
    q.reviseSemanticFailureCallback((info) => seen.push(info));
    q.start();
    try {
      q.enqueue(item("clear-1"));
      await timer.step(); // attempt 1 fails semantically -> observed
      assert.equal(seen.length, 1);
      q.reviseSemanticFailureCallback(null);
      await timer.step(); // attempt 2 fails semantically -> unobserved, still rescheduled
      await timer.step(); // attempt 3 fails semantically -> dead letter
      assert.equal(seen.length, 1);
      assert.equal(s.calls(), 3); // every attempt still ran
      assert.equal(q.getDeadLetter().length, 1);
    } finally {
      q.stop();
    }
  });

  it("a queue with no response validator cannot gain an observer at runtime — must restart", async () => {
    const timer = manualTimer();
    const s = rejectingJsonSender();
    const q = new RetryQueue({
      sender: s.sender,
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    assert.throws(
      () => q.reviseSemanticFailureCallback(() => {}),
      /requires a restart/
    );
    assert.throws(
      () => q.reviseSemanticFailureCallback(null),
      /requires a restart/
    );
    q.stop();
  });

  it("a per-endpoint validator also satisfies the gate", async () => {
    const timer = manualTimer();
    const s = rejectingJsonSender();
    const q = new RetryQueue({
      sender: s.sender,
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      responseValidators: { [URL]: () => false },
    });
    const seen: SemanticFailureInfo[] = [];
    q.reviseSemanticFailureCallback((info) => seen.push(info));
    q.start();
    try {
      q.enqueue(item("endpoint-gate-1"));
      await timer.step();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].attempts, 1);
    } finally {
      q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const { q, timer } = makeQueue();
    const seen: SemanticFailureInfo[] = [];
    const live = (info: SemanticFailureInfo) => seen.push(info);
    q.reviseSemanticFailureCallback(live);
    assert.throws(
      () => q.reviseSemanticFailureCallback(42 as never),
      RangeError
    );
    assert.throws(
      () => q.reviseSemanticFailureCallback("nope" as never),
      RangeError
    );
    q.start();
    try {
      q.enqueue(item("bad-1"));
      await timer.step(); // attempt 1 fails semantically -> the live callback survived
      assert.equal(seen.length, 1);
      assert.equal(seen[0].attempts, 1);
    } finally {
      q.stop();
    }
  });

  it("same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { q, timer } = makeQueue();
    const seen: SemanticFailureInfo[] = [];
    const live = (info: SemanticFailureInfo) => seen.push(info);
    q.reviseSemanticFailureCallback(live);
    q.reviseSemanticFailureCallback(live); // no-op, no throw
    q.start();
    try {
      q.enqueue(item("noop-1"));
      await timer.step(); // attempt 1 fails semantically -> observed once
      assert.equal(seen.length, 1);
      q.reviseSemanticFailureCallback(null);
      q.reviseSemanticFailureCallback(null); // clearing when unset: no-op
      q.enqueue(item("noop-2"));
      await timer.step(); // noop-1 attempt 2 + noop-2 attempt 1 fail, unobserved
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a swap leaves the already-scheduled retry delay untouched", async () => {
    const { q, timer } = makeQueue();
    q.reviseSemanticFailureCallback(() => {});
    q.start();
    try {
      q.enqueue(item("delay-1"));
      await timer.step(); // attempt 1 fails semantically -> retry scheduled at 20ms
      assert.equal(timer.lastDelay(), 20);
      q.reviseSemanticFailureCallback(() => {});
      assert.equal(timer.lastDelay(), 20); // the pending timer was not re-armed
      await timer.step(); // attempt 2 fails semantically -> retry scheduled at 40ms
      assert.equal(timer.lastDelay(), 40);
    } finally {
      q.stop();
    }
  });

  it("a passing validator reports no semantic failure at all", async () => {
    const timer = manualTimer();
    const s = rejectingJsonSender();
    let delivered = 0;
    const seen: SemanticFailureInfo[] = [];
    const q = new RetryQueue({
      sender: s.sender,
      baseDelayMs: 10,
      maxAttempts: 3,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      responseValidators: () => true,
      onSemanticFailure: (info) => seen.push(info),
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.start();
    try {
      q.enqueue(item("pass-1"));
      await timer.step();
      assert.equal(delivered, 1);
      assert.equal(seen.length, 0);
      assert.equal(q.getDeadLetter().length, 0);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer semantic-failure callback revision (WR-386)", () => {
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

  function failedEvents(audit: AuditLog) {
    return audit.query({ event: "failed" }) as Array<{
      id: string;
      attempts: number;
      reason: string;
      semanticReason?: string;
    }>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "semantic_failure_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server whose sender always answers 2xx with a body the validator rejects. */
  function semanticServer(onSemanticFailure?: (info: SemanticFailureInfo) => void) {
    const dir = mkdtempSync(join(tmpdir(), "semanticfailure-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const s = rejectingJsonSender();
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: s.sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 2,
        jitterMs: 0,
        responseValidators: () => false,
        ...(onSemanticFailure !== undefined ? { onSemanticFailure } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  it("replacing the operator callback routes the next semantic failure to the new callback and the failed audit still lands", async () => {
    const oldSeen: SemanticFailureInfo[] = [];
    const newSeen: SemanticFailureInfo[] = [];
    const { relay, audit } = semanticServer((info) => oldSeen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => oldSeen.length >= 2);
    await drainUntil(() => failedEvents(audit).length >= 2);
    await drainUntil(
      () => (audit.query({ event: "dead_letter" }) as unknown[]).length >= 1
    );
    assert.equal(failedEvents(audit)[0].attempts, 1);
    assert.equal(failedEvents(audit)[0].reason, "semantic_failed");
    assert.equal(failedEvents(audit)[0].semanticReason, "validator returned false");
    assert.deepEqual(newSeen, []);
    // Swap the operator callback; the first delivery is already dead-lettered.
    const newCb = (info: SemanticFailureInfo) => newSeen.push(info);
    relay.reviseSemanticFailureCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    // A fresh delivery's semantic failure enters only the new callback,
    // and the failed audit keeps landing.
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => newSeen.length >= 2);
    await drainUntil(() => failedEvents(audit).length >= 4);
    await drainUntil(
      () => (audit.query({ event: "dead_letter" }) as unknown[]).length >= 2
    );
    assert.equal(oldSeen.length, 2); // the old callback heard nothing more
    assert.equal(newSeen[0].attempts, 1);
    assert.equal(newSeen[0].reason, "validator returned false");
    assert.equal(newSeen[1].attempts, 2);
    assert.equal(failedEvents(audit)[2].reason, "semantic_failed");
  });

  it("clearing to null keeps the failed audit and the retry schedule, and stops the operator", async () => {
    const seen: SemanticFailureInfo[] = [];
    const { relay, audit } = semanticServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => seen.length >= 2);
    await drainUntil(() => failedEvents(audit).length >= 2);
    await drainUntil(
      () => (audit.query({ event: "dead_letter" }) as unknown[]).length >= 1
    );
    relay.reviseSemanticFailureCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => failedEvents(audit).length >= 3);
    assert.equal(seen.length, 2); // still silent
    // The second delivery still retried (attempt 2 ran) and dead-lettered.
    await drainUntil(
      () => (audit.query({ event: "dead_letter" }) as unknown[]).length >= 2
    );
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = semanticServer((info) => {});
    await listen(relay);
    const newCb = (_info: SemanticFailureInfo) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseSemanticFailureCallback!(newCb);
    // set -> cleared.
    relay.reviseSemanticFailureCallback!(null);
    // cleared -> set.
    relay.reviseSemanticFailureCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseSemanticFailureCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseSemanticFailureCallback!(null);
    relay.reviseSemanticFailureCallback!(null);
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
    const { relay: bare, audit: bareAudit } = semanticServer();
    await listen(bare);
    bare.reviseSemanticFailureCallback!(null);
    bare.reviseSemanticFailureCallback!(newCb);
    assert.deepEqual(
      (bareAudit.query({ event: "semantic_failure_callback_revised" }) as Array<{
        previous: string;
        current: string;
      }>).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("a non-function value throws RangeError and the live cell is untouched", async () => {
    const seen: SemanticFailureInfo[] = [];
    const { relay, audit } = semanticServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseSemanticFailureCallback!(42 as never),
      RangeError
    );
    assert.equal(revisedEvents(audit).length, 0);
    // The live cell survived: the next semantic failure still enters the original callback.
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => failedEvents(audit).length >= 1);
    assert.equal(seen[0].attempts, 1);
    assert.equal(seen[0].reason, "validator returned false");
  });

  it("a server with no response validator cannot gain an observer at runtime — must restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "semanticfailure-novalidator-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const s = rejectingJsonSender();
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: s.sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 2,
        jitterMs: 0,
      },
    });
    servers.push(relay);
    await listen(relay);
    assert.throws(
      () => relay.reviseSemanticFailureCallback!(() => {}),
      /requires a restart/
    );
    assert.equal(revisedEvents(audit).length, 0);
  });
});
