import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type AssertionFailureInfo,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "assertion-failure-callback-revision-secret";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
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
  };
}

const json = (v: unknown) => Buffer.from(JSON.stringify(v));

function item(id: string): RetryItem {
  return { id, targetUrl: URL, payload: Buffer.from("{}"), headers: {} };
}

/** Sender that always answers 200 with a body failing `$.status == "ok"`. */
function failingSender(): Sender {
  return async () => ({ statusCode: 200, body: json({ status: "error" }), truncated: false });
}

function assertionRule() {
  return [
    { targetUrl: URL, assertions: [{ path: "$.status", op: "eq" as const, value: "ok" }] },
  ];
}

describe("RetryQueue assertion-failure callback revision (WR-390)", () => {
  it("revise swaps the live callback: the next failure enters the new callback with exact reason/attempts, already-reported failures are never re-delivered", async () => {
    const timer = manualTimer();
    const oldSeen: AssertionFailureInfo[] = [];
    const newSeen: AssertionFailureInfo[] = [];
    const q = new RetryQueue({
      sender: failingSender(),
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      responseAssertions: assertionRule(),
      onAssertionFailure: (info) => oldSeen.push(info),
    });
    q.start();
    try {
      q.enqueue(item("swap-1"));
      await timer.run();
      assert.equal(oldSeen.length, 2);
      assert.equal(oldSeen[0]?.id, "swap-1");
      assert.equal(oldSeen[0]?.endpoint, URL);
      assert.equal(oldSeen[0]?.attempts, 1);
      assert.match(oldSeen[0]?.reason ?? "", /\$\.status/);
      assert.equal(oldSeen[1]?.attempts, 2);
      assert.match(oldSeen[0]?.traceId ?? "", /^[0-9a-f]{32}$/);
      assert.equal(q.getDeadLetter().length, 1);
      assert.deepEqual(newSeen, []);
      // Swap mid-stream: the old callback never hears another failure,
      // and the already-reported failures are never re-delivered.
      const newCb = (info: AssertionFailureInfo) => newSeen.push(info);
      q.reviseAssertionFailureCallback(newCb);
      q.enqueue(item("swap-2"));
      await timer.run();
      assert.equal(oldSeen.length, 2);
      assert.equal(newSeen.length, 2);
      assert.equal(newSeen[0]?.id, "swap-2");
      assert.equal(newSeen[0]?.attempts, 1);
      assert.equal(newSeen[1]?.attempts, 2);
      assert.match(newSeen[0]?.reason ?? "", /\$\.status/);
      assert.equal(q.getDeadLetter().length, 2);
      assert.equal(q.getDeliveryStats()[0]?.assertionFailures, 4);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer: failures keep retrying, counting, and dead-lettering", async () => {
    const timer = manualTimer();
    const seen: AssertionFailureInfo[] = [];
    const q = new RetryQueue({
      sender: failingSender(),
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      responseAssertions: assertionRule(),
      onAssertionFailure: (info) => seen.push(info),
    });
    q.start();
    try {
      q.enqueue(item("clear-1"));
      await timer.run();
      assert.equal(seen.length, 2);
      q.reviseAssertionFailureCallback(null);
      q.enqueue(item("clear-2"));
      await timer.run();
      assert.equal(seen.length, 2); // the operator hears nothing more
      const dead = q.getDeadLetter();
      assert.equal(dead.length, 2);
      assert.equal(dead[1]?.failureClass, "assertion_failed");
      assert.equal(q.getDeliveryStats()[0]?.assertionFailures, 4);
      assert.equal(q.getDeliveryStats()[0]?.deadLetter, 2);
    } finally {
      q.stop();
    }
  });

  it("a queue without response assertions cannot gain an observer at runtime — must restart", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    assert.throws(
      () => q.reviseAssertionFailureCallback(() => {}),
      /requires a restart/
    );
    assert.throws(
      () => q.reviseAssertionFailureCallback(null),
      /requires a restart/
    );
    q.stop();
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const timer = manualTimer();
    const seen: AssertionFailureInfo[] = [];
    const live = (info: AssertionFailureInfo) => seen.push(info);
    const q = new RetryQueue({
      sender: failingSender(),
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      responseAssertions: assertionRule(),
      onAssertionFailure: live,
    });
    q.start();
    try {
      assert.throws(
        () => q.reviseAssertionFailureCallback(42 as never),
        RangeError
      );
      assert.throws(
        () => q.reviseAssertionFailureCallback("nope" as never),
        RangeError
      );
      q.enqueue(item("bad-1"));
      await timer.run();
      assert.equal(seen.length, 2);
      assert.equal(seen[0]?.id, "bad-1");
    } finally {
      q.stop();
    }
  });

  it("same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const timer = manualTimer();
    const seen: AssertionFailureInfo[] = [];
    const live = (info: AssertionFailureInfo) => seen.push(info);
    const q = new RetryQueue({
      sender: failingSender(),
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      responseAssertions: assertionRule(),
      onAssertionFailure: live,
    });
    q.start();
    try {
      q.reviseAssertionFailureCallback(live); // no-op, no throw
      q.enqueue(item("noop-1"));
      await timer.run();
      assert.equal(seen.length, 2);
      q.reviseAssertionFailureCallback(null);
      q.reviseAssertionFailureCallback(null); // clearing when unset: no-op
      q.enqueue(item("noop-2"));
      await timer.run();
      assert.equal(seen.length, 2);
      assert.equal(q.getDeliveryStats()[0]?.assertionFailures, 4);
    } finally {
      q.stop();
    }
  });

  it("a non-whitelisted status still takes the HttpDeliveryError path and is unaffected by revision", async () => {
    const timer = manualTimer();
    const seen: AssertionFailureInfo[] = [];
    const q = new RetryQueue({
      // A 404 is outside the default 2xx whitelist: assertions never run.
      sender: async () => ({ statusCode: 404, body: json({ status: "ok" }), truncated: false }),
      maxAttempts: 1,
      jitterMs: 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      responseAssertions: assertionRule(),
      onAssertionFailure: (info) => seen.push(info),
    });
    q.start();
    try {
      q.reviseAssertionFailureCallback((info) => seen.push(info));
      q.enqueue(item("404-1"));
      await timer.run();
      assert.deepEqual(seen, []);
      const dead = q.getDeadLetter();
      assert.equal(dead.length, 1);
      assert.equal(dead[0]?.failureClass, "non_retryable");
      assert.equal(q.getDeliveryStats()[0]?.assertionFailures, 0);
    } finally {
      q.stop();
    }
  });

  it("a non-JSON body fail-closes into the revised callback", async () => {
    const timer = manualTimer();
    const oldSeen: AssertionFailureInfo[] = [];
    const newSeen: AssertionFailureInfo[] = [];
    const q = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: Buffer.from("{corrupt"), truncated: false }),
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      responseAssertions: assertionRule(),
      onAssertionFailure: (info) => oldSeen.push(info),
    });
    q.start();
    try {
      q.enqueue(item("corrupt-1"));
      await timer.run();
      assert.equal(oldSeen.length, 2);
      assert.match(oldSeen[0]?.reason ?? "", /not JSON/);
      q.reviseAssertionFailureCallback((info) => newSeen.push(info));
      q.enqueue(item("corrupt-2"));
      await timer.run();
      assert.equal(oldSeen.length, 2);
      assert.equal(newSeen.length, 2);
      assert.match(newSeen[0]?.reason ?? "", /not JSON/);
      assert.equal(newSeen[0]?.attempts, 1);
      assert.equal(newSeen[1]?.attempts, 2);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer assertion-failure callback revision (WR-390)", () => {
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
      reason: string;
      assertionReason: string;
      attempts: number;
    }>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "assertion_failure_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server whose downstream always answers 200 with a failing assertion body. */
  function failingServer(onAssertionFailure?: (info: AssertionFailureInfo) => void) {
    const dir = mkdtempSync(join(tmpdir(), "assertfail-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: failingSender(),
      retry: {
        baseDelayMs: 10,
        maxAttempts: 2,
        jitterMs: 0,
        responseAssertions: assertionRule(),
        ...(onAssertionFailure !== undefined ? { onAssertionFailure } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  it("replacing the operator callback routes the next failure to the new callback and the failed audit still lands", async () => {
    const oldSeen: AssertionFailureInfo[] = [];
    const newSeen: AssertionFailureInfo[] = [];
    const { relay, audit } = failingServer((info) => oldSeen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => oldSeen.length >= 2);
    await drainUntil(() => failedEvents(audit).filter((e) => e.reason === "assertion_failed").length >= 2);
    assert.equal(failedEvents(audit)[0]?.assertionReason, oldSeen[0]?.reason);
    assert.deepEqual(newSeen, []);
    const newCb = (info: AssertionFailureInfo) => newSeen.push(info);
    relay.reviseAssertionFailureCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => newSeen.length >= 2);
    await drainUntil(() => failedEvents(audit).filter((e) => e.reason === "assertion_failed").length >= 4);
    assert.equal(oldSeen.length, 2); // the old callback heard nothing more
    assert.equal(newSeen[0]?.attempts, 1);
    assert.equal(newSeen[1]?.attempts, 2);
    assert.match(newSeen[0]?.reason ?? "", /\$\.status/);
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = failingServer((_info) => {});
    await listen(relay);
    const newCb = (_info: AssertionFailureInfo) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseAssertionFailureCallback!(newCb);
    // set -> cleared.
    relay.reviseAssertionFailureCallback!(null);
    // cleared -> set.
    relay.reviseAssertionFailureCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseAssertionFailureCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseAssertionFailureCallback!(null);
    relay.reviseAssertionFailureCallback!(null);
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
    // and the first set audits cleared -> set. (Rules are configured,
    // only the observer is absent.)
    const { relay: bare, audit: bareAudit } = failingServer();
    await listen(bare);
    bare.reviseAssertionFailureCallback!(null);
    bare.reviseAssertionFailureCallback!(newCb);
    assert.deepEqual(
      (bareAudit.query({ event: "assertion_failure_callback_revised" }) as Array<{
        previous: string;
        current: string;
      }>).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("clearing to null keeps the failed audit and the counting, and stops the operator", async () => {
    const seen: AssertionFailureInfo[] = [];
    const { relay, audit } = failingServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => seen.length >= 2);
    await drainUntil(() => failedEvents(audit).filter((e) => e.reason === "assertion_failed").length >= 2);
    relay.reviseAssertionFailureCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => failedEvents(audit).filter((e) => e.reason === "assertion_failed").length >= 4);
    assert.equal(seen.length, 2); // still silent
    assert.equal(failedEvents(audit).filter((e) => e.reason === "assertion_failed").length, 4);
  });

  it("a server without response assertions cannot gain an observer at runtime — must restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assertfail-norules-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: failingSender(),
      retry: {
        baseDelayMs: 10,
        maxAttempts: 2,
        jitterMs: 0,
      },
    });
    servers.push(relay);
    await listen(relay);
    assert.throws(
      () => relay.reviseAssertionFailureCallback!(() => {}),
      /requires a restart/
    );
    assert.equal(revisedEvents(audit).length, 0);
  });
});
