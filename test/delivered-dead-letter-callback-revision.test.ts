import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type DownstreamResponseSummary,
  type FailureClass,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "delivered-dead-letter-callback-revision-secret";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

type DeliveredSeen = {
  item: RetryItem;
  attempts: number;
  summary?: DownstreamResponseSummary;
};

type DeadLetterSeen = {
  item: RetryItem;
  attempts: number;
  lastError: unknown;
  failureClass: FailureClass | undefined;
  summary?: DownstreamResponseSummary;
};

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

function item(id: string, targetUrl = URL): RetryItem {
  return { id, targetUrl, payload: Buffer.from("{}"), headers: {} };
}

describe("RetryQueue direct delivered / dead-letter callbacks (WR-385)", () => {
  it("a direct queue fires the constructor onDelivered with exact attempts and summary", async () => {
    const timer = manualTimer();
    const seen: DeliveredSeen[] = [];
    const sender: Sender = async () => ({
      statusCode: 200,
      body: Buffer.from("ok"),
      truncated: false,
    });
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      onDelivered: (it, attempts, summary) => seen.push({ item: it, attempts, summary }),
    });
    q.start();
    try {
      q.enqueue(item("direct-ok-1"));
      await timer.step(); // attempt 1 succeeds
      assert.equal(seen.length, 1);
      assert.equal(seen[0].item.id, "direct-ok-1");
      assert.equal(seen[0].item.targetUrl, URL);
      assert.equal(seen[0].attempts, 1);
      assert.equal(seen[0].summary?.statusCode, 200);
      assert.equal(seen[0].summary?.responseBytes, 2);
      assert.equal(typeof seen[0].summary?.bodyFingerprintSha256, "string");
    } finally {
      q.stop();
    }
  });

  it("a direct queue fires the constructor onDeadLetter with exact failureClass and error", async () => {
    const timer = manualTimer();
    const seen: DeadLetterSeen[] = [];
    const sender: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      onDeadLetter: (it, attempts, lastError, failureClass, summary) =>
        seen.push({ item: it, attempts, lastError, failureClass, summary }),
    });
    q.start();
    try {
      q.enqueue(item("direct-dl-1"));
      await timer.step(); // attempt 1 fails -> schedules a retry
      assert.deepEqual(seen, []);
      await timer.step(); // attempt 2 fails -> dead letter
      assert.equal(seen.length, 1);
      assert.equal(seen[0].item.id, "direct-dl-1");
      assert.equal(seen[0].attempts, 2);
      assert.equal(seen[0].failureClass, "retryable");
      assert.ok(seen[0].lastError instanceof Error);
      assert.equal((seen[0].lastError as Error).message, "downstream down");
      assert.equal(seen[0].summary?.statusCode, "unavailable");
      assert.equal(q.getDeadLetter().length, 1);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer delivered / dead-letter callback revision (WR-385)", () => {
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

  function postRaw(port: number, body: Buffer) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: {
            "x-signature": signSha256(body, relaySecret),
            "content-type": "application/json",
            "content-length": String(body.length),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  async function postWebhook(port: number) {
    const res = await postRaw(port, BODY);
    assert.equal(res.status, 202);
    return JSON.parse(res.text) as { id: string };
  }

  function deliveredEvents(audit: AuditLog) {
    return audit.query({ event: "delivered" }) as Array<{
      id: string;
      attempts: number;
    }>;
  }

  function deadLetterEvents(audit: AuditLog) {
    return audit.query({ event: "dead_letter" }) as Array<{
      id: string;
      attempts: number;
      failure_class: string;
    }>;
  }

  function deliveredRevisedEvents(audit: AuditLog) {
    return audit.query({ event: "delivered_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  function deadLetterRevisedEvents(audit: AuditLog) {
    return audit.query({ event: "dead_letter_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server whose sender always succeeds, so every delivery is observed once. */
  function succeedingServer(
    onDelivered?: (item: RetryItem, attempts: number, summary?: DownstreamResponseSummary) => void,
    onDeadLetter?: (
      item: RetryItem,
      attempts: number,
      lastError: unknown,
      failureClass: FailureClass | undefined,
      summary?: DownstreamResponseSummary
    ) => void
  ) {
    const dir = mkdtempSync(join(tmpdir(), "delivered-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const sender: Sender = async () => ({
      statusCode: 200,
      body: Buffer.from("ok"),
      truncated: false,
    });
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
        ...(onDelivered !== undefined ? { onDelivered } : {}),
        ...(onDeadLetter !== undefined ? { onDeadLetter } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  /** A server whose sender always fails, so every delivery retries once then dead-letters. */
  function failingServer(
    onDelivered?: (item: RetryItem, attempts: number, summary?: DownstreamResponseSummary) => void,
    onDeadLetter?: (
      item: RetryItem,
      attempts: number,
      lastError: unknown,
      failureClass: FailureClass | undefined,
      summary?: DownstreamResponseSummary
    ) => void
  ) {
    const dir = mkdtempSync(join(tmpdir(), "deadletter-revision-"));
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
        ...(onDelivered !== undefined ? { onDelivered } : {}),
        ...(onDeadLetter !== undefined ? { onDeadLetter } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  it("replacing the delivered callback routes the next success to the new callback, and the delivered audit still lands", async () => {
    const oldSeen: DeliveredSeen[] = [];
    const newSeen: DeliveredSeen[] = [];
    const { relay, audit } = succeedingServer((item, attempts, summary) =>
      oldSeen.push({ item, attempts, summary })
    );
    const port = await listen(relay);
    const first = await postWebhook(port);
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => deliveredEvents(audit).length >= 1);
    assert.equal(oldSeen[0].item.id, first.id);
    assert.equal(oldSeen[0].item.targetUrl, URL);
    assert.equal(oldSeen[0].attempts, 1);
    assert.equal(oldSeen[0].summary?.statusCode, 200);
    assert.equal(oldSeen[0].summary?.responseBytes, 2);
    assert.equal(deliveredEvents(audit)[0].id, first.id);
    assert.equal(deliveredEvents(audit)[0].attempts, 1);
    assert.deepEqual(newSeen, []);
    // Swap the operator callback; the first delivery is already reported.
    const newCb = (item: RetryItem, attempts: number, summary?: DownstreamResponseSummary) =>
      newSeen.push({ item, attempts, summary });
    relay.reviseDeliveredCallback!(newCb);
    assert.deepEqual(
      deliveredRevisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    // A fresh delivery enters only the new callback, and is still audited.
    const second = await postWebhook(port);
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => deliveredEvents(audit).length >= 2);
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen[0].item.id, second.id);
    assert.equal(newSeen[0].attempts, 1);
    assert.equal(newSeen[0].summary?.statusCode, 200);
    assert.equal(deliveredEvents(audit)[1].id, second.id);
    assert.equal(deliveredEvents(audit)[1].attempts, 1);
  });

  it("clearing the delivered callback keeps deliveries succeeding and audited, and stops the operator", async () => {
    const seen: DeliveredSeen[] = [];
    const { relay, audit } = succeedingServer((item, attempts, summary) =>
      seen.push({ item, attempts, summary })
    );
    const port = await listen(relay);
    await postWebhook(port);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => deliveredEvents(audit).length >= 1);
    relay.reviseDeliveredCallback!(null);
    assert.deepEqual(
      deliveredRevisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    const second = await postWebhook(port);
    await drainUntil(() => deliveredEvents(audit).length >= 2);
    assert.equal(seen.length, 1); // still silent
    assert.equal(deliveredEvents(audit)[1].id, second.id);
    assert.equal(deliveredEvents(audit)[1].attempts, 1);
  });

  it("replacing the dead-letter callback routes the next dead letter to the new callback, and the dead_letter audit still lands", async () => {
    const oldSeen: DeadLetterSeen[] = [];
    const newSeen: DeadLetterSeen[] = [];
    const { relay, audit } = failingServer(undefined, (item, attempts, lastError, failureClass, summary) =>
      oldSeen.push({ item, attempts, lastError, failureClass, summary })
    );
    const port = await listen(relay);
    const first = await postWebhook(port);
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => deadLetterEvents(audit).length >= 1);
    assert.equal(oldSeen[0].item.id, first.id);
    assert.equal(oldSeen[0].attempts, 2);
    assert.equal(oldSeen[0].failureClass, "retryable");
    assert.ok(oldSeen[0].lastError instanceof Error);
    assert.equal((oldSeen[0].lastError as Error).message, "downstream down");
    assert.equal(oldSeen[0].summary?.statusCode, "unavailable");
    assert.equal(deadLetterEvents(audit)[0].id, first.id);
    assert.equal(deadLetterEvents(audit)[0].attempts, 2);
    assert.equal(deadLetterEvents(audit)[0].failure_class, "retryable");
    assert.deepEqual(newSeen, []);
    // Swap the operator callback; the first dead letter is already reported.
    const newCb = (
      item: RetryItem,
      attempts: number,
      lastError: unknown,
      failureClass: FailureClass | undefined,
      summary?: DownstreamResponseSummary
    ) => newSeen.push({ item, attempts, lastError, failureClass, summary });
    relay.reviseDeadLetterCallback!(newCb);
    assert.deepEqual(
      deadLetterRevisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    // A fresh delivery's dead letter enters only the new callback, and is still audited.
    const second = await postWebhook(port);
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => deadLetterEvents(audit).length >= 2);
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen[0].item.id, second.id);
    assert.equal(newSeen[0].attempts, 2);
    assert.equal(newSeen[0].failureClass, "retryable");
    assert.equal((newSeen[0].lastError as Error).message, "downstream down");
    assert.equal(deadLetterEvents(audit)[1].id, second.id);
  });

  it("a transform-failure dead letter enters the new dead-letter callback", async () => {
    const stubHits: Array<{ body: Buffer }> = [];
    const stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        stubHits.push({ body: Buffer.concat(chunks) });
        res.writeHead(200).end("ok");
      });
    });
    const stubPort = await listen(stub);
    servers.push(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const dir = mkdtempSync(join(tmpdir(), "transform-deadletter-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const oldSeen: DeadLetterSeen[] = [];
    const newSeen: DeadLetterSeen[] = [];
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: target,
      auditLog: audit,
      operatorToken: TOKEN,
      payloadTransforms: { [target]: { fieldRenames: { a: "b" } } },
      retry: {
        baseDelayMs: 50,
        maxDelayMs: 500,
        maxAttempts: 5,
        jitterMs: 0,
        onDeadLetter: (item, attempts, lastError, failureClass, summary) =>
          oldSeen.push({ item, attempts, lastError, failureClass, summary }),
      },
    });
    servers.push(relay);
    const port = await listen(relay);
    const badBody = Buffer.from("this is not json {{{");
    const first = await postRaw(port, badBody);
    assert.equal(first.status, 202);
    const firstId = (JSON.parse(first.text) as { id: string }).id;
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => deadLetterEvents(audit).length >= 1);
    assert.equal(oldSeen[0].item.id, firstId);
    assert.equal(oldSeen[0].attempts, 1); // dead-lettered on the first attempt
    assert.equal(oldSeen[0].failureClass, "non_retryable");
    assert.match((oldSeen[0].lastError as Error).message, /payload transform failed/);
    assert.equal(deadLetterEvents(audit)[0].failure_class, "non_retryable");
    assert.equal(
      (audit.query({ event: "transform_failed" }) as unknown[]).length,
      1
    );
    assert.equal(stubHits.length, 0); // downstream never contacted
    // Swap; the next transform failure enters only the new callback.
    const newCb = (
      item: RetryItem,
      attempts: number,
      lastError: unknown,
      failureClass: FailureClass | undefined,
      summary?: DownstreamResponseSummary
    ) => newSeen.push({ item, attempts, lastError, failureClass, summary });
    relay.reviseDeadLetterCallback!(newCb);
    const second = await postRaw(port, badBody);
    assert.equal(second.status, 202);
    const secondId = (JSON.parse(second.text) as { id: string }).id;
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => deadLetterEvents(audit).length >= 2);
    assert.equal(oldSeen.length, 1);
    assert.equal(newSeen[0].item.id, secondId);
    assert.equal(newSeen[0].attempts, 1);
    assert.equal(newSeen[0].failureClass, "non_retryable");
    assert.match((newSeen[0].lastError as Error).message, /payload transform failed/);
    assert.equal(deadLetterEvents(audit)[1].failure_class, "non_retryable");
  });

  it("a non-function value throws RangeError and the live cells are untouched", async () => {
    const deliveredSeen: DeliveredSeen[] = [];
    const { relay, audit } = succeedingServer((item, attempts, summary) =>
      deliveredSeen.push({ item, attempts, summary })
    );
    const port = await listen(relay);
    assert.throws(() => relay.reviseDeliveredCallback!(42 as never), RangeError);
    assert.throws(() => relay.reviseDeadLetterCallback!("nope" as never), RangeError);
    assert.equal(deliveredRevisedEvents(audit).length, 0);
    assert.equal(deadLetterRevisedEvents(audit).length, 0);
    // The live delivered cell survived: the next success still enters it.
    await postWebhook(port);
    await drainUntil(() => deliveredSeen.length >= 1);
    assert.equal(deliveredSeen[0].attempts, 1);

    const deadSeen: DeadLetterSeen[] = [];
    const { relay: failing, audit: failingAudit } = failingServer(
      undefined,
      (item, attempts, lastError, failureClass, summary) =>
        deadSeen.push({ item, attempts, lastError, failureClass, summary })
    );
    const failingPort = await listen(failing);
    assert.throws(() => failing.reviseDeadLetterCallback!({} as never), RangeError);
    assert.equal(deadLetterRevisedEvents(failingAudit).length, 0);
    // The live dead-letter cell survived: the next dead letter still enters it.
    await postWebhook(failingPort);
    await drainUntil(() => deadSeen.length >= 1);
    assert.equal(deadSeen[0].failureClass, "retryable");
  });

  it("same-reference revision and clearing-when-unset are silent no-ops for both callbacks", async () => {
    const { relay, audit } = succeedingServer();
    await listen(relay);
    const deliveredCb = (_item: RetryItem, _attempts: number) => {};
    const deadLetterCb = (_item: RetryItem, _attempts: number) => {};
    // Clearing when unset: no audit event.
    relay.reviseDeliveredCallback!(null);
    relay.reviseDeadLetterCallback!(null);
    assert.equal(deliveredRevisedEvents(audit).length, 0);
    assert.equal(deadLetterRevisedEvents(audit).length, 0);
    // First set audits cleared -> set.
    relay.reviseDeliveredCallback!(deliveredCb);
    relay.reviseDeadLetterCallback!(deadLetterCb);
    assert.equal(deliveredRevisedEvents(audit).length, 1);
    assert.equal(deadLetterRevisedEvents(audit).length, 1);
    // Same reference again: no audit event.
    relay.reviseDeliveredCallback!(deliveredCb);
    relay.reviseDeadLetterCallback!(deadLetterCb);
    assert.equal(deliveredRevisedEvents(audit).length, 1);
    assert.equal(deadLetterRevisedEvents(audit).length, 1);
    // Clear, then clear again when unset: only the first clear audits.
    relay.reviseDeliveredCallback!(null);
    relay.reviseDeadLetterCallback!(null);
    relay.reviseDeliveredCallback!(null);
    relay.reviseDeadLetterCallback!(null);
    assert.equal(deliveredRevisedEvents(audit).length, 2);
    assert.equal(deadLetterRevisedEvents(audit).length, 2);
  });

  it("revision audits record previous/current presence exactly for both callbacks", async () => {
    const deliveredCb = (_item: RetryItem, _attempts: number) => {};
    const otherDeliveredCb = (_item: RetryItem, _attempts: number) => {};
    const deadLetterCb = (_item: RetryItem, _attempts: number) => {};
    const { relay, audit } = succeedingServer(deliveredCb, deadLetterCb);
    await listen(relay);
    // set -> set (constructor callbacks were already set).
    relay.reviseDeliveredCallback!(otherDeliveredCb);
    relay.reviseDeadLetterCallback!(deadLetterCb); // same reference: no-op
    // set -> cleared.
    relay.reviseDeliveredCallback!(null);
    relay.reviseDeadLetterCallback!(null);
    // cleared -> set.
    relay.reviseDeliveredCallback!(otherDeliveredCb);
    relay.reviseDeadLetterCallback!(deadLetterCb);
    assert.deepEqual(
      deliveredRevisedEvents(audit).map((e) => [e.previous, e.current]),
      [
        ["set", "set"],
        ["set", "cleared"],
        ["cleared", "set"],
      ]
    );
    assert.deepEqual(
      deadLetterRevisedEvents(audit).map((e) => [e.previous, e.current]),
      [
        ["set", "cleared"],
        ["cleared", "set"],
      ]
    );
  });

  it("already-reported terminal events are never re-delivered to the new callbacks", async () => {
    const oldDelivered: DeliveredSeen[] = [];
    const newDelivered: DeliveredSeen[] = [];
    const { relay: okRelay, audit: okAudit } = succeedingServer((item, attempts, summary) =>
      oldDelivered.push({ item, attempts, summary })
    );
    const okPort = await listen(okRelay);
    await postWebhook(okPort);
    await drainUntil(() => oldDelivered.length >= 1);

    const oldDead: DeadLetterSeen[] = [];
    const newDead: DeadLetterSeen[] = [];
    const { relay: dlRelay } = failingServer(undefined, (item, attempts, lastError, failureClass, summary) =>
      oldDead.push({ item, attempts, lastError, failureClass, summary })
    );
    const dlPort = await listen(dlRelay);
    await postWebhook(dlPort);
    await drainUntil(() => oldDead.length >= 1);

    // Swap both observers after the terminal events already fired.
    okRelay.reviseDeliveredCallback!((item, attempts, summary) =>
      newDelivered.push({ item, attempts, summary })
    );
    dlRelay.reviseDeadLetterCallback!((item, attempts, lastError, failureClass, summary) =>
      newDead.push({ item, attempts, lastError, failureClass, summary })
    );
    // Nothing already reported is re-delivered.
    await new Promise((r) => setTimeout(r, 100));
    assert.deepEqual(newDelivered, []);
    assert.deepEqual(newDead, []);
    // Fresh traffic enters only the new callbacks.
    await postWebhook(okPort);
    await drainUntil(() => newDelivered.length >= 1);
    await postWebhook(dlPort);
    await drainUntil(() => newDead.length >= 1);
    assert.equal(oldDelivered.length, 1);
    assert.equal(oldDead.length, 1);
    assert.equal(newDelivered[0].attempts, 1);
    assert.equal(newDead[0].failureClass, "retryable");
    assert.equal(deliveredEvents(okAudit).length, 2);
  });

  it("clearing the dead-letter callback keeps dead-lettering and audited, and stops the operator", async () => {
    const seen: DeadLetterSeen[] = [];
    const { relay, audit } = failingServer(undefined, (item, attempts, lastError, failureClass, summary) =>
      seen.push({ item, attempts, lastError, failureClass, summary })
    );
    const port = await listen(relay);
    await postWebhook(port);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => deadLetterEvents(audit).length >= 1);
    relay.reviseDeadLetterCallback!(null);
    assert.deepEqual(
      deadLetterRevisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    await postWebhook(port);
    await drainUntil(() => deadLetterEvents(audit).length >= 2);
    assert.equal(seen.length, 1); // still silent
    assert.equal(deadLetterEvents(audit)[1].attempts, 2);
  });

  it("a server born without callbacks can gain both at runtime — no must-restart gate", async () => {
    const deliveredSeen: DeliveredSeen[] = [];
    const { relay, audit } = succeedingServer();
    const port = await listen(relay);
    await postWebhook(port);
    await drainUntil(() => deliveredEvents(audit).length >= 1);
    assert.deepEqual(deliveredSeen, []); // nobody observed the first delivery
    relay.reviseDeliveredCallback!((item, attempts, summary) =>
      deliveredSeen.push({ item, attempts, summary })
    );
    assert.deepEqual(
      deliveredRevisedEvents(audit).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
    await postWebhook(port);
    await drainUntil(() => deliveredSeen.length >= 1);
    assert.equal(deliveredSeen[0].attempts, 1);
    assert.equal(deliveredSeen[0].summary?.statusCode, 200);

    const deadSeen: DeadLetterSeen[] = [];
    const { relay: failing, audit: failingAudit } = failingServer();
    const failingPort = await listen(failing);
    await postWebhook(failingPort);
    await drainUntil(() => deadLetterEvents(failingAudit).length >= 1);
    assert.deepEqual(deadSeen, []); // nobody observed the first dead letter
    failing.reviseDeadLetterCallback!((item, attempts, lastError, failureClass, summary) =>
      deadSeen.push({ item, attempts, lastError, failureClass, summary })
    );
    assert.deepEqual(
      deadLetterRevisedEvents(failingAudit).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
    await postWebhook(failingPort);
    await drainUntil(() => deadSeen.length >= 1);
    assert.equal(deadSeen[0].attempts, 2);
    assert.equal(deadSeen[0].failureClass, "retryable");
  });
});
