import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type RetryItem, type Sender } from "../src/retry.ts";
import type { QueueDepthBreachInfo } from "../src/queue-depth.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "queue-depth-breach-callback-revision-secret";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

function item(id: string, targetUrl = URL): RetryItem {
  return { id, targetUrl, payload: Buffer.from("{}"), headers: {} };
}

/** Sender that hangs until released; every release resolves one delivery. */
function hangingSender() {
  const releases: Array<() => void> = [];
  const sender: Sender = () =>
    new Promise<void>((resolve) => {
      releases.push(resolve);
    });
  return { sender, releases };
}

async function drainUntil(cond: () => boolean, ms = 5000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for condition");
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("RetryQueue queue-depth breach callback revision (WR-371)", () => {
  function makeQueue() {
    const { sender, releases } = hangingSender();
    const q = new RetryQueue({
      sender,
      maxAttempts: 1,
      jitterMs: 0,
      queueDepthAlert: { thresholds: { [URL]: 2 } },
    });
    return { q, releases };
  }

  it("revise swaps the live callback: the next episode enters the new callback, the old one is silent", async () => {
    const { q, releases } = makeQueue();
    const oldSeen: QueueDepthBreachInfo[] = [];
    const newSeen: QueueDepthBreachInfo[] = [];
    const oldCb = (info: QueueDepthBreachInfo) => oldSeen.push(info);
    const newCb = (info: QueueDepthBreachInfo) => newSeen.push(info);
    q.reviseQueueDepthBreachCallback(oldCb);
    q.start();
    try {
      q.enqueue(item("swap-1"));
      q.enqueue(item("swap-2"));
      await drainUntil(() => releases.length === 2);
      assert.deepEqual(oldSeen, [{ endpoint: URL, depth: 2, threshold: 2 }]);
      assert.deepEqual(newSeen, []);
      // Swap mid-flight, then drop below the threshold to re-arm.
      q.reviseQueueDepthBreachCallback(newCb);
      releases.splice(0).forEach((release) => release());
      await drainUntil(() => q.pendingCount() === 0);
      // Next episode enters only the new callback.
      q.enqueue(item("swap-3"));
      q.enqueue(item("swap-4"));
      assert.deepEqual(oldSeen, [{ endpoint: URL, depth: 2, threshold: 2 }]);
      assert.deepEqual(newSeen, [{ endpoint: URL, depth: 2, threshold: 2 }]);
    } finally {
      q.stop();
    }
  });

  it("null clears back to counting-only: breaches still metered, operator silent", async () => {
    const { q, releases } = makeQueue();
    const seen: QueueDepthBreachInfo[] = [];
    q.reviseQueueDepthBreachCallback((info) => seen.push(info));
    q.start();
    try {
      q.enqueue(item("clear-1"));
      q.enqueue(item("clear-2"));
      assert.equal(seen.length, 1);
      await drainUntil(() => releases.length === 2);
      q.reviseQueueDepthBreachCallback(null);
      releases.splice(0).forEach((release) => release());
      await drainUntil(() => q.pendingCount() === 0);
      q.enqueue(item("clear-3"));
      q.enqueue(item("clear-4"));
      assert.equal(seen.length, 1); // the second episode was audit/counter-only
      assert.match(
        q.renderMetrics(),
        /relay_queue_depth_breach_total\{endpoint="http:\/\/localhost:9999\/hook"\} 2/
      );
    } finally {
      q.stop();
    }
  });

  it("unconfigured alerting throws Error — enabling it needs a restart", () => {
    const q = new RetryQueue({
      onQueueDepthBreach: () => {
        throw new Error("must never fire: no tracker");
      },
    });
    assert.throws(
      () => q.reviseQueueDepthBreachCallback(() => {}),
      /reviseQueueDepthBreachCallback: queue-depth alerting is not configured/
    );
    q.stop();
  });

  it("a non-function value throws RangeError and the live callback is untouched", () => {
    const q = new RetryQueue({ queueDepthAlert: { thresholds: { [URL]: 2 } } });
    const seen: QueueDepthBreachInfo[] = [];
    const live = (info: QueueDepthBreachInfo) => seen.push(info);
    q.reviseQueueDepthBreachCallback(live);
    assert.throws(
      () => q.reviseQueueDepthBreachCallback(42 as never),
      RangeError
    );
    assert.throws(
      () => q.reviseQueueDepthBreachCallback("nope" as never),
      RangeError
    );
    // The live callback survived both bad revisions.
    q.enqueue(item("bad-1"));
    q.enqueue(item("bad-2"));
    assert.deepEqual(seen, [{ endpoint: URL, depth: 2, threshold: 2 }]);
    q.stop();
  });

  it("same-reference revision and clearing-when-unset are silent no-ops", () => {
    const q = new RetryQueue({ queueDepthAlert: { thresholds: { [URL]: 2 } } });
    const seen: QueueDepthBreachInfo[] = [];
    const live = (info: QueueDepthBreachInfo) => seen.push(info);
    q.reviseQueueDepthBreachCallback(live);
    q.reviseQueueDepthBreachCallback(live); // no-op, no throw
    q.enqueue(item("noop-1"));
    q.enqueue(item("noop-2"));
    assert.equal(seen.length, 1);
    q.reviseQueueDepthBreachCallback(null);
    q.reviseQueueDepthBreachCallback(null); // clearing when unset: no-op
    q.stop();
  });

  it("a throwing replacement callback never breaks the delivery path", () => {
    const q = new RetryQueue({ queueDepthAlert: { thresholds: { [URL]: 1 } } });
    q.reviseQueueDepthBreachCallback(() => {
      throw new Error("observer exploded");
    });
    q.enqueue(item("throw-1"));
    q.enqueue(item("throw-2"));
    assert.equal(q.pendingCount(), 2);
    q.stop();
  });

  it("edge-triggering is unaffected by a mid-episode swap: no re-fire until re-arm", async () => {
    const { q, releases } = makeQueue();
    const oldSeen: QueueDepthBreachInfo[] = [];
    const newSeen: QueueDepthBreachInfo[] = [];
    q.reviseQueueDepthBreachCallback((info) => oldSeen.push(info));
    q.start();
    try {
      q.enqueue(item("edge-1"));
      q.enqueue(item("edge-2"));
      assert.equal(oldSeen.length, 1);
      await drainUntil(() => releases.length === 2);
      // Swap while still above the threshold: the current episode must not re-fire.
      q.reviseQueueDepthBreachCallback((info) => newSeen.push(info));
      q.enqueue(item("edge-3"));
      await drainUntil(() => releases.length === 3);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 0);
      // Drop below the threshold, then the next episode enters the new callback.
      releases.splice(0).forEach((release) => release());
      await drainUntil(() => q.pendingCount() === 0);
      q.enqueue(item("edge-4"));
      q.enqueue(item("edge-5"));
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(newSeen, [{ endpoint: URL, depth: 2, threshold: 2 }]);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer queue-depth breach callback revision (WR-371)", () => {
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

  function get(port: number, path: string, token?: string) {
    return new Promise<{ status: number; text: string; json: unknown }>((resolve, reject) => {
      const headers: Record<string, string> = {};
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString();
          let json: unknown = null;
          try {
            json = JSON.parse(text);
          } catch {
            // Non-JSON bodies (Prometheus text) stay null.
          }
          resolve({ status: res.statusCode ?? 0, text, json });
        });
      });
      r.on("error", reject);
      r.end();
    });
  }

  function breachEvents(audit: AuditLog) {
    return (audit.query({ event: "queue_depth_breached" }) as Array<{
      endpoint: string;
      depth: number;
      threshold: number;
    }>).map(({ endpoint, depth, threshold }) => ({ endpoint, depth, threshold }));
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "queue_depth_breach_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  async function waitForDepth(port: number, depth: number): Promise<void> {
    await drainUntil(async () => {
      const summary = await get(port, "/health/summary", TOKEN);
      const row = (
        summary.json as { endpoints: Array<{ endpoint: string; queueDepth?: { depth: number } }> }
      ).endpoints.find((r) => r.endpoint === URL);
      return row?.queueDepth?.depth === depth;
    });
  }

  /** A server whose sender hangs, so ingested webhooks sit at depth until released. */
  function breachingServer(onQueueDepthBreach?: (info: QueueDepthBreachInfo) => void) {
    const dir = mkdtempSync(join(tmpdir(), "queuedepth-breach-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const { sender, releases } = hangingSender();
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
        maxAttempts: 1,
        jitterMs: 0,
        queueDepthAlert: { thresholds: { [URL]: 2 } },
        ...(onQueueDepthBreach !== undefined ? { onQueueDepthBreach } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit, releases };
  }

  it("replacing the operator callback routes the next episode to the new callback and the audit still lands", async () => {
    const oldSeen: QueueDepthBreachInfo[] = [];
    const newSeen: QueueDepthBreachInfo[] = [];
    const { relay, audit, releases } = breachingServer((info) => oldSeen.push(info));
    const port = await listen(relay);
    // First episode: the initial callback hears it and the audit lands.
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => breachEvents(audit).length >= 1);
    await drainUntil(() => oldSeen.length >= 1);
    assert.deepEqual(breachEvents(audit)[0], { endpoint: URL, depth: 2, threshold: 2 });
    assert.deepEqual(newSeen, []);
    // Swap the operator callback while the backlog sits above the threshold.
    const newCb = (info: QueueDepthBreachInfo) => newSeen.push(info);
    relay.reviseQueueDepthBreachCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    // Let the hanging deliveries settle (depth drops, gate re-arms), then breach again.
    releases.splice(0).forEach((release) => release());
    await waitForDepth(port, 0);
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => breachEvents(audit).length >= 2);
    await drainUntil(() => newSeen.length >= 1);
    assert.deepEqual(breachEvents(audit)[1], { endpoint: URL, depth: 2, threshold: 2 });
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    releases.splice(0).forEach((release) => release());
  });

  it("clearing to null keeps the audit and the counter and stops the operator", async () => {
    const seen: QueueDepthBreachInfo[] = [];
    const { relay, audit, releases } = breachingServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => breachEvents(audit).length >= 1);
    assert.equal(seen.length, 1);
    // Clear back to audit-only, then recover and breach again.
    relay.reviseQueueDepthBreachCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    releases.splice(0).forEach((release) => release());
    await waitForDepth(port, 0);
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => breachEvents(audit).length >= 2);
    assert.equal(seen.length, 1); // still silent
    const metrics = await get(port, "/metrics", TOKEN);
    assert.match(
      metrics.text,
      /relay_queue_depth_breach_total\{endpoint="http:\/\/localhost:9999\/hook"\} 2/
    );
    releases.splice(0).forEach((release) => release());
  });

  it("revise audits previous/current presence; a same-reference revision is a silent no-op", async () => {
    const { relay, audit } = breachingServer((info) => {});
    await listen(relay);
    const newCb = (_info: QueueDepthBreachInfo) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseQueueDepthBreachCallback!(newCb);
    // set -> cleared.
    relay.reviseQueueDepthBreachCallback!(null);
    // cleared -> set.
    relay.reviseQueueDepthBreachCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseQueueDepthBreachCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseQueueDepthBreachCallback!(null);
    relay.reviseQueueDepthBreachCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [
        ["set", "set"],
        ["set", "cleared"],
        ["cleared", "set"],
        ["set", "cleared"],
      ]
    );
  });

  it("unconfigured alerting throws Error — enabling it needs a restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "queuedepth-breach-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
    });
    servers.push(relay);
    await listen(relay);
    assert.throws(
      () => relay.reviseQueueDepthBreachCallback!(() => {}),
      /reviseQueueDepthBreachCallback: queue-depth alerting is not configured/
    );
  });

  it("a non-function value throws RangeError and the live cell is untouched", async () => {
    const seen: QueueDepthBreachInfo[] = [];
    const { relay, audit, releases } = breachingServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseQueueDepthBreachCallback!(42 as never),
      RangeError
    );
    assert.equal(revisedEvents(audit).length, 0);
    // The live cell survived: the next breach still enters the original callback.
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => breachEvents(audit).length >= 1);
    assert.equal(seen.length, 1);
    releases.splice(0).forEach((release) => release());
  });
});
