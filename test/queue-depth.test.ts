import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type RetryItem, type Sender } from "../src/retry.ts";
import { QueueDepthAlert, type QueueDepthBreachInfo } from "../src/queue-depth.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const URL = "http://localhost:9999/hook";
const OTHER = "http://localhost:9999/other";
const hookSecret = "relay-secret";
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

describe("QueueDepthAlert", () => {
  it("edge-triggered: fires exactly once per breach episode", () => {
    const t = new QueueDepthAlert({ thresholds: { [URL]: 3 } });
    assert.equal(t.evaluate(URL, 1), undefined);
    assert.equal(t.evaluate(URL, 2), undefined);
    assert.deepEqual(t.evaluate(URL, 3), { endpoint: URL, depth: 3, threshold: 3 });
    // Staying at/above the threshold fires nothing more.
    assert.equal(t.evaluate(URL, 4), undefined);
    assert.equal(t.evaluate(URL, 3), undefined);
    assert.equal(t.isBreached(URL), true);
  });

  it("re-arms after the depth drops back below the threshold", () => {
    const t = new QueueDepthAlert({ thresholds: { [URL]: 3 } });
    assert.deepEqual(t.evaluate(URL, 3), { endpoint: URL, depth: 3, threshold: 3 });
    // Still at/above: no re-fire, and no re-arm either.
    assert.equal(t.evaluate(URL, 3), undefined);
    // Drop below: re-arms silently.
    assert.equal(t.evaluate(URL, 2), undefined);
    assert.equal(t.isBreached(URL), false);
    // Next episode fires again.
    assert.deepEqual(t.evaluate(URL, 5), { endpoint: URL, depth: 5, threshold: 3 });
  });

  it("endpoints without a configured threshold never breach", () => {
    const t = new QueueDepthAlert({ thresholds: { [URL]: 1 } });
    assert.equal(t.evaluate(OTHER, 100), undefined);
    assert.equal(t.isBreached(OTHER), false);
    assert.equal(t.thresholdFor(OTHER), undefined);
  });

  it("thresholdFor returns the configured threshold", () => {
    const t = new QueueDepthAlert({ thresholds: { [URL]: 7 } });
    assert.equal(t.thresholdFor(URL), 7);
  });

  it("rejects illegal thresholds at construction", () => {
    const bad: unknown[] = [0, -1, 1.5, Number.NaN, "3", null, true, Infinity];
    for (const threshold of bad) {
      assert.throws(
        () => new QueueDepthAlert({ thresholds: { [URL]: threshold as number } }),
        RangeError,
        `threshold ${String(threshold)}`
      );
    }
    assert.throws(() => new QueueDepthAlert({ thresholds: null as never }), RangeError);
    assert.throws(() => new QueueDepthAlert({ thresholds: [] as never }), RangeError);
    assert.throws(() => new QueueDepthAlert({ thresholds: { "": 3 } }), RangeError);
    // Absent or empty thresholds alert nothing — no throw.
    new QueueDepthAlert();
    new QueueDepthAlert({});
    new QueueDepthAlert({ thresholds: {} });
  });
});

describe("RetryQueue queue-depth alerting", () => {
  it("fires onQueueDepthBreach when the depth reaches the threshold", () => {
    const calls: QueueDepthBreachInfo[] = [];
    const q = new RetryQueue({
      queueDepthAlert: { thresholds: { [URL]: 3 } },
      onQueueDepthBreach: (info) => calls.push(info),
    });
    q.enqueue(item("d-1"));
    q.enqueue(item("d-2"));
    assert.equal(calls.length, 0);
    q.enqueue(item("d-3"));
    assert.deepEqual(calls, [{ endpoint: URL, depth: 3, threshold: 3 }]);
    q.stop();
  });

  it("edge-triggered while above the threshold, re-arms below it", async () => {
    const calls: QueueDepthBreachInfo[] = [];
    const { sender, releases } = hangingSender();
    const q = new RetryQueue({
      sender,
      maxAttempts: 1,
      jitterMs: 0,
      queueDepthAlert: { thresholds: { [URL]: 2 } },
      onQueueDepthBreach: (info) => calls.push(info),
    });
    q.start();
    q.enqueue(item("e-1"));
    q.enqueue(item("e-2"));
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0], { endpoint: URL, depth: 2, threshold: 2 });
    // Still above the threshold: no re-fire.
    q.enqueue(item("e-3"));
    assert.equal(calls.length, 1);
    // Settle two deliveries: depth drops 3 -> 1, below the threshold — re-armed.
    await drainUntil(() => releases.length === 3);
    releases.shift()!();
    releases.shift()!();
    await drainUntil(() => q.pendingCount() === 1);
    assert.equal(calls.length, 1);
    // Next episode fires again.
    q.enqueue(item("e-4"));
    assert.equal(calls.length, 2);
    assert.deepEqual(calls[1], { endpoint: URL, depth: 2, threshold: 2 });
    q.stop();
  });

  it("a throwing onQueueDepthBreach never breaks the delivery path", () => {
    const q = new RetryQueue({
      queueDepthAlert: { thresholds: { [URL]: 1 } },
      onQueueDepthBreach: () => {
        throw new Error("observer exploded");
      },
    });
    // Both enqueues land in the queue despite the throwing observer.
    q.enqueue(item("t-1"));
    q.enqueue(item("t-2"));
    assert.equal(q.pendingCount(), 2);
    q.stop();
  });

  it("alerting never pauses or gates delivery (orthogonal to WR-150)", async () => {
    const breaches: QueueDepthBreachInfo[] = [];
    const delivered: string[] = [];
    const { sender, releases } = hangingSender();
    const q = new RetryQueue({
      sender,
      maxAttempts: 1,
      jitterMs: 0,
      queueDepthAlert: { thresholds: { [URL]: 1 } },
      onQueueDepthBreach: (info) => breaches.push(info),
      onDelivered: (it) => delivered.push(it.id),
    });
    q.start();
    q.enqueue(item("f-1"));
    q.enqueue(item("f-2"));
    assert.equal(breaches.length, 1);
    // The breach changed nothing about the dispatch path: both deliver.
    await drainUntil(() => releases.length === 2);
    releases.shift()!();
    releases.shift()!();
    await drainUntil(() => q.pendingCount() === 0);
    assert.deepEqual(delivered.sort(), ["f-1", "f-2"]);
    assert.equal(q.isEndpointDisabled(URL), false);
    q.stop();
  });

  it("disabled by default: no hook, no series", () => {
    const calls: QueueDepthBreachInfo[] = [];
    const q = new RetryQueue({ onQueueDepthBreach: (info) => calls.push(info) });
    for (let i = 0; i < 5; i++) q.enqueue(item(`g-${i}`));
    assert.equal(calls.length, 0);
    assert.ok(!q.renderMetrics().includes("relay_queue_depth_breach_total"));
    q.stop();
  });

  it("relay_queue_depth_breach_total counts breach episodes", () => {
    const q = new RetryQueue({ queueDepthAlert: { thresholds: { [URL]: 2 } } });
    q.enqueue(item("m-1"));
    assert.ok(!q.renderMetrics().includes("relay_queue_depth_breach_total"));
    q.enqueue(item("m-2"));
    const text = q.renderMetrics();
    assert.match(
      text,
      /relay_queue_depth_breach_total\{endpoint="http:\/\/localhost:9999\/hook"\} 1/
    );
    q.stop();
  });

  it("per-endpoint thresholds are independent", () => {
    const calls: QueueDepthBreachInfo[] = [];
    const q = new RetryQueue({
      queueDepthAlert: { thresholds: { [URL]: 2 } },
      onQueueDepthBreach: (info) => calls.push(info),
    });
    // OTHER has no threshold: never alerts, however deep.
    q.enqueue(item("o-1", OTHER));
    q.enqueue(item("o-2", OTHER));
    q.enqueue(item("o-3", OTHER));
    assert.equal(calls.length, 0);
    // URL alerts on its own threshold.
    q.enqueue(item("o-4"));
    q.enqueue(item("o-5"));
    assert.deepEqual(calls, [{ endpoint: URL, depth: 2, threshold: 2 }]);
    q.stop();
  });

  it("rejects illegal thresholds at construction", () => {
    for (const threshold of [0, -2, 2.5]) {
      assert.throws(
        () => new RetryQueue({ queueDepthAlert: { thresholds: { [URL]: threshold } } }),
        RangeError
      );
    }
  });

  it("getQueueDepthStats reports current depth with threshold and breach state", () => {
    const q = new RetryQueue({ queueDepthAlert: { thresholds: { [URL]: 2 } } });
    assert.deepEqual(q.getQueueDepthStats(), []);
    q.enqueue(item("s-1"));
    q.enqueue(item("s-2", OTHER));
    q.enqueue(item("s-3"));
    const rows = q.getQueueDepthStats();
    assert.equal(rows.length, 2);
    const urlRow = rows.find((r) => r.endpoint === URL)!;
    assert.deepEqual(urlRow, { endpoint: URL, depth: 2, threshold: 2, breached: true });
    const otherRow = rows.find((r) => r.endpoint === OTHER)!;
    assert.deepEqual(otherRow, { endpoint: OTHER, depth: 1, breached: false });
    assert.ok(!("threshold" in otherRow));
    q.stop();
  });
});

describe("server queue-depth alerting", () => {
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
            "x-signature": signSha256(BODY, hookSecret),
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

  it("audits queue_depth_breached and exposes depth in /health/summary and /metrics", async () => {
    const dir = mkdtempSync(join(tmpdir(), "queuedepth-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const { sender, releases } = hangingSender();
    const relay = createRelayServer({
      secret: hookSecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 1,
        jitterMs: 0,
        queueDepthAlert: { thresholds: { [URL]: 2 } },
      },
    });
    servers.push(relay);
    const port = await listen(relay);

    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    // Both deliveries hang in flight: depth sits at 2, the breach edge fired.
    await drainUntil(() => releases.length === 2);

    const events = audit.query({ event: "queue_depth_breached" }) as Array<{
      endpoint: string;
      depth: number;
      threshold: number;
    }>;
    assert.equal(events.length, 1);
    assert.equal(events[0].endpoint, URL);
    assert.equal(events[0].depth, 2);
    assert.equal(events[0].threshold, 2);

    const summary = await get(port, "/health/summary", TOKEN);
    assert.equal(summary.status, 200);
    const row = (summary.json as { endpoints: Array<{ endpoint: string; queueDepth?: unknown }> })
      .endpoints.find((r) => r.endpoint === URL)!;
    assert.deepEqual(row.queueDepth, { depth: 2, threshold: 2, breached: true });

    const metrics = await get(port, "/metrics", TOKEN);
    assert.equal(metrics.status, 200);
    assert.match(
      metrics.text,
      /relay_queue_depth_breach_total\{endpoint="http:\/\/localhost:9999\/hook"\} 1/
    );

    // Let the hanging deliveries settle before teardown.
    releases.splice(0).forEach((release) => release());
  });
});
