import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OtlpExporter,
  buildOtlpPayload,
  mapOtlpTraceId,
  type OtlpRecordInput,
} from "../src/otlp.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) assert.fail(`timed out waiting for: ${what}`);
    await sleep(10);
  }
}

interface CapturedPost {
  method: string;
  url: string;
  contentType: string | undefined;
  body: string;
}

/** Local OTLP collector stub: records POSTs, answers with a scripted status. */
function startCollector(statuses?: () => number) {
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
      res.writeHead(statuses?.() ?? 200).end("ok");
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

function deliveredRecord(overrides: Partial<OtlpRecordInput> = {}): OtlpRecordInput {
  return {
    eventType: "delivered",
    eventId: "evt-1",
    traceId: "a".repeat(32),
    endpoint: "http://downstream/hook",
    attempts: 1,
    ...overrides,
  };
}

/** All logRecords across every captured POST, in capture order. */
function allLogRecords(posts: CapturedPost[]): Array<Record<string, any>> {
  const out: Array<Record<string, any>> = [];
  for (const p of posts) {
    const payload = JSON.parse(p.body);
    for (const rl of payload.resourceLogs) for (const sl of rl.scopeLogs) out.push(...sl.logRecords);
  }
  return out;
}

function attrMap(rec: Record<string, any>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of rec.attributes as Array<{ key: string; value: Record<string, string> }>) {
    out[a.key] = a.value.stringValue ?? a.value.intValue ?? "";
  }
  return out;
}

describe("otlp: traceId mapping", () => {
  it("passes 32-hex IDs through (lowercased)", () => {
    assert.equal(mapOtlpTraceId("a".repeat(32)), "a".repeat(32));
    assert.equal(mapOtlpTraceId("A".repeat(32)), "a".repeat(32));
    assert.equal(mapOtlpTraceId("0123456789abcdef0123456789ABCDEF"), "0123456789abcdef0123456789abcdef");
  });

  it("maps non-32-hex IDs through SHA-256 to 32 hex chars", () => {
    const client = "client-123_ABC";
    const mapped = mapOtlpTraceId(client);
    assert.match(mapped, /^[0-9a-f]{32}$/);
    assert.equal(mapped, createHash("sha256").update(client, "utf8").digest("hex").slice(0, 32));
    // Deterministic: the same client ID always maps the same way.
    assert.equal(mapOtlpTraceId(client), mapped);
    // Known vector: sha256("abc") starts with ba7816bf...
    assert.equal(mapOtlpTraceId("abc"), "ba7816bf8f01cfea414140de5dae2223");
  });
});

describe("otlp: payload shape", () => {
  it("renders the OTLP logs JSON envelope with INFO severity", () => {
    const payload = JSON.parse(buildOtlpPayload([deliveredRecord()], "webhook-relay-ts", 1_700_000_000_000));
    const rl = payload.resourceLogs[0];
    assert.equal(rl.resource.attributes[0].key, "service.name");
    assert.equal(rl.resource.attributes[0].value.stringValue, "webhook-relay-ts");
    const scope = rl.scopeLogs[0];
    assert.equal(scope.scope.name, "webhook-relay-ts");
    const rec = scope.logRecords[0];
    assert.equal(rec.severityNumber, 9);
    assert.equal(rec.severityText, "INFO");
    assert.equal(rec.traceId, "a".repeat(32));
    assert.equal(rec.body.stringValue, "delivered");
    assert.match(rec.timeUnixNano, /^[0-9]+$/);
    assert.equal(rec.timeUnixNano, (BigInt(1_700_000_000_000) * 1_000_000n).toString());
    assert.equal(rec.observedTimeUnixNano, rec.timeUnixNano);
    const attrs = attrMap(rec);
    assert.equal(attrs["relay.event_id"], "evt-1");
    assert.equal(attrs["relay.event_type"], "delivered");
    assert.equal(attrs["relay.endpoint"], "http://downstream/hook");
    assert.equal(attrs["relay.attempts"], "1");
    assert.ok(!("relay.tenant" in attrs), "tenant omitted when absent");
    assert.ok(!("relay.error" in attrs), "error omitted for delivered");
  });

  it("renders dead_letter with WARN severity and error attribute", () => {
    const rec = JSON.parse(
      buildOtlpPayload(
        [deliveredRecord({ eventType: "dead_letter", error: "connection refused", attempts: 3 })],
        "webhook-relay-ts",
        1_700_000_000_000
      )
    ).resourceLogs[0].scopeLogs[0].logRecords[0];
    assert.equal(rec.severityNumber, 13);
    assert.equal(rec.severityText, "WARN");
    assert.equal(rec.body.stringValue, "dead_letter");
    const attrs = attrMap(rec);
    assert.equal(attrs["relay.error"], "connection refused");
    assert.equal(attrs["relay.attempts"], "3");
  });

  it("renders slo_missed with slo/latency attributes and tenant", () => {
    const rec = JSON.parse(
      buildOtlpPayload(
        [
          deliveredRecord({
            eventType: "slo_missed",
            eventId: "slow-1",
            tenant: "acme",
            sloMs: 5000,
            latencyMs: 7321.6,
            attempts: undefined,
          }),
        ],
        "svc",
        1_700_000_000_000
      )
    ).resourceLogs[0].scopeLogs[0].logRecords[0];
    assert.equal(rec.severityNumber, 9);
    const attrs = attrMap(rec);
    assert.equal(attrs["relay.event_type"], "slo_missed");
    assert.equal(attrs["relay.tenant"], "acme");
    assert.equal(attrs["relay.slo_ms"], "5000");
    assert.equal(attrs["relay.latency_ms"], "7322");
    assert.ok(!("relay.attempts" in attrs));
  });

  it("batches multiple records into one POST payload", () => {
    const payload = JSON.parse(
      buildOtlpPayload(
        [deliveredRecord({ eventId: "e1" }), deliveredRecord({ eventId: "e2", eventType: "retrying" })],
        "webhook-relay-ts",
        1_700_000_000_000
      )
    );
    const records = payload.resourceLogs[0].scopeLogs[0].logRecords;
    assert.equal(records.length, 2);
    assert.equal(attrMap(records[0])["relay.event_id"], "e1");
    assert.equal(attrMap(records[1])["relay.event_id"], "e2");
  });
});

describe("otlp: option validation", () => {
  it("rejects bad endpoints with RangeError", () => {
    assert.throws(() => new OtlpExporter({ endpoint: "" }), RangeError);
    assert.throws(() => new OtlpExporter({ endpoint: "not-a-url" }), RangeError);
    assert.throws(() => new OtlpExporter({ endpoint: "ftp://collector/x" }), RangeError);
    assert.throws(() => new OtlpExporter({ endpoint: 42 as unknown as string }), RangeError);
  });

  it("rejects out-of-range sampleRate and bad maxBuffered with RangeError", () => {
    const url = "http://127.0.0.1:4318/v1/logs";
    assert.throws(() => new OtlpExporter({ endpoint: url, sampleRate: -0.1 }), RangeError);
    assert.throws(() => new OtlpExporter({ endpoint: url, sampleRate: 1.1 }), RangeError);
    assert.throws(() => new OtlpExporter({ endpoint: url, sampleRate: NaN }), RangeError);
    assert.throws(() => new OtlpExporter({ endpoint: url, maxBuffered: 0 }), RangeError);
    assert.throws(() => new OtlpExporter({ endpoint: url, maxBuffered: -5 }), RangeError);
    assert.throws(() => new OtlpExporter({ endpoint: url, maxBuffered: 1.5 }), RangeError);
  });

  it("accepts a minimal config and fails fast at the queue level too", () => {
    const url = "http://127.0.0.1:4318/v1/logs";
    assert.doesNotThrow(() => new OtlpExporter({ endpoint: url }));
    assert.doesNotThrow(
      () => new OtlpExporter({ endpoint: url, sampleRate: 0, maxBuffered: 1, serviceName: "x" })
    );
    assert.throws(() => new RetryQueue({ otlp: { endpoint: "bogus" } }), RangeError);
    assert.throws(
      () => new RetryQueue({ otlp: { endpoint: url, sampleRate: 2 } }),
      RangeError
    );
    // The validation above constructs queues that are never started:
    // no network, no timers — nothing to clean up.
  });
});

describe("otlp: sampling and buffering", () => {
  let collector: ReturnType<typeof startCollector>;

  before(async () => {
    collector = startCollector();
    collector.port = await listenPort(collector.server);
  });
  after(() => collector.close());

  it("samples with the injected random source (default 1.0 keeps everything)", async () => {
    const url = `http://127.0.0.1:${collector.port}/v1/logs`;
    const keep = new OtlpExporter({ endpoint: url, sampleRate: 0.5, random: () => 0.4 });
    keep.record(deliveredRecord());
    assert.equal(keep.stats().buffered, 1);
    const drop = new OtlpExporter({ endpoint: url, sampleRate: 0.5, random: () => 0.6 });
    drop.record(deliveredRecord());
    assert.equal(drop.stats().buffered, 0);
    const none = new OtlpExporter({ endpoint: url, sampleRate: 0 });
    none.record(deliveredRecord());
    assert.equal(none.stats().buffered, 0);
    // Drain the kept record before the next test resets the collector's
    // post log — stop()'s fire-and-forget flush would otherwise race it.
    await keep.flush();
    assert.equal(keep.stats().exported, 1);
    keep.stop();
    drop.stop();
    none.stop();
  });

  it("drop-oldest on overflow and counts otlpDroppedExports", async () => {
    const url = `http://127.0.0.1:${collector.port}/v1/logs`;
    const exporter = new OtlpExporter({ endpoint: url, maxBuffered: 2 });
    exporter.record(deliveredRecord({ eventId: "old-1" }));
    exporter.record(deliveredRecord({ eventId: "old-2" }));
    exporter.record(deliveredRecord({ eventId: "new-3" }));
    assert.equal(exporter.stats().buffered, 2);
    assert.equal(exporter.stats().dropped, 1);
    collector.posts.length = 0;
    await exporter.flush();
    assert.equal(collector.posts.length, 1);
    const ids = allLogRecords(collector.posts).map((r) => attrMap(r)["relay.event_id"]);
    assert.deepEqual(ids, ["old-2", "new-3"]);
    assert.equal(exporter.stats().exported, 2);
    assert.equal(exporter.stats().buffered, 0);
    exporter.stop();
  });

  it("record() never throws, even on hostile input", () => {
    const exporter = new OtlpExporter({ endpoint: "http://127.0.0.1:9/v1/logs" });
    assert.doesNotThrow(() =>
      exporter.record({ eventType: "delivered", eventId: "", traceId: "", endpoint: "" })
    );
    exporter.stop();
  });
});

describe("otlp: transport failure and background retry", () => {
  let collector: ReturnType<typeof startCollector>;
  let failCount: number;

  before(async () => {
    failCount = 0;
    collector = startCollector(() => (failCount > 0 ? (failCount--, 500) : 200));
    collector.port = await listenPort(collector.server);
  });
  after(() => collector.close());

  it("keeps the batch buffered on failure and retries to success", async () => {
    const url = `http://127.0.0.1:${collector.port}/v1/logs`;
    const exporter = new OtlpExporter({ endpoint: url });
    failCount = 1; // first POST gets a 500
    exporter.record(deliveredRecord({ eventId: "retry-me" }));
    await exporter.flush();
    let s = exporter.stats();
    assert.equal(s.buffered, 1);
    assert.equal(s.exported, 0);
    assert.ok(s.lastError !== undefined, "lastError is set");
    assert.ok(s.lastError.includes("500"), `lastError mentions the status, got: ${s.lastError}`);
    // Per-(event_type,status) counters: one failure so far.
    assert.deepEqual(exporter.exportCounts(), [
      { eventType: "delivered", status: "failure", count: 1 },
    ]);
    await exporter.flush(); // collector is healthy again
    s = exporter.stats();
    assert.equal(s.buffered, 0);
    assert.equal(s.exported, 1);
    assert.ok(s.lastError === undefined, "lastError cleared on success");
    assert.deepEqual(exporter.exportCounts(), [
      { eventType: "delivered", status: "success", count: 1 },
      { eventType: "delivered", status: "failure", count: 1 },
    ]);
    exporter.stop();
  });

  it("an unref'd background timer retries without any manual flush", async () => {
    const url = `http://127.0.0.1:${collector.port}/v1/logs`;
    const exporter = new OtlpExporter({ endpoint: url });
    collector.posts.length = 0;
    failCount = 1; // the immediate flush (50ms coalescing) fails with 500
    exporter.record(deliveredRecord({ eventId: "auto-retry" }));
    await waitFor(() => collector.posts.length >= 2, 5000, "background retry POST");
    await waitFor(() => exporter.stats().exported === 1, 5000, "background retry success");
    const s = exporter.stats();
    assert.equal(s.buffered, 0);
    assert.equal(s.dropped, 0);
    exporter.stop();
  });

  it("shutdown() flushes best-effort and never hangs on a dead collector", async () => {
    const dead = new OtlpExporter({ endpoint: "http://127.0.0.1:9/v1/logs" });
    dead.record(deliveredRecord());
    const start = Date.now();
    await dead.shutdown(300);
    assert.ok(Date.now() - start < 5000, "shutdown returned promptly");
    assert.equal(dead.stats().buffered, 1, "unsent batch stays buffered");
  });
});

describe("otlp: retry-queue integration", () => {
  let collector: ReturnType<typeof startCollector>;

  before(async () => {
    collector = startCollector();
    collector.port = await listenPort(collector.server);
  });
  after(() => collector.close());

  const item = (targetUrl: string) => ({
    id: "q1",
    payload: Buffer.from("hello"),
    targetUrl,
    headers: {},
  });

  it("exports a delivered event end to end", async () => {
    const url = `http://127.0.0.1:${collector.port}/v1/logs`;
    const ok: Sender = async () => {};
    const q = new RetryQueue({
      sender: ok,
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 2,
      otlp: { endpoint: url },
    });
    q.start();
    collector.posts.length = 0;
    q.enqueue(item("http://127.0.0.1:9/hook"));
    await waitFor(() => collector.posts.length > 0, 5000, "delivered OTLP export");
    const records = allLogRecords(collector.posts);
    assert.equal(records.length, 1);
    assert.equal(records[0].body.stringValue, "delivered");
    const attrs = attrMap(records[0]);
    assert.equal(attrs["relay.event_type"], "delivered");
    assert.equal(attrs["relay.endpoint"], "http://127.0.0.1:9/hook");
    assert.equal(attrs["relay.attempts"], "1");
    assert.equal(collector.posts[0].contentType, "application/json");
    const stats = q.getOtlpStats();
    assert.equal(stats.enabled, true);
    assert.equal(stats.exported, 1);
    assert.equal(stats.buffered, 0);
    await q.shutdown(2000);
  });

  it("exports retrying and dead_letter events", async () => {
    const url = `http://127.0.0.1:${collector.port}/v1/logs`;
    const failing: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: failing,
      baseDelayMs: 10,
      maxDelayMs: 20,
      jitterMs: 0,
      maxAttempts: 2,
      otlp: { endpoint: url },
    });
    q.start();
    collector.posts.length = 0;
    q.enqueue(item("http://127.0.0.1:9/hook"));
    await waitFor(
      () => {
        const types = new Set(allLogRecords(collector.posts).map((r) => r.body.stringValue));
        return types.has("retrying") && types.has("dead_letter");
      },
      8000,
      "retrying + dead_letter OTLP exports"
    );
    const records = allLogRecords(collector.posts);
    const dead = records.find((r) => r.body.stringValue === "dead_letter");
    assert.ok(dead);
    assert.equal(dead.severityNumber, 13);
    assert.ok(attrMap(dead)["relay.error"].includes("downstream down"));
    const retrying = records.find((r) => r.body.stringValue === "retrying");
    assert.ok(retrying);
    assert.equal(retrying.severityNumber, 9);
    await q.shutdown(2000);
  });

  it("exports slo_missed via the wrapped onSloMiss hook", async () => {
    const url = `http://127.0.0.1:${collector.port}/v1/logs`;
    let callerHookFired = 0;
    const slow: Sender = async () => {
      await sleep(40);
    };
    const q = new RetryQueue({
      sender: slow,
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      latency: { sloMs: 5, onSloMiss: () => (callerHookFired += 1) },
      otlp: { endpoint: url },
    });
    q.start();
    collector.posts.length = 0;
    q.enqueue(item("http://127.0.0.1:9/hook"));
    await waitFor(
      () => allLogRecords(collector.posts).some((r) => r.body.stringValue === "slo_missed"),
      5000,
      "slo_missed OTLP export"
    );
    assert.equal(callerHookFired, 1, "caller's onSloMiss still fires exactly once");
    const rec = allLogRecords(collector.posts).find((r) => r.body.stringValue === "slo_missed");
    assert.ok(rec);
    const attrs = attrMap(rec);
    assert.equal(attrs["relay.event_type"], "slo_missed");
    assert.equal(attrs["relay.slo_ms"], "5");
    assert.ok(Number(attrs["relay.latency_ms"]) >= 5, `latency_ms honest, got ${attrs["relay.latency_ms"]}`);
    await q.shutdown(2000);
  });

  it("disabled by default: no exporter, no hooks, no metrics series", async () => {
    const ok: Sender = async () => {};
    const q = new RetryQueue({ sender: ok, baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 });
    q.start();
    q.enqueue(item("http://127.0.0.1:9/hook"));
    await waitFor(() => q.getOtlpStats().exported === 0 && q.pendingCount() === 0, 3000, "delivery settles");
    await sleep(150); // past any coalescing delay — nothing may be scheduled
    const stats = q.getOtlpStats();
    assert.deepEqual(stats, { enabled: false, buffered: 0, dropped: 0, exported: 0 });
    assert.ok(!q.renderMetrics().includes("relay_otlp_"), "no OTLP series when disabled");
    await q.shutdown(2000);
  });

  it("emits relay_otlp_exports_total and relay_otlp_buffered when enabled", async () => {
    const url = `http://127.0.0.1:${collector.port}/v1/logs`;
    const ok: Sender = async () => {};
    const q = new RetryQueue({
      sender: ok,
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      otlp: { endpoint: url },
    });
    q.start();
    q.enqueue(item("http://127.0.0.1:9/hook"));
    await waitFor(() => q.getOtlpStats().exported === 1, 5000, "export lands");
    const exposition = q.renderMetrics();
    assert.ok(
      exposition.includes('relay_otlp_exports_total{event_type="delivered",status="success"} 1'),
      exposition
    );
    assert.ok(exposition.includes("relay_otlp_buffered 0"), exposition);
    await q.shutdown(2000);
  });
});

describe("otlp: server integration", () => {
  let collector: ReturnType<typeof startCollector>;
  let downstream: Server;
  let downstreamPort: number;
  const received: Buffer[] = [];

  before(async () => {
    collector = startCollector();
    collector.port = await listenPort(collector.server);
    downstream = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    downstreamPort = await listenPort(downstream);
  });
  after(async () => {
    await collector.close();
    downstream.close();
    await new Promise((r) => downstream.once("close", r));
  });

  const RELAY_KEY = "otlp-test-key";
  const BODY = Buffer.from(JSON.stringify({ hello: "otlp" }));

  async function postWebhook(port: number): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: {
            "x-signature": signSha256(BODY, RELAY_KEY),
            "content-type": "application/json",
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

  async function listenRelay(relay: Server): Promise<number> {
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const addr = relay.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  it("passes the otlp option through to the retry queue", async () => {
    const dir = mkdtempSync(join(tmpdir(), "otlp-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: RELAY_KEY,
      forwardUrl: `http://127.0.0.1:${downstreamPort}/hook`,
      auditLog: audit,
      otlp: { endpoint: `http://127.0.0.1:${collector.port}/v1/logs` },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listenRelay(relay);
    try {
      collector.posts.length = 0;
      received.length = 0;
      assert.equal(await postWebhook(port), 202);
      await waitFor(() => received.length > 0, 5000, "downstream delivery");
      await waitFor(() => collector.posts.length > 0, 5000, "server-level OTLP export");
      const types = allLogRecords(collector.posts).map((r) => r.body.stringValue);
      assert.ok(types.includes("delivered"), `expected a delivered export, got ${types}`);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("no behavior change when otlp is unset on the server", async () => {
    const dir = mkdtempSync(join(tmpdir(), "otlp-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: RELAY_KEY,
      forwardUrl: `http://127.0.0.1:${downstreamPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listenRelay(relay);
    try {
      collector.posts.length = 0;
      received.length = 0;
      assert.equal(await postWebhook(port), 202);
      await waitFor(() => received.length > 0, 5000, "downstream delivery");
      await sleep(300); // past the exporter's coalescing delay
      assert.equal(collector.posts.length, 0, "no OTLP export when unset");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
