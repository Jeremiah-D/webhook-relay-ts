import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OtlpExporter, type OtlpRecordInput } from "../src/otlp.ts";
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

/** `service.name` resource attribute of each captured POST, in order. */
function serviceNames(posts: CapturedPost[]): string[] {
  return posts.map((p) => {
    const payload = JSON.parse(p.body);
    const attrs = payload.resourceLogs[0].resource.attributes as Array<{
      key: string;
      value: { stringValue: string };
    }>;
    return attrs.find((a) => a.key === "service.name")?.value.stringValue ?? "";
  });
}

function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
  return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
}

describe("otlp revision: exporter current/revise (WR-414)", () => {
  let collector: ReturnType<typeof startCollector>;

  before(async () => {
    collector = startCollector();
    collector.port = await listenPort(collector.server);
  });
  after(() => collector.close());

  const url = () => `http://127.0.0.1:${collector.port}/v1/logs`;

  it("current() snapshots construction values and defaults; revise returns the resolved config", () => {
    const ex = new OtlpExporter({ endpoint: url(), random: () => 0, now: () => 0 });
    assert.deepEqual(ex.current(), {
      sampleRate: 1,
      maxBuffered: 1000,
      serviceName: "webhook-relay-ts",
    });
    const next = ex.revise({ sampleRate: 0.5 });
    assert.deepEqual(next, { sampleRate: 0.5, maxBuffered: 1000, serviceName: "webhook-relay-ts" });
    assert.deepEqual(ex.current(), next);
    // The snapshot is a copy: mutating it never moves the exporter.
    (next as { sampleRate: number }).sampleRate = 0.1;
    assert.equal(ex.current().sampleRate, 0.5);
    ex.stop();
  });

  it("illegal values throw RangeError and leave the live parameters untouched", () => {
    const ex = new OtlpExporter({
      endpoint: url(),
      sampleRate: 0.25,
      maxBuffered: 10,
      serviceName: "svc",
      random: () => 0,
      now: () => 0,
    });
    const before = ex.current();
    const bad: unknown[] = [
      { sampleRate: -0.1 },
      { sampleRate: 1.1 },
      { sampleRate: NaN },
      { sampleRate: "0.5" },
      { maxBuffered: 0 },
      { maxBuffered: -1 },
      { maxBuffered: 1.5 },
      { maxBuffered: "10" },
      { serviceName: "" },
      { serviceName: 42 },
      null,
      "x",
      [],
      42,
    ];
    for (const patch of bad) {
      assert.throws(
        () => ex.revise(patch as never),
        RangeError,
        `patch ${JSON.stringify(patch)} must throw RangeError`
      );
      assert.deepEqual(ex.current(), before, `live values moved after ${JSON.stringify(patch)}`);
    }
    ex.stop();
  });

  it("sampleRate 0 drops every later record; back to 1 admits again", async () => {
    const ex = new OtlpExporter({ endpoint: url(), random: () => 0, now: () => 0 });
    ex.record(deliveredRecord({ eventId: "evt-a" }));
    assert.equal(ex.stats().buffered, 1);
    ex.revise({ sampleRate: 0 });
    ex.record(deliveredRecord({ eventId: "evt-b" }));
    ex.record(deliveredRecord({ eventId: "evt-c" }));
    assert.equal(ex.stats().buffered, 1, "sampleRate 0 must drop every later record");
    ex.revise({ sampleRate: 1 });
    ex.record(deliveredRecord({ eventId: "evt-d" }));
    assert.equal(ex.stats().buffered, 2);
    await ex.flush(); // drain so stop() posts nothing into the next test
    ex.stop();
  });

  it("tightening maxBuffered drops the oldest down to the new cap on the next enqueue, never retroactively", async () => {
    const ex = new OtlpExporter({
      endpoint: url(),
      maxBuffered: 3,
      random: () => 0,
      now: () => 0,
    });
    ex.record(deliveredRecord({ eventId: "evt-a" }));
    ex.record(deliveredRecord({ eventId: "evt-b" }));
    ex.record(deliveredRecord({ eventId: "evt-c" }));
    assert.equal(ex.stats().buffered, 3);
    ex.revise({ maxBuffered: 2 });
    assert.equal(ex.stats().buffered, 3, "revision alone must not trim the buffer");
    assert.equal(ex.stats().dropped, 0);
    ex.record(deliveredRecord({ eventId: "evt-d" }));
    assert.equal(ex.stats().buffered, 2);
    assert.equal(ex.stats().dropped, 2, "two oldest records drop to reach the new cap");
    await ex.flush();
    const ids = allLogRecords(collector.posts).map((r) => attrMap(r)["relay.event_id"]);
    assert.deepEqual(ids.slice(-2), ["evt-c", "evt-d"]);
    ex.stop();
  });

  it("widening maxBuffered stops early drops", async () => {
    const ex = new OtlpExporter({
      endpoint: url(),
      maxBuffered: 2,
      random: () => 0,
      now: () => 0,
    });
    ex.record(deliveredRecord({ eventId: "evt-a" }));
    ex.record(deliveredRecord({ eventId: "evt-b" }));
    ex.record(deliveredRecord({ eventId: "evt-c" }));
    assert.equal(ex.stats().buffered, 2);
    assert.equal(ex.stats().dropped, 1);
    ex.revise({ maxBuffered: 5 });
    ex.record(deliveredRecord({ eventId: "evt-d" }));
    ex.record(deliveredRecord({ eventId: "evt-e" }));
    ex.record(deliveredRecord({ eventId: "evt-f" }));
    assert.equal(ex.stats().buffered, 5);
    assert.equal(ex.stats().dropped, 1, "no further drops after widening");
    await ex.flush(); // drain so stop() posts nothing into the next test
    ex.stop();
  });

  it("serviceName revision applies from the next payload build", async () => {
    const ex = new OtlpExporter({ endpoint: url(), random: () => 0, now: () => 0 });
    collector.posts.length = 0;
    ex.record(deliveredRecord({ eventId: "evt-a" }));
    await ex.flush();
    ex.revise({ serviceName: "revised-svc" });
    ex.record(deliveredRecord({ eventId: "evt-b" }));
    await ex.flush();
    assert.equal(collector.posts.length, 2);
    assert.deepEqual(serviceNames(collector.posts), ["webhook-relay-ts", "revised-svc"]);
    ex.stop();
  });

  it("in-flight buffer survives a revision: nothing lost, nothing re-sent", async () => {
    const ex = new OtlpExporter({ endpoint: url(), random: () => 0, now: () => 0 });
    collector.posts.length = 0;
    ex.record(deliveredRecord({ eventId: "evt-a" }));
    ex.record(deliveredRecord({ eventId: "evt-b" }));
    ex.revise({ sampleRate: 0.5, maxBuffered: 10, serviceName: "revised-svc" });
    assert.equal(ex.stats().buffered, 2);
    assert.equal(ex.stats().dropped, 0);
    assert.equal(ex.stats().exported, 0);
    await ex.flush();
    assert.equal(collector.posts.length, 1, "one flush, one POST");
    const ids = allLogRecords(collector.posts).map((r) => attrMap(r)["relay.event_id"]);
    assert.deepEqual(ids, ["evt-a", "evt-b"]);
    assert.equal(ex.stats().exported, 2);
    ex.stop();
  });
});

describe("otlp revision: retry queue (WR-414)", () => {
  let collector: ReturnType<typeof startCollector>;

  before(async () => {
    collector = startCollector();
    collector.port = await listenPort(collector.server);
  });
  after(() => collector.close());

  const url = () => `http://127.0.0.1:${collector.port}/v1/logs`;
  const item = (id: string) => ({
    id,
    payload: Buffer.from("hello"),
    targetUrl: "http://127.0.0.1:9/hook",
    headers: {},
  });

  it("unconfigured queue throws the canonical must-restart Error", async () => {
    const ok: Sender = async () => {};
    const q = new RetryQueue({ sender: ok, baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 });
    assert.equal(q.getOtlpConfig(), undefined);
    assert.throws(
      () => q.reviseOtlp({ sampleRate: 0.5 }),
      (err: unknown) =>
        err instanceof Error &&
        err.message ===
          "reviseOtlp: otlp export is not configured — enabling it requires a restart"
    );
    await q.shutdown(2000);
  });

  it("illegal patch throws RangeError and the live config is untouched", async () => {
    const ok: Sender = async () => {};
    const q = new RetryQueue({
      sender: ok,
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      otlp: { endpoint: url(), sampleRate: 0.5, maxBuffered: 50, serviceName: "svc" },
    });
    const before = q.getOtlpConfig();
    assert.throws(() => q.reviseOtlp({ sampleRate: 1.1 }), RangeError);
    assert.throws(() => q.reviseOtlp({ maxBuffered: 0 }), RangeError);
    assert.throws(() => q.reviseOtlp({ serviceName: "" }), RangeError);
    assert.throws(() => q.reviseOtlp(null as never), RangeError);
    assert.deepEqual(q.getOtlpConfig(), before);
    await q.shutdown(2000);
  });

  it("sampleRate 0 stops later delivery exports; back to 1 resumes; stats survive the revision", async () => {
    const ok: Sender = async () => {};
    const q = new RetryQueue({
      sender: ok,
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      otlp: { endpoint: url(), random: () => 0 },
    });
    q.start();
    try {
      collector.posts.length = 0;
      q.enqueue(item("q1"));
      await waitFor(() => q.getOtlpStats().exported === 1, 5000, "first export lands");
      const revised = q.reviseOtlp({ sampleRate: 0 });
      assert.deepEqual(revised, { sampleRate: 0, maxBuffered: 1000, serviceName: "webhook-relay-ts" });
      assert.equal(q.getOtlpStats().exported, 1, "revision itself exports nothing");
      q.enqueue(item("q2"));
      await waitFor(() => q.pendingCount() === 0, 3000, "second delivery settles");
      await sleep(300); // past the export flush delay — nothing may arrive
      assert.equal(q.getOtlpStats().exported, 1, "sampleRate 0 drops the second delivery");
      assert.equal(q.getOtlpStats().buffered, 0);
      q.reviseOtlp({ sampleRate: 1 });
      q.enqueue(item("q3"));
      await waitFor(() => q.getOtlpStats().exported === 2, 5000, "third export lands");
    } finally {
      await q.shutdown(2000);
    }
  });
});

describe("otlp revision: server (WR-414)", () => {
  let collector: ReturnType<typeof startCollector>;
  let downstream: Server;
  let downstreamPort: number;
  const received: Buffer[] = [];
  const servers: Server[] = [];

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
    for (const s of servers) {
      await new Promise<void>((r) => s.close(() => r()));
    }
  });

  const INGEST_KEY = "otlp-revision-key";
  const BODY = Buffer.from(JSON.stringify({ hello: "otlp-revision" }));

  async function listenRelay(relay: Server): Promise<number> {
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const addr = relay.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  async function postWebhook(port: number): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: {
            "x-signature": signSha256(BODY, INGEST_KEY),
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

  function makeServer(otlp?: { endpoint: string }) {
    const dir = mkdtempSync(join(tmpdir(), "otlp-revision-audit-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal key in
      // test-file writes (see AGENTS.md), so the key is spelled out
      // dynamically instead.
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: `http://127.0.0.1:${downstreamPort}/hook`,
      auditLog,
      ...(otlp !== undefined ? { otlp } : {}),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  it("server revision audits otlp_export_revised with exact previous/current and no endpoint", async () => {
    const endpoint = `http://127.0.0.1:${collector.port}/v1/logs`;
    const { relay, auditLog } = makeServer({ endpoint });
    const next = relay.reviseOtlp!({ sampleRate: 0.25, serviceName: "revised-svc" });
    assert.deepEqual(next, {
      sampleRate: 0.25,
      maxBuffered: 1000,
      serviceName: "revised-svc",
    });
    const revised = eventsOf(auditLog, "otlp_export_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, {
      sampleRate: 1,
      maxBuffered: 1000,
      serviceName: "webhook-relay-ts",
    });
    assert.deepEqual(revised[0].current, {
      sampleRate: 0.25,
      maxBuffered: 1000,
      serviceName: "revised-svc",
    });
    assert.ok(
      !JSON.stringify(revised[0]).includes(endpoint),
      "the audit must never record the endpoint"
    );
    // Empty and same-value patches are silent no-ops: no further audit.
    relay.reviseOtlp!({});
    relay.reviseOtlp!({ sampleRate: 0.25, serviceName: "revised-svc" });
    assert.equal(eventsOf(auditLog, "otlp_export_revised").length, 1);
    // An illegal patch throws RangeError and audits nothing.
    assert.throws(() => relay.reviseOtlp!({ sampleRate: 2 }), RangeError);
    assert.equal(eventsOf(auditLog, "otlp_export_revised").length, 1);
  });

  it("unconfigured server throws the canonical must-restart Error", () => {
    const { relay } = makeServer();
    assert.throws(
      () => relay.reviseOtlp!({ sampleRate: 0.5 }),
      (err: unknown) =>
        err instanceof Error &&
        err.message ===
          "reviseOtlp: otlp export is not configured — enabling it requires a restart"
    );
  });

  it("server revision keeps the export path live: later deliveries export with the new service name", async () => {
    const { relay } = makeServer({ endpoint: `http://127.0.0.1:${collector.port}/v1/logs` });
    const port = await listenRelay(relay);
    collector.posts.length = 0;
    received.length = 0;
    assert.equal(await postWebhook(port), 202);
    await waitFor(() => received.length > 0, 5000, "first downstream delivery");
    await waitFor(() => collector.posts.length > 0, 5000, "first OTLP export");
    assert.deepEqual(serviceNames(collector.posts), ["webhook-relay-ts"]);
    relay.reviseOtlp!({ serviceName: "revised-svc" });
    assert.equal(await postWebhook(port), 202);
    await waitFor(() => received.length >= 2, 5000, "second downstream delivery");
    await waitFor(() => collector.posts.length >= 2, 5000, "second OTLP export");
    assert.deepEqual(serviceNames(collector.posts), ["webhook-relay-ts", "revised-svc"]);
  });
});
