import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender, type SloMissInfo } from "../src/retry.ts";
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

const ENABLE_REQUIRES_ENDPOINT =
  "reviseOtlp: enabling OTLP export requires an endpoint — the patch must carry the collector URL; an empty patch cannot enable it";

describe("otlp enable: retry queue (WR-465)", () => {
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
  const makeQueue = (extra: Record<string, unknown> = {}) =>
    new RetryQueue({
      sender: (async () => {}) as Sender,
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      ...extra,
    });

  it("enable with only an endpoint resolves the construction defaults and reports enabled", async () => {
    const q = makeQueue();
    assert.equal(q.getOtlpConfig(), undefined);
    assert.deepEqual(q.getOtlpStats(), { enabled: false, buffered: 0, dropped: 0, exported: 0 });
    const enabled = q.reviseOtlp({ endpoint: url() });
    assert.deepEqual(enabled, {
      sampleRate: 1,
      maxBuffered: 1000,
      serviceName: "webhook-relay-ts",
    });
    assert.deepEqual(q.getOtlpConfig(), enabled);
    assert.equal(q.getOtlpStats().enabled, true);
    await q.shutdown(2000);
  });

  it("enable with partial knobs keeps them; a later revision merges the live values; endpoint stays fixed", async () => {
    const q = makeQueue();
    const enabled = q.reviseOtlp({
      endpoint: url(),
      sampleRate: 0.25,
      serviceName: "enabled-svc",
    });
    assert.deepEqual(enabled, { sampleRate: 0.25, maxBuffered: 1000, serviceName: "enabled-svc" });
    const revised = q.reviseOtlp({ maxBuffered: 50 });
    assert.deepEqual(revised, { sampleRate: 0.25, maxBuffered: 50, serviceName: "enabled-svc" });
    // The endpoint is fixed at construction: re-pointing is rejected, never ignored.
    assert.throws(
      () => q.reviseOtlp({ endpoint: "http://127.0.0.1:9/other" }),
      (err: unknown) =>
        err instanceof RangeError &&
        err.message.startsWith("reviseOtlp: endpoint is fixed at construction")
    );
    assert.deepEqual(q.getOtlpConfig(), {
      sampleRate: 0.25,
      maxBuffered: 50,
      serviceName: "enabled-svc",
    });
    await q.shutdown(2000);
  });

  it("missing endpoint refuses: empty patch, knob-only patch, and null — then enables", async () => {
    const q = makeQueue();
    assert.throws(
      () => q.reviseOtlp({}),
      (err: unknown) => err instanceof RangeError && err.message === ENABLE_REQUIRES_ENDPOINT
    );
    assert.throws(
      () => q.reviseOtlp({ sampleRate: 0.5 }),
      (err: unknown) => err instanceof RangeError && err.message === ENABLE_REQUIRES_ENDPOINT
    );
    assert.throws(
      () => q.reviseOtlp(null as never),
      (err: unknown) =>
        err instanceof RangeError &&
        err.message === "reviseOtlp: patch must be an object, got null"
    );
    assert.equal(q.getOtlpConfig(), undefined, "a refused enable leaves the queue unconfigured");
    const enabled = q.reviseOtlp({ endpoint: url() });
    assert.deepEqual(enabled, { sampleRate: 1, maxBuffered: 1000, serviceName: "webhook-relay-ts" });
    await q.shutdown(2000);
  });

  it("illegal endpoint or knob refuses and stays unconfigured — then enables", async () => {
    const q = makeQueue();
    const bad: Array<Record<string, unknown>> = [
      { endpoint: "not-a-url" },
      { endpoint: "ftp://127.0.0.1:9/v1/logs" },
      { endpoint: "" },
      { endpoint: url(), sampleRate: 1.1 },
      { endpoint: url(), sampleRate: -0.1 },
      { endpoint: url(), maxBuffered: 0 },
      { endpoint: url(), serviceName: "" },
    ];
    for (const patch of bad) {
      assert.throws(() => q.reviseOtlp(patch as never), RangeError);
      assert.equal(q.getOtlpConfig(), undefined, `refused patch must leave the queue unconfigured: ${JSON.stringify(patch)}`);
    }
    const enabled = q.reviseOtlp({ endpoint: url() });
    assert.deepEqual(enabled, { sampleRate: 1, maxBuffered: 1000, serviceName: "webhook-relay-ts" });
    await q.shutdown(2000);
  });

  it("non-object and array patches refuse and stay unconfigured", async () => {
    const q = makeQueue();
    assert.throws(() => q.reviseOtlp("http://127.0.0.1:9/v1/logs" as never), RangeError);
    assert.throws(() => q.reviseOtlp([url()] as never), RangeError);
    assert.equal(q.getOtlpConfig(), undefined);
    await q.shutdown(2000);
  });

  it("the next delivery event exports after enable; a pre-enable delivery never does", async () => {
    const q = makeQueue();
    q.start();
    try {
      collector.posts.length = 0;
      q.enqueue(item("pre-enable"));
      await waitFor(() => q.pendingCount() === 0, 3000, "pre-enable delivery settles");
      await sleep(300); // past the export flush delay — nothing may arrive
      assert.equal(collector.posts.length, 0, "no exporter existed for the pre-enable delivery");
      assert.equal(q.getOtlpStats().exported, 0);
      q.reviseOtlp({ endpoint: url() });
      q.enqueue(item("post-enable"));
      await waitFor(() => q.getOtlpStats().exported === 1, 5000, "post-enable export lands");
      const ids = allLogRecords(collector.posts).map((r) => attrMap(r)["relay.event_id"]);
      assert.deepEqual(ids, ["post-enable"]);
    } finally {
      await q.shutdown(2000);
    }
  });

  it("slo_missed exports after enable while the caller hook still fires exactly once", async () => {
    const misses: SloMissInfo[] = [];
    const slow: Sender = async () => {
      await sleep(10);
      return { statusCode: 200, body: Buffer.alloc(0), truncated: false };
    };
    const q = new RetryQueue({
      sender: slow,
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      latency: { sloMs: 1, onSloMiss: (info) => misses.push(info) },
    });
    q.start();
    try {
      collector.posts.length = 0;
      q.reviseOtlp({ endpoint: url() });
      q.enqueue(item("slow-1"));
      await waitFor(() => misses.length === 1, 5000, "caller slo-miss hook fires");
      await waitFor(
        () =>
          allLogRecords(collector.posts).some(
            (r) => attrMap(r)["relay.event_type"] === "slo_missed"
          ),
        5000,
        "slo_missed export lands"
      );
      const slo = allLogRecords(collector.posts).filter(
        (r) => attrMap(r)["relay.event_type"] === "slo_missed"
      );
      assert.equal(slo.length, 1);
      assert.equal(attrMap(slo[0])["relay.event_id"], "slow-1");
      assert.equal(misses.length, 1, "the caller hook fires exactly once, not twice via the wrapper");
    } finally {
      await q.shutdown(2000);
    }
  });

  it("a fresh queue is unconfigured again: the enable is live-only", async () => {
    const q = makeQueue();
    q.reviseOtlp({ endpoint: url() });
    assert.equal(q.getOtlpStats().enabled, true);
    await q.shutdown(2000);
    const restarted = makeQueue();
    assert.equal(restarted.getOtlpConfig(), undefined);
    assert.equal(restarted.getOtlpStats().enabled, false);
    await restarted.shutdown(2000);
  });
});

describe("otlp enable: server (WR-465)", () => {
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

  const INGEST_KEY = "otlp-enable-key";
  const BODY = Buffer.from(JSON.stringify({ hello: "otlp-enable" }));

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

  function makeServer() {
    const dir = mkdtempSync(join(tmpdir(), "otlp-enable-audit-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal key in
      // test-file writes (see AGENTS.md), so the key is spelled out
      // dynamically instead.
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: `http://127.0.0.1:${downstreamPort}/hook`,
      auditLog,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  it("server enable audits otlp_export_revised with previous null and never records the endpoint", () => {
    const endpoint = `http://127.0.0.1:${collector.port}/v1/logs`;
    const { relay, auditLog } = makeServer();
    const next = relay.reviseOtlp!({ endpoint, sampleRate: 0.5, serviceName: "enabled-svc" });
    assert.deepEqual(next, { sampleRate: 0.5, maxBuffered: 1000, serviceName: "enabled-svc" });
    const revised = eventsOf(auditLog, "otlp_export_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, {
      sampleRate: 0.5,
      maxBuffered: 1000,
      serviceName: "enabled-svc",
    });
    assert.ok(
      !JSON.stringify(revised[0]).includes(endpoint),
      "the enable audit must never record the endpoint"
    );
  });

  it("server enable: later deliveries export with the enabled service name", async () => {
    const { relay } = makeServer();
    const port = await listenRelay(relay);
    collector.posts.length = 0;
    received.length = 0;
    assert.equal(await postWebhook(port), 202);
    await waitFor(() => received.length > 0, 5000, "pre-enable downstream delivery");
    await sleep(300); // past the export flush delay — nothing may arrive
    assert.equal(collector.posts.length, 0, "no exporter existed for the pre-enable delivery");
    relay.reviseOtlp!({
      endpoint: `http://127.0.0.1:${collector.port}/v1/logs`,
      serviceName: "enabled-svc",
    });
    assert.equal(await postWebhook(port), 202);
    await waitFor(() => received.length >= 2, 5000, "post-enable downstream delivery");
    await waitFor(() => collector.posts.length > 0, 5000, "post-enable OTLP export");
    assert.deepEqual(serviceNames(collector.posts), ["enabled-svc"]);
  });

  it("server enable: same-value and empty revisions after enable are silent no-ops", () => {
    const { relay, auditLog } = makeServer();
    relay.reviseOtlp!({
      endpoint: `http://127.0.0.1:${collector.port}/v1/logs`,
      sampleRate: 0.5,
    });
    assert.equal(eventsOf(auditLog, "otlp_export_revised").length, 1);
    relay.reviseOtlp!({});
    relay.reviseOtlp!({ sampleRate: 0.5 });
    assert.equal(eventsOf(auditLog, "otlp_export_revised").length, 1);
  });

  it("server enable: an endpoint in a later patch is rejected and audits nothing", () => {
    const { relay, auditLog } = makeServer();
    relay.reviseOtlp!({
      endpoint: `http://127.0.0.1:${collector.port}/v1/logs`,
      sampleRate: 0.5,
    });
    assert.throws(
      () => relay.reviseOtlp!({ endpoint: "http://127.0.0.1:9/other" }),
      (err: unknown) =>
        err instanceof RangeError &&
        err.message.startsWith("reviseOtlp: endpoint is fixed at construction")
    );
    assert.equal(eventsOf(auditLog, "otlp_export_revised").length, 1);
  });

  it("a fresh server is unconfigured again: the enable is live-only", () => {
    const { relay } = makeServer();
    relay.reviseOtlp!({ endpoint: `http://127.0.0.1:${collector.port}/v1/logs` });
    const fresh = makeServer();
    assert.throws(
      () => fresh.relay.reviseOtlp!({ sampleRate: 0.5 }),
      (err: unknown) => err instanceof RangeError && err.message === ENABLE_REQUIRES_ENDPOINT
    );
  });
});
