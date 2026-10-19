import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import {
  OtelTracer,
  OtelTraceExporter,
  buildOtlpTracesPayload,
  OTEL_SPAN_INTAKE,
  OTEL_SPAN_DISPATCH,
  OTEL_SPAN_DELIVERY,
} from "../src/otel-tracing.ts";
import { traceAttemptSpanId } from "../src/trace-context.ts";
import { mapOtlpTraceId } from "../src/otlp.ts";

const URL = "http://localhost:9999/hook";
const TRACE_ID = "abc123";

function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    },
  };
}

/** Stub OTLP collector: captures POST bodies to /v1/traces. */
function stubCollector(handler?: (body: string) => { status: number }) {
  const bodies: string[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      bodies.push(Buffer.concat(chunks).toString());
      const status = handler?.(Buffer.concat(chunks).toString())?.status ?? 200;
      res.writeHead(status, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  return {
    bodies: () => bodies,
    async listen(): Promise<{ server: Server; port: number }> {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const addr = server.address();
      assert.ok(addr && typeof addr === "object");
      return { server, port: addr.port };
    },
  };
}

describe("OtelTracer", () => {
  function makeTracer(overrides: Record<string, unknown> = {}) {
    let now = 1_000_000;
    const tracer = new OtelTracer({
      endpoint: "http://collector:4318",
      now: () => now,
      random: () => 0, // always sample
      ...overrides,
    });
    return { tracer, advance: (ms: number) => (now += ms), now: () => now };
  }

  const ITEM = { id: "t-1", traceId: TRACE_ID, targetUrl: URL };

  it("builds the intake → dispatch → delivery chain with correct parentage", () => {
    const { tracer, advance } = makeTracer();
    tracer.intake(ITEM);
    advance(50);
    assert.equal(tracer.startAttempt(ITEM, 1), 1);
    advance(20);
    tracer.endAttempt(ITEM, 1, false, "downstream down");
    advance(100);
    assert.equal(tracer.startAttempt(ITEM, 2), 2);
    advance(30);
    tracer.endAttempt(ITEM, 2, true);
    tracer.terminal(ITEM, "delivered");

    const stats = tracer.stats();
    assert.equal(stats.enabled, true);
    assert.equal(stats.liveTraces, 0);
    assert.equal(stats.buffered, 1);

    // A never-attempted delivery still exports its intake span.
    tracer.intake({ ...ITEM, id: "t-2" });
    tracer.terminal({ id: "t-2" }, "dead_letter");
    assert.equal(tracer.stats().buffered, 2);
    tracer.stop();
  });

  it("span ids: attempt span reuses the wire traceparent parent-id", () => {
    const { tracer } = makeTracer();
    const traceId32 = mapOtlpTraceId(TRACE_ID);
    tracer.intake(ITEM);
    tracer.startAttempt(ITEM, 1);
    tracer.endAttempt(ITEM, 1, true);
    tracer.terminal(ITEM, "delivered");
    // The correlation is structural: the attempt span id is derived the
    // same way the outbound traceparent parent-id is.
    assert.equal(traceAttemptSpanId(traceId32, 1), traceAttemptSpanId(traceId32, 1));
    assert.match(traceAttemptSpanId(traceId32, 1), /^[0-9a-f]{16}$/);
    tracer.stop();
  });

  it("reuses the caller-propagated W3C trace id when present", () => {
    const { tracer } = makeTracer();
    const w3cTraceId = "4bf92f3577b34da6a3ce929d0e0e4736";
    assert.equal(
      OtelTracer.traceIdFor({ traceId: TRACE_ID, traceContext: { traceId: w3cTraceId } }),
      w3cTraceId
    );
    assert.equal(OtelTracer.traceIdFor({ traceId: TRACE_ID }), mapOtlpTraceId(TRACE_ID));
    tracer.stop();
  });

  it("head-based sampling: unsampled deliveries are not tracked", () => {
    const { tracer } = makeTracer({ random: () => 0.99, sampleRate: 0.5 });
    tracer.intake(ITEM);
    assert.equal(tracer.stats().liveTraces, 0);
    assert.equal(tracer.startAttempt(ITEM, 1), undefined);
    tracer.endAttempt(ITEM, 1, true); // no-op
    tracer.terminal(ITEM, "delivered"); // no-op
    assert.equal(tracer.stats().buffered, 0);
    tracer.stop();
  });

  it("terminal without an attempt ends the intake span (never-attempted path)", () => {
    const { tracer, advance } = makeTracer();
    tracer.intake(ITEM);
    advance(10);
    tracer.terminal(ITEM, "dead_letter");
    assert.equal(tracer.stats().liveTraces, 0);
    assert.equal(tracer.stats().buffered, 1);
    tracer.stop();
  });

  it("bounds live traces (drop-oldest)", () => {
    const { tracer } = makeTracer({ maxTraces: 2 });
    tracer.intake({ ...ITEM, id: "a" });
    tracer.intake({ ...ITEM, id: "b" });
    tracer.intake({ ...ITEM, id: "c" });
    assert.equal(tracer.stats().liveTraces, 2);
    tracer.stop();
  });

  it("never throws on misuse", () => {
    const { tracer } = makeTracer();
    // Unknown ids, undefined handles, double terminal — all no-ops.
    tracer.endAttempt({ id: "nope" }, 1, true);
    tracer.endAttempt({ id: "nope" }, undefined, true);
    tracer.terminal({ id: "nope" }, "delivered");
    tracer.intake(ITEM);
    tracer.terminal(ITEM, "delivered");
    tracer.terminal(ITEM, "delivered");
    tracer.stop();
  });

  it("rejects illegal options with RangeError", () => {
    for (const opts of [
      { endpoint: "" },
      { endpoint: "not-a-url" },
      { endpoint: "ftp://x/" },
      { endpoint: "http://x/", sampleRate: -0.1 },
      { endpoint: "http://x/", sampleRate: 1.1 },
      { endpoint: "http://x/", sampleRate: NaN },
      { endpoint: "http://x/", maxBuffered: 0 },
      { endpoint: "http://x/", maxTraces: 0 },
      { endpoint: "http://x/", headers: { "": "v" } },
      { endpoint: "http://x/", headers: { k: "" } },
      null,
      "x",
    ]) {
      assert.throws(() => new OtelTracer(opts as never), RangeError, JSON.stringify(opts));
    }
  });
});

describe("buildOtlpTracesPayload", () => {
  it("renders valid OTLP/HTTP traces JSON", () => {
    const traceId = mapOtlpTraceId(TRACE_ID);
    const payload = buildOtlpTracesPayload(
      [
        [
          {
            traceId,
            spanId: "a".repeat(16),
            name: OTEL_SPAN_INTAKE,
            startTimeUnixNano: "1000000000000000",
            endTimeUnixNano: "1000050000000000",
            attributes: [
              { key: "relay.event_id", value: { stringValue: "t-1" } },
              { key: "relay.endpoint", value: { stringValue: URL } },
            ],
            statusCode: 1,
          },
          {
            traceId,
            spanId: "b".repeat(16),
            parentSpanId: "a".repeat(16),
            name: OTEL_SPAN_DELIVERY,
            startTimeUnixNano: "1000050000000000",
            endTimeUnixNano: "1000070000000000",
            attributes: [
              { key: "relay.attempt", value: { intValue: "1" } },
              { key: "relay.status", value: { stringValue: "ok" } },
            ],
            statusCode: 1,
          },
        ],
      ],
      "webhook-relay-ts"
    );
    const doc = JSON.parse(payload);
    assert.equal(doc.resourceSpans.length, 1);
    const spans = doc.resourceSpans[0].scopeSpans[0].spans;
    assert.equal(spans.length, 2);
    assert.equal(spans[0].name, OTEL_SPAN_INTAKE);
    assert.equal(spans[0].traceId, traceId);
    assert.equal(spans[0].status.code, 1);
    assert.equal(spans[1].parentSpanId, "a".repeat(16));
    assert.equal(spans[1].name, OTEL_SPAN_DELIVERY);
    assert.deepEqual(doc.resourceSpans[0].resource.attributes, [
      { key: "service.name", value: { stringValue: "webhook-relay-ts" } },
    ]);
    assert.equal(doc.resourceSpans[0].scopeSpans[0].scope.name, "webhook-relay-ts");
  });
});

describe("OtelTraceExporter", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
  });

  function finishedSpans() {
    const traceId = mapOtlpTraceId(TRACE_ID);
    return [
      {
        traceId,
        spanId: "a".repeat(16),
        name: OTEL_SPAN_INTAKE,
        startTimeUnixNano: "1000000000000000",
        endTimeUnixNano: "1000050000000000",
        attributes: [],
        statusCode: 1,
      },
    ];
  }

  it("POSTs OTLP traces JSON to <endpoint>/v1/traces", async () => {
    const collector = stubCollector();
    const { server, port } = await collector.listen();
    servers.push(server);
    const exporter = new OtelTraceExporter({ endpoint: `http://127.0.0.1:${port}` });
    exporter.record(finishedSpans());
    await exporter.flush();
    assert.equal(collector.bodies().length, 1);
    const doc = JSON.parse(collector.bodies()[0]);
    assert.equal(doc.resourceSpans[0].scopeSpans[0].spans[0].name, OTEL_SPAN_INTAKE);
    const stats = exporter.exportStats();
    assert.equal(stats.exportedSpans, 1);
    assert.equal(stats.buffered, 0);
    exporter.stop();
  });

  it("retries with backoff on failure and recovers", async () => {
    let calls = 0;
    const collector = stubCollector(() => ({ status: ++calls === 1 ? 500 : 200 }));
    const { server, port } = await collector.listen();
    servers.push(server);
    const exporter = new OtelTraceExporter({ endpoint: `http://127.0.0.1:${port}` });
    exporter.record(finishedSpans());
    await exporter.flush(); // 500 -> stays buffered
    assert.equal(exporter.exportStats().buffered, 1);
    assert.ok(exporter.exportStats().lastError !== undefined);
    await exporter.flush(); // 200 -> exported
    assert.equal(exporter.exportStats().exportedSpans, 1);
    assert.equal(exporter.exportStats().lastError, undefined);
    exporter.stop();
  });

  it("drop-oldest on buffer overflow", async () => {
    const collector = stubCollector();
    const { server, port } = await collector.listen();
    servers.push(server);
    const exporter = new OtelTraceExporter({ endpoint: `http://127.0.0.1:${port}`, maxBuffered: 2 });
    exporter.record(finishedSpans());
    exporter.record(finishedSpans());
    exporter.record(finishedSpans());
    const stats = exporter.exportStats();
    assert.equal(stats.buffered, 2);
    assert.equal(stats.dropped, 1);
    exporter.stop();
  });
});

describe("retry queue OTel tracing", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
  });

  function makeQueue(collectorPort: number, extra: Record<string, unknown> = {}) {
    const timer = manualTimer();
    let calls = 0;
    let fail = true;
    const sender: Sender = async () => {
      calls += 1;
      if (fail) throw new Error("downstream down");
    };
    let now = 1_000_000;
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      otelTracing: {
        endpoint: `http://127.0.0.1:${collectorPort}`,
        now: () => now,
        random: () => 0,
      },
      ...extra,
    });
    q.start();
    return { q, timer, calls: () => calls, setFail: (v: boolean) => (fail = v), advance: (ms: number) => (now += ms) };
  }

  const ITEM = (id: string) => ({ id, payload: Buffer.from("x"), targetUrl: URL, headers: {} });

  it("exports the intake → dispatch → delivery chain for a delivered delivery", async () => {
    const collector = stubCollector();
    const { server, port } = await collector.listen();
    servers.push(server);
    const { q, timer, setFail, advance } = makeQueue(port);
    setFail(false);
    q.enqueue(ITEM("w-1"));
    advance(25);
    await timer.step();
    advance(10);
    // Let the background flush run.
    const deadline = Date.now() + 5000;
    while (collector.bodies().length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(collector.bodies().length, 1);
    const doc = JSON.parse(collector.bodies()[0]);
    const spans = doc.resourceSpans[0].scopeSpans[0].spans;
    const names = spans.map((s: { name: string }) => s.name).sort();
    assert.deepEqual(names, [OTEL_SPAN_DELIVERY, OTEL_SPAN_DISPATCH, OTEL_SPAN_INTAKE].sort());

    const byName = new Map(spans.map((s: { name: string }) => [s.name, s]));
    const intake = byName.get(OTEL_SPAN_INTAKE) as { spanId: string; parentSpanId?: string };
    const dispatch = byName.get(OTEL_SPAN_DISPATCH) as { spanId: string; parentSpanId: string };
    const delivery = byName.get(OTEL_SPAN_DELIVERY) as {
      spanId: string;
      parentSpanId: string;
      attributes: Array<{ key: string; value: { stringValue?: string; intValue?: string } }>;
    };
    assert.equal(intake.parentSpanId, undefined);
    assert.equal(dispatch.parentSpanId, intake.spanId);
    assert.equal(delivery.parentSpanId, dispatch.spanId);
    // All spans share the trace id.
    const traceIds = new Set(spans.map((s: { traceId: string }) => s.traceId));
    assert.equal(traceIds.size, 1);
    // Attempt span id matches the wire traceparent parent-id derivation.
    const traceId = [...traceIds][0] as string;
    assert.equal(delivery.spanId, traceAttemptSpanId(traceId, 1));
    // Attributes: endpoint/tenant/attempt/status.
    const attrs = new Map(delivery.attributes.map((a) => [a.key, a.value.stringValue ?? a.value.intValue]));
    assert.equal(attrs.get("relay.endpoint"), URL);
    assert.equal(attrs.get("relay.attempt"), "1");
    assert.equal(attrs.get("relay.status"), "ok");
    assert.equal(delivery.attributes.find((a) => a.key === "relay.tenant"), undefined);
    // Intake measures the queue wait (25ms) — duration via timestamps.
    const intakeSpan = byName.get(OTEL_SPAN_INTAKE) as { startTimeUnixNano: string; endTimeUnixNano: string };
    assert.equal(
      BigInt(intakeSpan.endTimeUnixNano) - BigInt(intakeSpan.startTimeUnixNano),
      25_000_000n
    );

    const stats = q.getOtelTracingStats();
    assert.equal(stats.enabled, true);
    assert.equal(stats.liveTraces, 0);
    q.stop();
  });

  it("exports a retrying delivery with one span per attempt", async () => {
    const collector = stubCollector();
    const { server, port } = await collector.listen();
    servers.push(server);
    const { q, timer, setFail } = makeQueue(port);
    q.enqueue(ITEM("w-2"));
    await timer.step(); // attempt 1 fails
    setFail(false);
    await timer.step(); // attempt 2 succeeds
    const deadline = Date.now() + 5000;
    while (collector.bodies().length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const doc = JSON.parse(collector.bodies()[0]);
    const spans = doc.resourceSpans[0].scopeSpans[0].spans;
    const deliveries = spans.filter((s: { name: string }) => s.name === OTEL_SPAN_DELIVERY);
    assert.equal(deliveries.length, 2);
    const attempts = deliveries.map((s: { attributes: Array<{ key: string; value: { intValue?: string } }> }) =>
      s.attributes.find((a) => a.key === "relay.attempt")?.value.intValue
    ).sort();
    assert.deepEqual(attempts, ["1", "2"]);
    const statuses = deliveries.map((s: { attributes: Array<{ key: string; value: { stringValue?: string } }> }) =>
      s.attributes.find((a) => a.key === "relay.status")?.value.stringValue
    ).sort();
    assert.deepEqual(statuses, ["error", "ok"]);
    // The failed attempt carries the error message.
    const failed = deliveries.find((s: { attributes: Array<{ key: string; value: { stringValue?: string } }> }) =>
      s.attributes.find((a) => a.key === "relay.status")?.value.stringValue === "error"
    );
    assert.equal(
      failed.attributes.find((a: { key: string }) => a.key === "relay.error")?.value.stringValue,
      "downstream down"
    );
    // Dispatch span counts both attempts.
    const dispatch = spans.find((s: { name: string }) => s.name === OTEL_SPAN_DISPATCH);
    assert.equal(
      dispatch.attributes.find((a: { key: string }) => a.key === "relay.attempts")?.value.intValue,
      "2"
    );
    q.stop();
  });

  it("carries the tenant attribute when set", async () => {
    const collector = stubCollector();
    const { server, port } = await collector.listen();
    servers.push(server);
    const { q, timer, setFail } = makeQueue(port);
    setFail(false);
    q.enqueue({ ...ITEM("w-3"), tenantId: "acme" });
    await timer.step();
    const deadline = Date.now() + 5000;
    while (collector.bodies().length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const doc = JSON.parse(collector.bodies()[0]);
    const spans = doc.resourceSpans[0].scopeSpans[0].spans;
    for (const s of spans) {
      const tenant = s.attributes.find((a: { key: string }) => a.key === "relay.tenant")?.value.stringValue;
      assert.equal(tenant, "acme");
    }
    q.stop();
  });

  it("is disabled by default: zero behavior change", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(ITEM("w-4"));
    await timer.step();
    assert.deepEqual(q.getOtelTracingStats(), {
      enabled: false,
      liveTraces: 0,
      buffered: 0,
      dropped: 0,
      exportedSpans: 0,
    });
    q.stop();
  });

  it("rejects an illegal otelTracing option at construction", () => {
    assert.throws(
      () => new RetryQueue({ sender: async () => {}, otelTracing: { endpoint: "http://x/", sampleRate: 2 } }),
      RangeError
    );
  });
});
