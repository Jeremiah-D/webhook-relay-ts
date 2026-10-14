import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  formatTraceparent,
  parseInboundTraceContext,
  parseTraceparent,
  parseTraceState,
  resolveOutboundTraceContext,
  resolveTraceContextOptions,
  traceAttemptSpanId,
} from "../src/trace-context.ts";
import { mapOtlpTraceId, buildOtlpPayload, type OtlpRecordInput } from "../src/otlp.ts";
import { createRelayServer } from "../src/server.ts";
import { RetryQueue, type DeliveryEvent } from "../src/retry.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const testSecret = "trace-ctx-secret";
const BODY = Buffer.from(JSON.stringify({ event: "trace.probe" }));
const TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT_ID = "00f067aa0ba902b7";
const TRACESTATE = "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE";

function validTraceparent(flags = "01"): string {
  return `00-${TRACE_ID}-${PARENT_ID}-${flags}`;
}

describe("WR-98 traceparent parsing", () => {
  it("parses a valid sampled traceparent", () => {
    const ctx = parseTraceparent(validTraceparent("01"));
    assert.deepEqual(ctx, { traceId: TRACE_ID, spanId: PARENT_ID, sampled: true });
  });

  it("parses the unsampled flag (00)", () => {
    const ctx = parseTraceparent(validTraceparent("00"));
    assert.equal(ctx?.sampled, false);
  });

  it("reads only the sampled bit of the flags", () => {
    assert.equal(parseTraceparent(validTraceparent("09"))?.sampled, true);
    assert.equal(parseTraceparent(validTraceparent("08"))?.sampled, false);
  });

  it("lowercases uppercase hex", () => {
    const ctx = parseTraceparent(`00-${TRACE_ID.toUpperCase()}-${PARENT_ID.toUpperCase()}-01`);
    assert.equal(ctx?.traceId, TRACE_ID);
    assert.equal(ctx?.spanId, PARENT_ID);
  });

  it("accepts a future version with trailing fields", () => {
    const ctx = parseTraceparent(`01-${TRACE_ID}-${PARENT_ID}-01-abc123`);
    assert.deepEqual(ctx, { traceId: TRACE_ID, spanId: PARENT_ID, sampled: true });
  });

  it("rejects: version ff (reserved)", () => {
    assert.equal(parseTraceparent(`ff-${TRACE_ID}-${PARENT_ID}-01`), undefined);
  });

  it("rejects: all-zero trace-id and parent-id", () => {
    assert.equal(parseTraceparent(`00-${"0".repeat(32)}-${PARENT_ID}-01`), undefined);
    assert.equal(parseTraceparent(`00-${TRACE_ID}-${"0".repeat(16)}-01`), undefined);
  });

  it("rejects: malformed shapes", () => {
    assert.equal(parseTraceparent(`00-${TRACE_ID.slice(2)}-${PARENT_ID}-01`), undefined); // short trace-id
    assert.equal(parseTraceparent(`00-${TRACE_ID}-${PARENT_ID.slice(2)}-01`), undefined); // short parent-id
    assert.equal(parseTraceparent(`00-${TRACE_ID}-${PARENT_ID}-0`), undefined); // short flags
    assert.equal(parseTraceparent(`00-${TRACE_ID}-${PARENT_ID}`), undefined); // missing flags
    assert.equal(parseTraceparent(`00-${TRACE_ID}-${PARENT_ID}-zz`), undefined); // non-hex flags
    assert.equal(parseTraceparent(`00-${TRACE_ID}-${PARENT_ID}-01-extra`), undefined); // v00 + extra
    assert.equal(parseTraceparent("not-a-traceparent"), undefined);
    assert.equal(parseTraceparent(""), undefined);
    assert.equal(parseTraceparent(undefined), undefined);
  });

  it("takes the first value of a repeated header", () => {
    const ctx = parseTraceparent([validTraceparent("00"), validTraceparent("01")]);
    assert.equal(ctx?.sampled, false);
  });
});

describe("WR-98 tracestate parsing", () => {
  it("passes a well-formed tracestate through verbatim", () => {
    assert.equal(parseTraceState(TRACESTATE), TRACESTATE);
  });

  it("drops malformed values but keeps them from breaking the traceparent", () => {
    assert.equal(parseTraceState("no-equals-here"), undefined);
    assert.equal(parseTraceState("a=1,,b=2"), undefined);
    assert.equal(parseTraceState(`k=${"x".repeat(600)}`), undefined); // over the 512-byte cap
    assert.equal(parseTraceState(undefined), undefined);
    // …while the traceparent alone still parses:
    const ctx = parseInboundTraceContext(validTraceparent("01"), "junk");
    assert.deepEqual(ctx, { traceId: TRACE_ID, spanId: PARENT_ID, sampled: true });
  });

  it("combines traceparent + tracestate", () => {
    const ctx = parseInboundTraceContext(validTraceparent("01"), TRACESTATE);
    assert.deepEqual(ctx, {
      traceId: TRACE_ID,
      spanId: PARENT_ID,
      sampled: true,
      traceState: TRACESTATE,
    });
  });

  it("returns undefined when the traceparent is invalid or absent", () => {
    assert.equal(parseInboundTraceContext("bogus", TRACESTATE), undefined);
    assert.equal(parseInboundTraceContext(undefined, TRACESTATE), undefined);
  });
});

describe("WR-98 format + span id derivation", () => {
  it("formats a traceparent value", () => {
    assert.equal(
      formatTraceparent(TRACE_ID, PARENT_ID, true),
      `00-${TRACE_ID}-${PARENT_ID}-01`
    );
    assert.equal(
      formatTraceparent(TRACE_ID, PARENT_ID, false),
      `00-${TRACE_ID}-${PARENT_ID}-00`
    );
  });

  it("derives a deterministic 16-hex span id per (trace id, attempt)", () => {
    const a = traceAttemptSpanId(TRACE_ID, 1);
    assert.match(a, /^[0-9a-f]{16}$/);
    assert.equal(traceAttemptSpanId(TRACE_ID, 1), a); // deterministic
    assert.notEqual(traceAttemptSpanId(TRACE_ID, 2), a); // unique per attempt
    assert.notEqual(traceAttemptSpanId("0".repeat(31) + "1", 1), a); // unique per trace
  });
});

describe("WR-98 option resolution", () => {
  it("undefined stays undefined (feature off)", () => {
    assert.equal(resolveTraceContextOptions(undefined), undefined);
  });

  it("defaults sampled to true", () => {
    assert.deepEqual(resolveTraceContextOptions({}), { sampled: true });
    assert.deepEqual(resolveTraceContextOptions({ sampled: false }), { sampled: false });
  });

  it("rejects invalid option shapes", () => {
    assert.throws(() => resolveTraceContextOptions({ sampled: "yes" } as never), RangeError);
    assert.throws(() => resolveTraceContextOptions(null as never), RangeError);
    assert.throws(() => resolveTraceContextOptions([] as never), RangeError);
  });

  it("createRelayServer fails fast on a bad traceContext option", () => {
    const dir = mkdtempSync(join(tmpdir(), "trace-ctx-opt-"));
    assert.throws(
      () =>
        createRelayServer({
secret: testSecret,
          forwardUrl: "http://127.0.0.1:9/hook",
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          traceContext: { sampled: "yes" } as never,
        }),
      RangeError
    );
  });

  it("RetryQueue fails fast on a bad traceContext option", () => {
    assert.throws(
      () => new RetryQueue({ traceContext: { sampled: 1 } as never }),
      RangeError
    );
  });
});

describe("WR-98 outbound resolution", () => {
  const enabled = resolveTraceContextOptions({})!;

  it("feature off: resolves undefined even with a trace id (zero overhead)", () => {
    assert.equal(
      resolveOutboundTraceContext({ traceId: TRACE_ID }, undefined),
      undefined
    );
  });

  it("no trace identity at all: skip (no generation, no injection)", () => {
    assert.equal(resolveOutboundTraceContext({}, enabled), undefined);
    assert.equal(resolveOutboundTraceContext({ traceId: "" }, enabled), undefined);
  });

  it("caller-propagated context passes trace id, sampled flag, and tracestate through", () => {
    const ctx = resolveOutboundTraceContext(
      {
        traceId: TRACE_ID,
        traceContext: { traceId: TRACE_ID, spanId: PARENT_ID, sampled: false, traceState: TRACESTATE },
      },
      enabled
    );
    assert.deepEqual(ctx, { traceId: TRACE_ID, sampled: false, traceState: TRACESTATE });
  });

  it("generated: 32-hex trace ids pass through; others map like the OTLP export", () => {
    const hex = resolveOutboundTraceContext({ traceId: TRACE_ID.toUpperCase() }, enabled);
    assert.deepEqual(hex, { traceId: TRACE_ID, sampled: true });
    const client = "client-123_ABC";
    const mapped = resolveOutboundTraceContext({ traceId: client }, enabled);
    assert.equal(mapped?.traceId, mapOtlpTraceId(client));
    assert.match(mapped!.traceId, /^[0-9a-f]{32}$/);
  });

  it("generated: sampled flag is configurable", () => {
    const off = resolveTraceContextOptions({ sampled: false })!;
    assert.equal(resolveOutboundTraceContext({ traceId: TRACE_ID }, off)?.sampled, false);
  });
});

describe("WR-98 OTLP span correlation attributes", () => {
  function deliveredRecord(overrides: Partial<OtlpRecordInput> = {}): OtlpRecordInput {
    return {
      eventType: "delivered",
      eventId: "evt-1",
      traceId: TRACE_ID,
      endpoint: "http://downstream/hook",
      attempts: 1,
      ...overrides,
    };
  }

  function attrMap(rec: Record<string, unknown>): Record<string, string> {
    const out: Record<string, string> = {};
    for (const a of rec.attributes as Array<{ key: string; value: Record<string, string> }>) {
      out[a.key] = a.value.stringValue ?? a.value.intValue ?? "";
    }
    return out;
  }

  it("renders trace.trace_id / trace.span_id / trace.sampled when a span resolved", () => {
    const payload = JSON.parse(
      buildOtlpPayload(
        [deliveredRecord({ traceSpanId: "abcdef0123456789", traceSampled: true })],
        "webhook-relay-ts",
        1_700_000_000_000
      )
    );
    const rec = payload.resourceLogs[0].scopeLogs[0].logRecords[0];
    assert.equal(rec.traceId, TRACE_ID);
    const attrs = attrMap(rec);
    assert.equal(attrs["trace.trace_id"], TRACE_ID);
    assert.equal(attrs["trace.span_id"], "abcdef0123456789");
    assert.equal(attrs["trace.sampled"], "true");
  });

  it("maps a non-32-hex trace id in trace.trace_id like the record traceId", () => {
    const payload = JSON.parse(
      buildOtlpPayload(
        [deliveredRecord({ traceId: "client-1", traceSpanId: "abcdef0123456789" })],
        "webhook-relay-ts",
        1_700_000_000_000
      )
    );
    const rec = payload.resourceLogs[0].scopeLogs[0].logRecords[0];
    assert.equal(rec.traceId, mapOtlpTraceId("client-1"));
    assert.equal(attrMap(rec)["trace.trace_id"], mapOtlpTraceId("client-1"));
  });

  it("renders no trace attributes when no span resolved (default payload unchanged)", () => {
    const payload = JSON.parse(
      buildOtlpPayload([deliveredRecord()], "webhook-relay-ts", 1_700_000_000_000)
    );
    const attrs = attrMap(payload.resourceLogs[0].scopeLogs[0].logRecords[0]);
    assert.equal(attrs["trace.trace_id"], undefined);
    assert.equal(attrs["trace.span_id"], undefined);
    assert.equal(attrs["trace.sampled"], undefined);
  });
});

// ---- server wiring: real HTTP downstream asserts the injected headers ----

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(BODY);
  });
}

describe("WR-98 server wiring", () => {
  let stub: Server;
  let stubPort: number;
  let seen: Array<Record<string, unknown>>;
  let stubStatus: number;
  /** Per-test status override for the stub; `stubStatus` applies when unset. */
  let stubResponder: (() => number) | undefined;

  before(async () => {
    seen = [];
    stubStatus = 200;
    stubResponder = undefined;
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ ...req.headers });
        res.writeHead(stubResponder?.() ?? stubStatus).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "trace-ctx-"));
    return createRelayServer({
secret: testSecret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    });
  }

  function inboundHeaders(extra: Record<string, string> = {}): Record<string, string> {
    return {
      "content-type": "application/json",
      "x-signature": signSha256(BODY, testSecret),
      ...extra,
    };
  }

  async function postAndWait(port: number, headers: Record<string, string> = {}) {
    seen.length = 0;
    const res = await post(port, headers);
    assert.equal(res.status, 202);
    const deadline = Date.now() + 5000;
    while (seen.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(seen.length, 1, "stub received the delivery");
    return { wire: seen[0] as Record<string, string>, accepted: JSON.parse(res.text) as { traceId: string } };
  }

  async function withRelay(extra: Record<string, unknown>, fn: (port: number) => Promise<void>) {
    const relay = makeRelay(extra);
    const port = await listen(relay);
    try {
      await fn(port);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  }

  function parseTp(value: string) {
    const [, traceId, parentId, flags] = value.split("-");
    return { traceId, parentId, flags };
  }

  it("propagates an inbound traceparent: same trace id, fresh span id, sampled passthrough, tracestate verbatim", async () => {
    await withRelay({ traceContext: {} }, async (port) => {
      const { wire, accepted } = await postAndWait(
        port,
        inboundHeaders({ traceparent: validTraceparent("01"), tracestate: TRACESTATE })
      );
      // The W3C trace id becomes the event's trace id everywhere.
      assert.equal(accepted.traceId, TRACE_ID);
      assert.equal(wire["x-trace-id"], TRACE_ID);
      const tp = parseTp(wire["traceparent"]);
      assert.equal(tp.traceId, TRACE_ID);
      assert.match(tp.parentId, /^[0-9a-f]{16}$/);
      assert.notEqual(tp.parentId, PARENT_ID, "the relay stamps its own child span id");
      assert.equal(tp.flags, "01", "sampled flag passes through");
      assert.equal(wire["tracestate"], TRACESTATE);
    });
  });

  it("passes an unsampled flag through untouched", async () => {
    await withRelay({ traceContext: {} }, async (port) => {
      const { wire } = await postAndWait(port, inboundHeaders({ traceparent: validTraceparent("00") }));
      assert.equal(parseTp(wire["traceparent"]).flags, "00");
    });
  });

  it("generates a traceparent from the relay trace id when no inbound context exists", async () => {
    await withRelay({ traceContext: {} }, async (port) => {
      const { wire, accepted } = await postAndWait(port, inboundHeaders());
      assert.match(accepted.traceId, /^[0-9a-f]{32}$/);
      const tp = parseTp(wire["traceparent"]);
      assert.equal(tp.traceId, accepted.traceId, "generated trace id matches x-trace-id");
      assert.equal(tp.traceId, wire["x-trace-id"]);
      assert.match(tp.parentId, /^[0-9a-f]{16}$/);
      assert.equal(tp.flags, "01", "default sampled");
      assert.equal(wire["tracestate"], undefined);
    });
  });

  it("honors sampled:false for generated traceparents", async () => {
    await withRelay({ traceContext: { sampled: false } }, async (port) => {
      const { wire } = await postAndWait(port, inboundHeaders());
      assert.equal(parseTp(wire["traceparent"]).flags, "00");
    });
  });

  it("ignores an invalid inbound traceparent (still 202, generates instead)", async () => {
    await withRelay({ traceContext: {} }, async (port) => {
      const { wire, accepted } = await postAndWait(
        port,
        inboundHeaders({ traceparent: "00-zzzz-not-hex-00f067aa0ba902b7-01" })
      );
      assert.match(accepted.traceId, /^[0-9a-f]{32}$/);
      assert.notEqual(accepted.traceId, "zzzz-not-hex");
      const tp = parseTp(wire["traceparent"]);
      assert.equal(tp.traceId, accepted.traceId, "falls back to a generated traceparent");
    });
  });

  it("feature off: no traceparent/tracestate is injected (zero overhead)", async () => {
    await withRelay({}, async (port) => {
      const { wire } = await postAndWait(port, inboundHeaders());
      assert.equal(wire["traceparent"], undefined);
      assert.equal(wire["tracestate"], undefined);
      // …but the relay's own trace id header still flows as before.
      assert.match(wire["x-trace-id"] as string, /^[0-9a-f]{32}$/);
    });
  });

  it("stamps a fresh span id per attempt", async () => {
    const dir = mkdtempSync(join(tmpdir(), "trace-ctx-retry-"));
    const relay = createRelayServer({
secret: testSecret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
      traceContext: {},
    });
    const port = await listen(relay);
    // Deterministic per-request outcome: the first two attempts fail,
    // the third succeeds — no timing race on a shared status flag.
    let n = 0;
    stubResponder = () => (++n <= 2 ? 500 : 200);
    try {
      seen.length = 0;
      const res = await post(port, inboundHeaders({ traceparent: validTraceparent("01") }));
      assert.equal(res.status, 202);
      const deadline = Date.now() + 8000;
      while (seen.length < 3 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(seen.length, 3);
      const parents = (seen as Array<Record<string, string>>).map((h) => parseTp(h["traceparent"]).parentId);
      assert.equal(new Set(parents).size, 3, "each attempt is its own span");
      for (const h of seen as Array<Record<string, string>>) {
        assert.equal(parseTp(h["traceparent"]).traceId, TRACE_ID);
      }
    } finally {
      stubResponder = undefined;
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});

describe("WR-98 queue span references + OTLP end-to-end", () => {
  it("delivery events carry the wire span reference when enabled", async () => {
    const events: DeliveryEvent[] = [];
    const queue = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: Buffer.alloc(0), truncated: false }),
      traceContext: {},
    });
    const unsub = queue.subscribeDeliveryEvents((e) => events.push(e));
    queue.start();
    try {
      queue.enqueue({ id: "tc-1", payload: BODY, targetUrl: "http://x/hook", headers: {}, traceId: TRACE_ID });
      const deadline = Date.now() + 5000;
      while (events.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(events.length, 1);
      assert.equal(events[0].type, "delivered");
      assert.equal(events[0].traceSpan?.spanId, traceAttemptSpanId(TRACE_ID, 1));
      assert.equal(events[0].traceSpan?.sampled, true);
    } finally {
      unsub();
      queue.stop();
    }
  });

  it("delivery events carry no span reference when the feature is off", async () => {
    const events: DeliveryEvent[] = [];
    const queue = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: Buffer.alloc(0), truncated: false }),
    });
    const unsub = queue.subscribeDeliveryEvents((e) => events.push(e));
    queue.start();
    try {
      queue.enqueue({ id: "tc-2", payload: BODY, targetUrl: "http://x/hook", headers: {}, traceId: TRACE_ID });
      const deadline = Date.now() + 5000;
      while (events.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(events.length, 1);
      assert.equal(events[0].traceSpan, undefined);
    } finally {
      unsub();
      queue.stop();
    }
  });

  it("correlates a failed downstream span with the exported OTLP dead_letter record", async () => {
    // Local OTLP collector stub.
    const posts: string[] = [];
    const collector = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        posts.push(Buffer.concat(chunks).toString());
        res.writeHead(200).end("ok");
      });
    });
    const collectorPort = await listen(collector);
    // Downstream that always fails: the delivery dead-letters after one attempt.
    let wireTraceparent = "";
    const downstream = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        wireTraceparent = req.headers["traceparent"] as string;
        res.writeHead(500).end("boom");
      });
    });
    const downstreamPort = await listen(downstream);
    const dir = mkdtempSync(join(tmpdir(), "trace-ctx-otlp-"));
    const relay = createRelayServer({
secret: testSecret,
      forwardUrl: `http://127.0.0.1:${downstreamPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      traceContext: {},
      otlp: { endpoint: `http://127.0.0.1:${collectorPort}/v1/logs` },
    });
    const relayPort = await listen(relay);
    try {
      const res = await post(relayPort, {
        "content-type": "application/json",
        "x-signature": signSha256(BODY, testSecret),
        traceparent: validTraceparent("01"),
      });
      assert.equal(res.status, 202);
      const deadline = Date.now() + 10000;
      while (posts.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.equal(posts.length, 1, "the collector received the export");
      assert.ok(wireTraceparent.length > 0, "the failing attempt carried a traceparent");
      const [, wireTraceId, wireParentId, wireFlags] = wireTraceparent.split("-");
      const payload = JSON.parse(posts[0]);
      const records: Array<Record<string, unknown>> = [];
      for (const rl of payload.resourceLogs) for (const sl of rl.scopeLogs) records.push(...sl.logRecords);
      const dead = records.find((r) => (r.body as { stringValue: string }).stringValue === "dead_letter");
      assert.ok(dead, "a dead_letter record was exported");
      // The OTLP relay span shares the trace id with the downstream trace…
      assert.equal(dead.traceId, TRACE_ID);
      assert.equal(dead.traceId, wireTraceId);
      const attrs: Record<string, string> = {};
      for (const a of dead.attributes as Array<{ key: string; value: Record<string, string> }>) {
        attrs[a.key] = a.value.stringValue ?? a.value.intValue ?? "";
      }
      assert.equal(attrs["trace.trace_id"], wireTraceId);
      // …and names the exact span the failing attempt stamped on the wire.
      assert.equal(attrs["trace.span_id"], wireParentId);
      assert.equal(attrs["trace.span_id"], traceAttemptSpanId(TRACE_ID, 1));
      assert.equal(attrs["trace.sampled"], "true");
      assert.equal(wireFlags, "01");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      downstream.close();
      await new Promise((r) => downstream.once("close", r));
      collector.close();
      await new Promise((r) => collector.once("close", r));
    }
  });
});
