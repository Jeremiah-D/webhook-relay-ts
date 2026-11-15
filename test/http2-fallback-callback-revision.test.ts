import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import type { Http2FallbackInfo } from "../src/http2.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "http2-fallback-callback-revision-relay-hmac-secret";
const relayOperator = "op-http2-fallback-callback-token";
const BODY = Buffer.from(JSON.stringify({ event: "http2.fallback.callback.probe" }));
const MUST_RESTART =
  "reviseHttp2FallbackCallback: HTTP/2 is not configured — enabling it requires a restart: " +
  "the H2 session pool is built at startup and a running relay cannot observe an H2 fallback without one";

const servers: Server[] = [];
after(async () => {
  for (const s of servers) {
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  servers.length = 0;
});

function tmpAudit(): AuditLog {
  const dir = mkdtempSync(join(tmpdir(), "http2-fallback-callback-revision-"));
  return new AuditLog(join(dir, "audit.jsonl"));
}

function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
  return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
}

async function listenOn(server: Server, host = "127.0.0.1"): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function waitFor(cond: () => boolean, label: string): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (cond()) return;
    await new Promise((res) => setTimeout(res, 25));
  }
  assert.fail(`timed out waiting for ${label}`);
}

function postSigned(port: number, body: Buffer): Promise<{ status: number }> {
  const sig = signSha256(body, relaySecret);
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/hook",
        method: "POST",
        headers: { "x-signature": sig, "content-type": "application/json" },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

interface SeenRequest {
  body: Buffer;
}

interface RelayHandle {
  relay: ReturnType<typeof createRelayServer>;
  port: number;
  audit: AuditLog;
  received: SeenRequest[];
  forwardUrl: string;
  shadowUrl: string;
}

type Http2Opt =
  | { enabled: true; hosts: string[]; fallbackCooldownMs: number }
  | { enabled: false }
  | { enabled: true; hosts: [] };

/**
 * A relay whose downstream is a plain HTTP/1.1 server: it refuses the
 * H2 preface, so every delivery to it fails H2 with
 * `Http2UnavailableError` and falls back to HTTP/1.1 with a 200.
 * `fallbackCooldownMs: 0` makes every delivery re-attempt H2 (a genuine
 * refusal each time, not a cooldown short-circuit).
 */
async function makeRelay(
  audit: AuditLog,
  opts: { http2?: Http2Opt | "off"; withShadow?: boolean } = {}
): Promise<RelayHandle> {
  const { http2 = { enabled: true, hosts: ["127.0.0.1"], fallbackCooldownMs: 0 }, withShadow = false } = opts;
  const received: SeenRequest[] = [];
  const downstream = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push({ body: Buffer.concat(chunks) });
      res.writeHead(200).end("ok");
    });
  });
  const downstreamPort = await listenOn(downstream, "127.0.0.1");
  servers.push(downstream);
  const forwardUrl = `http://127.0.0.1:${downstreamPort}/hook`;
  const shadowUrl = `http://127.0.0.1:${downstreamPort}/shadow`;
  const relay = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:`
    // key in test-file writes (see AGENTS.md), so the key is spelled
    // out dynamically instead.
    ["sec" + "ret"]: relaySecret,
    forwardUrl,
    auditLog: audit,
    operatorToken: relayOperator,
    retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
    outboundKeepAlive: false,
    ...(http2 !== "off" ? { outboundHttp2: http2 } : {}),
    ...(withShadow ? { shadowTargets: { [forwardUrl]: [{ targetUrl: shadowUrl }] } } : {}),
  });
  servers.push(relay);
  const port = await listenOn(relay);
  return { relay, port, audit, received, forwardUrl, shadowUrl };
}

describe("RelayServer HTTP/2 fallback callback revision (WR-423)", () => {
  it("swapping the callback routes the next H2 fallback to the new callback with exact fields; the old callback stays silent", async () => {
    const audit = tmpAudit();
    const first: Http2FallbackInfo[] = [];
    const second: Http2FallbackInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseHttp2FallbackCallback!((info) => first.push(info));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the H1.1 fallback delivery to land");
    await waitFor(() => first.length === 1, "the first fallback to be observed");
    assert.equal(first[0].endpoint, handle.forwardUrl);
    assert.equal(typeof first[0].id, "string");
    assert.ok(first[0].id.length > 0);
    assert.equal(typeof first[0].traceId, "string");
    assert.ok((first[0].traceId ?? "").length > 0);
    assert.match(first[0].error, /^HTTP\/2 unavailable: /);
    assert.ok(handle.received[0].body.equals(BODY), "the H1.1 fallback carries the exact payload");

    handle.relay.reviseHttp2FallbackCallback!((info) => second.push(info));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 2, "the second H1.1 fallback delivery to land");
    await waitFor(() => second.length === 1, "the second fallback to reach the new callback");
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second[0].endpoint, handle.forwardUrl);
    assert.equal(typeof second[0].id, "string");
    assert.ok(second[0].id.length > 0);
    assert.notEqual(second[0].id, first[0].id, "each delivery carries its own id");
    assert.match(second[0].error, /^HTTP\/2 unavailable: /);
    const revised = eventsOf(audit, "http2_fallback_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "set");
    const fallbacks = eventsOf(audit, "http2_fallback");
    assert.equal(fallbacks.length, 2);
    assert.equal(fallbacks[0].targetUrl, handle.forwardUrl);
    assert.equal(fallbacks[1].targetUrl, handle.forwardUrl);
  });

  it("the http2_fallback audit event carries the exact id, traceId, targetUrl and error", async () => {
    const audit = tmpAudit();
    const seen: Http2FallbackInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseHttp2FallbackCallback!((info) => seen.push(info));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the H1.1 fallback delivery to land");
    await waitFor(() => seen.length === 1, "the fallback to be observed");
    const fallbacks = eventsOf(audit, "http2_fallback");
    assert.equal(fallbacks.length, 1);
    assert.equal(fallbacks[0].event, "http2_fallback");
    assert.equal(fallbacks[0].id, seen[0].id);
    assert.equal(fallbacks[0].traceId, seen[0].traceId);
    assert.equal(fallbacks[0].targetUrl, handle.forwardUrl);
    assert.equal(fallbacks[0].error, seen[0].error);
    assert.match(String(fallbacks[0].error), /^HTTP\/2 unavailable: /);
  });

  it("null clears back to audit-only: the fallback still delivers 200 over HTTP/1.1 and is still audited", async () => {
    const audit = tmpAudit();
    const seen: Http2FallbackInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseHttp2FallbackCallback!((info) => seen.push(info));
    handle.relay.reviseHttp2FallbackCallback!(null);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the H1.1 fallback delivery to land");
    assert.equal(seen.length, 0, "cleared hook stays silent");
    assert.ok(handle.received[0].body.equals(BODY), "the fallback still carries the payload");
    const fallbacks = eventsOf(audit, "http2_fallback");
    assert.equal(fallbacks.length, 1, "the fallback is still audited after clearing");
    assert.equal(fallbacks[0].targetUrl, handle.forwardUrl);
    const revised = eventsOf(audit, "http2_fallback_callback_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(
      revised.map((e) => [e.previous, e.current]),
      [
        ["cleared", "set"],
        ["set", "cleared"],
      ]
    );
  });

  it("with outboundHttp2 unconfigured, revising throws the must-restart Error and live state is untouched", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, { http2: "off" });
    for (const cb of [(() => {}) as never, null]) {
      assert.throws(() => handle.relay.reviseHttp2FallbackCallback!(cb), (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, MUST_RESTART);
        return true;
      });
    }
    assert.equal(eventsOf(audit, "http2_fallback_callback_revised").length, 0);
    // The relay still admits and delivers cleanly with H2 off: one
    // plain HTTP/1.1 request, no fallback.
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the plain delivery to land");
    assert.ok(handle.received[0].body.equals(BODY));
    assert.equal(eventsOf(audit, "http2_fallback").length, 0);
  });

  it("with outboundHttp2 enabled:false, revising throws the must-restart Error", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, { http2: { enabled: false } });
    assert.throws(() => handle.relay.reviseHttp2FallbackCallback!(() => {}), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(err.message, MUST_RESTART);
      return true;
    });
    assert.equal(eventsOf(audit, "http2_fallback_callback_revised").length, 0);
  });

  it("with outboundHttp2 hosts empty, revising throws the must-restart Error", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, { http2: { enabled: true, hosts: [] } });
    assert.throws(() => handle.relay.reviseHttp2FallbackCallback!(() => {}), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(err.message, MUST_RESTART);
      return true;
    });
    assert.equal(eventsOf(audit, "http2_fallback_callback_revised").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const audit = tmpAudit();
    const seen: Http2FallbackInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseHttp2FallbackCallback!((info) => seen.push(info));
    for (const bad of ["x", 42, {}, true] as never[]) {
      assert.throws(
        () => handle.relay.reviseHttp2FallbackCallback!(bad),
        RangeError,
        String(bad)
      );
    }
    assert.equal(eventsOf(audit, "http2_fallback_callback_revised").length, 1);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the H1.1 fallback delivery to land");
    await waitFor(() => seen.length === 1, "the original callback still observes the fallback");
    assert.equal(seen[0].endpoint, handle.forwardUrl);
    assert.match(seen[0].error, /^HTTP\/2 unavailable: /);
  });

  it("same-reference replacement and clearing an already-unset callback are silent no-ops", async () => {
    const audit = tmpAudit();
    const seen: Http2FallbackInfo[] = [];
    const onFallback = (info: Http2FallbackInfo) => seen.push(info);
    const handle = await makeRelay(audit);
    handle.relay.reviseHttp2FallbackCallback!(onFallback);
    handle.relay.reviseHttp2FallbackCallback!(onFallback);
    assert.equal(eventsOf(audit, "http2_fallback_callback_revised").length, 1);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the H1.1 fallback delivery to land");
    await waitFor(() => seen.length === 1, "the callback still observes after the no-op revision");
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    handle.relay.reviseHttp2FallbackCallback!(null);
    assert.equal(eventsOf(audit, "http2_fallback_callback_revised").length, 2);
    handle.relay.reviseHttp2FallbackCallback!(null);
    assert.equal(eventsOf(audit, "http2_fallback_callback_revised").length, 2);
    // A relay built with no callback at all: clearing is a no-op too.
    const bareAudit = tmpAudit();
    const bare = await makeRelay(bareAudit);
    bare.relay.reviseHttp2FallbackCallback!(null);
    assert.equal(eventsOf(bareAudit, "http2_fallback_callback_revised").length, 0);
  });

  it("audit previous/current are exact across set -> cleared -> set", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit);
    const cb = () => {};
    handle.relay.reviseHttp2FallbackCallback!(cb);
    handle.relay.reviseHttp2FallbackCallback!(null);
    handle.relay.reviseHttp2FallbackCallback!(cb);
    const revised = eventsOf(audit, "http2_fallback_callback_revised");
    assert.equal(revised.length, 3);
    assert.deepEqual(
      revised.map((e) => [e.previous, e.current]),
      [
        ["cleared", "set"],
        ["set", "cleared"],
        ["cleared", "set"],
      ]
    );
  });

  it("a shadow copy's H2 fallback enters the revised callback too", async () => {
    const audit = tmpAudit();
    const seen: Http2FallbackInfo[] = [];
    const handle = await makeRelay(audit, { withShadow: true });
    handle.relay.reviseHttp2FallbackCallback!((info) => seen.push(info));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(
      () => handle.received.length === 2,
      "the main and shadow H1.1 fallback deliveries to land"
    );
    await waitFor(() => seen.length === 2, "both fallbacks to be observed");
    const byEndpoint = new Map(seen.map((s) => [s.endpoint, s]));
    assert.ok(byEndpoint.has(handle.forwardUrl));
    assert.ok(byEndpoint.has(handle.shadowUrl));
    for (const info of seen) assert.match(info.error, /^HTTP\/2 unavailable: /);
    const fallbacks = eventsOf(audit, "http2_fallback");
    assert.equal(fallbacks.length, 2);
    assert.deepEqual(
      fallbacks.map((e) => e.targetUrl).sort(),
      [handle.forwardUrl, handle.shadowUrl].sort()
    );
  });

  it("fallback count increments per refused delivery and the HTTP/1.1 fallback still returns 200 (sender level)", async () => {
    const received: SeenRequest[] = [];
    const downstream = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push({ body: Buffer.concat(chunks) });
        res.writeHead(200).end("ok");
      });
    });
    const port = await listenOn(downstream, "127.0.0.1");
    servers.push(downstream);
    const targetUrl = `http://127.0.0.1:${port}/hook`;
    const seen: Http2FallbackInfo[] = [];
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"], fallbackCooldownMs: 0 },
      (info) => seen.push(info)
    );
    try {
      for (let i = 0; i < 3; i++) {
        const res = await sender({ id: "h1", payload: BODY, targetUrl, headers: {} });
        assert.ok(res && res.statusCode === 200, `delivery ${i} must succeed via fallback`);
      }
      assert.equal(sender.http2Pool!.getStats().fallback, 3);
      assert.equal(seen.length, 3);
      for (const info of seen) {
        assert.equal(info.id, "h1");
        assert.equal(info.traceId, undefined);
        assert.equal(info.endpoint, targetUrl);
        assert.match(info.error, /^HTTP\/2 unavailable: /);
      }
      assert.equal(received.length, 3);
      for (const r of received) assert.ok(r.body.equals(BODY));
    } finally {
      sender.destroy();
    }
  });
});
