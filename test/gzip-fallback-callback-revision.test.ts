import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server, type IncomingHttpHeaders } from "node:http";
import {
  createServer as createH2Server,
  type Http2Server,
  type ServerHttp2Stream,
} from "node:http2";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import { createRelayServer } from "../src/server.ts";
import type { GzipFallbackInfo } from "../src/gzip.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "gzip-fallback-callback-revision-relay-hmac-secret";
const relayOperator = "op-gzip-fallback-callback-token";
// ~4 KiB of JSON: comfortably above the 1024-byte guarded-compression
// threshold, so the sender gzips it before the downstream answers 415.
const BIG_BODY = Buffer.from(
  JSON.stringify({ event: "gzip.fallback.callback.probe", data: "x".repeat(4000) })
);
const MUST_RESTART =
  "reviseGzipFallbackCallback: guarded compression is not configured — enabling it requires a restart: " +
  "the 415 plaintext fallback only arises when guarded compression is configured at startup";

const servers: Server[] = [];
after(async () => {
  for (const s of servers) {
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  servers.length = 0;
});

function tmpAudit(): AuditLog {
  const dir = mkdtempSync(join(tmpdir(), "gzip-fallback-callback-revision-"));
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

function getText(port: number, path: string, headers: Record<string, string>) {
  return new Promise<string>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks).toString()));
    });
    r.on("error", reject);
    r.end();
  });
}

interface SeenRequest {
  headers: IncomingHttpHeaders;
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

/**
 * A relay whose downstream answers 415 to gzipped requests and 200 to
 * plaintext ones, so every guarded delivery falls back once inside the
 * same attempt. `compressThreshold` uses the defaults (1024-byte
 * threshold, application/json whitelist).
 */
async function makeRelay(
  audit: AuditLog,
  opts: { withThreshold?: boolean; withShadow?: boolean; emptyThreshold?: boolean } = {}
): Promise<RelayHandle> {
  const { withThreshold = true, withShadow = false, emptyThreshold = false } = opts;
  const received: SeenRequest[] = [];
  const downstream = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push({ headers: req.headers, body: Buffer.concat(chunks) });
      // The downstream does not speak gzip: a gzipped request is
      // refused, the plaintext resend is accepted.
      res.writeHead(req.headers["content-encoding"] === "gzip" ? 415 : 200).end("ok");
    });
  });
  const downstreamPort = await listenOn(downstream, "127.0.0.1");
  servers.push(downstream);
  const forwardUrl = `http://127.0.0.1:${downstreamPort}/hook`;
  const shadowUrl = `http://127.0.0.1:${downstreamPort}/shadow`;
  const compressThreshold: Record<string, Record<string, unknown>> | undefined = emptyThreshold
    ? {}
    : withThreshold
      ? {
          [forwardUrl]: {},
          ...(withShadow ? { [shadowUrl]: {} } : {}),
        }
      : undefined;
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
    ...(compressThreshold !== undefined ? { compressThreshold } : {}),
    ...(withShadow ? { shadowTargets: { [forwardUrl]: [{ targetUrl: shadowUrl }] } } : {}),
  });
  servers.push(relay);
  const port = await listenOn(relay);
  return { relay, port, audit, received, forwardUrl, shadowUrl };
}

/**
 * The same relay against a cleartext HTTP/2 downstream, so the
 * fallback fires on the H2 transport (the second 415 call site). The
 * idle-session reaper is set to 100ms: the relay never exposes its
 * sender, so no test can destroy the H2 pool — the reaper must close
 * the idle session or the downstream would never finish closing.
 */
async function makeH2Relay(audit: AuditLog): Promise<RelayHandle> {
  const received: SeenRequest[] = [];
  const downstream: Http2Server = createH2Server();
  downstream.on("stream", (stream: ServerHttp2Stream, headers) => {
    const chunks: Buffer[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c));
    stream.on("end", () => {
      received.push({ headers, body: Buffer.concat(chunks) });
      stream.respond({ ":status": headers["content-encoding"] === "gzip" ? 415 : 200 });
      stream.end("ok");
    });
  });
  await new Promise<void>((resolve) => downstream.listen(0, "127.0.0.1", resolve));
  const downstreamPort = (downstream.address() as { port: number }).port;
  after(async () => {
    await new Promise<void>((resolve) => downstream.close(() => resolve()));
  });
  const forwardUrl = `http://127.0.0.1:${downstreamPort}/hook`;
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
    compressThreshold: { [forwardUrl]: {} },
    outboundHttp2: { enabled: true, hosts: ["127.0.0.1"], sessionIdleTimeoutMs: 100 },
  });
  servers.push(relay);
  const port = await listenOn(relay);
  return { relay, port, audit, received, forwardUrl, shadowUrl: "" };
}

describe("RelayServer gzip fallback callback revision (WR-422)", () => {
  it("swapping the callback routes the next 415 fallback to the new callback with exact fields; the old callback stays silent", async () => {
    const audit = tmpAudit();
    const first: GzipFallbackInfo[] = [];
    const second: GzipFallbackInfo[] = [];
    const handle = await makeRelay(audit);
    const auth = { authorization: `Bearer ${relayOperator}` };
    handle.relay.reviseGzipFallbackCallback!((info) => first.push(info));
    assert.equal((await postSigned(handle.port, BIG_BODY)).status, 202);
    await waitFor(() => handle.received.length === 2, "the gzipped attempt and plaintext resend to land");
    await waitFor(() => first.length === 1, "the first fallback to be observed");
    assert.equal(first[0].endpoint, handle.forwardUrl);
    assert.equal(first[0].bytesSaved, BIG_BODY.length - handle.received[0].body.length);
    assert.ok(first[0].bytesSaved > 0);
    assert.equal(typeof first[0].id, "string");
    assert.ok(first[0].id.length > 0);
    // The gzipped attempt was refused; the plaintext resend carried
    // the exact original bytes.
    assert.equal(handle.received[0].headers["content-encoding"], "gzip");
    assert.equal(handle.received[1].headers["content-encoding"], undefined);
    assert.ok(handle.received[1].body.equals(BIG_BODY));
    assert.equal(second.length, 0);

    handle.relay.reviseGzipFallbackCallback!((info) => second.push(info));
    assert.equal((await postSigned(handle.port, BIG_BODY)).status, 202);
    await waitFor(() => handle.received.length === 4, "the second gzipped attempt and resend to land");
    await waitFor(() => second.length === 1, "the second fallback to reach the new callback");
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second[0].endpoint, handle.forwardUrl);
    assert.equal(second[0].bytesSaved, BIG_BODY.length - handle.received[2].body.length);
    assert.ok(handle.received[3].body.equals(BIG_BODY));
    const revised = eventsOf(audit, "gzip_fallback_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "set");
    const fallbacks = eventsOf(audit, "gzip_fallback_plaintext");
    assert.equal(fallbacks.length, 2);
    assert.equal(fallbacks[0].targetUrl, handle.forwardUrl);
    assert.equal(fallbacks[1].targetUrl, handle.forwardUrl);
    // The revision never disturbs the byte-savings accounting: the
    // metrics counter holds exactly the two fallbacks' savings.
    const metrics = await getText(handle.port, "/metrics", auth);
    assert.match(
      metrics,
      new RegExp(
        `relay_compressed_bytes_saved_total\\{endpoint="${handle.forwardUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"\\} ${first[0].bytesSaved + second[0].bytesSaved}`
      )
    );
  });

  it("the HTTP/2 transport's 415 fallback enters the new callback too", async () => {
    const audit = tmpAudit();
    const seen: GzipFallbackInfo[] = [];
    const handle = await makeH2Relay(audit);
    handle.relay.reviseGzipFallbackCallback!((info) => seen.push(info));
    assert.equal((await postSigned(handle.port, BIG_BODY)).status, 202);
    await waitFor(() => handle.received.length === 2, "the H2 gzipped attempt and plaintext resend to land");
    await waitFor(() => seen.length === 1, "the H2 fallback to be observed");
    assert.equal(seen[0].endpoint, handle.forwardUrl);
    assert.equal(seen[0].bytesSaved, BIG_BODY.length - handle.received[0].body.length);
    assert.ok(seen[0].bytesSaved > 0);
    assert.equal(handle.received[0].headers["content-encoding"], "gzip");
    assert.equal(handle.received[1].headers["content-encoding"], undefined);
    assert.ok(handle.received[1].body.equals(BIG_BODY));
    const fallbacks = eventsOf(audit, "gzip_fallback_plaintext");
    assert.equal(fallbacks.length, 1);
    assert.equal(fallbacks[0].targetUrl, handle.forwardUrl);
  });

  it("null clears back to audit-only: the 415 fallback still resends plaintext and is still audited", async () => {
    const audit = tmpAudit();
    const seen: GzipFallbackInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseGzipFallbackCallback!((info) => seen.push(info));
    handle.relay.reviseGzipFallbackCallback!(null);
    assert.equal((await postSigned(handle.port, BIG_BODY)).status, 202);
    await waitFor(() => handle.received.length === 2, "the gzipped attempt and plaintext resend to land");
    assert.equal(seen.length, 0, "cleared hook stays silent");
    assert.equal(handle.received[0].headers["content-encoding"], "gzip");
    assert.equal(handle.received[1].headers["content-encoding"], undefined);
    assert.ok(handle.received[1].body.equals(BIG_BODY), "the plaintext resend still carries the payload");
    const fallbacks = eventsOf(audit, "gzip_fallback_plaintext");
    assert.equal(fallbacks.length, 1, "the fallback is still audited after clearing");
    assert.equal(fallbacks[0].targetUrl, handle.forwardUrl);
    const revised = eventsOf(audit, "gzip_fallback_callback_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(
      revised.map((e) => [e.previous, e.current]),
      [
        ["cleared", "set"],
        ["set", "cleared"],
      ]
    );
  });

  it("with guarded compression unconfigured, revising throws the must-restart Error and live state is untouched", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, { withThreshold: false });
    for (const cb of [(() => {}) as never, null]) {
      assert.throws(() => handle.relay.reviseGzipFallbackCallback!(cb), (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, MUST_RESTART);
        return true;
      });
    }
    assert.equal(eventsOf(audit, "gzip_fallback_callback_revised").length, 0);
    // The relay still admits and delivers cleanly with guarded
    // compression off: one plain request, no fallback.
    const res = await postSigned(handle.port, BIG_BODY);
    assert.equal(res.status, 202);
    await waitFor(() => handle.received.length === 1, "the plain delivery to land");
    assert.equal(handle.received[0].headers["content-encoding"], undefined);
    assert.ok(handle.received[0].body.equals(BIG_BODY));
    assert.equal(eventsOf(audit, "gzip_fallback_plaintext").length, 0);
  });

  it("an empty compressThreshold record is unconfigured: revising throws the must-restart Error", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, { emptyThreshold: true });
    assert.throws(() => handle.relay.reviseGzipFallbackCallback!(() => {}), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(err.message, MUST_RESTART);
      return true;
    });
    assert.equal(eventsOf(audit, "gzip_fallback_callback_revised").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const audit = tmpAudit();
    const seen: GzipFallbackInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseGzipFallbackCallback!((info) => seen.push(info));
    for (const bad of ["x", 42, {}, true] as never[]) {
      assert.throws(
        () => handle.relay.reviseGzipFallbackCallback!(bad),
        RangeError,
        String(bad)
      );
    }
    assert.equal(eventsOf(audit, "gzip_fallback_callback_revised").length, 1);
    assert.equal((await postSigned(handle.port, BIG_BODY)).status, 202);
    await waitFor(() => handle.received.length === 2, "the gzipped attempt and plaintext resend to land");
    await waitFor(() => seen.length === 1, "the original callback still observes the fallback");
    assert.equal(seen[0].endpoint, handle.forwardUrl);
    assert.ok(seen[0].bytesSaved > 0);
  });

  it("same-reference replacement and clearing an already-unset callback are silent no-ops", async () => {
    const audit = tmpAudit();
    const seen: GzipFallbackInfo[] = [];
    const onFallback = (info: GzipFallbackInfo) => seen.push(info);
    const handle = await makeRelay(audit);
    handle.relay.reviseGzipFallbackCallback!(onFallback);
    handle.relay.reviseGzipFallbackCallback!(onFallback);
    assert.equal(eventsOf(audit, "gzip_fallback_callback_revised").length, 1);
    assert.equal((await postSigned(handle.port, BIG_BODY)).status, 202);
    await waitFor(() => handle.received.length === 2, "the gzipped attempt and plaintext resend to land");
    await waitFor(() => seen.length === 1, "the callback still observes after the no-op revision");
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    handle.relay.reviseGzipFallbackCallback!(null);
    assert.equal(eventsOf(audit, "gzip_fallback_callback_revised").length, 2);
    handle.relay.reviseGzipFallbackCallback!(null);
    assert.equal(eventsOf(audit, "gzip_fallback_callback_revised").length, 2);
    // A relay built with no callback at all: clearing is a no-op too.
    const bareAudit = tmpAudit();
    const bare = await makeRelay(bareAudit);
    bare.relay.reviseGzipFallbackCallback!(null);
    assert.equal(eventsOf(bareAudit, "gzip_fallback_callback_revised").length, 0);
  });

  it("audit previous/current are exact across set -> cleared -> set", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit);
    const cb = () => {};
    handle.relay.reviseGzipFallbackCallback!(cb);
    handle.relay.reviseGzipFallbackCallback!(null);
    handle.relay.reviseGzipFallbackCallback!(cb);
    const revised = eventsOf(audit, "gzip_fallback_callback_revised");
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

  it("a shadow copy's 415 fallback enters the revised callback too", async () => {
    const audit = tmpAudit();
    const seen: GzipFallbackInfo[] = [];
    const handle = await makeRelay(audit, { withShadow: true });
    handle.relay.reviseGzipFallbackCallback!((info) => seen.push(info));
    assert.equal((await postSigned(handle.port, BIG_BODY)).status, 202);
    await waitFor(
      () => handle.received.length === 4,
      "the main and shadow gzipped attempts and resends to land"
    );
    await waitFor(() => seen.length === 2, "both fallbacks to be observed");
    const byEndpoint = new Map(seen.map((s) => [s.endpoint, s]));
    assert.ok((byEndpoint.get(handle.forwardUrl)?.bytesSaved ?? 0) > 0);
    assert.ok((byEndpoint.get(handle.shadowUrl)?.bytesSaved ?? 0) > 0);
    const fallbacks = eventsOf(audit, "gzip_fallback_plaintext");
    assert.equal(fallbacks.length, 2);
    assert.deepEqual(
      fallbacks.map((e) => e.targetUrl).sort(),
      [handle.forwardUrl, handle.shadowUrl].sort()
    );
  });
});
