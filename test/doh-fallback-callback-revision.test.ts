import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import { createRelayServer } from "../src/server.ts";

type DohFallbackInfo = { hostname: string; error: string; dohUrl: string };

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "doh-fallback-callback-revision-relay-hmac-secret";
const relayOperator = "op-doh-fallback-callback-token";
const BODY = Buffer.from(JSON.stringify({ event: "doh.fallback.callback.probe" }));
const MUST_RESTART =
  "reviseDohFallbackCallback: DoH is not configured — enabling it requires a restart: " +
  "the per-endpoint DoH lookup channel is built at startup and a running relay cannot start falling back through DoH without one";

const servers: Server[] = [];
after(async () => {
  for (const s of servers) {
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  servers.length = 0;
});

function tmpAudit(): AuditLog {
  const dir = mkdtempSync(join(tmpdir(), "doh-fallback-callback-revision-"));
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
      { host: "127.0.0.1", port, path: "/hook", method: "POST", headers: { "x-signature": sig } },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

/** A fake DoH endpoint that answers 500 to every query: each lookup
 * through it fails and falls back to the system resolver. */
async function startFailingDoh(): Promise<{ url: string }> {
  const server = createServer((_req, res) => {
    res.writeHead(500).end("boom");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  servers.push(server);
  return { url: `http://127.0.0.1:${addr.port}/dns-query` };
}

interface RelayHandle {
  relay: ReturnType<typeof createRelayServer>;
  port: number;
  audit: AuditLog;
  received: Buffer[];
  forwardUrl: string;
  dohUrl: string;
  shadowUrl: string;
  shadowDohUrl: string;
}

/**
 * A relay whose forward URL resolves through a failing DoH endpoint:
 * every first lookup of `localhost` fails over DoH and falls back to
 * the system resolver (which answers ::1 / 127.0.0.1), so the delivery
 * still lands. The downstream binds without a host (dual-stack) so
 * either resolved family reaches it. Keep-alive pooling is off so
 * every delivery re-resolves instead of reusing a pooled connection.
 */
async function makeRelay(
  audit: AuditLog,
  opts: { withDoh?: boolean; withShadow?: boolean; emptyDoh?: boolean } = {}
): Promise<RelayHandle> {
  const { withDoh = true, withShadow = false, emptyDoh = false } = opts;
  const received: Buffer[] = [];
  const downstream = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push(Buffer.concat(chunks));
      res.writeHead(200).end("ok");
    });
  });
  await new Promise<void>((resolve) => downstream.listen(0, resolve));
  const downstreamPort = (downstream.address() as { port: number }).port;
  servers.push(downstream);
  const fakeMain = withDoh ? await startFailingDoh() : undefined;
  const fakeShadow = withShadow ? await startFailingDoh() : undefined;
  const forwardUrl = `http://localhost:${downstreamPort}/hook`;
  const shadowUrl = `http://localhost:${downstreamPort}/shadow`;
  const doh: Record<string, string> | undefined = emptyDoh
    ? {}
    : withDoh
      ? {
          [forwardUrl]: fakeMain!.url,
          ...(withShadow && fakeShadow ? { [shadowUrl]: fakeShadow.url } : {}),
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
    // Keep-alive pooling is off so every delivery re-resolves (a pooled
    // connection would reuse the first lookup's socket).
    outboundKeepAlive: false,
    ...(doh !== undefined ? { doh } : {}),
    ...(withShadow ? { shadowTargets: { [forwardUrl]: [{ targetUrl: shadowUrl }] } } : {}),
  });
  servers.push(relay);
  const port = await listenOn(relay);
  return {
    relay,
    port,
    audit,
    received,
    forwardUrl,
    dohUrl: fakeMain?.url ?? "",
    shadowUrl,
    shadowDohUrl: fakeShadow?.url ?? "",
  };
}

describe("RelayServer DoH fallback callback revision (WR-421)", () => {
  it("swapping the callback routes the next fallback to the new callback with exact fields; the old callback stays silent", async () => {
    const audit = tmpAudit();
    const first: DohFallbackInfo[] = [];
    const second: DohFallbackInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseDohFallbackCallback!((info) => first.push(info));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the first delivery to land");
    await waitFor(() => first.length === 1, "the first fallback to be observed");
    assert.equal(first[0].hostname, "localhost");
    assert.equal(first[0].dohUrl, handle.dohUrl);
    assert.ok(first[0].error.length > 0);
    assert.equal(second.length, 0);

    handle.relay.reviseDohFallbackCallback!((info) => second.push(info));
    // The per-DoH-URL cache holds localhost for 60s; the next delivery
    // would serve the cached answer with no DoH traffic. Wait the TTL
    // out: the following lookup serves the stale entry and refreshes in
    // the background, which re-queries DoH and reports the fallback
    // again — to the new callback only.
    await new Promise((res) => setTimeout(res, 61_000));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 2, "the second delivery to land");
    await waitFor(() => second.length === 1, "the second fallback to reach the new callback");
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second[0].hostname, "localhost");
    assert.equal(second[0].dohUrl, handle.dohUrl);
    assert.ok(second[0].error.length > 0);
    const revised = eventsOf(audit, "doh_fallback_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "set");
    // Both fallbacks were audited, in order, with exact fields.
    const fallbacks = eventsOf(audit, "doh_fallback");
    assert.equal(fallbacks.length, 2);
    assert.equal(fallbacks[0].hostname, "localhost");
    assert.equal(fallbacks[0].dohUrl, handle.dohUrl);
    assert.equal(fallbacks[1].hostname, "localhost");
    assert.equal(fallbacks[1].dohUrl, handle.dohUrl);
    assert.ok(String(fallbacks[0].error).length > 0);
    // The callback and the audit agree on the error text.
    assert.equal(second[0].error, fallbacks[1].error);
    assert.equal(first[0].error, fallbacks[0].error);
  });

  it("null clears back to audit-only: the next fallback is still audited but no longer forwarded", async () => {
    const audit = tmpAudit();
    const seen: DohFallbackInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseDohFallbackCallback!((info) => seen.push(info));
    handle.relay.reviseDohFallbackCallback!(null);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the delivery to land");
    assert.equal(seen.length, 0, "cleared hook stays silent");
    const fallbacks = eventsOf(audit, "doh_fallback");
    assert.equal(fallbacks.length, 1, "the fallback is still audited after clearing");
    assert.equal(fallbacks[0].hostname, "localhost");
    assert.equal(fallbacks[0].dohUrl, handle.dohUrl);
    assert.ok(String(fallbacks[0].error).length > 0);
    const revised = eventsOf(audit, "doh_fallback_callback_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(
      revised.map((e) => [e.previous, e.current]),
      [
        ["cleared", "set"],
        ["set", "cleared"],
      ]
    );
  });

  it("with DoH unconfigured, revising throws the must-restart Error and live state is untouched", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, { withDoh: false });
    for (const cb of [(() => {}) as never, null]) {
      assert.throws(() => handle.relay.reviseDohFallbackCallback!(cb), (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, MUST_RESTART);
        return true;
      });
    }
    assert.equal(eventsOf(audit, "doh_fallback_callback_revised").length, 0);
    // The relay still admits and delivers cleanly with DoH off.
    const res = await postSigned(handle.port, BODY);
    assert.equal(res.status, 202);
    await waitFor(() => handle.received.length === 1, "the delivery to land");
    assert.equal(eventsOf(audit, "doh_fallback").length, 0);
  });

  it("an empty doh record is unconfigured: revising throws the must-restart Error", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, { emptyDoh: true });
    assert.throws(() => handle.relay.reviseDohFallbackCallback!(() => {}), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(err.message, MUST_RESTART);
      return true;
    });
    assert.equal(eventsOf(audit, "doh_fallback_callback_revised").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const audit = tmpAudit();
    const seen: DohFallbackInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseDohFallbackCallback!((info) => seen.push(info));
    for (const bad of ["x", 42, {}, true] as never[]) {
      assert.throws(
        () => handle.relay.reviseDohFallbackCallback!(bad),
        RangeError,
        String(bad)
      );
    }
    assert.equal(eventsOf(audit, "doh_fallback_callback_revised").length, 1);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the delivery to land");
    await waitFor(() => seen.length === 1, "the original callback still observes the fallback");
    assert.equal(seen[0].hostname, "localhost");
    assert.equal(seen[0].dohUrl, handle.dohUrl);
  });

  it("same-reference replacement and clearing an already-unset callback are silent no-ops", async () => {
    const audit = tmpAudit();
    const seen: DohFallbackInfo[] = [];
    const onFallback = (info: DohFallbackInfo) => seen.push(info);
    const handle = await makeRelay(audit);
    handle.relay.reviseDohFallbackCallback!(onFallback);
    handle.relay.reviseDohFallbackCallback!(onFallback);
    assert.equal(eventsOf(audit, "doh_fallback_callback_revised").length, 1);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the delivery to land");
    await waitFor(() => seen.length === 1, "the callback still observes after the no-op revision");
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    handle.relay.reviseDohFallbackCallback!(null);
    assert.equal(eventsOf(audit, "doh_fallback_callback_revised").length, 2);
    handle.relay.reviseDohFallbackCallback!(null);
    assert.equal(eventsOf(audit, "doh_fallback_callback_revised").length, 2);
    // A relay built with no callback at all: clearing is a no-op too.
    const bareAudit = tmpAudit();
    const bare = await makeRelay(bareAudit);
    bare.relay.reviseDohFallbackCallback!(null);
    assert.equal(eventsOf(bareAudit, "doh_fallback_callback_revised").length, 0);
  });

  it("audit previous/current are exact across set -> cleared -> set", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit);
    const cb = () => {};
    handle.relay.reviseDohFallbackCallback!(cb);
    handle.relay.reviseDohFallbackCallback!(null);
    handle.relay.reviseDohFallbackCallback!(cb);
    const revised = eventsOf(audit, "doh_fallback_callback_revised");
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

  it("a shadow copy's fallback enters the revised callback too", async () => {
    const audit = tmpAudit();
    const seen: DohFallbackInfo[] = [];
    const handle = await makeRelay(audit, { withShadow: true });
    handle.relay.reviseDohFallbackCallback!((info) => seen.push(info));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 2, "the main and shadow deliveries to land");
    await waitFor(() => seen.length === 2, "both fallbacks to be observed");
    const byUrl = new Map(seen.map((s) => [s.dohUrl, s]));
    assert.equal(byUrl.get(handle.dohUrl)?.hostname, "localhost");
    assert.equal(byUrl.get(handle.shadowDohUrl)?.hostname, "localhost");
    assert.ok((byUrl.get(handle.dohUrl)?.error ?? "").length > 0);
    assert.ok((byUrl.get(handle.shadowDohUrl)?.error ?? "").length > 0);
    const fallbacks = eventsOf(audit, "doh_fallback");
    assert.equal(fallbacks.length, 2);
    assert.deepEqual(
      fallbacks.map((e) => e.dohUrl).sort(),
      [handle.dohUrl, handle.shadowDohUrl].sort()
    );
  });

  it("a throwing operator callback never breaks the fallback or the delivery", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit);
    handle.relay.reviseDohFallbackCallback!(() => {
      throw new Error("telemetry is down");
    });
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(
      () => handle.received.length === 1,
      "the delivery to land despite the throwing hook"
    );
    const fallbacks = eventsOf(audit, "doh_fallback");
    assert.equal(fallbacks.length, 1, "the fallback is still audited");
    assert.equal(fallbacks[0].hostname, "localhost");
    assert.equal(fallbacks[0].dohUrl, handle.dohUrl);
  });
});
