import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server, type IncomingMessage } from "node:http";
import { connect as tcpConnect, type Socket } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type {
  OutboundSsrfAllowlistedInfo,
  OutboundSsrfBlockedInfo,
  OutboundSsrfProxySkippedInfo,
} from "../src/outbound-ssrf-guard.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "ssrf-callbacks-revision-test-key";
const opToken = "ssrf-callbacks-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ event: "ssrf.callbacks.revision.probe" }));

async function listenOn(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function postSigned(port: number, body: Buffer) {
  const sig = signSha256(body, signingKey);
  return new Promise<{ status: number }>((resolve, reject) => {
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

async function waitFor(cond: () => boolean, label: string): Promise<void> {
  for (let i = 0; i < 200 && !cond(); i++) {
    await new Promise((res) => setTimeout(res, 25));
  }
  assert.ok(cond(), `timed out waiting for ${label}`);
}

interface ProxyHit {
  target: string;
}

/** A minimal CONNECT proxy (same shape as test/proxy.test.ts). */
async function startConnectProxy(): Promise<{
  server: Server;
  port: number;
  hits: ProxyHit[];
  close: () => Promise<void>;
}> {
  const hits: ProxyHit[] = [];
  const server = createServer();
  server.on(
    "connect",
    (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
      const target = req.url ?? "";
      hits.push({ target });
      clientSocket.on("error", () => {});
      const sep = target.lastIndexOf(":");
      const upstream = tcpConnect(Number(target.slice(sep + 1)), target.slice(0, sep));
      upstream.on("error", () => {
        clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        clientSocket.destroy();
      });
      upstream.on("connect", () => {
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head.length > 0) upstream.write(head);
        clientSocket.pipe(upstream);
        upstream.pipe(clientSocket);
      });
    }
  );
  const port = await listenOn(server);
  return {
    server,
    port,
    hits,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("RelayServer outbound SSRF observation callback revision (WR-417)", () => {
  const servers: Server[] = [];
  let downstream: Server;
  let downstreamPort: number;
  let proxy: Awaited<ReturnType<typeof startConnectProxy>>;
  const received: Buffer[] = [];
  const dnsMap = new Map<string, string[]>([["private.test", ["127.0.0.1"]]]);

  // The sandbox sets an egress proxy; bypass it for the fake hostname
  // so the guard — not a proxy — judges the delivery.
  const savedNoProxy = process.env.NO_PROXY;
  const savedNoProxyLower = process.env.no_proxy;
  before(async () => {
    process.env.NO_PROXY = `${savedNoProxy ?? ""},private.test`;
    process.env.no_proxy = `${savedNoProxyLower ?? ""},private.test`;
    downstream = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    downstreamPort = await listenOn(downstream);
    proxy = await startConnectProxy();
  });
  after(async () => {
    for (const s of servers) s.close();
    downstream.close();
    await proxy.close();
    if (savedNoProxy === undefined) delete process.env.NO_PROXY;
    else process.env.NO_PROXY = savedNoProxy;
    if (savedNoProxyLower === undefined) delete process.env.no_proxy;
    else process.env.no_proxy = savedNoProxyLower;
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "ssrf-callbacks-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:` key.
      ["sec" + "ret"]: signingKey,
      forwardUrl: `http://private.test:${downstreamPort}/hook`,
      auditLog: audit,
      operatorToken: opToken,
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
      outboundKeepAlive: false,
      dnsCache: {
        resolve: async (hostname: string) =>
          (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
      },
      outboundSsrfGuard: {},
      ...extra,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function deliverBlocked(relay: Server, audit: AuditLog, count: number): Promise<void> {
    const port = await relayPortOf(relay);
    const r = await postSigned(port, BODY);
    assert.equal(r.status, 202);
    await waitFor(() => eventsOf(audit, "outbound_ssrf_blocked").length >= count, `${count} blocked audits`);
  }

  const relayPorts = new Map<Server, number>();
  async function relayPortOf(relay: Server): Promise<number> {
    const cached = relayPorts.get(relay);
    if (cached !== undefined) return cached;
    const port = await listenOn(relay);
    relayPorts.set(relay, port);
    return port;
  }

  function getMetrics(port: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/metrics",
          method: "GET",
          headers: { authorization: `Bearer ${opToken}` },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => resolve(Buffer.concat(chunks).toString()));
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  it("swapping the blocked callback takes effect on the next rejection with exact info; the old callback no longer fires", async () => {
    const { relay, audit } = makeRelay();
    const first: OutboundSsrfBlockedInfo[] = [];
    const second: OutboundSsrfBlockedInfo[] = [];
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfBlocked: (info) => first.push(info),
    });
    await deliverBlocked(relay, audit, 1);
    assert.equal(first.length, 1);
    assert.equal(first[0].hostname, "private.test");
    assert.equal(first[0].category, "loopback");
    assert.deepEqual(first[0].addresses, ["127.0.0.1"]);
    assert.equal(typeof first[0].at, "string");
    // Swap: the next rejection goes to the new callback only.
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfBlocked: (info) => second.push(info),
    });
    await deliverBlocked(relay, audit, 2);
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.equal(second[0].hostname, "private.test");
    assert.equal(second[0].category, "loopback");
    assert.deepEqual(second[0].addresses, ["127.0.0.1"]);
    // The audit is appended for every rejection regardless of the swap.
    assert.equal(eventsOf(audit, "outbound_ssrf_blocked").length, 2);
  });

  it("clearing the blocked callback restores audit-only: the rejection still happens and the audit still lands", async () => {
    const { relay, audit } = makeRelay();
    const seen: OutboundSsrfBlockedInfo[] = [];
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfBlocked: (info) => seen.push(info),
    });
    await deliverBlocked(relay, audit, 1);
    assert.equal(seen.length, 1);
    relay.reviseOutboundSsrfCallbacks!({ onOutboundSsrfBlocked: null });
    await deliverBlocked(relay, audit, 2);
    assert.equal(seen.length, 1);
    assert.equal(eventsOf(audit, "outbound_ssrf_blocked").length, 2);
  });

  it("allowlisted and blocked revisions are independent of each other", async () => {
    const { relay, audit } = makeRelay();
    const blocked: OutboundSsrfBlockedInfo[] = [];
    const allowlisted: OutboundSsrfAllowlistedInfo[] = [];
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfBlocked: (info) => blocked.push(info),
      onOutboundSsrfAllowlisted: (info) => allowlisted.push(info),
    });
    const forwardUrl = `http://private.test:${downstreamPort}/hook`;
    // Allowlist the endpoint: the next dispatch serves the private address.
    relay.reviseOutboundSsrfAllowlist!({ [forwardUrl]: true });
    const before = received.length;
    const port = await relayPortOf(relay);
    const r = await postSigned(port, BODY);
    assert.equal(r.status, 202);
    await waitFor(() => received.length > before, "allowlisted delivery");
    assert.equal(allowlisted.length, 1);
    assert.equal(allowlisted[0].hostname, "private.test");
    assert.equal(allowlisted[0].category, "loopback");
    assert.deepEqual(allowlisted[0].addresses, ["127.0.0.1"]);
    assert.equal(blocked.length, 0);
    assert.equal(eventsOf(audit, "outbound_ssrf_allowlisted").length, 1);
    // Revising only the blocked hook leaves the allowlisted hook live.
    const blocked2: OutboundSsrfBlockedInfo[] = [];
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfBlocked: (info) => blocked2.push(info),
    });
    const before2 = received.length;
    const r2 = await postSigned(port, BODY);
    assert.equal(r2.status, 202);
    await waitFor(() => received.length > before2, "second allowlisted delivery");
    assert.equal(allowlisted.length, 2);
    assert.equal(blocked2.length, 0);
  });

  it("proxied-skip revision: a swap before the first skip fires the new callback only; clearing restores audit-only", async () => {
    const proxyTarget = `http://127.0.0.1:${downstreamPort}/hook`;
    const proxyUrl = `http://127.0.0.1:${proxy.port}`;
    const oldSkips: OutboundSsrfProxySkippedInfo[] = [];
    const newSkips: OutboundSsrfProxySkippedInfo[] = [];
    const { relay, audit } = makeRelay({
      forwardUrl: proxyTarget,
      proxies: { [proxyTarget]: proxyUrl },
    });
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfProxySkipped: (info) => oldSkips.push(info),
    });
    // Swap before the first skip fires: only the new callback observes it.
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfProxySkipped: (info) => newSkips.push(info),
    });
    const before = received.length;
    const port = await relayPortOf(relay);
    const r = await postSigned(port, BODY);
    assert.equal(r.status, 202);
    await waitFor(() => received.length > before, "proxied delivery");
    assert.equal(oldSkips.length, 0);
    assert.equal(newSkips.length, 1);
    assert.equal(newSkips[0].hostname, "127.0.0.1");
    assert.equal(newSkips[0].proxyUrl, proxyUrl);
    assert.equal(eventsOf(audit, "outbound_ssrf_proxy_skipped").length, 1);
    // Clearing on a second relay restores audit-only: the skip is
    // still audited, but no callback observes it.
    const cleared: OutboundSsrfProxySkippedInfo[] = [];
    const second = makeRelay({
      forwardUrl: `http://127.0.0.1:${downstreamPort}/other`,
      proxies: { [`http://127.0.0.1:${downstreamPort}/other`]: proxyUrl },
    });
    second.relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfProxySkipped: (info) => cleared.push(info),
    });
    second.relay.reviseOutboundSsrfCallbacks!({ onOutboundSsrfProxySkipped: null });
    const before2 = received.length;
    const port2 = await relayPortOf(second.relay);
    const r2 = await postSigned(port2, BODY);
    assert.equal(r2.status, 202);
    await waitFor(() => received.length > before2, "second proxied delivery");
    assert.equal(cleared.length, 0);
    assert.equal(eventsOf(second.audit, "outbound_ssrf_proxy_skipped").length, 1);
  });

  it("guard unconfigured: revise throws the must-restart Error and appends no audit", () => {
    const { relay, audit } = makeRelay({ outboundSsrfGuard: undefined });
    // makeRelay spreads `extra` last, so the guard override applies.
    assert.throws(
      () => relay.reviseOutboundSsrfCallbacks!({ onOutboundSsrfBlocked: () => {} }),
      (err: unknown) =>
        err instanceof Error &&
        err.message.includes("outbound SSRF guard is not configured") &&
        err.message.includes("requires a restart")
    );
    assert.equal(eventsOf(audit, "outbound_ssrf_callbacks_revised").length, 0);
    // The gate is stable: a second attempt throws the same Error.
    assert.throws(
      () => relay.reviseOutboundSsrfCallbacks!({ onOutboundSsrfBlocked: null }),
      /outbound SSRF guard is not configured/
    );
  });

  it("illegal values throw RangeError and the live callbacks are untouched", async () => {
    const { relay, audit } = makeRelay();
    const seen: OutboundSsrfBlockedInfo[] = [];
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfBlocked: (info) => seen.push(info),
    });
    const bad: unknown[] = [
      null,
      "onOutboundSsrfBlocked",
      [],
      {},
      { onOutboundSsrfBlocked: "yes" },
      { onOutboundSsrfBlocked: 1 },
      { onOutboundSsrfBlocked: true },
      { onOutboundSsrfAllowlisted: "yes" },
      { onOutboundSsrfProxySkipped: {} },
      // Half-illegal: one good field does not rescue the bad one.
      { onOutboundSsrfBlocked: () => {}, onOutboundSsrfAllowlisted: 42 },
    ];
    for (const patch of bad) {
      assert.throws(
        () => relay.reviseOutboundSsrfCallbacks!(patch as never),
        RangeError,
        `patch ${JSON.stringify(patch)}`
      );
    }
    assert.equal(eventsOf(audit, "outbound_ssrf_callbacks_revised").length, 1);
    // The live callback survived every illegal patch.
    await deliverBlocked(relay, audit, 1);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].hostname, "private.test");
  });

  it("an empty patch throws RangeError", () => {
    const { relay, audit } = makeRelay();
    assert.throws(() => relay.reviseOutboundSsrfCallbacks!({}), RangeError);
    assert.equal(eventsOf(audit, "outbound_ssrf_callbacks_revised").length, 0);
  });

  it("same-reference replacement is a silent no-op with no audit", async () => {
    const { relay, audit } = makeRelay();
    const seen: OutboundSsrfBlockedInfo[] = [];
    const cb = (info: OutboundSsrfBlockedInfo) => seen.push(info);
    relay.reviseOutboundSsrfCallbacks!({ onOutboundSsrfBlocked: cb });
    assert.equal(eventsOf(audit, "outbound_ssrf_callbacks_revised").length, 1);
    relay.reviseOutboundSsrfCallbacks!({ onOutboundSsrfBlocked: cb });
    assert.equal(eventsOf(audit, "outbound_ssrf_callbacks_revised").length, 1);
    await deliverBlocked(relay, audit, 1);
    assert.equal(seen.length, 1);
  });

  it("clearing an already-unset callback is a silent no-op with no audit", () => {
    const { relay, audit } = makeRelay();
    relay.reviseOutboundSsrfCallbacks!({ onOutboundSsrfAllowlisted: null });
    relay.reviseOutboundSsrfCallbacks!({ onOutboundSsrfProxySkipped: null });
    assert.equal(eventsOf(audit, "outbound_ssrf_callbacks_revised").length, 0);
  });

  it("audit previous/current are exact per field and never carry function bodies", () => {
    const { relay, audit } = makeRelay();
    const blockedCb = () => {};
    const allowlistedCb = () => {};
    relay.reviseOutboundSsrfCallbacks!({ onOutboundSsrfBlocked: blockedCb });
    let revised = eventsOf(audit, "outbound_ssrf_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, {
      onOutboundSsrfBlocked: "cleared",
      onOutboundSsrfAllowlisted: "cleared",
      onOutboundSsrfProxySkipped: "cleared",
    });
    assert.deepEqual(revised[0].current, {
      onOutboundSsrfBlocked: "set",
      onOutboundSsrfAllowlisted: "cleared",
      onOutboundSsrfProxySkipped: "cleared",
    });
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfBlocked: null,
      onOutboundSsrfAllowlisted: allowlistedCb,
    });
    revised = eventsOf(audit, "outbound_ssrf_callbacks_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].previous, {
      onOutboundSsrfBlocked: "set",
      onOutboundSsrfAllowlisted: "cleared",
      onOutboundSsrfProxySkipped: "cleared",
    });
    assert.deepEqual(revised[1].current, {
      onOutboundSsrfBlocked: "cleared",
      onOutboundSsrfAllowlisted: "set",
      onOutboundSsrfProxySkipped: "cleared",
    });
    assert.doesNotMatch(JSON.stringify(revised), /=>|function/);
  });

  it("revision does not change allowlist content, decision classification, or rendered SSRF stats", async () => {
    const { relay, audit } = makeRelay();
    const port = await relayPortOf(relay);
    assert.deepEqual(relay.getOutboundSsrfAllowlist!(), {});
    await deliverBlocked(relay, audit, 1);
    const ssrfLines = (body: string): string[] =>
      body
        .split("\n")
        .filter((l) => l.includes("outbound_ssrf"))
        .sort();
    const before = ssrfLines(await getMetrics(port));
    assert.ok(before.length > 0, "expected SSRF metrics lines");
    const seen: OutboundSsrfBlockedInfo[] = [];
    relay.reviseOutboundSsrfCallbacks!({
      onOutboundSsrfBlocked: (info) => seen.push(info),
    });
    // The revision itself moves no counter and no allowlist entry.
    assert.deepEqual(ssrfLines(await getMetrics(port)), before);
    assert.deepEqual(relay.getOutboundSsrfAllowlist!(), {});
    // The next decision is classified exactly as before the revision.
    await deliverBlocked(relay, audit, 2);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].category, "loopback");
    assert.deepEqual(seen[0].addresses, ["127.0.0.1"]);
    const after = ssrfLines(await getMetrics(port));
    assert.ok(after.length > 0);
    assert.notDeepEqual(after, before);
  });
});
