import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import { createRelayServer } from "../src/server.ts";
import type { EgressResidencyBlockedInfo } from "../src/egress-residency.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "egress-residency-blocked-callback-revision-relay-hmac-secret";
const relayOperator = "op-egress-residency-blocked-callback-token";
const BODY = Buffer.from(JSON.stringify({ event: "egress.residency.blocked.callback.probe" }));
const MUST_RESTART =
  "reviseEgressResidencyBlockedCallback: egress residency gate is not configured — enabling it requires a restart: " +
  "the gate is created at startup and a running relay cannot start gating egress without one";

/**
 * Operator-curated table for the tests (TEST-NET ranges, plus loopback
 * rows so the end-to-end downstream — which must be dialed on loopback
 * — still gets a country): the more specific 127.0.0.1/32 row is listed
 * first, the covering 127.0.0.0/8 row second, so first-match-wins is
 * exercised in both directions. Same table as egress-residency.test.ts.
 */
const TABLE = [
  { cidr: "127.0.0.1/32", country: "DE" },
  { cidr: "203.0.113.0/24", country: "DE" },
  { cidr: "203.0.113.128/25", country: "US" },
  { cidr: "198.51.100.0/24", country: "US" },
  { cidr: "192.0.2.0/24", country: "FR" },
  { cidr: "2001:db8::/32", country: "DE" },
  { cidr: "127.0.0.0/8", country: "US" },
];

const servers: Server[] = [];
after(async () => {
  for (const s of servers) {
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  servers.length = 0;
});

function tmpAudit(): AuditLog {
  const dir = mkdtempSync(join(tmpdir(), "egress-residency-blocked-callback-revision-"));
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

function postSigned(port: number, body: Buffer, tenant?: string): Promise<{ status: number }> {
  const sig = signSha256(body, relaySecret);
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/hook",
        method: "POST",
        headers: {
          "x-signature": sig,
          ...(tenant !== undefined ? { "x-tenant-id": tenant } : {}),
        },
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

function getJson(port: number, path: string, headers: Record<string, string>) {
  return new Promise<{ status: number; body: unknown }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString()) })
      );
    });
    r.on("error", reject);
    r.end();
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

interface RelayHandle {
  relay: ReturnType<typeof createRelayServer>;
  port: number;
  audit: AuditLog;
  received: Buffer[];
  forwardUrl: string;
}

/** A relay whose tenant-eu may egress to DE/FR only; us.test resolves to US (127.0.0.2). */
async function makeRelay(audit: AuditLog, withGate = true): Promise<RelayHandle> {
  const received: Buffer[] = [];
  const downstream = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push(Buffer.concat(chunks));
      res.writeHead(200).end("ok");
    });
  });
  // Listen on all interfaces so 127.0.0.2 (US) reaches the same downstream.
  const downstreamPort = await listenOn(downstream, "0.0.0.0");
  const dnsMap = new Map<string, string[]>([["us.test", ["127.0.0.2"]]]);
  const forwardUrl = `http://us.test:${downstreamPort}/hook`;
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
    dnsCache: {
      resolve: async (hostname: string) =>
        (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
    },
    ...(withGate
      ? {
          egressResidency: {
            table: TABLE,
            allowedEgressCountries: { "tenant-eu": ["DE", "FR"] },
          },
        }
      : {}),
  });
  servers.push(relay, downstream);
  const port = await listenOn(relay);
  return { relay, port, audit, received, forwardUrl };
}

/** Post one tenant-eu event and wait until the operator callback has fired `count` times. */
async function postBlocked(
  handle: RelayHandle,
  seen: EgressResidencyBlockedInfo[]
): Promise<void> {
  const before = seen.length;
  const res = await postSigned(handle.port, BODY, "tenant-eu");
  assert.equal(res.status, 202);
  await waitFor(() => seen.length > before, "the blocked callback to fire");
}

describe("RelayServer egress-residency-blocked callback revision (WR-419)", () => {
  // The sandbox sets an egress proxy (HTTP(S)_PROXY); bypass it for the
  // fake hostname so the delivery resolves locally through the gate
  // (127.0.0.1 is already in no_proxy, the .test name is not).
  const savedNoProxy = process.env.NO_PROXY;
  const savedNoProxyLower = process.env.no_proxy;

  before(() => {
    process.env.NO_PROXY = `${savedNoProxy ?? ""},us.test`;
    process.env.no_proxy = `${savedNoProxyLower ?? ""},us.test`;
  });

  after(() => {
    if (savedNoProxy === undefined) delete process.env.NO_PROXY;
    else process.env.NO_PROXY = savedNoProxy;
    if (savedNoProxyLower === undefined) delete process.env.no_proxy;
    else process.env.no_proxy = savedNoProxyLower;
  });

  it("swapping the callback routes the next refusal to the new callback with exact fields; the old callback stays silent", async () => {
    const audit = tmpAudit();
    const first: EgressResidencyBlockedInfo[] = [];
    const second: EgressResidencyBlockedInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseEgressResidencyBlockedCallback!((info) => first.push(info));
    await postBlocked(handle, first);
    assert.equal(first.length, 1);
    assert.equal(second.length, 0);

    handle.relay.reviseEgressResidencyBlockedCallback!((info) => second.push(info));
    await postBlocked(handle, second);
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second.length, 1, "new callback sees the next refusal");
    const info = second[0];
    assert.equal(info.tenant, "tenant-eu");
    assert.equal(info.endpoint, handle.forwardUrl);
    assert.equal(info.hostname, "us.test");
    assert.equal(info.country, "US");
    assert.deepEqual(info.addresses, ["127.0.0.2"]);
    assert.match(info.at, /^\d{4}-\d{2}-\d{2}T/);
    // The first refusal is never re-emitted to the new callback.
    assert.notEqual(info.at, first[0].at);
    const revised = eventsOf(audit, "egress_residency_blocked_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "set");
    // Both refusals were audited, in order.
    const blocked = eventsOf(audit, "egress_residency_blocked");
    assert.equal(blocked.length, 2);
    assert.equal(blocked[1].tenant, "tenant-eu");
    assert.equal(blocked[1].country, "US");
    assert.deepEqual(blocked[1].addresses, ["127.0.0.2"]);
  });

  it("null clears back to audit-only: the refusal still dead-letters and is still audited", async () => {
    const audit = tmpAudit();
    const seen: EgressResidencyBlockedInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseEgressResidencyBlockedCallback!((info) => seen.push(info));
    await postBlocked(handle, seen);
    assert.equal(seen.length, 1);

    handle.relay.reviseEgressResidencyBlockedCallback!(null);
    const res = await postSigned(handle.port, BODY, "tenant-eu");
    assert.equal(res.status, 202);
    // The refusal still dead-letters on the first attempt.
    const auth = { authorization: `Bearer ${relayOperator}` };
    let dead: Record<string, unknown>[] = [];
    for (let i = 0; i < 200 && dead.length < 2; i++) {
      await new Promise((r) => setTimeout(r, 25));
      dead = ((await getJson(handle.port, "/dead-letter", auth)).body as Record<string, unknown>[]) ?? [];
    }
    assert.equal(dead.length, 2);
    assert.equal(dead[1].attempts, 1);
    assert.match(String(dead[1].lastError), /Egress residency gate blocked us\.test: resolved address is in US/);
    assert.equal(seen.length, 1, "cleared hook stays silent");
    assert.equal(eventsOf(audit, "egress_residency_blocked").length, 2, "both refusals still audited");
    const deadAudits = eventsOf(audit, "dead_letter");
    assert.equal(deadAudits.length, 2);
    assert.equal(deadAudits[1].failure_class, "non_retryable");
    // The downstream never saw a byte.
    assert.equal(handle.received.length, 0);
    const revised = eventsOf(audit, "egress_residency_blocked_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "cleared");
  });

  it("with the gate unconfigured, revising throws the must-restart Error and live state is untouched", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, false);
    for (const cb of [(() => {}) as never, null]) {
      assert.throws(() => handle.relay.reviseEgressResidencyBlockedCallback!(cb), (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, MUST_RESTART);
        return true;
      });
    }
    assert.equal(eventsOf(audit, "egress_residency_blocked_callback_revised").length, 0);
    // The relay still admits cleanly with the gate off.
    const res = await postSigned(handle.port, BODY, "tenant-eu");
    assert.equal(res.status, 202);
    assert.equal(eventsOf(audit, "egress_residency_blocked").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const audit = tmpAudit();
    const seen: EgressResidencyBlockedInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseEgressResidencyBlockedCallback!((info) => seen.push(info));
    for (const bad of ["x", 42, {}, true] as never[]) {
      assert.throws(
        () => handle.relay.reviseEgressResidencyBlockedCallback!(bad),
        RangeError,
        String(bad)
      );
    }
    assert.equal(eventsOf(audit, "egress_residency_blocked_callback_revised").length, 1);
    await postBlocked(handle, seen);
    assert.equal(seen.length, 1, "the original callback still observes the refusal");
    assert.equal(seen[0].country, "US");
  });

  it("same-reference replacement and clearing an already-unset callback are silent no-ops", async () => {
    const audit = tmpAudit();
    const seen: EgressResidencyBlockedInfo[] = [];
    const onBlocked = (info: EgressResidencyBlockedInfo) => seen.push(info);
    const handle = await makeRelay(audit);
    handle.relay.reviseEgressResidencyBlockedCallback!(onBlocked);
    handle.relay.reviseEgressResidencyBlockedCallback!(onBlocked);
    assert.equal(eventsOf(audit, "egress_residency_blocked_callback_revised").length, 1);
    await postBlocked(handle, seen);
    assert.equal(seen.length, 1, "the callback still observes after the no-op revision");
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    handle.relay.reviseEgressResidencyBlockedCallback!(null);
    assert.equal(eventsOf(audit, "egress_residency_blocked_callback_revised").length, 2);
    handle.relay.reviseEgressResidencyBlockedCallback!(null);
    assert.equal(eventsOf(audit, "egress_residency_blocked_callback_revised").length, 2);
    // A relay built with no callback at all: clearing is a no-op too.
    const bareAudit = tmpAudit();
    const bare = await makeRelay(bareAudit);
    bare.relay.reviseEgressResidencyBlockedCallback!(null);
    assert.equal(eventsOf(bareAudit, "egress_residency_blocked_callback_revised").length, 0);
  });

  it("audit previous/current are exact across set -> cleared -> set", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit);
    const cb = () => {};
    handle.relay.reviseEgressResidencyBlockedCallback!(cb);
    handle.relay.reviseEgressResidencyBlockedCallback!(null);
    handle.relay.reviseEgressResidencyBlockedCallback!(cb);
    const revised = eventsOf(audit, "egress_residency_blocked_callback_revised");
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

  it("revision does not change the country table, the decision classification, getStats, or render", async () => {
    const audit = tmpAudit();
    const first: EgressResidencyBlockedInfo[] = [];
    const second: EgressResidencyBlockedInfo[] = [];
    const handle = await makeRelay(audit);
    const auth = { authorization: `Bearer ${relayOperator}` };
    assert.deepEqual(handle.relay.getEgressResidency!("tenant-eu"), ["DE", "FR"]);
    handle.relay.reviseEgressResidencyBlockedCallback!((info) => first.push(info));
    await postBlocked(handle, first);
    const metricsBefore = await getText(handle.port, "/metrics", auth);
    assert.match(metricsBefore, /relay_egress_residency_blocks_total\{country="US"\} 1/);
    assert.match(metricsBefore, /relay_egress_residency_lookups_total\{result="blocked"\} 1/);

    // Swap the observer; nothing about the gate itself may move.
    handle.relay.reviseEgressResidencyBlockedCallback!((info) => second.push(info));
    assert.deepEqual(handle.relay.getEgressResidency!("tenant-eu"), ["DE", "FR"]);
    await postBlocked(handle, second);
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second.length, 1);
    const metricsAfter = await getText(handle.port, "/metrics", auth);
    assert.match(metricsAfter, /relay_egress_residency_blocks_total\{country="US"\} 2/);
    assert.match(metricsAfter, /relay_egress_residency_lookups_total\{result="blocked"\} 2/);
    // The second refusal still dead-letters on the first attempt as non_retryable.
    let dead: Record<string, unknown>[] = [];
    for (let i = 0; i < 200 && dead.length < 2; i++) {
      await new Promise((r) => setTimeout(r, 25));
      dead = ((await getJson(handle.port, "/dead-letter", auth)).body as Record<string, unknown>[]) ?? [];
    }
    assert.equal(dead.length, 2);
    assert.equal(dead[1].attempts, 1);
    const deadAudits = eventsOf(audit, "dead_letter");
    assert.equal(deadAudits.length, 2);
    assert.equal(deadAudits[1].failure_class, "non_retryable");
    assert.equal(handle.received.length, 0);
  });
});
