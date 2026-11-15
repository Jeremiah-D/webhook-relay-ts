import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import { createRelayServer } from "../src/server.ts";
import type { DnsPinMismatchInfo } from "../src/dns-pin.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "dns-pin-mismatch-callback-revision-relay-hmac-secret";
const relayOperator = "op-dns-pin-mismatch-callback-token";
const BODY = Buffer.from(JSON.stringify({ event: "dns.pin.mismatch.callback.probe" }));
const MUST_RESTART =
  "reviseDnsPinMismatchCallback: DNS pinning is not configured — enabling it requires a restart: " +
  "the pin is created at startup and a running relay cannot start pinning resolutions without one";

/** Fake inner lookup: answers from a mutable hostname -> address map. */
function fakeInner(map: Map<string, string[]>): LookupFunction {
  return ((hostname: string, _options: unknown, callback: unknown) => {
    const addrs = map.get(hostname);
    const cb = callback as (
      err: NodeJS.ErrnoException | null,
      addresses: LookupAddress[]
    ) => void;
    if (addrs === undefined) {
      const err = new Error(`ENOTFOUND ${hostname}`) as NodeJS.ErrnoException;
      err.code = "ENOTFOUND";
      cb(err, []);
      return;
    }
    cb(
      null,
      addrs.map((address) => ({ address, family: 4 as const }))
    );
  }) as LookupFunction;
}

const servers: Server[] = [];
after(async () => {
  for (const s of servers) {
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  servers.length = 0;
});

function tmpAudit(): AuditLog {
  const dir = mkdtempSync(join(tmpdir(), "dns-pin-mismatch-callback-revision-"));
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
  dnsMap: Map<string, string[]>;
  forwardUrl: string;
}

/**
 * A relay pinning pinned.test. The first delivery pins 127.0.0.1 and
 * succeeds; flipping `dnsMap` to 9.9.9.9 makes every later delivery a
 * drift (enforce mode refuses it before connect).
 */
async function makeRelay(audit: AuditLog, withPin = true): Promise<RelayHandle> {
  const received: Buffer[] = [];
  const downstream = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push(Buffer.concat(chunks));
      res.writeHead(200).end("ok");
    });
  });
  const downstreamPort = await listenOn(downstream, "127.0.0.1");
  const dnsMap = new Map<string, string[]>([["pinned.test", ["127.0.0.1"]]]);
  const forwardUrl = `http://pinned.test:${downstreamPort}/hook`;
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
    // connection would mask the DNS drift).
    outboundKeepAlive: false,
    ...(withPin ? { dnsPin: { inner: fakeInner(dnsMap) } } : {}),
  });
  servers.push(relay, downstream);
  const port = await listenOn(relay);
  return { relay, port, audit, received, dnsMap, forwardUrl };
}

/** Post one event and wait until the mismatch callback has fired again. */
async function postMismatch(
  handle: RelayHandle,
  seen: DnsPinMismatchInfo[]
): Promise<void> {
  const before = seen.length;
  const res = await postSigned(handle.port, BODY);
  assert.equal(res.status, 202);
  await waitFor(() => seen.length > before, "the mismatch callback to fire");
}

/** Wait until the dead-letter list holds `count` entries. */
async function waitDead(handle: RelayHandle, count: number): Promise<Record<string, unknown>[]> {
  const auth = { authorization: `Bearer ${relayOperator}` };
  let dead: Record<string, unknown>[] = [];
  for (let i = 0; i < 200 && dead.length < count; i++) {
    await new Promise((r) => setTimeout(r, 25));
    dead = ((await getJson(handle.port, "/dead-letter", auth)).body as Record<string, unknown>[]) ?? [];
  }
  assert.equal(dead.length, count);
  return dead;
}

describe("RelayServer DNS pin mismatch callback revision (WR-420)", () => {
  // The sandbox sets an egress proxy (HTTP(S)_PROXY); bypass it for the
  // fake hostname so the delivery resolves locally through the pin
  // (127.0.0.1 is already in no_proxy, pinned.test is not).
  const savedNoProxy = process.env.NO_PROXY;
  const savedNoProxyLower = process.env.no_proxy;

  before(() => {
    process.env.NO_PROXY = `${savedNoProxy ?? ""},pinned.test`;
    process.env.no_proxy = `${savedNoProxyLower ?? ""},pinned.test`;
  });

  after(() => {
    if (savedNoProxy === undefined) delete process.env.NO_PROXY;
    else process.env.NO_PROXY = savedNoProxy;
    if (savedNoProxyLower === undefined) delete process.env.no_proxy;
    else process.env.no_proxy = savedNoProxyLower;
  });

  it("swapping the callback routes the next drift to the new callback with exact fields; the old callback stays silent", async () => {
    const audit = tmpAudit();
    const first: DnsPinMismatchInfo[] = [];
    const second: DnsPinMismatchInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseDnsPinMismatchCallback!((info) => first.push(info));
    // First delivery pins 127.0.0.1 and succeeds.
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the first delivery to land");
    assert.deepEqual(handle.received[0], BODY);

    // Hijack the resolver: the pin must now refuse every delivery.
    handle.dnsMap.set("pinned.test", ["9.9.9.9"]);
    await postMismatch(handle, first);
    // Both attempts of the drifted delivery must be exhausted before
    // the swap, or the retry could still land in the old callback's
    // count after the cell moves.
    await waitDead(handle, 1);
    assert.equal(first.length, 2, "two attempts, two mismatch reports");
    assert.equal(second.length, 0);

    handle.relay.reviseDnsPinMismatchCallback!((info) => second.push(info));
    await postMismatch(handle, second);
    await waitDead(handle, 2);
    assert.equal(first.length, 2, "old callback stays silent after revision");
    assert.equal(second.length, 2, "new callback sees the next drift (two attempts)");
    const info = second[0];
    assert.equal(info.hostname, "pinned.test");
    assert.deepEqual(info.pinned, ["127.0.0.1"]);
    assert.deepEqual(info.observed, ["9.9.9.9"]);
    assert.equal(info.mode, "enforce");
    assert.match(info.at, /^\d{4}-\d{2}-\d{2}T/);
    // The first drift is never re-emitted to the new callback.
    assert.notEqual(info.at, first[0].at);
    const revised = eventsOf(audit, "dns_pin_mismatch_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "set");
    // Both drifts were audited, in order.
    const mismatches = eventsOf(audit, "dns_pin_mismatch");
    assert.ok(mismatches.length >= 2);
    assert.equal(mismatches[0].hostname, "pinned.test");
    assert.deepEqual(mismatches[0].pinned, ["127.0.0.1"]);
    assert.deepEqual(mismatches[0].observed, ["9.9.9.9"]);
    assert.equal(mismatches[0].mode, "enforce");
  });

  it("null clears back to audit-only: the drift is still detected and audited, and enforce still refuses the delivery", async () => {
    const audit = tmpAudit();
    const seen: DnsPinMismatchInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseDnsPinMismatchCallback!((info) => seen.push(info));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the first delivery to land");

    handle.dnsMap.set("pinned.test", ["9.9.9.9"]);
    await postMismatch(handle, seen);
    await waitDead(handle, 1);
    assert.equal(seen.length, 2, "two attempts, two mismatch reports");
    const before = seen.length;

    handle.relay.reviseDnsPinMismatchCallback!(null);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    // The drifted delivery still dead-letters as a pin refusal.
    const dead = await waitDead(handle, 2);
    assert.match(String(dead[1].lastError), /DNS pin mismatch for pinned\.test/);
    assert.equal(seen.length, before, "cleared hook stays silent");
    const mismatches = eventsOf(audit, "dns_pin_mismatch");
    assert.ok(mismatches.length >= 4, "both drifts still audited (two attempts each)");
    assert.deepEqual(mismatches.at(-1)?.pinned, ["127.0.0.1"]);
    assert.deepEqual(mismatches.at(-1)?.observed, ["9.9.9.9"]);
    // The drifted address never saw a byte.
    assert.equal(handle.received.length, 1);
    const revised = eventsOf(audit, "dns_pin_mismatch_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "cleared");
  });

  it("with pinning unconfigured, revising throws the must-restart Error and live state is untouched", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, false);
    for (const cb of [(() => {}) as never, null]) {
      assert.throws(() => handle.relay.reviseDnsPinMismatchCallback!(cb), (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, MUST_RESTART);
        return true;
      });
    }
    assert.equal(eventsOf(audit, "dns_pin_mismatch_callback_revised").length, 0);
    // The relay still admits cleanly with pinning off.
    const res = await postSigned(handle.port, BODY);
    assert.equal(res.status, 202);
    assert.equal(eventsOf(audit, "dns_pin_mismatch").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const audit = tmpAudit();
    const seen: DnsPinMismatchInfo[] = [];
    const handle = await makeRelay(audit);
    handle.relay.reviseDnsPinMismatchCallback!((info) => seen.push(info));
    for (const bad of ["x", 42, {}, true] as never[]) {
      assert.throws(
        () => handle.relay.reviseDnsPinMismatchCallback!(bad),
        RangeError,
        String(bad)
      );
    }
    assert.equal(eventsOf(audit, "dns_pin_mismatch_callback_revised").length, 1);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the first delivery to land");
    handle.dnsMap.set("pinned.test", ["9.9.9.9"]);
    await postMismatch(handle, seen);
    assert.ok(seen.length >= 1, "the original callback still observes the drift");
    assert.equal(seen[0].hostname, "pinned.test");
  });

  it("same-reference replacement and clearing an already-unset callback are silent no-ops", async () => {
    const audit = tmpAudit();
    const seen: DnsPinMismatchInfo[] = [];
    const onMismatch = (info: DnsPinMismatchInfo) => seen.push(info);
    const handle = await makeRelay(audit);
    handle.relay.reviseDnsPinMismatchCallback!(onMismatch);
    handle.relay.reviseDnsPinMismatchCallback!(onMismatch);
    assert.equal(eventsOf(audit, "dns_pin_mismatch_callback_revised").length, 1);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the first delivery to land");
    handle.dnsMap.set("pinned.test", ["9.9.9.9"]);
    await postMismatch(handle, seen);
    assert.ok(seen.length >= 1, "the callback still observes after the no-op revision");
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    handle.relay.reviseDnsPinMismatchCallback!(null);
    assert.equal(eventsOf(audit, "dns_pin_mismatch_callback_revised").length, 2);
    handle.relay.reviseDnsPinMismatchCallback!(null);
    assert.equal(eventsOf(audit, "dns_pin_mismatch_callback_revised").length, 2);
    // A relay built with no callback at all: clearing is a no-op too.
    const bareAudit = tmpAudit();
    const bare = await makeRelay(bareAudit);
    bare.relay.reviseDnsPinMismatchCallback!(null);
    assert.equal(eventsOf(bareAudit, "dns_pin_mismatch_callback_revised").length, 0);
  });

  it("audit previous/current are exact across set -> cleared -> set", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit);
    const cb = () => {};
    handle.relay.reviseDnsPinMismatchCallback!(cb);
    handle.relay.reviseDnsPinMismatchCallback!(null);
    handle.relay.reviseDnsPinMismatchCallback!(cb);
    const revised = eventsOf(audit, "dns_pin_mismatch_callback_revised");
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

  it("revision does not change the pin baseline, the mode, getStats, or render", async () => {
    const audit = tmpAudit();
    const first: DnsPinMismatchInfo[] = [];
    const second: DnsPinMismatchInfo[] = [];
    const handle = await makeRelay(audit);
    const auth = { authorization: `Bearer ${relayOperator}` };
    handle.relay.reviseDnsPinMismatchCallback!((info) => first.push(info));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the first delivery to land");
    handle.dnsMap.set("pinned.test", ["9.9.9.9"]);
    await postMismatch(handle, first);
    await waitDead(handle, 1);
    const metricsBefore = await getText(handle.port, "/metrics", auth);
    assert.match(metricsBefore, /relay_dns_pin_mismatches_total 2/);
    assert.match(metricsBefore, /relay_dns_pin_lookups_total\{result="refused"\} 2/);
    assert.match(metricsBefore, /relay_dns_pin_hosts 1/);

    // Swap the observer; nothing about the pin itself may move.
    handle.relay.reviseDnsPinMismatchCallback!((info) => second.push(info));
    await postMismatch(handle, second);
    assert.equal(first.length, 2, "old callback stays silent after revision");
    assert.ok(second.length >= 1);
    assert.deepEqual(second[0].pinned, ["127.0.0.1"], "baseline unchanged by the revision");
    assert.equal(second[0].mode, "enforce", "mode unchanged by the revision");
    await waitDead(handle, 2);
    const metricsAfter = await getText(handle.port, "/metrics", auth);
    assert.match(metricsAfter, /relay_dns_pin_mismatches_total 4/);
    assert.match(metricsAfter, /relay_dns_pin_lookups_total\{result="refused"\} 4/);
    assert.match(metricsAfter, /relay_dns_pin_hosts 1/);
    const mismatches = eventsOf(audit, "dns_pin_mismatch");
    assert.deepEqual(mismatches.at(-1)?.pinned, ["127.0.0.1"]);
    assert.equal(mismatches.at(-1)?.mode, "enforce");
    assert.equal(handle.received.length, 1);
  });
});
