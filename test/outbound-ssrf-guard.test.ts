import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server, type IncomingMessage } from "node:http";
import { connect as tcpConnect, type Socket } from "node:net";
import type { LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OutboundSsrfGuard,
  OutboundSsrfBlockedError,
  classifyIpAddress,
  type OutboundSsrfBlockedInfo,
} from "../src/outbound-ssrf-guard.ts";
import { classifyFailure } from "../src/failure.ts";
import { createRelayServer, createDefaultSender, type PooledSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const relaySecret = "outbound-ssrf-guard-secret";
const OPERATOR = "op-ssrf-guard-token";
const BODY = Buffer.from(JSON.stringify({ event: "ssrf.guard.probe" }));

/** Fake inner lookup: answers from a mutable hostname -> address map. */
function fakeInner(map: Map<string, string[]>): LookupFunction {
  return ((hostname: string, options: unknown, callback: unknown) => {
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
      addrs.map((address) => ({ address, family: (address.includes(":") ? 6 : 4) as 4 | 6 }))
    );
  }) as LookupFunction;
}

function lookupPromise(
  lookup: LookupFunction,
  hostname: string,
  options: { all?: boolean; family?: number } = {}
): Promise<{ address: string; family: number } | LookupAddress[]> {
  return new Promise((resolve, reject) => {
    lookup(hostname, options, ((err: unknown, address: unknown, family: unknown) => {
      if (err) reject(err);
      else if (options.all === true) resolve(address as LookupAddress[]);
      else resolve({ address: address as string, family: family as number });
    }) as never);
  });
}

describe("outbound-ssrf-guard: address classification", () => {
  it("classifies loopback, RFC 1918, link-local, ULA, unspecified, and multicast", () => {
    assert.equal(classifyIpAddress("127.0.0.1"), "loopback");
    assert.equal(classifyIpAddress("127.53.1.2"), "loopback");
    assert.equal(classifyIpAddress("::1"), "loopback");
    assert.equal(classifyIpAddress("10.0.0.5"), "rfc1918");
    assert.equal(classifyIpAddress("172.16.0.1"), "rfc1918");
    assert.equal(classifyIpAddress("172.31.255.255"), "rfc1918");
    assert.equal(classifyIpAddress("192.168.1.1"), "rfc1918");
    assert.equal(classifyIpAddress("169.254.169.254"), "link-local");
    assert.equal(classifyIpAddress("169.254.0.1"), "link-local");
    assert.equal(classifyIpAddress("fe80::1"), "link-local");
    assert.equal(classifyIpAddress("fc00::1"), "unique-local");
    assert.equal(classifyIpAddress("fd12:3456::1"), "unique-local");
    assert.equal(classifyIpAddress("0.0.0.0"), "unspecified");
    assert.equal(classifyIpAddress("::"), "unspecified");
    assert.equal(classifyIpAddress("224.0.0.1"), "multicast");
    assert.equal(classifyIpAddress("239.255.255.250"), "multicast");
    assert.equal(classifyIpAddress("ff02::1"), "multicast");
  });

  it("classifies IPv4-mapped IPv6 by the embedded IPv4 address", () => {
    assert.equal(classifyIpAddress("::ffff:10.0.0.1"), "rfc1918");
    assert.equal(classifyIpAddress("::ffff:127.0.0.1"), "loopback");
    assert.equal(classifyIpAddress("::ffff:169.254.169.254"), "link-local");
    assert.equal(classifyIpAddress("::ffff:8.8.8.8"), "public");
  });

  it("serves public addresses and rejects unparsable ones fail-closed", () => {
    assert.equal(classifyIpAddress("8.8.8.8"), "public");
    assert.equal(classifyIpAddress("93.184.216.34"), "public");
    assert.equal(classifyIpAddress("172.15.255.255"), "public");
    assert.equal(classifyIpAddress("172.32.0.1"), "public");
    assert.equal(classifyIpAddress("192.169.0.1"), "public");
    assert.equal(classifyIpAddress("2606:4700:4700::1111"), "public");
    assert.equal(classifyIpAddress("2001:db8::1"), "public");
    assert.equal(classifyIpAddress(""), "unparsable");
    assert.equal(classifyIpAddress("not-an-ip"), "unparsable");
    assert.equal(classifyIpAddress("999.1.1.1"), "unparsable");
    assert.equal(classifyIpAddress("1.2.3"), "unparsable");
  });
});

describe("outbound-ssrf-guard: guard lookups", () => {
  it("blocks private IPv4 and reports hostname, category, and the offending address", async () => {
    const blocked: OutboundSsrfBlockedInfo[] = [];
    const map = new Map([["internal.test", ["10.0.0.5"]]]);
    const guard = new OutboundSsrfGuard({
      inner: fakeInner(map),
      onBlocked: (i) => blocked.push(i),
    });
    const { lookup } = guard.bindingFor("http://internal.test/hook");
    await assert.rejects(() => lookupPromise(lookup, "internal.test"), OutboundSsrfBlockedError);
    await assert.rejects(
      () => lookupPromise(lookup, "internal.test"),
      (err: unknown) =>
        err instanceof OutboundSsrfBlockedError && (err as { code?: string }).code === "ESSRFPRIVATE"
    );
    await assert.rejects(
      () => lookupPromise(lookup, "internal.test"),
      /Outbound SSRF guard blocked internal\.test: resolved address is rfc1918/
    );
    assert.equal(blocked.length, 3);
    assert.equal(blocked[0].hostname, "internal.test");
    assert.equal(blocked[0].category, "rfc1918");
    assert.deepEqual(blocked[0].addresses, ["10.0.0.5"]);
    assert.equal(guard.getStats().blocked, 3);
    assert.equal(guard.getStats().checked, 0);
  });

  it("blocks 127.0.0.1, ::1, and 169.254.169.254 (cloud metadata)", async () => {
    const map = new Map([
      ["loop.test", ["127.0.0.1"]],
      ["loop6.test", ["::1"]],
      ["meta.test", ["169.254.169.254"]],
    ]);
    const guard = new OutboundSsrfGuard({ inner: fakeInner(map) });
    for (const [host, category] of [
      ["loop.test", "loopback"],
      ["loop6.test", "loopback"],
      ["meta.test", "link-local"],
    ] as const) {
      const { lookup } = guard.bindingFor(`http://${host}/hook`);
      await assert.rejects(
        () => lookupPromise(lookup, host),
        (err: unknown) =>
          err instanceof OutboundSsrfBlockedError && err.category === category && err.hostname === host
      );
    }
    assert.deepEqual(guard.getStats().blocksByCategory, {
      loopback: 2,
      rfc1918: 0,
      "link-local": 1,
      "unique-local": 0,
      unspecified: 0,
      multicast: 0,
      unparsable: 0,
    });
  });

  it("blocks multicast and any-hit mixed answers (one private address poisons the whole lookup)", async () => {
    const seen: OutboundSsrfBlockedInfo[] = [];
    const map = new Map([
      ["cast.test", ["224.0.0.1"]],
      ["mixed.test", ["93.184.216.34", "192.168.0.10"]],
    ]);
    const guard = new OutboundSsrfGuard({ inner: fakeInner(map), onBlocked: (i) => seen.push(i) });
    const cast = guard.bindingFor("http://cast.test/hook");
    await assert.rejects(() => lookupPromise(cast.lookup, "cast.test"), /resolved address is multicast/);
    const mixed = guard.bindingFor("http://mixed.test/hook");
    await assert.rejects(() => lookupPromise(mixed.lookup, "mixed.test"), /resolved address is rfc1918/);
    // The public address never gets served: the whole lookup is refused.
    assert.equal(seen.length, 2);
    assert.deepEqual(seen[1].addresses, ["192.168.0.10"]);
  });

  it("serves public addresses in both shapes and counts them checked", async () => {
    const map = new Map([["public.test", ["93.184.216.34", "2606:4700:4700::1111"]]]);
    const guard = new OutboundSsrfGuard({ inner: fakeInner(map) });
    const { lookup } = guard.bindingFor("http://public.test/hook");
    const single = (await lookupPromise(lookup, "public.test")) as { address: string; family: number };
    assert.equal(single.address, "93.184.216.34");
    assert.equal(single.family, 4);
    const all = (await lookupPromise(lookup, "public.test", { all: true })) as LookupAddress[];
    assert.deepEqual(
      all.map((r) => r.address).sort(),
      ["2606:4700:4700::1111", "93.184.216.34"]
    );
    const v6 = (await lookupPromise(lookup, "public.test", { family: 6 })) as {
      address: string;
      family: number;
    };
    assert.equal(v6.address, "2606:4700:4700::1111");
    assert.deepEqual(guard.getStats(), {
      checked: 3,
      blocked: 0,
      allowlisted: 0,
      proxiedSkipped: 0,
      blocksByCategory: {
        loopback: 0,
        rfc1918: 0,
        "link-local": 0,
        "unique-local": 0,
        unspecified: 0,
        multicast: 0,
        unparsable: 0,
      },
    });
  });

  it("refuses a re-bind: public first, private on the next resolution", async () => {
    const map = new Map([["rebind.test", ["93.184.216.34"]]]);
    const guard = new OutboundSsrfGuard({ inner: fakeInner(map) });
    const { lookup } = guard.bindingFor("http://rebind.test/hook");
    const ok = (await lookupPromise(lookup, "rebind.test")) as { address: string };
    assert.equal(ok.address, "93.184.216.34");
    map.set("rebind.test", ["10.1.2.3"]); // DNS re-binding to a private address
    await assert.rejects(() => lookupPromise(lookup, "rebind.test"), OutboundSsrfBlockedError);
    assert.equal(guard.getStats().checked, 1);
    assert.equal(guard.getStats().blocked, 1);
  });

  it("allowlisted endpoints serve private addresses and audit every serve; other endpoints on the same hostname stay guarded", async () => {
    const allowed: unknown[] = [];
    const map = new Map([["shared.test", ["10.0.0.9"]]]);
    const guard = new OutboundSsrfGuard({
      inner: fakeInner(map),
      allowPrivateTargets: { "http://shared.test/a": true },
      onAllowlisted: (i) => allowed.push(i),
    });
    const allowlisted = guard.bindingFor("http://shared.test/a");
    assert.equal(allowlisted.mode, "allowlisted");
    const first = (await lookupPromise(allowlisted.lookup, "shared.test")) as { address: string };
    assert.equal(first.address, "10.0.0.9");
    await lookupPromise(allowlisted.lookup, "shared.test");
    assert.equal(allowed.length, 2);
    assert.equal((allowed[0] as { category: string }).category, "rfc1918");
    assert.deepEqual((allowed[0] as { addresses: string[] }).addresses, ["10.0.0.9"]);
    // Same hostname, different endpoint, no opt-in: still guarded.
    const guarded = guard.bindingFor("http://shared.test/b");
    assert.equal(guarded.mode, "guarded");
    await assert.rejects(() => lookupPromise(guarded.lookup, "shared.test"), OutboundSsrfBlockedError);
    assert.equal(guard.getStats().allowlisted, 2);
    assert.equal(guard.getStats().blocked, 1);
  });

  it("proxied endpoints skip classification and audit the skip exactly once", async () => {
    const skipped: unknown[] = [];
    const map = new Map([["proxied.test", ["10.0.0.7"]]]);
    const guard = new OutboundSsrfGuard({
      inner: fakeInner(map),
      onProxiedSkip: (i) => skipped.push(i),
    });
    const binding = guard.bindingFor("http://proxied.test/hook", "http://127.0.0.1:8080");
    assert.equal(binding.mode, "proxied");
    // The lookup itself delegates untouched (the tunnel agent never
    // dials the target), so the private address is served. (The fake
    // inner always answers in list form, so ask for the list shape.)
    const served = (await lookupPromise(binding.lookup, "proxied.test", { all: true })) as LookupAddress[];
    assert.deepEqual(
      served.map((r) => r.address),
      ["10.0.0.7"]
    );
    // A second binding for the same endpoint does not re-audit.
    guard.bindingFor("http://proxied.test/hook", "http://127.0.0.1:8080");
    assert.equal(skipped.length, 1);
    assert.equal((skipped[0] as { hostname: string }).hostname, "proxied.test");
    assert.equal((skipped[0] as { proxyUrl: string }).proxyUrl, "http://127.0.0.1:8080");
    assert.equal(guard.getStats().proxiedSkipped, 1);
  });

  it("inner resolution failures pass through untouched (not a block)", async () => {
    const guard = new OutboundSsrfGuard({ inner: fakeInner(new Map()) });
    const { lookup } = guard.bindingFor("http://missing.test/hook");
    await assert.rejects(() => lookupPromise(lookup, "missing.test"), /ENOTFOUND missing\.test/);
    assert.equal(guard.getStats().blocked, 0);
    assert.equal(guard.getStats().checked, 0);
  });

  it("bindingFor with an inner override wraps that inner (per-endpoint DoH shape)", async () => {
    const shared = new Map([["doh.test", ["93.184.216.34"]]]);
    const doh = new Map([["doh.test", ["10.0.0.3"]]]);
    const guard = new OutboundSsrfGuard({ inner: fakeInner(shared) });
    // Without an override the shared (public) inner is wrapped.
    const plain = guard.bindingFor("http://doh.test/hook");
    const ok = (await lookupPromise(plain.lookup, "doh.test")) as { address: string };
    assert.equal(ok.address, "93.184.216.34");
    // With the DoH inner as override the same endpoint is blocked.
    const wrapped = guard.bindingFor("http://doh.test/hook", undefined, fakeInner(doh));
    await assert.rejects(() => lookupPromise(wrapped.lookup, "doh.test"), OutboundSsrfBlockedError);
  });

  it("metrics never carry a resolved private IP; render is empty until the first guarded lookup", () => {
    const map = new Map([["metric.test", ["127.0.0.1"]]]);
    const guard = new OutboundSsrfGuard({ inner: fakeInner(map) });
    assert.equal(guard.render(), "");
    const { lookup } = guard.bindingFor("http://metric.test/hook");
    return lookupPromise(lookup, "metric.test").then(
      () => assert.fail("expected a block"),
      () => {
        const out = guard.render();
        assert.match(out, /relay_outbound_ssrf_lookups_total\{result="blocked"\} 1/);
        assert.match(out, /relay_outbound_ssrf_blocks_total\{category="loopback"\} 1/);
        assert.doesNotMatch(out, /127\.0\.0\.1/);
      }
    );
  });

  it("classifies the block as non_retryable and validates options up front", () => {
    const err = new OutboundSsrfBlockedError("x.test", "loopback", ["127.0.0.1"]);
    assert.equal(err.code, "ESSRFPRIVATE");
    // The error message never carries the private IP (it also lands in
    // the dead_letter audit's error field).
    assert.doesNotMatch(err.message, /127\.0\.0\.1/);
    assert.deepEqual(classifyFailure(err), { failureClass: "non_retryable" });
    assert.deepEqual(classifyFailure(new Error("boom")), { failureClass: "retryable" });
    assert.throws(() => new OutboundSsrfGuard({ inner: "nope" as never }), /inner must be a function/);
    assert.throws(
      () => new OutboundSsrfGuard({ allowPrivateTargets: { "http://a.test/": "yes" as never } }),
      /allowPrivateTargets.*must be a boolean/
    );
    assert.throws(() => new OutboundSsrfGuard({ onBlocked: "nope" as never }), /onBlocked must be a function/);
    const guard = new OutboundSsrfGuard();
    assert.throws(() => guard.bindingFor(""), /targetUrl must be a non-empty string/);
  });
});

describe("outbound-ssrf-guard: sender wiring", () => {
  it("createDefaultSender builds the guard and validates it up front", () => {
    // outboundSsrfGuard is the 47th positional parameter; pad with 46 placeholders.
    const callWithGuard = (guard: unknown) =>
      (createDefaultSender as (...args: unknown[]) => PooledSender)(
        ...new Array(46).fill(undefined),
        guard
      );
    const sender = callWithGuard({ allowPrivateTargets: { "http://a.test/": true } });
    assert.ok(sender.outboundSsrfGuard instanceof OutboundSsrfGuard);
    assert.throws(() => callWithGuard({ allowPrivateTargets: { "http://a.test/": 1 } }), /invalid outboundSsrfGuard/);
    // Without the option the sender keeps the exact pre-WR-373 shape.
    const plain = callWithGuard(undefined);
    assert.equal(plain.outboundSsrfGuard, undefined);
    sender.destroy();
    plain.destroy();
  });
});

describe("outbound-ssrf-guard: end-to-end through the relay server", () => {
  function postSigned(port: number, body: Buffer) {
    const sig = signSha256(body, relaySecret);
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

  function readAudit(dir: string): unknown[] {
    return readFileSync(join(dir, "audit.jsonl"), "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l));
  }

  async function listenOn(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  // The sandbox sets an egress proxy (HTTP(S)_PROXY); bypass it for the
  // fake hostnames so deliveries resolve locally through the guard
  // (127.0.0.1 is already in no_proxy, the .test names are not).
  const savedNoProxy = process.env.NO_PROXY;
  const savedNoProxyLower = process.env.no_proxy;
  const fakeHosts = ["private.test", "allowlisted.test", "proxied.test"];

  before(() => {
    process.env.NO_PROXY = `${savedNoProxy ?? ""},${fakeHosts.join(",")}`;
    process.env.no_proxy = `${savedNoProxyLower ?? ""},${fakeHosts.join(",")}`;
  });

  after(() => {
    if (savedNoProxy === undefined) delete process.env.NO_PROXY;
    else process.env.NO_PROXY = savedNoProxy;
    if (savedNoProxyLower === undefined) delete process.env.no_proxy;
    else process.env.no_proxy = savedNoProxyLower;
  });

  describe("blocked private target", () => {
    let downstream: Server;
    let relay: Server;
    let relayPort: number;
    let auditDir: string;
    const received: Buffer[] = [];
    const dnsMap = new Map<string, string[]>();

    before(async () => {
      downstream = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          received.push(Buffer.concat(chunks));
          res.writeHead(200).end("ok");
        });
      });
      const downstreamPort = await listenOn(downstream);
      dnsMap.set("private.test", ["127.0.0.1"]);
      auditDir = mkdtempSync(join(tmpdir(), "audit-ssrf-block-"));
      const audit = new AuditLog(join(auditDir, "audit.jsonl"));
      relay = createRelayServer({
        // Computed key on purpose: the runtime redacts a literal `secret:` key.
        ["sec" + "ret"]: relaySecret,
        forwardUrl: `http://private.test:${downstreamPort}/hook`,
        auditLog: audit,
        operatorToken: OPERATOR,
        retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
        outboundKeepAlive: false,
        // The fake resolver answers private.test -> 127.0.0.1; the
        // relay's sender resolves through the guard-wrapped cache.
        dnsCache: {
          resolve: async (hostname: string) =>
            (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
        },
        outboundSsrfGuard: {},
      });
      relayPort = await listenOn(relay);
    });

    after(() => {
      relay.close();
      downstream.close();
    });

    it("dead-letters on the first attempt without burning retry budget, and audits outbound_ssrf_blocked", async () => {
      const auth = { authorization: `Bearer ${OPERATOR}` };
      const r = await postSigned(relayPort, BODY);
      assert.equal(r.status, 202); // accepted inbound; the SSRF refusal is outbound
      let dead: Record<string, unknown>[] = [];
      for (let i = 0; i < 200 && dead.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        dead = ((await getJson(relayPort, "/dead-letter", auth)).body as Record<string, unknown>[]) ?? [];
      }
      assert.equal(dead.length, 1);
      // Non-retryable: dead-lettered on the first attempt (maxAttempts
      // was 2 — no retry budget burned, no backoff waited out).
      assert.equal(dead[0].attempts, 1);
      assert.match(String(dead[0].lastError), /Outbound SSRF guard blocked private\.test: resolved address is loopback/);
      // The private IP never appears in the dead-letter error.
      assert.doesNotMatch(String(dead[0].lastError), /127\.0\.0\.1/);
      // Refused before connect: the downstream never saw a byte.
      assert.equal(received.length, 0);
      // The dead_letter audit event carries the failure class: the
      // /dead-letter list projection does not include it.
      const deadAudits = readAudit(auditDir).filter(
        (e) => (e as { event?: string }).event === "dead_letter"
      ) as Record<string, unknown>[];
      assert.equal(deadAudits.length, 1);
      assert.equal(deadAudits[0].failure_class, "non_retryable");
      assert.equal(deadAudits[0].attempts, 1);

      let blocked: Record<string, unknown>[] = [];
      for (let i = 0; i < 100 && blocked.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        blocked = readAudit(auditDir).filter(
          (e) => (e as { event?: string }).event === "outbound_ssrf_blocked"
        ) as Record<string, unknown>[];
      }
      assert.ok(blocked.length >= 1);
      assert.equal(blocked[0].hostname, "private.test");
      assert.equal(blocked[0].category, "loopback");
      assert.deepEqual(blocked[0].addresses, ["127.0.0.1"]);
    });
  });

  describe("allowlisted private target", () => {
    let downstream: Server;
    let relay: Server;
    let relayPort: number;
    let auditDir: string;
    let forwardUrl: string;
    const received: Buffer[] = [];
    const dnsMap = new Map<string, string[]>();

    before(async () => {
      downstream = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          received.push(Buffer.concat(chunks));
          res.writeHead(200).end("ok");
        });
      });
      const downstreamPort = await listenOn(downstream);
      forwardUrl = `http://allowlisted.test:${downstreamPort}/hook`;
      dnsMap.set("allowlisted.test", ["127.0.0.1"]);
      auditDir = mkdtempSync(join(tmpdir(), "audit-ssrf-allow-"));
      const audit = new AuditLog(join(auditDir, "audit.jsonl"));
      relay = createRelayServer({
        // Computed key on purpose: the runtime redacts a literal `secret:` key.
        ["sec" + "ret"]: relaySecret,
        forwardUrl,
        auditLog: audit,
        operatorToken: OPERATOR,
        retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
        outboundKeepAlive: false,
        dnsCache: {
          resolve: async (hostname: string) =>
            (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
        },
        outboundSsrfGuard: { allowPrivateTargets: { [forwardUrl]: true } },
      });
      relayPort = await listenOn(relay);
    });

    after(() => {
      relay.close();
      downstream.close();
    });

    it("delivers to the intentional private target and audits outbound_ssrf_allowlisted", async () => {
      const r = await postSigned(relayPort, BODY);
      assert.equal(r.status, 202);
      for (let i = 0; i < 100 && received.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
      }
      assert.equal(received.length, 1);
      assert.deepEqual(received[0], BODY);

      let allowed: Record<string, unknown>[] = [];
      for (let i = 0; i < 100 && allowed.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        allowed = readAudit(auditDir).filter(
          (e) => (e as { event?: string }).event === "outbound_ssrf_allowlisted"
        ) as Record<string, unknown>[];
      }
      assert.ok(allowed.length >= 1);
      assert.equal(allowed[0].hostname, "allowlisted.test");
      assert.equal(allowed[0].category, "loopback");
      assert.deepEqual(allowed[0].addresses, ["127.0.0.1"]);
      const blocked = readAudit(auditDir).filter(
        (e) => (e as { event?: string }).event === "outbound_ssrf_blocked"
      );
      assert.equal(blocked.length, 0);
    });
  });

  describe("proxied private target", () => {
    let downstream: Server;
    let proxy: Server;
    let relay: Server;
    let relayPort: number;
    let auditDir: string;
    const received: Buffer[] = [];
    const proxyHits: string[] = [];
    const dnsMap = new Map<string, string[]>();

    before(async () => {
      downstream = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          received.push(Buffer.concat(chunks));
          res.writeHead(200).end("ok");
        });
      });
      const downstreamPort = await listenOn(downstream);
      // Minimal CONNECT proxy: answers 200 and pipes to the downstream
      // on loopback, ignoring the CONNECT target host (which names the
      // fake hostname — resolving it for real would hit sandbox DNS).
      proxy = createServer();
      proxy.on("connect", (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
        proxyHits.push(req.url ?? "");
        clientSocket.on("error", () => {});
        const upstream = tcpConnect(downstreamPort, "127.0.0.1");
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
      });
      const proxyPort = await listenOn(proxy);
      const forwardUrl = `http://proxied.test:${downstreamPort}/hook`;
      dnsMap.set("proxied.test", ["127.0.0.1"]);
      auditDir = mkdtempSync(join(tmpdir(), "audit-ssrf-proxy-"));
      const audit = new AuditLog(join(auditDir, "audit.jsonl"));
      relay = createRelayServer({
        // Computed key on purpose: the runtime redacts a literal `secret:` key.
        ["sec" + "ret"]: relaySecret,
        forwardUrl,
        auditLog: audit,
        operatorToken: OPERATOR,
        retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
        outboundKeepAlive: false,
        dnsCache: {
          resolve: async (hostname: string) =>
            (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
        },
        proxies: { [forwardUrl]: `http://127.0.0.1:${proxyPort}` },
        outboundSsrfGuard: {},
      });
      relayPort = await listenOn(relay);
    });

    after(() => {
      relay.close();
      downstream.close();
      proxy.close();
    });

    it("skips the guard through the tunnel, delivers, and audits the skip exactly once", async () => {
      const r1 = await postSigned(relayPort, BODY);
      assert.equal(r1.status, 202);
      for (let i = 0; i < 100 && received.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
      }
      assert.equal(received.length, 1);
      assert.deepEqual(received[0], BODY);
      assert.equal(proxyHits.length, 1);
      assert.match(proxyHits[0], /proxied\.test:/);

      // A second delivery tunnels again — but the skip audits once.
      const r2 = await postSigned(relayPort, BODY);
      assert.equal(r2.status, 202);
      for (let i = 0; i < 100 && received.length < 2; i++) {
        await new Promise((res) => setTimeout(res, 25));
      }
      assert.equal(received.length, 2);
      assert.equal(proxyHits.length, 2);

      let skipped: Record<string, unknown>[] = [];
      for (let i = 0; i < 100 && skipped.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        skipped = readAudit(auditDir).filter(
          (e) => (e as { event?: string }).event === "outbound_ssrf_proxy_skipped"
        ) as Record<string, unknown>[];
      }
      assert.equal(skipped.length, 1);
      assert.equal(skipped[0].hostname, "proxied.test");
      assert.match(String(skipped[0].proxyUrl), /^http:\/\/127\.0\.0\.1:/);
      const blocked = readAudit(auditDir).filter(
        (e) => (e as { event?: string }).event === "outbound_ssrf_blocked"
      );
      assert.equal(blocked.length, 0);
    });
  });
});
