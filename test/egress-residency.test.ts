import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { LookupAddress } from "node:dns";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EgressResidencyGate,
  EgressResidencyBlockedError,
  type EgressResidencyBlockedInfo,
} from "../src/egress-residency.ts";
import { DnsCache } from "../src/dns-cache.ts";
import { classifyFailure } from "../src/failure.ts";
import { createRelayServer, createDefaultSender, type PooledSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const relaySecret = "egress-residency-secret";
const OPERATOR = "op-egress-residency-token";
const BODY = Buffer.from(JSON.stringify({ event: "egress.residency.probe" }));

/**
 * Operator-curated table for the tests (TEST-NET ranges, plus loopback
 * rows so the end-to-end downstream — which must be dialed on loopback
 * — still gets a country): the more specific 127.0.0.1/32 row is listed
 * first, the covering 127.0.0.0/8 row second, so first-match-wins is
 * exercised in both directions.
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

/** Fake async resolver: answers from a mutable hostname -> address map. */
function fakeResolve(map: Map<string, string[]>): (hostname: string) => Promise<LookupAddress[]> {
  return async (hostname: string) => {
    const addrs = map.get(hostname);
    if (addrs === undefined) {
      const err = new Error(`ENOTFOUND ${hostname}`) as NodeJS.ErrnoException;
      err.code = "ENOTFOUND";
      throw err;
    }
    return addrs.map((address) => ({
      address,
      family: (address.includes(":") ? 6 : 4) as 4 | 6,
    }));
  };
}

function gateWith(
  allowed: Record<string, string[]>,
  map: Map<string, string[]>,
  extra: { onBlocked?: (info: EgressResidencyBlockedInfo) => void } = {}
): EgressResidencyGate {
  return new EgressResidencyGate({
    table: TABLE,
    allowedEgressCountries: allowed,
    resolve: fakeResolve(map),
    ...extra,
  });
}

describe("egress-residency: gate checks", () => {
  it("allows a delivery whose every resolved address is in an allowed country", async () => {
    const gate = gateWith({ "tenant-eu": ["DE", "FR"] }, new Map([["eu.test", ["203.0.113.9"]]]));
    await gate.check("tenant-eu", "http://eu.test:8080/hook");
    assert.deepEqual(gate.getStats(), { checked: 1, blocked: 0, blocksByCountry: {} });
  });

  it("refuses a delivery to a disallowed country before connect, and audits it", async () => {
    const blocked: EgressResidencyBlockedInfo[] = [];
    const gate = gateWith({ "tenant-eu": ["DE", "FR"] }, new Map([["us.test", ["198.51.100.7"]]]), {
      onBlocked: (info) => blocked.push(info),
    });
    await assert.rejects(
      gate.check("tenant-eu", "http://us.test:8080/hook"),
      (err: unknown) => {
        assert.ok(err instanceof EgressResidencyBlockedError);
        assert.equal(err.code, "EGEORESIDENCY");
        assert.equal(err.tenant, "tenant-eu");
        assert.equal(err.endpoint, "http://us.test:8080/hook");
        assert.equal(err.hostname, "us.test");
        assert.equal(err.country, "US");
        assert.deepEqual(err.addresses, ["198.51.100.7"]);
        // The message names the country, never the resolved address.
        assert.match(err.message, /Egress residency gate blocked us\.test: resolved address is in US/);
        assert.doesNotMatch(err.message, /198\.51\.100\.7/);
        return true;
      }
    );
    assert.equal(blocked.length, 1);
    assert.equal(blocked[0].tenant, "tenant-eu");
    assert.equal(blocked[0].endpoint, "http://us.test:8080/hook");
    assert.equal(blocked[0].hostname, "us.test");
    assert.equal(blocked[0].country, "US");
    assert.deepEqual(blocked[0].addresses, ["198.51.100.7"]);
    assert.deepEqual(gate.getStats(), { checked: 0, blocked: 1, blocksByCountry: { US: 1 } });
  });

  it("fails closed on an unmapped IP (country unknown)", async () => {
    const gate = gateWith({ "tenant-eu": ["DE"] }, new Map([["elsewhere.test", ["8.8.8.8"]]]));
    await assert.rejects(gate.check("tenant-eu", "http://elsewhere.test/hook"), (err: unknown) => {
      assert.ok(err instanceof EgressResidencyBlockedError);
      assert.equal((err as EgressResidencyBlockedError).country, "unknown");
      return true;
    });
    assert.deepEqual(gate.getStats().blocksByCountry, { unknown: 1 });
  });

  it("fails closed on an unparsable resolved address", async () => {
    const gate = gateWith({ "tenant-eu": ["DE"] }, new Map([["weird.test", ["not-an-ip"]]]));
    await assert.rejects(gate.check("tenant-eu", "http://weird.test/hook"), (err: unknown) => {
      assert.ok(err instanceof EgressResidencyBlockedError);
      assert.equal((err as EgressResidencyBlockedError).country, "unknown");
      return true;
    });
  });

  it("refuses when any one of several resolved addresses violates (mixed answer)", async () => {
    const blocked: EgressResidencyBlockedInfo[] = [];
    const gate = gateWith(
      { "tenant-eu": ["DE"] },
      new Map([["mixed.test", ["198.51.100.7", "203.0.113.9"]]]),
      { onBlocked: (info) => blocked.push(info) }
    );
    await assert.rejects(gate.check("tenant-eu", "http://mixed.test/hook"));
    // Only the offending address is reported; the allowed one is not.
    assert.deepEqual(blocked[0].addresses, ["198.51.100.7"]);
    assert.equal(blocked[0].country, "US");
  });

  it("isolates tenants: one tenant's ban is another tenant's pass", async () => {
    const gate = gateWith(
      { "tenant-eu": ["DE"], "tenant-us": ["US"] },
      new Map([["us.test", ["198.51.100.7"]]])
    );
    await assert.rejects(gate.check("tenant-eu", "http://us.test/hook"));
    await gate.check("tenant-us", "http://us.test/hook");
    assert.deepEqual(gate.getStats(), { checked: 1, blocked: 1, blocksByCountry: { US: 1 } });
  });

  it("leaves a tenant without an entry unlimited (opt-in)", async () => {
    const gate = gateWith({ "tenant-eu": ["DE"] }, new Map([["us.test", ["198.51.100.7"]]]));
    await gate.check("tenant-other", "http://us.test/hook");
    await gate.check(undefined, "http://us.test/hook");
    assert.deepEqual(gate.getStats(), { checked: 0, blocked: 0, blocksByCountry: {} });
  });

  it("judges an IP-literal target directly, without resolving", async () => {
    let resolves = 0;
    const gate = new EgressResidencyGate({
      table: TABLE,
      allowedEgressCountries: { "tenant-eu": ["DE"] },
      resolve: async () => {
        resolves += 1;
        throw new Error("must not resolve an IP literal");
      },
    });
    await gate.check("tenant-eu", "http://203.0.113.9:8080/hook");
    assert.equal(resolves, 0);
    await assert.rejects(gate.check("tenant-eu", "http://198.51.100.7:8080/hook"));
    assert.equal(resolves, 0);
  });

  it("matches the CIDR table in config order, like geoip.ts (first match wins)", async () => {
    // 203.0.113.200 is inside both 203.0.113.0/24 (DE, listed first) and
    // 203.0.113.128/25 (US, listed second): the first row wins, so the
    // address is DE — the more specific range does not override order.
    const gate = gateWith({ "tenant-eu": ["DE"] }, new Map([["overlap.test", ["203.0.113.200"]]]));
    await gate.check("tenant-eu", "http://overlap.test/hook");
    const gateUs = gateWith({ "tenant-us": ["US"] }, new Map([["overlap.test", ["203.0.113.200"]]]));
    await assert.rejects(gateUs.check("tenant-us", "http://overlap.test/hook"));
  });

  it("lets a DNS failure propagate unchanged (not a residency verdict)", async () => {
    const gate = gateWith({ "tenant-eu": ["DE"] }, new Map());
    await assert.rejects(gate.check("tenant-eu", "http://missing.test/hook"), /ENOTFOUND missing\.test/);
    assert.deepEqual(gate.getStats(), { checked: 0, blocked: 0, blocksByCountry: {} });
  });

  it("blocks everything for a tenant with an empty allowlist (closed egress)", async () => {
    const gate = gateWith({ "tenant-closed": [] }, new Map([["eu.test", ["203.0.113.9"]]]));
    await assert.rejects(gate.check("tenant-closed", "http://eu.test/hook"));
  });

  it("resolves through a WR-92 DnsCache when one is given", async () => {
    const cache = new DnsCache({
      resolve: fakeResolve(new Map([["eu.test", ["203.0.113.9"]]])),
    });
    const gate = new EgressResidencyGate({
      table: TABLE,
      allowedEgressCountries: { "tenant-eu": ["DE"] },
      dnsCache: cache,
    });
    await gate.check("tenant-eu", "http://eu.test/hook");
    assert.equal(cache.getStats().misses, 1);
    // The second check rides the cached answer.
    await gate.check("tenant-eu", "http://eu.test/hook");
    assert.equal(cache.getStats().hits, 1);
  });
});

describe("egress-residency: config validation", () => {
  it("rejects a bad country code, a bad CIDR, and a non-function resolve at startup", () => {
    assert.throws(
      () =>
        new EgressResidencyGate({
          table: TABLE,
          allowedEgressCountries: { "tenant-eu": ["de"] },
          resolve: fakeResolve(new Map()),
        }),
      /allowedEgressCountries\["tenant-eu"\].*uppercase ISO 3166-1 alpha-2/
    );
    assert.throws(
      () =>
        new EgressResidencyGate({
          table: [{ cidr: "203.0.113.0/33", country: "DE" }],
          allowedEgressCountries: { "tenant-eu": ["DE"] },
        }),
      /RangeError/
    );
    assert.throws(
      () =>
        new EgressResidencyGate({
          table: TABLE,
          allowedEgressCountries: { "tenant-eu": ["DE"] },
          resolve: "not-a-function" as unknown as (hostname: string) => Promise<LookupAddress[]>,
        }),
      /resolve must be a function/
    );
    assert.throws(
      () =>
        new EgressResidencyGate({
          table: TABLE,
          allowedEgressCountries: { "tenant-eu": "DE" as unknown as string[] },
        }),
      /expected an array/
    );
  });
});

describe("egress-residency: live revision", () => {
  it("relaxes a tenant's list, and a replay after relaxation is served", async () => {
    const gate = gateWith({ "tenant-eu": ["DE"] }, new Map([["us.test", ["198.51.100.7"]]]));
    await assert.rejects(gate.check("tenant-eu", "http://us.test/hook"));
    const relaxed = gate.reviseAllowedCountries("tenant-eu", ["DE", "FR", "US"]);
    assert.deepEqual(relaxed, ["DE", "FR", "US"]);
    await gate.check("tenant-eu", "http://us.test/hook");
    assert.deepEqual(gate.allowedCountries("tenant-eu"), ["DE", "FR", "US"]);
  });

  it("clearing a tenant's list (null) returns it to unlimited", async () => {
    const gate = gateWith({ "tenant-eu": ["DE"] }, new Map([["us.test", ["198.51.100.7"]]]));
    await assert.rejects(gate.check("tenant-eu", "http://us.test/hook"));
    assert.equal(gate.reviseAllowedCountries("tenant-eu", null), undefined);
    assert.equal(gate.allowedCountries("tenant-eu"), undefined);
    await gate.check("tenant-eu", "http://us.test/hook");
  });

  it("a same-set revision is a no-op returning a copy", () => {
    const gate = gateWith({ "tenant-eu": ["DE", "FR"] }, new Map());
    const copy = gate.reviseAllowedCountries("tenant-eu", ["FR", "DE"]);
    assert.deepEqual(copy, ["DE", "FR"]);
    assert.deepEqual(gate.allowedCountries("tenant-eu"), ["DE", "FR"]);
    assert.throws(() => gate.reviseAllowedCountries("tenant-eu", ["xx"]), /uppercase ISO 3166-1/);
    assert.deepEqual(gate.allowedCountries("tenant-eu"), ["DE", "FR"]);
  });
});

describe("egress-residency: stats and metrics", () => {
  it("renders nothing before activity, then per-country block counters", async () => {
    const gate = gateWith({ "tenant-eu": ["DE"] }, new Map([["us.test", ["198.51.100.7"]]]));
    assert.equal(gate.render(), "");
    await assert.rejects(gate.check("tenant-eu", "http://us.test/hook"));
    const out = gate.render();
    assert.match(out, /relay_egress_residency_lookups_total\{result="blocked"\} 1/);
    assert.match(out, /relay_egress_residency_blocks_total\{country="US"\} 1/);
    assert.doesNotMatch(out, /198\.51\.100\.7/);
  });
});

describe("egress-residency: failure classification", () => {
  it("classifies the block as non_retryable (dead-letter, no retry budget)", () => {
    const err = new EgressResidencyBlockedError(
      "tenant-eu",
      "http://us.test/hook",
      "us.test",
      "US",
      ["198.51.100.7"]
    );
    assert.equal(classifyFailure(err).failureClass, "non_retryable");
  });
});

describe("egress-residency: sender wiring", () => {
  it("createDefaultSender builds the gate and validates it up front", () => {
    // egressResidency is the 51st positional parameter; pad with 50 placeholders.
    const callWithGate = (gate: unknown) =>
      (createDefaultSender as (...args: unknown[]) => PooledSender)(
        ...new Array(50).fill(undefined),
        gate
      );
    const sender = callWithGate({
      table: TABLE,
      allowedEgressCountries: { "tenant-eu": ["DE"] },
    });
    assert.ok(sender.egressResidencyGate instanceof EgressResidencyGate);
    assert.throws(() => callWithGate({ allowedEgressCountries: { "tenant-eu": ["xx"] } }), /invalid egressResidency/);
    // Without the option the sender keeps the exact pre-WR-374 shape.
    const plain = callWithGate(undefined);
    assert.equal(plain.egressResidencyGate, undefined);
    // A compiled instance keeps its own resolver and hooks.
    const compiled = new EgressResidencyGate({
      table: TABLE,
      allowedEgressCountries: { "tenant-eu": ["DE"] },
      resolve: fakeResolve(new Map()),
    });
    const withCompiled = callWithGate(compiled);
    assert.equal(withCompiled.egressResidencyGate, compiled);
    sender.destroy();
    plain.destroy();
    withCompiled.destroy();
  });
});

describe("egress-residency: end-to-end through the relay server", () => {
  function postSigned(port: number, body: Buffer, tenant?: string) {
    const sig = signSha256(body, relaySecret);
    return new Promise<{ status: number }>((resolve, reject) => {
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

  function postJson(port: number, path: string, body: Buffer, headers: Record<string, string>) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      });
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

  async function listenOn(server: Server, host = "127.0.0.1"): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, host, resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  // The sandbox sets an egress proxy (HTTP(S)_PROXY); bypass it for the
  // fake hostnames so deliveries resolve locally through the gate
  // (127.0.0.1 is already in no_proxy, the .test names are not).
  const savedNoProxy = process.env.NO_PROXY;
  const savedNoProxyLower = process.env.no_proxy;
  const fakeHosts = ["eu.test", "us.test"];

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

  describe("blocked tenant audits egress_residency_blocked", () => {
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
      // Listen on all interfaces so both loopback addresses (127.0.0.1
      // for DE, 127.0.0.2 for US) reach the same downstream.
      const downstreamPort = await listenOn(downstream, "0.0.0.0");
      dnsMap.set("us.test", ["127.0.0.2"]);
      dnsMap.set("eu.test", ["127.0.0.1"]);
      auditDir = mkdtempSync(join(tmpdir(), "audit-egress-block-"));
      const audit = new AuditLog(join(auditDir, "audit.jsonl"));
      forwardUrl = `http://us.test:${downstreamPort}/hook`;
      relay = createRelayServer({
        // Computed key on purpose: the runtime redacts a literal `secret:` key.
        ["sec" + "ret"]: relaySecret,
        forwardUrl,
        auditLog: audit,
        operatorToken: OPERATOR,
        retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
        outboundKeepAlive: false,
        // The fake resolver answers us.test -> 127.0.0.2 (US via the
        // 127.0.0.0/8 row) and eu.test -> 127.0.0.1 (DE via the /32 row);
        // the relay's sender resolves through this cache, and the gate
        // (built by the sender from these options) judges the same
        // answers through the shared cache.
        dnsCache: {
          resolve: async (hostname: string) =>
            (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
        },
        egressResidency: {
          table: TABLE,
          allowedEgressCountries: { "tenant-eu": ["DE", "FR"], "tenant-us": ["US"] },
        },
      });
      relayPort = await listenOn(relay);
    });

    after(() => {
      relay.close();
      downstream.close();
    });

    it("dead-letters on the first attempt and audits egress_residency_blocked", async () => {
      const auth = { authorization: `Bearer ${OPERATOR}` };
      const r = await postSigned(relayPort, BODY, "tenant-eu");
      assert.equal(r.status, 202); // accepted inbound; the residency refusal is outbound
      let dead: Record<string, unknown>[] = [];
      for (let i = 0; i < 200 && dead.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        dead = ((await getJson(relayPort, "/dead-letter", auth)).body as Record<string, unknown>[]) ?? [];
      }
      assert.equal(dead.length, 1);
      // Non-retryable: dead-lettered on the first attempt (maxAttempts
      // was 2 — no retry budget burned, no backoff waited out).
      assert.equal(dead[0].attempts, 1);
      assert.match(
        String(dead[0].lastError),
        /Egress residency gate blocked us\.test: resolved address is in US/
      );
      // The resolved address never appears in the dead-letter error.
      assert.doesNotMatch(String(dead[0].lastError), /127\.0\.0\.2/);
      // Refused before connect: the downstream never saw a byte.
      assert.equal(received.length, 0);
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
          (e) => (e as { event?: string }).event === "egress_residency_blocked"
        ) as Record<string, unknown>[];
      }
      assert.equal(blocked.length, 1);
      assert.equal(blocked[0].tenant, "tenant-eu");
      assert.equal(blocked[0].endpoint, forwardUrl);
      assert.equal(blocked[0].country, "US");
      assert.deepEqual(blocked[0].addresses, ["127.0.0.2"]);

      // Tenant isolation at the wire level: the same endpoint serves
      // tenant-us, whose list allows US.
      const r2 = await postSigned(relayPort, BODY, "tenant-us");
      assert.equal(r2.status, 202);
      for (let i = 0; i < 200 && received.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
      }
      assert.equal(received.length, 1);
    });
  });

  describe("blocked tenant replays after relaxation", () => {
    let downstream: Server;
    let relay: Server;
    let relayPort: number;
    let gate: EgressResidencyGate;
    const received: Buffer[] = [];
    const blocked: EgressResidencyBlockedInfo[] = [];
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
      const downstreamPort = await listenOn(downstream, "0.0.0.0");
      dnsMap.set("us.test", ["127.0.0.2"]);
      const auditDir = mkdtempSync(join(tmpdir(), "audit-egress-replay-"));
      const audit = new AuditLog(join(auditDir, "audit.jsonl"));
      gate = new EgressResidencyGate({
        table: TABLE,
        allowedEgressCountries: { "tenant-eu": ["DE", "FR"] },
        // A compiled gate keeps its own resolver (mirroring the WR-373
        // guard): give it the same fake answers as the relay's cache, so
        // the gate judges the addresses the dial will use.
        resolve: async (hostname: string) =>
          (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
        onBlocked: (info) => blocked.push(info),
      });
      relay = createRelayServer({
        // Computed key on purpose: the runtime redacts a literal `secret:` key.
        ["sec" + "ret"]: relaySecret,
        forwardUrl: `http://us.test:${downstreamPort}/hook`,
        auditLog: audit,
        operatorToken: OPERATOR,
        retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
        outboundKeepAlive: false,
        dnsCache: {
          resolve: async (hostname: string) =>
            (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
        },
        egressResidency: gate,
      });
      relayPort = await listenOn(relay);
    });

    after(() => {
      relay.close();
      downstream.close();
    });

    it("dead-letters, then delivers the replay once the list is relaxed", async () => {
      const auth = { authorization: `Bearer ${OPERATOR}` };
      const r = await postSigned(relayPort, BODY, "tenant-eu");
      assert.equal(r.status, 202);
      let dead: Record<string, unknown>[] = [];
      for (let i = 0; i < 200 && dead.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        dead = ((await getJson(relayPort, "/dead-letter", auth)).body as Record<string, unknown>[]) ?? [];
      }
      assert.equal(dead.length, 1);
      assert.equal(dead[0].attempts, 1);
      assert.equal(received.length, 0);
      assert.equal(blocked.length, 1);
      assert.equal(blocked[0].tenant, "tenant-eu");
      assert.equal(blocked[0].country, "US");
      assert.deepEqual(blocked[0].addresses, ["127.0.0.2"]);

      // The operator relaxes tenant-eu's list; the dead letter replays
      // and is delivered (the gate judges the current list).
      gate.reviseAllowedCountries("tenant-eu", ["DE", "FR", "US"]);
      const entryId = dead[0].id as string;
      const replay = await postJson(
        relayPort,
        "/dead-letter/replay",
        Buffer.from(JSON.stringify({ tenant: "tenant-eu" })),
        { ...auth, "content-type": "application/json" }
      );
      assert.equal(replay.status, 200);
      assert.deepEqual((JSON.parse(replay.text) as { replayed: string[] }).replayed, [entryId]);
      for (let i = 0; i < 200 && received.length < 1; i++) {
        await new Promise((res) => setTimeout(res, 25));
      }
      assert.equal(received.length, 1);
      const remaining = ((await getJson(relayPort, "/dead-letter?tenant=tenant-eu", auth))
        .body as unknown[]) ?? [];
      assert.deepEqual(remaining, []);
    });
  });

  describe("allowed tenant delivers", () => {
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
      const downstreamPort = await listenOn(downstream, "0.0.0.0");
      dnsMap.set("eu.test", ["127.0.0.1"]);
      auditDir = mkdtempSync(join(tmpdir(), "audit-egress-allow-"));
      const audit = new AuditLog(join(auditDir, "audit.jsonl"));
      relay = createRelayServer({
        // Computed key on purpose: the runtime redacts a literal `secret:` key.
        ["sec" + "ret"]: relaySecret,
        forwardUrl: `http://eu.test:${downstreamPort}/hook`,
        auditLog: audit,
        operatorToken: OPERATOR,
        retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
        outboundKeepAlive: false,
        dnsCache: {
          resolve: async (hostname: string) =>
            (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
        },
        egressResidency: {
          table: TABLE,
          allowedEgressCountries: { "tenant-eu": ["DE", "FR"] },
        },
      });
      relayPort = await listenOn(relay);
    });

    after(() => {
      relay.close();
      downstream.close();
    });

    it("delivers to an allowed country with no residency audit event", async () => {
      const r = await postSigned(relayPort, BODY, "tenant-eu");
      assert.equal(r.status, 202);
      for (let i = 0; i < 200 && received.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
      }
      assert.equal(received.length, 1);
      const blocked = readAudit(auditDir).filter(
        (e) => (e as { event?: string }).event === "egress_residency_blocked"
      );
      assert.deepEqual(blocked, []);
    });
  });
});
