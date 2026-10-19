import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  GeoIpInboundPolicy,
  assertValidGeoIpOptions,
  compileGeoIpTable,
  lookupGeoCountry,
  resolveGeoVerdict,
  type GeoIpOptions,
  type GeoPolicy,
} from "../src/geoip.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// Sample config uses the RFC 5737 documentation ranges (203.0.113.0/24,
// 198.51.100.0/24, 192.0.2.0/24) and RFC 3849 (2001:db8::/32) — these are
// placeholder mappings for tests only, explicitly not real GeoIP data
// (WR-158 is config-only by design).
const US_ROW = { cidr: "203.0.113.0/24", country: "US" };
const CN_ROW = { cidr: "198.51.100.0/24", country: "CN" };
const DE_ROW = { cidr: "192.0.2.0/24", country: "DE" };
const JP_ROW = { cidr: "2001:db8::/32", country: "JP" };

const geoTestSecret = "geo-secret";
const BODY = Buffer.from(JSON.stringify({ event: "geo.probe" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: { "x-signature": signSha256(body, geoTestSecret), ...headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          r.destroy();
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
        });
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

/** Declared Content-Length larger than maxBodyBytes, tiny actual body. */
function postDeclaredLength(port: number, path: string, declaredLength: number) {
  return new Promise<{ status: number }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: {
          "x-signature": signSha256(BODY, geoTestSecret),
          "content-length": String(declaredLength),
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => {
          r.destroy();
          resolve({ status: res.statusCode ?? 0 });
        });
      }
    );
    r.on("error", reject);
    r.write(BODY); // deliberately short of the declared length
  });
}

function readRejected(dir: string): Array<Record<string, unknown>> {
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === "rejected");
}

describe("geoip: table compile and lookup", () => {
  it("matches rows and returns the country; unmapped addresses return undefined", () => {
    const table = compileGeoIpTable([US_ROW, CN_ROW, DE_ROW]);
    assert.equal(lookupGeoCountry("203.0.113.7", table), "US");
    assert.equal(lookupGeoCountry("198.51.100.200", table), "CN");
    assert.equal(lookupGeoCountry("192.0.2.1", table), "DE");
    assert.equal(lookupGeoCountry("10.0.0.1", table), undefined);
    assert.equal(lookupGeoCountry("8.8.8.8", table), undefined);
  });

  it("first match wins when ranges overlap", () => {
    const table = compileGeoIpTable([
      { cidr: "203.0.113.0/25", country: "US" },
      US_ROW, // 203.0.113.0/24 covers the /25 above
    ]);
    assert.equal(lookupGeoCountry("203.0.113.5", table), "US"); // /25 row first
    const flipped = compileGeoIpTable([
      US_ROW,
      { cidr: "203.0.113.0/25", country: "CN" },
    ]);
    assert.equal(lookupGeoCountry("203.0.113.5", flipped), "US"); // /24 row first
    assert.equal(lookupGeoCountry("203.0.113.200", flipped), "US");
  });

  it("IPv4-mapped IPv6 socket addresses match IPv4 rows", () => {
    const table = compileGeoIpTable([US_ROW]);
    // A dual-stack listener reports "::ffff:203.0.113.9" as remoteAddress.
    assert.equal(lookupGeoCountry("::ffff:203.0.113.9", table), "US");
  });

  it("IPv6 rows match IPv6 addresses", () => {
    const table = compileGeoIpTable([JP_ROW]);
    assert.equal(lookupGeoCountry("2001:db8::1", table), "JP");
    assert.equal(lookupGeoCountry("2001:db8:ffff::99", table), "JP");
    assert.equal(lookupGeoCountry("2001:db9::1", table), undefined);
    assert.equal(lookupGeoCountry("::1", table), undefined);
  });

  it("a bare address means a single host; host bits are masked off", () => {
    const table = compileGeoIpTable([{ cidr: "203.0.113.9", country: "US" }]);
    assert.equal(lookupGeoCountry("203.0.113.9", table), "US");
    assert.equal(lookupGeoCountry("203.0.113.10", table), undefined);
    const sloppy = compileGeoIpTable([{ cidr: "203.0.113.77/24", country: "US" }]);
    assert.equal(lookupGeoCountry("203.0.113.1", sloppy), "US");
  });

  it("lookup throws RangeError on garbage; resolve fail-closes garbage to deny", () => {
    const table = compileGeoIpTable([US_ROW]);
    assert.throws(() => lookupGeoCountry("not-an-ip", table), RangeError);
    assert.throws(() => lookupGeoCountry("", table), RangeError);
    const policy: GeoPolicy = { default: "allow", countries: {} };
    // Even with a permissive default, an unparseable IP is denied.
    assert.equal(resolveGeoVerdict("not-an-ip", table, policy), "deny");
    assert.equal(resolveGeoVerdict("::ffff:not-an-ip", table, policy), "deny");
  });

  it("resolve never throws on hostile input", () => {
    const table = compileGeoIpTable([US_ROW]);
    const policy: GeoPolicy = { default: "allow", countries: {} };
    for (const ip of ["", "…", "1.2.3.4.5", "fe80::1%eth0", "\0"]) {
      assert.equal(resolveGeoVerdict(ip, table, policy), "deny");
    }
  });
});

describe("geoip: policy resolution", () => {
  const table = compileGeoIpTable([US_ROW, CN_ROW, DE_ROW]);

  it("default allow: listed countries are denied, everything else admitted", () => {
    const policy: GeoPolicy = { default: "allow", countries: { CN: "deny", RU: "deny" } };
    assert.equal(resolveGeoVerdict("198.51.100.9", table, policy), "deny"); // CN
    assert.equal(resolveGeoVerdict("203.0.113.9", table, policy), "allow"); // US
    assert.equal(resolveGeoVerdict("10.0.0.1", table, policy), "allow"); // unmapped
  });

  it("default deny: only listed countries are admitted", () => {
    const policy: GeoPolicy = { default: "deny", countries: { US: "allow", DE: "allow" } };
    assert.equal(resolveGeoVerdict("203.0.113.9", table, policy), "allow"); // US
    assert.equal(resolveGeoVerdict("192.0.2.9", table, policy), "allow"); // DE
    assert.equal(resolveGeoVerdict("198.51.100.9", table, policy), "deny"); // CN
    assert.equal(resolveGeoVerdict("10.0.0.1", table, policy), "deny"); // unmapped
  });

  it("a table country missing from the countries map follows the default", () => {
    const allowDefault: GeoPolicy = { default: "allow", countries: { US: "deny" } };
    assert.equal(resolveGeoVerdict("192.0.2.9", table, allowDefault), "allow"); // DE unlisted
    const denyDefault: GeoPolicy = { default: "deny", countries: { US: "allow" } };
    assert.equal(resolveGeoVerdict("192.0.2.9", table, denyDefault), "deny"); // DE unlisted
  });

  it("empty countries map reduces to the default for every IP", () => {
    const denyAll: GeoPolicy = { default: "deny", countries: {} };
    assert.equal(resolveGeoVerdict("203.0.113.9", table, denyAll), "deny");
    assert.equal(resolveGeoVerdict("10.0.0.1", table, denyAll), "deny");
    const allowAll: GeoPolicy = { default: "allow", countries: {} };
    assert.equal(resolveGeoVerdict("203.0.113.9", table, allowAll), "allow");
  });

  it("an empty table classifies every IP by the default", () => {
    const policy = new GeoIpInboundPolicy({ policy: { default: "deny", countries: { US: "allow" } } });
    assert.deepEqual(policy.classify("203.0.113.9"), { verdict: "deny", country: undefined });
    assert.deepEqual(policy.classify("not-an-ip"), { verdict: "deny", country: undefined });
  });

  it("classify reports the country and never throws", () => {
    const policy = new GeoIpInboundPolicy({
      table: [US_ROW, CN_ROW],
      policy: { default: "allow", countries: { CN: "deny" } },
    });
    assert.deepEqual(policy.classify("203.0.113.9"), { verdict: "allow", country: "US" });
    assert.deepEqual(policy.classify("198.51.100.9"), { verdict: "deny", country: "CN" });
    assert.deepEqual(policy.classify("10.0.0.1"), { verdict: "allow", country: undefined });
    assert.deepEqual(policy.classify("garbage"), { verdict: "deny", country: undefined });
  });
});

describe("geoip: config validation", () => {
  const goodPolicy: GeoPolicy = { default: "allow", countries: {} };

  it("rejects malformed table entries", () => {
    assert.throws(() => assertValidGeoIpOptions(undefined), RangeError);
    assert.throws(
      () => assertValidGeoIpOptions({ table: "nope" as never, policy: goodPolicy }),
      RangeError
    );
    assert.throws(
      () => assertValidGeoIpOptions({ table: ["203.0.113.0/24"] as never, policy: goodPolicy }),
      RangeError
    );
    assert.throws(
      () => assertValidGeoIpOptions({ table: [{ cidr: "bogus", country: "US" }], policy: goodPolicy }),
      RangeError
    );
    assert.throws(
      () => assertValidGeoIpOptions({ table: [{ cidr: "203.0.113.0/99", country: "US" }], policy: goodPolicy }),
      RangeError
    );
    assert.throws(
      () => assertValidGeoIpOptions({ table: [{ cidr: "", country: "US" }], policy: goodPolicy }),
      RangeError
    );
  });

  it("rejects country codes that are not uppercase ISO 3166-1 alpha-2", () => {
    for (const country of ["us", "USA", "U1", "U", "", 42, null] as never[]) {
      assert.throws(
        () => assertValidGeoIpOptions({ table: [{ cidr: "203.0.113.0/24", country }], policy: goodPolicy }),
        RangeError,
        `country ${JSON.stringify(country)}`
      );
    }
  });

  it("rejects malformed policies", () => {
    assert.throws(
      () => assertValidGeoIpOptions({ table: [US_ROW] } as never),
      RangeError
    );
    assert.throws(
      () => assertValidGeoIpOptions({ table: [US_ROW], policy: { default: "sometimes", countries: {} } } as never),
      RangeError
    );
    for (const countries of [undefined, null, [], "US"] as never[]) {
      assert.throws(
        () => assertValidGeoIpOptions({ table: [US_ROW], policy: { default: "allow", countries } }),
        RangeError,
        `countries ${JSON.stringify(countries)}`
      );
    }
    assert.throws(
      () =>
        assertValidGeoIpOptions({
          table: [US_ROW],
          policy: { default: "allow", countries: { us: "deny" } },
        }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidGeoIpOptions({
          table: [US_ROW],
          policy: { default: "allow", countries: { USA: "deny" } },
        }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidGeoIpOptions({
          table: [US_ROW],
          policy: { default: "allow", countries: { CN: "maybe" } } as never,
        }),
      RangeError
    );
  });

  it("GeoIpInboundPolicy construction validates, and the server fails fast at startup", () => {
    assert.throws(
      () => new GeoIpInboundPolicy({ table: [US_ROW], policy: { default: "nope", countries: {} } as never }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          secret: geoTestSecret,
          forwardUrl: "http://127.0.0.1:9/unused",
          auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "audit-geo-bad-")), "audit.jsonl")),
          geoIp: { table: [US_ROW], policy: { default: "nope", countries: {} } } as never,
        }),
      RangeError
    );
  });
});

describe("geoip: relay server integration", () => {
  let dir: string;
  let audit: AuditLog;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), "audit-geo-"));
    audit = new AuditLog(join(dir, "audit.jsonl"));
  });

  async function start(opts: { geoIp?: GeoIpOptions; ipAcl?: { trustedProxies?: string[] }; maxBodyBytes?: number }) {
    const relay = createRelayServer({
      secret: geoTestSecret,
      forwardUrl: "http://127.0.0.1:9/unused", // never reached for denials
      auditLog: audit,
      ...opts,
    });
    const port = await listen(relay);
    return { relay, port };
  }

  async function stop(relay: Server) {
    relay.close();
    await new Promise((r) => relay.once("close", r));
  }

  it("an allowed country is admitted; a denied country gets 403 and a geo_blocked audit event", async () => {
    const { relay, port } = await start({
      geoIp: {
        table: [{ cidr: "127.0.0.0/8", country: "US" }],
        policy: { default: "deny", countries: { US: "allow" } },
      },
    });
    try {
      // Loopback maps to US, which the policy allows.
      const ok = await post(port, "/hooks/stripe", BODY);
      assert.equal(ok.status, 202);
    } finally {
      await stop(relay);
    }
    const { relay: relay2, port: port2 } = await start({
      geoIp: {
        table: [{ cidr: "127.0.0.0/8", country: "CN" }],
        policy: { default: "deny", countries: { US: "allow" } },
      },
    });
    try {
      const before = readRejected(dir).filter((e) => e.reason === "geo_blocked").length;
      const denied = await post(port2, "/hooks/stripe", BODY);
      assert.equal(denied.status, 403);
      const blocked = readRejected(dir).filter((e) => e.reason === "geo_blocked");
      assert.equal(blocked.length - before, 1);
      const entry = blocked[blocked.length - 1];
      assert.equal(entry.country, "CN");
      assert.ok(typeof entry.ip === "string" && (entry.ip as string).includes("127.0.0.1"));
      assert.ok(typeof entry.traceId === "string" && (entry.traceId as string).length > 0);
    } finally {
      await stop(relay2);
    }
  });

  it("default deny blocks unmapped IPs; default allow admits them", async () => {
    const { relay, port } = await start({
      geoIp: {
        // 127.0.0.1 is not in the table at all.
        table: [{ cidr: "203.0.113.0/24", country: "US" }],
        policy: { default: "deny", countries: { US: "allow" } },
      },
    });
    try {
      assert.equal((await post(port, "/hooks/x", BODY)).status, 403);
    } finally {
      await stop(relay);
    }
    const { relay: relay2, port: port2 } = await start({
      geoIp: {
        table: [{ cidr: "203.0.113.0/24", country: "US" }],
        policy: { default: "allow", countries: { US: "deny" } },
      },
    });
    try {
      assert.equal((await post(port2, "/hooks/x", BODY)).status, 202);
    } finally {
      await stop(relay2);
    }
  });

  it("the GeoIP gate runs before the body is read: a blocked oversized POST gets 403, not 413", async () => {
    const { relay, port } = await start({
      maxBodyBytes: 32,
      geoIp: {
        table: [{ cidr: "127.0.0.0/8", country: "CN" }],
        policy: { default: "deny", countries: { US: "allow" } },
      },
    });
    try {
      // Declared 1 MiB, GeoIP blocks loopback: 403 wins over the 413.
      const before = readRejected(dir).filter((e) => e.reason === "geo_blocked").length;
      const denied = await postDeclaredLength(port, "/hooks/x", 1_048_576);
      assert.equal(denied.status, 403);
      const blocked = readRejected(dir).filter((e) => e.reason === "geo_blocked");
      assert.ok(blocked.length - before >= 1);
    } finally {
      await stop(relay);
    }
  });

  it("an unparseable client IP fails closed to geo_blocked", async () => {
    const { relay, port } = await start({
      // Trust loopback as a proxy so the XFF chain is honored; no ACL
      // rules means the ACL itself admits everything.
      ipAcl: { trustedProxies: ["127.0.0.0/8"] },
      geoIp: {
        table: [{ cidr: "127.0.0.0/8", country: "US" }],
        policy: { default: "deny", countries: { US: "allow" } },
      },
    });
    try {
      // The XFF claim is garbage: the resolved client IP cannot be
      // looked up, so the gate fail-closes to deny.
      const before = readRejected(dir).filter(
        (e) => e.reason === "geo_blocked" && e.country === "unknown"
      ).length;
      const denied = await post(port, "/hooks/x", BODY, { "x-forwarded-for": "not-an-ip" });
      assert.equal(denied.status, 403);
      const blocked = readRejected(dir).filter(
        (e) => e.reason === "geo_blocked" && e.country === "unknown"
      );
      assert.equal(blocked.length - before, 1);
      assert.equal(blocked[blocked.length - 1].ip, "not-an-ip");
    } finally {
      await stop(relay);
    }
  });

  it("without geoIp configured, intake behavior is unchanged", async () => {
    const { relay, port } = await start({});
    try {
      const before = readRejected(dir).filter((e) => e.reason === "geo_blocked").length;
      assert.equal((await post(port, "/hooks/x", BODY)).status, 202);
      const blocked = readRejected(dir).filter((e) => e.reason === "geo_blocked");
      assert.equal(blocked.length - before, 0);
    } finally {
      await stop(relay);
    }
  });

  after(async () => {
    // The shared audit dir accumulates events across servers; nothing to tear down.
  });
});
