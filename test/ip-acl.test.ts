import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  InboundIpAcl,
  IpAclMetrics,
  assertValidEndpointIpAclRules,
  cidrContains,
  parseCidr,
  selectEndpointIpAclRule,
  type IpAclOptions,
} from "../src/ip-acl.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const SECRET = "acl-secret";
const BODY = Buffer.from(JSON.stringify({ event: "acl.probe" }));

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
        headers: { "x-signature": signSha256(body, SECRET), ...headers },
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
          "x-signature": signSha256(BODY, SECRET),
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

function getMetrics(port: number, token: string) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/metrics",
        headers: { authorization: `Bearer ${token}` },
      },
      (resp) => {
        const chunks: Buffer[] = [];
        resp.on("data", (c: Buffer) => chunks.push(c));
        resp.on("end", () =>
          resolve({ status: resp.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end();
  });
}

describe("ip-acl: IPv4 CIDR parsing and matching", () => {
  it("matches inside the range, rejects outside, honors prefix boundaries", () => {
    const c = parseCidr("192.168.1.0/24");
    assert.equal(cidrContains(c, "192.168.1.0"), true); // network address
    assert.equal(cidrContains(c, "192.168.1.1"), true);
    assert.equal(cidrContains(c, "192.168.1.255"), true); // broadcast address
    assert.equal(cidrContains(c, "192.168.2.0"), false);
    assert.equal(cidrContains(c, "192.168.0.255"), false);
    assert.equal(cidrContains(c, "10.0.0.1"), false);
  });

  it("bare address means a single host; /0 matches every IPv4 address", () => {
    const single = parseCidr("10.9.8.7");
    assert.equal(cidrContains(single, "10.9.8.7"), true);
    assert.equal(cidrContains(single, "10.9.8.8"), false);
    const all = parseCidr("0.0.0.0/0");
    assert.equal(cidrContains(all, "1.2.3.4"), true);
    assert.equal(cidrContains(all, "255.255.255.255"), true);
  });

  it("/8 and /16 carve the right supernets", () => {
    const c8 = parseCidr("10.0.0.0/8");
    assert.equal(cidrContains(c8, "10.255.255.255"), true);
    assert.equal(cidrContains(c8, "11.0.0.0"), false);
    const c16 = parseCidr("172.16.0.0/12");
    assert.equal(cidrContains(c16, "172.31.255.255"), true);
    assert.equal(cidrContains(c16, "172.32.0.0"), false);
  });

  it("masks off host bits instead of rejecting them", () => {
    // "192.168.1.77/24" is sloppy config, not an error: the network wins.
    const c = parseCidr("192.168.1.77/24");
    assert.equal(cidrContains(c, "192.168.1.1"), true);
  });
});

describe("ip-acl: IPv6 CIDR parsing and matching", () => {
  it("matches inside the range, rejects outside", () => {
    const c = parseCidr("2001:db8::/32");
    assert.equal(cidrContains(c, "2001:db8::1"), true);
    assert.equal(cidrContains(c, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), true);
    assert.equal(cidrContains(c, "2001:db9::1"), false);
    assert.equal(cidrContains(c, "::1"), false);
  });

  it("handles ::1, full form, and /128 single hosts", () => {
    assert.equal(cidrContains(parseCidr("::1/128"), "::1"), true);
    assert.equal(cidrContains(parseCidr("::1/128"), "::2"), false);
    const full = parseCidr("2001:0db8:0000:0000:0000:0000:0000:0042/128");
    assert.equal(cidrContains(full, "2001:db8::42"), true);
    assert.equal(cidrContains(full, "2001:db8::43"), false);
  });

  it("::/0 matches every IPv6 address including IPv4-mapped ones", () => {
    const c = parseCidr("::/0");
    assert.equal(cidrContains(c, "2001:db8::1"), true);
    assert.equal(cidrContains(c, "::ffff:10.1.2.3"), true);
    assert.equal(cidrContains(c, "10.1.2.3"), true); // IPv4, mapped
  });

  it("supports an IPv4 tail and prefix math on it", () => {
    const c = parseCidr("::ffff:192.0.2.0/120");
    assert.equal(cidrContains(c, "::ffff:192.0.2.9"), true);
    assert.equal(cidrContains(c, "::ffff:192.0.3.1"), false);
    assert.equal(cidrContains(c, "192.0.2.9"), true); // same address, v4 spelling
    // Tails are legal wherever they are the final 32 bits.
    assert.equal(cidrContains(parseCidr("::1.2.3.4/128"), "::102:304"), true);
    assert.equal(cidrContains(parseCidr("1::2.3.4.5/128"), "1::203:405"), true);
  });

  it("a plain IPv4 rule matches a dual-stack ::ffff: remoteAddress", () => {
    // Node reports IPv4 peers on a dual-stack socket as ::ffff:127.0.0.1.
    const allow = parseCidr("127.0.0.0/8");
    assert.equal(cidrContains(allow, "::ffff:127.0.0.1"), true);
    assert.equal(cidrContains(allow, "::ffff:128.0.0.1"), false);
    const deny = parseCidr("::ffff:10.0.0.0/104");
    assert.equal(cidrContains(deny, "10.9.9.9"), true);
    assert.equal(cidrContains(deny, "11.0.0.1"), false);
  });
});

describe("ip-acl: malformed CIDRs fail fast with RangeError", () => {
  const bad = [
    "10.0.0.0/33",
    "10.0.0.0/-1",
    "10.0.0.0/abc",
    "10.0.0.256/24",
    "10.0.0/24",
    "10.0.0.0.1/24",
    "10.0.0.0/",
    "/24",
    "",
    "2001:db8::/129",
    "2001:db8::/-1",
    "2001:db8:::/64",
    "1:2:3:4:5:6:7:8:9/64",
    "1:2:3:4:5:6:7:8::/64", // "::" compresses nothing
    "2001:db8::g/64",
    "fe80::1%eth0/64", // zone id
    "2001:db8::1.2.3.999/64", // bad v4 tail
    "1.2.3.4::5/64", // v4 tail not last
    "not-an-ip",
  ];
  for (const c of bad) {
    it(`rejects "${c}"`, () => {
      assert.throws(() => parseCidr(c), RangeError);
    });
  }
  it("rejects non-string input", () => {
    assert.throws(() => parseCidr(123 as unknown as string), RangeError);
  });
});

describe("ip-acl: rule validation", () => {
  it("allow + deny on one rule is mutually exclusive", () => {
    assert.throws(
      () =>
        assertValidEndpointIpAclRules([
          { pattern: "/hooks/*", allow: ["10.0.0.0/8"], deny: ["192.168.0.0/16"] },
        ]),
      /mutually exclusive/
    );
  });

  it("rejects bad patterns, empty lists, non-arrays, and bad CIDRs", () => {
    assert.throws(() => assertValidEndpointIpAclRules("nope" as unknown as []), /expected an array/);
    assert.throws(() => assertValidEndpointIpAclRules([{ pattern: "hooks/*" }]), /pattern/);
    assert.throws(() => assertValidEndpointIpAclRules([{ pattern: "/hooks/*", allow: [] }]), /non-empty array/);
    assert.throws(
      () => assertValidEndpointIpAclRules([{ pattern: "/hooks/*", deny: ["10.0.0.0/33"] }]),
      RangeError
    );
    // ...and the InboundIpAcl constructor enforces the same at startup.
    assert.throws(
      () => new InboundIpAcl({ rules: [{ pattern: "/hooks/*", allow: ["bogus"] }] }),
      RangeError
    );
    assert.throws(() => new InboundIpAcl({ trustedProxies: ["10.0.0.0/33"] }), RangeError);
    assert.throws(
      () => new InboundIpAcl({ trustedProxies: "10.0.0.0/8" as unknown as string[] }),
      /trustedProxies/
    );
  });

  it("first matching rule wins (exact beats later prefix, config order)", () => {
    const rules = [
      { pattern: "/hooks/*", deny: ["10.0.0.0/8"] },
      { pattern: "/hooks/stripe", allow: ["10.0.0.0/8"] },
    ];
    assert.equal(selectEndpointIpAclRule("/hooks/stripe", rules)?.pattern, "/hooks/*");
    assert.equal(selectEndpointIpAclRule("/hooks/other", rules)?.pattern, "/hooks/*");
    assert.equal(selectEndpointIpAclRule("/other", rules), undefined);
    // Prefix also matches the bare prefix path itself.
    assert.equal(selectEndpointIpAclRule("/hooks", rules)?.pattern, "/hooks/*");
  });
});

describe("ip-acl: InboundIpAcl verdicts", () => {
  it("deny match rejects; allow mode rejects outsiders and admits insiders", () => {
    const acl = new InboundIpAcl({
      rules: [
        { pattern: "/hooks/*", deny: ["10.0.0.0/8", "2001:db8::/32"] },
        { pattern: "/admin", allow: ["192.168.0.0/16"] },
      ],
    });
    assert.deepEqual(acl.check("/hooks/stripe", "10.9.9.9"), {
      ok: false,
      reason: "ip_denied",
      pattern: "/hooks/*",
    });
    assert.deepEqual(acl.check("/hooks/stripe", "2001:db8::42"), {
      ok: false,
      reason: "ip_denied",
      pattern: "/hooks/*",
    });
    assert.deepEqual(acl.check("/hooks/stripe", "8.8.8.8"), { ok: true });
    assert.deepEqual(acl.check("/admin", "192.168.5.5"), { ok: true });
    assert.deepEqual(acl.check("/admin", "8.8.8.8"), {
      ok: false,
      reason: "ip_denied",
      pattern: "/admin",
    });
  });

  it("paths with no matching rule are admitted; empty config admits everything", () => {
    const acl = new InboundIpAcl({ rules: [{ pattern: "/hooks/*", deny: ["10.0.0.0/8"] }] });
    assert.deepEqual(acl.check("/other", "10.9.9.9"), { ok: true });
    assert.deepEqual(new InboundIpAcl().check("/hooks/x", "10.9.9.9"), { ok: true });
    assert.deepEqual(new InboundIpAcl({ rules: [] }).check("/hooks/x", "10.9.9.9"), { ok: true });
  });

  it("an unparseable IP on a guarded endpoint is denied (fail closed)", () => {
    const acl = new InboundIpAcl({ rules: [{ pattern: "/hooks/*", deny: ["10.0.0.0/8"] }] });
    const v = acl.check("/hooks/x", "garbage");
    assert.equal(v.ok, false);
    if (!v.ok) assert.equal(v.reason, "ip_denied");
    // ...but not on an unguarded path.
    assert.deepEqual(acl.check("/other", "garbage"), { ok: true });
  });
});

describe("ip-acl: client IP resolution and XFF trust", () => {
  it("by default only the direct socket peer is trusted; XFF is ignored", () => {
    const acl = new InboundIpAcl();
    assert.equal(acl.clientIp("203.0.113.7", "10.9.9.9"), "203.0.113.7");
    assert.equal(acl.clientIp("203.0.113.7", undefined), "203.0.113.7");
    assert.equal(acl.clientIp(undefined, "10.9.9.9"), "unknown");
  });

  it("with trusted proxies, the chain strips to the leftmost untrusted hop", () => {
    const acl = new InboundIpAcl({ trustedProxies: ["10.0.0.0/8", "2001:db8::/32"] });
    // Direct peer is a trusted proxy: client is the leftmost untrusted hop.
    assert.equal(acl.clientIp("10.0.0.2", "198.51.100.9, 10.0.0.1"), "198.51.100.9");
    assert.equal(acl.clientIp("10.0.0.2", "198.51.100.9"), "198.51.100.9");
    // Every hop trusted: keep the leftmost claim.
    assert.equal(acl.clientIp("10.0.0.2", "10.9.9.9, 10.0.0.1"), "10.9.9.9");
    // IPv6 proxy chain.
    assert.equal(acl.clientIp("2001:db8::2", "198.51.100.9, 2001:db8::1"), "198.51.100.9");
  });

  it("an untrusted direct peer makes XFF untrusted input (spoof-proof)", () => {
    const acl = new InboundIpAcl({ trustedProxies: ["10.0.0.0/8"] });
    // Attacker claims to be 10.9.9.9 via XFF but connects directly.
    assert.equal(acl.clientIp("203.0.113.7", "10.9.9.9"), "203.0.113.7");
    // No XFF at all behind a trusted proxy: the peer itself is the client.
    assert.equal(acl.clientIp("10.0.0.2", undefined), "10.0.0.2");
  });

  it("unparseable XFF hops are kept verbatim so check() fail-closes them", () => {
    const acl = new InboundIpAcl({
      rules: [{ pattern: "/hooks/*", deny: ["10.0.0.0/8"] }],
      trustedProxies: ["127.0.0.0/8"],
    });
    const ip = acl.clientIp("127.0.0.1", "unknown");
    assert.equal(ip, "unknown");
    assert.equal(acl.check("/hooks/x", ip).ok, false);
  });
});

describe("ip-acl: IpAclMetrics", () => {
  it("renders nothing when empty, and one series per endpoint pattern", () => {
    const m = new IpAclMetrics();
    assert.equal(m.render(), "");
    m.record("/hooks/*");
    m.record("/hooks/*");
    m.record("/admin");
    const out = m.render();
    assert.ok(out.includes("# HELP relay_inbound_ip_denied_total"));
    assert.ok(out.includes('relay_inbound_ip_denied_total{endpoint="/hooks/*"} 2'));
    assert.ok(out.includes('relay_inbound_ip_denied_total{endpoint="/admin"} 1'));
  });
});

describe("ip-acl: relay server integration", () => {
  let dir: string;
  let audit: AuditLog;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), "audit-acl-"));
    audit = new AuditLog(join(dir, "audit.jsonl"));
  });

  async function start(opts: { ipAcl?: IpAclOptions; maxBodyBytes?: number; operatorToken?: string }) {
    const relay = createRelayServer({
      secret: SECRET,
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

  it("a denied IP gets 403, an audit trail, and a metrics series", async () => {
    const { relay, port } = await start({
      operatorToken: "op-acl",
      ipAcl: { rules: [{ pattern: "/hooks/*", deny: ["127.0.0.0/8"] }] },
    });
    try {
      // Loopback is inside the deny range (covers ::ffff:127.0.0.1 too).
      const denied = await post(port, "/hooks/stripe", BODY);
      assert.equal(denied.status, 403);

      const rejected = readRejected(dir).filter((e) => e.reason === "ip_denied");
      assert.equal(rejected.length, 1);
      const entry = rejected[0];
      assert.equal(entry.endpoint, "/hooks/*");
      assert.ok(typeof entry.traceId === "string" && entry.traceId.length > 0);

      // The denial renders in the Prometheus exposition.
      const metrics = await getMetrics(port, "op-acl");
      assert.equal(metrics.status, 200);
      assert.ok(metrics.text.includes('relay_inbound_ip_denied_total{endpoint="/hooks/*"} 1'));

      // Unguarded paths are untouched.
      const ok = await post(port, "/other", BODY);
      assert.equal(ok.status, 202);
    } finally {
      await stop(relay);
    }
  });

  it("allow mode admits insiders and rejects outsiders", async () => {
    const { relay, port } = await start({
      ipAcl: { rules: [{ pattern: "/hooks/*", allow: ["10.0.0.0/8"] }] },
    });
    try {
      // Loopback is outside 10/8: rejected.
      assert.equal((await post(port, "/hooks/x", BODY)).status, 403);
    } finally {
      await stop(relay);
    }
    const { relay: relay2, port: port2 } = await start({
      ipAcl: { rules: [{ pattern: "/hooks/*", allow: ["127.0.0.0/8", "::1/128"] }] },
    });
    try {
      assert.equal((await post(port2, "/hooks/x", BODY)).status, 202);
    } finally {
      await stop(relay2);
    }
  });

  it("a spoofed x-forwarded-for is ignored by default, honored behind trusted proxies", async () => {
    const rules = [{ pattern: "/hooks/*", deny: ["10.0.0.0/8"] as string[] }];
    // Default: XFF claiming a denied IP does not deny; the direct peer (loopback) is used.
    const { relay, port } = await start({ ipAcl: { rules } });
    try {
      const r = await post(port, "/hooks/x", BODY, { "x-forwarded-for": "10.9.9.9" });
      assert.equal(r.status, 202);
    } finally {
      await stop(relay);
    }
    // Behind a trusted proxy (loopback is the proxy), the XFF chain resolves
    // to 10.9.9.9, which the deny list rejects.
    const { relay: relay2, port: port2 } = await start({
      ipAcl: { rules, trustedProxies: ["127.0.0.0/8"] },
    });
    try {
      const r = await post(port2, "/hooks/x", BODY, { "x-forwarded-for": "10.9.9.9" });
      assert.equal(r.status, 403);
      // A benign client through the same proxy is still admitted.
      const ok = await post(port2, "/hooks/x", BODY, { "x-forwarded-for": "198.51.100.9" });
      assert.equal(ok.status, 202);
    } finally {
      await stop(relay2);
    }
  });

  it("the ACL runs before the body limit: a denied oversized POST gets 403, not 413", async () => {
    const { relay, port } = await start({
      maxBodyBytes: 32,
      ipAcl: { rules: [{ pattern: "/hooks/*", deny: ["127.0.0.0/8"] }] },
    });
    try {
      // Declared 1 MiB, deny list covers loopback: 403 wins over the 413.
      const denied = await postDeclaredLength(port, "/hooks/x", 1_048_576);
      assert.equal(denied.status, 403);
      const rejected = readRejected(dir).filter((e) => e.reason === "ip_denied");
      assert.ok(rejected.length >= 1);
    } finally {
      await stop(relay);
    }
    // Control: without the ACL the same oversized POST is a 413.
    const { relay: relay2, port: port2 } = await start({ maxBodyBytes: 32 });
    try {
      assert.equal((await postDeclaredLength(port2, "/hooks/x", 1_048_576)).status, 413);
    } finally {
      await stop(relay2);
    }
  });

  it("rules are scoped per endpoint pattern", async () => {
    const { relay, port } = await start({
      ipAcl: { rules: [{ pattern: "/admin/*", deny: ["127.0.0.0/8"] }] },
    });
    try {
      assert.equal((await post(port, "/admin/panel", BODY)).status, 403);
      assert.equal((await post(port, "/hooks/stripe", BODY)).status, 202);
    } finally {
      await stop(relay);
    }
  });

  it("with ipAcl unset, intake is unchanged and no metric series renders", async () => {
    const { relay, port } = await start({ operatorToken: "op-acl-plain" });
    try {
      assert.equal((await post(port, "/hooks/x", BODY)).status, 202);
      const res = await getMetrics(port, "op-acl-plain");
      assert.equal(res.status, 200);
      assert.ok(!res.text.includes("relay_inbound_ip_denied_total"));
    } finally {
      await stop(relay);
    }
  });

  it("invalid ipAcl config fails fast at server startup", () => {
    assert.throws(
      () =>
        createRelayServer({
          secret: SECRET,
          forwardUrl: "http://127.0.0.1:9/unused",
          auditLog: audit,
          ipAcl: { rules: [{ pattern: "/hooks/*", deny: ["999.1.1.1/24"] }] },
        }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          secret: SECRET,
          forwardUrl: "http://127.0.0.1:9/unused",
          auditLog: audit,
          ipAcl: { rules: [{ pattern: "/hooks/*", allow: ["10.0.0.0/8"], deny: ["10.1.0.0/16"] }] },
        }),
      /mutually exclusive/
    );
  });
});
