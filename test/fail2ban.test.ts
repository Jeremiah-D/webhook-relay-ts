import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Fail2Ban,
  Fail2BanMetrics,
  assertValidFail2BanOptions,
  DEFAULT_FAIL2BAN_MAX_ENTRIES,
  type Fail2BanOptions,
} from "../src/fail2ban.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const secret = "f2b-secret";
const BODY = Buffer.from(JSON.stringify({ event: "f2b.probe" }));
const OP = "op-f2b";

function validOptions(over: Partial<Fail2BanOptions> = {}): Fail2BanOptions {
  return { maxConsecutiveFailures: 3, banDurationMs: 60_000, ...over };
}

describe("fail2ban: option validation (fail-fast RangeError)", () => {
  it("accepts a sane config", () => {
    assert.doesNotThrow(() => assertValidFail2BanOptions(validOptions()));
    assert.doesNotThrow(() => assertValidFail2BanOptions(validOptions({ maxEntries: 10 })));
  });

  it("rejects bad maxConsecutiveFailures", () => {
    for (const v of [0, -1, 1.5, Number.NaN, "3", undefined]) {
      assert.throws(
        () => assertValidFail2BanOptions(validOptions({ maxConsecutiveFailures: v as number })),
        RangeError,
        `maxConsecutiveFailures=${String(v)}`
      );
    }
  });

  it("rejects bad banDurationMs", () => {
    for (const v of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, "1000", undefined]) {
      assert.throws(
        () => assertValidFail2BanOptions(validOptions({ banDurationMs: v as number })),
        RangeError,
        `banDurationMs=${String(v)}`
      );
    }
  });

  it("rejects bad maxEntries / now / isExempt", () => {
    assert.throws(() => assertValidFail2BanOptions(validOptions({ maxEntries: 0 })), RangeError);
    assert.throws(() => assertValidFail2BanOptions(validOptions({ maxEntries: 2.5 })), RangeError);
    assert.throws(() => assertValidFail2BanOptions(validOptions({ now: 42 as never })), RangeError);
    assert.throws(
      () => assertValidFail2BanOptions(validOptions({ isExempt: true as never })),
      RangeError
    );
  });

  it("the constructor validates too", () => {
    assert.throws(() => new Fail2Ban(validOptions({ maxConsecutiveFailures: 0 })), RangeError);
  });

  it("default maxEntries is the exported constant", () => {
    assert.equal(DEFAULT_FAIL2BAN_MAX_ENTRIES, 10000);
  });
});

describe("fail2ban: consecutive-failure banning (injected clock)", () => {
  let nowMs: number;
  let f2b: Fail2Ban;
  beforeEach(() => {
    nowMs = 1_000_000;
    f2b = new Fail2Ban(validOptions({ now: () => nowMs }));
  });

  it("bans after exactly N consecutive failures", () => {
    const ip = "203.0.113.7";
    assert.equal(f2b.recordFailure("/hooks/a", ip).banned, false);
    assert.equal(f2b.recordFailure("/hooks/a", ip).banned, false);
    const third = f2b.recordFailure("/hooks/a", ip);
    assert.equal(third.banned, true);
    assert.equal(third.justBanned, true);
    assert.equal(third.consecutiveFailures, 3);
    assert.equal(f2b.isBanned("/hooks/a", ip), true);
    // A further failure extends the ban but is not a new activation.
    const fourth = f2b.recordFailure("/hooks/a", ip);
    assert.equal(fourth.banned, true);
    assert.equal(fourth.justBanned, false);
  });

  it("the ban lifts after banDurationMs", () => {
    const ip = "203.0.113.8";
    for (let i = 0; i < 3; i++) f2b.recordFailure("/hooks/a", ip);
    assert.equal(f2b.isBanned("/hooks/a", ip), true);
    nowMs += 59_999;
    assert.equal(f2b.isBanned("/hooks/a", ip), true);
    nowMs += 1;
    assert.equal(f2b.isBanned("/hooks/a", ip), false);
  });

  it("any success zeroes the counter", () => {
    const ip = "203.0.113.9";
    f2b.recordFailure("/hooks/a", ip);
    f2b.recordFailure("/hooks/a", ip);
    f2b.recordSuccess(ip);
    f2b.recordFailure("/hooks/a", ip);
    f2b.recordFailure("/hooks/a", ip);
    assert.equal(f2b.isBanned("/hooks/a", ip), false);
    assert.equal(f2b.size, 1);
  });

  it("a success during a live ban keeps the ban but clears the counter", () => {
    const ip = "203.0.113.10";
    for (let i = 0; i < 3; i++) f2b.recordFailure("/hooks/a", ip);
    f2b.recordSuccess(ip); // e.g. an exempt-path request that succeeded
    assert.equal(f2b.isBanned("/hooks/a", ip), true);
    const bans = f2b.bans();
    assert.equal(bans.length, 1);
    assert.equal(bans[0].consecutiveFailures, 0);
  });

  it("different IPs are tracked independently", () => {
    f2b.recordFailure("/hooks/a", "203.0.113.11");
    f2b.recordFailure("/hooks/a", "203.0.113.11");
    f2b.recordFailure("/hooks/a", "203.0.113.12");
    assert.equal(f2b.isBanned("/hooks/a", "203.0.113.11"), false);
    assert.equal(f2b.isBanned("/hooks/a", "203.0.113.12"), false);
    f2b.recordFailure("/hooks/a", "203.0.113.11");
    assert.equal(f2b.isBanned("/hooks/a", "203.0.113.11"), true);
    assert.equal(f2b.isBanned("/hooks/a", "203.0.113.12"), false);
  });
});

describe("fail2ban: static-allow exemption", () => {
  it("an exempt IP is never banned and never reported banned", () => {
    const f2b = new Fail2Ban(
      validOptions({ isExempt: (pathname, ip) => pathname === "/hooks/a" && ip === "10.1.2.3" })
    );
    for (let i = 0; i < 10; i++) {
      const r = f2b.recordFailure("/hooks/a", "10.1.2.3");
      assert.equal(r.banned, false);
    }
    assert.equal(f2b.isBanned("/hooks/a", "10.1.2.3"), false);
    // The same IP on a non-exempt path is not protected.
    for (let i = 0; i < 3; i++) f2b.recordFailure("/hooks/b", "10.1.2.3");
    assert.equal(f2b.isBanned("/hooks/b", "10.1.2.3"), true);
    // ...but the exempt path still admits it (exemption wins at check time).
    assert.equal(f2b.isBanned("/hooks/a", "10.1.2.3"), false);
  });
});

describe("fail2ban: bounded memory (maxEntries, oldest eviction)", () => {
  it("evicts the least-recently-active entry when full", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(validOptions({ maxEntries: 3, now: () => nowMs }));
    f2b.recordFailure("/h", "10.0.0.1"); // lastSeen 1000
    nowMs += 1000;
    f2b.recordFailure("/h", "10.0.0.2"); // lastSeen 2000
    nowMs += 1000;
    f2b.recordFailure("/h", "10.0.0.3"); // lastSeen 3000
    assert.equal(f2b.size, 3);
    nowMs += 1000;
    // Touch 10.0.0.1 so it is no longer the oldest.
    f2b.recordFailure("/h", "10.0.0.1"); // lastSeen 4000
    nowMs += 1000;
    f2b.recordFailure("/h", "10.0.0.4"); // evicts 10.0.0.2 (oldest lastSeen)
    assert.equal(f2b.size, 3);
    // 10.0.0.2 was evicted: its counter starts over.
    assert.equal(f2b.recordFailure("/h", "10.0.0.2").consecutiveFailures, 1);
    // 10.0.0.1 kept its history (2 failures).
    assert.equal(f2b.recordFailure("/h", "10.0.0.1").consecutiveFailures, 3);
  });

  it("a live ban is never evicted to make room", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(
      validOptions({ maxConsecutiveFailures: 2, banDurationMs: 60_000, maxEntries: 2, now: () => nowMs })
    );
    f2b.recordFailure("/h", "10.0.0.1");
    f2b.recordFailure("/h", "10.0.0.1"); // banned
    nowMs += 1000;
    f2b.recordFailure("/h", "10.0.0.2");
    nowMs += 1000;
    // Full (2 entries); adding a third must evict 10.0.0.2, not the banned 10.0.0.1.
    f2b.recordFailure("/h", "10.0.0.3");
    assert.equal(f2b.isBanned("/h", "10.0.0.1"), true);
    assert.equal(f2b.bans().length, 1);
    assert.equal(f2b.bans()[0].ip, "10.0.0.1");
  });

  it("expired bans are swept before evicting live entries", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(
      validOptions({ maxConsecutiveFailures: 1, banDurationMs: 500, maxEntries: 2, now: () => nowMs })
    );
    f2b.recordFailure("/h", "10.0.0.1"); // banned until 1500
    f2b.recordFailure("/h", "10.0.0.2"); // banned until 1500
    nowMs = 10_000; // both bans expired
    f2b.recordFailure("/h", "10.0.0.3"); // sweeps the expired bans, no live eviction
    assert.equal(f2b.isBanned("/h", "10.0.0.3"), true);
    assert.equal(f2b.bans().length, 1);
  });
});

describe("fail2ban: operator unban", () => {
  it("unban lifts the ban and resets the counter", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(validOptions({ now: () => nowMs }));
    for (let i = 0; i < 3; i++) f2b.recordFailure("/h", "10.0.0.9");
    assert.equal(f2b.unban("10.0.0.9"), true);
    assert.equal(f2b.isBanned("/h", "10.0.0.9"), false);
    // Counter reset: the next failure starts from 1, not 4.
    assert.equal(f2b.recordFailure("/h", "10.0.0.9").consecutiveFailures, 1);
    assert.equal(f2b.unban("10.0.0.9"), false);
    assert.equal(f2b.unban("192.0.2.99"), false);
  });
});

describe("fail2ban: bans() listing", () => {
  it("lists active bans oldest-first with ban windows", () => {
    let nowMs = 1_000_000;
    const f2b = new Fail2Ban(
      validOptions({ maxConsecutiveFailures: 2, banDurationMs: 30_000, now: () => nowMs })
    );
    f2b.recordFailure("/h", "10.0.0.5");
    f2b.recordFailure("/h", "10.0.0.5"); // banned at 1_000_000
    nowMs += 5_000;
    f2b.recordFailure("/h", "10.0.0.6");
    f2b.recordFailure("/h", "10.0.0.6"); // banned at 1_005_000
    f2b.recordFailure("/h", "10.0.0.7"); // not banned: only 1 failure
    const bans = f2b.bans();
    assert.equal(bans.length, 2);
    assert.equal(bans[0].ip, "10.0.0.5");
    assert.equal(bans[0].bannedAt, 1_000_000);
    assert.equal(bans[0].expiresAt, 1_030_000);
    assert.equal(bans[0].consecutiveFailures, 2);
    assert.equal(bans[1].ip, "10.0.0.6");
    // Expired bans drop out of the listing.
    nowMs = 2_000_000;
    assert.equal(f2b.bans().length, 0);
  });
});

describe("fail2ban: metrics", () => {
  it("renders nothing when idle, both series when active", () => {
    const m = new Fail2BanMetrics();
    assert.equal(m.render(), "");
    m.recordBlocked("/hooks/a");
    m.recordBlocked("/hooks/a");
    m.recordBlocked("/hooks/b");
    m.recordBan();
    const text = m.render();
    assert.ok(text.includes('relay_inbound_ip_banned_total{endpoint="/hooks/a"} 2'));
    assert.ok(text.includes('relay_inbound_ip_banned_total{endpoint="/hooks/b"} 1'));
    assert.ok(text.includes("relay_inbound_ip_ban_activations_total 1"));
    assert.ok(text.includes("# TYPE relay_inbound_ip_banned_total counter"));
  });

  it("escapes label values", () => {
    const m = new Fail2BanMetrics();
    m.recordBlocked('/hooks/"weird"');
    assert.ok(m.render().includes('endpoint="/hooks/\\"weird\\""'));
  });
});

// ---------------------------------------------------------------------------
// Server integration
// ---------------------------------------------------------------------------

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer, signature?: string) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (signature !== undefined) headers["x-signature"] = signature;
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        r.destroy();
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
      });
    });
    r.on("error", reject);
    r.end(body);
  });
}

function authed(port: number, path: string, headers: Record<string, string>, method = "GET") {
  return new Promise<{ status: number; json: unknown; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString();
        let json: unknown = null;
        try {
          json = JSON.parse(text);
        } catch {
          /* not JSON */
        }
        resolve({ status: res.statusCode ?? 0, json, text });
      });
    });
    r.on("error", reject);
    r.end();
  });
}

interface ServerHarness {
  relay: Server;
  port: number;
  dir: string;
  audit: AuditLog;
  stop: () => Promise<void>;
  setNow: (ms: number) => void;
}

async function startServer(opts: {
  fail2ban?: Fail2BanOptions;
  ipAcl?: { rules: Array<{ pattern: string; allow?: string[]; deny?: string[] }> };
  rateLimit?: { perIpPerSecond: number };
  operatorToken?: string;
} = {}): Promise<ServerHarness> {
  const dir = mkdtempSync(join(tmpdir(), "audit-f2b-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  let nowMs = 5_000_000;
  const relay = createRelayServer({
    secret,
    forwardUrl: "http://127.0.0.1:9/unused",
    auditLog: audit,
    fail2ban:
      opts.fail2ban === undefined
        ? undefined
        : { ...opts.fail2ban, now: () => nowMs },
    ipAcl: opts.ipAcl,
    rateLimit: opts.rateLimit,
    operatorToken: opts.operatorToken,
  });
  const port = await listen(relay);
  return {
    relay,
    port,
    dir,
    audit,
    setNow: (ms: number) => {
      nowMs = ms;
    },
    stop: async () => {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    },
  };
}

function readAudit(dir: string): Array<Record<string, unknown>> {
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  return audit.readAll() as Array<Record<string, unknown>>;
}

const goodSig = () => signSha256(BODY, secret);
const badSig = () => "sha256=" + "0".repeat(64);

describe("fail2ban: relay server integration", () => {
  it("N bad signatures ban the IP; banned requests get 403 without verification", async () => {
    const h = await startServer({
      operatorToken: OP,
      fail2ban: { maxConsecutiveFailures: 3, banDurationMs: 60_000 },
    });
    try {
      assert.equal((await post(h.port, "/hooks/a", BODY, badSig())).status, 401);
      assert.equal((await post(h.port, "/hooks/a", BODY, badSig())).status, 401);
      assert.equal((await post(h.port, "/hooks/a", BODY, badSig())).status, 401);
      // Now banned: even a VALID signature is 403 (the ban check runs
      // before verification — no verifier CPU is burned).
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 403);
      // And a bad signature is 403, not 401 (ban short-circuits admission).
      assert.equal((await post(h.port, "/hooks/a", BODY, badSig())).status, 403);
      // Other paths are banned too (the ban is per-IP).
      assert.equal((await post(h.port, "/hooks/b", BODY, goodSig())).status, 403);

      const events = readAudit(h.dir);
      const banned = events.filter((e) => e.event === "ip_banned");
      assert.equal(banned.length, 1);
      assert.equal(banned[0].consecutiveFailures, 3);
      assert.equal(banned[0].endpoint, "/hooks/a");
      const blocked = events.filter((e) => e.event === "ip_blocked");
      assert.equal(blocked.length, 3);
      assert.ok(blocked.every((e) => typeof e.traceId === "string"));

      // Metrics render both series.
      const metrics = await authed(h.port, "/metrics", { authorization: `Bearer ${OP}` });
      assert.equal(metrics.status, 200);
      assert.ok(metrics.text.includes('relay_inbound_ip_banned_total{endpoint="/hooks/a"} 2'));
      assert.ok(metrics.text.includes('relay_inbound_ip_banned_total{endpoint="/hooks/b"} 1'));
      assert.ok(metrics.text.includes("relay_inbound_ip_ban_activations_total 1"));
    } finally {
      await h.stop();
    }
  });

  it("the ban lifts after banDurationMs (injected clock)", async () => {
    const h = await startServer({
      fail2ban: { maxConsecutiveFailures: 2, banDurationMs: 10_000 },
    });
    try {
      await post(h.port, "/hooks/a", BODY, badSig());
      await post(h.port, "/hooks/a", BODY, badSig());
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 403);
      h.setNow(5_000_000 + 10_001);
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 202);
    } finally {
      await h.stop();
    }
  });

  it("a successful request zeroes the counter", async () => {
    const h = await startServer({
      fail2ban: { maxConsecutiveFailures: 3, banDurationMs: 60_000 },
    });
    try {
      await post(h.port, "/hooks/a", BODY, badSig());
      await post(h.port, "/hooks/a", BODY, badSig());
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 202);
      await post(h.port, "/hooks/a", BODY, badSig());
      await post(h.port, "/hooks/a", BODY, badSig());
      // Counter was zeroed by the 202: still not banned.
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 202);
    } finally {
      await h.stop();
    }
  });

  it("inbound 429s count toward the ban", async () => {
    const h = await startServer({
      fail2ban: { maxConsecutiveFailures: 2, banDurationMs: 60_000 },
      rateLimit: { perIpPerSecond: 1 },
    });
    try {
      // First request consumes the per-IP token (202 = success, counter stays 0).
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 202);
      // Immediate follow-ups hit the limiter: two 429s arm the ban.
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 429);
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 429);
      // Now banned: the ban check runs before the rate limiter.
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 403);
      const blocked = readAudit(h.dir).filter((e) => e.event === "ip_blocked");
      assert.ok(blocked.length >= 1);
    } finally {
      await h.stop();
    }
  });

  it("a static allow-list hit is never banned (exemption wins)", async () => {
    const h = await startServer({
      fail2ban: { maxConsecutiveFailures: 2, banDurationMs: 60_000 },
      ipAcl: { rules: [{ pattern: "/hooks/*", allow: ["127.0.0.0/8"] }] },
    });
    try {
      // Loopback is allow-listed: ten bad signatures, still 401 every time.
      for (let i = 0; i < 10; i++) {
        assert.equal((await post(h.port, "/hooks/a", BODY, badSig())).status, 401);
      }
      const events = readAudit(h.dir);
      assert.equal(events.filter((e) => e.event === "ip_banned").length, 0);
      assert.equal(events.filter((e) => e.event === "ip_blocked").length, 0);
    } finally {
      await h.stop();
    }
  });

  it("operator-plane failures do not feed the counter", async () => {
    const h = await startServer({
      operatorToken: OP,
      fail2ban: { maxConsecutiveFailures: 2, banDurationMs: 60_000 },
    });
    try {
      // Ten bad-bearer operator requests: 403s on the operator plane.
      for (let i = 0; i < 10; i++) {
        const r = await authed(h.port, "/bans", { authorization: "Bearer wrong" });
        assert.equal(r.status, 403);
      }
      // The sender IP is not banned: a webhook still verifies normally.
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 202);
      const bans = await authed(h.port, "/bans", { authorization: `Bearer ${OP}` });
      assert.equal(bans.status, 200);
      assert.deepEqual(bans.json, []);
    } finally {
      await h.stop();
    }
  });
});

describe("fail2ban: operator endpoints", () => {
  it("GET /bans is 404 without an operator credential, 403 on a bad bearer", async () => {
    const h = await startServer({
      fail2ban: { maxConsecutiveFailures: 2, banDurationMs: 60_000 },
    });
    try {
      assert.equal((await authed(h.port, "/bans", {})).status, 404);
      assert.equal((await authed(h.port, "/bans/1.2.3.4/unban", {}, "POST")).status, 404);
    } finally {
      await h.stop();
    }
    const h2 = await startServer({
      operatorToken: OP,
      fail2ban: { maxConsecutiveFailures: 2, banDurationMs: 60_000 },
    });
    try {
      assert.equal((await authed(h2.port, "/bans", { authorization: "Bearer wrong" })).status, 403);
      assert.equal(
        (await authed(h2.port, "/bans/1.2.3.4/unban", { authorization: "Bearer wrong" }, "POST"))
          .status,
        403
      );
    } finally {
      await h2.stop();
    }
  });

  it("GET /bans lists bans; POST /bans/:ip/unban lifts one", async () => {
    const h = await startServer({
      operatorToken: OP,
      fail2ban: { maxConsecutiveFailures: 2, banDurationMs: 60_000 },
    });
    try {
      assert.equal((await post(h.port, "/hooks/a", BODY, badSig())).status, 401);
      assert.equal((await post(h.port, "/hooks/a", BODY, badSig())).status, 401);
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 403);

      const list = await authed(h.port, "/bans", { authorization: `Bearer ${OP}` });
      assert.equal(list.status, 200);
      const bans = list.json as Array<Record<string, unknown>>;
      assert.equal(bans.length, 1);
      // Loopback arrives as ::ffff:127.0.0.1 on the dual-stack socket.
      assert.ok(typeof bans[0].ip === "string" && (bans[0].ip as string).includes("127.0.0.1"));
      assert.equal(bans[0].consecutiveFailures, 2);
      assert.ok(typeof bans[0].bannedAt === "string");
      assert.ok(typeof bans[0].expiresAt === "string");

      // Wrong method on the list route is 405 (registry-driven).
      assert.equal((await authed(h.port, "/bans", { authorization: `Bearer ${OP}` }, "POST")).status, 405);
      // Wrong method on the unban route is 405.
      const ip = bans[0].ip as string;
      assert.equal(
        (await authed(h.port, `/bans/${ip}/unban`, { authorization: `Bearer ${OP}` })).status,
        405
      );

      // Unban a missing IP: 200 with unbanned:false.
      const miss = await authed(
        h.port,
        "/bans/192.0.2.99/unban",
        { authorization: `Bearer ${OP}` },
        "POST"
      );
      assert.equal(miss.status, 200);
      assert.deepEqual(miss.json, { ip: "192.0.2.99", unbanned: false });

      // Unban the real one (URL-encoded; raw IPv6 colons would work too).
      const unban = await authed(
        h.port,
        `/bans/${encodeURIComponent(ip)}/unban`,
        { authorization: `Bearer ${OP}` },
        "POST"
      );
      assert.equal(unban.status, 200);
      assert.deepEqual(unban.json, { ip, unbanned: true });

      // The ban is gone and the counter was reset: a valid webhook is 202.
      assert.equal((await post(h.port, "/hooks/a", BODY, goodSig())).status, 202);
      const list2 = await authed(h.port, "/bans", { authorization: `Bearer ${OP}` });
      assert.deepEqual(list2.json, []);
      const unbannedEvents = readAudit(h.dir).filter((e) => e.event === "ip_unbanned");
      assert.equal(unbannedEvents.length, 2);
    } finally {
      await h.stop();
    }
  });

  it("the operator surface 404s when fail2ban is not configured", async () => {
    const h = await startServer({ operatorToken: OP });
    try {
      const list = await authed(h.port, "/bans", { authorization: `Bearer ${OP}` });
      assert.equal(list.status, 404);
      assert.deepEqual(list.json, { error: "fail2ban is not configured" });
      const unban = await authed(
        h.port,
        "/bans/1.2.3.4/unban",
        { authorization: `Bearer ${OP}` },
        "POST"
      );
      assert.equal(unban.status, 404);
    } finally {
      await h.stop();
    }
  });

  it("malformed unban targets are 400/404", async () => {
    const h = await startServer({
      operatorToken: OP,
      fail2ban: { maxConsecutiveFailures: 2, banDurationMs: 60_000 },
    });
    try {
      // Empty IP segment: not a recognized route (registry-driven 404).
      assert.equal(
        (await authed(h.port, "/bans//unban", { authorization: `Bearer ${OP}` }, "POST")).status,
        404
      );
      // A slash inside the decoded IP: 400.
      assert.equal(
        (await authed(h.port, "/bans/a%2Fb/unban", { authorization: `Bearer ${OP}` }, "POST"))
          .status,
        400
      );
    } finally {
      await h.stop();
    }
  });
});
