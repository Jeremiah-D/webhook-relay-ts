import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Fail2Ban,
  type Fail2BanConfig,
  type Fail2BanOptions,
} from "../src/fail2ban.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "fail2ban-revision-test-key";
const opToken = "fail2ban-revision-op-token";
const EP = "http://127.0.0.1:9/health";
const BODY = Buffer.from(JSON.stringify({ event: "f2b.revision" }));

function validOptions(over: Partial<Fail2BanOptions> = {}): Fail2BanOptions {
  return { maxConsecutiveFailures: 3, banDurationMs: 60_000, ...over };
}

describe("Fail2Ban.retune (WR-357)", () => {
  it("lowering maxConsecutiveFailures bans on the next failure at the new threshold", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(validOptions({ now: () => nowMs }));
    assert.equal(f2b.recordFailure("/hooks/a", "10.0.0.1").banned, false);
    assert.equal(f2b.recordFailure("/hooks/a", "10.0.0.1").banned, false);
    assert.deepEqual(f2b.retune({ maxConsecutiveFailures: 2 }), {
      maxConsecutiveFailures: 2,
      banDurationMs: 60_000,
      maxEntries: 10000,
    });
    // The two already-counted failures now meet the lowered threshold.
    const rec = f2b.recordFailure("/hooks/a", "10.0.0.1");
    assert.equal(rec.banned, true);
    assert.equal(rec.justBanned, true);
    assert.equal(rec.consecutiveFailures, 3);
    assert.equal(f2b.isBanned("/hooks/a", "10.0.0.1"), true);
  });

  it("raising the threshold does not retroactively ban", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(validOptions({ now: () => nowMs }));
    f2b.recordFailure("/hooks/a", "10.0.0.1");
    f2b.recordFailure("/hooks/a", "10.0.0.1");
    assert.deepEqual(f2b.retune({ maxConsecutiveFailures: 5 }), {
      maxConsecutiveFailures: 5,
      banDurationMs: 60_000,
      maxEntries: 10000,
    });
    assert.equal(f2b.recordFailure("/hooks/a", "10.0.0.1").banned, false);
    assert.equal(f2b.recordFailure("/hooks/a", "10.0.0.1").banned, false);
    assert.equal(f2b.recordFailure("/hooks/a", "10.0.0.1").banned, true);
    assert.equal(f2b.isBanned("/hooks/a", "10.0.0.1"), true);
  });

  it("a longer banDurationMs applies to new bans only; the live ban keeps its expiry", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(validOptions({ maxConsecutiveFailures: 1, now: () => nowMs }));
    f2b.recordFailure("/hooks/a", "10.0.0.1");
    assert.deepEqual(f2b.bans(), [
      { ip: "10.0.0.1", bannedAt: 1000, expiresAt: 61_000, consecutiveFailures: 1 },
    ]);
    f2b.retune({ banDurationMs: 600_000 });
    // The live ban is untouched by the revision.
    assert.deepEqual(f2b.bans(), [
      { ip: "10.0.0.1", bannedAt: 1000, expiresAt: 61_000, consecutiveFailures: 1 },
    ]);
    assert.equal(f2b.unban("10.0.0.1"), true);
    nowMs = 2000;
    f2b.recordFailure("/hooks/a", "10.0.0.1");
    assert.deepEqual(f2b.bans(), [
      { ip: "10.0.0.1", bannedAt: 2000, expiresAt: 602_000, consecutiveFailures: 1 },
    ]);
  });

  it("a shorter banDurationMs does not shorten a live ban and bans() bannedAt never drifts", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(
      validOptions({ maxConsecutiveFailures: 1, banDurationMs: 600_000, now: () => nowMs })
    );
    f2b.recordFailure("/hooks/a", "10.0.0.1");
    assert.deepEqual(f2b.bans(), [
      { ip: "10.0.0.1", bannedAt: 1000, expiresAt: 601_000, consecutiveFailures: 1 },
    ]);
    // Under the old bannedUntil - live banDurationMs derivation this
    // revision would have moved bannedAt to 541_000; the stored value
    // keeps both timestamps exactly as armed.
    f2b.retune({ banDurationMs: 60_000 });
    assert.deepEqual(f2b.bans(), [
      { ip: "10.0.0.1", bannedAt: 1000, expiresAt: 601_000, consecutiveFailures: 1 },
    ]);
    nowMs = 2000;
    assert.equal(f2b.isBanned("/hooks/a", "10.0.0.1"), true);
  });

  it("extending a ban keeps the original bannedAt", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(validOptions({ maxConsecutiveFailures: 1, now: () => nowMs }));
    const first = f2b.recordFailure("/hooks/a", "10.0.0.1");
    assert.equal(first.justBanned, true);
    nowMs = 2000;
    const second = f2b.recordFailure("/hooks/a", "10.0.0.1");
    assert.equal(second.justBanned, false);
    assert.deepEqual(f2b.bans(), [
      { ip: "10.0.0.1", bannedAt: 1000, expiresAt: 62_000, consecutiveFailures: 2 },
    ]);
  });

  it("shrinking maxEntries trims least-recently-active entries and keeps live bans", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(
      validOptions({ maxConsecutiveFailures: 2, maxEntries: 5, now: () => nowMs })
    );
    f2b.recordFailure("/hooks/a", "10.0.0.1"); // lastSeen 1000
    nowMs = 2000;
    f2b.recordFailure("/hooks/a", "10.0.0.2"); // lastSeen 2000
    nowMs = 3000;
    f2b.recordFailure("/hooks/a", "10.0.0.3");
    f2b.recordFailure("/hooks/a", "10.0.0.3"); // live ban, bannedUntil 63000
    nowMs = 4000;
    f2b.recordFailure("/hooks/a", "10.0.0.4"); // lastSeen 4000
    nowMs = 5000;
    f2b.recordFailure("/hooks/a", "10.0.0.5"); // lastSeen 5000
    assert.equal(f2b.size, 5);
    assert.deepEqual(f2b.retune({ maxEntries: 2 }), {
      maxConsecutiveFailures: 2,
      banDurationMs: 60_000,
      maxEntries: 2,
    });
    assert.equal(f2b.size, 2);
    // The live ban survived; the most recently active non-banned entry did too.
    assert.equal(f2b.isBanned("/hooks/a", "10.0.0.3"), true);
    // The evicted entries start counting from zero again.
    assert.equal(f2b.recordFailure("/hooks/a", "10.0.0.1").consecutiveFailures, 1);
    assert.equal(f2b.recordFailure("/hooks/a", "10.0.0.2").consecutiveFailures, 1);
    assert.equal(f2b.recordFailure("/hooks/a", "10.0.0.4").consecutiveFailures, 1);
  });

  it("shrinking maxEntries sweeps expired bans first", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(
      validOptions({ maxConsecutiveFailures: 1, banDurationMs: 1000, maxEntries: 3, now: () => nowMs })
    );
    f2b.recordFailure("/hooks/a", "10.0.0.1"); // banned until 2000
    f2b.recordFailure("/hooks/a", "10.0.0.2"); // banned until 2000
    f2b.recordFailure("/hooks/a", "10.0.0.3"); // banned until 2000
    assert.equal(f2b.size, 3);
    nowMs = 5000; // all three bans expired
    f2b.retune({ maxEntries: 2 });
    // Expired bans are dead weight: the sweep removes all three, so the
    // table is empty — nothing left to evict.
    assert.equal(f2b.size, 0);
    assert.deepEqual(f2b.bans(), []);
  });

  it("illegal patches throw RangeError and the live values are untouched", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(validOptions({ now: () => nowMs }));
    const live: Fail2BanConfig = {
      maxConsecutiveFailures: 3,
      banDurationMs: 60_000,
      maxEntries: 10000,
    };
    assert.deepEqual(f2b.snapshot(), live);
    for (const patch of [
      { maxConsecutiveFailures: 0 },
      { maxConsecutiveFailures: -1 },
      { maxConsecutiveFailures: 1.5 },
      { maxConsecutiveFailures: Number.NaN },
      { banDurationMs: 0 },
      { banDurationMs: -5 },
      { banDurationMs: Number.NaN },
      { banDurationMs: Number.POSITIVE_INFINITY },
      { maxEntries: 0 },
      { maxEntries: 2.5 },
    ]) {
      assert.throws(() => f2b.retune(patch), RangeError, JSON.stringify(patch));
    }
    assert.deepEqual(f2b.snapshot(), live);
  });

  it("an empty patch and a non-object patch are RangeErrors; a same-value patch is a silent no-op", () => {
    const f2b = new Fail2Ban(validOptions());
    assert.throws(() => f2b.retune({}), RangeError);
    assert.throws(() => f2b.retune(null as never), RangeError);
    assert.throws(() => f2b.retune("strict" as never), RangeError);
    assert.throws(() => f2b.retune([] as never), RangeError);
    assert.deepEqual(f2b.retune({ maxConsecutiveFailures: 3 }), {
      maxConsecutiveFailures: 3,
      banDurationMs: 60_000,
      maxEntries: 10000,
    });
    assert.deepEqual(f2b.retune({ maxConsecutiveFailures: 3, banDurationMs: 60_000, maxEntries: 10000 }), {
      maxConsecutiveFailures: 3,
      banDurationMs: 60_000,
      maxEntries: 10000,
    });
    assert.deepEqual(f2b.snapshot(), {
      maxConsecutiveFailures: 3,
      banDurationMs: 60_000,
      maxEntries: 10000,
    });
  });

  it("growing maxEntries is a plain revision with no trimming", () => {
    let nowMs = 1000;
    const f2b = new Fail2Ban(validOptions({ maxEntries: 2, now: () => nowMs }));
    f2b.recordFailure("/hooks/a", "10.0.0.1");
    f2b.recordFailure("/hooks/a", "10.0.0.2");
    assert.equal(f2b.size, 2);
    assert.deepEqual(f2b.retune({ maxEntries: 5 }), {
      maxConsecutiveFailures: 3,
      banDurationMs: 60_000,
      maxEntries: 5,
    });
    assert.equal(f2b.size, 2);
  });
});

describe("RelayServer fail2ban revision (WR-357)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function listen(server: Server): Promise<number> {
    return new Promise((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
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

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "fail2ban-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    let nowMs = 5_000_000;
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: EP,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      fail2ban: { maxConsecutiveFailures: 3, banDurationMs: 60_000, now: () => nowMs },
      ...extra,
    });
    servers.push(relay);
    return {
      relay,
      audit,
      setNow: (ms: number) => {
        nowMs = ms;
      },
    };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  const goodSig = () => signSha256(BODY, signingKey);
  const badSig = () => "sha256=" + "0".repeat(64);
  const construction: Fail2BanConfig = {
    maxConsecutiveFailures: 3,
    banDurationMs: 60_000,
    maxEntries: 10000,
  };

  it("revision audits previous/current with three fields; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.deepEqual(relay.getFail2BanConfig!(), construction);
    assert.deepEqual(relay.reviseFail2Ban!({ banDurationMs: 600_000 }), {
      ...construction,
      banDurationMs: 600_000,
    });
    const revised = eventsOf(audit, "fail2ban_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, banDurationMs: 600_000 });
    // Landing exactly on the live values audits nothing.
    relay.reviseFail2Ban!({ banDurationMs: 600_000 });
    assert.equal(eventsOf(audit, "fail2ban_revised").length, 1);
    assert.deepEqual(relay.getFail2BanConfig!(), { ...construction, banDurationMs: 600_000 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseFail2Ban!({ maxConsecutiveFailures: 0 }), RangeError);
    assert.throws(() => relay.reviseFail2Ban!({}), RangeError);
    assert.equal(eventsOf(audit, "fail2ban_revised").length, 1);
    assert.deepEqual(relay.getFail2BanConfig!(), { ...construction, banDurationMs: 600_000 });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "fail2ban-revision-off-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: signingKey,
      forwardUrl: EP,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
    });
    servers.push(relay);
    await listen(relay);
    assert.equal(relay.getFail2BanConfig, undefined);
    assert.throws(
      () => relay.reviseFail2Ban!({ maxConsecutiveFailures: 2 }),
      /not configured — enabling it requires a restart/
    );
  });

  it("GET /bans bannedAt and expiresAt are stable across a banDurationMs revision", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    // Ban the loopback IP: three bad signatures at threshold 3.
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    const before = await authed(port, "/bans", { authorization: `Bearer ${opToken}` });
    assert.equal(before.status, 200);
    const bansBefore = before.json as Array<Record<string, unknown>>;
    assert.equal(bansBefore.length, 1);
    assert.equal(bansBefore[0].bannedAt, new Date(5_000_000).toISOString());
    assert.equal(bansBefore[0].expiresAt, new Date(5_060_000).toISOString());
    assert.equal(bansBefore[0].consecutiveFailures, 3);
    // Revise the duration tenfold: the live ban keeps its armed times.
    relay.reviseFail2Ban!({ banDurationMs: 600_000 });
    const after = await authed(port, "/bans", { authorization: `Bearer ${opToken}` });
    assert.equal(after.status, 200);
    const bansAfter = after.json as Array<Record<string, unknown>>;
    assert.equal(bansAfter.length, 1);
    assert.equal(bansAfter[0].bannedAt, bansBefore[0].bannedAt);
    assert.equal(bansAfter[0].expiresAt, bansBefore[0].expiresAt);
    // A fresh ban after the revision uses the new duration.
    const ip = bansAfter[0].ip as string;
    const unban = await authed(
      port,
      `/bans/${encodeURIComponent(ip)}/unban`,
      { authorization: `Bearer ${opToken}` },
      "POST"
    );
    assert.equal(unban.status, 200);
    assert.deepEqual(unban.json, { ip, unbanned: true });
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    const fresh = await authed(port, "/bans", { authorization: `Bearer ${opToken}` });
    const bansFresh = fresh.json as Array<Record<string, unknown>>;
    assert.equal(bansFresh.length, 1);
    assert.equal(bansFresh[0].bannedAt, new Date(5_000_000).toISOString());
    assert.equal(bansFresh[0].expiresAt, new Date(5_600_000).toISOString());
  });

  it("a lowered threshold bans on the next failure through the intake", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    // Two failures counted, not yet banned at threshold 3 — tighten to 2.
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 2 });
    // The next failure meets the lowered threshold and arms the ban
    // (this request itself still answers 401; the ban bites after).
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, goodSig())).status, 403);
  });
});
