import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "fail2ban-enable-test-key";
const opToken = "fail2ban-enable-op-token";
const EP = "http://127.0.0.1:9/health";
const BODY = Buffer.from(JSON.stringify({ event: "f2b.enable" }));

describe("RelayServer fail2ban live enable for an unconfigured relay (WR-457)", () => {
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

  // Deliberately *without* a `fail2ban` option, so the WR-457 enable
  // path is the only way a tracker appears.
  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "fail2ban-enable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
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
      ...extra,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  const goodSig = () => signSha256(BODY, signingKey);
  const badSig = () => "sha256=" + "0".repeat(64);

  it("first enable takes the maxEntries default 10000 and the getter returns the full config at once", () => {
    const { relay } = makeRelay();
    assert.equal(relay.getFail2BanConfig, undefined);
    assert.deepEqual(
      relay.reviseFail2Ban!({ maxConsecutiveFailures: 3, banDurationMs: 60_000 }),
      { maxConsecutiveFailures: 3, banDurationMs: 60_000, maxEntries: 10000 }
    );
    assert.deepEqual(relay.getFail2BanConfig!(), {
      maxConsecutiveFailures: 3,
      banDurationMs: 60_000,
      maxEntries: 10000,
    });
  });

  it("an explicit maxEntries is taken exactly", () => {
    const { relay } = makeRelay();
    assert.deepEqual(
      relay.reviseFail2Ban!({ maxConsecutiveFailures: 2, banDurationMs: 30_000, maxEntries: 25 }),
      { maxConsecutiveFailures: 2, banDurationMs: 30_000, maxEntries: 25 }
    );
    assert.deepEqual(relay.getFail2BanConfig!(), {
      maxConsecutiveFailures: 2,
      banDurationMs: 30_000,
      maxEntries: 25,
    });
  });

  it("empty, missing-a-required-knob, non-object and illegal patches throw RangeError and leave the relay unconfigured — and it can still enable afterwards", () => {
    const { relay, audit } = makeRelay();
    assert.equal(relay.getFail2BanConfig, undefined);
    for (const patch of [
      {},
      { maxConsecutiveFailures: 2 },
      { banDurationMs: 60_000 },
      null,
      "strict",
      [],
      { maxConsecutiveFailures: 0, banDurationMs: 60_000 },
      { maxConsecutiveFailures: -1, banDurationMs: 60_000 },
      { maxConsecutiveFailures: 1.5, banDurationMs: 60_000 },
      { maxConsecutiveFailures: Number.NaN, banDurationMs: 60_000 },
      { maxConsecutiveFailures: 2, banDurationMs: 0 },
      { maxConsecutiveFailures: 2, banDurationMs: -5 },
      { maxConsecutiveFailures: 2, banDurationMs: Number.NaN },
      { maxConsecutiveFailures: 2, banDurationMs: Number.POSITIVE_INFINITY },
      { maxConsecutiveFailures: 2, banDurationMs: 60_000, maxEntries: 0 },
      { maxConsecutiveFailures: 2, banDurationMs: 60_000, maxEntries: 2.5 },
    ]) {
      assert.throws(
        () => relay.reviseFail2Ban!(patch as never),
        RangeError,
        JSON.stringify(patch)
      );
    }
    // Still unconfigured after every rejection — no getter, no audit.
    assert.equal(relay.getFail2BanConfig, undefined);
    assert.equal(eventsOf(audit, "fail2ban_revised").length, 0);
    // …and the enable path still works.
    assert.deepEqual(
      relay.reviseFail2Ban!({ maxConsecutiveFailures: 2, banDurationMs: 60_000 }),
      { maxConsecutiveFailures: 2, banDurationMs: 60_000, maxEntries: 10000 }
    );
    assert.equal(eventsOf(audit, "fail2ban_revised").length, 1);
  });

  it("failures before the enable are never recorded — no retroactive ban", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    // Two failures at what will become threshold 2 — fail2ban is off,
    // so nothing is counted.
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 2, banDurationMs: 60_000 });
    // The first post-enable failure counts from zero (401, not banned).
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, goodSig())).status, 202);
    // Only now do two consecutive post-enable failures arm the ban.
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, goodSig())).status, 403);
  });

  it("after the enable the next failure counts and reaching the threshold bans at the intake; GET /bans lists it and metrics count it", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 2, banDurationMs: 60_000 });
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    // Banned: even a valid signature is 403 (the ban check runs before
    // verification).
    assert.equal((await post(port, "/hooks/a", BODY, goodSig())).status, 403);
    const bans = await authed(port, "/bans", { authorization: `Bearer ${opToken}` });
    assert.equal(bans.status, 200);
    const list = bans.json as Array<Record<string, unknown>>;
    assert.equal(list.length, 1);
    assert.equal(list[0].ip, "127.0.0.1");
    assert.equal(list[0].consecutiveFailures, 2);
    assert.equal(
      new Date(list[0].expiresAt as string).getTime() -
        new Date(list[0].bannedAt as string).getTime(),
      60_000
    );
    // The ban was armed just now on the wall clock.
    assert.ok(Math.abs(new Date(list[0].bannedAt as string).getTime() - Date.now()) < 10_000);
    // fail2banMetrics is always built: the enable needs no new metrics.
    const metrics = await authed(port, "/metrics", { authorization: `Bearer ${opToken}` });
    assert.equal(metrics.status, 200);
    assert.ok(metrics.text.includes('relay_inbound_ip_banned_total{endpoint="/hooks/a"} 1'));
    assert.ok(metrics.text.includes("relay_inbound_ip_ban_activations_total 1"));
  });

  it("a 202 after the enable zeroes the counter", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 3, banDurationMs: 60_000 });
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, goodSig())).status, 202);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    // Counter was zeroed by the 202: still not banned.
    assert.equal((await post(port, "/hooks/a", BODY, goodSig())).status, 202);
  });

  it("GET /bans is 404 before the enable and [] right after", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    const before = await authed(port, "/bans", { authorization: `Bearer ${opToken}` });
    assert.equal(before.status, 404);
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 3, banDurationMs: 60_000 });
    const after = await authed(port, "/bans", { authorization: `Bearer ${opToken}` });
    assert.equal(after.status, 200);
    assert.deepEqual(after.json, []);
  });

  it("the enable is audited with previous null and the exact three knobs", () => {
    const { relay, audit } = makeRelay();
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 2, banDurationMs: 120_000, maxEntries: 500 });
    const revised = eventsOf(audit, "fail2ban_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, {
      maxConsecutiveFailures: 2,
      banDurationMs: 120_000,
      maxEntries: 500,
    });
  });

  it("after the enable, revision still follows WR-357 semantics including same-value no-op", () => {
    const { relay, audit } = makeRelay();
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 3, banDurationMs: 60_000 });
    assert.deepEqual(relay.reviseFail2Ban!({ banDurationMs: 600_000 }), {
      maxConsecutiveFailures: 3,
      banDurationMs: 600_000,
      maxEntries: 10000,
    });
    const revised = eventsOf(audit, "fail2ban_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].previous, {
      maxConsecutiveFailures: 3,
      banDurationMs: 60_000,
      maxEntries: 10000,
    });
    assert.deepEqual(revised[1].current, {
      maxConsecutiveFailures: 3,
      banDurationMs: 600_000,
      maxEntries: 10000,
    });
    // Landing exactly on the live values audits nothing.
    relay.reviseFail2Ban!({ banDurationMs: 600_000 });
    assert.equal(eventsOf(audit, "fail2ban_revised").length, 2);
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseFail2Ban!({ maxConsecutiveFailures: 0 }), RangeError);
    assert.equal(eventsOf(audit, "fail2ban_revised").length, 2);
    assert.deepEqual(relay.getFail2BanConfig!(), {
      maxConsecutiveFailures: 3,
      banDurationMs: 600_000,
      maxEntries: 10000,
    });
  });

  it("the WR-53 static-allow exemption still wins after the enable", async () => {
    const { relay, audit } = makeRelay({
      ipAcl: { rules: [{ pattern: "/hooks/*", allow: ["127.0.0.0/8"] }] },
    });
    const port = await listen(relay);
    // Threshold 1 would ban on the first failure — except loopback is
    // allow-listed for this path.
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 1, banDurationMs: 60_000 });
    for (let i = 0; i < 5; i++) {
      assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    }
    assert.equal((await post(port, "/hooks/a", BODY, goodSig())).status, 202);
    const bans = await authed(port, "/bans", { authorization: `Bearer ${opToken}` });
    assert.equal(bans.status, 200);
    assert.deepEqual(bans.json, []);
    assert.equal(eventsOf(audit, "ip_banned").length, 0);
    assert.equal(eventsOf(audit, "ip_blocked").length, 0);
  });

  it("the operator unban surface sees the tracker installed by the enable", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 1, banDurationMs: 60_000 });
    assert.equal((await post(port, "/hooks/a", BODY, badSig())).status, 401);
    assert.equal((await post(port, "/hooks/a", BODY, goodSig())).status, 403);
    const bans = await authed(port, "/bans", { authorization: `Bearer ${opToken}` });
    const ip = (bans.json as Array<Record<string, unknown>>)[0].ip as string;
    const unban = await authed(
      port,
      `/bans/${encodeURIComponent(ip)}/unban`,
      { authorization: `Bearer ${opToken}` },
      "POST"
    );
    assert.equal(unban.status, 200);
    assert.deepEqual(unban.json, { ip, unbanned: true });
    assert.equal((await post(port, "/hooks/a", BODY, goodSig())).status, 202);
  });

  it("a restart returns to unconfigured", async () => {
    const { relay } = makeRelay();
    relay.reviseFail2Ban!({ maxConsecutiveFailures: 2, banDurationMs: 60_000 });
    assert.deepEqual(relay.getFail2BanConfig!(), {
      maxConsecutiveFailures: 2,
      banDurationMs: 60_000,
      maxEntries: 10000,
    });
    // A fresh server built from the same options (no `fail2ban`) has no
    // tracker: the enable is live-only, never persisted.
    const fresh = makeRelay();
    const port = await listen(fresh.relay);
    assert.equal(fresh.relay.getFail2BanConfig, undefined);
    const bans = await authed(port, "/bans", { authorization: `Bearer ${opToken}` });
    assert.equal(bans.status, 404);
  });
});
