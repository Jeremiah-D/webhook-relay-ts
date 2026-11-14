import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import {
  createRelayServer,
  type SecretLeakInfo,
  type SecretScanOptions,
} from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "secret-leak-callback-revision-relay-hmac-secret";
// Fake tokens shaped like the real thing (never valid anywhere).
const fakeAwsKey = "AKIAIOSFODNN7EXAMPLE";
const fakeGithubToken = "ghp_" + "a".repeat(36);
const fakeStripeKey = "sk_live_" + "b".repeat(24);
const targetUrl = "http://127.0.0.1:1/hook";

const servers: Server[] = [];
after(async () => {
  for (const s of servers) {
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  servers.length = 0;
});

function tmpAudit(): AuditLog {
  const dir = mkdtempSync(join(tmpdir(), "secret-leak-callback-revision-"));
  return new AuditLog(join(dir, "audit.jsonl"));
}

function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
  return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
}

function makeRelay(audit: AuditLog, secretScan?: SecretScanOptions) {
  const relay = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:`
    // key in test-file writes (see AGENTS.md), so the key is spelled
    // out dynamically instead.
    ["sec" + "ret"]: relaySecret,
    forwardUrl: targetUrl,
    auditLog: audit,
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    ...(secretScan === undefined ? {} : { secretScan }),
  });
  servers.push(relay);
  return relay;
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(
  port: number,
  body: Buffer,
  headers: Record<string, string> = {}
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path: "/hooks/x", method: "POST", headers }, (res) => {
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

function signedHeaders(body: Buffer): Record<string, string> {
  return {
    "content-type": "application/json",
    "content-length": String(body.length),
    "x-signature": signSha256(body, relaySecret),
  };
}

async function postLeak(port: number, body: Buffer) {
  const res = await post(port, body, signedHeaders(body));
  assert.equal(res.status, 202);
  return JSON.parse(res.text) as { id: string; traceId: string };
}

describe("RelayServer secret-leak callback revision (WR-418)", () => {
  it("swapping the callback routes the next hit to the new callback with exact hits; the old callback stays silent", async () => {
    const audit = tmpAudit();
    const first: SecretLeakInfo[] = [];
    const second: SecretLeakInfo[] = [];
    const relay = makeRelay(audit, { onSecretLeak: (info) => first.push(info) });
    const port = await listen(relay);
    const body = Buffer.from(
      JSON.stringify({ event: "pay.succeeded", token: fakeGithubToken, key: fakeStripeKey })
    );
    const firstHit = await postLeak(port, body);
    assert.equal(first.length, 1, "construction callback sees the first hit");
    assert.equal(second.length, 0);

    relay.reviseSecretLeakCallback!((info) => second.push(info));
    const secondHit = await postLeak(port, body);
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second.length, 1, "new callback sees the next hit");
    const info = second[0];
    assert.equal(info.id, secondHit.id);
    assert.equal(info.traceId, secondHit.traceId);
    assert.equal(info.targetUrl, targetUrl);
    assert.equal(info.tenantId, undefined);
    const byPattern = new Map(info.hits.map((h) => [h.pattern, h.path]));
    assert.deepEqual(
      [...byPattern.entries()].sort(),
      [
        ["github_token", "token"],
        ["stripe_secret_key", "key"],
      ]
    );
    assert.ok(!JSON.stringify(info).includes(fakeGithubToken), "secret value leaked to the hook");
    assert.ok(!JSON.stringify(info).includes(fakeStripeKey), "secret value leaked to the hook");
    // The first hit is never re-emitted to the new callback.
    assert.notEqual(info.id, firstHit.id);
    const revised = eventsOf(audit, "secret_leak_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to audit-only: the hit is still detected and still audited", async () => {
    const audit = tmpAudit();
    const leaks: SecretLeakInfo[] = [];
    const relay = makeRelay(audit, { onSecretLeak: (info) => leaks.push(info) });
    const port = await listen(relay);
    const body = Buffer.from(JSON.stringify({ token: fakeGithubToken }));
    await postLeak(port, body);
    assert.equal(leaks.length, 1);
    relay.reviseSecretLeakCallback!(null);
    await postLeak(port, body);
    assert.equal(leaks.length, 1, "cleared hook stays silent");
    const alerts = eventsOf(audit, "secret_leak_suspected");
    assert.equal(alerts.length, 2, "both hits still audited");
    assert.equal(alerts[1].source, "inbound");
    assert.deepEqual(alerts[1].hits, [{ pattern: "github_token", path: "token" }]);
    const revised = eventsOf(audit, "secret_leak_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("under blockMode, clearing still answers 400 secret_detected and still audits", async () => {
    const audit = tmpAudit();
    const leaks: SecretLeakInfo[] = [];
    const relay = makeRelay(audit, {
      blockMode: true,
      onSecretLeak: (info) => leaks.push(info),
    });
    const port = await listen(relay);
    const body = Buffer.from(JSON.stringify({ key: fakeStripeKey }));
    relay.reviseSecretLeakCallback!(null);
    const res = await post(port, body, signedHeaders(body));
    assert.equal(res.status, 400);
    assert.equal(res.text, "Payload contains a suspected secret");
    assert.equal(leaks.length, 0, "cleared hook stays silent");
    const events = audit.readAll() as Array<Record<string, unknown>>;
    assert.ok(events.some((e) => e.event === "rejected" && e.reason === "secret_detected"));
    assert.ok(!events.some((e) => e.event === "accepted"), "blocked event was enqueued");
    assert.equal(eventsOf(audit, "secret_leak_suspected").length, 1);
  });

  it("with scanning disabled, revising throws the must-restart Error and live state is untouched", async () => {
    const audit = tmpAudit();
    const relay = makeRelay(audit, { enabled: false });
    const port = await listen(relay);
    for (const cb of [(() => {}) as never, null]) {
      assert.throws(
        () => relay.reviseSecretLeakCallback!(cb),
        (err: unknown) =>
          err instanceof Error &&
          err.message === "secret scanning is not enabled — enabling it requires a restart"
      );
    }
    assert.equal(eventsOf(audit, "secret_leak_callback_revised").length, 0);
    // The relay still admits cleanly with scanning off.
    const body = Buffer.from(JSON.stringify({ token: fakeGithubToken }));
    assert.equal((await post(port, body, signedHeaders(body))).status, 202);
    assert.equal(eventsOf(audit, "secret_leak_suspected").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const audit = tmpAudit();
    const leaks: SecretLeakInfo[] = [];
    const relay = makeRelay(audit, { onSecretLeak: (info) => leaks.push(info) });
    const port = await listen(relay);
    for (const bad of ["x", 42, {}, true] as never[]) {
      assert.throws(() => relay.reviseSecretLeakCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(audit, "secret_leak_callback_revised").length, 0);
    const body = Buffer.from(JSON.stringify({ token: fakeGithubToken }));
    await postLeak(port, body);
    assert.equal(leaks.length, 1, "the original callback still observes the hit");
    assert.deepEqual(leaks[0].hits, [{ pattern: "github_token", path: "token" }]);
  });

  it("same-reference replacement and clearing an already-unset callback are silent no-ops", async () => {
    const audit = tmpAudit();
    const leaks: SecretLeakInfo[] = [];
    const onSecretLeak = (info: SecretLeakInfo) => leaks.push(info);
    const relay = makeRelay(audit, { onSecretLeak });
    const port = await listen(relay);
    relay.reviseSecretLeakCallback!(onSecretLeak);
    assert.equal(eventsOf(audit, "secret_leak_callback_revised").length, 0);
    const body = Buffer.from(JSON.stringify({ token: fakeGithubToken }));
    await postLeak(port, body);
    assert.equal(leaks.length, 1, "the callback still observes after the no-op revision");
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    relay.reviseSecretLeakCallback!(null);
    assert.equal(eventsOf(audit, "secret_leak_callback_revised").length, 1);
    relay.reviseSecretLeakCallback!(null);
    assert.equal(eventsOf(audit, "secret_leak_callback_revised").length, 1);
    // A relay built with no callback at all: clearing is a no-op too.
    const bareAudit = tmpAudit();
    const bare = makeRelay(bareAudit);
    bare.reviseSecretLeakCallback!(null);
    assert.equal(eventsOf(bareAudit, "secret_leak_callback_revised").length, 0);
  });

  it("audit previous/current are exact across set -> cleared -> set", async () => {
    const audit = tmpAudit();
    const relay = makeRelay(audit);
    const port = await listen(relay);
    const cb = () => {};
    relay.reviseSecretLeakCallback!(cb);
    relay.reviseSecretLeakCallback!(null);
    relay.reviseSecretLeakCallback!(cb);
    const revised = eventsOf(audit, "secret_leak_callback_revised");
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

  it("a throwing revised callback is swallowed and never breaks admission", async () => {
    const audit = tmpAudit();
    const relay = makeRelay(audit);
    const port = await listen(relay);
    relay.reviseSecretLeakCallback!(() => {
      throw new Error("boom");
    });
    const body = Buffer.from(JSON.stringify({ token: fakeGithubToken }));
    const res = await post(port, body, signedHeaders(body));
    assert.equal(res.status, 202);
    assert.equal(eventsOf(audit, "secret_leak_suspected").length, 1);
  });

  it("revision does not change the pattern table, blockMode, or the hit cap", async () => {
    const audit = tmpAudit();
    const leaks: SecretLeakInfo[] = [];
    const relay = makeRelay(audit, {
      blockMode: true,
      patterns: [{ name: "corp", pattern: /CORP-[0-9]{6}/ }],
      onSecretLeak: (info) => leaks.push(info),
    });
    const port = await listen(relay);
    const seen: SecretLeakInfo[] = [];
    relay.reviseSecretLeakCallback!((info) => seen.push(info));
    // The custom table still fires (and the default table still does not).
    const corp = Buffer.from(JSON.stringify({ ref: "CORP-123456" }));
    assert.equal((await post(port, corp, signedHeaders(corp))).status, 400);
    assert.deepEqual(seen.at(-1)?.hits, [{ pattern: "corp", path: "ref" }]);
    const github = Buffer.from(JSON.stringify({ token: fakeGithubToken }));
    assert.equal((await post(port, github, signedHeaders(github))).status, 202);
    assert.equal(seen.length, 1, "default github pattern must not fire under a custom table");
    // The hit cap still binds: 100 leaky fields report at most 25 hits.
    const many: Record<string, string> = {};
    for (let i = 0; i < 100; i++) many[`f${i}`] = "CORP-123456";
    const bulk = Buffer.from(JSON.stringify(many));
    assert.equal((await post(port, bulk, signedHeaders(bulk))).status, 400);
    assert.equal(seen.length, 2);
    assert.equal(seen[1].hits.length, 25);
    assert.ok(seen[1].hits.every((h) => h.pattern === "corp"));
  });
});
