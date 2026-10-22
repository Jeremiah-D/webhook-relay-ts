import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import { SecretScanner, DEFAULT_SECRET_PATTERNS } from "../src/secret-scan.ts";
import { FieldMask } from "../src/masking.ts";
import { signSha256 } from "../src/verify.ts";
import { createRelayServer, type SecretLeakInfo, type SecretScanOptions } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "secret-scan-relay-hmac-secret";
const opToken = "secret-scan-op-token";
// Fake tokens shaped like the real thing (never valid anywhere).
const fakeAwsKey = "AKIAIOSFODNN7EXAMPLE";
const fakeGithubToken = "ghp_" + "a".repeat(36);
const fakeStripeKey = "sk_live_" + "b".repeat(24);
const fakeSlackToken = "xoxb-123-456-abcdefghij";
const fakePrivateKey = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----";

function tmpLog(opts: {
  auditKey?: { id: string; key: string | Buffer };
  secretScanner?: SecretScanner;
  fieldMask?: FieldMask;
} = {}): { audit: AuditLog; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "secret-scan-"));
  const path = join(dir, "audit.jsonl");
  return { audit: new AuditLog(path, opts), path };
}

function rawText(path: string): string {
  return readFileSync(path, "utf8");
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(
  port: number,
  path: string,
  body: Buffer,
  headers: Record<string, string> = {}
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
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

function signedHeaders(body: Buffer): Record<string, string> {
  return {
    "content-type": "application/json",
    "content-length": String(body.length),
    "x-signature": signSha256(body, relaySecret),
  };
}

describe("SecretScanner unit (WR-183)", () => {
  it("detects every default pattern by name", () => {
    const s = new SecretScanner();
    const cases: Array<[string, string]> = [
      [fakeAwsKey, "aws_access_key_id"],
      ["AKIDIOSFODNN7EXAMPLE", "aws_access_key_id"],
      [fakeGithubToken, "github_token"],
      ["gho_" + "c".repeat(36), "github_token"],
      [fakeStripeKey, "stripe_secret_key"],
      ["sk_test_" + "d".repeat(24), "stripe_secret_key"],
      [fakeSlackToken, "slack_bot_token"],
      [fakePrivateKey, "private_key"],
    ];
    for (const [text, name] of cases) {
      const hits = s.scanText(`payload: ${text} end`);
      assert.ok(
        hits.some((h) => h.pattern === name && h.path === "(raw)"),
        `expected ${name} to fire on ${text.slice(0, 20)}`
      );
    }
  });

  it("stays quiet on clean text", () => {
    const s = new SecretScanner();
    assert.deepEqual(s.scanText("hello world"), []);
    assert.deepEqual(s.scanText(JSON.stringify({ event: "ping", n: 42 })), []);
    // Near-misses that must not fire: short/odd-shaped lookalikes.
    assert.deepEqual(s.scanText("AKIA too short"), []);
    assert.deepEqual(s.scanText("ghp_short"), []);
  });

  it("walks JSON with dot paths, arrays, and nesting", () => {
    const s = new SecretScanner();
    const hits = s.scanJson({
      payment: { card: { cvv: "n/a", note: fakeStripeKey } },
      items: [{ sku: "x" }, { sku: fakeGithubToken }],
    });
    const byPath = new Map(hits.map((h) => [`${h.pattern}@${h.path}`, true]));
    assert.ok(byPath.has(`stripe_secret_key@payment.card.note`));
    assert.ok(byPath.has(`github_token@items[1].sku`));
  });

  it("scans wire buffers: JSON bodies get paths, other bodies get (raw)", () => {
    const s = new SecretScanner();
    const jsonHits = s.scanBuffer(Buffer.from(JSON.stringify({ token: fakeAwsKey })));
    assert.deepEqual(jsonHits, [{ pattern: "aws_access_key_id", path: "token" }]);
    const rawHits = s.scanBuffer(Buffer.from(`plain text ${fakeSlackToken}`));
    assert.deepEqual(rawHits, [{ pattern: "slack_bot_token", path: "(raw)" }]);
  });

  it("skips __proto__/constructor/prototype lanes and caps hits", () => {
    const s = new SecretScanner();
    const evil = JSON.parse(`{"__proto__": {"x": "${fakeGithubToken}"}}`);
    assert.deepEqual(s.scanJson(evil), []);
    const many: Record<string, string> = {};
    for (let i = 0; i < 100; i++) many[`f${i}`] = fakeStripeKey;
    assert.ok(s.scanJson(many).length <= 25);
  });

  it("a custom table replaces the defaults; invalid tables throw RangeError", () => {
    const custom = new SecretScanner({ patterns: [{ name: "corp", pattern: /CORP-[0-9]{6}/ }] });
    assert.deepEqual(custom.patternNames(), ["corp"]);
    assert.equal(custom.scanText("CORP-123456").length, 1);
    assert.deepEqual(custom.scanText(fakeGithubToken), []);
    assert.throws(() => new SecretScanner({ patterns: [] }), RangeError);
    assert.throws(() => new SecretScanner({ patterns: [{ name: "", pattern: /x/ }] }), RangeError);
    assert.throws(() => new SecretScanner({ patterns: [{ name: "x", pattern: "not-a-regex" as never }] }), RangeError);
    assert.throws(() => new SecretScanner({ patterns: [{ name: "x", pattern: /a/g }] }), RangeError);
    assert.throws(
      () =>
        new SecretScanner({
          patterns: [
            { name: "dup", pattern: /a/ },
            { name: "dup", pattern: /b/ },
          ],
        }),
      RangeError
    );
  });

  it("scanEventPayload reads payload fields and never throws", () => {
    const s = new SecretScanner();
    assert.deepEqual(
      s.scanEventPayload({ event: "accepted", payload: Buffer.from(JSON.stringify({ k: fakeAwsKey })) }),
      [{ pattern: "aws_access_key_id", path: "k" }]
    );
    assert.deepEqual(s.scanEventPayload({ event: "accepted" }), []);
    assert.deepEqual(s.scanEventPayload({ event: "accepted", payload: 42 }), []);
    assert.deepEqual(s.scanEventPayload({ event: "accepted", payload: null }), []);
  });

  it("DEFAULT_SECRET_PATTERNS exposes the default table", () => {
    assert.ok(DEFAULT_SECRET_PATTERNS.length >= 5);
  });
});

describe("AuditLog secret scan (WR-183)", () => {
  it("appends a secret_leak_suspected alert with pattern+path, never the value", () => {
    const { audit, path } = tmpLog({ secretScanner: new SecretScanner() });
    audit.append({
      event: "accepted",
      id: "e1",
      targetUrl: "http://127.0.0.1:9/hook",
      payload: Buffer.from(JSON.stringify({ token: fakeGithubToken })),
    });
    const events = audit.readAll() as Array<Record<string, unknown>>;
    assert.equal(events.length, 2);
    const alert = events[1];
    assert.equal(alert.event, "secret_leak_suspected");
    assert.equal(alert.source, "audit");
    assert.deepEqual(alert.hits, [{ pattern: "github_token", path: "token" }]);
    assert.equal(alert.id, "e1");
    // The secret value never reaches the file — neither in the alert nor
    // anywhere else.
    assert.ok(!rawText(path).includes(fakeGithubToken), "secret value leaked to the audit file");
  });

  it("masking still lands first: the persisted line is masked, the alert is separate", () => {
    const { audit, path } = tmpLog({
      secretScanner: new SecretScanner(),
      fieldMask: new FieldMask({ "http://127.0.0.1:9/hook": [{ path: "token" }] }),
    });
    audit.append({
      event: "accepted",
      id: "e2",
      targetUrl: "http://127.0.0.1:9/hook",
      payload: { token: fakeGithubToken },
    });
    const text = rawText(path);
    assert.ok(!text.includes(fakeGithubToken), "raw secret reached the audit file");
    assert.ok(text.includes("****"), "mask did not land");
    const alerts = (audit.readAll() as Array<Record<string, unknown>>).filter(
      (e) => e.event === "secret_leak_suspected"
    );
    assert.equal(alerts.length, 1);
    assert.deepEqual(alerts[0].hits, [{ pattern: "github_token", path: "token" }]);
  });

  it("alert events are never re-scanned (no recursion)", () => {
    const { audit, path } = tmpLog({ secretScanner: new SecretScanner() });
    audit.append({ event: "accepted", id: "e3", payload: fakePrivateKey });
    const events = audit.readAll() as Array<Record<string, unknown>>;
    assert.equal(events.length, 2);
    assert.equal(events[1].event, "secret_leak_suspected");
    assert.ok(rawText(path).split("\n").filter((l) => l.trim().length > 0).length === 2);
  });

  it("clean payloads produce no alert", () => {
    const { audit } = tmpLog({ secretScanner: new SecretScanner() });
    audit.append({ event: "accepted", id: "e4", payload: { hello: "world" } });
    assert.equal((audit.readAll() as unknown[]).length, 1);
  });

  it("setSecretScanner installs the scanner after construction", () => {
    const { audit } = tmpLog();
    audit.setSecretScanner(new SecretScanner());
    audit.append({ event: "accepted", id: "e5", payload: fakeSlackToken });
    const events = audit.readAll() as Array<Record<string, unknown>>;
    assert.equal(events.length, 2);
    assert.equal(events[1].event, "secret_leak_suspected");
  });
});

describe("server inbound secret scan (WR-183)", () => {
  function makeRelay(
    audit: AuditLog,
    secretScan?: SecretScanOptions,
    extra: { auditPayloads?: boolean } = {}
  ) {
    return createRelayServer({
      secret: relaySecret,
      forwardUrl: "http://127.0.0.1:1/hook",
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...(secretScan === undefined ? {} : { secretScan }),
      ...extra,
    });
  }

  async function closeRelay(relay: { close(): void; once(e: string, cb: () => void): void }) {
    relay.close();
    await new Promise<void>((r) => relay.once("close", r));
  }

  it("default alert-only: 202 accepted, alert audited, onSecretLeak called, no secret value stored", async () => {
    const { audit, path } = tmpLog();
    const leaks: SecretLeakInfo[] = [];
    const relay = makeRelay(audit, { onSecretLeak: (info) => leaks.push(info) });
    const port = await listen(relay);
    try {
      const body = Buffer.from(JSON.stringify({ event: "pay.succeeded", token: fakeGithubToken }));
      const res = await post(port, "/hooks/x", body, signedHeaders(body));
      assert.equal(res.status, 202);
      assert.equal(leaks.length, 1);
      assert.deepEqual(leaks[0].hits, [{ pattern: "github_token", path: "token" }]);
      assert.ok(!JSON.stringify(leaks[0]).includes(fakeGithubToken));
      const alerts = (audit.readAll() as Array<Record<string, unknown>>).filter(
        (e) => e.event === "secret_leak_suspected"
      );
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].source, "inbound");
      assert.ok(!rawText(path).includes(fakeGithubToken), "secret value leaked to audit file");
    } finally {
      await closeRelay(relay);
    }
  });

  it("blockMode: 400 secret_detected, never enqueued, alert audited", async () => {
    const { audit } = tmpLog();
    const relay = makeRelay(audit, { blockMode: true });
    const port = await listen(relay);
    try {
      const body = Buffer.from(JSON.stringify({ key: fakeStripeKey }));
      const res = await post(port, "/hooks/x", body, signedHeaders(body));
      assert.equal(res.status, 400);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      assert.ok(events.some((e) => e.event === "rejected" && e.reason === "secret_detected"));
      assert.ok(!events.some((e) => e.event === "accepted"), "blocked event was enqueued");
      const alerts = events.filter((e) => e.event === "secret_leak_suspected");
      assert.equal(alerts.length, 1);
      assert.deepEqual(alerts[0].hits, [{ pattern: "stripe_secret_key", path: "key" }]);
    } finally {
      await closeRelay(relay);
    }
  });

  it("blockMode with a custom pattern table", async () => {
    const { audit } = tmpLog();
    const relay = makeRelay(audit, {
      blockMode: true,
      patterns: [{ name: "corp", pattern: /CORP-[0-9]{6}/ }],
    });
    const port = await listen(relay);
    try {
      const body = Buffer.from(JSON.stringify({ ref: "CORP-123456" }));
      assert.equal((await post(port, "/hooks/x", body, signedHeaders(body))).status, 400);
      const clean = Buffer.from(JSON.stringify({ ref: "nope" }));
      assert.equal((await post(port, "/hooks/x", clean, signedHeaders(clean))).status, 202);
    } finally {
      await closeRelay(relay);
    }
  });

  it("enabled: false disables the intake scan entirely", async () => {
    const { audit } = tmpLog();
    const relay = makeRelay(audit, { enabled: false });
    const port = await listen(relay);
    try {
      const body = Buffer.from(JSON.stringify({ token: fakeGithubToken }));
      assert.equal((await post(port, "/hooks/x", body, signedHeaders(body))).status, 202);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      assert.ok(!events.some((e) => e.event === "secret_leak_suspected"));
    } finally {
      await closeRelay(relay);
    }
  });

  it("with auditPayloads on, exactly one alert fires (the audit-log scan)", async () => {
    const { audit } = tmpLog();
    const relay = makeRelay(audit, undefined, { auditPayloads: true });
    const port = await listen(relay);
    try {
      const body = Buffer.from(JSON.stringify({ token: fakeAwsKey }));
      assert.equal((await post(port, "/hooks/x", body, signedHeaders(body))).status, 202);
      const alerts = (audit.readAll() as Array<Record<string, unknown>>).filter(
        (e) => e.event === "secret_leak_suspected"
      );
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].source, "audit");
    } finally {
      await closeRelay(relay);
    }
  });

  it("a throwing onSecretLeak hook never breaks admission", async () => {
    const { audit } = tmpLog();
    const relay = makeRelay(audit, {
      onSecretLeak: () => {
        throw new Error("boom");
      },
    });
    const port = await listen(relay);
    try {
      const body = Buffer.from(JSON.stringify({ token: fakeGithubToken }));
      assert.equal((await post(port, "/hooks/x", body, signedHeaders(body))).status, 202);
    } finally {
      await closeRelay(relay);
    }
  });

  it("blockMode with enabled: false is a RangeError at startup", () => {
    const { audit } = tmpLog();
    assert.throws(
      () => makeRelay(audit, { enabled: false, blockMode: true }),
      RangeError
    );
  });
});
