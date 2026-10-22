import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import {
  DEFAULT_OPERATOR_REQUESTS_PER_MINUTE,
  digestOperatorCredential,
  OPERATOR_RATE_LIMIT_WINDOW_MS,
  OperatorRateLimiter,
  OperatorRateLimitMetrics,
} from "../src/operator-ratelimit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const legacyToken = "wr180-legacy-token-aaa";
const keyOne = "wr180-key-one-bbb111";
const keyTwo = "wr180-key-two-ccc222";
const wrongKey = "wr180-wrong-key-zzz999";
const forwardTarget = "http://127.0.0.1:1/hook";

/** Deterministic clock for the sliding-window unit tests. */
function fakeClock(startMs = 1_000_000) {
  let at = startMs;
  return {
    now: () => at,
    advance: (ms: number) => {
      at += ms;
    },
  };
}

describe("digestOperatorCredential", () => {
  it("is the stable SHA-256 hex digest of the credential", () => {
    const d = digestOperatorCredential(keyOne);
    assert.equal(d, createHash("sha256").update(keyOne, "utf8").digest("hex"));
    assert.match(d, /^[0-9a-f]{64}$/);
    assert.equal(digestOperatorCredential(keyOne), d);
  });

  it("differs per credential", () => {
    assert.notEqual(digestOperatorCredential(keyOne), digestOperatorCredential(keyTwo));
  });
});

describe("OperatorRateLimiter", () => {
  it("defaults to 60 requests/minute per client", () => {
    const clock = fakeClock();
    const limiter = new OperatorRateLimiter({ now: clock.now });
    assert.equal(limiter.budgetPerMinute(), DEFAULT_OPERATOR_REQUESTS_PER_MINUTE);
    assert.equal(limiter.keyByMode(), "ip");
    for (let i = 0; i < 60; i++) {
      assert.deepEqual(limiter.take("c1", "single"), { ok: true });
    }
    const verdict = limiter.take("c1", "single");
    assert.equal(verdict.ok, false);
    if (!verdict.ok) assert.ok(verdict.retryAfterMs > 0);
  });

  it("honors a custom budget", () => {
    const clock = fakeClock();
    const limiter = new OperatorRateLimiter({ requestsPerMinute: 2, now: clock.now });
    assert.deepEqual(limiter.take("c1", "single"), { ok: true });
    assert.deepEqual(limiter.take("c1", "single"), { ok: true });
    const verdict = limiter.take("c1", "single");
    assert.equal(verdict.ok, false);
  });

  it("throws RangeError on invalid budgets", () => {
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      assert.throws(() => new OperatorRateLimiter({ requestsPerMinute: bad }), RangeError);
    }
    assert.throws(
      () => new OperatorRateLimiter({ keyBy: "bogus" as never }),
      RangeError
    );
  });

  it("floors fractional budgets with a minimum of 1", () => {
    const clock = fakeClock();
    const limiter = new OperatorRateLimiter({ requestsPerMinute: 2.9, now: clock.now });
    assert.equal(limiter.budgetPerMinute(), 2);
    const tiny = new OperatorRateLimiter({ requestsPerMinute: 0.5, now: clock.now });
    assert.equal(tiny.budgetPerMinute(), 1);
  });

  it("is a true sliding window: budget frees as admissions expire", () => {
    const clock = fakeClock();
    const limiter = new OperatorRateLimiter({ requestsPerMinute: 2, now: clock.now });
    limiter.take("c1", "single");
    limiter.take("c1", "single");
    assert.equal(limiter.take("c1", "single").ok, false);
    // Half the window later the first admission still counts.
    clock.advance(OPERATOR_RATE_LIMIT_WINDOW_MS / 2);
    const mid = limiter.take("c1", "single");
    assert.equal(mid.ok, false);
    if (!mid.ok) {
      // Honest retry-after: ~30s until the oldest admission expires.
      assert.ok(mid.retryAfterMs > 0 && mid.retryAfterMs <= OPERATOR_RATE_LIMIT_WINDOW_MS / 2);
    }
    // Past the full window both admissions expired.
    clock.advance(OPERATOR_RATE_LIMIT_WINDOW_MS / 2 + 1);
    assert.deepEqual(limiter.take("c1", "single"), { ok: true });
  });

  it("a rejection never consumes budget", () => {
    const clock = fakeClock();
    const limiter = new OperatorRateLimiter({ requestsPerMinute: 1, now: clock.now });
    assert.deepEqual(limiter.take("c1", "single"), { ok: true });
    const rejected = limiter.take("c1", "single");
    assert.equal(rejected.ok, false);
    // The rejected request must not have extended the window: right after
    // the single admission expires, one request is admitted again.
    if (!rejected.ok) clock.advance(rejected.retryAfterMs + 1);
    assert.deepEqual(limiter.take("c1", "single"), { ok: true });
  });

  it("isolates clients and planes (WR-56: shared instance, per-plane counters)", () => {
    const clock = fakeClock();
    const limiter = new OperatorRateLimiter({ requestsPerMinute: 1, now: clock.now });
    assert.deepEqual(limiter.take("c1", "single"), { ok: true });
    assert.equal(limiter.take("c1", "single").ok, false);
    // Another client is unaffected…
    assert.deepEqual(limiter.take("c2", "single"), { ok: true });
    // …and the same client on the other plane has its own budget.
    assert.deepEqual(limiter.take("c1", "operator"), { ok: true });
    assert.equal(limiter.take("c1", "operator").ok, false);
    assert.equal(limiter.trackedClients(), 3);
  });

  it("clamps a backward clock at zero (never grants extra budget)", () => {
    const clock = fakeClock();
    const limiter = new OperatorRateLimiter({ requestsPerMinute: 1, now: clock.now });
    assert.deepEqual(limiter.take("c1", "single"), { ok: true });
    clock.advance(-OPERATOR_RATE_LIMIT_WINDOW_MS);
    assert.equal(limiter.take("c1", "single").ok, false);
  });

  it("stats() exposes per-client windows deterministically ordered", () => {
    const clock = fakeClock();
    const limiter = new OperatorRateLimiter({ requestsPerMinute: 5, now: clock.now });
    limiter.take("zeta", "operator");
    limiter.take("alpha", "single");
    limiter.take("alpha", "single");
    const s = limiter.stats();
    assert.equal(s.enabled, true);
    assert.equal(s.budgetPerMinute, 5);
    assert.equal(s.keyBy, "ip");
    assert.equal(s.clients.length, 2);
    // Sorted by plane, then client key.
    assert.deepEqual(
      s.clients.map((c) => [c.plane, c.clientKey, c.admittedInWindow]),
      [
        ["operator", "zeta", 1],
        ["single", "alpha", 2],
      ]
    );
    assert.ok(s.clients[0].windowResetsInMs > 0);
  });
});

describe("OperatorRateLimitMetrics", () => {
  it("renders nothing until the first denial", () => {
    assert.equal(new OperatorRateLimitMetrics().render(), "");
  });

  it("renders one counter series per plane that denied", () => {
    const m = new OperatorRateLimitMetrics();
    m.record("single");
    m.record("single");
    m.record("operator");
    const out = m.render();
    assert.ok(out.includes("# HELP relay_operator_ratelimited_total"));
    assert.ok(out.includes("# TYPE relay_operator_ratelimited_total counter"));
    assert.ok(out.includes('relay_operator_ratelimited_total{plane="single"} 2'));
    assert.ok(out.includes('relay_operator_ratelimited_total{plane="operator"} 1'));
  });
});

// ---------------------------------------------------------------------------
// Server integration: the limiter sits after auth, before business handling.
// ---------------------------------------------------------------------------

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function call(
  port: number,
  method: string,
  path: string,
  bearer?: string
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; text: string }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (bearer !== undefined) headers["authorization"] = `Bearer ${bearer}`;
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers as Record<string, string | string[] | undefined>,
          text: Buffer.concat(chunks).toString(),
        })
      );
    });
    r.on("error", reject);
    r.end();
  });
}

function makeRelay(opts: {
  operatorToken?: string;
  operatorKeys?: Array<{ id: string; key: string; scopes?: Array<"read" | "admin"> }>;
  operatorRateLimit?: { requestsPerMinute?: number; keyBy?: "token" | "ip" };
}) {
  const dir = mkdtempSync(join(tmpdir(), "wr180-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const server = createRelayServer({
    forwardUrl: forwardTarget,
    auditLog: audit,
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    operatorToken: opts.operatorToken,
    operatorKeys: opts.operatorKeys,
    operatorRateLimit: opts.operatorRateLimit,
  });
  return { server, audit };
}

async function closeRelay(server: Server) {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function rejectedAudits(audit: AuditLog): Array<Record<string, unknown>> {
  return (audit.readAll() as Array<Record<string, unknown>>).filter(
    (e) => e["event"] === "rejected" && e["reason"] === "operator_rate_limited"
  );
}

describe("server: operator-plane rate limiting (WR-180)", () => {
  it("answers 429 with retry-after once the budget is spent", async () => {
    const { server, audit } = makeRelay({
      operatorToken: legacyToken,
      operatorRateLimit: { requestsPerMinute: 2 },
    });
    const port = await listen(server);
    try {
      assert.equal((await call(port, "GET", "/metrics", legacyToken)).status, 200);
      assert.equal((await call(port, "GET", "/metrics", legacyToken)).status, 200);
      const denied = await call(port, "GET", "/metrics", legacyToken);
      assert.equal(denied.status, 429);
      const retryAfter = Number(denied.headers["retry-after"]);
      assert.ok(Number.isInteger(retryAfter) && retryAfter >= 1);
      // Audited as rejected/operator_rate_limited with the key identity.
      const audits = rejectedAudits(audit);
      assert.equal(audits.length, 1);
      assert.equal(audits[0]["path"], "/metrics");
      assert.equal(audits[0]["operatorKeyId"], "legacy");
      assert.ok(typeof audits[0]["retryAfterMs"] === "number");
    } finally {
      await closeRelay(server);
    }
  });

  it("is unlimited when the option is unset (byte-identical operator path)", async () => {
    const { server } = makeRelay({ operatorToken: legacyToken });
    const port = await listen(server);
    try {
      for (let i = 0; i < 5; i++) {
        assert.equal((await call(port, "GET", "/metrics", legacyToken)).status, 200);
      }
      // getOperatorRateLimitStats is only exposed when configured.
      assert.equal(server.getOperatorRateLimitStats, undefined);
    } finally {
      await closeRelay(server);
    }
  });

  it("wrong bearer stays 403 and never burns the real budget", async () => {
    const { server } = makeRelay({
      operatorToken: legacyToken,
      operatorRateLimit: { requestsPerMinute: 1 },
    });
    const port = await listen(server);
    try {
      assert.equal((await call(port, "GET", "/metrics", wrongKey)).status, 403);
      assert.equal((await call(port, "GET", "/metrics", wrongKey)).status, 403);
      // The real token still has its full budget: auth failures are not
      // rate-limited here (they keep the existing 403 posture).
      assert.equal((await call(port, "GET", "/metrics", legacyToken)).status, 200);
      assert.equal((await call(port, "GET", "/metrics", legacyToken)).status, 429);
    } finally {
      await closeRelay(server);
    }
  });

  it('keyBy "token" attributes the budget to the credential, not the IP', async () => {
    const { server } = makeRelay({
      operatorKeys: [
        { id: "one", key: keyOne, scopes: ["read"] },
        { id: "two", key: keyTwo, scopes: ["read"] },
      ],
      operatorRateLimit: { requestsPerMinute: 1, keyBy: "token" },
    });
    const port = await listen(server);
    try {
      assert.equal((await call(port, "GET", "/metrics", keyOne)).status, 200);
      assert.equal((await call(port, "GET", "/metrics", keyOne)).status, 429);
      // A different credential has its own budget even from the same IP.
      assert.equal((await call(port, "GET", "/metrics", keyTwo)).status, 200);
      assert.equal((await call(port, "GET", "/metrics", keyTwo)).status, 429);
      const stats = server.getOperatorRateLimitStats?.();
      assert.ok(stats !== undefined);
      assert.equal(stats.keyBy, "token");
      // Client keys are digests — the raw credential never appears.
      const expectedKeys = new Set([digestOperatorCredential(keyOne), digestOperatorCredential(keyTwo)]);
      for (const c of stats.clients) assert.ok(expectedKeys.has(c.clientKey));
      assert.ok(!JSON.stringify(stats).includes(keyOne));
      assert.ok(!JSON.stringify(stats).includes(keyTwo));
    } finally {
      await closeRelay(server);
    }
  });

  it("exposes getOperatorRateLimitStats with per-client windows", async () => {
    const { server } = makeRelay({
      operatorToken: legacyToken,
      operatorRateLimit: { requestsPerMinute: 10 },
    });
    const port = await listen(server);
    try {
      await call(port, "GET", "/audit", legacyToken);
      await call(port, "GET", "/audit", legacyToken);
      const stats = server.getOperatorRateLimitStats?.();
      assert.ok(stats !== undefined);
      assert.equal(stats.enabled, true);
      assert.equal(stats.budgetPerMinute, 10);
      assert.equal(stats.clients.length, 1);
      assert.equal(stats.clients[0].plane, "single");
      assert.equal(stats.clients[0].admittedInWindow, 2);
    } finally {
      await closeRelay(server);
    }
  });

  it("renders relay_operator_ratelimited_total in the exposition", async () => {
    // keyBy "token" gives each credential its own budget, so keyOne can
    // spend its budget (firing the counter) while keyTwo still has budget
    // to read the exposition.
    const { server } = makeRelay({
      operatorKeys: [
        { id: "one", key: keyOne, scopes: ["read"] },
        { id: "two", key: keyTwo, scopes: ["read"] },
      ],
      operatorRateLimit: { requestsPerMinute: 1, keyBy: "token" },
    });
    const port = await listen(server);
    try {
      const before = await call(port, "GET", "/metrics", keyOne);
      assert.equal(before.status, 200);
      assert.ok(!before.text.includes("relay_operator_ratelimited_total"));
      assert.equal((await call(port, "GET", "/metrics", keyOne)).status, 429);
      const after = await call(port, "GET", "/metrics", keyTwo);
      assert.equal(after.status, 200);
      assert.ok(after.text.includes('relay_operator_ratelimited_total{plane="single"} 1'));
    } finally {
      await closeRelay(server);
    }
  });

  it("applies to every operator path, not just /metrics", async () => {
    const { server } = makeRelay({
      operatorToken: legacyToken,
      operatorRateLimit: { requestsPerMinute: 1 },
    });
    const port = await listen(server);
    try {
      assert.equal((await call(port, "GET", "/audit", legacyToken)).status, 200);
      const denied = await call(port, "GET", "/dead-letter", legacyToken);
      assert.equal(denied.status, 429);
    } finally {
      await closeRelay(server);
    }
  });

  it("throws RangeError at startup for an invalid budget", () => {
    const dir = mkdtempSync(join(tmpdir(), "wr180-bad-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          forwardUrl: forwardTarget,
          auditLog: audit,
          operatorToken: legacyToken,
          operatorRateLimit: { requestsPerMinute: 0 },
        }),
      RangeError
    );
  });
});
