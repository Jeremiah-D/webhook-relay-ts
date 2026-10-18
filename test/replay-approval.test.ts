import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import {
  ReplayApprovalStore,
  ReplayApprovalError,
  approvalScopeCovers,
  DEFAULT_REPLAY_APPROVAL_TTL_MS,
} from "../src/replay-approval.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";

const SIGN_KEY = "relay-secret";
const OP_TOKEN = "op-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "approval" }));
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";
const FORWARD = "http://127.0.0.1:1/unused";

/** A manually advanced clock for deterministic TTL tests. */
function fakeClock(startMs: number): { now: () => number; advance: (ms: number) => void } {
  let t = startMs;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

/** Build a running queue whose sender always fails, pre-filled with dead letters. */
function seedDeadLetters(
  items: Array<{ id: string; targetUrl: string }>,
  extraOpts: Record<string, unknown> = {}
) {
  const timer = manualTimer();
  const q = new RetryQueue({
    sender: async () => {
      throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 2,
    jitterMs: 0,
    setTimer: timer.setTimer,
    ...extraOpts,
  });
  q.start();
  for (const item of items) {
    q.enqueue({
      id: item.id,
      payload: Buffer.from(`payload-${item.id}`),
      targetUrl: item.targetUrl,
      headers: {},
    });
  }
  return { q, timer };
}

function isApprovalDeny(err: unknown, reason: string): boolean {
  return err instanceof ReplayApprovalError && err.reason === reason;
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "GET", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end();
  });
}

function postJson(
  port: number,
  path: string,
  body: unknown,
  token?: string,
  extraHeaders: Record<string, string> = {}
) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...extraHeaders,
    };
    if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
      );
    });
    r.on("error", reject);
    r.end(raw);
  });
}

function postWebhook(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
      );
    });
    r.on("error", reject);
    r.end(body);
  });
}

async function waitDeadLetters(
  port: number,
  token: string,
  expected: number
): Promise<Array<{ id: string; attempts: number }>> {
  const deadline = Date.now() + 5000;
  for (;;) {
    const res = await get(port, "/dead-letter", { authorization: `Bearer ${token}` });
    assert.equal(res.status, 200);
    const entries = JSON.parse(res.text) as Array<{ id: string; attempts: number }>;
    if (entries.length >= expected) return entries;
    if (Date.now() >= deadline) throw new Error("timed out waiting for dead letters");
    await new Promise((r) => setTimeout(r, 25));
  }
}

function auditEvents(audit: AuditLog, event: string): Array<Record<string, unknown>> {
  return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === event);
}

describe("ReplayApprovalStore (unit)", () => {
  it("issues unique one-shot tokens consumed exactly once", () => {
    const store = new ReplayApprovalStore();
    const a = store.issue({});
    const b = store.issue({});
    assert.notEqual(a.approvalToken, b.approvalToken);
    assert.equal(a.expiresAt, b.expiresAt);
    assert.deepEqual(store.consume(a.approvalToken, {}), { ok: true });
    assert.deepEqual(store.consume(a.approvalToken, {}), { ok: false, reason: "reused" });
    assert.deepEqual(store.consume(b.approvalToken, {}), { ok: true });
  });

  it("rejects a missing or unknown token without consuming anything", () => {
    const store = new ReplayApprovalStore();
    assert.deepEqual(store.consume(undefined, {}), { ok: false, reason: "missing" });
    assert.deepEqual(store.consume("", {}), { ok: false, reason: "missing" });
    assert.deepEqual(store.consume("never-issued", {}), { ok: false, reason: "missing" });
    // The denials above consumed nothing: a later issue still works.
    const g = store.issue({});
    assert.deepEqual(store.consume(g.approvalToken, {}), { ok: true });
  });

  it("expires tokens after the TTL and sweeps them lazily", () => {
    const clock = fakeClock(1_700_000_000_000);
    const store = new ReplayApprovalStore({ ttlMs: 1000, now: clock.now });
    const old = store.issue({});
    assert.equal(old.expiresAt, 1_700_000_000_000 + 1000);
    clock.advance(1001);
    // Consumed right at expiry: reported as expired, not silently missing.
    assert.deepEqual(store.consume(old.approvalToken, {}), { ok: false, reason: "expired" });
    // Lazy sweep: issuing again drops the expired record, so a second
    // attempt on the swept token reads as missing.
    const gone = store.issue({});
    clock.advance(2000);
    store.issue({}); // sweep runs here
    assert.deepEqual(store.consume(gone.approvalToken, {}), { ok: false, reason: "missing" });
  });

  it("binds scope: a broad token executes narrow, never the reverse", () => {
    assert.ok(approvalScopeCovers({}, { endpoint: EP_A }));
    assert.ok(approvalScopeCovers({ endpoint: EP_A }, { endpoint: EP_A }));
    assert.ok(!approvalScopeCovers({ endpoint: EP_A }, { endpoint: EP_B }));
    assert.ok(!approvalScopeCovers({ endpoint: EP_A }, {}));
    assert.ok(approvalScopeCovers({ tenant: "acme" }, { tenant: "acme", endpoint: EP_A }));
    assert.ok(!approvalScopeCovers({ tenant: "acme" }, { tenant: "other" }));
    assert.ok(approvalScopeCovers({ ids: ["a", "b"] }, { ids: ["a"] }));
    assert.ok(!approvalScopeCovers({ ids: ["a"] }, { ids: ["a", "b"] }));
    assert.ok(!approvalScopeCovers({ ids: ["a"] }, {}));
  });

  it("a scope-mismatched token stays unspent", () => {
    const store = new ReplayApprovalStore();
    const g = store.issue({ endpoint: EP_A });
    assert.deepEqual(store.consume(g.approvalToken, { endpoint: EP_B }), {
      ok: false,
      reason: "scope_mismatch",
    });
    // Not consumed: the correct scope still spends it.
    assert.deepEqual(store.consume(g.approvalToken, { endpoint: EP_A }), { ok: true });
  });

  it("defaults to a 5-minute TTL and validates ttlMs with RangeError", () => {
    const store = new ReplayApprovalStore();
    assert.equal(store.tokenTtlMs(), DEFAULT_REPLAY_APPROVAL_TTL_MS);
    assert.equal(DEFAULT_REPLAY_APPROVAL_TTL_MS, 5 * 60 * 1000);
    const clock = fakeClock(0);
    const custom = new ReplayApprovalStore({ ttlMs: 30_000, now: clock.now });
    assert.equal(custom.issue({}).expiresAt, 30_000);
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => new ReplayApprovalStore({ ttlMs: bad }), RangeError);
    }
  });
});

describe("RetryQueue replay approval (programmatic)", () => {
  it("is off by default: replayDeadLetter works with no token", async () => {
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }]);
    await timer.run();
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getReplayApprovalStore(), undefined);
    assert.equal(q.issueReplayApprovalToken({}), undefined);
    assert.equal(q.replayDeadLetter("a"), true);
  });

  it("denies replays without a token when enabled", async () => {
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], { replayApproval: {} });
    await timer.run();
    assert.ok(q.getReplayApprovalStore() instanceof ReplayApprovalStore);
    assert.throws(() => q.replayDeadLetter("a"), (e: unknown) => isApprovalDeny(e, "missing"));
    assert.throws(
      () => q.replayDeadLetter("a", { approvalToken: "bogus" }),
      (e: unknown) => isApprovalDeny(e, "missing")
    );
    assert.throws(
      () => q.replayDeadLetters({}),
      (e: unknown) => isApprovalDeny(e, "missing")
    );
    // Nothing was consumed or replayed by the denials.
    assert.equal(q.getDeadLetter().length, 1);
  });

  it("spends one token per replay: single, batch, and reuse", async () => {
    const { q, timer } = seedDeadLetters(
      [
        { id: "a", targetUrl: EP_A },
        { id: "b", targetUrl: EP_A },
      ],
      { replayApproval: {} }
    );
    await timer.run();
    const single = q.issueReplayApprovalToken({ ids: ["a"] })!;
    assert.equal(q.replayDeadLetter("a", { approvalToken: single.approvalToken }), true);
    // One-shot: the same token cannot pay for another replay.
    assert.throws(
      () => q.replayDeadLetter("b", { approvalToken: single.approvalToken }),
      (e: unknown) => isApprovalDeny(e, "reused")
    );
    // A batch token covers the whole batch but is equally one-shot.
    const batch = q.issueReplayApprovalToken({ endpoint: EP_A })!;
    const result = q.replayDeadLetters({ endpoint: EP_A }, { approvalToken: batch.approvalToken });
    assert.deepEqual(result.replayed, ["b"]);
    assert.throws(
      () => q.replayDeadLetters({ endpoint: EP_A }, { approvalToken: batch.approvalToken }),
      (e: unknown) => isApprovalDeny(e, "reused")
    );
  });

  it("an endpoint-scoped token covers single replays on that endpoint", async () => {
    const { q, timer } = seedDeadLetters(
      [
        { id: "a", targetUrl: EP_A },
        { id: "b", targetUrl: EP_B },
      ],
      { replayApproval: {} }
    );
    await timer.run();
    const scoped = q.issueReplayApprovalToken({ endpoint: EP_A })!;
    assert.equal(q.replayDeadLetter("a", { approvalToken: scoped.approvalToken }), true);
    const other = q.issueReplayApprovalToken({ endpoint: EP_A })!;
    assert.throws(
      () => q.replayDeadLetter("b", { approvalToken: other.approvalToken }),
      (e: unknown) => isApprovalDeny(e, "scope_mismatch")
    );
  });

  it("bypassApproval is an explicit escape hatch", async () => {
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], { replayApproval: {} });
    await timer.run();
    assert.equal(q.replayDeadLetter("a", { bypassApproval: true }), true);
    // An explicit `false` does not bypass.
    const { q: q2, timer: t2 } = seedDeadLetters([{ id: "x", targetUrl: EP_A }], {
      replayApproval: {},
    });
    await t2.run();
    assert.throws(
      () => q2.replayDeadLetter("x", { bypassApproval: false }),
      (e: unknown) => isApprovalDeny(e, "missing")
    );
    assert.equal(q2.replayAllDeadLetters({ bypassApproval: true }), 1);
  });

  it("dry runs never need approval", async () => {
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], { replayApproval: {} });
    await timer.run();
    const preview = q.replayDeadLetters({}, { dryRun: true });
    assert.equal(preview.length, 1);
    assert.equal(preview[0].id, "a");
    assert.equal(q.getDeadLetter().length, 1);
  });

  it("throws RangeError at construction for an illegal ttlMs", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          replayApproval: { ttlMs: 0 },
        }),
      RangeError
    );
  });
});

describe("HTTP two-phase replay approval", () => {
  function makeRelay(audit: AuditLog, extra: Record<string, unknown> = {}) {
    return createRelayServer({
      secret: SIGN_KEY,
      forwardUrl: FORWARD,
      auditLog: audit,
      sender: async () => {
        throw new Error("downstream 500");
      },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      operatorToken: OP_TOKEN,
      ...extra,
    });
  }

  it("approve-request is 404 when approval is not configured", async () => {
    const dir = mkdtempSync(join(tmpdir(), "approval-404-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = makeRelay(audit);
    const port = await listen(relay);
    try {
      const res = await postJson(port, "/dead-letter/replay/approve-request", {}, OP_TOKEN);
      assert.equal(res.status, 404);
      assert.match(res.text, /not configured/);
      // And replays still run on the operator token alone (default off).
      const sig = { "x-signature": signSha256(BODY, SIGN_KEY) };
      assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
      assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
      const listed = await waitDeadLetters(port, OP_TOKEN, 2);
      const [batchId, singleId] = listed.map((e) => e.id);
      const replay = await postJson(port, "/dead-letter/replay", { ids: [batchId] }, OP_TOKEN);
      assert.equal(replay.status, 200);
      assert.deepEqual((JSON.parse(replay.text) as { replayed: string[] }).replayed, [batchId]);
      const single = await postJson(port, `/dead-letter/${singleId}/replay`, {}, OP_TOKEN);
      assert.equal(single.status, 200);
      // No replay_approved audit lines when the gate is off.
      assert.equal(auditEvents(audit, "replay_approved").length, 0);
      assert.ok(auditEvents(audit, "dead_letter_replayed").length >= 1);
    } finally {
      await close(relay);
    }
  });

  it("issues a scoped token; execution consumes it and audits replay_approved", async () => {
    const dir = mkdtempSync(join(tmpdir(), "approval-ok-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = makeRelay(audit, { replayApproval: {} });
    const port = await listen(relay);
    try {
      const sig = { "x-signature": signSha256(BODY, SIGN_KEY) };
      assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
      const listed = await waitDeadLetters(port, OP_TOKEN, 1);
      const id = listed[0].id;

      // No token: 403, nothing replayed.
      const denied = await postJson(port, "/dead-letter/replay", {}, OP_TOKEN);
      assert.equal(denied.status, 403);
      assert.match(denied.text, /approval token required/);
      assert.equal((await waitDeadLetters(port, OP_TOKEN, 1)).length, 1);

      // Issue scoped to the exact ids, then execute.
      const grantRes = await postJson(port, "/dead-letter/replay/approve-request", { ids: [id] }, OP_TOKEN);
      assert.equal(grantRes.status, 200);
      const grant = JSON.parse(grantRes.text) as { approvalToken: string; expiresAt: number };
      assert.ok(typeof grant.approvalToken === "string" && grant.approvalToken.length >= 32);
      assert.ok(grant.expiresAt > Date.now());

      const exec = await postJson(
        port,
        "/dead-letter/replay",
        { ids: [id], approvalToken: grant.approvalToken },
        OP_TOKEN
      );
      assert.equal(exec.status, 200);
      const execBody = JSON.parse(exec.text) as { replayed: string[]; failed: unknown[] };
      assert.deepEqual(execBody.replayed, [id]);

      const approved = auditEvents(audit, "replay_approved");
      assert.equal(approved.length, 1);
      assert.deepEqual(approved[0].replayed, [id]);
      // The token itself is never written to the audit log.
      assert.ok(!JSON.stringify(approved[0]).includes(grant.approvalToken));

      // One-shot: reuse is 403.
      const reuse = await postJson(port, "/dead-letter/replay", { approvalToken: grant.approvalToken }, OP_TOKEN);
      assert.equal(reuse.status, 403);
      assert.match(reuse.text, /already used/);
      assert.equal(auditEvents(audit, "replay_approved").length, 1);
    } finally {
      await close(relay);
    }
  });

  it("an expired token is 403 and audits replay_approval_expired", async () => {
    const dir = mkdtempSync(join(tmpdir(), "approval-exp-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const clock = fakeClock(1_700_000_000_000);
    const relay = makeRelay(audit, { replayApproval: { ttlMs: 60_000, now: clock.now } });
    const port = await listen(relay);
    try {
      const sig = { "x-signature": signSha256(BODY, SIGN_KEY) };
      assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
      await waitDeadLetters(port, OP_TOKEN, 1);

      const grantRes = await postJson(port, "/dead-letter/replay/approve-request", {}, OP_TOKEN);
      assert.equal(grantRes.status, 200);
      const grant = JSON.parse(grantRes.text) as { approvalToken: string; expiresAt: number };
      // TTL is configurable: expiresAt honors the injected clock and ttlMs.
      assert.equal(grant.expiresAt, 1_700_000_000_000 + 60_000);

      clock.advance(60_001);
      const exec = await postJson(port, "/dead-letter/replay", { approvalToken: grant.approvalToken }, OP_TOKEN);
      assert.equal(exec.status, 403);
      assert.match(exec.text, /expired/);
      const expired = auditEvents(audit, "replay_approval_expired");
      assert.equal(expired.length, 1);
      assert.equal(expired[0].reason, "approval_token_expired");
      assert.equal(auditEvents(audit, "replay_approved").length, 0);
    } finally {
      await close(relay);
    }
  });

  it("rejects scope mismatches on endpoint and ids", async () => {
    const dir = mkdtempSync(join(tmpdir(), "approval-scope-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = makeRelay(audit, { replayApproval: {} });
    const port = await listen(relay);
    try {
      const sig = { "x-signature": signSha256(BODY, SIGN_KEY) };
      assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
      const listed = await waitDeadLetters(port, OP_TOKEN, 1);
      const id = listed[0].id;

      const epGrant = JSON.parse(
        (await postJson(port, "/dead-letter/replay/approve-request", { endpoint: EP_A }, OP_TOKEN)).text
      ) as { approvalToken: string };
      const wrongEp = await postJson(
        port,
        "/dead-letter/replay",
        { endpoint: FORWARD, approvalToken: epGrant.approvalToken },
        OP_TOKEN
      );
      assert.equal(wrongEp.status, 403);
      assert.match(wrongEp.text, /scope mismatch/);

      const idsGrant = JSON.parse(
        (await postJson(port, "/dead-letter/replay/approve-request", { ids: ["nope"] }, OP_TOKEN)).text
      ) as { approvalToken: string };
      const wrongIds = await postJson(
        port,
        "/dead-letter/replay",
        { ids: [id, "nope"], approvalToken: idsGrant.approvalToken },
        OP_TOKEN
      );
      assert.equal(wrongIds.status, 403);
      assert.match(wrongIds.text, /scope mismatch/);

      // The mismatched tokens were not consumed: a correct-scope token works.
      const okGrant = JSON.parse(
        (await postJson(port, "/dead-letter/replay/approve-request", { ids: [id] }, OP_TOKEN)).text
      ) as { approvalToken: string };
      const ok = await postJson(
        port,
        "/dead-letter/replay",
        { ids: [id], approvalToken: okGrant.approvalToken },
        OP_TOKEN
      );
      assert.equal(ok.status, 200);
      assert.equal(auditEvents(audit, "replay_approved").length, 1);
    } finally {
      await close(relay);
    }
  });

  it("dry runs never need approval", async () => {
    const dir = mkdtempSync(join(tmpdir(), "approval-dry-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = makeRelay(audit, { replayApproval: {} });
    const port = await listen(relay);
    try {
      const sig = { "x-signature": signSha256(BODY, SIGN_KEY) };
      assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
      await waitDeadLetters(port, OP_TOKEN, 1);
      const before = audit.readAll().length;
      const res = await postJson(port, "/dead-letter/replay", { dryRun: true }, OP_TOKEN);
      assert.equal(res.status, 200);
      const body = JSON.parse(res.text) as { dryRun: boolean; entries: unknown[] };
      assert.equal(body.dryRun, true);
      assert.equal(body.entries.length, 1);
      assert.equal(audit.readAll().length, before);
    } finally {
      await close(relay);
    }
  });

  it("single replay needs a token too, via body or header", async () => {
    const dir = mkdtempSync(join(tmpdir(), "approval-single-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = makeRelay(audit, { replayApproval: {} });
    const port = await listen(relay);
    try {
      const sig = { "x-signature": signSha256(BODY, SIGN_KEY) };
      assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
      assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
      const listed = await waitDeadLetters(port, OP_TOKEN, 2);
      const [first, second] = listed.map((e) => e.id);

      // No token on the single route: 403 (not 404).
      const denied = await postJson(port, `/dead-letter/${first}/replay`, {}, OP_TOKEN);
      assert.equal(denied.status, 403);

      // Endpoint-scoped token covers a single replay on that endpoint.
      const grant = JSON.parse(
        (await postJson(port, "/dead-letter/replay/approve-request", { endpoint: FORWARD }, OP_TOKEN)).text
      ) as { approvalToken: string };
      const ok = await postJson(port, `/dead-letter/${first}/replay`, { approvalToken: grant.approvalToken }, OP_TOKEN);
      assert.equal(ok.status, 200);
      assert.deepEqual(JSON.parse(ok.text), { id: first, replayed: true });
      const approved = auditEvents(audit, "replay_approved");
      assert.equal(approved.length, 1);
      assert.equal(approved[0].id, first);

      // Unknown id still 404s even with a token (entry check precedes scope).
      const other = JSON.parse(
        (await postJson(port, "/dead-letter/replay/approve-request", {}, OP_TOKEN)).text
      ) as { approvalToken: string };
      const missing = await postJson(port, "/dead-letter/nope/replay", { approvalToken: other.approvalToken }, OP_TOKEN);
      assert.equal(missing.status, 404);

      // The header carrier works as well.
      const viaHeader = await postJson(
        port,
        `/dead-letter/${second}/replay`,
        {},
        OP_TOKEN,
        { "x-replay-approval-token": other.approvalToken }
      );
      assert.equal(viaHeader.status, 200);
      assert.equal(auditEvents(audit, "replay_approved").length, 2);
    } finally {
      await close(relay);
    }
  });

  it("validates approve-request bodies and token fields", async () => {
    const dir = mkdtempSync(join(tmpdir(), "approval-bad-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = makeRelay(audit, { replayApproval: {} });
    const port = await listen(relay);
    try {
      assert.equal((await postJson(port, "/dead-letter/replay/approve-request", "not json", OP_TOKEN)).status, 400);
      assert.equal((await postJson(port, "/dead-letter/replay/approve-request", { endpoint: 42 }, OP_TOKEN)).status, 400);
      assert.equal((await postJson(port, "/dead-letter/replay/approve-request", { ids: "x" }, OP_TOKEN)).status, 400);
      assert.equal((await postJson(port, "/dead-letter/replay", { approvalToken: 42 }, OP_TOKEN)).status, 400);
    } finally {
      await close(relay);
    }
  });
});
