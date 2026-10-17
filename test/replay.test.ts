import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { ReplayGuard, REPLAY_JOURNAL_FILE } from "../src/replay.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

/** A manually advanced clock for deterministic window tests. */
function fakeClock(startMs: number): { now: () => number; advance: (ms: number) => void } {
  let t = startMs;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

describe("replay guard", () => {
  it("accepts a fresh nonce and rejects its replay", () => {
    const guard = new ReplayGuard();
    assert.deepEqual(guard.check("n1"), { ok: true });
    assert.deepEqual(guard.check("n1"), { ok: false, reason: "duplicate_nonce" });
    assert.deepEqual(guard.check("n2"), { ok: true });
  });

  it("rejects a missing or empty nonce", () => {
    const guard = new ReplayGuard();
    assert.deepEqual(guard.check(undefined), { ok: false, reason: "missing_nonce" });
    assert.deepEqual(guard.check(""), { ok: false, reason: "missing_nonce" });
    // A missing nonce is never recorded, so the next valid check is unaffected.
    assert.deepEqual(guard.check("n1"), { ok: true });
  });

  it("rejects timestamps outside the window on both sides", () => {
    const clock = fakeClock(1_700_000_000_000);
    const guard = new ReplayGuard({ windowSec: 60, nowMs: clock.now });
    assert.deepEqual(guard.check("old", clock.now() - 61_000), {
      ok: false,
      reason: "expired_timestamp",
    });
    assert.deepEqual(guard.check("future", clock.now() + 61_000), {
      ok: false,
      reason: "future_timestamp",
    });
    assert.deepEqual(guard.check("edge-old", clock.now() - 60_000), { ok: true });
    assert.deepEqual(guard.check("edge-future", clock.now() + 60_000), { ok: true });
  });

  it("treats a non-numeric timestamp as out of window", () => {
    const guard = new ReplayGuard();
    assert.deepEqual(guard.check("n1", NaN), { ok: false, reason: "expired_timestamp" });
  });

  it("forgets a nonce once the window passes", () => {
    const clock = fakeClock(1_700_000_000_000);
    const guard = new ReplayGuard({ windowSec: 60, nowMs: clock.now });
    assert.deepEqual(guard.check("n1"), { ok: true });
    assert.deepEqual(guard.check("n1"), { ok: false, reason: "duplicate_nonce" });
    clock.advance(61_000);
    assert.equal(guard.size(), 0);
    // Same nonce is a fresh delivery again after expiry.
    assert.deepEqual(guard.check("n1"), { ok: true });
  });

  it("evicts the oldest nonces beyond maxEntries", () => {
    const guard = new ReplayGuard({ maxEntries: 2 });
    assert.deepEqual(guard.check("a"), { ok: true });
    assert.deepEqual(guard.check("b"), { ok: true });
    assert.equal(guard.size(), 2);
    assert.deepEqual(guard.check("c"), { ok: true });
    assert.equal(guard.size(), 2);
    // "a" was evicted, so it is no longer a duplicate.
    assert.deepEqual(guard.check("a"), { ok: true });
    assert.deepEqual(guard.check("c"), { ok: false, reason: "duplicate_nonce" });
  });

  it("validates its configuration", () => {
    assert.throws(() => new ReplayGuard({ windowSec: 0 }), RangeError);
    assert.throws(() => new ReplayGuard({ windowSec: -5 }), RangeError);
    assert.throws(() => new ReplayGuard({ maxEntries: 0 }), RangeError);
    assert.throws(() => new ReplayGuard({ maxEntries: 1.5 }), RangeError);
  });
});

describe("replay guard durable journal (WR-122)", () => {
  function journalDir(): string {
    return mkdtempSync(join(tmpdir(), "replay-journal-"));
  }

  it("journals accepted nonces and reports durability stats", async () => {
    const dir = journalDir();
    const guard = new ReplayGuard({ windowSec: 60, journalDir: dir });
    assert.deepEqual(guard.check("n1", undefined, "https://down.example/hook"), { ok: true });
    assert.equal(guard.journalStats().enabled, true);
    assert.equal(guard.journalStats().pendingLines, 1);
    await guard.flush();
    assert.equal(guard.journalStats().pendingLines, 0);
    assert.equal(guard.journalStats().journalErrors, 0);
    const lines = readFileSync(join(dir, REPLAY_JOURNAL_FILE), "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
    const rec = JSON.parse(lines[0]) as Record<string, unknown>;
    assert.equal(rec["nonce"], "n1");
    assert.equal(rec["scope"], "https://down.example/hook");
    assert.ok(typeof rec["expiresAtMs"] === "number");
  });

  it("survives a restart: a replayed nonce is still 409", async () => {
    const dir = journalDir();
    const clock = fakeClock(1_700_000_000_000);
    const before = new ReplayGuard({ windowSec: 60, nowMs: clock.now, journalDir: dir });
    assert.deepEqual(before.check("n1", undefined, "scope-a"), { ok: true });
    assert.deepEqual(before.check("n2"), { ok: true }); // unscoped
    await before.flush();

    // "Restart": a fresh guard on the same directory recovers the window.
    const after = new ReplayGuard({ windowSec: 60, nowMs: clock.now, journalDir: dir });
    assert.equal(after.journalStats().recovered, 2);
    assert.deepEqual(after.check("n1", undefined, "scope-a"), {
      ok: false,
      reason: "duplicate_nonce",
    });
    assert.deepEqual(after.check("n2"), { ok: false, reason: "duplicate_nonce" });
    // Scope isolation survived the round-trip: same nonce, other scope.
    assert.deepEqual(after.check("n1", undefined, "scope-b"), { ok: true });
    assert.deepEqual(after.check("n3", undefined, "scope-a"), { ok: true });
  });

  it("drops expired nonces during recovery", async () => {
    const dir = journalDir();
    const clock = fakeClock(1_700_000_000_000);
    const before = new ReplayGuard({ windowSec: 60, nowMs: clock.now, journalDir: dir });
    assert.deepEqual(before.check("n1"), { ok: true });
    await before.flush();
    clock.advance(61_000);
    const after = new ReplayGuard({ windowSec: 60, nowMs: clock.now, journalDir: dir });
    assert.equal(after.journalStats().recovered, 0);
    // Recovery compacted the expired line away — the journal is empty again.
    assert.equal(readFileSync(join(dir, REPLAY_JOURNAL_FILE), "utf8").trim(), "");
    // The window passed — the nonce is a fresh delivery again.
    assert.deepEqual(after.check("n1"), { ok: true });
  });

  it("skips corrupt journal lines during recovery", async () => {
    const dir = journalDir();
    const clock = fakeClock(1_700_000_000_000);
    const before = new ReplayGuard({ windowSec: 60, nowMs: clock.now, journalDir: dir });
    assert.deepEqual(before.check("good"), { ok: true });
    await before.flush();
    appendFileSync(
      join(dir, REPLAY_JOURNAL_FILE),
      'this is not json\n{"nonce": 42}\n{"nonce":"","expiresAtMs":1}\n'
    );
    const after = new ReplayGuard({ windowSec: 60, nowMs: clock.now, journalDir: dir });
    assert.equal(after.journalStats().recovered, 1);
    assert.equal(after.journalStats().corruptLines, 3);
    assert.deepEqual(after.check("good"), { ok: false, reason: "duplicate_nonce" });
    assert.deepEqual(after.check("other"), { ok: true });
  });

  it("scopes the duplicate check by (scope, nonce) in memory", () => {
    const guard = new ReplayGuard();
    assert.deepEqual(guard.check("n1", undefined, "a"), { ok: true });
    assert.deepEqual(guard.check("n1", undefined, "a"), {
      ok: false,
      reason: "duplicate_nonce",
    });
    assert.deepEqual(guard.check("n1", undefined, "b"), { ok: true });
    assert.deepEqual(guard.check("n1"), { ok: true }); // unscoped is its own lane
    assert.deepEqual(guard.check("n1"), { ok: false, reason: "duplicate_nonce" });
  });

  it("stays purely in-memory without journalDir", () => {
    const guard = new ReplayGuard();
    assert.deepEqual(guard.check("n1"), { ok: true });
    assert.equal(guard.journalStats().enabled, false);
    assert.equal(guard.journalStats().pendingLines, 0);
  });

  it("rejects an empty journalDir", () => {
    assert.throws(() => new ReplayGuard({ journalDir: "" }), RangeError);
  });
});

describe("replay guard journal end-to-end (WR-122)", () => {
  const SIGN_KEY = "replay-e2e-key";
  const TOKEN = "op-token";

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

  function post(port: number, headers: Record<string, string>) {
    return new Promise<{ status: number }>((resolve, reject) => {
      const body = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(body, SIGN_KEY), ...headers },
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

  function makeRelay(journalDirPath: string, guard: ReplayGuard): Server {
    const dir = mkdtempSync(join(tmpdir(), "replay-e2e-"));
    return createRelayServer({
      secret: SIGN_KEY,
      forwardUrl: "http://127.0.0.1:1/hook",
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: TOKEN,
      replay: guard,
      retry: { sender: async () => {}, baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
  }

  it("a replayed nonce is 409 after a server restart", async () => {
    const journal = mkdtempSync(join(tmpdir(), "replay-restart-"));
    const guard1 = new ReplayGuard({ windowSec: 300, journalDir: journal });
    const relay1 = makeRelay(journal, guard1);
    const port1 = await listen(relay1);
    try {
      assert.equal((await post(port1, { "x-nonce": "restart-nonce" })).status, 202);
      assert.equal((await post(port1, { "x-nonce": "restart-nonce" })).status, 409);
    } finally {
      await close(relay1);
    }
    await guard1.flush();

    // "Restart": new server, new guard, same journal directory.
    const guard2 = new ReplayGuard({ windowSec: 300, journalDir: journal });
    const relay2 = makeRelay(journal, guard2);
    const port2 = await listen(relay2);
    try {
      assert.equal((await post(port2, { "x-nonce": "restart-nonce" })).status, 409);
      assert.equal((await post(port2, { "x-nonce": "fresh-nonce" })).status, 202);
    } finally {
      await close(relay2);
    }
  });
});
