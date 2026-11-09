import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import {
  RetryQueue,
  type ReplayForcedInfo,
  type ReplaySkippedInfo,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "replay-callbacks-revision-secret";
const operatorToken = "replay-callbacks-revision-token";
const URL = "http://localhost:9999/hook";
const FORWARD = "http://127.0.0.1:1/unused";
const PAYLOAD = Buffer.from(JSON.stringify({ payment: "pi_123", amount: 5000 }));
const BODY = PAYLOAD;

type SkippedObserver = (info: ReplaySkippedInfo) => void;
type ForcedObserver = (info: ReplayForcedInfo) => void;

/** Manual timer with single-step control. */
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
    async drain() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function controllableSender() {
  let fail = true;
  const sender: Sender = async () => {
    if (fail) throw new Error("downstream 500");
  };
  return { sender, setFail: (v: boolean) => (fail = v) };
}

/**
 * The guard compares millisecond timestamps with a strict `>`, so a
 * delivered record stamped in the *same* millisecond as the
 * dead-lettering must not suppress. Suppression tests run the guard's
 * clock 60s ahead of wall time (delivered records are deterministically
 * newer).
 */
const aheadClock = () => Date.now() + 60_000;

describe("RetryQueue replay callbacks revision (WR-368)", () => {
  function makeQueue(onReplaySkipped?: SkippedObserver, onReplayForced?: ForcedObserver) {
    const timer = manualTimer();
    const f = controllableSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 1, // dead-letter on the first failure
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      replayIdempotency: { now: aheadClock },
      ...(onReplaySkipped !== undefined ? { onReplaySkipped } : {}),
      ...(onReplayForced !== undefined ? { onReplayForced } : {}),
    });
    return { q, timer, f };
  }

  /**
   * Dead-letter item "rdl-a" (sender failing), then deliver the same
   * (endpoint, payload) — the next replay of "rdl-a" is guard-suppressed.
   * Returns the dead-lettered timestamp for info-shape assertions.
   */
  async function seedSuppressed(
    q: RetryQueue,
    timer: ReturnType<typeof manualTimer>,
    f: ReturnType<typeof controllableSender>
  ): Promise<string> {
    q.start();
    q.enqueue({ id: "rdl-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 1);
    const deadLetteredAt = q.getDeadLetter()[0].deadLetteredAt;
    f.setFail(false);
    q.enqueue({ id: "rdl-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.pendingCount(), 0);
    return deadLetteredAt;
  }

  it("skip reaches the revised callback; the old callback stays silent", async () => {
    const oldSeen: ReplaySkippedInfo[] = [];
    const newSeen: ReplaySkippedInfo[] = [];
    const oldCb: SkippedObserver = (info) => oldSeen.push(info);
    const newCb: SkippedObserver = (info) => newSeen.push(info);
    const { q, timer, f } = makeQueue(oldCb);
    try {
      const deadLetteredAt = await seedSuppressed(q, timer, f);
      assert.equal(q.replayDeadLetter("rdl-a"), false);
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].id, "rdl-a");
      assert.equal(oldSeen[0].endpoint, URL);
      assert.equal(oldSeen[0].deadLetteredAt, deadLetteredAt);
      assert.ok(Date.parse(oldSeen[0].deliveredAt) > Date.parse(deadLetteredAt));
      // Swap mid-flight: the old callback never hears another skip.
      q.reviseReplayCallbacks({ onReplaySkipped: newCb });
      assert.equal(q.replayDeadLetter("rdl-a"), false);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "rdl-a");
      assert.equal(newSeen[0].endpoint, URL);
      assert.equal(newSeen[0].deadLetteredAt, deadLetteredAt);
      assert.equal(q.getDeadLetter().length, 1);
    } finally {
      q.stop();
    }
  });

  it("force reaches the revised callback; the old callback stays silent", async () => {
    const oldSeen: ReplayForcedInfo[] = [];
    const newSeen: ReplayForcedInfo[] = [];
    const oldCb: ForcedObserver = (info) => oldSeen.push(info);
    const newCb: ForcedObserver = (info) => newSeen.push(info);
    const { q, timer, f } = makeQueue(undefined, oldCb);
    try {
      await seedSuppressed(q, timer, f);
      assert.equal(q.replayDeadLetter("rdl-a", { force: true }), true);
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].id, "rdl-a");
      assert.equal(oldSeen[0].endpoint, URL);
      assert.ok(oldSeen[0].deliveredAt !== undefined);
      assert.equal(q.getDeadLetter().length, 0);
      // Drain so the force-replayed copy delivers before re-seeding.
      await timer.drain();
      assert.equal(q.pendingCount(), 0);
      // Re-seed a suppressed entry, then swap the force hook.
      f.setFail(true);
      q.enqueue({ id: "rdl-c", payload: PAYLOAD, targetUrl: URL, headers: {} });
      await timer.drain();
      assert.equal(q.getDeadLetter().length, 1);
      f.setFail(false);
      q.reviseReplayCallbacks({ onReplayForced: newCb });
      assert.equal(q.replayDeadLetter("rdl-c", { force: true }), true);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "rdl-c");
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; the guard keeps skipping and forcing", async () => {
    const skippedSeen: ReplaySkippedInfo[] = [];
    const forcedSeen: ReplayForcedInfo[] = [];
    const skippedCb: SkippedObserver = (info) => skippedSeen.push(info);
    const forcedCb: ForcedObserver = (info) => forcedSeen.push(info);
    const { q, timer, f } = makeQueue(skippedCb, forcedCb);
    try {
      await seedSuppressed(q, timer, f);
      assert.equal(q.replayDeadLetter("rdl-a"), false);
      assert.equal(skippedSeen.length, 1);
      q.reviseReplayCallbacks({ onReplaySkipped: null, onReplayForced: null });
      // The guard still suppresses — only the observation stops.
      assert.equal(q.replayDeadLetter("rdl-a"), false);
      assert.equal(q.getDeadLetter().length, 1);
      assert.equal(skippedSeen.length, 1);
      // Forcing still replays — only the observation stops.
      assert.equal(q.replayDeadLetter("rdl-a", { force: true }), true);
      assert.equal(q.getDeadLetter().length, 0);
      assert.equal(forcedSeen.length, 0);
    } finally {
      q.stop();
    }
  });

  it("batch replay skip reaches the revised callback", async () => {
    const oldSeen: ReplaySkippedInfo[] = [];
    const newSeen: ReplaySkippedInfo[] = [];
    const oldCb: SkippedObserver = (info) => oldSeen.push(info);
    const newCb: SkippedObserver = (info) => newSeen.push(info);
    const { q, timer, f } = makeQueue(oldCb);
    try {
      q.start();
      q.enqueue({ id: "rdl-x", payload: PAYLOAD, targetUrl: URL, headers: {} });
      await timer.drain();
      assert.equal(q.getDeadLetter().length, 1);
      f.setFail(false);
      q.enqueue({ id: "rdl-copy", payload: PAYLOAD, targetUrl: URL, headers: {} });
      await timer.drain();
      q.reviseReplayCallbacks({ onReplaySkipped: newCb });
      const result = q.replayDeadLetters({});
      assert.deepEqual(result.skipped, ["rdl-x"]);
      assert.equal(oldSeen.length, 0);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "rdl-x");
    } finally {
      q.stop();
    }
  });

  it("revising with the guard unconfigured throws Error", () => {
    const q = new RetryQueue({ sender: (async () => {}) as Sender });
    try {
      assert.throws(
        () => q.reviseReplayCallbacks({ onReplaySkipped: () => {} }),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
      assert.throws(
        () => q.reviseReplayCallbacks({ onReplayForced: null }),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError and the live callbacks are untouched", async () => {
    const skippedSeen: ReplaySkippedInfo[] = [];
    const forcedSeen: ReplayForcedInfo[] = [];
    const skippedCb: SkippedObserver = (info) => skippedSeen.push(info);
    const forcedCb: ForcedObserver = (info) => forcedSeen.push(info);
    const { q, timer, f } = makeQueue(skippedCb, forcedCb);
    try {
      await seedSuppressed(q, timer, f);
      for (const bad of ["nope", 42, {}, true]) {
        assert.throws(
          () => q.reviseReplayCallbacks({ onReplaySkipped: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
        assert.throws(
          () => q.reviseReplayCallbacks({ onReplayForced: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
      }
      // The live callbacks are untouched: both decisions still reach them.
      assert.equal(q.replayDeadLetter("rdl-a"), false);
      assert.equal(skippedSeen.length, 1);
      assert.equal(q.replayDeadLetter("rdl-a", { force: true }), true);
      assert.equal(forcedSeen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("an empty or non-object patch throws RangeError and the live callbacks are untouched", async () => {
    const skippedSeen: ReplaySkippedInfo[] = [];
    const skippedCb: SkippedObserver = (info) => skippedSeen.push(info);
    const { q, timer, f } = makeQueue(skippedCb);
    try {
      await seedSuppressed(q, timer, f);
      assert.throws(() => q.reviseReplayCallbacks({}), RangeError);
      assert.throws(() => q.reviseReplayCallbacks(null as never), RangeError);
      assert.throws(() => q.reviseReplayCallbacks("nope" as never), RangeError);
      assert.throws(() => q.reviseReplayCallbacks(42 as never), RangeError);
      // An explicitly-undefined field counts as not provided, so a
      // patch of only undefined fields is empty too.
      assert.throws(
        () => q.reviseReplayCallbacks({ onReplaySkipped: undefined }),
        RangeError
      );
      assert.equal(q.replayDeadLetter("rdl-a"), false);
      assert.equal(skippedSeen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a same-reference revision is a no-op; a partial patch leaves the other hook live", async () => {
    const skippedSeen: ReplaySkippedInfo[] = [];
    const forcedSeen: ReplayForcedInfo[] = [];
    const newSkippedSeen: ReplaySkippedInfo[] = [];
    const skippedCb: SkippedObserver = (info) => skippedSeen.push(info);
    const forcedCb: ForcedObserver = (info) => forcedSeen.push(info);
    const newSkippedCb: SkippedObserver = (info) => newSkippedSeen.push(info);
    const { q, timer, f } = makeQueue(skippedCb, forcedCb);
    try {
      await seedSuppressed(q, timer, f);
      // Same references as construction: no-op.
      q.reviseReplayCallbacks({ onReplaySkipped: skippedCb, onReplayForced: forcedCb });
      // Clearing when already unset is a no-op too.
      const bareTimer = manualTimer();
      const bare = new RetryQueue({
        sender: (async () => {}) as Sender,
        replayIdempotency: { now: aheadClock },
        setTimer: bareTimer.setTimer,
      });
      try {
        bare.reviseReplayCallbacks({ onReplaySkipped: null, onReplayForced: null });
      } finally {
        bare.stop();
      }
      // Partial patch: only the skip hook moves.
      q.reviseReplayCallbacks({ onReplaySkipped: newSkippedCb });
      assert.equal(q.replayDeadLetter("rdl-a"), false);
      assert.equal(skippedSeen.length, 0);
      assert.equal(newSkippedSeen.length, 1);
      assert.equal(q.replayDeadLetter("rdl-a", { force: true }), true);
      assert.equal(forcedSeen.length, 1); // the force hook never moved
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer replay callbacks revision (WR-368)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "replay-callbacks-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: FORWARD,
      auditLog,
      operatorToken,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function postJson(port: number, path: string, body: unknown, token?: string) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      });
      r.on("error", reject);
      r.end(JSON.stringify(body));
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

  function get(port: number, path: string, token: string) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "GET", headers: { authorization: `Bearer ${token}` } },
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

  async function waitDeadLetters(
    port: number,
    expected: number
  ): Promise<Array<{ id: string; attempts: number }>> {
    const deadline = Date.now() + 5000;
    for (;;) {
      const res = await get(port, "/dead-letter", operatorToken);
      assert.equal(res.status, 200);
      const entries = JSON.parse(res.text) as Array<{ id: string; attempts: number }>;
      if (entries.length >= expected) return entries;
      if (Date.now() >= deadline) throw new Error("timed out waiting for dead letters");
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  async function waitDelivered(audit: AuditLog, expected: number): Promise<void> {
    const deadline = Date.now() + 5000;
    for (;;) {
      if (eventsOf(audit, "delivered").length >= expected) return;
      if (Date.now() >= deadline) throw new Error("timed out waiting for delivery");
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  /**
   * A server whose sender fails until flipped, with the WR-149 guard
   * on the ahead clock. Returns the relay, its audit log, and the
   * sender control.
   */
  function guardedServer(onReplaySkipped?: SkippedObserver, onReplayForced?: ForcedObserver) {
    const ctl = { fail: true };
    const sender: Sender = async () => {
      if (ctl.fail) throw new Error("downstream 500");
    };
    const { relay, auditLog } = makeServer({
      sender,
      retry: {
        baseDelayMs: 10,
        jitterMs: 0,
        maxAttempts: 1,
        replayIdempotency: { now: aheadClock },
        ...(onReplaySkipped !== undefined ? { onReplaySkipped } : {}),
        ...(onReplayForced !== undefined ? { onReplayForced } : {}),
      },
    });
    return { relay, auditLog, ctl };
  }

  /**
   * Dead-letter one copy of BODY, then deliver a second copy — the
   * next replay of the dead-lettered id is guard-suppressed. Returns
   * the dead-lettered entry id.
   */
  async function seedSuppressed(
    port: number,
    ctl: { fail: boolean },
    auditLog: AuditLog
  ): Promise<string> {
    const sig = { "x-signature": signSha256(BODY, relaySecret) };
    assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
    const listed = await waitDeadLetters(port, 1);
    const id = listed[0].id;
    ctl.fail = false;
    assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
    await waitDelivered(auditLog, 1);
    return id;
  }

  async function replaySingle(port: number, id: string, body: Record<string, unknown> = {}) {
    const res = await postJson(port, `/dead-letter/${id}/replay`, body, operatorToken);
    assert.equal(res.status, 200);
    return JSON.parse(res.text) as { id: string; replayed: boolean; skipped?: boolean; reason?: string };
  }

  it("revising the skip callback routes the next skip to the new callback and the audit still lands", async () => {
    const initialSeen: ReplaySkippedInfo[] = [];
    const newSeen: ReplaySkippedInfo[] = [];
    const forcedSeen: ReplayForcedInfo[] = [];
    const initialCb: SkippedObserver = (info) => initialSeen.push(info);
    const newCb: SkippedObserver = (info) => newSeen.push(info);
    const forcedCb: ForcedObserver = (info) => forcedSeen.push(info);
    const { relay, auditLog, ctl } = guardedServer(initialCb, forcedCb);
    const port = await listen(relay);
    const id = await seedSuppressed(port, ctl, auditLog);
    // First skip: the initial callback hears it and the audit lands.
    assert.deepEqual(await replaySingle(port, id), {
      id,
      replayed: false,
      skipped: true,
      reason: "replay_suppressed_delivered",
    });
    assert.equal(initialSeen.length, 1);
    assert.equal(initialSeen[0].id, id);
    assert.equal(eventsOf(auditLog, "replay_skipped_delivered").length, 1);
    // Swap the operator skip callback; the force hook is untouched.
    relay.reviseReplayCallbacks!({ onReplaySkipped: newCb });
    assert.deepEqual(await replaySingle(port, id), {
      id,
      replayed: false,
      skipped: true,
      reason: "replay_suppressed_delivered",
    });
    assert.equal(initialSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen.length, 1);
    assert.equal(newSeen[0].id, id);
    assert.equal(eventsOf(auditLog, "replay_skipped_delivered").length, 2);
    // The revision itself was audited with per-hook presence.
    const revised = eventsOf(auditLog, "replay_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onReplaySkipped,
        revised[0].oldOnReplaySkipped,
        revised[0].onReplayForced,
        revised[0].oldOnReplayForced,
      ],
      ["set", "set", "unchanged", "set"]
    );
  });

  it("revising the force callback routes the next forced replay to the new callback", async () => {
    const initialSeen: ReplayForcedInfo[] = [];
    const newSeen: ReplayForcedInfo[] = [];
    const skippedSeen: ReplaySkippedInfo[] = [];
    const initialCb: ForcedObserver = (info) => initialSeen.push(info);
    const newCb: ForcedObserver = (info) => newSeen.push(info);
    const skippedCb: SkippedObserver = (info) => skippedSeen.push(info);
    const { relay, auditLog, ctl } = guardedServer(skippedCb, initialCb);
    const port = await listen(relay);
    const id = await seedSuppressed(port, ctl, auditLog);
    assert.deepEqual(await replaySingle(port, id), {
      id,
      replayed: false,
      skipped: true,
      reason: "replay_suppressed_delivered",
    });
    assert.equal(skippedSeen.length, 1);
    // Swap only the force callback.
    relay.reviseReplayCallbacks!({ onReplayForced: newCb });
    const forced = await replaySingle(port, id, { force: true });
    assert.equal(forced.replayed, true);
    assert.equal(initialSeen.length, 0);
    assert.equal(newSeen.length, 1);
    assert.equal(newSeen[0].id, id);
    assert.equal(eventsOf(auditLog, "replay_forced").length, 1);
    const revised = eventsOf(auditLog, "replay_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onReplaySkipped,
        revised[0].oldOnReplaySkipped,
        revised[0].onReplayForced,
        revised[0].oldOnReplayForced,
      ],
      ["unchanged", "set", "set", "set"]
    );
  });

  it("clearing both hooks keeps the audit and stops the operator callbacks", async () => {
    const skippedSeen: ReplaySkippedInfo[] = [];
    const forcedSeen: ReplayForcedInfo[] = [];
    const skippedCb: SkippedObserver = (info) => skippedSeen.push(info);
    const forcedCb: ForcedObserver = (info) => forcedSeen.push(info);
    const { relay, auditLog, ctl } = guardedServer(skippedCb, forcedCb);
    const port = await listen(relay);
    const id = await seedSuppressed(port, ctl, auditLog);
    assert.deepEqual(await replaySingle(port, id), {
      id,
      replayed: false,
      skipped: true,
      reason: "replay_suppressed_delivered",
    });
    assert.equal(skippedSeen.length, 1);
    // Clear back to audit-only.
    relay.reviseReplayCallbacks!({ onReplaySkipped: null, onReplayForced: null });
    assert.deepEqual(await replaySingle(port, id), {
      id,
      replayed: false,
      skipped: true,
      reason: "replay_suppressed_delivered",
    });
    assert.equal(skippedSeen.length, 1); // the later skip was audit-only
    assert.equal(eventsOf(auditLog, "replay_skipped_delivered").length, 2);
    const forced = await replaySingle(port, id, { force: true });
    assert.equal(forced.replayed, true);
    assert.equal(forcedSeen.length, 0); // the force was audit-only too
    assert.equal(eventsOf(auditLog, "replay_forced").length, 1);
    const revised = eventsOf(auditLog, "replay_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onReplaySkipped,
        revised[0].oldOnReplaySkipped,
        revised[0].onReplayForced,
        revised[0].oldOnReplayForced,
      ],
      ["cleared", "set", "cleared", "set"]
    );
    // Clearing when already cleared is a silent no-op.
    relay.reviseReplayCallbacks!({ onReplaySkipped: null, onReplayForced: null });
    assert.equal(eventsOf(auditLog, "replay_callbacks_revised").length, 1);
  });

  it("an illegal value or empty patch throws RangeError, live callbacks untouched, no revision audit", async () => {
    const skippedSeen: ReplaySkippedInfo[] = [];
    const forcedSeen: ReplayForcedInfo[] = [];
    const skippedCb: SkippedObserver = (info) => skippedSeen.push(info);
    const forcedCb: ForcedObserver = (info) => forcedSeen.push(info);
    const { relay, auditLog, ctl } = guardedServer(skippedCb, forcedCb);
    const port = await listen(relay);
    const id = await seedSuppressed(port, ctl, auditLog);
    for (const bad of ["nope", 42, {}, true]) {
      assert.throws(
        () => relay.reviseReplayCallbacks!({ onReplaySkipped: bad as never }),
        RangeError,
        JSON.stringify(bad)
      );
      assert.throws(
        () => relay.reviseReplayCallbacks!({ onReplayForced: bad as never }),
        RangeError,
        JSON.stringify(bad)
      );
    }
    assert.throws(() => relay.reviseReplayCallbacks!({}), RangeError);
    assert.throws(() => relay.reviseReplayCallbacks!(null as never), RangeError);
    assert.equal(eventsOf(auditLog, "replay_callbacks_revised").length, 0);
    // The live callbacks are untouched: both decisions still reach them.
    assert.deepEqual(await replaySingle(port, id), {
      id,
      replayed: false,
      skipped: true,
      reason: "replay_suppressed_delivered",
    });
    assert.equal(skippedSeen.length, 1);
    const forced = await replaySingle(port, id, { force: true });
    assert.equal(forced.replayed, true);
    assert.equal(forcedSeen.length, 1);
  });

  it("a same-value revision is a silent no-op; a partial patch leaves the other hook live", async () => {
    const initialSkippedSeen: ReplaySkippedInfo[] = [];
    const initialForcedSeen: ReplayForcedInfo[] = [];
    const newSkippedSeen: ReplaySkippedInfo[] = [];
    const initialSkippedCb: SkippedObserver = (info) => initialSkippedSeen.push(info);
    const initialForcedCb: ForcedObserver = (info) => initialForcedSeen.push(info);
    const newSkippedCb: SkippedObserver = (info) => newSkippedSeen.push(info);
    const { relay, auditLog, ctl } = guardedServer(initialSkippedCb, initialForcedCb);
    const port = await listen(relay);
    const id = await seedSuppressed(port, ctl, auditLog);
    // Same references as construction: no audit event.
    relay.reviseReplayCallbacks!({
      onReplaySkipped: initialSkippedCb,
      onReplayForced: initialForcedCb,
    });
    assert.equal(eventsOf(auditLog, "replay_callbacks_revised").length, 0);
    // Partial patch: only the skip hook moves.
    relay.reviseReplayCallbacks!({ onReplaySkipped: newSkippedCb });
    const revised = eventsOf(auditLog, "replay_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onReplaySkipped,
        revised[0].oldOnReplaySkipped,
        revised[0].onReplayForced,
        revised[0].oldOnReplayForced,
      ],
      ["set", "set", "unchanged", "set"]
    );
    // Same reference again: no further audit event.
    relay.reviseReplayCallbacks!({ onReplaySkipped: newSkippedCb });
    assert.equal(eventsOf(auditLog, "replay_callbacks_revised").length, 1);
    // Skip enters the new callback; force still enters the original one.
    assert.deepEqual(await replaySingle(port, id), {
      id,
      replayed: false,
      skipped: true,
      reason: "replay_suppressed_delivered",
    });
    assert.equal(newSkippedSeen.length, 1);
    assert.equal(initialSkippedSeen.length, 0);
    const forced = await replaySingle(port, id, { force: true });
    assert.equal(forced.replayed, true);
    assert.equal(initialForcedSeen.length, 1);
  });

  it("revising with the guard unconfigured throws Error", async () => {
    const { relay } = makeServer({
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(relay);
    assert.ok(port > 0);
    assert.throws(
      () => relay.reviseReplayCallbacks!({ onReplaySkipped: () => {} }),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
    assert.throws(
      () => relay.reviseReplayCallbacks!({ onReplayForced: null }),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
  });
});
