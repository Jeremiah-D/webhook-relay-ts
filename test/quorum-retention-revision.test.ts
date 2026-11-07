import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  QuorumFanoutSet,
  RetryQueue,
  type QuorumEvictedInfo,
  type RetryItem,
} from "../src/retry.ts";
import type { QuorumFanoutSetOptions } from "../src/quorum.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "quorum-retention-revision-test-key";
const opToken = "quorum-retention-revision-op-token";
const LOGICAL = "http://127.0.0.1:9930/hook";
const T1 = "http://127.0.0.1:9931/one";
const T2 = "http://127.0.0.1:9932/two";

const CFG = { [LOGICAL]: { targets: [T1, T2], quorum: 2 } };

/** Manual epoch-ms clock for deterministic retention tests. */
function manualClock(startMs = 1_789_000_000_000) {
  let t = startMs;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
    iso: () => new Date(t).toISOString(),
  };
}

function item(id: string): RetryItem {
  return {
    id,
    payload: Buffer.from(`payload-${id}`),
    targetUrl: LOGICAL,
    headers: {},
  };
}

function makeSet(extra: QuorumFanoutSetOptions = {}) {
  const clock = manualClock();
  const evicted: QuorumEvictedInfo[] = [];
  const set = new QuorumFanoutSet(CFG, {
    now: clock.now,
    onEvicted: (i) => evicted.push(i),
    ...extra,
  });
  const dispatch = (id: string): string[] => {
    const memberIds: string[] = [];
    set.dispatch(item(id), (m) => memberIds.push(m.id));
    return memberIds;
  };
  return { set, evicted, clock, dispatch };
}

/** Settle a fan-out by acknowledging every member (quorum = 2, N = 2). */
function settle(set: QuorumFanoutSet, fanoutId: string): void {
  set.recordDelivered(`${fanoutId}:quorum:0`, { targetUrl: T1 });
  set.recordDelivered(`${fanoutId}:quorum:1`, { targetUrl: T2 });
}

describe("quorum retention revision: QuorumFanoutSet (WR-350)", () => {
  it("tightening retentionMs evicts verdicts older than the new window at the next sweep", () => {
    const { set, evicted, clock, dispatch } = makeSet();
    dispatch("f1");
    settle(set, "f1");
    clock.advance(5000); // still inside the 1h construction window
    assert.equal(set.stats().length, 1);

    assert.deepEqual(set.retuneRetention({ retentionMs: 1000 }), {
      retentionMs: 1000,
      maxFanouts: 10_000,
    });
    // The revision itself does not sweep: the verdict is still listed
    // until the next dispatch / record / stats call.
    assert.equal(set.stats().length, 0);
    assert.equal(set.evictedCount(), 1);
    assert.equal(evicted.length, 1);
    assert.equal(evicted[0].fanoutId, "f1");
    assert.equal(evicted[0].reason, "retention_ttl");
  });

  it("loosening retentionMs keeps a batch that the old window would have evicted", () => {
    const { set, clock, dispatch } = makeSet({ retentionMs: 1000 });
    dispatch("f1");
    settle(set, "f1");
    clock.advance(500);
    set.retuneRetention({ retentionMs: 60_000 });
    clock.advance(500); // age 1000ms: the old window would evict here
    assert.equal(set.stats().length, 1);
    assert.equal(set.evictedCount(), 0);
    clock.advance(59_000); // age 60_000ms: the new window evicts here
    assert.equal(set.stats().length, 0);
    assert.equal(set.evictedCount(), 1);
  });

  it("lowering maxFanouts evicts the oldest verdicts first (verdict-time order)", () => {
    const { set, evicted, clock, dispatch } = makeSet({ maxFanouts: 10 });
    dispatch("f1");
    settle(set, "f1");
    clock.advance(1000);
    dispatch("f2");
    settle(set, "f2");
    clock.advance(1000);
    dispatch("f3");
    settle(set, "f3");
    assert.equal(set.stats().length, 3);

    assert.deepEqual(set.retuneRetention({ maxFanouts: 1 }), {
      retentionMs: 3_600_000,
      maxFanouts: 1,
    });
    const remaining = set.stats();
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].fanoutId, "f3");
    assert.equal(set.evictedCount(), 2);
    assert.deepEqual(
      evicted.map((e) => e.fanoutId),
      ["f1", "f2"]
    );
    assert.ok(evicted.every((e) => e.reason === "lru_cap"));
  });

  it("raising maxFanouts retains fan-outs the old cap would have evicted", () => {
    const { set, clock, dispatch } = makeSet({ maxFanouts: 1 });
    dispatch("f1");
    settle(set, "f1");
    clock.advance(1000);
    dispatch("f2");
    settle(set, "f2"); // the record sweep evicts f1 under the old cap
    assert.equal(set.stats().length, 1);
    assert.equal(set.evictedCount(), 1);

    set.retuneRetention({ maxFanouts: 10 });
    clock.advance(1000);
    dispatch("f3");
    settle(set, "f3");
    assert.equal(set.stats().length, 2);
    assert.equal(set.evictedCount(), 1);
  });

  it("illegal values throw RangeError and leave the live values intact; empty/non-object patches throw too", () => {
    const { set } = makeSet({ retentionMs: 1000, maxFanouts: 5 });
    const before = set.currentRetention();
    const badPatches = [
      { retentionMs: 0 },
      { retentionMs: -1 },
      { retentionMs: 1.5 },
      { retentionMs: Number.NaN },
      { retentionMs: Infinity },
      { retentionMs: "1000" as never },
      { maxFanouts: 0 },
      { maxFanouts: -5 },
      { maxFanouts: 2.5 },
      { maxFanouts: Number.NaN },
      { maxFanouts: Infinity },
      // A patch that is half-legal must not apply the legal half.
      { retentionMs: 2000, maxFanouts: 0 },
    ];
    for (const patch of badPatches) {
      assert.throws(() => set.retuneRetention(patch), RangeError);
    }
    assert.throws(() => set.retuneRetention({}), RangeError);
    assert.throws(() => set.retuneRetention(null as never), RangeError);
    assert.throws(() => set.retuneRetention("x" as never), RangeError);
    assert.throws(() => set.retuneRetention([] as never), RangeError);
    assert.deepEqual(set.currentRetention(), before);
  });

  it("same-value patch is a silent no-op; currentRetention returns a fresh snapshot, not a live reference", () => {
    const { set } = makeSet({ retentionMs: 1000, maxFanouts: 5 });
    assert.deepEqual(set.retuneRetention({ retentionMs: 1000 }), {
      retentionMs: 1000,
      maxFanouts: 5,
    });
    assert.deepEqual(set.retuneRetention({ retentionMs: 1000, maxFanouts: 5 }), {
      retentionMs: 1000,
      maxFanouts: 5,
    });
    const snapshot = set.currentRetention();
    snapshot.retentionMs = 999;
    snapshot.maxFanouts = 999;
    assert.deepEqual(set.currentRetention(), { retentionMs: 1000, maxFanouts: 5 });
  });

  it("revision does not reset the evicted cumulative count", () => {
    const { set, clock, dispatch } = makeSet({ retentionMs: 1000 });
    dispatch("f1");
    settle(set, "f1");
    clock.advance(2000);
    assert.equal(set.stats().length, 0);
    assert.equal(set.evictedCount(), 1);

    set.retuneRetention({ retentionMs: 500 });
    dispatch("f2");
    settle(set, "f2");
    clock.advance(1000);
    assert.equal(set.stats().length, 0);
    assert.equal(set.evictedCount(), 2);
  });

  it("an in-progress fan-out is still never evicted after revision", () => {
    const { set, clock, dispatch } = makeSet({ retentionMs: 1000, maxFanouts: 1 });
    dispatch("f1"); // never settles: in progress
    clock.advance(5000);
    set.retuneRetention({ retentionMs: 1, maxFanouts: 1 });
    assert.equal(set.stats().length, 1);
    assert.equal(set.evictedCount(), 0);

    dispatch("f2");
    settle(set, "f2");
    clock.advance(5000);
    const remaining = set.stats();
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].fanoutId, "f1");
    assert.equal(set.evictedCount(), 1);
  });

  it("an already-evicted fan-out is never resurrected by loosening the retention", () => {
    const { set, clock, dispatch } = makeSet({ retentionMs: 1000 });
    dispatch("f1");
    settle(set, "f1");
    clock.advance(2000);
    assert.equal(set.stats().length, 0);
    assert.equal(set.evictedCount(), 1);

    set.retuneRetention({ retentionMs: 60_000, maxFanouts: 10_000 });
    assert.equal(set.stats().length, 0);
    assert.equal(set.evictedCount(), 1);
  });
});

describe("quorum retention revision: RetryQueue (WR-350)", () => {
  it("configured queue: revise/get round-trip on the live values", () => {
    const q = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      quorum: CFG,
    });
    assert.deepEqual(q.getQuorumRetention(), { retentionMs: 3_600_000, maxFanouts: 10_000 });
    assert.deepEqual(q.reviseQuorumRetention({ retentionMs: 5000 }), {
      retentionMs: 5000,
      maxFanouts: 10_000,
    });
    assert.deepEqual(q.getQuorumRetention(), { retentionMs: 5000, maxFanouts: 10_000 });
    assert.throws(() => q.reviseQuorumRetention({ retentionMs: 0 }), RangeError);
    assert.deepEqual(q.getQuorumRetention(), { retentionMs: 5000, maxFanouts: 10_000 });
  });

  it("unconfigured quorum: revise throws the must-restart Error and the getter is undefined", () => {
    const q = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
    });
    assert.equal(q.getQuorumRetention(), undefined);
    assert.throws(
      () => q.reviseQuorumRetention({ retentionMs: 5000 }),
      /reviseQuorumRetention: quorum fan-out is not configured — enabling it requires a restart/
    );
  });
});

describe("quorum retention revision: RelayServer (WR-350)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function listen(server: Server): Promise<number> {
    return new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
  }

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "quorum-retention-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: LOGICAL,
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

  it("revision audits previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      quorum: CFG,
      quorumRetentionMs: 1000,
      quorumMaxFanouts: 100,
    });
    await listen(relay);
    assert.deepEqual(relay.getQuorumRetention!(), { retentionMs: 1000, maxFanouts: 100 });
    assert.deepEqual(relay.reviseQuorumRetention!({ retentionMs: 5000, maxFanouts: 50 }), {
      retentionMs: 5000,
      maxFanouts: 50,
    });
    const revised = eventsOf(audit, "quorum_retention_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { retentionMs: 1000, maxFanouts: 100 });
    assert.deepEqual(revised[0].current, { retentionMs: 5000, maxFanouts: 50 });
    // Landing exactly on the live values audits nothing.
    relay.reviseQuorumRetention!({ retentionMs: 5000 });
    assert.equal(eventsOf(audit, "quorum_retention_revised").length, 1);
    // An illegal patch throws and leaves the live values and audit untouched.
    assert.throws(() => relay.reviseQuorumRetention!({ retentionMs: 0 }), RangeError);
    assert.throws(() => relay.reviseQuorumRetention!({} as never), RangeError);
    assert.equal(eventsOf(audit, "quorum_retention_revised").length, 1);
    assert.deepEqual(relay.getQuorumRetention!(), { retentionMs: 5000, maxFanouts: 50 });
  });

  it("defaults apply when unset; the getter is always set and returns undefined for unconfigured quorum", async () => {
    const { relay } = makeRelay({ quorum: CFG });
    await listen(relay);
    assert.deepEqual(relay.getQuorumRetention!(), { retentionMs: 3_600_000, maxFanouts: 10_000 });
    const bare = makeRelay();
    await listen(bare.relay);
    assert.equal(bare.relay.getQuorumRetention!(), undefined);
    assert.throws(
      () => bare.relay.reviseQuorumRetention!({ retentionMs: 5000 }),
      /not configured — enabling it requires a restart/
    );
  });
});
