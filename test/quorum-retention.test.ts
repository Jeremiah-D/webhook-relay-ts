import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import {
  QuorumFanoutSet,
  RetryQueue,
  assertValidQuorumRetentionOptions,
  type QuorumEvictedInfo,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import type { QuorumFanoutSetOptions } from "../src/quorum.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

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

describe("quorum retention (WR-109)", () => {
  it("evicts a settled fan-out once its verdict passes retentionMs (retention_ttl)", () => {
    const { set, evicted, clock, dispatch } = makeSet({ retentionMs: 1000 });
    const dispatchedIso = clock.iso();
    dispatch("f1");
    settle(set, "f1");
    const settledIso = clock.iso();

    assert.equal(set.stats().length, 1);
    assert.equal(set.evictedCount(), 0);

    // Boundary: age 999ms < retentionMs — retained.
    clock.advance(999);
    assert.equal(set.stats().length, 1);

    // Age 1000ms >= retentionMs — evicted on the read (stats sweeps).
    clock.advance(1);
    assert.equal(set.stats().length, 0);
    assert.equal(set.evictedCount(), 1);
    assert.equal(evicted.length, 1);
    const info = evicted[0];
    assert.equal(info.event, "quorum_evicted");
    assert.equal(info.fanoutId, "f1");
    assert.equal(info.endpoint, LOGICAL);
    assert.equal(info.status, "satisfied");
    assert.equal(info.acked, 2);
    assert.equal(info.targets, 2);
    assert.equal(info.deadLettered, 0);
    assert.equal(info.dispatchedAt, dispatchedIso);
    assert.equal(info.settledAt, settledIso);
    assert.equal(info.evictedAt, clock.iso());
    assert.equal(info.reason, "retention_ttl");
    // Operator metadata only — no payloads leak into the archive event.
    assert.ok(!("payload" in info));
    assert.ok(typeof info.traceId === "string" && info.traceId.length > 0);
  });

  it("evicts the oldest verdicts first when settled fan-outs exceed maxFanouts (lru_cap)", () => {
    const { set, evicted, clock, dispatch } = makeSet({
      retentionMs: 3_600_000,
      maxFanouts: 2,
    });
    dispatch("f1");
    settle(set, "f1");
    clock.advance(100);
    dispatch("f2");
    settle(set, "f2");
    clock.advance(100);
    // The third verdict trips the cap at settle time (recordDelivered sweeps).
    dispatch("f3");
    settle(set, "f3");

    assert.equal(set.evictedCount(), 1);
    assert.equal(evicted.length, 1);
    assert.equal(evicted[0].fanoutId, "f1");
    assert.equal(evicted[0].reason, "lru_cap");
    const rows = set.stats();
    assert.deepEqual(
      rows.map((r) => r.fanoutId),
      ["f2", "f3"]
    );
  });

  it("never evicts in-progress fan-outs, however old or numerous", () => {
    const { set, evicted, clock, dispatch } = makeSet({
      retentionMs: 1,
      maxFanouts: 1,
    });
    dispatch("f1");
    clock.advance(10_000);
    dispatch("f2");
    clock.advance(10_000);
    // Dispatch and reads both sweep — neither in-progress fan-out may go.
    const rows = set.stats();
    assert.equal(rows.length, 2);
    assert.ok(rows.every((r) => r.status === "in_progress"));
    assert.equal(set.evictedCount(), 0);
    assert.equal(evicted.length, 0);
  });

  it("purges member ids on eviction, so late outcomes are silently ignored", () => {
    const { set, evicted, clock, dispatch } = makeSet({ retentionMs: 1000 });
    dispatch("f1");
    assert.ok(set.isMemberId("f1:quorum:0"));
    settle(set, "f1");
    clock.advance(1001);
    set.stats(); // sweep runs on the read
    assert.equal(set.evictedCount(), 1);
    assert.ok(!set.isMemberId("f1:quorum:0"));
    assert.ok(!set.isMemberId("f1:quorum:1"));

    // Terminal semantics: a verdict, once reached and archived, is
    // immutable — late outcomes land as unknown ids and are ignored.
    set.recordDelivered("f1:quorum:0", { targetUrl: T1 });
    set.recordDeadLetter("f1:quorum:1", "transport", "late failure");
    assert.equal(set.evictedCount(), 1);
    assert.equal(evicted.length, 1);
    assert.equal(set.stats().length, 0);
  });

  it("the TTL sweep runs after a verdict, not only on reads", () => {
    const { set, clock, dispatch } = makeSet({ retentionMs: 100 });
    dispatch("f1");
    settle(set, "f1");
    clock.advance(200);
    // No stats() call between here and the next dispatch: the second
    // fan-out's dispatch must sweep the expired first one.
    dispatch("f2");
    assert.equal(set.evictedCount(), 1);
    assert.deepEqual(
      set.stats().map((r) => r.fanoutId),
      ["f2"]
    );
  });

  it("archives failed fan-outs with status failed and their lost-target count", () => {
    const { set, evicted, clock, dispatch } = makeSet({ retentionMs: 500 });
    dispatch("f1");
    // quorum = 2 of 2: losing one target makes the quorum unreachable.
    set.recordDeadLetter("f1:quorum:0", "transport", "connection refused");
    const failedIso = clock.iso();
    assert.equal(set.stats()[0].status, "failed");
    clock.advance(500);
    set.stats();
    assert.equal(evicted.length, 1);
    assert.equal(evicted[0].status, "failed");
    assert.equal(evicted[0].acked, 0);
    assert.equal(evicted[0].deadLettered, 1);
    assert.equal(evicted[0].settledAt, failedIso);
    assert.equal(evicted[0].reason, "retention_ttl");
  });

  it("rejects invalid retention options with RangeError at construction", () => {
    for (const retentionMs of [0, -1, 1.5, NaN, "1000", Infinity]) {
      assert.throws(
        () => new QuorumFanoutSet(CFG, { retentionMs: retentionMs as number }),
        RangeError,
        `retentionMs=${String(retentionMs)}`
      );
    }
    for (const maxFanouts of [0, -3, 2.5, NaN, "10", Infinity]) {
      assert.throws(
        () => new QuorumFanoutSet(CFG, { maxFanouts: maxFanouts as number }),
        RangeError,
        `maxFanouts=${String(maxFanouts)}`
      );
    }
    assert.throws(
      () => new QuorumFanoutSet(CFG, { now: "not-a-clock" as unknown as () => number }),
      RangeError
    );
    // Defaults are valid: absent options never throw.
    assert.doesNotThrow(() => new QuorumFanoutSet(CFG));
    assert.doesNotThrow(() => assertValidQuorumRetentionOptions({}));
  });

  it("fails fast through RetryQueue construction for invalid retention values", () => {
    const sender: Sender = async () => {};
    assert.throws(
      () =>
        new RetryQueue({
          sender,
          quorum: CFG,
          quorumRetentionMs: 0,
        }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          sender,
          quorum: CFG,
          quorumMaxFanouts: -2,
        }),
      RangeError
    );
    const q = new RetryQueue({ sender, quorum: CFG, quorumRetentionMs: 60_000 });
    assert.equal(q.getQuorumEvictedCount(), 0);
    q.stop();
  });
});

describe("quorum retention server wiring (WR-109)", () => {
  it("serves GET /quorum/stats with the eviction count and archives quorum_evicted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "quorum-retention-server-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const opToken = "op-token";
    const payload = Buffer.from(JSON.stringify({ n: 1 }));
    const server = createRelayServer({
      secret: "test-secret",
      forwardUrl: LOGICAL,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => {},
      quorum: { [LOGICAL]: { targets: [T1, T2], quorum: 2 } },
      quorumRetentionMs: 100,
      retry: { baseDelayMs: 5, maxDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const get = (path: string, headers: Record<string, string>) =>
        new Promise<{ status: number; body: string }>((resolve, reject) => {
          const req = httpRequest({ port, method: "GET", path, headers }, (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c: Buffer) => chunks.push(c));
            res.on("end", () =>
              resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") })
            );
          });
          req.on("error", reject);
          req.end();
        });
      const post = (path: string, headers: Record<string, string>, body: Buffer) =>
        new Promise<{ status: number; body: string }>((resolve, reject) => {
          const req = httpRequest({ port, method: "POST", path, headers }, (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c: Buffer) => chunks.push(c));
            res.on("end", () =>
              resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") })
            );
          });
          req.on("error", reject);
          req.end(body);
        });

      const accepted = await post(
        "/hook",
        { "content-type": "application/json", "x-signature": signSha256(payload, "test-secret") },
        payload
      );
      assert.equal(accepted.status, 202);

      // The sender acks immediately, so the fan-out settles within
      // milliseconds; retentionMs=100ms expires it, and the next stats
      // read sweeps it. Poll: delivery is async.
      const auth = { authorization: `Bearer ${opToken}` };
      let stats: { fanouts: unknown[]; evicted: number } | undefined;
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const res = await get("/quorum/stats", auth);
        assert.equal(res.status, 200);
        stats = JSON.parse(res.body) as { fanouts: unknown[]; evicted: number };
        if (stats.evicted >= 1) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(stats !== undefined && stats.evicted >= 1, "fan-out evicted by the retention sweep");
      assert.ok(Array.isArray(stats.fanouts));
      assert.equal(stats.fanouts.length, 0);

      // GET /quorum keeps its array shape (backward compatible).
      const quorumRes = await get("/quorum", auth);
      assert.equal(quorumRes.status, 200);
      assert.deepEqual(JSON.parse(quorumRes.body), []);

      // The eviction is archived in the audit trail (operator metadata).
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const evictedEvents = events.filter((e) => e.event === "quorum_evicted");
      assert.equal(evictedEvents.length, 1);
      assert.equal(evictedEvents[0].reason, "retention_ttl");
      assert.equal(evictedEvents[0].status, "satisfied");
      assert.ok(!("payload" in (evictedEvents[0] as object)));

      // The counter is rendered in Prometheus exposition (activity-gated).
      const metricsRes = await get("/metrics", auth);
      assert.equal(metricsRes.status, 200);
      assert.match(metricsRes.body, /relay_quorum_evicted_total 1/);

      // Fail-closed: a non-matching bearer is refused.
      const forbidden = await get("/quorum/stats", { authorization: "Bearer wrong" });
      assert.equal(forbidden.status, 403);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("exposes no eviction series until the first eviction (activity-gated)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "quorum-retention-gate-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const opToken = "op-token";
    const server = createRelayServer({
      secret: "test-secret",
      forwardUrl: LOGICAL,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => {},
      quorum: { [LOGICAL]: { targets: [T1, T2], quorum: 2 } },
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const res = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        const req = httpRequest(
          { port, method: "GET", path: "/metrics", headers: { authorization: `Bearer ${opToken}` } },
          (r) => {
            const chunks: Buffer[] = [];
            r.on("data", (c: Buffer) => chunks.push(c));
            r.on("end", () =>
              resolve({ status: r.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") })
            );
          }
        );
        req.on("error", reject);
        req.end();
      });
      assert.equal(res.status, 200);
      assert.ok(!res.body.includes("relay_quorum_evicted_total"));
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
