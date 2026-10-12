import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type Sender,
  type RetryItem,
  type RetryQueueOptions,
  type ScheduledFiredEvent,
} from "../src/retry.ts";
import { ScheduledDeliveryQueue } from "../src/scheduled.ts";
import { nextCronOccurrence, parseCronExpression } from "../src/cron.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const URL_A = "http://localhost:9999/a";
const relaySecret = "relay-secret-wr80";
const BODY = Buffer.from(JSON.stringify({ ping: "cron" }));

/** Manual timer: the scheduler arms exactly one timer (for the heap head). */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pendingCount: () => pending.length,
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
    },
  };
}

function item(id: string, targetUrl: string, extra: Partial<RetryItem> = {}): RetryItem {
  return { id, payload: Buffer.from(`payload-${id}`), targetUrl, headers: {}, ...extra };
}

// Monday 2026-10-12 08:00:00 UTC.
const T0 = Date.UTC(2026, 9, 12, 8, 0, 0);

function schedulerHarness() {
  let now = T0;
  const t = manualTimer();
  const due: RetryItem[][] = [];
  const q = new ScheduledDeliveryQueue({
    now: () => now,
    setTimer: t.setTimer,
    clearTimer: (h) => h.clear(),
    onDue: (items) => due.push(items),
  });
  q.arm();
  return { q, t, due, setNow: (ms: number) => { now = ms; }, now: () => now };
}

describe("WR-80 recurring scheduler", () => {
  it("registers a schedule and reports the next fire", () => {
    const { q } = schedulerHarness();
    const id = q.addRecurring(item("sched-1", URL_A, { traceId: "trace-tpl" }), "0 9 * * *");
    assert.equal(id, "sched-1");
    const expected = nextCronOccurrence(parseCronExpression("0 9 * * *"), T0);
    assert.equal(q.nextFireAt("sched-1"), expected);
    const listed = q.list();
    assert.equal(listed.length, 1);
    assert.equal(listed[0].recurring, true);
    assert.equal(listed[0].cron, "0 9 * * *");
    assert.equal(listed[0].nextAt, expected);
    assert.equal(listed[0].nextAtIso, new Date(expected).toISOString());
    assert.equal(listed[0].paused, false);
    assert.equal(listed[0].traceId, "trace-tpl");
    assert.ok(!("payload" in listed[0]), "payload must never leak to operators");
    const stats = q.stats();
    assert.equal(stats.recurring, 1);
    assert.equal(stats.fired, 0);
    assert.equal(stats.pending, 0);
  });

  it("rejects invalid cron expressions and duplicate ids", () => {
    const { q } = schedulerHarness();
    assert.throws(() => q.addRecurring(item("s1", URL_A), "not a cron"), RangeError);
    assert.throws(() => q.addRecurring(item("s1", URL_A), "*/0 * * * *"), RangeError);
    assert.throws(() => q.addRecurring({ ...item("x", URL_A), id: "" }, "* * * * *"), RangeError);
    q.addRecurring(item("s1", URL_A), "* * * * *");
    assert.throws(() => q.addRecurring(item("s1", URL_A), "* * * * *"), Error);
    // One-shot namespace is disjoint: a parked deliver_at id cannot be reused.
    q.park({ ...item("one-shot", URL_A), deliverAt: T0 + 60000 });
    assert.throws(() => q.addRecurring(item("one-shot", URL_A), "* * * * *"), Error);
    assert.throws(() => q.park({ ...item("s1", URL_A), deliverAt: T0 + 60000 }), Error);
  });

  it("generates one fresh delivery per cycle", () => {
    const { q, t, due, setNow } = schedulerHarness();
    q.addRecurring(item("sched-1", URL_A, { traceId: "trace-tpl" }), "* * * * *");
    // First fire: 08:01.
    setNow(T0 + 60000);
    t.step();
    assert.equal(due.length, 1);
    const [first] = due[0];
    assert.equal(first.id, "sched-1#1");
    assert.equal(first.scheduleId, "sched-1");
    assert.equal(first.targetUrl, URL_A);
    assert.ok(first.payload.equals(Buffer.from("payload-sched-1")));
    assert.ok(typeof first.traceId === "string" && first.traceId.length > 0);
    assert.notEqual(first.traceId, "trace-tpl");
    assert.equal(first.deliverAt, undefined);
    assert.equal(first.enqueuedAt, undefined);
    assert.equal(q.stats().fired, 1);
    // Second fire: 08:02, fresh traceId.
    setNow(T0 + 2 * 60000);
    t.step();
    const [second] = due[1];
    assert.equal(second.id, "sched-1#2");
    assert.notEqual(second.traceId, first.traceId);
    assert.equal(q.nextFireAt("sched-1"), T0 + 3 * 60000);
  });

  it("skips missed cycles instead of backfilling", () => {
    const { q, t, due, setNow } = schedulerHarness();
    q.addRecurring(item("sched-1", URL_A), "* * * * *");
    // Jump five cycles ahead: exactly one occurrence fires, and the next
    // fire is computed from now — the missed cycles never backfill.
    setNow(T0 + 5 * 60000);
    t.step();
    assert.equal(due.length, 1);
    assert.equal(due[0][0].id, "sched-1#1");
    assert.equal(q.nextFireAt("sched-1"), T0 + 6 * 60000);
    assert.equal(q.stats().fired, 1);
  });

  it("pause stops generation; resume recomputes from now", () => {
    const { q, t, due, setNow } = schedulerHarness();
    q.addRecurring(item("sched-1", URL_A), "* * * * *");
    assert.equal(q.pauseSchedule("sched-1"), true);
    assert.equal(q.pauseSchedule("sched-1"), true); // idempotent
    assert.equal(q.pauseSchedule("nope"), false);
    setNow(T0 + 60000);
    t.step();
    assert.equal(due.length, 0);
    assert.equal(q.nextFireAt("sched-1"), undefined);
    assert.equal(q.list()[0].paused, true);
    // Resume later: next fire is from now, not from the pause instant.
    setNow(T0 + 10 * 60000);
    assert.equal(q.resumeSchedule("sched-1"), true);
    assert.equal(q.resumeSchedule("sched-1"), true); // idempotent
    assert.equal(q.resumeSchedule("nope"), false);
    assert.equal(q.nextFireAt("sched-1"), T0 + 11 * 60000);
    setNow(T0 + 11 * 60000);
    t.step();
    assert.equal(due.length, 1);
    assert.equal(due[0][0].id, "sched-1#1");
  });

  it("one-shot parking is unaffected by recurring schedules", () => {
    const { q, t, due, setNow } = schedulerHarness();
    q.park({ ...item("one-shot", URL_A), deliverAt: T0 + 30000 });
    q.addRecurring(item("sched-1", URL_A), "* * * * *");
    setNow(T0 + 30000);
    t.step();
    assert.equal(due.length, 1);
    assert.equal(due[0][0].id, "one-shot");
    setNow(T0 + 60000);
    t.step();
    assert.equal(due[1][0].id, "sched-1#1");
    // cancel() only touches one-shot items.
    assert.equal(q.cancel("sched-1"), false);
    assert.equal(q.stats().recurring, 1);
  });

  it("clear() drops recurring schedules with everything else", () => {
    const { q } = schedulerHarness();
    q.addRecurring(item("sched-1", URL_A), "* * * * *");
    q.clear();
    assert.equal(q.stats().recurring, 0);
    assert.equal(q.list().length, 0);
    assert.equal(q.nextFireAt("sched-1"), undefined);
  });
});

describe("WR-80 recurring queue integration", () => {
  function queueHarness(opts: { deadlineMs?: number; extra?: RetryQueueOptions } = {}) {
    let now = T0;
    const t = manualTimer();
    const sent: RetryItem[] = [];
    const fired: ScheduledFiredEvent[] = [];
    const sender: Sender = async (it) => {
      sent.push(it);
      return { statusCode: 200, body: Buffer.from("ok"), truncated: false };
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 2,
      baseDelayMs: 50,
      jitterMs: 0,
      scheduled: { now: () => now, setTimer: t.setTimer },
      onScheduledFired: (e) => fired.push(e),
      ...(opts.deadlineMs !== undefined
        ? { deliveryDeadline: { deadlines: { [URL_A]: opts.deadlineMs }, now: () => now } }
        : {}),
      ...opts.extra,
    });
    q.start();
    // Drain both the scheduler and the queue's dispatch timers. Stepping
    // fires the scheduler's head timer early too, but an early fire is a
    // harmless no-op re-arm (the head is not due yet).
    const drain = async (rounds = 4) => {
      for (let i = 0; i < rounds; i++) {
        t.step();
        await new Promise((r) => setImmediate(r));
      }
    };
    return { q, t, sent, fired, setNow: (ms: number) => { now = ms; }, drain };
  }

  it("occurrences enter the normal path and audit scheduled_fired", async () => {
    const { q, t, sent, fired, setNow, drain } = queueHarness();
    const sid = q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
    assert.equal(sid, "sched-1");
    setNow(T0 + 60000);
    t.step();
    await drain();
    setNow(T0 + 2 * 60000);
    t.step();
    await drain();
    assert.equal(sent.length, 2);
    assert.equal(sent[0].id, "sched-1#1");
    assert.equal(sent[1].id, "sched-1#2");
    assert.equal(fired.length, 2);
    assert.equal(fired[0].event, "scheduled_fired");
    assert.equal(fired[0].scheduleId, "sched-1");
    assert.equal(fired[0].id, "sched-1#1");
    assert.equal(fired[0].targetUrl, URL_A);
    assert.equal(fired[0].nextAt, T0 + 2 * 60000);
    assert.equal(q.getScheduledStats().fired, 2);
    q.stop();
  });

  it("each occurrence gets an independent delivery deadline (WR-76 orthogonality)", async () => {
    const { q, t, sent, setNow, drain } = queueHarness({ deadlineMs: 60000 });
    q.addRecurringDelivery(item("sched-1", URL_A), "* * * * *");
    setNow(T0 + 60000);
    t.step();
    await drain();
    setNow(T0 + 5 * 60000);
    t.step();
    await drain();
    assert.equal(sent.length, 2);
    // The deadline clock (enqueuedAt) restarts per occurrence — a stale
    // clock from the template never leaks across cycles.
    assert.equal(sent[0].enqueuedAt, T0 + 60000);
    assert.equal(sent[1].enqueuedAt, T0 + 5 * 60000);
    q.stop();
  });
});

describe("WR-80 server integration", () => {
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

  function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path: "/", method: "POST", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  function get(port: number, path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "GET", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            let json: unknown = null;
            try {
              json = JSON.parse(Buffer.concat(chunks).toString());
            } catch {
              // Leave json as null; the status assertion will fail the test.
            }
            resolve({ status: res.statusCode ?? 0, json });
          });
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  function postOperator(port: number, path: string, token: string) {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path,
          method: "POST",
          headers: { authorization: `Bearer ${token}` },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            let json: unknown = null;
            try {
              json = JSON.parse(Buffer.concat(chunks).toString());
            } catch {
              // Leave json as null; the status assertion will fail the test.
            }
            resolve({ status: res.statusCode ?? 0, json });
          });
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  function signedHeaders(extra: Record<string, string> = {}) {
    return {
      "x-signature": signSha256(BODY, relaySecret),
      "content-type": "application/json",
      ...extra,
    };
  }

  async function makeRelay() {
    const stub = createServer((_req, res) => {
      res.writeHead(200).end("ok");
    });
    const stubPort = await listen(stub);
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr80-")), "audit.jsonl"));
    const token = "op-token-wr80";
    const relay = createRelayServer({
      secret: relaySecret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: token,
      retry: { baseDelayMs: 50, maxDelayMs: 1000, maxAttempts: 3, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    return { stub, relay, relayPort, audit, token };
  }

  it("registers a cron schedule via x-schedule-cron and lists it", async () => {
    const { stub, relay, relayPort, audit, token } = await makeRelay();
    try {
      const res = await post(relayPort, BODY, signedHeaders({ "x-schedule-cron": "*/5 * * * *" }));
      assert.equal(res.status, 202);
      const body = JSON.parse(res.text) as Record<string, unknown>;
      assert.equal(body.scheduled, true);
      assert.equal(body.recurring, true);
      assert.equal(body.cron, "*/5 * * * *");
      assert.ok(typeof body.scheduleId === "string");
      assert.ok(typeof body.nextAt === "string");

      const listed = await get(relayPort, "/scheduled", { authorization: `Bearer ${token}` });
      assert.equal(listed.status, 200);
      const items = listed.json as Array<Record<string, unknown>>;
      assert.equal(items.length, 1);
      assert.equal(items[0].id, body.scheduleId);
      assert.equal(items[0].recurring, true);
      assert.equal(items[0].cron, "*/5 * * * *");
      assert.equal(items[0].paused, false);
      assert.ok(!("payload" in items[0]), "payload must never leak to operators");

      const registered = audit.query({ event: "schedule_registered" }) as Array<{
        cron: string;
      }>;
      assert.equal(registered.length, 1);
      assert.equal(registered[0].cron, "*/5 * * * *");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("rejects invalid cron and conflicting headers with 400", async () => {
    const { stub, relay, relayPort, audit } = await makeRelay();
    try {
      const bad = await post(relayPort, BODY, signedHeaders({ "x-schedule-cron": "every minute" }));
      assert.equal(bad.status, 400);
      assert.match(bad.text, /x-schedule-cron/);
      const rejected = audit.query({ event: "rejected" }) as Array<{ reason: string }>;
      assert.ok(rejected.some((e) => e.reason === "invalid_schedule_cron"));

      const conflict = await post(
        relayPort,
        BODY,
        signedHeaders({ "x-schedule-cron": "* * * * *", "x-deliver-at": String(Date.now() + 60000) })
      );
      assert.equal(conflict.status, 400);
      assert.match(conflict.text, /mutually exclusive/);
      const rejected2 = audit.query({ event: "rejected" }) as Array<{ reason: string }>;
      assert.ok(rejected2.some((e) => e.reason === "conflicting_schedule"));
      // Neither the invalid nor the conflicting request registered anything.
      assert.equal(audit.query({ event: "schedule_registered" }).length, 0);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("pauses and resumes a schedule through the operator endpoints", async () => {
    const { stub, relay, relayPort, audit, token } = await makeRelay();
    try {
      const res = await post(relayPort, BODY, signedHeaders({ "x-schedule-cron": "* * * * *" }));
      const { scheduleId } = JSON.parse(res.text) as { scheduleId: string };

      const paused = await postOperator(relayPort, `/scheduled/${scheduleId}/pause`, token);
      assert.equal(paused.status, 200);
      assert.deepEqual(paused.json, { id: scheduleId, paused: true });
      const listed = (await get(relayPort, "/scheduled", {
        authorization: `Bearer ${token}`,
      })) as { status: number; json: Array<Record<string, unknown>> };
      assert.equal(listed.json[0].paused, true);
      assert.equal(audit.query({ event: "schedule_paused" }).length, 1);

      const resumed = await postOperator(relayPort, `/scheduled/${scheduleId}/resume`, token);
      assert.equal(resumed.status, 200);
      assert.equal((resumed.json as Record<string, unknown>).paused, false);
      assert.equal(audit.query({ event: "schedule_resumed" }).length, 1);

      // Unknown schedule: fail-closed 404.
      assert.equal((await postOperator(relayPort, "/scheduled/nope/pause", token)).status, 404);
      // No token: 403 (operator endpoints are enabled).
      assert.equal(
        (
          await new Promise<{ status: number }>((resolve, reject) => {
            const r = httpRequest(
              { host: "127.0.0.1", port: relayPort, path: `/scheduled/${scheduleId}/pause`, method: "POST" },
              (res) => resolve({ status: res.statusCode ?? 0 })
            );
            r.on("error", reject);
            r.end();
          })
        ).status,
        403
      );
    } finally {
      await close(relay);
      await close(stub);
    }
  });
});
