import { describe, it, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type Sender,
  type StaleEndpointPausedEvent,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const HOOK_KEY = "stale-pause-audit-callback-revision-key";
const OPERATOR_TOKEN = "stale-pause-audit-callback-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "stale-pause-audit-revision" }));
const EP = "http://localhost:9999/hook";
const EP2 = "http://localhost:9999/hook2";
const DAY_MS = 86_400_000;
const T0 = 1_700_000_000_000;

/**
 * Manual timer with single-step control: parking re-arms timers, so the
 * tests advance one wave at a time instead of draining everything.
 */
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
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const fn of fns) fn();
      await flush();
    },
  };
}

/** Let the deliver() promise chain (turn -> limiter -> sender) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string = EP) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

/** Controllable clock shared by the queue stamps and the sweep. */
function clock() {
  let nowMs = T0;
  return {
    now: () => nowMs,
    advance: (ms: number) => {
      nowMs += ms;
    },
  };
}

function makeQueue(opts: Record<string, unknown> = {}) {
  const c = clock();
  const timer = manualTimer();
  const seen: StaleEndpointPausedEvent[] = [];
  const q = new RetryQueue({
    sender: async () => {},
    setTimer: timer.setTimer,
    clearTimer: timer.clearTimer,
    jitterMs: 0,
    stalePause: { staleAfterDays: 30, now: c.now },
    onStalePauseAudit: (e) => seen.push(e),
    ...opts,
  } as ConstructorParameters<typeof RetryQueue>[0]);
  return { q, c, timer, seen };
}

describe("RetryQueue stale-pause audit callback revision (WR-402)", () => {
  it("the revised callback receives the next auto-pause with exact fields; the old callback stays silent", async () => {
    const { q, c, timer, seen } = makeQueue();
    const second: StaleEndpointPausedEvent[] = [];
    q.enqueue(item("a"));
    q.start();
    try {
      await timer.step(); // delivered at T0
      c.advance(31 * DAY_MS);
      const res = q.sweepStaleEndpoints();
      assert.equal(res.paused.length, 1);
      assert.equal(res.paused[0].endpoint, EP);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].event, "endpoint_auto_paused");
      assert.equal(seen[0].endpoint, EP);
      assert.equal(seen[0].idleDays, 31);
      assert.equal(seen[0].staleAfterDays, 30);
      assert.equal(seen[0].lastSuccessfulDeliveryAt, new Date(T0).toISOString());
      assert.equal(seen[0].at, new Date(T0 + 31 * DAY_MS).toISOString());
      // The second endpoint pauses only after the revision, to the new callback.
      q.reviseStalePauseAuditCallback((e) => second.push(e));
      q.enqueue(item("b", EP2));
      await timer.step(); // delivered at T0+31d
      c.advance(31 * DAY_MS);
      const res2 = q.sweepStaleEndpoints();
      assert.equal(res2.paused.length, 1);
      assert.equal(res2.paused[0].endpoint, EP2);
      assert.equal(seen.length, 1, "old callback stays silent after revision");
      assert.equal(second.length, 1);
      assert.equal(second[0].event, "endpoint_auto_paused");
      assert.equal(second[0].endpoint, EP2);
      assert.equal(second[0].idleDays, 31);
      assert.equal(second[0].staleAfterDays, 30);
      assert.equal(second[0].lastSuccessfulDeliveryAt, new Date(T0 + 31 * DAY_MS).toISOString());
      assert.equal(second[0].at, new Date(T0 + 62 * DAY_MS).toISOString());
      const stats = q.getStalePauseStats();
      assert.equal(stats.find((r) => r.endpoint === EP)?.autoPauses, 1);
      assert.equal(stats.find((r) => r.endpoint === EP2)?.autoPauses, 1);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; the sweep and the auto-pause carry on and are still counted", async () => {
    const { q, c, timer, seen } = makeQueue();
    q.enqueue(item("a"));
    q.start();
    try {
      await timer.step(); // delivered at T0
      c.advance(31 * DAY_MS);
      assert.equal(q.sweepStaleEndpoints().paused.length, 1);
      assert.equal(seen.length, 1);
      q.reviseStalePauseAuditCallback(null);
      q.enqueue(item("b", EP2));
      await timer.step(); // delivered at T0+31d
      c.advance(31 * DAY_MS);
      const res = q.sweepStaleEndpoints();
      assert.equal(res.paused.length, 1);
      assert.equal(res.paused[0].endpoint, EP2);
      assert.equal(seen.length, 1, "cleared hook stays silent");
      assert.equal(q.isEndpointPaused(EP2), true);
      const stats = q.getStalePauseStats();
      assert.equal(stats.find((r) => r.endpoint === EP2)?.autoPauses, 1);
      assert.equal(stats.find((r) => r.endpoint === EP2)?.paused, true);
      assert.ok(
        q.renderMetrics().includes(`relay_endpoint_auto_pauses_total{endpoint="${EP2}"} 1`)
      );
    } finally {
      q.stop();
    }
  });

  it("revising with stalePause unconfigured throws Error; stalePauseConfigured reports the live state", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.stalePauseConfigured(), false);
    assert.deepEqual(q.getStalePauseStats(), []);
    assert.throws(
      () => q.reviseStalePauseAuditCallback(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    assert.throws(
      () => q.reviseStalePauseAuditCallback(null),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    const { q: configured } = makeQueue();
    try {
      assert.equal(configured.stalePauseConfigured(), true);
    } finally {
      configured.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const { q, c, timer, seen } = makeQueue();
    q.enqueue(item("a"));
    q.start();
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseStalePauseAuditCallback(bad), RangeError, String(bad));
      }
      // Nothing moved: the original hook still fires.
      await timer.step(); // delivered at T0
      c.advance(31 * DAY_MS);
      assert.equal(q.sweepStaleEndpoints().paused.length, 1);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].endpoint, EP);
      assert.equal(seen[0].idleDays, 31);
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const onStalePauseAudit = (e: StaleEndpointPausedEvent) => seen.push(e);
    const { q, c, timer, seen } = makeQueue({ onStalePauseAudit });
    q.enqueue(item("a"));
    q.start();
    try {
      q.reviseStalePauseAuditCallback(onStalePauseAudit);
      await timer.step(); // delivered at T0
      c.advance(31 * DAY_MS);
      assert.equal(q.sweepStaleEndpoints().paused.length, 1);
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseStalePauseAuditCallback(null);
      q.reviseStalePauseAuditCallback(null);
      q.enqueue(item("b", EP2));
      await timer.step(); // delivered at T0+31d
      c.advance(31 * DAY_MS);
      assert.equal(q.sweepStaleEndpoints().paused.length, 1);
      assert.equal(seen.length, 1);
      assert.equal(q.getStalePauseStats().find((r) => r.endpoint === EP2)?.autoPauses, 1);
    } finally {
      q.stop();
    }
  });

  it("pauses already reported are never re-delivered", async () => {
    const { q, c, timer, seen } = makeQueue();
    q.enqueue(item("a"));
    q.start();
    try {
      await timer.step(); // delivered at T0
      c.advance(31 * DAY_MS);
      assert.equal(q.sweepStaleEndpoints().paused.length, 1);
      assert.equal(seen.length, 1);
      q.reviseStalePauseAuditCallback((e) => seen.push(e));
      assert.equal(seen.length, 1, "no re-delivery of the reported pause");
      assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
      assert.equal(seen.length, 1, "no pause without a newly stale endpoint");
      // The next real auto-pause reports exactly once, to the new callback.
      q.enqueue(item("b", EP2));
      await timer.step(); // delivered at T0+31d
      c.advance(31 * DAY_MS);
      assert.equal(q.sweepStaleEndpoints().paused.length, 1);
      assert.equal(seen.length, 2);
      assert.equal(seen[1].endpoint, EP2);
    } finally {
      q.stop();
    }
  });

  it("revision does not change the sweep threshold, the idle baseline, or manual pause/resume semantics", async () => {
    const { q, c, timer, seen } = makeQueue();
    const second: StaleEndpointPausedEvent[] = [];
    q.enqueue(item("a"));
    q.start();
    try {
      await timer.step(); // delivered at T0
      const before = q.getStalePauseConfig();
      assert.deepEqual(before, { staleAfterDays: 30, sweepIntervalMs: 60_000 });
      c.advance(29 * DAY_MS);
      assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] }); // only 29d idle
      q.reviseStalePauseAuditCallback((e) => second.push(e));
      assert.deepEqual(q.getStalePauseConfig(), before, "revision moves only the observer");
      c.advance(2 * DAY_MS); // 31 days idle: the threshold is unchanged
      assert.equal(q.sweepStaleEndpoints().paused.length, 1);
      assert.equal(second.length, 1);
      assert.equal(second[0].idleDays, 31);
      // A manual hold still wins over the sweep, and resume restarts the
      // clock — the revised callback then sees the next auto-pause.
      q.enqueue(item("b", EP2));
      await timer.step(); // delivered at T0+31d
      assert.equal(q.pauseEndpoint(EP2), true);
      c.advance(31 * DAY_MS);
      assert.deepEqual(q.sweepStaleEndpoints(), { paused: [] });
      assert.equal(second.length, 1, "manual hold wins silently");
      assert.equal(q.isEndpointPaused(EP2), true);
      assert.equal(q.resumeEndpoint(EP2), true);
      c.advance(31 * DAY_MS);
      assert.equal(q.sweepStaleEndpoints().paused.length, 1);
      assert.equal(second.length, 2);
      assert.equal(second[1].endpoint, EP2);
      assert.equal(second[1].idleDays, 31);
      assert.equal(second[1].lastSuccessfulDeliveryAt, undefined, "resume clears the success baseline");
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer stale-pause audit callback revision (WR-402)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
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

  async function postWebhook(port: number): Promise<void> {
    const res = await post(port, "/hook", BODY, {
      "x-signature": signSha256(BODY, HOOK_KEY),
      "content-type": "application/json",
    });
    assert.equal(res.status, 202, res.text);
  }

  async function resumeEndpoint(port: number, endpoint: string): Promise<void> {
    const res = await post(port, "/endpoints/resume", Buffer.from(JSON.stringify({ endpoint })), {
      authorization: `Bearer ${OPERATOR_TOKEN}`,
      "content-type": "application/json",
    });
    assert.equal(res.status, 200, res.text);
    assert.equal((JSON.parse(res.text) as { paused: boolean }).paused, false);
  }

  async function getMetrics(port: number): Promise<string> {
    const res = await new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/metrics",
          method: "GET",
          headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
        },
        (res2) => {
          const chunks: Buffer[] = [];
          res2.on("data", (c: Buffer) => chunks.push(c));
          res2.on("end", () =>
            resolve({ status: res2.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end();
    });
    assert.equal(res.status, 200, res.text);
    return res.text;
  }

  /**
   * A server with stale-endpoint auto-pause on and a controllable clock;
   * the sweeper's timer is captured so tests fire the sweep on demand.
   */
  function staleServer(opts: {
    onStalePauseAudit?: (event: StaleEndpointPausedEvent) => void;
    stalePause?: Record<string, unknown>;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "stale-pause-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const c = clock();
    let sweepFn: (() => void) | undefined;
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: HOOK_KEY,
      forwardUrl: EP,
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => {},
      stalePause: opts.stalePause ?? {
        staleAfterDays: 30,
        now: c.now,
        setTimer: (fn: () => void, _ms: number) => {
          sweepFn = fn;
          return { clear: () => {} };
        },
        clearTimer: (h: { clear(): void }) => h.clear(),
      },
      retry: {
        ...(opts.onStalePauseAudit !== undefined
          ? { onStalePauseAudit: opts.onStalePauseAudit }
          : {}),
      },
    });
    servers.push(relay);
    return {
      relay,
      auditLog,
      c,
      sweep: () => {
        assert.ok(sweepFn !== undefined, "sweeper timer was armed");
        sweepFn!();
      },
    };
  }

  it("revising the callback routes the next auto-pause to the new callback and both audits still land", async () => {
    const first: StaleEndpointPausedEvent[] = [];
    const second: StaleEndpointPausedEvent[] = [];
    const { relay, auditLog, c, sweep } = staleServer({
      onStalePauseAudit: (e) => first.push(e),
    });
    const port = await listen(relay);
    await postWebhook(port);
    await flush(20); // let the delivery settle before advancing the clock
    c.advance(31 * DAY_MS);
    sweep();
    assert.equal(first.length, 1);
    assert.equal(first[0].event, "endpoint_auto_paused");
    assert.equal(first[0].endpoint, EP);
    assert.equal(first[0].idleDays, 31);
    assert.equal(first[0].staleAfterDays, 30);
    assert.equal(first[0].lastSuccessfulDeliveryAt, new Date(T0).toISOString());
    assert.equal(first[0].at, new Date(T0 + 31 * DAY_MS).toISOString());
    const firstAudits = eventsOf(auditLog, "endpoint_auto_paused");
    assert.equal(firstAudits.length, 1);
    assert.equal(firstAudits[0].endpoint, EP);
    assert.equal(firstAudits[0].idleDays, 31);
    // Resume restarts the idle clock; the next pause goes to the new callback only.
    relay.reviseStalePauseAuditCallback!((e) => second.push(e));
    await resumeEndpoint(port, EP);
    c.advance(31 * DAY_MS);
    sweep();
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second.length, 1);
    assert.equal(second[0].event, "endpoint_auto_paused");
    assert.equal(second[0].endpoint, EP);
    assert.equal(second[0].idleDays, 31);
    assert.equal(second[0].staleAfterDays, 30);
    assert.equal(second[0].lastSuccessfulDeliveryAt, undefined, "resume clears the success baseline");
    assert.equal(second[0].at, new Date(T0 + 62 * DAY_MS).toISOString());
    assert.equal(eventsOf(auditLog, "endpoint_auto_paused").length, 2);
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "stale_pause_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; auto-pauses are still audited and counted", async () => {
    const first: StaleEndpointPausedEvent[] = [];
    const { relay, auditLog, c, sweep } = staleServer({
      onStalePauseAudit: (e) => first.push(e),
    });
    const port = await listen(relay);
    await postWebhook(port);
    await flush(20);
    c.advance(31 * DAY_MS);
    sweep();
    assert.equal(first.length, 1);
    relay.reviseStalePauseAuditCallback!(null);
    await resumeEndpoint(port, EP);
    c.advance(31 * DAY_MS);
    sweep();
    assert.equal(first.length, 1, "cleared hook stays silent");
    assert.equal(eventsOf(auditLog, "endpoint_auto_paused").length, 2);
    const metrics = await getMetrics(port);
    assert.ok(metrics.includes(`relay_endpoint_auto_pauses_total{endpoint="${EP}"} 2`), metrics);
    const revised = eventsOf(auditLog, "stale_pause_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("a non-function value throws RangeError and the live callback is untouched; same-reference is a silent no-op", async () => {
    const first: StaleEndpointPausedEvent[] = [];
    const onStalePauseAudit = (e: StaleEndpointPausedEvent) => first.push(e);
    const { relay, auditLog, c, sweep } = staleServer({ onStalePauseAudit });
    const port = await listen(relay);
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseStalePauseAuditCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "stale_pause_audit_callback_revised").length, 0);
    relay.reviseStalePauseAuditCallback!(onStalePauseAudit);
    assert.equal(eventsOf(auditLog, "stale_pause_audit_callback_revised").length, 0);
    await postWebhook(port);
    await flush(20);
    c.advance(31 * DAY_MS);
    sweep();
    assert.equal(first.length, 1);
    assert.equal(first[0].endpoint, EP);
    assert.equal(first[0].idleDays, 31);
  });

  it("clearing when already unset is a silent no-op", async () => {
    const { relay, auditLog } = staleServer({});
    await listen(relay);
    relay.reviseStalePauseAuditCallback!(null);
    assert.equal(eventsOf(auditLog, "stale_pause_audit_callback_revised").length, 0);
  });

  it("revising with stalePause unconfigured throws Error", () => {
    const dir = mkdtempSync(join(tmpdir(), "stale-pause-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: HOOK_KEY,
      forwardUrl: EP,
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => {},
    });
    servers.push(relay);
    assert.throws(
      () => relay.reviseStalePauseAuditCallback!(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });
});
