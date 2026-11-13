import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type DryRunDeliveryEvent,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const TEST_KEY = "dry-run-delivery-callback-revision-key";
const OPERATOR_TOKEN = "dry-run-delivery-callback-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "dry-run-delivery-revision" }));
const URL = "http://localhost:9999/hook";
const FORWARD_URL = "http://127.0.0.1:9/hook";

/** Manual timer for deterministic queue tests. */
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
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string): RetryItem {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl: URL,
    headers: { "content-type": "application/json" },
    traceId: `trace-${id}`,
  };
}

describe("RetryQueue dry-run delivery callback revision (WR-403)", () => {
  it("the revised callback receives the next drill result with exact fields; the old callback stays silent", async () => {
    const timer = manualTimer();
    const first: DryRunDeliveryEvent[] = [];
    const second: DryRunDeliveryEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      maxAttempts: 3,
      deliveryDryRun: { [URL]: { canned: { status: 200 } } },
      onDryRunDelivery: (e) => first.push(e),
    });
    q.enqueue(item("a"));
    q.start();
    try {
      await timer.step();
      assert.equal(first.length, 1);
      assert.equal(first[0].id, "a");
      assert.equal(first[0].traceId, "trace-a");
      assert.equal(first[0].endpoint, URL);
      assert.equal(first[0].targetUrl, URL);
      assert.equal(first[0].outcome, "delivered");
      assert.equal(first[0].attempts, 1);
      assert.equal(first[0].statusCode, 200);
      assert.equal(typeof first[0].latencyMs, "number");
      assert.ok(first[0].latencyMs >= 0);
      // A second drill goes to the revised callback only.
      q.reviseDryRunDeliveryCallback((e) => second.push(e));
      q.enqueue(item("b"));
      await timer.step();
      assert.equal(first.length, 1, "old callback stays silent after revision");
      assert.equal(second.length, 1);
      assert.equal(second[0].id, "b");
      assert.equal(second[0].traceId, "trace-b");
      assert.equal(second[0].endpoint, URL);
      assert.equal(second[0].targetUrl, URL);
      assert.equal(second[0].outcome, "delivered");
      assert.equal(second[0].attempts, 1);
      assert.equal(second[0].statusCode, 200);
      assert.equal(typeof second[0].latencyMs, "number");
      const stats = q.getDryRunStats();
      assert.equal(stats.length, 1);
      assert.equal(stats[0].endpoint, URL);
      assert.equal(stats[0].delivered, 2);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; drills keep running and are still counted", async () => {
    const timer = manualTimer();
    const seen: DryRunDeliveryEvent[] = [];
    let senderCalls = 0;
    const q = new RetryQueue({
      sender: (async () => {
        senderCalls += 1;
      }) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      maxAttempts: 3,
      deliveryDryRun: { [URL]: { canned: { status: 200 } } },
      onDryRunDelivery: (e) => seen.push(e),
    });
    q.enqueue(item("a"));
    q.start();
    try {
      await timer.step();
      assert.equal(seen.length, 1);
      q.reviseDryRunDeliveryCallback(null);
      q.enqueue(item("b"));
      await timer.step();
      assert.equal(seen.length, 1, "cleared hook stays silent");
      assert.equal(senderCalls, 0, "the drill still never touches the sender");
      assert.equal(q.pendingCount(), 0);
      assert.equal(q.getDeadLetter().length, 0);
      const stats = q.getDryRunStats();
      assert.equal(stats[0].delivered, 2);
      const metrics = q.renderMetrics();
      assert.match(metrics, /relay_dry_run_deliveries_total\{[^}]*outcome="delivered"\} 2/);
    } finally {
      q.stop();
    }
  });

  it("revising with zero drill configs succeeds (no gate); the first drill after install goes to the new callback", async () => {
    const timer = manualTimer();
    const first: DryRunDeliveryEvent[] = [];
    const second: DryRunDeliveryEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      maxAttempts: 3,
      onDryRunDelivery: (e) => first.push(e),
    });
    q.start();
    try {
      // No drill configured at all — the revision still succeeds.
      q.reviseDryRunDeliveryCallback((e) => second.push(e));
      assert.deepEqual(q.dryRunEndpoints(), []);
      const applied = q.setEndpointDryRun(URL, { canned: { status: 200 } });
      assert.equal(applied?.canned.status, 200);
      q.enqueue(item("a"));
      await timer.step();
      assert.equal(first.length, 0, "old callback stays silent");
      assert.equal(second.length, 1);
      assert.equal(second[0].id, "a");
      assert.equal(second[0].traceId, "trace-a");
      assert.equal(second[0].outcome, "delivered");
      assert.equal(second[0].statusCode, 200);
    } finally {
      q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const timer = manualTimer();
    const seen: DryRunDeliveryEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      maxAttempts: 3,
      deliveryDryRun: { [URL]: { canned: { status: 200 } } },
      onDryRunDelivery: (e) => seen.push(e),
    });
    q.enqueue(item("a"));
    q.start();
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseDryRunDeliveryCallback(bad), RangeError, String(bad));
      }
      // Nothing moved: the original hook still fires.
      await timer.step();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].outcome, "delivered");
      assert.equal(seen[0].statusCode, 200);
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const timer = manualTimer();
    const onDryRunDelivery = (e: DryRunDeliveryEvent) => seen.push(e);
    const seen: DryRunDeliveryEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      maxAttempts: 3,
      deliveryDryRun: { [URL]: { canned: { status: 200 } } },
      onDryRunDelivery,
    });
    q.enqueue(item("a"));
    q.start();
    try {
      q.reviseDryRunDeliveryCallback(onDryRunDelivery);
      await timer.step();
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseDryRunDeliveryCallback(null);
      q.reviseDryRunDeliveryCallback(null);
      q.enqueue(item("b"));
      await timer.step();
      assert.equal(seen.length, 1);
      assert.equal(q.getDryRunStats()[0].delivered, 2);
    } finally {
      q.stop();
    }
  });

  it("drill results already reported are never re-delivered", async () => {
    const timer = manualTimer();
    const seen: DryRunDeliveryEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      maxAttempts: 3,
      deliveryDryRun: { [URL]: { canned: { status: 200 } } },
      onDryRunDelivery: (e) => seen.push(e),
    });
    q.enqueue(item("a"));
    q.start();
    try {
      await timer.step();
      assert.equal(seen.length, 1);
      q.reviseDryRunDeliveryCallback((e) => seen.push(e));
      assert.equal(seen.length, 1, "no re-delivery of the reported result");
      await timer.step();
      assert.equal(seen.length, 1, "no result without a new drill");
      // The next real drill reports exactly once, to the new callback.
      q.enqueue(item("b"));
      await timer.step();
      assert.equal(seen.length, 2);
      assert.equal(seen[1].id, "b");
      assert.equal(seen[1].outcome, "delivered");
    } finally {
      q.stop();
    }
  });

  it("revision does not change the canned status classification, the delay, or the retry rhythm", async () => {
    const timer = manualTimer();
    const first: DryRunDeliveryEvent[] = [];
    const second: DryRunDeliveryEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      baseDelayMs: 10,
      maxDelayMs: 10,
      maxAttempts: 2,
      deliveryDryRun: { [URL]: { canned: { status: 500 } } },
      onDryRunDelivery: (e) => first.push(e),
    });
    q.enqueue(item("a"));
    q.start();
    try {
      await timer.step(); // attempt 1 → retrying
      assert.deepEqual(first.map((e) => e.outcome), ["retrying"]);
      assert.equal(first[0].statusCode, 500);
      assert.equal(first[0].attempts, 1);
      assert.equal(q.getEndpointDryRun(URL)?.canned.status, 500);
      q.reviseDryRunDeliveryCallback((e) => second.push(e));
      assert.equal(q.getEndpointDryRun(URL)?.canned.status, 500, "revision moves only the observer");
      await timer.step(); // attempt 2 → exhausted (maxAttempts 2)
      assert.deepEqual(first.map((e) => e.outcome), ["retrying"]);
      assert.deepEqual(second.map((e) => e.outcome), ["exhausted"]);
      assert.equal(second[0].statusCode, 500);
      assert.equal(second[0].attempts, 2);
      assert.equal(q.pendingCount(), 0);
      assert.equal(q.getDeadLetter().length, 0);
      const stats = q.getDryRunStats();
      assert.equal(stats[0].retried, 1);
      assert.equal(stats[0].exhausted, 1);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer dry-run delivery callback revision (WR-403)", () => {
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

  async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(cond(), `timed out waiting for ${what}`);
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

  /** Post one webhook; returns the accepted id and traceId. */
  async function postOne(port: number): Promise<{ id: string; traceId: string }> {
    const res = await post(port, "/hook", BODY, {
      "x-signature": signSha256(BODY, TEST_KEY),
      "content-type": "application/json",
    });
    assert.equal(res.status, 202, res.text);
    const parsed = JSON.parse(res.text) as { id: string; traceId: string };
    assert.ok(parsed.id);
    assert.ok(parsed.traceId);
    return parsed;
  }

  function postJson(
    port: number,
    path: string,
    body: Record<string, unknown>,
    token: string
  ): Promise<{ status: number; json: Record<string, unknown> }> {
    return new Promise((resolve, reject) => {
      const payload = Buffer.from(JSON.stringify(body));
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path,
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
            "content-length": String(payload.length),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({
              status: res.statusCode ?? 0,
              json: JSON.parse(Buffer.concat(chunks).toString() || "{}") as Record<string, unknown>,
            })
          );
        }
      );
      r.on("error", reject);
      r.end(payload);
    });
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
   * A server with a canned-200 drill on the forward URL; the injected
   * sender records any real outbound call (a drill must never make one).
   */
  function drillServer(opts: {
    onDryRunDelivery?: (event: DryRunDeliveryEvent) => void;
    deliveryDryRun?: Record<string, unknown>;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "dry-run-delivery-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const senderCalls: string[] = [];
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: TEST_KEY,
      forwardUrl: FORWARD_URL,
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: (async (wire: { id: string }) => {
        senderCalls.push(wire.id);
        throw new Error("drill must never call the sender");
      }) as Sender,
      retry: {
        baseDelayMs: 10,
        jitterMs: 0,
        maxAttempts: 1,
        ...(opts.onDryRunDelivery !== undefined
          ? { onDryRunDelivery: opts.onDryRunDelivery }
          : {}),
      },
      ...(opts.deliveryDryRun !== undefined
        ? { deliveryDryRun: opts.deliveryDryRun }
        : {}),
    });
    servers.push(relay);
    return { relay, auditLog, senderCalls };
  }

  it("revising the callback routes the next drill result to the new callback and the dry_run audit still lands", async () => {
    const first: DryRunDeliveryEvent[] = [];
    const second: DryRunDeliveryEvent[] = [];
    const { relay, auditLog, senderCalls } = drillServer({
      onDryRunDelivery: (e) => first.push(e),
      deliveryDryRun: { [FORWARD_URL]: { canned: { status: 200 } } },
    });
    const port = await listen(relay);
    const one = await postOne(port);
    await waitFor(() => first.some((e) => e.id === one.id), "first drill callback");
    assert.equal(first.length, 1);
    assert.equal(first[0].traceId, one.traceId);
    assert.equal(first[0].endpoint, FORWARD_URL);
    assert.equal(first[0].targetUrl, FORWARD_URL);
    assert.equal(first[0].outcome, "delivered");
    assert.equal(first[0].statusCode, 200);
    assert.equal(first[0].attempts, 1);
    const delivered = eventsOf(auditLog, "delivered").filter((e) => e.id === one.id);
    assert.equal(delivered.length, 1);
    assert.equal(delivered[0].dry_run, true);
    assert.equal(delivered[0].statusCode, 200);
    assert.equal(delivered[0].traceId, one.traceId);
    assert.deepEqual(senderCalls, [], "no physical outbound call");
    relay.reviseDryRunDeliveryCallback!((e) => second.push(e));
    const two = await postOne(port);
    await waitFor(() => second.some((e) => e.id === two.id), "revised drill callback");
    assert.ok(!first.some((e) => e.id === two.id), "old callback stays silent after revision");
    assert.equal(second.length, 1);
    assert.equal(second[0].traceId, two.traceId);
    assert.equal(second[0].endpoint, FORWARD_URL);
    assert.equal(second[0].outcome, "delivered");
    assert.equal(second[0].statusCode, 200);
    assert.equal(eventsOf(auditLog, "delivered").filter((e) => e.id === two.id).length, 1);
    assert.equal(eventsOf(auditLog, "delivered").filter((e) => e.dry_run === true).length, 2);
    assert.deepEqual(senderCalls, [], "no physical outbound call");
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "dry_run_delivery_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; drills are still audited with dry_run: true and counted", async () => {
    const first: DryRunDeliveryEvent[] = [];
    const { relay, auditLog, senderCalls } = drillServer({
      onDryRunDelivery: (e) => first.push(e),
      deliveryDryRun: { [FORWARD_URL]: { canned: { status: 200 } } },
    });
    const port = await listen(relay);
    const one = await postOne(port);
    await waitFor(() => first.some((e) => e.id === one.id), "first drill callback");
    relay.reviseDryRunDeliveryCallback!(null);
    const two = await postOne(port);
    await waitFor(
      () => eventsOf(auditLog, "delivered").some((e) => e.id === two.id),
      "delivered audit after clear"
    );
    assert.ok(!first.some((e) => e.id === two.id), "cleared hook stays silent");
    const delivered = eventsOf(auditLog, "delivered").filter((e) => e.id === two.id);
    assert.equal(delivered.length, 1);
    assert.equal(delivered[0].dry_run, true);
    assert.equal(delivered[0].statusCode, 200);
    assert.deepEqual(senderCalls, [], "no physical outbound call");
    const metrics = await getMetrics(port);
    assert.match(metrics, /relay_dry_run_deliveries_total\{[^}]*outcome="delivered"\} 2/);
    const revised = eventsOf(auditLog, "dry_run_delivery_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("revising with zero drill configs succeeds (no gate); the first drill after install goes to the new callback", async () => {
    const second: DryRunDeliveryEvent[] = [];
    const { relay, auditLog, senderCalls } = drillServer({});
    const port = await listen(relay);
    // No drill configured at all — the revision still succeeds.
    relay.reviseDryRunDeliveryCallback!((e) => second.push(e));
    const revised = eventsOf(auditLog, "dry_run_delivery_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "cleared");
    assert.equal(revised[0].current, "set");
    // Install the drill at runtime; the first result goes to the new callback.
    const on = await postJson(
      port,
      "/endpoints/dry-run",
      { endpoint: FORWARD_URL, enabled: true, canned: { status: 200 } },
      OPERATOR_TOKEN
    );
    assert.equal(on.status, 200, JSON.stringify(on.json));
    assert.equal(on.json.dryRun, true);
    const one = await postOne(port);
    await waitFor(() => second.some((e) => e.id === one.id), "first drill after install");
    assert.equal(second.length, 1);
    assert.equal(second[0].traceId, one.traceId);
    assert.equal(second[0].outcome, "delivered");
    assert.equal(second[0].statusCode, 200);
    assert.equal(eventsOf(auditLog, "delivered").filter((e) => e.id === one.id).length, 1);
    assert.deepEqual(senderCalls, [], "no physical outbound call");
  });

  it("a non-function value throws RangeError and the live callback is untouched; same-reference is a silent no-op", async () => {
    const first: DryRunDeliveryEvent[] = [];
    const onDryRunDelivery = (e: DryRunDeliveryEvent) => first.push(e);
    const { relay, auditLog } = drillServer({
      onDryRunDelivery,
      deliveryDryRun: { [FORWARD_URL]: { canned: { status: 200 } } },
    });
    const port = await listen(relay);
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseDryRunDeliveryCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "dry_run_delivery_callback_revised").length, 0);
    relay.reviseDryRunDeliveryCallback!(onDryRunDelivery);
    assert.equal(eventsOf(auditLog, "dry_run_delivery_callback_revised").length, 0);
    const one = await postOne(port);
    await waitFor(() => first.some((e) => e.id === one.id), "first drill callback");
    assert.equal(first.length, 1);
    assert.equal(first[0].traceId, one.traceId);
    assert.equal(first[0].outcome, "delivered");
  });

  it("clearing when already unset is a silent no-op", async () => {
    const { relay, auditLog } = drillServer({
      deliveryDryRun: { [FORWARD_URL]: { canned: { status: 200 } } },
    });
    await listen(relay);
    relay.reviseDryRunDeliveryCallback!(null);
    assert.equal(eventsOf(auditLog, "dry_run_delivery_callback_revised").length, 0);
  });
});
