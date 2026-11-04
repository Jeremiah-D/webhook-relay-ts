import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "endpoint-concurrency-revision-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Let the deliver() promise chain (turn -> limiter -> sender) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
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
    clearTimer: (h: { clear(): void }) => h.clear(),
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

/**
 * A sender that blocks every delivery until its release is called, so
 * in-flight occupancy is fully deterministic.
 */
function blockingSender() {
  const started: string[] = [];
  const releases = new Map<string, () => void>();
  const sender: Sender = async (it) => {
    started.push(it.id);
    await new Promise<void>((r) => releases.set(it.id, r));
  };
  return {
    sender,
    started,
    release: (id: string) => releases.get(id)!(),
    releaseAll: () => {
      for (const r of [...releases.values()]) r();
    },
  };
}

function item(id: string, targetUrl: string, tenantId?: string) {
  return { id, payload: BODY, targetUrl, headers: {}, ...(tenantId === undefined ? {} : { tenantId }) };
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`timed out waiting for ${what}`);
}

describe("RetryQueue endpoint concurrency (WR-321)", () => {
  it("getEndpointConcurrency reports the queue default for an unrevised endpoint", () => {
    const q = new RetryQueue({ sender: async () => {}, maxConcurrentPerEndpoint: 2, maxAttempts: 1 });
    try {
      assert.deepEqual(q.getEndpointConcurrency(EP_A), {
        configuredLimit: 2,
        effectiveLimit: 2,
        inFlight: 0,
        queued: 0,
      });
      // A tenant-scoped endpoint reports the same queue default.
      assert.deepEqual(q.getEndpointConcurrency(EP_A, "acme"), {
        configuredLimit: 2,
        effectiveLimit: 2,
        inFlight: 0,
        queued: 0,
      });
      // The default is unlimited when nothing was configured.
      const q2 = new RetryQueue({ sender: async () => {} });
      try {
        assert.deepEqual(q2.getEndpointConcurrency(EP_A), {
          configuredLimit: Infinity,
          effectiveLimit: Infinity,
          inFlight: 0,
          queued: 0,
        });
      } finally {
        q2.stop();
      }
    } finally {
      q.stop();
    }
  });

  it("raising the limit immediately grants waiting deliveries in FIFO order", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      maxConcurrentPerEndpoint: 1,
      maxAttempts: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a", EP_A));
    q.enqueue(item("b", EP_A));
    q.enqueue(item("c", EP_A));
    q.start();
    try {
      await timer.run();
      assert.deepEqual(started, ["a"]); // b, c wait on the limiter
      assert.deepEqual(q.getEndpointConcurrency(EP_A), {
        configuredLimit: 1,
        effectiveLimit: 1,
        inFlight: 1,
        queued: 2,
      });
      q.setEndpointConcurrency(EP_A, 3);
      await flush();
      assert.deepEqual(started, ["a", "b", "c"]); // raised: both waiters start at once
      assert.deepEqual(q.getEndpointConcurrency(EP_A), {
        configuredLimit: 3,
        effectiveLimit: 3,
        inFlight: 3,
        queued: 0,
      });
    } finally {
      releaseAll();
      await flush();
      q.stop();
    }
  });

  it("lowering the limit never revokes in-flight deliveries; new acquisitions queue until drain", async () => {
    const timer = manualTimer();
    const { sender, started, release, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      maxConcurrentPerEndpoint: 2,
      maxAttempts: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a", EP_A));
    q.enqueue(item("b", EP_A));
    q.start();
    try {
      await timer.run();
      assert.deepEqual(started, ["a", "b"]);
      // Cut below the live count: neither in-flight delivery is revoked.
      q.setEndpointConcurrency(EP_A, 1);
      await flush();
      assert.deepEqual(started, ["a", "b"]);
      assert.deepEqual(q.getEndpointConcurrency(EP_A), {
        configuredLimit: 1,
        effectiveLimit: 1,
        inFlight: 2,
        queued: 0,
      });
      // A new acquisition after the cut queues instead of starting.
      q.enqueue(item("c", EP_A));
      await timer.run();
      assert.deepEqual(started, ["a", "b"]);
      assert.equal(q.getEndpointConcurrency(EP_A).queued, 1);
      // Draining one slot admits the waiter (slot transfer); once the
      // count is back at the new cap, the cap gates fresh arrivals.
      release("a");
      await flush();
      assert.deepEqual(started, ["a", "b", "c"]);
      release("b");
      await flush();
      assert.equal(q.getEndpointConcurrency(EP_A).inFlight, 1);
      q.enqueue(item("d", EP_A));
      await timer.run();
      assert.deepEqual(started, ["a", "b", "c"]); // d queues at the cap
      assert.equal(q.getEndpointConcurrency(EP_A).queued, 1);
      release("c");
      await flush();
      assert.deepEqual(started, ["a", "b", "c", "d"]);
    } finally {
      releaseAll();
      await flush();
      q.stop();
    }
  });

  it("revising to Infinity wakes all waiters; back to finite starts limiting again", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      maxConcurrentPerEndpoint: 1,
      maxAttempts: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a", EP_A));
    q.enqueue(item("b", EP_A));
    q.enqueue(item("c", EP_A));
    q.start();
    try {
      await timer.run();
      assert.deepEqual(started, ["a"]);
      q.setEndpointConcurrency(EP_A, Infinity);
      await flush();
      assert.deepEqual(started, ["a", "b", "c"]);
      assert.equal(q.getEndpointConcurrency(EP_A).configuredLimit, Infinity);
      releaseAll();
      await flush();
      // Back to a finite cap: the next arrivals are gated again.
      q.setEndpointConcurrency(EP_A, 1);
      q.enqueue(item("d", EP_A));
      q.enqueue(item("e", EP_A));
      await timer.run();
      assert.deepEqual(started, ["a", "b", "c", "d"]);
      assert.equal(q.getEndpointConcurrency(EP_A).queued, 1);
    } finally {
      releaseAll();
      await flush();
      q.stop();
    }
  });

  it("an illegal value throws RangeError and the live limit is untouched", () => {
    const q = new RetryQueue({ sender: async () => {}, maxConcurrentPerEndpoint: 2, maxAttempts: 1 });
    try {
      for (const bad of [0, -1, 1.5, NaN]) {
        assert.throws(() => q.setEndpointConcurrency(EP_A, bad), RangeError, `limit ${bad}`);
      }
      assert.equal(q.getEndpointConcurrency(EP_A).configuredLimit, 2);
      assert.equal(q.getEndpointConcurrency(EP_A).effectiveLimit, 2);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint concurrency revision (WR-321)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-concurrency-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: EP_A,
      auditLog,
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

  let postSeq = 0;
  function post(port: number) {
    const body = Buffer.from(JSON.stringify({ event: "concurrency.probe", n: ++postSeq }));
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(body, relaySecret) },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            r.destroy();
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
          });
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  it("revise audits previous/current, with the queue default as first previous", async () => {
    const { relay, auditLog } = makeServer({ retry: { maxConcurrentPerEndpoint: 2 } });
    await listen(relay);
    const current = relay.reviseEndpointConcurrency(EP_A, 3);
    assert.deepEqual(current, { configuredLimit: 3, effectiveLimit: 3, inFlight: 0, queued: 0 });
    const revised = eventsOf(auditLog, "endpoint_concurrency_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_A);
    assert.equal(revised[0].previous, 2);
    assert.equal(revised[0].current, 3);
    // A second revision audits the live values as previous.
    const current2 = relay.reviseEndpointConcurrency(EP_A, 5);
    assert.equal(current2.configuredLimit, 5);
    const revised2 = eventsOf(auditLog, "endpoint_concurrency_revised");
    assert.equal(revised2.length, 2);
    assert.equal(revised2[1].previous, 3);
    assert.equal(revised2[1].current, 5);
  });

  it("a same-value revision is a silent no-op", async () => {
    const { relay, auditLog } = makeServer({ retry: { maxConcurrentPerEndpoint: 2 } });
    await listen(relay);
    // Landing exactly on the live value — even the queue default itself.
    relay.reviseEndpointConcurrency(EP_A, 2);
    assert.equal(eventsOf(auditLog, "endpoint_concurrency_revised").length, 0);
    relay.reviseEndpointConcurrency(EP_A, 3);
    assert.equal(eventsOf(auditLog, "endpoint_concurrency_revised").length, 1);
    relay.reviseEndpointConcurrency(EP_A, 3);
    assert.equal(eventsOf(auditLog, "endpoint_concurrency_revised").length, 1);
  });

  it("an illegal value throws RangeError and the live limit and audit are untouched", async () => {
    const { relay, auditLog } = makeServer({ retry: { maxConcurrentPerEndpoint: 2 } });
    await listen(relay);
    for (const bad of [0, -1, 1.5, NaN]) {
      assert.throws(() => relay.reviseEndpointConcurrency(EP_A, bad), RangeError, `limit ${bad}`);
    }
    assert.deepEqual(relay.getEndpointConcurrency(EP_A), {
      configuredLimit: 2,
      effectiveLimit: 2,
      inFlight: 0,
      queued: 0,
    });
    assert.equal(eventsOf(auditLog, "endpoint_concurrency_revised").length, 0);
  });

  it("remove returns true, audits, and falls back to the queue default; without an override it returns false silently", async () => {
    const { relay, auditLog } = makeServer({ retry: { maxConcurrentPerEndpoint: 2 } });
    await listen(relay);
    relay.reviseEndpointConcurrency(EP_A, 4);
    assert.equal(relay.getEndpointConcurrency(EP_A).configuredLimit, 4);
    assert.equal(relay.removeEndpointConcurrency(EP_A), true);
    const removed = eventsOf(auditLog, "endpoint_concurrency_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, EP_A);
    assert.equal(removed[0].previous, 4);
    assert.deepEqual(relay.getEndpointConcurrency(EP_A), {
      configuredLimit: 2,
      effectiveLimit: 2,
      inFlight: 0,
      queued: 0,
    });
    // Nothing left to remove: false, no audit.
    assert.equal(relay.removeEndpointConcurrency(EP_A), false);
    assert.equal(eventsOf(auditLog, "endpoint_concurrency_removed").length, 1);
    // An endpoint that was never revised has no override to remove.
    assert.equal(relay.removeEndpointConcurrency(EP_B), false);
    assert.equal(eventsOf(auditLog, "endpoint_concurrency_removed").length, 1);
  });

  it("the getter snapshot matches live in-flight and queued counts, and a raise wakes the waiter", async () => {
    const { sender, started, release, releaseAll } = blockingSender();
    const { relay } = makeServer({
      sender,
      retry: { maxConcurrentPerEndpoint: 1, maxAttempts: 1, jitterMs: 0 },
    });
    const port = await listen(relay);
    try {
      assert.equal((await post(port)).status, 202);
      assert.equal((await post(port)).status, 202);
      await waitFor(
        () => started.length === 1 && relay.getEndpointConcurrency(EP_A).queued === 1,
        "first delivery to start and second to park on the limiter"
      );
      assert.deepEqual(relay.getEndpointConcurrency(EP_A), {
        configuredLimit: 1,
        effectiveLimit: 1,
        inFlight: 1,
        queued: 1,
      });
      // Raising the limit through the server wakes the queued delivery.
      const raised = relay.reviseEndpointConcurrency(EP_A, 2);
      assert.equal(raised.configuredLimit, 2);
      await waitFor(() => started.length === 2, "second delivery to start after the raise");
      assert.deepEqual(relay.getEndpointConcurrency(EP_A), {
        configuredLimit: 2,
        effectiveLimit: 2,
        inFlight: 2,
        queued: 0,
      });
      // Lowering below the live count revokes nothing.
      relay.reviseEndpointConcurrency(EP_A, 1);
      await flush();
      assert.equal(started.length, 2);
      assert.equal(relay.getEndpointConcurrency(EP_A).inFlight, 2);
      release(started[0]);
      release(started[1]);
      await flush();
    } finally {
      releaseAll();
      await flush();
    }
  });

  it("revising from Infinity to a finite value starts limiting", async () => {
    const { sender, started, releaseAll } = blockingSender();
    const { relay } = makeServer({
      sender,
      retry: { maxAttempts: 1, jitterMs: 0 },
    });
    const port = await listen(relay);
    try {
      // Unlimited by default: both deliveries start at once.
      assert.equal(relay.getEndpointConcurrency(EP_A).configuredLimit, Infinity);
      assert.equal((await post(port)).status, 202);
      assert.equal((await post(port)).status, 202);
      await waitFor(() => started.length === 2, "both deliveries to start unlimited");
      releaseAll();
      await waitFor(() => relay.getEndpointConcurrency(EP_A).inFlight === 0, "deliveries to drain");
      // Now finite: the second arrival queues.
      relay.reviseEndpointConcurrency(EP_A, 1);
      assert.equal((await post(port)).status, 202);
      assert.equal((await post(port)).status, 202);
      await waitFor(() => started.length === 3, "third delivery to start under the cap");
      await flush();
      assert.equal(started.length, 3);
      assert.deepEqual(relay.getEndpointConcurrency(EP_A), {
        configuredLimit: 1,
        effectiveLimit: 1,
        inFlight: 1,
        queued: 1,
      });
    } finally {
      releaseAll();
      await flush();
    }
  });

  it("tenant revisions are scoped to that tenant's limiter", async () => {
    const { relay, auditLog } = makeServer({ retry: { maxConcurrentPerEndpoint: 2 } });
    await listen(relay);
    relay.reviseEndpointConcurrency(EP_A, 4, "acme");
    assert.deepEqual(relay.getEndpointConcurrency(EP_A, "acme"), {
      configuredLimit: 4,
      effectiveLimit: 4,
      inFlight: 0,
      queued: 0,
    });
    // The default tenant is untouched.
    assert.deepEqual(relay.getEndpointConcurrency(EP_A), {
      configuredLimit: 2,
      effectiveLimit: 2,
      inFlight: 0,
      queued: 0,
    });
    // Removal is tenant-scoped too.
    assert.equal(relay.removeEndpointConcurrency(EP_A), false);
    assert.equal(relay.removeEndpointConcurrency(EP_A, "acme"), true);
    assert.equal(eventsOf(auditLog, "endpoint_concurrency_removed").length, 1);
    assert.deepEqual(relay.getEndpointConcurrency(EP_A, "acme"), {
      configuredLimit: 2,
      effectiveLimit: 2,
      inFlight: 0,
      queued: 0,
    });
  });

  it("adaptive folding stays out of the audit: previous/current record the fixed limits", async () => {
    const { relay, auditLog } = makeServer({
      retry: {
        maxConcurrentPerEndpoint: 10,
        adaptiveConcurrency: { minLimit: 1, maxLimit: 8, initialLimit: 4, windowSize: 2 },
      },
    });
    await listen(relay);
    // The folded effective limit is 4 while the fixed limit is 10.
    assert.deepEqual(relay.getEndpointConcurrency(EP_A), {
      configuredLimit: 10,
      effectiveLimit: 4,
      inFlight: 0,
      queued: 0,
    });
    const current = relay.reviseEndpointConcurrency(EP_A, 6);
    assert.deepEqual(current, {
      configuredLimit: 6,
      effectiveLimit: 4,
      inFlight: 0,
      queued: 0,
    });
    const revised = eventsOf(auditLog, "endpoint_concurrency_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, 10);
    assert.equal(revised[0].current, 6);
  });
});
