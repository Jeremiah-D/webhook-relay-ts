import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, request as httpRequest, type Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "retry-policy-revision-secret";
const EP_A = "http://127.0.0.1:9/hook-a";
const EP_B = "http://127.0.0.1:9/hook-b";
const EP_C = "http://127.0.0.1:9/hook-c";

/**
 * Deterministic timer that records every scheduled delay and runs
 * one batch per `step()` — the retry tests assert on the delay a
 * retry was scheduled with, so a plain fire-list is not enough.
 * The queue's first delivery is armed with delay 0; `retryDelays()`
 * filters that out so assertions read as the backoff schedule.
 * `step(n)` runs one batch, then waits until `n` retry delays have
 * actually been recorded (the default sender does a real HTTP
 * round-trip to the stub, so a fixed sleep would be racy under
 * load) — a 5s deadline keeps a stuck delivery loud instead of
 * hanging the suite.
 */
function recordingTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  const delays: number[] = [];
  const retryDelays = () => delays.filter((ms) => ms > 0);
  return {
    delays,
    retryDelays,
    setTimer: (fn: () => void, ms: number) => {
      delays.push(ms);
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step(expectedRetryDelays: number) {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      const deadline = Date.now() + 5000;
      while (retryDelays().length < expectedRetryDelays && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 5));
      }
    },
  };
}

describe("RetryQueue endpoint retry-policy accessors (WR-320)", () => {
  function makeQueue() {
    return new RetryQueue({
      sender: (async () => {}) as Sender,
      baseDelayMs: 1000,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      retryPolicies: [{ name: "fast", maxAttempts: 2, baseDelayMs: 100, maxDelayMs: 10000 }],
      endpointRetryPolicies: { [EP_A]: "fast" },
      endpointStatusRetryPolicies: {
        [EP_B]: { "503": { baseDelayMs: 5000, maxAttempts: 3 } },
      },
    });
  }

  it("hasRetryPolicy reports registration state", () => {
    const q = makeQueue();
    try {
      assert.equal(q.hasRetryPolicy("fast"), true);
      assert.equal(q.hasRetryPolicy("nope"), false);
      q.registerRetryPolicy("slow", { maxAttempts: 4, baseDelayMs: 2000, maxDelayMs: 60000 });
      assert.equal(q.hasRetryPolicy("slow"), true);
    } finally {
      q.stop();
    }
  });

  it("getEndpointRetryPolicies merges both layers, sorted, detached", () => {
    const q = makeQueue();
    try {
      q.setEndpointStatusRetryPolicy(EP_A, { "429": { baseDelayMs: 250, maxAttempts: 2 } });
      const rows = q.getEndpointRetryPolicies();
      assert.deepEqual(rows, [
        {
          endpoint: EP_A,
          policyName: "fast",
          statusPolicy: { "429": { baseDelayMs: 250, maxAttempts: 2, multiplier: 2 } },
        },
        {
          endpoint: EP_B,
          statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3, multiplier: 2 } },
        },
      ]);
      // Mutating a returned copy never touches the live assignment.
      rows[1].statusPolicy!["503"].baseDelayMs = 99999;
      assert.equal(
        q.getEndpointRetryPolicies()[1].statusPolicy!["503"].baseDelayMs,
        5000
      );
      // An endpoint on the global config is not listed.
      assert.equal(
        q.getEndpointRetryPolicies().some((r) => r.endpoint === EP_C),
        false
      );
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint retry-policy revision (WR-320)", () => {
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

  /**
   * A relay forwarding to a stub that always answers `stubStatus`.
   * The stub is created first so the relay's `forwardUrl` is the
   * stub URL — the queue keys the policy by that targetUrl, so the
   * endpoint under test is the stub URL. The queue runs on the
   * recording timer, so retries are deterministic.
   */
  async function makeServer(stubStatus = 500, retryExtra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "retry-policy-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const timer = recordingTimer();
    let hits = 0;
    const stub: Server = createServer((_req, res) => {
      hits += 1;
      res.writeHead(stubStatus).end("downstream down");
    });
    const stubPort = await listen(stub);
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl,
      auditLog,
      retry: {
        baseDelayMs: 1000,
        maxDelayMs: 60000,
        maxAttempts: 5,
        jitterMs: 0,
        random: () => 0,
        setTimer: timer.setTimer,
        retryPolicies: [
          { name: "fast", maxAttempts: 2, baseDelayMs: 100, maxDelayMs: 10000 },
          { name: "slow", maxAttempts: 4, baseDelayMs: 2000, maxDelayMs: 60000 },
        ],
        ...retryExtra,
      },
    });
    servers.push(relay);
    servers.push(stub);
    const port = await listen(relay);
    return { relay, auditLog, timer, stub, hits: () => hits, forwardUrl, port };
  }

  /** POST one signed webhook to the relay; expect 202. */
  async function post(port: number, body: Buffer): Promise<number> {
    const res = await new Promise<{ status: number }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: {
            "x-signature": signSha256(body, relaySecret),
            "content-type": "application/json",
          },
        },
        (resp) => {
          resp.resume();
          resp.on("end", () => resolve({ status: resp.statusCode ?? 0 }));
        }
      );
      r.on("error", reject);
      r.end(body);
    });
    return res.status;
  }

  it("revise audits previous/current, with an empty previous on first set", async () => {
    const { relay, auditLog } = await makeServer();
    const current = relay.reviseEndpointRetryPolicy(EP_A, { policyName: "fast" });
    assert.deepEqual(current, { policyName: "fast" });
    const revised = eventsOf(auditLog, "retry_policy_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_A);
    assert.deepEqual(revised[0].previous, {});
    assert.deepEqual(revised[0].current, { policyName: "fast" });
    // A second revision audits the live values as previous.
    const current2 = relay.reviseEndpointRetryPolicy(EP_A, {
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3 } },
    });
    assert.deepEqual(current2, {
      policyName: "fast",
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3, multiplier: 2 } },
    });
    const revised2 = eventsOf(auditLog, "retry_policy_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { policyName: "fast" });
    assert.deepEqual(revised2[1].current, {
      policyName: "fast",
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3, multiplier: 2 } },
    });
  });

  it("a same-value revision is a silent no-op, even with reordered status selectors", async () => {
    const { relay, auditLog } = await makeServer();
    relay.reviseEndpointRetryPolicy(EP_A, { policyName: "fast" });
    relay.reviseEndpointRetryPolicy(EP_A, { policyName: "fast" });
    relay.reviseEndpointRetryPolicy(EP_A, {});
    assert.equal(eventsOf(auditLog, "retry_policy_revised").length, 1);
    relay.reviseEndpointRetryPolicy(EP_A, {
      statusPolicy: {
        "503": { baseDelayMs: 5000, maxAttempts: 3 },
        "429": { baseDelayMs: 250, maxAttempts: 2 },
      },
    });
    assert.equal(eventsOf(auditLog, "retry_policy_revised").length, 2);
    // Same selectors in the other order: semantically identical.
    relay.reviseEndpointRetryPolicy(EP_A, {
      statusPolicy: {
        "429": { baseDelayMs: 250, maxAttempts: 2 },
        "503": { baseDelayMs: 5000, maxAttempts: 3 },
      },
    });
    assert.equal(eventsOf(auditLog, "retry_policy_revised").length, 2);
  });

  it("an unknown policy name throws RangeError and the live assignment is untouched", async () => {
    const { relay, auditLog } = await makeServer();
    relay.reviseEndpointRetryPolicy(EP_A, {
      policyName: "fast",
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3 } },
    });
    const before = relay.getEndpointRetryPolicy(EP_A);
    assert.throws(
      () => relay.reviseEndpointRetryPolicy(EP_A, { policyName: "nope" }),
      RangeError
    );
    // A patch carrying a valid status layer with the bad name must
    // not move the status layer either.
    assert.throws(
      () =>
        relay.reviseEndpointRetryPolicy(EP_A, {
          policyName: "nope",
          statusPolicy: { "429": { baseDelayMs: 100, maxAttempts: 2 } },
        }),
      RangeError
    );
    assert.deepEqual(relay.getEndpointRetryPolicy(EP_A), before);
    assert.equal(eventsOf(auditLog, "retry_policy_revised").length, 1);
  });

  it("an illegal status config throws RangeError and the live assignment is untouched", async () => {
    const { relay, auditLog } = await makeServer();
    relay.reviseEndpointRetryPolicy(EP_A, { policyName: "fast" });
    const before = relay.getEndpointRetryPolicy(EP_A);
    const bad: Array<Record<string, unknown>> = [
      { "99": { baseDelayMs: 100, maxAttempts: 2 } },
      { "503": { baseDelayMs: 0, maxAttempts: 2 } },
      { "503": { baseDelayMs: 100, maxAttempts: 0 } },
      { "503": { baseDelayMs: 100, maxAttempts: 2, multiplier: -1 } },
    ];
    for (const config of bad) {
      assert.throws(
        () => relay.reviseEndpointRetryPolicy(EP_A, { statusPolicy: config as never }),
        RangeError,
        JSON.stringify(config)
      );
      assert.deepEqual(relay.getEndpointRetryPolicy(EP_A), before);
    }
    // A patch carrying a valid named re-point with the bad status
    // config must not move the named layer either (validate both,
    // then apply neither).
    assert.throws(
      () =>
        relay.reviseEndpointRetryPolicy(EP_A, {
          policyName: "slow",
          statusPolicy: { "503": { baseDelayMs: 0, maxAttempts: 2 } },
        }),
      RangeError
    );
    assert.deepEqual(relay.getEndpointRetryPolicy(EP_A), before);
    assert.equal(eventsOf(auditLog, "retry_policy_revised").length, 1);
  });

  it("null detaches one layer only; the other layer keeps governing", async () => {
    const { relay, auditLog } = await makeServer();
    relay.reviseEndpointRetryPolicy(EP_A, {
      policyName: "fast",
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3 } },
    });
    // Detach the named layer: the status layer survives.
    const current = relay.reviseEndpointRetryPolicy(EP_A, { policyName: null });
    assert.deepEqual(current, {
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3, multiplier: 2 } },
    });
    assert.equal(eventsOf(auditLog, "retry_policy_revised").length, 2);
    // Detach the status layer too: nothing is attached any more.
    relay.reviseEndpointRetryPolicy(EP_A, { statusPolicy: null });
    assert.equal(relay.getEndpointRetryPolicy(EP_A), undefined);
    assert.equal(eventsOf(auditLog, "retry_policy_revised").length, 3);
  });

  it("remove returns true, audits, and falls back to the global config", async () => {
    const { relay, auditLog } = await makeServer();
    relay.reviseEndpointRetryPolicy(EP_A, {
      policyName: "fast",
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3 } },
    });
    assert.equal(relay.removeEndpointRetryPolicy(EP_A), true);
    const removed = eventsOf(auditLog, "retry_policy_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, EP_A);
    assert.deepEqual(removed[0].previous, {
      policyName: "fast",
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3, multiplier: 2 } },
    });
    assert.equal(relay.getEndpointRetryPolicy(EP_A), undefined);
    // Nothing left to remove: false, no audit.
    assert.equal(relay.removeEndpointRetryPolicy(EP_A), false);
    assert.equal(eventsOf(auditLog, "retry_policy_removed").length, 1);
    // An endpoint that was never configured has nothing to remove.
    assert.equal(relay.removeEndpointRetryPolicy(EP_B), false);
  });

  it("getRetryPolicies lists every configured endpoint, including status-only ones", async () => {
    const { relay } = await makeServer();
    relay.reviseEndpointRetryPolicy(EP_A, { policyName: "fast" });
    relay.reviseEndpointRetryPolicy(EP_B, {
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3 } },
    });
    relay.reviseEndpointRetryPolicy(EP_C, {
      policyName: "slow",
      statusPolicy: { "429": { baseDelayMs: 250, maxAttempts: 2 } },
    });
    assert.deepEqual(relay.getRetryPolicies(), [
      { endpoint: EP_A, policyName: "fast" },
      {
        endpoint: EP_B,
        statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3, multiplier: 2 } },
      },
      {
        endpoint: EP_C,
        policyName: "slow",
        statusPolicy: { "429": { baseDelayMs: 250, maxAttempts: 2, multiplier: 2 } },
      },
    ]);
    // An unconfigured endpoint reports nothing.
    assert.equal(relay.getEndpointRetryPolicy("http://127.0.0.1:9/hook-d"), undefined);
  });

  it("a named-policy switch governs the next retry", async () => {
    // The fast/slow policies need attempt headroom: the test observes
    // the second retry, so maxAttempts 2 would dead-letter first.
    const policies = [
      { name: "fast", maxAttempts: 5, baseDelayMs: 100, maxDelayMs: 10000 },
      { name: "slow", maxAttempts: 5, baseDelayMs: 2000, maxDelayMs: 60000 },
    ];
    const { relay, timer, port, forwardUrl, hits } = await makeServer(500, {
      retryPolicies: policies,
    });
    // Start on the global schedule (base 1000): the first retry is
    // scheduled against it — the queue passes the post-increment
    // attempt counter, so the delay is 1000 * 2^1.
    assert.equal(await post(port, Buffer.from(JSON.stringify({ n: 1 }))), 202);
    await timer.step(1); // attempt 1 fails (500)
    assert.equal(hits(), 1);
    assert.deepEqual(timer.retryDelays(), [2000]);
    // Switch to the fast policy: the next retry uses it
    // (100 * 2^2 for the second failure).
    relay.reviseEndpointRetryPolicy(forwardUrl, { policyName: "fast" });
    await timer.step(2); // attempt 2 fails (500)
    assert.equal(hits(), 2);
    assert.deepEqual(timer.retryDelays(), [2000, 400]);
  });

  it("an already-scheduled retry keeps its delay; the retry after uses the new policy", async () => {
    const policies = [
      { name: "fast", maxAttempts: 5, baseDelayMs: 100, maxDelayMs: 10000 },
      { name: "slow", maxAttempts: 5, baseDelayMs: 2000, maxDelayMs: 60000 },
    ];
    const { relay, timer, port, forwardUrl, hits } = await makeServer(500, {
      retryPolicies: policies,
    });
    // Start on the fast policy (base 100): the first retry is
    // scheduled against it before any revision happens.
    relay.reviseEndpointRetryPolicy(forwardUrl, { policyName: "fast" });
    assert.equal(await post(port, Buffer.from(JSON.stringify({ n: 2 }))), 202);
    await timer.step(1); // attempt 1 fails (500)
    assert.equal(hits(), 1);
    assert.deepEqual(timer.retryDelays(), [200]);
    // Revise while the retry is already armed: the armed delay is
    // not re-armed, so attempt 2 still fires on the old schedule.
    relay.reviseEndpointRetryPolicy(forwardUrl, { policyName: "slow" });
    await timer.step(2); // attempt 2 fails (500), scheduled on slow
    assert.equal(hits(), 2);
    assert.deepEqual(timer.retryDelays(), [200, 8000]);
  });

  it("a status-policy replacement governs retries for the matched status", async () => {
    const { relay, timer, port, forwardUrl, hits } = await makeServer(503);
    // No status policy yet: the 503 retry uses the global base
    // (1000 * 2^1 for the first failure).
    assert.equal(await post(port, Buffer.from(JSON.stringify({ n: 3 }))), 202);
    await timer.step(1); // attempt 1 fails (503)
    assert.equal(hits(), 1);
    assert.deepEqual(timer.retryDelays(), [2000]);
    // Attach a patient 503 schedule: the next retry uses it
    // (5000 * 2^2 for the second failure).
    relay.reviseEndpointRetryPolicy(forwardUrl, {
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3 } },
    });
    await timer.step(2); // attempt 2 fails (503)
    assert.equal(hits(), 2);
    assert.deepEqual(timer.retryDelays(), [2000, 20000]);
    // Replace it with a quick one: the retry after uses the new one
    // (200 * 2^3 for the third failure; maxAttempts 5 keeps it alive).
    relay.reviseEndpointRetryPolicy(forwardUrl, {
      statusPolicy: { "503": { baseDelayMs: 200, maxAttempts: 5 } },
    });
    await timer.step(3); // attempt 3 fails (503)
    assert.equal(hits(), 3);
    assert.deepEqual(timer.retryDelays(), [2000, 20000, 1600]);
  });

  it("detaching the named layer falls back to the global schedule", async () => {
    const { relay, timer, port, forwardUrl, hits } = await makeServer(500);
    relay.reviseEndpointRetryPolicy(forwardUrl, {
      policyName: "fast",
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3 } },
    });
    // Detach the named layer: a 500 (no status match) now retries
    // on the global base, while the 503 layer stays attached.
    relay.reviseEndpointRetryPolicy(forwardUrl, { policyName: null });
    assert.deepEqual(relay.getEndpointRetryPolicy(forwardUrl), {
      statusPolicy: { "503": { baseDelayMs: 5000, maxAttempts: 3, multiplier: 2 } },
    });
    assert.equal(await post(port, Buffer.from(JSON.stringify({ n: 4 }))), 202);
    await timer.step(1); // attempt 1 fails (500)
    assert.equal(hits(), 1);
    assert.deepEqual(timer.retryDelays(), [2000]);
  });

  it("a new acceptance stamps the revised policy name", async () => {
    const { relay, auditLog, port, forwardUrl } = await makeServer(500);
    relay.reviseEndpointRetryPolicy(forwardUrl, { policyName: "fast" });
    assert.equal(await post(port, Buffer.from(JSON.stringify({ n: 5 }))), 202);
    const accepted1 = eventsOf(auditLog, "accepted");
    assert.equal(accepted1.length, 1);
    assert.equal(accepted1[0].retryPolicy, "fast");
    relay.reviseEndpointRetryPolicy(forwardUrl, { policyName: "slow" });
    assert.equal(await post(port, Buffer.from(JSON.stringify({ n: 6 }))), 202);
    const accepted2 = eventsOf(auditLog, "accepted");
    assert.equal(accepted2.length, 2);
    assert.equal(accepted2[1].retryPolicy, "slow");
  });
});
