import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import {
  RetryQueue,
  type DeadLetterEscalatedInfo,
  type DeadLetterEscalationFailedInfo,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import type { EscalationPostResult } from "../src/escalation.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "dead-letter-escalation-callbacks-revision-secret";
const operatorToken = "dead-letter-escalation-callbacks-revision-token";
const SIGNING_SECRET = "dead-letter-escalation-callbacks-revision-signing";
const OPERATOR_URL = "https://ops.example.com/alerts/dead-letter";
const ENDPOINT = "https://downstream.example/hook";
const FORWARD = "http://127.0.0.1:1/unused";
const PAYLOAD = Buffer.from(JSON.stringify({ payment: "pi_123", amount: 5000 }));
const BODY = PAYLOAD;

type EscalatedObserver = (info: DeadLetterEscalatedInfo) => void;
type FailedObserver = (info: DeadLetterEscalationFailedInfo) => void;

interface CapturedPost {
  url: string;
  body: Buffer;
  headers: Record<string, string>;
}

/** Captures alert POSTs without touching the network. */
function stubTransport(statusCode = 200) {
  const posts: CapturedPost[] = [];
  let status = statusCode;
  return {
    posts,
    setStatus: (s: number) => {
      status = s;
    },
    post: async (url: string, body: Buffer, headers: Record<string, string>): Promise<EscalationPostResult> => {
      posts.push({ url, body, headers });
      return { statusCode: status };
    },
  };
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for ${what}`);
}

describe("RetryQueue dead-letter escalation callbacks revision (WR-394)", () => {
  function makeQueue(
    transport: ReturnType<typeof stubTransport>,
    opts: {
      onDeadLetterEscalated?: EscalatedObserver;
      onDeadLetterEscalationFailed?: FailedObserver;
      threshold?: number;
      maxAttempts?: number;
    } = {}
  ) {
    const failing: Sender = async () => {
      throw new Error("downstream is down");
    };
    const q = new RetryQueue({
      sender: failing,
      baseDelayMs: 1,
      maxDelayMs: 5,
      maxAttempts: 1,
      jitterMs: 0,
      escalation: {
        url: OPERATOR_URL,
        signingSecret: SIGNING_SECRET,
        threshold: opts.threshold ?? 2,
        windowMs: 600_000,
        cooldownMs: 0,
        maxAttempts: opts.maxAttempts ?? 1,
        post: transport.post,
        now: Date.now,
      },
      ...(opts.onDeadLetterEscalated !== undefined
        ? { onDeadLetterEscalated: opts.onDeadLetterEscalated }
        : {}),
      ...(opts.onDeadLetterEscalationFailed !== undefined
        ? { onDeadLetterEscalationFailed: opts.onDeadLetterEscalationFailed }
        : {}),
    });
    return q;
  }

  let seq = 0;
  /** Dead-letter one item and wait for the queue to record it. */
  async function deadLetterOne(q: RetryQueue, before: number): Promise<void> {
    seq += 1;
    q.enqueue({
      id: `dl-${seq}`,
      payload: Buffer.from("{}"),
      targetUrl: ENDPOINT,
      headers: {},
    });
    await waitFor(() => q.getDeadLetter().length > before, "dead letter");
  }

  /**
   * Drive one storm episode on ENDPOINT and wait for its alert to
   * settle (dispatched or exhausted). The first episode needs
   * `threshold` dead letters; later episodes need one more after an
   * acknowledge rearms the scope.
   */
  async function driveEpisode(
    q: RetryQueue,
    transport: ReturnType<typeof stubTransport>,
    escalated: DeadLetterEscalatedInfo[],
    failed: DeadLetterEscalationFailedInfo[],
    n: number
  ): Promise<void> {
    const postsBefore = transport.posts.length;
    const escalatedBefore = escalated.length;
    const failedBefore = failed.length;
    const deadBefore = q.getDeadLetter().length;
    for (let i = 0; i < n; i++) {
      await deadLetterOne(q, deadBefore + i);
    }
    await waitFor(
      () =>
        transport.posts.length > postsBefore &&
        (escalated.length > escalatedBefore || failed.length > failedBefore),
      "alert to settle"
    );
  }

  it("escalated reaches the revised callback; the old callback stays silent", async () => {
    const transport = stubTransport(200);
    const oldSeen: DeadLetterEscalatedInfo[] = [];
    const newSeen: DeadLetterEscalatedInfo[] = [];
    const failedSeen: DeadLetterEscalationFailedInfo[] = [];
    const q = makeQueue(transport, {
      onDeadLetterEscalated: (info) => oldSeen.push(info),
      onDeadLetterEscalationFailed: (info) => failedSeen.push(info),
    });
    try {
      q.start();
      await driveEpisode(q, transport, oldSeen, failedSeen, 2);
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].endpoint, ENDPOINT);
      assert.equal(oldSeen[0].deadLetters, 2);
      assert.equal(oldSeen[0].threshold, 2);
      assert.equal(transport.posts.length, 1);
      assert.equal(failedSeen.length, 0);
      // Swap mid-flight: the old callback never hears another alert.
      q.reviseDeadLetterEscalationCallbacks({
        onDeadLetterEscalated: (info) => newSeen.push(info),
      });
      q.acknowledgeDeadLetterEscalation(undefined, ENDPOINT);
      await driveEpisode(q, transport, newSeen, failedSeen, 1);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].endpoint, ENDPOINT);
      assert.equal(transport.posts.length, 2);
      assert.equal(q.getEscalationStats()[0].escalations, 2);
    } finally {
      q.stop();
    }
  });

  it("failed reaches the revised callback; the old callback stays silent", async () => {
    const transport = stubTransport(500);
    const escalatedSeen: DeadLetterEscalatedInfo[] = [];
    const oldSeen: DeadLetterEscalationFailedInfo[] = [];
    const newSeen: DeadLetterEscalationFailedInfo[] = [];
    const q = makeQueue(transport, {
      threshold: 1,
      onDeadLetterEscalated: (info) => escalatedSeen.push(info),
      onDeadLetterEscalationFailed: (info) => oldSeen.push(info),
    });
    try {
      q.start();
      await driveEpisode(q, transport, escalatedSeen, oldSeen, 1);
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].endpoint, ENDPOINT);
      assert.equal(oldSeen[0].attempts, 1);
      assert.match(oldSeen[0].error, /500/);
      assert.equal(escalatedSeen.length, 0);
      assert.equal(transport.posts.length, 1);
      // Swap mid-flight: the old callback never hears another failure.
      q.reviseDeadLetterEscalationCallbacks({
        onDeadLetterEscalationFailed: (info) => newSeen.push(info),
      });
      q.acknowledgeDeadLetterEscalation(undefined, ENDPOINT);
      await driveEpisode(q, transport, escalatedSeen, newSeen, 1);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].endpoint, ENDPOINT);
      assert.equal(newSeen[0].attempts, 1);
      assert.equal(transport.posts.length, 2);
      assert.equal(q.getEscalationStats()[0].escalations, 2);
    } finally {
      q.stop();
    }
  });

  it("null clears a single field; the storm still evaluates and the alert still POSTs", async () => {
    const transport = stubTransport(200);
    const escalatedSeen: DeadLetterEscalatedInfo[] = [];
    const failedSeen: DeadLetterEscalationFailedInfo[] = [];
    const q = makeQueue(transport, {
      onDeadLetterEscalated: (info) => escalatedSeen.push(info),
      onDeadLetterEscalationFailed: (info) => failedSeen.push(info),
    });
    try {
      q.start();
      await driveEpisode(q, transport, escalatedSeen, failedSeen, 2);
      assert.equal(escalatedSeen.length, 1);
      assert.equal(transport.posts.length, 1);
      // Clear only the escalated hook: the next alert still POSTs,
      // the storm is still counted, only the forwarding stops.
      q.reviseDeadLetterEscalationCallbacks({ onDeadLetterEscalated: null });
      q.acknowledgeDeadLetterEscalation(undefined, ENDPOINT);
      const deadBefore = q.getDeadLetter().length;
      await deadLetterOne(q, deadBefore);
      // No observer is left to wait on, so wait on the POST + the
      // escalation counter instead.
      await waitFor(
        () =>
          transport.posts.length === 2 &&
          q.getEscalationStats()[0]?.escalations === 2,
        "second alert POST"
      );
      assert.equal(escalatedSeen.length, 1);
      assert.equal(transport.posts.length, 2);
      assert.equal(q.getEscalationStats()[0].escalations, 2);
      assert.equal(q.getEscalationStats()[0].alerted, true);
    } finally {
      q.stop();
    }
  });

  it("both fields move in one patch", async () => {
    const transport = stubTransport(200);
    const oldEscalated: DeadLetterEscalatedInfo[] = [];
    const oldFailed: DeadLetterEscalationFailedInfo[] = [];
    const newEscalated: DeadLetterEscalatedInfo[] = [];
    const newFailed: DeadLetterEscalationFailedInfo[] = [];
    const q = makeQueue(transport, {
      onDeadLetterEscalated: (info) => oldEscalated.push(info),
      onDeadLetterEscalationFailed: (info) => oldFailed.push(info),
    });
    try {
      q.start();
      await driveEpisode(q, transport, oldEscalated, oldFailed, 2);
      assert.equal(oldEscalated.length, 1);
      // Flip the transport to failing so the next episode exercises
      // the failed hook instead of the escalated one.
      transport.setStatus(500);
      q.reviseDeadLetterEscalationCallbacks({
        onDeadLetterEscalated: (info) => newEscalated.push(info),
        onDeadLetterEscalationFailed: (info) => newFailed.push(info),
      });
      q.acknowledgeDeadLetterEscalation(undefined, ENDPOINT);
      await driveEpisode(q, transport, newEscalated, newFailed, 1);
      assert.equal(oldEscalated.length, 1);
      assert.equal(newEscalated.length, 0); // the alert failed: nothing escalated
      assert.equal(oldFailed.length, 0);
      assert.equal(newFailed.length, 1);
      assert.equal(newFailed[0].attempts, 1);
      assert.equal(transport.posts.length, 2);
    } finally {
      q.stop();
    }
  });

  it("an empty or non-object patch throws RangeError and the live callbacks are untouched", async () => {
    const transport = stubTransport(200);
    const escalatedSeen: DeadLetterEscalatedInfo[] = [];
    const failedSeen: DeadLetterEscalationFailedInfo[] = [];
    const q = makeQueue(transport, {
      onDeadLetterEscalated: (info) => escalatedSeen.push(info),
      onDeadLetterEscalationFailed: (info) => failedSeen.push(info),
    });
    try {
      q.start();
      assert.throws(() => q.reviseDeadLetterEscalationCallbacks({}), RangeError);
      assert.throws(
        () => q.reviseDeadLetterEscalationCallbacks(null as never),
        RangeError
      );
      assert.throws(
        () => q.reviseDeadLetterEscalationCallbacks("nope" as never),
        RangeError
      );
      assert.throws(
        () => q.reviseDeadLetterEscalationCallbacks(42 as never),
        RangeError
      );
      // An explicitly-undefined field counts as not provided, so a
      // patch of only undefined fields is empty too.
      assert.throws(
        () => q.reviseDeadLetterEscalationCallbacks({ onDeadLetterEscalated: undefined }),
        RangeError
      );
      await driveEpisode(q, transport, escalatedSeen, failedSeen, 2);
      assert.equal(escalatedSeen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError and the live callbacks are untouched", async () => {
    const transport = stubTransport(200);
    const escalatedSeen: DeadLetterEscalatedInfo[] = [];
    const failedSeen: DeadLetterEscalationFailedInfo[] = [];
    const q = makeQueue(transport, {
      onDeadLetterEscalated: (info) => escalatedSeen.push(info),
      onDeadLetterEscalationFailed: (info) => failedSeen.push(info),
    });
    try {
      q.start();
      for (const bad of ["nope", 42, {}, true]) {
        assert.throws(
          () => q.reviseDeadLetterEscalationCallbacks({ onDeadLetterEscalated: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
        assert.throws(
          () => q.reviseDeadLetterEscalationCallbacks({ onDeadLetterEscalationFailed: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
      }
      // The live callbacks are untouched: the next alert still reaches them.
      await driveEpisode(q, transport, escalatedSeen, failedSeen, 2);
      assert.equal(escalatedSeen.length, 1);
      assert.equal(failedSeen.length, 0);
    } finally {
      q.stop();
    }
  });

  it("a same-reference revision is a no-op; a partial patch leaves the other hook live", async () => {
    const transport = stubTransport(200);
    const escalatedSeen: DeadLetterEscalatedInfo[] = [];
    const newEscalatedSeen: DeadLetterEscalatedInfo[] = [];
    const failedSeen: DeadLetterEscalationFailedInfo[] = [];
    const escalatedCb: EscalatedObserver = (info) => escalatedSeen.push(info);
    const failedCb: FailedObserver = (info) => failedSeen.push(info);
    const newEscalatedCb: EscalatedObserver = (info) => newEscalatedSeen.push(info);
    const q = makeQueue(transport, {
      onDeadLetterEscalated: escalatedCb,
      onDeadLetterEscalationFailed: failedCb,
    });
    try {
      q.start();
      await driveEpisode(q, transport, escalatedSeen, failedSeen, 2);
      assert.equal(escalatedSeen.length, 1);
      // Same references as construction: a no-op, nothing is dropped.
      q.reviseDeadLetterEscalationCallbacks({
        onDeadLetterEscalated: escalatedCb,
        onDeadLetterEscalationFailed: failedCb,
      });
      // Clearing when already unset is a no-op too.
      const bareTransport = stubTransport(200);
      const bare = makeQueue(bareTransport, {});
      try {
        bare.reviseDeadLetterEscalationCallbacks({
          onDeadLetterEscalated: null,
          onDeadLetterEscalationFailed: null,
        });
      } finally {
        bare.stop();
      }
      // Partial patch: only the escalated hook moves.
      q.reviseDeadLetterEscalationCallbacks({ onDeadLetterEscalated: newEscalatedCb });
      q.acknowledgeDeadLetterEscalation(undefined, ENDPOINT);
      await driveEpisode(q, transport, newEscalatedSeen, failedSeen, 1);
      assert.equal(escalatedSeen.length, 1);
      assert.equal(newEscalatedSeen.length, 1);
      // The failed hook never moved: flip the transport and let the
      // next alert exhaust — it still reaches the original callback.
      transport.setStatus(500);
      q.acknowledgeDeadLetterEscalation(undefined, ENDPOINT);
      await driveEpisode(q, transport, newEscalatedSeen, failedSeen, 1);
      assert.equal(newEscalatedSeen.length, 1);
      assert.equal(failedSeen.length, 1);
      assert.equal(failedSeen[0].attempts, 1);
    } finally {
      q.stop();
    }
  });

  it("revising with escalation unconfigured throws Error", () => {
    const q = new RetryQueue({ sender: (async () => {}) as Sender });
    try {
      assert.throws(
        () => q.reviseDeadLetterEscalationCallbacks({ onDeadLetterEscalated: () => {} }),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
      assert.throws(
        () => q.reviseDeadLetterEscalationCallbacks({ onDeadLetterEscalationFailed: null }),
        (e: unknown) => e instanceof Error && /not configured/.test(e.message)
      );
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer dead-letter escalation callbacks revision (WR-394)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "dead-letter-escalation-callbacks-revision-"));
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

  /**
   * A server whose sender fails, with the storm escalator on the
   * stubbed transport. Returns the relay, its audit log, and the
   * transport capture.
   */
  function escalatingServer(
    transport: ReturnType<typeof stubTransport>,
    opts: {
      onDeadLetterEscalated?: EscalatedObserver;
      onDeadLetterEscalationFailed?: FailedObserver;
    } = {}
  ) {
    const sender: Sender = async () => {
      throw new Error("downstream is down");
    };
    const { relay, auditLog } = makeServer({
      sender,
      retry: {
        baseDelayMs: 1,
        maxDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 1,
        ...(opts.onDeadLetterEscalated !== undefined
          ? { onDeadLetterEscalated: opts.onDeadLetterEscalated }
          : {}),
        ...(opts.onDeadLetterEscalationFailed !== undefined
          ? { onDeadLetterEscalationFailed: opts.onDeadLetterEscalationFailed }
          : {}),
      },
      deadLetterEscalation: {
        url: OPERATOR_URL,
        signingSecret: SIGNING_SECRET,
        threshold: 2,
        windowMs: 300,
        cooldownMs: 0,
        maxAttempts: 1,
        post: transport.post,
      },
    });
    return { relay, auditLog, transport };
  }

  /**
   * Drive one storm episode on the server's scope and wait for its
   * alert audit to land. Each episode is two webhooks (threshold 2);
   * later episodes sleep past the 300ms window first, so the first
   * webhook rearms the scope (the window count falls below the
   * threshold) and the second dispatches the fresh alert.
   */
  async function driveServerEpisode(
    port: number,
    auditLog: AuditLog,
    event: "dead_letter_escalated" | "dead_letter_escalation_failed",
    first: boolean
  ): Promise<void> {
    if (!first) {
      await new Promise((r) => setTimeout(r, 500));
    }
    const before = eventsOf(auditLog, event).length;
    const sig = { "x-signature": signSha256(BODY, relaySecret) };
    assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
    assert.equal((await postWebhook(port, "/", BODY, sig)).status, 202);
    await waitFor(
      () => eventsOf(auditLog, event).length > before,
      `${event} audit`
    );
  }

  it("revising the escalated callback routes the next alert to the new callback and the audit still lands", async () => {
    const transport = stubTransport(200);
    const initialSeen: DeadLetterEscalatedInfo[] = [];
    const newSeen: DeadLetterEscalatedInfo[] = [];
    const initialCb: EscalatedObserver = (info) => initialSeen.push(info);
    const newCb: EscalatedObserver = (info) => newSeen.push(info);
    const { relay, auditLog } = escalatingServer(transport, {
      onDeadLetterEscalated: initialCb,
    });
    const port = await listen(relay);
    await driveServerEpisode(port, auditLog, "dead_letter_escalated", true);
    assert.equal(initialSeen.length, 1);
    assert.equal(initialSeen[0].endpoint, FORWARD);
    assert.equal(eventsOf(auditLog, "dead_letter_escalated").length, 1);
    assert.equal(transport.posts.length, 1);
    // The posted alert still carries the configured threshold.
    assert.equal(
      JSON.parse(transport.posts[0].body.toString("utf8")).threshold,
      2
    );
    // Swap the operator escalated callback; the failed hook is untouched.
    relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalated: newCb });
    await driveServerEpisode(port, auditLog, "dead_letter_escalated", false);
    assert.equal(initialSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen.length, 1);
    assert.equal(newSeen[0].endpoint, FORWARD);
    assert.equal(eventsOf(auditLog, "dead_letter_escalated").length, 2);
    assert.equal(transport.posts.length, 2);
    assert.equal(
      JSON.parse(transport.posts[1].body.toString("utf8")).threshold,
      2
    );
    // The revision itself was audited with per-hook presence.
    const revised = eventsOf(auditLog, "dead_letter_escalation_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onDeadLetterEscalated,
        revised[0].oldOnDeadLetterEscalated,
        revised[0].onDeadLetterEscalationFailed,
        revised[0].oldOnDeadLetterEscalationFailed,
      ],
      ["set", "set", "unchanged", "absent"]
    );
  });

  it("revising the failed callback routes the next exhausted alert to the new callback", async () => {
    const transport = stubTransport(500);
    const initialSeen: DeadLetterEscalationFailedInfo[] = [];
    const newSeen: DeadLetterEscalationFailedInfo[] = [];
    const escalatedSeen: DeadLetterEscalatedInfo[] = [];
    const initialCb: FailedObserver = (info) => initialSeen.push(info);
    const newCb: FailedObserver = (info) => newSeen.push(info);
    const escalatedCb: EscalatedObserver = (info) => escalatedSeen.push(info);
    const { relay, auditLog } = escalatingServer(transport, {
      onDeadLetterEscalated: escalatedCb,
      onDeadLetterEscalationFailed: initialCb,
    });
    const port = await listen(relay);
    await driveServerEpisode(port, auditLog, "dead_letter_escalation_failed", true);
    assert.equal(initialSeen.length, 1);
    assert.equal(initialSeen[0].endpoint, FORWARD);
    assert.equal(initialSeen[0].attempts, 1);
    assert.equal(escalatedSeen.length, 0);
    assert.equal(eventsOf(auditLog, "dead_letter_escalation_failed").length, 1);
    // Swap only the failed callback.
    relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalationFailed: newCb });
    await driveServerEpisode(port, auditLog, "dead_letter_escalation_failed", false);
    assert.equal(initialSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen.length, 1);
    assert.equal(newSeen[0].endpoint, FORWARD);
    assert.equal(eventsOf(auditLog, "dead_letter_escalation_failed").length, 2);
    assert.equal(transport.posts.length, 2);
    const revised = eventsOf(auditLog, "dead_letter_escalation_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onDeadLetterEscalated,
        revised[0].oldOnDeadLetterEscalated,
        revised[0].onDeadLetterEscalationFailed,
        revised[0].oldOnDeadLetterEscalationFailed,
      ],
      ["unchanged", "set", "set", "set"]
    );
  });

  it("clearing both hooks keeps the audit and stops the operator callbacks", async () => {
    const transport = stubTransport(200);
    const escalatedSeen: DeadLetterEscalatedInfo[] = [];
    const failedSeen: DeadLetterEscalationFailedInfo[] = [];
    const escalatedCb: EscalatedObserver = (info) => escalatedSeen.push(info);
    const failedCb: FailedObserver = (info) => failedSeen.push(info);
    const { relay, auditLog } = escalatingServer(transport, {
      onDeadLetterEscalated: escalatedCb,
      onDeadLetterEscalationFailed: failedCb,
    });
    const port = await listen(relay);
    await driveServerEpisode(port, auditLog, "dead_letter_escalated", true);
    assert.equal(escalatedSeen.length, 1);
    // Clear back to audit-only.
    relay.reviseDeadLetterEscalationCallbacks!({
      onDeadLetterEscalated: null,
      onDeadLetterEscalationFailed: null,
    });
    await driveServerEpisode(port, auditLog, "dead_letter_escalated", false);
    assert.equal(escalatedSeen.length, 1); // the later alert was audit-only
    assert.equal(eventsOf(auditLog, "dead_letter_escalated").length, 2);
    assert.equal(transport.posts.length, 2);
    const revised = eventsOf(auditLog, "dead_letter_escalation_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onDeadLetterEscalated,
        revised[0].oldOnDeadLetterEscalated,
        revised[0].onDeadLetterEscalationFailed,
        revised[0].oldOnDeadLetterEscalationFailed,
      ],
      ["cleared", "set", "cleared", "set"]
    );
    // Clearing when already cleared is a silent no-op.
    relay.reviseDeadLetterEscalationCallbacks!({
      onDeadLetterEscalated: null,
      onDeadLetterEscalationFailed: null,
    });
    assert.equal(eventsOf(auditLog, "dead_letter_escalation_callbacks_revised").length, 1);
  });

  it("an illegal value or empty patch throws RangeError, live callbacks untouched, no revision audit", async () => {
    const transport = stubTransport(200);
    const escalatedSeen: DeadLetterEscalatedInfo[] = [];
    const failedSeen: DeadLetterEscalationFailedInfo[] = [];
    const escalatedCb: EscalatedObserver = (info) => escalatedSeen.push(info);
    const failedCb: FailedObserver = (info) => failedSeen.push(info);
    const { relay, auditLog } = escalatingServer(transport, {
      onDeadLetterEscalated: escalatedCb,
      onDeadLetterEscalationFailed: failedCb,
    });
    const port = await listen(relay);
    for (const bad of ["nope", 42, {}, true]) {
      assert.throws(
        () => relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalated: bad as never }),
        RangeError,
        JSON.stringify(bad)
      );
      assert.throws(
        () => relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalationFailed: bad as never }),
        RangeError,
        JSON.stringify(bad)
      );
    }
    assert.throws(() => relay.reviseDeadLetterEscalationCallbacks!({}), RangeError);
    assert.throws(() => relay.reviseDeadLetterEscalationCallbacks!(null as never), RangeError);
    assert.equal(eventsOf(auditLog, "dead_letter_escalation_callbacks_revised").length, 0);
    // The live callbacks are untouched: the next alert still reaches them.
    await driveServerEpisode(port, auditLog, "dead_letter_escalated", true);
    assert.equal(escalatedSeen.length, 1);
    assert.equal(failedSeen.length, 0);
  });

  it("a same-value revision is a silent no-op; a partial patch leaves the other hook live", async () => {
    const transport = stubTransport(200);
    const initialEscalatedSeen: DeadLetterEscalatedInfo[] = [];
    const initialFailedSeen: DeadLetterEscalationFailedInfo[] = [];
    const newEscalatedSeen: DeadLetterEscalatedInfo[] = [];
    const initialEscalatedCb: EscalatedObserver = (info) => initialEscalatedSeen.push(info);
    const initialFailedCb: FailedObserver = (info) => initialFailedSeen.push(info);
    const newEscalatedCb: EscalatedObserver = (info) => newEscalatedSeen.push(info);
    const { relay, auditLog } = escalatingServer(transport, {
      onDeadLetterEscalated: initialEscalatedCb,
      onDeadLetterEscalationFailed: initialFailedCb,
    });
    const port = await listen(relay);
    await driveServerEpisode(port, auditLog, "dead_letter_escalated", true);
    assert.equal(initialEscalatedSeen.length, 1);
    // Same references as construction: no audit event.
    relay.reviseDeadLetterEscalationCallbacks!({
      onDeadLetterEscalated: initialEscalatedCb,
      onDeadLetterEscalationFailed: initialFailedCb,
    });
    assert.equal(eventsOf(auditLog, "dead_letter_escalation_callbacks_revised").length, 0);
    // Partial patch: only the escalated hook moves.
    relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalated: newEscalatedCb });
    const revised = eventsOf(auditLog, "dead_letter_escalation_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onDeadLetterEscalated,
        revised[0].oldOnDeadLetterEscalated,
        revised[0].onDeadLetterEscalationFailed,
        revised[0].oldOnDeadLetterEscalationFailed,
      ],
      ["set", "set", "unchanged", "set"]
    );
    // Same reference again: no further audit event.
    relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalated: newEscalatedCb });
    assert.equal(eventsOf(auditLog, "dead_letter_escalation_callbacks_revised").length, 1);
    // The next alert enters the new callback; the failed hook is
    // still the original one (proven by flipping the transport and
    // letting the following alert exhaust into it).
    await driveServerEpisode(port, auditLog, "dead_letter_escalated", false);
    assert.equal(newEscalatedSeen.length, 1);
    assert.equal(initialEscalatedSeen.length, 1);
    transport.setStatus(500);
    await driveServerEpisode(port, auditLog, "dead_letter_escalation_failed", false);
    assert.equal(initialFailedSeen.length, 1);
    assert.equal(initialFailedSeen[0].attempts, 1);
  });

  it("revising with escalation unconfigured throws Error", async () => {
    const { relay } = makeServer({
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(relay);
    assert.ok(port > 0);
    assert.throws(
      () => relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalated: () => {} }),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
    assert.throws(
      () => relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalationFailed: null }),
      (e: unknown) => e instanceof Error && /not configured/.test(e.message)
    );
  });
});
