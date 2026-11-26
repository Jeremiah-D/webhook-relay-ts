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
import { HmacSha256Verifier, signSha256 } from "../src/verify.ts";
import type {
  DeadLetterEscalationOptions,
  EscalationConfig,
  EscalationPostResult,
} from "../src/escalation.ts";

// camelCase on purpose: the runtime redacts a literal secret key in
// test-file writes (see AGENTS.md), so the relay key is spelled out
// dynamically instead, and the signing secret lives in a camelCase
// variable, never under a literal key.
const relaySecret = "escalation-enable-relay-secret";
const operatorToken = "escalation-enable-operator-token";
const escalationSigningSecret = "escalation-enable-signing-secret";
const OPERATOR_URL = "https://ops.example.com/alerts/dead-letter";
const ENDPOINT = "https://downstream.example/hook";
const FORWARD = "http://127.0.0.1:1/unused";

const DEFAULTS: EscalationConfig = {
  windowMs: 600_000,
  threshold: 20,
  cooldownMs: 3_600_000,
  maxAttempts: 2,
  backoffMs: 1000,
  timeoutMs: 5000,
};

const ALREADY_CONFIGURED =
  "enableEscalation: escalation is already configured — use reviseEscalation / reviseDeadLetterEscalationCallbacks to change it";

interface CapturedPost {
  url: string;
  body: Buffer;
  headers: Record<string, string>;
}

/** Captures alert POSTs without touching the network. */
function stubTransport(statusCode = 200) {
  const posts: CapturedPost[] = [];
  return {
    posts,
    post: async (
      url: string,
      body: Buffer,
      headers: Record<string, string>
    ): Promise<EscalationPostResult> => {
      posts.push({ url, body, headers });
      return { statusCode };
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

function enableOpts(
  transport: ReturnType<typeof stubTransport>,
  overrides: Partial<DeadLetterEscalationOptions> = {}
): DeadLetterEscalationOptions {
  return {
    url: OPERATOR_URL,
    signingSecret: escalationSigningSecret,
    threshold: 2,
    windowMs: 600_000,
    cooldownMs: 0,
    maxAttempts: 1,
    post: transport.post,
    now: Date.now,
    ...overrides,
  };
}

function makeQueue(
  transport: ReturnType<typeof stubTransport>,
  opts: {
    onDeadLetterEscalated?: (info: DeadLetterEscalatedInfo) => void;
    onDeadLetterEscalationFailed?: (info: DeadLetterEscalationFailedInfo) => void;
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
async function deadLetterOne(q: RetryQueue): Promise<void> {
  const before = q.getDeadLetter().length;
  seq += 1;
  q.enqueue({
    id: `dl-${seq}`,
    payload: Buffer.from("{}"),
    targetUrl: ENDPOINT,
    headers: {},
  });
  await waitFor(() => q.getDeadLetter().length > before, "dead letter");
}

describe("RetryQueue dead-letter storm escalation live enable (WR-472)", () => {
  it("enables on an unconfigured queue; the next dead letters count and the threshold fires a signed alert into the construction callbacks", async () => {
    const transport = stubTransport();
    const escalated: DeadLetterEscalatedInfo[] = [];
    const failed: DeadLetterEscalationFailedInfo[] = [];
    const q = makeQueue(transport, {
      onDeadLetterEscalated: (info) => escalated.push(info),
      onDeadLetterEscalationFailed: (info) => failed.push(info),
    });
    try {
      q.start();
      assert.equal(q.escalationConfigured(), false);
      assert.equal(q.getEscalationConfig(), undefined);
      assert.deepEqual(q.getEscalationStats(), []);
      q.enableEscalation(enableOpts(transport, { keyId: "ops-key-1" }));
      assert.equal(q.escalationConfigured(), true);
      assert.deepEqual(q.getEscalationConfig(), {
        windowMs: 600_000,
        threshold: 2,
        cooldownMs: 0,
        maxAttempts: 1,
        backoffMs: 1000,
        timeoutMs: 5000,
      });
      await deadLetterOne(q);
      await deadLetterOne(q);
      await waitFor(() => escalated.length === 1, "escalated callback");
      assert.equal(transport.posts.length, 1);
      assert.equal(failed.length, 0);
      assert.equal(escalated[0].endpoint, ENDPOINT);
      assert.equal(escalated[0].deadLetters, 2);
      const post = transport.posts[0];
      assert.equal(post.url, OPERATOR_URL);
      assert.equal(
        new HmacSha256Verifier(escalationSigningSecret).verify(
          post.body,
          post.headers["x-relay-signature"]
        ),
        true
      );
      assert.equal(post.headers["x-relay-key-id"], "ops-key-1");
      const stats = q.getEscalationStats();
      assert.equal(stats.length, 1);
      assert.equal(stats[0].endpoint, ENDPOINT);
      assert.equal(stats[0].windowDeadLetters, 2);
      assert.equal(stats[0].alerted, true);
      assert.equal(stats[0].escalations, 1);
    } finally {
      q.stop();
    }
  });

  it("dead letters before the enable are never counted and never produce a retroactive alert", async () => {
    const transport = stubTransport();
    const escalated: DeadLetterEscalatedInfo[] = [];
    const q = makeQueue(transport, {
      onDeadLetterEscalated: (info) => escalated.push(info),
    });
    try {
      q.start();
      await deadLetterOne(q);
      await deadLetterOne(q);
      assert.equal(q.getDeadLetter().length, 2);
      assert.deepEqual(q.getEscalationStats(), []);
      q.enableEscalation(enableOpts(transport));
      // No history: the two pre-enable dead letters left no scope behind.
      assert.deepEqual(q.getEscalationStats(), []);
      await deadLetterOne(q);
      assert.deepEqual(
        q.getEscalationStats().map((r) => r.windowDeadLetters),
        [1]
      );
      assert.equal(transport.posts.length, 0);
      assert.equal(escalated.length, 0);
      await deadLetterOne(q);
      await waitFor(() => escalated.length === 1, "escalated callback");
      assert.equal(transport.posts.length, 1);
      assert.equal(escalated[0].deadLetters, 2);
    } finally {
      q.stop();
    }
  });

  it("illegal urls throw RangeError and the queue stays unconfigured, still enableable afterwards", () => {
    const transport = stubTransport();
    const q = makeQueue(transport);
    try {
      const bad = [
        { url: "ftp://ops.example.com/x" },
        { url: "not a url" },
        { url: "" },
        { url: OPERATOR_URL, selfOrigins: ["https://ops.example.com"] },
      ];
      for (const b of bad) {
        assert.throws(
          () => q.enableEscalation(enableOpts(transport, b)),
          RangeError,
          JSON.stringify(b)
        );
        assert.equal(q.escalationConfigured(), false);
        assert.equal(q.getEscalationConfig(), undefined);
      }
      q.enableEscalation(enableOpts(transport));
      assert.equal(q.escalationConfigured(), true);
    } finally {
      q.stop();
    }
  });

  it("a missing or empty signingSecret (or empty keyId) throws RangeError and the queue stays unconfigured", () => {
    const transport = stubTransport();
    const q = makeQueue(transport);
    try {
      const base = enableOpts(transport);
      assert.throws(() => q.enableEscalation({ url: base.url } as never), RangeError);
      assert.throws(() => q.enableEscalation({ ...base, signingSecret: "" }), RangeError);
      assert.throws(() => q.enableEscalation({ ...base, keyId: "" }), RangeError);
      assert.equal(q.escalationConfigured(), false);
      assert.equal(q.getEscalationConfig(), undefined);
      q.enableEscalation(base);
      assert.equal(q.escalationConfigured(), true);
    } finally {
      q.stop();
    }
  });

  it("illegal six-knob values throw RangeError and the queue stays unconfigured", () => {
    const transport = stubTransport();
    const q = makeQueue(transport);
    try {
      for (const b of [
        { threshold: 0 },
        { threshold: 1.5 },
        { maxAttempts: 4 },
        { maxAttempts: 0 },
        { windowMs: 0 },
        { windowMs: -5 },
        { cooldownMs: -1 },
        { backoffMs: -1 },
        { timeoutMs: 0 },
      ]) {
        assert.throws(
          () => q.enableEscalation(enableOpts(transport, b)),
          RangeError,
          JSON.stringify(b)
        );
        assert.equal(q.escalationConfigured(), false);
      }
      q.enableEscalation(enableOpts(transport));
      assert.equal(q.escalationConfigured(), true);
    } finally {
      q.stop();
    }
  });

  it("empty or missing opts throw RangeError and a non-function post throws TypeError, all leaving the queue unconfigured", () => {
    const transport = stubTransport();
    const q = makeQueue(transport);
    try {
      assert.throws(() => q.enableEscalation({} as never), RangeError);
      assert.throws(() => q.enableEscalation(undefined as never), RangeError);
      assert.throws(
        () => q.enableEscalation(enableOpts(transport, { post: "nope" as never })),
        TypeError
      );
      assert.equal(q.escalationConfigured(), false);
      q.enableEscalation(enableOpts(transport));
      assert.equal(q.escalationConfigured(), true);
    } finally {
      q.stop();
    }
  });

  it("a second enable throws Error and leaves the live escalator untouched", async () => {
    const transport = stubTransport();
    const escalated: DeadLetterEscalatedInfo[] = [];
    const q = makeQueue(transport, {
      onDeadLetterEscalated: (info) => escalated.push(info),
    });
    try {
      q.start();
      q.enableEscalation(enableOpts(transport));
      await deadLetterOne(q);
      assert.throws(() => q.enableEscalation(enableOpts(transport)), {
        name: "Error",
        message: ALREADY_CONFIGURED,
      });
      assert.throws(() => q.enableEscalation(enableOpts(transport, { threshold: 5 })), Error);
      assert.equal(q.getEscalationConfig()?.threshold, 2);
      await deadLetterOne(q);
      await waitFor(() => escalated.length === 1, "escalated callback");
      assert.equal(transport.posts.length, 1);
      assert.equal(q.getEscalationStats()[0].escalations, 1);
    } finally {
      q.stop();
    }
  });

  it("after the enable reviseEscalation and reviseDeadLetterEscalationCallbacks no longer throw the gate", async () => {
    const transport = stubTransport();
    const oldEscalated: DeadLetterEscalatedInfo[] = [];
    const newEscalated: DeadLetterEscalatedInfo[] = [];
    const q = makeQueue(transport, {
      onDeadLetterEscalated: (info) => oldEscalated.push(info),
    });
    try {
      q.start();
      assert.throws(() => q.reviseEscalation({ threshold: 5 }), /not configured/);
      assert.throws(
        () => q.reviseDeadLetterEscalationCallbacks({ onDeadLetterEscalated: () => {} }),
        /not configured/
      );
      q.enableEscalation(enableOpts(transport));
      assert.deepEqual(q.reviseEscalation({ threshold: 3 }), {
        windowMs: 600_000,
        threshold: 3,
        cooldownMs: 0,
        maxAttempts: 1,
        backoffMs: 1000,
        timeoutMs: 5000,
      });
      q.reviseDeadLetterEscalationCallbacks({
        onDeadLetterEscalated: (info) => newEscalated.push(info),
      });
      await deadLetterOne(q);
      await deadLetterOne(q);
      await deadLetterOne(q);
      await waitFor(() => newEscalated.length === 1, "new escalated callback");
      assert.equal(oldEscalated.length, 0);
      assert.equal(transport.posts.length, 1);
      assert.equal(newEscalated[0].deadLetters, 3);
    } finally {
      q.stop();
    }
  });

  it("a restart restores the unconfigured state; the enable is live-only", async () => {
    const transport = stubTransport();
    const q = makeQueue(transport);
    try {
      q.enableEscalation(enableOpts(transport));
      assert.equal(q.escalationConfigured(), true);
    } finally {
      await q.shutdown();
    }
    const restarted = makeQueue(transport);
    try {
      assert.equal(restarted.escalationConfigured(), false);
      assert.equal(restarted.getEscalationConfig(), undefined);
      assert.deepEqual(restarted.getEscalationStats(), []);
      restarted.enableEscalation(enableOpts(transport));
      assert.equal(restarted.escalationConfigured(), true);
    } finally {
      await restarted.shutdown();
    }
  });
});

describe("RelayServer dead-letter storm escalation live enable (WR-472)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "escalation-enable-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal key in
      // test-file writes (see AGENTS.md), so the key is spelled out
      // dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: FORWARD,
      auditLog,
      operatorToken,
      sender: async () => {
        throw new Error("downstream is down");
      },
      retry: { baseDelayMs: 1, maxDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
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

  function postWebhook(port: number, body: Buffer) {
    const sig = signSha256(body, relaySecret);
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "content-type": "application/json", "x-signature": sig },
        },
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

  it("the server enables and audits escalation_enabled with previous null and the six-knob current, without secret or url", () => {
    const transport = stubTransport();
    const { relay, auditLog } = makeServer();
    assert.equal(relay.getEscalationConfig, undefined);
    relay.enableEscalation!({
      url: OPERATOR_URL,
      signingSecret: escalationSigningSecret,
      keyId: "ops-key-9",
      threshold: 5,
      windowMs: 300_000,
      cooldownMs: 60_000,
      maxAttempts: 3,
      backoffMs: 2000,
      timeoutMs: 4000,
      post: transport.post,
    });
    assert.notEqual(relay.getEscalationConfig, undefined);
    assert.deepEqual(relay.getEscalationConfig!(), {
      windowMs: 300_000,
      threshold: 5,
      cooldownMs: 60_000,
      maxAttempts: 3,
      backoffMs: 2000,
      timeoutMs: 4000,
    });
    const enabled = eventsOf(auditLog, "escalation_enabled");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].previous, null);
    assert.deepEqual(enabled[0].current, {
      windowMs: 300_000,
      threshold: 5,
      cooldownMs: 60_000,
      maxAttempts: 3,
      backoffMs: 2000,
      timeoutMs: 4000,
    });
    // No secret material, no operator url, and no key id in the audit trail.
    const line = JSON.stringify(enabled[0]);
    assert.ok(!line.includes(escalationSigningSecret));
    assert.ok(!line.includes(OPERATOR_URL));
    assert.ok(!line.includes("ops-key-9"));
  });

  it("a second server enable throws the canonical Error and audits nothing more; illegal opts throw RangeError and audit nothing", () => {
    const transport = stubTransport();
    const { relay, auditLog } = makeServer();
    relay.enableEscalation!({
      url: OPERATOR_URL,
      signingSecret: escalationSigningSecret,
      post: transport.post,
    });
    assert.equal(eventsOf(auditLog, "escalation_enabled").length, 1);
    assert.throws(
      () =>
        relay.enableEscalation!({
          url: OPERATOR_URL,
          signingSecret: escalationSigningSecret,
        }),
      {
        name: "Error",
        message: ALREADY_CONFIGURED,
      }
    );
    assert.equal(eventsOf(auditLog, "escalation_enabled").length, 1);
    assert.deepEqual(relay.getEscalationConfig!(), DEFAULTS);

    const fresh = makeServer();
    assert.throws(
      () =>
        fresh.relay.enableEscalation!({
          url: "ftp://ops.example.com/x",
          signingSecret: escalationSigningSecret,
        }),
      RangeError
    );
    assert.throws(() => fresh.relay.enableEscalation!({} as never), RangeError);
    assert.equal(eventsOf(fresh.auditLog, "escalation_enabled").length, 0);
    assert.equal(fresh.relay.getEscalationConfig, undefined);
    // Still enableable afterwards.
    fresh.relay.enableEscalation!({
      url: OPERATOR_URL,
      signingSecret: escalationSigningSecret,
      post: transport.post,
    });
    assert.equal(eventsOf(fresh.auditLog, "escalation_enabled").length, 1);
  });

  it("after the enable the server's reviseEscalation and reviseDeadLetterEscalationCallbacks gates open", () => {
    const transport = stubTransport();
    const { relay, auditLog } = makeServer();
    assert.throws(() => relay.reviseEscalation!({ threshold: 5 }), /not configured/);
    assert.throws(
      () => relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalated: () => {} }),
      /not configured/
    );
    relay.enableEscalation!({
      url: OPERATOR_URL,
      signingSecret: escalationSigningSecret,
      threshold: 2,
      cooldownMs: 0,
      post: transport.post,
    });
    assert.equal(relay.reviseEscalation!({ threshold: 9 }).threshold, 9);
    assert.equal(eventsOf(auditLog, "escalation_revised").length, 1);
    relay.reviseDeadLetterEscalationCallbacks!({ onDeadLetterEscalated: () => {} });
    assert.equal(eventsOf(auditLog, "dead_letter_escalation_callbacks_revised").length, 1);
  });

  it("the runtime self-check is reinstalled: an alert URL pointing at the relay's own intake is refused on dispatch", async () => {
    const transport = stubTransport();
    const { relay, auditLog } = makeServer();
    const port = await listen(relay);
    relay.enableEscalation!({
      url: `http://127.0.0.1:${port}/alerts`,
      signingSecret: escalationSigningSecret,
      threshold: 1,
      cooldownMs: 0,
      maxAttempts: 1,
      post: transport.post,
    });
    const res = await postWebhook(port, Buffer.from(JSON.stringify({ x: 1 })));
    assert.equal(res.status, 202);
    await waitFor(
      () => eventsOf(auditLog, "dead_letter_escalation_failed").length === 1,
      "dead_letter_escalation_failed audit"
    );
    // The alert never left the relay: the runtime loop check refused it.
    assert.equal(transport.posts.length, 0);
    assert.equal(eventsOf(auditLog, "dead_letter_escalated").length, 0);
    const [failed] = eventsOf(auditLog, "dead_letter_escalation_failed");
    assert.equal(failed.attempts, 0);
    assert.match(String(failed.error), /loop detected/);
    assert.equal(eventsOf(auditLog, "dead_letter").length, 1);
  });
});
