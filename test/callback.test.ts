import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  createBoundAddressSelfCheck,
  isSelfCallbackTarget,
  resolveCompletionCallbackConfig,
  type CallbackPostResult,
  type CompletionCallbackFailedInfo,
  type CompletionReceipt,
} from "../src/callback.ts";
import { deriveIdempotencyKey, IDEMPOTENCY_KEY_HEADER } from "../src/idempotency-key.ts";
import { TRACE_ID_HEADER } from "../src/trace.ts";

const SIGNING_SECRET = "callback-signing-secret";
const IDEM_SECRET = "callback-idempotency-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

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

/** Captures receipt POSTs without touching the network. */
function stubTransport() {
  const posts: Array<{ url: string; body: Buffer; headers: Record<string, string> }> = [];
  return {
    posts,
    post: async (url: string, body: Buffer, headers: Record<string, string>): Promise<CallbackPostResult> => {
      posts.push({ url, body, headers });
      return { statusCode: 200 };
    },
  };
}

function receiptOf(post: { body: Buffer }): CompletionReceipt {
  return JSON.parse(post.body.toString("utf8")) as CompletionReceipt;
}

describe("WR-47 resolveCompletionCallbackConfig", () => {
  it("is off by default (undefined when unset)", () => {
    assert.equal(resolveCompletionCallbackConfig(undefined), undefined);
  });

  it("rejects a non-URL, a non-http(s) URL, and an empty URL", () => {
    assert.throws(() => resolveCompletionCallbackConfig({ url: "not a url" }), RangeError);
    assert.throws(() => resolveCompletionCallbackConfig({ url: "ftp://x/y" }), RangeError);
    assert.throws(() => resolveCompletionCallbackConfig({ url: "" }), RangeError);
  });

  it("rejects a callback URL targeting a declared self origin (config-time loop check)", () => {
    assert.throws(
      () =>
        resolveCompletionCallbackConfig({
          url: "http://127.0.0.1:8080/callback",
          selfOrigins: ["http://127.0.0.1:8080"],
        }),
      /own inbound origin/
    );
    // A different origin passes.
    const cfg = resolveCompletionCallbackConfig({
      url: "http://127.0.0.1:8080/callback",
      selfOrigins: ["http://127.0.0.1:9090"],
    });
    assert.ok(cfg);
  });

  it("rejects bad selfOrigins values", () => {
    assert.throws(
      () => resolveCompletionCallbackConfig({ url: "http://x/cb", selfOrigins: "nope" as never }),
      RangeError
    );
  });

  it("caps maxAttempts at 3 and validates the numeric knobs", () => {
    assert.throws(() => resolveCompletionCallbackConfig({ url: "http://x/cb", maxAttempts: 4 }), RangeError);
    assert.throws(() => resolveCompletionCallbackConfig({ url: "http://x/cb", maxAttempts: 0 }), RangeError);
    assert.throws(() => resolveCompletionCallbackConfig({ url: "http://x/cb", backoffMs: -1 }), RangeError);
    assert.throws(() => resolveCompletionCallbackConfig({ url: "http://x/cb", timeoutMs: 0 }), RangeError);
    assert.throws(
      () => resolveCompletionCallbackConfig({ url: "http://x/cb", signingSecret: "" }),
      RangeError
    );
    assert.throws(
      () => resolveCompletionCallbackConfig({ url: "http://x/cb", idempotencySecret: "" }),
      RangeError
    );
    const cfg = resolveCompletionCallbackConfig({ url: "http://x/cb" });
    assert.equal(cfg?.maxAttempts, 3);
    assert.equal(cfg?.backoffMs, 500);
    assert.equal(cfg?.timeoutMs, 5000);
  });
});

describe("WR-47 isSelfCallbackTarget / createBoundAddressSelfCheck", () => {
  it("matches on origin (scheme+host+port), not path", () => {
    assert.equal(isSelfCallbackTarget("http://127.0.0.1:8080/cb", ["http://127.0.0.1:8080/other"]), true);
    assert.equal(isSelfCallbackTarget("http://127.0.0.1:8080/cb", ["http://127.0.0.1:9090"]), false);
    assert.equal(isSelfCallbackTarget("https://127.0.0.1:8080/cb", ["http://127.0.0.1:8080"]), false);
  });

  it("flags loopback URLs on the bound port when listening on all interfaces", () => {
    const check = createBoundAddressSelfCheck(() => ({ address: "0.0.0.0", port: 8080 }));
    assert.equal(check("http://localhost:8080/cb"), true);
    assert.equal(check("http://127.0.0.1:8080/cb"), true);
    assert.equal(check("http://127.0.0.1:9090/cb"), false);
    assert.equal(check("http://example.com:8080/cb"), false);
  });

  it("flags the bound address itself", () => {
    const check = createBoundAddressSelfCheck(() => ({ address: "192.168.1.5", port: 8080 }));
    assert.equal(check("http://192.168.1.5:8080/cb"), true);
    assert.equal(check("http://192.168.1.5:9090/cb"), false);
    assert.equal(check("http://localhost:8080/cb"), false);
  });

  it("is inert for unix sockets, unlistened servers, and unparsable URLs", () => {
    assert.equal(createBoundAddressSelfCheck(() => "/tmp/relay.sock")("http://127.0.0.1:8080/cb"), false);
    assert.equal(createBoundAddressSelfCheck(() => null)("http://127.0.0.1:8080/cb"), false);
    const check = createBoundAddressSelfCheck(() => ({ address: "0.0.0.0", port: 8080 }));
    assert.equal(check("::not a url::"), false);
  });
});

describe("WR-47 queue-level receipts", () => {
  it("POSTs a signed receipt on delivered (traceId + signature + idempotency key)", async () => {
    const stub = stubTransport();
    const failed: CompletionCallbackFailedInfo[] = [];
    const sender: Sender = async () => undefined; // success
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      jitterMs: 0,
      completionCallback: {
        url: "http://caller.example/receipts",
        signingSecret: SIGNING_SECRET,
        keyId: "k1",
        idempotencySecret: IDEM_SECRET,
        keyPrefix: "cb-",
        post: stub.post,
      },
      onCompletionCallbackFailed: (info) => failed.push(info),
    });
    q.start();
    try {
      q.enqueue({ id: "evt-1", traceId: "tid-1", payload: BODY, targetUrl: "http://down/hook", headers: {} });
      await waitFor(() => stub.posts.length === 1, "receipt POST");
      const post = stub.posts[0];
      assert.equal(post.url, "http://caller.example/receipts");
      const receipt = receiptOf(post);
      assert.equal(receipt.id, "evt-1");
      assert.equal(receipt.traceId, "tid-1");
      assert.equal(receipt.targetUrl, "http://down/hook");
      assert.equal(receipt.terminalState, "delivered");
      assert.equal(receipt.attempts, 1);
      assert.ok(typeof receipt.at === "string");
      assert.equal(receipt.error, undefined);
      // Headers: trace echo, WR-26-style signature, WR-44-style idempotency key.
      assert.equal(post.headers[TRACE_ID_HEADER], "tid-1");
      assert.equal(post.headers["content-type"], "application/json");
      assert.equal(post.headers["x-relay-signature"], signSha256(post.body, SIGNING_SECRET));
      assert.equal(post.headers["x-relay-key-id"], "k1");
      assert.equal(
        post.headers[IDEMPOTENCY_KEY_HEADER],
        deriveIdempotencyKey(IDEM_SECRET, "evt-1", 1, "cb-")
      );
      assert.equal(failed.length, 0);
    } finally {
      q.stop();
    }
  });

  it("POSTs a dead_letter receipt with the failure error", async () => {
    const stub = stubTransport();
    const sender: Sender = async () => {
      throw new Error("downstream exploded");
    };
    const q = new RetryQueue({
      sender,
      maxAttempts: 1,
      baseDelayMs: 10,
      maxDelayMs: 50,
      jitterMs: 0,
      completionCallback: { url: "http://caller.example/receipts", post: stub.post },
    });
    q.start();
    try {
      q.enqueue({ id: "evt-9", traceId: "tid-9", payload: BODY, targetUrl: "http://down/hook", headers: {} });
      await waitFor(() => stub.posts.length === 1, "dead-letter receipt POST");
      const receipt = receiptOf(stub.posts[0]);
      assert.equal(receipt.terminalState, "dead_letter");
      assert.equal(receipt.error, "downstream exploded");
      assert.equal(receipt.attempts, 1);
      // No signature/idempotency headers when no secrets are configured.
      assert.equal(stub.posts[0].headers["x-relay-signature"], undefined);
      assert.equal(stub.posts[0].headers[IDEMPOTENCY_KEY_HEADER], undefined);
    } finally {
      q.stop();
    }
  });

  it("retries a failing receipt at most maxAttempts times, then reports failure — never enqueues", async () => {
    let calls = 0;
    const failed: CompletionCallbackFailedInfo[] = [];
    const sender: Sender = async () => undefined;
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      jitterMs: 0,
      completionCallback: {
        url: "http://caller.example/receipts",
        maxAttempts: 3,
        backoffMs: 5,
        post: async () => {
          calls += 1;
          return { statusCode: 500 };
        },
      },
      onCompletionCallbackFailed: (info) => failed.push(info),
    });
    q.start();
    try {
      q.enqueue({ id: "evt-2", traceId: "tid-2", payload: BODY, targetUrl: "http://down/hook", headers: {} });
      await waitFor(() => failed.length === 1, "callback_failed report");
      assert.equal(calls, 3);
      const info = failed[0];
      assert.equal(info.id, "evt-2");
      assert.equal(info.traceId, "tid-2");
      assert.equal(info.terminalState, "delivered");
      assert.equal(info.attempts, 3);
      assert.match(info.error, /unexpected status 500/);
      // The failed receipt never entered the retry queue: the original
      // delivery is done and no new queue/dead-letter artifacts exist.
      assert.equal(q.getDeadLetter().length, 0);
    } finally {
      q.stop();
    }
  });

  it("refuses to POST when the runtime self-check flags a loop", async () => {
    let calls = 0;
    const failed: CompletionCallbackFailedInfo[] = [];
    const sender: Sender = async () => undefined;
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      jitterMs: 0,
      completionCallback: {
        url: "http://127.0.0.1:8080/callback",
        post: async () => {
          calls += 1;
          return { statusCode: 200 };
        },
      },
      onCompletionCallbackFailed: (info) => failed.push(info),
    });
    q.setCompletionCallbackSelfCheck(() => true); // the relay itself
    q.start();
    try {
      q.enqueue({ id: "evt-3", traceId: "tid-3", payload: BODY, targetUrl: "http://down/hook", headers: {} });
      await waitFor(() => failed.length === 1, "loop refusal report");
      assert.equal(calls, 0);
      assert.match(failed[0].error, /loop detected/);
      assert.equal(failed[0].attempts, 0);
    } finally {
      q.stop();
    }
  });

  it("is inert when not configured", async () => {
    const sender: Sender = async () => undefined;
    const q = new RetryQueue({ sender, baseDelayMs: 10, maxDelayMs: 50, jitterMs: 0 });
    q.start();
    try {
      q.enqueue({ id: "evt-4", traceId: "tid-4", payload: BODY, targetUrl: "http://down/hook", headers: {} });
      await new Promise((r) => setTimeout(r, 150));
      // Nothing to observe directly — the point is no throw and no timers
      // left behind; stop() must be clean.
    } finally {
      q.stop();
    }
  });

  it("uses the (id, callback attempt) for the idempotency key across receipt retries", async () => {
    const keys: Array<string | undefined> = [];
    const sender: Sender = async () => undefined;
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      jitterMs: 0,
      completionCallback: {
        url: "http://caller.example/receipts",
        idempotencySecret: IDEM_SECRET,
        maxAttempts: 2,
        backoffMs: 5,
        post: async (_url, _body, headers) => {
          keys.push(headers[IDEMPOTENCY_KEY_HEADER]);
          return { statusCode: 503 };
        },
      },
      onCompletionCallbackFailed: () => {},
    });
    q.start();
    try {
      q.enqueue({ id: "evt-5", traceId: "tid-5", payload: BODY, targetUrl: "http://down/hook", headers: {} });
      await waitFor(() => keys.length === 2, "two receipt attempts");
      assert.equal(keys[0], deriveIdempotencyKey(IDEM_SECRET, "evt-5", 1));
      assert.equal(keys[1], deriveIdempotencyKey(IDEM_SECRET, "evt-5", 2));
    } finally {
      q.stop();
    }
  });
});

describe("WR-47 server-level", () => {
  let dir: string;
  let auditLog: AuditLog;
  let relay: Server;
  let relayPort: number;
  let downstream: Server;
  let callbackServer: Server;
  let receipts: Array<{ body: Buffer; headers: Record<string, string | string[] | undefined> }>;

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "wr47-"));
    auditLog = new AuditLog(join(dir, "audit.jsonl"));
    downstream = createServer((req, res) => {
      res.writeHead(200, { "content-type": "text/plain" }).end("ok");
    });
    const downstreamPort = await listen(downstream);
    receipts = [];
    callbackServer = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        receipts.push({ body: Buffer.concat(chunks), headers: { ...req.headers } });
        res.writeHead(200).end("ack");
      });
    });
    const callbackPort = await listen(callbackServer);
    relay = createRelayServer({
      secret: "inbound-secret",
      forwardUrl: `http://127.0.0.1:${downstreamPort}/hook`,
      auditLog,
      operatorToken: "op",
      completionCallback: {
        url: `http://127.0.0.1:${callbackPort}/receipts`,
        signingSecret: SIGNING_SECRET,
        idempotencySecret: IDEM_SECRET,
      },
    });
    relayPort = await listen(relay);
  });

  after(async () => {
    await new Promise<void>((r) => relay.close(() => r()));
    await new Promise<void>((r) => downstream.close(() => r()));
    await new Promise<void>((r) => callbackServer.close(() => r()));
  });

  it("delivers the event downstream and POSTs the receipt end to end", async () => {
    const { request } = await import("node:http");
    const payload = JSON.stringify({ order: "pay-1" });
    const sig = signSha256(Buffer.from(payload), "inbound-secret");
    await new Promise<void>((resolve, reject) => {
      const req = request(
        {
          method: "POST",
          hostname: "127.0.0.1",
          port: relayPort,
          path: "/",
          headers: { "content-type": "application/json", "x-signature": sig },
        },
        (res) => {
          res.resume();
          res.on("end", () => (res.statusCode === 202 ? resolve() : reject(new Error(`status ${res.statusCode}`))));
        }
      );
      req.on("error", reject);
      req.end(payload);
    });
    await waitFor(() => receipts.length === 1, "end-to-end receipt");
    const receipt = JSON.parse(receipts[0].body.toString("utf8")) as CompletionReceipt;
    assert.equal(receipt.terminalState, "delivered");
    assert.equal(receipt.attempts, 1);
    assert.ok(receipt.traceId);
    assert.equal(receipts[0].headers["x-trace-id"], receipt.traceId);
    assert.equal(
      receipts[0].headers["x-relay-signature"],
      signSha256(receipts[0].body, SIGNING_SECRET)
    );
    assert.equal(
      receipts[0].headers[IDEMPOTENCY_KEY_HEADER],
      deriveIdempotencyKey(IDEM_SECRET, receipt.id, 1)
    );
    // The audit trail shows the delivery but no callback failure.
    const events = auditLog.query({ event: "callback_failed" });
    assert.equal(events.length, 0);
    assert.ok(auditLog.query({ event: "delivered" }).length >= 1);
  });

  it("rejects a self-targeting callback URL at server construction (config-time)", () => {
    assert.throws(
      () =>
        createRelayServer({
          secret: "s",
          forwardUrl: "http://127.0.0.1:9/hook",
          auditLog,
          completionCallback: {
            url: "http://127.0.0.1:8080/receipts",
            selfOrigins: ["http://127.0.0.1:8080"],
          },
        }),
      /own inbound origin/
    );
  });
});

describe("WR-47 callback_failed audit", () => {
  it("audits callback_failed after 3 failed receipt attempts and never re-enqueues", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wr47-fail-"));
    const log = new AuditLog(join(dir, "audit.jsonl"));
    // Port 1 is (practically) never listening: every receipt POST fails fast.
    const relay = createRelayServer({
      secret: "inbound-secret",
      forwardUrl: "http://127.0.0.1:1/hook",
      sender: async () => undefined, // downstream "succeeds" so the receipt path is what fails
      auditLog: log,
      operatorToken: "op",
      completionCallback: {
        url: "http://127.0.0.1:1/receipts",
        maxAttempts: 3,
        backoffMs: 5,
        timeoutMs: 500,
      },
    });
    const port = await listen(relay);
    try {
      const { request } = await import("node:http");
      const payload = JSON.stringify({ x: 1 });
      const sig = signSha256(Buffer.from(payload), "inbound-secret");
      await new Promise<void>((resolve, reject) => {
        const req = request(
          {
            method: "POST",
            hostname: "127.0.0.1",
            port,
            path: "/",
            headers: { "content-type": "application/json", "x-signature": sig },
          },
          (res) => {
            res.resume();
            res.on("end", () => (res.statusCode === 202 ? resolve() : reject(new Error(`status ${res.statusCode}`))));
          }
        );
        req.on("error", reject);
        req.end(payload);
      });
      await waitFor(() => log.query({ event: "callback_failed" }).length === 1, "callback_failed audit");
      const [failed] = log.query({ event: "callback_failed" }) as Array<Record<string, unknown>>;
      assert.equal(failed.terminalState, "delivered");
      assert.equal(failed.attempts, 3);
      assert.ok(typeof failed.error === "string" && failed.error.length > 0);
      // The failed receipt never re-entered intake: exactly one accepted event.
      assert.equal(log.query({ event: "accepted" }).length, 1);
    } finally {
      await new Promise<void>((r) => relay.close(() => r()));
    }
  });
});
