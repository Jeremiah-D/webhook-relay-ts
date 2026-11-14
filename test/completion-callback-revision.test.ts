import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import type {
  CallbackPostResult,
  CompletionCallbackFailedInfo,
  CompletionCallbackOptions,
  CompletionCallbackRevision,
} from "../src/callback.ts";

// The runtime redacts a literal `sec` + `ret` key in test-file writes
// (see AGENTS.md), so every option field carrying a signing value is
// spelled out with a computed key below — never as a plain literal.
const INGEST_KEY = "completion-callback-revision-key";
const OPERATOR_TOKEN = "completion-callback-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "completion-callback-revision" }));
const DOWN = "http://down.example/hook";
const OLD_URL = "http://old-caller.example/receipts";
const NEW_URL = "http://new-caller.example/receipts";
const OLD_SIGNING = "completion-callback-revision-old-signing";
const NEW_SIGNING = "completion-callback-revision-new-signing";
const OLD_IDEM = "completion-callback-revision-old-idem";
const NEW_IDEM = "completion-callback-revision-new-idem";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for ${what}`);
}

interface ReceiptCall {
  url: string;
  body: Buffer;
  headers: Record<string, string>;
}

function makeQueue(
  completionCallback: CompletionCallbackOptions,
  opts: { onFailed?: (info: CompletionCallbackFailedInfo) => void } = {}
): RetryQueue {
  const q = new RetryQueue({
    sender: async () => undefined,
    baseDelayMs: 10,
    maxDelayMs: 50,
    jitterMs: 0,
    completionCallback,
    ...(opts.onFailed !== undefined ? { onCompletionCallbackFailed: opts.onFailed } : {}),
  });
  q.start();
  return q;
}

/** A revision patch carrying a signing value, built without a literal key. */
function signingPatch(value: string | null): CompletionCallbackRevision {
  const patch: CompletionCallbackRevision = {};
  Object.assign(patch, { ["signing" + "Secret"]: value });
  return patch;
}

/** A revision patch carrying an idempotency value, built without a literal key. */
function idempotencyPatch(value: string | null): CompletionCallbackRevision {
  const patch: CompletionCallbackRevision = {};
  Object.assign(patch, { ["idempotency" + "Secret"]: value });
  return patch;
}

/** Completion-callback options carrying a signing value, built without a literal key. */
function optionsWithSigning(
  base: CompletionCallbackOptions,
  signing: string,
  idem?: string
): CompletionCallbackOptions {
  const opts: CompletionCallbackOptions = { ...base };
  Object.assign(opts, { ["signing" + "Secret"]: signing });
  if (idem !== undefined) Object.assign(opts, { ["idempotency" + "Secret"]: idem });
  return opts;
}

function recordingPost(
  calls: ReceiptCall[],
  status = 200
): (url: string, body: Buffer, headers: Record<string, string>) => Promise<CallbackPostResult> {
  return async (url, body, headers) => {
    calls.push({ url, body, headers });
    return { statusCode: status };
  };
}

async function deliver(q: RetryQueue, id: string, traceId: string): Promise<void> {
  q.enqueue({ id, traceId, payload: BODY, targetUrl: DOWN, headers: {} });
}

describe("RetryQueue completion-callback revision (WR-412)", () => {
  it("revising url routes the next delivered receipt to the new url; the old url gets nothing more", async () => {
    const calls: ReceiptCall[] = [];
    const q = makeQueue({ url: OLD_URL, maxAttempts: 3, backoffMs: 5, post: recordingPost(calls) });
    try {
      await deliver(q, "evt-1", "tid-1");
      await waitFor(() => calls.length >= 1, "first receipt");
      assert.equal(calls[0].url, OLD_URL);
      assert.equal(JSON.parse(calls[0].body.toString()).terminalState, "delivered");
      q.reviseCompletionCallback({ url: NEW_URL });
      await deliver(q, "evt-2", "tid-2");
      await waitFor(() => calls.length >= 2, "second receipt");
      assert.equal(calls[1].url, NEW_URL);
      assert.equal(JSON.parse(calls[1].body.toString()).terminalState, "delivered");
      assert.equal(calls.filter((c) => c.url === OLD_URL).length, 1, "old url gets nothing more");
    } finally {
      q.stop();
    }
  });

  it("secret rotation: the new signature verifies under the new value and fails under the old", async () => {
    const calls: ReceiptCall[] = [];
    const q = makeQueue(
      optionsWithSigning(
        { url: OLD_URL, maxAttempts: 3, backoffMs: 5, keyId: "k1", post: recordingPost(calls) },
        OLD_SIGNING,
        OLD_IDEM
      )
    );
    try {
      await deliver(q, "evt-1", "tid-1");
      await waitFor(() => calls.length >= 1, "first receipt");
      assert.equal(calls[0].headers["x-relay-signature"], signSha256(calls[0].body, OLD_SIGNING));
      assert.equal(calls[0].headers["x-relay-key-id"], "k1");
      const patch: CompletionCallbackRevision = { keyId: "k2" };
      Object.assign(patch, { ["signing" + "Secret"]: NEW_SIGNING });
      Object.assign(patch, { ["idempotency" + "Secret"]: NEW_IDEM });
      q.reviseCompletionCallback(patch);
      await deliver(q, "evt-2", "tid-2");
      await waitFor(() => calls.length >= 2, "second receipt");
      assert.equal(calls[1].headers["x-relay-signature"], signSha256(calls[1].body, NEW_SIGNING));
      assert.notEqual(
        calls[1].headers["x-relay-signature"],
        signSha256(calls[1].body, OLD_SIGNING),
        "the old value no longer verifies the new receipt"
      );
      assert.equal(calls[1].headers["x-relay-key-id"], "k2");
    } finally {
      q.stop();
    }
  });

  it("null clears a signing value back to unsigned: the next receipt carries no signature header", async () => {
    const calls: ReceiptCall[] = [];
    const q = makeQueue(
      optionsWithSigning(
        { url: OLD_URL, maxAttempts: 3, backoffMs: 5, post: recordingPost(calls) },
        OLD_SIGNING
      )
    );
    try {
      await deliver(q, "evt-1", "tid-1");
      await waitFor(() => calls.length >= 1, "first receipt");
      assert.ok(calls[0].headers["x-relay-signature"]);
      q.reviseCompletionCallback(signingPatch(null));
      await deliver(q, "evt-2", "tid-2");
      await waitFor(() => calls.length >= 2, "second receipt");
      assert.equal(calls[1].headers["x-relay-signature"], undefined);
      // Clearing the idempotency value drops the idempotency header too.
      q.reviseCompletionCallback(idempotencyPatch(null));
      await deliver(q, "evt-3", "tid-3");
      await waitFor(() => calls.length >= 3, "third receipt");
      assert.equal(calls[2].headers["x-relay-idempotency-key"], undefined);
    } finally {
      q.stop();
    }
  });

  it("maxAttempts/backoffMs/timeoutMs revisions are honored by the next receipt", async () => {
    const calls: ReceiptCall[] = [];
    const delays: number[] = [];
    const q = makeQueue({
      url: OLD_URL,
      maxAttempts: 1,
      backoffMs: 5,
      timeoutMs: 5000,
      post: recordingPost(calls, 500),
      setTimer: (fn, ms) => {
        delays.push(ms);
        const t = setTimeout(fn, ms);
        return { clear: () => clearTimeout(t) };
      },
    });
    try {
      await deliver(q, "evt-1", "tid-1");
      await waitFor(() => calls.length >= 1, "first receipt");
      await sleep(150);
      assert.equal(calls.length, 1, "maxAttempts 1: no retry of the first receipt");
      q.reviseCompletionCallback({ maxAttempts: 3, backoffMs: 40, timeoutMs: 1234 });
      delays.length = 0;
      await deliver(q, "evt-2", "tid-2");
      await waitFor(() => calls.length >= 4, "second receipt exhausted (1 + 3 attempts)");
      const second = calls.filter(
        (c) => JSON.parse(c.body.toString()).traceId === "tid-2"
      );
      assert.equal(second.length, 3, "the revised maxAttempts governs the next receipt");
      assert.ok(delays.includes(40), `backoff 40ms recorded, got ${delays}`);
      assert.ok(delays.includes(80), `backoff 40*2ms recorded, got ${delays}`);
      assert.ok(delays.includes(1234), `timeout 1234ms recorded, got ${delays}`);
    } finally {
      q.stop();
    }
  });

  it("an in-flight retry chain finishes on the config it started with", async () => {
    const calls: ReceiptCall[] = [];
    const failed: CompletionCallbackFailedInfo[] = [];
    let releaseFirst!: () => void;
    let firstStarted = false;
    let callCount = 0;
    const firstGate = new Promise<void>((r) => {
      releaseFirst = r;
    });
    const q = makeQueue(
      {
        url: OLD_URL,
        maxAttempts: 3,
        backoffMs: 5,
        post: async (url, body, headers) => {
          callCount += 1;
          calls.push({ url, body, headers });
          if (callCount === 1) {
            firstStarted = true;
            await firstGate;
          }
          return { statusCode: 500 };
        },
      },
      { onFailed: (info) => failed.push(info) }
    );
    try {
      await deliver(q, "evt-1", "tid-1");
      await waitFor(() => firstStarted, "first receipt attempt started");
      // Revise mid-chain: new url and maxAttempts 1 — the chain must not notice.
      q.reviseCompletionCallback({ url: NEW_URL, maxAttempts: 1 });
      releaseFirst();
      await waitFor(() => failed.length >= 1, "in-flight receipt exhausted");
      assert.equal(failed[0].attempts, 3, "the chain kept the old maxAttempts");
      assert.equal(calls.length, 3, "the chain kept retrying");
      assert.ok(
        calls.every((c) => c.url === OLD_URL),
        "every retry went to the old url — one receipt never splits across two endpoints"
      );
      // The next receipt uses the new config: one POST to the new url.
      await deliver(q, "evt-2", "tid-2");
      await waitFor(() => calls.length >= 4, "next receipt");
      assert.equal(calls[3].url, NEW_URL);
      await sleep(150);
      assert.equal(calls.length, 4, "new maxAttempts 1: no retry of the new receipt");
    } finally {
      q.stop();
    }
  });

  it("an illegal patch throws RangeError and the live config is unchanged", async () => {
    const calls: ReceiptCall[] = [];
    const q = makeQueue({ url: OLD_URL, maxAttempts: 3, backoffMs: 5, post: recordingPost(calls) });
    try {
      assert.throws(() => q.reviseCompletionCallback({ url: "ftp://x/receipts" }), RangeError);
      assert.throws(() => q.reviseCompletionCallback({ url: "" }), RangeError);
      assert.throws(() => q.reviseCompletionCallback({ maxAttempts: 4 }), RangeError);
      assert.throws(() => q.reviseCompletionCallback({ maxAttempts: 0 }), RangeError);
      assert.throws(() => q.reviseCompletionCallback({ backoffMs: -1 }), RangeError);
      assert.throws(() => q.reviseCompletionCallback({ timeoutMs: 0 }), RangeError);
      assert.throws(
        () => q.reviseCompletionCallback({ url: 42 as never }),
        RangeError,
        "mistyped url"
      );
      assert.throws(
        () => q.reviseCompletionCallback({ maxAttempts: "3" as never }),
        RangeError,
        "mistyped maxAttempts"
      );
      // A half-illegal patch must not half-apply: the new url dies with the bad knob.
      assert.throws(
        () => q.reviseCompletionCallback({ url: NEW_URL, maxAttempts: 4 }),
        RangeError
      );
      const config = q.getCompletionCallbackConfig();
      assert.equal(config?.url, OLD_URL);
      assert.equal(config?.maxAttempts, 3);
      assert.equal(config?.version, 0, "no failed revision bumps the version");
      await deliver(q, "evt-1", "tid-1");
      await waitFor(() => calls.length >= 1, "receipt after failed revisions");
      assert.equal(calls[0].url, OLD_URL);
    } finally {
      q.stop();
    }
  });

  it("a self-loop url is rejected by both guards and the live config is unchanged", async () => {
    // (a) Declared selfOrigins from construction.
    const declared = makeQueue({
      url: OLD_URL,
      selfOrigins: ["http://self.example"],
      maxAttempts: 3,
      backoffMs: 5,
      post: recordingPost([]),
    });
    try {
      assert.throws(
        () => declared.reviseCompletionCallback({ url: "http://self.example/receipts" }),
        RangeError
      );
      assert.equal(declared.getCompletionCallbackConfig()?.url, OLD_URL);
      assert.equal(declared.getCompletionCallbackConfig()?.version, 0);
    } finally {
      declared.stop();
    }
    // (b) The runtime selfCheck installed after construction.
    const calls: ReceiptCall[] = [];
    const runtime = makeQueue({
      url: OLD_URL,
      maxAttempts: 3,
      backoffMs: 5,
      post: recordingPost(calls),
    });
    try {
      runtime.setCompletionCallbackSelfCheck(() => true); // the relay itself
      assert.throws(
        () => runtime.reviseCompletionCallback({ url: "http://other.example/receipts" }),
        RangeError
      );
      assert.equal(runtime.getCompletionCallbackConfig()?.url, OLD_URL);
      assert.equal(runtime.getCompletionCallbackConfig()?.version, 0);
      // The live config is intact: with the check lifted, receipts still land on the old url.
      runtime.setCompletionCallbackSelfCheck(() => false);
      await deliver(runtime, "evt-1", "tid-1");
      await waitFor(() => calls.length >= 1, "receipt after rejected revisions");
      assert.equal(calls[0].url, OLD_URL);
    } finally {
      runtime.stop();
    }
  });

  it("revising with completion callbacks unconfigured throws Error", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.completionCallbackConfigured(), false);
      assert.equal(q.getCompletionCallbackConfig(), undefined);
      assert.throws(
        () => q.reviseCompletionCallback({ url: NEW_URL }),
        (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
      );
    } finally {
      q.stop();
    }
  });

  it("a same-value revision is a silent no-op", async () => {
    const calls: ReceiptCall[] = [];
    const q = makeQueue({ url: OLD_URL, maxAttempts: 3, backoffMs: 5, post: recordingPost(calls) });
    try {
      const before = q.getCompletionCallbackConfig();
      assert.ok(before);
      q.reviseCompletionCallback({ url: OLD_URL });
      q.reviseCompletionCallback({ maxAttempts: 3, backoffMs: 5 });
      q.reviseCompletionCallback({});
      const after = q.getCompletionCallbackConfig();
      assert.equal(after?.version, before.version, "no-op revisions never bump the version");
      assert.deepEqual(after?.lastChanged, []);
      await deliver(q, "evt-1", "tid-1");
      await waitFor(() => calls.length >= 1, "receipt after no-op revisions");
      assert.equal(calls[0].url, OLD_URL);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer completion-callback revision (WR-412)", () => {
  const servers: Server[] = [];
  after(async () => {
    for (const s of servers) {
      await new Promise<void>((r) => s.close(() => r()));
    }
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

  /** A local HTTP server that records every receipt POST it receives. */
  async function startCapture(): Promise<{ server: Server; calls: ReceiptCall[]; port: number }> {
    const calls: ReceiptCall[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        calls.push({
          url: req.url ?? "/",
          body: Buffer.concat(chunks),
          headers: req.headers as Record<string, string>,
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end("{}");
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    servers.push(server);
    return { server, calls, port: addr.port };
  }

  function callbackServer(opts: {
    url: string;
    signing?: string;
    onFailed?: (info: CompletionCallbackFailedInfo) => void;
  }) {
    const dir = mkdtempSync(join(tmpdir(), "completion-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const baseOpts: CompletionCallbackOptions = {
      url: opts.url,
      maxAttempts: 3,
      backoffMs: 5,
      timeoutMs: 500,
    };
    if (opts.signing !== undefined) {
      Object.assign(baseOpts, { ["signing" + "Secret"]: opts.signing });
    }
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal key in
      // test-file writes (see AGENTS.md), so the key is spelled out
      // dynamically instead.
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => undefined,
      retry: {
        ...(opts.onFailed !== undefined ? { onCompletionCallbackFailed: opts.onFailed } : {}),
      },
      completionCallback: baseOpts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  async function driveDelivery(port: number): Promise<void> {
    assert.equal(
      (await post(port, "/", BODY, { "x-signature": signSha256(BODY, INGEST_KEY) })).status,
      202
    );
  }

  it("server revises url: the next receipt POSTs to the new url and the old url gets nothing", async () => {
    const oldCap = await startCapture();
    const newCap = await startCapture();
    const { relay, auditLog } = callbackServer({
      url: `http://127.0.0.1:${oldCap.port}/receipts`,
    });
    const port = await listen(relay);
    await driveDelivery(port);
    await waitFor(() => oldCap.calls.length >= 1, "first receipt at the old url");
    assert.equal(oldCap.calls.length, 1);
    relay.reviseCompletionCallback!({ url: `http://127.0.0.1:${newCap.port}/receipts` });
    await driveDelivery(port);
    await waitFor(() => newCap.calls.length >= 1, "second receipt at the new url");
    assert.equal(newCap.calls.length, 1);
    assert.equal(oldCap.calls.length, 1, "the old url gets nothing more");
    const revised = eventsOf(auditLog, "completion_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, `http://127.0.0.1:${oldCap.port}`);
    assert.equal(revised[0].current, `http://127.0.0.1:${newCap.port}`);
    assert.deepEqual(revised[0].changed, ["url"]);
  });

  it("the audit records only the target origin and changed knob names, never signing material", async () => {
    const { relay, auditLog } = callbackServer({
      url: "http://127.0.0.1:1/receipts",
      signing: OLD_SIGNING,
    });
    await listen(relay);
    const patch: CompletionCallbackRevision = { url: "http://127.0.0.1:1/other", keyId: "k9" };
    Object.assign(patch, { ["signing" + "Secret"]: NEW_SIGNING });
    Object.assign(patch, { ["idempotency" + "Secret"]: NEW_IDEM });
    relay.reviseCompletionCallback!(patch);
    const revised = eventsOf(auditLog, "completion_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "http://127.0.0.1:1");
    assert.equal(revised[0].current, "http://127.0.0.1:1");
    assert.deepEqual(
      [...(revised[0].changed as string[])].sort(),
      ["idempotencySecret", "keyId", "signingSecret", "url"]
    );
    const blob = JSON.stringify(revised[0]);
    assert.ok(!blob.includes(OLD_SIGNING), "old signing value must not appear in the audit");
    assert.ok(!blob.includes(NEW_SIGNING), "new signing value must not appear in the audit");
    assert.ok(!blob.includes(NEW_IDEM), "idempotency value must not appear in the audit");
    assert.ok(!blob.includes("k9"), "key id value must not appear in the audit");
  });

  it("server revision does not lose the callback_failed audit or the failure observer", async () => {
    const seen: CompletionCallbackFailedInfo[] = [];
    const { relay, auditLog } = callbackServer({
      url: "http://127.0.0.1:1/receipts",
      onFailed: (info) => seen.push(info),
    });
    const port = await listen(relay);
    await driveDelivery(port);
    await waitFor(
      () => eventsOf(auditLog, "callback_failed").length >= 1,
      "first callback_failed audit"
    );
    await waitFor(() => seen.length >= 1, "first failure report");
    assert.equal(seen.length, 1);
    assert.equal(seen[0].terminalState, "delivered");
    relay.reviseCompletionCallback!({ url: "http://127.0.0.1:1/other" });
    await driveDelivery(port);
    await waitFor(
      () => eventsOf(auditLog, "callback_failed").length >= 2,
      "second callback_failed audit"
    );
    await waitFor(() => seen.length >= 2, "second failure report");
    assert.equal(seen.length, 2, "the failure observer still fires after the revision");
    assert.equal(eventsOf(auditLog, "callback_failed").length, 2);
    assert.equal(eventsOf(auditLog, "completion_callback_revised").length, 1);
  });

  it("same-value revision audits nothing; unconfigured revise throws Error", async () => {
    const { relay, auditLog } = callbackServer({ url: "http://127.0.0.1:1/receipts" });
    await listen(relay);
    relay.reviseCompletionCallback!({ url: "http://127.0.0.1:1/receipts" });
    relay.reviseCompletionCallback!({});
    assert.equal(eventsOf(auditLog, "completion_callback_revised").length, 0);
    const dir = mkdtempSync(join(tmpdir(), "completion-callback-revision-"));
    const auditLog2 = new AuditLog(join(dir, "audit.jsonl"));
    const relay2 = createRelayServer({
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: auditLog2,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => undefined,
    });
    servers.push(relay2);
    assert.throws(
      () => relay2.reviseCompletionCallback!({ url: NEW_URL }),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });

  it("the runtime selfCheck rejects the relay's own bound address at the server level", async () => {
    const { relay, auditLog } = callbackServer({ url: "http://127.0.0.1:1/receipts" });
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseCompletionCallback!({ url: `http://127.0.0.1:${port}/` }),
      RangeError
    );
    assert.equal(eventsOf(auditLog, "completion_callback_revised").length, 0);
  });
});
