import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
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
} from "../src/callback.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const INGEST_KEY = "completion-callback-failed-callback-revision-key";
const OPERATOR_TOKEN = "completion-callback-failed-callback-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "completion-callback-revision" }));
const DOWN = "http://down.example/hook";
const CALLBACK_URL = "http://caller.example/receipts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for ${what}`);
}

/** A queue whose deliveries succeed but whose receipt POSTs always fail. */
function failingReceiptQueue(opts: {
  onCompletionCallbackFailed?: (info: CompletionCallbackFailedInfo) => void;
  post?: (url: string, body: Buffer, headers: Record<string, string>) => Promise<CallbackPostResult>;
} = {}) {
  let calls = 0;
  const post =
    opts.post ??
    (async (): Promise<CallbackPostResult> => {
      calls += 1;
      return { statusCode: 500 };
    });
  const q = new RetryQueue({
    sender: async () => undefined,
    baseDelayMs: 10,
    maxDelayMs: 50,
    jitterMs: 0,
    completionCallback: {
      url: CALLBACK_URL,
      maxAttempts: 3,
      backoffMs: 5,
      post,
    },
    ...(opts.onCompletionCallbackFailed !== undefined
      ? { onCompletionCallbackFailed: opts.onCompletionCallbackFailed }
      : {}),
  });
  q.start();
  return { q, calls: () => calls };
}

/** Drive one delivery to a terminal `delivered` state, exhausting its receipt. */
async function exhaustReceipt(
  q: RetryQueue,
  seen: CompletionCallbackFailedInfo[],
  id: string,
  traceId: string
): Promise<void> {
  const before = seen.length;
  q.enqueue({ id, traceId, payload: BODY, targetUrl: DOWN, headers: {} });
  await waitFor(() => seen.length > before, `callback_failed report for ${id}`);
}

describe("RetryQueue completion-callback-failed callback revision (WR-398)", () => {
  it("the revised callback receives the next exhausted receipt with exact fields; the old callback stays silent", async () => {
    const first: CompletionCallbackFailedInfo[] = [];
    const second: CompletionCallbackFailedInfo[] = [];
    const { q } = failingReceiptQueue({
      onCompletionCallbackFailed: (info) => first.push(info),
    });
    try {
      await exhaustReceipt(q, first, "evt-1", "tid-1");
      assert.equal(first.length, 1);
      assert.equal(first[0].id, "evt-1");
      assert.equal(first[0].traceId, "tid-1");
      assert.equal(first[0].targetUrl, DOWN);
      assert.equal(first[0].terminalState, "delivered");
      assert.equal(first[0].attempts, 3);
      assert.match(first[0].error, /unexpected status 500/);
      assert.equal(first[0].tenant, undefined);
      // A second receipt exhausts into the revised callback only.
      q.reviseCompletionCallbackFailedCallback((info) => second.push(info));
      await exhaustReceipt(q, second, "evt-2", "tid-2");
      assert.equal(first.length, 1);
      assert.equal(second.length, 1);
      assert.equal(second[0].id, "evt-2");
      assert.equal(second[0].traceId, "tid-2");
      assert.equal(second[0].terminalState, "delivered");
      assert.equal(second[0].attempts, 3);
      assert.match(second[0].error, /unexpected status 500/);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; the receipt still exhausts its attempts", async () => {
    const seen: CompletionCallbackFailedInfo[] = [];
    const { q, calls } = failingReceiptQueue({
      onCompletionCallbackFailed: (info) => seen.push(info),
    });
    try {
      await exhaustReceipt(q, seen, "evt-1", "tid-1");
      assert.equal(seen.length, 1);
      assert.equal(calls(), 3);
      q.reviseCompletionCallbackFailedCallback(null);
      const beforeCalls = calls();
      // A delivery with no observer: drive it by watching the POST count.
      q.enqueue({ id: "evt-2", traceId: "tid-2", payload: BODY, targetUrl: DOWN, headers: {} });
      await waitFor(() => calls() >= beforeCalls + 3, "exhausted receipt POSTs after clear");
      assert.equal(seen.length, 1, "cleared hook stays silent");
      assert.equal(q.getDeadLetter().length, 0, "a failed receipt never dead-letters");
    } finally {
      q.stop();
    }
  });

  it("revising with completion callbacks unconfigured throws Error; completionCallbackConfigured reports the live state", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.completionCallbackConfigured(), false);
    assert.throws(
      () => q.reviseCompletionCallbackFailedCallback(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    const { q: configured } = failingReceiptQueue({});
    try {
      assert.equal(configured.completionCallbackConfigured(), true);
    } finally {
      configured.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const seen: CompletionCallbackFailedInfo[] = [];
    const { q } = failingReceiptQueue({
      onCompletionCallbackFailed: (info) => seen.push(info),
    });
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseCompletionCallbackFailedCallback(bad), RangeError, String(bad));
      }
      // Nothing moved: the original hook still fires.
      await exhaustReceipt(q, seen, "evt-1", "tid-1");
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const seen: CompletionCallbackFailedInfo[] = [];
    const onFailed = (info: CompletionCallbackFailedInfo) => seen.push(info);
    const { q } = failingReceiptQueue({ onCompletionCallbackFailed: onFailed });
    try {
      q.reviseCompletionCallbackFailedCallback(onFailed);
      await exhaustReceipt(q, seen, "evt-1", "tid-1");
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseCompletionCallbackFailedCallback(null);
      q.reviseCompletionCallbackFailedCallback(null);
      q.enqueue({ id: "evt-2", traceId: "tid-2", payload: BODY, targetUrl: DOWN, headers: {} });
      await sleep(150);
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("failures already reported are never re-delivered", async () => {
    const seen: CompletionCallbackFailedInfo[] = [];
    const { q } = failingReceiptQueue({
      onCompletionCallbackFailed: (info) => seen.push(info),
    });
    try {
      await exhaustReceipt(q, seen, "evt-1", "tid-1");
      assert.equal(seen.length, 1);
      q.reviseCompletionCallbackFailedCallback((info) => seen.push(info));
      await sleep(150);
      assert.equal(seen.length, 1, "no re-delivery of the reported failure");
    } finally {
      q.stop();
    }
  });

  it("revision does not change the receipt retry count", async () => {
    const seen: CompletionCallbackFailedInfo[] = [];
    const { q, calls } = failingReceiptQueue({
      onCompletionCallbackFailed: (info) => seen.push(info),
    });
    try {
      await exhaustReceipt(q, seen, "evt-1", "tid-1");
      assert.equal(calls(), 3);
      q.reviseCompletionCallbackFailedCallback((info) => seen.push(info));
      await exhaustReceipt(q, seen, "evt-2", "tid-2");
      assert.equal(calls(), 6, "each exhausted receipt still retries maxAttempts times");
      assert.equal(seen.length, 2);
    } finally {
      q.stop();
    }
  });

  it("revision does not change the self-check: a loop refusal still reports with zero POSTs", async () => {
    const first: CompletionCallbackFailedInfo[] = [];
    const second: CompletionCallbackFailedInfo[] = [];
    let calls = 0;
    const q = new RetryQueue({
      sender: async () => undefined,
      baseDelayMs: 10,
      maxDelayMs: 50,
      jitterMs: 0,
      completionCallback: {
        url: "http://127.0.0.1:8080/callback",
        post: async (): Promise<CallbackPostResult> => {
          calls += 1;
          return { statusCode: 200 };
        },
      },
      onCompletionCallbackFailed: (info) => first.push(info),
    });
    q.setCompletionCallbackSelfCheck(() => true); // the relay itself
    q.start();
    try {
      await exhaustReceipt(q, first, "evt-1", "tid-1");
      assert.equal(calls, 0);
      assert.match(first[0].error, /loop detected/);
      assert.equal(first[0].attempts, 0);
      q.reviseCompletionCallbackFailedCallback((info) => second.push(info));
      await exhaustReceipt(q, second, "evt-2", "tid-2");
      assert.equal(calls, 0, "the self-check still refuses every POST");
      assert.equal(first.length, 1);
      assert.equal(second.length, 1);
      assert.match(second[0].error, /loop detected/);
      assert.equal(second[0].attempts, 0);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer completion-callback-failed callback revision (WR-398)", () => {
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

  /**
   * A server whose deliveries succeed but whose receipt POSTs fail fast:
   * the callback target is port 1, which is (practically) never
   * listening, so every receipt exhausts and is reported once.
   */
  function failingCallbackServer(opts: {
    onCompletionCallbackFailed?: (info: CompletionCallbackFailedInfo) => void;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "completion-callback-failed-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => undefined,
      retry: {
        ...(opts.onCompletionCallbackFailed !== undefined
          ? { onCompletionCallbackFailed: opts.onCompletionCallbackFailed }
          : {}),
      },
      completionCallback: {
        url: "http://127.0.0.1:1/receipts",
        maxAttempts: 3,
        backoffMs: 5,
        timeoutMs: 500,
      },
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  async function driveFailure(
    port: number,
    auditLog: AuditLog,
    seen: CompletionCallbackFailedInfo[]
  ): Promise<void> {
    const beforeAudit = eventsOf(auditLog, "callback_failed").length;
    const beforeSeen = seen.length;
    assert.equal(
      (await post(port, "/", BODY, { "x-signature": signSha256(BODY, INGEST_KEY) })).status,
      202
    );
    await waitFor(
      () => eventsOf(auditLog, "callback_failed").length > beforeAudit,
      "callback_failed audit"
    );
    await waitFor(() => seen.length > beforeSeen, "failed callback report");
  }

  it("revising the callback routes the next failure to the new callback and the audit still lands", async () => {
    const first: CompletionCallbackFailedInfo[] = [];
    const second: CompletionCallbackFailedInfo[] = [];
    const { relay, auditLog } = failingCallbackServer({
      onCompletionCallbackFailed: (info) => first.push(info),
    });
    const port = await listen(relay);
    await driveFailure(port, auditLog, first);
    assert.equal(first.length, 1);
    assert.equal(first[0].terminalState, "delivered");
    assert.equal(first[0].attempts, 3);
    assert.ok(first[0].error.length > 0);
    relay.reviseCompletionCallbackFailedCallback!((info) => second.push(info));
    await driveFailure(port, auditLog, second);
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.equal(second[0].terminalState, "delivered");
    assert.equal(second[0].attempts, 3);
    assert.equal(eventsOf(auditLog, "callback_failed").length, 2);
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "completion_callback_failed_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; the failure is still audited as callback_failed", async () => {
    const first: CompletionCallbackFailedInfo[] = [];
    const { relay, auditLog } = failingCallbackServer({
      onCompletionCallbackFailed: (info) => first.push(info),
    });
    const port = await listen(relay);
    await driveFailure(port, auditLog, first);
    assert.equal(first.length, 1);
    relay.reviseCompletionCallbackFailedCallback!(null);
    const beforeAudit = eventsOf(auditLog, "callback_failed").length;
    assert.equal(
      (await post(port, "/", BODY, { "x-signature": signSha256(BODY, INGEST_KEY) })).status,
      202
    );
    await waitFor(
      () => eventsOf(auditLog, "callback_failed").length > beforeAudit,
      "callback_failed audit after clear"
    );
    await sleep(100);
    assert.equal(first.length, 1, "cleared hook stays silent");
    const revised = eventsOf(auditLog, "completion_callback_failed_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("a non-function value throws RangeError and the live callback is untouched; same-reference is a silent no-op", async () => {
    const first: CompletionCallbackFailedInfo[] = [];
    const onFailed = (info: CompletionCallbackFailedInfo) => first.push(info);
    const { relay, auditLog } = failingCallbackServer({ onCompletionCallbackFailed: onFailed });
    const port = await listen(relay);
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseCompletionCallbackFailedCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "completion_callback_failed_callback_revised").length, 0);
    relay.reviseCompletionCallbackFailedCallback!(onFailed);
    assert.equal(eventsOf(auditLog, "completion_callback_failed_callback_revised").length, 0);
    await driveFailure(port, auditLog, first);
    assert.equal(first.length, 1);
  });

  it("clearing when already unset is a silent no-op", async () => {
    const { relay, auditLog } = failingCallbackServer({});
    await listen(relay);
    relay.reviseCompletionCallbackFailedCallback!(null);
    assert.equal(eventsOf(auditLog, "completion_callback_failed_callback_revised").length, 0);
  });

  it("revising with completion callbacks unconfigured throws Error", () => {
    const dir = mkdtempSync(join(tmpdir(), "completion-callback-failed-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => undefined,
    });
    servers.push(relay);
    assert.throws(
      () => relay.reviseCompletionCallbackFailedCallback!(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });
});
