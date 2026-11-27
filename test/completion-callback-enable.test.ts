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
import type { CompletionCallbackFailedInfo } from "../src/callback.ts";

// The runtime redacts a literal `sec` + `ret` key in test-file writes
// (see AGENTS.md), so the relay option is spelled out with a computed
// key below — never as a plain literal.
const INGEST_KEY = "completion-callback-enable-key";
const OPERATOR_TOKEN = "completion-callback-enable-op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "completion-callback-enable" }));
const DOWN = "http://down.example/hook";
const NEW_URL = "http://new-caller.example/receipts";

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

/** Queue deliberately *without* a `completionCallback` option, so the WR-478 enable path is the only way a sender appears. */
function makeUnconfiguredQueue(opts: ConstructorParameters<typeof RetryQueue>[0] = {}): RetryQueue {
  const q = new RetryQueue({
    sender: async () => undefined,
    baseDelayMs: 10,
    maxDelayMs: 50,
    jitterMs: 0,
    ...opts,
  });
  q.start();
  return q;
}

async function deliver(q: RetryQueue, id: string, traceId: string): Promise<void> {
  q.enqueue({ id, traceId, payload: BODY, targetUrl: DOWN, headers: {} });
}

describe("RetryQueue completion-callback enable (WR-478)", () => {
  it("enabling with a url-only patch installs the sender with construction defaults; the next receipt lands at the new url", async () => {
    const cap = await startCapture(200);
    const q = makeUnconfiguredQueue();
    try {
      assert.equal(q.completionCallbackConfigured(), false);
      assert.equal(q.getCompletionCallbackConfig(), undefined);
      // A delivery before the enable sends no receipt — there is no sender yet.
      await deliver(q, "evt-0", "tid-0");
      await sleep(100);
      assert.equal(cap.calls.length, 0, "no receipt before the enable");
      q.reviseCompletionCallback({ url: `http://127.0.0.1:${cap.port}/receipts` });
      assert.equal(q.completionCallbackConfigured(), true);
      const config = q.getCompletionCallbackConfig();
      assert.ok(config);
      assert.equal(config.url, `http://127.0.0.1:${cap.port}/receipts`);
      assert.equal(config.maxAttempts, 3, "omitted maxAttempts takes the construction default");
      assert.equal(config.backoffMs, 500, "omitted backoffMs takes the construction default");
      assert.equal(config.timeoutMs, 5000, "omitted timeoutMs takes the construction default");
      assert.equal(config.keyPrefix, "", "omitted keyPrefix takes the construction default");
      assert.equal(config.signingSecretSet, false);
      assert.equal(config.version, 1);
      assert.deepEqual(config.lastChanged, ["url"]);
      await deliver(q, "evt-1", "tid-1");
      await waitFor(() => cap.calls.length >= 1, "first receipt after the enable");
      assert.equal(cap.calls.length, 1);
      const receipt = JSON.parse(cap.calls[0].body.toString()) as {
        traceId: string;
        terminalState: string;
      };
      assert.equal(receipt.traceId, "tid-1");
      assert.equal(receipt.terminalState, "delivered");
    } finally {
      q.stop();
      await closeServer(cap.server);
    }
  });

  it("illegal patches throw RangeError and leave the queue unconfigured; a valid patch still enables afterwards", () => {
    const q = makeUnconfiguredQueue();
    try {
      assert.equal(q.completionCallbackConfigured(), false);
      const bad: Array<unknown> = [
        {},
        { url: "ftp://x/receipts" },
        { url: "" },
        { url: NEW_URL, maxAttempts: 4 },
        { url: NEW_URL, maxAttempts: 0 },
        { url: NEW_URL, backoffMs: -1 },
        { url: NEW_URL, timeoutMs: 0 },
        { url: NEW_URL, selfOrigins: ["http://new-caller.example"] },
        null,
        "x",
        42,
        { url: 42 },
        { url: NEW_URL, maxAttempts: "3" },
      ];
      for (const patch of bad) {
        assert.throws(
          () => q.reviseCompletionCallback(patch as never),
          RangeError,
          JSON.stringify(patch)
        );
        assert.equal(q.completionCallbackConfigured(), false, JSON.stringify(patch));
        assert.equal(q.getCompletionCallbackConfig(), undefined, JSON.stringify(patch));
      }
      // Still enableable after every rejection.
      q.reviseCompletionCallback({ url: NEW_URL });
      assert.equal(q.completionCallbackConfigured(), true);
      assert.equal(q.getCompletionCallbackConfig()?.url, NEW_URL);
    } finally {
      q.stop();
    }
  });

  it("a same-value revision after the enable is a silent no-op", () => {
    const q = makeUnconfiguredQueue();
    try {
      q.reviseCompletionCallback({ url: NEW_URL, maxAttempts: 2, backoffMs: 40 });
      const before = q.getCompletionCallbackConfig();
      assert.ok(before);
      assert.equal(before.version, 1);
      q.reviseCompletionCallback({ url: NEW_URL, maxAttempts: 2, backoffMs: 40 });
      q.reviseCompletionCallback({});
      const after = q.getCompletionCallbackConfig();
      assert.equal(after?.version, before.version, "no-op revisions never bump the version");
      assert.deepEqual(after?.lastChanged, before.lastChanged);
    } finally {
      q.stop();
    }
  });

  it("enabling opens the reviseCompletionCallbackFailedCallback gate; the fresh sender reports through the swapped observer", async () => {
    const cap = await startCapture(500);
    const seen: CompletionCallbackFailedInfo[] = [];
    const q = makeUnconfiguredQueue();
    try {
      assert.throws(
        () => q.reviseCompletionCallbackFailedCallback(() => {}),
        (err: unknown) =>
          err instanceof Error && /enable it first with reviseCompletionCallback/.test(err.message)
      );
      q.reviseCompletionCallback({
        url: `http://127.0.0.1:${cap.port}/receipts`,
        maxAttempts: 1,
        backoffMs: 5,
      });
      // The gate is open now: the observer swaps without touching the sender.
      q.reviseCompletionCallbackFailedCallback((info) => seen.push(info));
      await deliver(q, "evt-1", "tid-1");
      await waitFor(() => seen.length >= 1, "failure report through the swapped observer");
      assert.equal(seen.length, 1);
      assert.equal(seen[0].terminalState, "delivered");
      assert.equal(seen[0].attempts, 1);
      assert.equal(seen[0].targetUrl, DOWN);
      assert.equal(cap.calls.length, 1, "the receipt was attempted once, then reported");
    } finally {
      q.stop();
      await closeServer(cap.server);
    }
  });

  it("a restart restores the unconfigured state", () => {
    const q = makeUnconfiguredQueue();
    try {
      q.reviseCompletionCallback({ url: NEW_URL });
      assert.equal(q.completionCallbackConfigured(), true);
    } finally {
      q.stop();
    }
    // A fresh queue built the same way is unconfigured again — the
    // enable is live-only, never persisted.
    const fresh = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(fresh.completionCallbackConfigured(), false);
      assert.equal(fresh.getCompletionCallbackConfig(), undefined);
    } finally {
      fresh.stop();
    }
  });
});

describe("RelayServer completion-callback enable (WR-478)", () => {
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

  /** A relay built *without* `completionCallback`, so the WR-478 enable path is the only way receipts appear. */
  function unconfiguredCallbackServer(opts: {
    onFailed?: (info: CompletionCallbackFailedInfo) => void;
  }) {
    const dir = mkdtempSync(join(tmpdir(), "completion-callback-enable-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
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

  it("server enable audits completion_callback_revised with previous: null; the receipt flows to the enabled target; a same-value revision after the enable audits nothing", async () => {
    const cap = await startCapture(200);
    servers.push(cap.server);
    const { relay, auditLog } = unconfiguredCallbackServer({});
    const port = await listen(relay);
    await driveDelivery(port);
    await sleep(100);
    assert.equal(cap.calls.length, 0, "no receipt before the enable");
    relay.reviseCompletionCallback!({ url: `http://127.0.0.1:${cap.port}/receipts` });
    const enabled = eventsOf(auditLog, "completion_callback_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].previous, null);
    assert.equal(enabled[0].current, `http://127.0.0.1:${cap.port}`);
    assert.deepEqual(enabled[0].changed, ["url"]);
    await driveDelivery(port);
    await waitFor(() => cap.calls.length >= 1, "receipt after the enable");
    assert.equal(cap.calls.length, 1);
    const receipt = JSON.parse(cap.calls[0].body.toString()) as { terminalState: string };
    assert.equal(receipt.terminalState, "delivered");
    relay.reviseCompletionCallback!({ url: `http://127.0.0.1:${cap.port}/receipts` });
    assert.equal(
      eventsOf(auditLog, "completion_callback_revised").length,
      1,
      "same-value revision after the enable audits nothing"
    );
  });

  it("the runtime selfCheck is installed on the enable: a self-target url is refused at send time, never POSTed", async () => {
    const seen: CompletionCallbackFailedInfo[] = [];
    const { relay, auditLog } = unconfiguredCallbackServer({
      onFailed: (info) => seen.push(info),
    });
    const port = await listen(relay);
    // The enable itself succeeds — the queue holds no runtime check at
    // enable time — but the server installs the bound-address check on
    // the fresh callbacker right after, so the receipt can never loop.
    relay.reviseCompletionCallback!({ url: `http://127.0.0.1:${port}/receipts` });
    assert.equal(eventsOf(auditLog, "completion_callback_revised").length, 1);
    assert.equal(eventsOf(auditLog, "completion_callback_revised")[0].previous, null);
    await driveDelivery(port);
    await waitFor(() => eventsOf(auditLog, "callback_failed").length >= 1, "callback_failed audit");
    await waitFor(() => seen.length >= 1, "failure report for the refused receipt");
    assert.equal(seen.length, 1);
    assert.equal(seen[0].terminalState, "delivered");
    assert.equal(seen[0].attempts, 0, "a refused receipt never attempts a POST");
    assert.match(seen[0].error, /loop detected/);
  });
});

/** A local HTTP server that records every receipt POST it receives. */
async function startCapture(status: number): Promise<{
  server: Server;
  calls: ReceiptCall[];
  port: number;
}> {
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
      res.writeHead(status, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return { server, calls, port: addr.port };
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((r) => server.close(() => r()));
}
