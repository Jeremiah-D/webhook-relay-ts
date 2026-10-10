import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { RetryQueue } from "../src/retry.ts";
import type { RetryItem } from "../src/retry.ts";
import {
  deriveIdempotencyKey,
  IDEMPOTENCY_KEY_HEADER,
  resolveIdempotencyKeyConfig,
} from "../src/idempotency-key.ts";

const SECRET = "relay-secret";
const OUTBOUND_SECRET = "outbound-relay-secret";
const IDEM_SECRET = "idempotency-relay-secret";
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

describe("WR-44 deriveIdempotencyKey", () => {
  it("is deterministic for the same (secret, event id, attempt)", () => {
    const a = deriveIdempotencyKey(IDEM_SECRET, "evt-1", 1);
    const b = deriveIdempotencyKey(IDEM_SECRET, "evt-1", 1);
    assert.equal(a, b);
    assert.match(a, /^[0-9a-f]{64}$/);
  });

  it("changes with the attempt number (a retry is a new key)", () => {
    const k1 = deriveIdempotencyKey(IDEM_SECRET, "evt-1", 1);
    const k2 = deriveIdempotencyKey(IDEM_SECRET, "evt-1", 2);
    assert.notEqual(k1, k2);
  });

  it("changes with the event id", () => {
    assert.notEqual(deriveIdempotencyKey(IDEM_SECRET, "evt-1", 1), deriveIdempotencyKey(IDEM_SECRET, "evt-2", 1));
  });

  it("is unforgeable without the secret (HMAC key sensitivity)", () => {
    assert.notEqual(
      deriveIdempotencyKey(IDEM_SECRET, "evt-1", 1),
      deriveIdempotencyKey("attacker-secret", "evt-1", 1)
    );
  });

  it("prepends keyPrefix when configured", () => {
    const k = deriveIdempotencyKey(IDEM_SECRET, "evt-1", 1, "relay-");
    assert.ok(k.startsWith("relay-"));
    assert.equal(k, "relay-" + deriveIdempotencyKey(IDEM_SECRET, "evt-1", 1));
  });
});

describe("WR-44 resolveIdempotencyKeyConfig", () => {
  it("is off by default (undefined / enabled: false resolve to undefined)", () => {
    assert.equal(resolveIdempotencyKeyConfig(undefined), undefined);
    assert.equal(resolveIdempotencyKeyConfig({}), undefined);
    assert.equal(resolveIdempotencyKeyConfig({ enabled: false, secret: "x" }), undefined);
  });

  it("resolves a valid config, defaulting keyPrefix to empty", () => {
    assert.deepEqual(resolveIdempotencyKeyConfig({ enabled: true, secret: "s" }), {
      enabled: true,
      secret: "s",
      keyPrefix: "",
    });
  });

  it("throws RangeError when enabled without a usable secret or with a bad prefix", () => {
    assert.throws(() => resolveIdempotencyKeyConfig({ enabled: true }), RangeError);
    assert.throws(() => resolveIdempotencyKeyConfig({ enabled: true, secret: "" }), RangeError);
    assert.throws(
      () => resolveIdempotencyKeyConfig({ enabled: true, secret: "s", keyPrefix: 42 as unknown as string }),
      RangeError
    );
  });

  it("createDefaultSender rejects invalid idempotencyKey config at startup", () => {
    assert.throws(
      () =>
        createDefaultSender(undefined, false, undefined, undefined, undefined, undefined, undefined, {
          enabled: true,
        }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          secret: SECRET,
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "idem-")), "audit.jsonl")),
          outboundIdempotencyKey: { enabled: true, secret: "" },
        }),
      RangeError
    );
  });
});

describe("WR-44 sender idempotency-key stamping", () => {
  let stub: Server;
  let stubPort: number;
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function item(overrides: Partial<RetryItem> = {}): RetryItem {
    return {
      id: "item-1",
      traceId: "trace-1",
      payload: BODY,
      targetUrl: `http://127.0.0.1:${stubPort}/hook`,
      headers: {},
      ...overrides,
    };
  }

  function senderWith(opts: Parameters<typeof createDefaultSender>[7]) {
    return createDefaultSender(undefined, false, undefined, undefined, undefined, undefined, undefined, opts);
  }

  async function deliverOnce(sender: ReturnType<typeof createDefaultSender>, it: RetryItem) {
    seen.length = 0;
    await sender(it);
    await waitFor(() => seen.length > 0, "downstream delivery");
    sender.destroy();
    return seen[0];
  }

  it("stamps x-relay-idempotency-key derived from (event id, attempt 1) for a hand-built item", async () => {
    const sender = senderWith({ enabled: true, secret: IDEM_SECRET });
    const got = await deliverOnce(sender, item());
    assert.equal(got.headers[IDEMPOTENCY_KEY_HEADER], deriveIdempotencyKey(IDEM_SECRET, "item-1", 1));
  });

  it("uses the queue-stamped attempt (attempt + 1) for the in-flight attempt number", async () => {
    const sender = senderWith({ enabled: true, secret: IDEM_SECRET });
    // The queue hands the sender a spread copy with `attempt` = attempts
    // consumed so far (0-based): attempt: 2 means the 3rd attempt is in flight.
    const got = await deliverOnce(sender, item({ attempt: 2 }));
    assert.equal(got.headers[IDEMPOTENCY_KEY_HEADER], deriveIdempotencyKey(IDEM_SECRET, "item-1", 3));
  });

  it("applies keyPrefix to the stamped header", async () => {
    const sender = senderWith({ enabled: true, secret: IDEM_SECRET, keyPrefix: "relay-" });
    const got = await deliverOnce(sender, item());
    assert.equal(
      got.headers[IDEMPOTENCY_KEY_HEADER],
      "relay-" + deriveIdempotencyKey(IDEM_SECRET, "item-1", 1)
    );
  });

  it("stamps nothing when disabled (default)", async () => {
    const sender = senderWith(undefined);
    const got = await deliverOnce(sender, item());
    // The sender never invents the header when the feature is off; a
    // forged inbound value is stripped earlier, at intake (see below).
    assert.equal(got.headers[IDEMPOTENCY_KEY_HEADER], undefined);
  });
});

describe("WR-44 retry / replay / batch key semantics through a real queue", () => {
  let stub: Server;
  let stubPort: number;
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];
  let failFirst: number;

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
        if (failFirst > 0) {
          failFirst -= 1;
          res.writeHead(500).end("boom");
        } else {
          res.writeHead(200).end("ok");
        }
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function makeSender() {
    return createDefaultSender(
      undefined,
      false,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      { enabled: true, secret: IDEM_SECRET }
    );
  }

  function targetUrl() {
    return `http://127.0.0.1:${stubPort}/hook`;
  }

  it("fixes one key per (event id, attempt): attempt 1 and attempt 2 differ, both deterministic", async () => {
    failFirst = 1;
    seen.length = 0;
    const sender = makeSender();
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 3,
      jitterMs: 0,
    });
    try {
      q.start();
      q.enqueue({ id: "evt-retry", payload: BODY, targetUrl: targetUrl(), headers: {} });
      await waitFor(() => seen.length === 2, "two delivery attempts");
      const k1 = deriveIdempotencyKey(IDEM_SECRET, "evt-retry", 1);
      const k2 = deriveIdempotencyKey(IDEM_SECRET, "evt-retry", 2);
      assert.notEqual(k1, k2);
      assert.equal(seen[0].headers[IDEMPOTENCY_KEY_HEADER], k1);
      assert.equal(seen[1].headers[IDEMPOTENCY_KEY_HEADER], k2);
      await waitFor(() => q.pendingCount() === 0, "queue drain");
      assert.equal(q.getDeadLetter().length, 0);
    } finally {
      q.stop();
      sender.destroy();
    }
  });

  it("dead-letter replay preserves the original keys (replay restarts at attempt 1)", async () => {
    failFirst = Number.MAX_SAFE_INTEGER; // downstream always fails
    seen.length = 0;
    const sender = makeSender();
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 2,
      jitterMs: 0,
    });
    try {
      q.start();
      q.enqueue({ id: "evt-dl", payload: BODY, targetUrl: targetUrl(), headers: {} });
      await waitFor(() => q.getDeadLetter().length === 1, "dead letter");
      await waitFor(() => seen.length === 2, "two failed attempts");
      const originalAttempt1 = seen[0].headers[IDEMPOTENCY_KEY_HEADER];
      const originalAttempt2 = seen[1].headers[IDEMPOTENCY_KEY_HEADER];
      assert.equal(originalAttempt1, deriveIdempotencyKey(IDEM_SECRET, "evt-dl", 1));
      assert.equal(originalAttempt2, deriveIdempotencyKey(IDEM_SECRET, "evt-dl", 2));

      // Replay with a fresh budget: the replayed attempt 1 must carry the
      // ORIGINAL attempt-1 key, not a newly minted one.
      seen.length = 0;
      assert.ok(q.replayDeadLetter("evt-dl"));
      await waitFor(() => seen.length === 2, "replayed attempts");
      assert.equal(seen[0].headers[IDEMPOTENCY_KEY_HEADER], originalAttempt1);
      assert.equal(seen[1].headers[IDEMPOTENCY_KEY_HEADER], originalAttempt2);
    } finally {
      q.stop();
      sender.destroy();
    }
  });

  it("batch deliveries derive the key from the batch_id", async () => {
    failFirst = 0;
    seen.length = 0;
    const sender = makeSender();
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 1,
      jitterMs: 0,
      batch: { windowMs: 50, maxBatchSize: 10 },
    });
    try {
      q.start();
      const url = targetUrl();
      q.enqueue({ id: "evt-b1", payload: BODY, targetUrl: url, headers: {} });
      q.enqueue({ id: "evt-b2", payload: BODY, targetUrl: url, headers: {} });
      await waitFor(() => seen.length === 1, "flushed batch delivery");
      const batchId = String(seen[0].headers["x-batch-id"]);
      assert.ok(batchId.startsWith("batch:"));
      assert.equal(
        seen[0].headers[IDEMPOTENCY_KEY_HEADER],
        deriveIdempotencyKey(IDEM_SECRET, batchId, 1)
      );
    } finally {
      q.stop();
      sender.destroy();
    }
  });
});

describe("WR-44 forged inbound x-relay-idempotency-key is stripped at intake", () => {
  let stub: Server;
  let stubPort: number;
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  async function postInbound(relayPort: number, forged: string | undefined) {
    await new Promise<void>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port: relayPort,
          path: "/",
          method: "POST",
          headers: {
            "x-signature": signSha256(BODY, SECRET),
            ...(forged !== undefined ? { [IDEMPOTENCY_KEY_HEADER]: forged } : {}),
          },
        },
        (res) => {
          res.resume();
          res.on("end", resolve);
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
  }

  function makeRelay(outboundIdempotencyKey: { enabled: boolean; secret: string } | undefined) {
    const dir = mkdtempSync(join(tmpdir(), "idem-"));
    return createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      outboundIdempotencyKey,
    });
  }

  it("relay stamps its own derived key, overwriting the forged inbound one", async () => {
    const relay = makeRelay({ enabled: true, secret: IDEM_SECRET });
    const port = await listen(relay);
    try {
      seen.length = 0;
      await postInbound(port, "attacker-key");
      await waitFor(() => seen.length === 1, "relayed delivery");
      const key = String(seen[0].headers[IDEMPOTENCY_KEY_HEADER]);
      assert.notEqual(key, "attacker-key");
      assert.match(key, /^[0-9a-f]{64}$/);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("strips the forged header entirely when the feature is off", async () => {
    const relay = makeRelay(undefined);
    const port = await listen(relay);
    try {
      seen.length = 0;
      await postInbound(port, "attacker-key");
      await waitFor(() => seen.length === 1, "relayed delivery");
      assert.equal(seen[0].headers[IDEMPOTENCY_KEY_HEADER], undefined);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
