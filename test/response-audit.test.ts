import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { AesGcmEncryptor, randomAes256Key } from "../src/encrypt.ts";
import { signSha256 } from "../src/verify.ts";
import type { DownstreamResponseSummary } from "../src/response-summary.ts";

const SECRET = "wr54-test-secret";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

/** Poll until `cond()` is true or the timeout elapses. */
async function waitFor(cond: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() >= deadline) throw new Error("waitFor: timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
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

function sha256First256Hex(body: Buffer): string {
  return createHash("sha256").update(body.subarray(0, 256)).digest("hex");
}

type Req = Parameters<Parameters<typeof createServer>[0]>[0];
type Res = Parameters<Parameters<typeof createServer>[0]>[1];

describe("response audit (WR-54)", () => {
  let stub: Server;
  let stubPort: number;
  let stubBehavior: (req: Req, res: Res) => void = (_req, res) => {
    res.writeHead(200);
    res.end("ok");
  };

  before(async () => {
    stub = createServer((req, res) => stubBehavior(req, res));
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  it("delivered summary carries status, byte count, TTFB and body fingerprint", async () => {
    const downstreamBody = Buffer.from(JSON.stringify({ ok: true, seq: 42 }));
    stubBehavior = (_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(downstreamBody);
    };
    const sender = createDefaultSender();
    let summary: DownstreamResponseSummary | undefined;
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      jitterMs: 0,
      onDelivered: (_item, _attempts, s) => {
        summary = s;
      },
    });
    try {
      q.start();
      q.enqueue({
        id: "wr54-1",
        payload: Buffer.from("{}"),
        targetUrl: `http://127.0.0.1:${stubPort}/hook`,
        headers: {},
      });
      await waitFor(() => summary !== undefined);
      const s = summary as DownstreamResponseSummary;
      assert.equal(s.statusCode, 200);
      assert.equal(s.responseBytes, downstreamBody.length);
      assert.ok(
        typeof s.timeToFirstByteMs === "number" &&
          Number.isFinite(s.timeToFirstByteMs) &&
          s.timeToFirstByteMs >= 0,
        `TTFB is a sane non-negative number, got ${s.timeToFirstByteMs}`
      );
      assert.equal(s.bodyFingerprintSha256, sha256First256Hex(downstreamBody));
      assert.ok(!("capturedBody" in s), "no body captured by default");
    } finally {
      q.stop();
      sender.destroy();
    }
  });

  it("audit delivered event carries the summary but no body by default", async () => {
    const downstreamBody = Buffer.from("ok-body");
    stubBehavior = (_req, res) => {
      res.writeHead(200);
      res.end(downstreamBody);
    };
    const dir = mkdtempSync(join(tmpdir(), "wr54-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listen(relay);
    try {
      const payload = Buffer.from(JSON.stringify({ event: "ping" }));
      const res = await post(port, payload, {
        "x-signature": signSha256(payload, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      let delivered: Record<string, unknown> | undefined;
      await waitFor(() => {
        const events = audit.readAll() as Array<Record<string, unknown>>;
        delivered = events.find((e) => e.event === "delivered");
        return delivered !== undefined;
      });
      const summary = delivered!.response_summary as Record<string, unknown>;
      assert.ok(summary, "delivered audit event carries response_summary");
      assert.equal(summary.statusCode, 200);
      assert.equal(summary.responseBytes, downstreamBody.length);
      assert.ok(typeof summary.timeToFirstByteMs === "number");
      assert.equal(summary.bodyFingerprintSha256, sha256First256Hex(downstreamBody));
      assert.ok(!("capturedBody" in summary), "no body captured by default");
    } finally {
      relay.close();
    }
  });

  it("opt-in responseBodyCapture seals the full body so it decrypts back", async () => {
    const downstreamBody = Buffer.from(JSON.stringify({ secret: "downstream-data", n: 1 }));
    stubBehavior = (_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(downstreamBody);
    };
    const key = randomAes256Key();
    const encryptor = new AesGcmEncryptor(key);
    const dir = mkdtempSync(join(tmpdir(), "wr54-capture-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      payloadEncryptor: encryptor,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2, responseBodyCapture: true },
    });
    const port = await listen(relay);
    try {
      const payload = Buffer.from(JSON.stringify({ event: "capture-me" }));
      const res = await post(port, payload, {
        "x-signature": signSha256(payload, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      let delivered: Record<string, unknown> | undefined;
      await waitFor(() => {
        const events = audit.readAll() as Array<Record<string, unknown>>;
        delivered = events.find((e) => e.event === "delivered");
        return delivered !== undefined;
      });
      const summary = delivered!.response_summary as Record<string, unknown>;
      assert.ok(summary.capturedBody, "capturedBody present when opted in");
      const plain = encryptor.decrypt(
        summary.capturedBody as Parameters<AesGcmEncryptor["decrypt"]>[0]
      );
      assert.deepEqual(plain, downstreamBody);
    } finally {
      relay.close();
    }
  });

  it("a void custom sender yields an all-unavailable summary", async () => {
    let summary: DownstreamResponseSummary | undefined;
    const voidSender: Sender = async () => {};
    const q = new RetryQueue({
      sender: voidSender,
      onDelivered: (_item, _attempts, s) => {
        summary = s;
      },
    });
    try {
      q.start();
      q.enqueue({
        id: "wr54-void",
        payload: Buffer.from("x"),
        targetUrl: "http://127.0.0.1:1/hook",
        headers: {},
      });
      await waitFor(() => summary !== undefined);
      assert.deepEqual(summary, {
        statusCode: "unavailable",
        responseBytes: "unavailable",
        timeToFirstByteMs: "unavailable",
      });
    } finally {
      q.stop();
    }
  });

  it("a custom response without TTFB marks only TTFB unavailable", async () => {
    const body = Buffer.from("hi");
    const custom: Sender = async () => ({ statusCode: 201, body, truncated: false });
    let summary: DownstreamResponseSummary | undefined;
    const q = new RetryQueue({
      sender: custom,
      onDelivered: (_item, _attempts, s) => {
        summary = s;
      },
    });
    try {
      q.start();
      q.enqueue({
        id: "wr54-custom",
        payload: Buffer.from("x"),
        targetUrl: "http://127.0.0.1:1/hook",
        headers: {},
      });
      await waitFor(() => summary !== undefined);
      const s = summary as DownstreamResponseSummary;
      assert.equal(s.statusCode, 201);
      assert.equal(s.responseBytes, 2);
      assert.equal(s.timeToFirstByteMs, "unavailable");
      assert.equal(s.bodyFingerprintSha256, sha256First256Hex(body));
    } finally {
      q.stop();
    }
  });

  it("an empty response body omits the fingerprint field", async () => {
    const custom: Sender = async () => ({
      statusCode: 200,
      body: Buffer.alloc(0),
      truncated: false,
      timeToFirstByteMs: 3,
    });
    let summary: DownstreamResponseSummary | undefined;
    const q = new RetryQueue({
      sender: custom,
      onDelivered: (_item, _attempts, s) => {
        summary = s;
      },
    });
    try {
      q.start();
      q.enqueue({
        id: "wr54-empty",
        payload: Buffer.from("x"),
        targetUrl: "http://127.0.0.1:1/hook",
        headers: {},
      });
      await waitFor(() => summary !== undefined);
      const s = summary as DownstreamResponseSummary;
      assert.equal(s.responseBytes, 0);
      assert.ok(!("bodyFingerprintSha256" in s), "no fingerprint for an empty body");
    } finally {
      q.stop();
    }
  });

  it("dead_letter after exhausted 500s audits the last status code", async () => {
    stubBehavior = (_req, res) => {
      res.writeHead(500);
      res.end("boom");
    };
    const dir = mkdtempSync(join(tmpdir(), "wr54-dl500-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listen(relay);
    try {
      const payload = Buffer.from(JSON.stringify({ event: "fail500" }));
      const res = await post(port, payload, {
        "x-signature": signSha256(payload, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      let dead: Record<string, unknown> | undefined;
      await waitFor(() => {
        const events = audit.readAll() as Array<Record<string, unknown>>;
        dead = events.find((e) => e.event === "dead_letter");
        return dead !== undefined;
      });
      assert.equal(dead!.failure_class, "retryable");
      const summary = dead!.response_summary as Record<string, unknown>;
      assert.ok(summary, "dead_letter audit event carries response_summary");
      assert.equal(summary.statusCode, 500);
      assert.equal(summary.responseBytes, "unavailable");
      assert.equal(summary.timeToFirstByteMs, "unavailable");
      assert.ok(!("bodyFingerprintSha256" in summary));
      assert.ok(!("capturedBody" in summary), "dead letters never capture a body");
    } finally {
      relay.close();
    }
  });

  it("immediate dead_letter on 400 audits status code 400", async () => {
    stubBehavior = (_req, res) => {
      res.writeHead(400);
      res.end("bad request");
    };
    const dir = mkdtempSync(join(tmpdir(), "wr54-dl400-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 5 },
    });
    const port = await listen(relay);
    try {
      const payload = Buffer.from(JSON.stringify({ event: "poison" }));
      const res = await post(port, payload, {
        "x-signature": signSha256(payload, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      let dead: Record<string, unknown> | undefined;
      await waitFor(() => {
        const events = audit.readAll() as Array<Record<string, unknown>>;
        dead = events.find((e) => e.event === "dead_letter");
        return dead !== undefined;
      });
      assert.equal(dead!.failure_class, "non_retryable");
      assert.equal(dead!.attempts, 1);
      const summary = dead!.response_summary as Record<string, unknown>;
      assert.equal(summary.statusCode, 400);
      assert.equal(summary.responseBytes, "unavailable");
      assert.equal(summary.timeToFirstByteMs, "unavailable");
    } finally {
      relay.close();
    }
  });

  it("dead_letter from a transport error marks statusCode unavailable", async () => {
    const failing: Sender = async () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:1");
    };
    let summary: DownstreamResponseSummary | undefined;
    const q = new RetryQueue({
      sender: failing,
      maxAttempts: 1,
      baseDelayMs: 10,
      jitterMs: 0,
      onDeadLetter: (_item, _attempts, _err, _failureClass, s) => {
        summary = s;
      },
    });
    try {
      q.start();
      q.enqueue({
        id: "wr54-connrefused",
        payload: Buffer.from("x"),
        targetUrl: "http://127.0.0.1:1/hook",
        headers: {},
      });
      await waitFor(() => summary !== undefined);
      assert.deepEqual(summary, {
        statusCode: "unavailable",
        responseBytes: "unavailable",
        timeToFirstByteMs: "unavailable",
      });
    } finally {
      q.stop();
    }
  });

  it("responseBodyCapture without an encryptor throws RangeError at construction", () => {
    assert.throws(() => new RetryQueue({ responseBodyCapture: true }), RangeError);
    // And the positive control: with an encryptor it constructs fine.
    const q = new RetryQueue({
      responseBodyCapture: true,
      payloadEncryptor: new AesGcmEncryptor(randomAes256Key()),
    });
    q.stop();
  });
});
