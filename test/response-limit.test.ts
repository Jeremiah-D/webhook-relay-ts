import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  assertValidResponseGuardConfig,
  DEFAULT_MAX_RESPONSE_BYTES,
  ResponseTooLargeError,
} from "../src/response-limit.ts";

// NOTE: intentionally not named SECRET — the runner's secret redaction
// rewrites `secret: SECRET` occurrences in test sources.
const SIGNING_SECRET = "resplimit-test-secret";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

type AuditEvent = Record<string, unknown>;

function events(audit: AuditLog, event: string): AuditEvent[] {
  return audit.query({ event }) as AuditEvent[];
}

/** Stub answering 200 with a fixed-size response body. */
function bigBodyStub(responseBytes: number) {
  const hits: number[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      hits.push(Date.now());
      res.writeHead(200).end(Buffer.alloc(responseBytes, "z"));
    });
  });
  return { server, hits };
}

describe("WR-169 response body size limit", () => {
  const BODY = Buffer.from(JSON.stringify({ order: "ord_7", amount: 50 }));

  function relay(
    stubPort: number,
    guard: Record<string, { maxResponseBytes?: number }>,
    maxAttempts: number
  ) {
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "resplimit-")), "audit.jsonl"));
    const targetUrl = `http://127.0.0.1:${stubPort}/hook`;
    const server = createRelayServer({
      secret: SIGNING_SECRET,
      forwardUrl: targetUrl,
      auditLog: audit,
      responseGuard: { [targetUrl]: guard },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts },
    });
    return { server, audit };
  }

  it("ResponseTooLargeError carries the audit token and the cap", () => {
    const err = new ResponseTooLargeError("http://x/hook", 1024, 200);
    assert.match(err.message, /response_too_large/);
    assert.match(err.message, /maxResponseBytes=1024/);
    assert.equal(err.name, "ResponseTooLargeError");
    assert.equal(err.maxBytes, 1024);
    assert.equal(err.statusCode, 200);
  });

  it("rejects illegal caps at startup", () => {
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "resplimit-")), "audit.jsonl"));
    for (const bad of [0, -1, 1.5, Number.NaN, "1024", null]) {
      assert.throws(
        () =>
          createRelayServer({
            secret: SIGNING_SECRET,
            forwardUrl: "http://127.0.0.1:9/hook",
            auditLog: audit,
            responseGuard: { "http://127.0.0.1:9/hook": { maxResponseBytes: bad as number } },
          }),
        RangeError,
        `maxResponseBytes=${String(bad)}`
      );
    }
    assert.equal(DEFAULT_MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
  });

  it("dead-letters an over-cap response and audits response_too_large", async () => {
    const { server: stub, hits } = bigBodyStub(2048);
    const stubPort = await listen(stub);
    const { server: relayServer, audit } = relay(stubPort, { maxResponseBytes: 1024 }, 3);
    const relayPort = await listen(relayServer);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SIGNING_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => hits.length >= 3, 15000, "3 downstream attempts");
      assert.equal(hits.length, 3);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      const dead = events(audit, "dead_letter");
      assert.equal(dead.length, 1);
      assert.match(String(dead[0]?.error), /response_too_large/);
      assert.equal(dead[0]?.failure_class, "retryable");
      // The 2xx status rides into the response summary honestly.
      assert.equal(
        (dead[0]?.response_summary as Record<string, unknown>)?.statusCode,
        200
      );
      const overruns = events(audit, "response_too_large");
      assert.equal(overruns.length, 1);
      assert.equal(overruns[0]?.maxBytes, 1024);
      assert.match(String(overruns[0]?.error), /response_too_large/);
      assert.equal(overruns[0]?.targetUrl, `http://127.0.0.1:${stubPort}/hook`);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("delivers a body exactly at the cap", async () => {
    const { server: stub } = bigBodyStub(1024);
    const stubPort = await listen(stub);
    const { server: relayServer, audit } = relay(stubPort, { maxResponseBytes: 1024 }, 1);
    const relayPort = await listen(relayServer);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SIGNING_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "response_too_large").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("a small body under a custom cap delivers normally", async () => {
    const { server: stub } = bigBodyStub(64);
    const stubPort = await listen(stub);
    const { server: relayServer, audit } = relay(stubPort, { maxResponseBytes: 4096 }, 1);
    const relayPort = await listen(relayServer);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SIGNING_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("unguarded endpoints keep the legacy truncated-capture behavior", async () => {
    // No responseGuard at all: a 200 KiB 2xx body still delivers (the
    // pre-WR-169 truncated capture is untouched for unguarded endpoints).
    const { server: stub } = bigBodyStub(200 * 1024);
    const stubPort = await listen(stub);
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "resplimit-")), "audit.jsonl"));
    const relayServer = createRelayServer({
      secret: SIGNING_SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const relayPort = await listen(relayServer);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SIGNING_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "response_too_large").length, 0);
      assert.equal(events(audit, "dead_letter").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("assertValidResponseGuardConfig validates the record shape", () => {
    assert.throws(() => assertValidResponseGuardConfig(null), RangeError);
    assert.throws(() => assertValidResponseGuardConfig([]), RangeError);
    assert.throws(() => assertValidResponseGuardConfig({ "": {} }), RangeError);
    assert.throws(
      () => assertValidResponseGuardConfig({ "http://x/": { maxResponseBytes: 0 } }),
      RangeError
    );
    assertValidResponseGuardConfig({});
    assertValidResponseGuardConfig({ "http://x/": {} });
    assertValidResponseGuardConfig({ "http://x/": { maxResponseBytes: 1 } });
  });
});
