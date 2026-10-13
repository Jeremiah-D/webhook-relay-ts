import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import {
  AuditSink,
  AUDIT_SINK_DEAD_LETTER_EVENT,
  AUDIT_SINK_EVENT_HEADER,
  AUDIT_SINK_SIGNATURE_HEADER,
  AUDIT_SINK_TENANT_HEADER,
  type AuditSinkOptions,
} from "../src/audit-sink.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

const sinkSecret = "sink-secret-key";
const tenantSecret = "tenant-secret-key";
const serverSecret = "server-intake-secret";

function tmpAudit(): { dir: string; log: AuditLog } {
  const dir = mkdtempSync(join(tmpdir(), "audit-sink-"));
  return { dir, log: new AuditLog(join(dir, "audit.jsonl")) };
}

interface Hit {
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

/** Local webhook stub: fails the first `failures` POSTs with 500, then answers 200. */
function stubResponder(failures: number): { server: Server; hits: Hit[] } {
  const hits: Hit[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const status = hits.length < failures ? 500 : 200;
      hits.push({ headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(status).end(status === 200 ? "ok" : "boom");
    });
  });
  return { server, hits };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function closeServer(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function sinkOpts(url: string, extra: Partial<AuditSinkOptions> = {}): AuditSinkOptions {
  return {
    url,
    secret: sinkSecret,
    pollIntervalMs: 10,
    initialBackoffMs: 5,
    maxBackoffMs: 20,
    httpTimeoutMs: 2000,
    ...extra,
  };
}

function expectedSig(body: Buffer, secret: string): string {
  return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (cond()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

function postJson(
  port: number,
  path: string,
  body: Buffer,
  headers: Record<string, string>
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
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

describe("audit sink (WR-90)", () => {
  it("rejects invalid config fail-fast", () => {
    const { log } = tmpAudit();
    assert.throws(
      () => new AuditSink(log, { url: "", secret: sinkSecret }),
      RangeError,
      "empty url"
    );
    assert.throws(
      () => new AuditSink(log, { url: "ftp://example.com/hook", secret: sinkSecret }),
      RangeError,
      "non-http(s) url"
    );
    assert.throws(
      () => new AuditSink(log, { url: "http://example.com/hook", secret: "" }),
      RangeError,
      "empty secret (unsigned webhooks can be forged)"
    );
    assert.throws(
      () => new AuditSink(log, sinkOpts("http://example.com/", { maxAttempts: 0 })),
      RangeError,
      "maxAttempts < 1"
    );
    assert.throws(
      () => new AuditSink(log, sinkOpts("http://example.com/", { pollIntervalMs: -1 })),
      RangeError,
      "negative poll interval"
    );
    assert.throws(
      () =>
        new AuditSink(
          log,
          sinkOpts("http://example.com/", { tenantSinks: { "bad id!": { url: "http://x/" } } })
        ),
      RangeError,
      "bad tenant id"
    );
    assert.throws(
      () =>
        new AuditSink(
          log,
          sinkOpts("http://example.com/", { tenantSinks: { acme: { url: "" } } })
        ),
      RangeError,
      "bad tenant url"
    );
    assert.throws(
      () => new AuditSink({} as unknown as AuditLog, sinkOpts("http://example.com/")),
      TypeError,
      "not an AuditLog"
    );
  });

  it("forwards new events with HMAC signature and audit metadata", async () => {
    const { server, hits } = stubResponder(0);
    const port = await listen(server);
    const { log } = tmpAudit();
    const sink = new AuditSink(log, sinkOpts(`http://127.0.0.1:${port}/hook`));
    sink.start();
    try {
      log.append({ event: "accepted", id: "evt-1", targetUrl: "https://down.example/hook" });
      log.append({ event: "delivered", id: "evt-2", tenant: "acme" });
      await waitFor(() => hits.length >= 2, 5000, "2 forwarded events");
      assert.equal(sink.stats().sent, 2);

      const first = hits[0];
      assert.equal(first.headers[AUDIT_SINK_EVENT_HEADER], "accepted");
      assert.equal(first.headers["content-type"], "application/json");
      assert.equal(first.headers[AUDIT_SINK_SIGNATURE_HEADER], expectedSig(first.body, sinkSecret));
      const parsed = JSON.parse(first.body.toString("utf8"));
      assert.equal(parsed.event, "accepted");
      assert.equal(parsed.id, "evt-1");
      // The forwarded body is the exact log line: hash-chain fields included.
      assert.match(parsed.hash, /^[0-9a-f]{64}$/);
      assert.match(parsed.prevHash, /^[0-9a-f]{64}$/);

      const second = hits[1];
      assert.equal(second.headers[AUDIT_SINK_EVENT_HEADER], "delivered");
      assert.equal(second.headers[AUDIT_SINK_TENANT_HEADER], "acme");
      assert.equal(second.headers[AUDIT_SINK_SIGNATURE_HEADER], expectedSig(second.body, sinkSecret));
    } finally {
      sink.stop();
      await closeServer(server);
    }
  });

  it("routes per-tenant URLs with per-tenant secrets, default for the rest", async () => {
    const a = stubResponder(0);
    const b = stubResponder(0);
    const portA = await listen(a.server);
    const portB = await listen(b.server);
    const { log } = tmpAudit();
    const sink = new AuditSink(
      log,
      sinkOpts(`http://127.0.0.1:${portA}/hook`, {
        tenantSinks: { acme: { url: `http://127.0.0.1:${portB}/hook`, secret: tenantSecret } },
      })
    );
    sink.start();
    try {
      log.append({ event: "accepted", id: "plain" });
      log.append({ event: "accepted", id: "t1", tenant: "acme" });
      log.append({ event: "accepted", id: "t2", tenant: "other" });
      await waitFor(() => a.hits.length >= 2 && b.hits.length >= 1, 5000, "tenant routing");
      assert.equal(a.hits.length, 2);
      assert.equal(b.hits.length, 1);
      // Tenant deliveries are signed with the tenant secret...
      assert.equal(
        b.hits[0].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(b.hits[0].body, tenantSecret)
      );
      assert.equal(JSON.parse(b.hits[0].body.toString()).id, "t1");
      // ...everything else with the default secret.
      for (const h of a.hits) {
        assert.equal(h.headers[AUDIT_SINK_SIGNATURE_HEADER], expectedSig(h.body, sinkSecret));
      }
      const idsA = a.hits.map((h) => JSON.parse(h.body.toString()).id).sort();
      assert.deepEqual(idsA, ["plain", "t2"]);
    } finally {
      sink.stop();
      await closeServer(a.server);
      await closeServer(b.server);
    }
  });

  it("retries with backoff and delivers exactly once after failures", async () => {
    const { server, hits } = stubResponder(2);
    const port = await listen(server);
    const { log } = tmpAudit();
    const sink = new AuditSink(log, sinkOpts(`http://127.0.0.1:${port}/hook`, { maxAttempts: 5 }));
    sink.start();
    try {
      log.append({ event: "accepted", id: "flaky" });
      await waitFor(() => sink.stats().sent >= 1, 5000, "event delivered");
      assert.equal(hits.length, 3);
      assert.equal(sink.stats().failedAttempts, 2);
      assert.equal(sink.stats().deadLetters, 0);
      // Retries redeliver the identical line.
      assert.equal(hits[0].body.toString(), hits[2].body.toString());
    } finally {
      sink.stop();
      await closeServer(server);
    }
  });

  it("dead-letters after exhausting retries and never re-forwards the dead letter", async () => {
    const { server, hits } = stubResponder(Number.MAX_SAFE_INTEGER);
    const port = await listen(server);
    const { dir, log } = tmpAudit();
    const sink = new AuditSink(log, sinkOpts(`http://127.0.0.1:${port}/hook`, { maxAttempts: 3 }));
    sink.start();
    try {
      log.append({ event: "accepted", id: "poison" });
      await waitFor(() => sink.stats().deadLetters >= 1, 5000, "dead letter recorded");
      assert.equal(hits.length, 3);
      assert.equal(sink.stats().failedAttempts, 3);

      const lines = readFileSync(join(dir, "audit.jsonl"), "utf8")
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l));
      const dl = lines.find((l) => l.event === AUDIT_SINK_DEAD_LETTER_EVENT);
      assert.ok(dl, "audit_sink_dead_letter line exists in the audit log");
      assert.equal(dl.attempts, 3);
      assert.equal(dl.lastStatus, 500);
      assert.equal(dl.eventName, "accepted");

      // The dead-letter line itself is never forwarded: no loop, cursor advanced.
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(hits.length, 3);
      assert.ok(
        hits.every((h) => !h.body.toString().includes(AUDIT_SINK_DEAD_LETTER_EVENT)),
        "no forwarded body is a dead-letter line"
      );
      assert.ok(sink.cursorOffset() > 0);
    } finally {
      sink.stop();
      await closeServer(server);
    }
  });

  it("does not replay history on first start", async () => {
    const { server, hits } = stubResponder(0);
    const port = await listen(server);
    const { log } = tmpAudit();
    log.append({ event: "accepted", id: "old-1" });
    log.append({ event: "accepted", id: "old-2" });
    const sink = new AuditSink(log, sinkOpts(`http://127.0.0.1:${port}/hook`));
    sink.start();
    try {
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(hits.length, 0);
      log.append({ event: "accepted", id: "new-1" });
      await waitFor(() => hits.length >= 1, 5000, "new event forwarded");
      assert.equal(JSON.parse(hits[0].body.toString()).id, "new-1");
    } finally {
      sink.stop();
      await closeServer(server);
    }
  });

  it("stop halts forwarding; a restart resumes from the cursor", async () => {
    const { server, hits } = stubResponder(0);
    const port = await listen(server);
    const { log } = tmpAudit();
    const opts = sinkOpts(`http://127.0.0.1:${port}/hook`);
    const sink = new AuditSink(log, opts);
    sink.start();
    log.append({ event: "accepted", id: "before-stop" });
    await waitFor(() => hits.length >= 1, 5000, "first event forwarded");
    sink.stop();
    log.append({ event: "accepted", id: "after-stop" });
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(hits.length, 1);

    const sink2 = new AuditSink(log, opts);
    sink2.start();
    try {
      await waitFor(() => hits.length >= 2, 5000, "resumed event forwarded");
      assert.equal(JSON.parse(hits[1].body.toString()).id, "after-stop");
    } finally {
      sink2.stop();
      await closeServer(server);
    }
  });

  it("createRelayServer wires auditSink: intake audit events are forwarded", async () => {
    const downstream = stubResponder(0);
    const dPort = await listen(downstream.server);
    const sinkStub = stubResponder(0);
    const sPort = await listen(sinkStub.server);
    const dir = mkdtempSync(join(tmpdir(), "audit-sink-srv-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const server = createRelayServer({
      secret: serverSecret,
      forwardUrl: `http://127.0.0.1:${dPort}/down`,
      auditLog,
      auditSink: {
        url: `http://127.0.0.1:${sPort}/audit-hook`,
        secret: sinkSecret,
        pollIntervalMs: 10,
        initialBackoffMs: 5,
        maxBackoffMs: 20,
        httpTimeoutMs: 2000,
      },
    });
    const port = await listen(server);
    try {
      const body = Buffer.from(JSON.stringify({ order: "ord-9" }));
      const res = await postJson(port, "/", body, { "x-signature": signSha256(body, serverSecret) });
      assert.equal(res.status, 202);
      await waitFor(
        () => sinkStub.hits.some((h) => JSON.parse(h.body.toString()).event === "accepted"),
        5000,
        "accepted audit event forwarded by the server-owned sink"
      );
      const hit = sinkStub.hits.find((h) => JSON.parse(h.body.toString()).event === "accepted");
      assert.ok(hit);
      assert.equal(hit.headers[AUDIT_SINK_SIGNATURE_HEADER], expectedSig(hit.body, sinkSecret));
    } finally {
      await closeServer(server);
      await closeServer(downstream.server);
      await closeServer(sinkStub.server);
    }
  });
});
