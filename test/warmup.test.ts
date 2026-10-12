import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer, request as httpRequest, type Server } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer as createTcpServer, type Server as TcpServer, type Socket as TcpSocket } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OutboundConnectionPool } from "../src/keepalive.ts";
import {
  warmupOutboundPool,
  resolveWarmupOptions,
} from "../src/warmup.ts";
import { createRelayServer, createDefaultSender } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

const relaySecret = "warmup-test-secret";
const BODY = Buffer.from(JSON.stringify({ event: "warmup.probe" }));

async function listenHttp(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

describe("warmup options", () => {
  it("resolves defaults", () => {
    assert.deepEqual(resolveWarmupOptions(), {
      timeoutMs: 5000,
      concurrency: 8,
      socketsPerOrigin: 1,
    });
    assert.deepEqual(resolveWarmupOptions({}), {
      timeoutMs: 5000,
      concurrency: 8,
      socketsPerOrigin: 1,
    });
  });

  it("rejects invalid values with RangeError", () => {
    for (const bad of [
      { timeoutMs: 0 },
      { timeoutMs: -1 },
      { timeoutMs: NaN },
      { timeoutMs: Infinity },
      { concurrency: 0 },
      { concurrency: 1.5 },
      { socketsPerOrigin: 0 },
      { socketsPerOrigin: -2 },
    ]) {
      assert.throws(() => resolveWarmupOptions(bad), RangeError, JSON.stringify(bad));
    }
  });
});

describe("warmupOutboundPool", () => {
  let stub: Server;
  let stubPort: number;
  let serverConns = 0;

  before(async () => {
    stub = createHttpServer((req, res) => res.end("ok"));
    stub.on("connection", () => serverConns++);
    stubPort = await listenHttp(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  it("pre-connects the origin and the first delivery reuses the socket", async () => {
    serverConns = 0;
    const sender = createDefaultSender(undefined, {});
    try {
      const target = `http://127.0.0.1:${stubPort}/hook`;
      const rep = await warmupOutboundPool(sender.pool!, [target]);
      assert.equal(rep.results.length, 1);
      assert.equal(rep.results[0].ok, true);
      assert.equal(rep.warmed, 1);
      assert.equal(rep.failed, 0);
      assert.ok((rep.results[0].connectMs ?? -1) >= 0);
      assert.equal(serverConns, 1, "warm-up opens exactly one connection");

      const stats = sender.pool!.getStats();
      assert.equal(stats.endpoints.length, 1);
      assert.equal(stats.endpoints[0].freeSockets, 1);

      // Three deliveries ride the single warmed connection.
      for (const n of [1, 2, 3]) {
        const res = await sender({
          id: `wu-${n}`,
          payload: BODY,
          targetUrl: target,
          headers: {},
        });
        assert.equal(res?.statusCode, 200);
      }
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(serverConns, 1, "all deliveries reuse the warmed connection");
    } finally {
      sender.destroy();
    }
  });

  it("warms socketsPerOrigin sockets per origin", async () => {
    const pool = new OutboundConnectionPool();
    try {
      const target = `http://127.0.0.1:${stubPort}/hook`;
      const rep = await warmupOutboundPool(pool, [target], {}, { socketsPerOrigin: 3 });
      assert.equal(rep.results[0].ok, true);
      assert.equal(pool.getStats().endpoints[0].freeSockets, 3);
    } finally {
      pool.destroy();
    }
  });

  it("dedupes repeated endpoints to one warm per origin", async () => {
    const pool = new OutboundConnectionPool();
    try {
      const base = `http://127.0.0.1:${stubPort}`;
      const rep = await warmupOutboundPool(pool, [`${base}/a`, `${base}/b`, `${base}/a`]);
      assert.equal(rep.warmed, 2, "two unique endpoints both report ok");
      assert.equal(rep.failed, 0);
      assert.equal(pool.getStats().endpoints.length, 1, "one pool agent for the shared origin");
      assert.equal(pool.getStats().endpoints[0].freeSockets, 1, "warmed once, not per endpoint");
    } finally {
      pool.destroy();
    }
  });

  it("reports per-endpoint failures without throwing", async () => {
    const pool = new OutboundConnectionPool();
    try {
      const rep = await warmupOutboundPool(pool, [
        "not-a-url",
        "ws://example.com/hook",
        `http://127.0.0.1:1/refused`,
      ]);
      assert.equal(rep.warmed, 0);
      assert.equal(rep.failed, 3);
      for (const r of rep.results) {
        assert.equal(r.ok, false);
        assert.ok(typeof r.error === "string" && r.error.length > 0, "error is data");
      }
      assert.ok(rep.results[0].error!.startsWith("invalid_url"));
      assert.ok(rep.results[1].error!.startsWith("unsupported_protocol"));
      assert.match(rep.results[2].error!, /ECONNREFUSED|connect/);
    } finally {
      pool.destroy();
    }
  });

  it("times out a hanging handshake instead of hanging", async () => {
    // A plain-TCP server that accepts but never speaks TLS: the client
    // TLS handshake never completes, so the timeout must fire. Note:
    // destroying a mid-handshake TLS socket does not propagate FIN to
    // the peer (Node quirk), so the test tracks and destroys the
    // server-side socket itself instead of relying on holder.close()
    // to drain it.
    let serverSock: TcpSocket | undefined;
    const holder: TcpServer = createTcpServer((s) => {
      serverSock = s;
    });
    await new Promise<void>((resolve) => holder.listen(0, "127.0.0.1", resolve));
    const addr = holder.address();
    assert.ok(addr && typeof addr === "object");
    const pool = new OutboundConnectionPool();
    try {
      const rep = await warmupOutboundPool(
        pool,
        [`https://127.0.0.1:${addr.port}/x`],
        {},
        { timeoutMs: 300 }
      );
      assert.equal(rep.results[0].ok, false);
      assert.match(rep.results[0].error!, /connect_timeout/);
    } finally {
      pool.destroy();
      serverSock?.destroy();
      holder.close();
      await new Promise((r) => holder.once("close", r));
    }
  });

  it("warms TLS origins with pins; the pin is verified on first delivery", async () => {
    const httpsStub: HttpsServer = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
      (req, res) => res.end("ok")
    );
    let tlsConns = 0;
    httpsStub.on("secureConnection", () => tlsConns++);
    await new Promise<void>((resolve) => httpsStub.listen(0, "127.0.0.1", resolve));
    const addr = httpsStub.address();
    assert.ok(addr && typeof addr === "object");
    try {
      const target = `https://127.0.0.1:${addr.port}/hook`;
      const tlsPins = { [target]: [TLS_FIXTURE_SPKI_PIN] };
      const sender = createDefaultSender(tlsPins, {});
      try {
        const rep = await warmupOutboundPool(sender.pool!, [target], { tlsPins });
        assert.equal(rep.results[0].ok, true, rep.results[0].error);
        // First delivery over the warmed socket: the pin is verified
        // from the peer certificate (no cached pin yet) and succeeds.
        const r1 = await sender({ id: "wu-tls-1", payload: BODY, targetUrl: target, headers: {} });
        assert.equal(r1?.statusCode, 200);
        const r2 = await sender({ id: "wu-tls-2", payload: BODY, targetUrl: target, headers: {} });
        assert.equal(r2?.statusCode, 200);
        await new Promise((r) => setTimeout(r, 100));
        assert.equal(tlsConns, 1, "one warmed TLS connection serves both deliveries");
      } finally {
        sender.destroy();
      }
    } finally {
      httpsStub.close();
      await new Promise((r) => httpsStub.once("close", r));
    }
  });

  it("fails warm-up on pin mismatch and never parks the socket", async () => {
    const httpsStub: HttpsServer = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
      (req, res) => res.end("ok")
    );
    await new Promise<void>((resolve) => httpsStub.listen(0, "127.0.0.1", resolve));
    const addr = httpsStub.address();
    assert.ok(addr && typeof addr === "object");
    try {
      const target = `https://127.0.0.1:${addr.port}/hook`;
      const wrongPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      const sender = createDefaultSender({ [target]: [wrongPin] }, {});
      try {
        const rep = await warmupOutboundPool(sender.pool!, [target], { tlsPins: { [target]: [wrongPin] } });
        assert.equal(rep.results[0].ok, false);
        assert.match(rep.results[0].error!, /pin_mismatch/);
        assert.equal(sender.pool!.getStats().endpoints[0]?.freeSockets ?? 0, 0);
      } finally {
        sender.destroy();
      }
    } finally {
      httpsStub.close();
      await new Promise((r) => httpsStub.once("close", r));
    }
  });
});

describe("relay server warmup option", () => {
  let stub: Server;
  let stubPort: number;

  before(async () => {
    stub = createHttpServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => res.end("ok"));
    });
    stubPort = await listenHttp(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function relayWith(audit: AuditLog, warmup: unknown) {
    return createRelayServer({
      secret: relaySecret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      warmup: warmup as { endpoints: string[] },
    });
  }

  async function waitForAuditEvent(audit: AuditLog, event: string, timeoutMs = 8000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const found = events.find((e) => e.event === event);
      if (found) return found;
      if (Date.now() > deadline) throw new Error(`timed out waiting for audit event ${event}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  it("warms up at startup without blocking it, and audits warmup_completed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const startedAt = Date.now();
    const relay = relayWith(audit, { endpoints: [`http://127.0.0.1:${stubPort}/hook`] });
    // createRelayServer returned already — warm-up runs in the background.
    assert.ok(Date.now() - startedAt < 5000, "startup not blocked by warm-up");
    const port = await listenHttp(relay);
    try {
      const done = await waitForAuditEvent(audit, "warmup_completed");
      assert.equal(done.warmed, 1);
      assert.equal(done.failed, 0);
      assert.ok(typeof done.elapsedMs === "number");

      // The warmed connection serves the first real delivery: post a
      // webhook and confirm it is delivered.
      const body = await new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          { host: "127.0.0.1", port, path: "/", method: "POST", headers: { "x-signature": signSha256(BODY, relaySecret) } },
          (res) => {
            res.resume();
            res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end(BODY);
      });
      assert.equal(body.status, 202);
      await waitForAuditEvent(audit, "delivered");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("audits warmup_failed per endpoint and never fails startup", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = relayWith(audit, {
      endpoints: [`http://127.0.0.1:${stubPort}/hook`, "http://127.0.0.1:1/refused"],
    });
    const port = await listenHttp(relay);
    try {
      const done = await waitForAuditEvent(audit, "warmup_completed");
      assert.equal(done.warmed, 1);
      assert.equal(done.failed, 1);
      const failed = await waitForAuditEvent(audit, "warmup_failed");
      assert.equal(failed.endpoint, "http://127.0.0.1:1/refused");
      assert.ok(typeof failed.error === "string");
      // The relay itself is up and serving despite the failed warm-up.
      assert.ok(port > 0);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("throws RangeError at startup for a malformed warmup option", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          secret: relaySecret,
          forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
          auditLog: audit,
          warmup: { endpoints: "not-an-array" } as unknown as { endpoints: string[] },
        }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          secret: relaySecret,
          forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
          auditLog: audit,
          warmup: { endpoints: [`http://127.0.0.1:${stubPort}/hook`], timeoutMs: -5 },
        }),
      RangeError
    );
  });
});
