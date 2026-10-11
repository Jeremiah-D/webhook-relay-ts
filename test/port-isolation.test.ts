import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, type RelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const SECRET = "port-isolation-secret";
const TOKEN = "operator-token";
const BODY = Buffer.from(JSON.stringify({ order: "ord_456", amount: 1200 }));

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

interface Response {
  status: number;
  contentType: string;
  text: string;
}

function request(
  port: number,
  path: string,
  method: string,
  headers: Record<string, string> = {},
  body?: Buffer
): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method, headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            contentType: res.headers["content-type"] ?? "",
            text: Buffer.concat(chunks).toString(),
          })
        );
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

function stubDownstream() {
  const hits: Buffer[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      hits.push(Buffer.concat(chunks));
      res.writeHead(200).end("ok");
    });
  });
  return { server, hits };
}

function makeAudit(): AuditLog {
  return new AuditLog(join(mkdtempSync(join(tmpdir(), "port-iso-")), "audit.jsonl"));
}

function operatorPortOf(relay: RelayServer): Promise<number> {
  const op = relay.operatorServer;
  assert.ok(op, "operatorServer should be set");
  return (async () => {
    // The relay binds the operator plane at creation, but `listen()` is
    // asynchronous — the address is only readable after 'listening'.
    if (!op.listening) {
      await new Promise<void>((resolve, reject) => {
        op.once("listening", () => resolve());
        op.once("error", reject);
      });
    }
    const addr = op.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  })();
}

describe("operator/intake plane split (WR-56)", () => {
  it("serves operator endpoints only on the operator plane", async () => {
    const { server: stub, hits } = stubDownstream();
    const stubPort = await listen(stub);
    const audit = makeAudit();
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: TOKEN,
      operatorPort: { port: 0 },
      retry: { baseDelayMs: 10, maxDelayMs: 100, maxAttempts: 2, jitterMs: 0 },
    });
    try {
      const intakePort = await listen(relay);
      const opPort = await operatorPortOf(relay);

      // The operator plane binds 127.0.0.1 by default — never 0.0.0.0.
      const opAddr = relay.operatorServer!.address();
      assert.ok(opAddr && typeof opAddr === "object");
      assert.equal(opAddr.address, "127.0.0.1");

      // Operator endpoint works on the operator plane (bearer auth intact).
      const metrics = await request(opPort, "/metrics", "GET", {
        authorization: `Bearer ${TOKEN}`,
      });
      assert.equal(metrics.status, 200);
      assert.ok(metrics.contentType.startsWith("text/plain"));

      // Operator endpoint is unauthenticated-gated on its own plane too.
      const metricsNoAuth = await request(opPort, "/metrics", "GET");
      assert.equal(metricsNoAuth.status, 403);

      // Operator paths on the intake plane: plain 404, no operator
      // fingerprint — indistinguishable from an unknown path.
      for (const path of ["/metrics", "/dead-letter", "/audit"]) {
        const r = await request(intakePort, path, "GET", {
          authorization: `Bearer ${TOKEN}`,
        });
        assert.equal(r.status, 404, path);
        assert.equal(r.contentType, "text/plain");
        assert.equal(r.text, "Not found");
      }
      // Same 404 without a bearer: the intake plane never hints that an
      // operator plane exists.
      const noAuth = await request(intakePort, "/metrics", "GET");
      assert.equal(noAuth.status, 404);
      assert.equal(noAuth.text, "Not found");

      // Webhooks are accepted on the intake plane...
      const accepted = await request(intakePort, "/", "POST", {
        "x-signature": signSha256(BODY, SECRET),
        "content-type": "application/json",
      }, BODY);
      assert.equal(accepted.status, 202);

      // ...but 404 on the operator plane and are never enqueued.
      const opPost = await request(opPort, "/", "POST", {
        "x-signature": signSha256(BODY, SECRET),
        "content-type": "application/json",
      }, BODY);
      assert.equal(opPost.status, 404);
      assert.equal(opPost.text, "Not found");
      assert.equal(audit.query({ event: "accepted" }).length, 1);

      // The intake-plane delivery still flows downstream.
      const deadline = Date.now() + 5000;
      while (hits.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(hits.length, 1);
      assert.deepEqual(hits[0], BODY);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("closing the intake server closes the operator plane", async () => {
    const { server: stub } = stubDownstream();
    const stubPort = await listen(stub);
    try {
      const relay = createRelayServer({
        secret: SECRET,
        forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
        auditLog: makeAudit(),
        operatorToken: TOKEN,
        operatorPort: { port: 0 },
      });
      const opPort = await operatorPortOf(relay);
      try {
        await listen(relay);
        // Sanity: the operator plane answers before close.
        const before = await request(opPort, "/metrics", "GET", {
          authorization: `Bearer ${TOKEN}`,
        });
        assert.equal(before.status, 200);
      } finally {
        await close(relay);
      }
      // The operator listener is stopped with the intake server.
      assert.equal(relay.operatorServer!.listening, false);
      // Behaviorally: the operator plane is unreachable. A fresh connect
      // is refused (ECONNREFUSED); a stale pooled keep-alive socket is
      // reset (ECONNRESET). Either way, nothing serves the operator plane.
      await assert.rejects(request(opPort, "/metrics", "GET"), (err: unknown) => {
        const code = (err as NodeJS.ErrnoException).code;
        assert.ok(
          code === "ECONNREFUSED" || code === "ECONNRESET",
          `unexpected error code: ${code}`
        );
        return true;
      });
    } finally {
      await close(stub);
    }
  });

  it("keeps single-plane behavior when operatorPort is not configured", async () => {
    const { server: stub } = stubDownstream();
    const stubPort = await listen(stub);
    const audit = makeAudit();
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: TOKEN,
      retry: { baseDelayMs: 10, maxDelayMs: 100, maxAttempts: 2, jitterMs: 0 },
    });
    try {
      assert.equal(relay.operatorServer, undefined);
      const port = await listen(relay);
      const metrics = await request(port, "/metrics", "GET", {
        authorization: `Bearer ${TOKEN}`,
      });
      assert.equal(metrics.status, 200);
      const accepted = await request(port, "/", "POST", {
        "x-signature": signSha256(BODY, SECRET),
        "content-type": "application/json",
      }, BODY);
      assert.equal(accepted.status, 202);
      assert.equal(audit.query({ event: "accepted" }).length, 1);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("rejects invalid operatorPort config at startup", async () => {
    const base = {
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/hook",
      auditLog: makeAudit(),
    };
    for (const port of [-1, 1.5, 65536, NaN]) {
      assert.throws(
        () => createRelayServer({ ...base, operatorPort: { port } }),
        RangeError,
        `port ${String(port)}`
      );
    }
    assert.throws(
      () => createRelayServer({ ...base, operatorPort: { port: 0, host: "" } }),
      RangeError,
      "empty host"
    );
    // port 0 (ephemeral) and explicit hosts are accepted.
    const relay = createRelayServer({ ...base, operatorPort: { port: 0 } });
    assert.ok(relay.operatorServer);
    await listen(relay);
    await close(relay);
    const relay2 = createRelayServer({
      ...base,
      auditLog: makeAudit(),
      operatorPort: { port: 0, host: "127.0.0.1" },
    });
    assert.ok(relay2.operatorServer);
    await listen(relay2);
    await close(relay2);
  });
});
