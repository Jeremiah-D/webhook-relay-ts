import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import type { CorsPolicy } from "../src/cors.ts";

const ORIGIN = "https://dashboard.example.com";
const OTHER_ORIGIN = "https://evil.example.com";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function relay(opts: { cors?: CorsPolicy; operatorToken?: string }) {
  const dir = mkdtempSync(join(tmpdir(), "cors-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const server = createRelayServer({
    forwardUrl: "http://localhost:9999/hook",
    auditLog: audit,
    operatorToken: opts.operatorToken,
    cors: opts.cors,
    sender: async () => {},
  });
  return server;
}

interface Resp {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  text: string;
}

function http(
  port: number,
  method: string,
  path: string,
  headers: Record<string, string> = {}
): Promise<Resp> {
  return new Promise<Resp>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers as Resp["headers"],
          text: Buffer.concat(chunks).toString(),
        })
      );
    });
    r.on("error", reject);
    r.end();
  });
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err?: Error) => (err ? reject(err) : resolve()));
  });
}

describe("WR-159 operator CORS", () => {
  let server: Server;
  let port: number;

  before(async () => {
    server = relay({
      operatorToken: "op-token",
      cors: {
        allowedOrigins: [ORIGIN],
        allowedMethods: ["GET", "OPTIONS"],
        allowCredentials: true,
      },
    });
    port = await listen(server);
  });

  after(async () => {
    await close(server);
  });

  it("preflight to an allowlisted origin is answered 204 before auth", async () => {
    // No bearer token on purpose: the preflight must short-circuit
    // before operator auth.
    const res = await http(port, "OPTIONS", "/metrics", {
      origin: ORIGIN,
      "access-control-request-method": "GET",
    });
    assert.equal(res.status, 204);
    assert.equal(res.headers["access-control-allow-origin"], ORIGIN);
    assert.equal(res.headers["vary"], "Origin");
    assert.ok(String(res.headers["access-control-allow-methods"]).includes("GET"));
    assert.equal(res.headers["access-control-allow-credentials"], "true");
    assert.ok(res.headers["access-control-max-age"] !== undefined);
  });

  it("preflight from a non-allowlisted origin gets a bare 204 (no echo)", async () => {
    const res = await http(port, "OPTIONS", "/metrics", {
      origin: OTHER_ORIGIN,
      "access-control-request-method": "GET",
    });
    assert.equal(res.status, 204);
    assert.equal(res.headers["access-control-allow-origin"], undefined);
  });

  it("preflight without an Origin header gets a bare 204", async () => {
    const res = await http(port, "OPTIONS", "/metrics", {});
    assert.equal(res.status, 204);
    assert.equal(res.headers["access-control-allow-origin"], undefined);
  });

  it("actual operator responses to allowlisted origins carry CORS headers", async () => {
    const res = await http(port, "GET", "/metrics", {
      origin: ORIGIN,
      authorization: "Bearer op-token",
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers["access-control-allow-origin"], ORIGIN);
    assert.equal(res.headers["vary"], "Origin");
    assert.equal(res.headers["access-control-allow-credentials"], "true");
  });

  it("actual operator responses to other origins carry no CORS headers", async () => {
    const res = await http(port, "GET", "/metrics", {
      origin: OTHER_ORIGIN,
      authorization: "Bearer op-token",
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers["access-control-allow-origin"], undefined);
  });

  it("non-browser operator calls (no Origin) are byte-identical to before", async () => {
    const res = await http(port, "GET", "/metrics", { authorization: "Bearer op-token" });
    assert.equal(res.status, 200);
    assert.equal(res.headers["access-control-allow-origin"], undefined);
  });

  it("the webhook intake is untouched by CORS", async () => {
    const res = await http(port, "POST", "/", { origin: ORIGIN });
    assert.equal(res.headers["access-control-allow-origin"], undefined);
  });
});

describe("WR-159 CORS disabled by default", () => {
  let plain: Server;
  let plainPort: number;

  before(async () => {
    plain = relay({ operatorToken: "op-token" });
    plainPort = await listen(plain);
  });

  after(async () => {
    await close(plain);
  });

  it("OPTIONS to an operator path is not treated as a preflight", async () => {
    const res = await http(plainPort, "OPTIONS", "/metrics", {
      origin: ORIGIN,
      authorization: "Bearer op-token",
    });
    assert.notEqual(res.status, 204);
    assert.equal(res.headers["access-control-allow-origin"], undefined);
  });

  it("operator responses carry no CORS headers", async () => {
    const res = await http(plainPort, "GET", "/metrics", {
      origin: ORIGIN,
      authorization: "Bearer op-token",
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers["access-control-allow-origin"], undefined);
  });
});

describe("WR-159 CORS config validation", () => {
  it("rejects wildcard origins", () => {
    assert.throws(
      () => relay({ cors: { allowedOrigins: ["*"] } }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("rejects empty origin strings", () => {
    assert.throws(
      () => relay({ cors: { allowedOrigins: [""] } }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("rejects a non-object policy", () => {
    assert.throws(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      () => relay({ cors: "nope" as unknown as CorsPolicy }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("rejects empty allowedMethods", () => {
    assert.throws(
      () => relay({ cors: { allowedOrigins: [ORIGIN], allowedMethods: [] } }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("rejects a non-boolean allowCredentials", () => {
    assert.throws(
      () =>
        relay({
          cors: { allowedOrigins: [ORIGIN], allowCredentials: "yes" as unknown as boolean },
        }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("an empty allowlist disables CORS (zero behavior change)", async () => {
    const srv = relay({ operatorToken: "op-token", cors: { allowedOrigins: [] } });
    const p = await listen(srv);
    try {
      const res = await http(p, "OPTIONS", "/metrics", { origin: ORIGIN });
      assert.notEqual(res.status, 204);
      assert.equal(res.headers["access-control-allow-origin"], undefined);
    } finally {
      await close(srv);
    }
  });
});

describe("WR-159 CORS on the split-plane operator listener", () => {
  it("preflight is answered on the operator port", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cors-split-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const srv = createRelayServer({
      forwardUrl: "http://localhost:9999/hook",
      auditLog: audit,
      operatorToken: "op-token",
      operatorPort: { port: 0 },
      cors: { allowedOrigins: [ORIGIN] },
      sender: async () => {},
    });
    const intakePort = await listen(srv);
    const opAddr = (srv as { operatorServer?: Server }).operatorServer?.address();
    assert.ok(opAddr && typeof opAddr === "object");
    try {
      const res = await http(opAddr.port, "OPTIONS", "/metrics", {
        origin: ORIGIN,
        "access-control-request-method": "GET",
      });
      assert.equal(res.status, 204);
      assert.equal(res.headers["access-control-allow-origin"], ORIGIN);
      // The intake plane still does not speak CORS.
      const intake = await http(intakePort, "OPTIONS", "/metrics", { origin: ORIGIN });
      assert.equal(intake.status, 404);
      assert.equal(intake.headers["access-control-allow-origin"], undefined);
    } finally {
      // WR-56: the intake server owns the operator plane's lifecycle —
      // closing it stops the operator listener too.
      const op = (srv as { operatorServer?: Server }).operatorServer;
      const opClosed =
        op && op.listening
          ? new Promise<void>((resolve) => op.once("close", () => resolve()))
          : Promise.resolve();
      await close(srv);
      await opClosed;
    }
  });
});
