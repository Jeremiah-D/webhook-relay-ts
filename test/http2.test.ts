import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createH2Server, createSecureServer as createH2SecureServer } from "node:http2";
import type { ServerHttp2Session, Http2Server } from "node:http2";
import { createServer, type Server, type IncomingMessage } from "node:http";
import { connect as tcpConnect, type Socket } from "node:net";
import { X509Certificate } from "node:crypto";
import { Http2SessionPool, Http2UnavailableError, resolveHttp2PoolOptions } from "../src/http2.ts";
import { createDefaultSender } from "../src/server.ts";
import { HttpDeliveryError } from "../src/failure.ts";
import { spkiFingerprint, TlsPinMismatchError } from "../src/pinning.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";
import {
  MTLS_CA_PEM,
  MTLS_CLIENT_CERT_PEM,
  MTLS_CLIENT_KEY_PEM,
  MTLS_SERVER_CERT_PEM,
  MTLS_SERVER_KEY_PEM,
} from "./mtls-fixture.ts";

const BODY = Buffer.from(JSON.stringify({ event: "http2.probe" }));
const WRONG_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const item = (targetUrl: string) => ({ id: "h1", payload: BODY, targetUrl, headers: {} });

async function listen(server: Server | Http2Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

/** h2c echo stub; records :path values and counts TCP connections. */
function startH2cStub(onStream?: (path: string) => void): {
  server: Http2Server;
  port: Promise<number>;
  connections: () => number;
  streams: () => number;
  close: () => Promise<void>;
} {
  const server = createH2Server();
  let connections = 0;
  let streams = 0;
  server.on("connection", () => connections++);
  server.on("stream", (stream, headers) => {
    streams++;
    onStream?.(String(headers[":path"] ?? ""));
    stream.resume();
    stream.on("end", () => {
      stream.respond({ ":status": 200 });
      stream.end("ok");
    });
  });
  const port = listen(server);
  return {
    server,
    port,
    connections: () => connections,
    streams: () => streams,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const PROXY_ENV_VARS = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
  "NO_PROXY",
  "no_proxy",
];

/** Run `fn` with the proxy-related environment replaced; restore afterwards. */
async function withProxyEnv(
  vars: Record<string, string | undefined>,
  fn: () => Promise<void>
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const k of PROXY_ENV_VARS) saved[k] = process.env[k];
  try {
    for (const k of PROXY_ENV_VARS) delete process.env[k];
    for (const [k, v] of Object.entries(vars)) {
      if (v !== undefined) process.env[k] = v;
    }
    await fn();
  } finally {
    for (const k of PROXY_ENV_VARS) delete process.env[k];
    for (const [k, v] of Object.entries(saved)) {
      if (v !== undefined) process.env[k] = v;
    }
  }
}

/** A minimal CONNECT proxy (mirrors test/proxy.test.ts). */
async function startConnectProxy(): Promise<{
  server: Server;
  port: number;
  hits: string[];
  close: () => Promise<void>;
}> {
  const hits: string[] = [];
  const server = createServer();
  server.on("connect", (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
    const target = req.url ?? "";
    hits.push(target);
    clientSocket.on("error", () => {});
    const sep = target.lastIndexOf(":");
    const upstream = tcpConnect(Number(target.slice(sep + 1)), target.slice(0, sep));
    upstream.on("error", () => {
      clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      clientSocket.destroy();
    });
    upstream.on("connect", () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) upstream.write(head);
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    });
  });
  const port = await listen(server);
  return { server, port, hits, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

describe("http2: option validation", () => {
  it("rejects invalid values with RangeError at construction", () => {
    assert.throws(() => resolveHttp2PoolOptions({ enabled: "yes" as unknown as boolean }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ hosts: [""] }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ hosts: ["   "] }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ hosts: [":8080"] }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ hosts: ["host:0"] }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ hosts: ["host:99999"] }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ hosts: ["host:notaport"] }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ hosts: "nope" as unknown as string[] }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ sessionIdleTimeoutMs: -1 }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ sessionIdleTimeoutMs: NaN }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ fallbackCooldownMs: -5 }), RangeError);
    assert.throws(() => resolveHttp2PoolOptions({ fallbackCooldownMs: Infinity }), RangeError);
  });

  it("accepts valid values and normalizes host entries", () => {
    const resolved = resolveHttp2PoolOptions({
      enabled: true,
      hosts: ["Example.COM", "example.com", "api.internal:8443"],
      sessionIdleTimeoutMs: 0,
      fallbackCooldownMs: 0,
    });
    assert.equal(resolved.enabled, true);
    assert.deepEqual(resolved.hosts, ["example.com", "api.internal:8443"]);
    assert.equal(resolved.sessionIdleTimeoutMs, 0);
    assert.equal(resolved.fallbackCooldownMs, 0);
  });

  it("is off by default: no pool unless enabled with eligible hosts", () => {
    const off = createDefaultSender();
    assert.equal(off.http2Pool, undefined);
    off.destroy();
    const disabledFlag = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: false, hosts: ["127.0.0.1"] }
    );
    assert.equal(disabledFlag.http2Pool, undefined);
    disabledFlag.destroy();
    const enabledNoHosts = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true }
    );
    assert.equal(enabledNoHosts.http2Pool, undefined);
    enabledNoHosts.destroy();
    const on = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"] }
    );
    assert.ok(on.http2Pool instanceof Http2SessionPool);
    on.destroy();
  });

  it("createDefaultSender validates http2 options at startup", () => {
    assert.throws(
      () =>
        createDefaultSender(undefined, undefined, undefined, undefined, undefined, undefined, {
          enabled: true,
          hosts: [""],
        }),
      RangeError
    );
    assert.throws(
      () =>
        createDefaultSender(undefined, undefined, undefined, undefined, undefined, undefined, {
          enabled: true,
          fallbackCooldownMs: -1,
        }),
      RangeError
    );
  });
});

describe("http2: h2c session reuse", () => {
  let stub: ReturnType<typeof startH2cStub>;
  let targetUrl: string;

  before(async () => {
    stub = startH2cStub();
    targetUrl = `http://127.0.0.1:${await stub.port}/hook`;
  });

  after(async () => {
    await stub.close();
  });

  it("multiplexes many deliveries over one connection", async () => {
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"] }
    );
    const before = stub.connections();
    for (let i = 0; i < 10; i++) {
      const res = await sender(item(targetUrl));
      assert.ok(res && res.statusCode === 200);
    }
    assert.equal(stub.streams(), 10);
    assert.equal(stub.connections() - before, 1);
    const stats = sender.http2Pool!.getStats();
    assert.equal(stats.established, 1);
    assert.equal(stats.reused, 9);
    assert.equal(stats.fallback, 0);
    assert.equal(stats.sessions.length, 1);
    assert.equal(stats.sessions[0]!.scheme, "http");
    assert.equal(stats.sessions[0]!.pinned, false);
    assert.equal(stats.sessions[0]!.clientCert, false);
    sender.destroy();
  });

  it("preserves the query string in :path", async () => {
    const seen: string[] = [];
    const qs = startH2cStub((path) => seen.push(path));
    const url = `http://127.0.0.1:${await qs.port}/hook?token=abc&n=1`;
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"] }
    );
    await sender(item(url));
    assert.deepEqual(seen, ["/hook?token=abc&n=1"]);
    sender.destroy();
    await qs.close();
  });

  it("re-establishes after the server closes the session", async () => {
    const local = startH2cStub();
    const url = `http://127.0.0.1:${await local.port}/hook`;
    const serverSessions: ServerHttp2Session[] = [];
    local.server.on("session", (s) => serverSessions.push(s));
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"], fallbackCooldownMs: 0 }
    );
    await sender(item(url));
    assert.equal(sender.http2Pool!.getStats().established, 1);
    assert.equal(serverSessions.length, 1);
    // Server-side close: the client evicts the dead session and the next
    // delivery establishes a fresh one.
    serverSessions[0]!.destroy();
    await sleep(150);
    await sender(item(url));
    assert.equal(sender.http2Pool!.getStats().established, 2);
    assert.equal(serverSessions.length, 2);
    sender.destroy();
    await local.close();
  });

  it("closes idle sessions after sessionIdleTimeoutMs", async () => {
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"], sessionIdleTimeoutMs: 50, fallbackCooldownMs: 0 }
    );
    await sender(item(targetUrl));
    assert.equal(sender.http2Pool!.getStats().established, 1);
    await sleep(300);
    await sender(item(targetUrl));
    assert.equal(sender.http2Pool!.getStats().established, 2);
    sender.destroy();
  });

  it("does not attempt H2 for ineligible hosts", async () => {
    const plain = createServer((req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    const plainUrl = `http://127.0.0.1:${await listen(plain)}/hook`;
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["other.invalid"] }
    );
    const res = await sender(item(plainUrl));
    assert.ok(res && res.statusCode === 200);
    const stats = sender.http2Pool!.getStats();
    assert.equal(stats.established, 0);
    assert.equal(stats.fallback, 0);
    // Plain HTTP/1.1 pool served it.
    assert.ok(sender.pool!.getStats().created >= 1);
    sender.destroy();
    await new Promise<void>((resolve) => plain.close(() => resolve()));
  });

  it("host:port entries match exactly", async () => {
    const plain = createServer((req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    const plainUrl = `http://127.0.0.1:${await listen(plain)}/hook`;
    const port = new URL(plainUrl).port;
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: [`127.0.0.1:${Number(port) + 1}`] }
    );
    await sender(item(plainUrl));
    assert.equal(sender.http2Pool!.getStats().established, 0);
    sender.destroy();
    await new Promise<void>((resolve) => plain.close(() => resolve()));
  });
});

describe("http2: https with pinning (WR-21)", () => {
  let server: Http2Server;
  let targetUrl: string;
  let connections = 0;

  before(async () => {
    server = createH2SecureServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM });
    server.on("connection", () => connections++);
    server.on("stream", (stream) => {
      stream.resume();
      stream.on("end", () => {
        stream.respond({ ":status": 200 });
        stream.end("ok");
      });
    });
    const port = await listen(server);
    targetUrl = `https://127.0.0.1:${port}/hook`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("reuses one TLS session for pinned deliveries", async () => {
    const sender = createDefaultSender(
      { [targetUrl]: [TLS_FIXTURE_SPKI_PIN] },
      undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"] }
    );
    const before = connections;
    for (let i = 0; i < 3; i++) {
      const res = await sender(item(targetUrl));
      assert.ok(res && res.statusCode === 200);
    }
    assert.equal(connections - before, 1);
    const stats = sender.http2Pool!.getStats();
    assert.equal(stats.established, 1);
    assert.equal(stats.reused, 2);
    assert.equal(stats.sessions[0]!.pinned, true);
    sender.destroy();
  });

  it("pin mismatch falls back to HTTP/1.1 and fails loudly there", async () => {
    const sender = createDefaultSender(
      { [targetUrl]: [WRONG_PIN] },
      undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"], fallbackCooldownMs: 0 }
    );
    await assert.rejects(sender(item(targetUrl)), TlsPinMismatchError);
    // The delivery was attempted over H2 first, then failed on the H1.1
    // pin path — one place owns the pin error.
    assert.equal(sender.http2Pool!.getStats().fallback, 1);
    sender.destroy();
  });
});

describe("http2: mTLS client certificates (WR-36)", () => {
  it("presents the client cert on the H2 handshake and pins the server", async () => {
    let presentedCN: string | undefined;
    const server = createH2SecureServer({
      key: MTLS_SERVER_KEY_PEM,
      cert: MTLS_SERVER_CERT_PEM,
      requestCert: true,
      ca: [MTLS_CA_PEM],
    });
    server.on("stream", (stream) => {
      const sock = (stream.session as ServerHttp2Session).socket as unknown as {
        getPeerCertificate(): { subject?: { CN?: string } };
      };
      presentedCN = sock.getPeerCertificate().subject?.CN;
      stream.resume();
      stream.on("end", () => {
        stream.respond({ ":status": 200 });
        stream.end("ok");
      });
    });
    const port = await listen(server);
    const url = `https://127.0.0.1:${port}/hook`;
    const serverPin = `sha256/${spkiFingerprint(Buffer.from(new X509Certificate(MTLS_SERVER_CERT_PEM).raw))}`;
    const sender = createDefaultSender(
      { [url]: [serverPin] },
      undefined, undefined, undefined,
      { [url]: { cert: MTLS_CLIENT_CERT_PEM, key: MTLS_CLIENT_KEY_PEM } },
      undefined,
      { enabled: true, hosts: ["127.0.0.1"] }
    );
    for (let i = 0; i < 2; i++) {
      const res = await sender(item(url));
      assert.ok(res && res.statusCode === 200);
    }
    assert.equal(presentedCN, "relay-client");
    const stats = sender.http2Pool!.getStats();
    assert.equal(stats.established, 1);
    assert.equal(stats.reused, 1);
    assert.equal(stats.sessions[0]!.pinned, true);
    assert.equal(stats.sessions[0]!.clientCert, true);
    sender.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("http2: fallback to HTTP/1.1", () => {
  let server: Server;
  let targetUrl: string;

  before(async () => {
    // A plain HTTP/1.1 server refuses H2 (h2c preface is garbage to it).
    server = createServer((req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    const port = await listen(server);
    targetUrl = `http://127.0.0.1:${port}/hook`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("never loses a delivery when H2 is refused", async () => {
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"], fallbackCooldownMs: 60_000 }
    );
    for (let i = 0; i < 3; i++) {
      const res = await sender(item(targetUrl));
      assert.ok(res && res.statusCode === 200, `delivery ${i} must succeed via fallback`);
    }
    const stats = sender.http2Pool!.getStats();
    assert.equal(stats.fallback, 3);
    // The HTTP/1.1 pool served the fallbacks (and reused its connections).
    assert.ok(sender.pool!.getStats().reused >= 1);
    sender.destroy();
  });

  it("non-2xx over H2 surfaces HttpDeliveryError without fallback", async () => {
    const failing = createH2Server();
    failing.on("stream", (stream) => {
      stream.resume();
      stream.on("end", () => {
        stream.respond({ ":status": 500 });
        stream.end("boom");
      });
    });
    const port = await listen(failing);
    const url = `http://127.0.0.1:${port}/hook`;
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"] }
    );
    await assert.rejects(sender(item(url)), (err: Error) => {
      assert.ok(err instanceof HttpDeliveryError);
      assert.equal((err as HttpDeliveryError).statusCode, 500);
      return true;
    });
    // An application-level 500 is not an H2 transport failure: no fallback.
    assert.equal(sender.http2Pool!.getStats().fallback, 0);
    sender.destroy();
    await new Promise<void>((resolve) => failing.close(() => resolve()));
  });
});

describe("http2: proxy interplay", () => {
  it("proxied endpoints bypass H2 and ride the HTTP/1.1 tunnel", async () => {
    const target = createServer((req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    const targetPort = await listen(target);
    const targetUrl = `http://127.0.0.1:${targetPort}/hook`;
    const proxy = await startConnectProxy();
    try {
      await withProxyEnv({}, async () => {
        const sender = createDefaultSender(
          undefined, undefined, undefined,
          { [targetUrl]: `http://127.0.0.1:${proxy.port}` },
          undefined, undefined,
          { enabled: true, hosts: ["127.0.0.1"] }
        );
        const res = await sender(item(targetUrl));
        assert.ok(res && res.statusCode === 200);
        // The delivery went through the proxy tunnel, never H2.
        assert.deepEqual(proxy.hits, [`127.0.0.1:${targetPort}`]);
        assert.equal(sender.http2Pool!.getStats().established, 0);
        assert.equal(sender.http2Pool!.getStats().fallback, 0);
        sender.destroy();
      });
    } finally {
      await proxy.close();
      await new Promise<void>((resolve) => target.close(() => resolve()));
    }
  });
});

describe("http2: stats and destroy", () => {
  it("getStats reports per-session state and totals", async () => {
    const stub = startH2cStub();
    const url = `http://127.0.0.1:${await stub.port}/hook`;
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"] }
    );
    await sender(item(url));
    const stats = sender.http2Pool!.getStats();
    assert.equal(stats.sessions.length, 1);
    const s = stats.sessions[0]!;
    assert.match(s.key, /^http\/\/127\.0\.0\.1:\d+$/);
    assert.equal(s.scheme, "http");
    assert.equal(s.host, "127.0.0.1");
    assert.equal(typeof s.port, "number");
    assert.equal(s.activeStreams, 0);
    assert.equal(s.connected, true);
    assert.equal(stats.established, 1);
    sender.destroy();
    assert.equal(sender.http2Pool!.getStats().sessions.length, 0);
    await stub.close();
  });

  it("Http2UnavailableError carries its cause", () => {
    const cause = new Error("boom");
    const err = new Http2UnavailableError("nope", cause);
    assert.equal(err.name, "Http2UnavailableError");
    assert.equal(err.cause, cause);
    assert.match(err.message, /HTTP\/2 unavailable/);
  });
});
