import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  createServer as createNetServer,
  connect as tcpConnect,
  type Server as NetServer,
  type Socket,
} from "node:net";
import {
  createServer as createHttpServer,
  get as httpGet,
  type Server as HttpServer,
} from "node:http";
import {
  createServer as createHttpsServer,
  get as httpsGet,
  type Server as HttpsServer,
} from "node:https";
import {
  Socks5Error,
  assertValidSocks5Url,
  isSocks5ProxyUrl,
  connectViaSocks5,
  createSocks5Agent,
  socksPoolKeyFragment,
} from "../src/socks5.ts";
import { proxyPoolKeyFragment } from "../src/proxy.ts";
import { TLS_FIXTURE_CERT_PEM, TLS_FIXTURE_KEY_PEM } from "./tls-fixture.ts";

// Credential names stay lowercase/mixed-case: an all-caps `SECRET`
// constant would be rewritten by the runtime redaction pass.
const PROXY_USER = "relayuser";
const PROXY_PASS = "wonderland-99";

async function listen(server: NetServer | HttpServer | HttpsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

/**
 * Buffered exact-size reader for a socket. Bytes beyond the requested
 * size stay in the buffer for the next read — a plain "read n bytes"
 * helper drops them, which deadlocks multi-phase handshakes when the
 * peer coalesces writes (e.g. the 3-byte SOCKS5 greeting).
 */
class SocketReader {
  private buf = Buffer.alloc(0);
  private waiter: ((chunk: Buffer | null) => void) | null = null;

  constructor(client: Socket) {
    client.on("data", (chunk: Buffer) => {
      if (this.waiter !== null) {
        const w = this.waiter;
        this.waiter = null;
        w(chunk);
      } else {
        this.buf = Buffer.concat([this.buf, chunk]);
      }
    });
    client.on("close", () => {
      const w = this.waiter;
      this.waiter = null;
      if (w) w(null);
    });
    client.on("error", () => {
      // Errors surface as a close; the reader just needs to stop waiting.
    });
  }

  async readExactly(n: number): Promise<Buffer> {
    while (this.buf.length < n) {
      const chunk = await new Promise<Buffer | null>((resolve) => {
        this.waiter = resolve;
      });
      if (chunk === null) throw new Error("socket closed before enough bytes");
      this.buf = Buffer.concat([this.buf, chunk]);
    }
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return Buffer.from(out);
  }
}

interface FakeSocks5Config {
  username?: string;
  password?: string;
  /** CONNECT reply code; default 0x00 (success). */
  rep?: number;
}

interface FakeSocks5 {
  server: NetServer;
  port: number;
  proxyUrl: string;
  seenGreetings: Buffer[];
  seenAuth: Buffer[];
  connectRequests: { host: string; port: number }[];
  close(): Promise<void>;
}

function formatIPv6(bytes: Buffer): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(bytes.readUInt16BE(i).toString(16));
  return groups.join(":");
}

/** A minimal in-test SOCKS5 server (RFC 1928) on 127.0.0.1. */
async function startFakeSocks5(cfg: FakeSocks5Config = {}): Promise<FakeSocks5> {
  const seenGreetings: Buffer[] = [];
  const seenAuth: Buffer[] = [];
  const connectRequests: { host: string; port: number }[] = [];
  const clients = new Set<Socket>();
  const server = createNetServer((client) => {
    clients.add(client);
    client.on("close", () => clients.delete(client));
    handle(client).catch(() => client.destroy());
  });

  async function handle(client: Socket): Promise<void> {
    const reader = new SocketReader(client);
    // Greeting.
    const head = await reader.readExactly(2);
    if (head[0] !== 0x05) {
      client.destroy();
      return;
    }
    const methods = await reader.readExactly(head[1]);
    seenGreetings.push(Buffer.concat([head, methods]));
    const wantsAuth = cfg.username !== undefined;
    if (wantsAuth && methods.includes(0x02)) {
      client.write(Buffer.from([0x05, 0x02]));
    } else {
      client.write(Buffer.from([0x05, 0x00]));
    }
    // Username/password subnegotiation (RFC 1929).
    if (wantsAuth && methods.includes(0x02)) {
      const authHead = await reader.readExactly(2);
      const uname = await reader.readExactly(authHead[1]);
      const plenBuf = await reader.readExactly(1);
      const passwd = await reader.readExactly(plenBuf[0]);
      seenAuth.push(Buffer.concat([authHead, uname, plenBuf, passwd]));
      const ok =
        authHead[0] === 0x01 &&
        uname.toString("utf8") === cfg.username &&
        passwd.toString("utf8") === cfg.password;
      client.write(Buffer.from([0x01, ok ? 0x00 : 0x01]));
      if (!ok) {
        client.destroy();
        return;
      }
    }
    // CONNECT request.
    const reqHead = await reader.readExactly(4);
    const atyp = reqHead[3];
    let host: string;
    if (atyp === 0x01) {
      const b = await reader.readExactly(4);
      host = [...b].join(".");
    } else if (atyp === 0x04) {
      host = formatIPv6(await reader.readExactly(16));
    } else if (atyp === 0x03) {
      const len = (await reader.readExactly(1))[0];
      host = (await reader.readExactly(len)).toString("utf8");
    } else {
      client.destroy();
      return;
    }
    const port = (await reader.readExactly(2)).readUInt16BE(0);
    connectRequests.push({ host, port });
    const rep = cfg.rep ?? 0x00;
    client.write(Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
    if (rep !== 0x00) {
      client.destroy();
      return;
    }
    // Tunnel: pipe the client through to the requested target.
    const upstream = tcpConnect({ host, port });
    upstream.on("connect", () => {
      client.pipe(upstream);
      upstream.pipe(client);
    });
    upstream.on("error", () => client.destroy());
    client.on("error", () => upstream.destroy());
    client.on("close", () => upstream.destroy());
  }

  const port = await listen(server);
  return {
    server,
    port,
    proxyUrl: `socks5://127.0.0.1:${port}`,
    seenGreetings,
    seenAuth,
    connectRequests,
    close: async () => {
      for (const c of clients) c.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** Accumulate a socket's bytes until it ends/closes (with a timeout). */
function readUntilClose(sock: Socket, timeoutMs = 10_000): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let done = false;
    const finish = (fn: () => void): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.off("data", onData);
      sock.off("end", onEnd);
      sock.off("close", onEnd);
      sock.off("error", onErr);
      fn();
    };
    const timer = setTimeout(() => finish(() => reject(new Error("timed out waiting for socket close"))), timeoutMs);
    timer.unref();
    const onData = (c: Buffer): void => chunks.push(c);
    const onEnd = (): void => finish(() => resolve(Buffer.concat(chunks)));
    const onErr = (e: Error): void => finish(() => reject(e));
    sock.on("data", onData);
    sock.on("end", onEnd);
    sock.on("close", onEnd);
    sock.on("error", onErr);
  });
}

describe("assertValidSocks5Url", () => {
  it("accepts socks5://user:pass@127.0.0.1:1080", () => {
    const url = assertValidSocks5Url("socks5://user:pass@127.0.0.1:1080");
    assert.equal(url.protocol, "socks5:");
    assert.equal(url.hostname, "127.0.0.1");
    assert.equal(url.port, "1080");
    assert.equal(url.username, "user");
    assert.equal(url.password, "pass");
  });

  it("accepts a URL with no explicit port (1080 is the dial-time default)", () => {
    const url = assertValidSocks5Url("socks5://proxy.internal");
    assert.equal(url.hostname, "proxy.internal");
    assert.equal(url.port, "");
  });

  it("rejects an http:// proxy URL", () => {
    assert.throws(() => assertValidSocks5Url("http://127.0.0.1:8080"), RangeError);
  });

  it("rejects garbage", () => {
    assert.throws(() => assertValidSocks5Url("not a url"), RangeError);
    assert.throws(() => assertValidSocks5Url(""), RangeError);
  });

  it("rejects a URL with a missing hostname", () => {
    assert.throws(() => assertValidSocks5Url("socks5://"), RangeError);
    assert.throws(() => assertValidSocks5Url("socks5://:1080"), RangeError);
  });
});

describe("isSocks5ProxyUrl", () => {
  it("returns true for socks5:// URLs, case-insensitively", () => {
    assert.equal(isSocks5ProxyUrl("socks5://127.0.0.1:1080"), true);
    assert.equal(isSocks5ProxyUrl("SOCKS5://127.0.0.1:1080"), true);
    assert.equal(isSocks5ProxyUrl("socks5://user:pass@proxy:1080"), true);
  });

  it("returns false for http:// and garbage, without throwing", () => {
    assert.equal(isSocks5ProxyUrl("http://127.0.0.1:8080"), false);
    assert.equal(isSocks5ProxyUrl("not a url"), false);
    assert.equal(isSocks5ProxyUrl(""), false);
  });
});

describe("socksPoolKeyFragment", () => {
  it("is deterministic and shaped like |socks5:<16 hex>", () => {
    const a = socksPoolKeyFragment("socks5://127.0.0.1:1080");
    const b = socksPoolKeyFragment("socks5://127.0.0.1:1080");
    assert.equal(a, b);
    assert.match(a, /^\|socks5:[0-9a-f]{16}$/);
  });

  it("does not collide with the HTTP-CONNECT pool fragment for the same URL", () => {
    const url = "socks5://127.0.0.1:1080";
    assert.notEqual(socksPoolKeyFragment(url), proxyPoolKeyFragment(url));
    assert.ok(!socksPoolKeyFragment(url).startsWith("|proxy:"));
  });
});

describe("connectViaSocks5 option validation", () => {
  it("throws RangeError synchronously for non-positive connectTimeoutMs", () => {
    assert.throws(
      () => connectViaSocks5("socks5://127.0.0.1:1080", "example.com", 80, { connectTimeoutMs: 0 }),
      RangeError
    );
    assert.throws(
      () => connectViaSocks5("socks5://127.0.0.1:1080", "example.com", 80, { connectTimeoutMs: -5 }),
      RangeError
    );
  });

  it("throws RangeError synchronously for an invalid proxy URL", () => {
    assert.throws(() => connectViaSocks5("http://127.0.0.1:8080", "example.com", 80), RangeError);
  });
});

describe("connectViaSocks5 handshake against a fake SOCKS5 server", () => {
  let proxy: FakeSocks5;
  let httpTarget: HttpServer;
  let httpPort: number;

  before(async () => {
    proxy = await startFakeSocks5();
    httpTarget = createHttpServer((_req, res) => {
      res.end("socks5-pong");
    });
    httpPort = await listen(httpTarget);
  });

  after(async () => {
    await proxy.close();
    httpTarget.closeAllConnections();
    await new Promise<void>((resolve) => httpTarget.close(() => resolve()));
  });

  it("no-auth flow: sends greeting [0x05, 0x01, 0x00] and tunnels", async () => {
    const before = proxy.seenGreetings.length;
    const sock = await connectViaSocks5(proxy.proxyUrl, "127.0.0.1", httpPort);
    try {
      assert.deepEqual(proxy.seenGreetings[before], Buffer.from([0x05, 0x01, 0x00]));
      const req = proxy.connectRequests[proxy.connectRequests.length - 1];
      assert.deepEqual(req, { host: "127.0.0.1", port: httpPort });
    } finally {
      sock.destroy();
    }
  });

  it("CONNECTs a local plain HTTP server through the tunnel: request/response round-trips", async () => {
    const sock = await connectViaSocks5(proxy.proxyUrl, "127.0.0.1", httpPort);
    try {
      sock.write("GET /ping HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
      const resp = await readUntilClose(sock);
      const text = resp.toString("latin1");
      // Node's HTTP server answers HTTP/1.1 even to a 1.0 request.
      assert.match(text, /^HTTP\/1\.[01] 200 OK/);
      assert.match(text, /socks5-pong/);
    } finally {
      sock.destroy();
    }
  });

  it("domain-name targets use ATYP 0x03 (the fake server sees the name)", async () => {
    const before = proxy.connectRequests.length;
    const sock = await connectViaSocks5(proxy.proxyUrl, "localhost", httpPort);
    try {
      const req = proxy.connectRequests[before];
      assert.deepEqual(req, { host: "localhost", port: httpPort });
    } finally {
      sock.destroy();
    }
  });
});

describe("connectViaSocks5 username/password auth", () => {
  let proxy: FakeSocks5;

  before(async () => {
    proxy = await startFakeSocks5({ username: PROXY_USER, password: PROXY_PASS });
  });

  after(async () => {
    await proxy.close();
  });

  const authedProxyUrl = (): string =>
    `socks5://${encodeURIComponent(PROXY_USER)}:${encodeURIComponent(PROXY_PASS)}@127.0.0.1:${proxy.port}`;

  it("sends the username/password subnegotiation and connects", async () => {
    const before = proxy.seenAuth.length;
    // Target a port nothing listens on... actually a live blackhole: the
    // handshake itself is what we assert. resume() keeps the server-side
    // socket from lingering half-open (see the timeout test).
    const blackhole = createNetServer((s) => {
      s.resume();
    });
    const targetPort = await listen(blackhole);
    try {
      const sock = await connectViaSocks5(authedProxyUrl(), "127.0.0.1", targetPort);
      sock.destroy();
      const auth = proxy.seenAuth[before];
      assert.equal(auth[0], 0x01);
      assert.equal(auth[1], PROXY_USER.length);
      assert.equal(auth.subarray(2, 2 + PROXY_USER.length).toString("utf8"), PROXY_USER);
      const plenOff = 2 + PROXY_USER.length;
      assert.equal(auth[plenOff], PROXY_PASS.length);
      assert.equal(
        auth.subarray(plenOff + 1, plenOff + 1 + PROXY_PASS.length).toString("utf8"),
        PROXY_PASS
      );
    } finally {
      await new Promise<void>((resolve) => blackhole.close(() => resolve()));
    }
  });

  it("rejects with Socks5Error when the password is wrong", async () => {
    await assert.rejects(
      () =>
        connectViaSocks5(
          `socks5://${encodeURIComponent(PROXY_USER)}:wrong-pass@127.0.0.1:${proxy.port}`,
          "127.0.0.1",
          80
        ),
      (err: unknown) => {
        assert.ok(err instanceof Socks5Error);
        assert.match((err as Error).message, /authentication rejected/);
        assert.equal((err as Socks5Error).stage, "auth");
        return true;
      }
    );
  });
});

describe("connectViaSocks5 CONNECT failures", () => {
  it("rejects with Socks5Error when the proxy answers REP=0x05 (connection refused)", async () => {
    const proxy = await startFakeSocks5({ rep: 0x05 });
    try {
      await assert.rejects(
        () => connectViaSocks5(proxy.proxyUrl, "127.0.0.1", 80),
        (err: unknown) => {
          assert.ok(err instanceof Socks5Error);
          assert.match((err as Error).message, /refused/);
          assert.equal((err as Socks5Error).stage, "connect");
          assert.equal((err as Socks5Error).targetHost, "127.0.0.1");
          assert.equal((err as Socks5Error).proxyUrl, proxy.proxyUrl);
          return true;
        }
      );
    } finally {
      await proxy.close();
    }
  });

  it("rejects with Socks5Error on TCP connect failure", async () => {
    // A port that was just closed: nothing listens there.
    const tmp = createNetServer(() => {});
    const port = await listen(tmp);
    await new Promise<void>((resolve) => tmp.close(() => resolve()));
    await assert.rejects(
      () => connectViaSocks5(`socks5://127.0.0.1:${port}`, "127.0.0.1", 80),
      (err: unknown) => {
        assert.ok(err instanceof Socks5Error);
        assert.match((err as Error).message, /TCP connect to proxy failed/);
        return true;
      }
    );
  });

  it("rejects with Socks5Error within connectTimeoutMs against a blackhole", async () => {
    // Accepts the TCP connection but never speaks SOCKS5. resume() puts
    // the socket in flowing mode and discards bytes: without a reader the
    // greeting + FIN would leave the server-side socket half-open forever
    // (a paused socket never emits 'end'/'close' with unread data) and
    // server.close() below would hang.
    const blackhole = createNetServer((s) => {
      s.resume();
    });
    const port = await listen(blackhole);
    try {
      const started = Date.now();
      await assert.rejects(
        () =>
          connectViaSocks5(`socks5://127.0.0.1:${port}`, "127.0.0.1", 80, {
            connectTimeoutMs: 300,
          }),
        (err: unknown) => {
          assert.ok(err instanceof Socks5Error);
          assert.match((err as Error).message, /timed out after 300ms/);
          return true;
        }
      );
      const elapsed = Date.now() - started;
      assert.ok(elapsed < 10_000, `timeout took too long: ${elapsed}ms`);
    } finally {
      await new Promise<void>((resolve) => blackhole.close(() => resolve()));
    }
  });
});

describe("createSocks5Agent", () => {
  let proxy: FakeSocks5;
  let httpTarget: HttpServer;
  let httpPort: number;

  before(async () => {
    proxy = await startFakeSocks5();
    httpTarget = createHttpServer((_req, res) => {
      res.end("agent-pong");
    });
    httpPort = await listen(httpTarget);
  });

  after(async () => {
    await proxy.close();
    httpTarget.closeAllConnections();
    await new Promise<void>((resolve) => httpTarget.close(() => resolve()));
  });

  it("rejects invalid proxy URLs", () => {
    assert.throws(() => createSocks5Agent("http", "http://127.0.0.1:8080"), RangeError);
  });

  it("http end-to-end: http.request through the SOCKS5 tunnel returns 200 + body", async () => {
    const agent = createSocks5Agent("http", proxy.proxyUrl);
    try {
      const { statusCode, body } = await new Promise<{ statusCode?: number; body: string }>(
        (resolve, reject) => {
          const req = httpGet(
            { host: "127.0.0.1", port: httpPort, path: "/agent", agent },
            (res) => {
              const chunks: Buffer[] = [];
              res.on("data", (c: Buffer) => chunks.push(c));
              res.on("end", () =>
                resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString() })
              );
            }
          );
          req.on("error", reject);
          req.setTimeout(10_000, () => req.destroy(new Error("http request timed out")));
        }
      );
      assert.equal(statusCode, 200);
      assert.equal(body, "agent-pong");
    } finally {
      agent.destroy();
    }
  });
});

describe("createSocks5Agent https smoke", () => {
  let proxy: FakeSocks5;
  let httpsTarget: HttpsServer;
  let httpsPort: number;

  before(async () => {
    proxy = await startFakeSocks5();
    httpsTarget = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
      (_req, res) => {
        res.end("tls-pong");
      }
    );
    httpsPort = await listen(httpsTarget);
  });

  after(async () => {
    await proxy.close();
    httpsTarget.closeAllConnections();
    await new Promise<void>((resolve) => httpsTarget.close(() => resolve()));
  });

  it("https request through the SOCKS5 tunnel returns 200 + body", async () => {
    const agent = createSocks5Agent("https", proxy.proxyUrl);
    try {
      const { statusCode, body } = await new Promise<{ statusCode?: number; body: string }>(
        (resolve, reject) => {
          const req = httpsGet(
            {
              host: "127.0.0.1",
              port: httpsPort,
              path: "/tls",
              agent,
              // Self-signed fixture cert: the tunnel is what we exercise,
              // not the trust chain.
              rejectUnauthorized: false,
            },
            (res) => {
              const chunks: Buffer[] = [];
              res.on("data", (c: Buffer) => chunks.push(c));
              res.on("end", () =>
                resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString() })
              );
            }
          );
          req.on("error", reject);
          req.setTimeout(10_000, () => req.destroy(new Error("https request timed out")));
        }
      );
      assert.equal(statusCode, 200);
      assert.equal(body, "tls-pong");
    } finally {
      agent.destroy();
    }
  });
});
