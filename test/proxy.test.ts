import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, type Server, type IncomingMessage } from "node:http";
import { connect as tcpConnect, type Socket } from "node:net";
import {
  assertValidProxyUrl,
  createProxiedAgent,
  ProxyConnectError,
  resolveProxyUrl,
} from "../src/proxy.ts";
import { createDefaultSender } from "../src/server.ts";
import { TlsPinMismatchError } from "../src/pinning.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

const BODY = Buffer.from(JSON.stringify({ event: "proxy.probe" }));
const WRONG_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const item = (targetUrl: string) => ({ id: "p1", payload: BODY, targetUrl, headers: {} });

async function listen(server: Server | HttpsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
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

interface ProxyHit {
  target: string;
  authHeader: string | undefined;
}

/** A minimal CONNECT proxy. `requireAuth` is the expected base64 userinfo. */
async function startConnectProxy(opts: { requireAuth?: string } = {}): Promise<{
  server: Server;
  port: number;
  hits: ProxyHit[];
  close: () => Promise<void>;
}> {
  const hits: ProxyHit[] = [];
  const server = createServer();
  server.on(
    "connect",
    (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
      const authHeader = req.headers["proxy-authorization"] as string | undefined;
      const target = req.url ?? "";
      hits.push({ target, authHeader });
      clientSocket.on("error", () => {});
      if (opts.requireAuth !== undefined && authHeader !== `Basic ${opts.requireAuth}`) {
        clientSocket.write(
          "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"
        );
        clientSocket.destroy();
        return;
      }
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
    }
  );
  const port = await listen(server);
  return {
    server,
    port,
    hits,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("assertValidProxyUrl", () => {
  it("accepts a plain-HTTP proxy URL", () => {
    assert.doesNotThrow(() => assertValidProxyUrl("http://proxy.internal:8080"));
  });

  it("rejects proxy-over-TLS (out of scope)", () => {
    assert.throws(() => assertValidProxyUrl("https://proxy.internal:8443"), RangeError);
  });

  it("rejects garbage and missing hostnames", () => {
    assert.throws(() => assertValidProxyUrl("not a url"), RangeError);
    assert.throws(() => assertValidProxyUrl("http://"), RangeError);
    assert.throws(() => assertValidProxyUrl(""), RangeError);
  });
});

describe("resolveProxyUrl", () => {
  it("returns undefined with no config and no env", async () => {
    await withProxyEnv({}, async () => {
      assert.equal(resolveProxyUrl("http://example.com/hook"), undefined);
    });
  });

  it("explicit per-endpoint config wins over the environment", async () => {
    await withProxyEnv({ HTTP_PROXY: "http://env:8080" }, async () => {
      assert.equal(
        resolveProxyUrl("http://example.com/hook", {
          "http://example.com/hook": "http://explicit:9090",
        }),
        "http://explicit:9090"
      );
      // ...but only for the exact targetUrl.
      assert.equal(
        resolveProxyUrl("http://other.com/hook", {
          "http://example.com/hook": "http://explicit:9090",
        }),
        "http://env:8080"
      );
    });
  });

  it("falls back to scheme-specific env vars, then ALL_PROXY", async () => {
    await withProxyEnv(
      {
        HTTP_PROXY: "http://h:1111",
        HTTPS_PROXY: "http://s:2222",
        ALL_PROXY: "http://a:3333",
      },
      async () => {
        assert.equal(resolveProxyUrl("http://example.com/"), "http://h:1111");
        assert.equal(resolveProxyUrl("https://example.com/"), "http://s:2222");
      }
    );
    await withProxyEnv({ ALL_PROXY: "http://a:3333" }, async () => {
      assert.equal(resolveProxyUrl("http://example.com/"), "http://a:3333");
      assert.equal(resolveProxyUrl("https://example.com/"), "http://a:3333");
    });
  });

  it("NO_PROXY bypasses the env fallback (exact, suffix, wildcard)", async () => {
    await withProxyEnv(
      { HTTP_PROXY: "http://h:1111", NO_PROXY: "internal.example.com, .corp.example, *" },
      async () => {
        assert.equal(resolveProxyUrl("http://internal.example.com/"), undefined);
        assert.equal(resolveProxyUrl("http://a.corp.example/"), undefined);
        assert.equal(resolveProxyUrl("http://anything.else/"), undefined);
      }
    );
    await withProxyEnv(
      { HTTP_PROXY: "http://h:1111", NO_PROXY: ".corp.example" },
      async () => {
        // A leading-dot entry matches subdomains, not the bare domain.
        assert.equal(resolveProxyUrl("http://a.corp.example/"), undefined);
        assert.equal(resolveProxyUrl("http://corp.example/"), "http://h:1111");
      }
    );
  });

  it("an explicit entry wins over NO_PROXY", async () => {
    await withProxyEnv({ HTTP_PROXY: "http://h:1111", NO_PROXY: "*" }, async () => {
      assert.equal(
        resolveProxyUrl("http://example.com/hook", {
          "http://example.com/hook": "http://explicit:9090",
        }),
        "http://explicit:9090"
      );
    });
  });

  it("an invalid env proxy URL throws RangeError", async () => {
    await withProxyEnv({ HTTP_PROXY: "https://tls-proxy:8443" }, async () => {
      assert.throws(() => resolveProxyUrl("http://example.com/"), RangeError);
    });
  });

  it("non-HTTP(S) targets never use a proxy", async () => {
    await withProxyEnv({ ALL_PROXY: "http://a:3333" }, async () => {
      assert.equal(resolveProxyUrl("ftp://example.com/x"), undefined);
    });
  });
});

describe("CONNECT tunneling", () => {
  let target: Server;
  let targetPort: number;
  let received: { url: string; body: Buffer }[];
  let proxy: Awaited<ReturnType<typeof startConnectProxy>>;

  before(async () => {
    received = [];
    target = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push({ url: req.url ?? "", body: Buffer.concat(chunks) });
        res.end("ok");
      });
    });
    targetPort = await listen(target);
    proxy = await startConnectProxy();
  });

  after(async () => {
    await proxy.close();
    await new Promise<void>((resolve) => target.close(() => resolve()));
  });

  const targetUrl = () => `http://127.0.0.1:${targetPort}/hook`;
  const proxyUrl = () => `http://127.0.0.1:${proxy.port}`;

  it("delivers through the proxy tunnel (pooled: one CONNECT, many deliveries)", async () => {
    await withProxyEnv({}, async () => {
      const sender = createDefaultSender(undefined, undefined, undefined, {
        [targetUrl()]: proxyUrl(),
      });
      try {
        await sender(item(targetUrl()));
        await sender(item(targetUrl()));
        assert.equal(received.length, 2);
        assert.deepEqual(received[0].body, BODY);
        // One CONNECT for both deliveries: the tunneled socket is pooled.
        assert.equal(proxy.hits.length, 1);
        assert.equal(proxy.hits[0].target, `127.0.0.1:${targetPort}`);
        // The pool key binds the proxy.
        const keys = (sender.pool?.getStats().endpoints ?? []).map((e) => e.key);
        assert.ok(
          keys.some((k) => k.includes("|proxy:")),
          `expected a proxy-bound pool key, got ${JSON.stringify(keys)}`
        );
      } finally {
        sender.destroy();
      }
    });
  });

  it("pooling disabled: each delivery opens its own tunnel", async () => {
    const before = proxy.hits.length;
    await withProxyEnv({}, async () => {
      const sender = createDefaultSender(undefined, false, undefined, {
        [targetUrl()]: proxyUrl(),
      });
      try {
        assert.equal(sender.pool, undefined);
        await sender(item(targetUrl()));
        await sender(item(targetUrl()));
        assert.equal(proxy.hits.length - before, 2);
      } finally {
        sender.destroy();
      }
    });
  });

  it("proxy basic auth from the URL userinfo; wrong creds fail with 407", async () => {
    const authed = await startConnectProxy({
      requireAuth: Buffer.from("user:s3cret").toString("base64"),
    });
    try {
      await withProxyEnv({}, async () => {
        const good = `http://user:s3cret@127.0.0.1:${authed.port}`;
        const sender = createDefaultSender(undefined, false, undefined, {
          [targetUrl()]: good,
        });
        try {
          await sender(item(targetUrl()));
        } finally {
          sender.destroy();
        }
        assert.equal(authed.hits[0].authHeader, `Basic ${Buffer.from("user:s3cret").toString("base64")}`);

        const bad = `http://user:wrong@127.0.0.1:${authed.port}`;
        const badSender = createDefaultSender(undefined, false, undefined, {
          [targetUrl()]: bad,
        });
        try {
          await assert.rejects(() => badSender(item(targetUrl())), (err: unknown) => {
            assert.ok(err instanceof ProxyConnectError);
            assert.equal((err as ProxyConnectError).statusCode, 407);
            return true;
          });
        } finally {
          badSender.destroy();
        }
      });
    } finally {
      await authed.close();
    }
  });

  it("env fallback routes deliveries without explicit config", async () => {
    const before = proxy.hits.length;
    await withProxyEnv({ HTTP_PROXY: proxyUrl(), NO_PROXY: "" }, async () => {
      const sender = createDefaultSender();
      try {
        await sender(item(targetUrl()));
        assert.equal(proxy.hits.length - before, 1);
      } finally {
        sender.destroy();
      }
    });
  });

  it("NO_PROXY bypasses the env proxy for the target", async () => {
    // A bogus proxy would refuse the connection; NO_PROXY must skip it.
    await withProxyEnv(
      { HTTP_PROXY: "http://127.0.0.1:1", NO_PROXY: "127.0.0.1" },
      async () => {
        const sender = createDefaultSender();
        try {
          await sender(item(targetUrl()));
        } finally {
          sender.destroy();
        }
      }
    );
  });

  it("createDefaultSender rejects invalid proxy URLs at startup", () => {
    assert.throws(
      () =>
        createDefaultSender(undefined, undefined, undefined, {
          "http://example.com/hook": "https://tls-proxy:8443",
        }),
      RangeError
    );
    assert.throws(
      () =>
        createDefaultSender(undefined, undefined, undefined, {
          "http://example.com/hook": "not a url",
        }),
      RangeError
    );
  });

  it("createProxiedAgent rejects invalid proxy URLs", () => {
    assert.throws(() => createProxiedAgent("http", "https://tls-proxy:8443"), RangeError);
  });
});

describe("HTTPS through the proxy with TLS pinning", () => {
  let httpsTarget: HttpsServer;
  let httpsPort: number;
  let received: Buffer[];
  let proxy: Awaited<ReturnType<typeof startConnectProxy>>;

  before(async () => {
    received = [];
    httpsTarget = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
      (req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          received.push(Buffer.concat(chunks));
          res.end("ok");
        });
      }
    );
    httpsPort = await listen(httpsTarget);
    proxy = await startConnectProxy();
  });

  after(async () => {
    await proxy.close();
    await new Promise<void>((resolve) => httpsTarget.close(() => resolve()));
  });

  const targetUrl = () => `https://127.0.0.1:${httpsPort}/hook`;
  const proxyUrl = () => `http://127.0.0.1:${proxy.port}`;

  it("pin verified after the tunnel handshake: matching pin delivers", async () => {
    await withProxyEnv({}, async () => {
      const sender = createDefaultSender(
        { [targetUrl()]: [TLS_FIXTURE_SPKI_PIN] },
        undefined,
        undefined,
        { [targetUrl()]: proxyUrl() }
      );
      try {
        await sender(item(targetUrl()));
        assert.equal(received.length, 1);
        assert.deepEqual(received[0], BODY);
        assert.equal(proxy.hits.length, 1);
        assert.equal(proxy.hits[0].target, `127.0.0.1:${httpsPort}`);
      } finally {
        sender.destroy();
      }
    });
  });

  it("pin verified after the tunnel handshake: mismatch fails before any payload byte", async () => {
    await withProxyEnv({}, async () => {
      const sender = createDefaultSender(
        { [targetUrl()]: [WRONG_PIN] },
        undefined,
        undefined,
        { [targetUrl()]: proxyUrl() }
      );
      try {
        const before = received.length;
        await assert.rejects(() => sender(item(targetUrl())), TlsPinMismatchError);
        assert.equal(received.length, before);
      } finally {
        sender.destroy();
      }
    });
  });
});
