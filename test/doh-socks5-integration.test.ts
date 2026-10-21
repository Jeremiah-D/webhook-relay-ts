import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  createServer,
  request as httpRequest,
  type Server,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import {
  createServer as createNetServer,
  connect as tcpConnect,
  type Socket,
} from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDefaultSender,
  createRelayServer,
  type RelayServer,
} from "../src/server.ts";
import { resolveProxyUrl } from "../src/proxy.ts";
import { OutboundConnectionPool } from "../src/keepalive.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const RELAY_SECRET = "doh-socks5-integration-key";
const BODY = Buffer.from(JSON.stringify({ event: "integration.probe" }));
const item = (targetUrl: string) => ({ id: "i1", payload: BODY, targetUrl, headers: {} });

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

async function waitFor(fn: () => boolean, timeoutMs = 8000): Promise<void> {
  const start = Date.now();
  while (!fn()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
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

/** Downstream stub recording received deliveries. */
function startStub(): { server: Server; received: { url: string; body: Buffer }[] } {
  const received: { url: string; body: Buffer }[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => {
      received.push({ url: req.url ?? "", body: Buffer.concat(chunks) });
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
  });
  return { server, received };
}

/**
 * Minimal fake DNS-over-HTTPS server (plain HTTP). Answers A queries for
 * names where `answerFor` returns an IPv4 address; anything else gets
 * NXDOMAIN (RCODE=3). `status` forces every response to that HTTP status
 * (for failure-path tests).
 */
function startFakeDoh(
  answerFor: (name: string) => string | undefined,
  opts: { status?: number } = {}
): { server: Server; queries: () => number } {
  let queries = 0;
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    queries += 1;
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => {
      if (opts.status !== undefined) {
        res.writeHead(opts.status);
        res.end();
        return;
      }
      const q = Buffer.concat(chunks);
      const id = q.subarray(0, 2);
      let p = 12;
      let name = "";
      while (q[p] !== 0) {
        const len = q[p];
        name += (name === "" ? "" : ".") + q.subarray(p + 1, p + 1 + len).toString("ascii");
        p += len + 1;
      }
      const qnameEnd = p;
      const question = q.subarray(12, qnameEnd + 5); // QNAME + QTYPE + QCLASS
      const ip = answerFor(name);
      if (ip === undefined) {
        const head = Buffer.concat([
          id,
          Buffer.from([0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
          question,
        ]);
        res.writeHead(200, {
          "content-type": "application/dns-message",
          "content-length": head.length,
        });
        res.end(head);
        return;
      }
      const octets = ip.split(".").map(Number);
      assert.equal(octets.length, 4);
      const answer = Buffer.concat([
        Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]), // compressed name, A, IN
        Buffer.from([0x00, 0x00, 0x0e, 0x10]), // TTL 3600
        Buffer.from([0x00, 0x04]),
        Buffer.from(octets),
      ]);
      const head = Buffer.concat([
        id,
        Buffer.from([0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
        question,
        answer,
      ]);
      res.writeHead(200, {
        "content-type": "application/dns-message",
        "content-length": head.length,
      });
      res.end(head);
    });
  });
  return { server, queries: () => queries };
}

/** Minimal fake SOCKS5 server (RFC 1928, no-auth) tunneling to the target. */
function startFakeSocks5(): { server: Server; handshakes: () => number } {
  let handshakes = 0;
  const server = createNetServer((client: Socket) => {
    let stage = 0;
    let buf = Buffer.alloc(0);
    client.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 0 && buf.length >= 2) {
        const nmethods = buf[1];
        if (buf.length < 2 + nmethods) return;
        client.write(Buffer.from([0x05, 0x00])); // no authentication
        buf = buf.subarray(2 + nmethods);
        stage = 1;
      }
      if (stage === 1 && buf.length >= 4) {
        const atyp = buf[3];
        let off = 4;
        let addrLen: number;
        if (atyp === 0x01) addrLen = 4;
        else if (atyp === 0x04) addrLen = 16;
        else if (atyp === 0x03) {
          if (buf.length < 5) return;
          addrLen = buf[4];
          off = 5;
        } else {
          client.destroy();
          return;
        }
        if (buf.length < off + addrLen + 2) return;
        const port = buf.readUInt16BE(off + addrLen);
        let host: string;
        if (atyp === 0x01) host = [...buf.subarray(off, off + 4)].join(".");
        else if (atyp === 0x04) host = `[${buf.subarray(off, off + 16).toString("hex")}]`;
        else host = buf.subarray(off, off + addrLen).toString("ascii");
        handshakes += 1;
        const target = tcpConnect({ host, port }, () => {
          client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          target.pipe(client);
          client.pipe(target);
        });
        target.on("error", () => {
          client.write(Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          client.destroy();
        });
        stage = 2;
        buf = Buffer.alloc(0);
      }
    });
    client.on("error", () => {});
  });
  return { server: server as unknown as Server, handshakes: () => handshakes };
}

function makeAudit(): AuditLog {
  return new AuditLog(join(mkdtempSync(join(tmpdir(), "doh-socks5-")), "audit.jsonl"));
}

function postWebhook(port: number, path: string, body: Buffer): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": body.length,
          "x-signature": signSha256(body, RELAY_SECRET),
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      }
    );
    req.on("error", reject);
    req.end(body);
  });
}

describe("WR-171 SOCKS5: resolveProxyUrl scheme dispatch", () => {
  const target = "http://127.0.0.1:9999/hook";

  it("explicit socks5:// value is returned as-is (SOCKS5 path)", async () => {
    await withProxyEnv({}, async () => {
      assert.equal(
        resolveProxyUrl(target, { [target]: "socks5://127.0.0.1:1080" }),
        "socks5://127.0.0.1:1080"
      );
      assert.equal(
        resolveProxyUrl(target, { [target]: "socks5://user:pass@127.0.0.1:1080" }),
        "socks5://user:pass@127.0.0.1:1080"
      );
    });
  });

  it("explicit http:// value still takes the HTTP CONNECT path", async () => {
    await withProxyEnv({}, async () => {
      assert.equal(
        resolveProxyUrl(target, { [target]: "http://127.0.0.1:8080" }),
        "http://127.0.0.1:8080"
      );
    });
  });

  it("ALL_PROXY=socks5:// env fallback selects SOCKS5", async () => {
    await withProxyEnv({ ALL_PROXY: "socks5://127.0.0.1:1080" }, async () => {
      assert.equal(resolveProxyUrl(target), "socks5://127.0.0.1:1080");
    });
  });

  it("ALL_PROXY=http:// env fallback keeps the HTTP CONNECT path", async () => {
    await withProxyEnv({ ALL_PROXY: "http://127.0.0.1:8080" }, async () => {
      assert.equal(resolveProxyUrl(target), "http://127.0.0.1:8080");
    });
  });

  it("NO_PROXY bypasses the env SOCKS5 fallback", async () => {
    await withProxyEnv(
      { ALL_PROXY: "socks5://127.0.0.1:1080", NO_PROXY: "127.0.0.1" },
      async () => {
        assert.equal(resolveProxyUrl(target), undefined);
      }
    );
  });

  it("explicit entry beats the env fallback", async () => {
    await withProxyEnv({ ALL_PROXY: "socks5://127.0.0.1:1080" }, async () => {
      assert.equal(
        resolveProxyUrl(target, { [target]: "http://127.0.0.1:8080" }),
        "http://127.0.0.1:8080"
      );
    });
  });

  it("invalid explicit socks5 value throws RangeError", async () => {
    await withProxyEnv({}, async () => {
      assert.throws(
        () => resolveProxyUrl(target, { [target]: "socks5://" }),
        RangeError
      );
    });
  });
});

describe("WR-171 SOCKS5: pooled delivery through the tunnel", () => {
  let socks: ReturnType<typeof startFakeSocks5>;
  let stub: ReturnType<typeof startStub>;
  let socksPort = 0;
  let stubPort = 0;

  before(async () => {
    socks = startFakeSocks5();
    socksPort = await listen(socks.server);
    stub = startStub();
    stubPort = await listen(stub.server);
  });

  after(async () => {
    await closeServer(socks.server);
    await closeServer(stub.server);
  });

  it("delivers through the SOCKS5 tunnel with a |socks5: pool key", async () => {
    await withProxyEnv({}, async () => {
      const targetUrl = `http://127.0.0.1:${stubPort}/hook`;
      const sender = createDefaultSender(undefined, undefined, undefined, {
        [targetUrl]: `socks5://127.0.0.1:${socksPort}`,
      });
      await sender(item(targetUrl));
      await sender(item(targetUrl));
      assert.equal(stub.received.length, 2);
      assert.deepEqual(stub.received[0].body, BODY);
      // One SOCKS5 handshake serves both deliveries: the tunneled
      // socket is pooled.
      assert.equal(socks.handshakes(), 1);
      const keys = (sender.pool?.getStats().endpoints ?? []).map((e) => e.key);
      assert.ok(keys.some((k) => k.includes("|socks5:")));
      assert.ok(!keys.some((k) => k.includes("|proxy:")));
    });
  });

  it("SOCKS5 and HTTP-CONNECT agents are pool-isolated", async () => {
    const pool = new OutboundConnectionPool();
    const url = new URL(`http://127.0.0.1:${stubPort}/hook`);
    const socksAgent = pool.agentFor(url, undefined, "socks5://127.0.0.1:1080");
    const httpAgent = pool.agentFor(url, undefined, "http://127.0.0.1:8080");
    assert.notEqual(socksAgent, httpAgent);
    const socksAgent2 = pool.agentFor(url, undefined, "socks5://127.0.0.1:1080");
    assert.equal(socksAgent, socksAgent2);
    const keys = pool.getStats().endpoints.map((e) => e.key);
    assert.ok(keys.some((k) => k.includes("|socks5:")));
    assert.ok(keys.some((k) => k.includes("|proxy:")));
  });
});

describe("WR-170 DoH: delivery resolves through DNS-over-HTTPS", () => {
  let doh: ReturnType<typeof startFakeDoh>;
  let stub: ReturnType<typeof startStub>;
  let dohPort = 0;
  let stubPort = 0;
  let relay: RelayServer | undefined;

  before(async () => {
    // The sandbox DNS hijacks bogus hostnames to a blackhole — answering
    // "doh-only.invalid" with 127.0.0.1 here proves the DoH path was
    // used (the system resolver could never deliver to it).
    doh = startFakeDoh((name) => (name === "doh-only.invalid" ? "127.0.0.1" : undefined));
    dohPort = await listen(doh.server);
    stub = startStub();
    stubPort = await listen(stub.server);
  });

  after(async () => {
    relay?.close();
    relay = undefined;
    await closeServer(doh.server);
    await closeServer(stub.server);
  });

  it("forwards through a DoH-resolved address", async () => {
    // The sandbox exports an egress proxy via env vars — clear them so
    // this test exercises the direct (DoH-resolved) path, not the proxy.
    await withProxyEnv({}, async () => {
      const targetUrl = `http://doh-only.invalid:${stubPort}/hook`;
      const dohUrl = `http://127.0.0.1:${dohPort}/dns-query`;
      relay = createRelayServer({
        secret: RELAY_SECRET,
        forwardUrl: targetUrl,
        auditLog: makeAudit(),
        retry: { baseDelayMs: 10, maxDelayMs: 50, maxAttempts: 3, jitterMs: 0 },
        doh: { [targetUrl]: dohUrl },
      });
      try {
        const relayPort = await listen(relay);
        const status = await postWebhook(relayPort, "/", BODY);
        assert.equal(status, 202);
        await waitFor(() => stub.received.length === 1);
        assert.deepEqual(stub.received[0].body, BODY);
        assert.ok(doh.queries() >= 1, "expected at least one DoH query");
      } finally {
        relay.close();
        relay = undefined;
      }
    });
  });

  it("DoH failure falls back to system DNS and audits doh_fallback", async () => {
    // Same env-proxy hygiene as above: the fallback must be to the
    // system resolver, not to the sandbox egress proxy.
    await withProxyEnv({}, async () => {
    const failing = startFakeDoh(() => "127.0.0.1", { status: 500 });
    const failingPort = await listen(failing.server);
    try {
      const targetUrl = `http://localhost:${stubPort}/hook`;
      const audit = makeAudit();
      const r = createRelayServer({
        secret: RELAY_SECRET,
        forwardUrl: targetUrl,
        auditLog: audit,
        retry: { baseDelayMs: 10, maxDelayMs: 50, maxAttempts: 3, jitterMs: 0 },
        doh: { [targetUrl]: `http://127.0.0.1:${failingPort}/dns-query` },
      });
      try {
        const relayPort = await listen(r);
        const status = await postWebhook(relayPort, "/", BODY);
        assert.equal(status, 202);
        // System DNS resolves localhost — the delivery succeeds despite
        // the dead DoH endpoint.
        await waitFor(() => stub.received.length === 2);
        const fallbacks = audit.query({ event: "doh_fallback" });
        assert.ok(fallbacks.length >= 1, "expected a doh_fallback audit event");
        const first = fallbacks[0] as { hostname?: string; error?: string };
        assert.equal(first.hostname, "localhost");
        assert.ok(typeof first.error === "string" && first.error.length > 0);
      } finally {
        r.close();
      }
    } finally {
      await closeServer(failing.server);
    }
    });
  });

  it("invalid DoH URL throws RangeError at startup", () => {
    assert.throws(
      () =>
        createRelayServer({
          secret: RELAY_SECRET,
          forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
          auditLog: makeAudit(),
          doh: { "http://127.0.0.1:1/hook": "not a url" },
        }),
      RangeError
    );
  });

  it("per-endpoint DoH agents are pool-isolated with a |doh: key", () => {
    const pool = new OutboundConnectionPool();
    const url = new URL(`http://127.0.0.1:${stubPort}/hook`);
    const dohUrl = `http://127.0.0.1:${dohPort}/dns-query`;
    const dohAgent = pool.agentFor(url, undefined, undefined, undefined, undefined, undefined, undefined, undefined, {
      url: dohUrl,
      lookup: (hostname, _opts, cb) => cb(null, "127.0.0.1", 4),
    });
    const plainAgent = pool.agentFor(url);
    assert.notEqual(dohAgent, plainAgent);
    const dohAgent2 = pool.agentFor(url, undefined, undefined, undefined, undefined, undefined, undefined, undefined, {
      url: dohUrl,
      lookup: (hostname, _opts, cb) => cb(null, "127.0.0.1", 4),
    });
    assert.equal(dohAgent, dohAgent2);
    const keys = pool.getStats().endpoints.map((e) => e.key);
    assert.ok(keys.some((k) => k.includes("|doh:")));
  });
});
