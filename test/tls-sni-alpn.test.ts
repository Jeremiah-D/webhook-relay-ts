import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer as createHttpServer, type Server as HttpServer, type IncomingMessage } from "node:http";
import type { TLSSocket } from "node:tls";
import { connect as tcpConnect, type Socket } from "node:net";
import { createSecureServer as createH2SecureServer, type Http2Server, type ServerHttp2Session } from "node:http2";
import { X509Certificate } from "node:crypto";
import { createDefaultSender } from "../src/server.ts";
import { OutboundConnectionPool } from "../src/keepalive.ts";
import {
  assertValidTlsSniOverride,
  resolveTlsSniOverride,
  tlsSniPoolKeyFragment,
  DEFAULT_TLS_ALPN_PROTOCOLS,
  type TlsSniOverride,
} from "../src/tls-sni.ts";
import { TlsPinMismatchError } from "../src/pinning.ts";
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
  MTLS_SERVER_SPKI_PIN,
} from "./mtls-fixture.ts";

const BODY = Buffer.from(JSON.stringify({ event: "tls-sni.probe" }));
const WRONG_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const item = (targetUrl: string) => ({ id: "s1", payload: BODY, targetUrl, headers: {} });

async function listen(server: HttpsServer | HttpServer | Http2Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

/** createDefaultSender with pins + tlsSniOverrides set (1st and 11th positional args). */
function sniSender(
  overrides: Record<string, TlsSniOverride>,
  keepAlive?: false,
  pins?: Record<string, string[]>
) {
  return createDefaultSender(
    pins, keepAlive, undefined, undefined, undefined,
    undefined, undefined, undefined, undefined, undefined, overrides
  );
}

describe("tls-sni: config validation", () => {
  it("accepts empty and fully-specified entries", () => {
    assert.doesNotThrow(() => assertValidTlsSniOverride({}, "t"));
    assert.doesNotThrow(() =>
      assertValidTlsSniOverride({ servername: "front.example.com", alpnProtocols: ["h2", "http/1.1"] }, "t")
    );
    assert.doesNotThrow(() => assertValidTlsSniOverride({ servername: "edge.example.net" }, "t"));
    assert.doesNotThrow(() => assertValidTlsSniOverride({ alpnProtocols: ["http/1.1"] }, "t"));
  });

  it("rejects non-objects, empty servernames, and IP-literal servernames", () => {
    for (const bad of [null, undefined, "front.example.com", 42, [], ["h2"]]) {
      assert.throws(() => assertValidTlsSniOverride(bad, "t"), RangeError, JSON.stringify(bad));
    }
    for (const bad of ["", "   "]) {
      assert.throws(() => assertValidTlsSniOverride({ servername: bad }, "t"), /'servername' must be a non-empty string/);
    }
    assert.throws(() => assertValidTlsSniOverride({ servername: 42 }, "t"), /'servername' must be a non-empty string/);
    // SNI carries no IP addresses (RFC 6066) — fail at startup, not as a
    // Node deprecation warning mid-handshake.
    for (const ip of ["127.0.0.1", "::1", " 10.0.0.1 "]) {
      assert.throws(() => assertValidTlsSniOverride({ servername: ip }, "t"), /not an IP literal/);
    }
  });

  it("rejects missing, empty, and malformed alpnProtocols", () => {
    assert.throws(() => assertValidTlsSniOverride({ alpnProtocols: "h2" }, "t"), /'alpnProtocols' must be a non-empty array/);
    assert.throws(() => assertValidTlsSniOverride({ alpnProtocols: [] }, "t"), /'alpnProtocols' must be a non-empty array/);
    assert.throws(() => assertValidTlsSniOverride({ alpnProtocols: [""] }, "t"), /entries must be non-empty strings/);
    assert.throws(() => assertValidTlsSniOverride({ alpnProtocols: ["h2", 42] }, "t"), /entries must be non-empty strings/);
    assert.throws(() => assertValidTlsSniOverride({ alpnProtocols: ["  "] }, "t"), /entries must be non-empty strings/);
  });

  it("createDefaultSender validates overrides up front with RangeError", () => {
    const good = { "https://example.com/hook": { servername: "front.example.com" } };
    const sender = sniSender(good);
    sender.destroy();
    assert.throws(
      () => sniSender({ "https://x/": { servername: "" } }),
      /invalid TLS SNI override for https:\/\/x\/.*'servername' must be a non-empty string/
    );
    assert.throws(
      () => sniSender({ "https://x/": { servername: "127.0.0.1" } }),
      /invalid TLS SNI override.*not an IP literal/
    );
    assert.throws(
      () => sniSender({ "https://x/": { alpnProtocols: [] } }),
      /invalid TLS SNI override.*'alpnProtocols' must be a non-empty array/
    );
    // SNI/ALPN only exist on the TLS handshake: non-https: keys are config errors.
    assert.throws(
      () => sniSender({ "http://x/hook": {} }),
      /invalid TLS SNI override.*only https: targets/
    );
    assert.throws(
      () => sniSender({ "wss://x/hook": {} }),
      /invalid TLS SNI override.*only https: targets/
    );
    assert.throws(
      () => sniSender({ "not a url": {} }),
      /invalid TLS SNI override.*not a valid URL/
    );
  });
});

describe("tls-sni: resolve + pool-key fragment", () => {
  it("returns undefined when no entry exists for the targetUrl (default behavior)", () => {
    const url = new URL("https://example.com/hook");
    assert.equal(resolveTlsSniOverride("https://example.com/hook", url, undefined), undefined);
    assert.equal(resolveTlsSniOverride("https://example.com/hook", url, {}), undefined);
    // Exact-match keys: a different path is a different endpoint.
    assert.equal(
      resolveTlsSniOverride("https://example.com/other", url, { "https://example.com/hook": {} }),
      undefined
    );
  });

  it("defaults servername to the target host and ALPN to [h2, http/1.1]", () => {
    assert.deepEqual(DEFAULT_TLS_ALPN_PROTOCOLS, ["h2", "http/1.1"]);
    const hostUrl = new URL("https://example.com/hook");
    assert.deepEqual(resolveTlsSniOverride("https://example.com/hook", hostUrl, { "https://example.com/hook": {} }), {
      servername: "example.com",
      alpnProtocols: ["h2", "http/1.1"],
    });
    // IP-literal targets keep Node's default (no SNI sent).
    const ipUrl = new URL("https://127.0.0.1:8443/hook");
    assert.deepEqual(
      resolveTlsSniOverride("https://127.0.0.1:8443/hook", ipUrl, { "https://127.0.0.1:8443/hook": {} }),
      { servername: undefined, alpnProtocols: ["h2", "http/1.1"] }
    );
  });

  it("honors explicit servername/alpnProtocols and returns a fresh ALPN copy", () => {
    const url = new URL("https://example.com/hook");
    const overrides = { "https://example.com/hook": { servername: "front.example.com", alpnProtocols: ["http/1.1"] } };
    const first = resolveTlsSniOverride("https://example.com/hook", url, overrides)!;
    assert.deepEqual(first, { servername: "front.example.com", alpnProtocols: ["http/1.1"] });
    first.alpnProtocols.push("h2");
    const second = resolveTlsSniOverride("https://example.com/hook", url, overrides)!;
    assert.deepEqual(second.alpnProtocols, ["http/1.1"]);
  });

  it("the pool-key fragment is stable and binds the effective TLS identity", () => {
    const a = { servername: "a.example", alpnProtocols: ["h2", "http/1.1"] };
    const b = { servername: "b.example", alpnProtocols: ["h2", "http/1.1"] };
    const c = { servername: "a.example", alpnProtocols: ["http/1.1"] };
    const fragA = tlsSniPoolKeyFragment(a);
    assert.match(fragA, /^\|sni:[0-9a-f]{16}$/);
    assert.equal(fragA, tlsSniPoolKeyFragment({ ...a }));
    assert.notEqual(fragA, tlsSniPoolKeyFragment(b));
    assert.notEqual(fragA, tlsSniPoolKeyFragment(c));
  });
});

interface HandshakeObservation {
  servername: string | false | undefined;
  alpn: string | false;
}

describe("tls-sni: real TLS handshakes over HTTP/1.1", () => {
  let https: HttpsServer;
  let port: number;
  const observations: HandshakeObservation[] = [];

  before(async () => {
    https = createHttpsServer(
      {
        key: TLS_FIXTURE_KEY_PEM,
        cert: TLS_FIXTURE_CERT_PEM,
        // The server must negotiate ALPN for the client offer to be observable.
        ALPNProtocols: ["h2", "http/1.1"],
      },
      (req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    https.on("secureConnection", (sock: TLSSocket) => {
      observations.push({ servername: sock.servername as string | false | undefined, alpn: sock.alpnProtocol });
    });
    port = await listen(https);
  });

  after(() => https.close());

  const url = (path = "/hook") => `https://127.0.0.1:${port}${path}`;

  it("without an entry the handshake is byte-identical to the old default (no SNI, no ALPN)", async () => {
    // The fixture cert is self-signed: the relay trusts it via pinning so
    // the handshake itself — not chain verification — is what we observe.
    const sender = createDefaultSender({ [url()]: [TLS_FIXTURE_SPKI_PIN] });
    observations.length = 0;
    const res = await sender(item(url()));
    assert.ok(res && res.statusCode === 200);
    sender.destroy();
    assert.equal(observations.length, 1);
    // IP literal: Node sends no SNI; and the relay sets no ALPNProtocols —
    // both must stay false so "no override configured" stays a zero-change path.
    assert.equal(observations[0]!.servername, false);
    assert.equal(observations[0]!.alpn, false);
  });

  it("an explicit servername reaches the server as the SNI", async () => {
    const pins = { [url()]: [TLS_FIXTURE_SPKI_PIN] };
    const sender = sniSender({ [url()]: { servername: "front.example.com" } }, undefined, pins);
    observations.length = 0;
    const res = await sender(item(url()));
    assert.ok(res && res.statusCode === 200);
    sender.destroy();
    assert.equal(observations.length, 1);
    assert.equal(observations[0]!.servername, "front.example.com");
    // Default ALPN offer ["h2","http/1.1"]: the server picks its first overlap.
    assert.equal(observations[0]!.alpn, "h2");
  });

  it("an explicit alpnProtocols list is offered verbatim", async () => {
    const pins = { [url()]: [TLS_FIXTURE_SPKI_PIN] };
    const sender = sniSender({ [url()]: { alpnProtocols: ["http/1.1"] } }, undefined, pins);
    observations.length = 0;
    const res = await sender(item(url()));
    assert.ok(res && res.statusCode === 200);
    sender.destroy();
    assert.equal(observations.length, 1);
    assert.equal(observations[0]!.alpn, "http/1.1");
    // No explicit servername on an IP-literal target: Node's default (no SNI).
    assert.equal(observations[0]!.servername, false);
  });

  it("servername and alpnProtocols combine on one endpoint", async () => {
    const pins = { [url()]: [TLS_FIXTURE_SPKI_PIN] };
    const sender = sniSender({ [url()]: { servername: "edge.example.net", alpnProtocols: ["http/1.1"] } }, undefined, pins);
    observations.length = 0;
    const res = await sender(item(url()));
    assert.ok(res && res.statusCode === 200);
    sender.destroy();
    assert.equal(observations.length, 1);
    assert.equal(observations[0]!.servername, "edge.example.net");
    assert.equal(observations[0]!.alpn, "http/1.1");
  });

  it("the override also applies when pooling is disabled (fresh connection per delivery)", async () => {
    const pins = { [url()]: [TLS_FIXTURE_SPKI_PIN] };
    const sender = sniSender({ [url()]: { servername: "oneoff.example.com" } }, false, pins);
    observations.length = 0;
    const res = await sender(item(url()));
    assert.ok(res && res.statusCode === 200);
    sender.destroy();
    assert.equal(observations.length, 1);
    assert.equal(observations[0]!.servername, "oneoff.example.com");
  });

  it("pinning is verified on the overridden-SNI connection (WR-21 consistency)", async () => {
    const target = url();
    const sender = createDefaultSender(
      { [target]: [TLS_FIXTURE_SPKI_PIN] },
      undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined,
      { [target]: { servername: "front.example.com" } }
    );
    observations.length = 0;
    const res = await sender(item(target));
    assert.ok(res && res.statusCode === 200);
    sender.destroy();
    // The pin matched AND the server saw the overridden SNI: the pin check
    // ran on the connection handshaked with the effective servername.
    assert.equal(observations.length, 1);
    assert.equal(observations[0]!.servername, "front.example.com");
  });

  it("a pin mismatch still fails loudly when an SNI override is configured", async () => {
    const target = url();
    const sender = createDefaultSender(
      { [target]: [WRONG_PIN] },
      undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined,
      { [target]: { servername: "front.example.com" } }
    );
    await assert.rejects(() => sender(item(target)), TlsPinMismatchError);
    sender.destroy();
  });
});

describe("tls-sni: keep-alive pool isolation by effective TLS identity", () => {
  let https: HttpsServer;
  let port: number;
  const observations: HandshakeObservation[] = [];

  before(async () => {
    https = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM, ALPNProtocols: ["h2", "http/1.1"] },
      (req, res) => {
        req.resume();
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    https.on("secureConnection", (sock: TLSSocket) => {
      observations.push({ servername: sock.servername as string | false | undefined, alpn: sock.alpnProtocol });
    });
    port = await listen(https);
  });

  after(() => https.close());

  const url = (path: string) => `https://127.0.0.1:${port}${path}`;

  it("agentFor isolates agents per TLS identity and keeps legacy keys untouched", () => {
    const pool = new OutboundConnectionPool();
    const u = new URL(url("/a"));
    const sniA = resolveTlsSniOverride(url("/a"), u, { [url("/a")]: { servername: "a.example" } })!;
    const sniB = resolveTlsSniOverride(url("/b"), u, { [url("/b")]: { servername: "b.example" } })!;
    const a1 = pool.agentFor(u, undefined, undefined, undefined, sniA);
    const a1again = pool.agentFor(u, undefined, undefined, undefined, sniA);
    const a2 = pool.agentFor(u, undefined, undefined, undefined, sniB);
    const a3 = pool.agentFor(u);
    assert.equal(a1, a1again, "same effective TLS identity reuses the agent");
    assert.notEqual(a1, a2, "different SNI gets a different agent");
    assert.notEqual(a1, a3, "overridden endpoint never shares the legacy agent");
    const keys = pool.getStats().endpoints.map((e) => e.key);
    assert.equal(keys.length, 3);
    assert.equal(keys.filter((k) => k.includes("|sni:")).length, 2);
    assert.ok(keys.some((k) => !k.includes("|sni:")), "the legacy key has no |sni: fragment");
    pool.destroy();
  });

  it("end-to-end: same origin, different SNI overrides never share a connection", async () => {
    const targetA = url("/a");
    const targetB = url("/b");
    const pins = { [targetA]: [TLS_FIXTURE_SPKI_PIN], [targetB]: [TLS_FIXTURE_SPKI_PIN] };
    const sender = sniSender(
      {
        [targetA]: { servername: "a.example" },
        [targetB]: { servername: "b.example" },
      },
      undefined,
      pins
    );
    observations.length = 0;
    await sender(item(targetA));
    await sender(item(targetB));
    assert.equal(observations.length, 2);
    assert.deepEqual(
      observations.map((o) => o.servername).sort(),
      ["a.example", "b.example"]
    );
    // A repeat delivery to A reuses A's connection — no new handshake, and
    // the pool holds exactly two TLS-identity-bound endpoints.
    await sender(item(targetA));
    assert.equal(observations.length, 2);
    const stats = sender.pool!.getStats();
    assert.equal(stats.endpoints.length, 2);
    assert.ok(stats.endpoints.every((e) => e.key.includes("|sni:")));
    assert.equal(stats.reused, 1);
    sender.destroy();
  });
});

describe("tls-sni: mTLS composition (WR-36)", () => {
  let https: HttpsServer;
  let port: number;
  const observations: HandshakeObservation[] = [];
  let lastCN: string | null = null;
  let lastAuthorized = false;

  before(async () => {
    https = createHttpsServer(
      {
        key: MTLS_SERVER_KEY_PEM,
        cert: MTLS_SERVER_CERT_PEM,
        ca: MTLS_CA_PEM,
        requestCert: true,
        rejectUnauthorized: true,
        ALPNProtocols: ["h2", "http/1.1"],
      },
      (req, res) => {
        const sock = req.socket as TLSSocket;
        lastAuthorized = sock.authorized === true;
        const peer = sock.getPeerCertificate() as unknown as { raw?: Buffer };
        if (peer?.raw !== undefined) {
          const m = /CN=([^,\n]+)/.exec(new X509Certificate(peer.raw).subject);
          lastCN = m ? m[1] : null;
        }
        req.resume();
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    https.on("secureConnection", (sock: TLSSocket) => {
      observations.push({ servername: sock.servername as string | false | undefined, alpn: sock.alpnProtocol });
    });
    port = await listen(https);
  });

  after(() => https.close());

  it("the client certificate and the SNI override ride the same handshake", async () => {
    const target = `https://127.0.0.1:${port}/hook`;
    const sender = createDefaultSender(
      { [target]: [MTLS_SERVER_SPKI_PIN] },
      undefined, undefined, undefined,
      { [target]: { cert: MTLS_CLIENT_CERT_PEM, key: MTLS_CLIENT_KEY_PEM } },
      undefined, undefined, undefined, undefined, undefined,
      { [target]: { servername: "front.example.com" } }
    );
    observations.length = 0;
    const res = await sender(item(target));
    assert.ok(res && res.statusCode === 200);
    sender.destroy();
    assert.equal(lastAuthorized, true);
    assert.equal(lastCN, "relay-client");
    assert.equal(observations.length, 1);
    assert.equal(observations[0]!.servername, "front.example.com");
  });
});

describe("tls-sni: HTTP/2 composition (WR-42)", () => {
  let server: Http2Server;
  let port: number;
  const observations: HandshakeObservation[] = [];

  before(async () => {
    server = createH2SecureServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM });
    server.on("session", (session: ServerHttp2Session) => {
      const sock = session.socket as TLSSocket;
      observations.push({ servername: sock.servername as string | false | undefined, alpn: sock.alpnProtocol });
    });
    server.on("stream", (stream) => {
      stream.resume();
      stream.on("end", () => {
        stream.respond({ ":status": 200 });
        stream.end("ok");
      });
    });
    port = await listen(server);
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const url = (path: string) => `https://127.0.0.1:${port}${path}`;

  it("H2 sessions handshake with the overridden SNI and stay isolated per TLS identity", async () => {
    const targetA = url("/a");
    const targetB = url("/b");
    const sender = createDefaultSender(
      { [targetA]: [TLS_FIXTURE_SPKI_PIN], [targetB]: [TLS_FIXTURE_SPKI_PIN] },
      undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"] },
      undefined, undefined, undefined,
      { [targetA]: { servername: "h2front.example" }, [targetB]: { servername: "h2edge.example" } }
    );
    observations.length = 0;
    const resA = await sender(item(targetA));
    assert.ok(resA && resA.statusCode === 200);
    assert.equal(observations.length, 1);
    assert.equal(observations[0]!.servername, "h2front.example");
    assert.equal(observations[0]!.alpn, "h2");
    // A second endpoint with a different SNI gets its own session —
    // never the first endpoint's handshaked connection.
    const resB = await sender(item(targetB));
    assert.ok(resB && resB.statusCode === 200);
    assert.equal(observations.length, 2);
    assert.equal(observations[1]!.servername, "h2edge.example");
    const sessions = sender.http2Pool!.getStats().sessions;
    assert.equal(sessions.length, 2);
    assert.ok(sessions.every((s) => s.key.includes("|sni:")));
    sender.destroy();
  });

  it("an H2 endpoint without an override keeps the historical session key", async () => {
    const target = url("/plain");
    const sender = createDefaultSender(
      { [target]: [TLS_FIXTURE_SPKI_PIN] },
      undefined, undefined, undefined, undefined, undefined,
      { enabled: true, hosts: ["127.0.0.1"] }
    );
    const res = await sender(item(target));
    assert.ok(res && res.statusCode === 200);
    const sessions = sender.http2Pool!.getStats().sessions;
    assert.equal(sessions.length, 1);
    assert.ok(!sessions[0]!.key.includes("|sni:"), "no |sni: fragment without an override entry");
    sender.destroy();
  });
});

describe("tls-sni: proxied endpoints (WR-27)", () => {
  let downstream: HttpsServer;
  let proxy: HttpServer;
  let downstreamPort: number;
  let proxyPort: number;
  const observations: HandshakeObservation[] = [];
  const proxyHits: string[] = [];

  before(async () => {
    downstream = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM, ALPNProtocols: ["h2", "http/1.1"] },
      (req, res) => {
        req.resume();
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    downstream.on("secureConnection", (sock: TLSSocket) => {
      observations.push({ servername: sock.servername as string | false | undefined, alpn: sock.alpnProtocol });
    });
    downstreamPort = await listen(downstream);
    proxy = createHttpServer();
    proxy.on("connect", (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
      const target = req.url ?? "";
      proxyHits.push(target);
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
    proxyPort = await listen(proxy);
  });

  after(() => {
    downstream.close();
    proxy.close();
  });

  it("the SNI/ALPN override applies to the TLS handshake over the CONNECT tunnel", async () => {
    const target = `https://127.0.0.1:${downstreamPort}/hook`;
    const sender = createDefaultSender(
      { [target]: [TLS_FIXTURE_SPKI_PIN] },
      undefined, undefined,
      { [target]: `http://127.0.0.1:${proxyPort}` },
      undefined, undefined, undefined, undefined, undefined, undefined,
      { [target]: { servername: "proxied.example.com", alpnProtocols: ["http/1.1"] } }
    );
    observations.length = 0;
    proxyHits.length = 0;
    const res = await sender(item(target));
    assert.ok(res && res.statusCode === 200);
    const keys = sender.pool!.getStats().endpoints.map((e) => e.key);
    sender.destroy();
    assert.deepEqual(proxyHits, [`127.0.0.1:${downstreamPort}`]);
    assert.equal(observations.length, 1);
    assert.equal(observations[0]!.servername, "proxied.example.com");
    assert.equal(observations[0]!.alpn, "http/1.1");
    assert.ok(keys.some((k) => k.includes("|proxy:") && k.includes("|sni:")));
  });
});
