import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { TLSSocket } from "node:tls";
import { X509Certificate } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertValidClientCert,
  clientCertIdentity,
  type TlsClientCert,
} from "../src/mtls.ts";
import { createRelayServer, createDefaultSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  MTLS_SERVER_CERT_PEM,
  MTLS_SERVER_KEY_PEM,
  MTLS_CA_PEM,
  MTLS_CLIENT_CERT_PEM,
  MTLS_CLIENT_KEY_PEM,
  MTLS_EVIL_CLIENT_CERT_PEM,
  MTLS_EVIL_CLIENT_KEY_PEM,
  MTLS_SERVER_SPKI_PIN,
} from "./mtls-fixture.ts";

const SECRET = "mtls-secret";
const BODY = Buffer.from(JSON.stringify({ event: "mtls.probe" }));

const GOOD_CERT: TlsClientCert = { cert: MTLS_CLIENT_CERT_PEM, key: MTLS_CLIENT_KEY_PEM };
const EVIL_CERT: TlsClientCert = { cert: MTLS_EVIL_CLIENT_CERT_PEM, key: MTLS_EVIL_CLIENT_KEY_PEM };

async function listenHttps(server: HttpsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function listenHttp(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function clientCN(sock: TLSSocket): string | null {
  const peer = sock.getPeerCertificate() as unknown as { raw?: Buffer };
  if (peer?.raw === undefined) return null;
  const m = /CN=([^,\n]+)/.exec(new X509Certificate(peer.raw).subject);
  return m ? m[1] : null;
}

describe("mtls: config validation", () => {
  it("accepts the fixture identity, computes a stable 16-hex-char identity", () => {
    assert.doesNotThrow(() => assertValidClientCert(GOOD_CERT, "good"));
    const id = clientCertIdentity(GOOD_CERT);
    assert.match(id, /^[0-9a-f]{16}$/);
    assert.equal(id, clientCertIdentity(GOOD_CERT));
    assert.notEqual(id, clientCertIdentity(EVIL_CERT));
  });

  it("rejects broken identities at config time", () => {
    assert.throws(
      () => assertValidClientCert({ cert: "", key: MTLS_CLIENT_KEY_PEM }, "x"),
      /'cert' must be a non-empty PEM string/
    );
    assert.throws(
      () => assertValidClientCert({ cert: MTLS_CLIENT_CERT_PEM, key: "  " }, "x"),
      /'key' must be a non-empty PEM string/
    );
    assert.throws(
      () => assertValidClientCert({ cert: "not a pem", key: MTLS_CLIENT_KEY_PEM }, "x"),
      /invalid TLS client certificate\/key PEM/
    );
    assert.throws(
      () => assertValidClientCert({ cert: MTLS_CLIENT_CERT_PEM, key: "not a pem" }, "x"),
      /invalid TLS client certificate\/key PEM/
    );
    // A key that does not belong to the cert is caught too, not at 3am.
    assert.throws(
      () =>
        assertValidClientCert(
          { cert: MTLS_CLIENT_CERT_PEM, key: MTLS_EVIL_CLIENT_KEY_PEM },
          "x"
        ),
      /invalid TLS client certificate\/key PEM/
    );
    assert.throws(
      () =>
        assertValidClientCert(
          { cert: MTLS_CLIENT_CERT_PEM, key: MTLS_CLIENT_KEY_PEM, passphrase: 42 as never },
          "x"
        ),
      /'passphrase' must be a string/
    );
    assert.throws(
      () => assertValidClientCert(null as never, "x"),
      /must be an object/
    );
  });

  it("createDefaultSender validates tlsClientCerts up front", () => {
    assert.throws(
      () => createDefaultSender(undefined, undefined, undefined, undefined, { "https://x/": { cert: "bogus", key: "bogus" } }),
      /invalid TLS client certificate.*invalid TLS client certificate\/key PEM/
    );
    assert.doesNotThrow(() =>
      createDefaultSender(undefined, undefined, undefined, undefined, { "https://x/": GOOD_CERT })
    );
  });
});

describe("mtls: real handshakes through createDefaultSender", () => {
  let https: HttpsServer;
  let port: number;
  let requests = 0;
  let lastAuthorized = false;
  let lastCN: string | null = null;
  const received: Buffer[] = [];

  before(async () => {
    https = createHttpsServer(
      {
        key: MTLS_SERVER_KEY_PEM,
        cert: MTLS_SERVER_CERT_PEM,
        ca: MTLS_CA_PEM,
        requestCert: true,
        rejectUnauthorized: true,
      },
      (req, res) => {
        const sock = req.socket as TLSSocket;
        lastAuthorized = sock.authorized === true;
        lastCN = clientCN(sock);
        requests++;
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          received.push(Buffer.concat(chunks));
          res.writeHead(200).end("ok");
        });
      }
    );
    port = await listenHttps(https);
  });

  after(() => https.close());

  const url = () => `https://127.0.0.1:${port}/hook`;
  const item = (targetUrl: string) => ({ id: "m1", payload: BODY, targetUrl, headers: {} });
  // The fixture server cert is self-signed by the throwaway test CA, so the
  // relay trusts it via WR-21 pinning — the same composition operators use
  // for private-CA downstreams.
  const pinsFor = (u: string) => ({ [u]: [MTLS_SERVER_SPKI_PIN] });

  it("presents the client certificate: the downstream sees an authorized relay-client", async () => {
    const sender = createDefaultSender(pinsFor(url()), undefined, undefined, undefined, {
      [url()]: GOOD_CERT,
    });
    await sender(item(url()));
    sender.destroy();
    assert.equal(requests, 1);
    assert.equal(lastAuthorized, true);
    assert.equal(lastCN, "relay-client");
    assert.deepEqual(received[0], BODY);
  });

  it("a wrong client certificate fails the handshake before any payload byte is sent", async () => {
    const sender = createDefaultSender(pinsFor(url()), undefined, undefined, undefined, {
      [url()]: EVIL_CERT,
    });
    const before = requests;
    // The server aborts the handshake with a TLS alert; surfacing on the
    // client as a transport-level error (alert text varies by timing —
    // "socket hang up" vs ECONNRESET — so match broadly).
    await assert.rejects(() => sender(item(url())), /certificate|alert|handshake|ECONNRESET|socket hang up/i);
    // The server aborted the handshake: it never saw a request, let alone
    // the payload — and the dead socket was never pooled for reuse.
    assert.equal(requests, before);
    const stats = sender.pool!.getStats();
    assert.equal(stats.endpoints.length, 1);
    assert.equal(stats.endpoints[0].freeSockets, 0);
    sender.destroy();
  });

  it("no client certificate configured: the server rejects the handshake", async () => {
    const sender = createDefaultSender(pinsFor(url()));
    const before = requests;
    await assert.rejects(() => sender(item(url())), /certificate|alert|handshake|ECONNRESET|socket hang up/i);
    assert.equal(requests, before);
    sender.destroy();
  });

  it("the pool isolates agents per (origin, client identity)", async () => {
    const sender = createDefaultSender(pinsFor(url()), undefined, undefined, undefined, {
      [url()]: GOOD_CERT,
    });
    const pool = sender.pool!;
    const u = new URL(url());
    const idA = clientCertIdentity(GOOD_CERT);
    const idB = clientCertIdentity(EVIL_CERT);
    const a1 = pool.agentFor(u, undefined, undefined, idA);
    const a2 = pool.agentFor(u, undefined, undefined, idB);
    const a3 = pool.agentFor(u, undefined, undefined, idA);
    const a0 = pool.agentFor(u);
    assert.notEqual(a1, a2, "different identities must not share an agent");
    assert.equal(a1, a3, "same identity shares the agent");
    assert.notEqual(a1, a0, "cert-bound agent differs from the anonymous one");
    const keys = pool.getStats().endpoints.map((e) => e.key);
    assert.ok(keys.some((k) => k.includes(`|cert:${idA}`)), `pool key binds the cert id: ${keys}`);
    assert.ok(pool.getStats().endpoints.some((e) => e.clientCert));
    sender.destroy();
  });

  it("keep-alive reuses the authenticated connection for the same identity", async () => {
    const sender = createDefaultSender(pinsFor(url()), undefined, undefined, undefined, {
      [url()]: GOOD_CERT,
    });
    await sender(item(url()));
    await sender(item(url()));
    const stats = sender.pool!.getStats();
    assert.equal(stats.endpoints.length, 1);
    assert.equal(stats.endpoints[0].created, 1);
    assert.ok(stats.endpoints[0].reused >= 1, `expected reuse, got ${JSON.stringify(stats.endpoints[0])}`);
    assert.equal(requests >= 2, true);
    sender.destroy();
  });
});

describe("mtls: end-to-end through the relay server", () => {
  let https: HttpsServer;
  let relay: Server;
  let relayPort: number;
  let authorizedDownstream = 0;
  const OPERATOR = "op-mtls-token";

  function postSigned(port: number, headers: Record<string, string>) {
    return new Promise<{ status: number }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: { ...headers, "x-signature": signSha256(BODY, SECRET) },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
  }

  before(async () => {
    https = createHttpsServer(
      {
        key: MTLS_SERVER_KEY_PEM,
        cert: MTLS_SERVER_CERT_PEM,
        ca: MTLS_CA_PEM,
        requestCert: true,
        rejectUnauthorized: true,
      },
      (req, res) => {
        if ((req.socket as TLSSocket).authorized === true) authorizedDownstream++;
        req.resume();
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    const downstreamPort = await listenHttps(https);
    const forwardUrl = `https://127.0.0.1:${downstreamPort}/hook`;
    const dir = mkdtempSync(join(tmpdir(), "audit-mtls-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    relay = createRelayServer({
      secret: SECRET,
      forwardUrl,
      auditLog: audit,
      operatorToken: OPERATOR,
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2 },
      tlsPins: { [forwardUrl]: [MTLS_SERVER_SPKI_PIN] },
      tlsClientCerts: { [forwardUrl]: GOOD_CERT },
    });
    relayPort = await listenHttp(relay);
  });

  after(() => {
    relay.close();
    https.close();
  });

  it("the relay delivers to an mTLS downstream presenting its client certificate", async () => {
    const r = await postSigned(relayPort, {});
    assert.equal(r.status, 202);
    for (let i = 0; i < 100 && authorizedDownstream === 0; i++) {
      await new Promise((res) => setTimeout(res, 25));
    }
    assert.equal(authorizedDownstream, 1);
  });
});
