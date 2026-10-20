import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TlsPinMismatchError,
  assertValidCaBundle,
  spkiFingerprint,
} from "../src/pinning.ts";
import { createRelayServer, createDefaultSender, type PooledSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { OutboundConnectionPool } from "../src/keepalive.ts";
import { CA_A_PEM, CA_B_PEM, SRV_CERT_PEM, SRV_KEY_PEM } from "./ca-fixture.ts";

const SECRET = "ca-secret";
const TOKEN = "op-ca-token";
const BODY = Buffer.from(JSON.stringify({ event: "ca.probe" }));
const WRONG_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

function srvCertDer(): Buffer {
  const b64 = SRV_CERT_PEM.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return Buffer.from(b64, "base64");
}

/** Call createDefaultSender with the trailing tlsCa slot (params are positional). */
function senderWithCa(
  tlsCa: Record<string, string>,
  tlsPins?: Record<string, string[]>
): PooledSender {
  const n = createDefaultSender.length;
  const args: unknown[] = new Array(n).fill(undefined);
  args[0] = tlsPins;
  args[n - 1] = tlsCa;
  return (createDefaultSender as (...rest: unknown[]) => PooledSender)(...args);
}

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

describe("ca-bundle: assertValidCaBundle", () => {
  it("accepts a single-cert bundle", () => {
    assert.doesNotThrow(() => assertValidCaBundle(CA_A_PEM));
  });

  it("accepts a multi-cert bundle", () => {
    assert.doesNotThrow(() => assertValidCaBundle(`${CA_A_PEM}\n${CA_B_PEM}\n`));
  });

  it("rejects empty, non-PEM, and non-certificate input at config time", () => {
    assert.throws(() => assertValidCaBundle(""), /non-empty PEM/);
    assert.throws(() => assertValidCaBundle("   \n  "), /non-empty PEM/);
    assert.throws(() => assertValidCaBundle("definitely not pem"), /no PEM CERTIFICATE block/);
    // A private key block is PEM, but not a certificate.
    assert.throws(() => assertValidCaBundle(SRV_KEY_PEM), /no PEM CERTIFICATE block/);
  });

  it("rejects garbled certificate blocks", () => {
    const badB64 =
      "-----BEGIN CERTIFICATE-----\nnot valid base64 !!!\n-----END CERTIFICATE-----\n";
    assert.throws(() => assertValidCaBundle(badB64), /invalid base64/);
    // Valid base64, but not DER/X.509.
    const notDer = Buffer.from("this is not a certificate at all").toString("base64");
    const notDerPem = `-----BEGIN CERTIFICATE-----\n${notDer}\n-----END CERTIFICATE-----\n`;
    assert.throws(() => assertValidCaBundle(notDerPem), /not a parseable X.509/);
  });
});

describe("ca-bundle: real TLS handshakes through createDefaultSender", () => {
  let https: HttpsServer;
  let port: number;
  const received: Buffer[] = [];

  before(async () => {
    https = createHttpsServer({ key: SRV_KEY_PEM, cert: SRV_CERT_PEM }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    port = await listenHttps(https);
  });

  after(() => https.close());

  const url = () => `https://127.0.0.1:${port}/hook`;
  const item = (targetUrl: string) => ({ id: "c1", payload: BODY, targetUrl, headers: {} });

  it("a configured bundle chains the private-CA downstream and delivers", async () => {
    const sender = senderWithCa({ [url()]: CA_A_PEM });
    await sender(item(url()));
    assert.equal(received.length, 1);
    assert.deepEqual(received[0], BODY);
    sender.destroy();
  });

  it("without the bundle the private-CA chain fails the delivery", async () => {
    const sender = createDefaultSender();
    const before = received.length;
    await assert.rejects(() => sender(item(url())), /certificate|unable to verify/i);
    assert.equal(received.length, before);
    sender.destroy();
  });

  it("the wrong bundle does not validate the chain", async () => {
    const sender = senderWithCa({ [url()]: CA_B_PEM });
    const before = received.length;
    await assert.rejects(() => sender(item(url())), /certificate|unable to verify/i);
    assert.equal(received.length, before);
    sender.destroy();
  });

  it("bundle + matching pin composes: chain first, then pin", async () => {
    const pin = `sha256/${spkiFingerprint(srvCertDer())}`;
    const sender = senderWithCa({ [url()]: CA_A_PEM }, { [url()]: [pin] });
    await sender(item(url()));
    assert.ok(received.length >= 1);
    sender.destroy();
  });

  it("bundle + wrong pin fails on the pin check, not the chain", async () => {
    const sender = senderWithCa({ [url()]: CA_A_PEM }, { [url()]: [WRONG_PIN] });
    const before = received.length;
    // The chain verifies against the bundle (no TLS alert), then the
    // pin check rejects the peer — a distinguishable failure class.
    await assert.rejects(() => sender(item(url())), TlsPinMismatchError);
    assert.equal(received.length, before);
    sender.destroy();
  });

  it("createDefaultSender validates bundles up front", () => {
    assert.throws(
      () => senderWithCa({ "https://x/": "not-a-bundle" }),
      /invalid TLS CA bundle.*no PEM CERTIFICATE block/
    );
    assert.doesNotThrow(() => senderWithCa({ "https://x/": CA_A_PEM }));
  });
});

describe("ca-bundle: keep-alive pool key binds the trust store", () => {
  it("same origin with different bundles gets different agents", () => {
    const pool = new OutboundConnectionPool({ maxSocketsPerHost: 7, maxFreeSockets: 9 });
    try {
      const url = new URL("https://127.0.0.1:1/hook");
      const a1 = pool.agentFor(url, undefined, undefined, undefined, undefined, undefined, undefined, CA_A_PEM);
      const a2 = pool.agentFor(url, undefined, undefined, undefined, undefined, undefined, undefined, CA_B_PEM);
      const a3 = pool.agentFor(url, undefined, undefined, undefined, undefined, undefined, undefined, CA_A_PEM);
      const plain = pool.agentFor(url);
      assert.notEqual(a1, a2);
      assert.notEqual(a1, plain);
      // Same bundle on the same origin reuses the agent.
      assert.equal(a1, a3);
    } finally {
      pool.destroy();
    }
  });
});

describe("ca-bundle: end-to-end through the relay server", () => {
  let https: HttpsServer;
  const received: Buffer[] = [];

  before(async () => {
    https = createHttpsServer({ key: SRV_KEY_PEM, cert: SRV_CERT_PEM }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    await listenHttps(https);
  });

  after(() => https.close());

  function postSigned(port: number): Promise<number> {
    return new Promise((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(BODY, SECRET) },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
  }

  async function waitForReceived(count: number, timeoutMs = 8000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (received.length >= count) return;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error(`downstream did not receive ${count} deliveries`);
  }

  it("the tlsCa server option reaches the private-CA downstream", async () => {
    const downstreamPort = (https.address() as { port: number }).port;
    const forwardUrl = `https://127.0.0.1:${downstreamPort}/hook`;
    const dir = mkdtempSync(join(tmpdir(), "audit-ca-"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: TOKEN,
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2 },
      tlsCa: { [forwardUrl]: CA_A_PEM },
    });
    const relayPort = await listenHttp(relay);
    try {
      const before = received.length;
      assert.equal(await postSigned(relayPort), 202);
      await waitForReceived(before + 1);
      assert.deepEqual(received[received.length - 1], BODY);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("an invalid tlsCa bundle fails the relay at startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-ca-bad-"));
    assert.throws(
      () =>
        createRelayServer({
          secret: SECRET,
          forwardUrl: "https://127.0.0.1:1/hook",
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          tlsCa: { "https://127.0.0.1:1/hook": "not-a-bundle" },
        }),
      /invalid TLS CA bundle/
    );
  });
});
