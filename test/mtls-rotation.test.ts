import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { TLSSocket } from "node:tls";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RotatingClientCertSet,
  DEFAULT_CLIENT_CERT_GRACE_MS,
  type RotatingClientCertConfig,
} from "../src/mtls-rotation.ts";
import { clientCertIdentity } from "../src/mtls.ts";
import { createRelayServer, createDefaultSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  CertExpiryMonitor,
  resolveCertExpiryOptions,
  type CertExpiringAuditEvent,
} from "../src/cert-expiry.ts";
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

// The "new" certificate: valid PEM pair, but signed by the throwaway
// evil-ca — a strict downstream that only trusts relay-test-ca rejects
// it, exactly the rotation hazard (downstream hasn't picked up the new
// identity yet).
const NEW_CERT = { cert: MTLS_EVIL_CLIENT_CERT_PEM, key: MTLS_EVIL_CLIENT_KEY_PEM };
// The "old" certificate: trusted by the strict downstream (relay-client,
// signed by relay-test-ca).
const OLD_CERT = { cert: MTLS_CLIENT_CERT_PEM, key: MTLS_CLIENT_KEY_PEM };

const rotationSecret = "mtls-rotation-secret";
const BODY = Buffer.from(JSON.stringify({ event: "mtls-rotation.probe" }));

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

/**
 * createDefaultSender with a rotation set as the 20th (trailing)
 * positional argument — everything else default, exactly like the
 * server's own call site.
 */
function senderWithRotation(
  pins: Record<string, string[]>,
  url: string,
  set: RotatingClientCertSet,
  monitor?: CertExpiryMonitor
) {
  return createDefaultSender(
    pins, // tlsPins
    undefined, // keepAlive
    undefined, // outboundSigning
    undefined, // proxies
    undefined, // tlsClientCerts
    undefined, // compressOutbound
    undefined, // http2
    undefined, // idempotencyKey
    undefined, // websocket
    undefined, // outboundEncryption
    undefined, // tlsSniOverrides
    undefined, // responseCompression
    undefined, // forwardHeaders
    monitor, // certExpiryMonitor
    undefined, // minTlsVersions
    undefined, // tlsVersionMonitor
    undefined, // compressThreshold
    undefined, // onGzipFallback
    undefined, // onE2eeKeyRotated
    new Map([[url, set]]) // tlsClientCertRotation
  );
}

const rotationCfg = (retiredAtMs?: number): RotatingClientCertConfig => ({
  certificates: [
    { id: "cert-new", ...NEW_CERT },
    { id: "cert-old", ...OLD_CERT, ...(retiredAtMs !== undefined ? { retiredAtMs } : {}) },
  ],
});

describe("mtls-rotation: config validation", () => {
  it("rejects an empty certificate set", () => {
    assert.throws(() => new RotatingClientCertSet({ certificates: [] }), /non-empty array/);
    assert.throws(
      () => new RotatingClientCertSet({ certificates: undefined as never }),
      /non-empty array/
    );
  });

  it("rejects duplicate ids", () => {
    assert.throws(
      () =>
        new RotatingClientCertSet({
          certificates: [
            { id: "a", ...NEW_CERT },
            { id: "a", ...OLD_CERT },
          ],
        }),
      /duplicate certificate id "a"/
    );
  });

  it("rejects empty ids", () => {
    assert.throws(
      () => new RotatingClientCertSet({ certificates: [{ id: "", ...NEW_CERT }] }),
      /non-empty string id/
    );
  });

  it("rejects unparsable PEMs", () => {
    assert.throws(
      () => new RotatingClientCertSet({ certificates: [{ id: "x", cert: "bogus", key: "bogus" }] }),
      /invalid TLS client certificate\/key PEM/
    );
  });

  it("rejects a fully retired set — the primary must stay in service", () => {
    assert.throws(
      () =>
        new RotatingClientCertSet({
          certificates: [
            { id: "a", ...NEW_CERT, retiredAtMs: Date.now() },
            { id: "b", ...OLD_CERT, retiredAtMs: Date.now() },
          ],
        }),
      /no non-retired certificate/
    );
  });

  it("rejects an invalid retiredAtMs", () => {
    assert.throws(
      () =>
        new RotatingClientCertSet({
          certificates: [{ id: "a", ...NEW_CERT, retiredAtMs: -1 }],
        }),
      /invalid retiredAtMs/
    );
    assert.throws(
      () =>
        new RotatingClientCertSet({
          certificates: [{ id: "a", ...NEW_CERT, retiredAtMs: Number.NaN }],
        }),
      /invalid retiredAtMs/
    );
  });

  it("rejects a negative graceMs", () => {
    assert.throws(
      () => new RotatingClientCertSet({ certificates: [{ id: "a", ...NEW_CERT }], graceMs: -1 }),
      /graceMs/
    );
  });

  it("accepts a valid set: primary is the first non-retired entry", () => {
    const set = new RotatingClientCertSet(rotationCfg(Date.now()));
    assert.equal(set.primary().id, "cert-new");
    assert.deepEqual(set.activeCertIds(), ["cert-new", "cert-old"]);
    assert.equal(DEFAULT_CLIENT_CERT_GRACE_MS, 86_400_000);
  });

  it("createDefaultSender rejects an endpoint in both tlsClientCerts and tlsClientCertRotation", () => {
    const url = "https://127.0.0.1:9/hook";
    assert.throws(
      () =>
        createDefaultSender(
          undefined, undefined, undefined, undefined,
          { [url]: OLD_CERT },
          undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined,
          new Map([[url, new RotatingClientCertSet(rotationCfg())]])
        ),
      /both tlsClientCerts and tlsClientCertRotation/
    );
  });

  it("createDefaultSender rejects a non-Map rotation value", () => {
    assert.throws(
      () =>
        createDefaultSender(
          undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined,
          {} as never
        ),
      /must be a Map/
    );
  });

  it("createDefaultSender rejects values that are not compiled sets", () => {
    assert.throws(
      () =>
        createDefaultSender(
          undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined,
          new Map([["https://127.0.0.1:9/hook", { certificates: [] } as never]])
        ),
      /expected a RotatingClientCertSet/
    );
  });

  it("createRelayServer rejects invalid raw rotation config at startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-mtls-rot-"));
    assert.throws(
      () =>
        createRelayServer({
          secret: rotationSecret,
          forwardUrl: "https://127.0.0.1:9/hook",
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          tlsClientCertRotation: {
            "https://127.0.0.1:9/hook": { certificates: [] },
          },
        }),
      /invalid tlsClientCertRotation.*non-empty array/
    );
  });
});

describe("mtls-rotation: grace semantics", () => {
  const T0 = 1_750_000_000_000;
  let now = T0;
  const set = () =>
    new RotatingClientCertSet({
      ...rotationCfg(T0),
      graceMs: 1000,
      nowMs: () => now,
    });

  it("the grace boundary is inclusive", () => {
    now = T0 + 1000;
    const s = set();
    assert.deepEqual(s.fallbacks().map((f) => f.id), ["cert-old"]);
    assert.equal(s.rotationInProgress(), true);
    assert.equal(s.isRotationComplete(), false);
    assert.deepEqual(s.activeCertIds(), ["cert-new", "cert-old"]);
  });

  it("past the boundary the rotation is complete", () => {
    now = T0 + 1001;
    const s = set();
    assert.deepEqual(s.fallbacks(), []);
    assert.equal(s.rotationInProgress(), false);
    assert.equal(s.isRotationComplete(), true);
    assert.deepEqual(s.activeCertIds(), ["cert-new"]);
  });

  it("the expiry watch excludes retired-out-of-grace certificates", () => {
    now = T0 + 1001;
    assert.deepEqual(
      set().certificatesForExpiryWatch().map((c) => c.id),
      ["cert-new"]
    );
    // Inside grace: fallback first, primary last (the monitor's
    // per-endpoint gauge settles on the primary).
    now = T0;
    assert.deepEqual(
      set().certificatesForExpiryWatch().map((c) => c.id),
      ["cert-old", "cert-new"]
    );
  });
});

describe("mtls-rotation: real handshakes through createDefaultSender", () => {
  // Strict downstream: trusts only relay-test-ca — the new (evil-ca)
  // certificate is rejected, the old (relay-client) one accepted.
  let strict: HttpsServer;
  let strictPort: number;
  let strictRequests = 0;
  let strictCN: string | null = null;
  // Lenient downstream: requests but never verifies the client cert —
  // every handshake completes, so the primary is used directly.
  let lenient: HttpsServer;
  let lenientPort: number;
  let lenientRequests = 0;
  let lenientCN: string | null = null;
  let lenientSecureConnections = 0;

  before(async () => {
    strict = createHttpsServer(
      {
        key: MTLS_SERVER_KEY_PEM,
        cert: MTLS_SERVER_CERT_PEM,
        ca: MTLS_CA_PEM,
        requestCert: true,
        rejectUnauthorized: true,
      },
      (req, res) => {
        strictRequests++;
        strictCN = clientCN(req.socket as TLSSocket);
        req.resume();
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    strictPort = await listenHttps(strict);
    lenient = createHttpsServer(
      {
        key: MTLS_SERVER_KEY_PEM,
        cert: MTLS_SERVER_CERT_PEM,
        requestCert: true,
        rejectUnauthorized: false,
      },
      (req, res) => {
        lenientRequests++;
        lenientCN = clientCN(req.socket as TLSSocket);
        req.resume();
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    lenient.on("secureConnection", () => lenientSecureConnections++);
    lenientPort = await listenHttps(lenient);
  });

  after(() => {
    strict.close();
    lenient.close();
  });

  const strictUrl = () => `https://127.0.0.1:${strictPort}/hook`;
  const lenientUrl = () => `https://127.0.0.1:${lenientPort}/hook`;
  const item = (targetUrl: string) => ({ id: "m1", payload: BODY, targetUrl, headers: {} });
  const pinsFor = (u: string) => ({ [u]: [MTLS_SERVER_SPKI_PIN] });

  it("falls back to the retired certificate when the downstream rejects the new one", async () => {
    const set = new RotatingClientCertSet(rotationCfg(Date.now()));
    const sender = senderWithRotation(pinsFor(strictUrl()), strictUrl(), set);
    const before = strictRequests;
    const res = await sender(item(strictUrl()));
    sender.destroy();
    // The rejected primary handshake produced no HTTP request — zero
    // payload bytes reached the downstream; only the fallback did.
    assert.equal(strictRequests, before + 1);
    assert.equal(strictCN, "relay-client");
    assert.ok(res !== undefined);
    assert.equal(res.clientCertId, "cert-old");
  });

  it("uses the primary directly when the downstream accepts it — no fallback handshake", async () => {
    const set = new RotatingClientCertSet(rotationCfg(Date.now()));
    const sender = senderWithRotation(pinsFor(lenientUrl()), lenientUrl(), set);
    const before = lenientRequests;
    const res = await sender(item(lenientUrl()));
    const stats = sender.pool!.getStats();
    sender.destroy();
    assert.equal(lenientRequests, before + 1);
    assert.equal(lenientCN, "evil-client");
    assert.ok(res !== undefined);
    assert.equal(res.clientCertId, "cert-new");
    // Exactly one pooled identity: the primary's — no fallback agent
    // was ever created.
    assert.equal(stats.endpoints.length, 1);
    assert.ok(stats.endpoints[0].key.includes(`|cert:${clientCertIdentity(NEW_CERT)}`));
  });

  it("the pool isolates agents per actually-used certificate identity", async () => {
    const set = new RotatingClientCertSet(rotationCfg(Date.now()));
    const sender = senderWithRotation(pinsFor(strictUrl()), strictUrl(), set);
    await sender({ id: "m2", payload: BODY, targetUrl: strictUrl(), headers: {} });
    await sender({ id: "m3", payload: BODY, targetUrl: strictUrl(), headers: {} });
    const stats = sender.pool!.getStats();
    sender.destroy();
    const idNew = clientCertIdentity(NEW_CERT);
    const idOld = clientCertIdentity(OLD_CERT);
    assert.equal(stats.endpoints.length, 2);
    const keys = stats.endpoints.map((e) => e.key);
    assert.ok(keys.some((k) => k.includes(`|cert:${idNew}`)), `primary identity keyed: ${keys}`);
    assert.ok(keys.some((k) => k.includes(`|cert:${idOld}`)), `fallback identity keyed: ${keys}`);
    const oldEp = stats.endpoints.find((e) => e.key.includes(`|cert:${idOld}`))!;
    const newEp = stats.endpoints.find((e) => e.key.includes(`|cert:${idNew}`))!;
    // The fallback connection is pooled and reused; every primary
    // handshake failed and opened its own (destroyed) connection.
    assert.equal(oldEp.created, 1);
    assert.ok(oldEp.reused >= 1, `expected fallback reuse, got ${JSON.stringify(oldEp)}`);
    assert.equal(newEp.created, 2);
    assert.equal(newEp.reused, 0);
  });

  it("a pin mismatch never falls back — it is not about the client identity", async () => {
    const set = new RotatingClientCertSet(rotationCfg(Date.now()));
    const wrongPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const sender = senderWithRotation({ [lenientUrl()]: [wrongPin] }, lenientUrl(), set);
    await assert.rejects(() => sender(item(lenientUrl())), /pin mismatch/i);
    const stats = sender.pool!.getStats();
    sender.destroy();
    // Only the primary handshake ran: no fallback retry on a pin
    // failure, which proves the server side, not the client cert.
    // Counted client-side: with requestCert the server never sees a
    // completed handshake when the client aborts on the pin (it waits
    // for the client Certificate that never comes), so server-side
    // secureConnection counting cannot observe this attempt.
    assert.equal(sender.takeRotationClientCertId?.("m1"), "cert-new");
    const keys = stats.endpoints.map((e) => e.key);
    assert.ok(
      !keys.some((k) => k.includes(`|cert:${clientCertIdentity(OLD_CERT)}`)),
      `fallback identity must never be used: ${keys}`
    );
  });

  it("a WR-36 single-identity endpoint keeps the legacy response shape (no clientCertId)", async () => {
    const sender = createDefaultSender(pinsFor(strictUrl()), undefined, undefined, undefined, {
      [strictUrl()]: OLD_CERT,
    });
    const res = await sender(item(strictUrl()));
    sender.destroy();
    assert.ok(res !== undefined);
    assert.ok(!("clientCertId" in res), "single-identity responses must not carry clientCertId");
  });

  it("non-TLS errors never fall back and leave no certificate attribution", async () => {
    // A closed localhost port: TCP connect fails immediately with
    // ECONNREFUSED — a non-TLS error, no handshake ever runs. (A bogus
    // hostname is not used: some resolvers answer those instead of
    // failing, which would turn this into a connect-timeout wait.)
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
    const addr = probe.address();
    assert.ok(addr && typeof addr === "object");
    const closedPort = addr.port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const badUrl = `https://127.0.0.1:${closedPort}/hook`;
    const set = new RotatingClientCertSet(rotationCfg(Date.now()));
    const sender = senderWithRotation({}, badUrl, set);
    await assert.rejects(() => sender(item(badUrl)), /ECONNREFUSED/i);
    sender.destroy();
    // No handshake ever ran for this delivery: honestly absent, never
    // a stale id from another delivery.
    assert.equal(sender.takeRotationClientCertId?.("m1"), undefined);
  });
});

describe("mtls-rotation: WR-73 cert-expiry silence", () => {
  const HUGE_THRESHOLD = 20 * 365 * 24 * 3600; // 20 years: every fixture cert would warn

  function watchedMonitor() {
    const events: CertExpiringAuditEvent[] = [];
    const monitor = new CertExpiryMonitor(
      resolveCertExpiryOptions({ enabled: true, thresholdSeconds: HUGE_THRESHOLD, now: () => Date.now() }),
      { onCertExpiring: (e) => events.push(e) }
    );
    return { monitor, events };
  }

  it("a retired-out-of-grace certificate is not warned about", () => {
    const { monitor, events } = watchedMonitor();
    const url = "https://127.0.0.1:9/hook";
    const set = new RotatingClientCertSet(
      rotationCfg(Date.now() - DEFAULT_CLIENT_CERT_GRACE_MS - 1000)
    );
    const sender = senderWithRotation({}, url, set, monitor);
    sender.destroy();
    // Only the primary warns — the dead old identity stays silent.
    assert.equal(events.length, 1);
  });

  it("control: the same certificate retired inside grace is still watched", () => {
    const { monitor, events } = watchedMonitor();
    const url = "https://127.0.0.1:9/hook";
    const set = new RotatingClientCertSet(rotationCfg(Date.now()));
    const sender = senderWithRotation({}, url, set, monitor);
    sender.destroy();
    assert.equal(events.length, 2);
  });
});

describe("mtls-rotation: end-to-end through the relay server", () => {
  let https: HttpsServer;
  let relay: Server;
  let relayPort: number;
  let downstreamPort: number;
  let requests = 0;
  let lastCN: string | null = null;
  const dir = mkdtempSync(join(tmpdir(), "audit-mtls-rot-"));
  const auditPath = join(dir, "audit.jsonl");

  function postSigned(port: number, headers: Record<string, string>) {
    return new Promise<{ status: number }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: { ...headers, "x-signature": signSha256(BODY, rotationSecret) },
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

  function readAudit(): Record<string, unknown>[] {
    const raw = readFileSync(auditPath, "utf8");
    return raw
      .split("\n")
      .filter((l) => l.trim() !== "")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  }

  async function waitFor(pred: (e: Record<string, unknown>) => boolean) {
    const start = Date.now();
    for (;;) {
      const found = readAudit().find(pred);
      if (found !== undefined) return found;
      if (Date.now() - start > 8000) throw new Error("timed out waiting for audit event");
      await new Promise((r) => setTimeout(r, 25));
    }
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
        requests++;
        lastCN = clientCN(req.socket as TLSSocket);
        req.resume();
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    downstreamPort = await listenHttps(https);
    const forwardUrl = `https://127.0.0.1:${downstreamPort}/hook`;
    relay = createRelayServer({
      secret: rotationSecret,
      forwardUrl,
      auditLog: new AuditLog(auditPath),
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2 },
      tlsPins: { [forwardUrl]: [MTLS_SERVER_SPKI_PIN] },
      tlsClientCertRotation: {
        [forwardUrl]: {
          certificates: [
            { id: "cert-new", ...NEW_CERT },
            { id: "cert-old", ...OLD_CERT, retiredAtMs: Date.now() },
          ],
        },
      },
    });
    relayPort = await listenHttp(relay);
  });

  after(() => {
    relay.close();
    https.close();
  });

  it("delivers via the fallback identity and audits clientCertId", async () => {
    const r = await postSigned(relayPort, {});
    assert.equal(r.status, 202);
    const delivered = await waitFor((e) => e.event === "delivered");
    assert.equal(delivered.clientCertId, "cert-old");
    const summary = delivered.response_summary as Record<string, unknown>;
    assert.equal(summary.clientCertId, "cert-old");
    assert.equal(requests, 1);
    assert.equal(lastCN, "relay-client");
  });
});

describe("mtls-rotation: dead_letter carries clientCertId", () => {
  let https: HttpsServer;
  let relay: Server;
  let relayPort: number;
  const dir = mkdtempSync(join(tmpdir(), "audit-mtls-rot-dl-"));
  const auditPath = join(dir, "audit.jsonl");

  function postSigned(port: number) {
    return new Promise<{ status: number }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: { "x-signature": signSha256(BODY, rotationSecret) },
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

  function readAudit(): Record<string, unknown>[] {
    const raw = readFileSync(auditPath, "utf8");
    return raw
      .split("\n")
      .filter((l) => l.trim() !== "")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  }

  async function waitFor(pred: (e: Record<string, unknown>) => boolean) {
    const start = Date.now();
    for (;;) {
      const found = readAudit().find(pred);
      if (found !== undefined) return found;
      if (Date.now() - start > 8000) throw new Error("timed out waiting for audit event");
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  before(async () => {
    // Lenient downstream that always 500s: the primary handshake
    // succeeds, the delivery dead-letters on the first attempt.
    https = createHttpsServer(
      {
        key: MTLS_SERVER_KEY_PEM,
        cert: MTLS_SERVER_CERT_PEM,
        requestCert: true,
        rejectUnauthorized: false,
      },
      (req, res) => {
        req.resume();
        req.on("end", () => res.writeHead(500).end("boom"));
      }
    );
    const downstreamPort = await listenHttps(https);
    const forwardUrl = `https://127.0.0.1:${downstreamPort}/hook`;
    relay = createRelayServer({
      secret: rotationSecret,
      forwardUrl,
      auditLog: new AuditLog(auditPath),
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 1 },
      tlsPins: { [forwardUrl]: [MTLS_SERVER_SPKI_PIN] },
      tlsClientCertRotation: {
        [forwardUrl]: {
          certificates: [
            { id: "cert-new", ...NEW_CERT },
            { id: "cert-old", ...OLD_CERT, retiredAtMs: Date.now() },
          ],
        },
      },
    });
    relayPort = await listenHttp(relay);
  });

  after(() => {
    relay.close();
    https.close();
  });

  it("the dead_letter audit names the primary identity that authenticated the attempts", async () => {
    const r = await postSigned(relayPort);
    assert.equal(r.status, 202);
    const deadLetter = await waitFor((e) => e.event === "dead_letter");
    assert.equal(deadLetter.clientCertId, "cert-new");
  });
});
