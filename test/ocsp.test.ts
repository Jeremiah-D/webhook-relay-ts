import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { request as httpRequest } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OcspMonitor,
  OcspError,
  OcspRevokedError,
  DerError,
  resolveOcspEndpointOptions,
  DEFAULT_OCSP_RESPONDER_TIMEOUT_MS,
  certIdForLeaf,
  buildOcspRequest,
  evaluateOcspResponse,
  extractOcspResponderUrl,
  issuerNameDer,
  parseDer,
  derSequence,
  derEnumerated,
  derExplicit,
  derImplicit,
  derImplicitConstructed,
  derOctetString,
  derNull,
  derOid,
  derGeneralizedTime,
  derBitString,
  derIntegerBytes,
  type OcspCertId,
  type OcspRevokedAuditEvent,
  type OcspAlert,
  type OcspTlsSocket,
  type ResolvedOcspEndpointOptions,
} from "../src/ocsp.ts";
import { renderPrometheus } from "../src/metrics.ts";
import { createRelayServer, createDefaultSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";
import { MTLS_SERVER_CERT_PEM, MTLS_CA_PEM } from "./mtls-fixture.ts";

const TEST_KEY = "ocsp-test-secret";
const BODY = Buffer.from(JSON.stringify({ event: "ocsp.probe" }));
const RESPONDER_URL = "http://127.0.0.1:9/ocsp";

function pemDer(pem: string): Buffer {
  return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
}

const LEAF_DER = pemDer(TLS_FIXTURE_CERT_PEM);

/** Build a minimal RFC 6960 OCSPResponse for `certId` with the given SingleResponse status. */
function buildOcspResponse(certId: OcspCertId, status: "good" | "revoked" | "unknown"): Buffer {
  const certIdDer = derSequence(
    derSequence(derOid("1.3.14.3.2.26"), derNull()),
    derOctetString(certId.issuerNameHash),
    derOctetString(certId.issuerKeyHash),
    derIntegerBytes(certId.serialNumber)
  );
  const certStatus =
    status === "good"
      ? derImplicit(0, Buffer.alloc(0))
      : status === "unknown"
        ? derImplicit(2, Buffer.alloc(0))
        : derImplicitConstructed(1, derGeneralizedTime("20261013000000Z"));
  const single = derSequence(certIdDer, certStatus, derGeneralizedTime("20261014000000Z"));
  const tbs = derSequence(
    derExplicit(1, issuerNameDer(LEAF_DER)),
    derGeneralizedTime("20261014000000Z"),
    derSequence(single)
  );
  const basic = derSequence(
    tbs,
    derSequence(derOid("1.2.840.113549.1.1.11"), derNull()),
    derBitString(Buffer.from([0, 0xde, 0xad]))
  );
  return derSequence(
    derEnumerated(0),
    derExplicit(
      0,
      derSequence(derOid("1.3.6.1.5.5.7.48.1.1"), derOctetString(basic))
    )
  );
}

/** Fake TLS socket surface for checkPeer: self-signed leaf, optional stapled response. */
function fakeTlsSocket(leafDer: Buffer, stapled?: Buffer): OcspTlsSocket {
  return {
    getPeerCertificate: (detailed?: boolean) =>
      detailed === true
        ? { raw: leafDer, issuerCertificate: { raw: leafDer } }
        : { raw: leafDer },
    getOCSPResponse: () => (stapled !== undefined ? stapled : Buffer.alloc(0)),
  };
}

function testMonitor(): {
  monitor: OcspMonitor;
  revoked: OcspRevokedAuditEvent[];
  alerts: OcspAlert[];
} {
  const revoked: OcspRevokedAuditEvent[] = [];
  const alerts: OcspAlert[] = [];
  const monitor = new OcspMonitor({
    onRevoked: (e) => revoked.push(e),
    onAlert: (a) => alerts.push(a),
  });
  return { monitor, revoked, alerts };
}

describe("ocsp: option validation", () => {
  it("defaults to fail-open with stapling on", () => {
    const r = resolveOcspEndpointOptions({});
    assert.equal(r.mode, "fail-open");
    assert.equal(r.useStapled, true);
    assert.equal(r.responderUrl, undefined);
    assert.equal(r.responderTimeoutMs, DEFAULT_OCSP_RESPONDER_TIMEOUT_MS);
    assert.equal(typeof r.responderFetcher, "function");
  });

  it("accepts a full fail-closed config", () => {
    const fetcher = async () => Buffer.alloc(0);
    const r = resolveOcspEndpointOptions({
      mode: "fail-closed",
      useStapled: false,
      responderUrl: "https://ocsp.example.com/",
      responderFetcher: fetcher,
      responderTimeoutMs: 1000,
    });
    assert.equal(r.mode, "fail-closed");
    assert.equal(r.useStapled, false);
    assert.equal(r.responderUrl, "https://ocsp.example.com/");
    assert.equal(r.responderFetcher, fetcher);
    assert.equal(r.responderTimeoutMs, 1000);
  });

  it("rejects malformed configs with RangeError", () => {
    assert.throws(() => resolveOcspEndpointOptions({ mode: "sometimes" as never }), RangeError);
    assert.throws(() => resolveOcspEndpointOptions({ useStapled: "yes" as never }), RangeError);
    assert.throws(() => resolveOcspEndpointOptions({ responderUrl: "not a url" }), RangeError);
    assert.throws(() => resolveOcspEndpointOptions({ responderUrl: "ftp://x/" }), RangeError);
    assert.throws(() => resolveOcspEndpointOptions({ responderUrl: "" }), RangeError);
    assert.throws(() => resolveOcspEndpointOptions({ responderFetcher: 42 as never }), RangeError);
    assert.throws(() => resolveOcspEndpointOptions({ responderTimeoutMs: 50 }), RangeError);
    assert.throws(() => resolveOcspEndpointOptions({ responderTimeoutMs: 60000 }), RangeError);
    assert.throws(() => resolveOcspEndpointOptions({ responderTimeoutMs: NaN }), RangeError);
    assert.throws(() => resolveOcspEndpointOptions(null as never), RangeError);
    assert.throws(() => resolveOcspEndpointOptions([] as never), RangeError);
  });

  it("createDefaultSender rejects an invalid tlsOcsp entry at startup", () => {
    assert.throws(
      () =>
        createDefaultSender(
          undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined,
          { "https://x/hook": { mode: "bogus" as never } }
        ),
      /invalid tlsOcsp for https:\/\/x\/hook/
    );
  });
});

describe("ocsp: response evaluation", () => {
  const certId = certIdForLeaf(LEAF_DER);

  it("maps good / revoked / unknown stapled statuses", () => {
    const good = evaluateOcspResponse(buildOcspResponse(certId, "good"), certId);
    assert.equal(good.status, "good");
    assert.ok(good.serialNumber.length > 0);
    assert.equal(good.revokedAt, undefined);

    const revoked = evaluateOcspResponse(buildOcspResponse(certId, "revoked"), certId);
    assert.equal(revoked.status, "revoked");
    assert.equal(revoked.serialNumber, good.serialNumber);
    assert.equal(revoked.revokedAt, "2026-10-13T00:00:00.000Z");

    const unknown = evaluateOcspResponse(buildOcspResponse(certId, "unknown"), certId);
    assert.equal(unknown.status, "unknown");
  });

  it("rejects a response that is not about this certificate", () => {
    const other = { ...certId, serialNumber: Buffer.from([1, 2, 3]) };
    assert.throws(
      () => evaluateOcspResponse(buildOcspResponse(certId, "good"), other),
      DerError
    );
    const otherKey = { ...certId, issuerKeyHash: Buffer.alloc(20, 7) };
    assert.throws(
      () => evaluateOcspResponse(buildOcspResponse(certId, "good"), otherKey),
      DerError
    );
  });

  it("rejects non-successful, wrong-type, and truncated responses", () => {
    const tryLater = derSequence(derEnumerated(3));
    assert.throws(() => evaluateOcspResponse(tryLater, certId), /tryLater/);

    const wrongType = derSequence(
      derEnumerated(0),
      derExplicit(0, derSequence(derOid("1.2.3.4"), derOctetString(Buffer.from([1]))))
    );
    assert.throws(() => evaluateOcspResponse(wrongType, certId), /responseType/);

    assert.throws(() => evaluateOcspResponse(Buffer.from([0x30, 0x03, 0x0a]), certId), DerError);
    assert.throws(() => evaluateOcspResponse(Buffer.from("not-der"), certId), DerError);
  });

  it("certIdForLeaf needs an issuer cert for non-self-signed leaves", () => {
    // The fixture is self-signed, so omitting the issuer works.
    const self = certIdForLeaf(LEAF_DER);
    assert.equal(self.issuerNameHash.length, 20);
    // The mtls fixture server cert is CA-signed (issuer != subject): no
    // issuer cert means no honest issuerKeyHash — an error, not a guess.
    const caSignedDer = pemDer(MTLS_SERVER_CERT_PEM);
    assert.throws(() => certIdForLeaf(caSignedDer), DerError);
    // With the issuing CA cert it works.
    const withIssuer = certIdForLeaf(caSignedDer, pemDer(MTLS_CA_PEM));
    assert.equal(withIssuer.issuerKeyHash.length, 20);
  });

  it("buildOcspRequest produces a parseable request for this certificate", () => {
    const req = buildOcspRequest(certId);
    const node = parseDer(req);
    assert.equal(node.tag, 0x10);
    // OCSPRequest -> tbsRequest -> requestList -> Request -> reqCert.
    const reqCert = node.children[0].children[0].children[0].children[0];
    assert.equal(reqCert.tag, 0x10);
    assert.equal(reqCert.children[1].value.toString("hex"), certId.issuerNameHash.toString("hex"));
    assert.equal(reqCert.children[2].value.toString("hex"), certId.issuerKeyHash.toString("hex"));
    // Serial INTEGER may carry a 0x00 sign pad; compare the significant bytes.
    const serialValue = reqCert.children[3].value;
    const significant = serialValue[0] === 0 ? serialValue.subarray(1) : serialValue;
    assert.ok(significant.equals(certId.serialNumber));
  });

  it("extractOcspResponderUrl returns undefined for the fixture (no AIA) and never throws", () => {
    assert.equal(extractOcspResponderUrl(LEAF_DER), undefined);
    assert.equal(extractOcspResponderUrl(Buffer.from("garbage")), undefined);
  });
});

describe("ocsp: monitor accounting and exposition", () => {
  it("is inert with no checks: no series, empty render", () => {
    const { monitor } = testMonitor();
    assert.equal(monitor.socketVerified({}, "https://x/hook"), false);
    assert.deepEqual(monitor.series(), []);
    assert.equal(monitor.render(), "");
  });

  it("counts outcomes per (endpoint, status) and renders relay_ocsp_total", () => {
    const { monitor } = testMonitor();
    monitor.record("https://a/hook", "good");
    monitor.record("https://a/hook", "good");
    monitor.record("https://a/hook", "revoked");
    monitor.record("https://b/hook", "error");
    const text = monitor.render();
    assert.match(text, /# HELP relay_ocsp_total/);
    assert.match(text, /# TYPE relay_ocsp_total counter/);
    assert.match(text, /relay_ocsp_total\{endpoint="https:\/\/a\/hook",status="good"\} 2/);
    assert.match(text, /relay_ocsp_total\{endpoint="https:\/\/a\/hook",status="revoked"\} 1/);
    assert.match(text, /relay_ocsp_total\{endpoint="https:\/\/b\/hook",status="error"\} 1/);
  });

  it("renderPrometheus carries the block when ocsp input is present, omits it otherwise", () => {
    const text = renderPrometheus({
      deliveries: [],
      circuits: [],
      latencyHistograms: [],
      ocsp: [{ endpoint: "https://a/hook", status: "revoked", count: 3 }],
    });
    assert.match(text, /relay_ocsp_total\{endpoint="https:\/\/a\/hook",status="revoked"\} 3/);
    const bare = renderPrometheus({ deliveries: [], circuits: [], latencyHistograms: [] });
    assert.ok(!bare.includes("relay_ocsp_total"));
  });
});

describe("ocsp: checkPeer with a fake TLS socket", () => {
  const certId = certIdForLeaf(LEAF_DER);
  const endpoint = "https://ocsp-check/hook";

  function cfg(overrides: Partial<ResolvedOcspEndpointOptions> = {}): ResolvedOcspEndpointOptions {
    return {
      mode: "fail-open",
      useStapled: true,
      responderUrl: undefined,
      responderFetcher: async () => {
        throw new Error("no fetcher configured in this test");
      },
      responderTimeoutMs: 3000,
      ...overrides,
    };
  }

  it("stapled good resolves, marks the socket verified, counts good", async () => {
    const { monitor, revoked, alerts } = testMonitor();
    const socket = fakeTlsSocket(LEAF_DER, buildOcspResponse(certId, "good"));
    await monitor.checkPeer(socket, endpoint, cfg());
    assert.equal(monitor.socketVerified(socket, endpoint), true);
    assert.equal(monitor.socketVerified(socket, "https://other/hook"), false);
    assert.deepEqual(revoked, []);
    assert.deepEqual(alerts, []);
    assert.match(monitor.render(), /relay_ocsp_total\{endpoint="https:\/\/ocsp-check\/hook",status="good"\} 1/);
  });

  it("stapled revoked throws OcspRevokedError with audit event + alert", async () => {
    const { monitor, revoked, alerts } = testMonitor();
    const socket = fakeTlsSocket(LEAF_DER, buildOcspResponse(certId, "revoked"));
    const err = await monitor.checkPeer(socket, endpoint, cfg({ mode: "fail-closed" })).then(
      () => null,
      (e: unknown) => e
    );
    assert.ok(err instanceof OcspRevokedError);
    assert.equal(err.endpoint, endpoint);
    assert.ok(err.message.includes("revoked"));
    // The socket is deliberately NOT marked verified: every delivery over
    // a revoked peer must fail.
    assert.equal(monitor.socketVerified(socket, endpoint), false);
    assert.equal(revoked.length, 1);
    const event = revoked[0];
    assert.equal(event.event, "ocsp_revoked");
    assert.equal(event.endpoint, endpoint);
    assert.equal(event.source, "stapled");
    assert.equal(event.mode, "fail-closed");
    assert.ok(event.serialNumber.length > 0);
    assert.equal(event.revokedAt, "2026-10-13T00:00:00.000Z");
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].kind, "revoked");
    assert.equal(alerts[0].outcome, "rejected");
    assert.match(monitor.render(), /status="revoked"\} 1/);
  });

  it("stapled response for another certificate: fail-open proceeds with alert, fail-closed throws OcspError", async () => {
    const other = { ...certId, serialNumber: Buffer.from([9, 9, 9]) };
    const stapled = buildOcspResponse(other, "good");

    const open = testMonitor();
    await open.monitor.checkPeer(fakeTlsSocket(LEAF_DER, stapled), endpoint, cfg({ mode: "fail-open" }));
    assert.equal(open.alerts.length, 1);
    assert.equal(open.alerts[0].kind, "ocsp_unavailable");
    assert.equal(open.alerts[0].outcome, "proceeded");
    assert.match(open.monitor.render(), /status="error"\} 1/);

    const closed = testMonitor();
    const err = await closed.monitor
      .checkPeer(fakeTlsSocket(LEAF_DER, stapled), endpoint, cfg({ mode: "fail-closed" }))
      .then(() => null, (e: unknown) => e);
    assert.ok(err instanceof OcspError);
    assert.ok(!(err instanceof OcspRevokedError));
    assert.equal(closed.alerts.length, 1);
    assert.equal(closed.alerts[0].outcome, "rejected");
  });

  it("no stapled response and no responder: fail-open proceeds, fail-closed throws", async () => {
    const open = testMonitor();
    await open.monitor.checkPeer(fakeTlsSocket(LEAF_DER), endpoint, cfg({ mode: "fail-open" }));
    assert.equal(open.alerts.length, 1);
    assert.match(open.alerts[0].detail, /no OCSP responder URL/);

    const closed = testMonitor();
    const err = await closed.monitor
      .checkPeer(fakeTlsSocket(LEAF_DER), endpoint, cfg({ mode: "fail-closed" }))
      .then(() => null, (e: unknown) => e);
    assert.ok(err instanceof OcspError);
  });

  it("responder fallback uses the injected fetcher with the configured URL", async () => {
    const { monitor, revoked, alerts } = testMonitor();
    const seen: { url: string; request: Buffer }[] = [];
    const socket = fakeTlsSocket(LEAF_DER);
    await monitor.checkPeer(
      socket,
      endpoint,
      cfg({
        useStapled: false,
        responderUrl: RESPONDER_URL,
        responderFetcher: async (url, request) => {
          seen.push({ url, request });
          // The request must be a parseable OCSPRequest for this cert.
          parseDer(request);
          return buildOcspResponse(certId, "good");
        },
      })
    );
    assert.equal(seen.length, 1);
    assert.equal(seen[0].url, RESPONDER_URL);
    assert.equal(monitor.socketVerified(socket, endpoint), true);
    assert.deepEqual(revoked, []);
    assert.deepEqual(alerts, []);
  });

  it("responder fetch failure: fail-open proceeds with alert, fail-closed throws OcspError", async () => {
    const failing = async (): Promise<Buffer> => {
      throw new Error("responder down");
    };
    const open = testMonitor();
    await open.monitor.checkPeer(
      fakeTlsSocket(LEAF_DER),
      endpoint,
      cfg({ useStapled: false, responderUrl: RESPONDER_URL, responderFetcher: failing, mode: "fail-open" })
    );
    assert.equal(open.alerts.length, 1);
    assert.equal(open.alerts[0].kind, "ocsp_unavailable");
    assert.equal(open.alerts[0].outcome, "proceeded");
    assert.match(open.alerts[0].detail, /responder down/);

    const closed = testMonitor();
    const err = await closed.monitor
      .checkPeer(
        fakeTlsSocket(LEAF_DER),
        endpoint,
        cfg({ useStapled: false, responderUrl: RESPONDER_URL, responderFetcher: failing, mode: "fail-closed" })
      )
      .then(() => null, (e: unknown) => e);
    assert.ok(err instanceof OcspError);
    assert.equal(closed.alerts[0].outcome, "rejected");
  });

  it("responder 'unknown' verdict follows the mode", async () => {
    const unknownFetcher = async () => buildOcspResponse(certId, "unknown");
    const open = testMonitor();
    await open.monitor.checkPeer(
      fakeTlsSocket(LEAF_DER),
      endpoint,
      cfg({ useStapled: false, responderUrl: RESPONDER_URL, responderFetcher: unknownFetcher })
    );
    assert.equal(open.alerts.length, 1);
    assert.match(open.alerts[0].detail, /"unknown"/);

    const closed = testMonitor();
    const err = await closed.monitor
      .checkPeer(
        fakeTlsSocket(LEAF_DER),
        endpoint,
        cfg({ useStapled: false, responderUrl: RESPONDER_URL, responderFetcher: unknownFetcher, mode: "fail-closed" })
      )
      .then(() => null, (e: unknown) => e);
    assert.ok(err instanceof OcspError);
  });

  it("a throwing hook never downgrades the verdict", async () => {
    const monitor = new OcspMonitor({
      onRevoked: () => {
        throw new Error("audit sink down");
      },
      onAlert: () => {
        throw new Error("alert sink down");
      },
    });
    const socket = fakeTlsSocket(LEAF_DER, buildOcspResponse(certId, "revoked"));
    const err = await monitor
      .checkPeer(socket, endpoint, cfg({ mode: "fail-closed" }))
      .then(() => null, (e: unknown) => e);
    assert.ok(err instanceof OcspRevokedError);
  });
});

describe("ocsp: real handshake through createDefaultSender", () => {
  let https: HttpsServer;
  let port: number;
  let requests: number;
  const certId = certIdForLeaf(LEAF_DER);

  before(async () => {
    requests = 0;
    https = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
      (_req, res) => {
        requests++;
        res.writeHead(200).end("ok");
      }
    );
    await new Promise<void>((resolve) => https.listen(0, "127.0.0.1", resolve));
    const addr = https.address();
    assert.ok(addr && typeof addr === "object");
    port = addr.port;
  });

  after(() => https.close());

  // createDefaultSender positional args: pins, keepAlive, outboundSigning,
  // proxies, tlsClientCerts, compressOutbound, http2, idempotencyKey,
  // websocket, outboundEncryption, tlsSniOverrides, responseCompression,
  // forwardHeaders, certExpiryMonitor, minTlsVersions, tlsVersionMonitor,
  // compressThreshold, onGzipFallback, onE2eeKeyRotated,
  // tlsClientCertRotation, dnsCache, measureLatencyPhases, traceContext,
  // tlsOcsp, ocspMonitor.
  function makeSender(
    url: string,
    tlsOcsp: Record<string, Parameters<typeof resolveOcspEndpointOptions>[0]>,
    monitor?: OcspMonitor
  ): ReturnType<typeof createDefaultSender> {
    const pins = { [url]: [TLS_FIXTURE_SPKI_PIN] };
    const u = undefined;
    return createDefaultSender(
      pins, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u,
      tlsOcsp,
      monitor
    );
  }

  it("revoked: rejects with OcspRevokedError, zero payload bytes reach the server", async () => {
    const url = `https://127.0.0.1:${port}/revoked`;
    const { monitor, revoked, alerts } = testMonitor();
    const seen: string[] = [];
    const sender = makeSender(
      url,
      {
        [url]: {
          mode: "fail-closed",
          responderUrl: RESPONDER_URL,
          responderFetcher: async (fetchUrl) => {
            seen.push(fetchUrl);
            return buildOcspResponse(certId, "revoked");
          },
        },
      },
      monitor
    );
    const before = requests;
    const err = await sender({ id: "o1", payload: BODY, targetUrl: url, headers: {} }).then(
      () => null,
      (e: unknown) => e
    );
    // Second delivery: the revoked peer fails again (never verified).
    const err2 = await sender({ id: "o2", payload: BODY, targetUrl: url, headers: {} }).then(
      () => null,
      (e: unknown) => e
    );
    sender.destroy();
    assert.ok(err instanceof OcspRevokedError, `expected OcspRevokedError, got ${err}`);
    assert.ok(err2 instanceof OcspRevokedError);
    assert.equal(requests, before, "revoked peer must never see a request (zero payload bytes)");
    assert.deepEqual(seen, [RESPONDER_URL, RESPONDER_URL]);
    assert.equal(revoked.length, 2);
    assert.equal(revoked[0].event, "ocsp_revoked");
    assert.equal(revoked[0].endpoint, url);
    assert.equal(revoked[0].source, "responder");
    assert.equal(alerts.length, 2);
    assert.equal(alerts[0].kind, "revoked");
    assert.match(monitor.render(), new RegExp(`relay_ocsp_total\\{endpoint="${url.replace(/\//g, "\\/")}",status="revoked"\\} 2`));
  });

  it("fail-open on responder failure: delivery proceeds after the alert", async () => {
    const url = `https://127.0.0.1:${port}/failopen`;
    const { monitor, alerts } = testMonitor();
    const sender = makeSender(
      url,
      {
        [url]: {
          mode: "fail-open",
          responderUrl: RESPONDER_URL,
          responderFetcher: async () => {
            throw new Error("responder down");
          },
        },
      },
      monitor
    );
    const before = requests;
    const res = await sender({ id: "o3", payload: BODY, targetUrl: url, headers: {} });
    sender.destroy();
    assert.equal((res as { statusCode: number }).statusCode, 200);
    assert.equal(requests, before + 1);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].kind, "ocsp_unavailable");
    assert.equal(alerts[0].outcome, "proceeded");
    assert.match(monitor.render(), /status="error"\} 1/);
  });

  it("fail-closed on responder failure: attempt fails with OcspError", async () => {
    const url = `https://127.0.0.1:${port}/failclosed`;
    const { monitor, alerts } = testMonitor();
    const sender = makeSender(
      url,
      {
        [url]: {
          mode: "fail-closed",
          responderUrl: RESPONDER_URL,
          responderFetcher: async () => {
            throw new Error("responder down");
          },
        },
      },
      monitor
    );
    const before = requests;
    const err = await sender({ id: "o4", payload: BODY, targetUrl: url, headers: {} }).then(
      () => null,
      (e: unknown) => e
    );
    sender.destroy();
    assert.ok(err instanceof OcspError, `expected OcspError, got ${err}`);
    assert.ok(!(err instanceof OcspRevokedError));
    assert.equal(requests, before, "fail-closed query failure must not send the payload");
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].outcome, "rejected");
  });

  it("pooled TLS session: the check runs on session establishment, reuse skips it", async () => {
    const url = `https://127.0.0.1:${port}/pooled`;
    const { monitor } = testMonitor();
    let fetches = 0;
    const sender = makeSender(
      url,
      {
        [url]: {
          mode: "fail-open",
          responderUrl: RESPONDER_URL,
          responderFetcher: async () => {
            fetches++;
            return buildOcspResponse(certId, "good");
          },
        },
      },
      monitor
    );
    const r1 = await sender({ id: "o5", payload: BODY, targetUrl: url, headers: {} });
    const r2 = await sender({ id: "o6", payload: BODY, targetUrl: url, headers: {} });
    // The pool really reused the connection (created once).
    const stats = sender.pool?.getStats();
    sender.destroy();
    assert.equal((r1 as { statusCode: number }).statusCode, 200);
    assert.equal((r2 as { statusCode: number }).statusCode, 200);
    assert.equal(fetches, 1, "second delivery must reuse the verified pooled session");
    assert.ok(
      (stats?.reused ?? 0) >= 1,
      `expected pooled reuse, got ${JSON.stringify(stats)}`
    );
    assert.match(monitor.render(), /status="good"\} 1/);
  });

  it("tlsOcsp without an explicit monitor still gates (auto-created inert monitor)", async () => {
    const url = `https://127.0.0.1:${port}/automon`;
    const sender = makeSender(url, {
      [url]: {
        mode: "fail-closed",
        responderUrl: RESPONDER_URL,
        responderFetcher: async () => buildOcspResponse(certId, "revoked"),
      },
    });
    const err = await sender({ id: "o7", payload: BODY, targetUrl: url, headers: {} }).then(
      () => null,
      (e: unknown) => e
    );
    sender.destroy();
    assert.ok(err instanceof OcspRevokedError);
  });

  it("endpoints without a tlsOcsp entry behave exactly as before", async () => {
    const url = `https://127.0.0.1:${port}/plain`;
    const sender = makeSender(url, {});
    const before = requests;
    const res = await sender({ id: "o8", payload: BODY, targetUrl: url, headers: {} });
    sender.destroy();
    assert.equal((res as { statusCode: number }).statusCode, 200);
    assert.equal(requests, before + 1);
  });
});

describe("ocsp: relay server integration", () => {
  let https: HttpsServer;
  let relay: ReturnType<typeof createRelayServer>;
  let relayPort: number;
  let audit: AuditLog;
  let forwardUrl: string;
  const OPERATOR = "op-ocsp-token";
  const certId = certIdForLeaf(LEAF_DER);

  async function postEvent(): Promise<number> {
    const sig = signSha256(BODY, TEST_KEY);
    return new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        { host: "127.0.0.1", port: relayPort, path: "/", method: "POST" },
        (res) => resolve(res.statusCode ?? 0)
      );
      req.on("error", reject);
      req.setHeader("x-signature", sig);
      req.setHeader("content-type", "application/json");
      req.end(BODY);
    });
  }

  async function waitForAudit(event: string): Promise<Array<Record<string, unknown>>> {
    const deadline = Date.now() + 8000;
    for (;;) {
      const events = audit.readAll() as Array<Record<string, unknown>>;
      if (events.some((e) => e.event === event)) return events;
      if (Date.now() > deadline) throw new Error(`timed out waiting for audit event ${event}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  async function getMetrics(): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port: relayPort,
          path: "/metrics",
          method: "GET",
          headers: { authorization: `Bearer ${OPERATOR}` },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => resolve(Buffer.concat(chunks).toString()));
        }
      );
      req.on("error", reject);
      req.end();
    });
  }

  function startRelay(
    tlsOcsp: Record<string, Parameters<typeof resolveOcspEndpointOptions>[0]>
  ): void {
    const dir = mkdtempSync(join(tmpdir(), "audit-ocsp-"));
    audit = new AuditLog(join(dir, "audit.jsonl"));
    relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl,
      auditLog: audit,
      operatorToken: OPERATOR,
      retry: {
        baseDelayMs: 5,
        maxDelayMs: 10,
        maxAttempts: 1,
        circuitBreaker: { failureThreshold: 1, cooldownMs: 60000 },
      },
      tlsPins: { [forwardUrl]: [TLS_FIXTURE_SPKI_PIN] },
      tlsOcsp,
    });
  }

  before(async () => {
    https = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
      (_req, res) => res.writeHead(200).end("ok")
    );
    await new Promise<void>((resolve) => https.listen(0, "127.0.0.1", resolve));
    const addr = https.address();
    assert.ok(addr && typeof addr === "object");
    forwardUrl = `https://127.0.0.1:${addr.port}/hook`;
  });

  after(() => {
    // Each test closes its own relay in `finally`; this is only a
    // backstop for a test that failed before reaching it.
    try {
      const r = relay as unknown as { listening?: boolean; close?: () => void } | undefined;
      if (r?.listening === true) r.close?.();
    } catch {
      // Already closed — nothing to do.
    }
    https.close();
  });

  it("OCSP query failure does NOT trip the circuit breaker (fail-closed)", async () => {
    startRelay({
      [forwardUrl]: {
        mode: "fail-closed",
        responderUrl: RESPONDER_URL,
        responderFetcher: async () => {
          throw new Error("responder down");
        },
      },
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const raddr = relay.address();
    assert.ok(raddr && typeof raddr === "object");
    relayPort = raddr.port;
    try {
      assert.equal(await postEvent(), 202);
      const events = await waitForAudit("dead_letter");
      const dead = events.filter((e) => e.event === "dead_letter");
      assert.equal(dead.length, 1);
      const alert = events.find((e) => e.event === "ocsp_alert");
      assert.ok(alert, "expected an ocsp_alert audit event");
      assert.equal(alert.kind, "ocsp_unavailable");
      assert.equal(alert.outcome, "rejected");
      const metrics = await getMetrics();
      // The breaker never saw this failure: no circuit state series.
      assert.ok(
        !metrics.includes("relay_endpoint_circuit_state"),
        "OCSP query failure must not be recorded as a breaker failure"
      );
      assert.match(metrics, /relay_ocsp_total\{endpoint="https:\/\/127\.0\.0\.1:\d+\/hook",status="error"\} 1/);
    } finally {
      relay.close();
    }
  });

  it("revocation DOES trip the circuit breaker (fail-closed)", async () => {
    startRelay({
      [forwardUrl]: {
        mode: "fail-closed",
        responderUrl: RESPONDER_URL,
        responderFetcher: async () => buildOcspResponse(certId, "revoked"),
      },
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const raddr = relay.address();
    assert.ok(raddr && typeof raddr === "object");
    relayPort = raddr.port;
    try {
      assert.equal(await postEvent(), 202);
      const events = await waitForAudit("dead_letter");
      const revokedEvents = events.filter((e) => e.event === "ocsp_revoked");
      assert.equal(revokedEvents.length, 1);
      assert.equal(revokedEvents[0].endpoint, forwardUrl);
      const metrics = await getMetrics();
      // A revoked certificate is a real endpoint failure: the breaker
      // recorded it and tripped open (2).
      assert.match(
        metrics,
        /relay_endpoint_circuit_state\{endpoint="https:\/\/127\.0\.0\.1:\d+\/hook"\} 2/
      );
      assert.match(metrics, /relay_ocsp_total\{endpoint="https:\/\/127\.0\.0\.1:\d+\/hook",status="revoked"\} 1/);
    } finally {
      relay.close();
    }
  });
});
