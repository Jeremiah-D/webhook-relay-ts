import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { X509Certificate } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CertExpiryMonitor,
  resolveCertExpiryOptions,
  DEFAULT_CERT_EXPIRY_THRESHOLD_SECONDS,
  type CertExpiringAuditEvent,
} from "../src/cert-expiry.ts";
import { renderPrometheus } from "../src/metrics.ts";
import { createRelayServer, createDefaultSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { request as httpRequest } from "node:http";
import {
  MTLS_SERVER_CERT_PEM,
  MTLS_SERVER_KEY_PEM,
  MTLS_CLIENT_CERT_PEM,
  MTLS_CLIENT_KEY_PEM,
  MTLS_SERVER_SPKI_PIN,
} from "./mtls-fixture.ts";

const TEST_KEY = "certexpiry-secret";
const BODY = Buffer.from(JSON.stringify({ event: "certexpiry.probe" }));
const FOURTEEN_DAYS = 14 * 24 * 3600;

function pemDer(pem: string): Buffer {
  return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
}

function fakeSocket(raw?: Buffer): { getPeerCertificate(): unknown } {
  return { getPeerCertificate: () => (raw === undefined ? {} : { raw }) };
}

function enabledMonitor(
  now: () => number,
  thresholdSeconds = FOURTEEN_DAYS
): { monitor: CertExpiryMonitor; events: CertExpiringAuditEvent[] } {
  const events: CertExpiringAuditEvent[] = [];
  const monitor = new CertExpiryMonitor(
    resolveCertExpiryOptions({ enabled: true, thresholdSeconds, now }),
    { onCertExpiring: (e) => events.push(e) }
  );
  return { monitor, events };
}

describe("cert-expiry: option validation", () => {
  it("defaults to disabled with a 14-day threshold", () => {
    const resolved = resolveCertExpiryOptions();
    assert.equal(resolved.enabled, false);
    assert.equal(resolved.thresholdSeconds, DEFAULT_CERT_EXPIRY_THRESHOLD_SECONDS);
    assert.equal(resolved.thresholdSeconds, FOURTEEN_DAYS);
  });

  it("accepts enabled + custom threshold", () => {
    const resolved = resolveCertExpiryOptions({ enabled: true, thresholdSeconds: 3600 });
    assert.equal(resolved.enabled, true);
    assert.equal(resolved.thresholdSeconds, 3600);
  });

  it("rejects invalid values", () => {
    assert.throws(() => resolveCertExpiryOptions({ enabled: "yes" as never }), RangeError);
    assert.throws(() => resolveCertExpiryOptions({ thresholdSeconds: -1 }), RangeError);
    assert.throws(() => resolveCertExpiryOptions({ thresholdSeconds: NaN }), RangeError);
    assert.throws(() => resolveCertExpiryOptions({ thresholdSeconds: Infinity }), RangeError);
    assert.throws(() => resolveCertExpiryOptions({ thresholdSeconds: "x" as never }), RangeError);
    assert.throws(() => resolveCertExpiryOptions({ now: 42 as never }), RangeError);
  });

  it("createDefaultSender rejects an invalid tlsCertExpiry at startup via the monitor", () => {
    assert.throws(
      () => resolveCertExpiryOptions({ enabled: true, thresholdSeconds: -5 }),
      /thresholdSeconds/
    );
  });
});

describe("cert-expiry: disabled monitor is inert", () => {
  it("observations are no-ops: no events, no series, empty render", () => {
    const events: CertExpiringAuditEvent[] = [];
    const monitor = new CertExpiryMonitor(resolveCertExpiryOptions(), {
      onCertExpiring: (e) => events.push(e),
    });
    assert.equal(monitor.enabled, false);
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://x/hook");
    monitor.observePeerCertificateDer(pemDer(MTLS_SERVER_CERT_PEM), "https://x/hook");
    monitor.checkClientCertificate(MTLS_CLIENT_CERT_PEM, "https://x/hook");
    assert.equal(events.length, 0);
    assert.deepEqual(monitor.series(), []);
    assert.equal(monitor.render(), "");
  });
});

describe("cert-expiry: handshake observation and gauge", () => {
  it("records the peer certificate's expiry as a gauge row, no alert when far from expiry", () => {
    const { monitor, events } = enabledMonitor(() => Date.now());
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(events.length, 0);
    const series = monitor.series();
    assert.equal(series.length, 1);
    assert.equal(series[0].endpoint, "https://a/hook");
    assert.equal(series[0].kind, "downstream");
    // The fixture cert is valid for 10 years; the countdown must be huge.
    assert.ok(series[0].expirySeconds > 5 * 365 * 86400, `got ${series[0].expirySeconds}`);
    const text = monitor.render();
    assert.match(text, /# HELP relay_cert_expiry_seconds/);
    assert.match(text, /# TYPE relay_cert_expiry_seconds gauge/);
    assert.match(
      text,
      /relay_cert_expiry_seconds\{endpoint="https:\/\/a\/hook",kind="downstream"\} \d+/
    );
  });

  it("skips empty peer certificates (resumed TLS 1.3 sessions) without crashing", () => {
    const { monitor, events } = enabledMonitor(() => Date.now());
    monitor.observePeerCertificate(fakeSocket(), "https://a/hook");
    monitor.observePeerCertificate(
      { getPeerCertificate: () => { throw new Error("boom"); } },
      "https://a/hook"
    );
    monitor.observePeerCertificateDer(Buffer.from("not-a-cert"), "https://a/hook");
    assert.equal(events.length, 0);
    assert.deepEqual(monitor.series(), []);
    assert.equal(monitor.render(), "");
  });

  it("keeps the latest certificate per endpoint, in first-seen order", () => {
    const { monitor } = enabledMonitor(() => Date.now());
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_CLIENT_CERT_PEM)), "https://b/hook");
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    const endpoints = monitor.series().map((s) => s.endpoint);
    assert.deepEqual(endpoints, ["https://a/hook", "https://b/hook"]);
  });
});

describe("cert-expiry: edge-triggered cert_expiring audit", () => {
  const serverNotAfterMs = Date.parse(new X509Certificate(MTLS_SERVER_CERT_PEM).validTo);

  it("fires once when expiry is within the threshold, with full event fields", () => {
    const nowMs = serverNotAfterMs - 5 * 86400 * 1000;
    const { monitor, events } = enabledMonitor(() => nowMs);
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(events.length, 1);
    const e = events[0];
    assert.equal(e.event, "cert_expiring");
    assert.equal(e.kind, "downstream");
    assert.equal(e.endpoint, "https://a/hook");
    assert.equal(e.notAfter, new Date(serverNotAfterMs).toISOString());
    assert.equal(e.expirySeconds, 5 * 86400);
    assert.equal(e.thresholdSeconds, FOURTEEN_DAYS);
    assert.equal(e.at, new Date(nowMs).toISOString());
    // Re-observing the same certificate (every handshake on a pooled
    // connection) does not re-fire — edge-triggered, not per-handshake.
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    monitor.observePeerCertificateDer(pemDer(MTLS_SERVER_CERT_PEM), "https://a/hook");
    assert.equal(events.length, 1);
  });

  it("fires again for a different (renewed) certificate on the same endpoint", () => {
    const nowMs = serverNotAfterMs - 5 * 86400 * 1000;
    const { monitor, events } = enabledMonitor(() => nowMs);
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(events.length, 1);
    // A renewed certificate has a new fingerprint: its own warning.
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_CLIENT_CERT_PEM)), "https://a/hook");
    assert.equal(events.length, 2);
  });

  it("fires at the exact threshold boundary and for already-expired certificates", () => {
    const { monitor: m1, events: e1 } = enabledMonitor(
      () => serverNotAfterMs - FOURTEEN_DAYS * 1000
    );
    m1.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(e1.length, 1, "expiry == threshold must fire (<=)");

    const { monitor: m2, events: e2 } = enabledMonitor(() => serverNotAfterMs + 1000);
    m2.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(e2.length, 1);
    assert.ok(e2[0].expirySeconds < 0, "already expired: negative countdown");
  });

  it("stays silent outside the threshold; honors a custom threshold", () => {
    const { monitor, events } = enabledMonitor(
      () => serverNotAfterMs - (FOURTEEN_DAYS + 1) * 86400 * 1000
    );
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(events.length, 0);

    const twoHours = 2 * 3600;
    const { monitor: m2, events: e2 } = enabledMonitor(
      () => serverNotAfterMs - twoHours * 1000,
      3600
    );
    m2.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(e2.length, 0, "2h out > 1h threshold: silent");
    const { monitor: m3, events: e3 } = enabledMonitor(
      () => serverNotAfterMs - 30 * 60 * 1000,
      3600
    );
    m3.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(e3.length, 1, "30m out < 1h threshold: fires");
    assert.equal(e3[0].thresholdSeconds, 3600);
  });
});

describe("cert-expiry: relay's own mTLS client certificates", () => {
  const clientNotAfterMs = Date.parse(new X509Certificate(MTLS_CLIENT_CERT_PEM).validTo);

  it("checks the client cert at config load with kind=client", () => {
    const nowMs = clientNotAfterMs - 3 * 86400 * 1000;
    const { monitor, events } = enabledMonitor(() => nowMs);
    monitor.checkClientCertificate(MTLS_CLIENT_CERT_PEM, "https://a/hook");
    assert.equal(events.length, 1);
    const e = events[0];
    assert.equal(e.event, "cert_expiring");
    assert.equal(e.kind, "client");
    assert.equal(e.endpoint, "https://a/hook");
    assert.equal(e.notAfter, new Date(clientNotAfterMs).toISOString());
    assert.equal(e.expirySeconds, 3 * 86400);
    const series = monitor.series();
    assert.equal(series.length, 1);
    assert.equal(series[0].kind, "client");
    assert.match(
      monitor.render(),
      /relay_cert_expiry_seconds\{endpoint="https:\/\/a\/hook",kind="client"\} \d+/
    );
  });

  it("accepts DER input and ignores garbage without throwing", () => {
    const { monitor, events } = enabledMonitor(() => Date.now());
    monitor.checkClientCertificate(pemDer(MTLS_CLIENT_CERT_PEM), "https://a/hook");
    monitor.checkClientCertificate("-----BEGIN CERTIFICATE-----\nbogus\n-----END CERTIFICATE-----", "https://b/hook");
    assert.equal(events.length, 0);
    assert.equal(monitor.series().length, 1);
  });
});

describe("cert-expiry: metrics exposition", () => {
  it("renderPrometheus carries the gauge when certExpiry input is present", () => {
    const text = renderPrometheus({
      deliveries: [],
      circuits: [],
      latencyHistograms: [],
      certExpiry: [
        { endpoint: "https://a/hook", kind: "downstream", expirySeconds: 123 },
        { endpoint: "https://b/hook", kind: "client", expirySeconds: -7 },
      ],
    });
    assert.match(
      text,
      /relay_cert_expiry_seconds\{endpoint="https:\/\/a\/hook",kind="downstream"\} 123/
    );
    assert.match(text, /relay_cert_expiry_seconds\{endpoint="https:\/\/b\/hook",kind="client"\} -7/);
  });

  it("renderPrometheus omits the gauge when certExpiry is absent", () => {
    const text = renderPrometheus({ deliveries: [], circuits: [], latencyHistograms: [] });
    assert.ok(!text.includes("relay_cert_expiry_seconds"));
  });
});

describe("cert-expiry: real handshake through createDefaultSender", () => {
  let https: HttpsServer;
  let port: number;

  before(async () => {
    https = createHttpsServer(
      { key: MTLS_SERVER_KEY_PEM, cert: MTLS_SERVER_CERT_PEM },
      (_req, res) => res.writeHead(200).end("ok")
    );
    await new Promise<void>((resolve) => https.listen(0, "127.0.0.1", resolve));
    const addr = https.address();
    assert.ok(addr && typeof addr === "object");
    port = addr.port;
  });

  after(() => https.close());

  it("captures the peer cert's notAfter on the pinned H1 handshake path", async () => {
    const url = `https://127.0.0.1:${port}/hook`;
    const events: CertExpiringAuditEvent[] = [];
    // Threshold far beyond the fixture's 10-year validity: any real
    // handshake cert lands inside the warning window.
    const monitor = new CertExpiryMonitor(
      resolveCertExpiryOptions({ enabled: true, thresholdSeconds: 30 * 365 * 86400 }),
      { onCertExpiring: (e) => events.push(e) }
    );
    const sender = createDefaultSender(
      { [url]: [MTLS_SERVER_SPKI_PIN] },
      undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined,
      monitor
    );
    await sender({ id: "c1", payload: BODY, targetUrl: url, headers: {} });
    // Second delivery reuses the pooled connection: still exactly one event.
    await sender({ id: "c2", payload: BODY, targetUrl: url, headers: {} });
    sender.destroy();
    assert.equal(events.length, 1);
    assert.equal(events[0].event, "cert_expiring");
    assert.equal(events[0].kind, "downstream");
    assert.equal(events[0].endpoint, url);
    assert.ok(events[0].expirySeconds > 0);
    const series = monitor.series();
    assert.equal(series.length, 1);
    assert.equal(series[0].endpoint, url);
  });

  it("checks mTLS client certs at createDefaultSender config load", () => {
    const events: CertExpiringAuditEvent[] = [];
    const monitor = new CertExpiryMonitor(
      resolveCertExpiryOptions({ enabled: true, thresholdSeconds: 30 * 365 * 86400 }),
      { onCertExpiring: (e) => events.push(e) }
    );
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined,
      { "https://never-dialed/hook": { cert: MTLS_CLIENT_CERT_PEM, key: MTLS_CLIENT_KEY_PEM } },
      undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
      monitor
    );
    sender.destroy();
    assert.equal(events.length, 1);
    assert.equal(events[0].kind, "client");
    assert.equal(events[0].endpoint, "https://never-dialed/hook");
  });
});

describe("cert-expiry: relay server integration", () => {
  let https: HttpsServer;
  let relay: ReturnType<typeof createRelayServer>;
  let relayPort: number;
  let audit: AuditLog;
  const OPERATOR = "op-certexpiry-token";

  before(async () => {
    https = createHttpsServer(
      { key: MTLS_SERVER_KEY_PEM, cert: MTLS_SERVER_CERT_PEM },
      (_req, res) => res.writeHead(200).end("ok")
    );
    await new Promise<void>((resolve) => https.listen(0, "127.0.0.1", resolve));
    const addr = https.address();
    assert.ok(addr && typeof addr === "object");
    const forwardUrl = `https://127.0.0.1:${addr.port}/hook`;
    const dir = mkdtempSync(join(tmpdir(), "audit-certexpiry-"));
    audit = new AuditLog(join(dir, "audit.jsonl"));
    relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl,
      auditLog: audit,
      operatorToken: OPERATOR,
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 1 },
      tlsPins: { [forwardUrl]: [MTLS_SERVER_SPKI_PIN] },
      // Threshold far beyond the fixture's 10-year validity: the real
      // handshake cert lands inside the warning window.
      tlsCertExpiry: { enabled: true, thresholdSeconds: 30 * 365 * 86400 },
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const raddr = relay.address();
    assert.ok(raddr && typeof raddr === "object");
    relayPort = raddr.port;
  });

  after(() => {
    relay.close();
    https.close();
  });

  it("audits cert_expiring and exposes relay_cert_expiry_seconds in /metrics", async () => {
    const sig = signSha256(BODY, TEST_KEY);
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        { host: "127.0.0.1", port: relayPort, path: "/", method: "POST" },
        (res) => resolve(res.statusCode ?? 0)
      );
      req.on("error", reject);
      req.setHeader("x-signature", sig);
      req.setHeader("content-type", "application/json");
      req.end(BODY);
    });
    assert.equal(status, 202);
    // Wait for the delivery (and its handshake) to settle.
    for (let i = 0; i < 100; i++) {
      const found = audit.readAll().some((e) => (e as { event?: string }).event === "cert_expiring");
      if (found) break;
      await new Promise((res) => setTimeout(res, 25));
    }
    const expiring = audit.readAll().filter((e) => (e as { event?: string }).event === "cert_expiring");
    assert.equal(expiring.length, 1);
    assert.equal((expiring[0] as { kind?: string }).kind, "downstream");

    const metrics = await new Promise<string>((resolve, reject) => {
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
    assert.match(metrics, /# TYPE relay_cert_expiry_seconds gauge/);
    assert.match(metrics, /relay_cert_expiry_seconds\{endpoint="https:\/\/127\.0\.0\.1:\d+\/hook",kind="downstream"\} \d+/);
  });
});
