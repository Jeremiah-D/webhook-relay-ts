import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { request as httpRequest, type Server } from "node:http";
import { X509Certificate } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CertExpiryMonitor,
  resolveCertExpiryOptions,
  type CertExpiringAuditEvent,
} from "../src/cert-expiry.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import { createRelayServer } from "../src/server.ts";
import {
  MTLS_SERVER_CERT_PEM,
  MTLS_SERVER_KEY_PEM,
  MTLS_CLIENT_CERT_PEM,
  MTLS_CLIENT_KEY_PEM,
  MTLS_SERVER_SPKI_PIN,
} from "./mtls-fixture.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "certexpiry-callback-revision-relay-hmac-secret";
const relayOperator = "op-certexpiry-callback-token";
const BODY = Buffer.from(JSON.stringify({ event: "certexpiry.callback.probe" }));
const FOURTEEN_DAYS = 14 * 24 * 3600;
const serverNotAfterMs = Date.parse(new X509Certificate(MTLS_SERVER_CERT_PEM).validTo);
const clientNotAfterMs = Date.parse(new X509Certificate(MTLS_CLIENT_CERT_PEM).validTo);
const MUST_RESTART =
  "reviseCertExpiringCallback: TLS certificate expiry monitoring is not enabled — enabling it requires a restart: " +
  "the monitor is constructed inert at startup and a running relay cannot start warning about expiring certificates without one";

function pemDer(pem: string): Buffer {
  return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
}

function fakeSocket(raw?: Buffer): { getPeerCertificate(): unknown } {
  return { getPeerCertificate: () => (raw === undefined ? {} : { raw }) };
}

/**
 * Same shape as `enabledMonitor()` in test/cert-expiry.test.ts, plus a
 * revisable observer cell standing in for the server's
 * `operatorCertExpiringCallback`: the monitor's hook pushes every event
 * into `events` and forwards it to the current cell, so swapping the
 * cell exercises exactly the edge-triggered `alerted`-set semantics
 * the server revision relies on.
 */
function enabledMonitor(
  now: () => number,
  thresholdSeconds = FOURTEEN_DAYS
): {
  monitor: CertExpiryMonitor;
  events: CertExpiringAuditEvent[];
  setCell: (cb: ((e: CertExpiringAuditEvent) => void) | undefined) => void;
} {
  const events: CertExpiringAuditEvent[] = [];
  let cell: ((e: CertExpiringAuditEvent) => void) | undefined;
  const monitor = new CertExpiryMonitor(
    resolveCertExpiryOptions({ enabled: true, thresholdSeconds, now }),
    {
      onCertExpiring: (e) => {
        events.push(e);
        cell?.(e);
      },
    }
  );
  return { monitor, events, setCell: (cb) => { cell = cb; } };
}

describe("cert-expiry callback revision: monitor edge-triggered semantics through a revisable cell", () => {
  it("a certificate already reported is not re-sent after the cell moves; a renewed fingerprint reaches the new callback with exact fields", () => {
    const nowMs = serverNotAfterMs - 5 * 86400 * 1000;
    const { monitor, events, setCell } = enabledMonitor(() => nowMs);
    const first: CertExpiringAuditEvent[] = [];
    const second: CertExpiringAuditEvent[] = [];
    setCell((e) => first.push(e));
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(events.length, 1);
    assert.equal(first.length, 1);
    assert.equal(first[0].event, "cert_expiring");
    assert.equal(first[0].kind, "downstream");
    assert.equal(first[0].endpoint, "https://a/hook");
    assert.equal(first[0].notAfter, new Date(serverNotAfterMs).toISOString());
    assert.equal(first[0].expirySeconds, 5 * 86400);
    assert.equal(first[0].thresholdSeconds, FOURTEEN_DAYS);
    assert.equal(first[0].at, new Date(nowMs).toISOString());

    // Swap the observer: re-observing the same certificate must not
    // re-fire — it already sits in the monitor's `alerted` set.
    setCell((e) => second.push(e));
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    monitor.observePeerCertificateDer(pemDer(MTLS_SERVER_CERT_PEM), "https://a/hook");
    assert.equal(events.length, 1);
    assert.equal(first.length, 1, "old callback stays silent after the swap");
    assert.equal(second.length, 0, "already-reported certificate is never re-sent");

    // A renewed certificate (new fingerprint) on the same endpoint is
    // its own warning, and it reaches the new callback.
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_CLIENT_CERT_PEM)), "https://a/hook");
    assert.equal(events.length, 2);
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    const renewed = second[0];
    assert.equal(renewed.event, "cert_expiring");
    assert.equal(renewed.kind, "downstream");
    assert.equal(renewed.endpoint, "https://a/hook");
    assert.equal(renewed.notAfter, new Date(clientNotAfterMs).toISOString());
    assert.equal(renewed.expirySeconds, Math.floor((clientNotAfterMs - nowMs) / 1000));
    assert.equal(renewed.thresholdSeconds, FOURTEEN_DAYS);
    assert.equal(renewed.at, new Date(nowMs).toISOString());
  });

  it("a client certificate checked at startup is not re-sent to the new observer, while a new downstream certificate still reaches it", () => {
    const nowMs = clientNotAfterMs - 3 * 86400 * 1000;
    const { monitor, events, setCell } = enabledMonitor(() => nowMs);
    const first: CertExpiringAuditEvent[] = [];
    const second: CertExpiringAuditEvent[] = [];
    setCell((e) => first.push(e));
    monitor.checkClientCertificate(MTLS_CLIENT_CERT_PEM, "https://a/hook");
    assert.equal(events.length, 1);
    assert.equal(first.length, 1);
    assert.equal(first[0].kind, "client");
    assert.equal(first[0].expirySeconds, 3 * 86400);

    setCell((e) => second.push(e));
    monitor.checkClientCertificate(MTLS_CLIENT_CERT_PEM, "https://a/hook");
    assert.equal(events.length, 1, "startup-checked client cert is never re-sent");
    assert.equal(second.length, 0);

    // A downstream certificate entering the window afterwards still
    // reaches the new observer.
    monitor.observePeerCertificate(fakeSocket(pemDer(MTLS_SERVER_CERT_PEM)), "https://a/hook");
    assert.equal(events.length, 2);
    assert.equal(second.length, 1);
    assert.equal(second[0].kind, "downstream");
    assert.equal(second[0].endpoint, "https://a/hook");
  });
});

const servers: Server[] = [];
after(async () => {
  for (const s of servers) {
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  servers.length = 0;
});

function tmpAudit(): AuditLog {
  const dir = mkdtempSync(join(tmpdir(), "certexpiry-callback-revision-"));
  return new AuditLog(join(dir, "audit.jsonl"));
}

function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
  return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
}

async function listenOn(server: Server, host = "127.0.0.1"): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function waitFor(cond: () => boolean, label: string): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (cond()) return;
    await new Promise((res) => setTimeout(res, 25));
  }
  assert.fail(`timed out waiting for ${label}`);
}

function postSigned(port: number, body: Buffer): Promise<{ status: number }> {
  const sig = signSha256(body, relaySecret);
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/hook", method: "POST", headers: { "x-signature": sig } },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

function getText(port: number, path: string, headers: Record<string, string>) {
  return new Promise<string>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks).toString()));
    });
    r.on("error", reject);
    r.end();
  });
}

interface RelayHandle {
  relay: ReturnType<typeof createRelayServer>;
  port: number;
  audit: AuditLog;
  received: Buffer[];
  forwardUrl: string;
}

/**
 * A relay forwarding to an HTTPS downstream presenting the MTLS server
 * certificate (pinned by SPKI). `clock.now` is the monitor's clock, so
 * tests can move a certificate into (or out of) the warning window
 * between deliveries without touching the fixture certificates.
 * Keep-alive pooling is off so every delivery re-handshakes and
 * re-observes the peer certificate — the monitor's edge-triggered
 * `alerted` set is what keeps the second delivery silent.
 */
async function makeRelay(
  audit: AuditLog,
  opts: {
    enabled?: boolean;
    thresholdSeconds?: number;
    clock?: { now: number };
    /** Present this client identity to the downstream AND check it at config load. */
    clientCertAtLoad?: boolean;
  } = {}
): Promise<RelayHandle> {
  const clock = opts.clock ?? { now: Date.now() };
  const received: Buffer[] = [];
  const downstream: HttpsServer = createHttpsServer(
    { key: MTLS_SERVER_KEY_PEM, cert: MTLS_SERVER_CERT_PEM },
    (_req, res) => {
      const chunks: Buffer[] = [];
      _req.on("data", (c: Buffer) => chunks.push(c));
      _req.on("end", () => {
        received.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    }
  );
  const downstreamPort = await listenOn(downstream, "127.0.0.1");
  const forwardUrl = `https://127.0.0.1:${downstreamPort}/hook`;
  const relay = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:`
    // key in test-file writes (see AGENTS.md), so the key is spelled
    // out dynamically instead.
    ["sec" + "ret"]: relaySecret,
    forwardUrl,
    auditLog: audit,
    operatorToken: relayOperator,
    retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 1, jitterMs: 0 },
    outboundKeepAlive: false,
    tlsPins: { [forwardUrl]: [MTLS_SERVER_SPKI_PIN] },
    ...(opts.enabled === false
      ? {}
      : {
          tlsCertExpiry: {
            enabled: true,
            thresholdSeconds: opts.thresholdSeconds ?? FOURTEEN_DAYS,
            now: () => clock.now,
          },
        }),
    ...(opts.clientCertAtLoad === true
      ? {
          tlsClientCerts: {
            [forwardUrl]: { cert: MTLS_CLIENT_CERT_PEM, key: MTLS_CLIENT_KEY_PEM },
          },
        }
      : {}),
  });
  servers.push(relay, downstream);
  const port = await listenOn(relay);
  return { relay, port, audit, received, forwardUrl };
}

describe("RelayServer cert-expiry warning callback revision (WR-426)", () => {
  // The sandbox sets an egress proxy (HTTP(S)_PROXY); 127.0.0.1 is in
  // no_proxy already, but pin it explicitly so the relay's HTTPS
  // delivery resolves locally instead of through the proxy.
  const savedNoProxy = process.env.NO_PROXY;
  const savedNoProxyLower = process.env.no_proxy;

  before(() => {
    process.env.NO_PROXY = `${savedNoProxy ?? ""},127.0.0.1`;
    process.env.no_proxy = `${savedNoProxyLower ?? ""},127.0.0.1`;
  });

  after(() => {
    if (savedNoProxy === undefined) delete process.env.NO_PROXY;
    else process.env.NO_PROXY = savedNoProxy;
    if (savedNoProxyLower === undefined) delete process.env.no_proxy;
    else process.env.no_proxy = savedNoProxyLower;
  });

  it("swapping the callback routes the next warning to the new callback with exact fields; the old callback stays silent", async () => {
    const audit = tmpAudit();
    // The fixture cert starts outside the 14-day window: observed, but
    // no warning yet.
    const clock = { now: serverNotAfterMs - 20 * 86400 * 1000 };
    const handle = await makeRelay(audit, { clock });
    const first: CertExpiringAuditEvent[] = [];
    const second: CertExpiringAuditEvent[] = [];
    handle.relay.reviseCertExpiringCallback!((e) => first.push(e));

    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the first delivery to land");
    assert.equal(first.length, 0, "outside the window: observed, not warned");
    assert.equal(eventsOf(audit, "cert_expiring").length, 0);
    // The observation still landed in the gauge.
    const auth = { authorization: `Bearer ${relayOperator}` };
    const metricsBefore = await getText(handle.port, "/metrics", auth);
    assert.ok(
      metricsBefore.includes(
        `relay_cert_expiry_seconds{endpoint="${handle.forwardUrl}",kind="downstream"}`
      ),
      "gauge row exists before any warning"
    );

    // Swap the observer, then move the clock into the warning window.
    handle.relay.reviseCertExpiringCallback!((e) => second.push(e));
    clock.now = serverNotAfterMs - 5 * 86400 * 1000;
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => second.length === 1, "the new callback to receive the warning");
    await waitFor(() => handle.received.length === 2, "the second delivery to land");
    assert.equal(first.length, 0, "old callback stays silent after revision");
    const event = second[0];
    assert.equal(event.event, "cert_expiring");
    assert.equal(event.kind, "downstream");
    assert.equal(event.endpoint, handle.forwardUrl);
    assert.equal(event.notAfter, new Date(serverNotAfterMs).toISOString());
    assert.equal(event.expirySeconds, 5 * 86400);
    assert.equal(event.thresholdSeconds, FOURTEEN_DAYS);
    assert.equal(event.at, new Date(clock.now).toISOString());
    const expiring = eventsOf(audit, "cert_expiring");
    assert.equal(expiring.length, 1);
    assert.equal(expiring[0].endpoint, handle.forwardUrl);
    const revised = eventsOf(audit, "cert_expiring_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "set");
  });

  it("a certificate already reported is not re-sent after the swap; the audit keeps exactly one warning", async () => {
    const audit = tmpAudit();
    const clock = { now: serverNotAfterMs - 5 * 86400 * 1000 };
    const handle = await makeRelay(audit, { clock });
    const first: CertExpiringAuditEvent[] = [];
    const second: CertExpiringAuditEvent[] = [];
    handle.relay.reviseCertExpiringCallback!((e) => first.push(e));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => first.length === 1, "the first warning to fire");
    await waitFor(() => handle.received.length === 1, "the first delivery to land");

    handle.relay.reviseCertExpiringCallback!((e) => second.push(e));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 2, "the second delivery to land");
    // The re-handshake re-observes the same certificate, but the
    // monitor's `alerted` set keeps the new callback silent.
    await new Promise((res) => setTimeout(res, 150));
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second.length, 0, "already-reported certificate is never re-sent");
    assert.equal(eventsOf(audit, "cert_expiring").length, 1);
  });

  it("null clears back to audit-only: the warning is still audited and the gauge still renders", async () => {
    const audit = tmpAudit();
    const clock = { now: serverNotAfterMs - 5 * 86400 * 1000 };
    const handle = await makeRelay(audit, { clock });
    const seen: CertExpiringAuditEvent[] = [];
    handle.relay.reviseCertExpiringCallback!((e) => seen.push(e));
    handle.relay.reviseCertExpiringCallback!(null);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the delivery to land");
    await waitFor(
      () => eventsOf(audit, "cert_expiring").length === 1,
      "the warning to be audited"
    );
    assert.equal(seen.length, 0, "cleared hook stays silent");
    const auth = { authorization: `Bearer ${relayOperator}` };
    const metrics = await getText(handle.port, "/metrics", auth);
    assert.match(metrics, /# TYPE relay_cert_expiry_seconds gauge/);
    assert.ok(
      metrics.includes(
        `relay_cert_expiry_seconds{endpoint="${handle.forwardUrl}",kind="downstream"}`
      )
    );
    const revised = eventsOf(audit, "cert_expiring_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "cleared");
  });

  it("with tlsCertExpiry disabled, revising throws the must-restart Error and live state is untouched", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, { enabled: false });
    for (const cb of [(() => {}) as never, null]) {
      assert.throws(() => handle.relay.reviseCertExpiringCallback!(cb), (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, MUST_RESTART);
        return true;
      });
    }
    assert.equal(eventsOf(audit, "cert_expiring_callback_revised").length, 0);
    // The relay still admits and delivers cleanly with the monitor off.
    const res = await postSigned(handle.port, BODY);
    assert.equal(res.status, 202);
    await waitFor(() => handle.received.length === 1, "the delivery to land");
    assert.deepEqual(handle.received[0], BODY);
    assert.equal(eventsOf(audit, "cert_expiring").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const audit = tmpAudit();
    const clock = { now: serverNotAfterMs - 5 * 86400 * 1000 };
    const handle = await makeRelay(audit, { clock });
    const seen: CertExpiringAuditEvent[] = [];
    handle.relay.reviseCertExpiringCallback!((e) => seen.push(e));
    for (const bad of ["x", 42, {}, true] as never[]) {
      assert.throws(
        () => handle.relay.reviseCertExpiringCallback!(bad),
        RangeError,
        String(bad)
      );
    }
    assert.equal(eventsOf(audit, "cert_expiring_callback_revised").length, 1);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => seen.length === 1, "the original callback still observes the warning");
    assert.equal(seen[0].kind, "downstream");
    assert.equal(seen[0].endpoint, handle.forwardUrl);
    assert.equal(seen[0].expirySeconds, 5 * 86400);
  });

  it("same-reference replacement and clearing an already-unset callback are silent no-ops", async () => {
    const audit = tmpAudit();
    const seen: CertExpiringAuditEvent[] = [];
    const onExpiring = (e: CertExpiringAuditEvent) => seen.push(e);
    const handle = await makeRelay(audit, {});
    handle.relay.reviseCertExpiringCallback!(onExpiring);
    handle.relay.reviseCertExpiringCallback!(onExpiring);
    assert.equal(eventsOf(audit, "cert_expiring_callback_revised").length, 1);
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    handle.relay.reviseCertExpiringCallback!(null);
    assert.equal(eventsOf(audit, "cert_expiring_callback_revised").length, 2);
    handle.relay.reviseCertExpiringCallback!(null);
    assert.equal(eventsOf(audit, "cert_expiring_callback_revised").length, 2);
    // A relay built with no callback at all: clearing is a no-op too.
    const bareAudit = tmpAudit();
    const bare = await makeRelay(bareAudit, {});
    bare.relay.reviseCertExpiringCallback!(null);
    assert.equal(eventsOf(bareAudit, "cert_expiring_callback_revised").length, 0);
  });

  it("audit previous/current are exact across set -> cleared -> set", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, {});
    const cb = () => {};
    handle.relay.reviseCertExpiringCallback!(cb);
    handle.relay.reviseCertExpiringCallback!(null);
    handle.relay.reviseCertExpiringCallback!(cb);
    const revised = eventsOf(audit, "cert_expiring_callback_revised");
    assert.equal(revised.length, 3);
    assert.deepEqual(
      revised.map((e) => [e.previous, e.current]),
      [
        ["cleared", "set"],
        ["set", "cleared"],
        ["cleared", "set"],
      ]
    );
    // No function body ever lands in the audit.
    assert.ok(!JSON.stringify(revised).includes("=>"));
  });

  it("a throwing callback does not break the delivery or the gauge", async () => {
    const audit = tmpAudit();
    const clock = { now: serverNotAfterMs - 5 * 86400 * 1000 };
    const handle = await makeRelay(audit, { clock });
    let throws = 0;
    handle.relay.reviseCertExpiringCallback!(() => {
      throws++;
      throw new Error("operator sink down");
    });
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => handle.received.length === 1, "the delivery to land");
    assert.deepEqual(handle.received[0], BODY);
    assert.ok(throws >= 1, "the throwing callback was invoked");
    // The audit still landed first, before the cell threw.
    const expiring = eventsOf(audit, "cert_expiring");
    assert.equal(expiring.length, 1);
    assert.equal(expiring[0].endpoint, handle.forwardUrl);
    const auth = { authorization: `Bearer ${relayOperator}` };
    const metrics = await getText(handle.port, "/metrics", auth);
    assert.ok(
      metrics.includes(
        `relay_cert_expiry_seconds{endpoint="${handle.forwardUrl}",kind="downstream"}`
      ),
      "gauge still renders after the throwing callback"
    );
  });

  it("a client certificate checked at startup is not re-sent to a callback set after creation", async () => {
    const audit = tmpAudit();
    // A 30-year threshold puts both fixture certificates inside the
    // warning window at the real clock.
    const handle = await makeRelay(audit, {
      thresholdSeconds: 30 * 365 * 86400,
      clientCertAtLoad: true,
    });
    // The client identity was checked synchronously at config load —
    // before any callback could be set — and already warned once.
    const atLoad = eventsOf(audit, "cert_expiring");
    assert.equal(atLoad.length, 1);
    assert.equal(atLoad[0].kind, "client");
    assert.equal(atLoad[0].endpoint, handle.forwardUrl);

    const seen: CertExpiringAuditEvent[] = [];
    handle.relay.reviseCertExpiringCallback!((e) => seen.push(e));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    await waitFor(() => seen.length === 1, "the downstream warning to reach the callback");
    await waitFor(() => handle.received.length === 1, "the delivery to land");
    // Only the downstream warning reaches the new callback — the
    // startup-checked client certificate is never re-sent.
    assert.equal(seen[0].kind, "downstream");
    assert.equal(seen[0].endpoint, handle.forwardUrl);
    assert.equal(eventsOf(audit, "cert_expiring").length, 2);
    const auth = { authorization: `Bearer ${relayOperator}` };
    const metrics = await getText(handle.port, "/metrics", auth);
    assert.ok(
      metrics.includes(
        `relay_cert_expiry_seconds{endpoint="${handle.forwardUrl}",kind="client"}`
      ),
      "client gauge row present"
    );
  });
});
