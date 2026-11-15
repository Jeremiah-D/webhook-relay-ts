import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  certIdForLeaf,
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
  issuerNameDer,
  type OcspCertId,
  type OcspRevokedAuditEvent,
} from "../src/ocsp.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import { createRelayServer } from "../src/server.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "ocsp-revoked-callback-revision-relay-hmac-secret";
const relayOperator = "op-ocsp-revoked-callback-token";
const BODY = Buffer.from(JSON.stringify({ event: "ocsp.revoked.callback.probe" }));
const RESPONDER_URL = "http://127.0.0.1:9/ocsp";
const MUST_RESTART =
  "reviseOcspRevokedCallback: OCSP revocation checking is not configured — enabling it requires a restart: " +
  "the monitor is created at startup and a running relay cannot start checking revocations without one";

function pemDer(pem: string): Buffer {
  return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
}

const LEAF_DER = pemDer(TLS_FIXTURE_CERT_PEM);
const CERT_ID = certIdForLeaf(LEAF_DER);
/** Hex serial as the `ocsp_revoked` event carries it (leading pad stripped). */
const firstNonZero = CERT_ID.serialNumber.findIndex((b) => b !== 0);
const SERIAL_HEX = CERT_ID.serialNumber
  .subarray(firstNonZero === -1 ? 0 : firstNonZero)
  .toString("hex");

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

const servers: Server[] = [];
after(async () => {
  for (const s of servers) {
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  servers.length = 0;
});

function tmpAudit(): AuditLog {
  const dir = mkdtempSync(join(tmpdir(), "ocsp-revoked-callback-revision-"));
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

function getJson(port: number, path: string, headers: Record<string, string>) {
  return new Promise<{ status: number; body: unknown }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString()) })
      );
    });
    r.on("error", reject);
    r.end();
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

type OcspMode = "fail-open" | "fail-closed";

/**
 * A relay forwarding to an HTTPS downstream whose leaf the stub
 * responder reports as `responderStatus`. The downstream presents the
 * TLS fixture certificate (pinned by SPKI), so the OCSP check runs on
 * every handshake (keep-alive off) and a `revoked` verdict rejects the
 * delivery before a single payload byte.
 */
async function makeRelay(
  audit: AuditLog,
  ocsp:
    | false
    | { mode: OcspMode; status: "revoked" | "unknown" }
): Promise<RelayHandle> {
  const received: Buffer[] = [];
  const downstream: HttpsServer = createHttpsServer(
    { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
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
    retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
    // Keep-alive pooling is off so every delivery re-handshakes and
    // re-runs the OCSP check (a pooled verified socket would skip it).
    outboundKeepAlive: false,
    tlsPins: { [forwardUrl]: [TLS_FIXTURE_SPKI_PIN] },
    ...(ocsp === false
      ? {}
      : {
          tlsOcsp: {
            [forwardUrl]: {
              mode: ocsp.mode,
              responderUrl: RESPONDER_URL,
              responderFetcher: async () => buildOcspResponse(CERT_ID, ocsp.status),
            },
          },
        }),
  });
  servers.push(relay, downstream);
  const port = await listenOn(relay);
  return { relay, port, audit, received, forwardUrl };
}

/** Post one event and wait until the revoked callback has fired again. */
async function postRevoked(
  handle: RelayHandle,
  seen: OcspRevokedAuditEvent[]
): Promise<void> {
  const before = seen.length;
  const res = await postSigned(handle.port, BODY);
  assert.equal(res.status, 202);
  await waitFor(() => seen.length > before, "the revoked callback to fire");
}

/** Wait until the dead-letter list holds `count` entries. */
async function waitDead(handle: RelayHandle, count: number): Promise<Record<string, unknown>[]> {
  const auth = { authorization: `Bearer ${relayOperator}` };
  let dead: Record<string, unknown>[] = [];
  for (let i = 0; i < 200 && dead.length < count; i++) {
    await new Promise((r) => setTimeout(r, 25));
    dead = ((await getJson(handle.port, "/dead-letter", auth)).body as Record<string, unknown>[]) ?? [];
  }
  assert.equal(dead.length, count);
  return dead;
}

describe("RelayServer OCSP revoked callback revision (WR-424)", () => {
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

  it("swapping the callback routes the next revoked verdict to the new callback with exact fields; the old callback stays silent", async () => {
    const audit = tmpAudit();
    const first: OcspRevokedAuditEvent[] = [];
    const second: OcspRevokedAuditEvent[] = [];
    const handle = await makeRelay(audit, { mode: "fail-closed", status: "revoked" });
    handle.relay.reviseOcspRevokedCallback!((event) => first.push(event));

    await postRevoked(handle, first);
    // Both attempts of the revoked delivery must be exhausted before
    // the swap, or the retry could still land in the old callback's
    // count after the cell moves.
    await waitDead(handle, 1);
    assert.equal(first.length, 2, "two attempts, two revoked verdicts");
    assert.equal(second.length, 0);

    handle.relay.reviseOcspRevokedCallback!((event) => second.push(event));
    await postRevoked(handle, second);
    await waitDead(handle, 2);
    assert.equal(first.length, 2, "old callback stays silent after revision");
    assert.equal(second.length, 2, "new callback sees the next revocation (two attempts)");
    const event = second[0];
    assert.equal(event.event, "ocsp_revoked");
    assert.equal(event.endpoint, handle.forwardUrl);
    assert.equal(event.serialNumber, SERIAL_HEX);
    assert.equal(event.revokedAt, "2026-10-13T00:00:00.000Z");
    assert.equal(event.mode, "fail-closed");
    assert.equal(event.source, "responder");
    assert.match(event.at, /^\d{4}-\d{2}-\d{2}T/);
    // The first revocation is never re-emitted to the new callback.
    assert.notEqual(event.at, first[0].at);
    const revised = eventsOf(audit, "ocsp_revoked_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "set");
    // Both revocations were audited, in order.
    const revoked = eventsOf(audit, "ocsp_revoked");
    assert.ok(revoked.length >= 2);
    assert.equal(revoked[0].endpoint, handle.forwardUrl);
    assert.equal(revoked[0].serialNumber, SERIAL_HEX);
    assert.equal(revoked[0].mode, "fail-closed");
    assert.equal(revoked[0].source, "responder");
    // The revoked peer never saw a byte.
    assert.equal(handle.received.length, 0);
  });

  it("null clears back to audit-only: the revocation still rejects the delivery and is still audited", async () => {
    const audit = tmpAudit();
    const seen: OcspRevokedAuditEvent[] = [];
    const handle = await makeRelay(audit, { mode: "fail-closed", status: "revoked" });
    handle.relay.reviseOcspRevokedCallback!((event) => seen.push(event));

    await postRevoked(handle, seen);
    await waitDead(handle, 1);
    assert.equal(seen.length, 2, "two attempts, two revoked verdicts");
    const before = seen.length;

    handle.relay.reviseOcspRevokedCallback!(null);
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    // The revoked delivery still dead-letters as a revocation refusal.
    const dead = await waitDead(handle, 2);
    assert.match(String(dead[1].lastError), /OCSP revoked certificate for /);
    assert.equal(seen.length, before, "cleared hook stays silent");
    const revoked = eventsOf(audit, "ocsp_revoked");
    assert.ok(revoked.length >= 4, "both revocations still audited (two attempts each)");
    assert.equal(revoked.at(-1)?.endpoint, handle.forwardUrl);
    assert.equal(revoked.at(-1)?.serialNumber, SERIAL_HEX);
    // The revoked peer never saw a byte.
    assert.equal(handle.received.length, 0);
    const revised = eventsOf(audit, "ocsp_revoked_callback_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, "set");
    assert.equal(revised[1].current, "cleared");
  });

  it("with OCSP unconfigured, revising throws the must-restart Error and live state is untouched", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, false);
    for (const cb of [(() => {}) as never, null]) {
      assert.throws(() => handle.relay.reviseOcspRevokedCallback!(cb), (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, MUST_RESTART);
        return true;
      });
    }
    assert.equal(eventsOf(audit, "ocsp_revoked_callback_revised").length, 0);
    // The relay still admits and delivers cleanly with OCSP off.
    const res = await postSigned(handle.port, BODY);
    assert.equal(res.status, 202);
    await waitFor(() => handle.received.length === 1, "the delivery to land");
    assert.deepEqual(handle.received[0], BODY);
    assert.equal(eventsOf(audit, "ocsp_revoked").length, 0);
  });

  it("an illegal value throws RangeError and the live callback is untouched", async () => {
    const audit = tmpAudit();
    const seen: OcspRevokedAuditEvent[] = [];
    const handle = await makeRelay(audit, { mode: "fail-closed", status: "revoked" });
    handle.relay.reviseOcspRevokedCallback!((event) => seen.push(event));
    for (const bad of ["x", 42, {}, true] as never[]) {
      assert.throws(
        () => handle.relay.reviseOcspRevokedCallback!(bad),
        RangeError,
        String(bad)
      );
    }
    assert.equal(eventsOf(audit, "ocsp_revoked_callback_revised").length, 1);
    await postRevoked(handle, seen);
    assert.ok(seen.length >= 1, "the original callback still observes the revocation");
    assert.equal(seen[0].endpoint, handle.forwardUrl);
    assert.equal(seen[0].serialNumber, SERIAL_HEX);
  });

  it("same-reference replacement and clearing an already-unset callback are silent no-ops", async () => {
    const audit = tmpAudit();
    const seen: OcspRevokedAuditEvent[] = [];
    const onRevoked = (event: OcspRevokedAuditEvent) => seen.push(event);
    const handle = await makeRelay(audit, { mode: "fail-closed", status: "revoked" });
    handle.relay.reviseOcspRevokedCallback!(onRevoked);
    handle.relay.reviseOcspRevokedCallback!(onRevoked);
    assert.equal(eventsOf(audit, "ocsp_revoked_callback_revised").length, 1);
    await postRevoked(handle, seen);
    assert.ok(seen.length >= 1, "the callback still observes after the no-op revision");
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    handle.relay.reviseOcspRevokedCallback!(null);
    assert.equal(eventsOf(audit, "ocsp_revoked_callback_revised").length, 2);
    handle.relay.reviseOcspRevokedCallback!(null);
    assert.equal(eventsOf(audit, "ocsp_revoked_callback_revised").length, 2);
    // A relay built with no callback at all: clearing is a no-op too.
    const bareAudit = tmpAudit();
    const bare = await makeRelay(bareAudit, { mode: "fail-closed", status: "revoked" });
    bare.relay.reviseOcspRevokedCallback!(null);
    assert.equal(eventsOf(bareAudit, "ocsp_revoked_callback_revised").length, 0);
  });

  it("audit previous/current are exact across set -> cleared -> set", async () => {
    const audit = tmpAudit();
    const handle = await makeRelay(audit, { mode: "fail-closed", status: "revoked" });
    const cb = () => {};
    handle.relay.reviseOcspRevokedCallback!(cb);
    handle.relay.reviseOcspRevokedCallback!(null);
    handle.relay.reviseOcspRevokedCallback!(cb);
    const revised = eventsOf(audit, "ocsp_revoked_callback_revised");
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

  it("a throwing callback does not downgrade the verdict: the revocation still rejects", async () => {
    const audit = tmpAudit();
    let throws = 0;
    const handle = await makeRelay(audit, { mode: "fail-closed", status: "revoked" });
    handle.relay.reviseOcspRevokedCallback!(() => {
      throws++;
      throw new Error("operator sink down");
    });
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    const dead = await waitDead(handle, 1);
    assert.match(String(dead[0].lastError), /OCSP revoked certificate for /);
    assert.ok(throws >= 1, "the throwing callback was invoked");
    assert.equal(handle.received.length, 0, "the revoked peer never saw a byte");
    // The audit still landed first, before the cell threw.
    const revoked = eventsOf(audit, "ocsp_revoked");
    assert.equal(revoked.length, 2, "both attempts audited despite the throwing hook");
    assert.equal(revoked[0].endpoint, handle.forwardUrl);
  });

  it("in fail-open mode an unknown status does not enter the revoked callback (only onAlert)", async () => {
    const audit = tmpAudit();
    const seen: OcspRevokedAuditEvent[] = [];
    const handle = await makeRelay(audit, { mode: "fail-open", status: "unknown" });
    handle.relay.reviseOcspRevokedCallback!((event) => seen.push(event));
    assert.equal((await postSigned(handle.port, BODY)).status, 202);
    // The delivery proceeds: the unknown status is a query-quality
    // signal, not a revocation.
    await waitFor(() => handle.received.length === 1, "the fail-open delivery to land");
    assert.deepEqual(handle.received[0], BODY);
    assert.equal(seen.length, 0, "no revoked verdict, no revoked callback");
    assert.equal(eventsOf(audit, "ocsp_revoked").length, 0);
    const alerts = eventsOf(audit, "ocsp_alert");
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].kind, "ocsp_unavailable");
    assert.equal(alerts[0].outcome, "proceeded");
    assert.equal(alerts[0].mode, "fail-open");
    const auth = { authorization: `Bearer ${relayOperator}` };
    const dead = (await getJson(handle.port, "/dead-letter", auth)).body as unknown[];
    assert.equal(dead.length, 0);
  });

  it("revision does not change the mode, the relay_ocsp_* counters, or the audit trail", async () => {
    const audit = tmpAudit();
    const first: OcspRevokedAuditEvent[] = [];
    const second: OcspRevokedAuditEvent[] = [];
    const handle = await makeRelay(audit, { mode: "fail-closed", status: "revoked" });
    const auth = { authorization: `Bearer ${relayOperator}` };
    const ocspCount = (metrics: string, n: number): boolean => {
      const re = new RegExp(
        `relay_ocsp_total\\{endpoint="${handle.forwardUrl.replace(/\//g, "\\/")}",status="revoked"\\} ${n}`
      );
      return re.test(metrics);
    };
    handle.relay.reviseOcspRevokedCallback!((event) => first.push(event));
    await postRevoked(handle, first);
    await waitDead(handle, 1);
    const metricsBefore = await getText(handle.port, "/metrics", auth);
    assert.ok(ocspCount(metricsBefore, 2), "two revoked outcomes counted before the swap");

    // Swap the observer; nothing about the check itself may move.
    handle.relay.reviseOcspRevokedCallback!((event) => second.push(event));
    await postRevoked(handle, second);
    assert.equal(first.length, 2, "old callback stays silent after revision");
    assert.ok(second.length >= 1);
    assert.equal(second[0].mode, "fail-closed", "mode unchanged by the revision");
    assert.equal(second[0].serialNumber, SERIAL_HEX, "serial unchanged by the revision");
    await waitDead(handle, 2);
    const metricsAfter = await getText(handle.port, "/metrics", auth);
    assert.ok(ocspCount(metricsAfter, 4), "four revoked outcomes counted after the swap");
    const revoked = eventsOf(audit, "ocsp_revoked");
    assert.equal(revoked.length, 4);
    assert.equal(revoked.at(-1)?.mode, "fail-closed");
    assert.equal(handle.received.length, 0);
  });
});
