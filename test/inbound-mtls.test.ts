import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "node:crypto";
import type { AddressInfo } from "node:net";
import { createRelayServer, type RelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  decideInboundMtls,
  peerCertFingerprint,
  resolveInboundMtlsConfig,
  type InboundMtlsConfig,
  type ResolvedInboundMtlsConfig,
} from "../src/inbound-mtls.ts";
import { generateInboundMtlsFixture } from "./inbound-mtls-fixture.ts";

const RELAY_SECRET = "inbound-mtls-test-secret";
const OPERATOR_TOKEN = "op-inbound-mtls-token";
const BODY = Buffer.from(JSON.stringify({ event: "mtls.probe" }));

// Generated once per file (~1s of RSA-2048 keygen); reused by every test.
const FIX = generateInboundMtlsFixture();
const CLIENT_FINGERPRINT = peerCertFingerprint(new X509Certificate(FIX.clientCertPem).raw);
const CLIENT_SUBJECT = new X509Certificate(FIX.clientCertPem).subject;
const EVIL_FINGERPRINT = peerCertFingerprint(new X509Certificate(FIX.evilClientCertPem).raw);

function baseMtlsConfig(overrides: Partial<InboundMtlsConfig> = {}): InboundMtlsConfig {
  return {
    key: FIX.serverKeyPem,
    cert: FIX.serverCertPem,
    ca: FIX.caCertPem,
    ...overrides,
  };
}

async function startRelay(
  t: { after: (fn: () => Promise<void> | void) => void },
  inboundMtls: InboundMtlsConfig | undefined,
  extra: Record<string, unknown> = {}
): Promise<{ relay: RelayServer; port: number; audit: AuditLog }> {
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr-mtls-")), "audit.jsonl"));
  const relay = createRelayServer({
    secret: RELAY_SECRET,
    forwardUrl: "http://127.0.0.1:1/unused",
    auditLog: audit,
    sender: async () => {},
    ...(inboundMtls === undefined ? {} : { inboundMtls }),
    ...extra,
  });
  await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
  const port = (relay.address() as AddressInfo).port;
  t.after(() => new Promise<void>((resolve) => relay.close(() => resolve())));
  return { relay, port, audit };
}

interface ClientOpts {
  cert?: string;
  key?: string;
}

function httpsCall(
  port: number,
  path: string,
  opts: { method?: string; headers?: Record<string, string>; body?: Buffer } & ClientOpts
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpsRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: opts.method ?? "GET",
        headers: opts.headers,
        cert: opts.cert,
        key: opts.key,
        rejectUnauthorized: false,
        agent: false, // fresh handshake per request — no pooled-TLS surprises
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") })
        );
      }
    );
    r.on("error", reject);
    if (opts.body) r.write(opts.body);
    r.end();
  });
}

function httpCall(
  port: number,
  path: string,
  opts: { method?: string; headers?: Record<string, string>; body?: Buffer } = {}
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: opts.method ?? "GET", headers: opts.headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") })
        );
      }
    );
    r.on("error", reject);
    if (opts.body) r.write(opts.body);
    r.end();
  });
}

function postHook(port: number, client: ClientOpts, useHttp = false) {
  const call = useHttp ? httpCall : httpsCall;
  return call(port, "/hook", {
    method: "POST",
    headers: { "x-signature": signSha256(BODY, RELAY_SECRET), "content-type": "application/json" },
    body: BODY,
    ...client,
  });
}

function lastEvent(audit: AuditLog, event: string): Record<string, unknown> {
  const matches = audit.query({ event }) as Record<string, unknown>[];
  assert.ok(matches.length > 0, `expected at least one ${event} audit event`);
  return matches[matches.length - 1] as Record<string, unknown>;
}

describe("inbound-mtls: config validation", () => {
  it("rejects bad configs at startup with RangeError", () => {
    const cases: Array<[string, InboundMtlsConfig]> = [
      ["empty key", baseMtlsConfig({ key: "" })],
      ["empty cert", baseMtlsConfig({ cert: "  " })],
      ["garbage key PEM", baseMtlsConfig({ key: "not-a-pem" })],
      ["mismatched key/cert", baseMtlsConfig({ cert: FIX.clientCertPem })],
      ["empty ca string", baseMtlsConfig({ ca: "" })],
      ["empty ca array", baseMtlsConfig({ ca: [] })],
      ["garbage ca PEM", baseMtlsConfig({ ca: "not-a-pem" })],
      ["non-boolean requireCert", baseMtlsConfig({ requireCert: "yes" as unknown as boolean })],
      ["non-boolean operatorMtls", baseMtlsConfig({ operatorMtls: 1 as unknown as boolean })],
      ["malformed fingerprint", baseMtlsConfig({ clientFingerprints: ["sha256/too-short"] })],
      ["empty fingerprint whitelist", baseMtlsConfig({ clientFingerprints: [] })],
      ["non-array fingerprints", baseMtlsConfig({ clientFingerprints: "x" as unknown as string[] })],
    ];
    for (const [label, cfg] of cases) {
      assert.throws(
        () =>
          createRelayServer({
            secret: RELAY_SECRET,
            forwardUrl: "http://127.0.0.1:1/unused",
            auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "wr-mtls-")), "audit.jsonl")),
            inboundMtls: cfg,
          }),
        RangeError,
        label
      );
    }
  });

  it("accepts a valid config and applies documented defaults", () => {
    const resolved = resolveInboundMtlsConfig(baseMtlsConfig());
    assert.equal(resolved.requireCert, true);
    assert.equal(resolved.operatorMtls, false);
    assert.deepEqual(resolved.clientFingerprints, []);
    assert.deepEqual(resolved.ca, [FIX.caCertPem]);
    const spelled = resolveInboundMtlsConfig(
      baseMtlsConfig({ clientFingerprints: [`sha256/${CLIENT_FINGERPRINT}`, `sha256:${CLIENT_FINGERPRINT}`] })
    );
    assert.deepEqual(spelled.clientFingerprints, [CLIENT_FINGERPRINT, CLIENT_FINGERPRINT]);
  });
});

describe("inbound-mtls: request-time gate (requireCert)", () => {
  it("answers 401 client_cert_required when no certificate is presented", async (t) => {
    const { port, audit } = await startRelay(t, baseMtlsConfig());
    const res = await postHook(port, {});
    assert.equal(res.status, 401);
    assert.deepEqual(JSON.parse(res.body), {
      error: "client certificate required",
      reason: "client_cert_required",
    });
    const rejected = lastEvent(audit, "rejected");
    assert.equal(rejected.reason, "client_cert_required");
    assert.equal(rejected.path, "/hook");
    assert.ok(!("clientCertFingerprint" in rejected), "no identity without a presented cert");
  });

  it("answers 401 client_cert_invalid for a certificate outside the CA chain", async (t) => {
    const { port, audit } = await startRelay(t, baseMtlsConfig());
    const res = await postHook(port, { cert: FIX.evilClientCertPem, key: FIX.evilClientKeyPem });
    assert.equal(res.status, 401);
    assert.equal((JSON.parse(res.body) as { reason: string }).reason, "client_cert_invalid");
    const rejected = lastEvent(audit, "rejected");
    assert.equal(rejected.reason, "client_cert_invalid");
    // The presented (but untrusted) certificate is still identified.
    assert.equal(rejected.clientCertFingerprint, EVIL_FINGERPRINT);
    assert.equal(rejected.clientCertSubject, "CN=evil-client");
  });

  it("accepts a valid certificate and records its identity on the accepted event", async (t) => {
    const { port, audit } = await startRelay(t, baseMtlsConfig());
    const res = await postHook(port, { cert: FIX.clientCertPem, key: FIX.clientKeyPem });
    assert.equal(res.status, 202);
    const accepted = lastEvent(audit, "accepted");
    assert.equal(accepted.clientCertFingerprint, CLIENT_FINGERPRINT);
    assert.equal(accepted.clientCertSubject, CLIENT_SUBJECT);
  });

  it("rejects a chain-valid certificate missing from the fingerprint whitelist", async (t) => {
    const other = peerCertFingerprint(Buffer.from("not-the-client-cert"));
    const { port, audit } = await startRelay(
      t,
      baseMtlsConfig({ clientFingerprints: [`sha256/${other}`] })
    );
    const res = await postHook(port, { cert: FIX.clientCertPem, key: FIX.clientKeyPem });
    assert.equal(res.status, 401);
    assert.equal((JSON.parse(res.body) as { reason: string }).reason, "client_cert_invalid");
    const rejected = lastEvent(audit, "rejected");
    assert.equal(rejected.reason, "client_cert_invalid");
    assert.equal(rejected.clientCertFingerprint, CLIENT_FINGERPRINT);
  });

  it("accepts a whitelisted fingerprint (sha256/ spelling)", async (t) => {
    const { port, audit } = await startRelay(
      t,
      baseMtlsConfig({ clientFingerprints: [`sha256/${CLIENT_FINGERPRINT}`] })
    );
    const res = await postHook(port, { cert: FIX.clientCertPem, key: FIX.clientKeyPem });
    assert.equal(res.status, 202);
    assert.equal(lastEvent(audit, "accepted").clientCertFingerprint, CLIENT_FINGERPRINT);
  });
});

describe("inbound-mtls: operatorMtls independent mode", () => {
  it("single plane: ingest stays open without a cert, operator routes 401", async (t) => {
    const { port, audit } = await startRelay(
      t,
      baseMtlsConfig({ requireCert: false, operatorMtls: true }),
      { operatorToken: OPERATOR_TOKEN }
    );
    // Ingest without a client certificate: open.
    const ingested = await postHook(port, {});
    assert.equal(ingested.status, 202);
    assert.ok(!("clientCertFingerprint" in lastEvent(audit, "accepted")));
    // Operator route without a client certificate: 401.
    const denied = await httpsCall(port, "/metrics", {
      headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
    });
    assert.equal(denied.status, 401);
    assert.equal((JSON.parse(denied.body) as { reason: string }).reason, "client_cert_required");
    // Operator route with a valid certificate: through to operator auth.
    const allowed = await httpsCall(port, "/metrics", {
      headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      cert: FIX.clientCertPem,
      key: FIX.clientKeyPem,
    });
    assert.equal(allowed.status, 200);
  });

  it("split plane: intake stays plain HTTP, operator plane alone terminates TLS", async (t) => {
    const { relay, port, audit } = await startRelay(
      t,
      baseMtlsConfig({ requireCert: false, operatorMtls: true }),
      { operatorToken: OPERATOR_TOKEN, operatorPort: { port: 0 } }
    );
    // Intake plane is plain HTTP: a cleartext POST is accepted.
    const ingested = await postHook(port, {}, true);
    assert.equal(ingested.status, 202);
    assert.ok(!("clientCertFingerprint" in lastEvent(audit, "accepted")));
    // Operator plane is HTTPS with mTLS enforced.
    const opPort = (relay.operatorServer!.address() as AddressInfo).port;
    const denied = await httpsCall(opPort, "/metrics", {
      headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
    });
    assert.equal(denied.status, 401);
    assert.equal((JSON.parse(denied.body) as { reason: string }).reason, "client_cert_required");
    const allowed = await httpsCall(opPort, "/metrics", {
      headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      cert: FIX.clientCertPem,
      key: FIX.clientKeyPem,
    });
    assert.equal(allowed.status, 200);
    // Webhooks can never enter through the operator plane.
    const sneaky = await httpsCall(opPort, "/hook", {
      method: "POST",
      headers: { "x-signature": signSha256(BODY, RELAY_SECRET) },
      body: BODY,
      cert: FIX.clientCertPem,
      key: FIX.clientKeyPem,
    });
    assert.equal(sneaky.status, 404);
  });
});

describe("inbound-mtls: hot-reload", () => {
  it("updateInboundMtlsConfig rotates the CA for new handshakes and audits the change", async (t) => {
    const { relay, port, audit } = await startRelay(t, baseMtlsConfig());
    const client = { cert: FIX.clientCertPem, key: FIX.clientKeyPem };
    const client2 = { cert: FIX.client2CertPem, key: FIX.client2KeyPem };
    // Before rotation: CA-1 client passes, CA-2 client is untrusted.
    assert.equal((await postHook(port, client)).status, 202);
    assert.equal((await postHook(port, client2)).status, 401);

    const changes = relay.updateInboundMtlsConfig!({ ca: FIX.ca2CertPem });
    assert.deepEqual(
      changes.map((c) => c.field),
      ["inboundMtls.ca"]
    );
    assert.deepEqual(changes[0].from, "<redacted>");
    assert.deepEqual(changes[0].to, "<redacted>");

    // After rotation (fresh handshake per request): trust flips to CA-2.
    assert.equal((await postHook(port, client2)).status, 202);
    const rejected = await postHook(port, client);
    assert.equal(rejected.status, 401);
    assert.equal((JSON.parse(rejected.body) as { reason: string }).reason, "client_cert_invalid");

    const updated = lastEvent(audit, "inbound_mtls_config_updated");
    assert.deepEqual(updated.fields, ["inboundMtls.ca"]);
  });

  it("rejects an illegal patch with RangeError and leaves the live config intact", async (t) => {
    const { relay, port, audit } = await startRelay(t, baseMtlsConfig());
    const client = { cert: FIX.clientCertPem, key: FIX.clientKeyPem };
    assert.throws(
      () => relay.updateInboundMtlsConfig!({ ca: "not-a-pem" } as unknown as { ca: string }),
      RangeError
    );
    assert.throws(
      () => relay.updateInboundMtlsConfig!({ bogus: 1 } as unknown as Record<string, unknown>),
      RangeError
    );
    assert.throws(
      () => relay.updateInboundMtlsConfig!({ requireCert: "yes" } as unknown as { requireCert: boolean }),
      RangeError
    );
    // Live config untouched: the valid client still passes.
    assert.equal((await postHook(port, client)).status, 202);
    assert.deepEqual(audit.query({ event: "inbound_mtls_config_updated" }), []);
  });

  it("rotating the whitelist takes effect immediately for new requests", async (t) => {
    const { relay, port } = await startRelay(t, baseMtlsConfig());
    const client = { cert: FIX.clientCertPem, key: FIX.clientKeyPem };
    assert.equal((await postHook(port, client)).status, 202);
    const changes = relay.updateInboundMtlsConfig!({
      clientFingerprints: [`sha256/${EVIL_FINGERPRINT}`],
    });
    assert.deepEqual(
      changes.map((c) => c.field),
      ["inboundMtls.clientFingerprints"]
    );
    // The previously-valid client is now rejected; the change is audited.
    const res = await postHook(port, client);
    assert.equal(res.status, 401);
    assert.equal((JSON.parse(res.body) as { reason: string }).reason, "client_cert_invalid");
  });

  it("toggling requireCert off opens ingest without a restart", async (t) => {
    const { relay, port } = await startRelay(t, baseMtlsConfig());
    assert.equal((await postHook(port, {})).status, 401);
    const changes = relay.updateInboundMtlsConfig!({ requireCert: false });
    assert.deepEqual(
      changes.map((c) => c.field),
      ["inboundMtls.requireCert"]
    );
    assert.equal((await postHook(port, {})).status, 202);
  });

  it("throws when inbound mTLS was never configured", async (t) => {
    const { relay } = await startRelay(t, undefined);
    assert.throws(() => relay.updateInboundMtlsConfig!({ requireCert: false }), Error);
  });
});

describe("inbound-mtls: decideInboundMtls unit matrix", () => {
  const cfg: ResolvedInboundMtlsConfig = resolveInboundMtlsConfig(baseMtlsConfig());

  it("no certificate, not required → allowed anonymously", () => {
    const open: ResolvedInboundMtlsConfig = { ...cfg, requireCert: false };
    const d = decideInboundMtls(open, { presented: false, authorized: false }, false);
    assert.deepEqual(d, { allowed: true });
  });

  it("no certificate, required → client_cert_required", () => {
    const d = decideInboundMtls(cfg, { presented: false, authorized: false }, false);
    assert.deepEqual(d, { allowed: false, reason: "client_cert_required" });
  });

  it("operator route under operatorMtls requires a cert even when requireCert is false", () => {
    const open: ResolvedInboundMtlsConfig = { ...cfg, requireCert: false, operatorMtls: true };
    assert.deepEqual(decideInboundMtls(open, { presented: false, authorized: false }, true), {
      allowed: false,
      reason: "client_cert_required",
    });
    // …but the ingest route on the same config stays open.
    assert.deepEqual(decideInboundMtls(open, { presented: false, authorized: false }, false), {
      allowed: true,
    });
  });

  it("unauthorized peer → client_cert_invalid with identity attached", () => {
    const d = decideInboundMtls(
      cfg,
      { presented: true, authorized: false, fingerprint: EVIL_FINGERPRINT, subject: "CN=evil-client" },
      false
    );
    assert.deepEqual(d, {
      allowed: false,
      reason: "client_cert_invalid",
      fingerprint: EVIL_FINGERPRINT,
      subject: "CN=evil-client",
    });
  });

  it("authorized peer yields its identity for the audit trail", () => {
    const d = decideInboundMtls(
      cfg,
      { presented: true, authorized: true, fingerprint: CLIENT_FINGERPRINT, subject: CLIENT_SUBJECT },
      false
    );
    assert.deepEqual(d, {
      allowed: true,
      identity: { fingerprint: CLIENT_FINGERPRINT, subject: CLIENT_SUBJECT },
    });
  });
});

describe("inbound-mtls: backward compatibility", () => {
  it("without inboundMtls the relay stays plain HTTP with zero behavior change", async (t) => {
    const { port, audit } = await startRelay(t, undefined);
    const res = await postHook(port, {}, true);
    assert.equal(res.status, 202);
    const accepted = lastEvent(audit, "accepted");
    assert.ok(!("clientCertFingerprint" in accepted));
    assert.ok(!("clientCertSubject" in accepted));
  });
});
