import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpsRequest } from "node:https";
import { createHash, createPublicKey } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertValidMeshOptions,
  MeshMetrics,
  DEFAULT_MAX_MESH_HOPS,
} from "../src/mesh.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { generateInboundMtlsFixture } from "./inbound-mtls-fixture.ts";

const FIX = generateInboundMtlsFixture();
const BODY = Buffer.from(JSON.stringify({ event: "mesh.mtls.probe" }));
const MESH_SECRET = "mesh-mtls-shared-secret";
const OPERATOR_TOKEN = "mesh-mtls-operator-token";

// SPKI pin of the generated fixture server cert — lets relay A trust
// relay B's TLS without touching process-wide CA settings (WR-21).
const SERVER_SPKI_PIN = `sha256/${createHash("sha256")
  .update(createPublicKey(FIX.serverCertPem).export({ type: "spki", format: "der" }) as Buffer)
  .digest("base64")}`;

interface ClientOpts {
  cert?: string;
  key?: string;
}

function httpsCall(
  port: number,
  path: string,
  opts: { method?: string; headers?: Record<string, string>; body?: Buffer } & ClientOpts
): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
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
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            headers: res.headers,
          })
        );
      }
    );
    r.on("error", reject);
    // End with the whole body at once so Node stamps `content-length`
    // (a write()+end() pair would send `transfer-encoding: chunked`,
    // which the relay must not forward — see the passthrough filter).
    r.end(opts.body);
  });
}

function readAudit(dir: string): Array<Record<string, unknown>> {
  let raw: string;
  try {
    raw = readFileSync(join(dir, "audit.jsonl"), "utf8").trim();
  } catch {
    return [];
  }
  if (raw === "") return [];
  return raw
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

async function waitFor(fn: () => boolean, ms: number, what: string): Promise<void> {
  const deadline = Date.now() + ms;
  while (!fn() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(fn(), what);
}

async function listenOn(server: { listen: (...a: never[]) => unknown; address: () => unknown }): Promise<number> {
  await new Promise<void>((resolve) =>
    (server.listen as (port: number, host: string, cb: () => void) => void)(0, "127.0.0.1", resolve)
  );
  return (server.address() as { port: number }).port;
}

async function closeServer(server: { close: (cb?: () => void) => void; once: (e: string, cb: () => void) => void }): Promise<void> {
  server.close();
  await new Promise<void>((r) => server.once("close", () => r()));
}

/** Intake terminates TLS (single plane, operatorMtls) but ingest stays open. */
function mtlsIntake() {
  return {
    key: FIX.serverKeyPem,
    cert: FIX.serverCertPem,
    ca: FIX.caCertPem,
    requireCert: false,
    operatorMtls: true,
  };
}

const GOOD_CLIENT = { cert: FIX.clientCertPem, key: FIX.clientKeyPem };
const EVIL_CLIENT = { cert: FIX.evilClientCertPem, key: FIX.evilClientKeyPem };

describe("WR-112 mesh mTLS config and metrics", () => {
  it("assertValidMeshOptions accepts mtls: {} and resolves mtls: true", () => {
    assert.deepEqual(assertValidMeshOptions({ mtls: {} }), {
      maxHops: DEFAULT_MAX_MESH_HOPS,
      mtls: true,
    });
    assert.deepEqual(assertValidMeshOptions({ maxHops: 3, mtls: {} }), { maxHops: 3, mtls: true });
  });

  it("assertValidMeshOptions keeps the legacy shape when mtls is absent", () => {
    // Guards the pre-WR-112 deepEqual contract in test/mesh.test.ts.
    assert.deepEqual(assertValidMeshOptions({}), { maxHops: DEFAULT_MAX_MESH_HOPS });
    assert.deepEqual(assertValidMeshOptions(undefined), undefined);
  });

  it("assertValidMeshOptions rejects non-object mtls", () => {
    for (const bad of [true, "yes", 1, [], null]) {
      assert.throws(() => assertValidMeshOptions({ mtls: bad as never }), RangeError);
    }
  });

  it("MeshMetrics counts mTLS rejections per path, activity-gated", () => {
    const m = new MeshMetrics();
    assert.equal(m.render(), "");
    m.recordMtlsRejected("/");
    m.recordMtlsRejected("/");
    m.recordMtlsRejected("/hook");
    const out = m.render();
    assert.match(out, /# HELP relay_mesh_mtls_rejects_total /);
    assert.match(out, /# TYPE relay_mesh_mtls_rejects_total counter/);
    assert.match(out, /relay_mesh_mtls_rejects_total\{path="\/"\} 2/);
    assert.match(out, /relay_mesh_mtls_rejects_total\{path="\/hook"\} 1/);
  });
});

describe("WR-112 mesh.mtls startup fail-fast", () => {
  function minimal(extra: Record<string, unknown>) {
    const dir = mkdtempSync(join(tmpdir(), "mesh-mtls-"));
    return () =>
      createRelayServer({
        secret: "s",
        forwardUrl: "http://127.0.0.1:9/hook",
        auditLog: new AuditLog(join(dir, "audit.jsonl")),
        ...extra,
      });
  }

  it("throws without inboundMtls", () => {
    assert.throws(minimal({ mesh: { mtls: {} } }), /mesh\.mtls requires inboundMtls/);
  });

  it("throws when the intake listener does not terminate TLS", () => {
    // requireCert:false + no operatorMtls on the single plane = plain HTTP intake.
    assert.throws(
      minimal({
        mesh: { mtls: {} },
        inboundMtls: {
          key: FIX.serverKeyPem,
          cert: FIX.serverCertPem,
          ca: FIX.caCertPem,
          requireCert: false,
        },
      }),
      /intake listener to terminate TLS/
    );
  });

  it("starts with inboundMtls terminating TLS on intake", () => {
    const relay = minimal({ mesh: { mtls: {} }, inboundMtls: mtlsIntake() })();
    relay.close();
  });
});

describe("WR-112 mesh mTLS inbound gate", () => {
  let relay: ReturnType<typeof createRelayServer>;
  let dir: string;
  let port: number;

  function meshHeaders(extra: Record<string, string> = {}): Record<string, string> {
    return {
      "content-type": "application/json",
      "x-relay-signature": signSha256(BODY, MESH_SECRET),
      "x-relay-hops": "0",
      ...extra,
    };
  }

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "mesh-mtls-"));
    relay = createRelayServer({
      secret: MESH_SECRET,
      forwardUrl: "http://127.0.0.1:9/hook",
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: OPERATOR_TOKEN,
      inboundMtls: mtlsIntake(),
      mesh: { mtls: {} },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    port = await listenOn(relay as never);
  });

  after(async () => {
    await closeServer(relay as never);
  });

  it("rejects a mesh-peer claim without a client certificate (401 mesh_mtls_reject)", async () => {
    const res = await httpsCall(port, "/", { method: "POST", headers: meshHeaders(), body: BODY });
    assert.equal(res.status, 401);
    assert.equal((JSON.parse(res.body) as { reason: string }).reason, "mesh_mtls_reject");
    const rejected = readAudit(dir).find((e) => e.event === "rejected" && e.reason === "mesh_mtls_reject");
    assert.ok(rejected, "audited as rejected/mesh_mtls_reject");
    assert.equal(rejected.path, "/");
  });

  it("counts the rejection on relay_mesh_mtls_rejects_total", async () => {
    const res = await httpsCall(
      port,
      "/metrics",
      { headers: { authorization: `Bearer ${OPERATOR_TOKEN}` }, ...GOOD_CLIENT }
    );
    assert.equal(res.status, 200);
    assert.match(res.body, /relay_mesh_mtls_rejects_total\{path="\/"\} 1/);
  });

  it("rejects a mesh peer whose certificate chains to the wrong CA", async () => {
    const res = await httpsCall(port, "/", {
      method: "POST",
      headers: meshHeaders(),
      body: BODY,
      ...EVIL_CLIENT,
    });
    assert.equal(res.status, 401);
    assert.equal((JSON.parse(res.body) as { reason: string }).reason, "mesh_mtls_reject");
    const rejected = readAudit(dir).filter(
      (e) => e.event === "rejected" && e.reason === "mesh_mtls_reject"
    );
    assert.ok(rejected.length >= 1);
    assert.ok(typeof rejected[rejected.length - 1].clientCertFingerprint === "string");
  });

  it("accepts a mesh peer with a valid client certificate, attributing the identity", async () => {
    const res = await httpsCall(port, "/", {
      method: "POST",
      headers: meshHeaders(),
      body: BODY,
      ...GOOD_CLIENT,
    });
    assert.equal(res.status, 202);
    const accepted = readAudit(dir).find(
      (e) => e.event === "accepted" && (e as { meshPeer?: boolean }).meshPeer === true
    );
    assert.ok(accepted, "mesh peer accepted");
    assert.ok(typeof accepted.clientCertFingerprint === "string", "identity on the audit trail");
    assert.equal(accepted.meshHops, 0);
  });

  it("leaves plain producers (no x-relay-signature) untouched", async () => {
    const res = await httpsCall(port, "/", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-signature": signSha256(BODY, MESH_SECRET),
      },
      body: BODY,
    });
    assert.equal(res.status, 202);
  });
});

describe("WR-112 mesh mTLS outbound pre-flight", () => {
  function makeSender(extra: Record<string, unknown>) {
    const dir = mkdtempSync(join(tmpdir(), "mesh-mtls-"));
    const relay = createRelayServer({
      secret: "sender-secret",
      forwardUrl: "http://127.0.0.1:9/hook",
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      inboundMtls: mtlsIntake(),
      mesh: { mtls: {} },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    });
    return { relay, dir };
  }

  async function deadLetterLastError(
    dir: string,
    port: number,
    headers: Record<string, string>
  ): Promise<string> {
    const res = await httpsCall(port, "/", { method: "POST", headers, body: BODY });
    assert.equal(res.status, 202);
    await waitFor(
      () => readAudit(dir).some((e) => e.event === "dead_letter"),
      8000,
      "dead letter recorded"
    );
    const dead = readAudit(dir).find((e) => e.event === "dead_letter") as { error: string };
    return dead.error;
  }

  function producerHeaders(secret: string): Record<string, string> {
    return { "content-type": "application/json", "x-signature": signSha256(BODY, secret) };
  }

  it("refuses a mesh hop to an https peer with no client identity configured", async () => {
    const { relay, dir } = makeSender({ forwardUrl: "https://127.0.0.1:9/hook" });
    const port = await listenOn(relay as never);
    try {
      const lastError = await deadLetterLastError(dir, port, producerHeaders("sender-secret"));
      assert.match(lastError, /mesh\.mtls: refusing unauthenticated mesh forward/);
    } finally {
      await closeServer(relay as never);
    }
  });

  it("refuses a mesh hop to a non-TLS peer", async () => {
    const { relay, dir } = makeSender({ forwardUrl: "http://127.0.0.1:9/hook" });
    const port = await listenOn(relay as never);
    try {
      const lastError = await deadLetterLastError(dir, port, producerHeaders("sender-secret"));
      assert.match(lastError, /mesh\.mtls: refusing unauthenticated mesh forward/);
    } finally {
      await closeServer(relay as never);
    }
  });

  it("mesh A→B over mutual TLS: hop forwarded with client cert, peer identity audited", async () => {
    // Relay B: verifies the x-relay-signature hop AND requires the mTLS client cert.
    const dirB = mkdtempSync(join(tmpdir(), "mesh-mtls-"));
    const relayB = createRelayServer({
      secret: MESH_SECRET,
      forwardUrl: "http://127.0.0.1:9/terminal",
      auditLog: new AuditLog(join(dirB, "audit.jsonl")),
      inboundMtls: mtlsIntake(),
      mesh: { mtls: {} },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const portB = await listenOn(relayB as never);
    const bUrl = `https://127.0.0.1:${portB}/`;
    // Relay A: carries its client identity (WR-36) and pins B's server cert (WR-21).
    const dirA = mkdtempSync(join(tmpdir(), "mesh-mtls-"));
    const relayA = createRelayServer({
      secret: "secret-a",
      forwardUrl: bUrl,
      auditLog: new AuditLog(join(dirA, "audit.jsonl")),
      inboundMtls: mtlsIntake(),
      mesh: { mtls: {} },
      tlsClientCerts: { [bUrl]: { cert: FIX.clientCertPem, key: FIX.clientKeyPem } },
      tlsPins: { [bUrl]: [SERVER_SPKI_PIN] },
      outboundSigning: { secret: MESH_SECRET },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const portA = await listenOn(relayA as never);
    try {
      const res = await httpsCall(portA, "/", {
        method: "POST",
        headers: producerHeaders("secret-a"),
        body: BODY,
      });
      assert.equal(res.status, 202);
      const acceptedA = JSON.parse(res.body) as { traceId: string };
      await waitFor(
        () => readAudit(dirB).some((e) => e.event === "accepted"),
        8000,
        "B accepted the mesh hop"
      );
      const acceptedB = readAudit(dirB).find((e) => e.event === "accepted") as Record<string, unknown>;
      assert.equal(acceptedB.meshPeer, true, "B verified the x-relay-signature hop");
      assert.equal(acceptedB.meshHops, 1, "B saw A's stamped hop");
      assert.ok(
        typeof acceptedB.clientCertFingerprint === "string",
        "B audited A's mTLS client identity"
      );
      assert.equal(acceptedB.traceId, acceptedA.traceId, "trace threads the mTLS hop");
    } finally {
      await closeServer(relayA as never);
      await closeServer(relayB as never);
    }
  });
});
