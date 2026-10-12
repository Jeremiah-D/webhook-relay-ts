import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertTlsVersionMeetsFloor,
  assertValidMinTlsVersion,
  compareTlsVersions,
  parseNegotiatedTlsVersion,
  TlsVersionMonitor,
  TlsVersionRejectedError,
} from "../src/tls-version.ts";
import { createRelayServer, createDefaultSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { OutboundConnectionPool } from "../src/keepalive.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

const TEST_KEY = "tls-version-key";
const BODY = Buffer.from(JSON.stringify({ event: "tls.probe" }));

describe("tls-version: validation and comparison", () => {
  it("assertValidMinTlsVersion accepts 1.2/1.3 and rejects the rest at config time", () => {
    assertValidMinTlsVersion("1.2");
    assertValidMinTlsVersion("1.3");
    for (const bad of ["1.0", "1.1", "TLSv1.3", "1.4", "", 1.3, null, undefined, {}]) {
      assert.throws(() => assertValidMinTlsVersion(bad), RangeError);
    }
  });

  it("compareTlsVersions orders 1.2 < 1.3 and future versions above any floor", () => {
    assert.equal(compareTlsVersions("1.2", "1.3"), -1);
    assert.equal(compareTlsVersions("1.3", "1.2"), 1);
    assert.equal(compareTlsVersions("1.3", "1.3"), 0);
    // A hypothetical TLS 1.4 must never be rejected by a floor the code
    // predates — it sorts above every known version.
    assert.equal(compareTlsVersions("1.4", "1.3"), 1);
    // Unparseable sorts below everything: unknown is never "at least".
    assert.equal(compareTlsVersions("bogus", "1.2"), -1);
  });

  it("parseNegotiatedTlsVersion maps Node protocol strings", () => {
    assert.equal(parseNegotiatedTlsVersion("TLSv1.2"), "1.2");
    assert.equal(parseNegotiatedTlsVersion("TLSv1.3"), "1.3");
    assert.equal(parseNegotiatedTlsVersion(undefined), undefined);
    assert.equal(parseNegotiatedTlsVersion(""), undefined);
    assert.equal(parseNegotiatedTlsVersion("unknown"), undefined);
  });

  it("assertTlsVersionMeetsFloor passes at/above the floor, rejects below, fails closed on unknown", () => {
    assert.equal(assertTlsVersionMeetsFloor("e", "TLSv1.3", "1.3"), "1.3");
    assert.equal(assertTlsVersionMeetsFloor("e", "TLSv1.3", "1.2"), "1.3");
    assert.equal(assertTlsVersionMeetsFloor("e", "TLSv1.2", "1.2"), "1.2");
    let caught: unknown;
    try {
      assertTlsVersionMeetsFloor("e", "TLSv1.2", "1.3");
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof TlsVersionRejectedError);
    assert.equal((caught as TlsVersionRejectedError).endpoint, "e");
    assert.equal((caught as TlsVersionRejectedError).negotiated, "TLSv1.2");
    assert.equal((caught as TlsVersionRejectedError).required, "1.3");
    assert.match((caught as Error).message, /below the configured minimum/);
    // Unparseable protocol fails closed — the floor cannot be verified.
    assert.throws(() => assertTlsVersionMeetsFloor("e", "mystery", "1.2"), TlsVersionRejectedError);
  });
});

describe("tls-version: monitor accounting and exposition", () => {
  it("render() is empty until the first rejection, then emits one series per (endpoint, version)", () => {
    const m = new TlsVersionMonitor();
    assert.equal(m.render(), "");
    const seen: string[] = [];
    const m2 = new TlsVersionMonitor({ onRejected: (r) => seen.push(r.endpoint) });
    m2.recordRejection("https://a/hook", "TLSv1.2", "1.3");
    m2.recordRejection("https://a/hook", "TLSv1.2", "1.3");
    m2.recordRejection("https://b/hook", "TLSv1.2", "1.3");
    assert.deepEqual(seen, ["https://a/hook", "https://a/hook", "https://b/hook"]);
    const out = m2.render();
    assert.match(out, /# HELP relay_tls_version_rejections_total/);
    assert.match(out, /# TYPE relay_tls_version_rejections_total counter/);
    assert.match(out, /relay_tls_version_rejections_total\{endpoint="https:\/\/a\/hook",version="TLSv1\.2"\} 2/);
    assert.match(out, /relay_tls_version_rejections_total\{endpoint="https:\/\/b\/hook",version="TLSv1\.2"\} 1/);
  });
});

describe("tls-version: pool key binds the floor", () => {
  it("agents differ by floor and are stable per floor", () => {
    const pool = new OutboundConnectionPool({ idleTimeoutMs: 0 });
    try {
      const url = new URL("https://downstream.example/hook");
      const plain = pool.agentFor(url);
      const f12 = pool.agentFor(url, undefined, undefined, undefined, undefined, "1.2");
      const f13a = pool.agentFor(url, undefined, undefined, undefined, undefined, "1.3");
      const f13b = pool.agentFor(url, undefined, undefined, undefined, undefined, "1.3");
      assert.notEqual(f12, f13a);
      assert.notEqual(plain, f13a);
      assert.equal(f13a, f13b);
    } finally {
      pool.destroy();
    }
  });
});

describe("tls-version: real TLS handshakes through createDefaultSender", () => {
  let tls12: HttpsServer;
  let tls12Port: number;
  const received12: Buffer[] = [];

  let tls13: HttpsServer;
  let tls13Port: number;
  const received13: Buffer[] = [];

  before(async () => {
    // Downstream that negotiates at most TLS 1.2.
    tls12 = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM, maxVersion: "TLSv1.2" },
      (req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          received12.push(Buffer.concat(chunks));
          res.writeHead(200).end("ok");
        });
      }
    );
    tls12Port = await new Promise<number>((resolve) =>
      tls12.listen(0, "127.0.0.1", () => {
        const addr = tls12.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      })
    );
    // Downstream that negotiates TLS 1.3 (Node default).
    tls13 = createHttpsServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received13.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    tls13Port = await new Promise<number>((resolve) =>
      tls13.listen(0, "127.0.0.1", () => {
        const addr = tls13.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      })
    );
  });

  after(() => {
    tls12.close();
    tls13.close();
  });

  const url12 = () => `https://127.0.0.1:${tls12Port}/hook`;
  const url13 = () => `https://127.0.0.1:${tls13Port}/hook`;
  const item = (targetUrl: string) => ({ id: "t1", payload: BODY, targetUrl, headers: {} });
  // Pins stand in for chain verification (self-signed fixture cert),
  // exactly like the pinning tests — the floor check is orthogonal.
  const pinsFor = (u: string) => ({ [u]: [TLS_FIXTURE_SPKI_PIN] });
  const senderWith = (u: string, floor: "1.2" | "1.3" | undefined, monitor?: TlsVersionMonitor) =>
    createDefaultSender(
      pinsFor(u),
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined,
      floor === undefined ? undefined : { [u]: floor },
      monitor
    );

  it("a floor of 1.3 rejects a TLS 1.2 negotiation before any payload is sent", async () => {
    const monitor = new TlsVersionMonitor();
    const sender = senderWith(url12(), "1.3", monitor);
    const before = received12.length;
    await assert.rejects(() => sender(item(url12())), TlsVersionRejectedError);
    await assert.rejects(() => sender(item(url12())), /below the configured minimum/);
    // The floor is enforced on secureConnect, before the payload write:
    // the downstream never observes the request body.
    assert.equal(received12.length, before);
    const out = monitor.render();
    assert.match(out, /relay_tls_version_rejections_total\{endpoint="https:\/\/127\.0\.0\.1:\d+\/hook",version="TLSv1\.2"\} 2/);
  });

  it("a floor of 1.2 accepts a TLS 1.2 negotiation", async () => {
    const sender = senderWith(url12(), "1.2");
    await sender(item(url12()));
    assert.equal(received12.length, 1);
    assert.deepEqual(received12[0], BODY);
  });

  it("a floor of 1.3 accepts a TLS 1.3 negotiation", async () => {
    const sender = senderWith(url13(), "1.3");
    await sender(item(url13()));
    assert.equal(received13.length, 1);
  });

  it("endpoints without a floor keep the historical behavior (TLS 1.2 downstream still delivers)", async () => {
    const sender = senderWith(url12(), undefined);
    await sender(item(url12()));
    assert.equal(received12.length, 2);
  });

  it("createDefaultSender validates floors up front", () => {
    assert.throws(
      () =>
        createDefaultSender(
          undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined,
          undefined,
          { "https://x/": "1.0" as "1.2" },
          undefined
        ),
      /invalid minTlsVersion.*1\.2.*1\.3/
    );
  });
});

describe("tls-version: end-to-end through the relay server", () => {
  let https: HttpsServer;
  let relay: Server;
  let relayPort: number;
  const OPERATOR = "op-tlsver-token";
  const auth = { authorization: `Bearer ${OPERATOR}` };

  function getJson(port: number, path: string, headers: Record<string, string>) {
    return new Promise<{ status: number; body: unknown; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let body: unknown = text;
          try {
            body = JSON.parse(text);
          } catch { /* plain text (e.g. /metrics) */ }
          resolve({ status: res.statusCode ?? 0, body, text });
        });
      });
      r.on("error", reject);
      r.end();
    });
  }

  function postSigned(port: number, headers: Record<string, string>) {
    return new Promise<{ status: number }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: { ...headers, "x-signature": signSha256(BODY, TEST_KEY) },
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
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM, maxVersion: "TLSv1.2" },
      (req, res) => {
        req.resume();
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    const downstreamPort = await new Promise<number>((resolve) =>
      https.listen(0, "127.0.0.1", () => {
        const addr = https.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      })
    );
    const forwardUrl = `https://127.0.0.1:${downstreamPort}/hook`;
    const dir = mkdtempSync(join(tmpdir(), "audit-tlsver-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl,
      auditLog: audit,
      operatorToken: OPERATOR,
      // One attempt: the floor rejection is deterministic, no point
      // burning retry budget proving it twice.
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 1 },
      // Pins stand in for chain verification (self-signed fixture).
      tlsPins: { [forwardUrl]: [TLS_FIXTURE_SPKI_PIN] },
      // The downstream negotiates TLS 1.2; the floor demands 1.3.
      minTlsVersions: { [forwardUrl]: "1.3" },
    });
    relayPort = await new Promise<number>((resolve) =>
      relay.listen(0, "127.0.0.1", () => {
        const addr = relay.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      })
    );
  });

  after(() => {
    relay.close();
    https.close();
  });

  it("a below-floor negotiation dead-letters, audits tls_version_rejected, and counts the metric", async () => {
    const r = await postSigned(relayPort, {});
    assert.equal(r.status, 202); // accepted inbound; the TLS failure is outbound
    let dead: unknown[] = [];
    for (let i = 0; i < 200 && dead.length === 0; i++) {
      await new Promise((res) => setTimeout(res, 25));
      dead = ((await getJson(relayPort, "/dead-letter", auth)).body as unknown[]) ?? [];
    }
    assert.equal(dead.length, 1);
    assert.match((dead[0] as { lastError: string }).lastError, /below the configured minimum/);

    const audit = ((await getJson(relayPort, "/audit", auth)).body as { event: string }[]) ?? [];
    const rejected = audit.filter((e) => e.event === "tls_version_rejected");
    assert.equal(rejected.length, 1);
    assert.equal((rejected[0] as { negotiatedVersion: string }).negotiatedVersion, "TLSv1.2");
    assert.equal((rejected[0] as { requiredMinVersion: string }).requiredMinVersion, "1.3");

    const metrics = (await getJson(relayPort, "/metrics", auth)).text;
    assert.match(metrics, /relay_tls_version_rejections_total\{endpoint="https:\/\/127\.0\.0\.1:\d+\/hook",version="TLSv1\.2"\} 1/);
  });

  it("an invalid floor fails relay startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-tlsver-bad-"));
    assert.throws(
      () =>
        createRelayServer({
          secret: TEST_KEY,
          forwardUrl: "https://127.0.0.1:1/hook",
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          minTlsVersions: { "https://127.0.0.1:1/hook": "1.0" as "1.2" },
        }),
      RangeError
    );
  });
});
