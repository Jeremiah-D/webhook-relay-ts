import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { appendFileSync, existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SourceBaselineDetector,
  assertValidSourceBaselineOptions,
  tlsFingerprintOf,
  SOURCE_BASELINE_FILE,
  PLAIN_FINGERPRINT,
} from "../src/source-baseline.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: the runtime redaction rewrites all-caps `SECRET` constants in test
// code, so this file uses a non-all-caps name.
const relayKey = "baseline-test-key";
const BODY = Buffer.from(JSON.stringify({ event: "baseline.probe" }));

/** A plain (non-TLS) socket stand-in: no getProtocol/getCipher. */
const PLAIN_SOCKET = {};
/** A TLS-socket stand-in: duck-typed like tls.TLSSocket. */
const TLS_SOCKET = {
  getProtocol: () => "TLSv1.3",
  getCipher: () => ({ name: "TLS_AES_256_GCM_SHA384" }),
};

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: { "x-signature": signSha256(body, relayKey) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          r.destroy();
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
        });
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

function readAnomalies(dir: string): Array<Record<string, unknown>> {
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  return (audit.readAll() as Array<Record<string, unknown>>).filter(
    (e) => e.event === "source_anomaly"
  );
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

describe("source-baseline: tlsFingerprintOf", () => {
  it("marks plain sockets as 'plain'", () => {
    assert.equal(tlsFingerprintOf(PLAIN_SOCKET), "plain");
    assert.equal(tlsFingerprintOf(undefined), "plain");
    assert.equal(tlsFingerprintOf(null), "plain");
    assert.equal(tlsFingerprintOf("garbage"), "plain");
    assert.equal(PLAIN_FINGERPRINT, "plain");
  });

  it("extracts protocol and cipher from a TLS-like socket", () => {
    assert.equal(tlsFingerprintOf(TLS_SOCKET), "TLSv1.3:TLS_AES_256_GCM_SHA384");
  });

  it("uses 'unknown' when the cipher is unavailable", () => {
    const noCipher = { getProtocol: () => "TLSv1.2", getCipher: () => null };
    assert.equal(tlsFingerprintOf(noCipher), "TLSv1.2:unknown");
  });

  it("never throws on a hostile socket", () => {
    const hostile = {
      getProtocol: () => {
        throw new Error("boom");
      },
      getCipher: () => {
        throw new Error("boom");
      },
    };
    assert.equal(tlsFingerprintOf(hostile), "unknown:unknown");
  });
});

describe("source-baseline: detector learning", () => {
  it("learns the first sighting silently (no anomaly)", () => {
    const d = new SourceBaselineDetector({ endpoints: ["/hooks/*"] });
    const out = d.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET);
    assert.equal(out, null);
    assert.equal(d.size, 1);
    const learned = d.learned();
    assert.equal(learned.length, 1);
    assert.equal(learned[0].endpoint, "/hooks/*");
    assert.equal(learned[0].sourceIp, "10.0.0.1");
    assert.equal(learned[0].fingerprint, "plain");
  });

  it("does not re-report a known (ip, fingerprint) triple", () => {
    const d = new SourceBaselineDetector({ endpoints: ["/hooks/*"] });
    assert.equal(d.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET), null);
    assert.equal(d.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET), null);
    assert.equal(d.size, 1);
  });

  it("reports a new source IP on a guarded endpoint", () => {
    const d = new SourceBaselineDetector({
      endpoints: ["/hooks/*"],
      now: () => 1700000000000,
    });
    d.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET);
    const anomaly = d.observe("/hooks/stripe", "10.0.0.2", PLAIN_SOCKET);
    assert.ok(anomaly !== null);
    assert.equal(anomaly.endpoint, "/hooks/*");
    assert.equal(anomaly.path, "/hooks/stripe");
    assert.equal(anomaly.sourceIp, "10.0.0.2");
    assert.equal(anomaly.fingerprint, "plain");
    assert.equal(anomaly.at, "2023-11-14T22:13:20.000Z");
    assert.equal(d.size, 2);
    // The anomaly is now part of the baseline: no repeat reports.
    assert.equal(d.observe("/hooks/stripe", "10.0.0.2", PLAIN_SOCKET), null);
  });

  it("reports a changed TLS fingerprint for a known IP", () => {
    const d = new SourceBaselineDetector({ endpoints: ["/hooks/*"] });
    d.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET);
    const anomaly = d.observe("/hooks/stripe", "10.0.0.1", TLS_SOCKET);
    assert.ok(anomaly !== null);
    assert.equal(anomaly.sourceIp, "10.0.0.1");
    assert.equal(anomaly.fingerprint, "TLSv1.3:TLS_AES_256_GCM_SHA384");
  });

  it("tracks exact and prefix patterns independently, first match wins", () => {
    const d = new SourceBaselineDetector({ endpoints: ["/hooks/stripe", "/hooks/*"] });
    d.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET);
    d.observe("/hooks/other", "10.0.0.1", PLAIN_SOCKET);
    assert.equal(d.size, 2);
    // /hooks/stripe matched the exact rule: same IP on /hooks/other's
    // prefix rule is a separate baseline key but already learned above.
    assert.equal(d.observe("/hooks/other", "10.0.0.1", PLAIN_SOCKET), null);
    const anomaly = d.observe("/hooks/other", "10.0.0.9", PLAIN_SOCKET);
    assert.ok(anomaly !== null);
    assert.equal(anomaly.endpoint, "/hooks/*");
  });

  it("ignores paths with no matching rule", () => {
    const d = new SourceBaselineDetector({ endpoints: ["/hooks/*"] });
    assert.equal(d.observe("/other", "10.0.0.1", PLAIN_SOCKET), null);
    assert.equal(d.size, 0);
  });

  it("treats an empty source IP as 'unknown' without throwing", () => {
    const d = new SourceBaselineDetector({ endpoints: ["/hooks/*"] });
    assert.equal(d.observe("/hooks/stripe", "", PLAIN_SOCKET), null);
    const anomaly = d.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET);
    assert.ok(anomaly !== null);
    assert.equal(anomaly.sourceIp, "10.0.0.1");
  });

  it("never throws on hostile input", () => {
    const d = new SourceBaselineDetector({ endpoints: ["/hooks/*"] });
    assert.equal(d.observe(undefined as unknown as string, undefined as unknown as string, undefined), null);
  });

  it("is inert with no endpoints configured", () => {
    const d = new SourceBaselineDetector();
    assert.equal(d.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET), null);
    assert.equal(d.size, 0);
  });
});

describe("source-baseline: config validation", () => {
  it("accepts valid and empty configs", () => {
    assertValidSourceBaselineOptions({});
    assertValidSourceBaselineOptions({ endpoints: [] });
    assertValidSourceBaselineOptions({ endpoints: ["/hooks/*", "/exact"] });
    assertValidSourceBaselineOptions({ dir: "/tmp/x", now: () => 0 });
  });

  it("throws RangeError on invalid config (fail fast at startup)", () => {
    const bad: unknown[] = [
      { endpoints: "/hooks/*" },
      { endpoints: ["no-leading-slash"] },
      { endpoints: [""] },
      { endpoints: [42] },
      { dir: "" },
      { dir: 42 },
      { now: "not-a-function" },
    ];
    for (const opts of bad) {
      assert.throws(
        () => new SourceBaselineDetector(opts as never),
        RangeError,
        `expected RangeError for ${JSON.stringify(opts)}`
      );
    }
  });
});

describe("source-baseline: persistence round-trip", () => {
  it("survives restarts via append-only JSONL, skipping corrupt lines", () => {
    const dir = mkdtempSync(join(tmpdir(), "source-baseline-"));
    const d1 = new SourceBaselineDetector({ endpoints: ["/hooks/*"], dir });
    // First sighting learns silently; the second triple deviates from the
    // now-established baseline (and is still persisted).
    assert.equal(d1.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET), null);
    const dev = d1.observe("/hooks/stripe", "10.0.0.2", TLS_SOCKET);
    assert.ok(dev !== null && dev.sourceIp === "10.0.0.2");
    const file = join(dir, SOURCE_BASELINE_FILE);
    assert.ok(existsSync(file));
    const lines = readFileSync(file, "utf8").trim().split("\n");
    assert.equal(lines.length, 2);
    // Simulate a torn write and a garbage line from a crash.
    appendFileSync(file, '{"endpoint": "/hooks/*", "broken"\n', "utf8");
    appendFileSync(file, "not json at all\n", "utf8");

    const d2 = new SourceBaselineDetector({ endpoints: ["/hooks/*"], dir });
    assert.equal(d2.size, 2);
    // Recovered triples do not re-trigger and are not re-appended.
    assert.equal(d2.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET), null);
    assert.equal(d2.observe("/hooks/stripe", "10.0.0.2", TLS_SOCKET), null);
    assert.equal(readFileSync(file, "utf8").trim().split("\n").length, 4);
    // But a genuinely new triple still reports.
    const anomaly = d2.observe("/hooks/stripe", "10.0.0.9", PLAIN_SOCKET);
    assert.ok(anomaly !== null);
    assert.equal(anomaly.sourceIp, "10.0.0.9");
    assert.equal(readFileSync(file, "utf8").trim().split("\n").length, 5);
  });

  it("ignores baselines for endpoints that are no longer configured", () => {
    const dir = mkdtempSync(join(tmpdir(), "source-baseline-stale-"));
    const d1 = new SourceBaselineDetector({ endpoints: ["/hooks/*"], dir });
    d1.observe("/hooks/stripe", "10.0.0.1", PLAIN_SOCKET);
    const d2 = new SourceBaselineDetector({ endpoints: ["/other/*"], dir });
    assert.equal(d2.size, 0);
    // And the stale baseline does not suppress a fresh observation.
    const anomaly = d2.observe("/other/x", "10.0.0.1", PLAIN_SOCKET);
    assert.equal(anomaly, null); // first sighting learns silently
    assert.equal(d2.size, 1);
  });
});

describe("source-baseline: relay server integration", () => {
  let dir: string;
  let audit: AuditLog;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), "audit-baseline-"));
    audit = new AuditLog(join(dir, "audit.jsonl"));
  });

  async function start(opts: {
    sourceBaseline: { endpoints: string[]; dir?: string };
    operatorToken?: string;
    forwardUrl?: string;
  }): Promise<{ relay: Server; port: number }> {
    const relay = createRelayServer({
      secret: relayKey,
      forwardUrl: opts.forwardUrl ?? "http://127.0.0.1:9/unused",
      auditLog: audit,
      operatorToken: opts.operatorToken,
      sourceBaseline: opts.sourceBaseline,
    });
    const port = await listen(relay);
    return { relay, port };
  }

  async function stop(relay: Server) {
    relay.close();
    await new Promise((r) => relay.once("close", r));
  }

  it("audits source_anomaly on deviation but still accepts and delivers (alert-only)", async () => {
    // A downstream stub that records every delivery.
    const hits: Buffer[] = [];
    const stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        hits.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    const stubPort = await listen(stub);

    // Pre-seed the baseline with a *different* source IP, so the first
    // real request (from 127.0.0.1) deviates immediately.
    const baselineDir = mkdtempSync(join(tmpdir(), "seeded-baseline-"));
    appendFileSync(
      join(baselineDir, SOURCE_BASELINE_FILE),
      JSON.stringify({
        endpoint: "/hooks/*",
        sourceIp: "203.0.113.9",
        fingerprint: "plain",
        at: "2026-01-01T00:00:00.000Z",
      }) + "\n",
      "utf8"
    );

    const { relay, port } = await start({
      sourceBaseline: { endpoints: ["/hooks/*"], dir: baselineDir },
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
    });
    try {
      const first = await post(port, "/hooks/stripe", BODY);
      assert.equal(first.status, 202);

      // Delivery continues exactly as before — alert-only, no blocking.
      await waitFor(() => hits.length >= 1, 15000, "downstream delivery of deviating request");
      assert.deepEqual(hits[0], BODY);

      const anomalies = readAnomalies(dir);
      assert.equal(anomalies.length, 1);
      const entry = anomalies[0];
      assert.equal(entry.endpoint, "/hooks/*");
      assert.equal(entry.path, "/hooks/stripe");
      assert.equal(entry.fingerprint, "plain");
      assert.ok(typeof entry.sourceIp === "string" && entry.sourceIp.length > 0);
      assert.ok(typeof entry.traceId === "string" && entry.traceId.length > 0);
      // The anomaly discloses only the deviating triple — never the rest
      // of the learned baseline (the seeded 203.0.113.9 must not appear).
      assert.ok(!JSON.stringify(entry).includes("203.0.113.9"));

      // Steady state: the same sender is now baseline — 202, delivered,
      // and no second anomaly.
      const second = await post(port, "/hooks/stripe", BODY);
      assert.equal(second.status, 202);
      await waitFor(() => hits.length >= 2, 15000, "downstream delivery of steady-state request");
      assert.equal(readAnomalies(dir).length, 1);
    } finally {
      await stop(relay);
      stub.close();
    }
  });

  it("first contact learns silently and unguarded paths are untouched", async () => {
    const { relay, port } = await start({
      sourceBaseline: { endpoints: ["/hooks/*"] },
    });
    try {
      const before = readAnomalies(dir).length;
      const res = await post(port, "/hooks/stripe", BODY);
      assert.equal(res.status, 202);
      assert.equal(readAnomalies(dir).length, before);

      const other = await post(port, "/other", BODY);
      assert.equal(other.status, 202);
      assert.equal(readAnomalies(dir).length, before);
    } finally {
      await stop(relay);
    }
  });

  it("invalid sourceBaseline config fails server startup with RangeError", () => {
    assert.throws(
      () =>
        createRelayServer({
          secret: relayKey,
          forwardUrl: "http://127.0.0.1:9/unused",
          auditLog: audit,
          sourceBaseline: { endpoints: ["no-leading-slash"] },
        }),
      RangeError
    );
  });
});
