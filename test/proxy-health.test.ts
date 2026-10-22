import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { connect as tcpConnect, type Socket } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ProxyHealthMonitor,
  redactProxyUrl,
  type ProxyHealthAuditEvent,
} from "../src/proxy-health.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const signingSecret = "wr181-test-secret";
const deadProxy = "http://127.0.0.1:1/sick";
const body = JSON.stringify({ hello: "proxy-health" });

/** A fake successful CONNECT: no network, just a destroyable handle. */
function fakeSocket(): Socket {
  return { destroy: () => undefined } as unknown as Socket;
}

function failingConnect(): Promise<Socket> {
  return Promise.reject(new Error("TCP connect to proxy failed: ECONNREFUSED"));
}

function okConnect(): Promise<Socket> {
  return Promise.resolve(fakeSocket());
}

describe("redactProxyUrl", () => {
  it("strips userinfo so credentials never reach labels or audits", () => {
    assert.equal(redactProxyUrl("http://user:pass@proxy:8080"), "http://proxy:8080");
    assert.equal(redactProxyUrl("http://proxy:8080"), "http://proxy:8080");
  });
  it("returns unparsable input unchanged", () => {
    assert.equal(redactProxyUrl("not a url"), "not a url");
  });
});

describe("ProxyHealthMonitor construction", () => {
  it("throws RangeError on invalid numeric options", () => {
    for (const intervalMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(() => new ProxyHealthMonitor({ intervalMs }), RangeError);
    }
    for (const probeTimeoutMs of [0, -1, Number.NaN]) {
      assert.throws(() => new ProxyHealthMonitor({ probeTimeoutMs }), RangeError);
    }
    for (const failureThreshold of [0, -1, 1.5, Number.NaN]) {
      assert.throws(() => new ProxyHealthMonitor({ failureThreshold }), RangeError);
    }
    assert.throws(
      () => new ProxyHealthMonitor({ probeTarget: { host: "", port: 443 } }),
      RangeError
    );
    assert.throws(
      () => new ProxyHealthMonitor({ probeTarget: { host: "h", port: 0 } }),
      RangeError
    );
    assert.throws(
      () => new ProxyHealthMonitor({ probeTarget: { host: "h", port: 65536 } }),
      RangeError
    );
  });
  it("throws RangeError on invalid proxies entries at startup", () => {
    assert.throws(() => new ProxyHealthMonitor({ proxies: [""] }), RangeError);
    assert.throws(() => new ProxyHealthMonitor({ proxies: ["not a url"] }), RangeError);
    assert.throws(
      () => new ProxyHealthMonitor({ proxies: ["https://proxy:8080"] }),
      RangeError
    );
  });
  it("skips socks5:// entries (CONNECT probing only)", () => {
    const m = new ProxyHealthMonitor({ proxies: ["socks5://proxy:1080"] });
    assert.deepEqual(m.stats(), []);
    assert.equal(m.renderMetrics(), "");
  });
  it("accepts sane values", () => {
    const m = new ProxyHealthMonitor({
      proxies: ["http://proxy:8080"],
      intervalMs: 1000,
      probeTimeoutMs: 500,
      failureThreshold: 2,
      probeTarget: { host: "example.com", port: 443 },
    });
    assert.equal(m.stats().length, 1);
    assert.equal(m.stats()[0].healthy, true);
  });
});

describe("ProxyHealthMonitor probing", () => {
  it("marks a proxy unhealthy after failureThreshold consecutive failures", async () => {
    const audits: ProxyHealthAuditEvent[] = [];
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      failureThreshold: 2,
      connect: failingConnect,
      onAudit: (e) => audits.push(e),
    });
    assert.equal(m.isHealthy(deadProxy), true); // no evidence yet
    await m.runRound(deadProxy);
    assert.equal(m.isHealthy(deadProxy), true); // below threshold
    assert.deepEqual(
      audits.filter((e) => e.event === "proxy_unhealthy"),
      []
    );
    await m.runRound(deadProxy);
    assert.equal(m.isHealthy(deadProxy), false);
    const unhealthy = audits.filter((e) => e.event === "proxy_unhealthy");
    assert.equal(unhealthy.length, 1);
    assert.equal(unhealthy[0].event, "proxy_unhealthy");
    assert.equal((unhealthy[0] as { consecutiveFailures: number }).consecutiveFailures, 2);
    // further failures do not re-audit the same transition
    await m.runRound(deadProxy);
    assert.equal(audits.filter((e) => e.event === "proxy_unhealthy").length, 1);
    m.stop();
  });
  it("re-admits on the first successful probe (canary) and audits recovery", async () => {
    const audits: ProxyHealthAuditEvent[] = [];
    let fail = true;
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      failureThreshold: 1,
      connect: () => (fail ? failingConnect() : okConnect()),
      onAudit: (e) => audits.push(e),
    });
    await m.runRound(deadProxy);
    assert.equal(m.isHealthy(deadProxy), false);
    fail = false;
    await m.runRound(deadProxy);
    assert.equal(m.isHealthy(deadProxy), true);
    const recovered = audits.filter((e) => e.event === "proxy_recovered");
    assert.equal(recovered.length, 1);
    assert.equal(recovered[0].proxyUrl, deadProxy);
    m.stop();
  });
  it("a throwing probe implementation counts as a failure, not a crash", async () => {
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      failureThreshold: 1,
      connect: () => {
        throw new Error("buggy probe");
      },
    });
    const results = await m.runRound(deadProxy);
    assert.equal(results[0].ok, false);
    assert.equal(m.isHealthy(deadProxy), false);
    m.stop();
  });
  it("ensureTracked lazily tracks dispatch-time proxies without throwing", () => {
    const m = new ProxyHealthMonitor();
    assert.equal(m.ensureTracked("http://env-proxy:8080"), true);
    assert.equal(m.isHealthy("http://env-proxy:8080"), true); // unknown = healthy
    assert.equal(m.ensureTracked("socks5://proxy:1080"), false);
    assert.equal(m.ensureTracked("bogus"), false);
    assert.equal(m.ensureTracked("http://env-proxy:8080"), true); // idempotent
    m.stop();
  });
  it("start/stop drive the injected schedule and clear it", async () => {
    const scheduled: Array<() => void> = [];
    let cleared = 0;
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      intervalMs: 50,
      failureThreshold: 99, // never trips in this test
      connect: failingConnect,
      setTimer: (fn) => {
        scheduled.push(fn);
        return { clear: () => { cleared += 1; } };
      },
    });
    m.start();
    assert.equal(scheduled.length, 1);
    await scheduled[0]!(); // one manual tick
    const s = m.stats()[0];
    assert.equal(s.failure, 1);
    assert.equal(s.healthy, true);
    assert.equal(scheduled.length, 2); // the tick re-scheduled the next round
    m.start(); // idempotent: no extra schedule
    assert.equal(scheduled.length, 2);
    m.stop();
    assert.equal(cleared, 1);
  });
});

describe("ProxyHealthMonitor.resolveProxy", () => {
  const backup = "http://backup:8080";
  function sickMonitor(
    audits: ProxyHealthAuditEvent[],
    opts: { directFallback?: boolean } = {}
  ): ProxyHealthMonitor {
    return new ProxyHealthMonitor({
      proxies: [deadProxy, backup],
      failureThreshold: 1,
      connect: (url) => (url === deadProxy ? failingConnect() : okConnect()),
      onAudit: (e) => audits.push(e),
      directFallback: opts.directFallback,
    });
  }
  it("uses the configured proxy when healthy", () => {
    const audits: ProxyHealthAuditEvent[] = [];
    const m = sickMonitor(audits);
    const d = m.resolveProxy(deadProxy, { targetUrl: "http://x/hook" });
    assert.deepEqual(d, { proxyUrl: deadProxy, degraded: false });
    assert.equal(audits.length, 0);
    m.stop();
  });
  it("degrades to a healthy backup proxy and audits proxy_degraded", async () => {
    const audits: ProxyHealthAuditEvent[] = [];
    const m = sickMonitor(audits);
    await m.runRound(deadProxy);
    const d = m.resolveProxy(deadProxy, { targetUrl: "http://x/hook" });
    assert.equal(d.degraded, true);
    assert.equal(d.reason, "backup_proxy");
    assert.equal(d.proxyUrl, backup);
    assert.equal(d.from, deadProxy);
    const degraded = audits.filter((e) => e.event === "proxy_degraded");
    assert.equal(degraded.length, 1);
    assert.deepEqual(degraded[0], {
      event: "proxy_degraded",
      targetUrl: "http://x/hook",
      proxyUrl: deadProxy,
      usedProxyUrl: backup,
      reason: "backup_proxy",
    });
    m.stop();
  });
  it("degrades to direct when no healthy backup exists", async () => {
    const audits: ProxyHealthAuditEvent[] = [];
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      failureThreshold: 1,
      connect: failingConnect,
      onAudit: (e) => audits.push(e),
    });
    await m.runRound(deadProxy);
    const d = m.resolveProxy(deadProxy, { targetUrl: "http://x/hook" });
    assert.equal(d.degraded, true);
    assert.equal(d.reason, "direct");
    assert.equal(d.proxyUrl, undefined);
    m.stop();
  });
  it("stays on the sick proxy when directFallback is false (normal retry path)", async () => {
    const audits: ProxyHealthAuditEvent[] = [];
    const m = new ProxyHealthMonitor({
      proxies: [deadProxy],
      failureThreshold: 1,
      connect: failingConnect,
      onAudit: (e) => audits.push(e),
      directFallback: false,
    });
    await m.runRound(deadProxy);
    const d = m.resolveProxy(deadProxy, { targetUrl: "http://x/hook" });
    assert.equal(d.degraded, true);
    assert.equal(d.reason, "no_healthy_proxy");
    assert.equal(d.proxyUrl, deadProxy); // never silently dropped
    m.stop();
  });
  it("redacts credentials in degraded audits", async () => {
    const audits: ProxyHealthAuditEvent[] = [];
    const secreted = "http://user:hunter2@127.0.0.1:2";
    const m = new ProxyHealthMonitor({
      proxies: [secreted, backup],
      failureThreshold: 1,
      connect: (url) => (url === secreted ? failingConnect() : okConnect()),
      onAudit: (e) => audits.push(e),
    });
    await m.runRound(secreted);
    const d = m.resolveProxy(secreted, { targetUrl: "http://x/hook" });
    assert.equal(d.reason, "backup_proxy");
    const degraded = audits.filter((e) => e.event === "proxy_degraded");
    assert.equal(degraded.length, 1);
    const asJson = JSON.stringify(degraded[0]);
    assert.ok(!asJson.includes("hunter2"), "password must not leak into audits");
    assert.ok(asJson.includes("http://127.0.0.1:2"));
    const stats = m.stats();
    assert.ok(!JSON.stringify(stats).includes("hunter2"));
    m.stop();
  });
});

describe("ProxyHealthMonitor.renderMetrics", () => {
  it("renders one relay_proxy_unhealthy gauge per tracked proxy", async () => {
    const m = new ProxyHealthMonitor({
      proxies: ["http://a:8080", "http://b:8080"],
      failureThreshold: 1,
      connect: (url) => (url === "http://a:8080" ? failingConnect() : okConnect()),
    });
    await m.runRound("http://a:8080");
    const out = m.renderMetrics();
    assert.ok(out.includes("# TYPE relay_proxy_unhealthy gauge"));
    assert.ok(out.includes('relay_proxy_unhealthy{proxy_url="http://a:8080"} 1'));
    assert.ok(out.includes('relay_proxy_unhealthy{proxy_url="http://b:8080"} 0'));
    m.stop();
  });
  it("never emits proxy credentials in metrics labels", async () => {
    const m = new ProxyHealthMonitor({
      proxies: ["http://user:hunter2@127.0.0.1:2"],
      failureThreshold: 1,
      connect: failingConnect,
    });
    await m.runRound();
    const out = m.renderMetrics();
    assert.ok(!out.includes("hunter2"));
    assert.ok(out.includes('proxy_url="http://127.0.0.1:2"'));
    m.stop();
  });
});

describe("server: proxy health failover (WR-181)", () => {
  let downstream: Server;
  let downstreamPort: number;
  let backupProxy: Server;
  let backupPort: number;
  const downstreamHits: string[] = [];
  const backupConnects: string[] = [];

  function listenOn(server: Server): Promise<number> {
    return new Promise((resolve, reject) => {
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (addr !== null && typeof addr === "object") resolve(addr.port);
        else reject(new Error("no address"));
      });
    });
  }

  before(async () => {
    downstream = createServer((req, res) => {
      downstreamHits.push(`${req.method} ${req.url}`);
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    downstreamPort = await listenOn(downstream);
    // Minimal fake CONNECT proxy: tunnels to the requested host:port.
    backupProxy = createServer();
    backupProxy.on("connect", (req, clientSocket) => {
      const [host, port] = (req.url ?? "").split(":");
      backupConnects.push(req.url ?? "");
      const upstream = tcpConnect(Number(port), host, () => {
        clientSocket.write("HTTP/1.1 200 Connection established\r\n\r\n");
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.on("error", () => {
        clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        clientSocket.destroy();
      });
      clientSocket.on("error", () => upstream.destroy());
    });
    backupPort = await listenOn(backupProxy);
  });

  after(async () => {
    downstream.close();
    backupProxy.close();
  });

  it("routes around a sick preferred proxy via a healthy backup", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wr181-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const target = `http://127.0.0.1:${downstreamPort}/hook`;
    const sickProxyUrl = `http://127.0.0.1:1/sick`; // nothing listens: refused
    const goodProxyUrl = `http://127.0.0.1:${backupPort}`;
    const relay = createRelayServer({
      secret: signingSecret,
      forwardUrl: target,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
      proxies: {
        [target]: sickProxyUrl,
        "http://127.0.0.1:1/unused-endpoint": goodProxyUrl,
      },
      proxyHealth: {
        intervalMs: 25,
        failureThreshold: 1,
        // Fake the probe network: the sick proxy refuses, the backup is fine.
        connect: (proxyUrl) =>
          proxyUrl === sickProxyUrl ? failingConnect() : okConnect(),
      },
    });
    const relayPort = await listenOn(relay);
    try {
      // Let a couple of probe rounds mark the sick proxy unhealthy.
      const stats = await waitFor(
        () => relay.getProxyHealthStats?.() ?? [],
        (s) => s.some((p) => p.proxyUrl === sickProxyUrl && !p.healthy)
      );
      assert.ok(
        stats.some((p) => p.proxyUrl === sickProxyUrl && !p.healthy),
        "sick proxy must be marked unhealthy"
      );
      assert.ok(
        stats.some((p) => p.proxyUrl === goodProxyUrl && p.healthy),
        "backup proxy must stay healthy"
      );
      // Deliver through the relay: it must take the backup proxy.
      const res = await post(relayPort, "/", body, {
        "x-signature": signSha256(body, signingSecret),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => downstreamHits, (h) => h.length > 0);
      assert.ok(downstreamHits.length > 0, "downstream must receive the delivery");
      assert.ok(
        backupConnects.some((c) => c === `127.0.0.1:${downstreamPort}`),
        `backup proxy must see CONNECT to downstream, saw: ${backupConnects.join(",")}`
      );
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const degraded = events.filter((e) => e["event"] === "proxy_degraded");
      assert.ok(degraded.length > 0, "proxy_degraded must be audited");
      assert.equal(degraded[0]["reason"], "backup_proxy");
      assert.equal(degraded[0]["proxyUrl"], sickProxyUrl);
      assert.equal(degraded[0]["usedProxyUrl"], goodProxyUrl);
      const unhealthy = events.filter((e) => e["event"] === "proxy_unhealthy");
      assert.ok(unhealthy.length > 0, "proxy_unhealthy must be audited");
      assert.ok(relay.getProxyHealthStats !== undefined);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});

/** Poll `read()` until `done()` or a 5s timeout. */
async function waitFor<T>(read: () => T, done: (v: T) => boolean): Promise<T> {
  const deadline = Date.now() + 5000;
  for (;;) {
    const v = read();
    if (done(v)) return v;
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}

async function post(
  port: number,
  path: string,
  bodyText: string,
  headers: Record<string, string>
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end(bodyText);
  });
}
