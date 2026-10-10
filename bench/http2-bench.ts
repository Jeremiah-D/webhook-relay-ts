/**
 * Benchmark: outbound HTTP/2 session reuse (WR-42).
 *
 * Compares high-concurrency delivery throughput of the default sender
 * with HTTP/2 enabled vs. the HTTP/1.1 keep-alive pool (WR-24), over:
 *
 * - HTTP: 1500 deliveries at 100-way concurrency to a local h2c stub.
 * - HTTPS with TLS pinning: 400 deliveries at 50-way concurrency to a
 *   local stub with the self-signed fixture cert (pin whitelist
 *   configured, `rejectUnauthorized: false` — the pin is the trust
 *   anchor).
 *
 * The H2 arms enable `outboundHttp2: { enabled: true, hosts: [...] }`;
 * the H1.1 arms use the default keep-alive pool. A refused-H2 control is
 * not needed here — the fallback path is covered by test/http2.test.ts.
 *
 * Run: `npm run bench:http2` (or `node bench/http2-bench.ts`).
 * Prints a Markdown table; paste the numbers into the README.
 */
import { createServer as createH2Server, createSecureServer as createH2SecureServer } from "node:http2";
import type { Http2Server } from "node:http2";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { performance } from "node:perf_hooks";
import { cpus, platform, arch } from "node:os";
import { createDefaultSender } from "../src/server.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "../test/tls-fixture.ts";

const WARMUP = 50;
const HTTP_DELIVERIES = 1500;
const HTTP_CONCURRENCY = 100;
const HTTPS_DELIVERIES = 400;
const HTTPS_CONCURRENCY = 50;

interface ScenarioResult {
  scenario: string;
  deliveries: number;
  concurrency: number;
  connections: number;
  totalMs: number;
  meanMs: number;
  p50Ms: number;
  p99Ms: number;
}

function quantiles(sorted: number[], q: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
}

/** Run `deliveries` deliveries at `concurrency`-way parallelism. */
async function runScenario(
  scenario: string,
  targetUrl: string,
  deliveries: number,
  concurrency: number,
  makeSender: () => ReturnType<typeof createDefaultSender>
): Promise<ScenarioResult> {
  const sender = makeSender();
  const item = (n: number) => ({
    id: `bench-${n}`,
    payload: Buffer.from(JSON.stringify({ n })),
    targetUrl,
    headers: {},
  });
  for (let i = 0; i < WARMUP; i++) await sender(item(i));
  const lat: number[] = [];
  const start = performance.now();
  for (let done = 0; done < deliveries; done += concurrency) {
    const batch: Promise<unknown>[] = [];
    for (let i = done; i < Math.min(done + concurrency, deliveries); i++) {
      const t0 = performance.now();
      batch.push(
        sender(item(i)).then(() => {
          lat.push(performance.now() - t0);
        })
      );
    }
    await Promise.all(batch);
  }
  const totalMs = performance.now() - start;
  const connections = connectionsSeen;
  const h2stats = sender.http2Pool?.getStats();
  sender.destroy();
  lat.sort((a, b) => a - b);
  return {
    scenario:
      h2stats !== undefined
        ? `${scenario} (h2 sessions: ${h2stats.established}, reused: ${h2stats.reused}, fallback: ${h2stats.fallback})`
        : scenario,
    deliveries,
    concurrency,
    connections,
    totalMs,
    meanMs: totalMs / deliveries,
    p50Ms: quantiles(lat, 0.5),
    p99Ms: quantiles(lat, 0.99),
  };
}

let connectionsSeen = 0;

function h2Stub(): Http2Server {
  const server = createH2Server();
  server.on("connection", () => connectionsSeen++);
  server.on("stream", (stream) => {
    stream.resume();
    stream.on("end", () => {
      stream.respond({ ":status": 200 });
      stream.end("ok");
    });
  });
  return server;
}

async function main(): Promise<void> {
  // --- plain HTTP/1.1 stub (for the H1.1 arm) ---
  const h1Stub = createHttpServer((req, res) => {
    req.resume();
    req.on("end", () => res.writeHead(200).end("ok"));
  });
  h1Stub.on("connection", () => connectionsSeen++);
  await new Promise<void>((r) => h1Stub.listen(0, "127.0.0.1", r));
  const h1Port = (h1Stub.address() as { port: number }).port;
  const h1Url = `http://127.0.0.1:${h1Port}/hook`;

  // --- h2c stub (for the H2 arm) ---
  const h2cStub = h2Stub();
  await new Promise<void>((r) => h2cStub.listen(0, "127.0.0.1", r));
  const h2cPort = (h2cStub.address() as { port: number }).port;
  const h2cUrl = `http://127.0.0.1:${h2cPort}/hook`;

  // --- HTTPS/1.1 stub (self-signed fixture, for the H1.1 arm) ---
  const https1Stub = createHttpsServer(
    { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
    (req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    }
  );
  https1Stub.on("connection", () => connectionsSeen++);
  await new Promise<void>((r) => https1Stub.listen(0, "127.0.0.1", r));
  const https1Port = (https1Stub.address() as { port: number }).port;
  const https1Url = `https://127.0.0.1:${https1Port}/hook`;

  // --- HTTPS stub (self-signed fixture), speaks H2 ---
  const httpsStub = createH2SecureServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM });
  httpsStub.on("connection", () => connectionsSeen++);
  httpsStub.on("stream", (stream) => {
    stream.resume();
    stream.on("end", () => {
      stream.respond({ ":status": 200 });
      stream.end("ok");
    });
  });
  await new Promise<void>((r) => httpsStub.listen(0, "127.0.0.1", r));
  const httpsPort = (httpsStub.address() as { port: number }).port;
  const httpsUrl = `https://127.0.0.1:${httpsPort}/hook`;

  const h2 = { enabled: true, hosts: ["127.0.0.1"] };
  const results: ScenarioResult[] = [];

  connectionsSeen = 0;
  results.push(
    await runScenario("HTTP/1.1 keep-alive pool", h1Url, HTTP_DELIVERIES, HTTP_CONCURRENCY, () =>
      createDefaultSender()
    )
  );

  connectionsSeen = 0;
  results.push(
    await runScenario("HTTP/2 (h2c)", h2cUrl, HTTP_DELIVERIES, HTTP_CONCURRENCY, () =>
      createDefaultSender(undefined, undefined, undefined, undefined, undefined, undefined, h2)
    )
  );

  connectionsSeen = 0;
  results.push(
    await runScenario("HTTPS+pins, HTTP/1.1 pool", https1Url, HTTPS_DELIVERIES, HTTPS_CONCURRENCY, () =>
      createDefaultSender({ [https1Url]: [TLS_FIXTURE_SPKI_PIN] })
    )
  );

  connectionsSeen = 0;
  results.push(
    await runScenario("HTTPS+pins, HTTP/2", httpsUrl, HTTPS_DELIVERIES, HTTPS_CONCURRENCY, () =>
      createDefaultSender(
        { [httpsUrl]: [TLS_FIXTURE_SPKI_PIN] },
        undefined, undefined, undefined, undefined, undefined, h2
      )
    )
  );

  h1Stub.close();
  https1Stub.close();
  h2cStub.close();
  httpsStub.close();

  const cpu = cpus()[0]?.model ?? "unknown";
  const node = process.version;
  const os = `${platform()} ${arch}`;
  const pad = (s: string, n: number): string => s.padEnd(n);

  console.log(`\nHTTP/2 session-reuse benchmark — ${node}, ${cpu}, ${os}`);
  console.log(`(${WARMUP} warmup deliveries per scenario, localhost stub; connection counts include warmup)\n`);
  console.log(
    `| ${pad("scenario", 30)} | ${pad("deliveries", 10)} | ${pad("concurrency", 11)} | ${pad("connections", 11)} | ${pad("total", 10)} | ${pad("mean", 9)} | ${pad("p50", 9)} | ${pad("p99", 9)} |`
  );
  console.log(
    `|${"-".repeat(32)}|${"-".repeat(12)}|${"-".repeat(13)}|${"-".repeat(13)}|${"-".repeat(12)}|${"-".repeat(11)}|${"-".repeat(11)}|${"-".repeat(11)}|`
  );
  for (const r of results) {
    const f = (n: number): string => `${n.toFixed(2)} ms`;
    console.log(
      `| ${pad(r.scenario, 30)} | ${pad(String(r.deliveries), 10)} | ${pad(String(r.concurrency), 11)} | ${pad(String(r.connections), 11)} | ${pad(f(r.totalMs), 10)} | ${pad(f(r.meanMs), 9)} | ${pad(f(r.p50Ms), 9)} | ${pad(f(r.p99Ms), 9)} |`
    );
  }
  const [a, b, c, d] = results;
  console.log(
    `\nSpeedup (total time): HTTP ${(a.totalMs / b.totalMs).toFixed(1)}x, HTTPS+pins ${(c.totalMs / d.totalMs).toFixed(1)}x.`
  );
}

void main();
