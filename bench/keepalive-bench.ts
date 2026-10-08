/**
 * Benchmark: outbound keep-alive connection pool (WR-24).
 *
 * Compares per-delivery latency of the default sender with the pool
 * enabled vs. disabled (`keepAlive: false` — one fresh connection per
 * delivery), over:
 *
 * - HTTP: 2000 sequential deliveries to a local stub server.
 * - HTTPS with TLS pinning: 400 sequential deliveries to a local stub
 *   server with the self-signed fixture cert (pin whitelist configured,
 *   `rejectUnauthorized: false` — the pin is the trust anchor).
 *
 * Run: `npm run bench:keepalive` (or `node bench/keepalive-bench.ts`).
 * Prints a Markdown table; paste the numbers into the README.
 */
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

interface ScenarioResult {
  scenario: string;
  deliveries: number;
  connections: number;
  totalMs: number;
  meanMs: number;
  p50Ms: number;
  p99Ms: number;
}

function quantiles(sorted: number[], q: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
}

async function runScenario(
  scenario: string,
  targetUrl: string,
  deliveries: number,
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
  for (let i = 0; i < deliveries; i++) {
    const t0 = performance.now();
    await sender(item(i));
    lat.push(performance.now() - t0);
  }
  const totalMs = performance.now() - start;
  const connections = connectionsSeen;
  sender.destroy();
  lat.sort((a, b) => a - b);
  return {
    scenario,
    deliveries,
    connections,
    totalMs,
    meanMs: totalMs / deliveries,
    p50Ms: quantiles(lat, 0.5),
    p99Ms: quantiles(lat, 0.99),
  };
}

let connectionsSeen = 0;

async function main(): Promise<void> {
  // --- HTTP stub ---
  const httpStub = createHttpServer((req, res) => {
    req.resume();
    req.on("end", () => res.writeHead(200).end("ok"));
  });
  httpStub.on("connection", () => connectionsSeen++);
  await new Promise<void>((r) => httpStub.listen(0, "127.0.0.1", r));
  const httpPort = (httpStub.address() as { port: number }).port;
  const httpUrl = `http://127.0.0.1:${httpPort}/hook`;

  // --- HTTPS stub (self-signed fixture) ---
  const httpsStub = createHttpsServer(
    { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
    (req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    }
  );
  httpsStub.on("connection", () => connectionsSeen++);
  await new Promise<void>((r) => httpsStub.listen(0, "127.0.0.1", r));
  const httpsPort = (httpsStub.address() as { port: number }).port;
  const httpsUrl = `https://127.0.0.1:${httpsPort}/hook`;

  const results: ScenarioResult[] = [];

  connectionsSeen = 0;
  results.push(await runScenario("HTTP, no pool", httpUrl, 2000, () => createDefaultSender(undefined, false)));

  connectionsSeen = 0;
  results.push(await runScenario("HTTP, keep-alive pool", httpUrl, 2000, () => createDefaultSender()));

  connectionsSeen = 0;
  results.push(
    await runScenario("HTTPS+pins, no pool", httpsUrl, 400, () =>
      createDefaultSender({ [httpsUrl]: [TLS_FIXTURE_SPKI_PIN] }, false)
    )
  );

  connectionsSeen = 0;
  results.push(
    await runScenario("HTTPS+pins, keep-alive pool", httpsUrl, 400, () =>
      createDefaultSender({ [httpsUrl]: [TLS_FIXTURE_SPKI_PIN] })
    )
  );

  httpStub.close();
  httpsStub.close();

  const cpu = cpus()[0]?.model ?? "unknown";
  const node = process.version;
  const os = `${platform()} ${arch}`;
  const pad = (s: string, n: number): string => s.padEnd(n);

  console.log(`\nKeep-alive pool benchmark — ${node}, ${cpu}, ${os}`);
  console.log(`(${WARMUP} warmup deliveries per scenario, sequential, localhost stub)\n`);
  console.log(
    `| ${pad("scenario", 26)} | ${pad("deliveries", 10)} | ${pad("connections", 11)} | ${pad("total", 10)} | ${pad("mean", 9)} | ${pad("p50", 9)} | ${pad("p99", 9)} |`
  );
  console.log(`|${"-".repeat(28)}|${"-".repeat(12)}|${"-".repeat(13)}|${"-".repeat(12)}|${"-".repeat(11)}|${"-".repeat(11)}|${"-".repeat(11)}|`);
  for (const r of results) {
    const f = (n: number): string => `${n.toFixed(2)} ms`;
    console.log(
      `| ${pad(r.scenario, 26)} | ${pad(String(r.deliveries), 10)} | ${pad(String(r.connections), 11)} | ${pad(f(r.totalMs), 10)} | ${pad(f(r.meanMs), 9)} | ${pad(f(r.p50Ms), 9)} | ${pad(f(r.p99Ms), 9)} |`
    );
  }
  const [a, b, c, d] = results;
  console.log(
    `\nSpeedup (total time): HTTP ${(a.totalMs / b.totalMs).toFixed(1)}x, HTTPS+pins ${(c.totalMs / d.totalMs).toFixed(1)}x.`
  );
}

void main();
