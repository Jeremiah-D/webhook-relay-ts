/**
 * Benchmark: outbound connection warm-up (WR-70).
 *
 * Measures *first-delivery* latency to a cold origin vs. a warmed origin:
 * each iteration builds a fresh default sender (fresh keep-alive pool),
 * optionally warms it with `warmupOutboundPool`, then times exactly one
 * delivery. The cold case pays the TCP (+ TLS) handshake inside the
 * delivery; the warm case paid it during warm-up.
 *
 * - HTTP: 200 iterations per case against a local stub.
 * - HTTPS with TLS pinning: 100 iterations per case against a local stub
 *   with the self-signed fixture cert (pin whitelist configured,
 *   `rejectUnauthorized: false` — the pin is the trust anchor).
 *
 * Run: `npm run bench:warmup` (or `node bench/warmup-bench.ts`).
 * Prints a Markdown table; paste the numbers into the README.
 */
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { performance } from "node:perf_hooks";
import { cpus, platform, arch } from "node:os";
import { createDefaultSender } from "../src/server.ts";
import { warmupOutboundPool } from "../src/warmup.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "../test/tls-fixture.ts";

const ITERATIONS_HTTP = 200;
const ITERATIONS_HTTPS = 100;

interface ScenarioResult {
  scenario: string;
  iterations: number;
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
  iterations: number,
  tlsPins: Record<string, string[]> | undefined,
  warm: boolean
): Promise<ScenarioResult> {
  const lat: number[] = [];
  for (let i = 0; i < iterations; i++) {
    // Fresh sender (fresh pool) per iteration: every "cold" delivery
    // pays a full handshake; every "warm" delivery reuses the warmed
    // socket.
    const sender = createDefaultSender(tlsPins, {});
    if (warm) {
      const rep = await warmupOutboundPool(sender.pool!, [targetUrl], { tlsPins });
      if (!rep.results[0].ok) throw new Error(`warmup failed: ${rep.results[0].error}`);
    }
    const t0 = performance.now();
    await sender({
      id: `bench-${i}`,
      payload: Buffer.from(JSON.stringify({ n: i })),
      targetUrl,
      headers: {},
    });
    lat.push(performance.now() - t0);
    sender.destroy();
  }
  lat.sort((a, b) => a - b);
  const totalMs = lat.reduce((n, v) => n + v, 0);
  return {
    scenario,
    iterations,
    meanMs: totalMs / iterations,
    p50Ms: quantiles(lat, 0.5),
    p99Ms: quantiles(lat, 0.99),
  };
}

async function main(): Promise<void> {
  const httpStub = createHttpServer((req, res) => {
    req.resume();
    req.on("end", () => res.writeHead(200).end("ok"));
  });
  await new Promise<void>((r) => httpStub.listen(0, "127.0.0.1", r));
  const httpPort = (httpStub.address() as { port: number }).port;
  const httpUrl = `http://127.0.0.1:${httpPort}/hook`;

  const httpsStub = createHttpsServer(
    { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM },
    (req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    }
  );
  await new Promise<void>((r) => httpsStub.listen(0, "127.0.0.1", r));
  const httpsPort = (httpsStub.address() as { port: number }).port;
  const httpsUrl = `https://127.0.0.1:${httpsPort}/hook`;
  const httpsPins = { [httpsUrl]: [TLS_FIXTURE_SPKI_PIN] };

  const results: ScenarioResult[] = [];
  results.push(await runScenario("HTTP first delivery, cold", httpUrl, ITERATIONS_HTTP, undefined, false));
  results.push(await runScenario("HTTP first delivery, warmed", httpUrl, ITERATIONS_HTTP, undefined, true));
  results.push(await runScenario("HTTPS+pins first delivery, cold", httpsUrl, ITERATIONS_HTTPS, httpsPins, false));
  results.push(await runScenario("HTTPS+pins first delivery, warmed", httpsUrl, ITERATIONS_HTTPS, httpsPins, true));

  httpStub.close();
  httpsStub.close();

  const cpu = cpus()[0]?.model ?? "unknown";
  const node = process.version;
  const os = `${platform()} ${arch}`;
  const pad = (s: string, n: number): string => s.padEnd(n);
  const ms = (v: number): string => v.toFixed(2);

  console.log(`\nConnection warm-up benchmark — ${node}, ${cpu}, ${os}`);
  console.log(`(fresh sender+pool per iteration, one timed delivery each, localhost stub)\n`);
  console.log(
    `| ${pad("scenario", 34)} | ${pad("iterations", 10)} | ${pad("mean", 9)} | ${pad("p50", 9)} | ${pad("p99", 9)} |`
  );
  console.log(`|${"-".repeat(36)}|${"-".repeat(12)}|${"-".repeat(11)}|${"-".repeat(11)}|${"-".repeat(11)}|`);
  for (const r of results) {
    console.log(
      `| ${pad(r.scenario, 34)} | ${pad(String(r.iterations), 10)} | ${pad(ms(r.meanMs) + " ms", 9)} | ${pad(ms(r.p50Ms) + " ms", 9)} | ${pad(ms(r.p99Ms) + " ms", 9)} |`
    );
  }
  const [httpCold, httpWarm, httpsCold, httpsWarm] = results;
  console.log(
    `\nFirst-delivery handshake saved: HTTP p50 ${(httpCold.p50Ms - httpWarm.p50Ms).toFixed(2)} ms, ` +
      `HTTPS+pins p50 ${(httpsCold.p50Ms - httpsWarm.p50Ms).toFixed(2)} ms.`
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
