import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, Agent as HttpAgent, request as httpRequest } from "node:http";
import type { LookupAddress } from "node:dns";
import { DnsCache } from "../src/dns-cache.ts";
import { createDefaultSender } from "../src/server.ts";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const PROXY_ENV_VARS = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
  "NO_PROXY",
  "no_proxy",
];

/**
 * Run `fn` with the proxy-related environment replaced; restore
 * afterwards. The sandbox sets an egress proxy (`HTTP_PROXY` etc.);
 * tests talking to `relay-fake.invalid` must not be routed through it
 * (WR-27 env fallback), so they clear the proxy env the way
 * `test/proxy.test.ts` does.
 */
async function withProxyEnv(
  vars: Record<string, string | undefined>,
  fn: () => Promise<void>
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const k of PROXY_ENV_VARS) saved[k] = process.env[k];
  try {
    for (const k of PROXY_ENV_VARS) delete process.env[k];
    for (const [k, v] of Object.entries(vars)) {
      if (v !== undefined) process.env[k] = v;
    }
    await fn();
  } finally {
    for (const k of PROXY_ENV_VARS) delete process.env[k];
    for (const [k, v] of Object.entries(saved)) {
      if (v !== undefined) process.env[k] = v;
    }
  }
}

/** Controllable clock + resolver so no test touches real DNS. */
function harness(opts: {
  ttlMs?: number;
  refreshBackoffMs?: number;
  maxHosts?: number;
  addresses?: LookupAddress[];
  failWith?: string;
} = {}) {
  let nowMs = 1_000_000;
  let resolveCalls = 0;
  const addresses = opts.addresses ?? [
    { address: "127.0.0.1", family: 4 },
    { address: "::1", family: 6 },
  ];
  const cache = new DnsCache({
    ttlMs: opts.ttlMs,
    refreshBackoffMs: opts.refreshBackoffMs,
    maxHosts: opts.maxHosts,
    now: () => nowMs,
    resolve: async () => {
      resolveCalls++;
      await sleep(1);
      if (opts.failWith !== undefined) {
        const err = new Error(opts.failWith) as NodeJS.ErrnoException;
        err.code = "ENOTFOUND";
        throw err;
      }
      return addresses;
    },
  });
  return {
    cache,
    get resolveCalls() {
      return resolveCalls;
    },
    advance(ms: number) {
      nowMs += ms;
    },
  };
}

function lookupAsync(
  cache: DnsCache,
  hostname: string,
  options: { family?: number; all?: boolean } = {}
): Promise<{ err: NodeJS.ErrnoException | null; address: string | LookupAddress[]; family?: number }> {
  return new Promise((resolve) => {
    (cache.lookup as (...args: unknown[]) => void)(
      hostname,
      options,
      (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) =>
        resolve({ err, address, family })
    );
  });
}

describe("dns-cache: option validation", () => {
  it("rejects invalid values with RangeError at construction", () => {
    assert.throws(() => new DnsCache({ ttlMs: 0 }), RangeError);
    assert.throws(() => new DnsCache({ ttlMs: -1 }), RangeError);
    assert.throws(() => new DnsCache({ ttlMs: NaN }), RangeError);
    assert.throws(() => new DnsCache({ ttlMs: Infinity }), RangeError);
    assert.throws(() => new DnsCache({ refreshBackoffMs: -1 }), RangeError);
    assert.throws(() => new DnsCache({ maxHosts: 0 }), RangeError);
    assert.throws(() => new DnsCache({ maxHosts: 1.5 }), RangeError);
    assert.throws(() => new DnsCache({ now: 42 as unknown as () => number }), RangeError);
    assert.throws(() => new DnsCache({ resolve: "x" as unknown as () => Promise<LookupAddress[]> }), RangeError);
  });

  it("accepts a zero refresh backoff (refresh on every expired lookup)", () => {
    const c = new DnsCache({ refreshBackoffMs: 0, resolve: async () => [] });
    assert.ok(c);
  });
});

describe("dns-cache: lookup behavior", () => {
  it("miss resolves on demand, then serves fresh hits without re-resolving", async () => {
    const h = harness();
    const first = await lookupAsync(h.cache, "api.example.test");
    assert.equal(first.err, null);
    assert.equal(first.address, "127.0.0.1");
    assert.equal(first.family, 4);
    assert.equal(h.resolveCalls, 1);
    const second = await lookupAsync(h.cache, "api.example.test");
    assert.equal(second.err, null);
    assert.equal(second.address, "127.0.0.1");
    assert.equal(h.resolveCalls, 1);
    assert.deepEqual(h.cache.getStats(), {
      hosts: 1,
      hits: 1,
      misses: 1,
      staleServed: 0,
      refreshes: 0,
      refreshFailures: 0,
      hitRate: 0.5,
    });
  });

  it("expired entries are served stale while a background refresh runs (single-flight)", async () => {
    const h = harness({ ttlMs: 1000 });
    await lookupAsync(h.cache, "api.example.test");
    assert.equal(h.resolveCalls, 1);
    h.advance(1500); // expire the entry
    // three concurrent expired lookups: one background refresh, all served stale
    const results = await Promise.all([
      lookupAsync(h.cache, "api.example.test"),
      lookupAsync(h.cache, "api.example.test"),
      lookupAsync(h.cache, "api.example.test"),
    ]);
    for (const r of results) {
      assert.equal(r.err, null);
      assert.equal(r.address, "127.0.0.1");
    }
    assert.equal(h.resolveCalls, 2); // single-flight: exactly one refresh
    await sleep(10); // let the refresh settle
    const stats = h.cache.getStats();
    assert.equal(stats.staleServed, 3);
    assert.equal(stats.refreshes, 1);
    assert.equal(stats.refreshFailures, 0);
    // the entry is fresh again — the next lookup is a hit, no new resolve
    const after = await lookupAsync(h.cache, "api.example.test");
    assert.equal(after.err, null);
    assert.equal(h.resolveCalls, 2);
    assert.equal(h.cache.getStats().hits, 1);
  });

  it("a failed refresh keeps serving stale; the error never reaches the caller", async () => {
    let shouldFail = false;
    let nowMs = 1_000_000;
    let resolveCalls = 0;
    const cache = new DnsCache({
      ttlMs: 1000,
      refreshBackoffMs: 5000,
      now: () => nowMs,
      resolve: async () => {
        resolveCalls++;
        await sleep(1);
        if (shouldFail) {
          const err = new Error("resolver down") as NodeJS.ErrnoException;
          err.code = "EAI_AGAIN";
          throw err;
        }
        return [{ address: "127.0.0.1", family: 4 }];
      },
    });
    await lookupAsync(cache, "api.example.test");
    assert.equal(resolveCalls, 1);
    shouldFail = true;
    nowMs += 1500; // expire
    const stale = await lookupAsync(cache, "api.example.test");
    assert.equal(stale.err, null); // no error to the caller
    assert.equal(stale.address, "127.0.0.1");
    await sleep(10);
    assert.equal(resolveCalls, 2);
    assert.equal(cache.getStats().refreshFailures, 1);
    // backoff suppresses refresh attempts: another expired lookup inside
    // the backoff window serves stale without re-resolving
    nowMs += 1000;
    await lookupAsync(cache, "api.example.test");
    await sleep(10);
    assert.equal(resolveCalls, 2);
    assert.equal(cache.getStats().staleServed, 2);
    // after the backoff elapses, the next expired lookup retries the refresh
    nowMs += 5000;
    shouldFail = false;
    const recovered = await lookupAsync(cache, "api.example.test");
    assert.equal(recovered.err, null);
    await sleep(10);
    assert.equal(resolveCalls, 3);
    assert.equal(cache.getStats().refreshFailures, 1);
  });

  it("with no cached entry at all, a DNS error propagates to the caller", async () => {
    const h = harness({ failWith: "no such host" });
    const r = await lookupAsync(h.cache, "missing.example.test");
    assert.ok(r.err instanceof Error);
    assert.equal(r.err.code, "ENOTFOUND");
    // failures are never cached: the next lookup tries again
    const r2 = await lookupAsync(h.cache, "missing.example.test");
    assert.ok(r2.err instanceof Error);
    assert.equal(h.resolveCalls, 2);
    assert.equal(h.cache.getStats().misses, 2);
  });

  it("an empty resolver answer is a failure, not a cached entry", async () => {
    const h = harness({ addresses: [] });
    const r = await lookupAsync(h.cache, "empty.example.test");
    assert.ok(r.err instanceof Error);
    assert.equal(r.err.code, "ENOTFOUND");
    assert.equal(h.cache.getStats().hosts, 0);
  });

  it("filters by family; honest ENOTFOUND when the family is absent", async () => {
    const h = harness();
    const v4 = await lookupAsync(h.cache, "api.example.test", { family: 4 });
    assert.equal(v4.address, "127.0.0.1");
    assert.equal(v4.family, 4);
    const v6 = await lookupAsync(h.cache, "api.example.test", { family: 6 });
    assert.equal(v6.address, "::1");
    assert.equal(v6.family, 6);
    const v4only = harness({ addresses: [{ address: "127.0.0.1", family: 4 }] });
    const noV6 = await lookupAsync(v4only.cache, "api.example.test", { family: 6 });
    assert.ok(noV6.err instanceof Error);
    assert.equal(noV6.err.code, "ENOTFOUND");
  });

  it("supports { all: true } with an address list", async () => {
    const h = harness();
    const r = await lookupAsync(h.cache, "api.example.test", { all: true });
    assert.equal(r.err, null);
    assert.ok(Array.isArray(r.address));
    assert.deepEqual(r.address, [
      { address: "127.0.0.1", family: 4 },
      { address: "::1", family: 6 },
    ]);
  });

  it("rejects empty hostnames with ENOTFOUND", async () => {
    const h = harness();
    const r = await lookupAsync(h.cache, "");
    assert.ok(r.err instanceof Error);
    assert.equal(r.err.code, "ENOTFOUND");
    assert.equal(h.resolveCalls, 0);
  });

  it("evicts the soonest-expiring entry when maxHosts is reached", async () => {
    const h = harness({ maxHosts: 2, ttlMs: 60_000 });
    await lookupAsync(h.cache, "a.example.test");
    h.advance(30_000);
    await lookupAsync(h.cache, "b.example.test");
    assert.equal(h.cache.getStats().hosts, 2);
    await lookupAsync(h.cache, "c.example.test");
    assert.equal(h.cache.getStats().hosts, 2);
    // "a" expires soonest (cached 30s earlier) — it was evicted
    const callsBefore = h.resolveCalls;
    await lookupAsync(h.cache, "a.example.test");
    assert.equal(h.resolveCalls, callsBefore + 1);
  });

  it("clear() drops entries; counters survive", async () => {
    const h = harness();
    await lookupAsync(h.cache, "api.example.test");
    h.cache.clear();
    assert.equal(h.cache.getStats().hosts, 0);
    const callsBefore = h.resolveCalls;
    await lookupAsync(h.cache, "api.example.test");
    assert.equal(h.resolveCalls, callsBefore + 1);
    assert.equal(h.cache.getStats().misses, 2);
  });
});

describe("dns-cache: metrics exposition", () => {
  it("renders nothing until the first lookup (activity-gated)", () => {
    const h = harness();
    assert.equal(h.cache.render(), "");
  });

  it("renders hit/miss/stale counters, refresh failures, and host gauge", async () => {
    const h = harness({ ttlMs: 1000 });
    await lookupAsync(h.cache, "a.example.test"); // miss
    await lookupAsync(h.cache, "a.example.test"); // hit
    h.advance(1500);
    await lookupAsync(h.cache, "a.example.test"); // stale + refresh
    await sleep(10);
    const out = h.cache.render();
    assert.match(out, /relay_dns_cache_lookups_total\{result="hit"\} 1/);
    assert.match(out, /relay_dns_cache_lookups_total\{result="miss"\} 1/);
    assert.match(out, /relay_dns_cache_lookups_total\{result="stale"\} 1/);
    assert.match(out, /relay_dns_cache_refresh_failures_total 0/);
    assert.match(out, /relay_dns_cache_hosts 1/);
  });
});

describe("dns-cache: Node integration", () => {
  let server: Server | undefined;
  let port: number;

  const start = async (): Promise<void> => {
    server = createServer((req, res) => {
      res.writeHead(200).end("ok");
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const addr = server!.address();
    assert.ok(addr && typeof addr === "object");
    port = addr.port;
  };

  // Safety net: a test that started the stub must not leave it listening —
  // an open server handle keeps the test process alive after the last test
  // (pools/agents are destroyed in each test's own finally first).
  const closeServer = async (): Promise<void> => {
    if (server !== undefined) {
      const s = server;
      server = undefined;
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
  };
  afterEach(closeServer);

  it("an http.Agent with cache.lookup connects through the cached address", async () => {
    await start();
    try {
      // "relay-fake.invalid" never touches real DNS: the injected
      // resolver maps it to the loopback stub.
      const cache = new DnsCache({
        resolve: async (hostname) => {
          assert.equal(hostname, "relay-fake.invalid");
          return [{ address: "127.0.0.1", family: 4 }];
        },
      });
      const agent = new HttpAgent({ lookup: cache.lookup });
      const body = await new Promise<string>((resolve, reject) => {
        const req = httpRequest(
          `http://relay-fake.invalid:${port}/`,
          { agent },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c: Buffer) => chunks.push(c));
            res.on("end", () => resolve(Buffer.concat(chunks).toString()));
          }
        );
        req.on("error", reject);
        req.end();
      });
      assert.equal(body, "ok");
      assert.equal(cache.getStats().misses, 1);
      // second request over the same agent: cache hit, no re-resolution
      const again = await new Promise<string>((resolve, reject) => {
        const req = httpRequest(
          `http://relay-fake.invalid:${port}/`,
          { agent },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c: Buffer) => chunks.push(c));
            res.on("end", () => resolve(Buffer.concat(chunks).toString()));
          }
        );
        req.on("error", reject);
        req.end();
      });
      assert.equal(again, "ok");
      assert.equal(cache.getStats().hits, 1);
      agent.destroy();
    } finally {
      await closeServer();
    }
  });

  it("createDefaultSender resolves through the cache and exposes it", async () => {
    // The fake hostname must bypass the sandbox's egress proxy env
    // (WR-27 env fallback would CONNECT-tunnel it to the real proxy).
    await withProxyEnv({}, async () => {
    await start();
    const sender = createDefaultSender(
      undefined, // tlsPins
      undefined, // keepAlive (pool enabled)
      undefined, // outboundSigning
      undefined, // proxies
      undefined, // tlsClientCerts
      undefined, // compressOutbound
      undefined, // http2
      undefined, // idempotencyKey
      undefined, // websocket
      undefined, // outboundEncryption
      undefined, // tlsSniOverrides
      undefined, // responseCompression
      undefined, // forwardHeaders
      undefined, // certExpiryMonitor
      undefined, // minTlsVersions
      undefined, // tlsVersionMonitor
      undefined, // compressThreshold
      undefined, // onGzipFallback
      undefined, // onE2eeKeyRotated
      undefined, // tlsClientCertRotation
      {
        // WR-92: fake hostname -> loopback stub, no real DNS involved
        resolve: async (hostname: string) => {
          assert.equal(hostname, "relay-fake.invalid");
          return [{ address: "127.0.0.1", family: 4 }];
        },
      }
    );
    try {
      assert.ok(sender.dnsCache instanceof DnsCache);
      const targetUrl = `http://relay-fake.invalid:${port}/hook`;
      await sender({ id: "d1", payload: Buffer.from("{}"), targetUrl, headers: {} });
      const stats = sender.dnsCache.getStats();
      assert.ok(stats.misses >= 1, `expected a cache miss, got ${JSON.stringify(stats)}`);
      assert.match(sender.dnsCache.render(), /relay_dns_cache_lookups_total/);
    } finally {
      sender.destroy();
    }
    });
  });

  it("createDefaultSender without dnsCache keeps the OS resolver and no cache", async () => {
    const sender = createDefaultSender();
    try {
      assert.equal(sender.dnsCache, undefined);
    } finally {
      sender.destroy();
    }
  });

  it("invalid dnsCache options throw RangeError at startup", () => {
    assert.throws(
      () =>
        createDefaultSender(
          undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined,
          { ttlMs: 0 }
        ),
      /createDefaultSender: invalid dnsCache/
    );
  });
});
