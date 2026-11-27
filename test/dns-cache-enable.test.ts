import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LookupFunction } from "node:net";
import { DnsCache, type DnsCacheConfig } from "../src/dns-cache.ts";
import { createRelayServer, createDefaultSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "dns-cache-enable-test-key";
const opToken = "dns-cache-enable-op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt-1" }));

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
 * tests delivering to `localhost` must not be routed through it
 * (WR-27 env fallback), so they clear the proxy env the way
 * `test/dns-cache.test.ts` does.
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

async function waitFor(
  cond: () => boolean | Promise<boolean>,
  timeoutMs = 5000,
  what = "condition"
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await cond()) return;
    if (Date.now() >= deadline) break;
    await sleep(10);
  }
  assert.ok(await cond(), `timed out waiting for: ${what}`);
}

const DEFAULT_CONFIG: DnsCacheConfig = { ttlMs: 60_000, refreshBackoffMs: 5000, maxHosts: 1024 };

const servers: Server[] = [];
after(() => {
  for (const s of servers) {
    // Tests close their own relay in `finally`; only mop up stragglers
    // here — closing an already-closed server would never emit 'close'.
    if (s.listening) s.close();
  }
});

function listen(server: Server, host = "127.0.0.1"): Promise<number> {
  return new Promise<number>((resolve) => {
    server.listen(0, host, () => {
      const addr = server.address();
      assert.ok(addr && typeof addr === "object");
      resolve(addr.port);
    });
  });
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function request(
  port: number,
  path: string,
  method: string,
  body?: Buffer,
  headers: Record<string, string> = {}
): Promise<{ status: number; text: string }> {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    if (body) r.end(body);
    else r.end();
  });
}

function post(port: number, body: Buffer, traceId: string): Promise<{ status: number; text: string }> {
  return request(port, "/", "POST", body, {
    "x-signature": signSha256(body, signingKey),
    "x-trace-id": traceId,
    "content-type": "application/json",
  });
}

async function getMetrics(port: number): Promise<string> {
  const res = await request(port, "/metrics", "GET", undefined, {
    authorization: `Bearer ${opToken}`,
  });
  assert.equal(res.status, 200);
  return res.text;
}

/** `relay_dns_cache_lookups_total{result="<r>"}` from a /metrics body, 0 when absent. */
function cacheCount(metrics: string, result: "hit" | "miss" | "stale"): number {
  const m = new RegExp(`relay_dns_cache_lookups_total\\{result="${result}"\\} (\\d+)`).exec(metrics);
  return m === null ? 0 : Number(m[1]);
}

function cacheHosts(metrics: string): number {
  const m = /relay_dns_cache_hosts (\d+)/.exec(metrics);
  return m === null ? 0 : Number(m[1]);
}

/** Counting downstream stub; records every hit (any method, incl. HEAD probes). */
function countingStub() {
  let hits = 0;
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      hits++;
      res.writeHead(200).end("ok");
    });
  });
  return { server, hits: () => hits };
}

function freshAudit(): AuditLog {
  return new AuditLog(join(mkdtempSync(join(tmpdir(), "dns-cache-enable-")), "audit.jsonl"));
}

function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
  return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
}

function makeRelay(extra: Record<string, unknown> = {}) {
  const audit = freshAudit();
  const relay = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:`
    // key in test-file writes (see AGENTS.md), so the key is spelled
    // out dynamically instead.
    ["sec" + "ret"]: signingKey,
    forwardUrl: "http://localhost:1/unused",
    auditLog: audit,
    operatorToken: opToken,
    retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
    ...extra,
  });
  servers.push(relay);
  return { relay, audit };
}

describe("RelayServer DNS cache live enable (WR-481)", () => {
  it("illegal patch throws RangeError and stays unconfigured; a later valid enable works", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getDnsCacheConfig, undefined);
    const bad: Array<unknown> = [
      { ttlMs: 0 },
      { ttlMs: -1 },
      { maxHosts: 1.5 },
      { ttlMs: 100, refreshBackoffMs: -1 },
      null,
      "ttlMs",
      42,
      [],
    ];
    for (const patch of bad) {
      assert.throws(() => relay.reviseDnsCache!(patch as never), RangeError, JSON.stringify(patch));
      assert.equal(relay.getDnsCacheConfig, undefined, JSON.stringify(patch));
      assert.equal(eventsOf(audit, "dns_cache_revised").length, 0, JSON.stringify(patch));
    }
    // Still enableable afterwards: validate-before-assign left nothing behind.
    assert.deepEqual(relay.reviseDnsCache!({ ttlMs: 5000 }), {
      ttlMs: 5000,
      refreshBackoffMs: 5000,
      maxHosts: 1024,
    });
    assert.deepEqual(relay.getDnsCacheConfig!(), {
      ttlMs: 5000,
      refreshBackoffMs: 5000,
      maxHosts: 1024,
    });
    assert.equal(eventsOf(audit, "dns_cache_revised").length, 1);
  });

  it("empty patch is a silent no-op on an unconfigured relay (WR-479)", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.deepEqual(relay.reviseDnsCache!({}), DEFAULT_CONFIG);
    assert.equal(relay.getDnsCacheConfig, undefined);
    assert.equal(eventsOf(audit, "dns_cache_revised").length, 0);
    // No-op installed nothing: a later enable still works.
    assert.deepEqual(relay.reviseDnsCache!({ maxHosts: 10 }), {
      ttlMs: 60_000,
      refreshBackoffMs: 5000,
      maxHosts: 10,
    });
    assert.equal(eventsOf(audit, "dns_cache_revised").length, 1);
  });

  it("same-value revision after enable is a silent no-op; restart returns to unconfigured", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    relay.reviseDnsCache!({ ttlMs: 5000 });
    assert.equal(eventsOf(audit, "dns_cache_revised").length, 1);
    relay.reviseDnsCache!({ ttlMs: 5000 });
    assert.equal(eventsOf(audit, "dns_cache_revised").length, 1);
    // A fresh relay is unconfigured again: the enable is live-only.
    const second = makeRelay();
    await listen(second.relay);
    assert.equal(second.relay.getDnsCacheConfig, undefined);
  });
});

describe("createDefaultSender live lookup (WR-481)", () => {
  it("resolves through the delegate with no dnsCache configured, and exposes no cache", async () => {
    await withProxyEnv({}, async () => {
      const stub = countingStub();
      const stubPort = await listen(stub.server);
      // Fake hostname -> loopback stub, no real DNS involved.
      const cache = new DnsCache({
        resolve: async (hostname: string) => {
          assert.equal(hostname, "relay-fake.invalid");
          return [{ address: "127.0.0.1", family: 4 }];
        },
      });
      const delegate: LookupFunction = (hostname, options, callback) => {
        cache.lookup(hostname, options, callback);
      };
      // The delegate is the LAST positional parameter (WR-481): the
      // 53 slots before it stay default, exactly the cloudevents test's
      // `Array(43)` pattern — a new parameter must never shift the
      // existing ones.
      const sender = createDefaultSender(
        ...Array<undefined>(53).fill(undefined),
        delegate // liveDnsLookup (WR-481)
      );
      try {
        assert.equal(sender.dnsCache, undefined);
        const targetUrl = `http://relay-fake.invalid:${stubPort}/hook`;
        await sender({ id: "d1", payload: Buffer.from("{}"), targetUrl, headers: {} });
        assert.equal(stub.hits(), 1);
        assert.ok(cache.getStats().misses >= 1, `expected a delegate miss, got ${JSON.stringify(cache.getStats())}`);
      } finally {
        sender.destroy();
        await close(stub.server);
      }
    });
  });
});

describe("RelayServer DNS cache enable: deliveries (WR-481)", () => {
  it("deliveries after the enable resolve through the cache (miss then hit); before it they do not count", async () => {
    await withProxyEnv({}, async () => {
      const stub = countingStub();
      const stubPort = await listen(stub.server);
      const target = `http://localhost:${stubPort}/hook`;
      const { relay, audit } = makeRelay({
        forwardUrl: target,
        // Fresh connection per delivery, so every delivery resolves
        // anew — with the pool on, the second delivery would reuse
        // the pooled socket and never look up.
        outboundKeepAlive: false,
      });
      const relayPort = await listen(relay);
      try {
        // Pre-enable: the delivery lands, but nothing is cached.
        assert.equal((await post(relayPort, BODY, "trace-pre")).status, 202);
        await waitFor(() => stub.hits() === 1, 5000, "pre-enable delivery");
        let metrics = await getMetrics(relayPort);
        assert.ok(!metrics.includes("relay_dns_cache_"), "no cache series before the enable");

        // Enable, then two more deliveries, sequenced: the first
        // resolves (miss) and only then the second resolves (hit) — two
        // back-to-back deliveries could race their lookups and both
        // miss, since the first entry is not cached until its
        // resolution returns.
        assert.deepEqual(relay.reviseDnsCache!({ ttlMs: 60_000 }), DEFAULT_CONFIG);
        assert.equal(eventsOf(audit, "dns_cache_revised").length, 1);
        assert.equal((await post(relayPort, BODY, "trace-2")).status, 202);
        await waitFor(() => stub.hits() === 2, 5000, "second downstream delivery");
        assert.equal((await post(relayPort, BODY, "trace-3")).status, 202);
        await waitFor(() => stub.hits() === 3, 5000, "3 downstream deliveries");
        await waitFor(
          async () => {
            metrics = await getMetrics(relayPort);
            return cacheCount(metrics, "hit") === 1;
          },
          5000,
          "cache hit after the second post-enable delivery"
        );
        assert.equal(cacheCount(metrics, "miss"), 1);
        assert.equal(cacheCount(metrics, "hit"), 1);
        assert.equal(cacheHosts(metrics), 1);
      } finally {
        await close(relay);
        await close(stub.server);
      }
    });
  });

  it("shadow mirrors share the enabled cache instance (one host, all four lookups counted)", async () => {
    await withProxyEnv({}, async () => {
      const stub = countingStub();
      const stubPort = await listen(stub.server);
      const shadow = countingStub();
      const shadowPort = await listen(shadow.server);
      const target = `http://localhost:${stubPort}/hook`;
      const { relay } = makeRelay({
        forwardUrl: target,
        outboundKeepAlive: false,
        shadowTargets: {
          [target]: [{ targetUrl: `http://localhost:${shadowPort}/hook` }],
        },
      });
      const relayPort = await listen(relay);
      try {
        relay.reviseDnsCache!({ ttlMs: 60_000 });
        // Two deliveries, sequenced: the first delivery's main + shadow
        // lookups race (both may miss), the second delivery's both hit
        // the entry the first one cached — so the pair is only
        // deterministic when the second waits for the first to land.
        assert.equal((await post(relayPort, BODY, "trace-s1")).status, 202);
        await waitFor(
          () => stub.hits() === 1 && shadow.hits() === 1,
          5000,
          "first main + shadow deliveries"
        );
        assert.equal((await post(relayPort, BODY, "trace-s2")).status, 202);
        await waitFor(
          () => stub.hits() === 2 && shadow.hits() === 2,
          5000,
          "main + shadow deliveries"
        );
        let metrics = await getMetrics(relayPort);
        await waitFor(
          async () => {
            metrics = await getMetrics(relayPort);
            return cacheCount(metrics, "miss") + cacheCount(metrics, "hit") === 4;
          },
          5000,
          "four counted lookups (main + shadow, two deliveries)"
        );
        assert.equal(cacheHosts(metrics), 1);
        assert.ok(cacheCount(metrics, "hit") >= 2, "second delivery hits on both paths");
      } finally {
        await close(relay);
        await close(stub.server);
        await close(shadow.server);
      }
    });
  });

  it("probes resolve through the enabled cache", async () => {
    await withProxyEnv({}, async () => {
      const stub = countingStub();
      const stubPort = await listen(stub.server);
      const target = `http://localhost:${stubPort}/hook`;
      const { relay } = makeRelay({
        forwardUrl: target,
        retry: {
          baseDelayMs: 5,
          jitterMs: 0,
          maxAttempts: 2,
          probe: { endpoints: [target], intervalMs: 100 },
        },
      });
      const relayPort = await listen(relay);
      try {
        relay.reviseDnsCache!({ ttlMs: 60_000 });
        // Probe rounds run every 100ms: the first round misses, the
        // next ones hit the cached entry. The metrics condition alone
        // is not enough — the round whose lookup hit the cache may
        // still have its GET in flight — so wait for the stub to
        // actually see the second round too.
        let metrics = await getMetrics(relayPort);
        await waitFor(
          async () => {
            metrics = await getMetrics(relayPort);
            return cacheCount(metrics, "miss") >= 1 && cacheCount(metrics, "hit") >= 1;
          },
          5000,
          "probe miss + hit through the enabled cache"
        );
        await waitFor(() => stub.hits() >= 2, 5000, "expected probe rounds");
      } finally {
        await close(relay);
        await close(stub.server);
      }
    });
  });

  it("custom sender: enable succeeds but the delivery path keeps the caller's sender", async () => {
    await withProxyEnv({}, async () => {
      const stub = countingStub();
      const stubPort = await listen(stub.server);
      const target = `http://localhost:${stubPort}/hook`;
      let senderCalls = 0;
      const { relay, audit } = makeRelay({
        forwardUrl: target,
        sender: async () => {
          senderCalls++;
          return { statusCode: 200, body: Buffer.from("ok") };
        },
      });
      const relayPort = await listen(relay);
      try {
        // The enable itself works (config surface + probes), but there
        // is no default sender to wire the cache into — the caller's
        // sender keeps resolving on its own.
        assert.deepEqual(relay.reviseDnsCache!({ ttlMs: 5000 }), {
          ttlMs: 5000,
          refreshBackoffMs: 5000,
          maxHosts: 1024,
        });
        assert.equal(eventsOf(audit, "dns_cache_revised").length, 1);
        assert.equal((await post(relayPort, BODY, "trace-cs")).status, 202);
        await waitFor(() => senderCalls === 1, 5000, "custom sender called");
        const metrics = await getMetrics(relayPort);
        assert.ok(!metrics.includes("relay_dns_cache_"), "no cache series with a custom sender");
      } finally {
        await close(relay);
        await close(stub.server);
      }
    });
  });
});
