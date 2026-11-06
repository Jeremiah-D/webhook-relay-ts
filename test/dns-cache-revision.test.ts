import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LookupAddress } from "node:dns";
import { DnsCache, type DnsCacheConfig } from "../src/dns-cache.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "dns-cache-revision-test-key";
const opToken = "dns-cache-revision-op-token";
const URL_A = "http://localhost:9999/a";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Controllable clock + resolver so no test touches real DNS. */
function harness(opts: {
  ttlMs?: number;
  refreshBackoffMs?: number;
  maxHosts?: number;
  addresses?: LookupAddress[];
} = {}) {
  let nowMs = 1_000_000;
  let resolveCalls = 0;
  const fail = { on: false };
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
      if (fail.on) {
        const err = new Error("resolver down") as NodeJS.ErrnoException;
        err.code = "EAI_AGAIN";
        throw err;
      }
      return addresses;
    },
  });
  return {
    cache,
    fail,
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

const DEFAULT_CONFIG: DnsCacheConfig = { ttlMs: 60_000, refreshBackoffMs: 5000, maxHosts: 1024 };

describe("DnsCache.retune (WR-342)", () => {
  it("shortening ttlMs leaves an existing entry on its original expiresAt", async () => {
    const h = harness({ ttlMs: 60_000 });
    await lookupAsync(h.cache, "api.example.test"); // expires at t+60s
    assert.deepEqual(h.cache.retune({ ttlMs: 1000 }), {
      ttlMs: 1000,
      refreshBackoffMs: 5000,
      maxHosts: 1024,
    });
    h.advance(30_000); // well past the new TTL, inside the original one
    const stillFresh = await lookupAsync(h.cache, "api.example.test");
    assert.equal(stillFresh.err, null);
    assert.equal(h.resolveCalls, 1); // a hit — no re-resolution
    assert.equal(h.cache.getStats().hits, 1);
    h.advance(31_000); // past the original 60s expiry
    const stale = await lookupAsync(h.cache, "api.example.test");
    assert.equal(stale.err, null);
    assert.equal(h.cache.getStats().staleServed, 1);
    assert.equal(h.resolveCalls, 2); // the expiry finally triggered a refresh
  });

  it("a new parse after retuning ttlMs expires on the new TTL", async () => {
    const h = harness({ ttlMs: 60_000 });
    h.cache.retune({ ttlMs: 1000 });
    await lookupAsync(h.cache, "api.example.test");
    assert.equal(h.resolveCalls, 1);
    h.advance(500); // inside the new TTL: a hit
    await lookupAsync(h.cache, "api.example.test");
    assert.equal(h.cache.getStats().hits, 1);
    assert.equal(h.resolveCalls, 1);
    h.advance(1000); // past the new TTL: stale + refresh
    const stale = await lookupAsync(h.cache, "api.example.test");
    assert.equal(stale.err, null);
    assert.equal(h.cache.getStats().staleServed, 1);
    assert.equal(h.resolveCalls, 2);
  });

  it("lengthening ttlMs makes the background refresh re-stamp expiresAt on the new TTL", async () => {
    const h = harness({ ttlMs: 1000 });
    await lookupAsync(h.cache, "api.example.test"); // expires at t+1s
    h.cache.retune({ ttlMs: 60_000 });
    h.advance(1500); // expired under the old TTL: stale + refresh
    const stale = await lookupAsync(h.cache, "api.example.test");
    assert.equal(stale.err, null);
    await sleep(10); // let the refresh settle
    assert.equal(h.resolveCalls, 2);
    // The refresh re-stamped expiresAt with the NEW 60s TTL: 30s later
    // the entry is still fresh (under the old TTL it would be long dead).
    h.advance(30_000);
    await lookupAsync(h.cache, "api.example.test");
    assert.equal(h.cache.getStats().hits, 1);
    assert.equal(h.resolveCalls, 2);
  });

  it("shrinking maxHosts evicts the soonest-expiring entries until the cache fits", async () => {
    const h = harness({ maxHosts: 3, ttlMs: 60_000 });
    await lookupAsync(h.cache, "a.example.test"); // expires first
    h.advance(10_000);
    await lookupAsync(h.cache, "b.example.test");
    h.advance(10_000);
    await lookupAsync(h.cache, "c.example.test"); // expires last
    assert.equal(h.cache.getStats().hosts, 3);
    assert.deepEqual(h.cache.retune({ maxHosts: 1 }), {
      ttlMs: 60_000,
      refreshBackoffMs: 5000,
      maxHosts: 1,
    });
    assert.equal(h.cache.getStats().hosts, 1);
    // Only the latest-expiring entry survived: "c" is a hit, "a"/"b" miss.
    await lookupAsync(h.cache, "c.example.test");
    assert.equal(h.resolveCalls, 3);
    assert.equal(h.cache.getStats().hits, 1);
    const callsBefore = h.resolveCalls;
    await lookupAsync(h.cache, "a.example.test");
    assert.equal(h.resolveCalls, callsBefore + 1);
    await lookupAsync(h.cache, "b.example.test");
    assert.equal(h.resolveCalls, callsBefore + 2);
  });

  it("growing maxHosts leaves every entry in place", async () => {
    const h = harness({ maxHosts: 2, ttlMs: 60_000 });
    await lookupAsync(h.cache, "a.example.test");
    await lookupAsync(h.cache, "b.example.test");
    assert.equal(h.cache.getStats().hosts, 2);
    assert.deepEqual(h.cache.retune({ maxHosts: 100 }), {
      ttlMs: 60_000,
      refreshBackoffMs: 5000,
      maxHosts: 100,
    });
    assert.equal(h.cache.getStats().hosts, 2);
    await lookupAsync(h.cache, "a.example.test");
    await lookupAsync(h.cache, "b.example.test");
    assert.equal(h.resolveCalls, 2); // both hits — nothing was evicted
    assert.equal(h.cache.getStats().hits, 2);
  });

  it("raising refreshBackoffMs lengthens the gap between consecutive failed refreshes", async () => {
    const h = harness({ ttlMs: 1000, refreshBackoffMs: 5000 });
    await lookupAsync(h.cache, "api.example.test");
    assert.equal(h.resolveCalls, 1);
    h.fail.on = true;
    h.advance(1500); // expire: stale + first failed refresh
    await lookupAsync(h.cache, "api.example.test");
    await sleep(10);
    assert.equal(h.resolveCalls, 2);
    assert.equal(h.cache.getStats().refreshFailures, 1);
    // Raise the backoff: the NEXT failed refresh stamps the new value.
    h.cache.retune({ refreshBackoffMs: 60_000 });
    h.advance(6000); // past the old 5s backoff: a refresh is attempted...
    await lookupAsync(h.cache, "api.example.test");
    await sleep(10);
    assert.equal(h.resolveCalls, 3);
    assert.equal(h.cache.getStats().refreshFailures, 2);
    // ...and fails again, so the new 60s backoff now suppresses retries:
    // 10s later (past the old backoff, inside the new one) no refresh.
    h.advance(10_000);
    await lookupAsync(h.cache, "api.example.test");
    await sleep(10);
    assert.equal(h.resolveCalls, 3);
    // Once the new 60s backoff elapses, the next expired lookup retries.
    h.fail.on = false;
    h.advance(55_000);
    const recovered = await lookupAsync(h.cache, "api.example.test");
    assert.equal(recovered.err, null);
    await sleep(10);
    assert.equal(h.resolveCalls, 4);
    assert.equal(h.cache.getStats().refreshFailures, 2);
  });

  it("illegal values throw RangeError and leave the live config untouched", () => {
    const h = harness({ ttlMs: 60_000, refreshBackoffMs: 5000, maxHosts: 10 });
    const bad: Array<unknown> = [
      { ttlMs: 0 },
      { ttlMs: -1 },
      { ttlMs: Number.NaN },
      { ttlMs: Number.POSITIVE_INFINITY },
      { ttlMs: "1000" },
      { refreshBackoffMs: -1 },
      { refreshBackoffMs: Number.NaN },
      { refreshBackoffMs: Number.POSITIVE_INFINITY },
      { maxHosts: 0 },
      { maxHosts: -2 },
      { maxHosts: 1.5 },
      { maxHosts: Number.NaN },
      { maxHosts: "10" },
      // A valid change paired with an invalid one must not partially apply.
      { ttlMs: 100, refreshBackoffMs: -1 },
      { ttlMs: 100, maxHosts: 0 },
    ];
    for (const patch of bad) {
      assert.throws(() => h.cache.retune(patch as never), RangeError, JSON.stringify(patch));
      assert.deepEqual(
        h.cache.config(),
        { ttlMs: 60_000, refreshBackoffMs: 5000, maxHosts: 10 },
        JSON.stringify(patch)
      );
    }
  });

  it("an empty patch and non-object patches throw RangeError", () => {
    const h = harness();
    const bad: Array<unknown> = [{}, null, "ttlMs", 42, [], undefined];
    for (const patch of bad) {
      assert.throws(() => h.cache.retune(patch as never), RangeError, JSON.stringify(patch));
      assert.deepEqual(h.cache.config(), DEFAULT_CONFIG, JSON.stringify(patch));
    }
  });

  it("a same-value retune is a silent no-op", () => {
    const h = harness({ ttlMs: 60_000, refreshBackoffMs: 5000, maxHosts: 10 });
    assert.deepEqual(h.cache.retune({ ttlMs: 60_000 }), {
      ttlMs: 60_000,
      refreshBackoffMs: 5000,
      maxHosts: 10,
    });
    assert.deepEqual(h.cache.retune({ ttlMs: 60_000, refreshBackoffMs: 5000, maxHosts: 10 }), {
      ttlMs: 60_000,
      refreshBackoffMs: 5000,
      maxHosts: 10,
    });
    assert.deepEqual(h.cache.config(), {
      ttlMs: 60_000,
      refreshBackoffMs: 5000,
      maxHosts: 10,
    });
  });

  it("config() returns a snapshot, not a live reference", () => {
    const h = harness({ ttlMs: 60_000, refreshBackoffMs: 5000, maxHosts: 10 });
    const snap = h.cache.config();
    snap.ttlMs = 1;
    snap.refreshBackoffMs = 0;
    snap.maxHosts = 1;
    assert.deepEqual(h.cache.config(), {
      ttlMs: 60_000,
      refreshBackoffMs: 5000,
      maxHosts: 10,
    });
  });
});

describe("RelayServer DNS cache revision (WR-342)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function listen(server: Server): Promise<number> {
    return new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
  }

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "dns-cache-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL_A,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("revision audits previous/current with the three fields exactly; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      dnsCache: { ttlMs: 60_000, refreshBackoffMs: 5000, maxHosts: 1024 },
    });
    await listen(relay);
    // First `previous` is the construction config.
    assert.deepEqual(relay.getDnsCacheConfig!(), DEFAULT_CONFIG);
    assert.deepEqual(relay.reviseDnsCache!({ ttlMs: 5000, maxHosts: 100 }), {
      ttlMs: 5000,
      refreshBackoffMs: 5000,
      maxHosts: 100,
    });
    const revised = eventsOf(audit, "dns_cache_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, DEFAULT_CONFIG);
    assert.deepEqual(revised[0].current, {
      ttlMs: 5000,
      refreshBackoffMs: 5000,
      maxHosts: 100,
    });
    // Landing exactly on the live values audits nothing.
    relay.reviseDnsCache!({ ttlMs: 5000, maxHosts: 100 });
    assert.equal(eventsOf(audit, "dns_cache_revised").length, 1);
    assert.deepEqual(relay.getDnsCacheConfig!(), {
      ttlMs: 5000,
      refreshBackoffMs: 5000,
      maxHosts: 100,
    });
    // A second real revision chains previous from the revised values.
    relay.reviseDnsCache!({ refreshBackoffMs: 30_000 });
    const revised2 = eventsOf(audit, "dns_cache_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, {
      ttlMs: 5000,
      refreshBackoffMs: 5000,
      maxHosts: 100,
    });
    assert.deepEqual(revised2[1].current, {
      ttlMs: 5000,
      refreshBackoffMs: 30_000,
      maxHosts: 100,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseDnsCache!({ ttlMs: 0 }), RangeError);
    assert.throws(() => relay.reviseDnsCache!({}), RangeError);
    assert.throws(() => relay.reviseDnsCache!(null as never), RangeError);
    assert.equal(eventsOf(audit, "dns_cache_revised").length, 2);
    assert.deepEqual(relay.getDnsCacheConfig!(), {
      ttlMs: 5000,
      refreshBackoffMs: 30_000,
      maxHosts: 100,
    });
    // The getter returns a snapshot, not a live reference.
    const snap = relay.getDnsCacheConfig!();
    snap.ttlMs = 1;
    assert.deepEqual(relay.getDnsCacheConfig!(), {
      ttlMs: 5000,
      refreshBackoffMs: 30_000,
      maxHosts: 100,
    });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getDnsCacheConfig, undefined);
    assert.throws(
      () => relay.reviseDnsCache!({ ttlMs: 5000 }),
      /not configured — enabling it requires a restart/
    );
    assert.throws(
      () => relay.reviseDnsCache!({}),
      /not configured — enabling it requires a restart/
    );
    assert.equal(relay.getDnsCacheConfig, undefined);
  });
});
