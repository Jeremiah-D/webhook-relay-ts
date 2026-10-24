import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { SrvRecord } from "node:dns";
import {
  SrvDiscovery,
  SrvDiscoveryError,
  buildSrvName,
  selectSrvTarget,
} from "../src/srv-discovery.ts";

function rec(priority: number, weight: number, port: number, name: string): SrvRecord {
  return { priority, weight, port, name };
}

function stubResolver(
  calls: string[],
  byName: Record<string, SrvRecord[] | Error>
): (srvName: string) => Promise<SrvRecord[]> {
  return async (srvName: string) => {
    calls.push(srvName);
    const v = byName[srvName];
    if (v instanceof Error) throw v;
    if (v === undefined) throw new Error(`ENOTFOUND ${srvName}`);
    return v;
  };
}

describe("buildSrvName", () => {
  it("normalizes underscores, case, and a trailing dot", () => {
    assert.equal(buildSrvName("https", "tcp", "events.example.com"), "_https._tcp.events.example.com");
    assert.equal(buildSrvName("_https", "_tcp", "events.example.com."), "_https._tcp.events.example.com");
    assert.equal(buildSrvName("HTTPS", "TCP", "Events.Example.COM"), "_https._tcp.events.example.com");
  });

  it("rejects empty or malformed parts", () => {
    assert.throws(() => buildSrvName("", "tcp", "example.com"), /service/);
    assert.throws(() => buildSrvName("ht tp", "tcp", "example.com"), /service/);
    assert.throws(() => buildSrvName("https", "tcp", ""), /name/);
  });
});

describe("selectSrvTarget (RFC 2782)", () => {
  it("only considers the lowest-priority group", () => {
    const records = [
      rec(10, 100, 8443, "backup.example.com"),
      rec(0, 100, 443, "primary.example.com"),
    ];
    const target = selectSrvTarget(records, "_https._tcp.example.com", () => 0.99);
    assert.equal(target.hostname, "primary.example.com");
    assert.equal(target.port, 443);
    assert.equal(target.priority, 0);
  });

  it("draws weight-proportionally inside a group", () => {
    const records = [rec(0, 60, 443, "a.example.com"), rec(0, 40, 443, "b.example.com")];
    // Draw 0.5 * 100 = 50 < 60 -> first record; 0.6 * 100 = 60 -> not < 60, second.
    assert.equal(selectSrvTarget(records, "_https._tcp.example.com", () => 0.5).hostname, "a.example.com");
    assert.equal(selectSrvTarget(records, "_https._tcp.example.com", () => 0.6).hostname, "b.example.com");
    assert.equal(selectSrvTarget(records, "_https._tcp.example.com", () => 0.0).hostname, "a.example.com");
  });

  it("draws uniformly when every weight in the group is zero", () => {
    const records = [rec(0, 0, 443, "a.example.com"), rec(0, 0, 443, "b.example.com")];
    assert.equal(selectSrvTarget(records, "_https._tcp.example.com", () => 0.0).hostname, "a.example.com");
    assert.equal(selectSrvTarget(records, "_https._tcp.example.com", () => 0.5).hostname, "b.example.com");
    assert.equal(selectSrvTarget(records, "_https._tcp.example.com", () => 0.99).hostname, "b.example.com");
  });

  it("strips a trailing dot and rejects a .-only set instead of guessing", () => {
    const target = selectSrvTarget(
      [rec(0, 10, 443, "receiver.example.com.")],
      "_https._tcp.example.com",
      () => 0
    );
    assert.equal(target.hostname, "receiver.example.com");
    assert.throws(
      () => selectSrvTarget([rec(0, 0, 0, ".")], "_https._tcp.example.com", () => 0),
      (err: unknown) => {
        assert.ok(err instanceof SrvDiscoveryError);
        assert.match(err.message, /not available/);
        return true;
      }
    );
    assert.throws(
      () => selectSrvTarget([], "_https._tcp.example.com", () => 0),
      SrvDiscoveryError
    );
  });

  it("rejects a random source outside [0, 1)", () => {
    assert.throws(
      () => selectSrvTarget([rec(0, 10, 443, "a.example.com")], "_https._tcp.example.com", () => 1),
      /random/
    );
  });
});

describe("SrvDiscovery", () => {
  it("validates ttlMs, maxEntries, and callback options at construction", () => {
    assert.throws(() => new SrvDiscovery({ ttlMs: 0 }), /ttlMs/);
    assert.throws(() => new SrvDiscovery({ ttlMs: Number.NaN }), /ttlMs/);
    assert.throws(() => new SrvDiscovery({ maxEntries: 0 }), /maxEntries/);
    assert.throws(
      () => new SrvDiscovery({ now: 42 as unknown as () => number }),
      /now must be a function/
    );
  });

  it("reuses a fresh record set and re-resolves after the TTL expires", async () => {
    let now = 0;
    const calls: string[] = [];
    const discovery = new SrvDiscovery({
      ttlMs: 1000,
      now: () => now,
      random: () => 0,
      resolve: stubResolver(calls, {
        "_https._tcp.events.example.com": [rec(0, 10, 8443, "r1.example.com")],
      }),
    });
    const first = await discovery.resolve("https", "tcp", "events.example.com");
    assert.equal(first.hostname, "r1.example.com");
    assert.equal(first.port, 8443);
    await discovery.resolve("https", "tcp", "events.example.com");
    assert.equal(calls.length, 1, "fresh entry must not re-resolve");
    assert.deepEqual(discovery.getStats(), {
      hosts: 1,
      lookups: 2,
      cacheHits: 1,
      resolverCalls: 1,
      resolverFailures: 0,
    });
    now = 1001;
    await discovery.resolve("https", "tcp", "events.example.com");
    assert.equal(calls.length, 2, "expired entry must re-resolve");
  });

  it("fail-closes on an empty record set and on a resolver error, never falling back", async () => {
    const calls: string[] = [];
    const discovery = new SrvDiscovery({
      random: () => 0,
      resolve: stubResolver(calls, {
        "_https._tcp.empty.example.com": [],
        "_https._tcp.down.example.com": new Error("ENOTFOUND"),
      }),
    });
    await assert.rejects(discovery.resolve("https", "tcp", "empty.example.com"), (err: unknown) => {
      assert.ok(err instanceof SrvDiscoveryError);
      assert.equal(err.srvName, "_https._tcp.empty.example.com");
      assert.match(err.message, /no SRV records/);
      return true;
    });
    await assert.rejects(discovery.resolve("https", "tcp", "down.example.com"), (err: unknown) => {
      assert.ok(err instanceof SrvDiscoveryError);
      assert.equal(err.srvName, "_https._tcp.down.example.com");
      assert.match(err.message, /resolver failed/);
      return true;
    });
    assert.equal(discovery.getStats().resolverFailures, 2);
  });

  it("rewrites a target URL preserving scheme, path, and query", async () => {
    const discovery = new SrvDiscovery({
      random: () => 0,
      resolve: stubResolver([], {
        "_https._tcp.events.example.com": [rec(0, 10, 8443, "receiver.example.com.")],
      }),
    });
    const rewritten = await discovery.resolveTargetUrl("https://events.example.com/hook?x=1", {
      service: "https",
      proto: "tcp",
    });
    assert.equal(rewritten, "https://receiver.example.com:8443/hook?x=1");
  });

  it("uses an explicit SRV name and rejects non-HTTP(S)/WS(S) targets", async () => {
    const discovery = new SrvDiscovery({
      random: () => 0,
      resolve: stubResolver([], {
        "_https._tcp.svc.internal": [rec(0, 10, 443, "node-1.internal")],
      }),
    });
    const rewritten = await discovery.resolveTargetUrl("https://anything.example/hook", {
      service: "https",
      proto: "tcp",
      name: "svc.internal",
    });
    assert.equal(rewritten, "https://node-1.internal/hook");
    await assert.rejects(
      discovery.resolveTargetUrl("ftp://example.com/hook", { service: "https", proto: "tcp" }),
      /http:|https:|ws:|wss:/
    );
    await assert.rejects(
      discovery.resolveTargetUrl("not-a-url", { service: "https", proto: "tcp" }),
      /valid URL/
    );
  });

  it("evicts the soonest-expiring entry when full and renders metrics only after use", async () => {
    let now = 0;
    const discovery = new SrvDiscovery({
      ttlMs: 1000,
      maxEntries: 1,
      now: () => now,
      random: () => 0,
      resolve: stubResolver([], {
        "_https._tcp.a.example.com": [rec(0, 10, 443, "a1.example.com")],
        "_https._tcp.b.example.com": [rec(0, 10, 443, "b1.example.com")],
      }),
    });
    assert.equal(discovery.render(), "");
    await discovery.resolve("https", "tcp", "a.example.com");
    now = 500; // Cache is full (maxEntries 1), so resolving b evicts a.
    await discovery.resolve("https", "tcp", "b.example.com");
    assert.equal(discovery.getStats().hosts, 1);
    assert.match(discovery.render(), /relay_srv_discovery_lookups_total/);
    assert.match(discovery.render(), /relay_srv_discovery_hosts 1/);
  });
});

