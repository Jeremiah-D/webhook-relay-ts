import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DnsPin, DnsPinMismatchError } from "../src/dns-pin.ts";
import { DnsCache } from "../src/dns-cache.ts";
import { createRelayServer, createDefaultSender, type PooledSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const SECRET = "dns-pin-secret";
const OPERATOR = "op-dns-pin-token";
const BODY = Buffer.from(JSON.stringify({ event: "dns.pin.probe" }));

/** Fake inner lookup: answers from a mutable hostname -> address map. */
function fakeInner(map: Map<string, string[]>): LookupFunction {
  return ((hostname: string, options: unknown, callback: unknown) => {
    const addrs = map.get(hostname);
    const cb = callback as (
      err: NodeJS.ErrnoException | null,
      addresses: LookupAddress[]
    ) => void;
    if (addrs === undefined) {
      const err = new Error(`ENOTFOUND ${hostname}`) as NodeJS.ErrnoException;
      err.code = "ENOTFOUND";
      cb(err, []);
      return;
    }
    cb(
      null,
      addrs.map((address) => ({ address, family: 4 as const }))
    );
  }) as LookupFunction;
}

function lookupPromise(
  pin: DnsPin,
  hostname: string,
  options: { all?: boolean; family?: number } = {}
): Promise<{ address: string; family: number } | LookupAddress[]> {
  return new Promise((resolve, reject) => {
    pin.lookup(hostname, options, ((err: unknown, address: unknown, family: unknown) => {
      if (err) reject(err);
      else if (options.all === true) resolve(address as LookupAddress[]);
      else resolve({ address: address as string, family: family as number });
    }) as never);
  });
}

describe("dns-pin: baseline and drift detection", () => {
  it("pins the first successful answer and serves matching lookups", async () => {
    const pin = new DnsPin({ inner: fakeInner(new Map([["a.test", ["1.2.3.4"]]])) });
    const first = (await lookupPromise(pin, "a.test")) as { address: string };
    assert.equal(first.address, "1.2.3.4");
    assert.deepEqual(pin.getPinned("a.test"), ["1.2.3.4"]);
    const second = (await lookupPromise(pin, "a.test")) as { address: string };
    assert.equal(second.address, "1.2.3.4");
    assert.deepEqual(pin.getStats(), { hosts: 1, checked: 2, mismatches: 0, refused: 0, warned: 0 });
  });

  it("round-robin ordering does not count as drift", async () => {
    const map = new Map([["b.test", ["1.1.1.1", "2.2.2.2"]]]);
    const pin = new DnsPin({ inner: fakeInner(map) });
    await lookupPromise(pin, "b.test");
    map.set("b.test", ["2.2.2.2", "1.1.1.1"]); // same set, new order
    const served = (await lookupPromise(pin, "b.test", { all: true })) as LookupAddress[];
    assert.deepEqual(
      served.map((r) => r.address).sort(),
      ["1.1.1.1", "2.2.2.2"]
    );
    assert.equal(pin.getStats().mismatches, 0);
  });

  it("enforce mode refuses drifted lookups fail-closed and keeps the baseline", async () => {
    const seen: unknown[] = [];
    const map = new Map([["c.test", ["1.2.3.4"]]]);
    const pin = new DnsPin({ inner: fakeInner(map), onMismatch: (i) => seen.push(i) });
    await lookupPromise(pin, "c.test");
    map.set("c.test", ["9.9.9.9"]); // hijacked answer
    await assert.rejects(() => lookupPromise(pin, "c.test"), DnsPinMismatchError);
    await assert.rejects(() => lookupPromise(pin, "c.test"), /EDNSPINMISMATCH|DNS pin mismatch/);
    // Every drifted lookup is audited (fail-closed evidence per attempt).
    assert.equal(seen.length, 2);
    assert.match(JSON.stringify(seen[0]), /"mode":"enforce"/);
    assert.match(JSON.stringify(seen[0]), /"pinned":\["1\.2\.3\.4"\]/);
    assert.match(JSON.stringify(seen[0]), /"observed":\["9\.9\.9\.9"\]/);
    const stats = pin.getStats();
    assert.equal(stats.mismatches, 2);
    assert.equal(stats.refused, 2);
    assert.equal(stats.warned, 0);
    // Fail-closed: the old baseline is kept, the drifted answer is never adopted.
    assert.deepEqual(pin.getPinned("c.test"), ["1.2.3.4"]);
    map.set("c.test", ["1.2.3.4"]); // resolver recovers
    const ok = (await lookupPromise(pin, "c.test")) as { address: string };
    assert.equal(ok.address, "1.2.3.4");
  });

  it("warn mode serves drifted answers, audits once, and adopts the new baseline", async () => {
    const seen: unknown[] = [];
    const map = new Map([["d.test", ["1.2.3.4"]]]);
    const pin = new DnsPin({
      inner: fakeInner(map),
      mode: "warn",
      onMismatch: (i) => seen.push(i),
    });
    await lookupPromise(pin, "d.test");
    map.set("d.test", ["5.6.7.8"]); // legitimate rotation
    const served = (await lookupPromise(pin, "d.test")) as { address: string };
    assert.equal(served.address, "5.6.7.8");
    assert.equal(seen.length, 1);
    assert.match(JSON.stringify(seen[0]), /"mode":"warn"/);
    // Baseline adopted: the same answer no longer audits.
    await lookupPromise(pin, "d.test");
    assert.equal(seen.length, 1);
    assert.deepEqual(pin.getPinned("d.test"), ["5.6.7.8"]);
    const stats = pin.getStats();
    assert.equal(stats.mismatches, 1);
    assert.equal(stats.refused, 0);
    assert.equal(stats.warned, 1);
  });

  it("inner resolution failures pass through untouched and pin nothing", async () => {
    const pin = new DnsPin({ inner: fakeInner(new Map()) });
    await assert.rejects(() => lookupPromise(pin, "missing.test"), /ENOTFOUND/);
    assert.equal(pin.getPinned("missing.test"), undefined);
    assert.deepEqual(pin.getStats(), { hosts: 0, checked: 0, mismatches: 0, refused: 0, warned: 0 });
  });

  it("reset() drops baselines so the next lookup re-pins", async () => {
    const map = new Map([["e.test", ["1.2.3.4"]]]);
    const pin = new DnsPin({ inner: fakeInner(map) });
    await lookupPromise(pin, "e.test");
    map.set("e.test", ["9.9.9.9"]);
    await assert.rejects(() => lookupPromise(pin, "e.test"), DnsPinMismatchError);
    pin.reset("e.test");
    const served = (await lookupPromise(pin, "e.test")) as { address: string };
    assert.equal(served.address, "9.9.9.9");
    assert.deepEqual(pin.getPinned("e.test"), ["9.9.9.9"]);
    pin.reset();
    assert.equal(pin.getStats().hosts, 0);
  });

  it("evicts the longest-pinned hostname when full", async () => {
    const map = new Map([
      ["f1.test", ["1.0.0.1"]],
      ["f2.test", ["1.0.0.2"]],
    ]);
    const pin = new DnsPin({ inner: fakeInner(map), maxHosts: 1 });
    await lookupPromise(pin, "f1.test");
    await lookupPromise(pin, "f2.test"); // evicts f1
    assert.equal(pin.getPinned("f1.test"), undefined);
    assert.deepEqual(pin.getPinned("f2.test"), ["1.0.0.2"]);
    map.set("f1.test", ["9.9.9.9"]);
    // f1 re-baselines instead of mismatching (it was evicted, not drifted).
    await lookupPromise(pin, "f1.test");
    assert.equal(pin.getStats().mismatches, 0);
  });

  it("wraps a DnsCache lookup and judges the cached answers", async () => {
    let now = 0;
    const map = new Map([["g.test", ["1.2.3.4"]]]);
    const cache = new DnsCache({ now: () => now, resolve: async (h) => (map.get(h) ?? []).map((address) => ({ address, family: 4 as const })) });
    const pin = new DnsPin({ inner: cache.lookup });
    await lookupPromise(pin, "g.test");
    // The cache now holds 1.2.3.4; drift the resolver — the pin sees the
    // cached (old) answer first, so no mismatch until the cache refreshes.
    map.set("g.test", ["9.9.9.9"]);
    const cached = (await lookupPromise(pin, "g.test")) as { address: string };
    assert.equal(cached.address, "1.2.3.4");
    assert.equal(pin.getStats().mismatches, 0);
    // Expire the cache entry: the next lookup serves the stale answer and
    // kicks the background refresh; the lookup after that sees the
    // drifted answer and the pin refuses it.
    now += 61_000;
    const stale = (await lookupPromise(pin, "g.test")) as { address: string };
    assert.equal(stale.address, "1.2.3.4");
    assert.equal(pin.getStats().mismatches, 0);
    await new Promise((r) => setTimeout(r, 20)); // let the background refresh land
    await assert.rejects(() => lookupPromise(pin, "g.test", { all: true }), DnsPinMismatchError);
  });

  it("rejects invalid options with RangeError", () => {
    assert.throws(() => new DnsPin({ mode: "sometimes" as never }), RangeError);
    assert.throws(() => new DnsPin({ maxHosts: 0 }), RangeError);
    assert.throws(() => new DnsPin({ maxHosts: 1.5 }), RangeError);
    assert.throws(() => new DnsPin({ inner: "nope" as never }), RangeError);
    assert.throws(() => new DnsPin({ now: 42 as never }), RangeError);
    assert.throws(() => new DnsPin({ onMismatch: "nope" as never }), RangeError);
  });

  it("render() is activity-gated and exposes relay_dns_pin_* series", async () => {
    const pin = new DnsPin({ inner: fakeInner(new Map([["h.test", ["1.2.3.4"]]])) });
    assert.equal(pin.render(), "");
    await lookupPromise(pin, "h.test");
    const out = pin.render();
    assert.match(out, /relay_dns_pin_lookups_total\{result="checked"\} 1/);
    assert.match(out, /relay_dns_pin_mismatches_total 0/);
    assert.match(out, /relay_dns_pin_hosts 1/);
  });
});

describe("dns-pin: sender and server wiring", () => {
  it("createDefaultSender builds the pin and validates it up front", () => {
    // dnsPin is the 44th positional parameter; pad with 43 placeholders.
    const callWithDnsPin = (dnsPin: unknown) =>
      (createDefaultSender as (...args: unknown[]) => PooledSender)(
        ...new Array(43).fill(undefined),
        dnsPin
      );
    const sender = callWithDnsPin({ mode: "warn" });
    assert.ok(sender.dnsPin instanceof DnsPin);
    assert.throws(() => callWithDnsPin({ mode: "sometimes" }), /invalid dnsPin/);
    // Without the option the sender keeps the exact pre-WR-194 shape.
    const plain = callWithDnsPin(undefined);
    assert.equal(plain.dnsPin, undefined);
    sender.destroy();
    plain.destroy();
  });

  describe("end-to-end through the relay server", () => {
    let downstream: Server;
    let relay: Server;
    let relayPort: number;
    const received: Buffer[] = [];
    const dnsMap = new Map<string, string[]>();
    // The sandbox sets an egress proxy (HTTP(S)_PROXY); bypass it for
    // the fake hostname so the delivery resolves locally through the
    // pin (127.0.0.1 is already in no_proxy, pinned.test is not).
    const savedNoProxy = process.env.NO_PROXY;
    const savedNoProxyLower = process.env.no_proxy;

    function postSigned(port: number, body: Buffer) {
      const sig = signSha256(body, SECRET);
      return new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          { host: "127.0.0.1", port, path: "/hook", method: "POST", headers: { "x-signature": sig } },
          (res) => {
            res.resume();
            res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end(body);
      });
    }

    function getJson(port: number, path: string, headers: Record<string, string>) {
      return new Promise<{ status: number; body: unknown }>((resolve, reject) => {
        const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString()) })
          );
        });
        r.on("error", reject);
        r.end();
      });
    }

    function readAudit(dir: string): unknown[] {
      return readFileSync(join(dir, "audit.jsonl"), "utf8")
        .split("\n")
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l));
    }

    before(async () => {
      process.env.NO_PROXY = `${savedNoProxy ?? ""},pinned.test`;
      process.env.no_proxy = `${savedNoProxyLower ?? ""},pinned.test`;
      downstream = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          received.push(Buffer.concat(chunks));
          res.writeHead(200).end("ok");
        });
      });
      await new Promise<void>((resolve) => downstream.listen(0, "127.0.0.1", resolve));
      const addr = downstream.address();
      assert.ok(addr && typeof addr === "object");
      const downstreamPort = addr.port;
      dnsMap.set("pinned.test", ["127.0.0.1"]);
      const dir = mkdtempSync(join(tmpdir(), "audit-dns-pin-"));
      const audit = new AuditLog(join(dir, "audit.jsonl"));
      (globalThis as Record<string, unknown>).__dnsPinAuditDir = dir;
      relay = createRelayServer({
        secret: SECRET,
        forwardUrl: `http://pinned.test:${downstreamPort}/hook`,
        auditLog: audit,
        operatorToken: OPERATOR,
        retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
        // The fake resolver answers pinned.test -> 127.0.0.1; the relay's
        // sender resolves through the pin. Keep-alive pooling is off so
        // every delivery re-resolves (a pooled connection would mask the
        // DNS drift — correct in production, but this test wants the
        // drift refused).
        outboundKeepAlive: false,
        dnsPin: { inner: fakeInner(dnsMap) },
      });
      await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
      const raddr = relay.address();
      assert.ok(raddr && typeof raddr === "object");
      relayPort = raddr.port;
    });

    after(() => {
      relay.close();
      downstream.close();
      if (savedNoProxy === undefined) delete process.env.NO_PROXY;
      else process.env.NO_PROXY = savedNoProxy;
      if (savedNoProxyLower === undefined) delete process.env.no_proxy;
      else process.env.no_proxy = savedNoProxyLower;
    });

    it("delivers while the resolution matches the baseline, then refuses drift and audits dns_pin_mismatch", async () => {
      const auth = { authorization: `Bearer ${OPERATOR}` };
      // First delivery pins 127.0.0.1 and succeeds.
      const r1 = await postSigned(relayPort, BODY);
      assert.equal(r1.status, 202);
      for (let i = 0; i < 100 && received.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
      }
      assert.equal(received.length, 1);
      assert.deepEqual(received[0], BODY);

      // Hijack the resolver: the pin must now refuse every delivery.
      dnsMap.set("pinned.test", ["9.9.9.9"]);
      const before = received.length;
      const r2 = await postSigned(relayPort, BODY);
      assert.equal(r2.status, 202); // accepted inbound; the DNS failure is outbound
      let dead: unknown[] = [];
      for (let i = 0; i < 200 && dead.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        dead = ((await getJson(relayPort, "/dead-letter", auth)).body as unknown[]) ?? [];
      }
      assert.equal(dead.length, 1);
      assert.match(JSON.stringify(dead[0]), /DNS pin mismatch/);
      // Refused before connect: the drifted address never saw a byte.
      assert.equal(received.length, before);

      // The mismatch is in the audit trail as dns_pin_mismatch.
      const dir = (globalThis as Record<string, unknown>).__dnsPinAuditDir as string;
      let mismatches: unknown[] = [];
      for (let i = 0; i < 100 && mismatches.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        mismatches = readAudit(dir).filter(
          (e) => (e as { event?: string }).event === "dns_pin_mismatch"
        );
      }
      assert.ok(mismatches.length >= 1);
      const first = mismatches[0] as Record<string, unknown>;
      assert.equal(first.hostname, "pinned.test");
      assert.deepEqual(first.pinned, ["127.0.0.1"]);
      assert.deepEqual(first.observed, ["9.9.9.9"]);
      assert.equal(first.mode, "enforce");
    });
  });
});
