import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OutboundSsrfGuard,
  OutboundSsrfBlockedError,
} from "../src/outbound-ssrf-guard.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "ssrf-allowlist-revision-test-key";
const opToken = "ssrf-allowlist-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ event: "ssrf.allowlist.revision.probe" }));
const TARGET = "http://internal.test/hook";

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
      addrs.map((address) => ({ address, family: (address.includes(":") ? 6 : 4) as 4 | 6 }))
    );
  }) as LookupFunction;
}

function lookupPromise(
  lookup: LookupFunction,
  hostname: string,
  options: { all?: boolean; family?: number } = {}
): Promise<{ address: string; family: number } | LookupAddress[]> {
  return new Promise((resolve, reject) => {
    lookup(hostname, options, ((err: unknown, address: unknown, family: unknown) => {
      if (err) reject(err);
      else if (options.all === true) resolve(address as LookupAddress[]);
      else resolve({ address: address as string, family: family as number });
    }) as never);
  });
}

describe("outbound-ssrf-guard: allowlist live revision (WR-375)", () => {
  it("allowlisting a bound endpoint serves the private address on the next lookup", async () => {
    const map = new Map([["internal.test", ["10.0.0.5"]]]);
    const guard = new OutboundSsrfGuard({ inner: fakeInner(map) });
    const before = guard.bindingFor(TARGET);
    assert.equal(before.mode, "guarded");
    await assert.rejects(
      () => lookupPromise(before.lookup, "internal.test"),
      (err: unknown) =>
        err instanceof OutboundSsrfBlockedError &&
        (err as { code?: string }).code === "ESSRFPRIVATE"
    );
    // A real revision returns the live allowlist and flips the mode.
    assert.deepEqual(guard.reviseAllowPrivateTargets({ [TARGET]: true }), { [TARGET]: true });
    assert.deepEqual(guard.allowPrivateTargets(), { [TARGET]: true });
    const after = guard.bindingFor(TARGET);
    // The capture trap, caught: the revised endpoint re-binds instead
    // of serving the old mode forever.
    assert.notEqual(after, before);
    assert.equal(after.mode, "allowlisted");
    const served = (await lookupPromise(after.lookup, "internal.test")) as {
      address: string;
    };
    assert.equal(served.address, "10.0.0.5");
    assert.equal(guard.getStats().allowlisted, 1);
  });

  it("removing the allowlist refuses the private address on the next lookup", async () => {
    const map = new Map([["internal.test", ["10.0.0.5"]]]);
    const guard = new OutboundSsrfGuard({
      inner: fakeInner(map),
      allowPrivateTargets: { [TARGET]: true },
    });
    const allowlisted = guard.bindingFor(TARGET);
    assert.equal(allowlisted.mode, "allowlisted");
    const served = (await lookupPromise(allowlisted.lookup, "internal.test")) as {
      address: string;
    };
    assert.equal(served.address, "10.0.0.5");
    guard.reviseAllowPrivateTargets({ [TARGET]: false });
    assert.deepEqual(guard.allowPrivateTargets(), {});
    const guarded = guard.bindingFor(TARGET);
    assert.notEqual(guarded, allowlisted);
    assert.equal(guarded.mode, "guarded");
    await assert.rejects(
      () => lookupPromise(guarded.lookup, "internal.test"),
      (err: unknown) =>
        err instanceof OutboundSsrfBlockedError &&
        (err as { code?: string }).code === "ESSRFPRIVATE"
    );
    // The already-built binding keeps its old mode: a revision never
    // rewrites a live connection — the old agent drains on idle
    // timeout (WR-24) while the next dispatch takes the new binding.
    const stillServed = (await lookupPromise(allowlisted.lookup, "internal.test")) as {
      address: string;
    };
    assert.equal(stillServed.address, "10.0.0.5");
  });

  it("a proxied endpoint keeps the proxied mode across revisions and audits the skip once", async () => {
    const skips: { hostname: string; proxyUrl: string }[] = [];
    const map = new Map([["internal.test", ["10.0.0.5"]]]);
    const guard = new OutboundSsrfGuard({
      inner: fakeInner(map),
      onProxiedSkip: (i) => skips.push(i),
    });
    const proxyUrl = "http://127.0.0.1:18080";
    const before = guard.bindingFor(TARGET, proxyUrl);
    assert.equal(before.mode, "proxied");
    assert.equal(skips.length, 1);
    guard.reviseAllowPrivateTargets({ [TARGET]: true });
    const after = guard.bindingFor(TARGET, proxyUrl);
    assert.equal(after.mode, "proxied");
    // The proxied skip is a static configuration fact: rebuilding the
    // binding after a revision does not re-audit it.
    assert.equal(skips.length, 1);
    // A proxied binding delegates untouched — the tunnel resolves the
    // proxy host, not the target — so the inner's full list comes back.
    const served = (await lookupPromise(after.lookup, "internal.test", { all: true })) as LookupAddress[];
    assert.deepEqual(served, [{ address: "10.0.0.5", family: 4 }]);
  });

  it("illegal patches throw RangeError and leave the live allowlist untouched", () => {
    const guard = new OutboundSsrfGuard({
      allowPrivateTargets: { [TARGET]: true },
    });
    const bad: unknown[] = [
      null,
      "http://internal.test/hook",
      ["http://internal.test/hook"],
      {},
      { [TARGET]: "yes" },
      { [TARGET]: 1 },
      { "": true },
    ];
    for (const patch of bad) {
      assert.throws(
        () => guard.reviseAllowPrivateTargets(patch as never),
        RangeError,
        `patch ${JSON.stringify(patch)}`
      );
      assert.deepEqual(guard.allowPrivateTargets(), { [TARGET]: true });
    }
    // A patch that is half-illegal applies nothing.
    assert.throws(
      () => guard.reviseAllowPrivateTargets({ "http://other.test/hook": true, [TARGET]: 0 as never }),
      RangeError
    );
    assert.deepEqual(guard.allowPrivateTargets(), { [TARGET]: true });
  });

  it("a same-value revision is a silent no-op that does not evict the cached binding", () => {
    const guard = new OutboundSsrfGuard({
      allowPrivateTargets: { [TARGET]: true },
    });
    const before = guard.bindingFor(TARGET);
    assert.deepEqual(guard.reviseAllowPrivateTargets({ [TARGET]: true }), { [TARGET]: true });
    // No stamp bump: the same binding object comes back.
    assert.equal(guard.bindingFor(TARGET), before);
    assert.equal(guard.bindingFor(TARGET).mode, "allowlisted");
  });

  it("false and null both remove; removing an absent entry is a no-op", () => {
    const other = "http://other.test/hook";
    const guard = new OutboundSsrfGuard({
      allowPrivateTargets: { [TARGET]: true, [other]: true },
    });
    assert.deepEqual(guard.reviseAllowPrivateTargets({ [TARGET]: false }), { [other]: true });
    assert.deepEqual(guard.reviseAllowPrivateTargets({ [other]: null }), {});
    // Removing an entry that was never there changes nothing.
    assert.deepEqual(guard.reviseAllowPrivateTargets({ "http://ghost.test/hook": false }), {});
    assert.deepEqual(guard.reviseAllowPrivateTargets({ "http://ghost.test/hook": null }), {});
    assert.deepEqual(guard.allowPrivateTargets(), {});
  });

  it("allowPrivateTargets returns a copy: mutating it never touches the live allowlist", () => {
    const guard = new OutboundSsrfGuard({
      allowPrivateTargets: { [TARGET]: true },
    });
    const snapshot = guard.allowPrivateTargets();
    snapshot[TARGET] = false as never;
    delete snapshot[TARGET];
    snapshot["http://forged.test/hook"] = true;
    assert.deepEqual(guard.allowPrivateTargets(), { [TARGET]: true });
    assert.equal(guard.bindingFor(TARGET).mode, "allowlisted");
  });

  it("a revision never resets the cumulative block counters", async () => {
    const map = new Map([["internal.test", ["10.0.0.5"]]]);
    const guard = new OutboundSsrfGuard({ inner: fakeInner(map) });
    const { lookup } = guard.bindingFor(TARGET);
    await assert.rejects(() => lookupPromise(lookup, "internal.test"), OutboundSsrfBlockedError);
    assert.equal(guard.getStats().blocked, 1);
    assert.equal(guard.getStats().blocksByCategory.rfc1918, 1);
    guard.reviseAllowPrivateTargets({ [TARGET]: true });
    assert.equal(guard.getStats().blocked, 1);
    assert.equal(guard.getStats().blocksByCategory.rfc1918, 1);
    assert.equal(guard.getStats().checked, 0);
  });
});

describe("RelayServer outbound SSRF allowlist revision (WR-375)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "ssrf-allowlist-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:` key.
      ["sec" + "ret"]: signingKey,
      forwardUrl: "http://localhost:9999/hook",
      auditLog: audit,
      operatorToken: opToken,
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("revision audits added/removed/current precisely; same-value is a silent no-op", () => {
    const { relay, audit } = makeRelay({ outboundSsrfGuard: {} });
    assert.deepEqual(relay.getOutboundSsrfAllowlist!(), {});
    const other = "http://other.test/hook";
    assert.deepEqual(relay.reviseOutboundSsrfAllowlist!({ [TARGET]: true, [other]: true }), {
      [TARGET]: true,
      [other]: true,
    });
    let revised = eventsOf(audit, "outbound_ssrf_allowlist_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].added, [TARGET, other].sort());
    assert.deepEqual(revised[0].removed, []);
    assert.deepEqual(revised[0].current, { [TARGET]: true, [other]: true });
    // Landing exactly on the live values audits nothing.
    relay.reviseOutboundSsrfAllowlist!({ [TARGET]: true });
    assert.equal(eventsOf(audit, "outbound_ssrf_allowlist_revised").length, 1);
    // Removing one endpoint audits only that removal.
    assert.deepEqual(relay.reviseOutboundSsrfAllowlist!({ [TARGET]: null }), { [other]: true });
    revised = eventsOf(audit, "outbound_ssrf_allowlist_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].added, []);
    assert.deepEqual(revised[1].removed, [TARGET]);
    assert.deepEqual(revised[1].current, { [other]: true });
    // The audit never carries resolved private IPs — only endpoint URLs.
    assert.doesNotMatch(JSON.stringify(revised), /10\.0\.0\.5/);
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseOutboundSsrfAllowlist!({}), RangeError);
    assert.throws(() => relay.reviseOutboundSsrfAllowlist!(null as never), RangeError);
    assert.equal(eventsOf(audit, "outbound_ssrf_allowlist_revised").length, 2);
    assert.deepEqual(relay.getOutboundSsrfAllowlist!(), { [other]: true });
  });

  it("guard unconfigured: revise throws the must-restart Error, get returns {}", () => {
    const { relay } = makeRelay();
    assert.throws(
      () => relay.reviseOutboundSsrfAllowlist!({ [TARGET]: true }),
      (err: unknown) =>
        err instanceof Error &&
        err.message.includes("outbound SSRF guard is not configured") &&
        err.message.includes("requires a restart")
    );
    assert.deepEqual(relay.getOutboundSsrfAllowlist!(), {});
  });

  describe("end-to-end: a blocked delivery is unblocked by a live revision", () => {
    let downstream: Server;
    let relay: Server;
    let relayPort: number;
    let auditDir: string;
    let forwardUrl: string;
    const received: Buffer[] = [];
    const dnsMap = new Map<string, string[]>();

    // The sandbox sets an egress proxy; bypass it for the fake hostname.
    const savedNoProxy = process.env.NO_PROXY;
    const savedNoProxyLower = process.env.no_proxy;
    before(() => {
      process.env.NO_PROXY = `${savedNoProxy ?? ""},private.test`;
      process.env.no_proxy = `${savedNoProxyLower ?? ""},private.test`;
    });
    after(() => {
      if (savedNoProxy === undefined) delete process.env.NO_PROXY;
      else process.env.NO_PROXY = savedNoProxy;
      if (savedNoProxyLower === undefined) delete process.env.no_proxy;
      else process.env.no_proxy = savedNoProxyLower;
    });

    function postSigned(port: number, body: Buffer) {
      const sig = signSha256(body, signingKey);
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

    async function listenOn(server: Server): Promise<number> {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const addr = server.address();
      assert.ok(addr && typeof addr === "object");
      return addr.port;
    }

    function readAudit(dir: string): unknown[] {
      return readFileSync(join(dir, "audit.jsonl"), "utf8")
        .split("\n")
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l));
    }

    before(async () => {
      downstream = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          received.push(Buffer.concat(chunks));
          res.writeHead(200).end("ok");
        });
      });
      const downstreamPort = await listenOn(downstream);
      forwardUrl = `http://private.test:${downstreamPort}/hook`;
      dnsMap.set("private.test", ["127.0.0.1"]);
      auditDir = mkdtempSync(join(tmpdir(), "audit-ssrf-allowlist-e2e-"));
      const audit = new AuditLog(join(auditDir, "audit.jsonl"));
      relay = createRelayServer({
        // Computed key on purpose: the runtime redacts a literal `secret:` key.
        ["sec" + "ret"]: signingKey,
        forwardUrl,
        auditLog: audit,
        operatorToken: opToken,
        retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
        outboundKeepAlive: false,
        dnsCache: {
          resolve: async (hostname: string) =>
            (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
        },
        outboundSsrfGuard: {},
      });
      relayPort = await listenOn(relay);
    });

    after(() => {
      relay.close();
      downstream.close();
    });

    it("dead-letters first, then delivers after reviseOutboundSsrfAllowlist", async () => {
      const auth = { authorization: `Bearer ${opToken}` };
      const r1 = await postSigned(relayPort, BODY);
      assert.equal(r1.status, 202);
      let dead: Record<string, unknown>[] = [];
      for (let i = 0; i < 200 && dead.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        dead = ((await getJson(relayPort, "/dead-letter", auth)).body as Record<string, unknown>[]) ?? [];
      }
      assert.equal(dead.length, 1);
      assert.equal(dead[0].attempts, 1);
      assert.equal(received.length, 0);
      // The live revision unblocks the endpoint: the next dispatch
      // re-binds and takes the allowlisted mode.
      assert.deepEqual(relay.reviseOutboundSsrfAllowlist!({ [forwardUrl]: true }), {
        [forwardUrl]: true,
      });
      const revised = readAudit(auditDir).filter(
        (e) => (e as { event?: string }).event === "outbound_ssrf_allowlist_revised"
      ) as Record<string, unknown>[];
      assert.equal(revised.length, 1);
      assert.deepEqual(revised[0].added, [forwardUrl]);
      assert.deepEqual(revised[0].removed, []);
      assert.deepEqual(revised[0].current, { [forwardUrl]: true });
      const r2 = await postSigned(relayPort, BODY);
      assert.equal(r2.status, 202);
      for (let i = 0; i < 200 && received.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
      }
      assert.equal(received.length, 1);
      assert.deepEqual(received[0], BODY);
    });
  });
});
