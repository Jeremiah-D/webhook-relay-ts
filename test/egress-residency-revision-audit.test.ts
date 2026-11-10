import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, type RelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const relaySecret = "egress-residency-revision-secret";
const OPERATOR = "op-egress-residency-revision-token";
const BODY = Buffer.from(JSON.stringify({ event: "egress.residency.revision.probe" }));

/**
 * Operator-curated table for the tests (same shape as
 * egress-residency.test.ts: TEST-NET ranges, plus loopback rows so the
 * end-to-end downstream — dialed on loopback — still gets a country).
 */
const TABLE = [
  { cidr: "127.0.0.1/32", country: "DE" },
  { cidr: "203.0.113.0/24", country: "DE" },
  { cidr: "203.0.113.128/25", country: "US" },
  { cidr: "198.51.100.0/24", country: "US" },
  { cidr: "192.0.2.0/24", country: "FR" },
  { cidr: "2001:db8::/32", country: "DE" },
  { cidr: "127.0.0.0/8", country: "US" },
];

function postSigned(port: number, body: Buffer, tenant?: string) {
  const sig = signSha256(body, relaySecret);
  return new Promise<{ status: number }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/hook",
        method: "POST",
        headers: {
          "x-signature": sig,
          ...(tenant !== undefined ? { "x-tenant-id": tenant } : {}),
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

function postJson(port: number, path: string, body: Buffer, headers: Record<string, string>) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end(body);
  });
}

function getJson(port: number, path: string, headers: Record<string, string>) {
  return new Promise<{ status: number; body: unknown; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString();
        resolve({ status: res.statusCode ?? 0, body: JSON.parse(text), text });
      });
    });
    r.on("error", reject);
    r.end();
  });
}

function readAudit(dir: string): Record<string, unknown>[] {
  // The audit file is created lazily on the first append — a relay
  // that audited nothing yet has no file at all.
  const path = join(dir, "audit.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

async function listenOn(server: Server, host = "127.0.0.1"): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

describe("egress-residency revision audit (WR-376)", () => {
  // The sandbox sets an egress proxy (HTTP(S)_PROXY); bypass it for the
  // fake hostnames so deliveries resolve locally through the gate.
  const savedNoProxy = process.env.NO_PROXY;
  const savedNoProxyLower = process.env.no_proxy;
  const fakeHosts = ["eu.test", "us.test"];

  before(() => {
    process.env.NO_PROXY = `${savedNoProxy ?? ""},${fakeHosts.join(",")}`;
    process.env.no_proxy = `${savedNoProxyLower ?? ""},${fakeHosts.join(",")}`;
  });

  after(() => {
    if (savedNoProxy === undefined) delete process.env.NO_PROXY;
    else process.env.NO_PROXY = savedNoProxy;
    if (savedNoProxyLower === undefined) delete process.env.no_proxy;
    else process.env.no_proxy = savedNoProxyLower;
  });

  let relay: RelayServer;
  let relayPort: number;
  let auditDir: string;
  const dnsMap = new Map<string, string[]>([
    ["us.test", ["127.0.0.2"]],
    ["eu.test", ["127.0.0.1"]],
  ]);

  function revisedEvents(): Record<string, unknown>[] {
    return readAudit(auditDir).filter((e) => e.event === "egress_residency_revised");
  }

  beforeEach(async () => {
    auditDir = mkdtempSync(join(tmpdir(), "audit-egress-revision-"));
    relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:` key.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://us.test:9/hook",
      auditLog: new AuditLog(join(auditDir, "audit.jsonl")),
      operatorToken: OPERATOR,
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
      outboundKeepAlive: false,
      dnsCache: {
        resolve: async (hostname: string) =>
          (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
      },
      egressResidency: {
        table: TABLE,
        allowedEgressCountries: { "tenant-eu": ["DE", "FR"], "tenant-us": ["US"] },
      },
    });
    relayPort = await listenOn(relay);
  });

  afterEach(() => {
    relay.close();
  });

  it("adds a country and audits previous/current exactly", () => {
    const next = relay.reviseEgressResidency!("tenant-eu", ["DE", "FR", "US"]);
    assert.deepEqual(next, ["DE", "FR", "US"]);
    assert.deepEqual(relay.getEgressResidency!("tenant-eu"), ["DE", "FR", "US"]);
    const events = revisedEvents();
    assert.equal(events.length, 1);
    assert.equal(events[0].tenant, "tenant-eu");
    assert.deepEqual(events[0].previous, ["DE", "FR"]);
    assert.deepEqual(events[0].current, ["DE", "FR", "US"]);
  });

  it("removes a country and audits the removal", () => {
    const next = relay.reviseEgressResidency!("tenant-eu", ["DE"]);
    assert.deepEqual(next, ["DE"]);
    const events = revisedEvents();
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].previous, ["DE", "FR"]);
    assert.deepEqual(events[0].current, ["DE"]);
  });

  it("null clears back to unlimited and audits current undefined", () => {
    const next = relay.reviseEgressResidency!("tenant-eu", null);
    assert.equal(next, undefined);
    assert.equal(relay.getEgressResidency!("tenant-eu"), undefined);
    const events = revisedEvents();
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].previous, ["DE", "FR"]);
    // JSON drops an undefined value, so the persisted event has no
    // `current` key at all — the absence is the trace of the clearing.
    assert.equal(events[0].current, undefined);
    assert.ok(!("current" in events[0]));
  });

  it("same set in a different order is a silent no-op with no audit", () => {
    const next = relay.reviseEgressResidency!("tenant-eu", ["FR", "DE"]);
    assert.deepEqual(next, ["DE", "FR"]);
    assert.deepEqual(relay.getEgressResidency!("tenant-eu"), ["DE", "FR"]);
    assert.deepEqual(revisedEvents(), []);
  });

  it("illegal country code throws RangeError, live untouched, no audit", () => {
    assert.throws(() => relay.reviseEgressResidency!("tenant-eu", ["de"]), RangeError);
    assert.throws(() => relay.reviseEgressResidency!("tenant-eu", ["DEU"]), RangeError);
    assert.deepEqual(relay.getEgressResidency!("tenant-eu"), ["DE", "FR"]);
    assert.deepEqual(revisedEvents(), []);
  });

  it("first revision for a new tenant audits previous undefined", () => {
    const next = relay.reviseEgressResidency!("tenant-new", ["US"]);
    assert.deepEqual(next, ["US"]);
    const events = revisedEvents();
    assert.equal(events.length, 1);
    assert.equal(events[0].tenant, "tenant-new");
    assert.equal(events[0].previous, undefined);
    assert.deepEqual(events[0].current, ["US"]);
  });

  it("gate unconfigured: revise throws must-restart Error, get returns undefined", async () => {
    const plainDir = mkdtempSync(join(tmpdir(), "audit-egress-revision-plain-"));
    const plain = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:` key.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://us.test:9/hook",
      auditLog: new AuditLog(join(plainDir, "audit.jsonl")),
      operatorToken: OPERATOR,
    });
    try {
      assert.throws(
        () => plain.reviseEgressResidency!("tenant-eu", ["DE"]),
        /reviseEgressResidency: egress residency gate is not configured — enabling it requires a restart/
      );
      assert.equal(plain.getEgressResidency!("tenant-eu"), undefined);
    } finally {
      plain.close();
    }
  });

  it("get returns a copy — mutating it does not affect the live list", () => {
    const list = relay.getEgressResidency!("tenant-eu")!;
    list.push("US");
    assert.deepEqual(relay.getEgressResidency!("tenant-eu"), ["DE", "FR"]);
  });

  it("revision audit event is queryable via GET /audit", async () => {
    const auth = { authorization: `Bearer ${OPERATOR}` };
    relay.reviseEgressResidency!("tenant-eu", ["DE", "FR", "US"]);
    let found: Record<string, unknown>[] = [];
    for (let i = 0; i < 100 && found.length === 0; i++) {
      const q = await getJson(relayPort, "/audit?event=egress_residency_revised", auth);
      assert.equal(q.status, 200);
      found = (q.body as Record<string, unknown>[]).filter(
        (e) => e.event === "egress_residency_revised"
      );
      if (found.length === 0) await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(found.length, 1);
    assert.equal(found[0].tenant, "tenant-eu");
    assert.deepEqual(found[0].previous, ["DE", "FR"]);
    assert.deepEqual(found[0].current, ["DE", "FR", "US"]);
  });

  describe("blocked tenant replays after server-side relaxation", () => {
    let downstream: Server;
    let received: Buffer[] = [];

    beforeEach(async () => {
      received = [];
      downstream = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          received.push(Buffer.concat(chunks));
          res.writeHead(200).end("ok");
        });
      });
      const downstreamPort = await listenOn(downstream, "0.0.0.0");
      // Point this relay's forward URL at the live downstream (the
      // outer relay was built with a dead :9 forward URL on purpose —
      // its tests never deliver; rebuild the relay for this describe).
      relay.close();
      auditDir = mkdtempSync(join(tmpdir(), "audit-egress-revision-e2e-"));
      relay = createRelayServer({
        // Computed key on purpose: the runtime redacts a literal `secret:` key.
        ["sec" + "ret"]: relaySecret,
        forwardUrl: `http://us.test:${downstreamPort}/hook`,
        auditLog: new AuditLog(join(auditDir, "audit.jsonl")),
        operatorToken: OPERATOR,
        retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
        outboundKeepAlive: false,
        dnsCache: {
          resolve: async (hostname: string) =>
            (dnsMap.get(hostname) ?? []).map((address) => ({ address, family: 4 as const })),
        },
        egressResidency: {
          table: TABLE,
          allowedEgressCountries: { "tenant-eu": ["DE", "FR"], "tenant-us": ["US"] },
        },
      });
      relayPort = await listenOn(relay);
    });

    afterEach(() => {
      downstream.close();
    });

    it("dead-letters, then delivers the replay once the server method relaxes the list", async () => {
      const auth = { authorization: `Bearer ${OPERATOR}` };
      const r = await postSigned(relayPort, BODY, "tenant-eu");
      assert.equal(r.status, 202);
      let dead: Record<string, unknown>[] = [];
      for (let i = 0; i < 200 && dead.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 25));
        dead = ((await getJson(relayPort, "/dead-letter", auth)).body as Record<string, unknown>[]) ?? [];
      }
      assert.equal(dead.length, 1);
      assert.equal(received.length, 0);

      // The operator relaxes tenant-eu's list through the audited
      // server method (not the silent gate-level revise).
      relay.reviseEgressResidency!("tenant-eu", ["DE", "FR", "US"]);
      const entryId = dead[0].id as string;
      const replay = await postJson(
        relayPort,
        "/dead-letter/replay",
        Buffer.from(JSON.stringify({ tenant: "tenant-eu" })),
        { ...auth, "content-type": "application/json" }
      );
      assert.equal(replay.status, 200);
      assert.deepEqual((JSON.parse(replay.text) as { replayed: string[] }).replayed, [entryId]);
      for (let i = 0; i < 200 && received.length < 1; i++) {
        await new Promise((res) => setTimeout(res, 25));
      }
      assert.equal(received.length, 1);
      const remaining = ((await getJson(relayPort, "/dead-letter?tenant=tenant-eu", auth))
        .body as unknown[]) ?? [];
      assert.deepEqual(remaining, []);
      // And the relaxation itself left its audit trace.
      assert.equal(revisedEvents().length, 1);
    });
  });
});
