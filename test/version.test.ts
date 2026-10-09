import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  ApiVersionRouter,
  VersionMetrics,
  assertValidVersionRoutes,
  type ApiVersionAdapter,
} from "../src/version.ts";

const SECRET = "relay-secret";

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      assert.ok(addr && typeof addr === "object");
      resolve(addr.port);
    });
  });
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "GET", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end();
  });
}

// v1 speaks { amount, currency }; the current schema speaks { amount_cents, currency }.
const v1Adapter: ApiVersionAdapter = {
  version: "v1",
  adapt(payload: Buffer): Buffer {
    const obj = JSON.parse(payload.toString("utf8")) as { amount: number; currency: string };
    return Buffer.from(JSON.stringify({ amount_cents: obj.amount * 100, currency: obj.currency }));
  },
};

const v2Adapter: ApiVersionAdapter = {
  version: "v2",
  adapt(payload: Buffer): Buffer {
    return payload; // already current schema
  },
};

describe("ApiVersionRouter", () => {
  const router = new ApiVersionRouter([
    { prefix: "/v", adapter: { version: "v0", adapt: (p: Buffer) => p } },
    { prefix: "/v1", adapter: v1Adapter },
  ]);

  it("matches exact and prefixed paths on segment boundaries", () => {
    assert.equal(router.match("/v1")?.adapter.version, "v1");
    assert.equal(router.match("/v1/")?.adapter.version, "v1");
    assert.equal(router.match("/v1/hooks/stripe")?.adapter.version, "v1");
  });

  it("never matches across segment boundaries", () => {
    assert.equal(router.match("/v10"), undefined);
    assert.equal(router.match("/v1x/hooks"), undefined);
    assert.equal(router.match("/"), undefined);
    assert.equal(router.match("/hooks/stripe"), undefined);
  });

  it("prefers the longest matching prefix", () => {
    assert.equal(router.match("/v/hooks")?.adapter.version, "v0");
    assert.equal(router.match("/v1/hooks")?.adapter.version, "v1");
  });

  it("rejects invalid route tables at startup", () => {
    assert.throws(() => assertValidVersionRoutes([]), RangeError);
    assert.throws(
      () => assertValidVersionRoutes([{ prefix: "v1", adapter: v1Adapter }]),
      RangeError
    );
    assert.throws(
      () => assertValidVersionRoutes([{ prefix: "/v1/", adapter: v1Adapter }]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidVersionRoutes([
          { prefix: "/v1", adapter: v1Adapter },
          { prefix: "/v1", adapter: v2Adapter },
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidVersionRoutes([
          { prefix: "/v1", adapter: { version: "", adapt: (p: Buffer) => p } },
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidVersionRoutes([
          { prefix: "/v1", adapter: { version: "v1" } as ApiVersionAdapter },
        ]),
      RangeError
    );
  });
});

describe("VersionMetrics", () => {
  it("renders nothing when no versions are configured", () => {
    assert.equal(new VersionMetrics().render(), "");
  });

  it("renders per-version intake counters", () => {
    const m = new VersionMetrics();
    m.record("v1", "accepted");
    m.record("v1", "accepted");
    m.record("v1", "rejected");
    m.record("none", "accepted");
    const text = m.render();
    assert.match(text, /relay_inbound_version_total\{version="v1",status="accepted"\} 2/);
    assert.match(text, /relay_inbound_version_total\{version="v1",status="rejected"\} 1/);
    assert.match(text, /relay_inbound_version_total\{version="none",status="accepted"\} 1/);
  });
});

describe("server API version routing", () => {
  let stub: Server;
  let stubPort: number;
  let receivedRaw: Buffer[];

  before(async () => {
    receivedRaw = [];
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        receivedRaw.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  async function waitForDelivery(count: number): Promise<void> {
    const deadline = Date.now() + 5000;
    while (receivedRaw.length < count && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(receivedRaw.length, count);
  }

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      versions: { routes: [{ prefix: "/v1", adapter: v1Adapter }] },
      ...extra,
    } as Parameters<typeof createRelayServer>[0]);
    return { relay, audit };
  }

  it("adapts the versioned payload and audits the version", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      receivedRaw = [];
      const v1Body = Buffer.from(JSON.stringify({ amount: 42, currency: "USD" }));
      const res = await post(port, "/v1/hook", v1Body, {
        "x-signature": signSha256(v1Body, SECRET), // signature covers the raw v1 body
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitForDelivery(1);
      // The downstream sees the current schema, not the v1 dialect.
      assert.deepEqual(JSON.parse(receivedRaw[0].toString()), {
        amount_cents: 4200,
        currency: "USD",
      });
      const accepted = audit.query({ event: ["accepted"] }) as { version?: string }[];
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].version, "v1");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("leaves unversioned paths untouched (backward compatible)", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      receivedRaw = [];
      const body = Buffer.from(JSON.stringify({ amount_cents: 4200, currency: "USD" }));
      const res = await post(port, "/hook", body, {
        "x-signature": signSha256(body, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitForDelivery(1);
      assert.deepEqual(receivedRaw[0], body);
      const accepted = audit.query({ event: ["accepted"] }) as { version?: string }[];
      assert.equal(accepted.length, 1);
      assert.ok(!("version" in accepted[0]));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("answers 400 when the adapter throws and never enqueues", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      versions: {
        routes: [
          {
            prefix: "/v1",
            adapter: {
              version: "v1",
              adapt(): Buffer {
                throw new Error("cannot adapt this shape");
              },
            },
          },
        ],
      },
    });
    const port = await listen(relay);
    try {
      receivedRaw = [];
      const body = Buffer.from(JSON.stringify({ broken: true }));
      const res = await post(port, "/v1/hook", body, {
        "x-signature": signSha256(body, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 400);
      // Nothing enqueued, nothing delivered.
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(receivedRaw.length, 0);
      const rejected = audit.query({ event: ["rejected"] }) as {
        reason?: string;
        version?: string;
      }[];
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason, "version_adapt_failed");
      assert.equal(rejected[0].version, "v1");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("dedups on the adapted payload across versions", async () => {
    const { relay } = makeRelay({
      versions: {
        routes: [
          { prefix: "/v1", adapter: v1Adapter },
          { prefix: "/v2", adapter: v2Adapter },
        ],
      },
      dedup: { windowMs: 60_000 },
    });
    const port = await listen(relay);
    try {
      receivedRaw = [];
      // v1 {amount:42} and current-schema {amount_cents:4200} are the same event.
      const v1Body = Buffer.from(JSON.stringify({ amount: 42, currency: "USD" }));
      const v2Body = Buffer.from(JSON.stringify({ amount_cents: 4200, currency: "USD" }));
      const r1 = await post(port, "/v1/hook", v1Body, {
        "x-signature": signSha256(v1Body, SECRET),
      });
      assert.equal(r1.status, 202);
      const r2 = await post(port, "/v2/hook", v2Body, {
        "x-signature": signSha256(v2Body, SECRET),
      });
      assert.equal(r2.status, 202);
      assert.match(r2.text, /"duplicate":true/);
      await waitForDelivery(1);
      // Exactly one downstream delivery: the canonical adapted body.
      assert.deepEqual(JSON.parse(receivedRaw[0].toString()), {
        amount_cents: 4200,
        currency: "USD",
      });
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("exposes version intake in the Prometheus exposition", async () => {
    const { relay } = makeRelay({ operatorToken: "op" });
    const port = await listen(relay);
    try {
      const v1Body = Buffer.from(JSON.stringify({ amount: 1, currency: "USD" }));
      await post(port, "/v1/hook", v1Body, { "x-signature": signSha256(v1Body, SECRET) });
      const plain = Buffer.from(JSON.stringify({ ok: true }));
      await post(port, "/hook", plain, { "x-signature": signSha256(plain, SECRET) });
      const res = await get(port, "/metrics", { authorization: "Bearer op" });
      assert.equal(res.status, 200);
      assert.match(res.text, /relay_inbound_version_total\{version="v1",status="accepted"\} 1/);
      assert.match(res.text, /relay_inbound_version_total\{version="none",status="accepted"\} 1/);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("keeps /metrics byte-identical when versioning is not configured", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      operatorToken: "op",
    });
    const port = await listen(relay);
    try {
      const res = await get(port, "/metrics", { authorization: "Bearer op" });
      assert.equal(res.status, 200);
      assert.ok(!res.text.includes("relay_inbound_version_total"));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
