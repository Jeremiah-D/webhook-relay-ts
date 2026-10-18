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
  assertValidVersionRoutes,
  normalizeVersionSunsetAt,
  type ApiVersionAdapter,
} from "../src/version.ts";

// NB: the constant is deliberately NOT named SECRET — the runtime's
// secret redaction rewrites `secret: SECRET` in written test files.
const TEST_KEY = "relay-test-signing-key";
const OPERATOR_TOKEN = "operator-test-token";

const v1Adapter: ApiVersionAdapter = {
  version: "v1",
  adapt: (p: Buffer) => p, // already current schema
};
const v2Adapter: ApiVersionAdapter = {
  version: "v2",
  adapt: (p: Buffer) => p,
};

describe("normalizeVersionSunsetAt", () => {
  it("accepts undefined as 'never sunsets'", () => {
    assert.equal(normalizeVersionSunsetAt(undefined), undefined);
  });

  it("accepts epoch-ms and ISO-8601 strings", () => {
    assert.equal(normalizeVersionSunsetAt(1700000000000), 1700000000000);
    assert.equal(
      normalizeVersionSunsetAt("2030-01-01T00:00:00.000Z"),
      Date.parse("2030-01-01T00:00:00.000Z")
    );
  });

  it("rejects invalid moments with RangeError", () => {
    for (const bad of [NaN, -1, Infinity, "not-a-date", "", {}, [], true]) {
      assert.throws(() => normalizeVersionSunsetAt(bad), RangeError, String(bad));
    }
  });
});

describe("ApiVersionRouter sunset validation", () => {
  it("rejects a bad sunsetAt at startup", () => {
    assert.throws(
      () =>
        assertValidVersionRoutes([
          { prefix: "/v1", adapter: v1Adapter, sunsetAt: "yesterday" },
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidVersionRoutes([
          { prefix: "/v1", adapter: v1Adapter, sunsetAt: -5 },
        ]),
      RangeError
    );
  });

  it("effectiveSunset reads config, override, and clear", () => {
    const past = Date.now() - 60_000;
    const router = new ApiVersionRouter([
      { prefix: "/v1", adapter: v1Adapter, sunsetAt: past },
      { prefix: "/v2", adapter: v2Adapter },
    ]);
    assert.equal(router.effectiveSunset("/v1"), past);
    assert.equal(router.effectiveSunset("/v2"), undefined);
    // Runtime override wins over config.
    const future = Date.now() + 3_600_000;
    router.setSunset("/v1", future);
    assert.equal(router.effectiveSunset("/v1"), future);
    // Explicit null clears the sunset entirely.
    router.setSunset("/v1", null);
    assert.equal(router.effectiveSunset("/v1"), undefined);
    // clearSunset drops the override, restoring configured state.
    router.setSunset("/v1", future);
    router.clearSunset("/v1");
    assert.equal(router.effectiveSunset("/v1"), past);
    // Unknown prefixes are a programming error.
    assert.throws(() => router.setSunset("/nope", future), RangeError);
    assert.throws(() => router.clearSunset("/nope"), RangeError);
    assert.throws(() => router.setSunset("/v1", "bogus"), RangeError);
  });
});

describe("server version sunset (WR-144)", () => {
  const servers: Server[] = [];
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
    await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
    const addr = stub.address();
    assert.ok(addr && typeof addr === "object");
    stubPort = addr.port;
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function post(
    port: number,
    path: string,
    body: Buffer,
    headers: Record<string, string> = {}
  ): Promise<{ status: number; text: string; headers: Record<string, string | string[] | undefined> }> {
    return new Promise((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            text: Buffer.concat(chunks).toString(),
            headers: res.headers as Record<string, string | string[] | undefined>,
          })
        );
      });
      r.on("error", reject);
      r.end(body);
    });
  }

  function get(
    port: number,
    path: string,
    token?: string
  ): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {};
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      });
      r.on("error", reject);
      r.end();
    });
  }

  function postJson(
    port: number,
    path: string,
    body: unknown,
    token?: string
  ): Promise<{ status: number; json: unknown }> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString() || "{}"),
          })
        );
      });
      r.on("error", reject);
      r.end(JSON.stringify(body));
    });
  }

  function signedHeaders(body: Buffer): Record<string, string> {
    return {
      "x-signature": signSha256(body, TEST_KEY),
      "content-type": "application/json",
    };
  }

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "sunset-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: OPERATOR_TOKEN,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      versions: {
        routes: [
          { prefix: "/v1", adapter: v1Adapter, sunsetAt: Date.now() - 60_000 },
          { prefix: "/v2", adapter: v2Adapter, sunsetAt: Date.now() + 3_600_000 },
          { prefix: "/v3", adapter: { version: "v3", adapt: (p: Buffer) => p } },
        ],
      },
      ...extra,
    } as Parameters<typeof createRelayServer>[0]);
    servers.push(relay);
    return { relay, audit };
  }

  it("answers 410 with the Sunset header for a sunset version", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    const body = Buffer.from(JSON.stringify({ a: 1 }));
    const res = await post(port, "/v1/hook", body, signedHeaders(body));
    assert.equal(res.status, 410);
    assert.ok(res.headers["sunset"], "Sunset header must be present");
    // RFC 8594: the Sunset value is an HTTP-date of the sunset moment.
    assert.ok(!Number.isNaN(Date.parse(res.headers["sunset"] as string)));
    assert.match(res.text, /v1/);
    // Nothing was delivered downstream.
    assert.equal(receivedRaw.length, 0);
    // Audited as rejected with reason version_sunset.
    const rejected = audit.query({ event: ["rejected"] }) as {
      reason?: string;
      version?: string;
      sunsetAt?: string;
    }[];
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].reason, "version_sunset");
    assert.equal(rejected[0].version, "v1");
    assert.ok(rejected[0].sunsetAt);
    // The version counter records the rejection.
    const metrics = (await get(port, "/metrics", OPERATOR_TOKEN)).text;
    assert.match(metrics, /relay_inbound_version_total\{version="v1",status="rejected"\} 1/);
  });

  it("leaves future and unset versions untouched", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    receivedRaw = [];
    for (const path of ["/v2/hook", "/v3/hook"]) {
      const body = Buffer.from(JSON.stringify({ a: 1 }));
      const res = await post(port, path, body, signedHeaders(body));
      assert.equal(res.status, 202, path);
    }
    const deadline = Date.now() + 5000;
    while (receivedRaw.length < 2 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(receivedRaw.length, 2);
  });

  it("hot-updates a sunset via the operator endpoint and audits it", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    // /v2 is live now.
    const live = Buffer.from(JSON.stringify({ a: 1 }));
    assert.equal((await post(port, "/v2/hook", live, signedHeaders(live))).status, 202);
    // Sunset it via the operator endpoint.
    const past = Date.now() - 1000;
    const set = await postJson(port, "/config/version-sunset", { prefix: "/v2", sunsetAt: past }, OPERATOR_TOKEN);
    assert.equal(set.status, 200);
    assert.equal((set.json as { prefix: string }).prefix, "/v2");
    // Effective immediately: 410 now.
    const res = await post(port, "/v2/hook", live, signedHeaders(live));
    assert.equal(res.status, 410);
    const updated = audit.query({ event: ["version_sunset_updated"] }) as {
      prefix?: string;
      sunsetAt?: string;
      keyId?: string;
    }[];
    assert.equal(updated.length, 1);
    assert.equal(updated[0].prefix, "/v2");
    assert.equal(updated[0].sunsetAt, new Date(past).toISOString());
    assert.equal(updated[0].keyId, "legacy");
    // Clear it again with null — /v2 serves again.
    const cleared = await postJson(port, "/config/version-sunset", { prefix: "/v2", sunsetAt: null }, OPERATOR_TOKEN);
    assert.equal(cleared.status, 200);
    assert.equal((cleared.json as { sunsetAt: null }).sunsetAt, null);
    assert.equal((await post(port, "/v2/hook", live, signedHeaders(live))).status, 202);
  });

  it("rejects bad operator updates with 400 and changes nothing", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    const live = Buffer.from(JSON.stringify({ a: 1 }));
    // Unknown prefix.
    assert.equal(
      (await postJson(port, "/config/version-sunset", { prefix: "/nope", sunsetAt: Date.now() }, OPERATOR_TOKEN)).status,
      400
    );
    // Invalid moment.
    assert.equal(
      (await postJson(port, "/config/version-sunset", { prefix: "/v2", sunsetAt: "bogus" }, OPERATOR_TOKEN)).status,
      400
    );
    // Missing sunsetAt.
    assert.equal(
      (await postJson(port, "/config/version-sunset", { prefix: "/v2" }, OPERATOR_TOKEN)).status,
      400
    );
    // Bad bearer.
    assert.equal(
      (await postJson(port, "/config/version-sunset", { prefix: "/v2", sunsetAt: Date.now() }, "wrong")).status,
      403
    );
    // /v2 still serves — none of the above mutated it.
    assert.equal((await post(port, "/v2/hook", live, signedHeaders(live))).status, 202);
  });

  it("GET /config/version-sunset lists every route's sunset", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    const res = await get(port, "/config/version-sunset", OPERATOR_TOKEN);
    assert.equal(res.status, 200);
    const body = JSON.parse(res.text) as {
      sunsets: { prefix: string; version: string; sunsetAt: string | null; source: string }[];
    };
    const byPrefix = new Map(body.sunsets.map((s) => [s.prefix, s]));
    assert.equal(byPrefix.get("/v1")?.version, "v1");
    assert.equal(byPrefix.get("/v1")?.source, "config");
    assert.ok(byPrefix.get("/v1")?.sunsetAt);
    assert.equal(byPrefix.get("/v2")?.source, "config");
    assert.equal(byPrefix.get("/v3")?.sunsetAt, null);
    assert.equal(byPrefix.get("/v3")?.source, "none");
    // No bearer → 403; unconfigured versioning → 404.
    assert.equal((await get(port, "/config/version-sunset")).status, 403);
    const { relay: plain } = makeRelay({ versions: undefined });
    const plainPort = await listen(plain);
    assert.equal((await get(plainPort, "/config/version-sunset", OPERATOR_TOKEN)).status, 404);
  });
});
