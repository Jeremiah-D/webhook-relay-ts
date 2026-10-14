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
  assertValidCompatibilityCorpus,
  createRequiredFieldsSchema,
  DEFAULT_COMPAT_CORPUS_MAX_SAMPLES,
  InboundSchemaRegistry,
  type EndpointSchemaRule,
  type PayloadSchema,
  type SchemaRegistration,
} from "../src/schema.ts";
import type { ApiVersionAdapter } from "../src/version.ts";

const TEST_KEY = "relay-secret";
const OPERATOR_TOKEN = "op-token";

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

// v1-era shape: { amount_cents, currency }. v2 adds a mandatory region.
const v1Schema: PayloadSchema = createRequiredFieldsSchema("payment-callback", "1", [
  "amount_cents",
  "currency",
]);
const v2Schema: PayloadSchema = createRequiredFieldsSchema("payment-callback", "2", [
  "amount_cents",
  "currency",
  "region",
]);

const v1Samples = [
  { amount_cents: 4200, currency: "USD" },
  { amount_cents: 100, currency: "EUR" },
];

function registryOf(rules: EndpointSchemaRule[]): InboundSchemaRegistry {
  return new InboundSchemaRegistry(rules);
}

describe("compatibility corpus validation", () => {
  it("accepts a plain sample array and the options object form", () => {
    const a = assertValidCompatibilityCorpus(v1Samples, "w");
    assert.deepEqual(a.manualSamples, v1Samples);
    assert.equal(a.accumulate, false);
    assert.equal(a.maxSamples, DEFAULT_COMPAT_CORPUS_MAX_SAMPLES);
    const b = assertValidCompatibilityCorpus(
      { samples: v1Samples, accumulate: true, maxSamples: 5 },
      "w"
    );
    assert.equal(b.accumulate, true);
    assert.equal(b.maxSamples, 5);
  });

  it("rejects malformed corpus configs with RangeError", () => {
    assert.throws(
      () => assertValidCompatibilityCorpus(42 as never, "w"),
      RangeError
    );
    assert.throws(
      () => assertValidCompatibilityCorpus({ samples: "nope" } as never, "w"),
      RangeError
    );
    assert.throws(
      () => assertValidCompatibilityCorpus({ accumulate: "yes" } as never, "w"),
      RangeError
    );
    assert.throws(() => assertValidCompatibilityCorpus({ maxSamples: 0 }, "w"), RangeError);
    assert.throws(() => assertValidCompatibilityCorpus({ maxSamples: 2.5 }, "w"), RangeError);
    assert.throws(
      () => assertValidCompatibilityCorpus({ samples: v1Samples, maxSamples: 1 }, "w"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidCompatibilityCorpus(
          new Array(DEFAULT_COMPAT_CORPUS_MAX_SAMPLES + 1).fill({}),
          "w"
        ),
      RangeError
    );
  });
});

describe("registration-time compatibility gate", () => {
  it("passes with a manual corpus and records gate stats", () => {
    const reg = registryOf([{ pattern: "/hooks/*", schema: v1Schema, compatibilityCorpus: v1Samples }]);
    const stats = reg.getStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].compatGate, "passed");
    assert.equal(stats[0].compatCorpusSize, 2);
    assert.equal(stats[0].corpusSize, 2);
    assert.equal(stats[0].superseded, false);
    assert.equal(reg.select("/hooks/stripe")?.schema.name, "payment-callback");
  });

  it("reports not-tested when no corpus is supplied", () => {
    const reg = registryOf([{ pattern: "/hooks/*", schema: v1Schema }]);
    const stats = reg.getStats();
    assert.equal(stats[0].compatGate, "not-tested");
    assert.equal(stats[0].compatCorpusSize, 0);
    assert.equal(stats[0].corpusSize, 0);
  });

  it("fails registration with RangeError when a sample is rejected — zero registration", () => {
    const reg = new InboundSchemaRegistry();
    assert.throws(
      () =>
        reg.registerSchema({
          pattern: "/hooks/*",
          schema: v2Schema, // requires region; v1 samples lack it
          compatibilityCorpus: v1Samples,
        }),
      RangeError
    );
    assert.equal(reg.select("/hooks/stripe"), undefined);
    assert.deepEqual(reg.getStats(), []);
  });

  it("fails registration with RangeError when the validator throws on a sample", () => {
    const reg = new InboundSchemaRegistry();
    const throwing: PayloadSchema = {
      name: "boom",
      version: "1",
      validate: () => {
        throw new Error("validator bug");
      },
    };
    assert.throws(
      () =>
        reg.registerSchema({ pattern: "/hooks/*", schema: throwing, compatibilityCorpus: v1Samples }),
      RangeError
    );
    assert.deepEqual(reg.getStats(), []);
  });

  it("rejects an exact duplicate registration", () => {
    const reg = new InboundSchemaRegistry();
    reg.registerSchema({ pattern: "/hooks/*", schema: v1Schema });
    assert.throws(
      () => reg.registerSchema({ pattern: "/hooks/*", schema: v1Schema }),
      RangeError
    );
  });

  it("a successful new version supersedes the old one; a failing one leaves it untouched", () => {
    const reg2 = new InboundSchemaRegistry();
    reg2.registerSchema({
      pattern: "/hooks/*",
      schema: v1Schema,
      compatibilityCorpus: v1Samples,
    });
    // Failing v2 registration (v2 requires region; v1 samples lack it):
    // zero registration — the old version keeps serving, never stamped superseded.
    assert.throws(
      () =>
        reg2.registerSchema({
          pattern: "/hooks/*",
          schema: v2Schema,
          compatibilityCorpus: v1Samples,
        }),
      RangeError
    );
    let stats = reg2.getStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].schemaVersion, "1");
    assert.equal(stats[0].superseded, false);
    assert.equal(reg2.select("/hooks/stripe")?.schema.version, "1");

    // Successful v2 registration supersedes v1.
    reg2.registerSchema({
      pattern: "/hooks/*",
      schema: v2Schema,
      compatibilityCorpus: [{ amount_cents: 1, currency: "USD", region: "us" }],
    });
    stats = reg2.getStats();
    assert.equal(stats.length, 2);
    assert.equal(stats[0].superseded, true);
    assert.equal(stats[1].superseded, false);
    assert.equal(stats[1].compatGate, "passed");
    assert.equal(reg2.select("/hooks/stripe")?.schema.version, "2");
  });
});

describe("auto-accumulated corpus", () => {
  it("accumulates accepted payloads, bounded with oldest-first eviction", () => {
    const reg = new InboundSchemaRegistry();
    reg.registerSchema({
      pattern: "/hooks/*",
      schema: v1Schema,
      compatibilityCorpus: { accumulate: true, maxSamples: 3 },
    });
    const active = reg.select("/hooks/a") as SchemaRegistration;
    for (let i = 0; i < 5; i++) {
      reg.noteAcceptedPayload(active, { amount_cents: i, currency: "USD" });
    }
    const stats = reg.getStats();
    assert.equal(stats[0].corpusSize, 3);
    // Gate is not-tested: accumulation happened after registration.
    assert.equal(stats[0].compatGate, "not-tested");
    // Registering a compatible schema gates against the accumulated corpus.
    reg.registerSchema({
      pattern: "/hooks/*",
      schema: createRequiredFieldsSchema("payment-callback", "1b", ["amount_cents"]),
    });
    const after = reg.getStats();
    assert.equal(after[1].compatGate, "passed");
    assert.equal(after[1].compatCorpusSize, 3);
  });

  it("gates a new version against samples accumulated under the old version", () => {
    const reg = new InboundSchemaRegistry();
    reg.registerSchema({
      pattern: "/hooks/*",
      schema: v1Schema,
      compatibilityCorpus: { accumulate: true },
    });
    const active = reg.select("/hooks/a") as SchemaRegistration;
    reg.noteAcceptedPayload(active, { amount_cents: 4200, currency: "USD" });
    // v2 demands region: the accumulated v1 sample rejects it — zero registration.
    assert.throws(
      () => reg.registerSchema({ pattern: "/hooks/*", schema: v2Schema }),
      RangeError
    );
    assert.equal(reg.select("/hooks/a")?.schema.version, "1");
    assert.equal(reg.getStats().filter((s) => !s.superseded).length, 1);
  });

  it("deep-copies accumulated payloads so later mutation cannot corrupt the corpus", () => {
    const reg = new InboundSchemaRegistry();
    reg.registerSchema({
      pattern: "/hooks/*",
      schema: v1Schema,
      compatibilityCorpus: { accumulate: true },
    });
    const active = reg.select("/hooks/a") as SchemaRegistration;
    const payload = { amount_cents: 1, currency: "USD" };
    reg.noteAcceptedPayload(active, payload);
    payload.currency = "MUTATED";
    // A schema requiring currency === "USD" still passes against the pristine copy.
    const strict: PayloadSchema = {
      name: "strict",
      version: "9",
      validate: (p: unknown) => ({
        ok: typeof p === "object" && p !== null && (p as { currency?: string }).currency === "USD",
      }),
    };
    reg.registerSchema({ pattern: "/hooks/*", schema: strict });
    assert.equal(reg.select("/hooks/a")?.schema.version, "9");
  });

  it("ignores noteAcceptedPayload for rules without accumulate", () => {
    const reg = new InboundSchemaRegistry();
    reg.registerSchema({ pattern: "/hooks/*", schema: v1Schema });
    const active = reg.select("/hooks/a") as SchemaRegistration;
    reg.noteAcceptedPayload(active, { amount_cents: 1, currency: "USD" });
    assert.equal(reg.getStats()[0].corpusSize, 0);
    assert.equal(reg.renderMetrics(), "");
  });
});

describe("renderMetrics", () => {
  it("renders gate and corpus-size gauges only when a corpus is configured", () => {
    const reg = new InboundSchemaRegistry();
    assert.equal(reg.renderMetrics(), "");
    reg.registerSchema({
      pattern: "/hooks/*",
      schema: v1Schema,
      compatibilityCorpus: { samples: v1Samples, accumulate: true },
    });
    const text = reg.renderMetrics();
    assert.match(
      text,
      /relay_inbound_schema_compat_gate\{pattern="\/hooks\/\*",schema="payment-callback",version="1",gate="passed"\} 1/
    );
    assert.match(
      text,
      /relay_inbound_schema_corpus_size\{pattern="\/hooks\/\*",schema="payment-callback",version="1"\} 2/
    );
  });
});

describe("server wiring: compat gate (WR-96)", () => {
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

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      operatorToken: OPERATOR_TOKEN,
      ...extra,
    } as Parameters<typeof createRelayServer>[0]);
    return relay;
  }

  async function closeRelay(relay: Server): Promise<void> {
    relay.close();
    await new Promise((r) => relay.once("close", r));
  }

  it("fails startup with RangeError when the manual corpus rejects the schema", () => {
    assert.throws(
      () =>
        makeRelay({
          payloadSchemas: [
            { pattern: "/hooks/*", schema: v2Schema, compatibilityCorpus: v1Samples },
          ],
        }),
      RangeError
    );
  });

  it("fails startup on a malformed compatibilityCorpus", () => {
    assert.throws(
      () =>
        makeRelay({
          payloadSchemas: [
            { pattern: "/hooks/*", schema: v1Schema, compatibilityCorpus: { maxSamples: 0 } },
          ],
        }),
      RangeError
    );
  });

  it("accumulates accepted payloads and exposes gate stats on /metrics", async () => {
    const relay = makeRelay({
      payloadSchemas: [
        {
          pattern: "/hooks/*",
          schema: v1Schema,
          compatibilityCorpus: { accumulate: true, maxSamples: 5 },
        },
      ],
    });
    const port = await listen(relay);
    try {
      for (const amount of [100, 200]) {
        const body = Buffer.from(JSON.stringify({ amount_cents: amount, currency: "USD" }));
        const res = await post(port, "/hooks/stripe", body, {
          "x-signature": signSha256(body, TEST_KEY),
        });
        assert.equal(res.status, 202);
      }
      // A rejected payload never joins the corpus.
      const bad = Buffer.from(JSON.stringify({ amount_cents: 1 }));
      const badRes = await post(port, "/hooks/stripe", bad, {
        "x-signature": signSha256(bad, TEST_KEY),
      });
      assert.equal(badRes.status, 400);
      const metrics = await get(port, "/metrics", { authorization: "Bearer op-token" });
      assert.equal(metrics.status, 200);
      assert.match(
        metrics.text,
        /relay_inbound_schema_compat_gate\{pattern="\/hooks\/\*",schema="payment-callback",version="1",gate="not-tested"\} 1/
      );
      assert.match(
        metrics.text,
        /relay_inbound_schema_corpus_size\{pattern="\/hooks\/\*",schema="payment-callback",version="1"\} 2/
      );
    } finally {
      await closeRelay(relay);
    }
  });

  it("composes with WR-33 version routing: versioned requests feed the stripped-path corpus", async () => {
    const passthrough: ApiVersionAdapter = {
      version: "v1",
      adapt: (payload: Buffer) => payload,
    };
    const relay = makeRelay({
      versions: { routes: [{ prefix: "/v1", adapter: passthrough }] },
      payloadSchemas: [
        {
          pattern: "/hooks/*",
          schema: v1Schema,
          compatibilityCorpus: { accumulate: true, maxSamples: 5 },
        },
      ],
    });
    const port = await listen(relay);
    try {
      // /v1/hooks/stripe strips to /hooks/stripe and matches the one rule.
      const body = Buffer.from(JSON.stringify({ amount_cents: 50, currency: "JPY" }));
      const res = await post(port, "/v1/hooks/stripe", body, {
        "x-signature": signSha256(body, TEST_KEY),
      });
      assert.equal(res.status, 202);
      const metrics = await get(port, "/metrics", { authorization: "Bearer op-token" });
      assert.match(
        metrics.text,
        /relay_inbound_schema_corpus_size\{pattern="\/hooks\/\*",schema="payment-callback",version="1"\} 1/
      );
    } finally {
      await closeRelay(relay);
    }
  });

  it("keeps /metrics byte-identical when no corpus is configured", async () => {
    const relay = makeRelay({
      payloadSchemas: [{ pattern: "/hooks/*", schema: v1Schema }],
    });
    const port = await listen(relay);
    try {
      const metrics = await get(port, "/metrics", { authorization: "Bearer op-token" });
      assert.equal(metrics.status, 200);
      assert.ok(!metrics.text.includes("relay_inbound_schema_compat_gate"));
      assert.ok(!metrics.text.includes("relay_inbound_schema_corpus_size"));
    } finally {
      await closeRelay(relay);
    }
  });
});
