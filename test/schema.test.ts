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
  assertValidEndpointSchemaRules,
  createRequiredFieldsSchema,
  SchemaMetrics,
  selectEndpointSchema,
  type EndpointSchemaRule,
  type PayloadSchema,
} from "../src/schema.ts";

const SECRET = "relay-secret";
const OPERATOR_TOKEN = "op";

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

const paymentSchema = createRequiredFieldsSchema("payment-callback", "3", [
  "amount_cents",
  "currency",
]);

const schemaRules: EndpointSchemaRule[] = [{ pattern: "/hooks/*", schema: paymentSchema }];

describe("schema rule selection and validation", () => {
  const named = (name: string): PayloadSchema => ({
    name,
    version: "1",
    validate: () => ({ ok: true }),
  });

  it("selects exact, prefix, first-match, and falls back to undefined", () => {
    const rules: EndpointSchemaRule[] = [
      { pattern: "/hooks/stripe", schema: named("stripe") },
      { pattern: "/hooks/*", schema: named("generic") },
    ];
    assert.equal(selectEndpointSchema("/hooks/stripe", rules)?.schema.name, "stripe");
    assert.equal(selectEndpointSchema("/hooks/paypal", rules)?.schema.name, "generic");
    assert.equal(selectEndpointSchema("/hooks", rules)?.schema.name, "generic");
    assert.equal(selectEndpointSchema("/other", rules), undefined);
    // Prefix matching is segment-boundary only: /hooksx is not under /hooks/*.
    assert.equal(selectEndpointSchema("/hooksx", rules), undefined);
    assert.equal(selectEndpointSchema("/any", undefined), undefined);
  });

  it("rejects invalid rules at startup", () => {
    assert.doesNotThrow(() => assertValidEndpointSchemaRules(undefined));
    assert.throws(() => assertValidEndpointSchemaRules("x" as never), RangeError);
    assert.throws(
      () => assertValidEndpointSchemaRules([{ pattern: "no-slash", schema: paymentSchema }]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidEndpointSchemaRules([
          { pattern: "/hooks", schema: { ...paymentSchema, name: "" } },
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidEndpointSchemaRules([
          { pattern: "/hooks", schema: { ...paymentSchema, version: "" } },
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidEndpointSchemaRules([
          { pattern: "/hooks", schema: { name: "x", version: "1" } as never },
        ]),
      RangeError
    );
    assert.doesNotThrow(() => assertValidEndpointSchemaRules(schemaRules));
  });

  it("createRequiredFieldsSchema validates presence only", () => {
    assert.deepEqual(paymentSchema.validate({ amount_cents: 0, currency: null }), { ok: true });
    assert.deepEqual(paymentSchema.validate({ amount_cents: 100 }), {
      ok: false,
      errors: ["missing required field: currency"],
    });
    assert.deepEqual(paymentSchema.validate([1, 2]), {
      ok: false,
      errors: ["payload must be a JSON object"],
    });
    assert.deepEqual(paymentSchema.validate(null), {
      ok: false,
      errors: ["payload must be a JSON object"],
    });
    assert.throws(() => createRequiredFieldsSchema("", "1", ["a"]), RangeError);
    assert.throws(() => createRequiredFieldsSchema("x", "", ["a"]), RangeError);
    assert.throws(() => createRequiredFieldsSchema("x", "1", [""]), RangeError);
  });

  it("SchemaMetrics renders empty when idle", () => {
    const m = new SchemaMetrics();
    assert.equal(m.render(), "");
    m.record("payment-callback", "accepted");
    m.record("payment-callback", "rejected");
    const text = m.render();
    assert.match(text, /relay_inbound_schema_total\{schema="payment-callback",status="accepted"\} 1/);
    assert.match(text, /relay_inbound_schema_total\{schema="payment-callback",status="rejected"\} 1/);
  });
});

describe("server inbound schema registry", () => {
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
      payloadSchemas: schemaRules,
      ...extra,
    } as Parameters<typeof createRelayServer>[0]);
    return { relay, audit };
  }

  it("accepts a schema-valid payload and audits schema name + version", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      receivedRaw = [];
      const body = Buffer.from(JSON.stringify({ amount_cents: 4200, currency: "USD" }));
      const res = await post(port, "/hooks/stripe", body, {
        "x-signature": signSha256(body, SECRET),
      });
      assert.equal(res.status, 202);
      await waitForDelivery(1);
      assert.deepEqual(JSON.parse(receivedRaw[0].toString()), { amount_cents: 4200, currency: "USD" });
      const accepted = audit.query({ event: ["accepted"] }) as {
        schema?: string;
        schemaVersion?: string;
      }[];
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].schema, "payment-callback");
      assert.equal(accepted[0].schemaVersion, "3");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("rejects a schema-invalid payload with 400, never enqueues it", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      receivedRaw = [];
      const body = Buffer.from(JSON.stringify({ amount_cents: 4200 })); // missing currency
      const res = await post(port, "/hooks/stripe", body, {
        "x-signature": signSha256(body, SECRET),
      });
      assert.equal(res.status, 400);
      // Never reached the downstream: nothing was enqueued.
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(receivedRaw.length, 0);
      const rejected = audit.query({ event: ["rejected"] }) as {
        reason?: string;
        schema?: string;
        schemaVersion?: string;
        errors?: string[];
      }[];
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason, "schema_failed");
      assert.equal(rejected[0].schema, "payment-callback");
      assert.equal(rejected[0].schemaVersion, "3");
      assert.deepEqual(rejected[0].errors, ["missing required field: currency"]);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("rejects non-JSON bodies with schema_failed", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      const body = Buffer.from("not json at all");
      const res = await post(port, "/hooks/stripe", body, {
        "x-signature": signSha256(body, SECRET),
      });
      assert.equal(res.status, 400);
      const rejected = audit.query({ event: ["rejected"] }) as { reason?: string; errors?: string[] }[];
      assert.equal(rejected[0].reason, "schema_failed");
      assert.deepEqual(rejected[0].errors, ["body is not valid JSON"]);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("is fail-closed when the validator throws", async () => {
    const exploding: PayloadSchema = {
      name: "exploding",
      version: "1",
      validate: () => {
        throw new Error("boom");
      },
    };
    const { relay, audit } = makeRelay({
      payloadSchemas: [{ pattern: "/hooks/*", schema: exploding }],
    });
    const port = await listen(relay);
    try {
      const body = Buffer.from(JSON.stringify({ anything: true }));
      const res = await post(port, "/hooks/x", body, {
        "x-signature": signSha256(body, SECRET),
      });
      assert.equal(res.status, 400);
      const rejected = audit.query({ event: ["rejected"] }) as { reason?: string; errors?: string[] }[];
      assert.equal(rejected[0].reason, "schema_failed");
      assert.match(rejected[0].errors![0], /schema validator threw: boom/);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("leaves unmatched paths untouched (legacy behavior)", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      receivedRaw = [];
      // /plain is not under /hooks/*: no validation, no schema fields.
      const body = Buffer.from(JSON.stringify({ whatever: "goes" }));
      const res = await post(port, "/plain", body, {
        "x-signature": signSha256(body, SECRET),
      });
      assert.equal(res.status, 202);
      await waitForDelivery(1);
      const accepted = audit.query({ event: ["accepted"] }) as { schema?: string }[];
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].schema, undefined);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("schema failures burn no breaker trips or retry budget", async () => {
    const { relay, audit } = makeRelay({
      // A hair-trigger breaker: 2 failures would open it if schema
      // rejections ever touched delivery outcomes.
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2, circuitBreaker: { failureThreshold: 2 } },
    });
    const port = await listen(relay);
    try {
      receivedRaw = [];
      for (let i = 0; i < 5; i++) {
        const body = Buffer.from(JSON.stringify({ broken: i }));
        const res = await post(port, "/hooks/stripe", body, {
          "x-signature": signSha256(body, SECRET),
        });
        assert.equal(res.status, 400);
      }
      const circuitEvents = audit
        .query({ event: ["circuit_open", "circuit_half_open", "circuit_closed"] })
        .length;
      assert.equal(circuitEvents, 0, "schema rejections must not touch the breaker");
      // The relay still delivers fine afterwards: nothing was poisoned.
      const good = Buffer.from(JSON.stringify({ amount_cents: 1, currency: "USD" }));
      const res = await post(port, "/hooks/stripe", good, {
        "x-signature": signSha256(good, SECRET),
      });
      assert.equal(res.status, 202);
      await waitForDelivery(1);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("validates the adapted payload when composed with WR-33 version routing", async () => {
    // v1 speaks { amount, currency }; the current schema speaks { amount_cents, currency }.
    const v1Adapter = {
      version: "v1",
      adapt: (payload: Buffer) => {
        const v1 = JSON.parse(payload.toString("utf8")) as { amount: number; currency: string };
        return Buffer.from(JSON.stringify({ amount_cents: v1.amount * 100, currency: v1.currency }));
      },
    };
    const { relay, audit } = makeRelay({
      versions: { routes: [{ prefix: "/v1", adapter: v1Adapter }] },
    });
    const port = await listen(relay);
    try {
      receivedRaw = [];
      // The v1-shaped body adapts into a schema-valid payload: accepted.
      const v1Body = Buffer.from(JSON.stringify({ amount: 42, currency: "USD" }));
      const res = await post(port, "/v1/hooks/stripe", v1Body, {
        "x-signature": signSha256(v1Body, SECRET), // signature covers the raw v1 body
      });
      assert.equal(res.status, 202);
      await waitForDelivery(1);
      const accepted = audit.query({ event: ["accepted"] }) as {
        version?: string;
        schema?: string;
      }[];
      assert.equal(accepted[0].version, "v1");
      assert.equal(accepted[0].schema, "payment-callback");
      // The same raw body without the version prefix is schema-invalid:
      // the schema sees the unadapted body.
      const res2 = await post(port, "/hooks/stripe", v1Body, {
        "x-signature": signSha256(v1Body, SECRET),
      });
      assert.equal(res2.status, 400);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("prefers the stripped path but still honors per-version rules", async () => {
    const adminSchema = createRequiredFieldsSchema("admin-callback", "1", ["command"]);
    const v1Adapter = {
      version: "v1",
      adapt: (payload: Buffer) => payload, // identity: v1 already speaks the current schema
    };
    const { relay, audit } = makeRelay({
      versions: { routes: [{ prefix: "/v1", adapter: v1Adapter }] },
      payloadSchemas: [
        { pattern: "/admin/*", schema: adminSchema }, // matches the stripped path
        { pattern: "/v1/legacy/*", schema: adminSchema }, // matches only the full path
      ],
    });
    const port = await listen(relay);
    try {
      // /v1/admin/ping -> stripped /admin/ping matches the first rule.
      const ok = Buffer.from(JSON.stringify({ command: "ping" }));
      const res = await post(port, "/v1/admin/ping", ok, {
        "x-signature": signSha256(ok, SECRET),
      });
      assert.equal(res.status, 202);
      // /v1/legacy/job -> stripped /legacy/job matches nothing; the full
      // path falls back to the per-version rule.
      const bad = Buffer.from(JSON.stringify({ nope: true }));
      const res2 = await post(port, "/v1/legacy/job", bad, {
        "x-signature": signSha256(bad, SECRET),
      });
      assert.equal(res2.status, 400);
      const rejected = audit.query({ event: ["rejected"] }) as { reason?: string; schema?: string }[];
      assert.equal(rejected[0].reason, "schema_failed");
      assert.equal(rejected[0].schema, "admin-callback");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("exposes schema intake in the Prometheus exposition", async () => {
    const { relay } = makeRelay({ operatorToken: OPERATOR_TOKEN });
    const port = await listen(relay);
    try {
      const good = Buffer.from(JSON.stringify({ amount_cents: 1, currency: "USD" }));
      await post(port, "/hooks/a", good, { "x-signature": signSha256(good, SECRET) });
      const bad = Buffer.from(JSON.stringify({ amount_cents: 1 }));
      await post(port, "/hooks/b", bad, { "x-signature": signSha256(bad, SECRET) });
      const res = await get(port, "/metrics", { authorization: `Bearer ${OPERATOR_TOKEN}` });
      assert.equal(res.status, 200);
      assert.match(
        res.text,
        /relay_inbound_schema_total\{schema="payment-callback",status="accepted"\} 1/
      );
      assert.match(
        res.text,
        /relay_inbound_schema_total\{schema="payment-callback",status="rejected"\} 1/
      );
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("keeps /metrics byte-identical when the registry is not configured", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: OPERATOR_TOKEN,
    } as Parameters<typeof createRelayServer>[0]);
    const port = await listen(relay);
    try {
      const res = await get(port, "/metrics", { authorization: `Bearer ${OPERATOR_TOKEN}` });
      assert.equal(res.status, 200);
      assert.ok(!res.text.includes("relay_inbound_schema_total"));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("fails fast on invalid rules at startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
      secret: SECRET,
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: audit,
          payloadSchemas: [{ pattern: "no-slash", schema: paymentSchema }],
        } as Parameters<typeof createRelayServer>[0]),
      RangeError
    );
  });
});
