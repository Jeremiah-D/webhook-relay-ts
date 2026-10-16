import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256, verifySignature } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { classifyFailure } from "../src/failure.ts";
import { createRequiredFieldsSchema, type PayloadSchema } from "../src/schema.ts";
import {
  OutboundSchemaMetrics,
  OutboundSchemaRegistry,
  OutboundSchemaViolationError,
  assertValidOutboundSchemas,
} from "../src/outbound-schema.ts";

const hook = "https://downstream.example/hook";
const requiredAmount = (): PayloadSchema => createRequiredFieldsSchema("payment", "2", ["amount_cents"]);

/** Run `fn`, expecting an OutboundSchemaViolationError; return it. */
function throwsViolation(fn: () => void): OutboundSchemaViolationError {
  try {
    fn();
  } catch (err) {
    assert.ok(
      err instanceof OutboundSchemaViolationError,
      `expected OutboundSchemaViolationError, got ${String(err)}`
    );
    return err;
  }
  assert.fail("expected OutboundSchemaViolationError, but nothing was thrown");
}

// ---------------------------------------------------------------------------
// Unit: startup validation (RangeError fail-fast, zero partial application)
// ---------------------------------------------------------------------------

describe("assertValidOutboundSchemas", () => {
  it("accepts undefined (feature off) and an empty record", () => {
    assert.doesNotThrow(() => assertValidOutboundSchemas(undefined));
    assert.doesNotThrow(() => assertValidOutboundSchemas({}));
  });

  it("rejects non-record shapes", () => {
    for (const bad of [[], null, "x", 42, true]) {
      assert.throws(() => assertValidOutboundSchemas(bad as never), RangeError);
    }
  });

  it("rejects empty targetUrl keys", () => {
    assert.throws(
      () => assertValidOutboundSchemas({ "": requiredAmount() }),
      RangeError
    );
  });

  it("rejects schemas with an unusable name/version/validate", () => {
    const good = requiredAmount();
    assert.throws(
      () =>
        assertValidOutboundSchemas({
          [hook]: { ...good, name: "" },
        }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidOutboundSchemas({
          [hook]: { ...good, version: "" },
        }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidOutboundSchemas({
          [hook]: { name: "n", version: "v" } as never,
        }),
      RangeError
    );
  });

  it("a bad record fails the whole registry construction (zero partial application)", () => {
    assert.throws(
      () =>
        new OutboundSchemaRegistry({
          [hook]: requiredAmount(),
          "https://other.example/hook": { name: "", version: "1", validate: () => ({ ok: true }) },
        }),
      RangeError
    );
  });
});

// ---------------------------------------------------------------------------
// Unit: exact-targetUrl selection (no prefix matching)
// ---------------------------------------------------------------------------

describe("OutboundSchemaRegistry selection", () => {
  it("matches only the exact targetUrl", () => {
    const reg = new OutboundSchemaRegistry({ [hook]: requiredAmount() });
    assert.equal(reg.hasRules(hook), true);
    assert.equal(reg.select(hook)?.name, "payment");
    // Outbound configs key by exact targetUrl (WR-60/WR-42 convention):
    // no prefix or suffix matching.
    assert.equal(reg.hasRules(`${hook}/sub`), false);
    assert.equal(reg.select(`${hook}/sub`), undefined);
    assert.equal(reg.hasRules("https://downstream.example/hook2"), false);
    assert.equal(reg.hasRules("https://downstream.example/"), false);
  });

  it("unconfigured endpoints keep byte-exact behavior", () => {
    const reg = new OutboundSchemaRegistry({ [hook]: requiredAmount() });
    assert.equal(reg.hasRules("https://someone-else.example/hook"), false);
    // validatePayload is a safe no-op without a rule (the caller gates
    // with hasRules, but the no-rule path cannot throw by construction).
    assert.doesNotThrow(() =>
      reg.validatePayload("https://someone-else.example/hook", Buffer.from("not even json {{{"))
    );
  });
});

// ---------------------------------------------------------------------------
// Unit: validation semantics and metrics
// ---------------------------------------------------------------------------

describe("OutboundSchemaRegistry.validatePayload", () => {
  it("accepts a conforming payload and records a valid counter", () => {
    const reg = new OutboundSchemaRegistry({ [hook]: requiredAmount() });
    assert.doesNotThrow(() =>
      reg.validatePayload(hook, Buffer.from(JSON.stringify({ amount_cents: 4200 })))
    );
    assert.deepEqual(reg.metrics.getStats(), [
      { schemaName: "payment", schemaVersion: "2", endpoint: hook, valid: 1, invalid: 0 },
    ]);
  });

  it("rejects a violating payload with a structured error", () => {
    const reg = new OutboundSchemaRegistry({ [hook]: requiredAmount() });
    const err = throwsViolation(() =>
      reg.validatePayload(hook, Buffer.from(JSON.stringify({ currency: "usd" })))
    );
    assert.equal(err.endpoint, hook);
    assert.equal(err.schemaName, "payment");
    assert.equal(err.schemaVersion, "2");
    assert.match(err.message, /missing required field: amount_cents/);
    assert.deepEqual(reg.metrics.getStats(), [
      { schemaName: "payment", schemaVersion: "2", endpoint: hook, valid: 0, invalid: 1 },
    ]);
  });

  it("bounds the reported violations (first 10)", () => {
    const schema = createRequiredFieldsSchema(
      "big",
      "1",
      Array.from({ length: 25 }, (_, i) => `field_${i}`)
    );
    const reg = new OutboundSchemaRegistry({ [hook]: schema });
    const err = throwsViolation(() => reg.validatePayload(hook, Buffer.from("{}")));
    // 10 violations joined by "; " — exactly 9 separators.
    assert.equal((err.message.match(/; /g) ?? []).length, 9);
    assert.match(err.message, /field_9/);
    assert.doesNotMatch(err.message, /field_10/);
  });

  it("fails a non-JSON payload under a configured rule (WR-41 convention)", () => {
    const reg = new OutboundSchemaRegistry({ [hook]: requiredAmount() });
    const err = throwsViolation(() =>
      reg.validatePayload(hook, Buffer.from("this is not json {{{"))
    );
    assert.match(err.message, /not JSON/);
  });

  it("is fail-closed on a throwing validator", () => {
    const throwing: PayloadSchema = {
      name: "boom",
      version: "1",
      validate: () => {
        throw new Error("validator bug");
      },
    };
    const reg = new OutboundSchemaRegistry({ [hook]: throwing });
    const err = throwsViolation(() =>
      reg.validatePayload(hook, Buffer.from(JSON.stringify({ a: 1 })))
    );
    assert.match(err.message, /fail-closed/);
    assert.equal((err as { cause?: unknown }).cause instanceof Error, true);
  });

  it("classifyFailure maps OutboundSchemaViolationError to non_retryable", () => {
    const c = classifyFailure(
      new OutboundSchemaViolationError(hook, requiredAmount(), "payload is not JSON")
    );
    assert.equal(c.failureClass, "non_retryable");
  });
});

describe("OutboundSchemaMetrics", () => {
  it("renders empty when nothing was recorded (metrics stays byte-identical)", () => {
    assert.equal(new OutboundSchemaMetrics().render(), "");
  });

  it("exposes per-schema/per-endpoint counters in Prometheus text", () => {
    const m = new OutboundSchemaMetrics();
    m.record(requiredAmount(), hook, "valid");
    m.record(requiredAmount(), hook, "invalid");
    const out = m.render();
    assert.match(out, /# TYPE relay_outbound_schema_total counter/);
    assert.match(
      out,
      /relay_outbound_schema_total\{schema="payment",version="2",endpoint="https:\/\/downstream\.example\/hook",status="valid"\} 1/
    );
    assert.match(
      out,
      /relay_outbound_schema_total\{schema="payment",version="2",endpoint="https:\/\/downstream\.example\/hook",status="invalid"\} 1/
    );
  });
});

// ---------------------------------------------------------------------------
// Server integration: real HTTP sender, real downstream stub.
// ---------------------------------------------------------------------------

const inboundKey = "wr117-inbound-key";
const signKey = "wr117-sign-key";
const operatorKey = "wr117-operator-key";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

function getText(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "GET", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end();
  });
}

function recordingStub() {
  const hits: Array<{ body: Buffer; headers: Record<string, string | string[] | undefined> }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      hits.push({ body: Buffer.concat(chunks), headers: { ...req.headers } });
      res.writeHead(200).end("ok");
    });
  });
  return { server, hits };
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

function newAudit(tag: string) {
  return new AuditLog(join(mkdtempSync(join(tmpdir(), tag)), "audit.jsonl"));
}

describe("server: outbound schema validation before delivery", () => {
  it("validates AFTER the transform: valid pre-transform but invalid post-transform dead-letters", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr117-");
    const relay = createRelayServer({
      secret: inboundKey,
      forwardUrl: target,
      auditLog: audit,
      operatorToken: operatorKey,
      outboundSigning: { secret: signKey },
      // The transform moves amount_cents -> amount, so the payload that
      // arrives is valid pre-transform but INVALID post-transform —
      // validation must see the transformed bytes.
      payloadTransforms: {
        [target]: { fieldRenames: { amount_cents: "amount" } },
      },
      outboundSchemas: {
        [target]: createRequiredFieldsSchema("payment", "2", ["amount_cents"]),
      },
      retry: { baseDelayMs: 50, maxDelayMs: 500, maxAttempts: 5, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      const inbound = Buffer.from(JSON.stringify({ amount_cents: 4200 }));
      const res = await post(relayPort, inbound, {
        "x-signature": signSha256(inbound, inboundKey),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      const accepted = JSON.parse(res.text) as { id: string };

      // Immediate dead letter: no retry budget burned, downstream never hit.
      await waitFor(
        () => audit.query({ event: "dead_letter" }).length > 0,
        10000,
        "dead_letter audit entry"
      );
      assert.equal(hits.length, 0, "downstream must never be contacted");
      const dlEvents = audit.query({ event: "dead_letter" }) as Array<{
        id: string;
        attempts: number;
        failure_class: string;
        error: string;
      }>;
      assert.equal(dlEvents.length, 1);
      assert.equal(dlEvents[0].id, accepted.id);
      assert.equal(dlEvents[0].attempts, 1, "dead-lettered on the first attempt");
      assert.equal(dlEvents[0].failure_class, "non_retryable");
      assert.match(dlEvents[0].error, /outbound schema validation failed/);

      // The dedicated schema_violation audit line carries id + error +
      // endpoint + schema identity.
      const svEvents = audit.query({ event: "schema_violation" }) as Array<{
        id: string;
        targetUrl: string;
        schema: string;
        schemaVersion: string;
        error: string;
      }>;
      assert.equal(svEvents.length, 1);
      assert.equal(svEvents[0].id, accepted.id);
      assert.equal(svEvents[0].targetUrl, target);
      assert.equal(svEvents[0].schema, "payment");
      assert.equal(svEvents[0].schemaVersion, "2");
      assert.match(svEvents[0].error, /missing required field: amount_cents/);

      // The breaker learned nothing from a local validation failure.
      assert.equal(
        audit.query({ event: "circuit_open" }).length,
        0,
        "breaker must stay closed on a schema violation"
      );

      // Prometheus exposes the per-endpoint invalid counter.
      const metrics = await getText(relayPort, "/metrics", {
        authorization: `Bearer ${operatorKey}`,
      });
      assert.equal(metrics.status, 200);
      const escTarget = target.replace(/\//g, "\\/");
      assert.match(
        metrics.text,
        new RegExp(
          `relay_outbound_schema_total\\{schema="payment",version="2",endpoint="${escTarget}",status="invalid"\\} 1`
        )
      );
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a valid post-transform payload is delivered and signed over the validated bytes", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr117-");
    const relay = createRelayServer({
      secret: inboundKey,
      forwardUrl: target,
      auditLog: audit,
      operatorToken: operatorKey,
      outboundSigning: { secret: signKey },
      payloadTransforms: {
        [target]: { fieldRenames: { amount: "amount_cents" } },
      },
      outboundSchemas: {
        [target]: createRequiredFieldsSchema("payment", "2", ["amount_cents"]),
      },
      retry: { baseDelayMs: 50, maxDelayMs: 500, maxAttempts: 2, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      const inbound = Buffer.from(JSON.stringify({ amount: 4200 }));
      const res = await post(relayPort, inbound, {
        "x-signature": signSha256(inbound, inboundKey),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);

      await waitFor(() => hits.length >= 1, 10000, "downstream hit");
      assert.equal(hits.length, 1);
      const hit = hits[0];
      assert.deepEqual(JSON.parse(hit.body.toString()), { amount_cents: 4200 });

      // WR-26 signature covers the validated (post-transform) bytes.
      const sig = hit.headers["x-relay-signature"];
      assert.ok(typeof sig === "string", "expected x-relay-signature");
      assert.ok(verifySignature(hit.body, sig, signKey), "signature must verify over validated body");

      // No violation audited; the valid counter rendered in /metrics.
      assert.equal(audit.query({ event: "schema_violation" }).length, 0);
      const metrics = await getText(relayPort, "/metrics", {
        authorization: `Bearer ${operatorKey}`,
      });
      const escTarget = target.replace(/\//g, "\\/");
      assert.match(
        metrics.text,
        new RegExp(
          `relay_outbound_schema_total\\{schema="payment",version="2",endpoint="${escTarget}",status="valid"\\} 1`
        )
      );
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("endpoints without schema rules pass the body through byte-for-byte", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr117-");
    const relay = createRelayServer({
      secret: inboundKey,
      forwardUrl: target,
      auditLog: audit,
      outboundSchemas: { "https://someone-else.example/hook": requiredAmount() },
      retry: { baseDelayMs: 50, maxDelayMs: 500, maxAttempts: 2, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      // Note the unusual whitespace: untouched bytes prove opt-in.
      const inbound = Buffer.from('{ "a" : 1,  "b":[1,2] }');
      const res = await post(relayPort, inbound, {
        "x-signature": signSha256(inbound, inboundKey),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => hits.length >= 1, 10000, "downstream hit");
      assert.ok(hits[0].body.equals(inbound), "bytes must pass through untouched");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("illegal outboundSchemas config fails the relay at startup (RangeError)", () => {
    const audit = newAudit("wr117-");
    assert.throws(
      () =>
        createRelayServer({
          secret: inboundKey,
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: audit,
          outboundSchemas: {
            "http://127.0.0.1:1/hook": { name: "", version: "1", validate: () => ({ ok: true }) },
          },
        }),
      RangeError
    );
  });
});
