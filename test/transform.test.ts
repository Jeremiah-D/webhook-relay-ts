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
import {
  PayloadTransformer,
  PayloadTransformError,
  TemplateError,
  type TransformContext,
} from "../src/transform.ts";

const endpoint = "https://downstream.example/hook";
const ctx: TransformContext = {
  eventId: "evt-1",
  endpoint,
  attempt: 2,
  timestamp: "2026-10-16T00:00:00.000Z",
};

function apply(rules: Record<string, unknown>, body: string, c: TransformContext = ctx) {
  return new PayloadTransformer({ [endpoint]: rules as never }).apply(endpoint, Buffer.from(body), c);
}

describe("PayloadTransformer unit: field operations", () => {
  it("renames a top-level field (move: source deleted)", () => {
    const { body } = apply(
      { fieldRenames: { amount: "amount_cents" } },
      JSON.stringify({ amount: 4200, currency: "usd" })
    );
    assert.deepEqual(JSON.parse(body.toString()), { amount_cents: 4200, currency: "usd" });
  });

  it("renames nested and array-indexed paths", () => {
    const { body } = apply(
      { fieldRenames: { "payment.card.number": "payment.card.pan", "items.0.sku": "items.0.code" } },
      JSON.stringify({ payment: { card: { number: "4111" } }, items: [{ sku: "a" }, { sku: "b" }] })
    );
    assert.deepEqual(JSON.parse(body.toString()), {
      payment: { card: { pan: "4111" } },
      items: [{ code: "a" }, { sku: "b" }],
    });
  });

  it("rename with a missing source is a no-op", () => {
    const { body } = apply(
      { fieldRenames: { nope: "x" } },
      JSON.stringify({ a: 1 })
    );
    assert.deepEqual(JSON.parse(body.toString()), { a: 1 });
  });

  it("rename creates intermediate objects on the target side", () => {
    const { body } = apply(
      { fieldRenames: { a: "meta.deep.b" } },
      JSON.stringify({ a: 7 })
    );
    assert.deepEqual(JSON.parse(body.toString()), { meta: { deep: { b: 7 } } });
  });

  it("deletes nested fields and array elements; missing paths are no-ops", () => {
    const { body } = apply(
      { fieldDeletes: ["card_number", "items.1", "missing.deeply"] },
      JSON.stringify({ card_number: "4111", keep: true, items: ["a", "b", "c"] })
    );
    assert.deepEqual(JSON.parse(body.toString()), { keep: true, items: ["a", "c"] });
  });

  it("fieldMaps copies (source kept)", () => {
    const { body } = apply(
      { fieldMaps: { "meta.order_id": "order" } },
      JSON.stringify({ order: "ord_1" })
    );
    assert.deepEqual(JSON.parse(body.toString()), { order: "ord_1", meta: { order_id: "ord_1" } });
  });

  it("constants inject literals, creating intermediates (arrays for numeric segments)", () => {
    const { body } = apply(
      { constants: { source: "relay", "meta.v": 1, "tags.0": "fintech", nested: { ok: true } } },
      JSON.stringify({})
    );
    assert.deepEqual(JSON.parse(body.toString()), {
      source: "relay",
      meta: { v: 1 },
      tags: ["fintech"],
      nested: { ok: true },
    });
  });

  it("constants overwrite existing values", () => {
    const { body } = apply(
      { constants: { mode: "live" } },
      JSON.stringify({ mode: "test" })
    );
    assert.deepEqual(JSON.parse(body.toString()), { mode: "live" });
  });

  it("applies deletes, then renames, then maps, then constants in order", () => {
    const { body } = apply(
      {
        fieldDeletes: ["gone"],
        fieldRenames: { a: "b" },
        fieldMaps: { c: "b" },
        constants: { b: "const-wins" },
      },
      JSON.stringify({ a: 1, gone: true })
    );
    assert.deepEqual(JSON.parse(body.toString()), { b: "const-wins", c: 1 });
  });

  it("does not mutate the caller's buffer", () => {
    const raw = JSON.stringify({ a: 1 });
    const buf = Buffer.from(raw);
    apply({ fieldRenames: { a: "b" }, fieldDeletes: ["nope"] }, raw);
    assert.equal(buf.toString(), raw);
    assert.deepEqual(JSON.parse(buf.toString()), { a: 1 });
  });
});

describe("PayloadTransformer unit: header injection and templates", () => {
  it("injects static headers", () => {
    const { headers } = apply(
      { headerInjections: { "x-tenant": "acme" } },
      JSON.stringify({ a: 1 })
    );
    assert.deepEqual(headers, { "x-tenant": "acme" });
  });

  it("renders all four template variables", () => {
    const { headers } = apply(
      {
        headerInjections: {
          "x-event": "evt-{{event_id}}",
          "x-target": "{{endpoint}}",
          "x-attempt": "try-{{attempt}}",
          "x-when": "{{ timestamp }}",
        },
      },
      JSON.stringify({ a: 1 })
    );
    assert.deepEqual(headers, {
      "x-event": "evt-evt-1",
      "x-target": endpoint,
      "x-attempt": "try-2",
      "x-when": "2026-10-16T00:00:00.000Z",
    });
  });

  it("static values with single braces are untouched", () => {
    const { headers } = apply(
      { headerInjections: { "x-note": "use {braces} freely" } },
      JSON.stringify({})
    );
    assert.equal(headers["x-note"], "use {braces} freely");
  });

  it("unknown template variable throws TemplateError at construction", () => {
    assert.throws(
      () => new PayloadTransformer({ [endpoint]: { headerInjections: { "x-a": "{{bogus}}" } } }),
      TemplateError
    );
  });

  it("unclosed braces throw TemplateError at construction", () => {
    assert.throws(
      () => new PayloadTransformer({ [endpoint]: { headerInjections: { "x-a": "v-{{event_id" } } }),
      TemplateError
    );
  });

  it("stray closing braces throw TemplateError at construction", () => {
    assert.throws(
      () => new PayloadTransformer({ [endpoint]: { headerInjections: { "x-a": "v-}}x" } } }),
      TemplateError
    );
  });

  it("prototype-pollution paths throw RangeError at construction", () => {
    for (const bad of ["__proto__.x", "a.constructor", "a.prototype.b"]) {
      assert.throws(
        () => new PayloadTransformer({ [endpoint]: { fieldDeletes: [bad] } }),
        RangeError,
        bad
      );
    }
  });

  it("empty path segments throw RangeError at construction", () => {
    assert.throws(
      () => new PayloadTransformer({ [endpoint]: { fieldDeletes: ["a..b"] } }),
      RangeError
    );
  });

  it("reserved relay/transport header names throw RangeError at construction", () => {
    for (const name of ["x-relay-signature", "X-Relay-Key-Id", "content-length", "traceparent"]) {
      assert.throws(
        () => new PayloadTransformer({ [endpoint]: { headerInjections: { [name]: "v" } } }),
        RangeError,
        name
      );
    }
  });

  it("non-JSON values in constants throw RangeError at construction", () => {
    assert.throws(
      () => new PayloadTransformer({ [endpoint]: { constants: { n: NaN } } }),
      RangeError
    );
    assert.throws(
      () =>
        new PayloadTransformer({
          [endpoint]: { constants: { f: (() => 1) as unknown as string } },
        }),
      RangeError
    );
  });

  it("non-object rules shapes throw RangeError at construction", () => {
    assert.throws(() => new PayloadTransformer(null as never), RangeError);
    assert.throws(() => new PayloadTransformer({ [endpoint]: null as never }), RangeError);
    assert.throws(
      () => new PayloadTransformer({ [endpoint]: { fieldDeletes: "x" as never } }),
      RangeError
    );
  });
});

describe("PayloadTransformer unit: failure and bypass semantics", () => {
  it("non-JSON payload throws PayloadTransformError", () => {
    const t = new PayloadTransformer({ [endpoint]: { fieldRenames: { a: "b" } } });
    assert.throws(
      () => t.apply(endpoint, Buffer.from("not json {{"), ctx),
      (err: unknown) => {
        assert.ok(err instanceof PayloadTransformError);
        assert.equal(err.endpoint, endpoint);
        assert.match(err.message, /not JSON/);
        return true;
      }
    );
  });

  it("endpoints without rules return the input buffer untouched", () => {
    const t = new PayloadTransformer({ [endpoint]: { fieldRenames: { a: "b" } } });
    const buf = Buffer.from(JSON.stringify({ a: 1 }));
    const out = t.apply("https://other.example/", buf, ctx);
    assert.ok(out.body === buf);
    assert.deepEqual(out.headers, {});
    assert.equal(t.hasRules("https://other.example/"), false);
    assert.equal(t.hasRules(endpoint), true);
  });

  it("classifyFailure maps PayloadTransformError to non_retryable", () => {
    const c = classifyFailure(new PayloadTransformError(endpoint, "payload is not JSON"));
    assert.equal(c.failureClass, "non_retryable");
  });
});

// ---------------------------------------------------------------------------
// Server integration: real HTTP sender, real downstream stub.
// ---------------------------------------------------------------------------

const inboundSecret = "transform-inbound-secret";
const signSecret = "transform-sign-secret";

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

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "GET", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          let json: unknown = null;
          try {
            json = JSON.parse(Buffer.concat(chunks).toString());
          } catch {
            // Leave json as null; the status assertion will fail the test.
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
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

describe("server: payload transform before delivery", () => {
  it("transforms the body, signs the transformed bytes, injects headers, strips forged inbound", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr115-")), "audit.jsonl"));
    const relay = createRelayServer({
      secret: inboundSecret,
      forwardUrl: target,
      auditLog: audit,
      outboundSigning: { secret: signSecret },
      payloadTransforms: {
        [target]: {
          fieldRenames: { amount: "amount_cents" },
          fieldDeletes: ["internal"],
          constants: { source: "relay" },
          headerInjections: {
            "x-event-id": "evt-{{event_id}}",
            "x-attempt": "{{attempt}}",
            "x-tenant": "acme",
          },
        },
      },
      retry: { baseDelayMs: 50, maxDelayMs: 500, maxAttempts: 2, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      const inbound = Buffer.from(JSON.stringify({ amount: 4200, internal: true, keep: "yes" }));
      const res = await post(relayPort, inbound, {
        "x-signature": signSha256(inbound, inboundSecret),
        "content-type": "application/json",
        // Forged: the relay must strip this and stamp its own value.
        "x-event-id": "forged",
      });
      assert.equal(res.status, 202);
      const accepted = JSON.parse(res.text) as { id: string };
      assert.ok(typeof accepted.id === "string" && accepted.id.length > 0);

      await waitFor(() => hits.length >= 1, 10000, "downstream hit");
      assert.equal(hits.length, 1);
      const hit = hits[0];

      // Body transformed (rename + delete + constant), canonical JSON.
      assert.deepEqual(JSON.parse(hit.body.toString()), {
        amount_cents: 4200,
        keep: "yes",
        source: "relay",
      });

      // WR-26 signature covers the TRANSFORMED bytes, not the inbound ones.
      const sig = hit.headers["x-relay-signature"];
      assert.ok(typeof sig === "string", "expected x-relay-signature");
      assert.ok(verifySignature(hit.body, sig, signSecret), "signature must verify over transformed body");
      assert.ok(
        !verifySignature(inbound, sig, signSecret),
        "signature must NOT verify over the pre-transform body"
      );

      // Injected headers rendered; forged inbound value stripped.
      assert.equal(hit.headers["x-event-id"], `evt-${accepted.id}`);
      assert.equal(hit.headers["x-attempt"], "1");
      assert.equal(hit.headers["x-tenant"], "acme");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("endpoint without transform rules passes the body through byte-for-byte", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr115-")), "audit.jsonl"));
    const relay = createRelayServer({
      secret: inboundSecret,
      forwardUrl: target,
      auditLog: audit,
      payloadTransforms: { "https://someone-else.example/hook": { fieldDeletes: ["a"] } },
      retry: { baseDelayMs: 50, maxDelayMs: 500, maxAttempts: 2, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      // Note the unusual whitespace: untouched bytes prove opt-in.
      const inbound = Buffer.from('{ "a" : 1,  "b":[1,2] }');
      const res = await post(relayPort, inbound, {
        "x-signature": signSha256(inbound, inboundSecret),
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

  it("non-JSON payload under a configured transform dead-letters immediately and audits transform_failed", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr115-")), "audit.jsonl"));
    const token = "wr115-op-token";
    const relay = createRelayServer({
      secret: inboundSecret,
      forwardUrl: target,
      auditLog: audit,
      operatorToken: token,
      payloadTransforms: { [target]: { fieldRenames: { a: "b" } } },
      retry: { baseDelayMs: 50, maxDelayMs: 500, maxAttempts: 5, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      const inbound = Buffer.from("this is not json {{{");
      const res = await post(relayPort, inbound, {
        "x-signature": signSha256(inbound, inboundSecret),
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
      assert.match(dlEvents[0].error, /payload transform failed/);

      // The dedicated transform_failed audit line carries id + error + endpoint.
      const tfEvents = audit.query({ event: "transform_failed" }) as Array<{
        id: string;
        targetUrl: string;
        error: string;
      }>;
      assert.equal(tfEvents.length, 1);
      assert.equal(tfEvents[0].id, accepted.id);
      assert.equal(tfEvents[0].targetUrl, target);
      assert.match(tfEvents[0].error, /not JSON/);

      // And the operator surface shows the dead-lettered entry.
      const dl = await get(relayPort, "/dead-letter", { authorization: `Bearer ${token}` });
      assert.equal(dl.status, 200);
      const entries = dl.json as Array<{ id: string; attempts: number; lastError: string }>;
      assert.equal(entries.length, 1);
      assert.equal(entries[0].id, accepted.id);
      assert.equal(entries[0].attempts, 1);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("illegal transform config fails the relay at startup (RangeError/TemplateError)", () => {
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr115-")), "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          secret: inboundSecret,
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: audit,
          payloadTransforms: {
            "http://127.0.0.1:1/hook": { headerInjections: { "x-a": "{{nope}}" } },
          },
        }),
      TemplateError
    );
    assert.throws(
      () =>
        createRelayServer({
          secret: inboundSecret,
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: audit,
          payloadTransforms: {
            "http://127.0.0.1:1/hook": { headerInjections: { "x-relay-signature": "v" } },
          },
        }),
      RangeError
    );
  });
});
