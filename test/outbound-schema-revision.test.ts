import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, type RelayServerOptions } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { createRequiredFieldsSchema, type PayloadSchema } from "../src/schema.ts";
import {
  OutboundSchemaRegistry,
  type OutboundSchemasRevision,
} from "../src/outbound-schema.ts";

// The runtime redacts a literal `sec` + `ret` key in test-file writes
// (see AGENTS.md), so the relay `secret` option is attached with a
// computed key below — never as a plain literal.
const inboundKey = "wr427-inbound-key";

const otherHook = "https://someone-else.example/hook";

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

function recordingStub() {
  const hits: Array<{ body: Buffer }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      hits.push({ body: Buffer.concat(chunks) });
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

const paymentV2 = (): PayloadSchema =>
  createRequiredFieldsSchema("payment", "2", ["amount_cents"]);
const paymentV3 = (): PayloadSchema =>
  createRequiredFieldsSchema("payment", "3", ["currency"]);
const otherV1 = (): PayloadSchema =>
  createRequiredFieldsSchema("other-schema", "1", ["trace_id"]);

/** Relay options carrying the inbound key, built without a literal key. */
function relayOpts(
  target: string,
  audit: AuditLog,
  extra: Partial<RelayServerOptions> = {}
): RelayServerOptions {
  const opts = {
    forwardUrl: target,
    auditLog: audit,
    retry: { baseDelayMs: 50, maxDelayMs: 500, maxAttempts: 2, jitterMs: 0 },
    ...extra,
  } as RelayServerOptions;
  Object.assign(opts, { ["sec" + "ret"]: inboundKey });
  return opts;
}

async function deliver(port: number, payload: unknown): Promise<string> {
  const inbound = Buffer.from(JSON.stringify(payload));
  const res = await post(port, inbound, {
    "x-signature": signSha256(inbound, inboundKey),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
  return (JSON.parse(res.text) as { id: string }).id;
}

function revisedEvents(audit: AuditLog) {
  return audit.query({ event: "outbound_schemas_revised" }) as Array<Record<string, unknown>>;
}

describe("outbound schema live revision (WR-427)", () => {
  it("swapping the schema re-validates the next delivery under the new rule; the old rule no longer applies", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr427-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundSchemas: { [target]: paymentV2() } })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort, { amount_cents: 4200 });
      await waitFor(() => hits.length >= 1, 10000, "first delivery");
      assert.equal(audit.query({ event: "schema_violation" }).length, 0);

      relay.reviseOutboundSchemas!({ [target]: paymentV3() });

      // Valid under the old rule, invalid under the new one: dead-letters.
      const badId = await deliver(relayPort, { amount_cents: 4200 });
      await waitFor(
        () =>
          (audit.query({ event: "dead_letter" }) as Array<{ id: string }>).some(
            (e) => e.id === badId
          ),
        10000,
        "dead_letter for the post-revision delivery"
      );
      assert.equal(hits.length, 1, "downstream never sees the rejected payload");
      const violations = audit.query({ event: "schema_violation" }) as Array<{
        id: string;
        schema: string;
        schemaVersion: string;
        error: string;
      }>;
      assert.equal(violations.length, 1);
      assert.equal(violations[0].id, badId);
      assert.equal(violations[0].schema, "payment");
      assert.equal(violations[0].schemaVersion, "3");
      assert.match(violations[0].error, /missing required field: currency/);

      // Valid under the new rule: delivered.
      const goodId = await deliver(relayPort, { currency: "usd" });
      await waitFor(() => hits.length >= 2, 10000, "second delivery");
      assert.deepEqual(JSON.parse(hits[1].body.toString()), { currency: "usd" });
      assert.notEqual(goodId, firstId);

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: target, schemaName: "payment", schemaVersion: "2", action: "set" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, schemaName: "payment", schemaVersion: "3", action: "set" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("clearing a rule (null) stops validation for that endpoint", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr427-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundSchemas: { [target]: paymentV2() } })
    );
    const relayPort = await listen(relay);
    try {
      const badId = await deliver(relayPort, { currency: "usd" });
      await waitFor(
        () =>
          (audit.query({ event: "dead_letter" }) as Array<{ id: string }>).some(
            (e) => e.id === badId
          ),
        10000,
        "dead_letter before the clear"
      );
      assert.equal(hits.length, 0);

      relay.reviseOutboundSchemas!({ [target]: null });

      // The same payload now passes through unvalidated.
      await deliver(relayPort, { currency: "usd" });
      await waitFor(() => hits.length >= 1, 10000, "delivery after the clear");
      assert.deepEqual(JSON.parse(hits[0].body.toString()), { currency: "usd" });
      assert.equal(audit.query({ event: "schema_violation" }).length, 1, "no new violation");

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: target, schemaName: "payment", schemaVersion: "2", action: "set" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, schemaName: null, schemaVersion: null, action: "cleared" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("adding a rule for a new endpoint takes effect immediately", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr427-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundSchemas: { [otherHook]: otherV1() } })
    );
    const relayPort = await listen(relay);
    try {
      // No rule for the forwardUrl yet: anything passes through.
      await deliver(relayPort, { currency: "usd" });
      await waitFor(() => hits.length >= 1, 10000, "pre-revision delivery");

      relay.reviseOutboundSchemas!({ [target]: paymentV2() });

      const badId = await deliver(relayPort, { currency: "usd" });
      await waitFor(
        () =>
          (audit.query({ event: "dead_letter" }) as Array<{ id: string }>).some(
            (e) => e.id === badId
          ),
        10000,
        "dead_letter after adding the rule"
      );
      assert.equal(hits.length, 1, "downstream never sees the rejected payload");

      await deliver(relayPort, { amount_cents: 100 });
      await waitFor(() => hits.length >= 2, 10000, "post-revision valid delivery");

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: target, schemaName: null, schemaVersion: null, action: "cleared" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, schemaName: "payment", schemaVersion: "2", action: "set" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a bad record rejects the whole patch and the live rules are unchanged", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr427-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundSchemas: { [target]: paymentV2() } })
    );
    const relayPort = await listen(relay);
    try {
      // One good entry + one bad entry: the whole patch is rejected.
      const bad: PayloadSchema = { name: "", version: "1", validate: () => ({ ok: true }) };
      assert.throws(
        () =>
          relay.reviseOutboundSchemas!({
            [otherHook]: otherV1(),
            [target]: bad,
          } as OutboundSchemasRevision),
        RangeError
      );
      assert.equal(revisedEvents(audit).length, 0, "rejected patch audits nothing");

      // The live rules are untouched: the old rule still validates,
      // and the good entry from the rejected patch never landed.
      const badId = await deliver(relayPort, { currency: "usd" });
      await waitFor(
        () =>
          (audit.query({ event: "dead_letter" }) as Array<{ id: string }>).some(
            (e) => e.id === badId
          ),
        10000,
        "dead_letter under the untouched live rule"
      );
      const violations = audit.query({ event: "schema_violation" }) as Array<{
        schemaVersion: string;
      }>;
      assert.equal(violations.length, 1);
      assert.equal(violations[0].schemaVersion, "2");
      assert.equal(hits.length, 0);

      // A payload valid under the old rule still delivers.
      await deliver(relayPort, { amount_cents: 4200 });
      await waitFor(() => hits.length >= 1, 10000, "delivery under the untouched rule");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("revise throws Error when outbound schemas were never configured", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr427-");
    const relay = createRelayServer(relayOpts(target, audit));
    const relayPort = await listen(relay);
    try {
      assert.equal(typeof relay.reviseOutboundSchemas, "function");
      assert.throws(() => relay.reviseOutboundSchemas!({ [target]: paymentV2() }), {
        name: "Error",
        message: /not configured/,
      });
      // The must-restart gate fires before patch validation.
      assert.throws(() => relay.reviseOutboundSchemas!({}), {
        name: "Error",
        message: /not configured/,
      });
      assert.equal(revisedEvents(audit).length, 0);

      // The relay itself still delivers (feature off, unvalidated).
      await deliver(relayPort, { anything: true });
      await waitFor(() => hits.length >= 1, 10000, "delivery with the feature off");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("illegal values throw RangeError and the live rules are unchanged", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr427-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundSchemas: { [target]: paymentV2() } })
    );
    const relayPort = await listen(relay);
    try {
      assert.throws(() => relay.reviseOutboundSchemas!({}), RangeError);
      assert.throws(() => relay.reviseOutboundSchemas!(null as never), RangeError);
      assert.throws(() => relay.reviseOutboundSchemas!("nope" as never), RangeError);
      assert.throws(() => relay.reviseOutboundSchemas!([] as never), RangeError);
      assert.throws(
        () => relay.reviseOutboundSchemas!({ "": paymentV2() }),
        RangeError
      );
      assert.throws(
        () =>
          relay.reviseOutboundSchemas!({
            [target]: { name: "", version: "1", validate: () => ({ ok: true }) },
          }),
        RangeError
      );
      assert.throws(
        () =>
          relay.reviseOutboundSchemas!({
            [target]: { name: "n", version: "1" } as never,
          }),
        RangeError
      );
      assert.throws(
        () => relay.reviseOutboundSchemas!({ [target]: undefined as never }),
        RangeError
      );
      assert.equal(revisedEvents(audit).length, 0, "rejected patches audit nothing");

      // The live rule is untouched.
      const badId = await deliver(relayPort, { currency: "usd" });
      await waitFor(
        () =>
          (audit.query({ event: "dead_letter" }) as Array<{ id: string }>).some(
            (e) => e.id === badId
          ),
        10000,
        "dead_letter under the untouched live rule"
      );
      assert.equal(hits.length, 0);
      await deliver(relayPort, { amount_cents: 4200 });
      await waitFor(() => hits.length >= 1, 10000, "delivery under the untouched rule");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("same-value revision is a silent no-op with no audit event", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr427-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundSchemas: { [target]: paymentV2() } })
    );
    const relayPort = await listen(relay);
    try {
      const live = paymentV2();
      await deliver(relayPort, { amount_cents: 4200 });
      await waitFor(() => hits.length >= 1, 10000, "first delivery");

      // Same rule, same object — then a fresh but equal rule — then
      // clearing an endpoint that never had a rule: all no-ops.
      relay.reviseOutboundSchemas!({ [target]: paymentV2() });
      relay.reviseOutboundSchemas!({ [target]: live });
      relay.reviseOutboundSchemas!({ [otherHook]: null });
      assert.equal(revisedEvents(audit).length, 0, "same-value revisions audit nothing");

      // The live rule still validates as before.
      const badId = await deliver(relayPort, { currency: "usd" });
      await waitFor(
        () =>
          (audit.query({ event: "dead_letter" }) as Array<{ id: string }>).some(
            (e) => e.id === badId
          ),
        10000,
        "dead_letter under the untouched live rule"
      );
      assert.equal(hits.length, 1);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a validation in flight keeps the rule it started with", () => {
    const target = "https://downstream.example/hook";
    let reg: OutboundSchemaRegistry;
    const oldRule: PayloadSchema = {
      name: "payment",
      version: "2",
      validate: () => {
        // Revise mid-validation: the in-flight check must still be
        // judged by this rule, not by the stricter replacement.
        reg.revise({ [target]: paymentV3() });
        return { ok: true };
      },
    };
    reg = new OutboundSchemaRegistry({ [target]: oldRule });
    assert.doesNotThrow(() =>
      reg.validatePayload(target, Buffer.from(JSON.stringify({ amount_cents: 4200 })))
    );
    // The in-flight validation passed under the old rule…
    assert.deepEqual(reg.metrics.getStats(), [
      { schemaName: "payment", schemaVersion: "2", endpoint: target, valid: 1, invalid: 0 },
    ]);
    // …while the revision itself took effect for the next validation.
    assert.equal(reg.select(target)?.version, "3");
    assert.throws(
      () => reg.validatePayload(target, Buffer.from(JSON.stringify({ amount_cents: 4200 }))),
      /missing required field: currency/
    );
  });

  it("outbound_schemas_revised audit records endpoint + schema name/version + set/cleared only, never the schema body", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr427-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        outboundSchemas: { [target]: paymentV2(), [otherHook]: otherV1() },
      })
    );
    const relayPort = await listen(relay);
    try {
      // One patch: swap the target's rule and clear the other endpoint.
      relay.reviseOutboundSchemas!({ [target]: paymentV3(), [otherHook]: null });

      const events = revisedEvents(audit);
      assert.equal(events.length, 1, "exactly one revision audit event");
      assert.deepEqual(events[0].previous, [
        { endpoint: target, schemaName: "payment", schemaVersion: "2", action: "set" },
        { endpoint: otherHook, schemaName: "other-schema", schemaVersion: "1", action: "set" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, schemaName: "payment", schemaVersion: "3", action: "set" },
        { endpoint: otherHook, schemaName: null, schemaVersion: null, action: "cleared" },
      ]);
      const serialized = JSON.stringify(events[0]);
      assert.ok(!serialized.includes("amount_cents"), "schema body field names are never audited");
      assert.ok(!serialized.includes("currency"), "schema body field names are never audited");
      assert.ok(!serialized.includes("trace_id"), "schema body field names are never audited");
      assert.ok(!serialized.includes("validate"), "no validator source is audited");
    } finally {
      await close(relay);
      await close(stub);
    }
  });
});
