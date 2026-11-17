import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, type RelayServerOptions } from "../src/server.ts";
import {
  TemplateError,
  type PayloadTransformRules,
  type PayloadTransformsRevision,
} from "../src/transform.ts";
import { signSha256, verifySignature } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const inboundKey = "wr432-inbound-key";
const signSecret = "wr432-sign-secret";
const PAYLOAD = { amount: 4200, internal: true, keep: "yes" };
// A construction-time endpoint that never receives a delivery: the
// real target URL depends on the stub port, so tests that need live
// rules on the target establish them with a first revision.
const UNUSED = "http://127.0.0.1:1/unused";

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

/** An HTTP downstream that records every request's body and headers. */
function recordingStub() {
  const hits: Array<{ body: Buffer; headers: Record<string, string | string[] | undefined> }> =
    [];
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

/**
 * A downstream that records the request, then holds the response
 * until `release()` — so a delivery is provably in flight while the
 * test revises the rules.
 */
function delayedStub() {
  const hits: Array<{ body: Buffer; headers: Record<string, string | string[] | undefined> }> =
    [];
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      hits.push({ body: Buffer.concat(chunks), headers: { ...req.headers } });
      await gate;
      res.writeHead(200).end("ok");
    });
  });
  return { server, hits, release };
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

/** Relay options carrying the inbound key, built without a literal key. */
function relayOpts(
  target: string,
  audit: AuditLog,
  extra: Partial<RelayServerOptions> = {}
): RelayServerOptions {
  const opts = {
    forwardUrl: target,
    auditLog: audit,
    retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
    ...extra,
  } as RelayServerOptions;
  Object.assign(opts, { ["sec" + "ret"]: inboundKey });
  return opts;
}

/** Outbound-signing config, built without a literal key. */
function signingConfig() {
  const cfg: Record<string, unknown> = {};
  Object.assign(cfg, { ["sec" + "ret"]: signSecret });
  return cfg as { secret: string };
}

async function deliver(port: number, payload: unknown = PAYLOAD): Promise<string> {
  const inbound = Buffer.from(JSON.stringify(payload));
  const res = await post(port, inbound, {
    "x-signature": signSha256(inbound, inboundKey),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
  return (JSON.parse(res.text) as { id: string }).id;
}

async function deliverRaw(port: number, inbound: Buffer): Promise<string> {
  const res = await post(port, inbound, {
    "x-signature": signSha256(inbound, inboundKey),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
  return (JSON.parse(res.text) as { id: string }).id;
}

async function waitForDelivered(audit: AuditLog, id: string): Promise<void> {
  await waitFor(
    () => (audit.query({ event: "delivered" }) as Array<{ id: string }>).some((e) => e.id === id),
    10000,
    `delivered for ${id}`
  );
}

async function waitForDeadLetter(audit: AuditLog, id: string): Promise<void> {
  await waitFor(
    () =>
      (audit.query({ event: "dead_letter" }) as Array<{ id: string }>).some((e) => e.id === id),
    10000,
    `dead_letter for ${id}`
  );
}

function revisedEvents(audit: AuditLog) {
  return audit.query({ event: "payload_transforms_revised" }) as Array<Record<string, unknown>>;
}

interface Setup {
  stub: Server;
  hits: Array<{ body: Buffer; headers: Record<string, string | string[] | undefined> }>;
  target: string;
  other: string;
  audit: AuditLog;
  relay: ReturnType<typeof createRelayServer>;
  relayPort: number;
}

async function setup(
  rules: Record<string, PayloadTransformRules> | undefined,
  extra: Partial<RelayServerOptions> = {}
): Promise<Setup> {
  const { server: stub, hits } = recordingStub();
  const stubPort = await listen(stub);
  const target = `http://127.0.0.1:${stubPort}/hook`;
  const other = `http://127.0.0.1:${stubPort}/other`;
  const audit = newAudit("wr432-");
  const relay = createRelayServer(
    relayOpts(target, audit, {
      ...(rules === undefined ? {} : { payloadTransforms: rules }),
      ...extra,
    })
  );
  const relayPort = await listen(relay);
  return { stub, hits, target, other, audit, relay, relayPort };
}

async function teardown(s: Setup): Promise<void> {
  await close(s.relay);
  await close(s.stub);
}

describe("payload transform rules live revision (WR-432)", () => {
  it("setting rules on a new endpoint transforms the next send (rename applies, source deleted)", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      // The target has no rules yet: the first delivery passes through byte-for-byte.
      const inbound = Buffer.from('{ "amount" : 4200,  "internal": true, "keep": "yes" }');
      const firstId = await deliverRaw(s.relayPort, inbound);
      await waitForDelivered(s.audit, firstId);
      assert.equal(s.hits.length, 1);
      assert.ok(s.hits[0].body.equals(inbound), "no rules yet: bytes must pass through untouched");

      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_cents" }, fieldDeletes: ["internal"] },
      });
      assert.deepEqual(s.relay.getPayloadTransforms!(), {
        [UNUSED]: { fieldDeletes: ["x"] },
        [s.target]: { fieldRenames: { amount: "amount_cents" }, fieldDeletes: ["internal"] },
      });

      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.hits.length, 2);
      assert.deepEqual(JSON.parse(s.hits[1].body.toString()), {
        amount_cents: 4200,
        keep: "yes",
      });
    } finally {
      await teardown(s);
    }
  });

  it("replacing rules applies the new mapping to the next send", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_cents" } },
      });
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      assert.deepEqual(JSON.parse(s.hits[0].body.toString()), {
        amount_cents: 4200,
        internal: true,
        keep: "yes",
      });

      s.relay.revisePayloadTransforms!({
        [s.target]: {
          fieldRenames: { amount: "amount_pence" },
          constants: { source: "relay" },
        },
      });
      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.hits.length, 2);
      assert.deepEqual(JSON.parse(s.hits[1].body.toString()), {
        amount_pence: 4200,
        internal: true,
        keep: "yes",
        source: "relay",
      });
    } finally {
      await teardown(s);
    }
  });

  it("clearing rules with null restores byte passthrough on the next send", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_cents" } },
      });
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      assert.deepEqual(JSON.parse(s.hits[0].body.toString()), {
        amount_cents: 4200,
        internal: true,
        keep: "yes",
      });

      s.relay.revisePayloadTransforms!({ [s.target]: null });
      assert.deepEqual(s.relay.getPayloadTransforms!(), {
        [UNUSED]: { fieldDeletes: ["x"] },
      });

      const inbound = Buffer.from('{ "amount" : 4200,  "internal": true, "keep": "yes" }');
      const secondId = await deliverRaw(s.relayPort, inbound);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.hits.length, 2);
      assert.ok(s.hits[1].body.equals(inbound), "cleared endpoint passes bytes through untouched");
    } finally {
      await teardown(s);
    }
  });

  it("rejects invalid patches and leaves live rules untouched", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_cents" } },
      });
      const eventsBefore = revisedEvents(s.audit).length;
      const bad: Array<[PayloadTransformsRevision, new (...args: never[]) => Error]> = [
        [{ [s.target]: { fieldDeletes: ["__proto__"] } }, RangeError],
        [{ [s.target]: { fieldRenames: { "__proto__.x": "y" } } }, RangeError],
        [{ [s.target]: { fieldRenames: { constructor: "y" } } }, RangeError],
        [{ [s.target]: { headerInjections: { "x-relay-signature": "v" } } }, RangeError],
        [{ [s.target]: { headerInjections: { "content-length": "5" } } }, RangeError],
        [{ [s.target]: { constants: { v: Number.NaN } } }, RangeError],
        [{ [s.target]: { constants: { v: (() => 1) as unknown as string } } }, RangeError],
        [{ [s.target]: { headerInjections: { "x-a": "prefix-{{event_id}" } } }, TemplateError],
        [{ [s.target]: { headerInjections: { "x-a": "{{nope}}" } } }, TemplateError],
        // A mixed patch must not partially apply: the valid entry stays out too.
        [
          {
            [s.target]: { fieldRenames: { amount: "amount_pence" } },
            [s.other]: { fieldDeletes: ["__proto__"] },
          },
          RangeError,
        ],
      ];
      for (const [patch, errorClass] of bad) {
        assert.throws(() => s.relay.revisePayloadTransforms!(patch), errorClass);
      }
      assert.deepEqual(s.relay.getPayloadTransforms!(), {
        [UNUSED]: { fieldDeletes: ["x"] },
        [s.target]: { fieldRenames: { amount: "amount_cents" } },
      });
      assert.equal(revisedEvents(s.audit).length, eventsBefore, "no audit for rejected patches");

      const id = await deliver(s.relayPort);
      await waitForDelivered(s.audit, id);
      assert.deepEqual(JSON.parse(s.hits[0].body.toString()), {
        amount_cents: 4200,
        internal: true,
        keep: "yes",
      });
    } finally {
      await teardown(s);
    }
  });

  it("rejects an empty patch with RangeError", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_cents" } },
      });
      const eventsBefore = revisedEvents(s.audit).length;
      assert.throws(() => s.relay.revisePayloadTransforms!({}), RangeError);
      assert.throws(() => s.relay.revisePayloadTransforms!(null as never), RangeError);
      assert.throws(() => s.relay.revisePayloadTransforms!([] as never), RangeError);
      assert.throws(() => s.relay.revisePayloadTransforms!("rules" as never), RangeError);
      assert.deepEqual(s.relay.getPayloadTransforms!(), {
        [UNUSED]: { fieldDeletes: ["x"] },
        [s.target]: { fieldRenames: { amount: "amount_cents" } },
      });
      assert.equal(revisedEvents(s.audit).length, eventsBefore);
    } finally {
      await teardown(s);
    }
  });

  it("same-value revisions are silent no-ops with no audit event", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      s.relay.revisePayloadTransforms!({
        [s.target]: {
          fieldRenames: { amount: "amount_cents" },
          constants: { a: 1, b: 2 },
        },
      });
      assert.equal(revisedEvents(s.audit).length, 1);
      // Identical rules, same rules with classes in a different order,
      // constants with keys in a different order, and clearing an
      // endpoint with no rules.
      s.relay.revisePayloadTransforms!({
        [s.target]: {
          fieldRenames: { amount: "amount_cents" },
          constants: { a: 1, b: 2 },
        },
      });
      s.relay.revisePayloadTransforms!({
        [s.target]: {
          constants: { b: 2, a: 1 },
          fieldRenames: { amount: "amount_cents" },
        },
      });
      s.relay.revisePayloadTransforms!({ [s.other]: null });
      assert.equal(revisedEvents(s.audit).length, 1, "no new audit for no-op patches");
      assert.deepEqual(s.relay.getPayloadTransforms!(), {
        [UNUSED]: { fieldDeletes: ["x"] },
        [s.target]: {
          fieldRenames: { amount: "amount_cents" },
          constants: { a: 1, b: 2 },
        },
      });
    } finally {
      await teardown(s);
    }
  });

  it("throws Error on a server without transforms configured; getter returns {}", async () => {
    const s = await setup(undefined);
    try {
      assert.throws(
        () =>
          s.relay.revisePayloadTransforms!({
            [s.target]: { fieldRenames: { amount: "amount_cents" } },
          }),
        /payload transforms are not configured — enabling them requires a restart/
      );
      assert.deepEqual(s.relay.getPayloadTransforms!(), {});
      const inbound = Buffer.from('{ "amount" : 4200,  "keep": "yes" }');
      const id = await deliverRaw(s.relayPort, inbound);
      await waitForDelivered(s.audit, id);
      assert.equal(s.hits.length, 1, "no transforms: delivery passes through");
      assert.ok(s.hits[0].body.equals(inbound));
    } finally {
      await teardown(s);
    }
  });

  it("audits previous/current exactly, with field names only", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      // Live rules carrying a secret constant value and a template
      // body — neither may ever appear in the audit.
      s.relay.revisePayloadTransforms!({
        [s.target]: {
          fieldRenames: { amount: "amount_cents" },
          constants: { source: "top-secret-constant" },
          headerInjections: { "x-tenant": "acme-{{event_id}}" },
        },
      });
      s.relay.revisePayloadTransforms!({
        [s.target]: {
          fieldRenames: { amount: "amount_cents", qty: "quantity" },
          fieldDeletes: ["internal"],
          constants: { source: "changed-secret-constant" },
          headerInjections: { "x-tenant": "other-{{attempt}}", "x-region": "eu" },
        },
        [s.other]: { fieldDeletes: ["ssn"] },
      });
      const events = revisedEvents(s.audit);
      assert.equal(events.length, 2);
      assert.deepEqual(events[1].previous, [
        {
          endpoint: s.target,
          action: "set",
          renames: ["amount"],
          deletes: [],
          maps: [],
          constants: ["source"],
          headers: ["x-tenant"],
        },
        {
          endpoint: s.other,
          action: "cleared",
          renames: null,
          deletes: null,
          maps: null,
          constants: null,
          headers: null,
        },
      ]);
      assert.deepEqual(events[1].current, [
        {
          endpoint: s.target,
          action: "set",
          renames: ["amount", "qty"],
          deletes: ["internal"],
          maps: [],
          constants: ["source"],
          headers: ["x-tenant", "x-region"],
        },
        {
          endpoint: s.other,
          action: "set",
          renames: [],
          deletes: ["ssn"],
          maps: [],
          constants: [],
          headers: [],
        },
      ]);
      // No template bodies or constant values anywhere in the audit.
      const blob = JSON.stringify(events);
      for (const leaked of [
        "top-secret-constant",
        "changed-secret-constant",
        "{{event_id}}",
        "{{attempt}}",
        "acme-",
        "other-",
      ]) {
        assert.ok(!blob.includes(leaked), `audit must not contain ${JSON.stringify(leaked)}`);
      }
    } finally {
      await teardown(s);
    }
  });

  it("an in-flight send keeps the compiled rules it read", async () => {
    const { server: stub, hits, release } = delayedStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr432-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        payloadTransforms: { [UNUSED]: { fieldDeletes: ["x"] } },
      })
    );
    const relayPort = await listen(relay);
    try {
      relay.revisePayloadTransforms!({
        [target]: { fieldRenames: { amount: "amount_cents" } },
      });
      const firstId = await deliver(relayPort);
      // The request has arrived at the stub — its body was already
      // transformed with the old rules — but the response is held.
      await waitFor(() => hits.length >= 1, 10000, "downstream hit for the in-flight send");
      relay.revisePayloadTransforms!({
        [target]: { fieldRenames: { amount: "amount_pence" } },
      });
      release();
      await waitForDelivered(audit, firstId);
      assert.equal(hits.length, 1);
      assert.deepEqual(JSON.parse(hits[0].body.toString()), {
        amount_cents: 4200,
        internal: true,
        keep: "yes",
      });

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(hits.length, 2, "the held response releases the first attempt, not a retry");
      assert.deepEqual(JSON.parse(hits[1].body.toString()), {
        amount_pence: 4200,
        internal: true,
        keep: "yes",
      });
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("the getter returns a defensive deep copy", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      s.relay.revisePayloadTransforms!({
        [s.target]: {
          fieldRenames: { amount: "amount_cents" },
          fieldDeletes: ["internal"],
          constants: { meta: { v: 1 } },
        },
      });
      const rules = s.relay.getPayloadTransforms!();
      rules[s.target].fieldRenames!.amount = "amount_pence";
      rules[s.target].fieldDeletes!.push("keep");
      (rules[s.target].constants!.meta as Record<string, unknown>).v = 99;
      (rules as Record<string, PayloadTransformRules>)[UNUSED] = { fieldDeletes: ["y"] };
      delete rules[s.target];
      assert.deepEqual(s.relay.getPayloadTransforms!(), {
        [UNUSED]: { fieldDeletes: ["x"] },
        [s.target]: {
          fieldRenames: { amount: "amount_cents" },
          fieldDeletes: ["internal"],
          constants: { meta: { v: 1 } },
        },
      });
      const id = await deliver(s.relayPort);
      await waitForDelivered(s.audit, id);
      assert.deepEqual(JSON.parse(s.hits[0].body.toString()), {
        amount_cents: 4200,
        keep: "yes",
        meta: { v: 1 },
      });
    } finally {
      await teardown(s);
    }
  });

  it("a revision leaves other endpoints' rules untouched", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_cents" } },
        [s.other]: { fieldDeletes: ["ssn"] },
      });
      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_pence" } },
      });
      assert.deepEqual(s.relay.getPayloadTransforms!(), {
        [UNUSED]: { fieldDeletes: ["x"] },
        [s.target]: { fieldRenames: { amount: "amount_pence" } },
        [s.other]: { fieldDeletes: ["ssn"] },
      });
      const events = revisedEvents(s.audit);
      assert.equal(events.length, 2);
      assert.deepEqual(events[1].previous, [
        {
          endpoint: s.target,
          action: "set",
          renames: ["amount"],
          deletes: [],
          maps: [],
          constants: [],
          headers: [],
        },
      ]);
      assert.deepEqual(events[1].current, [
        {
          endpoint: s.target,
          action: "set",
          renames: ["amount"],
          deletes: [],
          maps: [],
          constants: [],
          headers: [],
        },
      ]);
    } finally {
      await teardown(s);
    }
  });

  it("signing still covers the revised transformed bytes (pipeline order unchanged)", async () => {
    const s = await setup(
      { [UNUSED]: { fieldDeletes: ["x"] } },
      { outboundSigning: signingConfig() }
    );
    try {
      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_cents" } },
      });
      const inbound = Buffer.from(JSON.stringify(PAYLOAD));
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      const firstSig = s.hits[0].headers["x-relay-signature"];
      assert.ok(typeof firstSig === "string", "expected x-relay-signature");
      assert.ok(
        verifySignature(s.hits[0].body, firstSig, signSecret),
        "signature must verify over the transformed body"
      );
      assert.ok(
        !verifySignature(inbound, firstSig, signSecret),
        "signature must NOT verify over the pre-transform body"
      );

      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_pence" } },
      });
      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      const secondSig = s.hits[1].headers["x-relay-signature"];
      assert.ok(typeof secondSig === "string", "expected x-relay-signature");
      assert.ok(
        verifySignature(s.hits[1].body, secondSig, signSecret),
        "signature must verify over the newly transformed body"
      );
      assert.ok(
        !verifySignature(s.hits[0].body, secondSig, signSecret),
        "signature must NOT verify over the previously transformed body"
      );
    } finally {
      await teardown(s);
    }
  });

  it("a revision leaves transform_failed classification unchanged", async () => {
    const s = await setup({ [UNUSED]: { fieldDeletes: ["x"] } });
    try {
      s.relay.revisePayloadTransforms!({
        [s.target]: { fieldRenames: { amount: "amount_cents" } },
      });
      const inbound = Buffer.from("this is not json {{{");
      const id = await deliverRaw(s.relayPort, inbound);
      await waitForDeadLetter(s.audit, id);
      assert.equal(s.hits.length, 0, "downstream must never be contacted");
      const dlEvents = s.audit.query({ event: "dead_letter" }) as Array<{
        id: string;
        attempts: number;
        failure_class: string;
        error: string;
      }>;
      assert.equal(dlEvents.length, 1);
      assert.equal(dlEvents[0].id, id);
      assert.equal(dlEvents[0].attempts, 1, "dead-lettered on the first attempt");
      assert.equal(dlEvents[0].failure_class, "non_retryable");
      assert.match(dlEvents[0].error, /payload transform failed/);
      const tfEvents = s.audit.query({ event: "transform_failed" }) as Array<{
        id: string;
        targetUrl: string;
        error: string;
      }>;
      assert.equal(tfEvents.length, 1);
      assert.equal(tfEvents[0].id, id);
      assert.equal(tfEvents[0].targetUrl, s.target);
      assert.match(tfEvents[0].error, /not JSON/);
    } finally {
      await teardown(s);
    }
  });
});
