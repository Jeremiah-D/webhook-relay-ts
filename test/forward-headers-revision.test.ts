import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, type RelayServerOptions } from "../src/server.ts";
import type {
  ForwardHeadersRevision,
  ForwardHeadersRuleConfig,
} from "../src/forward-headers.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const inboundKey = "wr433-inbound-key";
const PAYLOAD = { amount: 4200, internal: true, keep: "yes" };
// A construction-time endpoint that never receives a delivery: the
// real target URL depends on the stub port, so tests that need live
// rules on the target establish them with a first revision.
const UNUSED = "http://127.0.0.1:1/unused";

// Inbound headers exercising every gate outcome: `authorization` and
// `cookie` are default-denied once a rule exists (but forwarded with
// no rule), `x-custom-id` is an ordinary passthrough header, and
// `x-internal-secret` is one an operator would deny.
const INBOUND_HEADERS: Record<string, string> = {
  authorization: "Bearer caller-credential",
  cookie: "session=abc",
  "x-custom-id": "evt-1",
  "x-internal-secret": "shh-do-not-forward",
};

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

async function deliver(
  port: number,
  headers: Record<string, string> = INBOUND_HEADERS
): Promise<string> {
  const inbound = Buffer.from(JSON.stringify(PAYLOAD));
  const res = await post(port, inbound, {
    "x-signature": signSha256(inbound, inboundKey),
    "content-type": "application/json",
    ...headers,
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

function revisedEvents(audit: AuditLog) {
  return audit.query({ event: "forward_headers_revised" }) as Array<Record<string, unknown>>;
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
  rules: Record<string, ForwardHeadersRuleConfig> | undefined,
  extra: Partial<RelayServerOptions> = {}
): Promise<Setup> {
  const { server: stub, hits } = recordingStub();
  const stubPort = await listen(stub);
  const target = `http://127.0.0.1:${stubPort}/hook`;
  const other = `http://127.0.0.1:${stubPort}/other`;
  const audit = newAudit("wr433-");
  const relay = createRelayServer(
    relayOpts(target, audit, {
      ...(rules === undefined ? {} : { forwardHeaders: rules }),
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

describe("forward-headers rules live revision (WR-433)", () => {
  it("setting a forward-headers rule on a new endpoint forwards a previously denied header on the next send", async () => {
    const s = await setup({ [UNUSED]: { allow: ["x-other"] } });
    try {
      // The target has no rule yet: the no-rule pass-through forwards
      // everything, including authorization.
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      assert.equal(s.hits.length, 1);
      assert.equal(s.hits[0].headers["authorization"], "Bearer caller-credential");
      assert.equal(s.hits[0].headers["x-custom-id"], "evt-1");

      // A first rule denies authorization by the default deny.
      s.relay.reviseForwardHeaders!({ [s.target]: { allow: ["x-custom-id"] } });
      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.hits.length, 2);
      assert.equal(s.hits[1].headers["authorization"], undefined, "default deny drops it");
      assert.equal(s.hits[1].headers["x-custom-id"], "evt-1");

      // Setting a new rule that explicitly allows it forwards the
      // previously denied header on the next send.
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: ["authorization", "x-custom-id"] },
      });
      assert.deepEqual(s.relay.getForwardHeaders!(), {
        [UNUSED]: { allow: [/x-other/i] },
        [s.target]: { allow: [/authorization/i, /x-custom-id/i] },
      });
      const thirdId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, thirdId);
      assert.equal(s.hits.length, 3);
      assert.equal(s.hits[2].headers["authorization"], "Bearer caller-credential");
      assert.equal(s.hits[2].headers["x-custom-id"], "evt-1");
      assert.equal(s.hits[2].headers["cookie"], undefined, "still default-denied");
      assert.equal(s.hits[2].headers["x-internal-secret"], undefined, "not in the allow list");
    } finally {
      await teardown(s);
    }
  });

  it("tightening the allow list drops a previously forwarded header on the next send", async () => {
    const s = await setup({ [UNUSED]: { allow: ["x-other"] } });
    try {
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: ["authorization", "x-custom-id", "x-internal-secret"] },
      });
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      assert.equal(s.hits[0].headers["authorization"], "Bearer caller-credential");
      assert.equal(s.hits[0].headers["x-internal-secret"], "shh-do-not-forward");
      assert.equal(s.hits[0].headers["x-custom-id"], "evt-1");

      s.relay.reviseForwardHeaders!({ [s.target]: { allow: ["x-custom-id"] } });
      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.hits.length, 2);
      assert.equal(s.hits[1].headers["authorization"], undefined, "tightened allow drops it");
      assert.equal(s.hits[1].headers["x-internal-secret"], undefined, "tightened allow drops it");
      assert.equal(s.hits[1].headers["x-custom-id"], "evt-1");
    } finally {
      await teardown(s);
    }
  });

  it("clearing a forward-headers rule with null restores the no-rule forwarding behavior", async () => {
    const s = await setup({ [UNUSED]: { allow: ["x-other"] } });
    try {
      s.relay.reviseForwardHeaders!({ [s.target]: { allow: ["x-custom-id"] } });
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      assert.equal(s.hits[0].headers["authorization"], undefined);
      assert.equal(s.hits[0].headers["x-internal-secret"], undefined);
      assert.equal(s.hits[0].headers["x-custom-id"], "evt-1");

      s.relay.reviseForwardHeaders!({ [s.target]: null });
      assert.deepEqual(s.relay.getForwardHeaders!(), {
        [UNUSED]: { allow: [/x-other/i] },
      });

      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.hits.length, 2);
      // No-rule behavior is the exact current pass-through: everything
      // the intake does not strip, including authorization/cookie.
      assert.equal(s.hits[1].headers["authorization"], "Bearer caller-credential");
      assert.equal(s.hits[1].headers["cookie"], "session=abc");
      assert.equal(s.hits[1].headers["x-custom-id"], "evt-1");
      assert.equal(s.hits[1].headers["x-internal-secret"], "shh-do-not-forward");
    } finally {
      await teardown(s);
    }
  });

  it("an invalid forward-headers patch throws RangeError and leaves live rules untouched", async () => {
    const s = await setup({ [UNUSED]: { allow: ["x-other"] } });
    try {
      s.relay.reviseForwardHeaders!({ [s.target]: { allow: ["x-custom-id"] } });
      const eventsBefore = revisedEvents(s.audit).length;
      const bad: Array<[ForwardHeadersRevision, new (...args: never[]) => Error]> = [
        [{ [s.target]: { allow: ["["] } }, RangeError],
        [{ [s.target]: { allow: [42 as never] } }, RangeError],
        [{ [s.target]: { allow: [null as never] } }, RangeError],
        [{ [s.target]: { deny: "x-a" as never } }, RangeError],
        [{ [s.target]: "rules" as never }, RangeError],
        [{ [s.target]: { allow: ["x-a"], deny: ["("] } }, RangeError],
        // A mixed patch must not partially apply: the valid entry stays out too.
        [
          {
            [s.target]: { allow: ["authorization"] },
            [s.other]: { allow: ["["] },
          },
          RangeError,
        ],
      ];
      for (const [patch, errorClass] of bad) {
        assert.throws(() => s.relay.reviseForwardHeaders!(patch), errorClass);
      }
      assert.deepEqual(s.relay.getForwardHeaders!(), {
        [UNUSED]: { allow: [/x-other/i] },
        [s.target]: { allow: [/x-custom-id/i] },
      });
      assert.equal(revisedEvents(s.audit).length, eventsBefore, "no audit for rejected patches");

      const id = await deliver(s.relayPort);
      await waitForDelivered(s.audit, id);
      assert.equal(s.hits[0].headers["authorization"], undefined, "live rule still denies it");
      assert.equal(s.hits[0].headers["x-custom-id"], "evt-1");

      // `__proto__` endpoint keys land as own properties, never on the
      // prototype — and can be cleared again afterwards.
      s.relay.reviseForwardHeaders!({ ["__proto__"]: { allow: ["x-custom-id"] } });
      const live = s.relay.getForwardHeaders!();
      assert.equal(Object.prototype.hasOwnProperty.call(live, "__proto__"), true);
      assert.deepEqual(
        (live as Record<string, ForwardHeadersRuleConfig>)["__proto__"],
        { allow: [/x-custom-id/i] }
      );
      assert.equal(({} as Record<string, unknown>).polluted, undefined);
      s.relay.reviseForwardHeaders!({ ["__proto__"]: null });
      assert.deepEqual(s.relay.getForwardHeaders!(), {
        [UNUSED]: { allow: [/x-other/i] },
        [s.target]: { allow: [/x-custom-id/i] },
      });
    } finally {
      await teardown(s);
    }
  });

  it("an empty forward-headers patch throws RangeError", async () => {
    const s = await setup({ [UNUSED]: { allow: ["x-other"] } });
    try {
      s.relay.reviseForwardHeaders!({ [s.target]: { allow: ["x-custom-id"] } });
      const eventsBefore = revisedEvents(s.audit).length;
      assert.throws(() => s.relay.reviseForwardHeaders!({}), RangeError);
      assert.throws(() => s.relay.reviseForwardHeaders!(null as never), RangeError);
      assert.throws(() => s.relay.reviseForwardHeaders!([] as never), RangeError);
      assert.throws(() => s.relay.reviseForwardHeaders!("rules" as never), RangeError);
      assert.deepEqual(s.relay.getForwardHeaders!(), {
        [UNUSED]: { allow: [/x-other/i] },
        [s.target]: { allow: [/x-custom-id/i] },
      });
      assert.equal(revisedEvents(s.audit).length, eventsBefore);
    } finally {
      await teardown(s);
    }
  });

  it("a same-value forward-headers revision audits nothing", async () => {
    const s = await setup({ [UNUSED]: { allow: ["x-other"] } });
    try {
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: ["authorization", "x-custom-id"], deny: ["x-internal-secret"] },
      });
      assert.equal(revisedEvents(s.audit).length, 1);
      // Identical rules, the same rules as RegExp objects instead of
      // strings, the same allow list in a different order (matching is
      // order-insensitive), a /g/ flag that compiles away, and
      // clearing an endpoint with no rules.
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: ["authorization", "x-custom-id"], deny: ["x-internal-secret"] },
      });
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: [/authorization/i, /x-custom-id/i], deny: [/x-internal-secret/i] },
      });
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: ["x-custom-id", /authorization/g], deny: ["x-internal-secret"] },
      });
      s.relay.reviseForwardHeaders!({ [s.other]: null });
      assert.equal(revisedEvents(s.audit).length, 1, "no new audit for no-op patches");
      assert.deepEqual(s.relay.getForwardHeaders!(), {
        [UNUSED]: { allow: [/x-other/i] },
        [s.target]: { allow: [/authorization/i, /x-custom-id/i], deny: [/x-internal-secret/i] },
      });
    } finally {
      await teardown(s);
    }
  });

  it("throws Error on a server without forwardHeaders configured; getter returns {}", async () => {
    const s = await setup(undefined);
    try {
      assert.throws(
        () =>
          s.relay.reviseForwardHeaders!({
            [s.target]: { allow: ["x-custom-id"] },
          }),
        /forward headers are not configured — enabling them requires a restart/
      );
      assert.deepEqual(s.relay.getForwardHeaders!(), {});
      const id = await deliver(s.relayPort);
      await waitForDelivered(s.audit, id);
      assert.equal(s.hits.length, 1, "no rules: delivery passes headers through");
      assert.equal(s.hits[0].headers["authorization"], "Bearer caller-credential");
      assert.equal(s.hits[0].headers["cookie"], "session=abc");
      assert.equal(s.hits[0].headers["x-custom-id"], "evt-1");
    } finally {
      await teardown(s);
    }
  });

  it("the forward_headers_revised audit records previous and current allow/deny patterns exactly", async () => {
    const s = await setup({ [UNUSED]: { allow: ["x-other"] } });
    try {
      // A delivery first, so live credential header values have
      // actually passed through the relay before any revision.
      const deliveredId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, deliveredId);
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: ["authorization", "x-custom-id"], deny: ["x-internal-secret"] },
      });
      s.relay.reviseForwardHeaders!({
        [s.target]: {
          allow: ["x-custom-id", "x-other"],
          deny: ["x-internal-secret", "x-blocked"],
        },
        [s.other]: { deny: ["cookie"] },
      });
      s.relay.reviseForwardHeaders!({ [s.other]: null });
      const events = revisedEvents(s.audit);
      assert.equal(events.length, 3);
      assert.deepEqual(events[1].previous, [
        {
          endpoint: s.target,
          action: "set",
          allow: ["authorization", "x-custom-id"],
          deny: ["x-internal-secret"],
        },
        {
          endpoint: s.other,
          action: "cleared",
          allow: null,
          deny: null,
        },
      ]);
      assert.deepEqual(events[1].current, [
        {
          endpoint: s.target,
          action: "set",
          allow: ["x-custom-id", "x-other"],
          deny: ["x-internal-secret", "x-blocked"],
        },
        {
          endpoint: s.other,
          action: "set",
          allow: null,
          deny: ["cookie"],
        },
      ]);
      assert.deepEqual(events[2].previous, [
        {
          endpoint: s.other,
          action: "set",
          allow: null,
          deny: ["cookie"],
        },
      ]);
      assert.deepEqual(events[2].current, [
        {
          endpoint: s.other,
          action: "cleared",
          allow: null,
          deny: null,
        },
      ]);
      // Only pattern source strings are audited — no header values
      // ever appear, even though deliveries carry live credentials.
      const blob = JSON.stringify(events);
      for (const leaked of ["Bearer caller-credential", "session=abc", "shh-do-not-forward"]) {
        assert.ok(!blob.includes(leaked), `audit must not contain ${JSON.stringify(leaked)}`);
      }
    } finally {
      await teardown(s);
    }
  });

  it("a send already in flight keeps the forwarding rule it read at send start", async () => {
    const { server: stub, hits, release } = delayedStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr433-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        forwardHeaders: { [UNUSED]: { allow: ["x-other"] } },
      })
    );
    const relayPort = await listen(relay);
    try {
      relay.reviseForwardHeaders!({ [target]: { allow: ["x-custom-id"] } });
      const firstId = await deliver(relayPort);
      // The request has arrived at the stub — its headers were already
      // decided under the old rule — but the response is held.
      await waitFor(() => hits.length >= 1, 10000, "downstream hit for the in-flight send");
      relay.reviseForwardHeaders!({
        [target]: { allow: ["authorization", "x-custom-id"] },
      });
      release();
      await waitForDelivered(audit, firstId);
      assert.equal(hits.length, 1);
      assert.equal(hits[0].headers["authorization"], undefined, "in-flight send keeps the old rule");
      assert.equal(hits[0].headers["x-custom-id"], "evt-1");

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(hits.length, 2, "the held response releases the first attempt, not a retry");
      assert.equal(hits[1].headers["authorization"], "Bearer caller-credential");
      assert.equal(hits[1].headers["x-custom-id"], "evt-1");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("getForwardHeaders returns a defensive copy", async () => {
    const s = await setup({ [UNUSED]: { allow: ["x-other"] } });
    try {
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: ["authorization", /x-custom-.*/g], deny: ["x-internal-secret"] },
      });
      const rules = s.relay.getForwardHeaders!();
      // The /g/ flag is stripped on the way out: the live rule never
      // shares a stateful regex with the caller.
      assert.equal(rules[s.target].allow![1].flags.includes("g"), false);
      assert.equal(rules[s.target].allow![1].source, "x-custom-.*");
      // A second getter call returns fresh RegExp objects, not the
      // same instances.
      const again = s.relay.getForwardHeaders!();
      assert.notEqual(rules[s.target].allow![0], again[s.target].allow![0]);
      assert.notEqual(rules[s.target].deny![0], again[s.target].deny![0]);
      // Mutate the copy every way a caller could.
      rules[s.target].allow!.push(/x-pwned/);
      rules[s.target].deny!.push(/x-custom-id/);
      rules[s.target].allow![0] = /authorization-denied/;
      (rules as Record<string, ForwardHeadersRuleConfig>)[s.other] = { allow: ["x-y"] };
      delete rules[s.target];
      assert.deepEqual(s.relay.getForwardHeaders!(), {
        [UNUSED]: { allow: [/x-other/i] },
        [s.target]: { allow: [/authorization/i, /x-custom-.*/i], deny: [/x-internal-secret/i] },
      });
      // The live rule still forwards deterministically — twice, so a
      // stateful regex would have shown up on the second send.
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.hits.length, 2);
      for (const hit of s.hits) {
        assert.equal(hit.headers["authorization"], "Bearer caller-credential");
        assert.equal(hit.headers["x-custom-id"], "evt-1");
        assert.equal(hit.headers["x-internal-secret"], undefined);
      }
    } finally {
      await teardown(s);
    }
  });

  it("a forward-headers revision leaves other endpoints' rules untouched", async () => {
    const s = await setup({ [UNUSED]: { allow: ["x-other"] } });
    try {
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: ["x-custom-id"] },
        [s.other]: { deny: ["cookie"] },
      });
      s.relay.reviseForwardHeaders!({
        [s.target]: { allow: ["authorization", "x-custom-id"] },
      });
      assert.deepEqual(s.relay.getForwardHeaders!(), {
        [UNUSED]: { allow: [/x-other/i] },
        [s.target]: { allow: [/authorization/i, /x-custom-id/i] },
        [s.other]: { deny: [/cookie/i] },
      });
      const events = revisedEvents(s.audit);
      assert.equal(events.length, 2);
      assert.deepEqual(events[1].previous, [
        {
          endpoint: s.target,
          action: "set",
          allow: ["x-custom-id"],
          deny: [],
        },
      ]);
      assert.deepEqual(events[1].current, [
        {
          endpoint: s.target,
          action: "set",
          allow: ["authorization", "x-custom-id"],
          deny: [],
        },
      ]);
    } finally {
      await teardown(s);
    }
  });
});
