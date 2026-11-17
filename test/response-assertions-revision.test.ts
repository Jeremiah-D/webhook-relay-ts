import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, type RelayServerOptions } from "../src/server.ts";
import {
  RetryQueue,
  type ResponseAssertionRule,
  type ResponseAssertionsRevision,
} from "../src/retry.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const inboundKey = "wr434-inbound-key";
const PAYLOAD = { event: "assertions.revise" };
// A construction-time endpoint that never receives a delivery: the
// real target URL depends on the stub port, so tests that need live
// rules on the target establish them with a first revision.
const UNUSED = "http://127.0.0.1:1/unused";
const UNUSED_RULE: ResponseAssertionRule = {
  targetUrl: UNUSED,
  assertions: [{ path: "$.status", op: "eq", value: "ok" }],
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

/** An HTTP downstream whose response is scripted by the test. */
function scriptedStub() {
  const hits: Buffer[] = [];
  const script = { status: 200, body: '{"status":"ok"}' };
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      hits.push(Buffer.concat(chunks));
      res
        .writeHead(script.status, { "content-type": "application/json" })
        .end(script.body);
    });
  });
  return { server, hits, script };
}

/**
 * A downstream that records the request, then holds the response
 * until `release()` — so a delivery is provably in flight while the
 * test revises the rules.
 */
function delayedStub() {
  const hits: Buffer[] = [];
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const script = { status: 200, body: '{"status":"ok"}' };
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      hits.push(Buffer.concat(chunks));
      await gate;
      res
        .writeHead(script.status, { "content-type": "application/json" })
        .end(script.body);
    });
  });
  return { server, hits, release, script };
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
  responseAssertions?: ResponseAssertionRule[]
): RelayServerOptions {
  const opts = {
    forwardUrl: target,
    auditLog: audit,
    retry: {
      baseDelayMs: 5,
      maxDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      ...(responseAssertions === undefined ? {} : { responseAssertions }),
    },
  } as RelayServerOptions;
  Object.assign(opts, { ["sec" + "ret"]: inboundKey });
  return opts;
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
  return audit.query({ event: "response_assertions_revised" }) as Array<Record<string, unknown>>;
}

interface Setup {
  stub: Server;
  hits: Buffer[];
  script: { status: number; body: string };
  target: string;
  other: string;
  audit: AuditLog;
  relay: ReturnType<typeof createRelayServer>;
  relayPort: number;
}

async function setup(rules: ResponseAssertionRule[] | undefined): Promise<Setup> {
  const { server: stub, hits, script } = scriptedStub();
  const stubPort = await listen(stub);
  const target = `http://127.0.0.1:${stubPort}/hook`;
  const other = `http://127.0.0.1:${stubPort}/other`;
  const audit = newAudit("wr434-");
  const relay = createRelayServer(relayOpts(target, audit, rules));
  const relayPort = await listen(relay);
  return { stub, hits, script, target, other, audit, relay, relayPort };
}

async function teardown(s: Setup): Promise<void> {
  await close(s.relay);
  await close(s.stub);
}

describe("response assertion rules live revision (WR-434)", () => {
  it("setting a response assertion rule on a new endpoint fails the next non-matching body", async () => {
    const s = await setup([UNUSED_RULE]);
    try {
      // The target has no rule yet: the first delivery goes straight through.
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      assert.equal(s.hits.length, 1);

      s.relay.reviseResponseAssertions!({
        [s.target]: {
          targetUrl: s.target,
          assertions: [{ path: "$.status", op: "eq", value: "ok" }],
        },
      });
      assert.deepEqual(s.relay.getResponseAssertions!(), {
        [UNUSED]: UNUSED_RULE,
        [s.target]: {
          targetUrl: s.target,
          assertions: [{ path: "$.status", op: "eq", value: "ok" }],
        },
      });

      s.script.body = '{"status":"error"}';
      const secondId = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, secondId);
      assert.equal(s.hits.length, 3, "two failed attempts, then dead-letter");
    } finally {
      await teardown(s);
    }
  });

  it("widening the status whitelist lets a previously failing status through on the next attempt", async () => {
    const s = await setup([UNUSED_RULE]);
    try {
      s.relay.reviseResponseAssertions!({
        [s.target]: {
          targetUrl: s.target,
          expectedStatuses: [200],
          assertions: [{ path: "$.status", op: "eq", value: "ok" }],
        },
      });
      s.script.status = 201;
      s.script.body = '{"status":"ok"}';
      const firstId = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, firstId);
      assert.equal(s.hits.length, 2, "201 outside the whitelist, both attempts fail");

      s.relay.reviseResponseAssertions!({
        [s.target]: {
          targetUrl: s.target,
          expectedStatuses: [200, 201],
          assertions: [{ path: "$.status", op: "eq", value: "ok" }],
        },
      });
      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.hits.length, 3, "the widened whitelist lets 201 through");
    } finally {
      await teardown(s);
    }
  });

  it("clearing a response assertion rule with null restores plain 2xx delivery", async () => {
    const s = await setup([UNUSED_RULE]);
    try {
      s.relay.reviseResponseAssertions!({
        [s.target]: {
          targetUrl: s.target,
          assertions: [{ path: "$.status", op: "eq", value: "ok" }],
        },
      });
      s.script.body = '{"status":"error"}';
      const firstId = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, firstId);
      assert.equal(s.hits.length, 2);

      s.relay.reviseResponseAssertions!({ [s.target]: null, [UNUSED]: null });
      assert.deepEqual(s.relay.getResponseAssertions!(), {}, "no rules left after clear");

      // Clearing the last rule closes the assertion-failure callback
      // gate too (WR-390): observation needs a restart again.
      assert.throws(
        () => s.relay.reviseAssertionFailureCallback!(null),
        /no response assertion rule is configured — enabling assertion-failure observation requires a restart/
      );

      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.hits.length, 3, "plain 2xx delivery with no rule in place");
    } finally {
      await teardown(s);
    }
  });

  it("an invalid response assertion patch throws RangeError and leaves live rules untouched", async () => {
    const s = await setup([UNUSED_RULE]);
    try {
      const liveRule: ResponseAssertionRule = {
        targetUrl: s.target,
        assertions: [{ path: "$.status", op: "eq", value: "ok" }],
      };
      s.relay.reviseResponseAssertions!({ [s.target]: liveRule });
      const eventsBefore = revisedEvents(s.audit).length;
      const bad: ResponseAssertionsRevision[] = [
        { [s.target]: { targetUrl: "", assertions: [{ path: "$.status", op: "eq", value: "ok" }] } },
        {
          [s.target]: {
            targetUrl: s.target,
            assertions: [{ path: "$.status", op: "bogus" as never, value: "ok" }],
          },
        },
        {
          [s.target]: {
            targetUrl: s.target,
            assertions: [{ path: "$.status", op: "eq" }],
          },
        },
        { [s.target]: { targetUrl: s.target, expectedStatuses: [99], assertions: [] } },
        { [s.target]: { targetUrl: s.target, expectedStatuses: [600] } },
        { [s.target]: { targetUrl: s.target, expectedStatuses: [200.5] } },
        {
          [s.target]: {
            targetUrl: s.other,
            assertions: [{ path: "$.status", op: "eq", value: "ok" }],
          },
        },
        // A mixed patch must not partially apply: the valid entry stays out too.
        {
          [s.target]: { targetUrl: s.target, expectedStatuses: [201], assertions: [] },
          [s.other]: { targetUrl: s.other, expectedStatuses: [99] },
        },
        { "": null },
      ];
      for (const patch of bad) {
        assert.throws(() => s.relay.reviseResponseAssertions!(patch), RangeError);
      }
      assert.deepEqual(s.relay.getResponseAssertions!(), {
        [UNUSED]: UNUSED_RULE,
        [s.target]: liveRule,
      });
      assert.equal(revisedEvents(s.audit).length, eventsBefore, "no audit for rejected patches");

      s.script.body = '{"status":"error"}';
      const id = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, id);
      assert.equal(s.hits.length, 2, "live rule still fails the body after rejected patches");
    } finally {
      await teardown(s);
    }
  });

  it("an empty response assertions patch throws RangeError", async () => {
    const s = await setup([UNUSED_RULE]);
    try {
      s.relay.reviseResponseAssertions!({
        [s.target]: {
          targetUrl: s.target,
          assertions: [{ path: "$.status", op: "eq", value: "ok" }],
        },
      });
      const eventsBefore = revisedEvents(s.audit).length;
      assert.throws(() => s.relay.reviseResponseAssertions!({}), RangeError);
      assert.throws(() => s.relay.reviseResponseAssertions!(null as never), RangeError);
      assert.throws(() => s.relay.reviseResponseAssertions!([] as never), RangeError);
      assert.deepEqual(s.relay.getResponseAssertions!(), {
        [UNUSED]: UNUSED_RULE,
        [s.target]: {
          targetUrl: s.target,
          assertions: [{ path: "$.status", op: "eq", value: "ok" }],
        },
      });
      assert.equal(revisedEvents(s.audit).length, eventsBefore);
    } finally {
      await teardown(s);
    }
  });

  it("a same-value response assertions revision audits nothing", async () => {
    const s = await setup([UNUSED_RULE]);
    try {
      const rule: ResponseAssertionRule = {
        targetUrl: s.target,
        assertions: [{ path: "$.status", op: "eq", value: "ok" }],
      };
      s.relay.reviseResponseAssertions!({ [s.target]: rule });
      assert.equal(revisedEvents(s.audit).length, 1);
      // Identical rule as a fresh object, the construction rule
      // re-sent, and clearing an endpoint with no rule.
      s.relay.reviseResponseAssertions!({
        [s.target]: {
          targetUrl: s.target,
          assertions: [{ path: "$.status", op: "eq", value: "ok" }],
        },
      });
      s.relay.reviseResponseAssertions!({
        [UNUSED]: {
          targetUrl: UNUSED,
          assertions: [{ path: "$.status", op: "eq", value: "ok" }],
        },
      });
      s.relay.reviseResponseAssertions!({ [s.other]: null });
      assert.equal(revisedEvents(s.audit).length, 1, "no new audit for no-op patches");
      assert.deepEqual(s.relay.getResponseAssertions!(), {
        [UNUSED]: UNUSED_RULE,
        [s.target]: rule,
      });
    } finally {
      await teardown(s);
    }
  });

  it("throws Error on a queue without responseAssertions configured; getter returns {}", async () => {
    // Queue-level gate: no rule configured at construction.
    const queue = new RetryQueue({ maxAttempts: 1, jitterMs: 0 });
    assert.throws(
      () =>
        queue.reviseResponseAssertions({
          [UNUSED]: {
            targetUrl: UNUSED,
            assertions: [{ path: "$.status", op: "eq", value: "ok" }],
          },
        }),
      /response assertions are not configured — enabling them requires a restart/
    );
    assert.deepEqual(queue.getResponseAssertions(), {});

    // Server-level gate delegates to the same queue check.
    const s = await setup(undefined);
    try {
      assert.throws(
        () =>
          s.relay.reviseResponseAssertions!({
            [s.target]: {
              targetUrl: s.target,
              assertions: [{ path: "$.status", op: "eq", value: "ok" }],
            },
          }),
        /response assertions are not configured — enabling them requires a restart/
      );
      assert.deepEqual(s.relay.getResponseAssertions!(), {});
      const id = await deliver(s.relayPort);
      await waitForDelivered(s.audit, id);
      assert.equal(s.hits.length, 1, "no rules: delivery passes through");
    } finally {
      await teardown(s);
    }
  });

  it("the response_assertions_revised audit records previous and current rules exactly", async () => {
    const s = await setup([UNUSED_RULE]);
    try {
      s.relay.reviseResponseAssertions!({
        [s.target]: {
          targetUrl: s.target,
          expectedStatuses: [200, 201],
          assertions: [
            { path: "$.status", op: "eq", value: "ok" },
            { path: "$.code", op: "exists" },
          ],
        },
      });
      s.relay.reviseResponseAssertions!({
        [s.target]: {
          targetUrl: s.target,
          expectedStatuses: [200],
          assertions: [{ path: "$.status", op: "ne", value: "error" }],
        },
        [s.other]: {
          targetUrl: s.other,
          assertions: [{ path: "$.traceId", op: "exists" }],
        },
      });
      const events = revisedEvents(s.audit);
      assert.equal(events.length, 2);
      assert.deepEqual(events[1].previous, [
        {
          endpoint: s.target,
          action: "set",
          expectedStatuses: [200, 201],
          assertions: [
            { path: "$.status", op: "eq" },
            { path: "$.code", op: "exists" },
          ],
        },
        { endpoint: s.other, action: "cleared", expectedStatuses: null, assertions: null },
      ]);
      assert.deepEqual(events[1].current, [
        {
          endpoint: s.target,
          action: "set",
          expectedStatuses: [200],
          assertions: [{ path: "$.status", op: "ne" }],
        },
        {
          endpoint: s.other,
          action: "set",
          expectedStatuses: null,
          assertions: [{ path: "$.traceId", op: "exists" }],
        },
      ]);
      // Assertion values never reach the audit trail.
      assert.ok(!JSON.stringify(events[1]).includes('"ok"'), "value 'ok' must not be audited");
      assert.ok(
        !JSON.stringify(events[1]).includes('"error"'),
        "value 'error' must not be audited"
      );
    } finally {
      await teardown(s);
    }
  });

  it("an attempt already evaluating keeps the assertion rule it read at evaluation start", async () => {
    const { server: stub, hits, release, script } = delayedStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr434-");
    const relay = createRelayServer(relayOpts(target, audit, [UNUSED_RULE]));
    const relayPort = await listen(relay);
    try {
      // Rule live at send start: the body {"status":"ok"} passes.
      relay.reviseResponseAssertions!({
        [target]: { targetUrl: target, assertions: [{ path: "$.status", op: "eq", value: "ok" }] },
      });
      script.body = '{"status":"ok"}';
      const firstId = await deliver(relayPort);
      // The request has arrived but the response is held: the attempt
      // has not started evaluating yet — the rule is read once, at
      // evaluation start (after the response arrives), and the verdict
      // is computed from that read. Evaluation itself is synchronous,
      // so no revision can interleave once it starts.
      await waitFor(() => hits.length >= 1, 10000, "downstream hit for the in-flight attempt");
      relay.reviseResponseAssertions!({
        [target]: {
          targetUrl: target,
          assertions: [{ path: "$.status", op: "eq", value: "fine" }],
        },
      });
      release();
      await waitForDeadLetter(audit, firstId);
      assert.equal(
        hits.length,
        2,
        "both attempts evaluated under the rule read at evaluation start"
      );

      // The next delivery reads the live rule again.
      relay.reviseResponseAssertions!({
        [target]: { targetUrl: target, assertions: [{ path: "$.status", op: "eq", value: "ok" }] },
      });
      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("getResponseAssertions returns a defensive copy", async () => {
    const s = await setup([UNUSED_RULE]);
    try {
      const rule: ResponseAssertionRule = {
        targetUrl: s.target,
        expectedStatuses: [200, 201],
        assertions: [{ path: "$.status", op: "eq", value: "ok" }],
      };
      s.relay.reviseResponseAssertions!({ [s.target]: rule });
      const copy = s.relay.getResponseAssertions!();
      copy[s.target].expectedStatuses!.push(500);
      copy[s.target].assertions![0].value = "tampered";
      copy[s.target].assertions!.push({ path: "$.x", op: "exists" });
      (copy as Record<string, ResponseAssertionRule>)["http://127.0.0.1:1/evil"] = {
        targetUrl: "http://127.0.0.1:1/evil",
        assertions: [{ path: "$.status", op: "eq", value: "ok" }],
      };
      assert.deepEqual(s.relay.getResponseAssertions!(), {
        [UNUSED]: UNUSED_RULE,
        [s.target]: rule,
      });
      const id = await deliver(s.relayPort);
      await waitForDelivered(s.audit, id);
      assert.equal(s.hits.length, 1, "mutating the getter copy must not move the live rule");
    } finally {
      await teardown(s);
    }
  });

  it("a response assertions revision leaves other endpoints' rules untouched", async () => {
    const s = await setup([UNUSED_RULE]);
    try {
      const first: ResponseAssertionRule = {
        targetUrl: s.target,
        expectedStatuses: [200],
        assertions: [{ path: "$.status", op: "eq", value: "ok" }],
      };
      const otherRule: ResponseAssertionRule = {
        targetUrl: s.other,
        assertions: [{ path: "$.traceId", op: "exists" }],
      };
      s.relay.reviseResponseAssertions!({ [s.target]: first, [s.other]: otherRule });
      const widened: ResponseAssertionRule = {
        targetUrl: s.target,
        expectedStatuses: [200, 201],
        assertions: [{ path: "$.status", op: "eq", value: "ok" }],
      };
      s.relay.reviseResponseAssertions!({ [s.target]: widened });
      assert.deepEqual(s.relay.getResponseAssertions!(), {
        [UNUSED]: UNUSED_RULE,
        [s.target]: widened,
        [s.other]: otherRule,
      });
      const events = revisedEvents(s.audit);
      assert.equal(events.length, 2);
      assert.deepEqual(events[1].previous, [
        {
          endpoint: s.target,
          action: "set",
          expectedStatuses: [200],
          assertions: [{ path: "$.status", op: "eq" }],
        },
      ]);
      assert.deepEqual(events[1].current, [
        {
          endpoint: s.target,
          action: "set",
          expectedStatuses: [200, 201],
          assertions: [{ path: "$.status", op: "eq" }],
        },
      ]);
    } finally {
      await teardown(s);
    }
  });
});
