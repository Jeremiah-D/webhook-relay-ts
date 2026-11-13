import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type EndpointHealthConfig,
  type EndpointHealthRevisedAuditEvent,
} from "../src/endpoint-health.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const signingKey = "endpoint-health-audit-callback-revision-key";
const opToken = "endpoint-health-audit-callback-revision-op-token";
const EP = "http://127.0.0.1:9/hook";

const defaults: EndpointHealthConfig = {
  ewmaAlpha: 0.2,
  maxLatencySamples: 256,
  sloMs: 5000,
  successWeight: 0.7,
  latencyWeight: 0.3,
  circuitOpenPenalty: 100,
  degradeThreshold: 40,
  recoverThreshold: 70,
};

describe("RetryQueue endpoint-health audit callback revision (WR-408)", () => {
  it("the swapped callback receives the next revision with exact previous/current eight knobs; the old callback stays silent and past revisions are never re-delivered", () => {
    const first: EndpointHealthRevisedAuditEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => ({ statusCode: 200, body: Buffer.alloc(0) })) as Sender,
      endpointHealth: {},
      onEndpointHealthAudit: (e) => first.push(e),
    });
    try {
      q.reviseEndpointHealth({ degradeThreshold: 30 });
      assert.equal(first.length, 1);
      assert.deepEqual(first[0], {
        event: "endpoint_health_revised",
        previous: defaults,
        current: { ...defaults, degradeThreshold: 30 },
      });
      const second: EndpointHealthRevisedAuditEvent[] = [];
      q.reviseEndpointHealthAuditCallback((e) => second.push(e));
      assert.equal(second.length, 0, "no re-delivery of the reported revision");
      assert.equal(first.length, 1);
      const next = q.reviseEndpointHealth({ sloMs: 2000, recoverThreshold: 80 });
      assert.deepEqual(next, {
        ...defaults,
        degradeThreshold: 30,
        sloMs: 2000,
        recoverThreshold: 80,
      });
      assert.equal(first.length, 1, "old callback stays silent after revision");
      assert.equal(second.length, 1);
      assert.deepEqual(second[0], {
        event: "endpoint_health_revised",
        previous: { ...defaults, degradeThreshold: 30 },
        current: { ...defaults, degradeThreshold: 30, sloMs: 2000, recoverThreshold: 80 },
      });
      assert.deepEqual(q.getEndpointHealthConfig(), {
        ...defaults,
        degradeThreshold: 30,
        sloMs: 2000,
        recoverThreshold: 80,
      });
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; revisions still apply and stay queryable", () => {
    const seen: EndpointHealthRevisedAuditEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => ({ statusCode: 200, body: Buffer.alloc(0) })) as Sender,
      endpointHealth: {},
      onEndpointHealthAudit: (e) => seen.push(e),
    });
    try {
      q.reviseEndpointHealth({ sloMs: 1000 });
      assert.equal(seen.length, 1);
      q.reviseEndpointHealthAuditCallback(null);
      const next = q.reviseEndpointHealth({ sloMs: 2000 });
      assert.deepEqual(next, { ...defaults, sloMs: 2000 });
      assert.deepEqual(q.getEndpointHealthConfig(), { ...defaults, sloMs: 2000 });
      assert.equal(seen.length, 1, "cleared hook stays silent");
      // Re-setting works: the next revision reaches the new callback.
      const third: EndpointHealthRevisedAuditEvent[] = [];
      q.reviseEndpointHealthAuditCallback((e) => third.push(e));
      q.reviseEndpointHealth({ sloMs: 3000 });
      assert.equal(third.length, 1);
      assert.deepEqual(third[0].current, { ...defaults, sloMs: 3000 });
    } finally {
      q.stop();
    }
  });

  it("an empty patch and a same-value revision do not trigger the new callback", () => {
    const second: EndpointHealthRevisedAuditEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => ({ statusCode: 200, body: Buffer.alloc(0) })) as Sender,
      endpointHealth: {},
      onEndpointHealthAudit: () => {},
    });
    try {
      q.reviseEndpointHealthAuditCallback((e) => second.push(e));
      assert.throws(() => q.reviseEndpointHealth({}), RangeError);
      assert.equal(second.length, 0);
      q.reviseEndpointHealth({ sloMs: 5000 });
      assert.equal(second.length, 0, "same-value revision is a silent no-op");
      assert.deepEqual(q.getEndpointHealthConfig(), defaults);
    } finally {
      q.stop();
    }
  });

  it("revising with health scoring unconfigured throws Error; the gate precedes validation and the live state is untouched", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getEndpointHealthConfig(), undefined);
      assert.throws(
        () => q.reviseEndpointHealthAuditCallback(() => {}),
        (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
      );
      assert.throws(
        () => q.reviseEndpointHealthAuditCallback(null),
        (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
      );
      // The must-restart gate fires before the handler validation.
      assert.throws(
        () => q.reviseEndpointHealthAuditCallback("x" as never),
        (err: unknown) => err instanceof Error && !(err instanceof RangeError)
      );
      assert.equal(q.getEndpointHealthConfig(), undefined);
    } finally {
      q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", () => {
    const seen: EndpointHealthRevisedAuditEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => ({ statusCode: 200, body: Buffer.alloc(0) })) as Sender,
      endpointHealth: {},
      onEndpointHealthAudit: (e) => seen.push(e),
    });
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseEndpointHealthAuditCallback(bad), RangeError, String(bad));
      }
      q.reviseEndpointHealth({ sloMs: 1000 });
      assert.equal(seen.length, 1);
      assert.deepEqual(seen[0], {
        event: "endpoint_health_revised",
        previous: defaults,
        current: { ...defaults, sloMs: 1000 },
      });
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", () => {
    const seen: EndpointHealthRevisedAuditEvent[] = [];
    const onEndpointHealthAudit = (e: EndpointHealthRevisedAuditEvent) => seen.push(e);
    const q = new RetryQueue({
      sender: (async () => ({ statusCode: 200, body: Buffer.alloc(0) })) as Sender,
      endpointHealth: {},
      onEndpointHealthAudit,
    });
    try {
      q.reviseEndpointHealthAuditCallback(onEndpointHealthAudit);
      q.reviseEndpointHealth({ sloMs: 1000 });
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseEndpointHealthAuditCallback(null);
      q.reviseEndpointHealthAuditCallback(null);
      q.reviseEndpointHealth({ sloMs: 2000 });
      assert.equal(seen.length, 1);
      assert.deepEqual(q.getEndpointHealthConfig(), { ...defaults, sloMs: 2000 });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint-health audit callback revision (WR-408)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  function makeRelay(opts: {
    onEndpointHealthAudit?: (event: EndpointHealthRevisedAuditEvent) => void;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-health-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: EP,
      auditLog,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      endpointHealth: {},
      retry: {
        ...(opts.onEndpointHealthAudit !== undefined
          ? { onEndpointHealthAudit: opts.onEndpointHealthAudit }
          : {}),
      },
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  it("revising the callback routes the next revision to the new callback; the audit log keeps every endpoint_health_revised and the revision itself is audited with exact previous/current", () => {
    const first: EndpointHealthRevisedAuditEvent[] = [];
    const second: EndpointHealthRevisedAuditEvent[] = [];
    const { relay, auditLog } = makeRelay({
      onEndpointHealthAudit: (e) => first.push(e),
    });
    relay.reviseEndpointHealth!({ degradeThreshold: 30 });
    assert.equal(first.length, 1);
    assert.equal(eventsOf(auditLog, "endpoint_health_revised").length, 1);
    relay.reviseEndpointHealthAuditCallback!((e) => second.push(e));
    assert.equal(second.length, 0, "no re-delivery of the reported revision");
    relay.reviseEndpointHealth!({ sloMs: 2000 });
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second.length, 1);
    assert.deepEqual(second[0], {
      event: "endpoint_health_revised",
      previous: { ...defaults, degradeThreshold: 30 },
      current: { ...defaults, degradeThreshold: 30, sloMs: 2000 },
    });
    assert.equal(eventsOf(auditLog, "endpoint_health_revised").length, 2);
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "endpoint_health_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; revisions are still audited and a second clear is a silent no-op", () => {
    const first: EndpointHealthRevisedAuditEvent[] = [];
    const { relay, auditLog } = makeRelay({
      onEndpointHealthAudit: (e) => first.push(e),
    });
    relay.reviseEndpointHealth!({ sloMs: 1000 });
    assert.equal(first.length, 1);
    relay.reviseEndpointHealthAuditCallback!(null);
    relay.reviseEndpointHealth!({ sloMs: 2000 });
    assert.equal(first.length, 1, "cleared hook stays silent");
    assert.equal(
      eventsOf(auditLog, "endpoint_health_revised").length,
      2,
      "revisions are still audited after clearing"
    );
    assert.deepEqual(relay.getEndpointHealthConfig!(), { ...defaults, sloMs: 2000 });
    const revised = eventsOf(auditLog, "endpoint_health_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
    relay.reviseEndpointHealthAuditCallback!(null);
    assert.equal(eventsOf(auditLog, "endpoint_health_audit_callback_revised").length, 1);
  });

  it("a non-function value throws RangeError and the live cell is untouched; same-reference and clear-when-unset are silent no-ops; setting from cleared audits cleared -> set", () => {
    const first: EndpointHealthRevisedAuditEvent[] = [];
    const onEndpointHealthAudit = (e: EndpointHealthRevisedAuditEvent) => first.push(e);
    const { relay, auditLog } = makeRelay({ onEndpointHealthAudit });
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseEndpointHealthAuditCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "endpoint_health_audit_callback_revised").length, 0);
    relay.reviseEndpointHealthAuditCallback!(onEndpointHealthAudit);
    assert.equal(eventsOf(auditLog, "endpoint_health_audit_callback_revised").length, 0);
    relay.reviseEndpointHealth!({ sloMs: 1000 });
    assert.equal(first.length, 1, "live callback untouched by the rejected values");
    // Bare server: clearing when unset is a silent no-op, and setting
    // from cleared audits as cleared -> set.
    const { relay: bare, auditLog: bareAudit } = makeRelay({});
    bare.reviseEndpointHealthAuditCallback!(null);
    assert.equal(eventsOf(bareAudit, "endpoint_health_audit_callback_revised").length, 0);
    bare.reviseEndpointHealthAuditCallback!((e) => first.push(e));
    const bareRevised = eventsOf(bareAudit, "endpoint_health_audit_callback_revised");
    assert.equal(bareRevised.length, 1);
    assert.equal(bareRevised[0].previous, "cleared");
    assert.equal(bareRevised[0].current, "set");
  });

  it("revising with health scoring unconfigured throws Error", () => {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-health-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: signingKey,
      forwardUrl: EP,
      auditLog,
      operatorToken: opToken,
      sender: async () => {},
    });
    servers.push(relay);
    assert.throws(
      () => relay.reviseEndpointHealthAuditCallback!(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    assert.throws(
      () => relay.reviseEndpointHealthAuditCallback!(null),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });
});
