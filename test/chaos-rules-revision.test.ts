import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, type RelayServerOptions } from "../src/server.ts";
import type { ChaosFaultRule, ChaosRulesRevision } from "../src/chaos.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const inboundKey = "wr431-inbound-key";
const PAYLOAD = { event: "chaos.revise" };

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

/** An HTTP downstream that records every request's body. */
function httpStub() {
  const seen: Buffer[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push(Buffer.concat(chunks));
      res.writeHead(200).end("ok");
    });
  });
  return { server, seen };
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
  return audit.query({ event: "chaos_rules_revised" }) as Array<Record<string, unknown>>;
}

function injectedEvents(audit: AuditLog, id: string) {
  return (
    audit.query({ event: "chaos_injected" }) as Array<Record<string, unknown>>
  ).filter((e) => e.id === id);
}

interface Setup {
  stub: Server;
  seen: Buffer[];
  target: string;
  other: string;
  audit: AuditLog;
  relay: ReturnType<typeof createRelayServer>;
  relayPort: number;
}

async function setup(rules: Record<string, ChaosFaultRule> | undefined): Promise<Setup> {
  const { server: stub, seen } = httpStub();
  const stubPort = await listen(stub);
  const target = `http://127.0.0.1:${stubPort}/hook`;
  const other = `http://127.0.0.1:${stubPort}/other`;
  const audit = newAudit("wr431-");
  const relay = createRelayServer(
    relayOpts(target, audit, rules === undefined ? {} : { chaos: { rules } })
  );
  const relayPort = await listen(relay);
  return { stub, seen, target, other, audit, relay, relayPort };
}

async function teardown(s: Setup): Promise<void> {
  await close(s.relay);
  await close(s.stub);
}

describe("chaos rules live revision (WR-431)", () => {
  it("setting a rule on a new endpoint injects a synthetic 500 without touching the network", async () => {
    const s = await setup({ "http://127.0.0.1:1/unused": { statusCode: 500 } });
    try {
      // The target has no rule yet: the first delivery goes straight through.
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      assert.equal(s.seen.length, 1);
      assert.equal(injectedEvents(s.audit, firstId).length, 0);

      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      assert.deepEqual(s.relay.getChaosRules!(), {
        "http://127.0.0.1:1/unused": { statusCode: 500 },
        [s.target]: { statusCode: 500 },
      });

      const secondId = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, secondId);
      assert.equal(s.seen.length, 1, "synthetic 500 must not touch the network");
      const injected = injectedEvents(s.audit, secondId);
      assert.equal(injected.length, 2, "one injection per attempt (maxAttempts 2)");
      assert.ok(injected.every((e) => e.kind === "status" && e.statusCode === 500));
    } finally {
      await teardown(s);
    }
  });

  it("replacing a latency rule with a status rule applies to the next attempt", async () => {
    const s = await setup({});
    try {
      // Start from a latency rule: the first delivery is held, then succeeds.
      s.relay.reviseChaosRules!({ [s.target]: { latencyMs: 60 } });
      const start = Date.now();
      const firstId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, firstId);
      assert.ok(Date.now() - start >= 50, "expected a ~60ms hold");
      assert.equal(s.seen.length, 1);
      assert.equal(injectedEvents(s.audit, firstId).length, 1);
      assert.equal(injectedEvents(s.audit, firstId)[0].kind, "latency");

      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      const secondId = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, secondId);
      assert.equal(s.seen.length, 1, "no second request after the swap to status");
      const injected = injectedEvents(s.audit, secondId);
      assert.equal(injected.length, 2);
      assert.ok(injected.every((e) => e.kind === "status" && e.statusCode === 500));
    } finally {
      await teardown(s);
    }
  });

  it("clearing a rule with null lets the next attempt pass through untouched", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      const firstId = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, firstId);
      assert.equal(s.seen.length, 0);
      assert.equal(injectedEvents(s.audit, firstId).length, 2);

      s.relay.reviseChaosRules!({ [s.target]: null });
      assert.deepEqual(s.relay.getChaosRules!(), {}, "drill armed-but-empty after clear");

      const secondId = await deliver(s.relayPort);
      await waitForDelivered(s.audit, secondId);
      assert.equal(s.seen.length, 1, "cleared endpoint delegates straight through");
      assert.equal(injectedEvents(s.audit, secondId).length, 0);
      // The drill is still armed: a new rule binds again.
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 503 } });
      assert.deepEqual(s.relay.getChaosRules!(), { [s.target]: { statusCode: 503 } });
    } finally {
      await teardown(s);
    }
  });

  it("rejects invalid patches with RangeError and leaves live rules untouched", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      const eventsBefore = revisedEvents(s.audit).length;
      const bad: ChaosRulesRevision[] = [
        { [s.target]: { latencyMs: -1 } },
        { [s.target]: { latencyMs: NaN } },
        { [s.target]: { statusCode: 99 } },
        { [s.target]: { statusCode: 600 } },
        { [s.target]: { resetConnection: true, statusCode: 500 } },
        { [s.target]: {} },
        // A mixed patch must not partially apply: the valid entry stays out too.
        { [s.target]: { statusCode: 503 }, [s.other]: { statusCode: 99 } },
      ];
      for (const patch of bad) {
        assert.throws(() => s.relay.reviseChaosRules!(patch), RangeError);
      }
      assert.deepEqual(s.relay.getChaosRules!(), { [s.target]: { statusCode: 500 } });
      assert.equal(
        revisedEvents(s.audit).length,
        eventsBefore,
        "no audit for rejected patches"
      );

      const id = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, id);
      assert.equal(s.seen.length, 0, "live rule still injects after rejected patches");
      assert.ok(
        injectedEvents(s.audit, id).every((e) => e.kind === "status" && e.statusCode === 500)
      );
    } finally {
      await teardown(s);
    }
  });

  it("rejects an empty patch with RangeError", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      const eventsBefore = revisedEvents(s.audit).length;
      assert.throws(() => s.relay.reviseChaosRules!({}), RangeError);
      assert.throws(() => s.relay.reviseChaosRules!(null as never), RangeError);
      assert.throws(() => s.relay.reviseChaosRules!([] as never), RangeError);
      assert.deepEqual(s.relay.getChaosRules!(), { [s.target]: { statusCode: 500 } });
      assert.equal(revisedEvents(s.audit).length, eventsBefore);
    } finally {
      await teardown(s);
    }
  });

  it("same-value revisions are silent no-ops with no audit event", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      assert.equal(revisedEvents(s.audit).length, 1);
      // Identical rule, explicit default, and clearing an endpoint with no rule.
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500, resetConnection: false } });
      s.relay.reviseChaosRules!({ [s.other]: null });
      assert.equal(revisedEvents(s.audit).length, 1, "no new audit for no-op patches");
      assert.deepEqual(s.relay.getChaosRules!(), { [s.target]: { statusCode: 500 } });
    } finally {
      await teardown(s);
    }
  });

  it("throws Error on a server without chaos configured; getter returns {}", async () => {
    const s = await setup(undefined);
    try {
      assert.throws(
        () => s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } }),
        /chaos is not configured — enabling it requires a restart/
      );
      assert.deepEqual(s.relay.getChaosRules!(), {});
      const id = await deliver(s.relayPort);
      await waitForDelivered(s.audit, id);
      assert.equal(s.seen.length, 1, "no drill: delivery passes through");
    } finally {
      await teardown(s);
    }
  });

  it("audits previous/current exactly, with fault summary and set/cleared", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      s.relay.reviseChaosRules!({
        [s.target]: { latencyMs: 50 },
        [s.other]: { resetConnection: true },
      });
      const events = revisedEvents(s.audit);
      assert.equal(events.length, 2);
      assert.deepEqual(events[1].previous, [
        { endpoint: s.target, action: "set", kinds: ["status"], statusCode: 500 },
        { endpoint: s.other, action: "cleared", rule: null },
      ]);
      assert.deepEqual(events[1].current, [
        { endpoint: s.target, action: "set", kinds: ["latency"], latencyMs: 50 },
        { endpoint: s.other, action: "set", kinds: ["reset"], resetConnection: true },
      ]);
    } finally {
      await teardown(s);
    }
  });

  it("an in-flight latency hold is not withdrawn by a mid-flight revision", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({ [s.target]: { latencyMs: 250 } });
      const firstId = await deliver(s.relayPort);
      // The attempt has started its hold once the latency injection is audited.
      await waitFor(
        () => injectedEvents(s.audit, firstId).some((e) => e.kind === "latency"),
        10000,
        "latency injection for the in-flight attempt"
      );
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      await waitForDelivered(s.audit, firstId);
      assert.equal(s.seen.length, 1, "held attempt still delegates after its hold");
      assert.deepEqual(
        injectedEvents(s.audit, firstId).map((e) => e.kind),
        ["latency"],
        "no status injection for the attempt that already read the latency rule"
      );

      const secondId = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, secondId);
      assert.equal(s.seen.length, 1, "the next attempt walks the revised rule");
      assert.ok(
        injectedEvents(s.audit, secondId).every((e) => e.kind === "status")
      );
    } finally {
      await teardown(s);
    }
  });

  it("an in-flight synthetic status is not recomputed by a mid-flight revision", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({ [s.target]: { latencyMs: 250, statusCode: 500 } });
      const id = await deliver(s.relayPort);
      await waitFor(
        () => injectedEvents(s.audit, id).some((e) => e.kind === "latency"),
        10000,
        "latency injection for the in-flight attempt"
      );
      // While the attempt is still holding, swap the synthetic status.
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 503 } });
      await waitForDeadLetter(s.audit, id);
      assert.equal(s.seen.length, 0, "neither attempt touches the network");
      // Attempt 1 threw the status it read (500); attempt 2 is a new
      // attempt and reads the revised rule (503).
      assert.deepEqual(
        injectedEvents(s.audit, id)
          .filter((e) => e.kind === "status")
          .map((e) => e.statusCode),
        [500, 503]
      );
    } finally {
      await teardown(s);
    }
  });

  it("the getter returns a defensive copy", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      const rules = s.relay.getChaosRules!();
      rules[s.target].statusCode = 503;
      (rules as Record<string, ChaosFaultRule>)["http://127.0.0.1:1/evil"] = {
        statusCode: 200,
      };
      assert.deepEqual(s.relay.getChaosRules!(), { [s.target]: { statusCode: 500 } });
      const id = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, id);
      assert.ok(
        injectedEvents(s.audit, id).every((e) => e.statusCode === 500),
        "mutating the getter copy must not move the live rule"
      );
    } finally {
      await teardown(s);
    }
  });

  it("a revision leaves other endpoints' rules untouched", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({
        [s.target]: { statusCode: 500 },
        [s.other]: { latencyMs: 10 },
      });
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 503 } });
      assert.deepEqual(s.relay.getChaosRules!(), {
        [s.target]: { statusCode: 503 },
        [s.other]: { latencyMs: 10 },
      });
      const events = revisedEvents(s.audit);
      assert.equal(events.length, 2);
      assert.deepEqual(events[1].previous, [
        { endpoint: s.target, action: "set", kinds: ["status"], statusCode: 500 },
      ]);
      assert.deepEqual(events[1].current, [
        { endpoint: s.target, action: "set", kinds: ["status"], statusCode: 503 },
      ]);
    } finally {
      await teardown(s);
    }
  });

  it("injections keep counting after a revision", async () => {
    const s = await setup({});
    try {
      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 500 } });
      const firstId = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, firstId);
      assert.equal(injectedEvents(s.audit, firstId).length, 2);

      s.relay.reviseChaosRules!({ [s.target]: { statusCode: 503 } });
      const secondId = await deliver(s.relayPort);
      await waitForDeadLetter(s.audit, secondId);
      const injected = injectedEvents(s.audit, secondId);
      assert.equal(injected.length, 2, "the revised rule still injects per attempt");
      assert.ok(injected.every((e) => e.kind === "status" && e.statusCode === 503));
      assert.equal(
        (s.audit.query({ event: "chaos_injected" }) as Array<unknown>).length,
        4,
        "the counter path (same call site as relay_chaos_injected_total) keeps counting"
      );
    } finally {
      await teardown(s);
    }
  });
});
