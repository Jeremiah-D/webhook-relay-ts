import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";
import {
  ContentRouteTable,
  assertValidContentRouteRules,
  CONTENT_ROUTE_DEFAULT_PRIORITY,
  type ContentRouteRule,
} from "../src/content-routes.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files, so no SECRET/OPERATOR_TOKEN-style names here.
const signingSecret = "relay-content-routes-secret";
const operatorToken = "content-routes-operator-token";
const forwardTarget = "http://127.0.0.1:1/forward";
const targetA = "http://127.0.0.1:1/team-a";
const targetB = "http://127.0.0.1:1/team-b";
const defaultTarget = "http://127.0.0.1:1/default";

function rule(over: Partial<ContentRouteRule> & { id: string }): ContentRouteRule {
  return {
    matchers: [{ field: "type", op: "equals", value: "x" }],
    targetUrl: targetA,
    ...over,
  };
}

describe("ContentRouteTable matching", () => {
  it("equals matches dot-path primitives", () => {
    const table = new ContentRouteTable([
      rule({ id: "express", matchers: [{ field: "order.type", op: "equals", value: "express" }] }),
    ]);
    const hit = table.resolve({ order: { type: "express" } });
    assert.equal(hit.ruleId, "express");
    assert.equal(hit.targetUrl, targetA);
    assert.equal(table.resolve({ order: { type: "standard" } }).ruleId, undefined);
    assert.equal(table.resolve({ order: {} }).ruleId, undefined);
    assert.equal(table.resolve({}).ruleId, undefined);
  });

  it("equals deep-compares arrays and objects via JSON", () => {
    const table = new ContentRouteTable([
      rule({ id: "tags", matchers: [{ field: "tags", op: "equals", value: ["a", "b"] }] }),
    ]);
    assert.equal(table.resolve({ tags: ["a", "b"] }).ruleId, "tags");
    assert.equal(table.resolve({ tags: ["b", "a"] }).ruleId, undefined);
    assert.equal(table.resolve({ tags: "a,b" }).ruleId, undefined);
  });

  it("a rule matches only when every matcher matches", () => {
    const table = new ContentRouteTable([
      rule({
        id: "both",
        matchers: [
          { field: "type", op: "equals", value: "order" },
          { field: "amount", op: "range", min: 100 },
        ],
      }),
    ]);
    assert.equal(table.resolve({ type: "order", amount: 200 }).ruleId, "both");
    assert.equal(table.resolve({ type: "order", amount: 50 }).ruleId, undefined);
    assert.equal(table.resolve({ type: "refund", amount: 200 }).ruleId, undefined);
  });

  it("contains: substring for strings, includes for arrays", () => {
    const table = new ContentRouteTable([
      rule({ id: "sub", matchers: [{ field: "note", op: "contains", value: "urgent" }] }),
      rule({ id: "arr", matchers: [{ field: "flags", op: "contains", value: "vip" }] }),
    ]);
    assert.equal(table.resolve({ note: "this is urgent!" }).ruleId, "sub");
    assert.equal(table.resolve({ note: "calm" }).ruleId, undefined);
    assert.equal(table.resolve({ flags: ["new", "vip"] }).ruleId, "arr");
    assert.equal(table.resolve({ flags: ["new"] }).ruleId, undefined);
  });

  it("contains does not match non-string/non-array fields", () => {
    const table = new ContentRouteTable([
      rule({ id: "sub", matchers: [{ field: "n", op: "contains", value: "1" }] }),
    ]);
    assert.equal(table.resolve({ n: 123 }).ruleId, undefined);
    assert.equal(table.resolve({ n: null }).ruleId, undefined);
  });

  it("regex applies to strings only", () => {
    const table = new ContentRouteTable([
      rule({ id: "re", matchers: [{ field: "id", op: "regex", value: "^ord_[0-9]+$" }] }),
    ]);
    assert.equal(table.resolve({ id: "ord_123" }).ruleId, "re");
    assert.equal(table.resolve({ id: "inv_123" }).ruleId, undefined);
    // Non-string fields never match a regex.
    assert.equal(table.resolve({ id: 123 }).ruleId, undefined);
    assert.equal(table.resolve({ id: ["ord_123"] }).ruleId, undefined);
  });

  it("exists: present and non-null only", () => {
    const table = new ContentRouteTable([
      rule({ id: "ex", matchers: [{ field: "meta.coupon", op: "exists" }] }),
    ]);
    assert.equal(table.resolve({ meta: { coupon: "SAVE10" } }).ruleId, "ex");
    assert.equal(table.resolve({ meta: { coupon: null } }).ruleId, undefined);
    assert.equal(table.resolve({ meta: {} }).ruleId, undefined);
    assert.equal(table.resolve({}).ruleId, undefined);
  });

  it("range: inclusive bounds, one-sided, numeric fields only", () => {
    const table = new ContentRouteTable([
      rule({ id: "band", matchers: [{ field: "amount", op: "range", min: 100, max: 500 }] }),
      rule({ id: "floor", matchers: [{ field: "score", op: "range", min: 10 }] }),
      rule({ id: "cap", matchers: [{ field: "retries", op: "range", max: 3 }] }),
    ]);
    assert.equal(table.resolve({ amount: 100 }).ruleId, "band");
    assert.equal(table.resolve({ amount: 500 }).ruleId, "band");
    assert.equal(table.resolve({ amount: 99 }).ruleId, undefined);
    assert.equal(table.resolve({ amount: 501 }).ruleId, undefined);
    assert.equal(table.resolve({ score: 10 }).ruleId, "floor");
    assert.equal(table.resolve({ score: 100000 }).ruleId, "floor");
    assert.equal(table.resolve({ retries: 3 }).ruleId, "cap");
    assert.equal(table.resolve({ retries: 4 }).ruleId, undefined);
    // Non-numeric fields never match a range.
    assert.equal(table.resolve({ amount: "200" }).ruleId, undefined);
    assert.equal(table.resolve({ amount: null }).ruleId, undefined);
  });

  it("priority ascending, stable, first match wins", () => {
    const table = new ContentRouteTable([
      rule({ id: "late", priority: 200, targetUrl: targetB, matchers: [{ field: "t", op: "exists" }] }),
      rule({ id: "early", priority: 10, targetUrl: targetA, matchers: [{ field: "t", op: "exists" }] }),
      rule({ id: "first", targetUrl: "http://x/1", matchers: [{ field: "t", op: "exists" }] }),
      rule({ id: "second", targetUrl: "http://x/2", matchers: [{ field: "t", op: "exists" }] }),
    ]);
    const hit = table.resolve({ t: 1 });
    assert.equal(hit.ruleId, "early");
    assert.equal(hit.targetUrl, targetA);
    // Ties at the default priority keep config order.
    const tied = new ContentRouteTable([
      rule({ id: "first", targetUrl: "http://x/1" }),
      rule({ id: "second", targetUrl: "http://x/2" }),
    ]);
    assert.equal(tied.resolve({ type: "x" }).ruleId, "first");
    assert.equal(CONTENT_ROUTE_DEFAULT_PRIORITY, 100);
  });

  it("falls back to the default target when no rule matches", () => {
    const table = new ContentRouteTable(
      [rule({ id: "a", matchers: [{ field: "type", op: "equals", value: "a" }] })],
      defaultTarget
    );
    const miss = table.resolve({ type: "zzz" });
    assert.equal(miss.ruleId, undefined);
    assert.equal(miss.targetUrl, defaultTarget);
  });

  it("empty rules and no default resolve to nothing (caller uses forwardUrl)", () => {
    const table = new ContentRouteTable([]);
    assert.deepEqual(table.resolve({ type: "x" }), {});
  });

  it("never throws: non-JSON payloads fall through", () => {
    const table = new ContentRouteTable([rule({ id: "a" })], defaultTarget);
    assert.doesNotThrow(() => table.resolve(Buffer.from("not json {")));
    assert.doesNotThrow(() => table.resolve("definitely not json"));
    assert.doesNotThrow(() => table.resolve(null));
    assert.doesNotThrow(() => table.resolve(42));
    assert.doesNotThrow(() => table.resolve(undefined));
    assert.equal(table.resolve(Buffer.from("not json {")).targetUrl, defaultTarget);
    const noDefault = new ContentRouteTable([rule({ id: "a" })]);
    assert.deepEqual(noDefault.resolve("garbage"), {});
  });

  it("accepts Buffer, string, and object payloads", () => {
    const table = new ContentRouteTable([
      rule({ id: "a", matchers: [{ field: "type", op: "equals", value: "a" }] }),
    ]);
    const body = Buffer.from(JSON.stringify({ type: "a" }));
    assert.equal(table.resolve(body).ruleId, "a");
    assert.equal(table.resolve(JSON.stringify({ type: "a" })).ruleId, "a");
    assert.equal(table.resolve({ type: "a" }).ruleId, "a");
  });

  it("setRules is atomic: a rejected update leaves the live table untouched", () => {
    const table = new ContentRouteTable([rule({ id: "a", targetUrl: targetA })]);
    assert.throws(
      () => table.setRules([{ id: "a", matchers: [], targetUrl: targetA }]),
      RangeError
    );
    assert.throws(
      () => table.setRules([rule({ id: "b", targetUrl: targetB })], ""),
      RangeError
    );
    // Still the original rule and no default.
    assert.equal(table.getRules().length, 1);
    assert.equal(table.getRules()[0].id, "a");
    assert.equal(table.resolve({ type: "x" }).ruleId, "a");
    assert.equal(table.getDefaultTargetUrl(), undefined);
    // A valid update swaps atomically.
    table.setRules([rule({ id: "b", targetUrl: targetB })], defaultTarget);
    assert.equal(table.resolve({ type: "x" }).ruleId, "b");
    assert.equal(table.resolve({ type: "x" }).targetUrl, targetB);
    assert.equal(table.getDefaultTargetUrl(), defaultTarget);
  });

  it("getRules returns a defensive copy", () => {
    const table = new ContentRouteTable([rule({ id: "a" })]);
    const snapshot = table.getRules();
    snapshot[0].id = "mutated";
    snapshot[0].matchers.push({ field: "z", op: "exists" });
    assert.equal(table.getRules()[0].id, "a");
    assert.equal(table.getRules()[0].matchers.length, 1);
  });
});

describe("assertValidContentRouteRules", () => {
  it("accepts valid rules and undefined-free shapes", () => {
    assert.doesNotThrow(() => assertValidContentRouteRules([]));
    assert.doesNotThrow(() =>
      assertValidContentRouteRules([
        {
          id: "r1",
          matchers: [{ field: "a.b", op: "equals", value: 1 }],
          targetUrl: "http://x/1",
        },
        {
          id: "r2",
          matchers: [{ field: "c", op: "range", min: 0, max: 9 }],
          targetUrl: "http://x/2",
          priority: 5,
        },
      ])
    );
  });

  it("rejects malformed rule lists", () => {
    assert.throws(() => assertValidContentRouteRules("nope" as never), RangeError);
    assert.throws(() => assertValidContentRouteRules([null] as never), RangeError);
    assert.throws(() => assertValidContentRouteRules([rule({ id: "" })]), RangeError);
    assert.throws(
      () => assertValidContentRouteRules([rule({ id: "dup" }), rule({ id: "dup" })]),
      RangeError
    );
    assert.throws(() => assertValidContentRouteRules([rule({ id: "x", targetUrl: "" })]), RangeError);
    assert.throws(() => assertValidContentRouteRules([rule({ id: "x", matchers: [] })]), RangeError);
    assert.throws(
      () => assertValidContentRouteRules([rule({ id: "x", priority: NaN })]),
      RangeError
    );
  });

  it("rejects malformed matchers", () => {
    assert.throws(
      () => assertValidContentRouteRules([rule({ id: "x", matchers: [{ field: "", op: "exists" }] })]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidContentRouteRules([
          rule({ id: "x", matchers: [{ field: "a", op: "bogus" as never }] }),
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidContentRouteRules([
          rule({ id: "x", matchers: [{ field: "a", op: "regex", value: "(unclosed" }] }),
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidContentRouteRules([
          rule({ id: "x", matchers: [{ field: "a", op: "regex", value: 42 as never }] }),
        ]),
      RangeError
    );
    assert.throws(
      () => assertValidContentRouteRules([rule({ id: "x", matchers: [{ field: "a", op: "equals" }] })]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidContentRouteRules([rule({ id: "x", matchers: [{ field: "a", op: "range" }] })]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidContentRouteRules([
          rule({ id: "x", matchers: [{ field: "a", op: "range", min: "low" as never }] }),
        ]),
      RangeError
    );
  });

  it("rejects a bad default target", () => {
    assert.throws(() => new ContentRouteTable([], ""), RangeError);
    assert.throws(() => new ContentRouteTable([], 42 as never), RangeError);
    assert.doesNotThrow(() => new ContentRouteTable([], defaultTarget));
    assert.doesNotThrow(() => new ContentRouteTable([]));
  });
});

// ---------------------------------------------------------------------------
// Server integration
// ---------------------------------------------------------------------------

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      assert.ok(addr && typeof addr === "object");
      resolve(addr.port);
    });
  });
}

function call(
  port: number,
  method: string,
  path: string,
  bearer?: string,
  body?: string
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (bearer !== undefined) headers["authorization"] = `Bearer ${bearer}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const req = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
      );
    });
    req.on("error", reject);
    req.end(body);
  });
}

function postWebhook(
  port: number,
  path: string,
  payload: unknown,
  secret: string = signingSecret
): Promise<{ status: number; text: string }> {
  const body = Buffer.from(JSON.stringify(payload));
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: { "x-signature": signSha256(body, secret) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    req.on("error", reject);
    req.end(body);
  });
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for ${what}`);
}

interface RelayHarness {
  server: Server;
  audit: AuditLog;
  received: RetryItem[];
  port: number;
}

async function makeRelay(extra: Record<string, unknown> = {}): Promise<RelayHarness> {
  const dir = mkdtempSync(join(tmpdir(), "content-routes-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const received: RetryItem[] = [];
  const server = createRelayServer({
    secret: signingSecret,
    forwardUrl: forwardTarget,
    auditLog: audit,
    sender: async (item) => {
      received.push(item);
    },
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    ...extra,
  } as Parameters<typeof createRelayServer>[0]);
  const port = await listen(server);
  return { server, audit, received, port };
}

async function closeRelay(h: RelayHarness): Promise<void> {
  h.server.close();
  await new Promise((r) => h.server.once("close", r));
}

function auditEvents(audit: AuditLog): Array<Record<string, unknown>> {
  return audit.readAll() as Array<Record<string, unknown>>;
}

function routedEvents(audit: AuditLog): Array<Record<string, unknown>> {
  return auditEvents(audit).filter((e) => e.event === "routed");
}

const intakeRules: ContentRouteRule[] = [
  {
    id: "express-orders",
    matchers: [{ field: "order.type", op: "equals", value: "express" }],
    targetUrl: targetA,
    priority: 10,
  },
  {
    id: "big-tickets",
    matchers: [{ field: "amount", op: "range", min: 1000 }],
    targetUrl: targetB,
  },
];

describe("content-based routing in the intake pipeline", () => {
  let h: RelayHarness;
  before(async () => {
    h = await makeRelay({ contentRoutes: intakeRules, contentRouteDefault: defaultTarget, operatorToken });
  });
  after(async () => {
    await closeRelay(h);
  });

  it("a signature failure stays 401 and is never routed", async () => {
    const res = await postWebhook(h.port, "/hooks", { order: { type: "express" } }, "wrong-secret");
    assert.equal(res.status, 401);
    assert.equal(routedEvents(h.audit).length, 0);
    assert.equal(h.received.length, 0);
    const rejected = auditEvents(h.audit).filter((e) => e.event === "rejected");
    assert.ok(rejected.some((e) => e.reason === "invalid_signature"));
  });

  it("a matching payload is delivered to the rule target", async () => {
    const res = await postWebhook(h.port, "/hooks", { order: { type: "express" }, amount: 5 });
    assert.equal(res.status, 202);
    await waitFor(() => h.received.length >= 1, "delivery to the routed target");
    assert.equal(h.received[h.received.length - 1].targetUrl, targetA);
    const routed = routedEvents(h.audit);
    assert.equal(routed.length, 1);
    assert.equal(routed[0].ruleId, "express-orders");
    assert.equal(routed[0].targetUrl, targetA);
  });

  it("a non-matching payload falls back to the default route", async () => {
    const res = await postWebhook(h.port, "/hooks", { order: { type: "standard" }, amount: 5 });
    assert.equal(res.status, 202);
    await waitFor(() => h.received.length >= 2, "delivery to the default target");
    assert.equal(h.received[h.received.length - 1].targetUrl, defaultTarget);
    const routed = routedEvents(h.audit);
    const last = routed[routed.length - 1];
    assert.equal(last.ruleId, "default");
    assert.equal(last.targetUrl, defaultTarget);
  });

  it("priority decides between overlapping rules", async () => {
    // Matches both rules (express type AND big amount) — priority 10 wins.
    const res = await postWebhook(h.port, "/hooks", { order: { type: "express" }, amount: 5000 });
    assert.equal(res.status, 202);
    await waitFor(() => h.received.length >= 3, "delivery after priority test");
    assert.equal(h.received[h.received.length - 1].targetUrl, targetA);
    const routed = routedEvents(h.audit);
    assert.equal(routed[routed.length - 1].ruleId, "express-orders");
  });

  it("a non-JSON body is never rejected by routing", async () => {
    const body = Buffer.from("this is not json");
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port: h.port,
          path: "/hooks",
          method: "POST",
          headers: { "x-signature": signSha256(body, signingSecret) },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      req.on("error", reject);
      req.end(body);
    });
    assert.equal(status, 202);
    const routed = routedEvents(h.audit);
    const last = routed[routed.length - 1];
    assert.equal(last.ruleId, "default");
    assert.equal(last.targetUrl, defaultTarget);
  });
});

describe("routing without a default falls back to forwardUrl", () => {
  let h: RelayHarness;
  before(async () => {
    h = await makeRelay({ contentRoutes: intakeRules });
  });
  after(async () => {
    await closeRelay(h);
  });

  it("unmatched payloads go to forwardUrl with ruleId default", async () => {
    const res = await postWebhook(h.port, "/hooks", { order: { type: "standard" } });
    assert.equal(res.status, 202);
    await waitFor(() => h.received.length >= 1, "delivery to forwardUrl");
    assert.equal(h.received[0].targetUrl, forwardTarget);
    const routed = routedEvents(h.audit);
    assert.equal(routed[0].ruleId, "default");
    assert.equal(routed[0].targetUrl, forwardTarget);
  });
});

describe("no routing configured: intake is byte-identical to before", () => {
  let h: RelayHarness;
  before(async () => {
    h = await makeRelay();
  });
  after(async () => {
    await closeRelay(h);
  });

  it("no routed audit event is emitted", async () => {
    const res = await postWebhook(h.port, "/hooks", { order: { type: "express" } });
    assert.equal(res.status, 202);
    await waitFor(() => h.received.length >= 1, "delivery");
    assert.equal(h.received[0].targetUrl, forwardTarget);
    assert.equal(routedEvents(h.audit).length, 0);
    const accepted = auditEvents(h.audit).filter((e) => e.event === "accepted");
    assert.equal(accepted[0].targetUrl, forwardTarget);
  });
});

describe("dedup is keyed on the routed target", () => {
  let h: RelayHarness;
  before(async () => {
    h = await makeRelay({
      contentRoutes: [
        {
          id: "express",
          matchers: [{ field: "order.type", op: "equals", value: "express" }],
          targetUrl: targetA,
        },
      ],
      dedup: { windowMs: 60_000 },
      operatorToken,
    });
  });
  after(async () => {
    await closeRelay(h);
  });

  it("the same payload to the same routed target suppresses once", async () => {
    const payload = { order: { type: "express" }, nonce: "dedup-1" };
    const first = await postWebhook(h.port, "/hooks", payload);
    assert.equal(first.status, 202);
    assert.ok(!JSON.parse(first.text).duplicate);
    const second = await postWebhook(h.port, "/hooks", payload);
    assert.equal(second.status, 202);
    assert.equal(JSON.parse(second.text).duplicate, true);
    const suppressed = auditEvents(h.audit).filter((e) => e.event === "duplicate_suppressed");
    assert.equal(suppressed[suppressed.length - 1].targetUrl, targetA);
  });

  it("re-routing the same payload to a new target is accepted again", async () => {
    const payload = { order: { type: "express" }, nonce: "dedup-2" };
    const first = await postWebhook(h.port, "/hooks", payload);
    assert.equal(first.status, 202);
    // Hot-swap: the same payload now routes to targetB. The dedup key is
    // (tenant, targetUrl), so this is a fresh pair, not a duplicate.
    const swap = await call(h.port, "POST", "/routing/rules", operatorToken, JSON.stringify({
      rules: [
        {
          id: "express",
          matchers: [{ field: "order.type", op: "equals", value: "express" }],
          targetUrl: targetB,
        },
      ],
    }));
    assert.equal(swap.status, 200);
    const second = await postWebhook(h.port, "/hooks", payload);
    assert.equal(second.status, 202);
    assert.ok(!JSON.parse(second.text).duplicate);
    const routed = routedEvents(h.audit);
    assert.equal(routed[routed.length - 1].ruleId, "express");
    assert.equal(routed[routed.length - 1].targetUrl, targetB);
  });
});

describe("operator /routing/rules", () => {
  describe("with the legacy operator token", () => {
    let h: RelayHarness;
    before(async () => {
      h = await makeRelay({ contentRoutes: intakeRules, contentRouteDefault: defaultTarget, operatorToken });
    });
    after(async () => {
      await closeRelay(h);
    });

    it("GET lists the live rules and default", async () => {
      const res = await call(h.port, "GET", "/routing/rules", operatorToken);
      assert.equal(res.status, 200);
      const body = JSON.parse(res.text) as { rules: ContentRouteRule[]; defaultTargetUrl: string };
      assert.equal(body.rules.length, 2);
      assert.equal(body.rules[0].id, "express-orders");
      assert.equal(body.defaultTargetUrl, defaultTarget);
    });

    it("POST replaces the rules and audits the change", async () => {
      const replacement: ContentRouteRule[] = [
        {
          id: "only",
          matchers: [{ field: "kind", op: "equals", value: "ping" }],
          targetUrl: targetB,
        },
      ];
      const res = await call(
        h.port,
        "POST",
        "/routing/rules",
        operatorToken,
        JSON.stringify({ rules: replacement })
      );
      assert.equal(res.status, 200);
      const body = JSON.parse(res.text) as { rules: ContentRouteRule[] };
      assert.deepEqual(
        body.rules.map((r) => r.id),
        ["only"]
      );
      assert.ok(!("defaultTargetUrl" in body));
      const updates = auditEvents(h.audit).filter((e) => e.event === "routing_rules_updated");
      assert.equal(updates.length, 1);
      assert.equal(updates[0].keyId, "legacy");
      assert.equal(updates[0].ruleCount, 1);
      // The replacement is live immediately.
      const posted = await postWebhook(h.port, "/hooks", { kind: "ping" });
      assert.equal(posted.status, 202);
      const routed = routedEvents(h.audit);
      assert.equal(routed[routed.length - 1].ruleId, "only");
      assert.equal(routed[routed.length - 1].targetUrl, targetB);
      const stale = await postWebhook(h.port, "/hooks", { order: { type: "express" } });
      assert.equal(stale.status, 202);
      const routedAfter = routedEvents(h.audit);
      assert.equal(routedAfter[routedAfter.length - 1].ruleId, "default");
    });

    it("POST with invalid rules is a 400 and changes nothing", async () => {
      const beforeRules = JSON.parse(
        (await call(h.port, "GET", "/routing/rules", operatorToken)).text
      ).rules;
      const bad = await call(
        h.port,
        "POST",
        "/routing/rules",
        operatorToken,
        JSON.stringify({ rules: [{ id: "dup" }, { id: "dup" }] })
      );
      assert.equal(bad.status, 400);
      assert.ok((JSON.parse(bad.text) as { error: string }).error.length > 0);
      const afterRules = JSON.parse(
        (await call(h.port, "GET", "/routing/rules", operatorToken)).text
      ).rules;
      assert.deepEqual(afterRules, beforeRules);
      const invalidJson = await call(h.port, "POST", "/routing/rules", operatorToken, "{oops");
      assert.equal(invalidJson.status, 400);
    });

    it("wrong bearer is 403", async () => {
      assert.equal((await call(h.port, "GET", "/routing/rules", "nope")).status, 403);
      assert.equal(
        (await call(h.port, "POST", "/routing/rules", "nope", JSON.stringify({ rules: [] }))).status,
        403
      );
    });
  });

  describe("with scoped operator keys (WR-82)", () => {
    const readKey = "content-routes-read-key";
    const adminKey = "content-routes-admin-key";
    let h: RelayHarness;
    before(async () => {
      h = await makeRelay({
        contentRoutes: intakeRules,
        operatorKeys: [
          { id: "monitor", key: readKey, scopes: ["read"] },
          { id: "human", key: adminKey, scopes: ["admin"] },
        ],
      });
    });
    after(async () => {
      await closeRelay(h);
    });

    it("GET works with a read-scoped key", async () => {
      const res = await call(h.port, "GET", "/routing/rules", readKey);
      assert.equal(res.status, 200);
      assert.equal((JSON.parse(res.text) as { rules: ContentRouteRule[] }).rules.length, 2);
    });

    it("POST with a read-scoped key is 403, admin succeeds", async () => {
      const forbidden = await call(
        h.port,
        "POST",
        "/routing/rules",
        readKey,
        JSON.stringify({ rules: [] })
      );
      assert.equal(forbidden.status, 403);
      const ok = await call(
        h.port,
        "POST",
        "/routing/rules",
        adminKey,
        JSON.stringify({ rules: [], defaultTargetUrl: defaultTarget })
      );
      assert.equal(ok.status, 200);
      const listed = JSON.parse(
        (await call(h.port, "GET", "/routing/rules", readKey)).text
      ) as { rules: ContentRouteRule[]; defaultTargetUrl: string };
      assert.deepEqual(listed.rules, []);
      assert.equal(listed.defaultTargetUrl, defaultTarget);
      const updates = auditEvents(h.audit).filter((e) => e.event === "routing_rules_updated");
      assert.equal(updates[updates.length - 1].keyId, "human");
    });
  });

  describe("fail-closed without operator credentials", () => {
    let h: RelayHarness;
    before(async () => {
      h = await makeRelay({ contentRoutes: intakeRules });
    });
    after(async () => {
      await closeRelay(h);
    });

    it("GET and POST both 404", async () => {
      assert.equal((await call(h.port, "GET", "/routing/rules")).status, 404);
      assert.equal(
        (await call(h.port, "POST", "/routing/rules", undefined, JSON.stringify({ rules: [] }))).status,
        404
      );
    });
  });
});

describe("createRelayServer validates content routing options", () => {
  it("throws RangeError on bad rules and bad defaults at startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "content-routes-startup-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const base = { secret: signingSecret, forwardUrl: forwardTarget, auditLog: audit };
    assert.throws(
      () => createRelayServer({ ...base, contentRoutes: [rule({ id: "x", targetUrl: "" })] }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          ...base,
          contentRoutes: [rule({ id: "dup" }), rule({ id: "dup" })],
        }),
      RangeError
    );
    assert.throws(() => createRelayServer({ ...base, contentRouteDefault: "" }), RangeError);
    assert.doesNotThrow(() =>
      createRelayServer({ ...base, contentRoutes: [rule({ id: "ok" })], contentRouteDefault: defaultTarget })
    );
  });
});
