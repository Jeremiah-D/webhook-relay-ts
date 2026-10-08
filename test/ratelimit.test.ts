import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InboundRateLimiter } from "../src/ratelimit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const SECRET = "rl-secret";
const BODY = Buffer.from(JSON.stringify({ event: "rl.probe" }));

function postSigned(port: number) {
  return new Promise<{ status: number; retryAfter: string | undefined }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/hook",
        method: "POST",
        headers: { "x-signature": signSha256(BODY, SECRET) },
      },
      (res) => {
        res.resume();
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, retryAfter: res.headers["retry-after"] as string | undefined })
        );
      }
    );
    r.on("error", reject);
    r.end(BODY);
  });
}

describe("ratelimit: InboundRateLimiter", () => {
  it("admits within budget, rejects past it with the honest retryAfterMs", () => {
    let now = 0;
    const rl = new InboundRateLimiter({ perIpPerSecond: 2, now: () => now });
    assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
    assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
    const v = rl.take("1.1.1.1", "ep");
    assert.equal(v.ok, false);
    if (!v.ok) {
      assert.equal(v.dimension, "ip");
      assert.equal(v.retryAfterMs, 500); // 1 token short at 2/sec
    }
    now += 499;
    assert.equal(rl.take("1.1.1.1", "ep").ok, false);
    now += 1;
    assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
  });

  it("per-endpoint dimension is keyed independently of the sender IP", () => {
    let now = 0;
    const rl = new InboundRateLimiter({ perEndpointPerSecond: 1, now: () => now });
    assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
    const v = rl.take("2.2.2.2", "ep"); // different IP, same endpoint
    assert.equal(v.ok, false);
    if (!v.ok) assert.equal(v.dimension, "endpoint");
    // ...but a different endpoint still has its own full budget.
    assert.deepEqual(rl.take("1.1.1.1", "other"), { ok: true });
  });

  it("per-ip dimension is keyed independently of the endpoint", () => {
    const rl = new InboundRateLimiter({ perIpPerSecond: 1 });
    assert.deepEqual(rl.take("1.1.1.1", "a"), { ok: true });
    const v = rl.take("1.1.1.1", "b"); // same IP, different endpoint
    assert.equal(v.ok, false);
    if (!v.ok) assert.equal(v.dimension, "ip");
    assert.deepEqual(rl.take("2.2.2.2", "a"), { ok: true });
  });

  it("a rejection never burns the other dimension's token", () => {
    const rl = new InboundRateLimiter({ perIpPerSecond: 1, perEndpointPerSecond: 1 });
    assert.deepEqual(rl.take("1.1.1.1", "ep1"), { ok: true });
    // ip bucket empty now; endpoint ep2 is untouched by the rejected request.
    assert.equal(rl.take("1.1.1.1", "ep2").ok, false);
    assert.deepEqual(rl.take("2.2.2.2", "ep2"), { ok: true });
  });

  it("clock skew backward never grants extra budget", () => {
    let now = 10_000;
    const rl = new InboundRateLimiter({ perIpPerSecond: 1, now: () => now });
    assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
    now = 0; // clock jumps backward
    assert.equal(rl.take("1.1.1.1", "ep").ok, false);
  });

  it("invalid budgets fail fast at construction", () => {
    assert.throws(() => new InboundRateLimiter({ perIpPerSecond: 0 }), /perIpPerSecond/);
    assert.throws(() => new InboundRateLimiter({ perIpPerSecond: -5 }), /perIpPerSecond/);
    assert.throws(() => new InboundRateLimiter({ perEndpointPerSecond: NaN }), /perEndpointPerSecond/);
    assert.throws(() => new InboundRateLimiter({ perEndpointPerSecond: Infinity }), /perEndpointPerSecond/);
  });

  it("no configured dimensions means unlimited", () => {
    const rl = new InboundRateLimiter();
    for (let i = 0; i < 50; i++) assert.deepEqual(rl.take("1.1.1.1", "ep"), { ok: true });
  });
});

describe("ratelimit: 429s at the relay server intake", () => {
  let relay: Server;
  let port: number;
  let audit: AuditLog;
  const OPERATOR = "op-rl-token";
  const auth = { authorization: `Bearer ${OPERATOR}` };

  before(async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-rl-"));
    audit = new AuditLog(join(dir, "audit.jsonl"));
    relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:9/unused", // never reached: intake gate is before delivery
      auditLog: audit,
      operatorToken: OPERATOR,
      rateLimit: { perIpPerSecond: 2 },
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const addr = relay.address();
    assert.ok(addr && typeof addr === "object");
    port = addr.port;
  });

  after(() => relay.close());

  it("admits within budget, answers 429 + retry-after past it, and audits the rejection", async () => {
    const first = await postSigned(port);
    const second = await postSigned(port);
    assert.equal(first.status, 202);
    assert.equal(second.status, 202);
    const third = await postSigned(port);
    assert.equal(third.status, 429);
    assert.ok(third.retryAfter !== undefined, "429 must carry retry-after");
    assert.ok(Number(third.retryAfter) >= 1, "retry-after is ceiling seconds, minimum 1");

    const rejected = audit
      .query({ event: ["rejected"] })
      .filter((e) => (e as { reason?: string }).reason === "rate_limited");
    assert.equal(rejected.length, 1);
    const entry = rejected[0] as { dimension?: string; retryAfterMs?: number; traceId?: string };
    assert.equal(entry.dimension, "ip");
    assert.ok(typeof entry.retryAfterMs === "number" && entry.retryAfterMs > 0);
    assert.ok(typeof entry.traceId === "string" && entry.traceId.length > 0);
  });
});
