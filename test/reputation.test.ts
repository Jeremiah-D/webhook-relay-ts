import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import {
  SenderReputationTracker,
  assertValidReputationOptions,
  renderSenderReputationBlock,
} from "../src/reputation.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "reputation-relay-hmac-secret";
const keyA = "reputation-api-key-abc123";
const probeBody = Buffer.from(JSON.stringify({ event: "reputation.probe" }));

/** Controllable clock for the module-level tests. */
function makeClock(startMs = 1_000_000) {
  let at = startMs;
  return {
    now: () => at,
    advance: (ms: number) => {
      at += ms;
    },
    set: (ms: number) => {
      at = ms;
    },
  };
}

describe("assertValidReputationOptions", () => {
  it("accepts undefined, empty, and fully specified options", () => {
    assertValidReputationOptions(undefined);
    assertValidReputationOptions({});
    assertValidReputationOptions({
      halfLifeMs: 60_000,
      lowThreshold: 30,
      highThreshold: 80,
      verifyFailurePenalty: 20,
      rateLimitPenalty: 4,
      schemaViolationPenalty: 8,
      now: () => 0,
    });
  });

  it("rejects bad half-lives", () => {
    for (const halfLifeMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(() => assertValidReputationOptions({ halfLifeMs }), RangeError, String(halfLifeMs));
    }
  });

  it("rejects thresholds outside [0, 100] or without a strict low < high gap", () => {
    assert.throws(() => assertValidReputationOptions({ lowThreshold: -1 }), RangeError);
    assert.throws(() => assertValidReputationOptions({ lowThreshold: 101 }), RangeError);
    assert.throws(() => assertValidReputationOptions({ highThreshold: 101 }), RangeError);
    assert.throws(
      () => assertValidReputationOptions({ lowThreshold: 70, highThreshold: 70 }),
      RangeError
    );
    assert.throws(
      () => assertValidReputationOptions({ lowThreshold: 80, highThreshold: 70 }),
      RangeError
    );
  });

  it("rejects negative or non-finite penalties", () => {
    assert.throws(() => assertValidReputationOptions({ verifyFailurePenalty: -1 }), RangeError);
    assert.throws(() => assertValidReputationOptions({ rateLimitPenalty: Number.NaN }), RangeError);
    assert.throws(
      () => assertValidReputationOptions({ schemaViolationPenalty: Number.POSITIVE_INFINITY }),
      RangeError
    );
  });
});

describe("SenderReputationTracker scoring", () => {
  it("starts pristine at 100, not degraded, with no tracked senders", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now });
    assert.equal(t.trackedSenders(), 0);
    assert.equal(t.renderMetrics(), ""); // activity-gated: no senders, no series
    assert.equal(t.score("k1"), 100);
    assert.equal(t.isDegraded("k1"), false);
    // The first touch registers the sender (lazy entry creation).
    assert.equal(t.trackedSenders(), 1);
    assert.match(t.renderMetrics(), /relay_sender_reputation_score\{key="k1"\} 100/);
  });

  it("applies the default weighted penalties", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now });
    assert.equal(t.recordPenalty("k1", "verify_failure"), undefined);
    assert.equal(t.score("k1"), 75); // 100 - 25
    assert.equal(t.recordPenalty("k1", "rate_limit"), undefined);
    assert.equal(t.score("k1"), 70); // - 5
    assert.equal(t.recordPenalty("k1", "schema_violation"), undefined);
    assert.equal(t.score("k1"), 60); // - 10
    assert.equal(t.isDegraded("k1"), false);
  });

  it("honors custom weights", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({
      now: clock.now,
      verifyFailurePenalty: 50,
      rateLimitPenalty: 1,
    });
    t.recordPenalty("k1", "verify_failure");
    assert.equal(t.score("k1"), 50);
    t.recordPenalty("k1", "rate_limit");
    assert.equal(t.score("k1"), 49);
  });

  it("downgrades when the score falls strictly below lowThreshold, exactly once", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now }); // low 40
    t.recordPenalty("k1", "verify_failure"); // 75
    t.recordPenalty("k1", "verify_failure"); // 50
    const crossing = t.recordPenalty("k1", "verify_failure"); // 25 < 40
    assert.ok(crossing !== undefined);
    assert.equal(crossing.kind, "downgraded");
    assert.equal(crossing.key, "k1");
    assert.equal(crossing.score, 25);
    assert.equal(crossing.at, clock.now());
    assert.equal(t.isDegraded("k1"), true);
    // A further penalty while degraded emits no second transition.
    assert.equal(t.recordPenalty("k1", "verify_failure"), undefined);
    assert.equal(t.isDegraded("k1"), true);
  });

  it("does not downgrade at exactly lowThreshold (strictly below)", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({
      now: clock.now,
      lowThreshold: 50,
      verifyFailurePenalty: 25,
    });
    t.recordPenalty("k1", "verify_failure"); // 75
    assert.equal(t.recordPenalty("k1", "verify_failure"), undefined); // 50, not < 50
    assert.equal(t.isDegraded("k1"), false);
  });

  it("recovers by half-life decay and upgrades strictly above highThreshold", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now, halfLifeMs: 60_000 }); // high 70
    t.recordPenalty("k1", "verify_failure");
    t.recordPenalty("k1", "verify_failure");
    t.recordPenalty("k1", "verify_failure"); // score 25, degraded
    assert.equal(t.isDegraded("k1"), true);

    clock.advance(60_000); // one half-life: demerit 75 -> 37.5, score 62.5
    const mid = t.observe("k1");
    assert.equal(mid.score, 62.5);
    assert.equal(mid.degraded, true);
    assert.equal(mid.transition, undefined);

    clock.advance(60_000); // demerit 18.75, score 81.25 > 70
    const up = t.observe("k1");
    assert.equal(up.degraded, false);
    assert.ok(up.transition !== undefined);
    assert.equal(up.transition.kind, "upgraded");
    assert.equal(up.transition.score, 81.25);
    // The transition is reported exactly once.
    assert.equal(t.observe("k1").transition, undefined);
  });

  it("clamps a backward clock at zero: no phantom recovery or extra demerit", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now });
    t.recordPenalty("k1", "verify_failure");
    clock.set(0); // way back
    t.recordPenalty("k1", "rate_limit");
    assert.equal(t.score("k1"), 70); // 25 + 5, no decay distortion
  });

  it("floors the score at 0 under a penalty flood", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now });
    for (let i = 0; i < 20; i++) t.recordPenalty("k1", "verify_failure");
    assert.equal(t.score("k1"), 0);
    assert.equal(t.isDegraded("k1"), true);
  });

  it("keeps senders independent", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now });
    for (let i = 0; i < 3; i++) t.recordPenalty("bad", "verify_failure");
    assert.equal(t.isDegraded("bad"), true);
    assert.equal(t.isDegraded("good"), false);
    assert.equal(t.score("good"), 100);
  });
});

describe("takeTightenedBudget", () => {
  it("admits up to the per-second budget and refills lazily", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now });
    assert.equal(t.takeTightenedBudget("k1", 2), true);
    assert.equal(t.takeTightenedBudget("k1", 2), true);
    assert.equal(t.takeTightenedBudget("k1", 2), false);
    clock.advance(500); // 1 token back at 2/s
    assert.equal(t.takeTightenedBudget("k1", 2), true);
    assert.equal(t.takeTightenedBudget("k1", 2), false);
  });

  it("never grants extra budget on a backward clock", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now });
    t.takeTightenedBudget("k1", 1);
    assert.equal(t.takeTightenedBudget("k1", 1), false);
    clock.set(0);
    assert.equal(t.takeTightenedBudget("k1", 1), false);
  });
});

describe("renderSenderReputationBlock", () => {
  it("renders nothing for an empty series", () => {
    assert.equal(renderSenderReputationBlock([]), "");
  });

  it("renders the score gauge and the downgrade counter only for downgraded senders", () => {
    const out = renderSenderReputationBlock([
      { key: "k1", score: 25, degraded: true, downgrades: 2 },
      { key: "k2", score: 100, degraded: false, downgrades: 0 },
    ]);
    assert.match(out, /relay_sender_reputation_score\{key="k1"\} 25/);
    assert.match(out, /relay_sender_reputation_score\{key="k2"\} 100/);
    assert.match(out, /relay_sender_reputation_degraded_total\{key="k1"\} 2/);
    assert.ok(!out.includes('relay_sender_reputation_degraded_total{key="k2"}'));
  });

  it("escapes label values", () => {
    const out = renderSenderReputationBlock([
      { key: 'a"b\\c\nd', score: 50, degraded: false, downgrades: 0 },
    ]);
    assert.match(out, /key="a\\"b\\\\c\\nd"/);
  });

  it("tracker renderMetrics is activity-gated", () => {
    const clock = makeClock();
    const t = new SenderReputationTracker({ now: clock.now });
    assert.equal(t.renderMetrics(), "");
    t.recordPenalty("k1", "rate_limit");
    const out = t.renderMetrics();
    assert.match(out, /relay_sender_reputation_score\{key="k1"\} 95/);
    // No downgrade yet: no counter series.
    assert.ok(!out.includes("relay_sender_reputation_degraded_total"));
  });
});

describe("server intake wiring", () => {
  let dir: string;
  let stub: Server;
  let stubPort: number;
  const closers: Array<() => Promise<void>> = [];

  const track = <T extends { close(cb?: () => void): unknown }>(s: T): T => {
    closers.push(
      () =>
        new Promise<void>((resolve) => {
          s.close(() => resolve());
        })
    );
    return s;
  };

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "reputation-"));
    stub = track(
      createServer((_req, res) => {
        res.writeHead(200, { "content-type": "application/json" }).end("{}");
      })
    );
    await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
    const addr = stub.address();
    assert.ok(addr && typeof addr === "object");
    stubPort = addr.port;
  });

  after(async () => {
    for (const close of closers.splice(0).reverse()) await close();
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const audit = new AuditLog(join(dir, `audit-${Math.random().toString(36).slice(2)}.jsonl`));
    const relay = track(
      createRelayServer({
        secret: relaySecret,
        forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
        auditLog: audit,
        retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
        ...extra,
      })
    );
    return { relay, audit };
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function post(
    port: number,
    path: string,
    headers: Record<string, string> = {},
    body: Buffer = probeBody
  ) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "POST", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            r.destroy();
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
          });
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  function get(port: number, path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "GET", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            r.destroy();
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
          });
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("is off by default: no reputation audit events, no new metric series", async () => {
    const { relay, audit } = makeRelay({ rateLimit: { perIpPerSecond: 2 } });
    const port = await listen(relay);
    // Two 429s would downgrade under the test weights — with the feature
    // off nothing is recorded.
    await post(port, "/", { "x-signature": signSha256(probeBody, relaySecret) });
    await post(port, "/", { "x-signature": signSha256(probeBody, relaySecret) });
    await post(port, "/", { "x-signature": signSha256(probeBody, relaySecret) });
    assert.equal(eventsOf(audit, "reputation_downgraded").length, 0);
    assert.equal(eventsOf(audit, "reputation_upgraded").length, 0);
  });

  it("downgrades an anonymous sender after repeated rate-limit hits and audits the crossing", async () => {
    const { relay, audit } = makeRelay({
      rateLimit: { perIpPerSecond: 2 },
      senderReputation: { rateLimitPenalty: 35, lowThreshold: 40, highThreshold: 70 },
    });
    const port = await listen(relay);
    const sig = { "x-signature": signSha256(probeBody, relaySecret) };
    // 2/s budget: the 3rd and 4th rapid requests hit the limiter.
    // Penalties: 35 + 35 -> score 30 < 40 on the second hit.
    const r1 = await post(port, "/", sig);
    const r2 = await post(port, "/", sig);
    const r3 = await post(port, "/", sig);
    const r4 = await post(port, "/", sig);
    assert.equal(r1.status, 202);
    assert.equal(r2.status, 202);
    assert.equal(r3.status, 429);
    assert.equal(r4.status, 429);
    const downgraded = eventsOf(audit, "reputation_downgraded");
    assert.equal(downgraded.length, 1);
    assert.equal(downgraded[0].keyId, "anonymous");
    assert.equal(downgraded[0].score, 30);
    // No audit event leaks the secret: the downgraded event serializes
    // without the relay secret anywhere in it.
    assert.ok(!JSON.stringify(downgraded[0]).includes(relaySecret));
  });

  it("exposes the score gauge and downgrade counter on the operator /metrics", async () => {
    const opToken = "metrics-op-token";
    const { relay } = makeRelay({
      operatorToken: opToken,
      rateLimit: { perIpPerSecond: 2 },
      senderReputation: { rateLimitPenalty: 35, lowThreshold: 40, highThreshold: 70 },
    });
    const port = await listen(relay);
    const sig = { "x-signature": signSha256(probeBody, relaySecret) };
    await post(port, "/", sig);
    await post(port, "/", sig);
    await post(port, "/", sig); // 429 -> one penalty, no downgrade yet
    const res = await get(port, "/metrics", { authorization: `Bearer ${opToken}` });
    assert.equal(res.status, 200);
    assert.match(res.text, /relay_sender_reputation_score\{key="anonymous"\} 65/);
    assert.ok(!res.text.includes("relay_sender_reputation_degraded_total"));
  });

  it("forces signature verification for a degraded API-key sender", async () => {
    const { relay, audit } = makeRelay({
      rateLimit: { perIpPerSecond: 4 },
      apiKeys: { rules: [{ pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }] }] },
      // Two rate-limit hits downgrade k1 (70 -> 30).
      senderReputation: { rateLimitPenalty: 35, lowThreshold: 40, highThreshold: 70 },
    });
    const port = await listen(relay);
    const keyed = (extra: Record<string, string> = {}) => ({
      "x-api-key": keyA,
      "x-signature": signSha256(probeBody, relaySecret),
      ...extra,
    });
    // 4/s budget: requests 5..8 hit the limiter. The api-key gate runs
    // before the limiter, so the penalties land on key id "k1".
    for (let i = 0; i < 4; i++) assert.equal((await post(port, "/hooks/keyed", keyed())).status, 202);
    for (let i = 0; i < 4; i++) assert.equal((await post(port, "/hooks/keyed", keyed())).status, 429);
    const downgraded = eventsOf(audit, "reputation_downgraded");
    assert.equal(downgraded.length, 1);
    assert.equal(downgraded[0].keyId, "k1");

    // The main limiter refills 4/s; wait for enough tokens that both the
    // forced-verify probe and the signed control request reach admission.
    await new Promise((r) => setTimeout(r, 800));
    // Healthy behavior for this rule (requireSignature unset): the API
    // key alone authenticates, no signature needed -> would be 202. The
    // degraded sender is forced through verification -> 401.
    const forced = await post(port, "/hooks/keyed", { "x-api-key": keyA });
    assert.equal(forced.status, 401);
    const sigRejected = eventsOf(audit, "rejected").filter((e) => e.reason === "invalid_signature");
    assert.ok(sigRejected.length >= 1);
    assert.equal(sigRejected[sigRejected.length - 1].keyId, "k1");
    // And a properly signed request still passes while degraded.
    const ok = await post(port, "/hooks/keyed", keyed());
    assert.equal(ok.status, 202);
  });

  it("records schema violations as penalties and downgrades on them", async () => {
    const { relay, audit } = makeRelay({
      payloadSchemas: [
        {
          pattern: "/hooks/typed",
          schema: {
            name: "typed-event",
            version: "1",
            validate: (payload: unknown) => {
              const p = payload as { kind?: unknown };
              return typeof p?.kind === "string"
                ? { ok: true }
                : { ok: false, errors: ["missing kind"] };
            },
          },
        },
      ],
      senderReputation: { schemaViolationPenalty: 35, lowThreshold: 40, highThreshold: 70 },
    });
    const port = await listen(relay);
    const sig = { "x-signature": signSha256(probeBody, relaySecret) };
    // probeBody has no `kind` -> schema_failed, twice -> 30 < 40.
    assert.equal((await post(port, "/hooks/typed", sig, probeBody)).status, 400);
    assert.equal((await post(port, "/hooks/typed", sig, probeBody)).status, 400);
    const downgraded = eventsOf(audit, "reputation_downgraded");
    assert.equal(downgraded.length, 1);
    assert.equal(downgraded[0].keyId, "anonymous");
  });

  it("rejects invalid senderReputation config at startup", () => {
    assert.throws(
      () =>
        createRelayServer({
          secret: relaySecret,
          forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
          auditLog: new AuditLog(join(dir, "audit-startup.jsonl")),
          senderReputation: { lowThreshold: 80, highThreshold: 70 },
        }),
      RangeError
    );
  });
});
