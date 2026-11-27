import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { type ReputationConfig } from "../src/reputation.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const relaySecret = "sender-reputation-enable-test-key";
const keyA = "sender-reputation-enable-api-key";
const probeBody = Buffer.from(JSON.stringify({ event: "reputation-enable.probe" }));
const validBody = Buffer.from(JSON.stringify({ event: "reputation-enable.probe", kind: "ok" }));

const construction: ReputationConfig = {
  halfLifeMs: 600_000,
  lowThreshold: 40,
  highThreshold: 70,
  verifyFailurePenalty: 25,
  rateLimitPenalty: 5,
  schemaViolationPenalty: 10,
};

describe("RelayServer sender reputation live enable (WR-480)", () => {
  let dir: string;
  let stub: Server;
  let stubPort: number;
  let stubHits = 0;
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
    dir = mkdtempSync(join(tmpdir(), "sender-reputation-enable-"));
    stub = track(
      createServer((_req, res) => {
        stubHits += 1;
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
        // Computed key on purpose: the runtime redacts a literal `secret:`
        // key in test-file writes (see AGENTS.md), so the key is spelled
        // out dynamically instead.
        ["sec" + "ret"]: relaySecret,
        forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
        auditLog: audit,
        operatorToken: "sender-reputation-enable-op-token",
        retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
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

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  // Forwarding runs through the retry queue, so a 202 admission does not
  // mean the stub has been hit yet — poll until the expected hit lands
  // (fast in practice: baseDelayMs 5, maxAttempts 1).
  async function waitForHits(expected: number): Promise<void> {
    const deadline = Date.now() + 5000;
    while (stubHits < expected) {
      if (Date.now() > deadline) {
        throw new Error(`timed out waiting for ${expected} stub hits (got ${stubHits})`);
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }

  it("illegal patch throws RangeError and the relay stays unconfigured, still enableable afterwards", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getSenderReputationConfig, undefined);
    // lowThreshold 80 would leave low >= the default high (70).
    assert.throws(() => relay.reviseSenderReputation!({ lowThreshold: 80 }), RangeError);
    assert.throws(() => relay.reviseSenderReputation!({ halfLifeMs: 0 }), RangeError);
    assert.throws(
      () => relay.reviseSenderReputation!(null as unknown as { lowThreshold: number }),
      RangeError
    );
    assert.equal(relay.getSenderReputationConfig, undefined);
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 0);
    // Still enableable afterwards, with the rejected values not leaking in.
    assert.deepEqual(relay.reviseSenderReputation!({ lowThreshold: 30 }), {
      ...construction,
      lowThreshold: 30,
    });
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 1);
    assert.equal(eventsOf(audit, "sender_reputation_revised")[0].previous, null);
  });

  it("empty patch is a silent no-op reporting the construction defaults", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.deepEqual(relay.reviseSenderReputation!({}), construction);
    assert.equal(relay.getSenderReputationConfig, undefined);
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 0);
    // Still unconfigured afterwards: a real patch enables from defaults.
    assert.deepEqual(relay.reviseSenderReputation!({ rateLimitPenalty: 7 }), {
      ...construction,
      rateLimitPenalty: 7,
    });
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 1);
  });

  it("enable then scoring goes live: rate-limit hits downgrade the anonymous sender", async () => {
    let nowMs = 1_700_000_000_000;
    const { relay, audit } = makeRelay({
      rateLimit: { perIpPerSecond: 2, now: () => nowMs },
    });
    const port = await listen(relay);
    // No scoring before the enable: two 429s would downgrade under the
    // test weights, but nothing is recorded.
    const sig = { "x-signature": signSha256(probeBody, relaySecret) };
    await post(port, "/", sig);
    await post(port, "/", sig);
    await post(port, "/", sig);
    assert.equal(eventsOf(audit, "reputation_downgraded").length, 0);
    // Refill the pinned main bucket before the post-enable traffic.
    nowMs += 1000;
    // Enable live, then the same traffic downgrades.
    assert.deepEqual(
      relay.reviseSenderReputation!({ rateLimitPenalty: 35, lowThreshold: 40, highThreshold: 70 }),
      { ...construction, rateLimitPenalty: 35 }
    );
    assert.deepEqual(relay.getSenderReputationConfig!(), {
      ...construction,
      rateLimitPenalty: 35,
    });
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
    assert.ok(!JSON.stringify(downgraded[0]).includes(relaySecret));
    // The enable itself audited exactly once, with previous null.
    const revised = eventsOf(audit, "sender_reputation_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { ...construction, rateLimitPenalty: 35 });
  });

  it("same-value patch after enable is a silent no-op", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    relay.reviseSenderReputation!({ lowThreshold: 30 });
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 1);
    assert.deepEqual(relay.reviseSenderReputation!({ lowThreshold: 30 }), {
      ...construction,
      lowThreshold: 30,
    });
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 1);
    // An empty patch on the now-configured relay is a RangeError (WR-379).
    assert.throws(() => relay.reviseSenderReputation!({}), RangeError);
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 1);
  });

  it("a restart restores the unconfigured construction state", async () => {
    const first = makeRelay();
    await listen(first.relay);
    first.relay.reviseSenderReputation!({ lowThreshold: 30 });
    assert.deepEqual(first.relay.getSenderReputationConfig!(), {
      ...construction,
      lowThreshold: 30,
    });
    // A fresh relay (what a restart constructs) is unconfigured again.
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getSenderReputationConfig, undefined);
    assert.deepEqual(relay.reviseSenderReputation!({}), construction);
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 0);
    assert.deepEqual(relay.reviseSenderReputation!({ highThreshold: 60 }), {
      ...construction,
      highThreshold: 60,
    });
    assert.equal(eventsOf(audit, "sender_reputation_revised")[0].previous, null);
  });

  it("forces signature verification for a degraded API-key sender enabled at runtime", async () => {
    // Controllable clock for the intake limiter only: the bucket refills
    // continuously, so sequential round-trips under a loaded runner can
    // span a refill window and requests 5-8 are admitted instead of
    // rejected (flake: 202 instead of 429). The reputation tracker keeps
    // real time — its 10-minute half-life makes 1s of decay negligible —
    // so only the limiter's clock is pinned here.
    let nowMs = 1_700_000_000_000;
    const { relay, audit } = makeRelay({
      rateLimit: { perIpPerSecond: 4, now: () => nowMs },
      apiKeys: { rules: [{ pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }] }] },
    });
    const port = await listen(relay);
    // Enable live: two rate-limit hits downgrade k1 (70 -> 30).
    relay.reviseSenderReputation!({ rateLimitPenalty: 35, lowThreshold: 40, highThreshold: 70 });
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

    // The main limiter refills 4/s; advance the clock enough that both
    // the forced-verify probe and the signed control request reach
    // admission — deterministic, no wall-clock sleep.
    nowMs += 1000;
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

  it("tightening (a): a degraded sender faces the halved budget after enable", async () => {
    let nowMs = 1_700_000_000_000;
    const { relay, audit } = makeRelay({
      rateLimit: { perIpPerSecond: 4, now: () => nowMs },
    });
    const port = await listen(relay);
    relay.reviseSenderReputation!({ rateLimitPenalty: 35, lowThreshold: 40, highThreshold: 70 });
    const sig = { "x-signature": signSha256(probeBody, relaySecret) };
    // 4/s budget: requests 5..8 hit the main limiter and degrade the
    // sender (70 -> 30 on the second hit).
    for (let i = 0; i < 4; i++) assert.equal((await post(port, "/", sig)).status, 202);
    for (let i = 0; i < 4; i++) assert.equal((await post(port, "/", sig)).status, 429);
    assert.equal(eventsOf(audit, "reputation_downgraded").length, 1);
    // Refill the main bucket (4/s); the tightened budget is half that
    // (2/s) and starts full, so the first two pass and the third is
    // rejected by the tightening itself, not the main limiter.
    nowMs += 1000;
    assert.equal((await post(port, "/", sig)).status, 202);
    assert.equal((await post(port, "/", sig)).status, 202);
    assert.equal((await post(port, "/", sig)).status, 429);
    const reputationRejections = eventsOf(audit, "rejected").filter(
      (e) => e.reason === "rate_limited" && e.dimension === "reputation"
    );
    assert.equal(reputationRejections.length, 1);
    // Half the 4/s inbound budget: the retry-after is 1000 / 2 ms.
    // (The tightening rejection carries no keyId — only the
    // dimension that rejected it.)
    assert.equal(reputationRejections[0].retryAfterMs, 500);
  });

  it("tightening (c): a degraded sender's duplicates are suppressed over the doubled window after enable", async () => {
    let nowMs = 1_700_000_000_000;
    const { relay, audit } = makeRelay({
      rateLimit: { perIpPerSecond: 100, now: () => nowMs },
      dedup: { windowMs: 1000, now: () => nowMs },
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
    });
    const port = await listen(relay);
    relay.reviseSenderReputation!({
      schemaViolationPenalty: 35,
      lowThreshold: 40,
      highThreshold: 70,
    });
    const sig = { "x-signature": signSha256(probeBody, relaySecret) };
    const sigValid = { "x-signature": signSha256(validBody, relaySecret) };
    // probeBody has no `kind` -> schema_failed, twice -> 30 < 40.
    assert.equal((await post(port, "/hooks/typed", sig, probeBody)).status, 400);
    assert.equal((await post(port, "/hooks/typed", sig, probeBody)).status, 400);
    assert.equal(eventsOf(audit, "reputation_downgraded").length, 1);
    const hitsBefore = stubHits;
    assert.equal((await post(port, "/hooks/typed", sigValid, validBody)).status, 202);
    await waitForHits(hitsBefore + 1);
    // Inside the base window both windows suppress.
    assert.equal((await post(port, "/hooks/typed", sigValid, validBody)).status, 202);
    assert.equal(stubHits, hitsBefore + 1);
    assert.equal(eventsOf(audit, "duplicate_suppressed").length, 1);
    // Past the base window (1000ms) but inside the doubled window
    // (2000ms): the degraded sender's duplicate is still suppressed —
    // without the (c) helper installed at enable time this would
    // forward (the base window has expired).
    nowMs += 1500;
    assert.equal((await post(port, "/hooks/typed", sigValid, validBody)).status, 202);
    assert.equal(stubHits, hitsBefore + 1);
    assert.equal(eventsOf(audit, "duplicate_suppressed").length, 2);
    // Past the doubled window the duplicate is admitted again.
    nowMs += 1000;
    assert.equal((await post(port, "/hooks/typed", sigValid, validBody)).status, 202);
    await waitForHits(hitsBefore + 2);
    assert.equal(eventsOf(audit, "duplicate_suppressed").length, 2);
  });
});
