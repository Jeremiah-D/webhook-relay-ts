import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type DownstreamResponse, type RetryItem, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "coalesce-enable-test-key";
const opToken = "coalesce-enable-op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt-1" }));
const BODY2 = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt-2" }));
const TARGET = "https://downstream.example.test/hook";
const SHADOW = "https://shadow.example.test/hook";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (cond()) return;
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await sleep(5);
  }
}

function item(id: string, body: Buffer = BODY, overrides: Partial<RetryItem> = {}): RetryItem {
  return { id, payload: body, targetUrl: TARGET, headers: {}, ...overrides };
}

const okResponse: DownstreamResponse = { statusCode: 200, body: Buffer.from("ok") };

/** A sender that holds every physical attempt open until released; re-armable per batch. */
function gatedSender() {
  let calls = 0;
  let gate: Promise<DownstreamResponse> = Promise.resolve(okResponse);
  let release!: (v: DownstreamResponse) => void;
  const arm = (): void => {
    gate = new Promise<DownstreamResponse>((r) => { release = r; });
  };
  arm();
  const inner: Sender = async () => {
    calls++;
    return gate;
  };
  return { inner, calls: () => calls, release: () => release(okResponse), arm };
}

describe("coalesce enable: RetryQueue live-enable (WR-475)", () => {
  it("enable from unconfigured, then a follower merges into the same attempt", async () => {
    const { inner, calls, release } = gatedSender();
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      onDelivered: () => { delivered++; },
    });
    q.start();
    try {
      assert.equal(q.getMaxFollowers(), undefined);
      assert.equal(q.getCoalesceStats(), undefined);
      assert.equal(q.reviseMaxFollowers(2), 2);
      assert.equal(q.getMaxFollowers(), 2);
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      q.enqueue(item("c"));
      await waitFor(() => calls() === 1);
      await sleep(30); // let the followers attach while the attempt is in flight
      release();
      await waitFor(() => delivered === 3);
      assert.equal(calls(), 1);
      assert.equal(q.getCoalesceStats()?.physicalAttempts, 1);
      assert.equal(q.getCoalesceStats()?.mergedDeliveries, 2);
    } finally {
      q.stop();
    }
  });

  it("illegal value throws RangeError, stays unconfigured, and is still enable-able afterwards", () => {
    const q = new RetryQueue({ sender: async () => okResponse });
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      assert.throws(() => q.reviseMaxFollowers(bad), RangeError);
      assert.equal(q.getMaxFollowers(), undefined);
      assert.equal(q.getCoalesceStats(), undefined);
    }
    assert.equal(q.reviseMaxFollowers(2), 2);
    assert.equal(q.getMaxFollowers(), 2);
  });

  it("deliveries already underway are NOT retroactively merged", async () => {
    const { inner, calls, release, arm } = gatedSender();
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      onDelivered: () => { delivered++; },
    });
    q.start();
    try {
      // "a" starts its physical attempt before coalescing exists.
      q.enqueue(item("a"));
      await waitFor(() => calls() === 1);
      // Enable mid-flight: the fresh coalescer has no history keys, so
      // it cannot know "a" is in flight.
      assert.equal(q.reviseMaxFollowers(2), 2);
      q.enqueue(item("b"));
      await waitFor(() => calls() === 2);
      release();
      await waitFor(() => delivered === 2);
      assert.equal(calls(), 2);
      assert.equal(q.getCoalesceStats()?.physicalAttempts, 1);
      assert.equal(q.getCoalesceStats()?.mergedDeliveries, 0);
      // But the very next pair merges, now that the coalescer exists.
      arm();
      q.enqueue(item("c", BODY2));
      q.enqueue(item("d", BODY2));
      await waitFor(() => calls() === 3);
      await sleep(30);
      release();
      await waitFor(() => delivered === 4);
      assert.equal(calls(), 3);
      assert.equal(q.getCoalesceStats()?.physicalAttempts, 2);
      assert.equal(q.getCoalesceStats()?.mergedDeliveries, 1);
    } finally {
      q.stop();
    }
  });

  it("coalesce:false is the same as unconfigured — enabling turns it on", async () => {
    const { inner, calls, release } = gatedSender();
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      coalesce: false,
      onDelivered: () => { delivered++; },
    });
    q.start();
    try {
      assert.equal(q.getMaxFollowers(), undefined);
      assert.equal(q.reviseMaxFollowers(1), 1);
      assert.equal(q.getMaxFollowers(), 1);
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      await waitFor(() => calls() === 1);
      await sleep(30);
      release();
      await waitFor(() => delivered === 2);
      assert.equal(calls(), 1);
      assert.equal(q.getCoalesceStats()?.mergedDeliveries, 1);
    } finally {
      q.stop();
    }
  });

  it("shadow mirrors share the enabled bound with the main path", async () => {
    const callsByTarget = new Map<string, number>();
    const inner: Sender = async (it) => {
      callsByTarget.set(it.targetUrl, (callsByTarget.get(it.targetUrl) ?? 0) + 1);
      await sleep(30);
      return okResponse;
    };
    let delivered = 0;
    let shadowDelivered = 0;
    const q = new RetryQueue({
      sender: inner,
      // No coalesce at construction, no dedicated sender for the shadow
      // target: the mirror goes through the queue's main sender.
      shadowTargets: { [TARGET]: [{ targetUrl: SHADOW }] },
      onDelivered: () => { delivered++; },
      onShadowDelivered: () => { shadowDelivered++; },
    });
    q.start();
    try {
      // Unconfigured: every delivery is its own physical attempt on
      // both paths.
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      q.enqueue(item("c"));
      await waitFor(() => shadowDelivered === 3);
      await waitFor(() => delivered === 3);
      assert.equal(callsByTarget.get(TARGET), 3);
      assert.equal(callsByTarget.get(SHADOW), 3);
      // Enable: the next batch of three identical deliveries merges on
      // both the main path and the shadow mirror alike — the mirrors
      // go through the same re-wrapped sender.
      q.reviseMaxFollowers(3);
      q.enqueue(item("d", BODY2));
      q.enqueue(item("e", BODY2));
      q.enqueue(item("f", BODY2));
      await waitFor(() => shadowDelivered === 6);
      await waitFor(() => delivered === 6);
      assert.equal(callsByTarget.get(TARGET), 4);
      assert.equal(callsByTarget.get(SHADOW), 4);
    } finally {
      q.stop();
    }
  });
});

describe("coalesce enable: RelayServer (WR-475)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function listen(server: Server): Promise<number> {
    return new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
  }

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "coalesce-enable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: TARGET,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("server enable audits max_followers_revised with previous:null and mounts the getter", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getMaxFollowers, undefined);
    assert.equal(relay.reviseMaxFollowers!(2), 2);
    assert.equal(relay.getMaxFollowers!(), 2);
    const revised = eventsOf(audit, "max_followers_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.equal(revised[0].current, 2);
    // A real revision after the enable audits the enabled value as previous.
    assert.equal(relay.reviseMaxFollowers!(5), 5);
    const revised2 = eventsOf(audit, "max_followers_revised");
    assert.equal(revised2.length, 2);
    assert.equal(revised2[1].previous, 2);
    assert.equal(revised2[1].current, 5);
  });

  it("same-value revision after the enable is a silent no-op", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    relay.reviseMaxFollowers!(3);
    assert.equal(eventsOf(audit, "max_followers_revised").length, 1);
    relay.reviseMaxFollowers!(3);
    assert.equal(eventsOf(audit, "max_followers_revised").length, 1);
    assert.equal(relay.getMaxFollowers!(), 3);
  });

  it("illegal server enable throws RangeError and leaves the relay unconfigured", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.throws(() => relay.reviseMaxFollowers!(0), RangeError);
    assert.equal(relay.getMaxFollowers, undefined);
    assert.equal(eventsOf(audit, "max_followers_revised").length, 0);
    // Still enable-able afterwards.
    assert.equal(relay.reviseMaxFollowers!(2), 2);
    assert.equal(relay.getMaxFollowers!(), 2);
    assert.equal(eventsOf(audit, "max_followers_revised").length, 1);
  });

  it("restart restores the unconfigured construction state", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.reviseMaxFollowers!(2), 2);
    assert.equal(eventsOf(audit, "max_followers_revised").length, 1);
    // A fresh relay built from the same options is unconfigured again:
    // the enable was live-only, with no persistence.
    const { relay: fresh } = makeRelay();
    await listen(fresh);
    assert.equal(fresh.getMaxFollowers, undefined);
    assert.equal(fresh.reviseMaxFollowers!(4), 4);
    assert.equal(fresh.getMaxFollowers!(), 4);
  });
});
