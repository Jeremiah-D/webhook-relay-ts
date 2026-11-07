import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OutboundCoalescer } from "../src/coalesce.ts";
import { RetryQueue, type DownstreamResponse, type RetryItem, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "coalesce-revision-test-key";
const opToken = "coalesce-revision-op-token";
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

describe("coalesce revision: OutboundCoalescer live maxFollowers (WR-348)", () => {
  it("tightening the bound spills overflow onto its own physical attempt", async () => {
    const { inner, calls, release } = gatedSender();
    const coalescer = new OutboundCoalescer({ maxFollowers: 2 });
    const sender = coalescer.wrap(inner);
    const results = Promise.all([
      sender(item("a")),
      sender(item("b")),
      sender(item("c")),
      sender(item("d")),
    ]);
    await waitFor(() => calls() === 2);
    await sleep(20); // let the followers attach while the attempts are in flight
    release();
    const settled = await results;
    assert.equal(calls(), 2);
    assert.deepEqual(settled, [okResponse, okResponse, okResponse, okResponse]);
    assert.equal(coalescer.getStats().physicalAttempts, 2);
    assert.equal(coalescer.getStats().mergedDeliveries, 2);
  });

  it("loosening the bound merges more followers into the same attempt", async () => {
    let calls = 0;
    const inner: Sender = async () => {
      calls++;
      await sleep(30);
      return okResponse;
    };
    const coalescer = new OutboundCoalescer({ maxFollowers: 1 });
    const sender = coalescer.wrap(inner);
    // maxFollowers 1 still admits one follower: two deliveries share.
    await Promise.all([sender(item("a")), sender(item("b"))]);
    assert.equal(calls, 1);
    assert.equal(coalescer.getStats().physicalAttempts, 1);
    assert.equal(coalescer.getStats().mergedDeliveries, 1);
    coalescer.retuneMaxFollowers(3);
    await Promise.all([sender(item("c")), sender(item("d")), sender(item("e"))]);
    assert.equal(calls, 2);
    assert.equal(coalescer.getStats().physicalAttempts, 2);
    assert.equal(coalescer.getStats().mergedDeliveries, 3);
  });

  it("tightening to 1 makes the third delivery its own attempt", async () => {
    let calls = 0;
    const inner: Sender = async () => {
      calls++;
      await sleep(30);
      return okResponse;
    };
    const coalescer = new OutboundCoalescer({ maxFollowers: 5 });
    const sender = coalescer.wrap(inner);
    coalescer.retuneMaxFollowers(1);
    await Promise.all([sender(item("a")), sender(item("b")), sender(item("c"))]);
    assert.equal(calls, 2);
    assert.equal(coalescer.getStats().physicalAttempts, 2);
    assert.equal(coalescer.getStats().mergedDeliveries, 1);
  });

  it("illegal values throw RangeError and leave the live value intact", () => {
    const coalescer = new OutboundCoalescer({ maxFollowers: 2 });
    for (const bad of [0, -1, 1.5, Number.NaN, "3" as never, undefined as never]) {
      assert.throws(() => coalescer.retuneMaxFollowers(bad), RangeError);
    }
    assert.equal(coalescer.currentMaxFollowers(), 2);
    // The default is unbounded.
    assert.equal(new OutboundCoalescer().currentMaxFollowers(), Infinity);
  });

  it("retune returns the live bound and currentMaxFollowers follows revisions", () => {
    const coalescer = new OutboundCoalescer({ maxFollowers: 2 });
    assert.equal(coalescer.retuneMaxFollowers(4), 4);
    assert.equal(coalescer.currentMaxFollowers(), 4);
    // Same-value retune returns the same value.
    assert.equal(coalescer.retuneMaxFollowers(4), 4);
    assert.equal(coalescer.currentMaxFollowers(), 4);
    assert.equal(coalescer.retuneMaxFollowers(Infinity), Infinity);
    assert.equal(coalescer.currentMaxFollowers(), Infinity);
  });

  it("revision does not reset the physical/merged counters", async () => {
    let calls = 0;
    const inner: Sender = async () => {
      calls++;
      await sleep(20);
      return okResponse;
    };
    const coalescer = new OutboundCoalescer({ maxFollowers: 5 });
    const sender = coalescer.wrap(inner);
    await Promise.all([sender(item("a")), sender(item("b"))]);
    assert.deepEqual(
      [coalescer.getStats().physicalAttempts, coalescer.getStats().mergedDeliveries],
      [1, 1]
    );
    coalescer.retuneMaxFollowers(1);
    await Promise.all([sender(item("c")), sender(item("d")), sender(item("e"))]);
    assert.equal(calls, 3);
    assert.deepEqual(
      [coalescer.getStats().physicalAttempts, coalescer.getStats().mergedDeliveries],
      [3, 2]
    );
  });

  it("in-flight entries are unaffected: attached followers stay on the shared attempt", async () => {
    const { inner, calls, release } = gatedSender();
    const coalescer = new OutboundCoalescer({ maxFollowers: 5 });
    const sender = coalescer.wrap(inner);
    const a = item("a");
    const b = item("b");
    const pa = sender(a);
    const pb = sender(b);
    await waitFor(() => calls() === 1);
    await sleep(20); // let b attach while the attempt is in flight
    coalescer.retuneMaxFollowers(1);
    // A newcomer arriving after the tightening starts its own attempt —
    // but the already-attached follower is never evicted.
    const pc = sender(item("c"));
    await waitFor(() => calls() === 2);
    release();
    const [ra, rb, rc] = await Promise.all([pa, pb, pc]);
    assert.equal(ra, okResponse);
    assert.equal(rb, okResponse);
    assert.equal(rc, okResponse);
    assert.equal(coalescer.wasLeader(a), true);
    assert.equal(coalescer.wasLeader(b), false);
    assert.equal(coalescer.getStats().physicalAttempts, 2);
    assert.equal(coalescer.getStats().mergedDeliveries, 1);
  });
});

describe("coalesce revision: RetryQueue (WR-348)", () => {
  it("unconfigured queue: revise throws the must-restart Error and the getter is undefined", () => {
    const q = new RetryQueue({ sender: async () => okResponse });
    assert.equal(q.getMaxFollowers(), undefined);
    assert.throws(
      () => q.reviseMaxFollowers(2),
      /reviseMaxFollowers: request coalescing is not configured — enabling it requires a restart/
    );
    assert.equal(q.getMaxFollowers(), undefined);
  });

  it("queue revision governs the next join; the getter follows the live value", async () => {
    const { inner, calls, release, arm } = gatedSender();
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      coalesce: { maxFollowers: 1 },
      onDelivered: () => { delivered++; },
    });
    q.start();
    try {
      assert.equal(q.getMaxFollowers(), 1);
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      await waitFor(() => calls() === 1);
      await sleep(30); // let the second delivery attach while the attempt is in flight
      release();
      await waitFor(() => delivered === 2);
      assert.equal(q.reviseMaxFollowers(3), 3);
      assert.equal(q.getMaxFollowers(), 3);
      arm();
      q.enqueue(item("c", BODY2));
      q.enqueue(item("d", BODY2));
      q.enqueue(item("e", BODY2));
      await waitFor(() => calls() === 2);
      await sleep(30); // let the followers attach while the attempt is in flight
      release();
      await waitFor(() => delivered === 5);
      assert.equal(calls(), 2);
      assert.equal(q.getCoalesceStats()?.physicalAttempts, 2);
      assert.equal(q.getCoalesceStats()?.mergedDeliveries, 3);
    } finally {
      q.stop();
    }
  });

  it("shadow mirrors share the revised bound with the main path", async () => {
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
      coalesce: { maxFollowers: 3 },
      // No dedicated sender for the shadow target: the mirror goes
      // through the queue's main (coalescer-wrapped) sender.
      shadowTargets: { [TARGET]: [{ targetUrl: SHADOW }] },
      onDelivered: () => { delivered++; },
      onShadowDelivered: () => { shadowDelivered++; },
    });
    q.start();
    try {
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      q.enqueue(item("c"));
      await waitFor(() => shadowDelivered === 3);
      assert.equal(callsByTarget.get(TARGET), 1);
      assert.equal(callsByTarget.get(SHADOW), 1);
      // Tighten: the next batch of three identical deliveries must spill
      // on both the main path and the shadow mirror alike.
      q.reviseMaxFollowers(1);
      q.enqueue(item("d", BODY2));
      q.enqueue(item("e", BODY2));
      q.enqueue(item("f", BODY2));
      await waitFor(() => shadowDelivered === 6);
      await waitFor(() => delivered === 6);
      assert.equal(callsByTarget.get(TARGET), 3);
      assert.equal(callsByTarget.get(SHADOW), 3);
    } finally {
      q.stop();
    }
  });
});

describe("coalesce revision: RelayServer (WR-348)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "coalesce-revision-"));
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

  it("revision audits previous/current with the construction value first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { coalesce: { maxFollowers: 2 } },
    });
    await listen(relay);
    assert.equal(relay.getMaxFollowers!(), 2);
    assert.equal(relay.reviseMaxFollowers!(4), 4);
    const revised = eventsOf(audit, "max_followers_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, 2);
    assert.equal(revised[0].current, 4);
    // Landing exactly on the live value audits nothing.
    relay.reviseMaxFollowers!(4);
    assert.equal(eventsOf(audit, "max_followers_revised").length, 1);
    assert.equal(relay.getMaxFollowers!(), 4);
    // An illegal value throws and leaves the live value and audit untouched.
    assert.throws(() => relay.reviseMaxFollowers!(0), RangeError);
    assert.throws(() => relay.reviseMaxFollowers!(Number.NaN), RangeError);
    assert.equal(eventsOf(audit, "max_followers_revised").length, 1);
    assert.equal(relay.getMaxFollowers!(), 4);
  });

  it("default construction: first previous is the unbounded default and the getter starts at Infinity", async () => {
    const { relay, audit } = makeRelay({
      retry: { coalesce: true },
    });
    await listen(relay);
    assert.equal(relay.getMaxFollowers!(), Infinity);
    assert.equal(relay.reviseMaxFollowers!(5), 5);
    const revised = eventsOf(audit, "max_followers_revised");
    assert.equal(revised.length, 1);
    // JSON has no Infinity: the audit log stores the unbounded default
    // as null. The live value itself is still Infinity until revised.
    assert.equal(revised[0].previous, null);
    assert.equal(revised[0].current, 5);
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getMaxFollowers, undefined);
    assert.throws(
      () => relay.reviseMaxFollowers!(2),
      /not configured — enabling it requires a restart/
    );
  });
});
