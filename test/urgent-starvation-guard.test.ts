import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { connect as tcpConnect, type Socket } from "node:net";
import {
  RetryQueue,
  type RetryItem,
  type Sender,
  type UrgentDowngradedEvent,
} from "../src/retry.ts";
import { createDefaultSender, type PooledSender } from "../src/server.ts";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return { clear: () => { const i = pending.indexOf(fn); if (i >= 0) pending.splice(i, 1); } };
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

/** Let queued microtask chains (admission -> turn grant -> sender) settle. */
async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

const URL = "http://localhost:9999/wr121";

function item(id: string, priority?: "urgent"): RetryItem {
  return {
    id,
    payload: Buffer.from(id),
    targetUrl: URL,
    headers: {},
    ...(priority !== undefined ? { priority } : {}),
  };
}

describe("urgent starvation guard config (WR-121)", () => {
  it("rejects invalid maxConsecutiveUrgent at construction (RangeError fail-fast)", () => {
    for (const v of [0, -1, 1.5, NaN, Infinity, -Infinity]) {
      assert.throws(
        () => new RetryQueue({ urgent: { maxConsecutiveUrgent: v } }),
        RangeError,
        `expected RangeError for ${String(v)}`
      );
    }
  });

  it("accepts boundary-valid values", () => {
    new RetryQueue({ urgent: { maxConsecutiveUrgent: 1 } });
    new RetryQueue({ urgent: { maxConsecutiveUrgent: 1000 } });
    new RetryQueue({}); // unset = disabled
  });

  it("is a complete no-op when disabled: urgent flood passes through untouched", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const audits: UrgentDowngradedEvent[] = [];
    const q = new RetryQueue({
      sender: async (it) => { seen.push(it.id); },
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0 },
      onUrgentDowngraded: (e) => audits.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 1; i <= 8; i++) q.enqueue(item(`u-${i}`, "urgent"));
    await timer.run();
    await settle();
    assert.deepEqual(seen, ["u-1", "u-2", "u-3", "u-4", "u-5", "u-6", "u-7", "u-8"]);
    assert.deepEqual(audits, []);
    const [s] = q.getUrgentStats();
    assert.equal(s.delivered, 8);
    assert.equal(s.downgraded, 0);
    assert.equal(s.throttled, 0);
  });
});

describe("consecutive-occupancy downgrade (WR-121)", () => {
  it("caps the urgent run: the (N+1)-th consecutive urgent is force-downgraded to normal", async () => {
    const timer = manualTimer();
    const priorities = new Map<string, string | undefined>();
    const audits: UrgentDowngradedEvent[] = [];
    const q = new RetryQueue({
      sender: async (it) => { priorities.set(it.id, it.priority); },
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 3 },
      onUrgentDowngraded: (e) => audits.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 1; i <= 6; i++) q.enqueue(item(`u-${i}`, "urgent"));
    await timer.run();
    await settle();
    assert.equal(q.pendingCount(), 0);
    // u-1..u-3 take the fast lane (streak 1,2,3); u-4 trips the guard and
    // rides the normal lane; the streak reset lets u-5, u-6 back on.
    assert.equal(priorities.get("u-1"), "urgent");
    assert.equal(priorities.get("u-2"), "urgent");
    assert.equal(priorities.get("u-3"), "urgent");
    assert.equal(priorities.get("u-4"), "normal");
    assert.equal(priorities.get("u-5"), "urgent");
    assert.equal(priorities.get("u-6"), "urgent");

    assert.equal(audits.length, 1);
    const [ev] = audits;
    assert.equal(ev.event, "urgent_downgraded");
    assert.equal(ev.endpoint, URL);
    assert.equal(ev.id, "u-4");
    assert.equal(typeof ev.traceId, "string");
    assert.ok(ev.traceId.length > 0);
    assert.equal(ev.consecutiveUrgent, 3);
    assert.equal(ev.maxConsecutiveUrgent, 3);

    const [s] = q.getUrgentStats();
    assert.equal(s.delivered, 5);
    assert.equal(s.downgraded, 1);
    assert.equal(s.throttled, 0);
  });

  it("maxConsecutiveUrgent 1 enforces strict alternation: normal keeps 1/2 of the slots", async () => {
    const timer = manualTimer();
    // Completion order across lanes is not deterministic; the guard
    // decision per item is — record it in a map, not an order.
    const priorities = new Map<string, string | undefined>();
    const q = new RetryQueue({
      sender: async (it) => { priorities.set(it.id, it.priority); },
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 1 },
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 1; i <= 4; i++) q.enqueue(item(`u-${i}`, "urgent"));
    await timer.run();
    await settle();
    assert.equal(q.pendingCount(), 0);
    assert.equal(priorities.size, 4);
    assert.equal(priorities.get("u-1"), "urgent");
    assert.equal(priorities.get("u-2"), "normal");
    assert.equal(priorities.get("u-3"), "urgent");
    assert.equal(priorities.get("u-4"), "normal");
    const [s] = q.getUrgentStats();
    assert.equal(s.delivered, 2);
    assert.equal(s.downgraded, 2);
  });

  it("a normal admission resets the streak: interleaved demand never trips the guard", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const audits: UrgentDowngradedEvent[] = [];
    const q = new RetryQueue({
      sender: async (it) => { seen.push(it.id); },
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
      onUrgentDowngraded: (e) => audits.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(item("u-1", "urgent"));
    q.enqueue(item("u-2", "urgent"));
    q.enqueue(item("n-1")); // normal admission resets the streak
    q.enqueue(item("u-3", "urgent"));
    await timer.run();
    await settle();
    assert.equal(q.pendingCount(), 0);
    assert.equal(seen.length, 4);
    assert.deepEqual(audits, []);
    const [s] = q.getUrgentStats();
    assert.equal(s.delivered, 3);
    assert.equal(s.downgraded, 0);
  });

  it("the streak is per endpoint: a flood on one endpoint never downgrades another", async () => {
    const timer = manualTimer();
    const priorities = new Map<string, string | undefined>();
    const other = "http://localhost:9998/other";
    const mk = (id: string, url: string): RetryItem => ({
      id,
      payload: Buffer.from(id),
      targetUrl: url,
      headers: {},
      priority: "urgent",
    });
    const q = new RetryQueue({
      sender: async (it) => { priorities.set(it.id, it.priority); },
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 1; i <= 3; i++) q.enqueue(mk(`a-${i}`, URL));
    for (let i = 1; i <= 2; i++) q.enqueue(mk(`b-${i}`, other));
    await timer.run();
    await settle();
    assert.equal(q.pendingCount(), 0);
    // Endpoint A: a-1, a-2 urgent, a-3 downgraded. Endpoint B untouched.
    assert.equal(priorities.get("a-3"), "normal");
    assert.equal(priorities.get("b-1"), "urgent");
    assert.equal(priorities.get("b-2"), "urgent");
    const byEndpoint = new Map(q.getUrgentStats().map((s) => [s.endpoint, s]));
    assert.equal(byEndpoint.get(URL)?.downgraded, 1);
    assert.equal(byEndpoint.get(other)?.downgraded, 0);
  });
});

describe("composes with WR-12 empty-bucket downgrade", () => {
  it("guard never double-downgrades: empty bucket degrades via throttled, not downgraded", async () => {
    const timer = manualTimer();
    const priorities = new Map<string, string | undefined>();
    const audits: UrgentDowngradedEvent[] = [];
    const q = new RetryQueue({
      sender: async (it) => { priorities.set(it.id, it.priority); },
      jitterMs: 0,
      // Frozen clock: exactly one urgent token ever. The guard bound (10)
      // is unreachable, so every degrade must come from the bucket.
      urgent: { maxUrgentPerSecond: 1, now: () => 0, maxConsecutiveUrgent: 10 },
      onUrgentDowngraded: (e) => audits.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 1; i <= 3; i++) q.enqueue(item(`u-${i}`, "urgent"));
    await timer.run();
    await settle();
    assert.equal(q.pendingCount(), 0);
    assert.equal(priorities.get("u-1"), "urgent");
    assert.equal(priorities.get("u-2"), "normal");
    assert.equal(priorities.get("u-3"), "normal");
    assert.deepEqual(audits, []);
    const [s] = q.getUrgentStats();
    assert.equal(s.delivered, 1);
    assert.equal(s.throttled, 2);
    assert.equal(s.downgraded, 0);
  });

  it("a WR-12 throttled degrade resets the streak, so the next urgent is admitted", async () => {
    const timer = manualTimer();
    // Guard decisions are per item; completion order across lanes is
    // not — record in a map.
    const priorities = new Map<string, string | undefined>();
    // Node v24 iron rule: `let` hoisted before the try, never a const
    // declared inside try referenced in finally.
    let nowMs = 0;
    const q = new RetryQueue({
      sender: async (it) => { priorities.set(it.id, it.priority); },
      jitterMs: 0,
      // One token per second; the clock advances between batches. The
      // guard bound (2) is reachable only if the streak were NOT reset
      // by the throttled degrade below.
      urgent: { maxUrgentPerSecond: 1, now: () => nowMs, maxConsecutiveUrgent: 2 },
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(item("u-1", "urgent"));
    await timer.run();
    await settle();
    // Bucket empty now: u-2 passes the guard (streak 1 < 2) then degrades
    // via WR-12 (throttled), resetting the WR-121 streak.
    q.enqueue(item("u-2", "urgent"));
    await timer.run();
    await settle();
    // A fresh second refills the bucket: u-3 is admitted on the fast
    // lane, because u-2's degrade broke the consecutive run. Without the
    // reset the streak would be 2 and the guard would fire here.
    nowMs += 1000;
    q.enqueue(item("u-3", "urgent"));
    await timer.run();
    await settle();
    assert.equal(priorities.get("u-1"), "urgent");
    assert.equal(priorities.get("u-2"), "normal");
    assert.equal(priorities.get("u-3"), "urgent");
    const [s] = q.getUrgentStats();
    assert.equal(s.delivered, 2);
    assert.equal(s.throttled, 1);
    assert.equal(s.downgraded, 0);
  });
});

describe("composes with WR-35 deficit round-robin", () => {
  it("guard fires at admission while DRR paces turns: no deadlock, normal keeps its share", async () => {
    const timer = manualTimer();
    const releases = new Map<string, () => void>();
    const priorities = new Map<string, string | undefined>();
    const order: string[] = [];
    const sender: Sender = async (it) => {
      order.push(it.id);
      priorities.set(it.id, it.priority);
      await new Promise<void>((r) => { releases.set(it.id, r); });
    };
    const audits: UrgentDowngradedEvent[] = [];
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: {
        maxUrgentPerSecond: 10000,
        now: () => 0,
        minNormalShare: 0.5,
        maxConsecutiveUrgent: 2,
      },
      onUrgentDowngraded: (e) => audits.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    for (const id of ["n-1", "n-2", "n-3"]) q.enqueue(item(id));
    await timer.run();
    await settle();
    // n-1 holds the only slot; n-2, n-3 wait in the limiter FIFO. The
    // urgents arrive after the settle (like test/starvation-guard.test.ts)
    // so n-1's dispatch earns no DRR deficit for them.
    assert.deepEqual(order, ["n-1"]);
    for (let i = 1; i <= 4; i++) q.enqueue(item(`u-${i}`, "urgent"));
    await timer.run();
    await settle();
    // u-1, u-2 admitted to the fast lane (streak 1, 2) but park at the
    // DRR gate behind the normal backlog; u-3 trips the WR-121 guard at
    // admission and joins the normal lane; u-4 is admitted after the
    // streak reset and parks too.
    assert.deepEqual(order, ["n-1"]);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].id, "u-3");
    assert.equal(audits[0].event, "urgent_downgraded");

    for (let round = 0; round < 20 && (releases.size > 0 || q.pendingCount() > 0); round++) {
      for (const release of [...releases.values()]) release();
      releases.clear();
      await timer.run();
      await settle();
    }
    assert.equal(q.pendingCount(), 0);
    assert.equal(order.length, 7);
    // The downgraded item rode the normal lane to completion.
    assert.equal(priorities.get("u-3"), "normal");
    // Normal lane kept at least its 0.5 share of dispatch turns:
    // n-1, n-2, n-3 plus the downgraded u-3 all rode the normal lane.
    const normalCount = order.filter((id) => !id.startsWith("u-") || priorities.get(id) === "normal").length;
    assert.ok(normalCount / order.length >= 0.5, `normal share too low: ${JSON.stringify(order)}`);
    // The parked urgents waited for normal progress (DRR pacing intact).
    assert.ok(order.indexOf("u-4") > order.indexOf("n-3"));
    const [us] = q.getUrgentStats();
    assert.equal(us.delivered, 3); // u-1, u-2, u-4 on the fast lane
    assert.equal(us.downgraded, 1); // u-3
    const [ls] = q.getLaneStats();
    assert.equal(ls.normalTurns, 4);
    assert.equal(ls.urgentTurns, 3);
    assert.ok(ls.guardActivations >= 1);
  });
});

/** A minimal CONNECT proxy (adapted from test/proxy.test.ts). */
async function startConnectProxy(): Promise<{
  port: number;
  hits: number;
  close: () => Promise<void>;
}> {
  let hits = 0;
  const server = createServer();
  server.on("connect", (req, clientSocket: Socket, head: Buffer) => {
    hits += 1;
    clientSocket.on("error", () => {});
    const target = req.url ?? "";
    const sep = target.lastIndexOf(":");
    const upstream = tcpConnect(Number(target.slice(sep + 1)), target.slice(0, sep));
    upstream.on("error", () => {
      clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      clientSocket.destroy();
    });
    upstream.on("connect", () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) upstream.write(head);
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return {
    port: addr.port,
    get hits() { return hits; },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("composes with WR-27 proxy tunneling (WR-12 + WR-121 + WR-27)", () => {
  it("guard downgrades over a real CONNECT tunnel: pooled, audited, nothing dropped", async () => {
    // Node v24 iron rule: hoisted `let`s, never try-scoped consts in finally.
    let target: Server | undefined;
    let proxy: Awaited<ReturnType<typeof startConnectProxy>> | undefined;
    let sender: PooledSender | undefined;
    let q: RetryQueue | undefined;
    try {
      const received: string[] = [];
      target = createServer((req, res) => {
        req.resume();
        req.on("end", () => {
          received.push(req.url ?? "");
          res.end("ok");
        });
      });
      await new Promise<void>((resolve) => target!.listen(0, "127.0.0.1", resolve));
      const taddr = target.address();
      assert.ok(taddr && typeof taddr === "object");
      const targetUrl = `http://127.0.0.1:${taddr.port}/hook`;

      proxy = await startConnectProxy();
      const proxyUrl = `http://127.0.0.1:${proxy.port}`;

      sender = createDefaultSender(undefined, undefined, undefined, {
        [targetUrl]: proxyUrl,
      });
      // Serialize the real sends through a mutex chain so the five
      // deliveries ride one pooled tunnel sequentially (the socket
      // returns to the pool when each real send completes, before the
      // next wrapper proceeds). The guard already fired at admission
      // time, so this only shapes the wire concurrency, not the lane
      // decisions under test.
      let tail: Promise<void> = Promise.resolve();
      const chainedSender: Sender = async (it) => {
        const prev = tail;
        let release!: () => void;
        tail = new Promise<void>((r) => { release = r; });
        await prev;
        try {
          await sender!(it);
        } finally {
          release();
        }
      };
      const audits: UrgentDowngradedEvent[] = [];
      const mk = (id: string): RetryItem => ({
        id,
        payload: Buffer.from(id),
        targetUrl,
        headers: {},
        priority: "urgent",
      });
      q = new RetryQueue({
        sender: chainedSender,
        jitterMs: 0,
        urgent: { maxUrgentPerSecond: 10000, now: () => 0, maxConsecutiveUrgent: 2 },
        onUrgentDowngraded: (e) => audits.push(e),
      });
      q.start();
      for (let i = 1; i <= 5; i++) q.enqueue(mk(`u-${i}`));
      // Real network: poll until all deliveries land.
      for (let i = 0; i < 200 && received.length < 5; i++) {
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.equal(received.length, 5);
      assert.equal(q.pendingCount(), 0);
      // u-3 tripped the guard mid-flood and rode the normal lane through
      // the same tunnel; everything else stayed on the fast lane.
      assert.equal(audits.length, 1);
      assert.equal(audits[0].id, "u-3");
      assert.equal(audits[0].event, "urgent_downgraded");
      const [s] = q.getUrgentStats();
      assert.equal(s.endpoint, targetUrl);
      assert.equal(s.delivered, 4);
      assert.equal(s.downgraded, 1);
      // WR-27: one CONNECT tunnel served all five deliveries (pooled),
      // and the pool key is proxy-bound.
      assert.equal(proxy.hits, 1);
      const keys = (sender.pool?.getStats().endpoints ?? []).map((e) => e.key);
      assert.ok(
        keys.some((k) => k.includes("|proxy:")),
        `expected a proxy-bound pool key, got ${JSON.stringify(keys)}`
      );
    } finally {
      q?.stop();
      sender?.destroy();
      await proxy?.close();
      if (target !== undefined) {
        await new Promise<void>((resolve) => target!.close(() => resolve()));
      }
    }
  });
});
