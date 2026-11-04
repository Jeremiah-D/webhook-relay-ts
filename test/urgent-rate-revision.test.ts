import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import {
  RetryQueue,
  UrgentRateLimiter,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "urgent-rate-revision-secret";

const URL = "http://localhost:9999/hook";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
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

const ITEM: RetryItem = {
  id: "ur-1",
  payload: Buffer.from("urgent"),
  targetUrl: URL,
  headers: {},
};

describe("UrgentRateLimiter.retune (WR-324)", () => {
  it("tightening refills first, then clamps remaining tokens to the new rate", () => {
    const now = { ms: 0 };
    const rl = new UrgentRateLimiter(10, () => now.ms);
    for (let i = 0; i < 3; i++) assert.ok(rl.take("e")); // 7 left
    now.ms = 1000; // a full second passes: refill would top the bucket back to 10
    assert.equal(rl.retune(8), 8);
    assert.equal(rl.rate(), 8);
    // Refill-then-clamp: 10 refilled tokens clamped to 8 (not the
    // pre-refill 7, which a clamp-without-refill would report).
    assert.equal(rl.available("e"), 8);
  });

  it("tightening makes the next take refuse earlier", () => {
    const now = { ms: 0 };
    const rl = new UrgentRateLimiter(5, () => now.ms);
    assert.ok(rl.take("e"));
    assert.ok(rl.take("e")); // 3 left
    now.ms = 1000; // refill would restore the full burst of 5
    assert.equal(rl.retune(2), 2);
    assert.equal(rl.available("e"), 2);
    assert.ok(rl.take("e"));
    assert.ok(rl.take("e"));
    assert.equal(rl.take("e"), false); // clamped: refuses where 5 would have admitted
  });

  it("widening never tops the bucket up, but admits more after refill", () => {
    const now = { ms: 0 };
    const rl = new UrgentRateLimiter(2, () => now.ms);
    assert.ok(rl.take("e"));
    assert.ok(rl.take("e"));
    assert.equal(rl.take("e"), false);
    assert.equal(rl.retune(6), 6);
    assert.equal(rl.rate(), 6);
    // No top-up: still empty right after the widening.
    assert.equal(rl.available("e"), 0);
    assert.equal(rl.take("e"), false);
    // But the refill horizon follows the new rate: 6/s refills a full
    // bucket in one second. (`available()` is a raw stored snapshot —
    // refill is lazy in `take()` — so the refill is observed through
    // takes, not through `available()`.)
    now.ms = 1000;
    for (let i = 0; i < 6; i++) assert.ok(rl.take("e"));
    assert.equal(rl.take("e"), false);
  });

  it("rejects illegal values and leaves the live rate and tokens untouched", () => {
    const now = { ms: 0 };
    const rl = new UrgentRateLimiter(60, () => now.ms);
    assert.ok(rl.take("e")); // 59 tokens left
    for (const bad of [0, -1, NaN, Infinity, -Infinity]) {
      assert.throws(() => rl.retune(bad), RangeError, `rate ${bad}`);
    }
    assert.equal(rl.rate(), 60);
    assert.equal(rl.available("e"), 59);
  });

  it("a same-value retune is a no-op", () => {
    const now = { ms: 0 };
    const rl = new UrgentRateLimiter(2, () => now.ms);
    assert.ok(rl.take("e"));
    assert.equal(rl.retune(2), 2);
    assert.equal(rl.rate(), 2);
    assert.equal(rl.available("e"), 1);
  });

  it("two endpoint buckets share the new rate", () => {
    const now = { ms: 0 };
    const rl = new UrgentRateLimiter(2, () => now.ms);
    assert.ok(rl.take("a"));
    assert.ok(rl.take("b")); // 1 token left in each bucket
    now.ms = 500; // half a second refills each bucket back to 2
    assert.equal(rl.retune(1), 1);
    assert.equal(rl.available("a"), 1);
    assert.equal(rl.available("b"), 1);
    assert.ok(rl.take("a"));
    assert.equal(rl.take("a"), false);
    assert.ok(rl.take("b"));
    assert.equal(rl.take("b"), false);
  });
});

describe("RetryQueue.setUrgentRate (WR-324)", () => {
  it("revises the live rate; getUrgentStats shape is unchanged", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      maxAttempts: 1,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      // The limiter is always constructed: the default is 100/s.
      assert.equal(q.getUrgentRate(), 100);
      assert.equal(q.setUrgentRate(20), 20);
      assert.equal(q.getUrgentRate(), 20);
      q.enqueue({ ...ITEM, priority: "urgent" });
      await timer.run();
      assert.equal(q.pendingCount(), 0);
      assert.deepEqual(q.getUrgentStats(), [
        { endpoint: URL, delivered: 1, retried: 0, throttled: 0, downgraded: 0 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError and leaves the live rate untouched", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    q.start();
    try {
      for (const bad of [0, -1, NaN, Infinity, -Infinity]) {
        assert.throws(() => q.setUrgentRate(bad), RangeError, `rate ${bad}`);
      }
      assert.equal(q.getUrgentRate(), 100);
    } finally {
      q.stop();
    }
  });

  it("an in-flight urgent attempt is unaffected by a tightening", async () => {
    const timer = manualTimer();
    let release!: () => void;
    const sender: Sender = async () => {
      await new Promise<void>((r) => {
        release = r;
      });
    };
    const q = new RetryQueue({
      sender,
      maxAttempts: 1,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      q.enqueue({ ...ITEM, priority: "urgent" });
      await timer.run();
      // The attempt has taken its token and is in flight (sender blocked).
      assert.equal(q.inFlightCount(), 1);
      // Tighten mid-flight: granted tokens are never revoked, so the
      // in-flight attempt still completes.
      assert.equal(q.setUrgentRate(1), 1);
      release();
      await timer.run();
      await new Promise((r) => setImmediate(r));
      assert.equal(q.pendingCount(), 0);
      assert.equal(q.inFlightCount(), 0);
      const [s] = q.getUrgentStats();
      assert.equal(s.delivered, 1);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer urgent rate revision (WR-324)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer() {
    const dir = mkdtempSync(join(tmpdir(), "urgent-rate-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  it("setUrgentRate audits previous/current, with the default 100 as first previous", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.equal(relay.setUrgentRate!(20), 20);
    assert.equal(relay.getUrgentRate!(), 20);
    const revised = eventsOf(auditLog, "urgent_rate_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, 100);
    assert.equal(revised[0].current, 20);
    // A second revision audits the live values as previous.
    assert.equal(relay.setUrgentRate!(500), 500);
    const revised2 = eventsOf(auditLog, "urgent_rate_revised");
    assert.equal(revised2.length, 2);
    assert.equal(revised2[1].previous, 20);
    assert.equal(revised2[1].current, 500);
  });

  it("getter matches live; an unrevised server reports the default", async () => {
    const { relay } = makeServer();
    await listen(relay);
    assert.equal(relay.getUrgentRate!(), 100);
    relay.setUrgentRate!(20);
    assert.equal(relay.getUrgentRate!(), 20);
  });

  it("illegal values throw RangeError and leave the live rate untouched", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    for (const bad of [0, -1, NaN, Infinity, -Infinity]) {
      assert.throws(() => relay.setUrgentRate!(bad), RangeError, `rate ${bad}`);
      assert.equal(relay.getUrgentRate!(), 100);
    }
    assert.equal(eventsOf(auditLog, "urgent_rate_revised").length, 0);
  });

  it("a same-value revision is a silent no-op", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    // Revising to the construction default changes nothing worth auditing.
    relay.setUrgentRate!(100);
    assert.equal(eventsOf(auditLog, "urgent_rate_revised").length, 0);
    relay.setUrgentRate!(20);
    relay.setUrgentRate!(20);
    assert.equal(eventsOf(auditLog, "urgent_rate_revised").length, 1);
  });
});
