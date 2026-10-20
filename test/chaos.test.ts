import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ChaosMetrics,
  chaosResetError,
  resolveChaosConfig,
  wrapSenderWithChaos,
  type ChaosInjectionInfo,
} from "../src/chaos.ts";
import { HttpDeliveryError, classifyFailure } from "../src/failure.ts";
import { RetryQueue, type RetryItem, type Sender } from "../src/retry.ts";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const ENDPOINT = "http://localhost:9999/hook";
const OTHER = "http://localhost:9999/other";

function item(targetUrl: string, id = "item-1"): RetryItem {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl,
    headers: { "content-type": "application/json" },
  };
}

function okSender(calls: { n: number }): Sender {
  return async () => {
    calls.n++;
    return { statusCode: 200, body: Buffer.from("ok"), truncated: false };
  };
}

describe("chaos: config validation", () => {
  it("returns undefined when the feature is off", () => {
    assert.equal(resolveChaosConfig(undefined, "createDefaultSender"), undefined);
  });

  it("rejects invalid latencyMs", () => {
    assert.throws(
      () => resolveChaosConfig({ rules: { [ENDPOINT]: { latencyMs: -1 } } }, "x"),
      RangeError
    );
    assert.throws(
      () => resolveChaosConfig({ rules: { [ENDPOINT]: { latencyMs: NaN } } }, "x"),
      RangeError
    );
  });

  it("rejects invalid statusCode", () => {
    for (const statusCode of [99, 600, 200.5, NaN]) {
      assert.throws(
        () => resolveChaosConfig({ rules: { [ENDPOINT]: { statusCode } } }, "x"),
        RangeError,
        `statusCode ${statusCode}`
      );
    }
  });

  it("rejects resetConnection combined with statusCode", () => {
    assert.throws(
      () =>
        resolveChaosConfig(
          { rules: { [ENDPOINT]: { resetConnection: true, statusCode: 500 } } },
          "x"
        ),
      RangeError
    );
  });

  it("rejects a rule with no fault and a non-object config", () => {
    assert.throws(() => resolveChaosConfig({ rules: { [ENDPOINT]: {} } }, "x"), RangeError);
    assert.throws(() => resolveChaosConfig(null as never, "x"), RangeError);
    assert.throws(() => resolveChaosConfig({ rules: null } as never, "x"), RangeError);
    assert.throws(() => resolveChaosConfig({ rules: { "": { statusCode: 500 } } }, "x"), RangeError);
  });

  it("accepts each fault kind", () => {
    const r = resolveChaosConfig(
      {
        rules: {
          [ENDPOINT]: { latencyMs: 50 },
          [OTHER]: { resetConnection: true, latencyMs: 0 },
        },
      },
      "x"
    );
    assert.ok(r !== undefined);
    assert.equal(r!.rules.size, 2);
  });
});

describe("chaos: fault injection", () => {
  it("holds the attempt back by latencyMs, then delegates", async () => {
    const metrics = new ChaosMetrics();
    const injected: ChaosInjectionInfo[] = [];
    const calls = { n: 0 };
    const sender = wrapSenderWithChaos(
      okSender(calls),
      resolveChaosConfig({ rules: { [ENDPOINT]: { latencyMs: 60 } } }, "x")!,
      metrics,
      { onInjected: (i) => injected.push(i) }
    );
    const start = Date.now();
    const res = await sender(item(ENDPOINT));
    const elapsed = Date.now() - start;
    assert.ok(elapsed >= 50, `expected a ~60ms hold, took ${elapsed}ms`);
    assert.equal(calls.n, 1, "delegates after the hold");
    assert.equal((res as { statusCode: number }).statusCode, 200);
    assert.equal(injected.length, 1);
    assert.equal(injected[0].kind, "latency");
    assert.equal(injected[0].detailMs, 60);
    assert.equal(injected[0].endpoint, ENDPOINT);
    assert.equal(injected[0].id, "item-1");
    assert.deepEqual(metrics.getStats(), { [ENDPOINT]: { latency: 1 } });
  });

  it("throws HttpDeliveryError for statusCode without touching the sender", async () => {
    const metrics = new ChaosMetrics();
    const injected: ChaosInjectionInfo[] = [];
    const calls = { n: 0 };
    const sender = wrapSenderWithChaos(
      okSender(calls),
      resolveChaosConfig({ rules: { [ENDPOINT]: { statusCode: 503 } } }, "x")!,
      metrics,
      { onInjected: (i) => injected.push(i) }
    );
    await assert.rejects(() => sender(item(ENDPOINT)), (err: unknown) => {
      assert.ok(err instanceof HttpDeliveryError);
      assert.equal((err as HttpDeliveryError).statusCode, 503);
      return true;
    });
    assert.equal(calls.n, 0, "the network is never touched");
    assert.equal(injected.length, 1);
    assert.equal(injected[0].kind, "status");
    assert.equal(injected[0].detailStatus, 503);
    // The queue classifies it exactly like a real downstream 503.
    assert.equal(classifyFailure(new HttpDeliveryError(503)).failureClass, "retryable");
  });

  it("throws a simulated ECONNRESET for resetConnection", async () => {
    const metrics = new ChaosMetrics();
    const calls = { n: 0 };
    const sender = wrapSenderWithChaos(
      okSender(calls),
      resolveChaosConfig({ rules: { [ENDPOINT]: { resetConnection: true } } }, "x")!,
      metrics
    );
    await assert.rejects(() => sender(item(ENDPOINT)), (err: unknown) => {
      const errno = err as NodeJS.ErrnoException;
      assert.equal(errno.code, "ECONNRESET");
      return true;
    });
    assert.equal(calls.n, 0);
    assert.deepEqual(metrics.getStats(), { [ENDPOINT]: { reset: 1 } });
    assert.equal(classifyFailure(chaosResetError()).failureClass, "retryable");
  });

  it("combines latencyMs with a terminal fault", async () => {
    const metrics = new ChaosMetrics();
    const injected: ChaosInjectionInfo[] = [];
    const calls = { n: 0 };
    const sender = wrapSenderWithChaos(
      okSender(calls),
      resolveChaosConfig({ rules: { [ENDPOINT]: { latencyMs: 20, statusCode: 500 } } }, "x")!,
      metrics,
      { onInjected: (i) => injected.push(i) }
    );
    const start = Date.now();
    await assert.rejects(() => sender(item(ENDPOINT)), HttpDeliveryError);
    assert.ok(Date.now() - start >= 15, "the hold applies before the fault");
    assert.equal(calls.n, 0);
    assert.deepEqual(
      injected.map((i) => i.kind),
      ["latency", "status"]
    );
  });

  it("delegates untouched for endpoints without a rule", async () => {
    const metrics = new ChaosMetrics();
    const injected: ChaosInjectionInfo[] = [];
    const calls = { n: 0 };
    const sender = wrapSenderWithChaos(
      okSender(calls),
      resolveChaosConfig({ rules: { [ENDPOINT]: { statusCode: 500 } } }, "x")!,
      metrics,
      { onInjected: (i) => injected.push(i) }
    );
    const res = await sender(item(OTHER));
    assert.equal((res as { statusCode: number }).statusCode, 200);
    assert.equal(calls.n, 1);
    assert.equal(injected.length, 0);
    assert.deepEqual(metrics.getStats(), {});
    assert.equal(metrics.render(), "", "no series before the first injection");
  });

  it("renders Prometheus exposition after injections", () => {
    const metrics = new ChaosMetrics();
    metrics.inject(ENDPOINT, "status");
    metrics.inject(ENDPOINT, "status");
    metrics.inject(OTHER, "latency");
    const out = metrics.render();
    assert.ok(out.includes("relay_chaos_injected_total"));
    assert.ok(out.includes(`endpoint="${ENDPOINT}",kind="status"} 2`));
    assert.ok(out.includes(`endpoint="${OTHER}",kind="latency"} 1`));
  });
});

describe("chaos: drill through the retry queue", () => {
  it("an injected 500 retries with backoff and dead-letters like a real failure", async () => {
    const metrics = new ChaosMetrics();
    const injected: ChaosInjectionInfo[] = [];
    const innerCalls = { n: 0 };
    const sender = wrapSenderWithChaos(
      okSender(innerCalls),
      resolveChaosConfig({ rules: { [ENDPOINT]: { statusCode: 500 } } }, "x")!,
      metrics,
      { onInjected: (i) => injected.push(i) }
    );
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 3,
      jitterMs: 0,
    });
    q.start();
    try {
      q.enqueue(item(ENDPOINT));
      const deadline = Date.now() + 5000;
      while (q.getDeadLetter().length === 0 && Date.now() < deadline) {
        await sleep(20);
      }
      const dead = q.getDeadLetter();
      assert.equal(dead.length, 1);
      assert.equal(dead[0].id, "item-1");
      assert.equal(dead[0].attempts, 3, "all attempts ran through the chaos wrapper");
      assert.equal(innerCalls.n, 0, "the real sender never saw the drill traffic");
      assert.equal(injected.length, 3, "one audit hook per injected fault");
      assert.ok(injected.every((i) => i.kind === "status" && i.detailStatus === 500));
      assert.deepEqual(metrics.getStats(), { [ENDPOINT]: { status: 3 } });
    } finally {
      await q.stop();
    }
  });

  it("an injected reset is retryable and the drill can be scoped per endpoint", async () => {
    const metrics = new ChaosMetrics();
    const innerCalls = { n: 0 };
    const sender = wrapSenderWithChaos(
      okSender(innerCalls),
      resolveChaosConfig({ rules: { [ENDPOINT]: { resetConnection: true } } }, "x")!,
      metrics
    );
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 2,
      jitterMs: 0,
    });
    q.start();
    try {
      // The drilled endpoint fails; the undrilled one delivers.
      q.enqueue(item(ENDPOINT, "item-1"));
      q.enqueue(item(OTHER, "item-2"));
      const deadline = Date.now() + 5000;
      while (q.getDeadLetter().length === 0 && Date.now() < deadline) {
        await sleep(20);
      }
      assert.equal(q.getDeadLetter().length, 1);
      assert.equal(q.getDeadLetter()[0].targetUrl, ENDPOINT);
      assert.equal(innerCalls.n, 1, "only the undrilled endpoint reached the sender");
    } finally {
      await q.stop();
    }
  });
});
