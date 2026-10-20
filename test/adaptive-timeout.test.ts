import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import {
  AdaptiveTimeout,
  AdaptiveTimeoutError,
  assertValidAdaptiveTimeoutOptions,
  readAdaptiveTimeoutMs,
} from "../src/adaptive-timeout.ts";

const A = "http://a/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Let the deliver() promise chain settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

/** Manual clock for deterministic latency samples. */
function manualClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

describe("assertValidAdaptiveTimeoutOptions", () => {
  it("rejects a missing or non-object config", () => {
    assert.throws(() => assertValidAdaptiveTimeoutOptions(undefined), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions(null), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions("1000"), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions([]), RangeError);
  });

  it("rejects a bad baseTimeoutMs", () => {
    assert.throws(() => assertValidAdaptiveTimeoutOptions({}), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ baseTimeoutMs: 0 }), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ baseTimeoutMs: -5 }), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ baseTimeoutMs: Infinity }), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ baseTimeoutMs: "1000" }), RangeError);
  });

  it("rejects bad margin/min/max/minSamples", () => {
    const base = { baseTimeoutMs: 1000 };
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ ...base, marginRatio: -0.1 }), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ ...base, marginRatio: NaN }), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ ...base, minTimeoutMs: 0 }), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ ...base, maxTimeoutMs: 0 }), RangeError);
    assert.throws(
      () => assertValidAdaptiveTimeoutOptions({ ...base, minTimeoutMs: 500, maxTimeoutMs: 100 }),
      RangeError
    );
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ ...base, minSamples: 0 }), RangeError);
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ ...base, minSamples: 1.5 }), RangeError);
    assert.throws(
      () => assertValidAdaptiveTimeoutOptions({ ...base, maxSamplesPerEndpoint: 0 }),
      RangeError
    );
    assert.throws(() => assertValidAdaptiveTimeoutOptions({ ...base, now: 42 }), RangeError);
  });

  it("accepts a minimal and a full config", () => {
    assert.doesNotThrow(() => assertValidAdaptiveTimeoutOptions({ baseTimeoutMs: 1000 }));
    assert.doesNotThrow(() =>
      assertValidAdaptiveTimeoutOptions({
        baseTimeoutMs: 1000,
        marginRatio: 0.25,
        minTimeoutMs: 50,
        maxTimeoutMs: 8000,
        minSamples: 3,
        maxSamplesPerEndpoint: 64,
        now: () => 0,
      })
    );
  });
});

describe("AdaptiveTimeoutError", () => {
  it("is a typed error with no statusCode (retryable fallthrough)", () => {
    const err = new AdaptiveTimeoutError(A, 250);
    assert.equal(err.name, "AdaptiveTimeoutError");
    assert.equal(err.targetUrl, A);
    assert.equal(err.timeoutMs, 250);
    assert.ok(err instanceof Error);
    assert.ok(!("statusCode" in err));
    assert.match(err.message, /adaptive outbound timeout/);
    assert.match(err.message, /250ms/);
  });
});

describe("readAdaptiveTimeoutMs", () => {
  it("reads a valid stamped cap and ignores junk", () => {
    assert.equal(readAdaptiveTimeoutMs({ adaptiveTimeoutMs: 300 }), 300);
    assert.equal(readAdaptiveTimeoutMs({}), undefined);
    assert.equal(readAdaptiveTimeoutMs({ adaptiveTimeoutMs: 0 }), undefined);
    assert.equal(readAdaptiveTimeoutMs({ adaptiveTimeoutMs: -1 }), undefined);
    assert.equal(readAdaptiveTimeoutMs({ adaptiveTimeoutMs: "300" }), undefined);
    assert.equal(readAdaptiveTimeoutMs({ adaptiveTimeoutMs: NaN }), undefined);
  });
});

describe("AdaptiveTimeout.timeoutFor", () => {
  it("returns baseTimeoutMs while cold (no samples / under minSamples)", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({ baseTimeoutMs: 1000, minSamples: 3, now: clock.now });
    assert.equal(at.timeoutFor(A), 1000);
    at.recordAccepted("1");
    clock.advance(100);
    at.recordDelivered("1", A);
    at.recordAccepted("2");
    clock.advance(100);
    at.recordDelivered("2", A);
    // 2 < minSamples 3: still cold.
    assert.equal(at.timeoutFor(A), 1000);
    at.recordAccepted("3");
    clock.advance(100);
    at.recordDelivered("3", A);
    // 3 samples of 100ms: p99=100, margin 0.5 -> 150.
    assert.equal(at.timeoutFor(A), 150);
  });

  it("applies the margin above p99 (slow endpoints are not false-killed)", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 500,
      marginRatio: 0.5,
      maxTimeoutMs: 20000,
      minSamples: 1,
      now: clock.now,
    });
    for (const [id, ms] of [["1", 4000], ["2", 5000], ["3", 6000]] as const) {
      at.recordAccepted(id);
      clock.advance(ms);
      at.recordDelivered(id, A);
    }
    // p99=6000 -> 9000, well above the static 500 but under the 4x ceiling.
    assert.equal(at.timeoutFor(A), 9000);
  });

  it("clamps to [minTimeoutMs, maxTimeoutMs]", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 200,
      maxTimeoutMs: 500,
      minSamples: 1,
      now: clock.now,
    });
    // Fast endpoint: p99=10 -> 15, floored at 200.
    at.recordAccepted("1");
    clock.advance(10);
    at.recordDelivered("1", A);
    assert.equal(at.timeoutFor(A), 200);
    // Slow endpoint: p99=10000 -> 15000, capped at 500.
    at.recordAccepted("2");
    clock.advance(10000);
    at.recordDelivered("2", "http://b/");
    assert.equal(at.timeoutFor("http://b/"), 500);
  });

  it("discard() drops a pending clock without sampling", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({ baseTimeoutMs: 1000, minSamples: 1, now: clock.now });
    at.recordAccepted("1");
    clock.advance(5000);
    at.discard("1");
    // No sample was taken: still cold.
    assert.equal(at.timeoutFor(A), 1000);
    assert.deepEqual(at.stats(), []);
  });

  it("stats() exposes per-endpoint rows", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({ baseTimeoutMs: 1000, minSamples: 1, now: clock.now });
    at.recordAccepted("1");
    clock.advance(200);
    at.recordDelivered("1", A);
    const rows = at.stats();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].endpoint, A);
    assert.equal(rows[0].timeoutMs, 300);
    assert.equal(rows[0].samples, 1);
    assert.equal(rows[0].p99Ms, 200);
  });

  it("samples are per-endpoint", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({ baseTimeoutMs: 1000, minSamples: 1, now: clock.now });
    at.recordAccepted("1");
    clock.advance(100);
    at.recordDelivered("1", A);
    assert.equal(at.timeoutFor(A), 150);
    // Unknown endpoint stays cold.
    assert.equal(at.timeoutFor("http://other/"), 1000);
  });
});

describe("RetryQueue adaptiveTimeout integration", () => {
  it("stamps the adaptive cap on the wire copy (cold start -> base)", async () => {
    const seen: Array<number | undefined> = [];
    const sender: Sender = async (it) => {
      seen.push(it.adaptiveTimeoutMs);
    };
    const q = new RetryQueue({
      sender,
      adaptiveTimeout: { baseTimeoutMs: 750, minSamples: 100 },
      maxAttempts: 1,
    });
    q.start();
    q.enqueue(item("w1", A));
    await flush();
    assert.deepEqual(seen, [750]);
    q.stop();
  });

  it("does not stamp anything when the feature is off", async () => {
    const seen: Array<number | undefined> = [];
    const sender: Sender = async (it) => {
      seen.push(it.adaptiveTimeoutMs);
    };
    const q = new RetryQueue({ sender, maxAttempts: 1 });
    q.start();
    q.enqueue(item("w1", A));
    await flush();
    assert.deepEqual(seen, [undefined]);
    q.stop();
  });

  it("adapts the stamped cap from delivered samples (injected clock)", async () => {
    const clock = manualClock();
    const seen: number[] = [];
    const sender: Sender = async (it) => {
      seen.push(it.adaptiveTimeoutMs as number);
    };
    const q = new RetryQueue({
      sender,
      adaptiveTimeout: { baseTimeoutMs: 1000, minSamples: 2, now: clock.now },
      maxAttempts: 1,
    });
    q.start();
    // recordAccepted runs synchronously inside enqueue(); advancing the
    // manual clock right after pins each sample's latency deterministically.
    const settle = () => new Promise((r) => setTimeout(r, 150));
    q.enqueue(item("s1", A));
    clock.advance(200);
    await settle();
    q.enqueue(item("s2", A));
    clock.advance(200);
    await settle();
    // Two 200ms samples: p99=200, margin 0.5 -> the third dispatch is
    // stamped 300 instead of the cold-start 1000.
    q.enqueue(item("s3", A));
    await settle();
    assert.deepEqual(seen, [1000, 1000, 300]);
    q.stop();
  });

  it("getAdaptiveTimeoutStats() exposes per-endpoint rows; empty when off", async () => {
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      adaptiveTimeout: { baseTimeoutMs: 1000, minSamples: 1 },
      maxAttempts: 1,
    });
    q.start();
    assert.deepEqual(q.getAdaptiveTimeoutStats(), []);
    q.enqueue(item("s1", A));
    await flush();
    const rows = q.getAdaptiveTimeoutStats();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].endpoint, A);
    assert.equal(rows[0].samples, 1);
    q.stop();

    const q2 = new RetryQueue({ sender, maxAttempts: 1 });
    q2.start();
    q2.enqueue(item("s1", A));
    await flush();
    assert.deepEqual(q2.getAdaptiveTimeoutStats(), []);
    q2.stop();
  });

  it("a timed-out attempt is retryable: retried, not dead-lettered at once", async () => {
    // A hanging sender that honors the stamped adaptive timeout exactly
    // like the default sender does (rejects with AdaptiveTimeoutError
    // after the stamped cap).
    const { AdaptiveTimeoutError: ATE } = await import("../src/adaptive-timeout.ts");
    let calls = 0;
    const hanging: Sender = (it) =>
      new Promise((_resolve, reject) => {
        calls += 1;
        const ms = it.adaptiveTimeoutMs ?? 30_000;
        const t = setTimeout(() => reject(new ATE(it.targetUrl, ms)), ms);
        t.unref?.();
      });
    const q = new RetryQueue({
      sender: hanging,
      adaptiveTimeout: { baseTimeoutMs: 150, minSamples: 1 },
      maxAttempts: 3,
      baseDelayMs: 5,
      maxDelayMs: 5,
    });
    q.start();
    q.enqueue(item("t1", A));
    // 3 attempts x ~150ms timeout + ~5ms backoffs: poll for completion.
    const deadline = Date.now() + 10_000;
    while (calls < 3 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.equal(calls, 3, "the timed-out attempt must be retried, not expired at once");
    const dlDeadline = Date.now() + 5000;
    while (q.getDeadLetterStats().total < 1 && Date.now() < dlDeadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(q.getDeadLetterStats().total, 1);
    q.stop();
  });

  it("the default sender enforces the stamped cap against a hung downstream", async () => {
    const { createServer } = await import("node:http");
    const server = createServer(() => {
      // Never respond: the attempt must time out.
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const { createDefaultSender } = await import("../src/server.ts");
    const sender = createDefaultSender();
    const start = Date.now();
    const err = await sender({
      id: "x",
      payload: BODY,
      targetUrl: `http://127.0.0.1:${port}/hook`,
      headers: {},
      adaptiveTimeoutMs: 120,
    }).then(
      () => null,
      (e: unknown) => e
    );
    const elapsed = Date.now() - start;
    assert.ok(err instanceof AdaptiveTimeoutError, `expected AdaptiveTimeoutError, got ${err}`);
    assert.ok(elapsed >= 100, `fired suspiciously early at ${elapsed}ms`);
    assert.ok(elapsed < 5000, `did not fire the adaptive cap (took ${elapsed}ms)`);
    sender.destroy();
    server.close();
  });

  it("AdaptiveTimeoutError classifies as retryable (breaker/latency see a normal timeout)", async () => {
    const { classifyFailure } = await import("../src/failure.ts");
    const err = new AdaptiveTimeoutError(A, 100);
    const classified = classifyFailure(err);
    assert.equal(classified.failureClass, "retryable");
  });

  it("constructor rejects an invalid adaptiveTimeout", () => {
    const sender: Sender = async () => {};
    assert.throws(
      () => new RetryQueue({ sender, adaptiveTimeout: { baseTimeoutMs: 0 } }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          sender,
          adaptiveTimeout: { baseTimeoutMs: 1000, minTimeoutMs: 900, maxTimeoutMs: 100 },
        }),
      RangeError
    );
  });
});
