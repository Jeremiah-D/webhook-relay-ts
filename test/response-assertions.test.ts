import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  AssertionFailedError,
  assertValidResponseAssertion,
  assertValidResponseAssertionRule,
  classifyFailure,
  evaluateResponseAssertionRule,
  isResponseStatusWhitelisted,
  parseAssertionPath,
  resolveAssertionPath,
  type AssertionFailureInfo,
  type DownstreamResponse,
  type ResponseAssertionRule,
  type Sender,
} from "../src/retry.ts";

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

const URL = "http://localhost:9999/hook";
const URL_OTHER = "http://localhost:9999/other";

const ITEM = {
  id: "item-1",
  payload: Buffer.from("hello"),
  targetUrl: URL,
  headers: { "content-type": "application/json" },
};

/** Sender replaying a scripted list of 200 responses (stuck on the last). */
function scriptedSender(bodies: Buffer[], calls: { count: number }): Sender {
  return async () => {
    calls.count += 1;
    const body = bodies[Math.min(calls.count - 1, bodies.length - 1)];
    const response: DownstreamResponse = { statusCode: 200, body, truncated: false };
    return response;
  };
}

const json = (v: unknown) => Buffer.from(JSON.stringify(v));

describe("WR-118 assertion path parsing", () => {
  it("parses the strict path grammar", () => {
    assert.deepEqual(parseAssertionPath("$"), []);
    assert.deepEqual(parseAssertionPath("$.status"), ["status"]);
    assert.deepEqual(parseAssertionPath("$.data.items[0].code"), ["data", "items", 0, "code"]);
    assert.deepEqual(parseAssertionPath("$[2]"), [2]);
    assert.deepEqual(parseAssertionPath("$._private.$x"), ["_private", "$x"]);
  });

  it("rejects illegal paths with RangeError (fail-fast)", () => {
    const bad = [
      "status", // no leading $
      "$.a b", // whitespace
      "$.", // dangling dot
      "$..a", // double dot
      "$.9abc", // identifier cannot start with a digit
      "$.a[", // unterminated bracket
      "$.a[x]", // non-numeric index
      "$.a[-1]", // negative index
      "$.a)b", // stray character
      "$a", // missing dot/bracket after $
    ];
    for (const path of bad) {
      assert.throws(() => parseAssertionPath(path), RangeError, `path ${path} should throw`);
    }
  });
});

describe("WR-118 assertion path resolution", () => {
  const doc = { a: { b: [{ c: 42 }] }, nil: null };

  it("resolves present values and fails soft on missing ones", () => {
    assert.equal(resolveAssertionPath(doc, parseAssertionPath("$.a.b[0].c")), 42);
    assert.equal(resolveAssertionPath(doc, parseAssertionPath("$")), doc);
    assert.equal(resolveAssertionPath(doc, parseAssertionPath("$.missing")), undefined);
    assert.equal(resolveAssertionPath(doc, parseAssertionPath("$.a.b[7].c")), undefined);
    assert.equal(resolveAssertionPath(doc, parseAssertionPath("$.nil.x")), undefined);
    assert.equal(resolveAssertionPath(doc, parseAssertionPath("$.a.b.c")), undefined);
  });
});

describe("WR-118 assertion evaluation", () => {
  const body = json({ status: "ok", latencyMs: 42, code: "PAY-123", nested: { on: true } });

  function one(path: string, op: string, value?: unknown) {
    const rule: ResponseAssertionRule = {
      targetUrl: URL,
      assertions: [{ path, op: op as never, ...(value === undefined ? {} : { value }) }],
    };
    return evaluateResponseAssertionRule(rule, body);
  }

  it("evaluates every operator", () => {
    assert.ok(one("$.status", "eq", "ok").passed);
    assert.ok(!one("$.status", "eq", "error").passed);
    assert.ok(one("$.status", "ne", "error").passed);
    assert.ok(!one("$.status", "ne", "ok").passed);
    assert.ok(one("$.latencyMs", "gt", 40).passed);
    assert.ok(one("$.latencyMs", "gte", 42).passed);
    assert.ok(one("$.latencyMs", "lt", 100).passed);
    assert.ok(one("$.latencyMs", "lte", 42).passed);
    assert.ok(!one("$.latencyMs", "gt", 42).passed);
    assert.ok(one("$.code", "matches", "^PAY-[0-9]+$").passed);
    assert.ok(!one("$.code", "matches", "^INV-").passed);
    assert.ok(one("$.nested.on", "exists").passed);
    assert.ok(!one("$.nested.off", "exists").passed);
  });

  it("uses strict equality for eq/ne (no type coercion)", () => {
    assert.ok(!one("$.latencyMs", "eq", "42").passed);
    assert.ok(one("$.latencyMs", "ne", "42").passed);
  });

  it("fails closed on non-JSON bodies", () => {
    const rule: ResponseAssertionRule = {
      targetUrl: URL,
      assertions: [{ path: "$.status", op: "eq", value: "ok" }],
    };
    const verdict = evaluateResponseAssertionRule(rule, Buffer.from("this is not json"));
    assert.equal(verdict.passed, false);
    assert.match(verdict.reason ?? "", /not JSON/);
  });

  it("fails closed on missing paths and type mismatches", () => {
    assert.ok(!one("$.missing", "eq", "x").passed);
    assert.ok(!one("$.status", "gt", 1).passed); // string vs number
    assert.ok(!one("$.latencyMs", "matches", "^4").passed); // number vs string
  });

  it("a rule with no assertions always passes (whitelist-only)", () => {
    const rule: ResponseAssertionRule = { targetUrl: URL };
    assert.ok(evaluateResponseAssertionRule(rule, Buffer.from("garbage")).passed);
  });
});

describe("WR-118 rule validation (fail-fast)", () => {
  it("accepts well-formed rules", () => {
    assertValidResponseAssertionRule(
      {
        targetUrl: URL,
        expectedStatuses: [200, 201],
        assertions: [
          { path: "$.status", op: "eq", value: "ok" },
          { path: "$.latencyMs", op: "lt", value: 100 },
          { path: "$.code", op: "matches", value: "^PAY-" },
          { path: "$.trace", op: "exists" },
        ],
      },
      "rule"
    );
  });

  it("rejects illegal rules with RangeError", () => {
    const bad: Array<[unknown, string]> = [
      [null, "non-object"],
      ["x", "non-object"],
      [{ assertions: [] }, "missing targetUrl"],
      [{ targetUrl: "", assertions: [] }, "empty targetUrl"],
      [{ targetUrl: URL, expectedStatuses: [] }, "empty whitelist"],
      [{ targetUrl: URL, expectedStatuses: [99] }, "status below 100"],
      [{ targetUrl: URL, expectedStatuses: [600] }, "status above 599"],
      [{ targetUrl: URL, expectedStatuses: [200.5] }, "non-integer status"],
      [{ targetUrl: URL, assertions: "nope" }, "non-array assertions"],
      [{ targetUrl: URL, assertions: [{ path: "status", op: "eq", value: 1 }] }, "bad path"],
      [{ targetUrl: URL, assertions: [{ path: "$.a", op: "bogus", value: 1 }] }, "bad op"],
      [{ targetUrl: URL, assertions: [{ path: "$.a", op: "exists", value: 1 }] }, "value on exists"],
      [{ targetUrl: URL, assertions: [{ path: "$.a", op: "eq" }] }, "missing value"],
      [
        { targetUrl: URL, assertions: [{ path: "$.a", op: "matches", value: "([" }] },
        "invalid regex",
      ],
      [
        { targetUrl: URL, assertions: [{ path: "$.a", op: "matches", value: 42 }] },
        "non-string regex",
      ],
      [
        { targetUrl: URL, assertions: [{ path: "$.a", op: "lt", value: "x" }] },
        "non-numeric comparison value",
      ],
      [{ targetUrl: URL, assertions: [null] }, "non-object assertion"],
    ];
    for (const [rule, why] of bad) {
      assert.throws(
        () => assertValidResponseAssertionRule(rule, "rule"),
        RangeError,
        `should reject: ${why}`
      );
    }
  });

  it("validates single assertions directly", () => {
    assertValidResponseAssertion({ path: "$.a[0]", op: "gte", value: 3 }, "a");
    // Unknown extra fields are tolerated (lenient — only known fields
    // are validated).
    assertValidResponseAssertion({ path: "$.a", op: "eq", value: 1, extra: 1 } as never, "a");
  });
});

describe("WR-118 status whitelist", () => {
  it("defaults to all 2xx", () => {
    const rule: ResponseAssertionRule = { targetUrl: URL };
    assert.ok(isResponseStatusWhitelisted(200, rule));
    assert.ok(isResponseStatusWhitelisted(299, rule));
    assert.ok(!isResponseStatusWhitelisted(199, rule));
    assert.ok(!isResponseStatusWhitelisted(300, rule));
    assert.ok(!isResponseStatusWhitelisted(404, rule));
  });

  it("honors an explicit whitelist", () => {
    const rule: ResponseAssertionRule = { targetUrl: URL, expectedStatuses: [200, 201] };
    assert.ok(isResponseStatusWhitelisted(201, rule));
    assert.ok(!isResponseStatusWhitelisted(202, rule));
    assert.ok(!isResponseStatusWhitelisted(500, rule));
  });
});

describe("WR-118 failure classification", () => {
  it("AssertionFailedError classifies as assertion_failed and stays retryable", () => {
    const err = new AssertionFailedError(URL, "expected $.status === \"ok\"", 200);
    assert.equal(err.name, "AssertionFailedError");
    const classified = classifyFailure(err);
    assert.equal(classified.failureClass, "assertion_failed");
    assert.equal(classified.statusCode, 200);
  });

  it("classifyFailure without a status code omits it", () => {
    const classified = classifyFailure(new AssertionFailedError(URL, "nope"));
    assert.equal(classified.failureClass, "assertion_failed");
    assert.equal(classified.statusCode, undefined);
  });
});

describe("WR-118 queue construction", () => {
  it("rejects a non-array responseAssertions with TypeError", () => {
    assert.throws(
      () => new RetryQueue({ responseAssertions: { x: 1 } as never }),
      TypeError
    );
  });

  it("rejects duplicate targetUrl rules with RangeError", () => {
    assert.throws(
      () =>
        new RetryQueue({
          responseAssertions: [
            { targetUrl: URL, assertions: [{ path: "$.a", op: "eq", value: 1 }] },
            { targetUrl: URL, assertions: [{ path: "$.b", op: "eq", value: 2 }] },
          ],
        }),
      RangeError
    );
  });

  it("applies zero partial application: one bad rule fails the whole option", () => {
    assert.throws(
      () =>
        new RetryQueue({
          responseAssertions: [
            { targetUrl: URL, assertions: [{ path: "$.a", op: "eq", value: 1 }] },
            { targetUrl: URL_OTHER, assertions: [{ path: "broken", op: "eq", value: 1 }] },
          ],
        }),
      RangeError
    );
  });
});

describe("WR-118 end-to-end: assertion failure retries, then delivers", () => {
  it("retries on assertion failure and delivers on the 3rd attempt", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    const assertionFailures: AssertionFailureInfo[] = [];
    let delivered = 0;
    const q = new RetryQueue({
      sender: scriptedSender([json({ status: "error" }), json({ status: "error" }), json({ status: "ok" })], calls),
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseAssertions: [
        { targetUrl: URL, assertions: [{ path: "$.status", op: "eq", value: "ok" }] },
      ],
      onAssertionFailure: (info) => assertionFailures.push(info),
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();

    assert.equal(calls.count, 3);
    assert.equal(delivered, 1);
    assert.equal(q.getDeadLetter().length, 0);
    // Two assertion failures, one per failed attempt.
    assert.equal(assertionFailures.length, 2);
    assert.equal(assertionFailures[0]?.endpoint, URL);
    assert.equal(assertionFailures[0]?.attempts, 1);
    assert.match(assertionFailures[0]?.reason ?? "", /\$\.status/);
    // Per-endpoint counters are visible via getDeliveryStats.
    const stats = q.getDeliveryStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0]?.endpoint, URL);
    assert.equal(stats[0]?.assertionFailures, 2);
    assert.equal(stats[0]?.delivered, 1);
    assert.equal(stats[0]?.failed, 2);
    assert.equal(stats[0]?.retried, 2);
    assert.equal(stats[0]?.tenant, undefined);
    // Prometheus exposes the counter.
    const metrics = q.renderMetrics();
    assert.match(
      metrics,
      new RegExp(`relay_assertion_failures_total\\{endpoint="${URL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"\\} 2`)
    );
    q.stop();
  });

  it("dead-letters with failure_class=assertion_failed when every attempt fails", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    let deadLetterClass: string | undefined;
    const q = new RetryQueue({
      sender: scriptedSender([json({ status: "error" })], calls),
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseAssertions: [
        { targetUrl: URL, assertions: [{ path: "$.status", op: "eq", value: "ok" }] },
      ],
      onDeadLetter: (_item, _attempts, _err, failureClass) => {
        deadLetterClass = failureClass;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();

    assert.equal(calls.count, 3);
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0]?.failureClass, "assertion_failed");
    // The audit-facing hook carries the same class — this is what the
    // `dead_letter` audit event's `failure_class` reports.
    assert.equal(deadLetterClass, "assertion_failed");
    assert.match(dead[0]?.lastError ?? "", /failed assertion/);
    const stats = q.getDeliveryStats();
    assert.equal(stats[0]?.assertionFailures, 3);
    assert.equal(stats[0]?.deadLetter, 1);
    q.stop();
  });

  it("fails closed on a corrupt JSON body", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    const assertionFailures: AssertionFailureInfo[] = [];
    let delivered = 0;
    const q = new RetryQueue({
      sender: scriptedSender(
        [Buffer.from("{corrupt"), Buffer.from("{corrupt"), json({ status: "ok" })],
        calls
      ),
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseAssertions: [
        { targetUrl: URL, assertions: [{ path: "$.status", op: "eq", value: "ok" }] },
      ],
      onAssertionFailure: (info) => assertionFailures.push(info),
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();

    assert.equal(calls.count, 3);
    assert.equal(delivered, 1);
    assert.equal(assertionFailures.length, 2);
    assert.match(assertionFailures[0]?.reason ?? "", /not JSON/);
    assert.equal(q.getDeliveryStats()[0]?.assertionFailures, 2);
    q.stop();
  });

  it("a 404 still classifies as before: no assertions run, no assertion counter", async () => {
    const timer = manualTimer();
    let delivered = 0;
    const assertionFailures: AssertionFailureInfo[] = [];
    const q = new RetryQueue({
      // A custom sender that answers 404 without throwing — the default
      // sender would throw HttpDeliveryError here.
      sender: async () => ({ statusCode: 404, body: json({ status: "ok" }), truncated: false }),
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseAssertions: [
        { targetUrl: URL, assertions: [{ path: "$.status", op: "eq", value: "ok" }] },
      ],
      onAssertionFailure: (info) => assertionFailures.push(info),
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();

    assert.equal(delivered, 0);
    assert.equal(assertionFailures.length, 0);
    // WR-30: a 404 is non_retryable — dead-lettered on the first attempt.
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0]?.failureClass, "non_retryable");
    const stats = q.getDeliveryStats();
    assert.equal(stats[0]?.assertionFailures, 0);
    q.stop();
  });

  it("a non-whitelisted 5xx from a custom sender keeps the WR-30 retryable path", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    const assertionFailures: AssertionFailureInfo[] = [];
    const sender: Sender = async () => {
      calls.count += 1;
      return { statusCode: 500, body: Buffer.from("boom"), truncated: false };
    };
    const q = new RetryQueue({
      sender,
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseAssertions: [{ targetUrl: URL, expectedStatuses: [200] }],
      onAssertionFailure: (info) => assertionFailures.push(info),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();

    // Retried (5xx is retryable), never counted as an assertion failure.
    assert.equal(calls.count, 2);
    assert.equal(assertionFailures.length, 0);
    assert.equal(q.getDeliveryStats()[0]?.assertionFailures, 0);
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0]?.failureClass, "retryable");
    q.stop();
  });

  it("endpoints without a rule keep byte-exact current behavior", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    let delivered = 0;
    const q = new RetryQueue({
      sender: scriptedSender([json({ status: "error" })], calls),
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseAssertions: [
        { targetUrl: URL_OTHER, assertions: [{ path: "$.status", op: "eq", value: "ok" }] },
      ],
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();

    // The body says "error" but no rule applies to URL — delivered once.
    assert.equal(calls.count, 1);
    assert.equal(delivered, 1);
    assert.equal(q.getDeliveryStats()[0]?.assertionFailures, 0);
    q.stop();
  });

  it("a void sender skips assertions (nothing to evaluate)", async () => {
    const timer = manualTimer();
    let delivered = 0;
    const assertionFailures: AssertionFailureInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseAssertions: [
        { targetUrl: URL, assertions: [{ path: "$.status", op: "eq", value: "ok" }] },
      ],
      onAssertionFailure: (info) => assertionFailures.push(info),
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();

    assert.equal(delivered, 1);
    assert.equal(assertionFailures.length, 0);
    q.stop();
  });

  it("no rule configured: /metrics has no assertion series", () => {
    const q = new RetryQueue({ sender: async () => {}, jitterMs: 0 });
    assert.ok(!q.renderMetrics().includes("assertion"));
    assert.deepEqual(q.getDeliveryStats(), []);
    q.stop();
  });
});
