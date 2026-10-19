import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import {
  createHedgedSender,
  HedgeCancelledError,
  HedgeMetrics,
  assertValidHedgedSenderOptions,
  type HedgeAuditEvent,
  type HedgedSenderOptions,
} from "../src/hedged.ts";
import { createDefaultSender } from "../src/server.ts";
import { HttpDeliveryError } from "../src/failure.ts";
import type { DownstreamResponse, RetryItem, Sender, SenderCallOptions } from "../src/retry.ts";

const item = (targetUrl: string, id = "dlv-1"): RetryItem => ({
  id,
  payload: Buffer.from(JSON.stringify({ event: "push" })),
  targetUrl,
  headers: { "content-type": "application/json" },
  traceId: "trace-1",
});

const okResponse = (): DownstreamResponse => ({
  statusCode: 200,
  body: Buffer.from("ok"),
  truncated: false,
});

/** A controllable stub inner sender. */
function stubSender(behavior: (call: number, signal: AbortSignal | undefined) => Promise<DownstreamResponse | void>) {
  const calls: Array<{ signal: AbortSignal | undefined }> = [];
  let n = 0;
  const inner: Sender = (_item, opts) => {
    const call = n++;
    calls.push({ signal: opts?.signal });
    return behavior(call, opts?.signal);
  };
  return { inner, calls };
}

/** Resolve after `ms` unless aborted. */
function delayed(ms: number, signal: AbortSignal | undefined): Promise<DownstreamResponse> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => resolve(okResponse()), ms);
    t.unref?.();
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new HedgeCancelledError("stub"));
      },
      { once: true }
    );
  });
}

describe("hedged requests (WR-146)", () => {
  it("validation: RangeError on non-positive/non-integer hedgeDelayMs", () => {
    for (const bad of [0, -50, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(
        () => assertValidHedgedSenderOptions({ enabled: true, hedgeDelayMs: bad }),
        RangeError
      );
    }
    assert.doesNotThrow(() => assertValidHedgedSenderOptions({ enabled: true, hedgeDelayMs: 1 }));
  });

  it("fast downstream: no hedge, single attempt", async () => {
    const { inner, calls } = stubSender(() => Promise.resolve(okResponse()));
    const metrics = new HedgeMetrics();
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 60,
      hedgeable: () => true,
      metrics,
      onHedge: (e) => audits.push(e),
    });
    const res = await sender(item("http://127.0.0.1:1/hook"));
    assert.equal(res?.statusCode, 200);
    assert.equal(res?.hedged, undefined);
    assert.equal(calls.length, 1);
    assert.equal(metrics.render(), "");
    assert.equal(audits.length, 0);
    assert.equal(sender.takeHedgedFlag?.("dlv-1"), false);
  });

  it("slow downstream: hedge fires, first settler wins, loser cancelled", async () => {
    const aborted: number[] = [];
    const { inner, calls } = stubSender((call, signal) => {
      // Primary hangs; the hedge answers fast.
      const p = delayed(call === 0 ? 10_000 : 5, signal);
      p.catch(() => aborted.push(call));
      return p;
    });
    const metrics = new HedgeMetrics();
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 60,
      hedgeable: () => true,
      metrics,
      onHedge: (e) => audits.push(e),
    });
    const start = Date.now();
    const res = await sender(item("http://127.0.0.1:1/hook"));
    const elapsed = Date.now() - start;
    // The hedge won — the delivery resolved far sooner than the primary's 10s.
    assert.ok(elapsed < 5_000, `elapsed=${elapsed}`);
    assert.equal(res?.statusCode, 200);
    assert.equal(res?.hedged, true);
    assert.equal(calls.length, 2);
    // The loser was cancelled through its AbortController.
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(aborted, [0]);
    // Metrics + audit + take-and-clear flag.
    assert.match(metrics.render(), /relay_hedged_total\{endpoint="http:\/\/127\.0\.0\.1:1\/hook"\} 1/);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].event, "hedged");
    assert.equal(audits[0].endpoint, "http://127.0.0.1:1/hook");
    assert.equal(audits[0].hedgeDelayMs, 60);
    assert.equal(sender.takeHedgedFlag?.("dlv-1"), true);
    assert.equal(sender.takeHedgedFlag?.("dlv-1"), false);
  });

  it("primary wins the race when it is merely slow: no loser leak", async () => {
    const { inner, calls } = stubSender((call, signal) => delayed(call === 0 ? 120 : 10_000, signal));
    const metrics = new HedgeMetrics();
    const sender = createHedgedSender(inner, { enabled: true, hedgeDelayMs: 60, hedgeable: () => true, metrics });
    const res = await sender(item("http://127.0.0.1:1/hook"));
    assert.equal(res?.statusCode, 200);
    assert.equal(res?.hedged, true);
    assert.equal(calls.length, 2);
    // The hedge (call 1) lost: its signal must have fired.
    assert.equal(calls[1].signal?.aborted, true);
    assert.equal(calls[0].signal?.aborted, false);
    assert.match(metrics.render(), /relay_hedged_total/);
  });

  it("non-hedgeable endpoint: never hedges, even when slow", async () => {
    const { inner, calls } = stubSender((_call, signal) => delayed(200, signal));
    const metrics = new HedgeMetrics();
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 60,
      hedgeable: (it) => it.targetUrl.includes("/idempotent"),
      metrics,
    });
    const res = await sender(item("http://127.0.0.1:1/non-idempotent"));
    assert.equal(res?.statusCode, 200);
    assert.equal(calls.length, 1);
    assert.equal(metrics.render(), "");
  });

  it("disabled: pure pass-through", async () => {
    const { inner, calls } = stubSender((_call, signal) => delayed(200, signal));
    const metrics = new HedgeMetrics();
    const sender = createHedgedSender(inner, { enabled: false, hedgeDelayMs: 60, hedgeable: () => true, metrics });
    const res = await sender(item("http://127.0.0.1:1/hook"));
    assert.equal(res?.statusCode, 200);
    assert.equal(calls.length, 1);
    assert.equal(metrics.render(), "");
  });

  it("returned 429 settles the attempt: no hedge, error propagates for normal backoff", async () => {
    const { inner, calls } = stubSender(() =>
      Promise.reject(new HttpDeliveryError(429, 1000))
    );
    const metrics = new HedgeMetrics();
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 60,
      hedgeable: () => true,
      metrics,
      onHedge: (e) => audits.push(e),
    });
    await assert.rejects(sender(item("http://127.0.0.1:1/hook")), (err: unknown) => {
      assert.ok(err instanceof HttpDeliveryError);
      assert.equal(err.statusCode, 429);
      return true;
    });
    // The attempt settled at ~0ms: the hedge timer never got a chance.
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(calls.length, 1);
    assert.equal(metrics.render(), "");
    assert.equal(audits.length, 0);
  });

  it("slow-then-500: hedge still applies (latency-gated), the 500 propagates", async () => {
    const { inner, calls } = stubSender((call, signal) =>
      new Promise<DownstreamResponse>((_resolve, reject) => {
        const t = setTimeout(() => reject(new HttpDeliveryError(500)), call === 0 ? 10_000 : 5);
        t.unref?.();
        signal?.addEventListener("abort", () => {
          clearTimeout(t);
          reject(new HedgeCancelledError("stub"));
        }, { once: true });
      })
    );
    const metrics = new HedgeMetrics();
    const sender = createHedgedSender(inner, { enabled: true, hedgeDelayMs: 60, hedgeable: () => true, metrics });
    await assert.rejects(sender(item("http://127.0.0.1:1/hook")), (err: unknown) => {
      assert.ok(err instanceof HttpDeliveryError);
      assert.equal(err.statusCode, 500);
      return true;
    });
    // A hedge was launched (nothing had returned within 60ms); the 500
    // is just the winning attempt's normal error — no special handling.
    assert.equal(calls.length, 2);
    assert.match(metrics.render(), /relay_hedged_total/);
  });

  it("loser's late rejection is swallowed (no unhandled rejection)", async () => {
    const aborted: number[] = [];
    const { inner } = stubSender((call, signal) =>
      call === 0
        ? new Promise<DownstreamResponse>((_resolve, reject) => {
            // The loser would explode at 300ms if it were not aborted.
            const t = setTimeout(() => reject(new Error("late loser boom")), 300);
            t.unref?.();
            signal?.addEventListener(
              "abort",
              () => {
                aborted.push(call);
                clearTimeout(t);
                reject(new HedgeCancelledError("stub"));
              },
              { once: true }
            );
          })
        : Promise.resolve(okResponse())
    );
    const sender = createHedgedSender(inner, { enabled: true, hedgeDelayMs: 60, hedgeable: () => true });
    const res = await sender(item("http://127.0.0.1:1/hook"));
    assert.equal(res?.statusCode, 200);
    // Give the loser time to settle after being aborted; its late timer
    // must never have fired (and no unhandled rejection may escape).
    await new Promise((r) => setTimeout(r, 400));
    assert.deepEqual(aborted, [0]);
  });

  it("end-to-end: default sender cancels the losing HTTP request (stub observes the abort)", async () => {
    let requests = 0;
    let slowAborted = 0;
    let fastCompleted = 0;
    const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
      requests++;
      if (requests === 1) {
        // The primary: hang. When the hedge wins, the relay must destroy
        // this request — the stub observes the socket close.
        req.on("close", () => {
          if (!res.writableEnded) slowAborted++;
        });
        return; // never respond
      }
      fastCompleted++;
      res.writeHead(200, { "content-type": "text/plain" }).end("fast");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/hook`;
    try {
      const pooled = createDefaultSender();
      const metrics = new HedgeMetrics();
      const audits: HedgeAuditEvent[] = [];
      const sender = createHedgedSender(pooled, {
        enabled: true,
        hedgeDelayMs: 80,
        hedgeable: () => true,
        metrics,
        onHedge: (e) => audits.push(e),
      });
      const start = Date.now();
      const res = await sender(item(url));
      const elapsed = Date.now() - start;
      assert.equal(res?.statusCode, 200);
      assert.equal(res?.hedged, true);
      assert.ok(elapsed < 5_000, `elapsed=${elapsed}`);
      // The slow loser's connection was torn down by the relay.
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(requests, 2);
      assert.equal(fastCompleted, 1);
      assert.equal(slowAborted, 1);
      assert.match(metrics.render(), new RegExp(`relay_hedged_total\\{endpoint="${url.replace(/\//g, "\\/")}"\\} 1`));
      assert.equal(audits.length, 1);
      pooled.destroy();
    } finally {
      server.close();
    }
  });

  it("HedgeMetrics renders nothing until the first hedge (activity-gated)", () => {
    const m = new HedgeMetrics();
    assert.equal(m.render(), "");
    m.noteHedged("http://x/hook");
    m.noteHedged("http://x/hook");
    assert.match(m.render(), /relay_hedged_total\{endpoint="http:\/\/x\/hook"\} 2/);
    assert.deepEqual(m.stats(), [{ endpoint: "http://x/hook", hedges: 2 }]);
  });
});
