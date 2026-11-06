import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createHedgedSender,
  HedgeCancelledError,
  HedgeMetrics,
  type HedgeAuditEvent,
} from "../src/hedged.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import type { DownstreamResponse, RetryItem, Sender } from "../src/retry.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "hedged-revision-test-key";
const opToken = "hedged-revision-op-token";
const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";
const URL_C = "http://localhost:9999/c";

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

async function waitFor(cond: () => boolean, label: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("HedgedSender live hedge-delay revision (WR-336)", () => {
  it("retune moves the next dispatch's hedge timer to the new delay", async () => {
    const { inner, calls } = stubSender((call, signal) => delayed(call === 0 ? 10_000 : 5, signal));
    const metrics = new HedgeMetrics();
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 1000,
      hedgeable: () => true,
      metrics,
      onHedge: (e) => audits.push(e),
    });
    assert.equal(sender.retuneHedgeDelayMs!(30), 30);
    const start = Date.now();
    const res = await sender(item(URL_A));
    const elapsed = Date.now() - start;
    // The hedge fired on the new 30ms delay, not the construction 1000ms.
    assert.ok(elapsed < 500, `elapsed=${elapsed}`);
    assert.equal(res?.statusCode, 200);
    assert.equal(res?.hedged, true);
    assert.equal(calls.length, 2);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].hedgeDelayMs, 30);
    assert.match(metrics.render(), /relay_hedged_total\{endpoint="http:\/\/localhost:9999\/a"\} 1/);
  });

  it("loosening the delay fires the hedge later", async () => {
    const { inner, calls } = stubSender((call, signal) => delayed(call === 0 ? 10_000 : 5, signal));
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 40,
      hedgeable: () => true,
      onHedge: (e) => audits.push(e),
    });
    sender.retuneHedgeDelayMs!(300);
    const start = Date.now();
    const res = await sender(item(URL_A));
    const elapsed = Date.now() - start;
    // Had the old 40ms delay survived, the hedge would have fired at ~40ms.
    assert.ok(elapsed >= 250, `hedge fired too early: elapsed=${elapsed}`);
    assert.ok(elapsed < 2000, `elapsed=${elapsed}`);
    assert.equal(res?.hedged, true);
    assert.equal(calls.length, 2);
    assert.equal(audits[0].hedgeDelayMs, 300);
  });

  it("illegal retune throws RangeError and leaves the live value untouched", async () => {
    const { inner, calls } = stubSender((call, signal) => delayed(call === 0 ? 10_000 : 5, signal));
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 60,
      hedgeable: () => true,
      onHedge: (e) => audits.push(e),
    });
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "100" as never]) {
      assert.throws(
        () => sender.retuneHedgeDelayMs!(bad as never),
        (err: unknown) =>
          err instanceof RangeError &&
          /hedgeDelayMs must be a positive integer of milliseconds/.test(err.message),
        `bad value ${String(bad)}`
      );
    }
    assert.equal(sender.currentHedgeDelayMs!(), 60);
    // The next dispatch still hedges on the untouched 60ms delay.
    const res = await sender(item(URL_A));
    assert.equal(res?.hedged, true);
    assert.equal(calls.length, 2);
    assert.equal(audits[0].hedgeDelayMs, 60);
  });

  it("an already-armed timer still fires on the old delay after revision", async () => {
    const { inner, calls } = stubSender((call, signal) => delayed(call === 0 ? 10_000 : 5, signal));
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 60,
      hedgeable: () => true,
      onHedge: (e) => audits.push(e),
    });
    const p = sender(item(URL_A));
    // Revise mid-flight, long after the timer was armed.
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(sender.retuneHedgeDelayMs!(5000), 5000);
    // The hedge must still fire at ~60ms from dispatch — if the revision
    // had re-armed the timer this would time out at 1000ms. The audit
    // event itself reads the live cell at fire time, so it carries the
    // revised 5000 even though the timer ran on the old 60ms delay.
    await waitFor(() => calls.length === 2, "hedge fires on the old delay", 1000);
    const res = await p;
    assert.equal(res?.hedged, true);
    assert.equal(audits[0].hedgeDelayMs, 5000);
  });

  it("post-revision hedge audit event carries the new hedgeDelayMs", async () => {
    const { inner } = stubSender((call, signal) => delayed(call === 0 ? 10_000 : 5, signal));
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 250,
      hedgeable: () => true,
      onHedge: (e) => audits.push(e),
    });
    sender.retuneHedgeDelayMs!(45);
    await sender(item(URL_A));
    assert.equal(audits.length, 1);
    assert.equal(audits[0].event, "hedged");
    assert.equal(audits[0].endpoint, URL_A);
    assert.equal(audits[0].hedgeDelayMs, 45);
  });

  it("first-hit-wins still settles normally after revision", async () => {
    const { inner, calls } = stubSender((call, signal) => delayed(call === 0 ? 5 : 10_000, signal));
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 30,
      hedgeable: () => true,
      onHedge: (e) => audits.push(e),
    });
    sender.retuneHedgeDelayMs!(200);
    const res = await sender(item(URL_A));
    assert.equal(res?.statusCode, 200);
    assert.equal(res?.hedged, undefined);
    assert.equal(calls.length, 1);
    assert.equal(sender.takeHedgedFlag?.("dlv-1"), false);
    // The primary won before the (loosened) hedge timer fired: no hedge
    // appears even after the old delay has passed.
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(calls.length, 1);
    assert.equal(audits.length, 0);
  });

  it("relay_hedged_total keeps accumulating across revisions", async () => {
    const { inner } = stubSender((call, signal) => delayed(call % 2 === 0 ? 10_000 : 5, signal));
    const metrics = new HedgeMetrics();
    const audits: HedgeAuditEvent[] = [];
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 30,
      hedgeable: () => true,
      metrics,
      onHedge: (e) => audits.push(e),
    });
    await sender(item(URL_A, "dlv-1"));
    sender.retuneHedgeDelayMs!(50);
    await sender(item(URL_A, "dlv-2"));
    assert.match(metrics.render(), /relay_hedged_total\{endpoint="http:\/\/localhost:9999\/a"\} 2/);
    assert.equal(audits.length, 2);
    assert.equal(audits[0].hedgeDelayMs, 30);
    assert.equal(audits[1].hedgeDelayMs, 50);
  });

  it("revision does not affect non-hedgeable endpoints; one value moves all hedgeable endpoints", async () => {
    const metrics = new HedgeMetrics();
    const audits: HedgeAuditEvent[] = [];
    const hedgeable = (it: RetryItem) => it.targetUrl === URL_A || it.targetUrl === URL_C;
    // Hedgeable primaries hang; the hedge answers fast (odd calls).
    const { inner } = stubSender((call, signal) => delayed(call % 2 === 0 ? 10_000 : 5, signal));
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 250,
      hedgeable,
      metrics,
      onHedge: (e) => audits.push(e),
    });
    sender.retuneHedgeDelayMs!(30);
    // Non-hedgeable endpoint: its primary answers on its own, no hedge
    // even though the (retuned) delay has long passed.
    const { inner: innerB, calls: callsB } = stubSender((_call, signal) => delayed(200, signal));
    const senderB = createHedgedSender(innerB, {
      enabled: true,
      hedgeDelayMs: 30,
      hedgeable,
      onHedge: (e) => audits.push(e),
    });
    const resB = await senderB(item(URL_B));
    assert.equal(resB?.statusCode, 200);
    assert.equal(resB?.hedged, undefined);
    assert.equal(callsB.length, 1);
    assert.equal(audits.length, 0);
    // Both hedgeable endpoints hedge on the single revised value.
    await sender(item(URL_A, "dlv-a"));
    await sender(item(URL_C, "dlv-c"));
    assert.equal(audits.length, 2);
    assert.deepEqual(
      audits.map((e) => e.endpoint),
      [URL_A, URL_C]
    );
    assert.ok(audits.every((e) => e.hedgeDelayMs === 30));
    assert.match(metrics.render(), /relay_hedged_total\{endpoint="http:\/\/localhost:9999\/a"\} 1/);
    assert.match(metrics.render(), /relay_hedged_total\{endpoint="http:\/\/localhost:9999\/c"\} 1/);
  });

  it("currentHedgeDelayMs tracks retunes and retune returns the revised value", () => {
    const { inner } = stubSender(() => Promise.resolve(okResponse()));
    const sender = createHedgedSender(inner, {
      enabled: true,
      hedgeDelayMs: 250,
      hedgeable: () => true,
    });
    assert.equal(sender.currentHedgeDelayMs!(), 250);
    assert.equal(sender.retuneHedgeDelayMs!(100), 100);
    assert.equal(sender.currentHedgeDelayMs!(), 100);
    // A same-value retune is accepted and returns the live value.
    assert.equal(sender.retuneHedgeDelayMs!(100), 100);
    assert.equal(sender.currentHedgeDelayMs!(), 100);
  });
});

describe("RelayServer hedge-delay revision (WR-336)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "hedged-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL_A,
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
      hedgedRequests: { enabled: true, hedgeDelayMs: 250, hedgeableEndpoints: [URL_A] },
    });
    await listen(relay);
    assert.equal(relay.getHedgeDelayMs!(), 250);
    assert.equal(relay.reviseHedgeDelayMs!(100), 100);
    const revised = eventsOf(audit, "hedge_delay_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, 250);
    assert.equal(revised[0].current, 100);
    // Landing exactly on the live value audits nothing.
    assert.equal(relay.reviseHedgeDelayMs!(100), 100);
    assert.equal(eventsOf(audit, "hedge_delay_revised").length, 1);
    assert.equal(relay.getHedgeDelayMs!(), 100);
    // An illegal value throws RangeError and leaves live value and audit untouched.
    assert.throws(() => relay.reviseHedgeDelayMs!(0), RangeError);
    assert.throws(() => relay.reviseHedgeDelayMs!(2.5), RangeError);
    assert.equal(eventsOf(audit, "hedge_delay_revised").length, 1);
    assert.equal(relay.getHedgeDelayMs!(), 100);
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter returns undefined", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getHedgeDelayMs!(), undefined);
    assert.throws(
      () => relay.reviseHedgeDelayMs!(100),
      /not configured — enabling them requires a restart/
    );
    assert.throws(
      () => relay.reviseHedgeDelayMs!(100),
      /cannot start hedging without one/
    );
    // `enabled: false` is equivalent to the block not being passed.
    const disabled = makeRelay({
      hedgedRequests: { enabled: false, hedgeDelayMs: 250, hedgeableEndpoints: [URL_A] },
    });
    await listen(disabled.relay);
    assert.equal(disabled.relay.getHedgeDelayMs!(), undefined);
    assert.throws(
      () => disabled.relay.reviseHedgeDelayMs!(100),
      /not configured — enabling them requires a restart/
    );
  });

  it("enabled-but-nothing-hedgeable revision still takes effect", async () => {
    const { relay, audit } = makeRelay({
      hedgedRequests: { enabled: true, hedgeDelayMs: 250 },
    });
    await listen(relay);
    assert.equal(relay.getHedgeDelayMs!(), 250);
    assert.equal(relay.reviseHedgeDelayMs!(80), 80);
    assert.equal(relay.getHedgeDelayMs!(), 80);
    const revised = eventsOf(audit, "hedge_delay_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, 250);
    assert.equal(revised[0].current, 80);
  });
});
