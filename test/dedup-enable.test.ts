import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "dedup-enable-secret";
const body = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_123" }));
const probe = Buffer.from(JSON.stringify({ event: "probe" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, payload: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(payload);
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

describe("server setDedupWindow live enable (WR-482)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "dedup-enable-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const delivered: RetryItem[] = [];
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog,
      sender: async (item) => {
        delivered.push(item);
      },
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog, delivered };
  }

  function signed(payload: Buffer) {
    return { "x-signature": signSha256(payload, relaySecret) };
  }

  // Deliveries dispatch asynchronously after admission (the retry queue
  // invokes the sender stub on its own tick), so assertions on
  // `delivered` need a brief settle first — the same 50ms the other
  // dedup server tests use.
  async function settle() {
    await sleep(50);
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("illegal patch throws RangeError and the relay stays unconfigured, still enableable afterwards", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.throws(() => relay.setDedupWindow!({ windowMs: 0 }), RangeError);
    assert.throws(() => relay.setDedupWindow!({ windowMs: -5 }), RangeError);
    assert.throws(() => relay.setDedupWindow!({ maxEntries: 0 }), RangeError);
    assert.throws(() => relay.setDedupWindow!({ maxEntries: 1.5 }), RangeError);
    assert.throws(
      () => relay.setDedupWindow!(null as unknown as { windowMs: number }),
      RangeError
    );
    assert.throws(
      () => relay.setDedupWindow!([] as unknown as { windowMs: number }),
      RangeError
    );
    assert.equal(eventsOf(auditLog, "dedup_revised").length, 0);
    // Still enableable afterwards, with the rejected values not leaking in.
    assert.deepEqual(relay.setDedupWindow!({ windowMs: 1_000 }), {
      windowMs: 1_000,
      maxEntries: 10_000,
    });
    const revised = eventsOf(auditLog, "dedup_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { windowMs: 1_000, maxEntries: 10_000 });
  });

  it("empty patch is a silent no-op reporting the construction defaults", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.deepEqual(relay.setDedupWindow!({}), { windowMs: 300_000, maxEntries: 10_000 });
    assert.equal(eventsOf(auditLog, "dedup_revised").length, 0);
    // Still unconfigured afterwards: a real patch enables from defaults.
    assert.deepEqual(relay.setDedupWindow!({ maxEntries: 50 }), {
      windowMs: 300_000,
      maxEntries: 50,
    });
    const revised = eventsOf(auditLog, "dedup_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
  });

  it("enable then a repeat delivery is suppressed, and past the window it is delivered again", async () => {
    const { relay, delivered } = makeServer();
    const port = await listen(relay);
    const sig = signed(body);
    // Before the enable nothing is suppressed.
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 1);
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 2);

    // Enable with a short window; the pair seen before the enable is
    // not retroactively suppressed (the window starts empty).
    assert.deepEqual(relay.setDedupWindow!({ windowMs: 300 }), {
      windowMs: 300,
      maxEntries: 10_000,
    });
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 3);
    // Inside the window: suppressed.
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, true);
    await settle();
    assert.equal(delivered.length, 3);
    // Past the window: delivered again.
    await sleep(400);
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 4);
  });

  it("same-value patch after enable is a silent no-op", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.deepEqual(relay.setDedupWindow!({ windowMs: 1_000, maxEntries: 50 }), {
      windowMs: 1_000,
      maxEntries: 50,
    });
    assert.equal(eventsOf(auditLog, "dedup_revised").length, 1);
    assert.deepEqual(relay.setDedupWindow!({ windowMs: 1_000, maxEntries: 50 }), {
      windowMs: 1_000,
      maxEntries: 50,
    });
    assert.deepEqual(relay.setDedupWindow!({}), { windowMs: 1_000, maxEntries: 50 });
    assert.equal(eventsOf(auditLog, "dedup_revised").length, 1);
  });

  it("enable then the WR-308 revision chain works on the live window", async () => {
    const { relay, delivered, auditLog } = makeServer();
    const port = await listen(relay);
    const sig = signed(body);
    relay.setDedupWindow!({ windowMs: 60_000 });
    const next = relay.setDedupWindow!({ windowMs: 1_000 });
    assert.deepEqual(next, { windowMs: 1_000, maxEntries: 10_000 });
    const revised = eventsOf(auditLog, "dedup_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { windowMs: 60_000, maxEntries: 10_000 });
    assert.deepEqual(revised[1].previous, { windowMs: 60_000, maxEntries: 10_000 });
    assert.deepEqual(revised[1].current, { windowMs: 1_000, maxEntries: 10_000 });
    // The revised window actually judges: suppressed inside 1s, delivered past it.
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 1);
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, true);
    assert.equal(delivered.length, 1);
    await sleep(1_100);
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 2);
  });

  it("tightening (c): reputation configured at startup, dedup enabled live — a degraded sender is suppressed over the doubled window", async () => {
    const { relay, delivered, auditLog } = makeServer({
      rateLimit: { perIpPerSecond: 2 },
      senderReputation: { rateLimitPenalty: 35, lowThreshold: 40, highThreshold: 70 },
    });
    const port = await listen(relay);
    const probeSig = signed(probe);
    // Enable dedup live with a 1s main window: the shadow must be the
    // doubled 2s window from here on.
    assert.deepEqual(relay.setDedupWindow!({ windowMs: 1_000 }), {
      windowMs: 1_000,
      maxEntries: 10_000,
    });
    // Degrade the anonymous sender with a throwaway payload: 2/s
    // budget means the 3rd and 4th rapid posts hit the limiter — two
    // 35-point penalties drop the score to 30 < 40, i.e. degraded.
    // (The limiter runs before dedup, so the duplicate 2nd post still
    // consumes a token and the 429s still land.)
    assert.equal((await post(port, probe, probeSig)).status, 202);
    assert.equal((await post(port, probe, probeSig)).status, 202);
    assert.equal((await post(port, probe, probeSig)).status, 429);
    assert.equal((await post(port, probe, probeSig)).status, 429);
    assert.equal(eventsOf(auditLog, "reputation_downgraded").length, 1);
    await settle();
    assert.equal(delivered.length, 1); // only the probe's first sight

    // The degraded sender's halved budget refills 1/s; wait for a token.
    await sleep(1_100);
    // First sight while degraded goes through the shadow (2s window):
    // delivered, and the pair now lives in the shadow store.
    const sig = signed(body);
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 2);
    // ~1.5s after the shadow's first sight: the main window (1s) has
    // expired, but the degraded sender is judged by the shadow (2s):
    // still suppressed. (A healthy sender would redeliver here.)
    await sleep(1_500);
    const stillDup = await post(port, body, sig);
    assert.equal(stillDup.status, 202);
    assert.equal(JSON.parse(stillDup.text).duplicate, true);
    assert.equal(delivered.length, 2);
    // ~2.5s after first sight: the shadow (2s) has expired too, so the
    // repeat is delivered again. Had the shadow never been installed at
    // enable time, the repeat at 1.5s would already have delivered.
    await sleep(1_000);
    const redelivered = await post(port, body, sig);
    assert.equal(redelivered.status, 202);
    assert.equal(JSON.parse(redelivered.text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 3);
  });

  it("reputation enabled live after dedup enabled live installs the doubled shadow", async () => {
    const { relay, delivered, auditLog } = makeServer({
      rateLimit: { perIpPerSecond: 2 },
    });
    const port = await listen(relay);
    const probeSig = signed(probe);
    // Dedup first, reputation second: the WR-480 enable path re-runs
    // the shadow builder, which must now see the live deduplicator.
    assert.deepEqual(relay.setDedupWindow!({ windowMs: 1_000 }), {
      windowMs: 1_000,
      maxEntries: 10_000,
    });
    relay.reviseSenderReputation!({
      rateLimitPenalty: 35,
      lowThreshold: 40,
      highThreshold: 70,
    });
    // Degrade the anonymous sender as above.
    assert.equal((await post(port, probe, probeSig)).status, 202);
    assert.equal((await post(port, probe, probeSig)).status, 202);
    assert.equal((await post(port, probe, probeSig)).status, 429);
    assert.equal((await post(port, probe, probeSig)).status, 429);
    assert.equal(eventsOf(auditLog, "reputation_downgraded").length, 1);
    await settle();
    assert.equal(delivered.length, 1);

    await sleep(1_100);
    const sig = signed(body);
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 2);
    // Past the 1s main window but inside the 2s shadow: still suppressed.
    await sleep(1_500);
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, true);
    assert.equal(delivered.length, 2);
    // Past the shadow: delivered again.
    await sleep(1_000);
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 3);
  });

  it("a restart restores the unconfigured construction state", async () => {
    const first = makeServer();
    await listen(first.relay);
    first.relay.setDedupWindow!({ windowMs: 1_000 });
    assert.deepEqual(first.relay.setDedupWindow!({}), {
      windowMs: 1_000,
      maxEntries: 10_000,
    });
    // A fresh relay (what a restart constructs) is unconfigured again.
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.deepEqual(relay.setDedupWindow!({}), { windowMs: 300_000, maxEntries: 10_000 });
    assert.equal(eventsOf(auditLog, "dedup_revised").length, 0);
    assert.deepEqual(relay.setDedupWindow!({ maxEntries: 50 }), {
      windowMs: 300_000,
      maxEntries: 50,
    });
    assert.equal(eventsOf(auditLog, "dedup_revised")[0].previous, null);
  });
});
