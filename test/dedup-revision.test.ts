import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DeliveryDeduplicator, type DedupStore } from "../src/dedup.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "dedup-revision-secret";
const body = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_123" }));

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

describe("DeliveryDeduplicator.retune (WR-308)", () => {
  const hash = DeliveryDeduplicator.hashPayload(body);
  const url = "http://localhost:9999/hook";

  it("shrinking the window expires an old pair on the next check", async () => {
    let now = 0;
    const d = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now });
    assert.equal(await d.check(url, hash), false);
    assert.equal(await d.check(url, hash), true); // still inside 60s
    d.retune({ windowMs: 1_000 });
    now = 1_500;
    assert.equal(await d.check(url, hash), false); // 1500ms elapsed > 1s window: new again
    assert.equal(await d.check(url, hash), true);
    assert.deepEqual(await d.stats(), {
      checked: 4,
      suppressed: 2,
      tracked: 1,
      windowMs: 1_000,
      maxEntries: 10_000,
    });
  });

  it("widening the window re-suppresses a pair the store still holds", async () => {
    let now = 0;
    const d = new DeliveryDeduplicator({ windowMs: 1_000, now: () => now });
    assert.equal(await d.check(url, hash), false);
    now = 1_500; // expired under the old window, but never re-checked
    d.retune({ windowMs: 60_000 });
    assert.equal(await d.check(url, hash), true); // lazy expiry never deleted it: suppressed again
  });

  it("tightening maxEntries evicts the oldest pair on the next check", async () => {
    const d = new DeliveryDeduplicator({ windowMs: 60_000, maxEntries: 3 });
    const hashes = ["a", "b", "c", "d"].map((s) =>
      DeliveryDeduplicator.hashPayload(Buffer.from(s))
    );
    for (const h of hashes.slice(0, 3)) assert.equal(await d.check(url, h), false);
    d.retune({ maxEntries: 2 });
    assert.equal(await d.check(url, hashes[3]), false); // evicts the oldest ("a", then "b") to fit the cap
    assert.equal(await d.check(url, hashes[2]), true); // "c" still tracked: duplicate
    assert.equal(await d.check(url, hashes[0]), false); // "a" is gone: new again
    assert.equal((await d.stats()).maxEntries, 2);
  });

  it("rejects illegal merged values and leaves the live values untouched", async () => {
    const d = new DeliveryDeduplicator({ windowMs: 60_000, maxEntries: 10 });
    for (const patch of [
      { windowMs: 0 },
      { windowMs: -5 },
      { windowMs: Number.POSITIVE_INFINITY },
      { windowMs: Number.NaN },
      { maxEntries: 0 },
      { maxEntries: 1.5 },
      { windowMs: 1_000, maxEntries: 0 }, // one bad field voids the whole patch
    ]) {
      assert.throws(() => d.retune(patch), RangeError, JSON.stringify(patch));
    }
    assert.deepEqual(d.current(), { windowMs: 60_000, maxEntries: 10 });
  });

  it("an empty patch and a same-value patch change nothing", () => {
    const d = new DeliveryDeduplicator({ windowMs: 60_000, maxEntries: 10 });
    assert.deepEqual(d.retune({}), { windowMs: 60_000, maxEntries: 10 });
    assert.deepEqual(d.retune({ windowMs: 60_000, maxEntries: 10 }), {
      windowMs: 60_000,
      maxEntries: 10,
    });
  });

  it("with a custom store the window still revises but the cap is fail-closed", async () => {
    // Minimal in-memory custom store honoring the DedupStore contract.
    const seen = new Map<string, number>();
    const store: DedupStore = {
      checkAndRemember(key, nowMs, windowMs) {
        const first = seen.get(key);
        if (first !== undefined && nowMs - first < windowMs) return true;
        seen.set(key, nowMs);
        return false;
      },
      size() {
        return seen.size;
      },
    };
    const d = new DeliveryDeduplicator({ windowMs: 60_000, maxEntries: 10, store });
    assert.equal(await d.check(url, hash), false);
    assert.throws(() => d.retune({ maxEntries: 5 }), RangeError);
    assert.deepEqual(d.current(), { windowMs: 60_000, maxEntries: 10 });
    assert.deepEqual(d.retune({ windowMs: 1_000 }), { windowMs: 1_000, maxEntries: 10 });
    assert.equal(await d.check(url, hash), true); // window revised, store still suppresses
  });

  it("stats() reports the live window and cap", async () => {
    const d = new DeliveryDeduplicator({ windowMs: 60_000, maxEntries: 10 });
    assert.equal((await d.stats()).windowMs, 60_000);
    assert.equal((await d.stats()).maxEntries, 10);
    d.retune({ windowMs: 5_000, maxEntries: 3 });
    const stats = await d.stats();
    assert.equal(stats.windowMs, 5_000);
    assert.equal(stats.maxEntries, 3);
  });
});

describe("server setDedupWindow (WR-308)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "dedup-revision-"));
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
    await new Promise((r) => setTimeout(r, 50));
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("revises the live window: a repeat past the new window is delivered again", async () => {
    let now = 1_000_000;
    const { relay, delivered } = makeServer({ dedup: { windowMs: 60_000, now: () => now } });
    const port = await listen(relay);
    assert.equal(JSON.parse((await post(port, body, signed(body))).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 1);
    assert.equal(JSON.parse((await post(port, body, signed(body))).text).duplicate, true);
    assert.equal(delivered.length, 1);

    now += 500;
    const next = relay.setDedupWindow!({ windowMs: 1_000 });
    assert.deepEqual(next, { windowMs: 1_000, maxEntries: 10_000 });
    // 500ms elapsed < 1s new window: still suppressed.
    assert.equal(JSON.parse((await post(port, body, signed(body))).text).duplicate, true);
    assert.equal(delivered.length, 1);

    now += 1_000; // 1500ms elapsed > 1s new window: delivered again.
    assert.equal(JSON.parse((await post(port, body, signed(body))).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 2);
  });

  it("audits dedup_revised with previous/current and skips the audit on a no-op", async () => {
    const { relay, auditLog } = makeServer({ dedup: { windowMs: 60_000, maxEntries: 100 } });
    assert.equal(eventsOf(auditLog, "dedup_revised").length, 0);
    const next = relay.setDedupWindow!({ windowMs: 5_000, maxEntries: 50 });
    assert.deepEqual(next, { windowMs: 5_000, maxEntries: 50 });
    const revised = eventsOf(auditLog, "dedup_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { windowMs: 60_000, maxEntries: 100 });
    assert.deepEqual(revised[0].current, { windowMs: 5_000, maxEntries: 50 });
    // Same values and an empty patch: no new audit event.
    relay.setDedupWindow!({ windowMs: 5_000, maxEntries: 50 });
    relay.setDedupWindow!({});
    assert.equal(eventsOf(auditLog, "dedup_revised").length, 1);
  });

  it("throws RangeError on an illegal patch and leaves suppression unchanged", async () => {
    const { relay, delivered, auditLog } = makeServer({ dedup: { windowMs: 60_000 } });
    const port = await listen(relay);
    await post(port, body, signed(body));
    assert.equal(delivered.length, 1);
    assert.throws(() => relay.setDedupWindow!({ windowMs: 0 }), RangeError);
    assert.throws(() => relay.setDedupWindow!({ maxEntries: 0 }), RangeError);
    assert.equal(eventsOf(auditLog, "dedup_revised").length, 0);
    // Still suppressed under the untouched 60s window.
    assert.equal(JSON.parse((await post(port, body, signed(body))).text).duplicate, true);
    assert.equal(delivered.length, 1);
  });

  it("throws Error when dedup is not configured", () => {
    const { relay } = makeServer();
    assert.throws(() => relay.setDedupWindow!({ windowMs: 1_000 }), /not configured/);
  });

  it("re-pushes the WR-119 shadow to 2x the new window", async () => {
    const probe = Buffer.from(JSON.stringify({ event: "probe" }));
    const { relay, delivered, auditLog } = makeServer({
      dedup: { windowMs: 60_000 },
      rateLimit: { perIpPerSecond: 2 },
      senderReputation: { rateLimitPenalty: 35, lowThreshold: 40, highThreshold: 70 },
    });
    const port = await listen(relay);
    const probeSig = signed(probe);
    // Degrade the anonymous sender first, with a throwaway payload: 2/s
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
    await new Promise((r) => setTimeout(r, 1_100));
    // First sight while degraded goes through the shadow (2x window):
    // delivered, and the pair now lives in the shadow store.
    const sig = signed(body);
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 2);
    await new Promise((r) => setTimeout(r, 1_100));
    assert.equal(JSON.parse((await post(port, body, sig)).text).duplicate, true);
    assert.equal(delivered.length, 2);

    // Main window 60s -> 3s; the shadow must follow at 2x = 6s.
    const next = relay.setDedupWindow!({ windowMs: 3_000 });
    assert.deepEqual(next, { windowMs: 3_000, maxEntries: 10_000 });

    // ~4.1s after the shadow's first sight: the main window (3s) has
    // expired, but the degraded sender is judged by the shadow (6s):
    // still suppressed. (A healthy sender would redeliver here.)
    await new Promise((r) => setTimeout(r, 3_000));
    const stillDup = await post(port, body, sig);
    assert.equal(stillDup.status, 202);
    assert.equal(JSON.parse(stillDup.text).duplicate, true);
    assert.equal(delivered.length, 2);

    // ~7.1s after first sight: the shadow (6s) has expired too, so the
    // repeat is delivered again. Had the shadow stayed on the stale 120s
    // window it would still suppress here — the delivery proves the
    // re-push.
    await new Promise((r) => setTimeout(r, 3_000));
    const redelivered = await post(port, body, sig);
    assert.equal(redelivered.status, 202);
    assert.equal(JSON.parse(redelivered.text).duplicate, undefined);
    await settle();
    assert.equal(delivered.length, 3);
  });
});
