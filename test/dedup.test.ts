import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync, writeFileSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DeliveryDeduplicator, DEDUP_JOURNAL_FILE } from "../src/dedup.ts";
import { AesGcmEncryptor, randomAes256Key } from "../src/encrypt.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

const URL = "http://localhost:9999/hook";
const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_123" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
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
    r.end(body);
  });
}

describe("DeliveryDeduplicator", () => {
  it("hashPayload is deterministic and distinguishes payloads", () => {
    const a = DeliveryDeduplicator.hashPayload(BODY);
    const b = DeliveryDeduplicator.hashPayload(Buffer.from(BODY));
    const c = DeliveryDeduplicator.hashPayload(Buffer.from("different"));
    assert.equal(a, b);
    assert.notEqual(a, c);
    assert.match(a, /^[0-9a-f]{64}$/);
  });

  it("first sight is new, every repeat inside the window is a duplicate", async () => {
    let now = 0;
    const d = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now });
    const hash = DeliveryDeduplicator.hashPayload(BODY);
    assert.equal(await d.check(URL, hash), false);
    assert.equal(await d.check(URL, hash), true);
    assert.equal(await d.check(URL, hash), true); // every repeat stays suppressed
    assert.deepEqual(await d.stats(), { checked: 3, suppressed: 2, tracked: 1 });
  });

  it("different payloads and different endpoints are independent deliveries", async () => {
    const d = new DeliveryDeduplicator({ windowMs: 60_000 });
    const h1 = DeliveryDeduplicator.hashPayload(BODY);
    const h2 = DeliveryDeduplicator.hashPayload(Buffer.from("other"));
    assert.equal(await d.check(URL, h1), false);
    assert.equal(await d.check(URL, h2), false); // different payload
    assert.equal(await d.check(URL + "/b", h1), false); // different endpoint
    assert.equal((await d.stats()).tracked, 3);
  });

  it("a pair seen again after the window expires counts as new", async () => {
    let now = 0;
    const d = new DeliveryDeduplicator({ windowMs: 1000, now: () => now });
    const hash = DeliveryDeduplicator.hashPayload(BODY);
    assert.equal(await d.check(URL, hash), false);
    now = 999;
    assert.equal(await d.check(URL, hash), true); // still inside the window
    now = 1000;
    assert.equal(await d.check(URL, hash), false); // window elapsed: redeliver
    assert.equal(await d.check(URL, hash), true); // and the new window suppresses
    assert.equal((await d.stats()).tracked, 1); // expired entry replaced, not duplicated
  });

  it("oldest entries are evicted past maxEntries so memory stays bounded", async () => {
    const d = new DeliveryDeduplicator({ windowMs: 60_000, maxEntries: 2 });
    const hashes = ["a", "b", "c"].map((s) => DeliveryDeduplicator.hashPayload(Buffer.from(s)));
    assert.equal(await d.check(URL, hashes[0]), false);
    assert.equal(await d.check(URL, hashes[1]), false);
    assert.equal(await d.check(URL, hashes[2]), false); // evicts the oldest ("a")
    assert.equal((await d.stats()).tracked, 2);
    assert.equal(await d.check(URL, hashes[1]), true); // "b" still tracked: duplicate
    assert.equal(await d.check(URL, hashes[0]), false); // "a" was evicted: new again
  });

  it("rejects invalid configuration", () => {
    assert.throws(() => new DeliveryDeduplicator({ windowMs: 0 }), RangeError);
    assert.throws(() => new DeliveryDeduplicator({ windowMs: -5 }), RangeError);
    assert.throws(() => new DeliveryDeduplicator({ windowMs: Infinity }), RangeError);
    assert.throws(() => new DeliveryDeduplicator({ maxEntries: 0 }), RangeError);
    assert.throws(() => new DeliveryDeduplicator({ maxEntries: 1.5 }), RangeError);
  });
});

describe("server payload-hash dedup", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  async function makeServer(dedup?: { windowMs?: number; maxEntries?: number; journalDir?: string }) {
    const dir = mkdtempSync(join(tmpdir(), "dedup-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const delivered: RetryItem[] = [];
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog,
      sender: async (item) => {
        delivered.push(item);
      },
      ...(dedup ? { dedup } : {}),
    });
    const port = await listen(relay);
    servers.push(relay);
    return { port, delivered, auditLog };
  }

  function signed(body: Buffer) {
    return { "x-signature": signSha256(body, SECRET) };
  }

  it("suppresses a repeated payment callback: 202 duplicate:true, one delivery", async () => {
    const { port, delivered, auditLog } = await makeServer({ windowMs: 60_000 });
    const first = await post(port, BODY, signed(BODY));
    assert.equal(first.status, 202);
    assert.equal(JSON.parse(first.text).status, "accepted");
    assert.equal(JSON.parse(first.text).duplicate, undefined);
    const second = await post(port, BODY, signed(BODY));
    assert.equal(second.status, 202);
    const parsed = JSON.parse(second.text);
    assert.equal(parsed.status, "accepted");
    assert.equal(parsed.duplicate, true);
    // The duplicate is acknowledged but never delivered — no double charge.
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(delivered.length, 1);
    const events = auditLog.query({ event: ["accepted", "duplicate_suppressed"] });
    assert.ok(events.some((e) => (e as { event: string }).event === "accepted"));
    assert.ok(events.some((e) => (e as { event: string }).event === "duplicate_suppressed"));
  });

  it("a different payload is a different event and is delivered", async () => {
    const { port, delivered } = await makeServer({ windowMs: 60_000 });
    const other = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_456" }));
    await post(port, BODY, signed(BODY));
    await post(port, other, signed(other));
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(delivered.length, 2);
  });

  it("dedup is off by default: identical payloads are both delivered", async () => {
    const { port, delivered } = await makeServer();
    await post(port, BODY, signed(BODY));
    await post(port, BODY, signed(BODY));
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(delivered.length, 2);
  });

  it("signature verification still runs before dedup", async () => {
    const { port, delivered } = await makeServer({ windowMs: 60_000 });
    const r = await post(port, BODY, { "x-signature": "bogus" });
    assert.equal(r.status, 401);
    await new Promise((r2) => setTimeout(r2, 50));
    assert.equal(delivered.length, 0);
  });

  it("journalDir survives restarts: the same payload stays suppressed, never re-delivered", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-server-"));
    const first = await makeServer({ windowMs: 60_000, journalDir: dir });
    await post(first.port, BODY, signed(BODY));
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(first.delivered.length, 1);
    // Simulate a process restart: a fresh server over the same journal dir.
    const second = await makeServer({ windowMs: 60_000, journalDir: dir });
    const r = await post(second.port, BODY, signed(BODY));
    assert.equal(r.status, 202);
    assert.match(r.text, /"duplicate":true/);
    await new Promise((r2) => setTimeout(r2, 50));
    assert.equal(second.delivered.length, 0);
  });
});

describe("DeliveryDeduplicator journal (WR-79)", () => {
  const HASH = DeliveryDeduplicator.hashPayload(BODY);

  function journalPath(dir: string): string {
    return join(dir, DEDUP_JOURNAL_FILE);
  }

  it("is off by default: no journal files are created", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-off-"));
    const d = new DeliveryDeduplicator({ windowMs: 60_000 });
    assert.equal(await d.check(URL, HASH), false);
    assert.equal((await d.stats()).journal, undefined);
    assert.deepEqual(readdirSync(dir), []);
  });

  it("survives restarts: duplicates stay suppressed after reconstructing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-restart-"));
    let now = 1_000_000;
    const d1 = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, journalDir: dir });
    assert.equal(await d1.check(URL, HASH), false);
    assert.equal((await d1.stats()).journal?.journaled, 1);
    // Simulate a process restart: a brand-new instance over the same dir.
    const d2 = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, journalDir: dir });
    assert.equal((await d2.stats()).journal?.recovered, 1);
    assert.equal((await d2.stats()).journal?.corruptLines, 0);
    assert.equal(await d2.check(URL, HASH), true); // still suppressed — no double charge
    assert.equal(await d2.check("http://localhost:9999/other", HASH), false); // different endpoint: new
  });

  it("does not recover pairs whose window already expired", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-expire-"));
    let now = 0;
    const d1 = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, journalDir: dir });
    assert.equal(await d1.check(URL, HASH), false);
    now = 60_000; // exactly at the window edge: expired, same as in-memory
    const d2 = new DeliveryDeduplicator({ windowMs: 60_000, now: () => now, journalDir: dir });
    assert.equal((await d2.stats()).journal?.recovered, 0);
    assert.equal(await d2.check(URL, HASH), false); // fresh window: delivered
  });

  it("skips corrupt lines and counts them", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-corrupt-"));
    const key = Buffer.from(`${URL}\n${HASH}`, "utf8").toString("base64");
    const valid = JSON.stringify({
      v: 1,
      op: "seen",
      at: Date.now(),
      key: { encoding: "base64", data: key },
    });
    writeFileSync(
      journalPath(dir),
      ["not json at all", "", valid, '{"v":1,"op":"bogus"}', '{"v":2,"op":"seen"}'].join("\n") + "\n"
    );
    const d = new DeliveryDeduplicator({ windowMs: 60_000, journalDir: dir });
    assert.equal((await d.stats()).journal?.recovered, 1);
    assert.equal((await d.stats()).journal?.corruptLines, 3);
    assert.equal(await d.check(URL, HASH), true); // the one good line still protects
  });

  it("seals journaled keys when a journalEncryptor is configured", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-enc-"));
    const key = randomAes256Key();
    let now = 1_000_000;
    const d1 = new DeliveryDeduplicator({
      windowMs: 60_000,
      now: () => now,
      journalDir: dir,
      journalEncryptor: new AesGcmEncryptor(key),
    });
    assert.equal(await d1.check(URL, HASH), false);
    // The endpoint URL never lands on disk in the clear.
    assert.ok(!readFileSync(journalPath(dir), "utf8").includes("localhost:9999"));
    const d2 = new DeliveryDeduplicator({
      windowMs: 60_000,
      now: () => now,
      journalDir: dir,
      journalEncryptor: new AesGcmEncryptor(key),
    });
    assert.equal((await d2.stats()).journal?.recovered, 1);
    assert.equal(await d2.check(URL, HASH), true);
    // A rotated-away key cannot open the sealed lines: counted as corrupt,
    // never fatal, nothing recovered.
    const d3 = new DeliveryDeduplicator({
      windowMs: 60_000,
      now: () => now,
      journalDir: dir,
      journalEncryptor: new AesGcmEncryptor(randomAes256Key()),
    });
    assert.equal((await d3.stats()).journal?.recovered, 0);
    assert.equal((await d3.stats()).journal?.corruptLines, 1);
    assert.equal(await d3.check(URL, HASH), false);
  });

  it("caps recovered state at maxEntries, newest first", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-cap-"));
    let now = 0;
    const d1 = new DeliveryDeduplicator({
      windowMs: 60_000,
      maxEntries: 2,
      now: () => now,
      journalDir: dir,
    });
    // maxEntries bounds memory, but every first sight is journaled.
    for (const ep of ["http://a/", "http://b/", "http://c/"]) {
      now += 1;
      assert.equal(await d1.check(ep, HASH), false);
    }
    assert.equal((await d1.stats()).tracked, 2);
    const d2 = new DeliveryDeduplicator({
      windowMs: 60_000,
      maxEntries: 2,
      now: () => now,
      journalDir: dir,
    });
    assert.equal((await d2.stats()).journal?.recovered, 2);
    assert.equal((await d2.stats()).tracked, 2);
    assert.equal(await d2.check("http://b/", HASH), true);
    assert.equal(await d2.check("http://c/", HASH), true);
    assert.equal(await d2.check("http://a/", HASH), false); // evicted oldest: fresh again
  });

  it("an uncreatable journal directory throws at construction", () => {
    const dir = mkdtempSync(join(tmpdir(), "dedup-baddir-"));
    const file = join(dir, "not-a-dir");
    writeFileSync(file, "x");
    assert.throws(
      () => new DeliveryDeduplicator({ journalDir: join(file, "sub") }),
      /ENOTDIR/
    );
  });
});
