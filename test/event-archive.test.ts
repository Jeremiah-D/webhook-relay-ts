import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { DeliveryEventArchiver } from "../src/event-archive.ts";
import type { DeliveryEvent, DeliveryEventType } from "../src/retry.ts";
import type { Sender } from "../src/retry.ts";

const SECRET = "archive-secret";
const TOKEN = "op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));
const FORWARD_URL = "http://127.0.0.1:1/hook"; // never called; the sender is injected

type RelayOptions = Parameters<typeof createRelayServer>[0];

function tmpDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

function makeEvent(partial: Partial<DeliveryEvent> & { type: DeliveryEventType }): DeliveryEvent {
  return {
    id: `id-${Math.random().toString(36).slice(2)}`,
    traceId: `trace-${Math.random().toString(36).slice(2)}`,
    targetUrl: "https://downstream.example/hook",
    attempts: 1,
    at: new Date().toISOString(),
    ...partial,
  };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end();
  });
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end(body);
  });
}

async function waitForArchive(
  port: number,
  path: string,
  pred: (events: DeliveryEvent[]) => boolean,
  timeoutMs = 5000
): Promise<DeliveryEvent[]> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const res = await get(port, path, { authorization: `Bearer ${TOKEN}` });
    assert.equal(res.status, 200);
    const events = JSON.parse(res.text) as DeliveryEvent[];
    if (pred(events)) return events;
    assert.ok(Date.now() < deadline, "timed out waiting for archived events");
    await new Promise((r) => setTimeout(r, 25));
  }
}

describe("DeliveryEventArchiver", () => {
  it("archives delivered/retrying/dead_letter events and queries them sorted by at", () => {
    const dir = tmpDir("archive-");
    const archiver = new DeliveryEventArchiver({ dir });
    const t0 = new Date("2026-10-10T10:00:00.000Z").toISOString();
    const t1 = new Date("2026-10-10T10:00:01.000Z").toISOString();
    const t2 = new Date("2026-10-10T10:00:02.000Z").toISOString();
    // Record out of chronological order; query must sort by `at` ascending.
    archiver.record(makeEvent({ type: "dead_letter", at: t2, attempts: 3, error: "boom" }));
    archiver.record(
      makeEvent({ type: "delivered", at: t0, attempts: 1, tenant: "acme", id: "delivered-1" })
    );
    archiver.record(makeEvent({ type: "retrying", at: t1, attempts: 1, error: "timeout" }));

    const events = archiver.query();
    assert.equal(events.length, 3);
    assert.deepEqual(events.map((e) => e.type), ["delivered", "retrying", "dead_letter"]);
    assert.equal(events[0].id, "delivered-1");
    assert.equal(events[0].tenant, "acme");
    assert.equal(events[0].error, undefined);
    assert.equal(events[1].error, "timeout");
    assert.equal(events[2].error, "boom");
    assert.equal(events[2].attempts, 3);
    // Line format on disk carries exactly the documented fields.
    const lines = readFileSync(join(dir, "events.jsonl"), "utf8").trim().split("\n");
    assert.equal(lines.length, 3);
    for (const line of lines) {
      const keys = Object.keys(JSON.parse(line)).sort();
      assert.ok(keys.includes("type") && keys.includes("id") && keys.includes("traceId"));
      assert.ok(keys.includes("targetUrl") && keys.includes("attempts") && keys.includes("at"));
    }
    archiver.close();
  });

  it("filters by since/until", () => {
    const dir = tmpDir("archive-");
    const archiver = new DeliveryEventArchiver({ dir });
    archiver.record(makeEvent({ type: "delivered", at: "2026-10-10T10:00:00.000Z", id: "e0" }));
    archiver.record(makeEvent({ type: "delivered", at: "2026-10-10T11:00:00.000Z", id: "e1" }));
    archiver.record(makeEvent({ type: "delivered", at: "2026-10-10T12:00:00.000Z", id: "e2" }));

    assert.deepEqual(
      archiver.query({ since: "2026-10-10T11:00:00.000Z" }).map((e) => e.id),
      ["e1", "e2"]
    );
    assert.deepEqual(
      archiver.query({ until: "2026-10-10T11:00:00.000Z" }).map((e) => e.id),
      ["e0", "e1"]
    );
    assert.deepEqual(
      archiver
        .query({ since: "2026-10-10T10:30:00.000Z", until: "2026-10-10T11:30:00.000Z" })
        .map((e) => e.id),
      ["e1"]
    );
    archiver.close();
  });

  it("filters by endpoint with exact match on targetUrl", () => {
    const dir = tmpDir("archive-");
    const archiver = new DeliveryEventArchiver({ dir });
    archiver.record(makeEvent({ type: "delivered", targetUrl: "https://a.example/hook", id: "e0" }));
    archiver.record(makeEvent({ type: "delivered", targetUrl: "https://a.example/hook/v2", id: "e1" }));

    const exact = archiver.query({ endpoint: "https://a.example/hook" });
    assert.deepEqual(exact.map((e) => e.id), ["e0"]);
    // A prefix is not a match — documented exact-match semantics.
    assert.equal(archiver.query({ endpoint: "https://a.example" }).length, 0);
    archiver.close();
  });

  it("filters by event type", () => {
    const dir = tmpDir("archive-");
    const archiver = new DeliveryEventArchiver({ dir });
    archiver.record(makeEvent({ type: "delivered", id: "e0" }));
    archiver.record(makeEvent({ type: "retrying", id: "e1" }));
    archiver.record(makeEvent({ type: "dead_letter", id: "e2" }));

    assert.deepEqual(archiver.query({ event: "dead_letter" }).map((e) => e.id), ["e2"]);
    assert.deepEqual(archiver.query({ event: "retrying" }).map((e) => e.id), ["e1"]);
    archiver.close();
  });

  it("throws on invalid since/until", () => {
    const dir = tmpDir("archive-");
    const archiver = new DeliveryEventArchiver({ dir });
    assert.throws(() => archiver.query({ since: "not-a-date" }), /since\/until/);
    assert.throws(() => archiver.query({ until: "2026-13-99" }), /since\/until/);
    archiver.close();
  });

  it("rejects invalid retention options at construction", () => {
    const dir = tmpDir("archive-");
    assert.throws(() => new DeliveryEventArchiver({ dir, maxBytes: 0 }), RangeError);
    assert.throws(() => new DeliveryEventArchiver({ dir, maxBytes: -5 }), RangeError);
    assert.throws(() => new DeliveryEventArchiver({ dir, maxAgeMs: 0 }), RangeError);
    assert.throws(() => new DeliveryEventArchiver({ dir, maxAgeMs: Number.NaN }), RangeError);
  });

  it("maxBytes evicts the oldest lines first and always keeps the newest", () => {
    const dir = tmpDir("archive-");
    // ~150 bytes per line; 200 forces eviction down to the newest line.
    const archiver = new DeliveryEventArchiver({ dir, maxBytes: 200 });
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const id = `e${i}`;
      ids.push(id);
      archiver.record(makeEvent({ type: "delivered", id }));
    }
    const events = archiver.query();
    assert.equal(events.length, 1);
    assert.equal(events[0].id, ids[4]);
    archiver.close();
  });

  it("maxAgeMs evicts expired events", () => {
    const dir = tmpDir("archive-");
    const archiver = new DeliveryEventArchiver({ dir, maxAgeMs: 60_000 });
    const old = new Date(Date.now() - 3_600_000).toISOString();
    archiver.record(makeEvent({ type: "delivered", at: old, id: "old-1" }));
    archiver.record(makeEvent({ type: "delivered", at: old, id: "old-2" }));
    archiver.record(makeEvent({ type: "delivered", id: "fresh" }));
    archiver.compactNow();
    assert.deepEqual(archiver.query().map((e) => e.id), ["fresh"]);
    archiver.close();
  });

  it("survives restart: reopening the same dir reads history", () => {
    const dir = tmpDir("archive-");
    const first = new DeliveryEventArchiver({ dir });
    first.record(makeEvent({ type: "delivered", id: "e0" }));
    first.record(makeEvent({ type: "dead_letter", id: "e1", error: "gone" }));
    first.close();

    const second = new DeliveryEventArchiver({ dir });
    const events = second.query();
    assert.equal(events.length, 2);
    assert.deepEqual(events.map((e) => e.id).sort(), ["e0", "e1"]);
    assert.equal(events.find((e) => e.id === "e1")!.error, "gone");
    // And it keeps appending to the same file.
    second.record(makeEvent({ type: "retrying", id: "e2" }));
    assert.equal(second.query().length, 3);
    second.close();
  });

  it("never throws on write failure; failures are counted", () => {
    const dir = tmpDir("archive-");
    // Replace the archive file with a directory so appends fail.
    mkdirSync(join(dir, "events.jsonl"));
    const archiver = new DeliveryEventArchiver({ dir });
    assert.doesNotThrow(() => archiver.record(makeEvent({ type: "delivered" })));
    assert.doesNotThrow(() => archiver.record(makeEvent({ type: "delivered" })));
    assert.equal(archiver.stats.writeErrors, 2);
    assert.equal(archiver.stats.appends, 0);
    archiver.close();
  });

  it("subscribes to an event source and unsubscribes on close", () => {
    const dir = tmpDir("archive-");
    const listeners = new Set<(e: DeliveryEvent) => void>();
    const source = {
      subscribeDeliveryEvents: (l: (e: DeliveryEvent) => void) => {
        listeners.add(l);
        return () => {
          listeners.delete(l);
        };
      },
    };
    const archiver = new DeliveryEventArchiver({ dir, source });
    assert.equal(listeners.size, 1);
    const evt = makeEvent({ type: "delivered", id: "live-1" });
    for (const l of listeners) l(evt);
    assert.deepEqual(archiver.query().map((e) => e.id), ["live-1"]);
    archiver.close();
    assert.equal(listeners.size, 0);
  });

  it("skips corrupt lines on query and on retention", () => {
    const dir = tmpDir("archive-");
    const archiver = new DeliveryEventArchiver({ dir, maxAgeMs: 60_000 });
    archiver.record(makeEvent({ type: "delivered", id: "good" }));
    appendFileSync(join(dir, "events.jsonl"), "this is not json\n{\"type\":\"nope\"}\n");
    assert.deepEqual(archiver.query().map((e) => e.id), ["good"]);
    // Retention must not drop the good line or crash on the bad ones.
    archiver.compactNow();
    assert.deepEqual(archiver.query().map((e) => e.id), ["good"]);
    archiver.close();
  });
});

describe("GET /events/archive", () => {
  function makeServer(partial: Partial<RelayOptions> & { sender: Sender }): Server {
    const dir = tmpDir("archive-srv-");
    const { sender, ...rest } = partial;
    return createRelayServer({
      secret: SECRET,
      forwardUrl: FORWARD_URL,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: TOKEN,
      ...rest,
      retry: { sender, baseDelayMs: 10, jitterMs: 0, maxAttempts: 3, ...(rest.retry ?? {}) },
    });
  }

  it("serves archived deliveries with filters end to end", async () => {
    const archiveDir = tmpDir("archive-e2e-");
    const relay = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
    });
    const port = await listen(relay);
    try {
      const posted = await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) });
      assert.equal(posted.status, 202);
      const id = (JSON.parse(posted.text) as { id: string }).id;

      const events = await waitForArchive(
        port,
        "/events/archive",
        (evts) => evts.some((e) => e.id === id)
      );
      const delivered = events.find((e) => e.id === id)!;
      assert.equal(delivered.type, "delivered");
      assert.equal(delivered.targetUrl, FORWARD_URL);
      assert.equal(delivered.attempts, 1);
      assert.match(delivered.at, /^\d{4}-\d{2}-\d{2}T/);
      assert.equal(delivered.error, undefined);

      // Query-param filters work through HTTP.
      const byEvent = await get(port, `/events/archive?event=delivered`, {
        authorization: `Bearer ${TOKEN}`,
      });
      assert.equal(byEvent.status, 200);
      assert.ok((JSON.parse(byEvent.text) as DeliveryEvent[]).some((e) => e.id === id));
      const dead = await get(port, `/events/archive?event=dead_letter`, {
        authorization: `Bearer ${TOKEN}`,
      });
      assert.equal(dead.status, 200);
      assert.deepEqual(JSON.parse(dead.text), []);
      const byEndpoint = await get(port, `/events/archive?endpoint=${encodeURIComponent(FORWARD_URL)}`, {
        authorization: `Bearer ${TOKEN}`,
      });
      assert.equal(byEndpoint.status, 200);
      assert.ok((JSON.parse(byEndpoint.text) as DeliveryEvent[]).some((e) => e.id === id));
      const byOtherEndpoint = await get(port, `/events/archive?endpoint=${encodeURIComponent("https://other.example/")}`, {
        authorization: `Bearer ${TOKEN}`,
      });
      assert.equal(byOtherEndpoint.status, 200);
      assert.deepEqual(JSON.parse(byOtherEndpoint.text), []);
    } finally {
      await close(relay);
    }
  });

  it("archives retrying and dead_letter through the live queue", async () => {
    const archiveDir = tmpDir("archive-e2e-");
    const relay = makeServer({
      sender: async () => {
        throw new Error("downstream boom");
      },
      retry: { maxAttempts: 2 },
      eventArchive: { dir: archiveDir },
    });
    const port = await listen(relay);
    try {
      const posted = await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) });
      assert.equal(posted.status, 202);
      const id = (JSON.parse(posted.text) as { id: string }).id;
      const events = await waitForArchive(
        port,
        "/events/archive",
        (evts) => evts.some((e) => e.id === id && e.type === "dead_letter")
      );
      const types = events.filter((e) => e.id === id).map((e) => e.type);
      assert.ok(types.includes("retrying"));
      assert.ok(types.includes("dead_letter"));
      const retrying = events.find((e) => e.id === id && e.type === "retrying")!;
      assert.equal(retrying.error, "downstream boom");
    } finally {
      await close(relay);
    }
  });

  it("404s fail-closed when the archive is not configured", async () => {
    const relay = makeServer({ sender: async () => {} });
    const port = await listen(relay);
    try {
      // Authenticated, but no archive configured: 404, no existence leak.
      assert.equal(
        (await get(port, "/events/archive", { authorization: `Bearer ${TOKEN}` })).status,
        404
      );
    } finally {
      await close(relay);
    }
  });

  it("is guarded like the other operator endpoints", async () => {
    const archiveDir = tmpDir("archive-e2e-");
    // No operatorToken at all: fail closed with 404.
    const dir = tmpDir("archive-srv-");
    const disabled = createRelayServer({
      secret: SECRET,
      forwardUrl: FORWARD_URL,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      eventArchive: { dir: archiveDir },
      retry: { sender: async () => {} },
    });
    const p0 = await listen(disabled);
    try {
      assert.equal((await get(p0, "/events/archive", { authorization: `Bearer ${TOKEN}` })).status, 404);
    } finally {
      await close(disabled);
    }

    const relay = makeServer({ sender: async () => {}, eventArchive: { dir: archiveDir } });
    const port = await listen(relay);
    try {
      assert.equal((await get(port, "/events/archive")).status, 403);
      assert.equal((await get(port, "/events/archive", { authorization: "Bearer wrong" })).status, 403);
      assert.equal(
        (await post(port, "/events/archive", Buffer.alloc(0), { authorization: `Bearer ${TOKEN}` }))
          .status,
        405
      );
    } finally {
      await close(relay);
    }
  });

  it("400s on an invalid event filter or invalid since/until", async () => {
    const archiveDir = tmpDir("archive-e2e-");
    const relay = makeServer({ sender: async () => {}, eventArchive: { dir: archiveDir } });
    const port = await listen(relay);
    const auth = { authorization: `Bearer ${TOKEN}` };
    try {
      assert.equal((await get(port, "/events/archive?event=bogus", auth)).status, 400);
      assert.equal((await get(port, "/events/archive?event=", auth)).status, 400);
      assert.equal((await get(port, "/events/archive?since=not-a-date", auth)).status, 400);
      assert.equal((await get(port, "/events/archive?until=2026-13-99", auth)).status, 400);
      // Valid values still 200.
      assert.equal((await get(port, "/events/archive?event=retrying", auth)).status, 200);
      assert.equal(
        (await get(port, "/events/archive?since=2026-10-10T00:00:00.000Z", auth)).status,
        200
      );
    } finally {
      await close(relay);
    }
  });
});
