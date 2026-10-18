import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

const relayKey = "relay-secret";
const opToken = "op-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "tenant-deadletter" }));
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";

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
        for (const f of fns) f();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

interface SeededItem {
  id: string;
  targetUrl: string;
  tenantId?: string;
}

/** Build a running queue whose sender always fails, pre-filled with dead letters. */
function seedDeadLetters(items: SeededItem[]) {
  const timer = manualTimer();
  const q = new RetryQueue({
    sender: async () => {
      throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 2,
    jitterMs: 0,
    setTimer: timer.setTimer,
  });
  q.start();
  for (const item of items) {
    q.enqueue({
      id: item.id,
      payload: Buffer.from(`payload-${item.id}`),
      targetUrl: item.targetUrl,
      headers: {},
      ...(item.tenantId !== undefined ? { tenantId: item.tenantId } : {}),
    });
  }
  return { q, timer };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function request(port: number, method: string, path: string, body: Buffer | undefined, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end(body);
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("tenant-scoped dead-letter replay filter", () => {
  it("replayDeadLetters({tenant}) only replays that tenant's entries", async () => {
    const { q, timer } = seedDeadLetters([
      { id: "a1", targetUrl: EP_A, tenantId: "acme" },
      { id: "a2", targetUrl: EP_A, tenantId: "acme" },
      { id: "b1", targetUrl: EP_A, tenantId: "globex" },
      { id: "d1", targetUrl: EP_A }, // default tenant
    ]);
    await timer.run();
    assert.deepEqual(
      q.getDeadLetter().map((e) => e.id).sort(),
      ["a1", "a2", "b1", "d1"]
    );

    // The dead-letter entries carry the tenant through the dead-lettering path.
    const acmeEntries = q.getDeadLetter().filter((e) => e.tenantId === "acme");
    assert.equal(acmeEntries.length, 2);

    const result = q.replayDeadLetters({ tenant: "acme" });
    assert.deepEqual(result.replayed.sort(), ["a1", "a2"]);
    assert.deepEqual(result.failed, []);
    // The other tenants' entries stay in the dead-letter list untouched.
    assert.deepEqual(
      q.getDeadLetter().map((e) => e.id).sort(),
      ["b1", "d1"]
    );
    await timer.run();
  });

  it("omitting tenant keeps the pre-tenant replay behavior", async () => {
    const { q, timer } = seedDeadLetters([
      { id: "a1", targetUrl: EP_A, tenantId: "acme" },
      { id: "d1", targetUrl: EP_A },
    ]);
    await timer.run();
    const result = q.replayDeadLetters();
    assert.deepEqual(result.replayed.sort(), ["a1", "d1"]);
    await timer.run();
  });

  it("tenant combines with endpoint and ids selectors", async () => {
    const { q, timer } = seedDeadLetters([
      { id: "a1", targetUrl: EP_A, tenantId: "acme" },
      { id: "a2", targetUrl: EP_B, tenantId: "acme" },
      { id: "b1", targetUrl: EP_A, tenantId: "globex" },
    ]);
    await timer.run();

    const preview = q.replayDeadLetters({ tenant: "acme", endpoint: EP_A }, { dryRun: true });
    assert.equal(preview.length, 1);
    assert.equal(preview[0].id, "a1");
    // The dry-run preview carries the tenant so operators can verify scope.
    assert.equal(preview[0].tenant, "acme");

    const result = q.replayDeadLetters({ tenant: "acme", ids: ["a2", "nope"] });
    assert.deepEqual(result.replayed, ["a2"]);
    assert.deepEqual(
      result.failed.map((f) => f.id),
      ["nope"]
    );
    assert.deepEqual(
      q.getDeadLetter().map((e) => e.id).sort(),
      ["a1", "b1"]
    );
    await timer.run();
  });

  it("getDeadLetterStats reports per-(tenant, endpoint) counts", async () => {
    const { q, timer } = seedDeadLetters([
      { id: "a1", targetUrl: EP_A, tenantId: "acme" },
      { id: "a2", targetUrl: EP_B, tenantId: "acme" },
      { id: "b1", targetUrl: EP_A, tenantId: "globex" },
      { id: "d1", targetUrl: EP_A },
    ]);
    await timer.run();

    const stats = q.getDeadLetterStats();
    assert.equal(stats.total, 4);
    // The unscoped row stays the sum across tenants (backward compatible).
    assert.deepEqual(stats.byEndpoint, [
      { endpoint: EP_A, count: 3 },
      { endpoint: EP_B, count: 1 },
    ]);
    // First-seen order: the tenant-less delivery skips the WR-140 tenant
    // gate (one fewer microtask per attempt), so it dead-letters first.
    assert.deepEqual(stats.byTenantEndpoint, [
      // The default tenant's row carries no `tenant` field.
      { endpoint: EP_A, count: 1 },
      { tenant: "acme", endpoint: EP_A, count: 1 },
      { tenant: "acme", endpoint: EP_B, count: 1 },
      { tenant: "globex", endpoint: EP_A, count: 1 },
    ]);
  });
});

describe("tenant-scoped dead-letter operator views", () => {
  /** Post an inbound webhook (optionally for a tenant) and wait for its dead letter. */
  async function relayWithDeadLetters() {
    const dir = mkdtempSync(join(tmpdir(), "dl-tenant-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: relayKey,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      sender: async () => {
        throw new Error("downstream 500");
      },
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
      operatorToken: opToken,
    });
    const port = await listen(relay);
    const auth = { authorization: `Bearer ${opToken}` };

    async function postHook(tenant?: string) {
      const headers: Record<string, string> = {
        "x-signature": signSha256(BODY, relayKey),
        ...(tenant !== undefined ? { "x-tenant-id": tenant } : {}),
      };
      const res = await request(port, "POST", "/", BODY, headers);
      assert.equal(res.status, 202);
    }

    try {
      await postHook("acme");
      await postHook("globex");
      await postHook(); // default tenant

      // Poll the operator list until all three dead letters land.
      for (let i = 0; i < 100; i++) {
        const list = await request(port, "GET", "/dead-letter", undefined, auth);
        assert.equal(list.status, 200);
        if ((JSON.parse(list.text) as unknown[]).length >= 3) break;
        await sleep(20);
      }
    } catch (err) {
      // Never leak a listening relay when seeding fails.
      relay.close();
      throw err;
    }
    return { relay, port, auth, audit };
  }

  it("GET /dead-letter filters by ?tenant= and exposes the tenant", async () => {
    const { relay, port, auth } = await relayWithDeadLetters();
    try {
      const all = JSON.parse((await request(port, "GET", "/dead-letter", undefined, auth)).text) as Array<{
        tenant?: string;
      }>;
      assert.equal(all.length, 3);
      // The dead-letter operator view carries the tenant (WR-48 isolation).
      const acmeRows = all.filter((e) => e.tenant === "acme");
      assert.equal(acmeRows.length, 1);
      assert.ok(all.some((e) => e.tenant === undefined), "the default tenant carries no tenant field");

      const filtered = JSON.parse(
        (await request(port, "GET", "/dead-letter?tenant=acme", undefined, auth)).text
      ) as Array<{ tenant?: string }>;
      assert.equal(filtered.length, 1);
      assert.equal(filtered[0].tenant, "acme");

      const none = JSON.parse(
        (await request(port, "GET", "/dead-letter?tenant=unknown", undefined, auth)).text
      ) as unknown[];
      assert.deepEqual(none, []);

      // The tenant filter shares the operator guard (404 fail-closed).
      assert.equal((await request(port, "GET", "/dead-letter?tenant=acme", undefined)).status, 403);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("POST /dead-letter/replay accepts tenant and scopes the replay", async () => {
    const { relay, port, auth, audit } = await relayWithDeadLetters();
    try {
      // Capture acme's entry id before the replay.
      const before = JSON.parse(
        (await request(port, "GET", "/dead-letter?tenant=acme", undefined, auth)).text
      ) as Array<{ id: string }>;
      assert.equal(before.length, 1);
      const [acmeEntry] = before;

      const replay = await request(
        port,
        "POST",
        "/dead-letter/replay",
        Buffer.from(JSON.stringify({ tenant: "acme" })),
        { ...auth, "content-type": "application/json" }
      );
      assert.equal(replay.status, 200);
      const result = JSON.parse(replay.text) as { replayed: string[]; failed: unknown[] };
      // Exactly acme's entry was replayed — the synchronous outcome, race-free.
      assert.deepEqual(result.replayed, [acmeEntry.id]);
      assert.deepEqual(result.failed, []);

      // The batch replay audit carries the tenant.
      const events = audit.readAll().filter((e) => e.event === "dead_letter_batch_replayed");
      assert.equal(events.length, 1);
      assert.equal((events[0] as Record<string, unknown>)["tenant"], "acme");
      assert.deepEqual((events[0] as Record<string, unknown>)["replayed"], [acmeEntry.id]);

      // An unknown tenant matches nothing: deterministic, zero side effects.
      const dryUnknown = await request(
        port,
        "POST",
        "/dead-letter/replay",
        Buffer.from(JSON.stringify({ tenant: "nobody", dryRun: true })),
        { ...auth, "content-type": "application/json" }
      );
      assert.equal(dryUnknown.status, 200);
      assert.deepEqual(
        (JSON.parse(dryUnknown.text) as { entries: unknown[] }).entries,
        []
      );

      // tenant must be a string when present.
      const bad = await request(
        port,
        "POST",
        "/dead-letter/replay",
        Buffer.from(JSON.stringify({ tenant: 42 })),
        { ...auth, "content-type": "application/json" }
      );
      assert.equal(bad.status, 400);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("dry-run replay preview honors the tenant filter", async () => {
    const { relay, port, auth } = await relayWithDeadLetters();
    try {
      const res = await request(
        port,
        "POST",
        "/dead-letter/replay",
        Buffer.from(JSON.stringify({ tenant: "globex", dryRun: true })),
        { ...auth, "content-type": "application/json" }
      );
      assert.equal(res.status, 200);
      const body = JSON.parse(res.text) as { dryRun: boolean; entries: Array<{ tenant?: string }> };
      assert.equal(body.dryRun, true);
      assert.equal(body.entries.length, 1);
      assert.equal(body.entries[0].tenant, "globex");
      // Dry run has zero side effects: the list is untouched.
      const all = JSON.parse((await request(port, "GET", "/dead-letter", undefined, auth)).text) as unknown[];
      assert.equal(all.length, 3);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("GET /dead-letter/stats exposes per-(tenant, endpoint) counts", async () => {
    const { relay, port, auth } = await relayWithDeadLetters();
    try {
      const stats = await request(port, "GET", "/dead-letter/stats", undefined, auth);
      assert.equal(stats.status, 200);
      const s = JSON.parse(stats.text) as {
        total: number;
        byEndpoint: Array<{ endpoint: string; count: number }>;
        byTenantEndpoint: Array<{ tenant?: string; endpoint: string; count: number }>;
      };
      assert.equal(s.total, 3);
      assert.deepEqual(s.byEndpoint, [{ endpoint: "http://127.0.0.1:1/unused", count: 3 }]);
      assert.equal(s.byTenantEndpoint.length, 3);
      assert.ok(
        s.byTenantEndpoint.some((r) => r.tenant === "acme" && r.count === 1),
        "acme row present"
      );
      assert.ok(
        s.byTenantEndpoint.some((r) => r.tenant === undefined && r.count === 1),
        "default-tenant row carries no tenant field"
      );
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
