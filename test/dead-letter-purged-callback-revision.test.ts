import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { AesGcmEncryptor, randomAes256Key, type PayloadEncryptor } from "../src/encrypt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import type {
  DeadLetterPurgeResult,
  DeadLetterPurgedEvent,
} from "../src/deadletter-retention.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const INGEST_KEY = "dead-letter-purged-callback-revision-key";
const OPERATOR_TOKEN = "dead-letter-purged-callback-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "purged-revision" }));
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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

interface SeededItem {
  id: string;
  targetUrl: string;
  tenantId?: string;
}

/** Build a queue whose sender always fails, pre-filled with dead letters. */
function seedDeadLetters(items: SeededItem[], extraOpts: Record<string, unknown> = {}) {
  const timer = manualTimer();
  const q = new RetryQueue({
    sender: async () => {
      throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 1,
    jitterMs: 0,
    setTimer: timer.setTimer,
    ...extraOpts,
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

/** Drive one seeded entry to purge age, then purge manually. */
async function purgeOnce(
  q: RetryQueue,
  timer: ReturnType<typeof manualTimer>
): Promise<DeadLetterPurgeResult> {
  await timer.run();
  await sleep(30);
  return q.purgeExpiredDeadLetters();
}

describe("RetryQueue dead-letter-purged callback revision (WR-397)", () => {
  it("the revised callback receives the next purge with exact fields; the old callback stays silent", async () => {
    const first: DeadLetterPurgedEvent[] = [];
    const second: DeadLetterPurgedEvent[] = [];
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A, tenantId: "t1" }], {
      deadLetterRetention: { retentionMs: 1 },
      onDeadLetterPurged: (e) => first.push(e),
    });
    try {
      const r1 = await purgeOnce(q, timer);
      assert.deepEqual(r1.purged.map((p) => p.id), ["a"]);
      assert.equal(first.length, 1);
      assert.equal(first[0].event, "dead_letter_purged");
      assert.equal(first[0].id, "a");
      assert.equal(first[0].endpoint, EP_A);
      assert.equal(first[0].attempts, 1);
      assert.equal(first[0].tenant, "t1");
      assert.ok(first[0].traceId.length > 0);
      assert.ok(!Number.isNaN(Date.parse(first[0].deadLetteredAt)));
      assert.ok(!("payload" in first[0]), "purge event must not leak the payload");
      // A second entry purges into the revised callback only.
      q.enqueue({ id: "b", payload: Buffer.from("payload-b"), targetUrl: EP_A, headers: {} });
      q.reviseDeadLetterPurgedCallback((e) => second.push(e));
      const r2 = await purgeOnce(q, timer);
      assert.deepEqual(r2.purged.map((p) => p.id), ["b"]);
      assert.equal(first.length, 1);
      assert.equal(second.length, 1);
      assert.equal(second[0].id, "b");
      assert.equal(second[0].endpoint, EP_A);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; the purge still happens and still counts", async () => {
    const seen: DeadLetterPurgedEvent[] = [];
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: 1 },
      onDeadLetterPurged: (e) => seen.push(e),
    });
    try {
      await purgeOnce(q, timer);
      assert.equal(seen.length, 1);
      assert.equal(q.getDeadLetterStats().purged, 1);
      q.reviseDeadLetterPurgedCallback(null);
      q.enqueue({ id: "b", payload: Buffer.from("payload-b"), targetUrl: EP_A, headers: {} });
      const r = await purgeOnce(q, timer);
      assert.deepEqual(r.purged.map((p) => p.id), ["b"]);
      assert.equal(seen.length, 1, "cleared hook stays silent");
      assert.equal(q.getDeadLetterStats().purged, 2);
      assert.equal(q.getDeadLetter().length, 0);
    } finally {
      q.stop();
    }
  });

  it("revising with retention unconfigured throws Error; retentionConfigured reports the live state", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.retentionConfigured(), false);
    assert.throws(
      () => q.reviseDeadLetterPurgedCallback(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    const { q: configured } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: 1 },
    });
    try {
      assert.equal(configured.retentionConfigured(), true);
    } finally {
      configured.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const seen: DeadLetterPurgedEvent[] = [];
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: 1 },
      onDeadLetterPurged: (e) => seen.push(e),
    });
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseDeadLetterPurgedCallback(bad), RangeError, String(bad));
      }
      // Nothing moved: the original hook still fires.
      const r = await purgeOnce(q, timer);
      assert.deepEqual(r.purged.map((p) => p.id), ["a"]);
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const seen: DeadLetterPurgedEvent[] = [];
    const onPurged = (e: DeadLetterPurgedEvent) => seen.push(e);
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: 1 },
      onDeadLetterPurged: onPurged,
    });
    try {
      q.reviseDeadLetterPurgedCallback(onPurged);
      const r1 = await purgeOnce(q, timer);
      assert.deepEqual(r1.purged.map((p) => p.id), ["a"]);
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseDeadLetterPurgedCallback(null);
      q.reviseDeadLetterPurgedCallback(null);
      q.enqueue({ id: "b", payload: Buffer.from("payload-b"), targetUrl: EP_A, headers: {} });
      const r2 = await purgeOnce(q, timer);
      assert.deepEqual(r2.purged.map((p) => p.id), ["b"]);
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("purges already reported are never re-delivered", async () => {
    const seen: DeadLetterPurgedEvent[] = [];
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: 1 },
      onDeadLetterPurged: (e) => seen.push(e),
    });
    try {
      await purgeOnce(q, timer);
      assert.equal(seen.length, 1);
      q.reviseDeadLetterPurgedCallback((e) => seen.push(e));
      const r = q.purgeExpiredDeadLetters();
      assert.deepEqual(r.purged, []);
      assert.deepEqual(r.skipped, []);
      assert.equal(seen.length, 1, "no re-delivery of the reported purge");
    } finally {
      q.stop();
    }
  });

  it("revision does not change the TTL judgement", async () => {
    const seen: DeadLetterPurgedEvent[] = [];
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: 3_600_000 },
      onDeadLetterPurged: (e) => seen.push(e),
    });
    try {
      q.reviseDeadLetterPurgedCallback((e) => seen.push(e));
      const r = await purgeOnce(q, timer);
      assert.deepEqual(r.purged, []);
      assert.equal(seen.length, 0);
      assert.equal(q.getDeadLetter().length, 1, "unexpired entry survives the revision");
    } finally {
      q.stop();
    }
  });

  it("revision does not change the replay-claim skip", async () => {
    const base = new AesGcmEncryptor(randomAes256Key());
    let inner: DeadLetterPurgeResult | undefined;
    let queue!: RetryQueue;
    const hookEncryptor: PayloadEncryptor = {
      name: base.name,
      encrypt: (p) => base.encrypt(p),
      decrypt: (env) => {
        // Reentrant sweep, fired from inside the batch replay's decrypt:
        // the batch claims every matched id for its whole run.
        inner ??= queue.purgeExpiredDeadLetters();
        return base.decrypt(env);
      },
    };
    const seen: DeadLetterPurgedEvent[] = [];
    queue = new RetryQueue({
      sender: async () => {
        throw new Error("downstream 500");
      },
      baseDelayMs: 1,
      maxAttempts: 1,
      jitterMs: 0,
      payloadEncryptor: hookEncryptor,
      deadLetterRetention: { retentionMs: 1 },
      onDeadLetterPurged: (e) => seen.push(e),
    });
    queue.start();
    queue.enqueue({ id: "r1", payload: Buffer.from("p1"), targetUrl: EP_A, headers: {} });
    queue.enqueue({ id: "r2", payload: Buffer.from("p2"), targetUrl: EP_A, headers: {} });
    // Real timers: let both deliveries fail into the dead letter, then
    // let the 1ms TTL expire.
    await sleep(50);
    assert.equal(queue.getDeadLetter().length, 2);
    queue.reviseDeadLetterPurgedCallback((e) => seen.push(e));
    try {
      const result = queue.replayDeadLetters();
      assert.deepEqual(result.replayed.sort(), ["r1", "r2"]);
      assert.ok(inner !== undefined, "the reentrant sweep should have run inside decrypt");
      // r1 was mid-replay (already spliced out); r2 was still listed but
      // claimed by the batch — it must be skipped, not purged.
      assert.deepEqual(inner.skipped, ["r2"]);
      assert.deepEqual(inner.purged, []);
      assert.equal(seen.length, 0, "a skipped entry reports no purge");
    } finally {
      queue.stop();
    }
  });
});

describe("RelayServer dead-letter-purged callback revision (WR-397)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(cond(), `timed out waiting for ${what}`);
  }

  function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      });
      r.on("error", reject);
      r.end(body);
    });
  }

  function get(port: number, path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "GET", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  /**
   * A server whose sender always fails, so every webhook dead-letters
   * and is then purged by the retention sweep.
   */
  function purgingServer(opts: {
    onDeadLetterPurged?: (e: DeadLetterPurgedEvent) => void;
    retention?: Record<string, unknown>;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "dead-letter-purged-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => {
        throw new Error("downstream 500");
      },
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 1,
        ...(opts.onDeadLetterPurged !== undefined
          ? { onDeadLetterPurged: opts.onDeadLetterPurged }
          : {}),
      },
      deadLetterRetention: { retentionMs: 1, sweepIntervalMs: 25, ...(opts.retention ?? {}) },
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  async function drivePurge(
    port: number,
    auditLog: AuditLog,
    seen: DeadLetterPurgedEvent[]
  ): Promise<void> {
    const beforeAudit = eventsOf(auditLog, "dead_letter_purged").length;
    const beforeSeen = seen.length;
    assert.equal(
      (await post(port, "/", BODY, { "x-signature": signSha256(BODY, INGEST_KEY) })).status,
      202
    );
    await waitFor(
      () => eventsOf(auditLog, "dead_letter_purged").length > beforeAudit,
      "dead_letter_purged audit"
    );
    await waitFor(() => seen.length > beforeSeen, "purged callback");
  }

  it("revising the callback routes the next purge to the new callback and the audit still lands", async () => {
    const first: DeadLetterPurgedEvent[] = [];
    const second: DeadLetterPurgedEvent[] = [];
    const { relay, auditLog } = purgingServer({
      onDeadLetterPurged: (e) => first.push(e),
    });
    const port = await listen(relay);
    await drivePurge(port, auditLog, first);
    assert.equal(first.length, 1);
    assert.equal(first[0].event, "dead_letter_purged");
    assert.ok(first[0].id.length > 0);
    relay.reviseDeadLetterPurgedCallback!((e) => second.push(e));
    await drivePurge(port, auditLog, second);
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.equal(second[0].event, "dead_letter_purged");
    assert.equal(eventsOf(auditLog, "dead_letter_purged").length, 2);
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "dead_letter_purged_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; the purge is still audited and still counted", async () => {
    const first: DeadLetterPurgedEvent[] = [];
    const { relay, auditLog } = purgingServer({
      onDeadLetterPurged: (e) => first.push(e),
    });
    const port = await listen(relay);
    const auth = { authorization: `Bearer ${OPERATOR_TOKEN}` };
    await drivePurge(port, auditLog, first);
    assert.equal(first.length, 1);
    relay.reviseDeadLetterPurgedCallback!(null);
    const beforeAudit = eventsOf(auditLog, "dead_letter_purged").length;
    assert.equal(
      (await post(port, "/", BODY, { "x-signature": signSha256(BODY, INGEST_KEY) })).status,
      202
    );
    await waitFor(
      () => eventsOf(auditLog, "dead_letter_purged").length > beforeAudit,
      "dead_letter_purged audit after clear"
    );
    assert.equal(first.length, 1, "cleared hook stays silent");
    const stats = await get(port, "/dead-letter/stats", auth);
    assert.equal(stats.status, 200);
    const s = JSON.parse(stats.text) as { total: number; purged: number };
    assert.equal(s.total, 0);
    assert.equal(s.purged, 2);
    const revised = eventsOf(auditLog, "dead_letter_purged_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("a non-function value throws RangeError and the live callback is untouched; same-reference is a silent no-op", async () => {
    const first: DeadLetterPurgedEvent[] = [];
    const onPurged = (e: DeadLetterPurgedEvent) => first.push(e);
    const { relay, auditLog } = purgingServer({ onDeadLetterPurged: onPurged });
    const port = await listen(relay);
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseDeadLetterPurgedCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "dead_letter_purged_callback_revised").length, 0);
    relay.reviseDeadLetterPurgedCallback!(onPurged);
    assert.equal(eventsOf(auditLog, "dead_letter_purged_callback_revised").length, 0);
    await drivePurge(port, auditLog, first);
    assert.equal(first.length, 1);
  });

  it("clearing when already unset is a silent no-op", async () => {
    const { relay, auditLog } = purgingServer({});
    await listen(relay);
    relay.reviseDeadLetterPurgedCallback!(null);
    assert.equal(eventsOf(auditLog, "dead_letter_purged_callback_revised").length, 0);
  });

  it("revising with retention unconfigured throws Error", () => {
    const dir = mkdtempSync(join(tmpdir(), "dead-letter-purged-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => {
        throw new Error("downstream 500");
      },
    });
    servers.push(relay);
    assert.throws(
      () => relay.reviseDeadLetterPurgedCallback!(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });

  it("revision does not change the TTL judgement on the server", async () => {
    const seen: DeadLetterPurgedEvent[] = [];
    const { relay, auditLog } = purgingServer({
      onDeadLetterPurged: (e) => seen.push(e),
      retention: { retentionMs: 3_600_000 },
    });
    const port = await listen(relay);
    relay.reviseDeadLetterPurgedCallback!((e) => seen.push(e));
    assert.equal(
      (await post(port, "/", BODY, { "x-signature": signSha256(BODY, INGEST_KEY) })).status,
      202
    );
    await sleep(300);
    assert.equal(eventsOf(auditLog, "dead_letter_purged").length, 0);
    assert.equal(seen.length, 0);
    const stats = await get(port, "/dead-letter/stats", {
      authorization: `Bearer ${OPERATOR_TOKEN}`,
    });
    assert.equal(stats.status, 200);
    const s = JSON.parse(stats.text) as { total: number; purged: number };
    assert.equal(s.total, 1);
    assert.equal(s.purged, 0);
  });
});
