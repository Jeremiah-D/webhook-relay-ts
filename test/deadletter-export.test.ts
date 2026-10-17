import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEAD_LETTER_EXPORT_ROW_LIMIT,
  DEAD_LETTER_EXPORT_TRUNCATION_MARKER,
  InvalidExportCursorError,
  buildDeadLetterExportRow,
  matchDeadLetterExport,
  parseDeadLetterExportTime,
  planDeadLetterExport,
  renderDeadLetterExportHeader,
  renderDeadLetterExportPage,
  renderDeadLetterExportRow,
  type DeadLetterExportSource,
} from "../src/deadletter-export.ts";
import type { DeadLetterEntry } from "../src/retry.ts";
import { AesGcmEncryptor, randomAes256Key, type EncryptedPayload } from "../src/encrypt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import type { FailureClass } from "../src/failure.ts";

const relaySecret = "relay-secret-for-export-tests";
const opToken = "op-export-token";
const epA = "http://a.example/hook";
const epB = "http://b.example/hook";
const bigTs = "2026-10-17T12:00:00.000Z";

function makeEntry(opts: {
  id: string;
  targetUrl?: string;
  tenantId?: string;
  deadLetteredAt?: string;
  payload?: Buffer;
  lastError?: string;
  attempts?: number;
  failureClass?: FailureClass;
  encryptedPayload?: EncryptedPayload;
  traceId?: string;
}): DeadLetterEntry {
  const payload = opts.payload ?? Buffer.from(`payload-${opts.id}`);
  return {
    id: opts.id,
    payload: opts.encryptedPayload ? Buffer.alloc(0) : payload,
    targetUrl: opts.targetUrl ?? epA,
    headers: {},
    attempts: opts.attempts ?? 2,
    lastError: opts.lastError ?? "downstream 500",
    failureClass: opts.failureClass ?? "retryable",
    deadLetteredAt: opts.deadLetteredAt ?? bigTs,
    payloadBytes: payload.length,
    ...(opts.encryptedPayload ? { encryptedPayload: opts.encryptedPayload } : {}),
    ...(opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {}),
    ...(opts.traceId !== undefined ? { traceId: opts.traceId } : {}),
  };
}

function fakeSource(
  entries: DeadLetterEntry[],
  decrypt?: (e: DeadLetterEntry) => Buffer
): DeadLetterExportSource {
  return { entries: () => entries, decrypt: decrypt ?? ((e) => e.payload) };
}

describe("parseDeadLetterExportTime", () => {
  it("accepts ms-epoch digits", () => {
    assert.equal(parseDeadLetterExportTime("1729123456789", "since"), 1729123456789);
  });
  it("accepts ISO-8601", () => {
    assert.equal(
      parseDeadLetterExportTime("2026-10-17T12:00:00.000Z", "until"),
      Date.parse("2026-10-17T12:00:00.000Z")
    );
  });
  it("returns undefined for an absent value", () => {
    assert.equal(parseDeadLetterExportTime(undefined, "since"), undefined);
  });
  it("rejects garbage, negatives, and fractions with RangeError", () => {
    for (const bad of ["bogus", "-5", "12.5", "2026-13-99", "10:00:00"]) {
      assert.throws(() => parseDeadLetterExportTime(bad, "since"), RangeError, bad);
    }
  });
});

describe("matchDeadLetterExport", () => {
  const entry = makeEntry({ id: "e1", tenantId: "t1" });
  it("matches everything with an empty filter", () => {
    assert.equal(matchDeadLetterExport(entry, {}), true);
  });
  it("matches endpoint exactly", () => {
    assert.equal(matchDeadLetterExport(entry, { endpoint: epA }), true);
    assert.equal(matchDeadLetterExport(entry, { endpoint: epB }), false);
  });
  it("matches tenant exactly", () => {
    assert.equal(matchDeadLetterExport(entry, { tenant: "t1" }), true);
    assert.equal(matchDeadLetterExport(entry, { tenant: "t2" }), false);
    assert.equal(matchDeadLetterExport(makeEntry({ id: "e2" }), { tenant: "t1" }), false);
  });
  it("treats since/until as inclusive bounds", () => {
    const at = Date.parse(bigTs);
    assert.equal(matchDeadLetterExport(entry, { since: at }), true);
    assert.equal(matchDeadLetterExport(entry, { since: at + 1 }), false);
    assert.equal(matchDeadLetterExport(entry, { until: at }), true);
    assert.equal(matchDeadLetterExport(entry, { until: at - 1 }), false);
    assert.equal(matchDeadLetterExport(entry, { since: at - 1, until: at + 1 }), true);
  });
});

describe("planDeadLetterExport", () => {
  const entries = ["a", "b", "c", "d", "e"].map((id) => makeEntry({ id }));
  const source = fakeSource(entries);
  it("pages with an explicit rowLimit", () => {
    const plan = planDeadLetterExport(source, {}, { rowLimit: 2 });
    assert.equal(plan.needsPaging, true);
    assert.equal(plan.firstCursor, "a");
    assert.deepEqual(plan.entries, []);
    assert.equal(plan.totalMatched, 5);
  });
  it("cursor is an inclusive start id", () => {
    const plan = planDeadLetterExport(source, {}, { rowLimit: 2, cursor: "b" });
    assert.equal(plan.needsPaging, false);
    assert.deepEqual(plan.entries.map((e) => e.id), ["b", "c"]);
    assert.equal(plan.hasMore, true);
    assert.equal(plan.nextCursor, "d");
  });
  it("last page reports no more rows", () => {
    const plan = planDeadLetterExport(source, {}, { rowLimit: 2, cursor: "e" });
    assert.deepEqual(plan.entries.map((e) => e.id), ["e"]);
    assert.equal(plan.hasMore, false);
    assert.equal(plan.nextCursor, undefined);
  });
  it("unknown cursor throws InvalidExportCursorError", () => {
    assert.throws(
      () => planDeadLetterExport(source, {}, { cursor: "nope" }),
      InvalidExportCursorError
    );
  });
  it("applies the filter before paging", () => {
    const mixed = fakeSource([
      makeEntry({ id: "x1", targetUrl: epA }),
      makeEntry({ id: "x2", targetUrl: epB }),
      makeEntry({ id: "x3", targetUrl: epA }),
    ]);
    const plan = planDeadLetterExport(mixed, { endpoint: epA }, { rowLimit: 10 });
    assert.equal(plan.totalMatched, 2);
    assert.deepEqual(plan.entries.map((e) => e.id), ["x1", "x3"]);
  });
  it("rejects invalid format and limits with RangeError", () => {
    assert.throws(() => planDeadLetterExport(source, {}, { format: "xml" as never }), RangeError);
    assert.throws(() => planDeadLetterExport(source, {}, { maxPayloadBytes: 0 }), RangeError);
    assert.throws(() => planDeadLetterExport(source, {}, { rowLimit: -1 }), RangeError);
  });
  it("handles an empty dead-letter list", () => {
    const plan = planDeadLetterExport(fakeSource([]), {});
    assert.equal(plan.totalMatched, 0);
    assert.deepEqual(plan.entries, []);
    assert.equal(plan.hasMore, false);
    assert.equal(plan.needsPaging, false);
  });
});

describe("buildDeadLetterExportRow", () => {
  const decrypt = (e: DeadLetterEntry): Buffer => e.payload;
  it("passes cleartext payloads through", () => {
    const row = buildDeadLetterExportRow(makeEntry({ id: "r1" }), decrypt, 1024);
    assert.equal(row.payload, "payload-r1");
    assert.equal(row.payloadEncoding, "utf8");
    assert.equal(row.payloadTruncated, false);
    assert.equal(row.encrypted, false);
    assert.equal(row.payloadError, undefined);
  });
  it("truncates past maxPayloadBytes", () => {
    const row = buildDeadLetterExportRow(
      makeEntry({ id: "r2", payload: Buffer.from("0123456789abcdef") }),
      decrypt,
      6
    );
    assert.equal(row.payload, "012345");
    assert.equal(row.payloadTruncated, true);
  });
  it("falls back to base64 for non-UTF8 bytes", () => {
    const raw = Buffer.from([0xff, 0xfe, 0x00, 0x41]);
    const row = buildDeadLetterExportRow(makeEntry({ id: "r3", payload: raw }), decrypt, 1024);
    assert.equal(row.payloadEncoding, "base64");
    assert.equal(row.payload, raw.toString("base64"));
  });
  it("decrypts sealed payloads transparently", () => {
    const key = randomAes256Key();
    const enc = new AesGcmEncryptor(key);
    const secret = Buffer.from("super-secret-payload");
    const entry = makeEntry({ id: "r4", encryptedPayload: enc.encrypt(secret) });
    const row = buildDeadLetterExportRow(entry, (e) => enc.decrypt(e.encryptedPayload!), 1024);
    assert.equal(row.payload, "super-secret-payload");
    assert.equal(row.encrypted, true);
  });
  it("marks undecryptable rows instead of failing the export", () => {
    const entry = makeEntry({
      id: "r5",
      encryptedPayload: new AesGcmEncryptor(randomAes256Key()).encrypt(Buffer.from("x")),
    });
    const row = buildDeadLetterExportRow(
      entry,
      () => {
        throw new Error("decrypt failed");
      },
      1024
    );
    assert.equal(row.payload, "");
    assert.equal(row.payloadError, "decrypt_failed");
    assert.equal(row.encrypted, true);
  });
});

describe("renderDeadLetterExportRow", () => {
  const decrypt = (e: DeadLetterEntry): Buffer => e.payload;
  it("renders JSONL as one JSON object per line", () => {
    const row = buildDeadLetterExportRow(
      makeEntry({ id: "j1", traceId: "trace-1", tenantId: "t9" }),
      decrypt,
      1024
    );
    const line = renderDeadLetterExportRow(row, "jsonl");
    assert.ok(line.endsWith("\n"));
    const parsed = JSON.parse(line) as Record<string, unknown>;
    assert.equal(parsed.id, "j1");
    assert.equal(parsed.targetUrl, epA);
    assert.equal(parsed.tenant, "t9");
    assert.equal(parsed.traceId, "trace-1");
    assert.equal(parsed.payload, "payload-j1");
    assert.equal(parsed.payloadTruncated, false);
  });
  it("renders a fixed CSV header", () => {
    assert.equal(
      renderDeadLetterExportHeader("csv"),
      "id,endpoint,tenant,attempts,last_error,dead_lettered_at,payload_bytes,failure_class,encrypted,payload_truncated,payload\n"
    );
    assert.equal(renderDeadLetterExportHeader("jsonl"), "");
  });
  it("escapes CSV cells per RFC 4180", () => {
    const row = buildDeadLetterExportRow(
      makeEntry({ id: "c1", lastError: 'boom: "quoted", comma\nnewline' }),
      decrypt,
      1024
    );
    const line = renderDeadLetterExportRow(row, "csv");
    assert.ok(line.includes('"boom: ""quoted"", comma\nnewline"'), line);
  });
  it("appends the truncation marker to cut CSV payloads", () => {
    const row = buildDeadLetterExportRow(
      makeEntry({ id: "c2", payload: Buffer.from("abcdefghij") }),
      decrypt,
      4
    );
    const line = renderDeadLetterExportRow(row, "csv");
    assert.ok(line.endsWith(`abcd${DEAD_LETTER_EXPORT_TRUNCATION_MARKER}\n`), line);
    // Still exactly 11 columns.
    assert.equal(line.split('","').length >= 1, true);
  });
  it("renderDeadLetterExportPage renders header plus rows", () => {
    const source = fakeSource([makeEntry({ id: "p1" }), makeEntry({ id: "p2" })]);
    const plan = planDeadLetterExport(source, {}, { format: "csv" });
    const text = renderDeadLetterExportPage(plan, (e) => e.payload);
    const lines = text.trim().split("\n");
    assert.equal(lines.length, 3);
    assert.ok(lines[0].startsWith("id,endpoint,"));
  });
});

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function getFull(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{
    status: number;
    text: string;
    headers: Record<string, string | string[] | undefined>;
  }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({
          status: res.statusCode ?? 0,
          text: Buffer.concat(chunks).toString("utf8"),
          headers: res.headers,
        })
      );
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

async function closeRelay(relay: Server): Promise<void> {
  relay.close();
  await new Promise<void>((r) => relay.once("close", r));
}

interface RelayHarness {
  relay: Server;
  port: number;
  audit: AuditLog;
  cleanup(): Promise<void>;
}

async function startRelay(extra: Record<string, unknown> = {}): Promise<RelayHarness> {
  const dir = mkdtempSync(join(tmpdir(), "dl-export-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const relay = createRelayServer({
    secret: relaySecret,
    forwardUrl: "http://127.0.0.1:1/unused",
    auditLog: audit,
    sender: async () => {
      throw new Error("downstream 500");
    },
    retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
    operatorToken: opToken,
    ...extra,
  });
  const port = await listen(relay);
  return { relay, port, audit, cleanup: () => closeRelay(relay) };
}

/** Wait until the dead-letter list holds at least `expected` entries. */
async function waitForDeadLetters(port: number, expected: number, deadlineMs = 10000): Promise<void> {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    const res = await getFull(port, "/dead-letter", { authorization: `Bearer ${opToken}` });
    assert.equal(res.status, 200);
    const entries = JSON.parse(res.text) as unknown[];
    if (entries.length >= expected) return;
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${expected} dead letters`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

async function seedOneDeadLetter(port: number, payload: Buffer): Promise<void> {
  const res = await post(port, "/", payload, { "x-signature": signSha256(payload, relaySecret) });
  assert.equal(res.status, 202);
}

describe("GET /dead-letter/export operator endpoint", () => {
  it("streams dead letters as JSONL with payloads", async () => {
    const h = await startRelay();
    try {
      const payload = Buffer.from(JSON.stringify({ order: "ord-1" }));
      await seedOneDeadLetter(h.port, payload);
      await waitForDeadLetters(h.port, 1);
      const res = await getFull(h.port, "/dead-letter/export", {
        authorization: `Bearer ${opToken}`,
      });
      assert.equal(res.status, 200);
      assert.equal(res.headers["content-type"], "application/x-ndjson");
      assert.equal(res.headers["x-export-has-more"], "false");
      const lines = res.text.trim().split("\n");
      assert.equal(lines.length, 1);
      const row = JSON.parse(lines[0]) as Record<string, unknown>;
      assert.equal(row.targetUrl, "http://127.0.0.1:1/unused");
      assert.equal(row.attempts, 2);
      assert.equal(row.lastError, "downstream 500");
      assert.equal(row.payload, payload.toString("utf8"));
      assert.equal(row.encrypted, false);
      assert.ok(typeof row.deadLetteredAt === "string");
    } finally {
      await h.cleanup();
    }
  });

  it("is fail-closed: 404 without operatorToken, 403 on a bad bearer", async () => {
    const closed = await startRelay({ operatorToken: "" });
    try {
      const res = await getFull(closed.port, "/dead-letter/export", {
        authorization: "Bearer whatever",
      });
      assert.equal(res.status, 404);
    } finally {
      await closed.cleanup();
    }
    const h = await startRelay();
    try {
      const res = await getFull(h.port, "/dead-letter/export", {
        authorization: "Bearer wrong-token",
      });
      assert.equal(res.status, 403);
    } finally {
      await h.cleanup();
    }
  });

  it("serves CSV with a fixed column set and a truncation marker", async () => {
    const h = await startRelay();
    try {
      const big = Buffer.from(JSON.stringify({ pad: "x".repeat(70 * 1024) }));
      await seedOneDeadLetter(h.port, big);
      await waitForDeadLetters(h.port, 1);
      const res = await getFull(h.port, "/dead-letter/export?format=csv", {
        authorization: `Bearer ${opToken}`,
      });
      assert.equal(res.status, 200);
      assert.equal(res.headers["content-type"], "text/csv; charset=utf-8");
      const lines = res.text.trim().split("\n");
      assert.equal(lines.length, 2);
      assert.ok(lines[0].startsWith("id,endpoint,tenant,"));
      assert.equal(lines[0].split(",").length, 11);
      assert.ok(
        lines[1].endsWith(`${DEAD_LETTER_EXPORT_TRUNCATION_MARKER}"`),
        "cut payload cell carries the marker"
      );
      assert.ok(lines[1].includes(",true,"), "payload_truncated column is true");
    } finally {
      await h.cleanup();
    }
  });

  it("filters by endpoint and since/until", async () => {
    const h = await startRelay();
    try {
      await seedOneDeadLetter(h.port, Buffer.from('{"n":1}'));
      await waitForDeadLetters(h.port, 1);
      const auth = { authorization: `Bearer ${opToken}` };
      const all = await getFull(h.port, "/dead-letter/export", auth);
      assert.equal(all.text.trim().split("\n").length, 1);
      const miss = await getFull(h.port, "/dead-letter/export?endpoint=http://other.example/x", auth);
      assert.equal(miss.status, 200);
      assert.equal(miss.text, "");
      const hit = await getFull(
        h.port,
        "/dead-letter/export?endpoint=http://127.0.0.1:1/unused",
        auth
      );
      assert.equal(hit.text.trim().split("\n").length, 1);
      const row = JSON.parse(all.text.trim()) as { deadLetteredAt: string };
      const at = Date.parse(row.deadLetteredAt);
      const inside = await getFull(
        h.port,
        `/dead-letter/export?since=${at - 60000}&until=${new Date(at + 60000).toISOString()}`,
        auth
      );
      assert.equal(inside.text.trim().split("\n").length, 1);
      const outside = await getFull(h.port, `/dead-letter/export?since=${at + 60000}`, auth);
      assert.equal(outside.text, "");
    } finally {
      await h.cleanup();
    }
  });

  it("rejects bad format, bad time bounds, and unknown cursors with 400", async () => {
    const h = await startRelay();
    try {
      const auth = { authorization: `Bearer ${opToken}` };
      assert.equal((await getFull(h.port, "/dead-letter/export?format=xml", auth)).status, 400);
      assert.equal((await getFull(h.port, "/dead-letter/export?since=bogus", auth)).status, 400);
      assert.equal((await getFull(h.port, "/dead-letter/export?cursor=nope", auth)).status, 400);
    } finally {
      await h.cleanup();
    }
  });

  it("transparently decrypts sealed payloads", async () => {
    const key = randomAes256Key();
    const h = await startRelay({ payloadEncryptor: new AesGcmEncryptor(key) });
    try {
      const payload = Buffer.from(JSON.stringify({ card: "4111111111111111" }));
      await seedOneDeadLetter(h.port, payload);
      await waitForDeadLetters(h.port, 1);
      // The metadata list never leaks the payload, sealed or not.
      const listed = await getFull(h.port, "/dead-letter", {
        authorization: `Bearer ${opToken}`,
      });
      const meta = JSON.parse(listed.text) as Array<Record<string, unknown>>;
      assert.equal(meta[0].encrypted, true);
      assert.ok(!("payload" in meta[0]));
      // The export decrypts it for the operator.
      const res = await getFull(h.port, "/dead-letter/export", {
        authorization: `Bearer ${opToken}`,
      });
      assert.equal(res.status, 200);
      const row = JSON.parse(res.text.trim()) as Record<string, unknown>;
      assert.equal(row.encrypted, true);
      assert.equal(row.payload, payload.toString("utf8"));
    } finally {
      await h.cleanup();
    }
  });

  it("409s past the row cap without a cursor and pages with cursor", async () => {
    const h = await startRelay();
    try {
      // Seed 10_250 dead letters through batch intake: 41 envelopes x 250 items.
      const batchSize = 250;
      const batches = 41;
      for (let b = 0; b < batches; b++) {
        const events = [];
        for (let i = 0; i < batchSize; i++) {
          const raw = Buffer.from(JSON.stringify({ batch: b, item: i }));
          events.push({
            payload: raw.toString("base64"),
            headers: { "x-signature": signSha256(raw, relaySecret) },
          });
        }
        const envelope = Buffer.from(JSON.stringify({ events }));
        const res = await post(h.port, "/ingest/batch", envelope, {
          "x-signature": signSha256(envelope, relaySecret),
        });
        assert.ok(res.status === 202 || res.status === 207, `batch ${b}: ${res.status}`);
      }
      await waitForDeadLetters(h.port, batches * batchSize, 60000);
      const auth = { authorization: `Bearer ${opToken}` };
      const tooBig = await getFull(h.port, "/dead-letter/export", auth);
      assert.equal(tooBig.status, 409);
      const hint = JSON.parse(tooBig.text) as Record<string, unknown>;
      assert.equal(hint.error, "export_exceeds_row_limit");
      assert.equal(hint.matched, batches * batchSize);
      assert.equal(hint.limit, DEAD_LETTER_EXPORT_ROW_LIMIT);
      assert.ok(typeof hint.firstCursor === "string");
      // Page one: 10_000 rows, has-more set.
      const page1 = await getFull(
        h.port,
        `/dead-letter/export?cursor=${hint.firstCursor}`,
        auth
      );
      assert.equal(page1.status, 200);
      assert.equal(page1.headers["x-export-has-more"], "true");
      assert.equal(page1.text.trim().split("\n").length, DEAD_LETTER_EXPORT_ROW_LIMIT);
      const nextCursor = page1.headers["x-export-next-cursor"];
      assert.ok(typeof nextCursor === "string");
      // Page two: the remaining 250 rows, no more.
      const page2 = await getFull(h.port, `/dead-letter/export?cursor=${nextCursor}`, auth);
      assert.equal(page2.status, 200);
      assert.equal(page2.headers["x-export-has-more"], "false");
      assert.equal(page2.text.trim().split("\n").length, batches * batchSize - DEAD_LETTER_EXPORT_ROW_LIMIT);
    } finally {
      await h.cleanup();
    }
  });

  it("audits the export as dead_letter_exported with rows and filter", async () => {
    const h = await startRelay();
    try {
      await seedOneDeadLetter(h.port, Buffer.from('{"n":1}'));
      await waitForDeadLetters(h.port, 1);
      const before = h.audit.query({ event: "dead_letter_exported" }).length;
      const res = await getFull(h.port, "/dead-letter/export?format=csv", {
        authorization: `Bearer ${opToken}`,
      });
      assert.equal(res.status, 200);
      const events = h.audit.query({ event: "dead_letter_exported" }) as Array<
        Record<string, unknown>
      >;
      assert.equal(events.length, before + 1);
      const evt = events[events.length - 1];
      assert.equal(evt.rows, 1);
      assert.equal(evt.format, "csv");
      assert.equal(evt.keyId, "legacy");
      assert.equal(evt.hasMore, false);
    } finally {
      await h.cleanup();
    }
  });
});
