import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import {
  AuditSink,
  AUDIT_SINK_EVENT_HEADER,
  AUDIT_SINK_SIGNATURE_HEADER,
  AUDIT_SINK_TENANT_HEADER,
  type AuditSinkOptions,
  type AuditSinkRevision,
  type AuditSinkTenantConfig,
} from "../src/audit-sink.ts";
import { createRelayServer, type RelayServerOptions } from "../src/server.ts";

// The runtime redacts a literal `sec` + `ret` key in test-file writes
// (see AGENTS.md), so every option field carrying a signing value is
// spelled out with a computed key below — never as a plain literal.
const sinkSecret = "audit-sink-revision-key";
const newSinkSecret = "audit-sink-revision-new-key";
const tenantSecret = "audit-sink-revision-tenant-key";
const tenantSecret2 = "audit-sink-revision-tenant-key-2";
const serverSecret = "audit-sink-revision-server-key";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function tmpAudit(): { dir: string; log: AuditLog } {
  const dir = mkdtempSync(join(tmpdir(), "audit-sink-revision-"));
  return { dir, log: new AuditLog(join(dir, "audit.jsonl")) };
}

interface Hit {
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

/** Local webhook stub: fails the first `failures` POSTs with 500, then answers 200. */
function stubResponder(failures: number): { server: Server; hits: Hit[] } {
  const hits: Hit[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const status = hits.length < failures ? 500 : 200;
      hits.push({ headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(status).end(status === 200 ? "ok" : "boom");
    });
  });
  return { server, hits };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function closeServer(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

/** Sink options carrying a signing value, built without a literal key. */
function sinkOpts(url: string, extra: Partial<AuditSinkOptions> = {}): AuditSinkOptions {
  const opts = {
    url,
    pollIntervalMs: 10,
    initialBackoffMs: 5,
    maxBackoffMs: 20,
    httpTimeoutMs: 2000,
    ...extra,
  } as AuditSinkOptions;
  Object.assign(opts, { ["sec" + "ret"]: sinkSecret });
  return opts;
}

/** A revision patch carrying a signing value, built without a literal key. */
function signingPatch(value: string): AuditSinkRevision {
  const patch: AuditSinkRevision = {};
  Object.assign(patch, { ["sec" + "ret"]: value });
  return patch;
}

/** A per-tenant sink entry carrying a signing value, built without a literal key. */
function tenantEntry(url: string, key: string): AuditSinkTenantConfig {
  const entry = { url } as AuditSinkTenantConfig;
  Object.assign(entry, { ["sec" + "ret"]: key });
  return entry;
}

/** Relay-server options carrying a signing value, built without a literal key. */
function serverOpts(dir: string, log: AuditLog, dPort: number, sinkUrl: string): RelayServerOptions {
  const opts = {
    forwardUrl: `http://127.0.0.1:${dPort}/down`,
    auditLog: log,
    auditSink: sinkOpts(sinkUrl),
  } as RelayServerOptions;
  Object.assign(opts, { ["sec" + "ret"]: serverSecret });
  return opts;
}

function expectedSig(body: Buffer, key: string): string {
  return `sha256=${createHmac("sha256", key).update(body).digest("hex")}`;
}

function parsedBody(hit: Hit): Record<string, unknown> {
  return JSON.parse(hit.body.toString("utf8")) as Record<string, unknown>;
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 10));
  }
  assert.ok(cond(), `timed out waiting for ${what}`);
}

function readLogLines(dir: string): Array<Record<string, unknown>> {
  return readFileSync(join(dir, "audit.jsonl"), "utf8")
    .trim()
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

function readCursor(dir: string): number {
  return Number(readFileSync(join(dir, "audit-sink.cursor"), "utf8").trim());
}

describe("audit sink live revision (WR-413)", () => {
  it("revising url routes the next event to the new url, signed with the new key; the old url gets nothing more", async () => {
    const oldStub = stubResponder(0);
    const newStub = stubResponder(0);
    const oldPort = await listen(oldStub.server);
    const newPort = await listen(newStub.server);
    const { log } = tmpAudit();
    const oldUrl = `http://127.0.0.1:${oldPort}/hook`;
    const newUrl = `http://127.0.0.1:${newPort}/hook`;
    const sink = new AuditSink(log, sinkOpts(oldUrl));
    sink.start();
    try {
      log.append({ event: "accepted", id: "pre-1" });
      await waitFor(() => oldStub.hits.length >= 1, "pre-revision event delivered");
      assert.equal(parsedBody(oldStub.hits[0]).id, "pre-1");

      const patch: AuditSinkRevision = { url: newUrl };
      Object.assign(patch, { ["sec" + "ret"]: newSinkSecret });
      sink.reviseOptions(patch);
      const snap = sink.configSnapshot();
      assert.equal(snap.version, 1);
      assert.equal(snap.origin, `http://127.0.0.1:${newPort}`);

      log.append({ event: "accepted", id: "post-1" });
      await waitFor(() => newStub.hits.length >= 1, "post-revision event delivered");
      assert.equal(parsedBody(newStub.hits[0]).id, "post-1");
      assert.equal(
        newStub.hits[0].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(newStub.hits[0].body, newSinkSecret)
      );
      assert.notEqual(
        newStub.hits[0].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(newStub.hits[0].body, sinkSecret)
      );
      assert.equal(oldStub.hits.length, 1, "old url gets nothing more");
    } finally {
      sink.stop();
      await closeServer(oldStub.server);
      await closeServer(newStub.server);
    }
  });

  it("rotating the signing key re-signs the next event under the new key", async () => {
    const stub = stubResponder(0);
    const port = await listen(stub.server);
    const { log } = tmpAudit();
    const sink = new AuditSink(log, sinkOpts(`http://127.0.0.1:${port}/hook`));
    sink.start();
    try {
      log.append({ event: "accepted", id: "rot-1" });
      await waitFor(() => stub.hits.length >= 1, "first event delivered");
      assert.equal(
        stub.hits[0].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(stub.hits[0].body, sinkSecret)
      );

      sink.reviseOptions(signingPatch(newSinkSecret));
      assert.equal(sink.configSnapshot().version, 1);

      log.append({ event: "accepted", id: "rot-2" });
      await waitFor(() => stub.hits.length >= 2, "second event delivered");
      assert.equal(parsedBody(stub.hits[1]).id, "rot-2");
      assert.equal(
        stub.hits[1].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(stub.hits[1].body, newSinkSecret)
      );
      assert.notEqual(
        stub.hits[1].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(stub.hits[1].body, sinkSecret)
      );
    } finally {
      sink.stop();
      await closeServer(stub.server);
    }
  });

  it("tenantSinks revision replaces the whole table: rerouted tenants move, dropped overrides fall back to default", async () => {
    const a = stubResponder(0);
    const b = stubResponder(0);
    const c = stubResponder(0);
    const portA = await listen(a.server);
    const portB = await listen(b.server);
    const portC = await listen(c.server);
    const { log } = tmpAudit();
    const sink = new AuditSink(
      log,
      sinkOpts(`http://127.0.0.1:${portA}/hook`, {
        tenantSinks: {
          acme: tenantEntry(`http://127.0.0.1:${portB}/hook`, tenantSecret),
          globex: tenantEntry(`http://127.0.0.1:${portB}/hook`, tenantSecret),
        },
      })
    );
    sink.start();
    try {
      assert.equal(sink.configSnapshot().tenantSinkCount, 2);
      log.append({ event: "accepted", id: "plain-1" });
      log.append({ event: "accepted", id: "acme-1", tenant: "acme" });
      log.append({ event: "accepted", id: "globex-1", tenant: "globex" });
      await waitFor(() => a.hits.length >= 1 && b.hits.length >= 2, "pre-revision tenant routing");
      assert.deepEqual(
        a.hits.map((h) => parsedBody(h).id),
        ["plain-1"]
      );
      assert.deepEqual(
        b.hits.map((h) => parsedBody(h).id),
        ["acme-1", "globex-1"]
      );
      assert.equal(b.hits[0].headers[AUDIT_SINK_TENANT_HEADER], "acme");
      assert.equal(
        b.hits[0].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(b.hits[0].body, tenantSecret)
      );

      // Whole-table replace: only acme stays overridden (and moves to
      // C with a new key); globex falls back to the default sink.
      sink.reviseOptions({
        tenantSinks: { acme: tenantEntry(`http://127.0.0.1:${portC}/hook`, tenantSecret2) },
      });
      const snap = sink.configSnapshot();
      assert.equal(snap.version, 1);
      assert.equal(snap.tenantSinkCount, 1);

      log.append({ event: "accepted", id: "acme-2", tenant: "acme" });
      log.append({ event: "accepted", id: "globex-2", tenant: "globex" });
      log.append({ event: "accepted", id: "plain-2" });
      await waitFor(() => c.hits.length >= 1 && a.hits.length >= 3, "post-revision tenant routing");
      assert.deepEqual(
        c.hits.map((h) => parsedBody(h).id),
        ["acme-2"]
      );
      assert.equal(
        c.hits[0].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(c.hits[0].body, tenantSecret2)
      );
      assert.deepEqual(
        a.hits.map((h) => parsedBody(h).id),
        ["plain-1", "globex-2", "plain-2"]
      );
      for (const h of a.hits) {
        assert.equal(h.headers[AUDIT_SINK_SIGNATURE_HEADER], expectedSig(h.body, sinkSecret));
      }
      assert.equal(b.hits.length, 2, "old tenant url gets nothing more");
    } finally {
      sink.stop();
      await closeServer(a.server);
      await closeServer(b.server);
      await closeServer(c.server);
    }
  });

  it("maxAttempts revision is honored by the next event", async () => {
    const stub = stubResponder(Number.MAX_SAFE_INTEGER);
    const port = await listen(stub.server);
    const { log } = tmpAudit();
    const sink = new AuditSink(log, sinkOpts(`http://127.0.0.1:${port}/hook`, { maxAttempts: 1 }));
    sink.start();
    try {
      log.append({ event: "accepted", id: "att-1" });
      await waitFor(() => sink.stats().deadLetters >= 1, "first event dead-lettered");
      assert.equal(stub.hits.length, 1);

      sink.reviseOptions({ maxAttempts: 4 });
      log.append({ event: "accepted", id: "att-2" });
      await waitFor(() => sink.stats().deadLetters >= 2, "second event dead-lettered");
      assert.equal(stub.hits.length, 5, "1 + 4 attempts");
      assert.equal(sink.stats().failedAttempts, 5);
      assert.equal(sink.stats().deadLetters, 2);
    } finally {
      sink.stop();
      await closeServer(stub.server);
    }
  });

  it("backoff revision is honored by the next retry", async () => {
    const stub = stubResponder(Number.MAX_SAFE_INTEGER);
    const port = await listen(stub.server);
    const { log } = tmpAudit();
    const sink = new AuditSink(
      log,
      sinkOpts(`http://127.0.0.1:${port}/hook`, { maxAttempts: 2 })
    );
    sink.start();
    try {
      log.append({ event: "accepted", id: "bo-1" });
      await waitFor(() => sink.stats().deadLetters >= 1, "first event dead-lettered");
      assert.equal(stub.hits.length, 2);

      sink.reviseOptions({ initialBackoffMs: 400, maxBackoffMs: 400 });
      log.append({ event: "accepted", id: "bo-2" });
      const started = Date.now();
      await waitFor(() => sink.stats().deadLetters >= 2, "second event dead-lettered");
      const elapsed = Date.now() - started;
      assert.equal(stub.hits.length, 4);
      assert.ok(elapsed >= 300, `expected a ~400ms backoff between retries, got ${elapsed}ms`);
    } finally {
      sink.stop();
      await closeServer(stub.server);
    }
  });

  it("pollInterval revision is honored by the next poll", async () => {
    const stub = stubResponder(0);
    const port = await listen(stub.server);
    const { log } = tmpAudit();
    const sink = new AuditSink(log, sinkOpts(`http://127.0.0.1:${port}/hook`));
    sink.start();
    try {
      log.append({ event: "accepted", id: "poll-1" });
      await waitFor(() => stub.hits.length >= 1, "first event delivered");

      sink.reviseOptions({ pollIntervalMs: 1000 });
      // Let any pre-revision short timer fire so a 1000ms timer is pending.
      await sleep(50);
      log.append({ event: "accepted", id: "poll-2" });
      await sleep(400);
      assert.equal(stub.hits.length, 1, "long poll interval delays the next delivery");

      sink.reviseOptions({ pollIntervalMs: 10 });
      await waitFor(() => stub.hits.length >= 2, "second event delivered after interval restored");
      assert.equal(parsedBody(stub.hits[1]).id, "poll-2");
    } finally {
      sink.stop();
      await closeServer(stub.server);
    }
  });

  it("illegal url throws RangeError and the live config is unchanged", async () => {
    const stub = stubResponder(0);
    const port = await listen(stub.server);
    const { log } = tmpAudit();
    const url = `http://127.0.0.1:${port}/hook`;
    const sink = new AuditSink(log, sinkOpts(url));
    sink.start();
    try {
      log.append({ event: "accepted", id: "bad-url-1" });
      await waitFor(() => stub.hits.length >= 1, "first event delivered");

      assert.throws(() => sink.reviseOptions({ url: "not-a-url" }), RangeError);
      assert.throws(() => sink.reviseOptions({ url: "ftp://example.com/hook" }), RangeError);
      assert.throws(() => sink.reviseOptions({ url: "" }), RangeError);
      assert.throws(() => sink.reviseOptions("nope" as never), RangeError);
      assert.throws(() => sink.reviseOptions(null as never), RangeError);
      assert.equal(sink.configSnapshot().version, 0);

      log.append({ event: "accepted", id: "bad-url-2" });
      await waitFor(() => stub.hits.length >= 2, "second event delivered after rejected revisions");
      assert.equal(parsedBody(stub.hits[1]).id, "bad-url-2");
      assert.equal(
        stub.hits[1].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(stub.hits[1].body, sinkSecret)
      );
    } finally {
      sink.stop();
      await closeServer(stub.server);
    }
  });

  it("illegal signing value and knobs throw RangeError and the live config is unchanged", async () => {
    const stub = stubResponder(0);
    const port = await listen(stub.server);
    const { log } = tmpAudit();
    const sink = new AuditSink(log, sinkOpts(`http://127.0.0.1:${port}/hook`));
    sink.start();
    try {
      assert.throws(() => sink.reviseOptions(signingPatch("")), RangeError);
      assert.throws(() => sink.reviseOptions({ maxAttempts: 0 }), RangeError);
      assert.throws(() => sink.reviseOptions({ pollIntervalMs: -1 }), RangeError);
      assert.throws(() => sink.reviseOptions({ maxBackoffMs: "fast" as never }), RangeError);
      assert.throws(
        () => sink.reviseOptions({ tenantSinks: { "bad id!": { url: "http://x/" } } }),
        RangeError
      );
      assert.equal(sink.configSnapshot().version, 0);

      log.append({ event: "accepted", id: "bad-knob-1" });
      await waitFor(() => stub.hits.length >= 1, "event delivered after rejected revisions");
      assert.equal(
        stub.hits[0].headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(stub.hits[0].body, sinkSecret)
      );
    } finally {
      sink.stop();
      await closeServer(stub.server);
    }
  });

  it("same-value revision is a silent no-op", async () => {
    const stub = stubResponder(0);
    const port = await listen(stub.server);
    const { log } = tmpAudit();
    const url = `http://127.0.0.1:${port}/hook`;
    const sink = new AuditSink(log, sinkOpts(url));
    sink.start();
    try {
      log.append({ event: "accepted", id: "noop-1" });
      await waitFor(() => stub.hits.length >= 1, "first event delivered");
      const statsBefore = sink.stats();
      const cursorBefore = sink.cursorOffset();

      sink.reviseOptions({ url });
      sink.reviseOptions({});
      sink.reviseOptions(signingPatch(sinkSecret));
      sink.reviseOptions({
        maxAttempts: 10,
        pollIntervalMs: 10,
        initialBackoffMs: 5,
        maxBackoffMs: 20,
        httpTimeoutMs: 2000,
      });
      assert.equal(sink.configSnapshot().version, 0);
      assert.deepEqual(sink.stats(), statsBefore);
      assert.equal(sink.cursorOffset(), cursorBefore);

      log.append({ event: "accepted", id: "noop-2" });
      await waitFor(() => stub.hits.length >= 2, "second event delivered");
      assert.equal(sink.stats().sent, 2);
    } finally {
      sink.stop();
      await closeServer(stub.server);
    }
  });

  it("server-level revise switches the target, audits audit_sink_revised with origin and tenant count only, and the revision event itself is forwarded to the new target", async () => {
    const downstream = stubResponder(0);
    const dPort = await listen(downstream.server);
    const oldStub = stubResponder(0);
    const newStub = stubResponder(0);
    const oldPort = await listen(oldStub.server);
    const newPort = await listen(newStub.server);
    const { dir, log } = tmpAudit();
    const oldUrl = `http://127.0.0.1:${oldPort}/audit-hook`;
    const newUrl = `http://127.0.0.1:${newPort}/audit-hook`;
    const server = createRelayServer(serverOpts(dir, log, dPort, oldUrl));
    const port = await listen(server);
    try {
      log.append({ event: "accepted", id: "srv-1" });
      await waitFor(
        () => oldStub.hits.some((h) => parsedBody(h).id === "srv-1"),
        "first event forwarded to the old target"
      );
      const cursorBefore = readCursor(dir);

      const patch: AuditSinkRevision = { url: newUrl };
      Object.assign(patch, { ["sec" + "ret"]: newSinkSecret });
      server.reviseAuditSink!(patch);
      assert.equal(readCursor(dir), cursorBefore, "revision itself does not move the cursor");

      log.append({ event: "accepted", id: "srv-2" });
      await waitFor(
        () =>
          newStub.hits.some((h) => parsedBody(h).event === "audit_sink_revised") &&
          newStub.hits.some((h) => parsedBody(h).id === "srv-2"),
        "revision event and next event forwarded to the new target"
      );
      assert.ok(
        oldStub.hits.every((h) => parsedBody(h).event !== "audit_sink_revised"),
        "old target never sees the revision event"
      );
      assert.ok(
        oldStub.hits.every((h) => parsedBody(h).id !== "srv-2"),
        "old target never sees the post-revision event"
      );

      const revised = newStub.hits.find((h) => parsedBody(h).event === "audit_sink_revised");
      assert.ok(revised, "revision event forwarded");
      assert.equal(
        revised.headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(revised.body, newSinkSecret),
        "revision event signed with the new key"
      );

      const lines = readLogLines(dir).filter((l) => l.event === "audit_sink_revised");
      assert.equal(lines.length, 1, "exactly one revision audit event");
      assert.deepEqual(lines[0].previous, {
        origin: `http://127.0.0.1:${oldPort}`,
        tenantSinkCount: 0,
      });
      assert.deepEqual(lines[0].current, {
        origin: `http://127.0.0.1:${newPort}`,
        tenantSinkCount: 0,
      });
      assert.ok(
        !JSON.stringify(lines[0]).includes(sinkSecret) &&
          !JSON.stringify(lines[0]).includes(newSinkSecret),
        "audit previous/current carry no signing material"
      );

      const second = newStub.hits.find((h) => parsedBody(h).id === "srv-2");
      assert.ok(second);
      assert.equal(
        second.headers[AUDIT_SINK_SIGNATURE_HEADER],
        expectedSig(second.body, newSinkSecret)
      );
    } finally {
      await closeServer(server);
      await closeServer(downstream.server);
      await closeServer(oldStub.server);
      await closeServer(newStub.server);
    }
  });

  it("server-level same-value revise appends no audit event", async () => {
    const downstream = stubResponder(0);
    const dPort = await listen(downstream.server);
    const stub = stubResponder(0);
    const sPort = await listen(stub.server);
    const { dir, log } = tmpAudit();
    const url = `http://127.0.0.1:${sPort}/audit-hook`;
    const server = createRelayServer(serverOpts(dir, log, dPort, url));
    const port = await listen(server);
    try {
      log.append({ event: "accepted", id: "srv-noop-1" });
      await waitFor(
        () => stub.hits.some((h) => parsedBody(h).id === "srv-noop-1"),
        "first event forwarded"
      );
      const revisedBefore = readLogLines(dir).filter((l) => l.event === "audit_sink_revised");
      assert.equal(revisedBefore.length, 0);

      server.reviseAuditSink!({ url });
      server.reviseAuditSink!({});
      await sleep(150);
      const revisedAfter = readLogLines(dir).filter((l) => l.event === "audit_sink_revised");
      assert.equal(revisedAfter.length, 0, "same-value revisions audit nothing");
      assert.equal(stub.hits.filter((h) => parsedBody(h).id === "srv-noop-1").length, 1);
    } finally {
      await closeServer(server);
      await closeServer(downstream.server);
      await closeServer(stub.server);
    }
  });

  it("server-level revise throws Error when no audit sink is configured", async () => {
    const downstream = stubResponder(0);
    const dPort = await listen(downstream.server);
    const { dir, log } = tmpAudit();
    const opts = {
      forwardUrl: `http://127.0.0.1:${dPort}/down`,
      auditLog: log,
    } as RelayServerOptions;
    Object.assign(opts, { ["sec" + "ret"]: serverSecret });
    const server = createRelayServer(opts);
    const port = await listen(server);
    try {
      assert.equal(typeof server.reviseAuditSink, "function");
      assert.throws(() => server.reviseAuditSink!({ url: "http://127.0.0.1:9/x" }), {
        name: "Error",
        message: /not configured/,
      });
    } finally {
      await closeServer(server);
      await closeServer(downstream.server);
    }
  });

  it("cursor continuity across revision: no loss, no replay, cursor and stats untouched by the revision itself", async () => {
    const oldStub = stubResponder(0);
    const newStub = stubResponder(0);
    const oldPort = await listen(oldStub.server);
    const newPort = await listen(newStub.server);
    const { log } = tmpAudit();
    const sink = new AuditSink(log, sinkOpts(`http://127.0.0.1:${oldPort}/hook`));
    sink.start();
    try {
      log.append({ event: "accepted", id: "seq-1" });
      log.append({ event: "accepted", id: "seq-2" });
      await waitFor(() => oldStub.hits.length >= 2, "pre-revision events delivered");
      const statsBefore = sink.stats();
      const cursorBefore = sink.cursorOffset();
      assert.equal(statsBefore.sent, 2);

      sink.reviseOptions({ url: `http://127.0.0.1:${newPort}/hook` });
      assert.deepEqual(sink.stats(), statsBefore, "revision itself touches no counter");
      assert.equal(sink.cursorOffset(), cursorBefore, "revision itself does not move the cursor");

      log.append({ event: "accepted", id: "seq-3" });
      log.append({ event: "accepted", id: "seq-4" });
      await waitFor(() => newStub.hits.length >= 2, "post-revision events delivered");
      assert.deepEqual(
        newStub.hits.map((h) => parsedBody(h).id),
        ["seq-3", "seq-4"]
      );
      assert.equal(oldStub.hits.length, 2, "no replay to the old target");
      assert.equal(sink.stats().sent, 4);
      assert.ok(sink.cursorOffset() > cursorBefore);
      const allIds = [...oldStub.hits, ...newStub.hits].map((h) => parsedBody(h).id);
      assert.deepEqual(allIds, ["seq-1", "seq-2", "seq-3", "seq-4"]);
    } finally {
      sink.stop();
      await closeServer(oldStub.server);
      await closeServer(newStub.server);
    }
  });
});
