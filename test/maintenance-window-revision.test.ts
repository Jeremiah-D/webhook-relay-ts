/**
 * WR-316: single-window live revision of one-shot maintenance windows
 * (`reviseMaintenanceWindow` / `cancelMaintenanceWindow`).
 *
 * Tests:
 * 1. Module `reviseWindow`: start/end/both revision, extend/shorten/move.
 * 2. Unknown window / illegal patch throw RangeError, table untouched.
 * 3. Announced flag: carried over while the window still covers now,
 *    reset when moved wholly into the future, closed once when the
 *    revised end is at or before now.
 * 4. Module `cancelWindow`: announced-active window fires closed once;
 *    unknown windows return false.
 * 5. A revision overlapping a neighbour merges.
 * 6. RelayServer methods delegate + audit (`maintenance_window_revised`
 *    with previous/current, `maintenance_window_cancelled`); same-value
 *    revisions stay silent; disabled features return null.
 * 7. Operator PATCH/DELETE /maintenance/windows: 200/400/404 + admin
 *    scope enforcement.
 * 8. An in-flight parked delivery re-parks to the revised end (extend
 *    re-parks, shorten flushes at the new end) without burning attempts.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { EndpointMaintenanceWindow } from "../src/maintenance-window.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "maintenance-window-revision-secret";
const operatorToken = "maintenance-revision-op-token";
const readerKey = "maintenance-revision-reader-key";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

/** Fixed instant: 2026-11-01T00:00:00Z. */
const T0 = Date.UTC(2026, 10, 1, 0, 0, 0);
const iso = (ms: number) => new Date(ms).toISOString();
const H = 3_600_000;

/** Manual timer that also records the scheduled delays. */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pendingCount: () => pending.length,
    lastDelay: () => pending[pending.length - 1]?.ms,
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

function auditEvents(audit: AuditLog): Array<Record<string, unknown>> {
  return audit.readAll() as Array<Record<string, unknown>>;
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function req(port: number, method: string, path: string, body?: unknown, token?: string) {
  const raw = body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body);
  const headers: Record<string, string> = { "content-type": "application/json" };
  // Node's http client does not auto-frame a DELETE body (no
  // Content-Length, no chunked encoding — the bytes land unframed and
  // the server's parser rejects the next "request line"), so always
  // send an explicit length when a body is present.
  if (raw !== undefined) headers["content-length"] = String(Buffer.byteLength(raw));
  if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
      );
    });
    r.on("error", reject);
    if (raw !== undefined) r.end(raw);
    else r.end();
  });
}

async function closeRelay(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

describe("EndpointMaintenanceWindow.reviseWindow", () => {
  it("revises start, end, or both; omitted fields keep live values", () => {
    let now = T0;
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
      now: () => now,
    });
    const key = { start: iso(T0 + H), end: iso(T0 + 2 * H) };
    // Start only.
    const moved = w.reviseWindow(URL_A, key, { newStart: iso(T0 + H / 2) });
    assert.equal(moved.start, iso(T0 + H / 2));
    assert.equal(moved.end, iso(T0 + 2 * H));
    // End only.
    const stretched = w.reviseWindow(
      URL_A,
      { start: iso(T0 + H / 2), end: iso(T0 + 2 * H) },
      { newEnd: iso(T0 + 3 * H) }
    );
    assert.equal(stretched.start, iso(T0 + H / 2));
    assert.equal(stretched.end, iso(T0 + 3 * H));
    // Both.
    const both = w.reviseWindow(
      URL_A,
      { start: iso(T0 + H / 2), end: iso(T0 + 3 * H) },
      { newStart: iso(T0 + 3 * H / 2), newEnd: iso(T0 + 5 * H / 2) }
    );
    assert.equal(both.start, iso(T0 + 3 * H / 2));
    assert.equal(both.end, iso(T0 + 5 * H / 2));
    assert.equal(w.windowsFor(URL_A).length, 1);
  });

  it("extends, shortens, and moves a window wholly into the future", () => {
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
      now: () => T0,
    });
    const extended = w.reviseWindow(
      URL_A,
      { start: iso(T0 + H), end: iso(T0 + 2 * H) },
      { newEnd: iso(T0 + 4 * H) }
    );
    assert.equal(extended.end, iso(T0 + 4 * H));
    const shortened = w.reviseWindow(
      URL_A,
      { start: iso(T0 + H), end: iso(T0 + 4 * H) },
      { newEnd: iso(T0 + 3 * H / 2) }
    );
    assert.equal(shortened.end, iso(T0 + 3 * H / 2));
    const moved = w.reviseWindow(
      URL_A,
      { start: iso(T0 + H), end: iso(T0 + 3 * H / 2) },
      { newStart: iso(T0 + 5 * H), newEnd: iso(T0 + 6 * H) }
    );
    assert.equal(moved.start, iso(T0 + 5 * H));
    assert.equal(moved.end, iso(T0 + 6 * H));
    assert.equal(w.windowsFor(URL_A).length, 1);
  });

  it("throws RangeError for an unknown window and leaves the table untouched", () => {
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
      now: () => T0,
    });
    assert.throws(
      () =>
        w.reviseWindow(URL_A, { start: iso(T0 + 5 * H), end: iso(T0 + 6 * H) }, { newEnd: iso(T0 + 7 * H) }),
      RangeError
    );
    assert.throws(
      () =>
        w.reviseWindow(URL_B, { start: iso(T0 + H), end: iso(T0 + 2 * H) }, { newEnd: iso(T0 + 3 * H) }),
      RangeError
    );
    assert.equal(w.windowsFor(URL_A).length, 1);
    assert.equal(w.windowsFor(URL_A)[0].end, iso(T0 + 2 * H));
  });

  it("throws RangeError for an illegal patch and leaves the table untouched", () => {
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
      now: () => T0,
    });
    const key = { start: iso(T0 + H), end: iso(T0 + 2 * H) };
    assert.throws(() => w.reviseWindow(URL_A, key, {}), RangeError, "empty patch");
    assert.throws(
      () => w.reviseWindow(URL_A, key, { newStart: iso(T0 + 2 * H), newEnd: iso(T0 + H) }),
      RangeError,
      "end before start"
    );
    assert.throws(
      () => w.reviseWindow(URL_A, key, { newEnd: iso(T0 + H) }),
      RangeError,
      "zero-length window"
    );
    assert.throws(
      () => w.reviseWindow(URL_A, key, { newStart: "not a date" }),
      RangeError,
      "non-RFC3339 newStart"
    );
    assert.equal(w.windowsFor(URL_A).length, 1);
    assert.equal(w.windowsFor(URL_A)[0].start, iso(T0 + H));
    assert.equal(w.windowsFor(URL_A)[0].end, iso(T0 + 2 * H));
  });

  it("keeps the announced flag when the revised window still covers now", () => {
    let now = T0;
    const transitions: string[] = [];
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
      now: () => now,
      onTransition: (t) => transitions.push(t.kind),
    });
    now = T0 + H + 1_000;
    assert.equal(w.announcePark(URL_A), true);
    assert.deepEqual(transitions, ["opened"]);
    // Still covers now: the flag carries over, no second `opened`.
    w.reviseWindow(
      URL_A,
      { start: iso(T0 + H), end: iso(T0 + 2 * H) },
      { newStart: iso(T0 + H / 2) }
    );
    assert.equal(w.announcePark(URL_A), false);
    assert.deepEqual(transitions, ["opened"]);
  });

  it("resets the announced flag when the window moves wholly into the future", () => {
    let now = T0;
    const transitions: string[] = [];
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
      now: () => now,
      onTransition: (t) => transitions.push(t.kind),
    });
    now = T0 + H + 1_000;
    assert.equal(w.announcePark(URL_A), true);
    w.reviseWindow(
      URL_A,
      { start: iso(T0 + H), end: iso(T0 + 2 * H) },
      { newStart: iso(T0 + 5 * H), newEnd: iso(T0 + 6 * H) }
    );
    // The moved window announces once on its first park.
    now = T0 + 5 * H + 1_000;
    assert.equal(w.announcePark(URL_A), true);
    assert.deepEqual(transitions, ["opened", "opened"]);
  });

  it("prunes a revision whose end is at or before now and fires closed exactly once", () => {
    let now = T0;
    const transitions: string[] = [];
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
      now: () => now,
      onTransition: (t) => transitions.push(t.kind),
    });
    now = T0 + H + 1_000;
    assert.equal(w.announcePark(URL_A), true);
    // Shorten the window to end before now: the next read prunes it.
    w.reviseWindow(
      URL_A,
      { start: iso(T0 + H), end: iso(T0 + 2 * H) },
      { newStart: iso(T0 + H / 2), newEnd: iso(T0 + H) }
    );
    assert.equal(w.windowsFor(URL_A).length, 0);
    assert.deepEqual(transitions, ["opened", "closed"]);
    // A second read does not re-fire.
    w.windowsFor(URL_A);
    assert.deepEqual(transitions, ["opened", "closed"]);
  });

  it("merges a revision that overlaps a neighbour", () => {
    const w = new EndpointMaintenanceWindow({
      windows: {
        [URL_A]: [
          { start: iso(T0 + H), end: iso(T0 + 2 * H) },
          { start: iso(T0 + 3 * H), end: iso(T0 + 4 * H) },
        ],
      },
      now: () => T0,
    });
    const merged = w.reviseWindow(
      URL_A,
      { start: iso(T0 + H), end: iso(T0 + 2 * H) },
      { newEnd: iso(T0 + 7 * H / 2) }
    );
    assert.equal(merged.start, iso(T0 + H));
    assert.equal(merged.end, iso(T0 + 4 * H));
    assert.equal(w.windowsFor(URL_A).length, 1);
  });
});

describe("EndpointMaintenanceWindow.cancelWindow", () => {
  it("cancelling an announced active window fires closed exactly once; unknown windows return false", () => {
    let now = T0;
    const transitions: string[] = [];
    const w = new EndpointMaintenanceWindow({
      windows: {
        [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }],
        [URL_B]: [{ start: iso(T0 + 3 * H), end: iso(T0 + 4 * H) }],
      },
      now: () => now,
      onTransition: (t) => transitions.push(t.kind),
    });
    now = T0 + H + 1_000;
    assert.equal(w.announcePark(URL_A), true);
    assert.equal(
      w.cancelWindow(URL_A, { start: iso(T0 + H), end: iso(T0 + 2 * H) }),
      true
    );
    assert.deepEqual(transitions, ["opened", "closed"]);
    assert.equal(w.windowsFor(URL_A).length, 0);
    // Unknown window / endpoint: false, table untouched.
    assert.equal(
      w.cancelWindow(URL_A, { start: iso(T0 + H), end: iso(T0 + 2 * H) }),
      false
    );
    assert.equal(
      w.cancelWindow(URL_B, { start: iso(T0 + H), end: iso(T0 + 2 * H) }),
      false
    );
    assert.equal(w.windowsFor(URL_B).length, 1);
    // Cancelling a never-announced window is silent (no closed).
    assert.equal(
      w.cancelWindow(URL_B, { start: iso(T0 + 3 * H), end: iso(T0 + 4 * H) }),
      true
    );
    assert.deepEqual(transitions, ["opened", "closed"]);
  });
});

describe("RelayServer maintenance window revision (WR-316)", () => {
  it("server methods delegate and audit; same-value revisions stay silent; disabled returns null", async () => {
    let now = T0;
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test files (see AGENTS.md).
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      retry: {
        maintenanceWindow: {
          windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
          now: () => now,
        },
      },
      operatorToken,
    });
    try {
      const revised = relay.reviseMaintenanceWindow(
        URL_A,
        { start: iso(T0 + H), end: iso(T0 + 2 * H) },
        { newEnd: iso(T0 + 3 * H) }
      );
      assert.ok(revised !== null);
      assert.equal(revised.end, iso(T0 + 3 * H));
      const revisedEvents = auditEvents(audit).filter((e) => e.event === "maintenance_window_revised");
      assert.equal(revisedEvents.length, 1);
      assert.equal(revisedEvents[0].endpoint, URL_A);
      assert.deepEqual(revisedEvents[0].previous, { start: iso(T0 + H), end: iso(T0 + 2 * H) });
      assert.deepEqual(revisedEvents[0].current, { start: iso(T0 + H), end: iso(T0 + 3 * H) });

      // Same-value revision: no audit event.
      relay.reviseMaintenanceWindow(
        URL_A,
        { start: iso(T0 + H), end: iso(T0 + 3 * H) },
        { newEnd: iso(T0 + 3 * H) }
      );
      assert.equal(
        auditEvents(audit).filter((e) => e.event === "maintenance_window_revised").length,
        1,
        "same-value revision is a silent no-op"
      );

      // Unknown window throws RangeError; no audit.
      assert.throws(
        () =>
          relay.reviseMaintenanceWindow(
            URL_A,
            { start: iso(T0 + 5 * H), end: iso(T0 + 6 * H) },
            { newEnd: iso(T0 + 7 * H) }
          ),
        RangeError
      );
      assert.equal(
        auditEvents(audit).filter((e) => e.event === "maintenance_window_revised").length,
        1
      );

      // Cancel: audited, then a second cancel is false and silent.
      assert.equal(
        relay.cancelMaintenanceWindow(URL_A, { start: iso(T0 + H), end: iso(T0 + 3 * H) }),
        true
      );
      const cancelled = auditEvents(audit).filter((e) => e.event === "maintenance_window_cancelled");
      assert.equal(cancelled.length, 1);
      assert.equal(cancelled[0].endpoint, URL_A);
      assert.equal(cancelled[0].start, iso(T0 + H));
      assert.equal(cancelled[0].end, iso(T0 + 3 * H));
      assert.equal(
        relay.cancelMaintenanceWindow(URL_A, { start: iso(T0 + H), end: iso(T0 + 3 * H) }),
        false
      );
      assert.equal(
        auditEvents(audit).filter((e) => e.event === "maintenance_window_cancelled").length,
        1
      );
    } finally {
      await closeRelay(relay);
    }

    // Disabled: both server methods return null.
    const bare = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "audit-")), "audit.jsonl")),
      operatorToken,
    });
    try {
      assert.equal(
        bare.reviseMaintenanceWindow(URL_A, { start: iso(T0 + H), end: iso(T0 + 2 * H) }, { newEnd: iso(T0 + 3 * H) }),
        null
      );
      assert.equal(
        bare.cancelMaintenanceWindow(URL_A, { start: iso(T0 + H), end: iso(T0 + 2 * H) }),
        null
      );
    } finally {
      await closeRelay(bare);
    }
  });

  it("operator PATCH/DELETE answer 200/400/404 and enforce admin scope", async () => {
    let now = T0;
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      retry: {
        maintenanceWindow: {
          windows: { [URL_A]: [{ start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z" }] },
          now: () => now,
        },
      },
      operatorToken,
    });
    const port = await listen(relay);
    try {
      // No token / bad bearer: 403.
      assert.equal(
        (await req(port, "PATCH", "/maintenance/windows", { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z", newEnd: "2026-11-01T08:00:00Z" })).status,
        403
      );
      assert.equal(
        (await req(port, "DELETE", "/maintenance/windows", { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z" }, "wrong-token")).status,
        403
      );

      // Valid revision: 200, audited as maintenance_window_revised.
      const patched = await req(
        port,
        "PATCH",
        "/maintenance/windows",
        { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z", newEnd: "2026-11-01T08:00:00Z" },
        operatorToken
      );
      assert.equal(patched.status, 200);
      const patchedBody = JSON.parse(patched.text) as { ok: boolean; window: { start: string; end: string } };
      assert.equal(patchedBody.ok, true);
      assert.equal(patchedBody.window.end, "2026-11-01T08:00:00Z");
      assert.equal(
        auditEvents(audit).filter((e) => e.event === "maintenance_window_revised").length,
        1
      );

      // Unknown window: 400. Empty patch: 400. Bad JSON: 400.
      assert.equal(
        (await req(port, "PATCH", "/maintenance/windows", { endpoint: URL_A, start: "2026-11-01T10:00:00Z", end: "2026-11-01T11:00:00Z", newEnd: "2026-11-01T12:00:00Z" }, operatorToken)).status,
        400
      );
      assert.equal(
        (await req(port, "PATCH", "/maintenance/windows", { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T08:00:00Z" }, operatorToken)).status,
        400
      );
      assert.equal(
        (await req(port, "PATCH", "/maintenance/windows", "not json", operatorToken)).status,
        400
      );

      // Cancel the revised window: 200, audited; a second cancel: 404.
      const deleted = await req(
        port,
        "DELETE",
        "/maintenance/windows",
        { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T08:00:00Z" },
        operatorToken
      );
      assert.equal(deleted.status, 200);
      assert.deepEqual(JSON.parse(deleted.text), { ok: true, removed: true });
      assert.equal(
        auditEvents(audit).filter((e) => e.event === "maintenance_window_cancelled").length,
        1
      );
      assert.equal(
        (await req(port, "DELETE", "/maintenance/windows", { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T08:00:00Z" }, operatorToken)).status,
        404
      );
    } finally {
      await closeRelay(relay);
    }

    // Read-scope key: PATCH/DELETE are admin-only (403).
    const readerRelay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "audit-")), "audit.jsonl")),
      retry: { maintenanceWindow: {} },
      operatorKeys: [{ id: "reader", key: readerKey, scopes: ["read"] }],
    });
    const readerPort = await listen(readerRelay);
    try {
      assert.equal(
        (await req(readerPort, "PATCH", "/maintenance/windows", { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z", newEnd: "2026-11-01T08:00:00Z" }, readerKey)).status,
        403
      );
      assert.equal(
        (await req(readerPort, "DELETE", "/maintenance/windows", { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z" }, readerKey)).status,
        403
      );
    } finally {
      await closeRelay(readerRelay);
    }

    // Disabled feature: PATCH/DELETE answer 404.
    const bare = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "audit-")), "audit.jsonl")),
      operatorToken,
    });
    const barePort = await listen(bare);
    try {
      assert.equal(
        (await req(barePort, "PATCH", "/maintenance/windows", { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z", newEnd: "2026-11-01T08:00:00Z" }, operatorToken)).status,
        404
      );
      assert.equal(
        (await req(barePort, "DELETE", "/maintenance/windows", { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z" }, operatorToken)).status,
        404
      );
    } finally {
      await closeRelay(bare);
    }
  });
});

describe("RetryQueue maintenance window revision (WR-316)", () => {
  it("a parked delivery re-parks to the revised end (extend), or flushes at the shortened end", async () => {
    // Extend: the armed timer fires at the old end, the live table is
    // re-checked, and the delivery re-parks to the new end.
    let now = T0;
    const t = manualTimer();
    let senderCalls = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 2,
      baseDelayMs: 10,
      jitterMs: 0,
      maintenanceWindow: {
        windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
        now: () => now,
      },
    });
    q.start();
    now = T0 + H + 1_000; // inside the window
    q.enqueue(item("r1", URL_A));
    await t.step(); // parked, no send
    assert.equal(senderCalls, 0);
    assert.equal(t.lastDelay(), H - 1_000);
    // Extend the window to 03:00 while the delivery is parked.
    const revised = q.reviseMaintenanceWindow(
      URL_A,
      { start: iso(T0 + H), end: iso(T0 + 2 * H) },
      { newEnd: iso(T0 + 3 * H) }
    );
    assert.ok(revised !== null);
    assert.equal(revised.end, iso(T0 + 3 * H));
    now = T0 + 2 * H; // old end: the armed timer fires, live table re-checked
    await t.step();
    assert.equal(senderCalls, 0, "extended window re-parks instead of escaping early");
    assert.equal(t.lastDelay(), H, "re-parked to the new end");
    now = T0 + 3 * H; // new end: flush
    await t.step();
    assert.equal(senderCalls, 1, "delivery goes out at the revised window end");
    q.stop();

    // Shorten: the armed timer fires past the new end, so the delivery
    // flushes instead of re-parking.
    now = T0;
    const t2 = manualTimer();
    let senderCalls2 = 0;
    const sender2: Sender = async () => {
      senderCalls2 += 1;
    };
    const q2 = new RetryQueue({
      sender: sender2,
      setTimer: t2.setTimer,
      maxAttempts: 2,
      baseDelayMs: 10,
      jitterMs: 0,
      maintenanceWindow: {
        windows: { [URL_A]: [{ start: iso(T0 + H), end: iso(T0 + 2 * H) }] },
        now: () => now,
      },
    });
    q2.start();
    now = T0 + H + 1_000;
    q2.enqueue(item("r2", URL_A));
    await t2.step();
    assert.equal(senderCalls2, 0);
    q2.reviseMaintenanceWindow(
      URL_A,
      { start: iso(T0 + H), end: iso(T0 + 2 * H) },
      { newEnd: iso(T0 + 3 * H / 2) }
    );
    now = T0 + 2 * H; // past the shortened end
    await t2.step();
    assert.equal(senderCalls2, 1, "shortened window flushes at the new end");
    q2.stop();
  });
});
