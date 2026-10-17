/**
 * WR-127: per-endpoint one-shot maintenance windows.
 *
 * Tests:
 * 1. RFC3339 parsing/validation of the window table.
 * 2. isParked / msUntilOpen edge semantics (start inclusive, end exclusive).
 * 3. Overlapping/touching window merge on insert.
 * 4. Lazy pruning of ended windows.
 * 5. maintenance_window_opened/closed transition announcements.
 * 6. RetryQueue gate: parked deliveries consume nothing and flush at window end.
 * 7. Operator endpoints GET/POST /maintenance/windows + audit wiring.
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
import { signSha256 } from "../src/verify.ts";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

/** Fixed instant: 2026-11-01T00:00:00Z. */
const T0 = Date.UTC(2026, 10, 1, 0, 0, 0);
const iso = (ms: number) => new Date(ms).toISOString();

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

function item(id: string, targetUrl: string, tenantId?: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {}, tenantId };
}

describe("EndpointMaintenanceWindow validation", () => {
  it("accepts RFC3339 instants (Z, offsets, seconds, fractions)", () => {
    const w = new EndpointMaintenanceWindow({
      windows: {
        [URL_A]: [
          { start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z" },
          { start: "2026-11-02T02:00:00+02:00", end: "2026-11-02T06:00:00+02:00" },
          { start: "2026-11-03T02:00:00.500Z", end: "2026-11-03T02:00:01Z" },
        ],
      },
    });
    assert.equal(w.windowsFor(URL_A).length, 3);
  });

  it("rejects non-RFC3339 or impossible windows with RangeError", () => {
    const cases: Array<[{ start: unknown; end: unknown }, string]> = [
      [{ start: "Nov 1 2026 02:00", end: "2026-11-01T06:00:00Z" }, "non-RFC3339 start"],
      [{ start: "2026-11-01 02:00:00Z", end: "2026-11-01T06:00:00Z" }, "space instead of T"],
      [{ start: "2026-13-01T02:00:00Z", end: "2026-11-01T06:00:00Z" }, "month 13"],
      [{ start: "2026-11-01T02:00:00Z", end: "2026-11-01T02:00:00Z" }, "zero-length"],
      [{ start: "2026-11-01T06:00:00Z", end: "2026-11-01T02:00:00Z" }, "end before start"],
      [{ start: "", end: "2026-11-01T06:00:00Z" }, "empty start"],
      [{ start: undefined, end: "2026-11-01T06:00:00Z" }, "missing start"],
    ];
    for (const [entry, why] of cases) {
      assert.throws(
        () => new EndpointMaintenanceWindow({ windows: { [URL_A]: [entry as never] } }),
        RangeError,
        why
      );
    }
    // A bad entry aborts the whole construction (zero partial application).
    assert.throws(
      () =>
        new EndpointMaintenanceWindow({
          windows: {
            [URL_A]: [{ start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z" }],
            [URL_B]: [{ start: "nope", end: "2026-11-01T06:00:00Z" }],
          },
        }),
      RangeError
    );
    assert.throws(() => new EndpointMaintenanceWindow({ windows: { "": [] } }), RangeError);
    assert.throws(
      () => new EndpointMaintenanceWindow({ windows: { [URL_A]: "nope" as never } }),
      RangeError
    );
  });
});

describe("EndpointMaintenanceWindow gating", () => {
  it("parks inside [start, end): start inclusive, end exclusive", () => {
    let now = T0;
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + 3_600_000), end: iso(T0 + 2 * 3_600_000) }] },
      now: () => now,
    });
    now = T0 + 3_600_000 - 1;
    assert.equal(w.isParked(URL_A), false);
    now = T0 + 3_600_000;
    assert.equal(w.isParked(URL_A), true); // start edge inclusive
    now = T0 + 2 * 3_600_000 - 1;
    assert.equal(w.isParked(URL_A), true);
    now = T0 + 2 * 3_600_000;
    assert.equal(w.isParked(URL_A), false); // end edge exclusive: flush at close
    now = T0 + 3 * 3_600_000;
    assert.equal(w.isParked(URL_A), false);
    assert.equal(w.isParked(URL_B), false); // unconfigured endpoint never parks
    assert.equal(w.isParked("unknown"), false);
  });

  it("msUntilOpen targets the window end when parked, 0 otherwise", () => {
    let now = T0;
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + 3_600_000), end: iso(T0 + 2 * 3_600_000) }] },
      now: () => now,
    });
    now = T0;
    assert.equal(w.msUntilOpen(URL_A), 0); // before the window: no pre-wait
    now = T0 + 3_600_000 + 1_000;
    assert.equal(w.msUntilOpen(URL_A), 3_600_000 - 1_000);
    now = T0 + 2 * 3_600_000;
    assert.equal(w.msUntilOpen(URL_A), 0);
    assert.equal(w.msUntilOpen(URL_B), 0);
  });

  it("merges overlapping and touching windows", () => {
    const w = new EndpointMaintenanceWindow({
      windows: {
        [URL_A]: [
          { start: iso(T0 + 3_600_000), end: iso(T0 + 4 * 3_600_000) },
          { start: iso(T0 + 2 * 3_600_000), end: iso(T0 + 5 * 3_600_000) }, // overlap
        ],
        [URL_B]: [
          { start: iso(T0 + 3_600_000), end: iso(T0 + 4 * 3_600_000) },
          { start: iso(T0 + 4 * 3_600_000), end: iso(T0 + 5 * 3_600_000) }, // touching
        ],
      },
    });
    const a = w.windowsFor(URL_A);
    assert.equal(a.length, 1);
    assert.equal(a[0].start, iso(T0 + 3_600_000));
    assert.equal(a[0].end, iso(T0 + 5 * 3_600_000));
    const b = w.windowsFor(URL_B);
    assert.equal(b.length, 1);
    assert.equal(b[0].start, iso(T0 + 3_600_000));
    assert.equal(b[0].end, iso(T0 + 5 * 3_600_000));
  });

  it("keeps disjoint windows separate", () => {
    const w = new EndpointMaintenanceWindow({
      windows: {
        [URL_A]: [
          { start: iso(T0 + 3_600_000), end: iso(T0 + 4 * 3_600_000) },
          { start: iso(T0 + 6 * 3_600_000), end: iso(T0 + 7 * 3_600_000) },
        ],
      },
    });
    assert.equal(w.windowsFor(URL_A).length, 2);
  });

  it("prunes ended windows lazily", () => {
    let now = T0;
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 - 2 * 3_600_000), end: iso(T0 - 3_600_000) }] },
      now: () => now,
    });
    // Constructed in the past; the first read prunes it.
    assert.equal(w.windowsFor(URL_A).length, 0);
    assert.deepEqual(w.endpoints(), []);
  });

  it("counts parks per endpoint", () => {
    const w = new EndpointMaintenanceWindow({ now: () => T0 });
    assert.equal(w.delayedCount(URL_A), 0);
    w.noteDelayed(URL_A);
    w.noteDelayed(URL_A);
    w.noteDelayed(URL_B);
    assert.equal(w.delayedCount(URL_A), 2);
    assert.equal(w.delayedCount(URL_B), 1);
  });
});

describe("maintenance window transitions (WR-127 audit)", () => {
  it("announces opened once per window, closed on lazy prune", () => {
    let now = T0;
    const transitions: Array<{ kind: string; endpoint: string }> = [];
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + 3_600_000), end: iso(T0 + 2 * 3_600_000) }] },
      now: () => now,
      onTransition: (t) => transitions.push({ kind: t.kind, endpoint: t.endpoint }),
    });
    now = T0 + 3_600_000 + 1_000;
    assert.equal(w.announcePark(URL_A), true);
    assert.equal(w.announcePark(URL_A), false); // no duplicate
    assert.deepEqual(
      transitions,
      [{ kind: "opened", endpoint: URL_A }],
      "exactly one opened announcement"
    );
    // A window that never parked a delivery leaves silently.
    now = T0 + 4 * 3_600_000;
    w.addWindow(URL_B, iso(T0 + 5 * 3_600_000), iso(T0 + 6 * 3_600_000));
    now = T0 + 7 * 3_600_000;
    w.isParked(URL_B); // prune: unannounced window, no closed
    assert.equal(transitions.filter((t) => t.endpoint === URL_B).length, 0);
    // The announced window ended: the next read prunes it and fires closed.
    w.isParked(URL_A);
    assert.deepEqual(
      transitions,
      [
        { kind: "opened", endpoint: URL_A },
        { kind: "closed", endpoint: URL_A },
      ],
      "closed fires exactly once on prune"
    );
  });

  it("a throwing onTransition never breaks gating", () => {
    let now = T0;
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + 3_600_000), end: iso(T0 + 2 * 3_600_000) }] },
      now: () => now,
      onTransition: () => {
        throw new Error("audit sink down");
      },
    });
    now = T0 + 3_600_000 + 1_000;
    assert.doesNotThrow(() => w.announcePark(URL_A));
    assert.equal(w.isParked(URL_A), true);
  });

  it("clearEndpoint announces closed for an announced active window", () => {
    let now = T0;
    const transitions: string[] = [];
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + 3_600_000), end: iso(T0 + 2 * 3_600_000) }] },
      now: () => now,
      onTransition: (t) => transitions.push(t.kind),
    });
    now = T0 + 3_600_000 + 1_000;
    w.announcePark(URL_A);
    assert.equal(w.clearEndpoint(URL_A), true);
    assert.deepEqual(transitions, ["opened", "closed"]);
    assert.equal(w.clearEndpoint(URL_A), false);
  });

  it("addWindow rejects invalid input and leaves the table intact", () => {
    let now = T0;
    const w = new EndpointMaintenanceWindow({
      windows: { [URL_A]: [{ start: iso(T0 + 3_600_000), end: iso(T0 + 4 * 3_600_000) }] },
      now: () => now,
    });
    assert.throws(
      () => w.addWindow(URL_A, "2026-11-01T05:00:00Z", "2026-11-01T04:00:00Z"),
      RangeError
    );
    assert.throws(() => w.addWindow("", iso(T0), iso(T0 + 1)), RangeError);
    // The table is untouched by the failed adds.
    assert.equal(w.windowsFor(URL_A).length, 1);
    const added = w.addWindow(URL_A, iso(T0 + 5 * 3_600_000), iso(T0 + 6 * 3_600_000));
    assert.equal(added.start, iso(T0 + 5 * 3_600_000));
    assert.equal(w.windowsFor(URL_A).length, 2);
    // Overlapping add merges (it overlaps both existing windows).
    const merged = w.addWindow(URL_A, iso(T0 + 3_600_000), iso(T0 + 7 * 3_600_000));
    assert.equal(merged.start, iso(T0 + 3_600_000));
    assert.equal(merged.end, iso(T0 + 7 * 3_600_000));
    assert.equal(w.windowsFor(URL_A).length, 1);
  });
});

describe("RetryQueue maintenance windows (WR-127)", () => {
  it("parks in-window deliveries until the window ends without consuming attempts", async () => {
    let now = T0; // 00:00, window is 01:00-02:00
    const t = manualTimer();
    let senderCalls = 0;
    let deadLetters = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
      throw new Error("downstream 500");
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 2,
      baseDelayMs: 10,
      jitterMs: 0,
      maintenanceWindow: {
        windows: { [URL_A]: [{ start: iso(T0 + 3_600_000), end: iso(T0 + 2 * 3_600_000) }] },
        now: () => now,
      },
      onDeadLetter: () => {
        deadLetters += 1;
      },
    });
    q.start();
    now = T0 + 3_600_000 + 1_000; // inside the window
    q.enqueue(item("m1", URL_A));
    await t.step(); // first timer: parked, no send
    assert.equal(senderCalls, 0);
    assert.equal(deadLetters, 0);
    // Re-scheduled for the window's end instant, not a backoff.
    assert.equal(t.lastDelay(), 3_600_000 - 1_000);
    await t.step(); // still in window: parked again, still no send
    assert.equal(senderCalls, 0);
    assert.equal(deadLetters, 0);
    // "Flush at window close": the boundary is exclusive, so a delivery
    // landing exactly on 02:00 goes out.
    now = T0 + 2 * 3_600_000;
    await t.step();
    assert.equal(senderCalls, 1, "first attempt only after the window closed");
    assert.equal(deadLetters, 0);
    await t.step(); // attempt 1 failed -> backoff -> attempt 2
    await t.step();
    assert.equal(senderCalls, 2);
    assert.equal(deadLetters, 1, "dead letter only after real attempts exhausted");
    q.stop();
  });

  it("stacks with WR-52: either gate parks the item", async () => {
    let now = T0;
    const t = manualTimer();
    let senderCalls = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    // WR-52's daily window is open at 01:30 (00:00-23:00 UTC); the
    // one-shot maintenance window [01:00, 02:00] is what parks the item —
    // the two gates stack orthogonally, either one parks.
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maintenanceWindow: {
        windows: { [URL_A]: [{ start: iso(T0 + 3_600_000), end: iso(T0 + 2 * 3_600_000) }] },
        now: () => now,
      },
      deliveryWindow: {
        windows: { [URL_A]: "00:00-23:00" },
        now: () => now,
      },
    });
    q.start();
    now = T0 + 3_600_000 + 30 * 60_000; // 01:30: WR-52 open, maintenance parking
    q.enqueue(item("m2", URL_A));
    await t.step();
    assert.equal(senderCalls, 0, "maintenance window parked it while WR-52 was open");
    const rows = q.getMaintenanceWindows();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].endpoint, URL_A);
    assert.equal(rows[0].delayed, 1);
    assert.equal(rows[0].parked, true);
    assert.deepEqual(
      rows[0].windows,
      [{ start: iso(T0 + 3_600_000), end: iso(T0 + 2 * 3_600_000) }],
      "live windows listed"
    );
    assert.deepEqual(q.getDeliveryWindowStats().length, 0, "WR-52 parked nothing");
    now = T0 + 2 * 3_600_000 + 30 * 60_000; // 02:30: both gates open
    await t.step();
    assert.equal(senderCalls, 1, "delivery goes out once both gates are open");
    q.stop();
  });
});

describe("operator /maintenance/windows endpoints", () => {
  const SECRET = "relay-secret";
  const TOKEN = "op-secret";

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function req(port: number, method: string, path: string, body?: unknown, token?: string) {
    const raw = body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body);
    const headers: Record<string, string> = { "content-type": "application/json" };
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

  it("GET lists windows; POST adds; invalid input is 400; auth is enforced", async () => {
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "audit-")), "audit.jsonl")),
      retry: { maintenanceWindow: {} },
      operatorToken: TOKEN,
    });
    const port = await listen(relay);
    try {
      assert.equal((await req(port, "GET", "/maintenance/windows")).status, 403, "bad bearer rejected");
      const empty = await req(port, "GET", "/maintenance/windows", undefined, TOKEN);
      assert.equal(empty.status, 200);
      assert.deepEqual(JSON.parse(empty.text), []);

      const add = await req(
        port,
        "POST",
        "/maintenance/windows",
        { endpoint: URL_A, start: "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z" },
        TOKEN
      );
      assert.equal(add.status, 200);
      const added = JSON.parse(add.text) as { ok: boolean; window: { start: string; end: string } };
      assert.equal(added.ok, true);
      assert.equal(added.window.start, "2026-11-01T02:00:00Z");

      const bad = await req(
        port,
        "POST",
        "/maintenance/windows",
        { endpoint: URL_A, start: "2026-11-01T06:00:00Z", end: "2026-11-01T02:00:00Z" },
        TOKEN
      );
      assert.equal(bad.status, 400);
      const badJson = await req(port, "POST", "/maintenance/windows", { endpoint: URL_A }, TOKEN);
      assert.equal(badJson.status, 400);
      const notJson = await req(port, "POST", "/maintenance/windows", "not json", TOKEN);
      assert.equal(notJson.status, 400);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }

    // Fail-closed: with no operator credential configured, the route 404s.
    const bare = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "audit-")), "audit.jsonl")),
      retry: { maintenanceWindow: {} },
    });
    const barePort = await listen(bare);
    try {
      assert.equal((await req(barePort, "GET", "/maintenance/windows")).status, 404);
      assert.equal(
        (
          await req(barePort, "POST", "/maintenance/windows", {
            endpoint: URL_A,
            start: "2026-11-01T02:00:00Z",
            end: "2026-11-01T06:00:00Z",
          })
        ).status,
        404
      );
    } finally {
      bare.close();
      await new Promise((r) => bare.once("close", r));
    }
  });

  it("window transitions reach the audit log as maintenance_window_opened/closed", async () => {
    let now = T0;
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const fwd = "http://127.0.0.1:1/hook";
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: fwd,
      auditLog: audit,
      retry: {
        maintenanceWindow: {
          windows: { [fwd]: [{ start: iso(T0 + 3_600_000), end: iso(T0 + 2 * 3_600_000) }] },
          now: () => now,
        },
      },
      operatorToken: TOKEN,
    });
    const port = await listen(relay);
    try {
      // Inside the window: an inbound delivery parks and announces opened.
      now = T0 + 3_600_000 + 1_000;
      // Post properly: the relay signs inbound bodies with the shared secret.
      const raw = Buffer.from(JSON.stringify({ cutover: true }));
      const inbound = await new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: { "content-type": "application/json", "x-signature": signSha256(raw, SECRET) },
          },
          (rs) => {
            rs.resume();
            rs.on("end", () => resolve({ status: rs.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end(raw);
      });
      assert.equal(inbound.status, 202);
      // Let the queue's first attempt run: it parks inside the window.
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));
      const events = audit.readAll().map((e) => e.event);
      assert.ok(events.includes("maintenance_window_opened"), `opened audited, got: ${events}`);

      // Past the window end: the next observation prunes it and fires closed.
      now = T0 + 3 * 3_600_000;
      const listed = await req(port, "GET", "/maintenance/windows", undefined, TOKEN);
      assert.equal(listed.status, 200);
      const events2 = audit.readAll().map((e) => e.event);
      assert.ok(events2.includes("maintenance_window_closed"), `closed audited, got: ${events2}`);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
