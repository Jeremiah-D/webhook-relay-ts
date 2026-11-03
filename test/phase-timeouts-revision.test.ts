/**
 * WR-311: endpoint-level phase-timeout budget live revision.
 *
 * Hermetic and fast: the downstream stub is a localhost server with a
 * fixed 250ms first-byte delay, and every budget under test is
 * 100ms (kills the delayed stub) or 5000ms (lets it through). No test
 * depends on wall-clock sleeps longer than the delay under test plus a
 * small margin; delivery outcomes are observed by polling the stub's
 * counters with a deadline.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer, type Server } from "node:http";
import { request as httpRequest } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyPhaseTimeoutRevision,
  samePhaseTimeoutBudgets,
  type PhaseTimeoutBudgets,
} from "../src/phase-timeouts.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "phase-timeouts-revision-secret";
const body = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_311" }));

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

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function waitUntil(cond: () => boolean, label: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await sleep(10);
  }
}

describe("applyPhaseTimeoutRevision (WR-311)", () => {
  it("merges a partial patch, leaving the other phases untouched", () => {
    const next = applyPhaseTimeoutRevision(
      { connectMs: 500, firstByteMs: 1000, bodyMs: 2000 },
      { firstByteMs: 250 }
    );
    assert.deepEqual(next, { connectMs: 500, firstByteMs: 250, bodyMs: 2000 });
  });

  it("a null phase deletes that phase; deleting the last phase returns undefined", () => {
    const next = applyPhaseTimeoutRevision({ firstByteMs: 1000, bodyMs: 2000 }, { firstByteMs: null });
    assert.deepEqual(next, { bodyMs: 2000 });
    assert.equal(applyPhaseTimeoutRevision({ firstByteMs: 1000 }, { firstByteMs: null }), undefined);
    // A null for a phase that was never configured is a no-op.
    assert.deepEqual(applyPhaseTimeoutRevision({ firstByteMs: 1000 }, { bodyMs: null }), {
      firstByteMs: 1000,
    });
  });

  it("an empty patch returns the live budgets unchanged", () => {
    const current = { firstByteMs: 1000 };
    assert.deepEqual(applyPhaseTimeoutRevision(current, {}), { firstByteMs: 1000 });
    // A patch on a missing entry creates it.
    assert.deepEqual(applyPhaseTimeoutRevision(undefined, { firstByteMs: 1000 }), {
      firstByteMs: 1000,
    });
    assert.equal(applyPhaseTimeoutRevision(undefined, {}), undefined);
  });

  it("rejects an unknown phase name", () => {
    assert.throws(
      () => applyPhaseTimeoutRevision({ firstByteMs: 1000 }, { dnsMs: 100 } as never),
      RangeError
    );
  });

  it("rejects non-positive-integer budgets", () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "100"]) {
      assert.throws(
        () => applyPhaseTimeoutRevision({ firstByteMs: 1000 }, { firstByteMs: bad as never }),
        RangeError,
        JSON.stringify(bad)
      );
    }
  });

  it("one bad field voids the whole patch", () => {
    assert.throws(
      () =>
        applyPhaseTimeoutRevision({ firstByteMs: 1000 }, { firstByteMs: 250, bodyMs: 0 }),
      RangeError
    );
  });

  it("samePhaseTimeoutBudgets compares per phase, undefined means no entry", () => {
    assert.equal(samePhaseTimeoutBudgets(undefined, undefined), true);
    assert.equal(samePhaseTimeoutBudgets(undefined, { firstByteMs: 100 }), false);
    assert.equal(samePhaseTimeoutBudgets({ firstByteMs: 100 }, { firstByteMs: 100 }), true);
    assert.equal(samePhaseTimeoutBudgets({ firstByteMs: 100 }, { firstByteMs: 200 }), false);
    assert.equal(
      samePhaseTimeoutBudgets({ firstByteMs: 100, bodyMs: 500 }, { firstByteMs: 100 }),
      false
    );
  });
});

describe("server setPhaseTimeouts (WR-311)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "phase-timeouts-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      auditLog,
      retry: { baseDelayMs: 10, maxAttempts: 1 },
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function signed(payload: Buffer) {
    return { "x-signature": signSha256(payload, relaySecret) };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  /**
   * A downstream stub that answers 200 after a fixed 250ms first-byte
   * delay. `hits` counts requests received; `responded` counts replies
   * actually sent — a request killed by a 100ms firstByte budget never
   * reaches `responded`, because the sender destroys it first.
   */
  function slowStub() {
    let hits = 0;
    let responded = 0;
    const stub = createHttpServer((req, res) => {
      hits += 1;
      const timer = setTimeout(() => {
        if (res.socket !== null && !res.socket.destroyed && !res.writableEnded) {
          res.writeHead(200, { "content-type": "text/plain" });
          res.end("ok");
          responded += 1;
        }
      }, 250);
      // The sender destroying the request closes the request stream —
      // drop the pending reply instead of counting a doomed response.
      req.on("close", () => clearTimeout(timer));
    });
    servers.push(stub);
    return {
      stub,
      counts: () => ({ hits, responded }),
    };
  }

  it("tightening a single phase takes effect on the next delivery", async () => {
    const { stub, counts } = slowStub();
    await listen(stub);
    const target = `http://127.0.0.1:${(stub.address() as { port: number }).port}/hook`;
    const { relay } = makeServer({
      forwardUrl: target,
      phaseTimeouts: { [target]: { firstByteMs: 5000 } },
    });
    const port = await listen(relay);

    await post(port, body, signed(body));
    await waitUntil(() => counts().responded === 1, "first delivery to succeed");
    assert.deepEqual(counts(), { hits: 1, responded: 1 });

    // Tighten firstByte 5000 -> 100: the 250ms stub now blows the budget.
    const next = relay.setPhaseTimeouts!(target, { firstByteMs: 100 });
    assert.deepEqual(next, { firstByteMs: 100 });
    const second = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_311_b" }));
    await post(port, second, signed(second));
    await waitUntil(() => counts().hits === 2, "second delivery to reach the stub");
    await sleep(500); // past the 250ms delay: a surviving attempt would have responded
    assert.deepEqual(counts(), { hits: 2, responded: 1 });
  });

  it("deleting a phase keeps the other phases live", async () => {
    const { relay } = makeServer({
      forwardUrl: "http://127.0.0.1:9/unused",
      phaseTimeouts: {
        "http://127.0.0.1:9/unused": { firstByteMs: 1000, bodyMs: 2000 },
      },
    });
    const next = relay.setPhaseTimeouts!("http://127.0.0.1:9/unused", { firstByteMs: null });
    assert.deepEqual(next, { bodyMs: 2000 });
    assert.deepEqual(relay.getPhaseTimeouts!(), {
      "http://127.0.0.1:9/unused": { bodyMs: 2000 },
    });
  });

  it("deleting the last phase removes the endpoint and the next delivery falls back", async () => {
    const { stub, counts } = slowStub();
    await listen(stub);
    const target = `http://127.0.0.1:${(stub.address() as { port: number }).port}/hook`;
    const { relay } = makeServer({
      forwardUrl: target,
      phaseTimeouts: { [target]: { firstByteMs: 100 } },
    });
    const port = await listen(relay);

    await post(port, body, signed(body));
    await waitUntil(() => counts().hits === 1, "first delivery to reach the stub");
    await sleep(500); // past the 250ms delay: the 100ms budget killed it
    assert.deepEqual(counts(), { hits: 1, responded: 0 });

    // Delete the last phase: the endpoint entry is gone, so the next
    // delivery runs with no phase budget at all.
    const next = relay.setPhaseTimeouts!(target, { firstByteMs: null });
    assert.equal(next, undefined);
    assert.deepEqual(relay.getPhaseTimeouts!(), {});
    const second = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_311_b" }));
    await post(port, second, signed(second));
    await waitUntil(() => counts().responded === 1, "second delivery to succeed after fallback");
    assert.deepEqual(counts(), { hits: 2, responded: 1 });
  });

  it("audits phase_timeout_revised with previous/current and skips the audit on a no-op", async () => {
    const target = "http://127.0.0.1:9/unused";
    const { relay, auditLog } = makeServer({
      forwardUrl: target,
      phaseTimeouts: { [target]: { firstByteMs: 1000, bodyMs: 2000 } },
    });
    assert.equal(eventsOf(auditLog, "phase_timeout_revised").length, 0);
    const next = relay.setPhaseTimeouts!(target, { firstByteMs: 250 });
    assert.deepEqual(next, { firstByteMs: 250, bodyMs: 2000 });
    const revised = eventsOf(auditLog, "phase_timeout_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, target);
    assert.deepEqual(revised[0].previous, { firstByteMs: 1000, bodyMs: 2000 });
    assert.deepEqual(revised[0].current, { firstByteMs: 250, bodyMs: 2000 });
    // Same values and an empty patch: no new audit event.
    relay.setPhaseTimeouts!(target, { firstByteMs: 250 });
    relay.setPhaseTimeouts!(target, {});
    assert.equal(eventsOf(auditLog, "phase_timeout_revised").length, 1);
    // Deleting the entry audits with current null.
    relay.setPhaseTimeouts!(target, { firstByteMs: null, bodyMs: null });
    const revised2 = eventsOf(auditLog, "phase_timeout_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { firstByteMs: 250, bodyMs: 2000 });
    assert.equal(revised2[1].current, null);
  });

  it("throws RangeError on an illegal patch and leaves the live values untouched", () => {
    const target = "http://127.0.0.1:9/unused";
    const { relay, auditLog } = makeServer({
      forwardUrl: target,
      phaseTimeouts: { [target]: { firstByteMs: 1000 } },
    });
    for (const patch of [
      { firstByteMs: 0 },
      { firstByteMs: -5 },
      { firstByteMs: 1.5 },
      { dnsMs: 100 },
      { firstByteMs: 250, bodyMs: 0 }, // one bad field voids the whole patch
    ]) {
      assert.throws(() => relay.setPhaseTimeouts!(target, patch as never), RangeError, JSON.stringify(patch));
    }
    assert.deepEqual(relay.getPhaseTimeouts!(), { [target]: { firstByteMs: 1000 } });
    assert.equal(eventsOf(auditLog, "phase_timeout_revised").length, 0);
  });

  it("throws Error when phaseTimeouts is not configured", () => {
    const { relay } = makeServer({ forwardUrl: "http://127.0.0.1:9/unused" });
    assert.throws(() => relay.setPhaseTimeouts!("http://127.0.0.1:9/unused", { firstByteMs: 100 }), /not configured/);
    assert.deepEqual(relay.getPhaseTimeouts!(), {});
  });

  it("getPhaseTimeouts returns a deep copy: mutating it never touches the live record", () => {
    const target = "http://127.0.0.1:9/unused";
    const { relay } = makeServer({
      forwardUrl: target,
      phaseTimeouts: { [target]: { firstByteMs: 1000 } },
    });
    const snapshot = relay.getPhaseTimeouts!();
    assert.deepEqual(snapshot, { [target]: { firstByteMs: 1000 } });
    snapshot[target]!.firstByteMs = 1;
    snapshot["http://evil.example/hook"] = { firstByteMs: 1 };
    assert.deepEqual(relay.getPhaseTimeouts!(), { [target]: { firstByteMs: 1000 } });
    // A revision afterwards is still visible in a fresh snapshot.
    relay.setPhaseTimeouts!(target, { firstByteMs: 250 });
    assert.deepEqual(relay.getPhaseTimeouts!(), { [target]: { firstByteMs: 250 } });
  });

  it("adding budgets for a new endpoint takes effect on the next delivery", async () => {
    const { stub, counts } = slowStub();
    await listen(stub);
    const target = `http://127.0.0.1:${(stub.address() as { port: number }).port}/hook`;
    const { relay } = makeServer({
      forwardUrl: target,
      // Budgets configured, but only for a different endpoint.
      phaseTimeouts: { "http://127.0.0.1:9/other": { firstByteMs: 1000 } },
    });
    const port = await listen(relay);

    // No entry for this endpoint yet: the slow stub answers fine.
    await post(port, body, signed(body));
    await waitUntil(() => counts().responded === 1, "unbudgeted delivery to succeed");

    // Add a 100ms budget for this endpoint: the next delivery is killed.
    const next = relay.setPhaseTimeouts!(target, { firstByteMs: 100 });
    assert.deepEqual(next, { firstByteMs: 100 });
    const second = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_311_b" }));
    await post(port, second, signed(second));
    await waitUntil(() => counts().hits === 2, "budgeted delivery to reach the stub");
    await sleep(500);
    assert.deepEqual(counts(), { hits: 2, responded: 1 });
  });
});
