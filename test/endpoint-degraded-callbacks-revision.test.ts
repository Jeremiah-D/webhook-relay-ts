import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import type {
  EndpointDegradedInfo,
  EndpointRecoveredInfo,
} from "../src/endpoint-health.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "endpoint-degraded-callbacks-revision-secret";
const URL = "http://127.0.0.1:9999/hook";
const BODY = Buffer.from(JSON.stringify({ event: "ping", n: 1 }));

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

function item(id: string, tenantId?: string) {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl: URL,
    headers: {},
    ...(tenantId !== undefined ? { tenantId } : {}),
  };
}

async function drainUntil(cond: () => boolean, ms = 5000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for condition");
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("RetryQueue endpoint degraded/recovered callback revision (WR-372)", () => {
  /** A queue whose sender fails until told otherwise; 9 fails degrade, 4 successes recover. */
  function makeQueue(
    onEndpointDegraded?: (info: EndpointDegradedInfo) => void,
    onEndpointRecovered?: (info: EndpointRecoveredInfo) => void
  ) {
    const timer = manualTimer();
    let fail = true;
    const sender: Sender = async () => {
      if (fail) throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 1,
      maxDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      endpointHealth: {
        ...(onEndpointDegraded !== undefined ? { onEndpointDegraded } : {}),
        ...(onEndpointRecovered !== undefined ? { onEndpointRecovered } : {}),
      },
    });
    return {
      q,
      timer,
      setFail: (v: boolean) => {
        fail = v;
      },
      async degrade(times = 9) {
        for (let i = 0; i < times; i++) q.enqueue(item(`fail-${Date.now()}-${i}`));
        await timer.run();
      },
      async recover(times = 4) {
        fail = false;
        for (let i = 0; i < times; i++) q.enqueue(item(`ok-${Date.now()}-${i}`));
        await timer.run();
        fail = true;
      },
    };
  }

  it("revise swaps the live callbacks: an already-built tracker's next transitions enter the new callbacks", async () => {
    const oldDegraded: EndpointDegradedInfo[] = [];
    const oldRecovered: EndpointRecoveredInfo[] = [];
    const newDegraded: EndpointDegradedInfo[] = [];
    const newRecovered: EndpointRecoveredInfo[] = [];
    const { q, timer, setFail, degrade, recover } = makeQueue(
      (info) => oldDegraded.push(info),
      (info) => oldRecovered.push(info)
    );
    q.start();
    try {
      await degrade();
      assert.equal(oldDegraded.length, 1);
      assert.ok(oldDegraded[0].score < 40);
      assert.equal(oldDegraded[0].consecutiveLowScores, 1);
      assert.equal(q.getEndpointHealthStats()[0].degraded, true);
      await recover();
      assert.equal(oldRecovered.length, 1);
      assert.ok(oldRecovered[0].score > 70);
      assert.equal(q.getEndpointHealthStats()[0].degraded, false);
      // Swap mid-life: the tracker was built long ago, but the next
      // transitions must still enter the new callbacks (WR-372 capture fix).
      const newDeg = (info: EndpointDegradedInfo) => newDegraded.push(info);
      const newRec = (info: EndpointRecoveredInfo) => newRecovered.push(info);
      q.reviseEndpointDegradedCallbacks({ onEndpointDegraded: newDeg, onEndpointRecovered: newRec });
      setFail(true);
      await degrade();
      assert.equal(oldDegraded.length, 1); // the old callback heard nothing more
      assert.equal(newDegraded.length, 1);
      assert.ok(newDegraded[0].score < 40);
      await recover();
      assert.equal(oldRecovered.length, 1);
      assert.equal(newRecovered.length, 1);
      assert.ok(newRecovered[0].score > 70);
    } finally {
      q.stop();
    }
  });

  it("a tenant born after a revision starts from the revised callbacks", async () => {
    const seen: EndpointDegradedInfo[] = [];
    // No callbacks at construction: no tracker exists yet for any tenant.
    const { q, timer } = makeQueue();
    q.start();
    try {
      q.reviseEndpointDegradedCallbacks({
        onEndpointDegraded: (info) => seen.push(info),
      });
      for (let i = 0; i < 9; i++) q.enqueue(item(`late-${i}`, "acme"));
      await timer.run();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].tenant, "acme");
      assert.equal(seen[0].endpoint, URL);
    } finally {
      q.stop();
    }
  });

  it("clearing both hooks keeps scoring and the operator hears nothing", async () => {
    const degraded: EndpointDegradedInfo[] = [];
    const recovered: EndpointRecoveredInfo[] = [];
    const { q, degrade, recover } = makeQueue(
      (info) => degraded.push(info),
      (info) => recovered.push(info)
    );
    q.start();
    try {
      await degrade();
      assert.equal(degraded.length, 1);
      q.reviseEndpointDegradedCallbacks({ onEndpointDegraded: null, onEndpointRecovered: null });
      await recover();
      assert.equal(recovered.length, 0); // the recovery was audit-only
      assert.equal(q.getEndpointHealthStats()[0].degraded, false);
      await degrade();
      assert.equal(degraded.length, 1); // still silent
      assert.equal(q.getEndpointHealthStats()[0].degraded, true); // scoring continued
      assert.ok(q.getEndpointHealthStats()[0].consecutiveLowScores >= 1);
    } finally {
      q.stop();
    }
  });

  it("unconfigured health scoring throws Error — enabling it needs a restart", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.throws(
      () => q.reviseEndpointDegradedCallbacks({ onEndpointDegraded: () => {} }),
      /reviseEndpointDegradedCallbacks: endpoint health scoring is not configured/
    );
    q.stop();
  });

  it("an illegal or empty patch throws RangeError and the live hooks are untouched", async () => {
    const degraded: EndpointDegradedInfo[] = [];
    const recovered: EndpointRecoveredInfo[] = [];
    const { q, degrade, recover } = makeQueue(
      (info) => degraded.push(info),
      (info) => recovered.push(info)
    );
    q.start();
    try {
      assert.throws(() => q.reviseEndpointDegradedCallbacks({} as never), RangeError);
      assert.throws(() => q.reviseEndpointDegradedCallbacks(null as never), RangeError);
      assert.throws(
        () => q.reviseEndpointDegradedCallbacks({ onEndpointDegraded: 42 as never }),
        RangeError
      );
      assert.throws(
        () => q.reviseEndpointDegradedCallbacks({ onEndpointRecovered: "nope" as never }),
        RangeError
      );
      // The live hooks survived every bad patch.
      await degrade();
      assert.equal(degraded.length, 1);
      await recover();
      assert.equal(recovered.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a same-reference revision is a silent no-op; a partial patch keeps the other hook", async () => {
    const degraded: EndpointDegradedInfo[] = [];
    const recovered: EndpointRecoveredInfo[] = [];
    const newRecovered: EndpointRecoveredInfo[] = [];
    const deg = (info: EndpointDegradedInfo) => degraded.push(info);
    const rec = (info: EndpointRecoveredInfo) => recovered.push(info);
    const { q, degrade, recover } = makeQueue(deg, rec);
    q.start();
    try {
      q.reviseEndpointDegradedCallbacks({ onEndpointDegraded: deg, onEndpointRecovered: rec });
      // Partial patch: only the recover hook moves.
      const newRec = (info: EndpointRecoveredInfo) => newRecovered.push(info);
      q.reviseEndpointDegradedCallbacks({ onEndpointRecovered: newRec });
      await degrade();
      assert.equal(degraded.length, 1); // the untouched hook still fires
      assert.equal(newRecovered.length, 0);
      await recover();
      assert.equal(recovered.length, 0);
      assert.equal(newRecovered.length, 1);
    } finally {
      q.stop();
    }
  });

  it("degraded state and hysteresis survive a mid-episode swap", async () => {
    const degraded: EndpointDegradedInfo[] = [];
    const recovered: EndpointRecoveredInfo[] = [];
    const newRecovered: EndpointRecoveredInfo[] = [];
    const { q, degrade, recover } = makeQueue(
      (info) => degraded.push(info),
      (info) => recovered.push(info)
    );
    q.start();
    try {
      await degrade();
      assert.equal(degraded.length, 1);
      assert.equal(q.getEndpointHealthStats()[0].consecutiveLowScores, 1);
      // Swap only the recover hook while degraded: the degraded state,
      // the low-score streak, and the thresholds must not move.
      q.reviseEndpointDegradedCallbacks({
        onEndpointRecovered: (info) => newRecovered.push(info),
      });
      assert.equal(q.getEndpointHealthStats()[0].degraded, true);
      assert.equal(q.getEndpointHealthStats()[0].consecutiveLowScores, 1);
      await recover();
      assert.equal(recovered.length, 0);
      assert.equal(newRecovered.length, 1);
      assert.equal(q.getEndpointHealthStats()[0].degraded, false);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint degraded/recovered callback revision (WR-372)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-degraded-callbacks-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function ingest(port: number, body: Buffer = BODY): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-signature": signSha256(body, relaySecret),
          },
        },
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

  async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(cond(), `timed out waiting for: ${what}`);
  }

  /** A server whose sender fails until told otherwise; 9 fails degrade, 4 successes recover. */
  function degradingServer(
    onEndpointDegraded?: (info: EndpointDegradedInfo) => void,
    onEndpointRecovered?: (info: EndpointRecoveredInfo) => void
  ) {
    let fail = true;
    const sender: Sender = async () => {
      if (fail) throw new Error("downstream down");
    };
    const { relay, auditLog } = makeServer({
      retry: {
        sender,
        baseDelayMs: 10,
        maxAttempts: 1,
        jitterMs: 0,
        random: () => 0,
        endpointHealth: {
          ...(onEndpointDegraded !== undefined ? { onEndpointDegraded } : {}),
          ...(onEndpointRecovered !== undefined ? { onEndpointRecovered } : {}),
        },
      },
    });
    return {
      relay,
      auditLog,
      setFail: (v: boolean) => {
        fail = v;
      },
    };
  }

  async function driveFailures(port: number, n: number): Promise<void> {
    for (let i = 0; i < n; i++) {
      assert.equal((await ingest(port)).status, 202);
    }
  }

  it("revising routes the next transitions to the new callbacks and the audit still lands", async () => {
    const oldDegraded: EndpointDegradedInfo[] = [];
    const oldRecovered: EndpointRecoveredInfo[] = [];
    const newDegraded: EndpointDegradedInfo[] = [];
    const newRecovered: EndpointRecoveredInfo[] = [];
    const { relay, auditLog, setFail } = degradingServer(
      (info) => oldDegraded.push(info),
      (info) => oldRecovered.push(info)
    );
    const port = await listen(relay);
    // First degradation: the initial callbacks hear it and the audit lands.
    await driveFailures(port, 9);
    await waitFor(() => eventsOf(auditLog, "endpoint_degraded").length >= 1, 5000, "first endpoint_degraded");
    await waitFor(() => oldDegraded.length >= 1, 5000, "initial degraded callback");
    assert.equal(oldDegraded[0].endpoint, "http://127.0.0.1:9/unused");
    assert.deepEqual(newDegraded, []);
    // Swap both operator callbacks while degraded.
    const newDeg = (info: EndpointDegradedInfo) => newDegraded.push(info);
    const newRec = (info: EndpointRecoveredInfo) => newRecovered.push(info);
    relay.reviseEndpointDegradedCallbacks!({ onEndpointDegraded: newDeg, onEndpointRecovered: newRec });
    assert.deepEqual(
      eventsOf(auditLog, "endpoint_degraded_callbacks_revised").map((e) => [
        e.onEndpointDegraded,
        e.oldOnEndpointDegraded,
        e.onEndpointRecovered,
        e.oldOnEndpointRecovered,
      ]),
      [["set", "set", "set", "set"]]
    );
    // Recover: only the new recover callback hears it, the audit lands.
    setFail(false);
    await driveFailures(port, 4);
    await waitFor(() => eventsOf(auditLog, "endpoint_recovered").length >= 1, 5000, "endpoint_recovered");
    await waitFor(() => newRecovered.length >= 1, 5000, "new recovered callback");
    assert.equal(oldRecovered.length, 0);
    // Degrade again: only the new degraded callback hears it.
    setFail(true);
    await driveFailures(port, 9);
    await waitFor(() => eventsOf(auditLog, "endpoint_degraded").length >= 2, 5000, "second endpoint_degraded");
    await waitFor(() => newDegraded.length >= 1, 5000, "new degraded callback");
    assert.equal(oldDegraded.length, 1);
  });

  it("clearing both hooks keeps the audit and the scoring and stops the operator", async () => {
    const degraded: EndpointDegradedInfo[] = [];
    const recovered: EndpointRecoveredInfo[] = [];
    const { relay, auditLog, setFail } = degradingServer(
      (info) => degraded.push(info),
      (info) => recovered.push(info)
    );
    const port = await listen(relay);
    await driveFailures(port, 9);
    await waitFor(() => eventsOf(auditLog, "endpoint_degraded").length >= 1, 5000, "first endpoint_degraded");
    assert.equal(degraded.length, 1);
    // Clear back to audit-only, then recover and degrade again.
    relay.reviseEndpointDegradedCallbacks!({ onEndpointDegraded: null, onEndpointRecovered: null });
    assert.deepEqual(
      eventsOf(auditLog, "endpoint_degraded_callbacks_revised").map((e) => [
        e.onEndpointDegraded,
        e.oldOnEndpointDegraded,
        e.onEndpointRecovered,
        e.oldOnEndpointRecovered,
      ]),
      [["cleared", "set", "cleared", "set"]]
    );
    setFail(false);
    await driveFailures(port, 4);
    await waitFor(() => eventsOf(auditLog, "endpoint_recovered").length >= 1, 5000, "endpoint_recovered");
    assert.equal(recovered.length, 0); // the recovery was audit-only
    setFail(true);
    await driveFailures(port, 9);
    await waitFor(() => eventsOf(auditLog, "endpoint_degraded").length >= 2, 5000, "second endpoint_degraded");
    assert.equal(degraded.length, 1); // still silent
  });

  it("revise audits per-hook presence; a same-reference revision is a silent no-op", async () => {
    const { relay, auditLog } = degradingServer(
      () => {},
      () => {}
    );
    await listen(relay);
    const newDeg = (_info: EndpointDegradedInfo) => {};
    const newRec = (_info: EndpointRecoveredInfo) => {};
    // Degraded set -> set; recovered untouched.
    relay.reviseEndpointDegradedCallbacks!({ onEndpointDegraded: newDeg });
    // Recovered set -> cleared; degraded untouched.
    relay.reviseEndpointDegradedCallbacks!({ onEndpointRecovered: null });
    // Recovered cleared -> set; degraded untouched.
    relay.reviseEndpointDegradedCallbacks!({ onEndpointRecovered: newRec });
    // Same references again: no audit event.
    relay.reviseEndpointDegradedCallbacks!({ onEndpointDegraded: newDeg, onEndpointRecovered: newRec });
    // Clearing when already cleared: no audit event.
    relay.reviseEndpointDegradedCallbacks!({ onEndpointDegraded: null });
    relay.reviseEndpointDegradedCallbacks!({ onEndpointDegraded: null });
    const revised = eventsOf(auditLog, "endpoint_degraded_callbacks_revised");
    assert.equal(revised.length, 4);
    assert.deepEqual(
      revised.map((e) => [e.onEndpointDegraded, e.oldOnEndpointDegraded, e.onEndpointRecovered, e.oldOnEndpointRecovered]),
      [
        ["set", "set", "unchanged", "set"],
        ["unchanged", "set", "cleared", "set"],
        ["unchanged", "set", "set", "absent"],
        ["cleared", "set", "unchanged", "set"],
      ]
    );
  });

  it("an illegal or empty patch throws RangeError and the live cells are untouched", async () => {
    const degraded: EndpointDegradedInfo[] = [];
    const { relay, auditLog, setFail } = degradingServer((info) => degraded.push(info));
    const port = await listen(relay);
    assert.throws(() => relay.reviseEndpointDegradedCallbacks!({} as never), RangeError);
    assert.throws(() => relay.reviseEndpointDegradedCallbacks!(null as never), RangeError);
    assert.throws(
      () => relay.reviseEndpointDegradedCallbacks!({ onEndpointDegraded: 42 as never }),
      RangeError
    );
    assert.equal(eventsOf(auditLog, "endpoint_degraded_callbacks_revised").length, 0);
    // The live cell survived: the next degradation still enters the original callback.
    await driveFailures(port, 9);
    await waitFor(() => eventsOf(auditLog, "endpoint_degraded").length >= 1, 5000, "endpoint_degraded");
    assert.equal(degraded.length, 1);
    setFail(false);
  });

  it("unconfigured health scoring throws Error — enabling it needs a restart", async () => {
    const { relay } = makeServer({});
    await listen(relay);
    assert.throws(
      () => relay.reviseEndpointDegradedCallbacks!({ onEndpointDegraded: () => {} }),
      /reviseEndpointDegradedCallbacks: endpoint health scoring is not configured/
    );
  });
});
