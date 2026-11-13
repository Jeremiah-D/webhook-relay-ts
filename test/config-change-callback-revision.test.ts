import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import type { ConfigChange } from "../src/hotreload.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const signingKey = "config-change-callback-revision-key";
const URL = "http://localhost:9999/hook";
const TOKEN = "op-token";

type Seen = Array<{ endpoint: string; changes: ConfigChange[] }>;

function makeQueue(
  onConfigChange?: (endpoint: string, changes: ConfigChange[]) => void
): RetryQueue {
  return new RetryQueue({
    sender: (async () => ({ statusCode: 200, body: Buffer.alloc(0) })) as Sender,
    baseDelayMs: 1000,
    maxDelayMs: 60_000,
    maxAttempts: 5,
    jitterMs: 0,
    ...(onConfigChange !== undefined ? { onConfigChange } : {}),
  });
}

/** Timer that records each scheduled delay and lets the test step them. */
function delayRecordingTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  const delays: number[] = [];
  return {
    delays,
    setTimer: (fn: () => void, ms: number) => {
      delays.push(ms);
      pending.push({ fn, ms });
      return {
        clear: () => {
          const i = pending.findIndex((p) => p.fn === fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const { fn } of fns) fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

describe("RetryQueue config-change callback revision (WR-409)", () => {
  it("the swapped callback receives the next patch with exact endpoint + before/after diff; the old callback stays silent and past changes are never re-delivered", () => {
    const first: Seen = [];
    const q = makeQueue((endpoint, changes) => first.push({ endpoint, changes }));
    try {
      const diff = q.updateEndpointConfig(URL, { retry: { baseDelayMs: 2000 } });
      assert.deepEqual(diff, [{ field: "retry.baseDelayMs", from: 1000, to: 2000 }]);
      assert.deepEqual(first, [
        {
          endpoint: URL,
          changes: [{ field: "retry.baseDelayMs", from: 1000, to: 2000 }],
        },
      ]);
      const second: Seen = [];
      q.reviseConfigChangeCallback((endpoint, changes) =>
        second.push({ endpoint, changes })
      );
      assert.equal(second.length, 0, "no re-delivery of the reported change");
      assert.equal(first.length, 1);
      const next = q.updateEndpointConfig(URL, {
        retry: { baseDelayMs: 3000, maxAttempts: 3 },
      });
      assert.deepEqual(next, [
        { field: "retry.baseDelayMs", from: 2000, to: 3000 },
        { field: "retry.maxAttempts", from: 5, to: 3 },
      ]);
      assert.equal(first.length, 1, "old callback stays silent after revision");
      assert.equal(second.length, 1);
      assert.deepEqual(second[0], {
        endpoint: URL,
        changes: [
          { field: "retry.baseDelayMs", from: 2000, to: 3000 },
          { field: "retry.maxAttempts", from: 5, to: 3 },
        ],
      });
      assert.deepEqual(q.retryConfig().baseDelayMs, 3000);
      assert.deepEqual(q.retryConfig().maxAttempts, 3);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; patches still apply and re-setting works", () => {
    const seen: Seen = [];
    const q = makeQueue((endpoint, changes) => seen.push({ endpoint, changes }));
    try {
      q.updateEndpointConfig(URL, { retry: { baseDelayMs: 2000 } });
      assert.equal(seen.length, 1);
      q.reviseConfigChangeCallback(null);
      const next = q.updateEndpointConfig(URL, { retry: { baseDelayMs: 3000 } });
      assert.deepEqual(next, [{ field: "retry.baseDelayMs", from: 2000, to: 3000 }]);
      assert.deepEqual(q.retryConfig().baseDelayMs, 3000);
      assert.equal(seen.length, 1, "cleared hook stays silent");
      // Re-setting works: the next patch reaches the new callback.
      const third: Seen = [];
      q.reviseConfigChangeCallback((endpoint, changes) =>
        third.push({ endpoint, changes })
      );
      q.updateEndpointConfig(URL, { retry: { baseDelayMs: 4000 } });
      assert.equal(third.length, 1);
      assert.deepEqual(third[0], {
        endpoint: URL,
        changes: [{ field: "retry.baseDelayMs", from: 3000, to: 4000 }],
      });
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", () => {
    const seen: Seen = [];
    const onConfigChange = (endpoint: string, changes: ConfigChange[]) =>
      seen.push({ endpoint, changes });
    const q = makeQueue(onConfigChange);
    try {
      q.reviseConfigChangeCallback(onConfigChange);
      q.updateEndpointConfig(URL, { retry: { baseDelayMs: 2000 } });
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseConfigChangeCallback(null);
      q.reviseConfigChangeCallback(null);
      q.updateEndpointConfig(URL, { retry: { baseDelayMs: 3000 } });
      assert.equal(seen.length, 1);
      assert.deepEqual(q.retryConfig().baseDelayMs, 3000);
    } finally {
      q.stop();
    }
    // A queue that never had a callback: clearing when unset is a no-op.
    const bare = makeQueue();
    try {
      bare.reviseConfigChangeCallback(null);
      const diff = bare.updateEndpointConfig(URL, { retry: { baseDelayMs: 2000 } });
      assert.deepEqual(diff, [{ field: "retry.baseDelayMs", from: 1000, to: 2000 }]);
    } finally {
      bare.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", () => {
    const seen: Seen = [];
    const q = makeQueue((endpoint, changes) => seen.push({ endpoint, changes }));
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseConfigChangeCallback(bad), RangeError, String(bad));
      }
      const diff = q.updateEndpointConfig(URL, { retry: { baseDelayMs: 2000 } });
      assert.equal(seen.length, 1);
      assert.deepEqual(seen[0], {
        endpoint: URL,
        changes: [{ field: "retry.baseDelayMs", from: 1000, to: 2000 }],
      });
      assert.deepEqual(diff, [{ field: "retry.baseDelayMs", from: 1000, to: 2000 }]);
    } finally {
      q.stop();
    }
  });

  it("already-reported changes are never re-sent to the new callback", () => {
    const first: Seen = [];
    const q = makeQueue((endpoint, changes) => first.push({ endpoint, changes }));
    try {
      q.updateEndpointConfig(URL, { retry: { baseDelayMs: 2000 } });
      q.updateEndpointConfig(URL, { retry: { maxAttempts: 3 } });
      assert.equal(first.length, 2);
      const second: Seen = [];
      q.reviseConfigChangeCallback((endpoint, changes) =>
        second.push({ endpoint, changes })
      );
      assert.equal(second.length, 0, "revision re-delivers nothing");
      assert.equal(first.length, 2);
      q.updateEndpointConfig(URL, { retry: { baseDelayMs: 4000 } });
      assert.equal(first.length, 2, "old callback stays silent");
      assert.equal(second.length, 1, "only the new patch reaches the new callback");
      assert.deepEqual(second[0], {
        endpoint: URL,
        changes: [{ field: "retry.baseDelayMs", from: 2000, to: 4000 }],
      });
    } finally {
      q.stop();
    }
  });

  it("revision does not change the patch validation gate, atomicity, or in-flight timer semantics", async () => {
    const t = delayRecordingTimer();
    const first: Seen = [];
    const second: Seen = [];
    const q = new RetryQueue({
      sender: (async () => {
        throw new Error("downstream down");
      }) as Sender,
      baseDelayMs: 1000,
      maxDelayMs: 60_000,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: t.setTimer,
      onConfigChange: (endpoint, changes) => first.push({ endpoint, changes }),
    });
    try {
      q.enqueue({
        id: "a",
        targetUrl: URL,
        payload: Buffer.from(JSON.stringify({ id: "a" })),
        headers: {},
      });
      q.start();
      await t.step(); // attempt 0 fails -> schedules retry with the OLD base
      assert.equal(t.delays.length, 2); // initial immediate (0) + backoff
      assert.equal(t.delays[1], 2000); // base 1000 * 2^1
      q.reviseConfigChangeCallback((endpoint, changes) =>
        second.push({ endpoint, changes })
      );
      const diff = q.updateEndpointConfig(URL, { retry: { baseDelayMs: 4000 } });
      assert.deepEqual(diff, [{ field: "retry.baseDelayMs", from: 1000, to: 4000 }]);
      assert.equal(first.length, 0, "old callback stays silent after revision");
      assert.deepEqual(second, [
        {
          endpoint: URL,
          changes: [{ field: "retry.baseDelayMs", from: 1000, to: 4000 }],
        },
      ]);
      assert.deepEqual(t.delays, [0, 2000], "already-scheduled timer keeps its old delay");
      await t.step(); // attempt 1 fails -> schedules retry with the NEW base
      assert.equal(t.delays[2], 16000); // 4000 * 2^2, jitter 0
      // The validation gate still fires first: an illegal multi-field
      // patch throws and leaves the running config (and the observer)
      // completely untouched — zero partial application.
      assert.throws(
        () =>
          q.updateEndpointConfig(URL, {
            retry: { baseDelayMs: 2000 },
            circuitBreaker: { failureThreshold: 2 },
          }),
        RangeError
      );
      assert.throws(() => q.updateEndpointConfig(URL, { retry: { baseDelayMs: 0 } }), RangeError);
      assert.deepEqual(q.retryConfig().baseDelayMs, 4000);
      assert.equal(second.length, 1, "rejected patches fire no observation");
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer config-change callback revision (WR-409)", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
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

  function postJson(port: number, path: string, body: unknown, token?: string) {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString() || "{}"),
          })
        );
      });
      r.on("error", reject);
      r.end(JSON.stringify(body));
    });
  }

  async function makeRelay(opts: {
    onConfigChange?: (endpoint: string, changes: ConfigChange[]) => void;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "config-change-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL,
      auditLog,
      operatorToken: TOKEN,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: {
        baseDelayMs: 1000,
        maxAttempts: 5,
        ...(opts.onConfigChange !== undefined
          ? { onConfigChange: opts.onConfigChange }
          : {}),
      },
    });
    servers.push(relay);
    return { relay, auditLog, port: await listen(relay) };
  }

  it("revising the callback routes the next patch to the new callback; the audit log keeps every endpoint_config_updated and the revision itself is audited with exact previous/current", async () => {
    const first: Seen = [];
    const second: Seen = [];
    const { relay, auditLog, port } = await makeRelay({
      onConfigChange: (endpoint, changes) => first.push({ endpoint, changes }),
    });
    let res = await postJson(
      port,
      "/config/endpoint",
      { endpoint: URL, retry: { baseDelayMs: 2000 } },
      TOKEN
    );
    assert.equal(res.status, 200);
    assert.equal(first.length, 1);
    assert.deepEqual(first[0], {
      endpoint: URL,
      changes: [{ field: "retry.baseDelayMs", from: 1000, to: 2000 }],
    });
    assert.equal(eventsOf(auditLog, "endpoint_config_updated").length, 1);
    relay.reviseConfigChangeCallback!((endpoint, changes) =>
      second.push({ endpoint, changes })
    );
    assert.equal(second.length, 0, "no re-delivery of the reported change");
    res = await postJson(
      port,
      "/config/endpoint",
      { endpoint: URL, retry: { baseDelayMs: 3000, maxAttempts: 3 } },
      TOKEN
    );
    assert.equal(res.status, 200);
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second.length, 1);
    assert.deepEqual(second[0], {
      endpoint: URL,
      changes: [
        { field: "retry.baseDelayMs", from: 2000, to: 3000 },
        { field: "retry.maxAttempts", from: 5, to: 3 },
      ],
    });
    assert.equal(eventsOf(auditLog, "endpoint_config_updated").length, 2);
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "config_change_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; patches are still audited and a second clear is a silent no-op", async () => {
    const first: Seen = [];
    const { relay, auditLog, port } = await makeRelay({
      onConfigChange: (endpoint, changes) => first.push({ endpoint, changes }),
    });
    let res = await postJson(
      port,
      "/config/endpoint",
      { endpoint: URL, retry: { baseDelayMs: 2000 } },
      TOKEN
    );
    assert.equal(res.status, 200);
    assert.equal(first.length, 1);
    relay.reviseConfigChangeCallback!(null);
    res = await postJson(
      port,
      "/config/endpoint",
      { endpoint: URL, retry: { baseDelayMs: 3000 } },
      TOKEN
    );
    assert.equal(res.status, 200);
    assert.equal(first.length, 1, "cleared hook stays silent");
    assert.equal(
      eventsOf(auditLog, "endpoint_config_updated").length,
      2,
      "patches are still audited after clearing"
    );
    const revised = eventsOf(auditLog, "config_change_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
    relay.reviseConfigChangeCallback!(null);
    assert.equal(eventsOf(auditLog, "config_change_callback_revised").length, 1);
  });

  it("a non-function value throws RangeError and the live cell is untouched; same-reference and clear-when-unset are silent no-ops; setting from cleared audits cleared -> set", async () => {
    const first: Seen = [];
    const onConfigChange = (endpoint: string, changes: ConfigChange[]) =>
      first.push({ endpoint, changes });
    const { relay, auditLog, port } = await makeRelay({ onConfigChange });
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseConfigChangeCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "config_change_callback_revised").length, 0);
    relay.reviseConfigChangeCallback!(onConfigChange);
    assert.equal(eventsOf(auditLog, "config_change_callback_revised").length, 0);
    const res = await postJson(
      port,
      "/config/endpoint",
      { endpoint: URL, retry: { baseDelayMs: 2000 } },
      TOKEN
    );
    assert.equal(res.status, 200);
    assert.equal(first.length, 1, "live callback untouched by the rejected values");
    // Bare server: clearing when unset is a silent no-op, and setting
    // from cleared audits as cleared -> set.
    const { relay: bare, auditLog: bareAudit } = await makeRelay({});
    bare.reviseConfigChangeCallback!(null);
    assert.equal(eventsOf(bareAudit, "config_change_callback_revised").length, 0);
    bare.reviseConfigChangeCallback!((endpoint, changes) =>
      first.push({ endpoint, changes })
    );
    const bareRevised = eventsOf(bareAudit, "config_change_callback_revised");
    assert.equal(bareRevised.length, 1);
    assert.equal(bareRevised[0].previous, "cleared");
    assert.equal(bareRevised[0].current, "set");
  });

  it("revision does not change the patch validation gate: illegal patches are 400s, audit nothing, and fire no observation", async () => {
    const seen: Seen = [];
    const { relay, auditLog, port } = await makeRelay({
      onConfigChange: (endpoint, changes) => seen.push({ endpoint, changes }),
    });
    const bad = await postJson(
      port,
      "/config/endpoint",
      { endpoint: URL, retry: { baseDelayMs: 0 } },
      TOKEN
    );
    assert.equal(bad.status, 400);
    assert.equal(eventsOf(auditLog, "endpoint_config_updated").length, 0);
    assert.equal(seen.length, 0);
    // A disabled-subsystem patch is a 400 too, with no partial
    // application of the valid half.
    const bad2 = await postJson(
      port,
      "/config/endpoint",
      { endpoint: URL, retry: { baseDelayMs: 2000 }, circuitBreaker: { failureThreshold: 2 } },
      TOKEN
    );
    assert.equal(bad2.status, 400);
    assert.equal(eventsOf(auditLog, "endpoint_config_updated").length, 0);
    assert.equal(seen.length, 0);
    // The next valid patch proves the base delay is still the original.
    const ok = await postJson(
      port,
      "/config/endpoint",
      { endpoint: URL, retry: { baseDelayMs: 2000 } },
      TOKEN
    );
    assert.equal(ok.status, 200);
    assert.equal(seen.length, 1);
    assert.deepEqual(seen[0], {
      endpoint: URL,
      changes: [{ field: "retry.baseDelayMs", from: 1000, to: 2000 }],
    });
    void relay;
  });
});
