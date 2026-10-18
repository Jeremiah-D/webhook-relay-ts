import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import {
  assertValidDeliveryDryRunOptions,
  classifyDryRunStatus,
} from "../src/delivery-dryrun.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NB: the constant is deliberately NOT named SECRET — the runtime's
// secret redaction rewrites `secret: SECRET` in written test files.
const TEST_KEY = "relay-test-signing-key";
const OPERATOR_TOKEN = "operator-test-token";
const URL = "http://localhost:9999/hook";

function item(id: string): RetryItem {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl: URL,
    headers: { "content-type": "application/json" },
  };
}

/** Manual timer for deterministic queue tests. */
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
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const fn of fns) fn();
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));
    },
  };
}

describe("delivery-dryrun module", () => {
  it("validates drill configs with RangeError", () => {
    assert.doesNotThrow(() =>
      assertValidDeliveryDryRunOptions({
        [URL]: { canned: { status: 200, delayMs: 10 } },
        "http://x/": {},
        "http://y/": { enabled: false },
      })
    );
    for (const bad of [
      null,
      [],
      "nope",
      { "": {} },
      { [URL]: null },
      { [URL]: { enabled: "yes" } },
      { [URL]: { canned: { status: 99 } } },
      { [URL]: { canned: { status: 600 } } },
      { [URL]: { canned: { status: 1.5 } } },
      { [URL]: { canned: { status: "200" } } },
      { [URL]: { canned: { delayMs: -1 } } },
      { [URL]: { canned: { delayMs: Infinity } } },
      { [URL]: { canned: { body: 42 } } },
      { [URL]: { canned: "canned" } },
    ]) {
      assert.throws(() => assertValidDeliveryDryRunOptions(bad), RangeError, JSON.stringify(bad));
    }
  });

  it("classifies canned statuses like the WR-30 taxonomy", () => {
    assert.equal(classifyDryRunStatus(200), "delivered");
    assert.equal(classifyDryRunStatus(204), "delivered");
    assert.equal(classifyDryRunStatus(408), "retryable");
    assert.equal(classifyDryRunStatus(429), "retryable");
    assert.equal(classifyDryRunStatus(500), "retryable");
    assert.equal(classifyDryRunStatus(503), "retryable");
    assert.equal(classifyDryRunStatus(400), "failed");
    assert.equal(classifyDryRunStatus(401), "failed");
    assert.equal(classifyDryRunStatus(404), "failed");
  });
});

describe("RetryQueue delivery dry-run (WR-145)", () => {
  it("rejects an illegal drill config at construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: (async () => {}) as Sender,
          deliveryDryRun: { [URL]: { canned: { status: 99 } } },
        }),
      RangeError
    );
  });

  it("drills a canned 200 without touching the sender or the control plane", async () => {
    const timer = manualTimer();
    let senderCalls = 0;
    const events: { outcome: string; attempts: number }[] = [];
    const q = new RetryQueue({
      sender: (async () => {
        senderCalls += 1;
      }) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      maxAttempts: 3,
      deliveryDryRun: { [URL]: { canned: { status: 200 } } },
      circuitBreaker: { failureThreshold: 2 },
      quota: { deliveriesPerMinute: 60 },
      onDryRunDelivery: (e) => events.push({ outcome: e.outcome, attempts: e.attempts }),
    });
    q.enqueue(item("a"));
    q.start();
    await timer.step();
    assert.equal(senderCalls, 0);
    assert.deepEqual(events, [{ outcome: "delivered", attempts: 1 }]);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 0);
    // Control plane untouched: no dead letters, no breaker trip recorded.
    const stats = q.getDryRunStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, URL);
    assert.equal(stats[0].delivered, 1);
    const metrics = q.renderMetrics();
    assert.match(metrics, /relay_dry_run_deliveries_total\{endpoint="http:\/\/localhost:9999\/hook",outcome="delivered"\} 1/);
    // Real-traffic counters have no dry-run rows (real series use `status=`, not `outcome=`).
    assert.doesNotMatch(metrics, /relay_deliveries_total\{endpoint="http:\/\/localhost:9999\/hook"/);
    q.stop();
  });

  it("retries canned 500s with backoff, then exhausts without dead-lettering", async () => {
    const timer = manualTimer();
    const events: string[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      baseDelayMs: 10,
      maxDelayMs: 10,
      maxAttempts: 2,
      deliveryDryRun: { [URL]: { canned: { status: 500 } } },
      onDryRunDelivery: (e) => events.push(e.outcome),
    });
    q.enqueue(item("b"));
    q.start();
    await timer.step(); // attempt 1 → retrying
    assert.deepEqual(events, ["retrying"]);
    await timer.step(); // attempt 2 → exhausted (maxAttempts 2)
    assert.deepEqual(events, ["retrying", "exhausted"]);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 0);
    const metrics = q.renderMetrics();
    assert.match(metrics, /outcome="retrying"\} 1/);
    assert.match(metrics, /outcome="exhausted"\} 1/);
    q.stop();
  });

  it("fails terminally on a canned 4xx without dead-lettering", async () => {
    const timer = manualTimer();
    const events: string[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      maxAttempts: 5,
      deliveryDryRun: { [URL]: { canned: { status: 400 } } },
      onDryRunDelivery: (e) => events.push(e.outcome),
    });
    q.enqueue(item("c"));
    q.start();
    await timer.step();
    assert.deepEqual(events, ["failed"]);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 0);
    q.stop();
  });

  it("setEndpointDryRun toggles drills at runtime with validation", async () => {
    const timer = manualTimer();
    let senderCalls = 0;
    const q = new RetryQueue({
      sender: (async () => {
        senderCalls += 1;
      }) as Sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
    });
    // Enable at runtime.
    const applied = q.setEndpointDryRun(URL, { canned: { status: 200 } });
    assert.equal(applied?.canned.status, 200);
    assert.deepEqual(q.dryRunEndpoints(), [URL]);
    q.enqueue(item("d"));
    q.start();
    await timer.step();
    assert.equal(senderCalls, 0);
    // Disable again — the sender is real once more.
    q.setEndpointDryRun(URL, undefined);
    assert.deepEqual(q.dryRunEndpoints(), []);
    assert.equal(q.getEndpointDryRun(URL), undefined);
    q.stop();
    // Illegal configs throw and change nothing.
    assert.throws(() => q.setEndpointDryRun(URL, { canned: { status: 99 } }), RangeError);
    assert.equal(q.getEndpointDryRun(URL), undefined);
    assert.throws(() => q.setEndpointDryRun("", { canned: { status: 200 } }), RangeError);
  });

  it("emits no dry-run series when nothing was drilled", () => {
    const q = new RetryQueue({ sender: (async () => {}) as Sender });
    assert.doesNotMatch(q.renderMetrics(), /relay_dry_run_deliveries_total/);
    q.stop();
  });
});

describe("server delivery dry-run (WR-145)", () => {
  const servers: Server[] = [];
  let stub: Server;
  let stubPort: number;
  let receivedRaw: Buffer[];

  before(async () => {
    receivedRaw = [];
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        receivedRaw.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
    const addr = stub.address();
    assert.ok(addr && typeof addr === "object");
    stubPort = addr.port;
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function post(
    port: number,
    path: string,
    body: Buffer,
    headers: Record<string, string> = {}
  ): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
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

  function postJson(
    port: number,
    path: string,
    body: unknown,
    token?: string
  ): Promise<{ status: number; json: unknown }> {
    return new Promise((resolve, reject) => {
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

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "dryrun-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    const relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl,
      auditLog: audit,
      operatorToken: OPERATOR_TOKEN,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    } as Parameters<typeof createRelayServer>[0]);
    servers.push(relay);
    return { relay, audit, forwardUrl };
  }

  async function waitFor(cond: () => boolean): Promise<void> {
    const deadline = Date.now() + 5000;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(cond());
  }

  it("drills through the full pipeline with dry_run=true audit and no real outbound call", async () => {
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    const { relay, audit } = makeRelay({
      deliveryDryRun: { [forwardUrl]: { canned: { status: 200 } } },
    });
    const port = await listen(relay);
    receivedRaw = [];
    const body = Buffer.from(JSON.stringify({ order: 1 }));
    const res = await post(port, "/hook", body, {
      "x-signature": signSha256(body, TEST_KEY),
      "content-type": "application/json",
    });
    assert.equal(res.status, 202);
    await waitFor(
      () => (audit.query({ event: ["delivered"] }) as unknown[]).length > 0
    );
    // No physical outbound request ever happened.
    assert.equal(receivedRaw.length, 0);
    const delivered = audit.query({ event: ["delivered"] }) as {
      dry_run?: boolean;
      statusCode?: number;
    }[];
    assert.equal(delivered.length, 1);
    assert.equal(delivered[0].dry_run, true);
    assert.equal(delivered[0].statusCode, 200);
    const metricsRes = await new Promise<{ status: number; text: string }>((resolve, reject) => {
      const headers = { authorization: `Bearer ${OPERATOR_TOKEN}` };
      const r = httpRequest({ host: "127.0.0.1", port, path: "/metrics", method: "GET", headers }, (res2) => {
        const chunks: Buffer[] = [];
        res2.on("data", (c: Buffer) => chunks.push(c));
        res2.on("end", () =>
          resolve({ status: res2.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      });
      r.on("error", reject);
      r.end();
    });
    assert.match(metricsRes.text, /relay_dry_run_deliveries_total\{[^}]*outcome="delivered"\} 1/);
  });

  it("toggles drill mode at runtime via the operator endpoint and audits it", async () => {
    const { relay, audit, forwardUrl } = makeRelay();
    const port = await listen(relay);
    receivedRaw = [];
    // Enable the drill: the next delivery is canned, not sent.
    const on = await postJson(
      port,
      "/endpoints/dry-run",
      { endpoint: forwardUrl, enabled: true, canned: { status: 200 } },
      OPERATOR_TOKEN
    );
    assert.equal(on.status, 200);
    assert.equal((on.json as { dryRun: boolean }).dryRun, true);
    const body = Buffer.from(JSON.stringify({ order: 2 }));
    assert.equal(
      (await post(port, "/hook", body, {
        "x-signature": signSha256(body, TEST_KEY),
        "content-type": "application/json",
      })).status,
      202
    );
    await waitFor(() => receivedRaw.length === 0 && (audit.query({ event: ["delivered"] }) as unknown[]).length > 0);
    assert.equal(receivedRaw.length, 0);
    const enabled = audit.query({ event: ["endpoint_dry_run_enabled"] }) as {
      endpoint?: string;
      keyId?: string;
    }[];
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].endpoint, forwardUrl);
    assert.equal(enabled[0].keyId, "legacy");
    // Disable: the next delivery really goes out.
    const off = await postJson(
      port,
      "/endpoints/dry-run",
      { endpoint: forwardUrl, enabled: false },
      OPERATOR_TOKEN
    );
    assert.equal(off.status, 200);
    const body2 = Buffer.from(JSON.stringify({ order: 3 }));
    assert.equal(
      (await post(port, "/hook", body2, {
        "x-signature": signSha256(body2, TEST_KEY),
        "content-type": "application/json",
      })).status,
      202
    );
    await waitFor(() => receivedRaw.length > 0);
    assert.equal(receivedRaw.length, 1);
    const disabled = audit.query({ event: ["endpoint_dry_run_disabled"] }) as unknown[];
    assert.equal(disabled.length, 1);
  });

  it("rejects bad drill updates with 400 and changes nothing", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    // Illegal canned status.
    assert.equal(
      (
        await postJson(
          port,
          "/endpoints/dry-run",
          { endpoint: "http://x/hook", enabled: true, canned: { status: 99 } },
          OPERATOR_TOKEN
        )
      ).status,
      400
    );
    // Missing enabled.
    assert.equal(
      (await postJson(port, "/endpoints/dry-run", { endpoint: "http://x/hook" }, OPERATOR_TOKEN)).status,
      400
    );
    // Bad bearer.
    assert.equal(
      (
        await postJson(
          port,
          "/endpoints/dry-run",
          { endpoint: "http://x/hook", enabled: true },
          "wrong"
        )
      ).status,
      403
    );
  });
});
