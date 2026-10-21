import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  normalizeErrorSignature,
  clusterDeadLetters,
  clusterIdFor,
  clusterIdDecode,
  topClusters,
} from "../src/deadletter-cluster.ts";
import { RetryQueue, type DeadLetterEntry } from "../src/retry.ts";
import { HttpDeliveryError } from "../src/failure.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

const testSecret = "relay-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";

function entry(partial: Partial<DeadLetterEntry> & { id: string }): DeadLetterEntry {
  return {
    payload: Buffer.from("x"),
    targetUrl: EP_A,
    headers: {},
    attempts: 2,
    lastError: "downstream 500",
    failureClass: "retryable",
    deadLetteredAt: "2026-10-21T09:00:00.000Z",
    payloadBytes: 1,
    ...partial,
  };
}

describe("deadletter-cluster: normalizeErrorSignature", () => {
  it("templates numbers, UUIDs, timestamps, and hex", () => {
    assert.equal(
      normalizeErrorSignature("connect ETIMEDOUT 93.184.216.34:443"),
      "connect ETIMEDOUT {n}.{n}.{n}.{n}:{n}"
    );
    assert.equal(
      normalizeErrorSignature("request 9f2b1c4d-7e8a-4f1d-9c3e-2a5b6d7e8f90 failed after 3 attempts"),
      "request {uuid} failed after {n} attempts"
    );
    assert.equal(
      normalizeErrorSignature("downstream 500 at 2026-10-21T09:12:33.123Z"),
      "downstream {n} at {ts}"
    );
    assert.equal(
      normalizeErrorSignature("retry at 1761037953123"),
      "retry at {ts}"
    );
    assert.equal(
      normalizeErrorSignature("payload sha256:9f2b1c4d7e8a4f1d9c3e2a5b6d7e8f90ab12cd34 invalid"),
      "payload sha256:{hex} invalid"
    );
    assert.equal(
      normalizeErrorSignature("bad digest 0xdeadBEEF"),
      "bad digest {hex}"
    );
    assert.equal(normalizeErrorSignature("downstream 500"), "downstream {n}");
  });

  it("is idempotent and trims", () => {
    const sig = normalizeErrorSignature("  connect ECONNREFUSED 10.0.0.1:8080  ");
    assert.equal(sig, "connect ECONNREFUSED {n}.{n}.{n}.{n}:{n}");
    assert.equal(normalizeErrorSignature(sig), sig);
    assert.equal(normalizeErrorSignature(""), "");
  });
});

describe("deadletter-cluster: clusterIdFor/clusterIdDecode", () => {
  it("round-trips the triple", () => {
    const id = clusterIdFor(EP_A, "retryable", "downstream {n}");
    const back = clusterIdDecode(id);
    assert.deepEqual(back, { endpoint: EP_A, failureClass: "retryable", signature: "downstream {n}" });
  });

  it("rejects malformed ids", () => {
    assert.throws(() => clusterIdDecode("!!!not-base64!!!"), /malformed cluster id/);
    assert.throws(
      () => clusterIdDecode(Buffer.from(JSON.stringify(["a", "b"]), "utf8").toString("base64url")),
      /malformed cluster id/
    );
  });
});

describe("deadletter-cluster: clusterDeadLetters", () => {
  it("groups by (endpoint, failureClass, signature) and sorts count-desc", () => {
    const entries = [
      entry({ id: "a1", lastError: "connect ECONNREFUSED 10.0.0.1:8080", deadLetteredAt: "2026-10-21T09:02:00.000Z" }),
      entry({ id: "a2", lastError: "connect ECONNREFUSED 10.0.0.2:9090", deadLetteredAt: "2026-10-21T09:01:00.000Z" }),
      entry({ id: "b1", targetUrl: EP_B, lastError: "downstream 503", deadLetteredAt: "2026-10-21T09:00:00.000Z" }),
      entry({
        id: "a3",
        lastError: "downstream 400",
        failureClass: "non_retryable",
        deadLetteredAt: "2026-10-21T09:03:00.000Z",
        traceId: "trace-a3",
      }),
    ];
    const clusters = clusterDeadLetters(entries);
    assert.equal(clusters.length, 3);
    // Loudest first: the two ECONNREFUSED entries share a signature.
    assert.equal(clusters[0].count, 2);
    assert.equal(clusters[0].endpoint, EP_A);
    assert.equal(clusters[0].failureClass, "retryable");
    assert.equal(clusters[0].signature, "connect ECONNREFUSED {n}.{n}.{n}.{n}:{n}");
    assert.equal(clusters[0].firstSeen, "2026-10-21T09:01:00.000Z");
    assert.equal(clusters[0].lastSeen, "2026-10-21T09:02:00.000Z");
    assert.equal(clusters[0].sample.id, "a2", "sample is the earliest member");
    assert.ok(clusters[0].clusterId.length > 0);
    // The 400 on EP_A is a different failure class → separate cluster.
    assert.equal(clusters[2].count, 1);
    assert.equal(clusters[2].failureClass, "non_retryable");
    assert.equal(clusters[2].sample.traceId, "trace-a3");
    assert.equal(clusters[2].sample.lastError, "downstream 400");
  });

  it("returns [] for empty input", () => {
    assert.deepEqual(clusterDeadLetters([]), []);
  });
});

describe("deadletter-cluster: topClusters", () => {
  it("caps the list and rejects bad tops", () => {
    const clusters = clusterDeadLetters([
      entry({ id: "a", lastError: "boom-alpha" }),
      entry({ id: "b", lastError: "boom-beta" }),
    ]);
    assert.equal(topClusters(clusters, 1).length, 1);
    assert.equal(topClusters(clusters, 99).length, 2);
    assert.throws(() => topClusters(clusters, 0), RangeError);
    assert.throws(() => topClusters(clusters, 1.5), RangeError);
  });
});

describe("RetryQueue.getDeadLetterClusters", () => {
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

  it("clusters live dead letters end to end", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async (it2) => {
        if (it2.targetUrl === EP_A) throw new Error("connect ECONNREFUSED 10.0.0.1:8080");
        throw new Error("connect ECONNREFUSED 10.0.0.2:9090");
      },
      baseDelayMs: 1,
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ id: "a1", payload: Buffer.from("a"), targetUrl: EP_A, headers: {} });
    q.enqueue({ id: "a2", payload: Buffer.from("a"), targetUrl: EP_A, headers: {} });
    q.enqueue({ id: "b1", payload: Buffer.from("b"), targetUrl: EP_B, headers: {} });
    await timer.run();
    assert.equal(q.getDeadLetter().length, 3);

    const clusters = q.getDeadLetterClusters();
    assert.equal(clusters.length, 2);
    assert.equal(clusters[0].endpoint, EP_A);
    assert.equal(clusters[0].count, 2);
    assert.equal(clusters[0].signature, "connect ECONNREFUSED {n}.{n}.{n}.{n}:{n}");
    assert.equal(clusters[1].endpoint, EP_B);
    assert.equal(clusters[1].count, 1);
    assert.equal(q.getDeadLetterClusters(1).length, 1);
    assert.throws(() => q.getDeadLetterClusters(0), RangeError);
  });
});

describe("GET/POST /dead-letter/clusters operator endpoints", () => {
  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function request(
    port: number,
    path: string,
    method: string,
    body: Buffer | string | undefined,
    auth?: string
  ) {
    const headers: Record<string, string> = {};
    if (auth !== undefined) headers["authorization"] = `Bearer ${auth}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      });
      r.on("error", reject);
      r.end(body === undefined ? undefined : typeof body === "string" ? body : body);
    });
  }

  async function signedPost(port: number, body: Buffer) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(body, testSecret) },
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

  async function waitDeadLetters(port: number, auth: string, n: number): Promise<void> {
    const deadline = Date.now() + 5000;
    for (;;) {
      const r = await request(port, "/dead-letter", "GET", undefined, auth);
      assert.equal(r.status, 200);
      if ((JSON.parse(r.text) as unknown[]).length >= n) return;
      if (Date.now() > deadline) throw new Error("timed out waiting for dead letters");
      await new Promise((res) => setTimeout(res, 20));
    }
  }

  function makeRelay(audit: AuditLog) {
    return createRelayServer({
      secret: testSecret,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      sender: async (it2) => {
        const body = it2.payload.toString();
        if (body.includes("poison")) throw new HttpDeliveryError(400);
        throw new Error(`connect ECONNREFUSED 10.0.0.9:8080 at ${Date.now()}`);
      },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      operatorToken: "op-secret",
    });
  }

  it("GET lists clusters; bad top is 400; unknown methods are 405", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const relay = makeRelay(new AuditLog(join(dir, "audit.jsonl")));
    const port = await listen(relay);
    const auth = "op-secret";
    try {
      assert.equal((await signedPost(port, Buffer.from('{"kind":"boom"}'))).status, 202);
      assert.equal((await signedPost(port, Buffer.from('{"kind":"boom2"}'))).status, 202);
      await waitDeadLetters(port, auth, 2);

      const res = await request(port, "/dead-letter/clusters", "GET", undefined, auth);
      assert.equal(res.status, 200);
      const body = JSON.parse(res.text) as { clusters: Array<Record<string, unknown>> };
      assert.equal(body.clusters.length, 1, "both ECONNREFUSED errors share one signature");
      const cluster = body.clusters[0];
      assert.equal(cluster.endpoint, "http://127.0.0.1:1/unused");
      assert.equal(cluster.failureClass, "retryable");
      assert.equal(cluster.signature, "connect ECONNREFUSED {n}.{n}.{n}.{n}:{n} at {ts}");
      assert.equal(cluster.count, 2);
      assert.ok(typeof cluster.firstSeen === "string");
      assert.ok(typeof cluster.lastSeen === "string");
      assert.ok(typeof cluster.clusterId === "string");
      const sample = cluster.sample as Record<string, unknown>;
      assert.ok(typeof sample.id === "string");
      assert.match(sample.lastError as string, /connect ECONNREFUSED/);

      assert.equal((await request(port, "/dead-letter/clusters?top=abc", "GET", undefined, auth)).status, 400);
      assert.equal((await request(port, "/dead-letter/clusters", "GET", undefined, "wrong")).status, 403);
      assert.equal((await request(port, "/dead-letter/clusters", "PUT", undefined, auth)).status, 405);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("POST replays a cluster by selector with dry-run and audit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = makeRelay(audit);
    const port = await listen(relay);
    const auth = "op-secret";
    const endpoint = "http://127.0.0.1:1/unused";
    try {
      assert.equal((await signedPost(port, Buffer.from('{"kind":"boom"}'))).status, 202);
      assert.equal((await signedPost(port, Buffer.from('{"kind":"poison"}'))).status, 202);
      await waitDeadLetters(port, auth, 2);

      // Selector that matches nothing is a loud 404, not a silent empty replay.
      assert.equal(
        (await request(port, "/dead-letter/clusters", "POST", JSON.stringify({ endpoint: "http://nope/" }), auth))
          .status,
        404
      );
      // Missing endpoint is a 400.
      assert.equal(
        (await request(port, "/dead-letter/clusters", "POST", JSON.stringify({}), auth)).status,
        400
      );

      // Dry run: preview only, zero side effects.
      const dry = await request(
        port,
        "/dead-letter/clusters",
        "POST",
        JSON.stringify({ endpoint, failureClass: "non_retryable", dryRun: true }),
        auth
      );
      assert.equal(dry.status, 200);
      const dryBody = JSON.parse(dry.text) as { dryRun: boolean; entries: Array<{ id: string }> };
      assert.equal(dryBody.dryRun, true);
      assert.equal(dryBody.entries.length, 1, "only the poison 400 is non_retryable");
      const listed = JSON.parse(
        (await request(port, "/dead-letter", "GET", undefined, auth)).text
      ) as unknown[];
      assert.equal(listed.length, 2, "dry run re-queued nothing");

      // Real replay of the retryable cluster.
      const replayed = await request(
        port,
        "/dead-letter/clusters",
        "POST",
        JSON.stringify({ endpoint, failureClass: "retryable" }),
        auth
      );
      assert.equal(replayed.status, 200);
      const replayedBody = JSON.parse(replayed.text) as { replayed: string[]; failed: unknown[]; skipped: unknown[] };
      assert.equal(replayedBody.replayed.length, 1);
      assert.deepEqual(replayedBody.failed, []);
      const events = audit.readAll().map((e) => (e as { event: string }).event);
      assert.ok(events.includes("dead_letter_cluster_replayed"), "cluster replay is audited");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
