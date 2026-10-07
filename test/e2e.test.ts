import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const SECRET = "e2e-secret";
const BODY = Buffer.from(JSON.stringify({ order: "ord_123", amount: 4200 }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
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
    r.end(body);
  });
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "GET", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          let json: unknown = null;
          try {
            json = JSON.parse(Buffer.concat(chunks).toString());
          } catch {
            // Leave json as null; the status assertion will fail the test.
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
      }
    );
    r.on("error", reject);
    r.end();
  });
}

/** Flaky downstream: fails `failures` times with 500, then answers 200. */
function flakyStub(failures: number) {
  const hits: Array<{ at: number; body: Buffer; status: number }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const status = hits.length < failures ? 500 : 200;
      hits.push({ at: Date.now(), body: Buffer.concat(chunks), status });
      res.writeHead(status).end(status === 200 ? "ok" : "boom");
    });
  });
  return { server, hits };
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

describe("end-to-end delivery", () => {
  it("retries a 500-ing downstream with growing backoff and eventually delivers", async () => {
    const { server: stub, hits } = flakyStub(2);
    const stubPort = await listen(stub);
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "e2e-")), "audit.jsonl"));
    // Real HTTP sender (not injected): the whole verify -> retry -> POST path.
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 100, maxDelayMs: 5000, maxAttempts: 5, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);

      await waitFor(() => hits.length >= 3, 15000, "3 downstream attempts");
      assert.equal(hits.length, 3);
      assert.deepEqual(
        hits.map((h) => h.status),
        [500, 500, 200]
      );
      // Payload survives the retry round-trips byte-for-byte.
      for (const h of hits) assert.deepEqual(h.body, BODY);

      // Backoff visibly grows between attempts (base*2^1=200ms, base*2^2=400ms).
      const gap1 = hits[1].at - hits[0].at;
      const gap2 = hits[2].at - hits[1].at;
      assert.ok(gap1 >= 100, `first retry came too fast (${gap1}ms)`);
      assert.ok(gap2 >= gap1 * 1.5, `backoff did not grow: ${gap1}ms then ${gap2}ms`);

      // The audit trail records the successful delivery with its attempt count.
      await waitFor(() => audit.query({ event: "delivered" }).length > 0, 5000, "delivered audit entry");
      const delivered = audit.query({ event: "delivered" }) as Array<{ attempts: number }>;
      assert.equal(delivered.length, 1);
      assert.equal(delivered[0].attempts, 3);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("dead-letters after maxAttempts when the downstream never recovers", async () => {
    const { server: stub, hits } = flakyStub(Number.MAX_SAFE_INTEGER);
    const stubPort = await listen(stub);
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "e2e-")), "audit.jsonl"));
    const token = "op-token";
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: token,
      retry: { baseDelayMs: 50, maxDelayMs: 1000, maxAttempts: 3, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);

      await waitFor(() => hits.length >= 3, 15000, "3 downstream attempts");
      assert.deepEqual(
        hits.map((h) => h.status),
        [500, 500, 500]
      );

      // The operator surface shows the dead-lettered delivery over real HTTP.
      await waitFor(() => audit.query({ event: "dead_letter" }).length > 0, 5000, "dead_letter audit entry");
      const dl = await get(relayPort, "/dead-letter", { authorization: `Bearer ${token}` });
      assert.equal(dl.status, 200);
      const entries = dl.json as Array<{ attempts: number; lastError: string }>;
      assert.equal(entries.length, 1);
      assert.equal(entries[0].attempts, 3);
      assert.match(entries[0].lastError, /500/);
    } finally {
      await close(relay);
      await close(stub);
    }
  });
});
