import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import { signSha256, verifySignature } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

const SECRET = "relay-secret";
const OUTBOUND_SECRET = "outbound-relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

describe("WR-26 outbound request signing", () => {
  let stub: Server;
  let stubPort: number;
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function item(): RetryItem {
    return {
      id: "item-1",
      traceId: "trace-1",
      payload: BODY,
      targetUrl: `http://127.0.0.1:${stubPort}/hook`,
      headers: {},
    };
  }

  async function deliverAndWait(sender: { (i: RetryItem): Promise<void>; destroy(): void }) {
    seen.length = 0;
    await sender(item());
    const deadline = Date.now() + 5000;
    while (seen.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    sender.destroy();
    assert.equal(seen.length, 1);
    return seen[0];
  }

  it("stamps x-relay-signature + x-relay-key-id and the signature verifies downstream", async () => {
    const sender = createDefaultSender(undefined, false, { secret: OUTBOUND_SECRET, keyId: "k1" });
    try {
      const got = await deliverAndWait(sender);
      const expected = signSha256(BODY, OUTBOUND_SECRET);
      assert.equal(got.headers["x-relay-signature"], expected);
      assert.equal(got.headers["x-relay-key-id"], "k1");
      // The downstream contract: verify with the shared secret.
      assert.ok(verifySignature(got.body, String(got.headers["x-relay-signature"]), OUTBOUND_SECRET));
      assert.ok(!verifySignature(got.body, String(got.headers["x-relay-signature"]), "wrong-secret"));
    } finally {
      sender.destroy();
    }
  });

  it("omits x-relay-key-id when no keyId is configured", async () => {
    const sender = createDefaultSender(undefined, false, { secret: OUTBOUND_SECRET });
    try {
      const got = await deliverAndWait(sender);
      assert.equal(got.headers["x-relay-signature"], signSha256(BODY, OUTBOUND_SECRET));
      assert.equal(got.headers["x-relay-key-id"], undefined);
    } finally {
      sender.destroy();
    }
  });

  it("adds no signing headers when disabled, even if the inbound request carried forged ones", async () => {
    const dir = mkdtempSync(join(tmpdir(), "outsign-"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(relay);
    try {
      seen.length = 0;
      await new Promise<void>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: {
              "x-signature": signSha256(BODY, SECRET),
              "x-relay-signature": "sha256=" + "de".repeat(32),
              "x-relay-key-id": "attacker-key",
            },
          },
          (res) => {
            res.resume();
            res.on("end", resolve);
          }
        );
        r.on("error", reject);
        r.end(BODY);
      });
      const deadline = Date.now() + 5000;
      while (seen.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(seen.length, 1);
      // Forged inbound relay headers must not pass through downstream.
      assert.equal(seen[0].headers["x-relay-signature"], undefined);
      assert.equal(seen[0].headers["x-relay-key-id"], undefined);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("overwrites a forged inbound x-relay-signature with the relay's own signature", async () => {
    const dir = mkdtempSync(join(tmpdir(), "outsign-"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      outboundSigning: { secret: OUTBOUND_SECRET, keyId: "k1" },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(relay);
    try {
      seen.length = 0;
      await new Promise<void>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: {
              "x-signature": signSha256(BODY, SECRET),
              "x-relay-signature": "sha256=" + "de".repeat(32),
              "x-relay-key-id": "attacker-key",
            },
          },
          (res) => {
            res.resume();
            res.on("end", resolve);
          }
        );
        r.on("error", reject);
        r.end(BODY);
      });
      const deadline = Date.now() + 5000;
      while (seen.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(seen.length, 1);
      const expected = signSha256(BODY, OUTBOUND_SECRET);
      assert.equal(seen[0].headers["x-relay-signature"], expected);
      assert.equal(seen[0].headers["x-relay-key-id"], "k1");
      assert.ok(verifySignature(seen[0].body, expected, OUTBOUND_SECRET));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("rejects invalid signing config with RangeError at startup", () => {
    assert.throws(() => createDefaultSender(undefined, false, { secret: "" }), RangeError);
    assert.throws(
      () => createDefaultSender(undefined, false, { secret: OUTBOUND_SECRET, keyId: "" }),
      RangeError
    );
    const dir = mkdtempSync(join(tmpdir(), "outsign-"));
    assert.throws(
      () =>
        createRelayServer({
          secret: SECRET,
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          outboundSigning: { secret: "" },
        }),
      RangeError
    );
  });
});
