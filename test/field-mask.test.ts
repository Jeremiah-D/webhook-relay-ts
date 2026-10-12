import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { FieldMask } from "../src/masking.ts";
import { AuditLog } from "../src/audit.ts";
import {
  AesGcmEncryptor,
  randomAes256Key,
  isEncryptedPayload,
  type EncryptedPayload,
} from "../src/encrypt.ts";
import { RetryQueue, type DownstreamResponseSummary } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return { clear: () => { const i = pending.indexOf(fn); if (i >= 0) pending.splice(i, 1); } };
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

const URL = "http://127.0.0.1:9999/hook";
const ITEM = { payload: Buffer.from("x"), targetUrl: URL, headers: {} };
const PAN = "4111111111111111";

function panMask() {
  return new FieldMask({
    [URL]: [
      { path: "card_number", strategy: "last4" },
      { path: "user.ssn" },
    ],
  });
}

describe("FieldMask", () => {
  it("rejects invalid paths and strategies at construction", () => {
    assert.throws(() => new FieldMask({ e: [{ path: "" }] }), RangeError);
    assert.throws(() => new FieldMask({ e: [{ path: "a..b" }] }), RangeError);
    assert.throws(() => new FieldMask({ e: [{ path: ".a" }] }), RangeError);
    assert.throws(() => new FieldMask({ e: [{ path: "a." }] }), RangeError);
    assert.throws(() => new FieldMask({ e: [{ path: "__proto__.x" }] }), RangeError);
    assert.throws(() => new FieldMask({ e: [{ path: "a.constructor.b" }] }), RangeError);
    assert.throws(() => new FieldMask({ e: [{ path: "a.prototype" }] }), RangeError);
    assert.throws(() => new FieldMask({ e: [{ path: 42 as unknown as string }] }), RangeError);
    assert.throws(
      () => new FieldMask({ e: [{ path: "a", strategy: "sha256" as never }] }),
      RangeError
    );
    assert.throws(() => new FieldMask({ e: "nope" as unknown as [] }), RangeError);
    assert.throws(() => new FieldMask(null as unknown as Record<string, []>), RangeError);
    // The forbidden segments really cannot pollute the prototype.
    const m = new FieldMask({ e: [{ path: "user.name" }] });
    m.maskJson("e", { user: { name: "x" } });
    assert.equal(({} as Record<string, unknown>).polluted, undefined);
  });

  it("masks nested paths and array elements; missing paths are no-ops", () => {
    const mask = new FieldMask({
      [URL]: [
        { path: "card_number", strategy: "last4" },
        { path: "payment.card.cvv" },
        { path: "items.0.sku", strategy: "last4" },
        { path: "missing.deep.path" },
      ],
    });
    const input = {
      card_number: PAN,
      payment: { card: { cvv: "123", number: PAN } },
      items: [{ sku: "SECRET-SKU-1" }, { sku: "other" }],
      untouched: "yes",
    };
    const out = mask.maskJson(URL, input) as Record<string, any>;
    assert.equal(out.card_number, "****1111");
    assert.equal(out.payment.card.cvv, "****");
    assert.equal(out.payment.card.number, PAN); // only the listed path is masked
    assert.equal(out.items[0].sku, "****KU-1");
    assert.equal(out.items[1].sku, "other");
    assert.equal(out.untouched, "yes");
    // The input is never mutated.
    assert.equal(input.card_number, PAN);
    assert.equal(input.payment.card.cvv, "123");
  });

  it("last4 degrades safely on short strings, non-strings, and subtrees", () => {
    const mask = new FieldMask({
      e: [
        { path: "short", strategy: "last4" },
        { path: "num", strategy: "last4" },
        { path: "sub", strategy: "last4" },
        { path: "nothing" },
      ],
    });
    const out = mask.maskJson("e", {
      short: "abc",
      num: 12345,
      sub: { x: 1 },
      nothing: null,
    }) as Record<string, unknown>;
    assert.deepEqual(out, { short: "****", num: "****", sub: "****", nothing: "****" });
  });

  it("returns the value untouched when the endpoint has no rules", () => {
    const mask = panMask();
    const v = { card_number: PAN };
    assert.equal(mask.maskJson("http://other/hook", v), v);
    assert.equal(mask.hasRules(URL), true);
    assert.equal(mask.hasRules("http://other/hook"), false);
  });
});

describe("AuditLog field masking", () => {
  it("masks the payload before encryption; the raw value never hits disk", () => {
    const dir = mkdtempSync(join(tmpdir(), "mask-"));
    const path = join(dir, "audit.jsonl");
    const enc = new AesGcmEncryptor(randomAes256Key());
    const audit = new AuditLog(path, { payloadEncryptor: enc, fieldMask: panMask() });
    audit.append({
      event: "accepted",
      targetUrl: URL,
      payload: Buffer.from(JSON.stringify({ card_number: PAN, user: { ssn: "123-45-6789" } })),
    });
    const raw = readFileSync(path, "utf8");
    assert.ok(!raw.includes(PAN), "raw PAN must never hit disk");
    assert.ok(!raw.includes("123-45-6789"), "raw SSN must never hit disk");
    assert.ok(raw.includes('"payloadEncrypted":true'), "the sealed envelope is on disk");
    // readAll transparently decrypts: the payload comes back masked.
    const [entry] = audit.readAll() as Array<Record<string, unknown>>;
    assert.equal(entry.payloadEncrypted, true);
    const buf = Buffer.from((entry.payload as { data: number[] }).data);
    const body = JSON.parse(buf.toString("utf8"));
    assert.equal(body.card_number, "****1111");
    assert.equal(body.user.ssn, "****");
  });

  it("masks plaintext payloads when no encryptor is configured", () => {
    const dir = mkdtempSync(join(tmpdir(), "mask-"));
    const path = join(dir, "audit.jsonl");
    const audit = new AuditLog(path, { fieldMask: panMask() });
    audit.append({
      event: "accepted",
      targetUrl: URL,
      payload: JSON.stringify({ card_number: PAN }),
    });
    const raw = readFileSync(path, "utf8");
    assert.ok(!raw.includes(PAN));
    assert.ok(raw.includes("****1111"));
  });

  it("leaves other endpoints, non-JSON payloads, and endpoint-less events alone", () => {
    const dir = mkdtempSync(join(tmpdir(), "mask-"));
    const path = join(dir, "audit.jsonl");
    const audit = new AuditLog(path, { fieldMask: panMask() });
    audit.append({
      event: "accepted",
      targetUrl: "http://other/hook",
      payload: JSON.stringify({ card_number: PAN }),
    });
    audit.append({ event: "accepted", targetUrl: URL, payload: "not json at all" });
    audit.append({ event: "accepted", payload: JSON.stringify({ card_number: PAN }) });
    const raw = readFileSync(path, "utf8");
    // Selectivity proof: the unmasked events still carry the raw value.
    assert.ok(raw.includes(PAN));
    const entries = audit.readAll() as Array<Record<string, unknown>>;
    assert.equal(entries.length, 3);
  });

  it("setFieldMask attaches a mask after construction", () => {
    const dir = mkdtempSync(join(tmpdir(), "mask-"));
    const path = join(dir, "audit.jsonl");
    const audit = new AuditLog(path);
    assert.equal(audit.hasFieldMask(), false);
    audit.append({ event: "accepted", targetUrl: URL, payload: JSON.stringify({ card_number: PAN }) });
    assert.ok(readFileSync(path, "utf8").includes(PAN));
    audit.setFieldMask(panMask());
    assert.equal(audit.hasFieldMask(), true);
    audit.append({ event: "accepted", targetUrl: URL, payload: JSON.stringify({ card_number: PAN }) });
    const lines = readFileSync(path, "utf8").trim().split("\n");
    assert.ok(!lines[1].includes(PAN));
    assert.ok(lines[1].includes("****1111"));
  });
});

describe("retry queue captured-body masking", () => {
  it("masks JSON bodies before WR-11 sealing; the fingerprint covers the original bytes", async () => {
    const timer = manualTimer();
    const enc = new AesGcmEncryptor(randomAes256Key());
    const seen: DownstreamResponseSummary[] = [];
    const downstreamBody = Buffer.from(JSON.stringify({ card_number: PAN, ok: true }));
    const q = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: downstreamBody, truncated: false }),
      jitterMs: 0,
      payloadEncryptor: enc,
      responseBodyCapture: true,
      fieldMask: new FieldMask({ [URL]: [{ path: "card_number", strategy: "last4" }] }),
      onDelivered: (_item, _attempts, summary) => {
        if (summary !== undefined) seen.push(summary);
      },
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "m-1" });
    await timer.run();
    assert.equal(seen.length, 1);
    const [summary] = seen;
    assert.ok(isEncryptedPayload(summary.capturedBody));
    const plain = JSON.parse(
      enc.decrypt(summary.capturedBody as EncryptedPayload).toString("utf8")
    );
    assert.equal(plain.card_number, "****1111");
    assert.equal(plain.ok, true);
    // Fingerprint honesty: it covers what the downstream actually sent.
    const expected = createHash("sha256")
      .update(downstreamBody.subarray(0, 256))
      .digest("hex");
    assert.equal(summary.bodyFingerprintSha256, expected);
  });

  it("seals non-JSON bodies untouched (field paths cannot apply)", async () => {
    const timer = manualTimer();
    const enc = new AesGcmEncryptor(randomAes256Key());
    const seen: DownstreamResponseSummary[] = [];
    const q = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: Buffer.from("plain text body"), truncated: false }),
      jitterMs: 0,
      payloadEncryptor: enc,
      responseBodyCapture: true,
      fieldMask: new FieldMask({ [URL]: [{ path: "card_number", strategy: "last4" }] }),
      onDelivered: (_item, _attempts, summary) => {
        if (summary !== undefined) seen.push(summary);
      },
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "m-2" });
    await timer.run();
    assert.equal(seen.length, 1);
    assert.ok(isEncryptedPayload(seen[0].capturedBody));
    assert.equal(
      enc.decrypt(seen[0].capturedBody as EncryptedPayload).toString("utf8"),
      "plain text body"
    );
  });
});

describe("field-mask server wiring", () => {
  let stub: Server;
  let stubPort: number;
  // Lowercase identifier: the all-caps SECRET name is redacted in this repo (see AGENTS.md).
  const hookKey = "hook-signing-key";

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function post(port: number, body: Buffer, headers: Record<string, string>) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path: "/", method: "POST", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  before(async () => {
    // The downstream answers with a JSON body containing the PAN.
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        const body = Buffer.from(JSON.stringify({ card_number: PAN, status: "ok" }));
        res.writeHead(200, { "content-type": "application/json" }).end(body);
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  it("never persists raw values: the accepted payload and the captured body are masked", async () => {
    const dir = mkdtempSync(join(tmpdir(), "fieldmask-"));
    const path = join(dir, "audit.jsonl");
    const enc = new AesGcmEncryptor(randomAes256Key());
    const audit = new AuditLog(path, { payloadEncryptor: enc });
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    const relay = createRelayServer({
      secret: hookKey,
      forwardUrl,
      auditLog: audit,
      payloadEncryptor: enc,
      auditPayloads: true,
      fieldMask: new FieldMask({ [forwardUrl]: [{ path: "card_number", strategy: "last4" }] }),
      retry: { baseDelayMs: 10, jitterMs: 0, responseBodyCapture: true },
    });
    const port = await listen(relay);
    try {
      const body = Buffer.from(JSON.stringify({ card_number: PAN, amount: 100 }));
      const res = await post(port, body, {
        "x-signature": signSha256(body, hookKey),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      // Wait for the delivery to land in the audit log.
      const deadline = Date.now() + 8000;
      let events: Array<Record<string, unknown>> = [];
      while (Date.now() < deadline) {
        events = audit.readAll() as Array<Record<string, unknown>>;
        if (events.some((e) => e.event === "delivered")) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(events.some((e) => e.event === "delivered"), "expected a delivered event");
      // The raw value appears nowhere on disk — not in the accepted
      // payload, not in the sealed captured body.
      const raw = readFileSync(path, "utf8");
      assert.ok(!raw.includes(PAN), "raw PAN must never hit disk");
      const accepted = events.find((e) => e.event === "accepted") as Record<string, any>;
      const acceptedBody = JSON.parse(
        Buffer.from(accepted.payload.data).toString("utf8")
      );
      assert.equal(acceptedBody.card_number, "****1111");
      assert.equal(acceptedBody.amount, 100);
      const delivered = events.find((e) => e.event === "delivered") as Record<string, any>;
      const summary = delivered.response_summary as Record<string, unknown>;
      assert.ok(isEncryptedPayload(summary.capturedBody));
      const captured = JSON.parse(
        enc.decrypt(summary.capturedBody as EncryptedPayload).toString("utf8")
      );
      assert.equal(captured.card_number, "****1111");
      assert.equal(captured.status, "ok");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
