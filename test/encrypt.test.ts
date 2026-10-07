import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import {
  AesGcmEncryptor,
  NoopEncryptor,
  isEncryptedPayload,
  randomAes256Key,
  type EncryptedPayload,
} from "../src/encrypt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook", secret: "s3cr3t-payload" }));

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

describe("AesGcmEncryptor", () => {
  it("round-trips arbitrary bytes", () => {
    const enc = new AesGcmEncryptor(randomAes256Key());
    for (const plain of [BODY, Buffer.alloc(0), Buffer.from([0, 255, 1, 2, 3])]) {
      const env = enc.encrypt(plain);
      assert.equal(env.alg, "aes-256-gcm");
      assert.deepEqual(enc.decrypt(env), plain);
    }
  });

  it("uses a fresh random IV per encryption", () => {
    const enc = new AesGcmEncryptor(randomAes256Key());
    const a = enc.encrypt(BODY);
    const b = enc.encrypt(BODY);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.data, b.data);
    assert.equal(Buffer.from(a.iv, "base64").length, 12);
    assert.equal(Buffer.from(a.tag!, "base64").length, 16);
    // Both still decrypt.
    assert.deepEqual(enc.decrypt(a), BODY);
    assert.deepEqual(enc.decrypt(b), BODY);
  });

  it("rejects non-32-byte keys", () => {
    for (const bad of [Buffer.alloc(16), Buffer.alloc(31), Buffer.alloc(33), Buffer.alloc(0)]) {
      assert.throws(() => new AesGcmEncryptor(bad), RangeError);
    }
    assert.throws(() => new AesGcmEncryptor("not-a-buffer" as unknown as Buffer), RangeError);
    new AesGcmEncryptor(randomAes256Key());
  });

  it("randomAes256Key produces fresh 32-byte keys", () => {
    const a = randomAes256Key();
    const b = randomAes256Key();
    assert.equal(a.length, 32);
    assert.ok(!a.equals(b));
  });

  it("decrypt fails loudly on wrong key, tampering, and malformed envelopes", () => {
    const enc = new AesGcmEncryptor(randomAes256Key());
    const other = new AesGcmEncryptor(randomAes256Key());
    const env = enc.encrypt(BODY);

    assert.throws(() => other.decrypt(env), /decrypt failed/); // wrong key

    const tamperedData: EncryptedPayload = {
      ...env,
      data: Buffer.from(BODY).toString("base64"), // not the ciphertext
    };
    assert.throws(() => enc.decrypt(tamperedData), /decrypt failed/);

    const tamperedTag: EncryptedPayload = { ...env, tag: Buffer.alloc(16).toString("base64") };
    assert.throws(() => enc.decrypt(tamperedTag), /decrypt failed/);

    const badIv: EncryptedPayload = { ...env, iv: Buffer.alloc(8).toString("base64") };
    assert.throws(() => enc.decrypt(badIv), /bad IV length/);

    const wrongAlg: EncryptedPayload = { ...env, alg: "aes-128-gcm" };
    assert.throws(() => enc.decrypt(wrongAlg), /unsupported envelope alg/);

    assert.throws(() => enc.decrypt({} as EncryptedPayload), /decrypt failed/);
    assert.equal(isEncryptedPayload(env), true);
    assert.equal(isEncryptedPayload({}), false);
    assert.equal(isEncryptedPayload(null), false);
  });
});

describe("NoopEncryptor", () => {
  it("round-trips without protecting anything", () => {
    const enc = new NoopEncryptor();
    assert.equal(enc.name, "none");
    const env = enc.encrypt(BODY);
    assert.deepEqual(enc.decrypt(env), BODY);
    assert.throws(() => enc.decrypt({ ...env, alg: "aes-256-gcm" }), /unsupported envelope alg/);
  });
});

describe("retry queue dead-letter encryption", () => {
  const ITEM = {
    id: "enc-1",
    payload: BODY,
    targetUrl: "http://localhost:9999/hook",
    headers: {},
  };

  it("seals the dead-letter payload when an encryptor is configured", async () => {
    const timer = manualTimer();
    const key = randomAes256Key();
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("down");
      },
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      payloadEncryptor: new AesGcmEncryptor(key),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();

    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    const entry = dead[0];
    assert.ok(isEncryptedPayload(entry.encryptedPayload));
    assert.equal(entry.encryptedPayload!.alg, "aes-256-gcm");
    assert.equal(entry.payload.length, 0); // sealed at rest
    assert.equal(entry.payloadBytes, BODY.length);
    // The envelope really holds the payload.
    assert.deepEqual(new AesGcmEncryptor(key).decrypt(entry.encryptedPayload!), BODY);
    assert.equal(entry.attempts, 2);
  });

  it("replayDeadLetter decrypts transparently before re-queueing", async () => {
    const timer = manualTimer();
    let failing = true;
    const received: Buffer[] = [];
    const sender: Sender = async (item) => {
      if (failing) throw new Error("down");
      received.push(item.payload);
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      setTimer: timer.setTimer,
      payloadEncryptor: new AesGcmEncryptor(randomAes256Key()),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(q.getDeadLetter().length, 1);

    failing = false;
    assert.equal(q.replayDeadLetter("enc-1"), true);
    await timer.run();
    assert.deepEqual(received, [BODY]); // original bytes redelivered
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("keeps payloads in the clear without an encryptor (existing behavior)", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("down");
      },
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    const entry = q.getDeadLetter()[0];
    assert.deepEqual(entry.payload, BODY);
    assert.equal(entry.encryptedPayload, undefined);
    assert.equal(entry.payloadBytes, BODY.length);
  });
});

describe("audit log payload encryption", () => {
  it("seals Buffer payloads at rest and round-trips them on read", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const path = join(dir, "audit.jsonl");
    const audit = new AuditLog(path, { payloadEncryptor: new AesGcmEncryptor(randomAes256Key()) });
    assert.equal(audit.hasPayloadEncryptor(), true);

    audit.append({ event: "accepted", id: "a1", payload: BODY });
    audit.append({ event: "delivered", id: "a1" });

    // The raw file never contains the plaintext payload.
    const raw = readFileSync(path, "utf8");
    assert.ok(!raw.includes("s3cr3t-payload"), "plaintext payload leaked to disk");

    const entries = audit.readAll() as Array<Record<string, unknown>>;
    assert.equal(entries.length, 2);
    const accepted = entries[0];
    assert.equal(accepted.event, "accepted");
    assert.equal(accepted.payloadEncrypted, true);
    assert.equal(accepted.payloadBytes, BODY.length);
    assert.deepEqual(accepted.payload, BODY.toJSON()); // Buffer JSON shape, like an unencrypted append

    const delivered = entries[1];
    assert.equal(delivered.payload, undefined); // events without payload are untouched
  });

  it("round-trips string payloads as strings", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"), {
      payloadEncryptor: new AesGcmEncryptor(randomAes256Key()),
    });
    audit.append({ event: "accepted", id: "s1", payload: "plain-text-body" });
    const entries = audit.readAll() as Array<Record<string, unknown>>;
    assert.equal(entries[0].payload, "plain-text-body");
  });

  it("query() decrypts sealed payloads too", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"), {
      payloadEncryptor: new AesGcmEncryptor(randomAes256Key()),
    });
    audit.append({ event: "accepted", id: "q1", endpoint: "http://x/hook", payload: BODY });
    audit.append({ event: "delivered", id: "q1", endpoint: "http://x/hook" });
    const found = audit.query({ event: "accepted" }) as Array<Record<string, unknown>>;
    assert.equal(found.length, 1);
    assert.deepEqual(found[0].payload, BODY.toJSON());
  });

  it("reading with the wrong key throws instead of returning garbage", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const path = join(dir, "audit.jsonl");
    new AuditLog(path, { payloadEncryptor: new AesGcmEncryptor(randomAes256Key()) }).append({
      event: "accepted",
      id: "w1",
      payload: BODY,
    });
    const wrongKey = new AuditLog(path, {
      payloadEncryptor: new AesGcmEncryptor(randomAes256Key()),
    });
    assert.throws(() => wrongKey.readAll(), /decrypt failed/);
  });

  it("passes payloads through untouched without an encryptor", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.equal(audit.hasPayloadEncryptor(), false);
    audit.append({ event: "accepted", id: "p1", payload: BODY });
    const entries = audit.readAll() as Array<Record<string, unknown>>;
    assert.deepEqual(entries[0].payload, BODY.toJSON());
    assert.equal(entries[0].payloadEncrypted, undefined);
  });
});

describe("server payload encryption", () => {
  function listen(server: Server): Promise<number> {
    return new Promise((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
  }

  function request(
    port: number,
    method: string,
    path: string,
    headers: Record<string, string> = {},
    body?: Buffer
  ) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      });
      r.on("error", reject);
      if (body) r.end(body);
      else r.end();
    });
  }

  it("seals accepted payloads in the audit log and dead letters at rest", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const auditPath = join(dir, "audit.jsonl");
    const key = randomAes256Key();
    const audit = new AuditLog(auditPath, { payloadEncryptor: new AesGcmEncryptor(key) });

    let failing = true;
    const stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    const received: Buffer[] = [];
    const stubPort = await listen(stub);

    const token = "op-token";
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      sender: async (item) => {
        if (failing) throw new Error("down");
        // Forward like the default sender so the stub sees the real bytes.
        await new Promise<void>((resolve, reject) => {
          const r = httpRequest(
            { host: "127.0.0.1", port: stubPort, path: "/hook", method: "POST" },
            (res) => {
              res.resume();
              res.on("end", () => resolve());
              res.on("error", reject);
            }
          );
          r.on("error", reject);
          r.end(item.payload);
        });
      },
      retry: { baseDelayMs: 10, maxDelayMs: 50, maxAttempts: 1, jitterMs: 0 },
      payloadEncryptor: new AesGcmEncryptor(key),
      auditPayloads: true,
      operatorToken: token,
    });
    const port = await listen(relay);
    try {
      const res = await request(port, "POST", "/", { "x-signature": signSha256(BODY, SECRET) }, BODY);
      assert.equal(res.status, 202);

      // Wait for the dead letter to land.
      const deadline = Date.now() + 5000;
      let listing: Array<Record<string, unknown>> = [];
      while (Date.now() < deadline) {
        const dl = await request(port, "GET", "/dead-letter", { authorization: `Bearer ${token}` });
        listing = JSON.parse(dl.text);
        if (listing.length > 0) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(listing.length, 1);
      assert.equal(listing[0].encrypted, true);
      assert.equal(listing[0].payloadBytes, BODY.length);

      // No plaintext payload anywhere on disk.
      const raw = readFileSync(auditPath, "utf8");
      assert.ok(!raw.includes("s3cr3t-payload"), "plaintext payload leaked to the audit log");

      // The accepted audit event round-trips the sealed payload.
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.find((e) => e.event === "accepted");
      assert.ok(accepted);
      assert.deepEqual(accepted.payload, BODY.toJSON());

      // Operator replay decrypts transparently: the stub gets the original bytes.
      failing = false;
      const id = listing[0].id as string;
      const replay = await request(
        port,
        "POST",
        `/dead-letter/${encodeURIComponent(id)}/replay`,
        { authorization: `Bearer ${token}` }
      );
      assert.equal(replay.status, 200);
      const dl2 = Date.now() + 5000;
      while (received.length === 0 && Date.now() < dl2) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.deepEqual(received, [BODY]);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  });
});
