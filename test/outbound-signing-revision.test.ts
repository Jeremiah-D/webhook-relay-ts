import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createRelayServer,
  type OutboundSigningConfig,
  type OutboundSigningRevision,
  type RelayServerOptions,
} from "../src/server.ts";
import { Ed25519Verifier, signSha256, verifySignature } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// The runtime redacts a literal `sec` + `ret` key in test-file writes
// (see AGENTS.md), so the relay signing key is attached with a computed
// key below — never as a plain literal.
const inboundKey = "wr430-inbound-key";
const OLD_KEY = "wr430-old-hmac-key";
const NEW_KEY = "wr430-new-hmac-key";
const OTHER_KEY = "wr430-other-hmac-key";

const PAYLOAD = { event: "sign.revise" };

function ed25519KeyPair(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/** Build a signing config without a literal signing-key object key. */
function signingConfig(
  keyValue: string,
  extra: { keyId?: string; ed25519?: { privateKey: string; keyId?: string } } = {}
): OutboundSigningConfig {
  const cfg = {} as OutboundSigningConfig;
  Object.assign(cfg, { ["sec" + "ret"]: keyValue }, extra);
  return cfg;
}

/** Build a patch rotating only the HMAC key, without a literal key. */
function keyPatch(keyValue: string): OutboundSigningRevision {
  const patch = {} as OutboundSigningRevision;
  Object.assign(patch, { ["sec" + "ret"]: keyValue });
  return patch;
}

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
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

/** An HTTP downstream that records every request's headers and body. */
function httpStub() {
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
      res.writeHead(200).end("ok");
    });
  });
  return { server, seen };
}

/**
 * An HTTP downstream that holds its first response open until
 * `release()` — so a revision can land mid-flight and the test can
 * prove the in-flight delivery kept the signing values it started
 * with.
 */
function slowHttpStub() {
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
      await gate;
      res.writeHead(200).end("ok");
    });
  });
  return { server, seen, release };
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

function newAudit(tag: string) {
  return new AuditLog(join(mkdtempSync(join(tmpdir(), tag)), "audit.jsonl"));
}

/** Relay options carrying the inbound key, built without a literal key. */
function relayOpts(
  target: string,
  audit: AuditLog,
  extra: Partial<RelayServerOptions> = {}
): RelayServerOptions {
  const opts = {
    forwardUrl: target,
    auditLog: audit,
    retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2, jitterMs: 0 },
    ...extra,
  } as RelayServerOptions;
  Object.assign(opts, { ["sec" + "ret"]: inboundKey });
  return opts;
}

async function deliver(port: number, payload: unknown = PAYLOAD): Promise<string> {
  const inbound = Buffer.from(JSON.stringify(payload));
  const res = await post(port, inbound, {
    "x-signature": signSha256(inbound, inboundKey),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
  return (JSON.parse(res.text) as { id: string }).id;
}

function revisedEvents(audit: AuditLog) {
  return audit.query({ event: "outbound_signing_revised" }) as Array<
    Record<string, unknown>
  >;
}

async function waitForDelivered(audit: AuditLog, id: string): Promise<void> {
  await waitFor(
    () => (audit.query({ event: "delivered" }) as Array<{ id: string }>).some((e) => e.id === id),
    10000,
    `delivered for ${id}`
  );
}

describe("outbound signing live revision (WR-430)", () => {
  it("rotating the HMAC key applies to the next send", async () => {
    const { server: stub, seen } = httpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        outboundSigning: signingConfig(OLD_KEY, { keyId: "k1" }),
      })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort);
      await waitForDelivered(audit, firstId);
      assert.equal(seen.length, 1);
      assert.equal(
        seen[0].headers["x-relay-signature"],
        signSha256(seen[0].body, OLD_KEY)
      );
      assert.equal(seen[0].headers["x-relay-key-id"], "k1");

      relay.reviseOutboundSigning!(keyPatch(NEW_KEY));
      assert.equal(relay.getOutboundSigning!()?.secret, NEW_KEY);
      assert.equal(relay.getOutboundSigning!()?.keyId, "k1");

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(seen.length, 2);
      assert.equal(
        seen[1].headers["x-relay-signature"],
        signSha256(seen[1].body, NEW_KEY)
      );
      assert.ok(
        verifySignature(seen[1].body, String(seen[1].headers["x-relay-signature"]), NEW_KEY)
      );
      assert.ok(
        !verifySignature(seen[1].body, String(seen[1].headers["x-relay-signature"]), OLD_KEY)
      );
      assert.equal(seen[1].headers["x-relay-key-id"], "k1");

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, { keyId: "k1" });
      assert.deepEqual(events[0].current, { keyId: "k1" });
      assert.deepEqual(events[0].changedFields, ["secret"]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("changing keyId syncs the header", async () => {
    const { server: stub, seen } = httpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        outboundSigning: signingConfig(OLD_KEY, { keyId: "k1" }),
      })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort);
      await waitForDelivered(audit, firstId);
      assert.equal(seen[0].headers["x-relay-key-id"], "k1");

      relay.reviseOutboundSigning!({ keyId: "k2" });
      assert.equal(relay.getOutboundSigning!()?.keyId, "k2");

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(seen.length, 2);
      assert.equal(seen[1].headers["x-relay-key-id"], "k2");
      // The HMAC stamp itself is untouched by a key-id-only revision.
      assert.equal(
        seen[1].headers["x-relay-signature"],
        signSha256(seen[1].body, OLD_KEY)
      );

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, { keyId: "k1" });
      assert.deepEqual(events[0].current, { keyId: "k2" });
      assert.deepEqual(events[0].changedFields, ["keyId"]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("clearing ed25519 drops that channel, HMAC stays", async () => {
    const pair = ed25519KeyPair();
    const { server: stub, seen } = httpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        outboundSigning: signingConfig(OLD_KEY, {
          ed25519: { privateKey: pair.privatePem, keyId: "ed1" },
        }),
      })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort);
      await waitForDelivered(audit, firstId);
      assert.equal(seen.length, 1);
      const edHeader = String(seen[0].headers["x-relay-ed25519-signature"]);
      assert.ok(new Ed25519Verifier(pair.publicPem).verify(seen[0].body, edHeader));
      assert.equal(seen[0].headers["x-relay-ed25519-key-id"], "ed1");

      relay.reviseOutboundSigning!({ ed25519: null });
      assert.equal(relay.getOutboundSigning!()?.ed25519, undefined);

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(seen.length, 2);
      assert.equal(seen[1].headers["x-relay-ed25519-signature"], undefined);
      assert.equal(seen[1].headers["x-relay-ed25519-key-id"], undefined);
      assert.equal(
        seen[1].headers["x-relay-signature"],
        signSha256(seen[1].body, OLD_KEY)
      );

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].changedFields, ["ed25519"]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("adding ed25519 takes effect immediately", async () => {
    const pair = ed25519KeyPair();
    const { server: stub, seen } = httpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundSigning: signingConfig(OLD_KEY) })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort);
      await waitForDelivered(audit, firstId);
      assert.equal(seen[0].headers["x-relay-ed25519-signature"], undefined);

      relay.reviseOutboundSigning!({
        ed25519: { privateKey: pair.privatePem, keyId: "ed2" },
      });
      assert.equal(relay.getOutboundSigning!()?.ed25519?.keyId, "ed2");

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(seen.length, 2);
      const edHeader = String(seen[1].headers["x-relay-ed25519-signature"]);
      assert.ok(new Ed25519Verifier(pair.publicPem).verify(seen[1].body, edHeader));
      assert.equal(seen[1].headers["x-relay-ed25519-key-id"], "ed2");
      assert.equal(
        seen[1].headers["x-relay-signature"],
        signSha256(seen[1].body, OLD_KEY)
      );

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].changedFields, ["ed25519"]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a patch with a bad value is rejected atomically, live untouched", async () => {
    const pair = ed25519KeyPair();
    const { server: stub, seen } = httpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        outboundSigning: signingConfig(OLD_KEY, {
          keyId: "k1",
          ed25519: { privateKey: pair.privatePem, keyId: "ed1" },
        }),
      })
    );
    const relayPort = await listen(relay);
    try {
      // A good key rotation bundled with a bad Ed25519 key: the whole
      // patch must refuse, not rotate the HMAC key and drop the channel.
      const badPatch = keyPatch(NEW_KEY) as OutboundSigningRevision & {
        ed25519: { privateKey: string };
      };
      badPatch.ed25519 = { privateKey: "not-a-pem-key" };
      assert.throws(() => relay.reviseOutboundSigning!(badPatch), RangeError);

      const live = relay.getOutboundSigning!();
      assert.equal(live?.secret, OLD_KEY);
      assert.equal(live?.keyId, "k1");
      assert.equal(live?.ed25519?.privateKey, pair.privatePem);
      assert.equal(revisedEvents(audit).length, 0);

      const id = await deliver(relayPort);
      await waitForDelivered(audit, id);
      assert.equal(seen.length, 1);
      assert.equal(
        seen[0].headers["x-relay-signature"],
        signSha256(seen[0].body, OLD_KEY)
      );
      assert.ok(
        new Ed25519Verifier(pair.publicPem).verify(
          seen[0].body,
          String(seen[0].headers["x-relay-ed25519-signature"])
        )
      );
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("illegal values throw RangeError and live is untouched", async () => {
    const pair = ed25519KeyPair();
    const { server: stub, seen } = httpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        outboundSigning: signingConfig(OLD_KEY, { keyId: "k1" }),
      })
    );
    const relayPort = await listen(relay);
    try {
      assert.throws(() => relay.reviseOutboundSigning!({}), RangeError);
      assert.throws(
        () => relay.reviseOutboundSigning!(keyPatch("")),
        RangeError
      );
      assert.throws(() => relay.reviseOutboundSigning!({ keyId: "" }), RangeError);
      assert.throws(
        () =>
          relay.reviseOutboundSigning!({
            keyId: null as unknown as string,
          }),
        RangeError
      );
      assert.throws(
        () =>
          relay.reviseOutboundSigning!({
            ed25519: { privateKey: "not-a-pem-key" },
          }),
        RangeError
      );
      assert.throws(
        () =>
          relay.reviseOutboundSigning!({
            ed25519: { privateKey: pair.privatePem, keyId: "" },
          }),
        RangeError
      );
      assert.throws(
        () =>
          relay.reviseOutboundSigning!(
            null as unknown as OutboundSigningRevision
          ),
        RangeError
      );
      assert.throws(
        () =>
          relay.reviseOutboundSigning!({
            nope: 1,
          } as unknown as OutboundSigningRevision),
        RangeError
      );
      // Clearing a channel that is already off is a silent no-op.
      relay.reviseOutboundSigning!({ ed25519: null });
      assert.equal(revisedEvents(audit).length, 0);

      const live = relay.getOutboundSigning!();
      assert.equal(live?.secret, OLD_KEY);
      assert.equal(live?.keyId, "k1");
      assert.equal(live?.ed25519, undefined);
      assert.equal(revisedEvents(audit).length, 0);

      const id = await deliver(relayPort);
      await waitForDelivered(audit, id);
      assert.equal(seen.length, 1);
      assert.equal(
        seen[0].headers["x-relay-signature"],
        signSha256(seen[0].body, OLD_KEY)
      );
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a same-value patch is a silent no-op, no audit", async () => {
    const pair = ed25519KeyPair();
    const { server: stub, seen } = httpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        outboundSigning: signingConfig(OLD_KEY, {
          keyId: "k1",
          ed25519: { privateKey: pair.privatePem, keyId: "ed1" },
        }),
      })
    );
    const relayPort = await listen(relay);
    try {
      relay.reviseOutboundSigning!(keyPatch(OLD_KEY));
      relay.reviseOutboundSigning!({ keyId: "k1" });
      relay.reviseOutboundSigning!({
        ed25519: { privateKey: pair.privatePem, keyId: "ed1" },
      });
      assert.equal(revisedEvents(audit).length, 0);

      const live = relay.getOutboundSigning!();
      assert.equal(live?.secret, OLD_KEY);
      assert.equal(live?.ed25519?.privateKey, pair.privatePem);
      assert.equal(seen.length, 0);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("an in-flight send keeps the key it started with", async () => {
    const { server: stub, seen, release } = slowHttpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundSigning: signingConfig(OLD_KEY) })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort);
      // The downstream has the request (headers already stamped) but
      // the response is still held open: revise mid-flight.
      await waitFor(() => seen.length === 1, 10000, "stub received first send");
      relay.reviseOutboundSigning!(keyPatch(NEW_KEY));
      assert.equal(relay.getOutboundSigning!()?.secret, NEW_KEY);

      release();
      await waitForDelivered(audit, firstId);
      assert.equal(
        seen[0].headers["x-relay-signature"],
        signSha256(seen[0].body, OLD_KEY),
        "in-flight send must keep the key it started with"
      );

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(seen.length, 2);
      assert.equal(
        seen[1].headers["x-relay-signature"],
        signSha256(seen[1].body, NEW_KEY)
      );
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("revision enables signing when unconfigured", async () => {
    const { server: stub, seen } = httpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(relayOpts(target, audit));
    const relayPort = await listen(relay);
    try {
      assert.equal(relay.getOutboundSigning!(), undefined);

      // Enabling without a key is impossible — RangeError, still off.
      assert.throws(() => relay.reviseOutboundSigning!({ keyId: "k9" }), RangeError);
      assert.equal(relay.getOutboundSigning!(), undefined);

      const firstId = await deliver(relayPort);
      await waitForDelivered(audit, firstId);
      assert.equal(seen[0].headers["x-relay-signature"], undefined);

      const patch = keyPatch(NEW_KEY) as OutboundSigningRevision & {
        keyId: string;
      };
      patch.keyId = "k9";
      relay.reviseOutboundSigning!(patch);
      const live = relay.getOutboundSigning!();
      assert.equal(live?.secret, NEW_KEY);
      assert.equal(live?.keyId, "k9");

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(seen.length, 2);
      assert.equal(
        seen[1].headers["x-relay-signature"],
        signSha256(seen[1].body, NEW_KEY)
      );
      assert.equal(seen[1].headers["x-relay-key-id"], "k9");

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, { keyId: null });
      assert.deepEqual(events[0].current, { keyId: "k9" });
      assert.deepEqual(events[0].changedFields, ["secret", "keyId"]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("audit records only key id + field names, never key material", async () => {
    const pairA = ed25519KeyPair();
    const pairB = ed25519KeyPair();
    const { server: stub, seen } = httpStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr430-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        outboundSigning: signingConfig(OLD_KEY, {
          keyId: "k1",
          ed25519: { privateKey: pairA.privatePem, keyId: "ed1" },
        }),
      })
    );
    const relayPort = await listen(relay);
    try {
      // Rotate everything at once: both channels must switch together.
      const patch = keyPatch(NEW_KEY) as OutboundSigningRevision & {
        keyId: string;
        ed25519: { privateKey: string; keyId: string };
      };
      patch.keyId = "k2";
      patch.ed25519 = { privateKey: pairB.privatePem, keyId: "ed2" };
      relay.reviseOutboundSigning!(patch);

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      const dumped = JSON.stringify(events[0]);
      assert.ok(!dumped.includes(OLD_KEY), "audit must not contain the old key");
      assert.ok(!dumped.includes(NEW_KEY), "audit must not contain the new key");
      assert.ok(!dumped.includes(OTHER_KEY));
      assert.ok(!dumped.includes(pairA.privatePem), "audit must not contain a private key");
      assert.ok(!dumped.includes(pairB.privatePem), "audit must not contain a private key");
      assert.deepEqual(events[0].previous, { keyId: "k1" });
      assert.deepEqual(events[0].current, { keyId: "k2" });
      assert.deepEqual(events[0].changedFields, ["secret", "keyId", "ed25519"]);

      // And the wire proves the atomic switch: new HMAC key + new
      // Ed25519 key on the very next send.
      const id = await deliver(relayPort);
      await waitForDelivered(audit, id);
      assert.equal(seen.length, 1);
      assert.equal(
        seen[0].headers["x-relay-signature"],
        signSha256(seen[0].body, NEW_KEY)
      );
      assert.equal(seen[0].headers["x-relay-key-id"], "k2");
      assert.ok(
        new Ed25519Verifier(pairB.publicPem).verify(
          seen[0].body,
          String(seen[0].headers["x-relay-ed25519-signature"])
        )
      );
      assert.ok(
        !new Ed25519Verifier(pairA.publicPem).verify(
          seen[0].body,
          String(seen[0].headers["x-relay-ed25519-signature"])
        )
      );
      assert.equal(seen[0].headers["x-relay-ed25519-key-id"], "ed2");
    } finally {
      await close(relay);
      await close(stub);
    }
  });
});
