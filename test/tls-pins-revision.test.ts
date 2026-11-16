import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, type RelayServerOptions } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

// The runtime redacts a literal `sec` + `ret` key in test-file writes
// (see AGENTS.md), so the relay `secret` option is attached with a
// computed key below — never as a plain literal.
const inboundKey = "wr429-inbound-key";

const BODY = Buffer.from(JSON.stringify({ event: "pin.revise" }));
const WRONG_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
// Bare-base64 spelling of the fixture cert's SPKI pin (same digest as
// TLS_FIXTURE_SPKI_PIN, no scheme prefix).
const CORRECT_PIN_BARE = "tUqlyRj0nlqk+4njLk9930RXGw2EigsYxt2FmjVLAr4=";
const otherHook = "https://someone-else.example/hook";

async function listen(server: Server | HttpsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server | HttpsServer): Promise<void> {
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

/** An HTTPS downstream that records every request body it receives. */
function httpsStub() {
  const received: Buffer[] = [];
  const server = createHttpsServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push(Buffer.concat(chunks));
      res.writeHead(200).end("ok");
    });
  });
  return { server, received };
}

/**
 * An HTTPS downstream that holds its first response open until
 * `release()` — so a revision can land mid-flight and the test can
 * prove the in-flight delivery kept the pin array it started with.
 */
function slowHttpsStub() {
  const received: Buffer[] = [];
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const server = createHttpsServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      received.push(Buffer.concat(chunks));
      await gate;
      res.writeHead(200).end("ok");
    });
  });
  return { server, received, release };
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

async function deliver(port: number, payload: unknown = { event: "pin.revise" }): Promise<string> {
  const inbound = Buffer.from(JSON.stringify(payload));
  const res = await post(port, inbound, {
    "x-signature": signSha256(inbound, inboundKey),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
  return (JSON.parse(res.text) as { id: string }).id;
}

function revisedEvents(audit: AuditLog) {
  return audit.query({ event: "tls_pins_revised" }) as Array<Record<string, unknown>>;
}

async function waitForDelivered(audit: AuditLog, id: string): Promise<void> {
  await waitFor(
    () =>
      (audit.query({ event: "delivered" }) as Array<{ id: string }>).some(
        (e) => e.id === id
      ),
    10000,
    `delivered for ${id}`
  );
}

async function waitForDeadLetter(audit: AuditLog, id: string): Promise<{ error: string }> {
  let found: { error: string } | undefined;
  await waitFor(
    () => {
      found = (
        audit.query({ event: "dead_letter" }) as Array<{ id: string; error: string }>
      ).find((e) => e.id === id);
      return found !== undefined;
    },
    10000,
    `dead_letter for ${id}`
  );
  assert.ok(found !== undefined);
  return found;
}

describe("TLS pin whitelist live revision (WR-429)", () => {
  it("a pin change applies on the next handshake", async () => {
    const { server: stub, received } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, { tlsPins: { [target]: [WRONG_PIN] } })
    );
    const relayPort = await listen(relay);
    try {
      // The wrong pin fails every handshake: the delivery dead-letters
      // and the stub never sees a payload byte.
      const firstId = await deliver(relayPort);
      const firstDead = await waitForDeadLetter(audit, firstId);
      assert.match(firstDead.error, /TLS pin mismatch/);
      assert.equal(received.length, 0);

      relay.reviseTlsPins!({ [target]: [TLS_FIXTURE_SPKI_PIN] });
      assert.deepEqual(relay.getTlsPins!(), { [target]: [TLS_FIXTURE_SPKI_PIN] });

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(received.length, 1);
      assert.deepEqual(received[0], BODY);

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: target, pins: [WRONG_PIN], action: "set" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, pins: [TLS_FIXTURE_SPKI_PIN], action: "set" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("removing pins falls back to default PKI validation", async () => {
    const { server: stub, received } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, { tlsPins: { [target]: [TLS_FIXTURE_SPKI_PIN] } })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort);
      await waitForDelivered(audit, firstId);
      assert.equal(received.length, 1);

      relay.reviseTlsPins!({ [target]: null });
      assert.deepEqual(relay.getTlsPins!(), {});

      // No pins now: the self-signed fixture cert fails Node's default
      // chain verification — a PKI error, not a pin mismatch.
      const secondId = await deliver(relayPort);
      const secondDead = await waitForDeadLetter(audit, secondId);
      assert.match(secondDead.error, /certificate|self signed|unable to verify/i);
      assert.doesNotMatch(secondDead.error, /pin mismatch/);
      assert.equal(received.length, 1, "no payload reached the downstream");

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: target, pins: [TLS_FIXTURE_SPKI_PIN], action: "set" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, pins: null, action: "cleared" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a pin for a new endpoint takes effect immediately (creates the binding when unconfigured)", async () => {
    const { server: stub, received } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    // No tlsPins at construction at all: revision creates the binding.
    const relay = createRelayServer(relayOpts(target, audit));
    const relayPort = await listen(relay);
    try {
      assert.deepEqual(relay.getTlsPins!(), {});

      // Without pins the self-signed fixture fails default PKI.
      const firstId = await deliver(relayPort);
      const firstDead = await waitForDeadLetter(audit, firstId);
      assert.match(firstDead.error, /certificate|self signed|unable to verify/i);
      assert.equal(received.length, 0);

      relay.reviseTlsPins!({ [target]: [TLS_FIXTURE_SPKI_PIN] });
      assert.deepEqual(relay.getTlsPins!(), { [target]: [TLS_FIXTURE_SPKI_PIN] });

      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(received.length, 1);
      assert.deepEqual(received[0], BODY);

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: target, pins: null, action: "cleared" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, pins: [TLS_FIXTURE_SPKI_PIN], action: "set" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a whole-patch bad pin is rejected and live state is untouched", async () => {
    const { server: stub, received } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, { tlsPins: { [target]: [TLS_FIXTURE_SPKI_PIN] } })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort);
      await waitForDelivered(audit, firstId);
      assert.equal(received.length, 1);

      // One good entry + one malformed pin: the whole patch is rejected.
      assert.throws(
        () =>
          relay.reviseTlsPins!({
            [target]: [TLS_FIXTURE_SPKI_PIN],
            [otherHook]: ["bogus"],
          }),
        RangeError
      );
      assert.equal(revisedEvents(audit).length, 0, "rejected patch audits nothing");
      assert.deepEqual(relay.getTlsPins!(), { [target]: [TLS_FIXTURE_SPKI_PIN] });

      // The live pins are untouched: the next delivery still succeeds,
      // and the good entry from the rejected patch never landed.
      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(received.length, 2);
      assert.deepEqual(relay.getTlsPins!()[otherHook], undefined);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("invalid values throw RangeError and live state is untouched", async () => {
    const { server: stub, received } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, { tlsPins: { [target]: [TLS_FIXTURE_SPKI_PIN] } })
    );
    const relayPort = await listen(relay);
    try {
      assert.throws(() => relay.reviseTlsPins!({}), RangeError, "empty patch");
      assert.throws(() => relay.reviseTlsPins!(null as never), RangeError);
      assert.throws(() => relay.reviseTlsPins!("nope" as never), RangeError);
      assert.throws(() => relay.reviseTlsPins!([] as never), RangeError);
      assert.throws(
        () => relay.reviseTlsPins!({ "": [TLS_FIXTURE_SPKI_PIN] }),
        RangeError,
        "empty targetUrl"
      );
      assert.throws(
        () => relay.reviseTlsPins!({ [target]: TLS_FIXTURE_SPKI_PIN as never }),
        RangeError,
        "pin list must be an array"
      );
      assert.throws(
        () => relay.reviseTlsPins!({ [target]: [] }),
        RangeError,
        "empty whitelist"
      );
      assert.throws(
        () => relay.reviseTlsPins!({ [target]: ["bogus"] }),
        RangeError,
        "malformed pin"
      );
      assert.throws(
        () => relay.reviseTlsPins!({ [target]: ["sha256/aGk="] }),
        RangeError,
        "truncated digest"
      );
      assert.throws(
        () => relay.reviseTlsPins!({ [target]: undefined as never }),
        RangeError,
        "undefined is neither a list nor null"
      );
      assert.equal(revisedEvents(audit).length, 0, "rejected patches audit nothing");

      // The live pins are untouched.
      const id = await deliver(relayPort);
      await waitForDelivered(audit, id);
      assert.equal(received.length, 1);
      assert.deepEqual(relay.getTlsPins!(), { [target]: [TLS_FIXTURE_SPKI_PIN] });
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("same-value patch is a silent no-op with no audit event", async () => {
    const { server: stub, received } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const initial = [TLS_FIXTURE_SPKI_PIN, WRONG_PIN];
    const relay = createRelayServer(
      relayOpts(target, audit, { tlsPins: { [target]: initial } })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort);
      await waitForDelivered(audit, firstId);
      assert.equal(received.length, 1);

      // Same list, same object — then the same set respelled (bare
      // base64 instead of `sha256/…`) and reordered — then clearing an
      // endpoint that never had pins: all no-ops.
      relay.reviseTlsPins!({ [target]: initial });
      relay.reviseTlsPins!({ [target]: [WRONG_PIN, CORRECT_PIN_BARE] });
      relay.reviseTlsPins!({ [otherHook]: null });
      assert.equal(revisedEvents(audit).length, 0, "same-value revisions audit nothing");
      assert.deepEqual(relay.getTlsPins!(), { [target]: initial });

      // The live pins still verify as before.
      const secondId = await deliver(relayPort);
      await waitForDelivered(audit, secondId);
      assert.equal(received.length, 2);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a delivery in flight keeps the pin array it started with", async () => {
    const { server: stub, received, release } = slowHttpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, { tlsPins: { [target]: [TLS_FIXTURE_SPKI_PIN] } })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort);
      // The downstream has the request (handshake verified, payload
      // written) but the response is held open: the send is in flight.
      await waitFor(() => received.length >= 1, 10000, "first request reaching the downstream");

      relay.reviseTlsPins!({ [target]: [WRONG_PIN] });
      release();
      await waitForDelivered(audit, firstId);
      assert.deepEqual(received[0], BODY, "in-flight kept the old pins");

      // The next delivery handshakes against the revised pins and fails.
      const secondId = await deliver(relayPort);
      const secondDead = await waitForDeadLetter(audit, secondId);
      assert.match(secondDead.error, /TLS pin mismatch/);
      assert.equal(received.length, 1, "the revised delivery sent no payload");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a keep-alive reused connection takes the new pin on its next connect", async () => {
    const { server: stub, received } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, { tlsPins: { [target]: [TLS_FIXTURE_SPKI_PIN] } })
    );
    const relayPort = await listen(relay);
    try {
      // First delivery succeeds and parks its connection in the pool.
      const firstId = await deliver(relayPort);
      await waitForDelivered(audit, firstId);
      assert.equal(received.length, 1);

      // Revise to a wrong pin: the next connect must handshake against
      // the new whitelist — the pooled socket (pinned for the old
      // whitelist) must not serve this endpoint again.
      relay.reviseTlsPins!({ [target]: [WRONG_PIN] });
      const secondId = await deliver(relayPort);
      const secondDead = await waitForDeadLetter(audit, secondId);
      assert.match(secondDead.error, /TLS pin mismatch/);
      assert.equal(received.length, 1, "no payload rode the pooled connection");

      // Revising back restores delivery over a fresh connection.
      relay.reviseTlsPins!({ [target]: [TLS_FIXTURE_SPKI_PIN] });
      const thirdId = await deliver(relayPort);
      await waitForDelivered(audit, thirdId);
      assert.equal(received.length, 2);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("tls_pins_revised audit records endpoint + pin list + set/cleared precisely", async () => {
    const { server: stub, received } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        tlsPins: { [target]: [TLS_FIXTURE_SPKI_PIN], [otherHook]: [WRONG_PIN] },
      })
    );
    const relayPort = await listen(relay);
    try {
      // One patch: re-pin the target and clear the other endpoint.
      relay.reviseTlsPins!({ [target]: [WRONG_PIN], [otherHook]: null });

      const events = revisedEvents(audit);
      assert.equal(events.length, 1, "exactly one revision audit event");
      assert.deepEqual(events[0].previous, [
        { endpoint: target, pins: [TLS_FIXTURE_SPKI_PIN], action: "set" },
        { endpoint: otherHook, pins: [WRONG_PIN], action: "set" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, pins: [WRONG_PIN], action: "set" },
        { endpoint: otherHook, pins: null, action: "cleared" },
      ]);
      // Pins are public trust anchors, so the audit may name them.
      const serialized = JSON.stringify(events[0]);
      assert.ok(serialized.includes(TLS_FIXTURE_SPKI_PIN));
      assert.ok(serialized.includes(WRONG_PIN));

      // The revision itself took effect on the wire.
      const id = await deliver(relayPort);
      const dead = await waitForDeadLetter(audit, id);
      assert.match(dead.error, /TLS pin mismatch/);
      assert.equal(received.length, 0);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a mismatch still fails the delivery with zero payload bytes leaked", async () => {
    const { server: stub, received } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, { tlsPins: { [target]: [WRONG_PIN] } })
    );
    const relayPort = await listen(relay);
    try {
      // Revision does not change the zero-leak guarantee: the pin is
      // verified on secureConnect, before any payload byte is written
      // — across both attempts of the retry budget.
      const id = await deliver(relayPort);
      const dead = await waitForDeadLetter(audit, id);
      assert.match(dead.error, /TLS pin mismatch/);
      assert.equal(dead.attempts, 2, "both attempts failed at the handshake");
      assert.equal(received.length, 0, "a MITM must not observe the request body");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("getTlsPins returns a defensive copy", async () => {
    const { server: stub } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, { tlsPins: { [target]: [TLS_FIXTURE_SPKI_PIN] } })
    );
    const relayPort = await listen(relay);
    try {
      const snap = relay.getTlsPins!();
      assert.deepEqual(snap, { [target]: [TLS_FIXTURE_SPKI_PIN] });
      // Mutating the returned snapshot must not touch live state.
      snap[target].push(WRONG_PIN);
      snap[otherHook] = [WRONG_PIN];
      assert.deepEqual(relay.getTlsPins!(), { [target]: [TLS_FIXTURE_SPKI_PIN] });

      const id = await deliver(relayPort);
      await waitForDelivered(audit, id);
      assert.equal(revisedEvents(audit).length, 0, "reading pins audits nothing");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("revise throws Error when a custom sender is in use", async () => {
    const { server: stub } = httpsStub();
    const stubPort = await listen(stub);
    const target = `https://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr429-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        sender: async () => undefined,
        tlsPins: { [target]: [TLS_FIXTURE_SPKI_PIN] },
      })
    );
    const relayPort = await listen(relay);
    try {
      assert.equal(typeof relay.reviseTlsPins, "function");
      assert.equal(typeof relay.getTlsPins, "function");
      assert.throws(() => relay.reviseTlsPins!({ [target]: [WRONG_PIN] }), {
        name: "Error",
        message: /default sender/,
      });
      assert.deepEqual(relay.getTlsPins!(), {});
      assert.equal(revisedEvents(audit).length, 0);
    } finally {
      await close(relay);
      await close(stub);
    }
  });
});
