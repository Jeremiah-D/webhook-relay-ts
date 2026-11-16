import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, type RelayServerOptions } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { OutboundCredentialConfig, OutboundCredentialsRevision } from "../src/outbound-credentials.ts";

// The runtime redacts a literal `sec` + `ret` key in test-file writes
// (see AGENTS.md), so the relay `secret` option is attached with a
// computed key below — never as a plain literal.
const inboundKey = "wr428-inbound-key";

const otherHook = "https://someone-else.example/hook";

const REF_OLD = "WR428_REF_OLD";
const REF_NEW = "WR428_REF_NEW";
const REF_OTHER = "WR428_REF_OTHER";
const OLD_VALUE = "old-value-428";
const NEW_VALUE = "new-value-428";
const OTHER_VALUE = "other-value-428";

const resolveOld = () => OLD_VALUE;
const resolveNew = () => NEW_VALUE;
const resolveOther = () => OTHER_VALUE;

function cred(
  id: string,
  header: string,
  secretRef: string,
  secretResolver: () => string
): OutboundCredentialConfig {
  return { id, header, secretRef, secretResolver };
}

const oldCred = () => cred("k-old", "x-api-key", REF_OLD, resolveOld);
const newCred = () => cred("k-new", "x-partner-key", REF_NEW, resolveNew);
const otherCred = () => cred("k-other", "x-other-key", REF_OTHER, resolveOther);

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

/** A stub downstream that records every request's headers. */
function recordingStub() {
  const hits: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      hits.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
      res.writeHead(200).end("ok");
    });
  });
  return { server, hits };
}

/**
 * A stub downstream that holds its first response open until
 * `release()` — so a revision can land mid-flight and the test can
 * prove the in-flight request kept the binding it started with.
 */
function slowStub() {
  const hits: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      hits.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
      await gate;
      res.writeHead(200).end("ok");
    });
  });
  return { server, hits, release };
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
    retry: { baseDelayMs: 50, maxDelayMs: 500, maxAttempts: 2, jitterMs: 0 },
    ...extra,
  } as RelayServerOptions;
  Object.assign(opts, { ["sec" + "ret"]: inboundKey });
  return opts;
}

async function deliver(port: number, payload: unknown): Promise<string> {
  const inbound = Buffer.from(JSON.stringify(payload));
  const res = await post(port, inbound, {
    "x-signature": signSha256(inbound, inboundKey),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
  return (JSON.parse(res.text) as { id: string }).id;
}

function revisedEvents(audit: AuditLog) {
  return audit.query({ event: "outbound_credentials_revised" }) as Array<
    Record<string, unknown>
  >;
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

function acceptedFor(audit: AuditLog, id: string) {
  const events = audit.query({ event: "accepted" }) as Array<{
    id: string;
    credentialIds?: string[];
  }>;
  return events.find((e) => e.id === id);
}

describe("outbound credential binding live revision (WR-428)", () => {
  it("rebinding an endpoint swaps the header and secretRef used by the next send", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr428-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundCredentials: { [target]: [oldCred()] } })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, firstId);
      assert.equal(hits.length, 1);
      assert.equal(hits[0].headers["x-api-key"], OLD_VALUE);
      assert.equal(hits[0].headers["x-partner-key"], undefined);

      relay.reviseOutboundCredentials!({ [target]: [newCred()] });

      const secondId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, secondId);
      assert.equal(hits.length, 2);
      assert.equal(hits[1].headers["x-partner-key"], NEW_VALUE);
      assert.equal(hits[1].headers["x-api-key"], undefined, "old header is gone");

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: target, credentialIds: ["k-old"], action: "set" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, credentialIds: ["k-new"], action: "set" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("clearing an endpoint (null) removes its credentials from the next send", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr428-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundCredentials: { [target]: [oldCred()] } })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, firstId);
      assert.equal(hits[0].headers["x-api-key"], OLD_VALUE);
      assert.deepEqual(acceptedFor(audit, firstId)?.credentialIds, ["k-old"]);

      relay.reviseOutboundCredentials!({ [target]: null });

      const secondId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, secondId);
      assert.equal(hits.length, 2);
      assert.equal(hits[1].headers["x-api-key"], undefined, "no credential is stamped");
      assert.equal(
        acceptedFor(audit, secondId)?.credentialIds,
        undefined,
        "the accepted event stops naming the cleared binding"
      );

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: target, credentialIds: ["k-old"], action: "set" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, credentialIds: null, action: "cleared" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("adding a binding for a new endpoint takes effect immediately", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr428-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundCredentials: { [otherHook]: [otherCred()] } })
    );
    const relayPort = await listen(relay);
    try {
      // No binding for the forwardUrl yet: nothing is stamped.
      const firstId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, firstId);
      assert.equal(hits[0].headers["x-partner-key"], undefined);
      assert.equal(acceptedFor(audit, firstId)?.credentialIds, undefined);

      relay.reviseOutboundCredentials!({ [target]: [newCred()] });

      const secondId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, secondId);
      assert.equal(hits.length, 2);
      assert.equal(hits[1].headers["x-partner-key"], NEW_VALUE);
      assert.deepEqual(acceptedFor(audit, secondId)?.credentialIds, ["k-new"]);

      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: target, credentialIds: null, action: "cleared" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, credentialIds: ["k-new"], action: "set" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a bad record rejects the whole patch and the live bindings are unchanged", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr428-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundCredentials: { [target]: [oldCred()] } })
    );
    const relayPort = await listen(relay);
    try {
      // One good entry + one bad entry (duplicate id): the whole
      // patch is rejected.
      const duplicateId = cred("k-old", "x-other-key", REF_OTHER, resolveOther);
      assert.throws(
        () =>
          relay.reviseOutboundCredentials!({
            [otherHook]: [otherCred()],
            [target]: [oldCred(), duplicateId],
          } as OutboundCredentialsRevision),
        RangeError
      );
      assert.equal(revisedEvents(audit).length, 0, "rejected patch audits nothing");

      // The live bindings are untouched: the old credential still stamps.
      const firstId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, firstId);
      assert.equal(hits[0].headers["x-api-key"], OLD_VALUE);

      // The good entry from the rejected patch never landed: binding
      // it now reports no previous binding.
      relay.reviseOutboundCredentials!({ [otherHook]: [otherCred()] });
      const events = revisedEvents(audit);
      assert.equal(events.length, 1);
      assert.deepEqual(events[0].previous, [
        { endpoint: otherHook, credentialIds: null, action: "cleared" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: otherHook, credentialIds: ["k-other"], action: "set" },
      ]);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("revise throws Error when outbound credentials were never configured", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr428-");
    const relay = createRelayServer(relayOpts(target, audit));
    const relayPort = await listen(relay);
    try {
      assert.equal(typeof relay.reviseOutboundCredentials, "function");
      assert.throws(() => relay.reviseOutboundCredentials!({ [target]: [oldCred()] }), {
        name: "Error",
        message: /not configured/,
      });
      // The must-restart gate fires before patch validation.
      assert.throws(() => relay.reviseOutboundCredentials!({}), {
        name: "Error",
        message: /not configured/,
      });
      assert.equal(revisedEvents(audit).length, 0);

      // The relay itself still delivers (feature off, unstamped).
      const id = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, id);
      assert.equal(hits[0].headers["x-api-key"], undefined);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("illegal values throw RangeError and the live bindings are unchanged", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr428-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundCredentials: { [target]: [oldCred()] } })
    );
    const relayPort = await listen(relay);
    try {
      assert.throws(() => relay.reviseOutboundCredentials!({}), RangeError);
      assert.throws(() => relay.reviseOutboundCredentials!(null as never), RangeError);
      assert.throws(() => relay.reviseOutboundCredentials!("nope" as never), RangeError);
      assert.throws(() => relay.reviseOutboundCredentials!([] as never), RangeError);
      assert.throws(
        () => relay.reviseOutboundCredentials!({ "": [oldCred()] }),
        RangeError
      );
      assert.throws(
        () =>
          relay.reviseOutboundCredentials!({
            [target]: [cred("k-x", "  ", REF_NEW, resolveNew)],
          }),
        RangeError
      );
      assert.throws(
        () =>
          relay.reviseOutboundCredentials!({
            [target]: [oldCred(), cred("k-old", "x-other-key", REF_NEW, resolveNew)],
          }),
        RangeError,
        "duplicate id"
      );
      assert.throws(
        () =>
          relay.reviseOutboundCredentials!({
            [target]: [oldCred(), cred("k-x", "X-API-KEY", REF_NEW, resolveNew)],
          }),
        RangeError,
        "duplicate header (case-insensitive)"
      );
      assert.throws(
        () =>
          relay.reviseOutboundCredentials!({
            [target]: [cred("k-x", "x-api-key", REF_NEW, () => "")],
          }),
        RangeError,
        "unresolvable secretRef"
      );
      assert.throws(
        () => relay.reviseOutboundCredentials!({ [target]: undefined as never }),
        RangeError
      );
      assert.throws(
        () => relay.reviseOutboundCredentials!({ [target]: [] }),
        RangeError,
        "empty binding list"
      );
      assert.equal(revisedEvents(audit).length, 0, "rejected patches audit nothing");

      // The live bindings are untouched.
      const id = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, id);
      assert.equal(hits[0].headers["x-api-key"], OLD_VALUE);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("same-value revision is a silent no-op with no audit event", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr428-");
    const initial = [oldCred()];
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundCredentials: { [target]: initial } })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, firstId);
      assert.equal(hits[0].headers["x-api-key"], OLD_VALUE);

      // Same list, same object — then a fresh but equal list (same
      // resolver reference) — then clearing an endpoint that never had
      // a binding: all no-ops.
      relay.reviseOutboundCredentials!({ [target]: initial });
      relay.reviseOutboundCredentials!({ [target]: [oldCred()] });
      relay.reviseOutboundCredentials!({ [otherHook]: null });
      assert.equal(revisedEvents(audit).length, 0, "same-value revisions audit nothing");

      // The live binding still stamps as before.
      const secondId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, secondId);
      assert.equal(hits.length, 2);
      assert.equal(hits[1].headers["x-api-key"], OLD_VALUE);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a send in flight keeps the binding it started with", async () => {
    const { server: stub, hits, release } = slowStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr428-");
    const relay = createRelayServer(
      relayOpts(target, audit, { outboundCredentials: { [target]: [oldCred()] } })
    );
    const relayPort = await listen(relay);
    try {
      const firstId = await deliver(relayPort, { hello: "webhook" });
      // The downstream has the request (headers fixed) but the
      // response is held open: the send is in flight.
      await waitFor(() => hits.length >= 1, 10000, "first request reaching the downstream");

      relay.reviseOutboundCredentials!({ [target]: [newCred()] });
      release();
      await waitForDelivered(audit, firstId);

      assert.equal(hits[0].headers["x-api-key"], OLD_VALUE, "in-flight kept the old binding");
      assert.equal(hits[0].headers["x-partner-key"], undefined);

      // The next send uses the revised binding.
      const secondId = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, secondId);
      assert.equal(hits.length, 2);
      assert.equal(hits[1].headers["x-partner-key"], NEW_VALUE);
      assert.equal(hits[1].headers["x-api-key"], undefined);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("outbound_credentials_revised audit records endpoint + credential ids + set/cleared only, never secret material", async () => {
    const { server: stub, hits } = recordingStub();
    const stubPort = await listen(stub);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const audit = newAudit("wr428-");
    const relay = createRelayServer(
      relayOpts(target, audit, {
        outboundCredentials: { [target]: [oldCred()], [otherHook]: [otherCred()] },
      })
    );
    const relayPort = await listen(relay);
    try {
      // One patch: rebind the target and clear the other endpoint.
      relay.reviseOutboundCredentials!({ [target]: [newCred()], [otherHook]: null });

      const events = revisedEvents(audit);
      assert.equal(events.length, 1, "exactly one revision audit event");
      assert.deepEqual(events[0].previous, [
        { endpoint: target, credentialIds: ["k-old"], action: "set" },
        { endpoint: otherHook, credentialIds: ["k-other"], action: "set" },
      ]);
      assert.deepEqual(events[0].current, [
        { endpoint: target, credentialIds: ["k-new"], action: "set" },
        { endpoint: otherHook, credentialIds: null, action: "cleared" },
      ]);
      const serialized = JSON.stringify(events[0]);
      for (const forbidden of [
        OLD_VALUE,
        NEW_VALUE,
        OTHER_VALUE,
        REF_OLD,
        REF_NEW,
        REF_OTHER,
        "x-api-key",
        "x-partner-key",
        "x-other-key",
      ]) {
        assert.ok(!serialized.includes(forbidden), `audit must not contain ${forbidden}`);
      }

      // The revision itself took effect on the wire.
      const id = await deliver(relayPort, { hello: "webhook" });
      await waitForDelivered(audit, id);
      assert.equal(hits[0].headers["x-partner-key"], NEW_VALUE);
      assert.equal(hits[0].headers["x-api-key"], undefined);
    } finally {
      await close(relay);
      await close(stub);
    }
  });
});
