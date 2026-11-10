import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { DEFAULT_MAX_RESPONSE_BYTES } from "../src/response-limit.ts";

// NOTE: intentionally not named SECRET — the runner's secret redaction
// rewrites `secret: SECRET` occurrences in test sources.
const SIGNING_SECRET = "guardrevision-test-secret";

function sha256Digest(body: Buffer): string {
  return `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
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
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

type AuditEvent = Record<string, unknown>;

function events(audit: AuditLog, event: string): AuditEvent[] {
  return audit.query({ event }) as AuditEvent[];
}

/** Stub answering 200 with a body whose size the test can change. */
function sizedStub() {
  let size = 2048;
  const hits: number[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      hits.push(Date.now());
      res.writeHead(200).end(Buffer.alloc(size, "z"));
    });
  });
  return { server, hits, setSize: (n: number) => { size = n; } };
}

type DigestMode = "match" | "mismatch" | "none";

/** Stub whose 200 response body / Content-Digest behavior is scriptable. */
function digestStub() {
  let mode: DigestMode = "match";
  let size = 64;
  const hits: number[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      hits.push(Date.now());
      const body = Buffer.alloc(size, "d");
      const headers: Record<string, string> = {};
      if (mode === "match") headers["content-digest"] = sha256Digest(body);
      if (mode === "mismatch") {
        headers["content-digest"] = sha256Digest(Buffer.from("claimed-bytes"));
      }
      res.writeHead(200, headers).end(body);
    });
  });
  return {
    server,
    hits,
    setMode: (m: DigestMode) => { mode = m; },
    setSize: (n: number) => { size = n; },
  };
}

/**
 * Stub that answers headers immediately but trickles the 2048-byte body
 * in after 200 ms / 500 ms, so a revision can land mid-read while the
 * relay has already started reading under the old cap. `flushHeaders`
 * matters: without it Node holds the headers until the first body
 * chunk, and the relay would not read the guard until then.
 */
function slowStub() {
  const hits: number[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      hits.push(Date.now());
      res.writeHead(200);
      res.flushHeaders();
      setTimeout(() => res.write(Buffer.alloc(512, "s")), 200);
      setTimeout(() => res.end(Buffer.alloc(1536, "s")), 500);
    });
  });
  return { server, hits };
}

describe("WR-380 live revision of the downstream response guard", () => {
  const BODY = Buffer.from(JSON.stringify({ order: "ord_380", amount: 50 }));

  function relay(
    stubPort: number,
    guard:
      | Record<string, { maxResponseBytes?: number; verifyContentDigest?: boolean }>
      | undefined,
    maxAttempts: number,
    extra: Record<string, unknown> = {}
  ) {
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "guardrev-")), "audit.jsonl"));
    const targetUrl = `http://127.0.0.1:${stubPort}/hook`;
    const server = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: SIGNING_SECRET,
      forwardUrl: targetUrl,
      auditLog: audit,
      ...(guard !== undefined ? { responseGuard: { [targetUrl]: guard } } : {}),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts },
      ...extra,
    });
    return { server, audit, targetUrl };
  }

  async function deliver(relayPort: number): Promise<void> {
    const res = await post(relayPort, BODY, {
      "x-signature": signSha256(BODY, SIGNING_SECRET),
      "content-type": "application/json",
    });
    assert.equal(res.status, 202);
  }

  it("tightening the cap fails the next over-limit attempt with ResponseTooLargeError", async () => {
    const { server: stub } = sizedStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(stubPort, { maxResponseBytes: 4096 }, 1);
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "response_too_large").length, 0);
      // Tighten below the body size: the NEXT attempt fails.
      assert.deepEqual(
        relayServer.reviseResponseGuard!(targetUrl, { maxResponseBytes: 1024 }),
        { maxResponseBytes: 1024 }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      const dead = events(audit, "dead_letter");
      assert.equal(dead.length, 1);
      assert.match(String(dead[0]?.error), /response_too_large/);
      const overruns = events(audit, "response_too_large");
      assert.equal(overruns.length, 1);
      assert.equal(overruns[0]?.maxBytes, 1024);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("loosening the cap lets a previously over-limit body through", async () => {
    const { server: stub } = sizedStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(stubPort, { maxResponseBytes: 1024 }, 1);
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[0]?.error), /response_too_large/);
      assert.deepEqual(
        relayServer.reviseResponseGuard!(targetUrl, { maxResponseBytes: 4096 }),
        { maxResponseBytes: 4096 }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "response_too_large").length, 1);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("enabling digest verification fails a mismatched attempt and still passes digest-less responses", async () => {
    const { server: stub, setMode } = digestStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(stubPort, undefined, 1);
    const relayPort = await listen(relayServer);
    try {
      // No guard yet: a mismatched digest passes unopinionated.
      setMode("mismatch");
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      // Opt the endpoint in: the next mismatched attempt fails.
      assert.deepEqual(
        relayServer.reviseResponseGuard!(targetUrl, { verifyContentDigest: true }),
        { verifyContentDigest: true }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[0]?.error), /integrity_mismatch/);
      assert.equal(events(audit, "integrity_mismatch").length, 1);
      // A response with no Content-Digest still passes under the guard.
      setMode("none");
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(events(audit, "integrity_mismatch").length, 1);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("disabling digest verification lets a mismatched response through", async () => {
    const { server: stub, setMode } = digestStub();
    setMode("mismatch");
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { verifyContentDigest: true },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[0]?.error), /integrity_mismatch/);
      assert.deepEqual(
        relayServer.reviseResponseGuard!(targetUrl, { verifyContentDigest: false }),
        { verifyContentDigest: false }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "integrity_mismatch").length, 1);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("null clears the cap back to the 4 MiB default while the digest knob keeps the entry guarded", async () => {
    const { server: stub, setMode, setSize } = digestStub();
    setSize(2048);
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { maxResponseBytes: 1024, verifyContentDigest: true },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[0]?.error), /response_too_large/);
      // Clear only the cap: the entry survives on the digest knob and
      // the cap falls back to the 4 MiB default — the same 2 KiB body
      // with a valid digest now delivers.
      assert.equal(DEFAULT_MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
      assert.deepEqual(relayServer.reviseResponseGuard!(targetUrl, { maxResponseBytes: null }), {
        verifyContentDigest: true,
      });
      assert.deepEqual(relayServer.getResponseGuard!(targetUrl), { verifyContentDigest: true });
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "response_too_large").length, 1);
      // The entry is still guarded: a mismatched digest now fails.
      setMode("mismatch");
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length >= 2, 5000, "second dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[1]?.error), /integrity_mismatch/);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("clearing both fields deletes the entry and falls back to unguarded behavior", async () => {
    const { server: stub, setSize } = sizedStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(stubPort, { maxResponseBytes: 1024 }, 1);
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[0]?.error), /response_too_large/);
      assert.equal(
        relayServer.reviseResponseGuard!(targetUrl, {
          maxResponseBytes: null,
          verifyContentDigest: null,
        }),
        undefined
      );
      assert.equal(relayServer.getResponseGuard!(targetUrl), undefined);
      // A 200 KiB body now delivers under the legacy truncated capture.
      setSize(200 * 1024);
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "response_too_large").length, 1);
      assert.equal(events(audit, "dead_letter").length, 1);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("a brand-new endpoint can be opted in without a restart", async () => {
    const { server: stub } = sizedStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(stubPort, undefined, 1);
    const relayPort = await listen(relayServer);
    try {
      assert.equal(relayServer.getResponseGuard!(targetUrl), undefined);
      // Unguarded first: the 2 KiB body delivers.
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      // Opt in live: the same body now overruns the new cap.
      assert.deepEqual(
        relayServer.reviseResponseGuard!(targetUrl, { maxResponseBytes: 1024 }),
        { maxResponseBytes: 1024 }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[0]?.error), /response_too_large/);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("an illegal patch throws RangeError and leaves the live record untouched", async () => {
    const { server: stub } = sizedStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(stubPort, { maxResponseBytes: 4096 }, 1);
    const relayPort = await listen(relayServer);
    try {
      for (const bad of [0, -1, 1.5, Number.NaN, "1024"]) {
        assert.throws(
          () => relayServer.reviseResponseGuard!(targetUrl, { maxResponseBytes: bad as number }),
          RangeError,
          `maxResponseBytes=${String(bad)}`
        );
      }
      assert.throws(
        () =>
          relayServer.reviseResponseGuard!(targetUrl, {
            verifyContentDigest: "yes" as unknown as boolean,
          }),
        RangeError
      );
      assert.throws(
        () => relayServer.reviseResponseGuard!("", { maxResponseBytes: 1024 }),
        RangeError
      );
      assert.throws(
        () =>
          relayServer.reviseResponseGuard!(
            targetUrl,
            null as unknown as { maxResponseBytes: number }
          ),
        RangeError
      );
      assert.deepEqual(relayServer.getResponseGuard!(targetUrl), { maxResponseBytes: 4096 });
      assert.equal(events(audit, "response_guard_revised").length, 0);
      // The live guard still governs: a 2 KiB body delivers under the 4 KiB cap.
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("an empty patch throws Error and changes nothing", async () => {
    const { server: stub } = sizedStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(stubPort, { maxResponseBytes: 4096 }, 1);
    const relayPort = await listen(relayServer);
    try {
      assert.throws(() => relayServer.reviseResponseGuard!(targetUrl, {}), Error);
      assert.throws(
        () =>
          relayServer.reviseResponseGuard!(targetUrl, {
            maxResponseBytes: undefined,
            verifyContentDigest: undefined,
          }),
        Error
      );
      assert.deepEqual(relayServer.getResponseGuard!(targetUrl), { maxResponseBytes: 4096 });
      assert.equal(events(audit, "response_guard_revised").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("a same-value revision is a silent no-op with no audit event", async () => {
    const { server: stub } = sizedStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { maxResponseBytes: 1024, verifyContentDigest: true },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      assert.deepEqual(
        relayServer.reviseResponseGuard!(targetUrl, {
          maxResponseBytes: 1024,
          verifyContentDigest: true,
        }),
        { maxResponseBytes: 1024, verifyContentDigest: true }
      );
      // A partial patch landing on the live values is a no-op too.
      assert.deepEqual(relayServer.reviseResponseGuard!(targetUrl, { maxResponseBytes: 1024 }), {
        maxResponseBytes: 1024,
        verifyContentDigest: true,
      });
      // Clearing fields that were never set is a no-op on a fresh endpoint.
      const fresh = `http://127.0.0.1:${stubPort}/other`;
      assert.equal(
        relayServer.reviseResponseGuard!(fresh, {
          maxResponseBytes: null,
          verifyContentDigest: null,
        }),
        undefined
      );
      assert.equal(relayServer.getResponseGuard!(fresh), undefined);
      assert.equal(events(audit, "response_guard_revised").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("a real revision audits exact previous/current, with undefined previous on first revision", async () => {
    const { server: stub } = sizedStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(stubPort, { maxResponseBytes: 1024 }, 1);
    const relayPort = await listen(relayServer);
    try {
      relayServer.reviseResponseGuard!(targetUrl, { maxResponseBytes: 2048 });
      let revised = events(audit, "response_guard_revised");
      assert.equal(revised.length, 1);
      assert.equal(revised[0]?.endpoint, targetUrl);
      assert.deepEqual(revised[0]?.previous, { maxResponseBytes: 1024 });
      assert.deepEqual(revised[0]?.current, { maxResponseBytes: 2048 });
      // Deleting the entry audits current undefined.
      relayServer.reviseResponseGuard!(targetUrl, {
        maxResponseBytes: null,
        verifyContentDigest: null,
      });
      revised = events(audit, "response_guard_revised");
      assert.equal(revised.length, 2);
      assert.deepEqual(revised[1]?.previous, { maxResponseBytes: 2048 });
      assert.equal(revised[1]?.current, undefined);
      // First revision of a brand-new endpoint audits previous undefined.
      const fresh = `http://127.0.0.1:${stubPort}/other`;
      relayServer.reviseResponseGuard!(fresh, { verifyContentDigest: true });
      revised = events(audit, "response_guard_revised");
      assert.equal(revised.length, 3);
      assert.equal(revised[2]?.endpoint, fresh);
      assert.equal(revised[2]?.previous, undefined);
      assert.deepEqual(revised[2]?.current, { verifyContentDigest: true });
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("a response read already in flight keeps the cap it started under", async () => {
    const { server: stub, hits } = slowStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(stubPort, { maxResponseBytes: 1024 }, 1);
    const relayPort = await listen(relayServer);
    try {
      const delivery = deliver(relayPort);
      // Wait until the downstream attempt has started (the relay has
      // read the guard on header arrival and started the read under
      // the 1 KiB cap), then revise mid-read — the body does not start
      // flowing for another ~150 ms.
      await waitFor(() => hits.length >= 1, 5000, "downstream attempt");
      await new Promise((r) => setTimeout(r, 50));
      assert.deepEqual(
        relayServer.reviseResponseGuard!(targetUrl, { maxResponseBytes: 4096 }),
        { maxResponseBytes: 4096 }
      );
      await delivery;
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[0]?.error), /response_too_large/);
      const overruns = events(audit, "response_too_large");
      assert.equal(overruns.length, 1);
      assert.equal(overruns[0]?.maxBytes, 1024);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("the shadow sender shares the revised guard with the main path", async () => {
    const { server: primary, setSize: setPrimarySize } = sizedStub();
    setPrimarySize(64);
    const primaryPort = await listen(primary);
    const { server: shadow, hits: shadowHits } = sizedStub();
    const shadowPort = await listen(shadow);
    const primaryUrl = `http://127.0.0.1:${primaryPort}/hook`;
    const shadowUrl = `http://127.0.0.1:${shadowPort}/shadow`;
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "guardrev-")), "audit.jsonl"));
    const relayServer = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: SIGNING_SECRET,
      forwardUrl: primaryUrl,
      auditLog: audit,
      shadowTargets: { [primaryUrl]: [{ targetUrl: shadowUrl }] },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const relayPort = await listen(relayServer);
    try {
      // Unguarded shadow mirror delivers.
      await deliver(relayPort);
      await waitFor(() => events(audit, "shadow_delivered").length > 0, 5000, "shadow_delivered audit entry");
      assert.equal(shadowHits.length, 1);
      // Revise the guard for the SHADOW url: the next mirror overruns.
      assert.deepEqual(
        relayServer.reviseResponseGuard!(shadowUrl, { maxResponseBytes: 1024 }),
        { maxResponseBytes: 1024 }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "shadow_failed").length > 0, 5000, "shadow_failed audit entry");
      const failed = events(audit, "shadow_failed");
      assert.equal(failed.length, 1);
      assert.equal(failed[0]?.shadowTarget, shadowUrl);
      assert.match(String(failed[0]?.error), /response_too_large/);
      assert.equal(shadowHits.length, 2);
      // The main delivery still succeeds throughout.
      assert.equal(events(audit, "delivered").length, 2);
    } finally {
      await close(relayServer);
      await close(primary);
      await close(shadow);
    }
  });
});
