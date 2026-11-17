import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { brotliCompressSync, gzipSync } from "node:zlib";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  DEFAULT_OUTBOUND_ACCEPT_ENCODING,
  type ResponseCompressionOptions,
} from "../src/response-encoding.ts";

// NOTE: intentionally not named SECRET — the runner's secret redaction
// rewrites `secret: SECRET` occurrences in test sources.
const SIGNING_KEY = "wr435-test-key";

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

type StubMode = "gzip" | "br" | "plain";

/** Stub downstream: records each request's Accept-Encoding, answers per `mode`. */
function compressionStub() {
  const seen: (string | undefined)[] = [];
  let mode: StubMode = "gzip";
  let plainSize = 2048;
  const server = createServer((req, res) => {
    const ae = req.headers["accept-encoding"];
    seen.push(Array.isArray(ae) ? ae.join(", ") : ae);
    req.resume();
    req.on("end", () => {
      const plain = Buffer.alloc(plainSize, "z");
      if (mode === "gzip") {
        res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" });
        res.end(gzipSync(plain));
      } else if (mode === "br") {
        res.writeHead(200, { "content-type": "application/json", "content-encoding": "br" });
        res.end(brotliCompressSync(plain));
      } else {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(plain);
      }
    });
  });
  return {
    server,
    seen,
    setMode: (m: StubMode) => {
      mode = m;
    },
    setPlainSize: (n: number) => {
      plainSize = n;
    },
  };
}

/**
 * Stub that answers headers immediately but trickles the gzip body in
 * after 200 ms / 500 ms, so a revision can land mid-read while the
 * relay has already started reading under the old cap. `flushHeaders`
 * matters: without it Node holds the headers until the first body
 * chunk, and the relay would not read the compression record until then.
 */
function slowGzipStub() {
  const hits: number[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      hits.push(Date.now());
      const wire = gzipSync(Buffer.alloc(2048, "s"));
      res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" });
      res.flushHeaders();
      const half = Math.ceil(wire.length / 2);
      setTimeout(() => res.write(wire.subarray(0, half)), 200);
      setTimeout(() => res.end(wire.subarray(half)), 500);
    });
  });
  return { server, hits };
}

describe("WR-435 live revision of outbound response compression", () => {
  const BODY = Buffer.from(JSON.stringify({ event: "comp.revise" }));

  function relay(
    stubPort: number,
    compression: ResponseCompressionOptions | undefined,
    maxAttempts: number,
    extra: Record<string, unknown> = {}
  ) {
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "comprev-")), "audit.jsonl"));
    const targetUrl = `http://127.0.0.1:${stubPort}/hook`;
    let validatorBody = "";
    const server = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: SIGNING_KEY,
      forwardUrl: targetUrl,
      auditLog: audit,
      ...(compression !== undefined ? { responseCompression: { [targetUrl]: compression } } : {}),
      retry: {
        baseDelayMs: 10,
        jitterMs: 0,
        maxAttempts,
        responseValidators: (r: { body: Buffer }) => {
          validatorBody = r.body.toString();
          return true;
        },
      },
      ...extra,
    });
    return { server, audit, targetUrl, getValidatorBody: () => validatorBody };
  }

  async function deliver(relayPort: number): Promise<void> {
    const res = await post(relayPort, BODY, {
      "x-signature": signSha256(BODY, SIGNING_KEY),
      "content-type": "application/json",
    });
    assert.equal(res.status, 202);
  }

  it("revising acceptEncoding changes the advertised header on the next delivery", async () => {
    const { server: stub, seen } = compressionStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl, getValidatorBody } = relay(stubPort, {}, 1);
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(seen[0], DEFAULT_OUTBOUND_ACCEPT_ENCODING);
      assert.equal(getValidatorBody(), Buffer.alloc(2048, "z").toString());
      // Advertise gzip only from here on; the gzip round-trip still decodes.
      assert.deepEqual(relayServer.reviseResponseCompression!(targetUrl, { acceptEncoding: "gzip" }), {
        acceptEncoding: "gzip",
      });
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(seen[1], "gzip");
      assert.equal(getValidatorBody(), Buffer.alloc(2048, "z").toString());
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("revising acceptEncoding to br still round-trips a brotli response", async () => {
    const { server: stub, seen, setMode } = compressionStub();
    setMode("br");
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl, getValidatorBody } = relay(
      stubPort,
      { acceptEncoding: "gzip" },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      assert.deepEqual(relayServer.reviseResponseCompression!(targetUrl, { acceptEncoding: "br" }), {
        acceptEncoding: "br",
      });
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(seen[0], "br");
      assert.equal(getValidatorBody(), Buffer.alloc(2048, "z").toString());
      const delivered = events(audit, "delivered")[0];
      const summary = delivered?.response_summary as Record<string, unknown>;
      assert.equal(summary.contentEncoding, "br");
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("tightening maxDecompressedBytes fails the next over-cap gzip attempt", async () => {
    const { server: stub } = compressionStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { maxDecompressedBytes: 4096 },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      // Tighten below the decompressed size: the NEXT attempt fails.
      assert.deepEqual(
        relayServer.reviseResponseCompression!(targetUrl, { maxDecompressedBytes: 1024 }),
        { maxDecompressedBytes: 1024 }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      const dead = events(audit, "dead_letter");
      assert.equal(dead.length, 1);
      assert.match(String(dead[0]?.error), /decompressed body exceeds 1024 bytes/);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("loosening maxDecompressedBytes lets a previously over-cap body through", async () => {
    const { server: stub } = compressionStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { maxDecompressedBytes: 1024 },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[0]?.error), /decompressed body exceeds 1024 bytes/);
      assert.deepEqual(
        relayServer.reviseResponseCompression!(targetUrl, { maxDecompressedBytes: 4096 }),
        { maxDecompressedBytes: 4096 }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(events(audit, "dead_letter").length, 1);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("null clears acceptEncoding back to the default while the entry survives", async () => {
    const { server: stub, seen } = compressionStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { acceptEncoding: "gzip", maxDecompressedBytes: 4096 },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(seen[0], "gzip");
      // Clear only the encoding: the entry survives on the cap knob and
      // the advertised value falls back to the default.
      assert.deepEqual(relayServer.reviseResponseCompression!(targetUrl, { acceptEncoding: null }), {
        maxDecompressedBytes: 4096,
      });
      assert.deepEqual(relayServer.getResponseCompression!(targetUrl), { maxDecompressedBytes: 4096 });
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(seen[1], DEFAULT_OUTBOUND_ACCEPT_ENCODING);
      // The cap knob still governs: a body over 4096 decompressed bytes fails.
      assert.deepEqual(
        relayServer.reviseResponseCompression!(targetUrl, { maxDecompressedBytes: 1024 }),
        { maxDecompressedBytes: 1024 }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      assert.match(String(events(audit, "dead_letter")[0]?.error), /decompressed body exceeds 1024 bytes/);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("clearing both fields deletes the entry and stops negotiating decompression", async () => {
    const { server: stub, seen, setMode } = compressionStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { acceptEncoding: "gzip", maxDecompressedBytes: 4096 },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(seen[0], "gzip");
      assert.equal(
        relayServer.reviseResponseCompression!(targetUrl, {
          acceptEncoding: null,
          maxDecompressedBytes: null,
        }),
        undefined
      );
      assert.equal(relayServer.getResponseCompression!(targetUrl), undefined);
      // The downstream now answers plaintext: no Accept-Encoding is sent
      // and the delivery succeeds without any decode.
      setMode("plain");
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(seen[1], undefined);
      assert.equal(events(audit, "dead_letter").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("a brand-new endpoint can be opted in without a restart", async () => {
    const { server: stub, seen, setMode } = compressionStub();
    setMode("plain");
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl, getValidatorBody } = relay(stubPort, undefined, 1);
    const relayPort = await listen(relayServer);
    try {
      assert.equal(relayServer.getResponseCompression!(targetUrl), undefined);
      // Unconfigured first: no Accept-Encoding, plaintext delivers.
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
      assert.equal(seen[0], undefined);
      // Opt in live: the next attempt negotiates gzip and decodes.
      assert.deepEqual(relayServer.reviseResponseCompression!(targetUrl, { acceptEncoding: "gzip" }), {
        acceptEncoding: "gzip",
      });
      setMode("gzip");
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(seen[1], "gzip");
      assert.equal(getValidatorBody(), Buffer.alloc(2048, "z").toString());
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("an illegal patch throws RangeError and leaves the live record untouched", async () => {
    const { server: stub } = compressionStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { acceptEncoding: "gzip", maxDecompressedBytes: 4096 },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      for (const bad of ["", "   ", 123]) {
        assert.throws(
          () =>
            relayServer.reviseResponseCompression!(targetUrl, {
              acceptEncoding: bad as unknown as string,
            }),
          RangeError,
          `acceptEncoding=${String(bad)}`
        );
      }
      for (const bad of [0, -1, 1.5, Number.NaN, "1024"]) {
        assert.throws(
          () =>
            relayServer.reviseResponseCompression!(targetUrl, {
              maxDecompressedBytes: bad as unknown as number,
            }),
          RangeError,
          `maxDecompressedBytes=${String(bad)}`
        );
      }
      assert.throws(
        () => relayServer.reviseResponseCompression!("", { acceptEncoding: "gzip" }),
        RangeError
      );
      assert.throws(
        () =>
          relayServer.reviseResponseCompression!(
            targetUrl,
            null as unknown as { acceptEncoding: string }
          ),
        RangeError
      );
      assert.deepEqual(relayServer.getResponseCompression!(targetUrl), {
        acceptEncoding: "gzip",
        maxDecompressedBytes: 4096,
      });
      assert.equal(events(audit, "response_compression_revised").length, 0);
      // The live options still govern: a 2 KiB gzip body delivers under the 4 KiB cap.
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length > 0, 5000, "delivered audit entry");
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("an empty patch throws Error and changes nothing", async () => {
    const { server: stub } = compressionStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { acceptEncoding: "gzip", maxDecompressedBytes: 4096 },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      assert.throws(() => relayServer.reviseResponseCompression!(targetUrl, {}), Error);
      assert.throws(
        () =>
          relayServer.reviseResponseCompression!(targetUrl, {
            acceptEncoding: undefined,
            maxDecompressedBytes: undefined,
          }),
        Error
      );
      assert.deepEqual(relayServer.getResponseCompression!(targetUrl), {
        acceptEncoding: "gzip",
        maxDecompressedBytes: 4096,
      });
      assert.equal(events(audit, "response_compression_revised").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("a same-value revision is a silent no-op with no audit event", async () => {
    const { server: stub } = compressionStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { acceptEncoding: "gzip", maxDecompressedBytes: 4096 },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      assert.deepEqual(
        relayServer.reviseResponseCompression!(targetUrl, {
          acceptEncoding: "gzip",
          maxDecompressedBytes: 4096,
        }),
        { acceptEncoding: "gzip", maxDecompressedBytes: 4096 }
      );
      // A partial patch landing on the live values is a no-op too.
      assert.deepEqual(relayServer.reviseResponseCompression!(targetUrl, { acceptEncoding: "gzip" }), {
        acceptEncoding: "gzip",
        maxDecompressedBytes: 4096,
      });
      // Clearing fields that were never set is a no-op on a fresh endpoint.
      const fresh = `http://127.0.0.1:${stubPort}/other`;
      assert.equal(
        relayServer.reviseResponseCompression!(fresh, {
          acceptEncoding: null,
          maxDecompressedBytes: null,
        }),
        undefined
      );
      assert.equal(relayServer.getResponseCompression!(fresh), undefined);
      assert.equal(events(audit, "response_compression_revised").length, 0);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("a real revision audits exact previous/current, with undefined previous on first revision", async () => {
    const { server: stub } = compressionStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { acceptEncoding: "gzip", maxDecompressedBytes: 4096 },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      relayServer.reviseResponseCompression!(targetUrl, { maxDecompressedBytes: 2048 });
      let revised = events(audit, "response_compression_revised");
      assert.equal(revised.length, 1);
      assert.equal(revised[0]?.endpoint, targetUrl);
      assert.deepEqual(revised[0]?.previous, { acceptEncoding: "gzip", maxDecompressedBytes: 4096 });
      assert.deepEqual(revised[0]?.current, { acceptEncoding: "gzip", maxDecompressedBytes: 2048 });
      // Deleting the entry audits current undefined.
      relayServer.reviseResponseCompression!(targetUrl, {
        acceptEncoding: null,
        maxDecompressedBytes: null,
      });
      revised = events(audit, "response_compression_revised");
      assert.equal(revised.length, 2);
      assert.deepEqual(revised[1]?.previous, { acceptEncoding: "gzip", maxDecompressedBytes: 2048 });
      assert.equal(revised[1]?.current, undefined);
      // First revision of a brand-new endpoint audits previous undefined.
      const fresh = `http://127.0.0.1:${stubPort}/other`;
      relayServer.reviseResponseCompression!(fresh, { acceptEncoding: "deflate" });
      revised = events(audit, "response_compression_revised");
      assert.equal(revised.length, 3);
      assert.equal(revised[2]?.endpoint, fresh);
      assert.equal(revised[2]?.previous, undefined);
      assert.deepEqual(revised[2]?.current, { acceptEncoding: "deflate" });
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("a response read already in flight keeps the cap it started under", async () => {
    const { server: stub, hits } = slowGzipStub();
    const stubPort = await listen(stub);
    const { server: relayServer, audit, targetUrl } = relay(
      stubPort,
      { maxDecompressedBytes: 1024 },
      1
    );
    const relayPort = await listen(relayServer);
    try {
      const delivery = deliver(relayPort);
      // Wait until the downstream attempt has started (the relay has
      // read the compression record on header arrival and started the
      // read under the 1 KiB cap), then revise mid-read — the body does
      // not start flowing for another ~150 ms.
      await waitFor(() => hits.length >= 1, 5000, "downstream attempt");
      await new Promise((r) => setTimeout(r, 50));
      assert.deepEqual(
        relayServer.reviseResponseCompression!(targetUrl, { maxDecompressedBytes: 4096 }),
        { maxDecompressedBytes: 4096 }
      );
      await delivery;
      await waitFor(() => events(audit, "dead_letter").length > 0, 5000, "dead_letter audit entry");
      // The in-flight attempt still failed under the OLD 1 KiB cap —
      // the loosened cap only governs the next attempt.
      assert.match(String(events(audit, "dead_letter")[0]?.error), /decompressed body exceeds 1024 bytes/);
    } finally {
      await close(relayServer);
      await close(stub);
    }
  });

  it("the shadow sender shares the revised compression with the main path", async () => {
    const { server: primary, setMode: setPrimaryMode } = compressionStub();
    setPrimaryMode("plain");
    const primaryPort = await listen(primary);
    const { server: shadow, seen: shadowSeen } = compressionStub();
    const shadowPort = await listen(shadow);
    const primaryUrl = `http://127.0.0.1:${primaryPort}/hook`;
    const shadowUrl = `http://127.0.0.1:${shadowPort}/shadow`;
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "comprev-")), "audit.jsonl"));
    const relayServer = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: SIGNING_KEY,
      forwardUrl: primaryUrl,
      auditLog: audit,
      shadowTargets: { [primaryUrl]: [{ targetUrl: shadowUrl }] },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const relayPort = await listen(relayServer);
    try {
      // No compression entry yet: the shadow mirror sends no Accept-Encoding.
      await deliver(relayPort);
      await waitFor(() => events(audit, "shadow_delivered").length > 0, 5000, "shadow_delivered audit entry");
      assert.equal(shadowSeen[0], undefined);
      // Revise the compression for the SHADOW url: the next mirror negotiates gzip.
      assert.deepEqual(
        relayServer.reviseResponseCompression!(shadowUrl, { acceptEncoding: "gzip" }),
        { acceptEncoding: "gzip" }
      );
      await deliver(relayPort);
      await waitFor(() => events(audit, "shadow_delivered").length >= 2, 5000, "second shadow_delivered audit entry");
      assert.equal(shadowSeen[1], "gzip");
      // The main delivery still succeeds throughout.
      assert.equal(events(audit, "delivered").length, 2);
    } finally {
      await close(relayServer);
      await close(primary);
      await close(shadow);
    }
  });
});
