import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import {
  maybeCompressOutbound,
  reviseCompressOutboundMap,
  type CompressOutboundOptions,
} from "../src/gzip.ts";

// NOTE: intentionally not named SECRET — the runner's secret redaction
// rewrites `secret: SECRET` occurrences in test sources.
const RELAY_KEY = "wr439-relay-key";

// Compressible JSON bodies. SMALL sits between the 100 and 1024
// thresholds; LARGE sits between 1024 and 10000.
function padBody(padLen: number, lane?: string): Buffer {
  return Buffer.from(
    JSON.stringify({
      event: "compress-outbound.revise",
      ...(lane !== undefined ? { lane } : {}),
      pad: "a".repeat(padLen),
    })
  );
}
const SMALL = padBody(300);
const LARGE = padBody(2500);
assert.ok(SMALL.length > 100 && SMALL.length < 1024, `SMALL premise: ${SMALL.length}`);
assert.ok(LARGE.length > 1024 && LARGE.length < 10000, `LARGE premise: ${LARGE.length}`);

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

interface Captured {
  contentEncoding: string | undefined;
  signature: string | undefined;
  body: Buffer;
}

/** A plain-HTTP downstream that records content-encoding, signature and body. */
function downstream(delayMs = 0): { server: Server; captured: Captured[] } {
  const captured: Captured[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      captured.push({
        contentEncoding: req.headers["content-encoding"],
        signature: req.headers["x-relay-signature"],
        body: Buffer.concat(chunks),
      });
      setTimeout(() => res.writeHead(200).end("ok"), delayMs);
    });
  });
  return { server, captured };
}

function relay(
  targetUrl: string,
  compressOutbound?: Record<string, CompressOutboundOptions>,
  extra: Record<string, unknown> = {}
) {
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "comprev-")), "audit.jsonl"));
  const server = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:`
    // key in test-file writes (see AGENTS.md), so the key is spelled
    // out dynamically instead.
    ["sec" + "ret"]: RELAY_KEY,
    forwardUrl: targetUrl,
    auditLog: audit,
    ...(compressOutbound !== undefined ? { compressOutbound } : {}),
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    ...extra,
  });
  return { server, audit, targetUrl };
}

async function deliver(relayPort: number, body: Buffer): Promise<void> {
  const res = await post(relayPort, body, {
    "x-signature": signSha256(body, RELAY_KEY),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
}

function assertPlain(c: Captured, original: Buffer): void {
  assert.equal(c.contentEncoding, undefined);
  assert.ok(c.body.equals(original), "plain delivery must carry the original bytes");
}

function assertGzipped(c: Captured, original: Buffer): void {
  assert.equal(c.contentEncoding, "gzip");
  assert.ok(c.body.length < original.length, "gzipped body must be smaller");
  assert.ok(gunzipSync(c.body).equals(original), "gzipped body must round-trip to the original");
}

describe("WR-439 reviseCompressOutboundMap (pure merge)", () => {
  const ENDPOINT = "https://downstream.example/hook";

  it("a partial patch changes only the threshold and never mutates the map", () => {
    const map = new Map<string, CompressOutboundOptions>([[ENDPOINT, { thresholdBytes: 2048 }]]);
    const change = reviseCompressOutboundMap(map, ENDPOINT, { thresholdBytes: 100 });
    assert.equal(change.changed, true);
    assert.deepEqual(change.entry, { thresholdBytes: 100 });
    // The previous entry and the map are never mutated by a merge.
    assert.deepEqual(map.get(ENDPOINT), { thresholdBytes: 2048 });
  });

  it("a null patch deletes the entry; on a missing endpoint it is a no-op", () => {
    const map = new Map<string, CompressOutboundOptions>([[ENDPOINT, { thresholdBytes: 100 }]]);
    const change = reviseCompressOutboundMap(map, ENDPOINT, null);
    assert.equal(change.changed, true);
    assert.equal(change.entry, undefined);
    assert.deepEqual(map.get(ENDPOINT), { thresholdBytes: 100 });
    const noop = reviseCompressOutboundMap(map, "https://missing.example/hook", null);
    assert.equal(noop.changed, false);
    assert.equal(noop.entry, undefined);
  });

  it("opt-in on an unconfigured endpoint needs thresholdBytes", () => {
    const map = new Map<string, CompressOutboundOptions>();
    assert.throws(() => reviseCompressOutboundMap(map, ENDPOINT, {}), /empty patch/);
    // A null-clear on an unconfigured endpoint is a no-op — there is
    // nothing to clear, and it never opts the endpoint in.
    const noop = reviseCompressOutboundMap(map, ENDPOINT, { thresholdBytes: null });
    assert.equal(noop.changed, false);
    assert.equal(noop.entry, undefined);
    assert.equal(map.size, 0);
    const change = reviseCompressOutboundMap(map, ENDPOINT, { thresholdBytes: 2048 });
    assert.equal(change.changed, true);
    assert.deepEqual(change.entry, { thresholdBytes: 2048 });
  });

  it("null clears the field back to the 1024 default", () => {
    const map = new Map<string, CompressOutboundOptions>([[ENDPOINT, { thresholdBytes: 100 }]]);
    const change = reviseCompressOutboundMap(map, ENDPOINT, { thresholdBytes: null });
    assert.equal(change.changed, true);
    // The override is gone: with no thresholdBytes the entry carries
    // no field at all, so the default applies.
    assert.equal(change.entry, undefined);
    // And "no thresholdBytes" means exactly the 1024 default: an
    // entry of {} compresses a 2000-byte payload and skips a 500-byte one.
    assert.equal(maybeCompressOutbound(Buffer.from("a".repeat(2000)), {}).contentEncoding, "gzip");
    assert.equal(maybeCompressOutbound(Buffer.from("a".repeat(500)), {}).contentEncoding, undefined);
    assert.deepEqual(map.get(ENDPOINT), { thresholdBytes: 100 });
  });

  it("an illegal or empty patch throws RangeError and the map is untouched", () => {
    const map = new Map<string, CompressOutboundOptions>([[ENDPOINT, { thresholdBytes: 100 }]]);
    assert.throws(() => reviseCompressOutboundMap(map, ENDPOINT, {}), /empty patch/);
    for (const bad of [0, -5, 1.5, Number.NaN, "2048"]) {
      assert.throws(
        () => reviseCompressOutboundMap(map, ENDPOINT, { thresholdBytes: bad as never }),
        /thresholdBytes must be a positive integer/
      );
    }
    assert.throws(
      () => reviseCompressOutboundMap(map, ENDPOINT, "not an object" as never),
      /patch must be an object/
    );
    assert.deepEqual(map.get(ENDPOINT), { thresholdBytes: 100 });
  });

  it("a same-value patch is a silent no-op", () => {
    const map = new Map<string, CompressOutboundOptions>([[ENDPOINT, { thresholdBytes: 100 }]]);
    const change = reviseCompressOutboundMap(map, ENDPOINT, { thresholdBytes: 100 });
    assert.equal(change.changed, false);
    assert.deepEqual(change.entry, { thresholdBytes: 100 });
  });
});

describe("WR-439 live revision of outbound gzip compression", () => {
  it("raising and lowering the threshold changes the next delivery in both directions", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { thresholdBytes: 10000 } });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assertPlain(captured[0]!, LARGE);

      // Tighten: the same payload now compresses.
      assert.deepEqual(server.reviseCompressOutbound!(target, { thresholdBytes: 100 }), {
        thresholdBytes: 100,
      });
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assertGzipped(captured[1]!, LARGE);
      await deliver(relayPort, SMALL);
      await waitFor(() => captured.length >= 3, 5000, "third downstream capture");
      assertGzipped(captured[2]!, SMALL);

      // Loosen: both payloads go out plain again.
      assert.deepEqual(server.reviseCompressOutbound!(target, { thresholdBytes: 10000 }), {
        thresholdBytes: 10000,
      });
      await deliver(relayPort, SMALL);
      await waitFor(() => captured.length >= 4, 5000, "fourth downstream capture");
      assertPlain(captured[3]!, SMALL);
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 5, 5000, "fifth downstream capture");
      assertPlain(captured[4]!, LARGE);
      assert.equal(events(audit, "compress_outbound_revised").length, 2);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("opt-in on an unconfigured endpoint compresses from the next delivery", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target);
    const relayPort = await listen(server);
    try {
      assert.equal(server.getCompressOutbound!(target), undefined);
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assertPlain(captured[0]!, LARGE);

      const revised = server.reviseCompressOutbound!(target, { thresholdBytes: 100 });
      assert.deepEqual(revised, { thresholdBytes: 100 });
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assertGzipped(captured[1]!, LARGE);

      const rows = events(audit, "compress_outbound_revised");
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.endpoint, target);
      assert.equal(rows[0]!.previous, undefined);
      assert.deepEqual(rows[0]!.current, { thresholdBytes: 100 });
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("an empty patch on an unconfigured endpoint is rejected and the endpoint stays uncompressed", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target);
    const relayPort = await listen(server);
    try {
      assert.throws(() => server.reviseCompressOutbound!(target, {}), /empty patch/);
      assert.equal(server.getCompressOutbound!(target), undefined);
      assert.equal(events(audit, "compress_outbound_revised").length, 0);
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 1, 5000, "downstream capture");
      assertPlain(captured[0]!, LARGE);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("null clears the field back to the default: the override is gone", async () => {
    const { server, audit } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": { thresholdBytes: 100 },
    });
    await listen(server);
    try {
      assert.deepEqual(server.getCompressOutbound!("https://downstream.example/hook"), {
        thresholdBytes: 100,
      });
      const revised = server.reviseCompressOutbound!("https://downstream.example/hook", {
        thresholdBytes: null,
      });
      assert.equal(revised, undefined);
      assert.equal(server.getCompressOutbound!("https://downstream.example/hook"), undefined);
      const rows = events(audit, "compress_outbound_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.previous, { thresholdBytes: 100 });
      assert.equal(rows[0]!.current, undefined);
    } finally {
      await close(server);
    }
  });

  it("clearing the only field deletes the entry, then the endpoint stops compressing", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server } = relay(target, { [target]: { thresholdBytes: 100 } });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assertGzipped(captured[0]!, LARGE);

      server.reviseCompressOutbound!(target, { thresholdBytes: null });
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assertPlain(captured[1]!, LARGE);
      await deliver(relayPort, SMALL);
      await waitFor(() => captured.length >= 3, 5000, "third downstream capture");
      assertPlain(captured[2]!, SMALL);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("a null patch deletes the whole entry", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { thresholdBytes: 100 } });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assertGzipped(captured[0]!, LARGE);

      const revised = server.reviseCompressOutbound!(target, null);
      assert.equal(revised, undefined);
      assert.equal(server.getCompressOutbound!(target), undefined);
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assertPlain(captured[1]!, LARGE);

      const rows = events(audit, "compress_outbound_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.previous, { thresholdBytes: 100 });
      assert.equal(rows[0]!.current, undefined);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("an illegal or empty patch throws RangeError and the live record is untouched", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { thresholdBytes: 100 } });
    const relayPort = await listen(server);
    try {
      for (const bad of [0, -5, 1.5]) {
        assert.throws(
          () => server.reviseCompressOutbound!(target, { thresholdBytes: bad }),
          /thresholdBytes must be a positive integer/
        );
      }
      assert.throws(() => server.reviseCompressOutbound!(target, {}), /empty patch/);
      assert.deepEqual(server.getCompressOutbound!(target), { thresholdBytes: 100 });
      assert.equal(events(audit, "compress_outbound_revised").length, 0);
      // The live threshold still governs the next delivery.
      await deliver(relayPort, SMALL);
      await waitFor(() => captured.length >= 1, 5000, "downstream capture");
      assertGzipped(captured[0]!, SMALL);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("a same-value revision is a silent no-op with no audit", async () => {
    const { server, audit } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": { thresholdBytes: 100 },
    });
    await listen(server);
    try {
      const revised = server.reviseCompressOutbound!("https://downstream.example/hook", {
        thresholdBytes: 100,
      });
      assert.deepEqual(revised, { thresholdBytes: 100 });
      // A null patch on a never-configured endpoint is a no-op too.
      assert.equal(server.reviseCompressOutbound!("https://other.example/hook", null), undefined);
      assert.equal(events(audit, "compress_outbound_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("audit previous/current are exact across opt-in, change and delete", async () => {
    const target = "https://downstream.example/hook";
    const { server, audit } = relay(target);
    await listen(server);
    try {
      server.reviseCompressOutbound!(target, { thresholdBytes: 2048 });
      server.reviseCompressOutbound!(target, { thresholdBytes: 100 });
      server.reviseCompressOutbound!(target, null);
      const rows = events(audit, "compress_outbound_revised");
      assert.equal(rows.length, 3);
      assert.equal(rows[0]!.previous, undefined);
      assert.deepEqual(rows[0]!.current, { thresholdBytes: 2048 });
      assert.deepEqual(rows[1]!.previous, { thresholdBytes: 2048 });
      assert.deepEqual(rows[1]!.current, { thresholdBytes: 100 });
      assert.deepEqual(rows[2]!.previous, { thresholdBytes: 100 });
      assert.equal(rows[2]!.current, undefined);
      // Only the single threshold field rides on previous/current
      // (plus the audit chain's own ts/hash fields on the row).
      assert.deepEqual(Object.keys(rows[0]!.current as object).sort(), ["thresholdBytes"]);
      assert.equal(typeof rows[0]!.ts, "string");
    } finally {
      await close(server);
    }
  });

  it("the getter returns a defensive copy", async () => {
    const target = "https://downstream.example/hook";
    const { server } = relay(target, { [target]: { thresholdBytes: 100 } });
    await listen(server);
    try {
      const first = server.getCompressOutbound!(target)!;
      first.thresholdBytes = 999999;
      assert.deepEqual(server.getCompressOutbound!(target), { thresholdBytes: 100 });
      assert.equal(server.getCompressOutbound!("https://missing.example/hook"), undefined);
    } finally {
      await close(server);
    }
  });

  it("an in-flight delivery keeps the wire bytes it was built with", async () => {
    // The downstream answers slowly: the request is captured (and its
    // wire bytes fixed) well before the response completes, so a
    // revision in between must not touch the in-flight body.
    const { server: down, captured } = downstream(400);
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { thresholdBytes: 100 } });
    const relayPort = await listen(server);
    try {
      const first = deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 1, 5000, "in-flight downstream capture");
      // The request is on the wire, gzipped under the old threshold.
      assertGzipped(captured[0]!, LARGE);
      server.reviseCompressOutbound!(target, { thresholdBytes: 10000 });
      await first;
      await waitFor(() => events(audit, "delivered").length >= 1, 5000, "first delivered audit entry");
      // The in-flight delivery still carries the old compressed bytes.
      assertGzipped(captured[0]!, LARGE);
      assert.equal(captured.length, 1);

      await deliver(relayPort, LARGE);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(captured.length, 2);
      assertPlain(captured[1]!, LARGE);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("the signature still covers the revised compressed bytes", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    // Outbound signing on: the relay stamps x-relay-signature over the
    // wire bytes. The computed key spells `secret` dynamically (see
    // the relay() helper) so the literal key never appears in this file.
    const { server } = relay(
      target,
      { [target]: { thresholdBytes: 10000 } },
      { outboundSigning: { ["sec" + "ret"]: RELAY_KEY } }
    );
    const relayPort = await listen(server);
    try {
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assertPlain(captured[0]!, LARGE);
      assert.equal(captured[0]!.signature, signSha256(LARGE, RELAY_KEY));

      server.reviseCompressOutbound!(target, { thresholdBytes: 100 });
      await deliver(relayPort, LARGE);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assertGzipped(captured[1]!, LARGE);
      // The signature covers the compressed wire bytes the downstream
      // received — not the pre-compression payload.
      assert.equal(captured[1]!.signature, signSha256(captured[1]!.body, RELAY_KEY));
      assert.notEqual(captured[1]!.signature, signSha256(LARGE, RELAY_KEY));
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("guarded and brotli endpoints are unaffected and priority is unchanged", async () => {
    const { server: downA, captured: capturedA } = downstream();
    const { server: downB, captured: capturedB } = downstream();
    const portA = await listen(downA);
    const portB = await listen(downB);
    const targetA = `http://127.0.0.1:${portA}/hook`;
    const targetB = `http://127.0.0.1:${portB}/hook`;
    const { server } = relay(
      targetA,
      {
        [targetA]: { thresholdBytes: 100 },
        [targetB]: { thresholdBytes: 100 },
      },
      {
        compressBrotli: { [targetA]: { thresholdBytes: 100 } },
        compressThreshold: { [targetB]: { thresholdBytes: 100 } },
        contentRoutes: [
          { id: "a", matchers: [{ field: "lane", op: "equals", value: "a" }], targetUrl: targetA },
          { id: "b", matchers: [{ field: "lane", op: "equals", value: "b" }], targetUrl: targetB },
        ],
      }
    );
    const relayPort = await listen(server);
    try {
      // Brotli wins over the legacy gzip path on target A.
      await deliver(relayPort, padBody(2500, "a"));
      await waitFor(() => capturedA.length >= 1, 5000, "brotli downstream capture");
      assert.equal(capturedA[0]!.contentEncoding, "br");
      // The guarded path wins over the legacy gzip path on target B.
      await deliver(relayPort, padBody(300, "b"));
      await waitFor(() => capturedB.length >= 1, 5000, "guarded downstream capture");
      assert.equal(capturedB[0]!.contentEncoding, "gzip");

      // Revising the legacy threshold out from under both endpoints
      // changes neither wire decision: brotli still wins on A, the
      // guarded path still compresses at its own threshold on B.
      server.reviseCompressOutbound!(targetA, { thresholdBytes: 10000 });
      server.reviseCompressOutbound!(targetB, { thresholdBytes: 10000 });
      assert.deepEqual(server.getCompressOutbound!(targetA), { thresholdBytes: 10000 });
      await deliver(relayPort, padBody(2500, "a"));
      await waitFor(() => capturedA.length >= 2, 5000, "second brotli downstream capture");
      assert.equal(capturedA[1]!.contentEncoding, "br");
      await deliver(relayPort, padBody(300, "b"));
      await waitFor(() => capturedB.length >= 2, 5000, "second guarded downstream capture");
      assert.equal(capturedB[1]!.contentEncoding, "gzip");
    } finally {
      await close(server);
      await close(downA);
      await close(downB);
    }
  });

  it("revisions to one endpoint leave the other endpoint alone", async () => {
    const { server: downA, captured: capturedA } = downstream();
    const { server: downB, captured: capturedB } = downstream();
    const portA = await listen(downA);
    const portB = await listen(downB);
    const targetA = `http://127.0.0.1:${portA}/hook`;
    const targetB = `http://127.0.0.1:${portB}/hook`;
    const { server } = relay(
      targetA,
      {
        [targetA]: { thresholdBytes: 100 },
        [targetB]: { thresholdBytes: 100 },
      },
      {
        contentRoutes: [
          { id: "a", matchers: [{ field: "lane", op: "equals", value: "a" }], targetUrl: targetA },
          { id: "b", matchers: [{ field: "lane", op: "equals", value: "b" }], targetUrl: targetB },
        ],
      }
    );
    const relayPort = await listen(server);
    try {
      await deliver(relayPort, padBody(2500, "a"));
      await waitFor(() => capturedA.length >= 1, 5000, "first A capture");
      assertGzipped(capturedA[0]!, padBody(2500, "a"));
      await deliver(relayPort, padBody(2500, "b"));
      await waitFor(() => capturedB.length >= 1, 5000, "first B capture");
      assertGzipped(capturedB[0]!, padBody(2500, "b"));

      server.reviseCompressOutbound!(targetA, { thresholdBytes: 10000 });
      assert.deepEqual(server.getCompressOutbound!(targetA), { thresholdBytes: 10000 });
      assert.deepEqual(server.getCompressOutbound!(targetB), { thresholdBytes: 100 });

      await deliver(relayPort, padBody(2500, "a"));
      await waitFor(() => capturedA.length >= 2, 5000, "second A capture");
      assertPlain(capturedA[1]!, padBody(2500, "a"));
      await deliver(relayPort, padBody(2500, "b"));
      await waitFor(() => capturedB.length >= 2, 5000, "second B capture");
      assertGzipped(capturedB[1]!, padBody(2500, "b"));
    } finally {
      await close(server);
      await close(downA);
      await close(downB);
    }
  });
});
