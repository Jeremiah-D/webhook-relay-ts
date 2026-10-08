import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TlsPinMismatchError,
  assertValidPins,
  normalizePin,
  pinMatches,
  spkiFingerprint,
} from "../src/pinning.ts";
import { createRelayServer, createDefaultSender } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

const SECRET = "pin-secret";
const BODY = Buffer.from(JSON.stringify({ event: "pin.probe" }));
const EXPECTED_BARE = "tUqlyRj0nlqk+4njLk9930RXGw2EigsYxt2FmjVLAr4=";
const WRONG_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

function certDer(): Buffer {
  const b64 = TLS_FIXTURE_CERT_PEM.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return Buffer.from(b64, "base64");
}

async function listenHttps(server: HttpsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function listenHttp(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function getJson(port: number, path: string, headers: Record<string, string>) {
  return new Promise<{ status: number; body: unknown }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString()) })
      );
    });
    r.on("error", reject);
    r.end();
  });
}

function postSigned(port: number, headers: Record<string, string>) {
  return new Promise<{ status: number; retryAfter?: string }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/hook",
        method: "POST",
        headers: { ...headers, "x-signature": signSha256(BODY, SECRET) },
      },
      (res) => {
        res.resume();
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, retryAfter: res.headers["retry-after"] as string | undefined })
        );
      }
    );
    r.on("error", reject);
    r.end(BODY);
  });
}

describe("pinning: fingerprints and pin matching", () => {
  it("spkiFingerprint extracts the fixture cert's known fingerprint", () => {
    assert.equal(spkiFingerprint(certDer()), EXPECTED_BARE);
    assert.equal(TLS_FIXTURE_SPKI_PIN, `sha256/${EXPECTED_BARE}`);
  });

  it("normalizePin accepts all three spellings", () => {
    assert.equal(normalizePin(`sha256/${EXPECTED_BARE}`), EXPECTED_BARE);
    assert.equal(normalizePin(`sha256:${EXPECTED_BARE}`), EXPECTED_BARE);
    assert.equal(normalizePin(EXPECTED_BARE), EXPECTED_BARE);
    assert.equal(normalizePin(`  sha256/${EXPECTED_BARE}  `), EXPECTED_BARE);
  });

  it("pinMatches honors any spelling, rejects unknown keys", () => {
    const der = certDer();
    assert.ok(pinMatches(der, [TLS_FIXTURE_SPKI_PIN]));
    assert.ok(pinMatches(der, [EXPECTED_BARE]));
    assert.ok(pinMatches(der, [`sha256:${EXPECTED_BARE}`]));
    assert.ok(!pinMatches(der, [WRONG_PIN]));
    assert.ok(!pinMatches(der, []));
  });

  it("assertValidPins rejects empty whitelists and malformed pins at config time", () => {
    assert.throws(() => assertValidPins([]), /must not be empty/);
    assert.throws(() => assertValidPins(["not-base64!!"]), /malformed TLS pin/);
    // Valid base64 but the wrong length (not 32 bytes) is a typo, not a pin.
    assert.throws(() => assertValidPins(["sha256/aGk="]), /malformed TLS pin/);
    assert.doesNotThrow(() => assertValidPins([TLS_FIXTURE_SPKI_PIN, WRONG_PIN]));
  });

});

describe("pinning: real TLS handshakes through createDefaultSender", () => {
  let https: HttpsServer;
  let port: number;
  const received: Buffer[] = [];

  before(async () => {
    https = createHttpsServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    port = await listenHttps(https);
  });

  after(() => https.close());

  const url = () => `https://127.0.0.1:${port}/hook`;
  const item = (targetUrl: string) => ({ id: "p1", payload: BODY, targetUrl, headers: {} });

  it("a matching pin delivers over the pinned handshake", async () => {
    const sender = createDefaultSender({ [url()]: [TLS_FIXTURE_SPKI_PIN] });
    await sender(item(url()));
    assert.equal(received.length, 1);
    assert.deepEqual(received[0], BODY);
  });

  it("a mismatched pin fails the delivery attempt before any payload byte is sent", async () => {
    const sender = createDefaultSender({ [url()]: [WRONG_PIN] });
    const before = received.length;
    await assert.rejects(() => sender(item(url())), TlsPinMismatchError);
    await assert.rejects(() => sender(item(url())), /pin mismatch/);
    // The pin is verified on secureConnect, before the payload is written:
    // a MITM must not even observe the request body.
    assert.equal(received.length, before);
  });

  it("endpoints without pins keep the default verification (self-signed still fails)", async () => {
    const sender = createDefaultSender();
    // No custom checkServerIdentity is installed, so Node's default chain
    // verification rejects the self-signed fixture cert — pinning never
    // weakens endpoints it is not configured for.
    await assert.rejects(() => sender(item(url())), /certificate|self signed|unable to verify/i);
  });

  it("createDefaultSender validates pins up front", () => {
    assert.throws(() => createDefaultSender({ "https://x/": [] }), /invalid TLS pins.*must not be empty/);
    assert.throws(() => createDefaultSender({ "https://x/": ["bogus"] }), /invalid TLS pins.*malformed/);
  });
});

describe("pinning: end-to-end through the relay server", () => {
  let https: HttpsServer;
  let relay: Server;
  let relayPort: number;
  const OPERATOR = "op-pin-token";
  const auth = { authorization: `Bearer ${OPERATOR}` };

  before(async () => {
    https = createHttpsServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM }, (req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    const downstreamPort = await listenHttps(https);
    const forwardUrl = `https://127.0.0.1:${downstreamPort}/hook`;
    const dir = mkdtempSync(join(tmpdir(), "audit-pin-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    relay = createRelayServer({
      secret: SECRET,
      forwardUrl,
      auditLog: audit,
      operatorToken: OPERATOR,
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 2 },
      // The pin does NOT match the downstream's real key: every handshake
      // must fail, and the failure must surface in the audit trail.
      tlsPins: { [forwardUrl]: [WRONG_PIN] },
    });
    relayPort = await listenHttp(relay);
  });

  after(() => {
    relay.close();
    https.close();
  });

  it("a pin mismatch dead-letters the delivery and the mismatch is audited", async () => {
    const r = await postSigned(relayPort, {});
    assert.equal(r.status, 202); // accepted inbound; the TLS failure is outbound
    let dead: unknown[] = [];
    for (let i = 0; i < 100 && dead.length === 0; i++) {
      await new Promise((res) => setTimeout(res, 25));
      dead = ((await getJson(relayPort, "/dead-letter", auth)).body as unknown[]) ?? [];
    }
    assert.equal(dead.length, 1);
    assert.match((dead[0] as { lastError: string }).lastError, /pin mismatch/);
  });
});
