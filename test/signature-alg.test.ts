import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import {
  Ed25519Verifier,
  HmacSha256Verifier,
  signEd25519,
  signSha256,
  type Verifier,
} from "../src/verify.ts";
import {
  SIGNATURE_ALG_HEADER,
  assertValidSignatureAlgorithmRules,
  normalizeSignatureAlg,
  selectSignatureAlgorithmVerifier,
  type SignatureAlgorithmRule,
} from "../src/signature-alg.ts";
import { AuditLog } from "../src/audit.ts";

const GLOBAL_SECRET = "sigalg-global-secret";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const PUB_PEM = publicKey.export({ type: "spki", format: "pem" }).toString();
const PRIV_PEM = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const edVerifier: Verifier = new Ed25519Verifier(PUB_PEM);
const hmacVerifier: Verifier = new HmacSha256Verifier(GLOBAL_SECRET);

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
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

function makeRelay(extra: Record<string, unknown> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "audit-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const relay = createRelayServer({
    secret: GLOBAL_SECRET,
    forwardUrl: "http://127.0.0.1:1/hook",
    auditLog: audit,
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    ...extra,
  } as Parameters<typeof createRelayServer>[0]);
  return { relay, audit };
}

async function withRelay(
  extra: Record<string, unknown>,
  fn: (port: number, audit: AuditLog) => Promise<void>
) {
  const { relay, audit } = makeRelay(extra);
  const port = await listen(relay);
  try {
    await fn(port, audit);
  } finally {
    relay.close();
    await new Promise((r) => relay.once("close", r));
  }
}

describe("normalizeSignatureAlg", () => {
  it("trims and lowercases", () => {
    assert.equal(normalizeSignatureAlg("  Ed25519 "), "ed25519");
    assert.equal(normalizeSignatureAlg("HMAC-SHA256"), "hmac-sha256");
  });

  it("returns undefined for missing, non-string, or blank values", () => {
    assert.equal(normalizeSignatureAlg(undefined), undefined);
    assert.equal(normalizeSignatureAlg(null), undefined);
    assert.equal(normalizeSignatureAlg(""), undefined);
    assert.equal(normalizeSignatureAlg("   "), undefined);
    assert.equal(normalizeSignatureAlg(42), undefined);
  });
});

describe("assertValidSignatureAlgorithmRules", () => {
  const valid: SignatureAlgorithmRule[] = [
    { alg: "hmac-sha256", verifier: hmacVerifier },
    { alg: "ed25519", verifier: edVerifier },
  ];

  it("accepts undefined and valid rules", () => {
    assertValidSignatureAlgorithmRules(undefined);
    assertValidSignatureAlgorithmRules(valid);
    assertValidSignatureAlgorithmRules([{ alg: " Ed25519 ", verifier: edVerifier }]);
  });

  it("rejects non-arrays, empty arrays, unknown algs, duplicates, bad verifiers", () => {
    assert.throws(() => assertValidSignatureAlgorithmRules("nope" as never), RangeError);
    assert.throws(() => assertValidSignatureAlgorithmRules([]), RangeError);
    assert.throws(
      () => assertValidSignatureAlgorithmRules([{ alg: "rsa-pss", verifier: edVerifier }]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidSignatureAlgorithmRules([
          { alg: "ed25519", verifier: edVerifier },
          { alg: "ED25519", verifier: edVerifier },
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidSignatureAlgorithmRules([
          { alg: "ed25519", verifier: { name: "bogus" } as Verifier },
        ]),
      RangeError
    );
  });
});

describe("selectSignatureAlgorithmVerifier", () => {
  const rules: SignatureAlgorithmRule[] = [
    { alg: "hmac-sha256", verifier: hmacVerifier },
    { alg: "ed25519", verifier: edVerifier },
  ];

  it("finds verifiers case-insensitively", () => {
    assert.equal(selectSignatureAlgorithmVerifier("ed25519", rules), edVerifier);
    assert.equal(selectSignatureAlgorithmVerifier("ED25519", rules), edVerifier);
    assert.equal(selectSignatureAlgorithmVerifier("hmac-sha256", rules), hmacVerifier);
  });

  it("returns undefined for unknown names or missing config", () => {
    assert.equal(selectSignatureAlgorithmVerifier("rsa-pss", rules), undefined);
    assert.equal(selectSignatureAlgorithmVerifier("ed25519", undefined), undefined);
    assert.equal(selectSignatureAlgorithmVerifier("ed25519", []), undefined);
  });
});

describe("server signature algorithm negotiation", () => {
  let stub: Server;
  let stubPort: number;

  before(async () => {
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  const rules: SignatureAlgorithmRule[] = [
    { alg: "hmac-sha256", verifier: hmacVerifier },
    { alg: "ed25519", verifier: edVerifier },
  ];

  it("default config ignores the header: legacy HMAC behavior is unchanged", async () => {
    await withRelay({ forwardUrl: `http://127.0.0.1:${stubPort}/hook` }, async (port, audit) => {
      // The header is meaningless without configuration — HMAC still verifies.
      const ok = await post(port, "/", BODY, {
        "x-signature": signSha256(BODY, GLOBAL_SECRET),
        [SIGNATURE_ALG_HEADER]: "ed25519",
      });
      assert.equal(ok.status, 202);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].algorithm, undefined);
    });
  });

  it("negotiates hmac-sha256 explicitly", async () => {
    await withRelay(
      { forwardUrl: `http://127.0.0.1:${stubPort}/hook`, signatureAlgorithms: rules },
      async (port, audit) => {
        const ok = await post(port, "/", BODY, {
          "x-signature": signSha256(BODY, GLOBAL_SECRET),
          [SIGNATURE_ALG_HEADER]: "hmac-sha256",
        });
        assert.equal(ok.status, 202);
        const events = audit.readAll() as Array<Record<string, unknown>>;
        const accepted = events.filter((e) => e.event === "accepted");
        assert.equal(accepted.length, 1);
        assert.equal(accepted[0].algorithm, "hmac-sha256");
      }
    );
  });

  it("negotiates ed25519: accepts ed25519 signatures, rejects HMAC ones", async () => {
    await withRelay(
      { forwardUrl: `http://127.0.0.1:${stubPort}/hook`, signatureAlgorithms: rules },
      async (port, audit) => {
        const ok = await post(port, "/", BODY, {
          "x-signature": signEd25519(BODY, PRIV_PEM),
          [SIGNATURE_ALG_HEADER]: "ed25519",
        });
        assert.equal(ok.status, 202);

        const wrong = await post(port, "/", BODY, {
          "x-signature": signSha256(BODY, GLOBAL_SECRET),
          [SIGNATURE_ALG_HEADER]: "ed25519",
        });
        assert.equal(wrong.status, 401);

        const events = audit.readAll() as Array<Record<string, unknown>>;
        const accepted = events.filter((e) => e.event === "accepted");
        assert.equal(accepted.length, 1);
        assert.equal(accepted[0].algorithm, "ed25519");
        const rejected = events.filter(
          (e) => e.event === "rejected" && e.reason === "invalid_signature"
        );
        assert.equal(rejected.length, 1);
        assert.equal(rejected[0].algorithm, "ed25519");
      }
    );
  });

  it("answers 400 + audits unsupported_algorithm for a non-allowlisted name", async () => {
    await withRelay(
      { forwardUrl: `http://127.0.0.1:${stubPort}/hook`, signatureAlgorithms: rules },
      async (port, audit) => {
        const res = await post(port, "/", BODY, {
          "x-signature": signSha256(BODY, GLOBAL_SECRET),
          [SIGNATURE_ALG_HEADER]: "rsa-pss",
        });
        assert.equal(res.status, 400);
        const events = audit.readAll() as Array<Record<string, unknown>>;
        const rejected = events.filter((e) => e.event === "rejected");
        assert.equal(rejected.length, 1);
        assert.equal(rejected[0].reason, "unsupported_algorithm");
        assert.equal(rejected[0].algorithm, "rsa-pss");
        // Nothing was accepted or enqueued.
        assert.ok(!events.some((e) => e.event === "accepted"));
      }
    );
  });

  it("matches the header case-insensitively and treats a missing header as legacy", async () => {
    await withRelay(
      { forwardUrl: `http://127.0.0.1:${stubPort}/hook`, signatureAlgorithms: rules },
      async (port, audit) => {
        const ok = await post(port, "/", BODY, {
          "x-signature": signEd25519(BODY, PRIV_PEM),
          [SIGNATURE_ALG_HEADER]: "  ED25519 ",
        });
        assert.equal(ok.status, 202);
        const legacy = await post(port, "/", BODY, {
          "x-signature": signSha256(BODY, GLOBAL_SECRET),
        });
        assert.equal(legacy.status, 202);
        const events = audit.readAll() as Array<Record<string, unknown>>;
        const accepted = events.filter((e) => e.event === "accepted");
        assert.equal(accepted.length, 2);
        assert.equal(accepted[0].algorithm, "ed25519");
        assert.equal(accepted[1].algorithm, undefined);
      }
    );
  });

  it("a per-endpoint pinned verifier is never widened by the header", async () => {
    const pinnedSecret = "pinned-secret";
    await withRelay(
      {
        forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
        signatureAlgorithms: rules,
        endpointVerifiers: [
          { pattern: "/hooks/pinned", verifier: new HmacSha256Verifier(pinnedSecret) },
        ],
      },
      async (port) => {
        // A valid ed25519 signature must NOT verify on the pinned HMAC path,
        // even though ed25519 is allowlisted globally.
        const res = await post(port, "/hooks/pinned", BODY, {
          "x-signature": signEd25519(BODY, PRIV_PEM),
          [SIGNATURE_ALG_HEADER]: "ed25519",
        });
        assert.equal(res.status, 401);
        // The pinned path's own HMAC secret still works.
        const ok = await post(port, "/hooks/pinned", BODY, {
          "x-signature": signSha256(BODY, pinnedSecret),
        });
        assert.equal(ok.status, 202);
      }
    );
  });

  it("rejects invalid signatureAlgorithms at startup", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const base = {
      secret: GLOBAL_SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
    } as Parameters<typeof createRelayServer>[0];
    assert.throws(
      () => createRelayServer({ ...base, signatureAlgorithms: [] }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          ...base,
          signatureAlgorithms: [{ alg: "rsa-pss", verifier: edVerifier }],
        }),
      RangeError
    );
  });
});
