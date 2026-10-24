import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify as cryptoVerify,
} from "node:crypto";
import { createServer, type Server } from "node:http";
import {
  buildDpopProofJwt,
  defaultOAuth2TokenFetcher,
  dpopJwkThumbprint,
  DPOP_PROOF_HEADER,
  DPOP_TOKEN_TYPE,
  OAuth2TokenCache,
  OAuth2TokenError,
  resolveOAuth2ClientConfig,
  type DpopKeyConfig,
  type OAuth2ClientCredentialsConfig,
  type OAuth2TokenFetchParams,
  type ResolvedDpopKey,
} from "../src/oauth-client.ts";
import { createDefaultSender } from "../src/server.ts";
import type { RetryItem } from "../src/retry.ts";

const TOKEN_ENDPOINT = "https://auth.example.com/oauth/token";
const CLIENT_ID = "relay-client-1";
const SCOPE = "webhooks:write";
const CLIENT_SECRET_VALUE = "oauth-test-secret-value";

function edKeyPair(): { privatePem: string; publicKey: ReturnType<typeof createPublicKey> } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicKey,
  };
}

function p256KeyPair(): { privatePem: string; publicKey: ReturnType<typeof createPublicKey> } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicKey,
  };
}

function dpopConfig(pem: string, alg: "Ed25519" | "ES256", keyId = "dpop-key-1"): OAuth2ClientCredentialsConfig {
  return {
    token_endpoint: TOKEN_ENDPOINT,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET_VALUE,
    scope: SCOPE,
    dpop: { privateKey: pem, keyId, alg },
  };
}

function resolvedDpop(pem: string, alg: "Ed25519" | "ES256", keyId = "dpop-key-1"): ResolvedDpopKey {
  const resolved = resolveOAuth2ClientConfig(dpopConfig(pem, alg, keyId), "test");
  assert.ok(resolved.dpop !== undefined);
  return resolved.dpop;
}

function decodeJwt(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const [h, p] = jwt.split(".");
  assert.equal(jwt.split(".").length, 3, "proof must be a 3-part JWT");
  return {
    header: JSON.parse(Buffer.from(h, "base64url").toString("utf8")),
    payload: JSON.parse(Buffer.from(p, "base64url").toString("utf8")),
  };
}

/** Raw R||S (JWS ES256) back to DER for `node:crypto` verification. */
function rawToDer(raw: Buffer): Buffer {
  assert.equal(raw.length, 64);
  const strip = (v: Buffer): Buffer => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0x00 && (v[i + 1]! & 0x80) === 0) i++;
    let out = v.subarray(i);
    if ((out[0]! & 0x80) !== 0) out = Buffer.concat([Buffer.from([0x00]), out]);
    return out;
  };
  const r = strip(raw.subarray(0, 32));
  const s = strip(raw.subarray(32, 64));
  const body = Buffer.concat([
    Buffer.from([0x02, r.length]),
    r,
    Buffer.from([0x02, s.length]),
    s,
  ]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function verifyDpopProof(
  jwt: string,
  publicKey: ReturnType<typeof createPublicKey>,
  alg: "Ed25519" | "ES256"
): boolean {
  const [h, p, s] = jwt.split(".");
  const data = Buffer.from(`${h}.${p}`, "utf8");
  const sig = Buffer.from(s, "base64url");
  return alg === "Ed25519"
    ? cryptoVerify(null, data, publicKey, sig)
    : cryptoVerify("SHA256", data, publicKey, rawToDer(sig));
}

function sha256b64u(s: string): string {
  return createHash("sha256").update(s, "utf8").digest().toString("base64url");
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  server.close();
  await new Promise((r) => server.once("close", r));
}

describe("WR-205: DPoP proof construction", () => {
  it("builds an Ed25519 proof with RFC 9449 header/payload and a verifiable signature", () => {
    const { privatePem, publicKey } = edKeyPair();
    const dpop = resolvedDpop(privatePem, "Ed25519");
    const proof = buildDpopProofJwt({
      dpop,
      htm: "POST",
      htu: "https://rs.example.com/hook?x=1#frag",
      nowMs: Date.UTC(2026, 9, 23, 10, 0, 0),
      jti: "fixed-jti-1",
    });
    const { header, payload } = decodeJwt(proof);
    assert.equal(header.typ, "dpop+jwt");
    assert.equal(header.alg, "EdDSA");
    const jwk = header.jwk as Record<string, unknown>;
    assert.equal(jwk.kty, "OKP");
    assert.equal(jwk.crv, "Ed25519");
    assert.ok(typeof jwk.x === "string" && jwk.x.length > 0);
    assert.equal(jwk.d, undefined, "the proof header must never carry private key material");
    // htu is normalized: query and fragment are stripped.
    assert.equal(payload.htm, "POST");
    assert.equal(payload.htu, "https://rs.example.com/hook");
    assert.equal(payload.iat, Math.floor(Date.UTC(2026, 9, 23, 10, 0, 0) / 1000));
    assert.equal(payload.jti, "fixed-jti-1");
    assert.equal(payload.ath, undefined, "token-request proofs carry no ath");
    assert.equal(payload.nonce, undefined);
    assert.ok(verifyDpopProof(proof, publicKey, "Ed25519"), "the proof must verify under the public key");
  });

  it("builds an ES256 proof with a P-256 JWK and a verifiable raw R||S signature", () => {
    const { privatePem, publicKey } = p256KeyPair();
    const dpop = resolvedDpop(privatePem, "ES256", "p256-key");
    const proof = buildDpopProofJwt({
      dpop,
      htm: "POST",
      htu: "https://rs.example.com/token",
      accessToken: "dpop-access-token-1",
    });
    const { header, payload } = decodeJwt(proof);
    assert.equal(header.typ, "dpop+jwt");
    assert.equal(header.alg, "ES256");
    const jwk = header.jwk as Record<string, unknown>;
    assert.equal(jwk.kty, "EC");
    assert.equal(jwk.crv, "P-256");
    assert.ok(typeof jwk.x === "string" && typeof jwk.y === "string");
    assert.ok(verifyDpopProof(proof, publicKey, "ES256"), "the ES256 proof must verify");
  });

  it("binds the access token with ath on resource proofs", () => {
    const { privatePem } = edKeyPair();
    const dpop = resolvedDpop(privatePem, "Ed25519");
    const token = "the-access-token";
    const withToken = buildDpopProofJwt({ dpop, htm: "POST", htu: "https://rs.example.com/", accessToken: token });
    const withoutToken = buildDpopProofJwt({ dpop, htm: "POST", htu: "https://rs.example.com/" });
    assert.equal(decodeJwt(withToken).payload.ath, sha256b64u(token));
    assert.equal(decodeJwt(withoutToken).payload.ath, undefined);
  });

  it("mints a unique jti per proof unless one is injected", () => {
    const { privatePem } = edKeyPair();
    const dpop = resolvedDpop(privatePem, "Ed25519");
    const input = { dpop, htm: "POST" as const, htu: "https://rs.example.com/", nowMs: 1_000_000 };
    const a = decodeJwt(buildDpopProofJwt(input)).payload.jti as string;
    const b = decodeJwt(buildDpopProofJwt(input)).payload.jti as string;
    assert.ok(typeof a === "string" && a.length >= 16);
    assert.notEqual(a, b, "proofs must never share a jti");
    const fixed = decodeJwt(buildDpopProofJwt({ ...input, jti: "injected" })).payload.jti;
    assert.equal(fixed, "injected");
  });

  it("carries the server nonce after a use_dpop_nonce challenge", () => {
    const { privatePem } = edKeyPair();
    const dpop = resolvedDpop(privatePem, "Ed25519");
    const proof = buildDpopProofJwt({
      dpop,
      htm: "POST",
      htu: TOKEN_ENDPOINT,
      nonce: "server-nonce-abc",
    });
    assert.equal(decodeJwt(proof).payload.nonce, "server-nonce-abc");
  });

  it("rejects invalid proof inputs", () => {
    const { privatePem } = edKeyPair();
    const dpop = resolvedDpop(privatePem, "Ed25519");
    const good = { dpop, htm: "POST", htu: "https://rs.example.com/" };
    assert.throws(() => buildDpopProofJwt({ ...good, htu: "not-a-url" }), RangeError);
    assert.throws(() => buildDpopProofJwt({ ...good, htu: "ftp://rs.example.com/" }), RangeError);
    assert.throws(() => buildDpopProofJwt({ ...good, htm: "" }), RangeError);
    assert.throws(() => buildDpopProofJwt({ ...good, accessToken: "" }), RangeError);
    assert.throws(() => buildDpopProofJwt({ ...good, nonce: "" }), RangeError);
    assert.throws(() => buildDpopProofJwt({ ...good, jti: "" }), RangeError);
    assert.throws(() => buildDpopProofJwt(null as never), TypeError);
    assert.throws(
      () => buildDpopProofJwt({ ...good, dpop: { alg: "Ed25519" } as never }),
      TypeError
    );
  });
});

describe("WR-205: jkt thumbprint (RFC 7638)", () => {
  it("precomputes the JWK SHA-256 thumbprint at startup", () => {
    const { privatePem } = edKeyPair();
    const dpop = resolvedDpop(privatePem, "Ed25519");
    // Independent recomputation over the RFC 7638 canonical form.
    const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${dpop.jwk.x}"}`;
    assert.equal(dpop.jkt, sha256b64u(canonical));
    assert.equal(dpopJwkThumbprint(dpop.jwk), dpop.jkt);
  });

  it("is stable per key and distinct across keys and algorithms", () => {
    const a = edKeyPair();
    const b = edKeyPair();
    const p256 = p256KeyPair();
    const jktA1 = resolvedDpop(a.privatePem, "Ed25519").jkt;
    const jktA2 = resolvedDpop(a.privatePem, "Ed25519").jkt;
    assert.equal(jktA1, jktA2, "the same key must always produce the same jkt");
    assert.notEqual(jktA1, resolvedDpop(b.privatePem, "Ed25519").jkt);
    const p256dpop = resolvedDpop(p256.privatePem, "ES256");
    const canonical = `{"crv":"P-256","kty":"EC","x":"${p256dpop.jwk.x}","y":"${p256dpop.jwk.y}"}`;
    assert.equal(p256dpop.jkt, sha256b64u(canonical));
  });
});

describe("WR-205: config validation (startup fail-fast)", () => {
  it("rejects bad DPoP keys at startup", () => {
    const { privatePem: edPem } = edKeyPair();
    const { privatePem: p256Pem } = p256KeyPair();
    const { privateKey: rsaKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPem = rsaKey.export({ type: "pkcs8", format: "pem" }) as string;
    const { privateKey: k1Key } = generateKeyPairSync("ec", { namedCurve: "secp256k1" });
    const k1Pem = k1Key.export({ type: "pkcs8", format: "pem" }) as string;
    const { privateKey: p384Key } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const p384Pem = p384Key.export({ type: "pkcs8", format: "pem" }) as string;

    const dpopOf = (dpop: unknown): OAuth2ClientCredentialsConfig => ({
      token_endpoint: TOKEN_ENDPOINT,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET_VALUE,
      dpop: dpop as DpopKeyConfig,
    });
    // Not a PEM at all.
    assert.throws(() => resolveOAuth2ClientConfig(dpopOf({ privateKey: "not-a-key", alg: "Ed25519" }), "test"), RangeError);
    // Wrong key type for the algorithm.
    assert.throws(() => resolveOAuth2ClientConfig(dpopOf({ privateKey: rsaPem, alg: "Ed25519" }), "test"), RangeError);
    assert.throws(() => resolveOAuth2ClientConfig(dpopOf({ privateKey: edPem, alg: "ES256" }), "test"), RangeError);
    // Wrong curve for ES256.
    assert.throws(() => resolveOAuth2ClientConfig(dpopOf({ privateKey: k1Pem, alg: "ES256" }), "test"), RangeError);
    assert.throws(() => resolveOAuth2ClientConfig(dpopOf({ privateKey: p384Pem, alg: "ES256" }), "test"), RangeError);
    // Unknown algorithm / empty key / empty key id / non-object.
    assert.throws(() => resolveOAuth2ClientConfig(dpopOf({ privateKey: edPem, alg: "RS256" }), "test"), RangeError);
    assert.throws(() => resolveOAuth2ClientConfig(dpopOf({ privateKey: "", alg: "Ed25519" }), "test"), RangeError);
    assert.throws(
      () => resolveOAuth2ClientConfig(dpopOf({ privateKey: edPem, alg: "Ed25519", keyId: "" }), "test"),
      RangeError
    );
    assert.throws(() => resolveOAuth2ClientConfig(dpopOf("nope"), "test"), RangeError);
    // Sanity: the good shapes resolve.
    assert.ok(resolveOAuth2ClientConfig(dpopOf({ privateKey: edPem, alg: "Ed25519" }), "test").dpop);
    assert.ok(resolveOAuth2ClientConfig(dpopOf({ privateKey: p256Pem, alg: "ES256" }), "test").dpop);
  });

  it("composes with either client authentication method (orthogonal to WR-189)", () => {
    const { privatePem: dpopPem } = edKeyPair();
    const { privatePem: assertPem } = edKeyPair();
    const withAssertion: OAuth2ClientCredentialsConfig = {
      token_endpoint: TOKEN_ENDPOINT,
      client_id: CLIENT_ID,
      private_key_jwt: { privateKey: assertPem, keyId: "assert-key", alg: "Ed25519" },
      dpop: { privateKey: dpopPem, keyId: "dpop-key", alg: "Ed25519" },
    };
    const resolved = resolveOAuth2ClientConfig(withAssertion, "test");
    assert.ok(resolved.assertion !== undefined, "WR-189 assertion still resolves");
    assert.ok(resolved.dpop !== undefined, "WR-205 DPoP key resolves alongside it");
    assert.notEqual(resolved.assertion.privateKey, resolved.dpop.privateKey);
  });
});

describe("WR-205: token endpoint integration", () => {
  it("sends the token-request proof without ath and accepts token_type DPoP", async () => {
    const seen: Array<{ headers: Record<string, string | string[] | undefined> }> = [];
    const stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        seen.push({ headers: req.headers });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ access_token: "dpop-tok-1", token_type: DPOP_TOKEN_TYPE, expires_in: 3600 }));
      });
    });
    const port = await listen(stub);
    const { privatePem, publicKey } = edKeyPair();
    const resolved = resolveOAuth2ClientConfig(
      { ...dpopConfig(privatePem, "Ed25519"), token_endpoint: `http://127.0.0.1:${port}/token` },
      "test"
    );
    const proof = buildDpopProofJwt({
      dpop: resolved.dpop!,
      htm: "POST",
      htu: `http://127.0.0.1:${port}/token`,
    });
    const resp = await defaultOAuth2TokenFetcher({
      tokenEndpoint: resolved.tokenEndpoint,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET_VALUE,
      dpopProofJwt: proof,
      timeoutMs: 5000,
    });
    assert.equal(resp.access_token, "dpop-tok-1");
    assert.equal(seen.length, 1);
    assert.equal(seen[0].headers[DPOP_PROOF_HEADER.toLowerCase()], proof);
    const sent = decodeJwt(seen[0].headers[DPOP_PROOF_HEADER.toLowerCase()] as string);
    assert.equal(sent.payload.ath, undefined, "the token-request proof carries no ath");
    assert.equal(sent.payload.htm, "POST");
    assert.ok(verifyDpopProof(proof, publicKey, "Ed25519"));
    await close(stub);
  });

  it("fails closed when the endpoint answers Bearer for a DPoP proof (binding confirmation)", async () => {
    const stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ access_token: "tok-1", token_type: "Bearer", expires_in: 3600 }));
      });
    });
    const port = await listen(stub);
    const { privatePem } = edKeyPair();
    const resolved = resolveOAuth2ClientConfig(
      { ...dpopConfig(privatePem, "Ed25519"), token_endpoint: `http://127.0.0.1:${port}/token` },
      "test"
    );
    const proof = buildDpopProofJwt({ dpop: resolved.dpop!, htm: "POST", htu: `http://127.0.0.1:${port}/token` });
    await assert.rejects(
      defaultOAuth2TokenFetcher({
        tokenEndpoint: resolved.tokenEndpoint,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET_VALUE,
        dpopProofJwt: proof,
        timeoutMs: 5000,
      }),
      (err: unknown) =>
        err instanceof OAuth2TokenError &&
        /token_type.*DPoP/.test(err.message) &&
        !err.message.includes(proof)
    );
    await close(stub);
  });

  it("the proof never appears in fetcher error messages", async () => {
    const stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        res.writeHead(500, { "content-type": "text/plain" }).end("boom");
      });
    });
    const port = await listen(stub);
    const knownProof = "known-header.known-payload.known-signature";
    const err = await defaultOAuth2TokenFetcher({
      tokenEndpoint: new URL(`http://127.0.0.1:${port}/token`),
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET_VALUE,
      dpopProofJwt: knownProof,
      timeoutMs: 5000,
    }).then(
      () => null,
      (e: unknown) => e
    );
    assert.ok(err instanceof OAuth2TokenError);
    assert.ok(!err.message.includes(knownProof), "the proof must never leak into error messages");
    assert.ok(err.message.includes("HTTP 500"), "the error still names the status");
    await close(stub);
  });

  it("tokenFor attaches the proof and isolates the cache per DPoP key", async () => {
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      fetchToken: async (params) => {
        seen.push(params);
        return { access_token: `tok-${seen.length}`, token_type: DPOP_TOKEN_TYPE, expires_in: 3600 };
      },
    });
    const { privatePem: pemA } = edKeyPair();
    const { privatePem: pemB } = edKeyPair();
    const cfgA = dpopConfig(pemA, "Ed25519", "key-a");
    const cfgB = dpopConfig(pemB, "Ed25519", "key-b");
    const t1 = await cache.tokenFor(cfgA);
    const t1again = await cache.tokenFor(cfgA);
    const t2 = await cache.tokenFor(cfgB);
    assert.equal(t1, "tok-1");
    assert.equal(t1again, "tok-1", "cached token must be reused");
    assert.equal(t2, "tok-2", "a different DPoP key must not share the cached token");
    assert.equal(seen.length, 2);
    assert.equal(cache.size(), 2);
    const proof = decodeJwt(seen[0].dpopProofJwt!);
    assert.equal(proof.payload.htm, "POST");
    assert.equal(proof.payload.htu, TOKEN_ENDPOINT);
    assert.equal(proof.payload.ath, undefined);
    assert.equal(seen[0].clientSecret, CLIENT_SECRET_VALUE);
  });

  it("retries once on a use_dpop_nonce challenge and then leads with the nonce", async () => {
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      fetchToken: async (params) => {
        seen.push(params);
        if (seen.length === 1) {
          throw new OAuth2TokenError("oauth2 token request failed: x -> HTTP 400", {
            statusCode: 400,
            dpopNonce: "server-nonce-1",
          });
        }
        return { access_token: `tok-${seen.length}`, token_type: DPOP_TOKEN_TYPE, expires_in: 3600 };
      },
    });
    const { privatePem } = edKeyPair();
    const cfg = dpopConfig(privatePem, "Ed25519");
    const token = await cache.tokenFor(cfg);
    assert.equal(token, "tok-2");
    assert.equal(seen.length, 2, "exactly one nonce retry");
    assert.equal(decodeJwt(seen[0].dpopProofJwt!).payload.nonce, undefined);
    assert.equal(decodeJwt(seen[1].dpopProofJwt!).payload.nonce, "server-nonce-1");
    assert.notEqual(
      decodeJwt(seen[0].dpopProofJwt!).payload.jti,
      decodeJwt(seen[1].dpopProofJwt!).payload.jti,
      "the retry uses a fresh proof, never a replay"
    );
    // The nonce is remembered: a forced refresh leads with it, no challenge needed.
    await cache.refreshFor(cfg);
    assert.equal(seen.length, 3);
    assert.equal(decodeJwt(seen[2].dpopProofJwt!).payload.nonce, "server-nonce-1");
  });

  it("gives up after one nonce retry instead of looping", async () => {
    let calls = 0;
    const cache = new OAuth2TokenCache({
      fetchToken: async () => {
        calls += 1;
        throw new OAuth2TokenError("oauth2 token request failed: x -> HTTP 400", {
          statusCode: 400,
          dpopNonce: `nonce-${calls}`,
        });
      },
    });
    const { privatePem } = edKeyPair();
    await assert.rejects(cache.tokenFor(dpopConfig(privatePem, "Ed25519")), OAuth2TokenError);
    assert.equal(calls, 2, "one initial attempt plus exactly one retry");
  });

  it("handles a real HTTP use_dpop_nonce round-trip against a stub", async () => {
    let hits = 0;
    const stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        hits += 1;
        if (hits === 1) {
          res.writeHead(400, {
            "content-type": "application/json",
            "DPoP-Nonce": "http-nonce-1",
          });
          res.end(JSON.stringify({ error: "use_dpop_nonce" }));
        } else {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ access_token: "dpop-tok", token_type: "DPoP", expires_in: 3600 }));
        }
      });
    });
    const port = await listen(stub);
    const { privatePem } = edKeyPair();
    const cache = new OAuth2TokenCache();
    const token = await cache.tokenFor({
      ...dpopConfig(privatePem, "Ed25519"),
      token_endpoint: `http://127.0.0.1:${port}/token`,
    });
    assert.equal(token, "dpop-tok");
    assert.equal(hits, 2, "challenge then retry");
    await close(stub);
  });
});

describe("WR-205: orthogonality with WR-189 private_key_jwt", () => {
  it("token request carries both the client assertion and the DPoP proof", async () => {
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      fetchToken: async (params) => {
        seen.push(params);
        return { access_token: "tok", token_type: DPOP_TOKEN_TYPE, expires_in: 3600 };
      },
    });
    const { privatePem: dpopPem } = edKeyPair();
    const { privatePem: assertPem } = edKeyPair();
    const cfg: OAuth2ClientCredentialsConfig = {
      token_endpoint: TOKEN_ENDPOINT,
      client_id: CLIENT_ID,
      private_key_jwt: { privateKey: assertPem, keyId: "assert-key", alg: "Ed25519" },
      dpop: { privateKey: dpopPem, keyId: "dpop-key", alg: "Ed25519" },
    };
    await cache.tokenFor(cfg);
    assert.equal(seen.length, 1);
    assert.ok(seen[0].clientAssertionJwt !== undefined, "the WR-189 assertion is sent");
    assert.ok(seen[0].dpopProofJwt !== undefined, "the WR-205 proof is sent alongside it");
    assert.equal(seen[0].clientSecret, undefined);
    const assertionParts = seen[0].clientAssertionJwt!.split(".");
    const proofParts = seen[0].dpopProofJwt!.split(".");
    assert.equal(assertionParts.length, 3);
    assert.equal(proofParts.length, 3);
    assert.notEqual(seen[0].clientAssertionJwt, seen[0].dpopProofJwt);
  });
});

interface SeenDpopDelivery {
  authorization: string | undefined;
  dpop: string | undefined;
}

async function stubDpopTokenEndpoint(): Promise<{
  server: Server;
  url: string;
  tokenProofs: string[];
}> {
  const tokenProofs: string[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const proof = req.headers[DPOP_PROOF_HEADER.toLowerCase()];
      if (typeof proof === "string") tokenProofs.push(proof);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "dpop-wire-token", token_type: DPOP_TOKEN_TYPE, expires_in: 3600 }));
    });
  });
  const port = await listen(server);
  return { server, url: `http://127.0.0.1:${port}/token`, tokenProofs };
}

async function stubDpopDownstream(): Promise<{
  server: Server;
  url: string;
  seen: SeenDpopDelivery[];
}> {
  const seen: SeenDpopDelivery[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      seen.push({
        authorization: req.headers["authorization"] as string | undefined,
        dpop: req.headers[DPOP_PROOF_HEADER.toLowerCase()] as string | undefined,
      });
      res.writeHead(200, { "content-type": "text/plain" }).end("ok");
    });
  });
  const port = await listen(server);
  return { server, url: `http://127.0.0.1:${port}/hook`, seen };
}

function makeSender(oauth2: Record<string, OAuth2ClientCredentialsConfig>) {
  const args = Array(33).fill(undefined) as Parameters<typeof createDefaultSender>;
  args[31] = oauth2;
  return createDefaultSender(...args);
}

function deliveryItem(targetUrl: string, id: string, headers: Record<string, string> = {}): RetryItem {
  return { id, payload: Buffer.from(JSON.stringify({ n: id })), targetUrl, headers };
}

describe("WR-205: sender wire format (resource proof)", () => {
  it("stamps Authorization: DPoP plus a per-request proof bound to the token", async () => {
    const tokenEp = await stubDpopTokenEndpoint();
    const downstream = await stubDpopDownstream();
    const { privatePem, publicKey } = edKeyPair();
    try {
      const sender = makeSender({
        [downstream.url]: {
          token_endpoint: tokenEp.url,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET_VALUE,
          dpop: { privateKey: privatePem, keyId: "wire-key", alg: "Ed25519" },
        },
      });
      try {
        const res = await sender(deliveryItem(downstream.url, "d1"));
        assert.equal(res?.statusCode, 200);
        assert.equal(downstream.seen.length, 1);
        const seen = downstream.seen[0];
        assert.equal(seen.authorization, "DPoP dpop-wire-token");
        assert.ok(typeof seen.dpop === "string");
        const { header, payload } = decodeJwt(seen.dpop!);
        assert.equal(header.typ, "dpop+jwt");
        assert.equal(payload.htm, "POST");
        assert.equal(payload.htu, downstream.url);
        assert.equal(payload.ath, sha256b64u("dpop-wire-token"));
        assert.ok(verifyDpopProof(seen.dpop!, publicKey, "Ed25519"));
        // The token request carried the other proof: same key, no ath.
        assert.equal(tokenEp.tokenProofs.length, 1);
        const tokenProof = decodeJwt(tokenEp.tokenProofs[0]);
        assert.equal(tokenProof.payload.ath, undefined);
        assert.notEqual(tokenEp.tokenProofs[0], seen.dpop, "token and resource proofs differ");
      } finally {
        sender.destroy();
      }
    } finally {
      await close(tokenEp.server);
      await close(downstream.server);
    }
  });

  it("strips a forged inbound dpop header (anti-forgery)", async () => {
    const tokenEp = await stubDpopTokenEndpoint();
    const downstream = await stubDpopDownstream();
    const { privatePem, publicKey } = edKeyPair();
    try {
      const sender = makeSender({
        [downstream.url]: {
          token_endpoint: tokenEp.url,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET_VALUE,
          dpop: { privateKey: privatePem, alg: "Ed25519" },
        },
      });
      try {
        const res = await sender(
          deliveryItem(downstream.url, "d1", {
            dpop: "forged-proof",
            authorization: "Bearer forged-token",
          })
        );
        assert.equal(res?.statusCode, 200);
        assert.equal(downstream.seen.length, 1);
        const seen = downstream.seen[0];
        assert.equal(seen.authorization, "DPoP dpop-wire-token");
        assert.notEqual(seen.dpop, "forged-proof");
        assert.ok(verifyDpopProof(seen.dpop!, publicKey, "Ed25519"), "the relay's own proof wins");
      } finally {
        sender.destroy();
      }
    } finally {
      await close(tokenEp.server);
      await close(downstream.server);
    }
  });

  it("mints a fresh proof jti per delivery", async () => {
    const tokenEp = await stubDpopTokenEndpoint();
    const downstream = await stubDpopDownstream();
    const { privatePem } = edKeyPair();
    try {
      const sender = makeSender({
        [downstream.url]: {
          token_endpoint: tokenEp.url,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET_VALUE,
          dpop: { privateKey: privatePem, alg: "Ed25519" },
        },
      });
      try {
        await sender(deliveryItem(downstream.url, "d1"));
        await sender(deliveryItem(downstream.url, "d2"));
        assert.equal(downstream.seen.length, 2);
        const jti1 = decodeJwt(downstream.seen[0].dpop!).payload.jti;
        const jti2 = decodeJwt(downstream.seen[1].dpop!).payload.jti;
        assert.notEqual(jti1, jti2);
        // One token fetch served both deliveries (cached token, fresh proofs).
        assert.equal(tokenEp.tokenProofs.length, 1);
      } finally {
        sender.destroy();
      }
    } finally {
      await close(tokenEp.server);
      await close(downstream.server);
    }
  });

  it("rejects a DPoP oauth2 entry with a bad key at sender startup", () => {
    assert.throws(
      () =>
        makeSender({
          "http://x.example.test/hook": {
            token_endpoint: TOKEN_ENDPOINT,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET_VALUE,
            dpop: { privateKey: "not-a-key", alg: "Ed25519" },
          },
        }),
      RangeError
    );
  });
});
