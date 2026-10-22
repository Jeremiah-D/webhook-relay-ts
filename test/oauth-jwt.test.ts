import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createPublicKey,
  generateKeyPairSync,
  verify as cryptoVerify,
} from "node:crypto";
import { createServer, type Server } from "node:http";
import {
  buildPrivateKeyJwtAssertion,
  defaultOAuth2TokenFetcher,
  OAuth2TokenCache,
  PRIVATE_KEY_JWT_ASSERTION_TYPE,
  PRIVATE_KEY_JWT_EXPIRY_SECONDS,
  resolveOAuth2ClientConfig,
  type OAuth2ClientCredentialsConfig,
  type OAuth2TokenFetchParams,
} from "../src/oauth-client.ts";

const TOKEN_ENDPOINT = "https://auth.example.com/oauth/token";
const CLIENT_ID = "relay-client-1";
const SCOPE = "webhooks:write";

function ed25519Pair(): { privatePem: string; publicKey: ReturnType<typeof createPublicKey> } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicKey,
  };
}

function rsaPair(): { privatePem: string; publicKey: ReturnType<typeof createPublicKey> } {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicKey,
  };
}

function assertionConfig(
  pem: string,
  alg: "Ed25519" | "RS256",
  keyId = "key-1"
): OAuth2ClientCredentialsConfig {
  return {
    token_endpoint: TOKEN_ENDPOINT,
    client_id: CLIENT_ID,
    private_key_jwt: { privateKey: pem, keyId, alg },
    scope: SCOPE,
  };
}

function decodeJwt(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const [h, p] = jwt.split(".");
  return {
    header: JSON.parse(Buffer.from(h, "base64url").toString("utf8")),
    payload: JSON.parse(Buffer.from(p, "base64url").toString("utf8")),
  };
}

function verifyJwt(
  jwt: string,
  publicKey: ReturnType<typeof createPublicKey>,
  alg: "Ed25519" | "RS256"
): boolean {
  const [h, p, s] = jwt.split(".");
  const data = Buffer.from(`${h}.${p}`, "utf8");
  const sig = Buffer.from(s, "base64url");
  // Ed25519 signs the raw message (no pre-hash): digest must be null.
  return alg === "Ed25519"
    ? cryptoVerify(null, data, publicKey, sig)
    : cryptoVerify("RSA-SHA256", data, publicKey, sig);
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

describe("WR-189: private_key_jwt assertion construction", () => {
  it("builds an Ed25519 assertion with RFC 7523 claims and a verifiable signature", () => {
    const { privatePem, publicKey } = ed25519Pair();
    const resolved = resolveOAuth2ClientConfig(assertionConfig(privatePem, "Ed25519"), "test");
    assert.ok(resolved.assertion !== undefined);
    const jwt = buildPrivateKeyJwtAssertion({
      clientId: CLIENT_ID,
      tokenEndpoint: TOKEN_ENDPOINT,
      assertion: resolved.assertion,
      nowMs: Date.UTC(2026, 9, 22, 14, 0, 0),
    });
    const { header, payload } = decodeJwt(jwt);
    assert.equal(header.alg, "EdDSA");
    assert.equal(header.typ, "JWT");
    assert.equal(header.kid, "key-1");
    assert.equal(payload.iss, CLIENT_ID);
    assert.equal(payload.sub, CLIENT_ID);
    assert.equal(payload.aud, TOKEN_ENDPOINT);
    assert.ok(typeof payload.jti === "string" && payload.jti.length >= 16);
    assert.equal(payload.exp - payload.iat, PRIVATE_KEY_JWT_EXPIRY_SECONDS);
    assert.ok(verifyJwt(jwt, publicKey, "Ed25519"), "the assertion must verify under the public key");
  });

  it("builds an RS256 assertion verifiable with the RSA public key", () => {
    const { privatePem, publicKey } = rsaPair();
    const resolved = resolveOAuth2ClientConfig(assertionConfig(privatePem, "RS256", "rsa-key"), "test");
    const jwt = buildPrivateKeyJwtAssertion({
      clientId: CLIENT_ID,
      tokenEndpoint: TOKEN_ENDPOINT,
      assertion: resolved.assertion!,
    });
    const { header } = decodeJwt(jwt);
    assert.equal(header.alg, "RS256");
    assert.equal(header.kid, "rsa-key");
    assert.ok(verifyJwt(jwt, publicKey, "RS256"));
  });

  it("omits kid when no keyId is configured and mints a fresh jti per build", () => {
    const { privatePem } = ed25519Pair();
    const resolved = resolveOAuth2ClientConfig(
      { ...assertionConfig(privatePem, "Ed25519"), private_key_jwt: { privateKey: privatePem, alg: "Ed25519" } },
      "test"
    );
    const a = buildPrivateKeyJwtAssertion({
      clientId: CLIENT_ID,
      tokenEndpoint: TOKEN_ENDPOINT,
      assertion: resolved.assertion!,
      nowMs: 1_000_000,
      jti: "fixed-jti",
    });
    const b = buildPrivateKeyJwtAssertion({
      clientId: CLIENT_ID,
      tokenEndpoint: TOKEN_ENDPOINT,
      assertion: resolved.assertion!,
      nowMs: 1_000_000,
    });
    assert.equal(decodeJwt(a).header.kid, undefined);
    assert.equal(decodeJwt(a).payload.jti, "fixed-jti");
    assert.notEqual(decodeJwt(b).payload.jti, "fixed-jti");
  });
});

describe("WR-189: config validation", () => {
  it("rejects both or neither authentication method", () => {
    const { privatePem } = ed25519Pair();
    const both: OAuth2ClientCredentialsConfig = {
      ...assertionConfig(privatePem, "Ed25519"),
      client_secret: "shh",
    };
    assert.throws(() => resolveOAuth2ClientConfig(both, "test"), RangeError);
    const neither: OAuth2ClientCredentialsConfig = {
      token_endpoint: TOKEN_ENDPOINT,
      client_id: CLIENT_ID,
    };
    assert.throws(() => resolveOAuth2ClientConfig(neither, "test"), RangeError);
  });

  it("rejects bad keys and algorithms at startup", () => {
    const { privatePem: edPem } = ed25519Pair();
    const { privatePem: rsaPem } = rsaPair();
    // Not a PEM at all.
    assert.throws(
      () => resolveOAuth2ClientConfig(assertionConfig("not-a-key", "Ed25519"), "test"),
      RangeError
    );
    // Wrong key type for the algorithm.
    assert.throws(
      () => resolveOAuth2ClientConfig(assertionConfig(edPem, "RS256"), "test"),
      RangeError
    );
    assert.throws(
      () => resolveOAuth2ClientConfig(assertionConfig(rsaPem, "Ed25519"), "test"),
      RangeError
    );
    // Unknown algorithm.
    assert.throws(
      () =>
        resolveOAuth2ClientConfig(
          { ...assertionConfig(edPem, "Ed25519"), private_key_jwt: { privateKey: edPem, alg: "ES256" as never } },
          "test"
        ),
      RangeError
    );
    // Empty key id.
    assert.throws(
      () =>
        resolveOAuth2ClientConfig(
          { ...assertionConfig(edPem, "Ed25519"), private_key_jwt: { privateKey: edPem, alg: "Ed25519", keyId: "" } },
          "test"
        ),
      RangeError
    );
  });
});

describe("WR-189: token fetch with client_assertion", () => {
  it("posts client_assertion instead of client_secret to a stub token endpoint", async () => {
    const captured: Array<{ body: string }> = [];
    const stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        captured.push({ body: Buffer.concat(chunks).toString("utf8") });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ access_token: "tok-1", token_type: "Bearer", expires_in: 3600 }));
      });
    });
    const port = await listen(stub);
    const { privatePem, publicKey } = ed25519Pair();
    const resolved = resolveOAuth2ClientConfig(
      { ...assertionConfig(privatePem, "Ed25519"), token_endpoint: `http://127.0.0.1:${port}/token` },
      "test"
    );
    const jwt = buildPrivateKeyJwtAssertion({
      clientId: CLIENT_ID,
      tokenEndpoint: `http://127.0.0.1:${port}/token`,
      assertion: resolved.assertion!,
    });
    const resp = await defaultOAuth2TokenFetcher({
      tokenEndpoint: resolved.tokenEndpoint,
      clientId: CLIENT_ID,
      clientAssertionJwt: jwt,
      scope: SCOPE,
      timeoutMs: 5000,
    });
    assert.equal(resp.access_token, "tok-1");
    assert.equal(captured.length, 1);
    const form = new URLSearchParams(captured[0].body);
    assert.equal(form.get("grant_type"), "client_credentials");
    assert.equal(form.get("client_assertion_type"), PRIVATE_KEY_JWT_ASSERTION_TYPE);
    assert.equal(form.get("client_assertion"), jwt);
    assert.equal(form.get("client_secret"), null, "the secret path must stay unused");
    assert.ok(verifyJwt(jwt, publicKey, "Ed25519"));
    await close(stub);
  });

  it("tokenFor builds a fresh assertion per fetch and caches the token", async () => {
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      fetchToken: async (params) => {
        seen.push(params);
        return { access_token: `tok-${seen.length}`, expires_in: 3600 };
      },
    });
    const { privatePem } = ed25519Pair();
    const cfg = assertionConfig(privatePem, "Ed25519");
    const t1 = await cache.tokenFor(cfg);
    const t2 = await cache.tokenFor(cfg);
    assert.equal(t1, "tok-1");
    assert.equal(t2, "tok-1", "cached token must be reused");
    assert.equal(seen.length, 1, "one fetch for two calls");
    assert.ok(seen[0].clientAssertionJwt !== undefined, "the fetcher must receive the assertion");
    assert.equal(seen[0].clientSecret, undefined, "no secret may travel for assertion configs");
  });

  it("single-flight shares one fetch across concurrent callers", async () => {
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      fetchToken: async (params) => {
        seen.push(params);
        await new Promise((r) => setTimeout(r, 20));
        return { access_token: "tok-shared", expires_in: 3600 };
      },
    });
    const rsa = rsaPair();
    const rsaCfg = assertionConfig(rsa.privatePem, "RS256", "k2");
    const [a, b] = await Promise.all([cache.tokenFor(rsaCfg), cache.tokenFor(rsaCfg)]);
    assert.equal(a, "tok-shared");
    assert.equal(b, "tok-shared");
    assert.equal(seen.length, 1, "concurrent callers share one in-flight fetch");
  });

  it("refreshFor mints a new assertion (fresh jti) for the 401 path", async () => {
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      nowMs: () => 5_000_000,
      fetchToken: async (params) => {
        seen.push(params);
        return { access_token: `tok-${seen.length}`, expires_in: 1 }; // 1s: below the 30s skew, expires immediately
      },
    });
    const { privatePem } = ed25519Pair();
    const cfg = assertionConfig(privatePem, "Ed25519");
    const t1 = await cache.tokenFor(cfg);
    const t2 = await cache.refreshFor(cfg);
    assert.notEqual(t1, t2);
    assert.equal(seen.length, 2);
    const jti = (p: OAuth2TokenFetchParams) =>
      (decodeJwt(p.clientAssertionJwt!).payload.jti as string);
    assert.notEqual(jti(seen[0]), jti(seen[1]), "each fetch must carry a fresh assertion");
  });

  it("client_secret configs are untouched: secret still flows, no assertion", async () => {
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      fetchToken: async (params) => {
        seen.push(params);
        return { access_token: "tok", expires_in: 3600 };
      },
    });
    const secretCfg: OAuth2ClientCredentialsConfig = {
      token_endpoint: TOKEN_ENDPOINT,
      client_id: CLIENT_ID,
      client_secret: "shh",
    };
    await cache.tokenFor(secretCfg);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].clientSecret, "shh");
    assert.equal(seen[0].clientAssertionJwt, undefined);
  });
});
