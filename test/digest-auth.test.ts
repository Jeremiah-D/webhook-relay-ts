import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  DigestAuthError,
  DigestAuthSession,
  assertValidDigestAuthConfig,
  buildDigestAuthorization,
  computeDigestResponse,
  digestUriFor,
  formatNonceCount,
  parseDigestChallenge,
  type DigestChallenge,
  type DigestFetchResponse,
} from "../src/digest-auth.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.
const testUsername = "Mufasa";
const testPassword = "Circle Of Life";
const testRealm = "testrealm@host.com";
const testNonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
const testUri = "/dir/index.html";
const testCnonce = "0a4f113b";

function md5Challenge(): DigestChallenge {
  return {
    realm: testRealm,
    nonce: testNonce,
    algorithm: "MD5",
    qop: "auth",
    stale: false,
  };
}

function challengeHeader(overrides: Record<string, string> = {}): string {
  const base: Record<string, string> = {
    realm: `"${testRealm}"`,
    nonce: `"${testNonce}"`,
    algorithm: "MD5",
    qop: "auth",
    opaque: `"5ccc069c403ebaf9f0171e9517f40e41"`,
  };
  const merged = { ...base, ...overrides };
  return `Digest ${Object.entries(merged)
    .map(([k, v]) => `${k}=${v}`)
    .join(", ")}`;
}

function sessionWithPassword(
  password: string,
  extra: Record<string, unknown> = {}
): DigestAuthSession {
  return new DigestAuthSession({
    username: testUsername,
    passwordSecretRef: "unused-when-injected",
    passwordResolver: () => password,
    cnonceGenerator: () => testCnonce,
    ...extra,
  });
}

function headerParams(header: string): Record<string, string> {
  const params = header.replace(/^Digest\s+/i, "");
  const out: Record<string, string> = {};
  for (const part of params.split(/,(?=(?:[^"]|"[^"]*")*$)/)) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    out[part.slice(0, eq).trim()] = part
      .slice(eq + 1)
      .trim()
      .replace(/^"|"$/g, "");
  }
  return out;
}

describe("parseDigestChallenge", () => {
  it("parses a full challenge, picking auth from a qop list", () => {
    const parsed = parseDigestChallenge(
      'Digest realm="testrealm@host.com", nonce="abc", qop="auth, auth-int", algorithm=SHA-256, opaque="op", stale=false'
    );
    assert.equal(parsed.realm, testRealm);
    assert.equal(parsed.nonce, "abc");
    assert.equal(parsed.algorithm, "SHA-256");
    assert.equal(parsed.qop, "auth");
    assert.equal(parsed.opaque, "op");
    assert.equal(parsed.stale, false);
  });

  it("defaults an absent algorithm to MD5 and an absent qop to legacy", () => {
    const parsed = parseDigestChallenge('Digest realm="r", nonce="n"');
    assert.equal(parsed.algorithm, "MD5");
    assert.equal(parsed.qop, undefined);
  });

  it("keeps a comma inside a quoted realm intact", () => {
    const parsed = parseDigestChallenge('Digest realm="a, b", nonce="n"');
    assert.equal(parsed.realm, "a, b");
  });

  it("rejects a missing nonce, an unsupported algorithm, auth-int-only qop, and userhash", () => {
    assert.throws(() => parseDigestChallenge('Digest realm="r"'), DigestAuthError);
    assert.throws(
      () => parseDigestChallenge('Digest realm="r", nonce="n", algorithm=SHA-512'),
      DigestAuthError
    );
    assert.throws(
      () => parseDigestChallenge('Digest realm="r", nonce="n", qop="auth-int"'),
      DigestAuthError
    );
    assert.throws(
      () => parseDigestChallenge('Digest realm="r", nonce="n", userhash=true'),
      DigestAuthError
    );
    assert.throws(() => parseDigestChallenge("Basic realm=\"r\""), DigestAuthError);
  });
});

describe("computeDigestResponse / buildDigestAuthorization (RFC vectors)", () => {
  it("matches the RFC 2617 MD5 qop=auth vector", () => {
    const computed = computeDigestResponse({
      username: testUsername,
      password: testPassword,
      method: "GET",
      uri: testUri,
      challenge: md5Challenge(),
      nc: 1,
      cnonce: testCnonce,
    });
    // RFC 2617 section 3.5 example, recomputed independently with
    // node:crypto before this test was written.
    assert.equal(computed.response, "6629fae49393a05397450978507c4ef1");
    const header = buildDigestAuthorization({
      username: testUsername,
      password: testPassword,
      method: "GET",
      uri: testUri,
      challenge: md5Challenge(),
      nc: 1,
      cnonce: testCnonce,
    });
    const params = headerParams(header);
    assert.equal(params.username, testUsername);
    assert.equal(params.realm, testRealm);
    assert.equal(params.nonce, testNonce);
    assert.equal(params.uri, testUri);
    assert.equal(params.response, "6629fae49393a05397450978507c4ef1");
    assert.equal(params.qop, "auth");
    assert.equal(params.nc, "00000001");
    assert.equal(params.cnonce, testCnonce);
    assert.equal(params.algorithm, "MD5");
  });

  it("matches the RFC 7616 SHA-256 vector for the same inputs", () => {
    const computed = computeDigestResponse({
      username: testUsername,
      password: testPassword,
      method: "get",
      uri: testUri,
      challenge: {
        realm: testRealm,
        nonce: testNonce,
        algorithm: "SHA-256",
        qop: "auth",
        stale: false,
      },
      nc: 1,
      cnonce: testCnonce,
    });
    // Same inputs as the MD5 vector, SHA-256 hashes, recomputed
    // independently with node:crypto before this test was written.
    assert.equal(computed.response, "5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b");
  });

  it("uses the legacy form (no nc/cnonce/qop) when the challenge has no qop", () => {
    const computed = computeDigestResponse({
      username: testUsername,
      password: testPassword,
      method: "GET",
      uri: testUri,
      challenge: { realm: testRealm, nonce: testNonce, algorithm: "MD5", stale: false },
    });
    assert.equal(computed.response, "670fd8c2df070c60b045671b8b24ff02");
    const header = buildDigestAuthorization({
      username: testUsername,
      password: testPassword,
      method: "GET",
      uri: testUri,
      challenge: { realm: testRealm, nonce: testNonce, algorithm: "MD5", stale: false },
    });
    assert.ok(!header.includes("qop="));
    assert.ok(!header.includes("nc="));
    assert.ok(!header.includes("cnonce="));
  });

  it("never puts the password in an error message", () => {
    assert.throws(
      () =>
        computeDigestResponse({
          username: testUsername,
          password: "",
          method: "GET",
          uri: testUri,
          challenge: md5Challenge(),
        }),
      (err: unknown) => {
        assert.ok(err instanceof DigestAuthError);
        assert.ok(!err.message.includes(testPassword));
        return true;
      }
    );
  });
});

describe("formatNonceCount / digestUriFor", () => {
  it("formats counts as eight hex digits and rejects non-positive counts", () => {
    assert.equal(formatNonceCount(1), "00000001");
    assert.equal(formatNonceCount(255), "000000ff");
    assert.throws(() => formatNonceCount(0), RangeError);
  });

  it("derives path+query from an absolute URL and rejects garbage", () => {
    assert.equal(digestUriFor("https://example.com/hook?tenant=1"), "/hook?tenant=1");
    assert.equal(digestUriFor("https://example.com/hook"), "/hook");
    assert.throws(() => digestUriFor("not a url"), DigestAuthError);
  });
});

describe("DigestAuthSession", () => {
  it("validates config shape and fails fast on an unresolvable secret", () => {
    assert.throws(
      () => assertValidDigestAuthConfig({ username: "" }, "test"),
      RangeError
    );
    assert.throws(
      () =>
        new DigestAuthSession({
          username: testUsername,
          passwordSecretRef: "missing-ref",
          passwordResolver: () => "",
        }),
      RangeError
    );
  });

  it("increments the nonce count per nonce and resets it for a fresh nonce", () => {
    const session = sessionWithPassword(testPassword);
    const first = session.authorizationFor(challengeHeader(), "GET", testUri);
    const second = session.authorizationFor(challengeHeader(), "GET", testUri);
    assert.equal(headerParams(first).nc, "00000001");
    assert.equal(headerParams(second).nc, "00000002");
    assert.notEqual(headerParams(first).response, headerParams(second).response);
    const fresh = session.authorizationFor(
      challengeHeader({ nonce: `"other-nonce"` }),
      "GET",
      testUri
    );
    assert.equal(headerParams(fresh).nc, "00000001");
  });

  it("picks up a rotated password on the next authorization", () => {
    let current = testPassword;
    const session = new DigestAuthSession({
      username: testUsername,
      passwordSecretRef: "rotating-ref",
      passwordResolver: () => current,
      cnonceGenerator: () => testCnonce,
    });
    const before = session.authorizationFor(challengeHeader(), "GET", testUri);
    current = "a different password entirely";
    const after = session.authorizationFor(challengeHeader(), "GET", testUri);
    assert.notEqual(headerParams(before).response, headerParams(after).response);
  });

  it("throws a DigestAuthError (never the password) when the secret stops resolving", () => {
    let current: string | undefined = testPassword;
    const session = new DigestAuthSession({
      username: testUsername,
      passwordSecretRef: "flaky-ref",
      passwordResolver: () => current ?? "",
      cnonceGenerator: () => testCnonce,
    });
    current = undefined;
    assert.throws(
      () => session.authorizationFor(challengeHeader(), "GET", testUri),
      (err: unknown) => {
        assert.ok(err instanceof DigestAuthError);
        assert.ok(err.message.includes("flaky-ref"));
        assert.ok(!err.message.includes(testPassword));
        return true;
      }
    );
  });

  it("classifies DigestAuthError as non_retryable", () => {
    assert.equal(
      classifyFailure(new DigestAuthError("unsupported algorithm")).failureClass,
      "non_retryable"
    );
  });
});

describe("DigestAuthSession.fetchWithDigestAuth", () => {
  function stubFetch(
    seen: Array<{ url: string; headers: Record<string, string> }>,
    respond: (seenSoFar: Array<{ url: string; headers: Record<string, string> }>) => DigestFetchResponse
  ) {
    return async (
      url: string,
      init: { headers?: Record<string, string> }
    ): Promise<DigestFetchResponse> => {
      const entry = { url, headers: { ...(init.headers ?? {}) } };
      seen.push(entry);
      return respond(seen);
    };
  }

  function headerMap(value: string | null): { get(name: string): string | null } {
    return {
      get: (name: string) =>
        name.toLowerCase() === "www-authenticate" ? value : null,
    };
  }

  it("sends the plain attempt first, then retries with the Digest header", async () => {
    const seen: Array<{ url: string; headers: Record<string, string> }> = [];
    const fetchFn = stubFetch(seen, (soFar) => {
      if (soFar.length === 1) {
        return { status: 401, headers: headerMap(challengeHeader()) };
      }
      return { status: 200, headers: headerMap(null) };
    });
    const session = sessionWithPassword(testPassword);
    const response = await session.fetchWithDigestAuth(
      fetchFn,
      "https://example.com/hook?tenant=1",
      { method: "POST" }
    );
    assert.equal(response.status, 200);
    assert.equal(seen.length, 2);
    assert.equal(seen[0].headers.Authorization, undefined);
    const params = headerParams(seen[1].headers.Authorization ?? "");
    // POST hashes a different method than the GET vector, so the
    // response differs from it — but it must be a full MD5 hex hash
    // and the header shape must be complete.
    assert.match(params.response, /^[0-9a-f]{32}$/);
    assert.equal(params.username, testUsername);
    assert.equal(params.nc, "00000001");
    assert.equal(params.uri, "/hook?tenant=1");
  });

  it("returns a 200 first attempt untouched, with no Authorization stamp", async () => {
    const seen: Array<{ url: string; headers: Record<string, string> }> = [];
    const fetchFn = stubFetch(seen, () => ({ status: 200, headers: headerMap(null) }));
    const session = sessionWithPassword(testPassword);
    const response = await session.fetchWithDigestAuth(fetchFn, "https://example.com/hook");
    assert.equal(response.status, 200);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].headers.Authorization, undefined);
  });

  it("returns a non-Digest 401 as-is without retrying", async () => {
    const seen: Array<{ url: string; headers: Record<string, string> }> = [];
    const fetchFn = stubFetch(seen, () => ({
      status: 401,
      headers: headerMap('Basic realm="r"'),
    }));
    const session = sessionWithPassword(testPassword);
    const response = await session.fetchWithDigestAuth(fetchFn, "https://example.com/hook");
    assert.equal(response.status, 401);
    assert.equal(seen.length, 1);
  });

  it("re-authenticates once on stale=true with the fresh nonce, then stops", async () => {
    const seen: Array<{ url: string; headers: Record<string, string> }> = [];
    const fetchFn = stubFetch(seen, (soFar) => {
      if (soFar.length === 1) {
        return { status: 401, headers: headerMap(challengeHeader()) };
      }
      if (soFar.length === 2) {
        return {
          status: 401,
          headers: headerMap(challengeHeader({ nonce: `"fresh-nonce"`, stale: "true" })),
        };
      }
      return { status: 200, headers: headerMap(null) };
    });
    const session = sessionWithPassword(testPassword);
    const response = await session.fetchWithDigestAuth(fetchFn, "https://example.com/hook");
    assert.equal(response.status, 200);
    assert.equal(seen.length, 3);
    assert.equal(headerParams(seen[2].headers.Authorization ?? "").nonce, "fresh-nonce");
    assert.equal(headerParams(seen[2].headers.Authorization ?? "").nc, "00000001");
  });

  it("does not loop on a second non-stale 401", async () => {
    const seen: Array<{ url: string; headers: Record<string, string> }> = [];
    const fetchFn = stubFetch(seen, () => ({
      status: 401,
      headers: headerMap(challengeHeader()),
    }));
    const session = sessionWithPassword(testPassword);
    const response = await session.fetchWithDigestAuth(fetchFn, "https://example.com/hook");
    assert.equal(response.status, 401);
    assert.equal(seen.length, 2);
  });
});
