// WR-198: mTLS client cert target patterns (exact / *.hostname / path prefix).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  assertValidClientCertTargetKey,
  clientCertIdentity,
  resolveClientCertTarget,
  type TlsClientCert,
} from "../src/mtls.ts";
import { createDefaultSender } from "../src/server.ts";
import { RotatingClientCertSet } from "../src/mtls-rotation.ts";
import { OutboundConnectionPool } from "../src/keepalive.ts";
import {
  MTLS_CLIENT_CERT_PEM,
  MTLS_CLIENT_KEY_PEM,
  MTLS_EVIL_CLIENT_CERT_PEM,
  MTLS_EVIL_CLIENT_KEY_PEM,
} from "./mtls-fixture.ts";

const GOOD_CERT: TlsClientCert = { cert: MTLS_CLIENT_CERT_PEM, key: MTLS_CLIENT_KEY_PEM };
const EVIL_CERT: TlsClientCert = { cert: MTLS_EVIL_CLIENT_CERT_PEM, key: MTLS_EVIL_CLIENT_KEY_PEM };

describe("WR-198 resolveClientCertTarget", () => {
  it("exact targetUrl beats wildcard and path prefix", () => {
    const map = {
      "*.example.com": EVIL_CERT,
      "https://hooks.example.com/v1": EVIL_CERT,
      "https://hooks.example.com/v1/x": GOOD_CERT,
    };
    assert.equal(
      resolveClientCertTarget(map, "https://hooks.example.com/v1/x"),
      GOOD_CERT
    );
  });

  it("wildcard matches exactly one DNS label (RFC 4592 semantics)", () => {
    const map = { "*.example.com": GOOD_CERT };
    assert.equal(resolveClientCertTarget(map, "https://hooks.example.com/x"), GOOD_CERT);
    // apex does not match
    assert.equal(resolveClientCertTarget(map, "https://example.com/x"), undefined);
    // nested subdomains do not match
    assert.equal(resolveClientCertTarget(map, "https://a.b.example.com/x"), undefined);
    // scheme and port are ignored; matching is case-insensitive
    assert.equal(resolveClientCertTarget(map, "https://HOOKS.EXAMPLE.COM:8443/x"), GOOD_CERT);
  });

  it("path prefix matches at segment boundaries only", () => {
    const map = { "https://api.example.com/v1": GOOD_CERT };
    assert.equal(resolveClientCertTarget(map, "https://api.example.com/v1/hooks"), GOOD_CERT);
    assert.equal(resolveClientCertTarget(map, "https://api.example.com/v1"), GOOD_CERT);
    // /v10 is not under /v1
    assert.equal(resolveClientCertTarget(map, "https://api.example.com/v10/x"), undefined);
    // different host does not match
    assert.equal(resolveClientCertTarget(map, "https://other.example.com/v1/x"), undefined);
  });

  it("wildcard beats path prefix; longest prefix wins", () => {
    const map = {
      "https://a.example.com/v1": GOOD_CERT,
      "*.example.com": EVIL_CERT,
    };
    // wildcard outranks even a longer path prefix on the same target
    assert.equal(resolveClientCertTarget(map, "https://a.example.com/v1/x"), EVIL_CERT);

    const prefixes = {
      "https://api.example.com/v1": GOOD_CERT,
      "https://api.example.com/v1/hooks": EVIL_CERT,
    };
    assert.equal(resolveClientCertTarget(prefixes, "https://api.example.com/v1/hooks/x"), EVIL_CERT);
    assert.equal(resolveClientCertTarget(prefixes, "https://api.example.com/v1/other"), GOOD_CERT);
  });

  it("no match returns undefined; no map returns undefined", () => {
    const map = { "*.example.com": GOOD_CERT };
    assert.equal(resolveClientCertTarget(map, "https://other.org/x"), undefined);
    assert.equal(resolveClientCertTarget(undefined, "https://hooks.example.com/x"), undefined);
  });

  it("a URL key with an empty path stays exact-only", () => {
    const map = { "https://api.example.com": GOOD_CERT };
    assert.equal(resolveClientCertTarget(map, "https://api.example.com"), GOOD_CERT);
    assert.equal(resolveClientCertTarget(map, "https://api.example.com/hooks"), undefined);
  });

  it("a wildcard identity resolves to one pool agent, a different identity to another", () => {
    const map = { "*.example.com": GOOD_CERT };
    const pool = new OutboundConnectionPool({});
    try {
      const certA = resolveClientCertTarget(map, "https://a.example.com/x");
      const certB = resolveClientCertTarget(map, "https://b.example.com/x");
      assert.equal(certA, certB); // same identity object resolves for both
      const urlA = new URL("https://a.example.com/x");
      // same (origin, identity) → the same agent
      assert.equal(
        pool.agentFor(urlA, undefined, undefined, clientCertIdentity(certA!)),
        pool.agentFor(urlA, undefined, undefined, clientCertIdentity(certB!))
      );
      // a different identity gets a different agent — never rides the same connection
      assert.notEqual(
        pool.agentFor(urlA, undefined, undefined, clientCertIdentity(certA!)),
        pool.agentFor(urlA, undefined, undefined, clientCertIdentity(EVIL_CERT))
      );
    } finally {
      pool.destroy();
    }
  });
});

describe("WR-198 assertValidClientCertTargetKey", () => {
  it("accepts wildcard, exact URL and path-prefix keys", () => {
    assert.doesNotThrow(() => assertValidClientCertTargetKey("*.example.com", "t"));
    assert.doesNotThrow(() => assertValidClientCertTargetKey("https://hooks.example.com/a/b", "t"));
    assert.doesNotThrow(() => assertValidClientCertTargetKey("http://localhost:8080", "t"));
  });

  it("rejects malformed keys with RangeError", () => {
    for (const bad of [
      "",
      "*",
      "*foo.com",
      "*..example.com",
      "*.example.com:443",
      "*.example.com/hooks",
      "example.com",
      "not a url",
      "ftp://example.com",
    ]) {
      assert.throws(
        () => assertValidClientCertTargetKey(bad, "t"),
        RangeError,
        `key ${JSON.stringify(bad)} should throw`
      );
    }
  });
});

describe("WR-198 sender integration", () => {
  it("startup validates pattern keys (RangeError on bad key)", () => {
    assert.throws(
      () =>
        createDefaultSender(
          undefined,
          undefined,
          undefined,
          undefined,
          { "*bad key!": GOOD_CERT }
        ),
      RangeError
    );
    // a valid wildcard + prefix config constructs without error
    const sender = createDefaultSender(
      undefined,
      undefined,
      undefined,
      undefined,
      { "*.example.com": GOOD_CERT, "https://api.example.com/v1": EVIL_CERT }
    );
    assert.ok(sender);
    sender.destroy();
  });

  it("a rotation endpoint overlapping a tlsClientCerts pattern is rejected", () => {
    const set = new RotatingClientCertSet({
      certificates: [{ id: "primary", cert: GOOD_CERT.cert, key: GOOD_CERT.key }],
    });
    assert.throws(
      () =>
        createDefaultSender(
          undefined,
          undefined,
          undefined,
          undefined,
          { "*.example.com": EVIL_CERT }, // would also match the rotation endpoint
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          new Map([["https://hooks.example.com/x", set]])
        ),
      RangeError
    );
  });
});
