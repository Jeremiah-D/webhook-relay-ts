import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import {
  buildSignatureBase,
  contentDigestSha512,
  headerComponent,
  parseSignatureInput,
  queryParamComponent,
  renderSignature,
  renderSignatureInput,
  signRfc9421,
  verifyRfc9421,
  type Rfc9421Message,
} from '../src/rfc9421.ts';

// ---------------------------------------------------------------------------
// RFC 9421 Appendix B official test vectors (fetched from
// https://www.rfc-editor.org/rfc/rfc9421.txt; values copied verbatim).
// ---------------------------------------------------------------------------

/** B.1.5 test-shared-secret: 64 random bytes, base64. */
const SHARED_SECRET_B64 =
  'uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBt' +
  'bmHhIDi6pcl8jsasjlTMtDQ==';
const SHARED_SECRET = Buffer.from(SHARED_SECRET_B64, 'base64');

/** B.1.4 test-key-ed25519 private seed (JWK "d", base64url). */
const ED25519_SEED_B64URL = 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU';

/** The RFC's test-request message (B.2). */
const TEST_REQUEST: Rfc9421Message = {
  method: 'POST',
  authority: 'example.com',
  path: '/foo',
  query: 'param=Value&Pet=dog',
  headers: {
    date: 'Tue, 20 Apr 2021 02:07:55 GMT',
    'content-type': 'application/json',
    'content-digest':
      'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
    'content-length': '18',
  },
};

/** Derive a PEM Ed25519 private key from a 32-byte seed (PKCS#8 DER). */
function ed25519KeyPairFromSeed(seedB64Url: string): { privateKeyPem: string; publicKeyPem: string } {
  const seed = Buffer.from(seedB64Url, 'base64url');
  assert.equal(seed.length, 32);
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  assert.equal(priv.asymmetricKeyType, 'ed25519');
  return {
    privateKeyPem: priv.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicKeyPem: createPublicKey(priv).export({ format: 'pem', type: 'spki' }).toString(),
  };
}

// ---------------------------------------------------------------------------
// B.2.5 — Signing a Request Using hmac-sha256
// ---------------------------------------------------------------------------

test('B.2.5: signature base matches the RFC byte-for-byte', () => {
  const base = buildSignatureBase(
    TEST_REQUEST,
    [headerComponent('date'), '@authority', headerComponent('content-type')],
    { created: 1618884473, keyId: 'test-shared-secret' }
  );
  assert.equal(
    base,
    '"date": Tue, 20 Apr 2021 02:07:55 GMT\n' +
      '"@authority": example.com\n' +
      '"content-type": application/json\n' +
      '"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"'
  );
});

test('B.2.5: signRfc9421 reproduces the official Signature value', () => {
  const signed = signRfc9421({
    message: TEST_REQUEST,
    components: [headerComponent('date'), '@authority', headerComponent('content-type')],
    label: 'sig-b25',
    key: { alg: 'hmac-sha256', secret: SHARED_SECRET },
    created: 1618884473,
    keyId: 'test-shared-secret',
  });
  assert.equal(
    signed.signatureInput,
    'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"'
  );
  assert.equal(signed.signature, 'sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:');
});

test('B.2.5: the official Signature-Input + Signature headers verify', () => {
  const ok = verifyRfc9421({
    message: TEST_REQUEST,
    signatureInput:
      'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
    signature: 'sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:',
    key: { alg: 'hmac-sha256', secret: SHARED_SECRET },
  });
  assert.equal(ok, true);
});

// ---------------------------------------------------------------------------
// B.2.6 — Signing a Request Using ed25519
// ---------------------------------------------------------------------------

test('B.2.6: signature base matches the RFC byte-for-byte', () => {
  const base = buildSignatureBase(
    TEST_REQUEST,
    [
      headerComponent('date'),
      '@method',
      '@path',
      '@authority',
      headerComponent('content-type'),
      headerComponent('content-length'),
    ],
    { created: 1618884473, keyId: 'test-key-ed25519' }
  );
  assert.equal(
    base,
    '"date": Tue, 20 Apr 2021 02:07:55 GMT\n' +
      '"@method": POST\n' +
      '"@path": /foo\n' +
      '"@authority": example.com\n' +
      '"content-type": application/json\n' +
      '"content-length": 18\n' +
      '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'
  );
});

test('B.2.6: signing with the RFC test key reproduces the official Signature value', () => {
  const { privateKeyPem } = ed25519KeyPairFromSeed(ED25519_SEED_B64URL);
  const signed = signRfc9421({
    message: TEST_REQUEST,
    components: [
      headerComponent('date'),
      '@method',
      '@path',
      '@authority',
      headerComponent('content-type'),
      headerComponent('content-length'),
    ],
    label: 'sig-b26',
    key: { alg: 'ed25519', privateKeyPem },
    created: 1618884473,
    keyId: 'test-key-ed25519',
  });
  // Ed25519 is deterministic: the RFC's signature must match exactly.
  assert.equal(
    signed.signature,
    'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:'
  );
});

test('B.2.6: the official Signature-Input + Signature headers verify', () => {
  const { publicKeyPem } = ed25519KeyPairFromSeed(ED25519_SEED_B64URL);
  const ok = verifyRfc9421({
    message: TEST_REQUEST,
    signatureInput:
      'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    signature:
      'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:',
    key: { alg: 'ed25519', publicKeyPem },
  });
  assert.equal(ok, true);
});

// ---------------------------------------------------------------------------
// content-digest pin against the RFC's test-request Content-Digest
// ---------------------------------------------------------------------------

test('contentDigestSha512 reproduces the RFC test-request digest', () => {
  const digest = contentDigestSha512(Buffer.from('{"hello": "world"}'));
  assert.equal(
    digest,
    'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:'
  );
});

// ---------------------------------------------------------------------------
// Round-trips, tampering, and config validation
// ---------------------------------------------------------------------------

test('round-trip: hmac-sha256 sign then verify', () => {
  const secret = Buffer.from('relay-shared-secret-for-downstream');
  const message: Rfc9421Message = {
    method: 'POST',
    authority: 'hooks.example.com',
    path: '/deliver',
    query: 'tenant=acme&mode=live',
    headers: { 'content-type': 'application/json', 'x-event': 'payment.succeeded' },
  };
  const signed = signRfc9421({
    message,
    components: [
      '@method',
      '@authority',
      '@path',
      '@query',
      queryParamComponent('tenant'),
      headerComponent('content-type'),
      headerComponent('x-event'),
    ],
    label: 'sig1',
    key: { alg: 'hmac-sha256', secret },
    created: 1700000000,
    keyId: 'k1',
    nonce: 'n-1',
  });
  assert.ok(
    verifyRfc9421({ message, signatureInput: signed.signatureInput, signature: signed.signature, key: { alg: 'hmac-sha256', secret } })
  );
  // The @query-param line covers the encoded value: tenant=acme.
  assert.ok(signed.signatureBase.includes('"@query-param";name="tenant": acme'));
  assert.ok(signed.signatureBase.includes('"@query": ?tenant=acme&mode=live'));
});

test('round-trip: ed25519 sign then verify with generated keys', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const message: Rfc9421Message = {
    method: 'POST',
    authority: 'bank.example',
    path: '/webhook',
    headers: { 'content-type': 'application/json' },
  };
  const signed = signRfc9421({
    message,
    components: ['@method', '@authority', '@path', headerComponent('content-type')],
    label: 'bank-sig',
    key: { alg: 'ed25519', privateKeyPem },
    created: 1700000000,
    keyId: 'bank-2024',
  });
  assert.ok(
    verifyRfc9421({
      message,
      signatureInput: signed.signatureInput,
      signature: signed.signature,
      key: { alg: 'ed25519', publicKeyPem },
    })
  );
});

test('verify fails closed: tampered component, wrong key, unknown label', () => {
  const secret = Buffer.from('s3cr3t');
  const message: Rfc9421Message = {
    method: 'POST',
    authority: 'example.com',
    path: '/pay',
    headers: { 'content-type': 'application/json' },
  };
  const signed = signRfc9421({
    message,
    components: ['@method', '@path', headerComponent('content-type')],
    label: 'sig1',
    key: { alg: 'hmac-sha256', secret },
    created: 1700000000,
  });
  const key = { alg: 'hmac-sha256' as const, secret };
  const good = { message, signatureInput: signed.signatureInput, signature: signed.signature, key };
  assert.equal(verifyRfc9421(good), true);
  // Tampered path.
  assert.equal(verifyRfc9421({ ...good, message: { ...message, path: '/steal' } }), false);
  // Tampered header.
  assert.equal(
    verifyRfc9421({ ...good, message: { ...message, headers: { 'content-type': 'text/plain' } } }),
    false
  );
  // Wrong secret.
  assert.equal(verifyRfc9421({ ...good, key: { alg: 'hmac-sha256', secret: Buffer.from('wrong') } }), false);
  // Wrong algorithm key.
  const { publicKey } = generateKeyPairSync('ed25519');
  assert.equal(
    verifyRfc9421({
      ...good,
      key: { alg: 'ed25519', publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString() },
    }),
    false
  );
  // Unknown label.
  assert.equal(verifyRfc9421({ ...good, label: 'nope' }), false);
  // Corrupted signature bytes.
  assert.equal(verifyRfc9421({ ...good, signature: 'sig1=:AAAA:' }), false);
});

test('verify never throws on malformed input', () => {
  const key = { alg: 'hmac-sha256' as const, secret: Buffer.from('x') };
  const message: Rfc9421Message = { method: 'GET', authority: 'a', path: '/', headers: {} };
  assert.equal(verifyRfc9421({ message, signatureInput: '', signature: '', key }), false);
  assert.equal(verifyRfc9421({ message, signatureInput: 'not-a-dictionary', signature: 'sig1=:AA==:', key }), false);
  assert.equal(verifyRfc9421({ message, signatureInput: 'sig1=(oops', signature: 'sig1=:AA==:', key }), false);
  assert.equal(verifyRfc9421({ message, signatureInput: 'sig1=("a");created=1', signature: 'garbage', key }), false);
  // @query-param for a missing parameter fails the base build, not the caller.
  assert.equal(
    verifyRfc9421({
      message,
      signatureInput: 'sig1=("@query-param";name="missing");created=1',
      signature: 'sig1=:AA==:',
      key,
    }),
    false
  );
});

test('declared alg mismatch fails closed', () => {
  const secret = Buffer.from('s3cr3t');
  const message: Rfc9421Message = { method: 'POST', authority: 'example.com', path: '/', headers: {} };
  const signed = signRfc9421({
    message,
    components: ['@method'],
    label: 'sig1',
    key: { alg: 'hmac-sha256', secret },
    created: 1700000000,
  });
  // The signer declared alg="hmac-sha256"; verifying with an ed25519 key must fail.
  const { publicKey } = generateKeyPairSync('ed25519');
  assert.equal(
    verifyRfc9421({
      message,
      signatureInput: signed.signatureInput,
      signature: signed.signature,
      key: { alg: 'ed25519', publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString() },
    }),
    false
  );
});

test('config errors throw RangeError at sign time (fail fast)', () => {
  const message: Rfc9421Message = { method: 'GET', authority: 'a', path: '/', headers: {} };
  const key = { alg: 'hmac-sha256' as const, secret: Buffer.from('x') };
  assert.throws(() => signRfc9421({ message, components: [], label: '', key }), RangeError);
  assert.throws(
    () => signRfc9421({ message, components: ['@bogus' as never], label: 's', key }),
    /unknown derived component/
  );
  assert.throws(
    () => buildSignatureBase(message, [headerComponent('x-missing')], {}),
    /not present/
  );
  assert.throws(
    () => buildSignatureBase({ ...message, query: 'a=1&a=2' }, [queryParamComponent('a')], {}),
    /occurs 2 times/
  );
  assert.throws(
    () => buildSignatureBase(message, [queryParamComponent('absent')], {}),
    /not present/
  );
  assert.throws(
    () => signRfc9421({ message, components: ['@method'], label: 's', key: { alg: 'hmac-sha256' } }),
    RangeError
  );
  assert.throws(
    () => signRfc9421({ message, components: ['@method'], label: 's', key: { alg: 'ed25519', privateKeyPem: 'nope' } }),
    RangeError
  );
  assert.throws(() => renderSignatureInput('s', [], { created: -1 }), RangeError);
});

test('parseSignatureInput handles multiple labeled signatures', () => {
  const entries = parseSignatureInput(
    'sig1=("@method" "@path");created=1618884473;keyid="k1", sig2=("@authority");created=1618884474;keyid="k2"'
  );
  assert.equal(entries.length, 2);
  assert.equal(entries[0].label, 'sig1');
  assert.equal(entries[0].paramsTail, ';created=1618884473;keyid="k1"');
  assert.equal(entries[1].label, 'sig2');
  assert.deepEqual(
    entries[1].items.map((i) => i.item),
    ['@authority']
  );
});

test('renderSignature produces the :base64: wrapping', () => {
  assert.equal(renderSignature('s', Buffer.from([1, 2, 3])), 's=:AQID:');
});

test('derived components: @scheme/@target-uri/@request-target/@query/@status', () => {
  const message: Rfc9421Message = {
    method: 'GET',
    authority: 'Example.COM:8443',
    scheme: 'HTTPS',
    path: '/p',
    query: 'a=1',
    headers: {},
    status: 201,
  };
  const base = buildSignatureBase(
    message,
    ['@scheme', '@authority', '@target-uri', '@request-target', '@path', '@query'],
    { created: 1 }
  );
  assert.ok(base.includes('"@scheme": https'));
  assert.ok(base.includes('"@authority": example.com:8443'));
  assert.ok(base.includes('"@target-uri": https://example.com:8443/p?a=1'));
  assert.ok(base.includes('"@request-target": /p?a=1'));
  assert.ok(base.includes('"@path": /p'));
  assert.ok(base.includes('"@query": ?a=1'));
  const noQuery = buildSignatureBase({ ...message, query: undefined }, ['@query'], { created: 1 });
  assert.ok(noQuery.includes('"@query": ?'));
  const emptyPath = buildSignatureBase({ ...message, path: '' }, ['@path'], { created: 1 });
  assert.ok(emptyPath.includes('"@path": /'));
});
