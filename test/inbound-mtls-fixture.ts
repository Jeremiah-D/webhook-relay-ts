import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";

/**
 * Runtime-generated X.509 fixture for inbound mTLS tests (WR-103).
 *
 * `node:crypto` cannot sign certificates, so this module builds minimal
 * DER-encoded X.509v3 certificates by hand and signs the TBSCertificate
 * with the CA key (`crypto.sign("sha256", tbs, caKey)` =
 * sha256WithRSAEncryption). Nothing is checked in — every key and
 * certificate is generated fresh per process, valid only for these
 * tests:
 *
 * - a throwaway CA (`CN=relay-test-ca`),
 * - a server certificate (`CN=localhost`, SAN `DNS:localhost` /
 *   `IP:127.0.0.1`, EKU serverAuth) signed by that CA,
 * - a client certificate (`CN=relay-client`, EKU clientAuth) signed by
 *   that CA,
 * - a second throwaway CA (`CN=evil-ca`) signing an "evil" client
 *   certificate (`CN=evil-client`) for negative handshake tests.
 *
 * The DER is intentionally minimal (single-CN RDNs, GeneralizedTime
 * validity, SKID/AKID, keyUsage, basicConstraints, EKU, SAN) — just
 * enough for OpenSSL chain verification and `X509Certificate` parsing.
 */

// --- Minimal DER writer -------------------------------------------------

function derLength(n: number): Buffer {
  if (n < 128) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

const seq = (...parts: Buffer[]): Buffer => tlv(0x30, ...parts);
const set = (...parts: Buffer[]): Buffer => tlv(0x31, ...parts);
const NULL_DER = tlv(0x05);
const BOOL_TRUE = tlv(0x01, Buffer.from([0xff]));
/** Primitive context-specific tag [n], e.g. GeneralName choices. */
const prim = (n: number, ...parts: Buffer[]): Buffer => tlv(0x80 + n, ...parts);
/** Constructed context-specific tag [n], e.g. version / extensions. */
const explicit = (n: number, ...parts: Buffer[]): Buffer => tlv(0xa0 + n, ...parts);

function oidDer(dotted: string): Buffer {
  const arcs = dotted.split(".").map((s) => parseInt(s, 10));
  const out: number[] = [40 * arcs[0] + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const digits: number[] = [];
    let v = arc;
    do {
      digits.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < digits.length - 1; i++) digits[i] |= 0x80;
    out.push(...digits);
  }
  return tlv(0x06, Buffer.from(out));
}

function intDer(bytes: Buffer): Buffer {
  let b = bytes;
  while (b.length > 1 && b[0] === 0x00) b = b.subarray(1);
  if ((b[0] as number) & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
  return tlv(0x02, b);
}

function utf8Der(s: string): Buffer {
  return tlv(0x0c, Buffer.from(s, "utf8"));
}

function generalizedTimeDer(d: Date): Buffer {
  const p = (n: number): string => String(n).padStart(2, "0");
  const s =
    `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x18, Buffer.from(s, "ascii"));
}

function cnRdn(cn: string): Buffer {
  return seq(set(seq(oidDer("2.5.4.3"), utf8Der(cn))));
}

const SIG_ALG = seq(oidDer("1.2.840.113549.1.1.11"), NULL_DER); // sha256WithRSAEncryption
const RSA_ALG = seq(oidDer("1.2.840.113549.1.1.1"), NULL_DER); // rsaEncryption

/**
 * keyUsage bits: 0 digitalSignature, 2 keyEncipherment, 5 keyCertSign,
 * 6 cRLSign (RFC 5280 §4.2.1.3, MSB-first).
 */
function keyUsageDer(...bits: number[]): Buffer {
  const max = Math.max(...bits);
  const nbytes = Math.floor(max / 8) + 1;
  const buf = Buffer.alloc(nbytes, 0);
  for (const b of bits) buf[Math.floor(b / 8)] = (buf[Math.floor(b / 8)] as number) | (0x80 >> (b % 8));
  const unused = nbytes * 8 - max - 1;
  return tlv(0x03, Buffer.concat([Buffer.from([unused]), buf]));
}

function extension(oid: string, critical: boolean, valueDer: Buffer): Buffer {
  return seq(oidDer(oid), ...(critical ? [BOOL_TRUE] : []), tlv(0x04, valueDer));
}

// --- Certificate builder ------------------------------------------------

interface CertSpec {
  serial: Buffer;
  issuer: Buffer;
  subject: Buffer;
  notBefore: Date;
  notAfter: Date;
  subjectPublicKeyDer: Buffer; // PKCS#1 RSAPublicKey DER
  extensions: Buffer[];
}

function tbsCertificate(spec: CertSpec): Buffer {
  const spki = seq(
    RSA_ALG,
    tlv(0x03, Buffer.concat([Buffer.from([0x00]), spec.subjectPublicKeyDer]))
  );
  return seq(
    explicit(0, intDer(Buffer.from([2]))), // v3
    intDer(spec.serial),
    SIG_ALG,
    spec.issuer,
    seq(generalizedTimeDer(spec.notBefore), generalizedTimeDer(spec.notAfter)),
    spec.subject,
    spki,
    explicit(3, seq(...spec.extensions))
  );
}

function issueCertificate(tbs: Buffer, caKey: KeyObject): Buffer {
  const signature = sign("sha256", tbs, caKey);
  return seq(tbs, SIG_ALG, tlv(0x03, Buffer.concat([Buffer.from([0x00]), signature])));
}

function pem(label: string, der: Buffer): string {
  const lines = der.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

interface KeyMaterial {
  key: KeyObject;
  publicKeyDer: Buffer;
  skid: Buffer;
}

function newRsaKey(): KeyMaterial {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicKeyDer = publicKey.export({ type: "pkcs1", format: "der" });
  return { key: privateKey, publicKeyDer, skid: createHash("sha1").update(publicKeyDer).digest() };
}

// --- Fixture --------------------------------------------------------------

export interface InboundMtlsFixture {
  caCertPem: string;
  serverCertPem: string;
  serverKeyPem: string;
  clientCertPem: string;
  clientKeyPem: string;
  evilClientCertPem: string;
  evilClientKeyPem: string;
  /** Second throwaway CA + client, for CA-rotation tests. */
  ca2CertPem: string;
  client2CertPem: string;
  client2KeyPem: string;
}

/**
 * Generate the whole fixture. RSA-2048 key generation takes ~1s total;
 * call once per test file and reuse.
 */
export function generateInboundMtlsFixture(): InboundMtlsFixture {
  const notBefore = new Date(Date.now() - 86_400_000);
  const notAfter = new Date(Date.now() + 10 * 365 * 86_400_000);

  // Throwaway CA (self-signed).
  const ca = newRsaKey();
  const caName = cnRdn("relay-test-ca");
  const caTbs = tbsCertificate({
    serial: randomBytes(8),
    issuer: caName,
    subject: caName,
    notBefore,
    notAfter,
    subjectPublicKeyDer: ca.publicKeyDer,
    extensions: [
      extension("2.5.29.19", true, seq(BOOL_TRUE)), // basicConstraints cA:TRUE
      extension("2.5.29.15", true, keyUsageDer(5, 6)), // keyCertSign, cRLSign
      extension("2.5.29.14", false, tlv(0x04, ca.skid)), // SKID
    ],
  });
  const caCertDer = issueCertificate(caTbs, ca.key);

  const signLeaf = (
    key: KeyMaterial,
    cn: string,
    ekuOid: string,
    sans: Buffer[],
    issuerKey: KeyObject,
    issuerName: Buffer,
    issuerSkid: Buffer
  ): Buffer => {
    const extensions = [
      extension("2.5.29.15", true, keyUsageDer(0, 2)),
      extension("2.5.29.37", false, seq(oidDer(ekuOid))),
      ...(sans.length > 0 ? [extension("2.5.29.17", false, seq(...sans))] : []),
      extension("2.5.29.14", false, tlv(0x04, key.skid)),
      extension("2.5.29.35", false, seq(prim(0, issuerSkid))),
    ];
    const tbs = tbsCertificate({
      serial: randomBytes(8),
      issuer: issuerName,
      subject: cnRdn(cn),
      notBefore,
      notAfter,
      subjectPublicKeyDer: key.publicKeyDer,
      extensions,
    });
    return issueCertificate(tbs, issuerKey);
  };

  // Server certificate: CN=localhost, SAN DNS:localhost + IP:127.0.0.1.
  const serverKey = newRsaKey();
  const serverCertDer = signLeaf(
    serverKey,
    "localhost",
    "1.3.6.1.5.5.7.3.1", // serverAuth
    [prim(2, Buffer.from("localhost", "ascii")), prim(7, Buffer.from([127, 0, 0, 1]))],
    ca.key,
    caName,
    ca.skid
  );

  // Client certificate: CN=relay-client.
  const clientKey = newRsaKey();
  const clientCertDer = signLeaf(
    clientKey,
    "relay-client",
    "1.3.6.1.5.5.7.3.2", // clientAuth
    [],
    ca.key,
    caName,
    ca.skid
  );

  // Evil CA + evil client (chain does NOT verify against the test CA).
  const evilCa = newRsaKey();
  const evilCaName = cnRdn("evil-ca");
  const evilCaTbs = tbsCertificate({
    serial: randomBytes(8),
    issuer: evilCaName,
    subject: evilCaName,
    notBefore,
    notAfter,
    subjectPublicKeyDer: evilCa.publicKeyDer,
    extensions: [
      extension("2.5.29.19", true, seq(BOOL_TRUE)),
      extension("2.5.29.15", true, keyUsageDer(5, 6)),
      extension("2.5.29.14", false, tlv(0x04, evilCa.skid)),
    ],
  });
  issueCertificate(evilCaTbs, evilCa.key); // self-signed; only the leaf matters below
  const evilClientKey = newRsaKey();
  const evilClientCertDer = signLeaf(
    evilClientKey,
    "evil-client",
    "1.3.6.1.5.5.7.3.2",
    [],
    evilCa.key,
    evilCaName,
    evilCa.skid
  );

  // Second throwaway CA + client, for CA-rotation (hot-reload) tests.
  const ca2 = newRsaKey();
  const ca2Name = cnRdn("relay-test-ca-2");
  const ca2Tbs = tbsCertificate({
    serial: randomBytes(8),
    issuer: ca2Name,
    subject: ca2Name,
    notBefore,
    notAfter,
    subjectPublicKeyDer: ca2.publicKeyDer,
    extensions: [
      extension("2.5.29.19", true, seq(BOOL_TRUE)),
      extension("2.5.29.15", true, keyUsageDer(5, 6)),
      extension("2.5.29.14", false, tlv(0x04, ca2.skid)),
    ],
  });
  const ca2CertDer = issueCertificate(ca2Tbs, ca2.key);
  const client2Key = newRsaKey();
  const client2CertDer = signLeaf(
    client2Key,
    "relay-client-2",
    "1.3.6.1.5.5.7.3.2",
    [],
    ca2.key,
    ca2Name,
    ca2.skid
  );

  return {
    caCertPem: pem("CERTIFICATE", caCertDer),
    serverCertPem: pem("CERTIFICATE", serverCertDer),
    serverKeyPem: serverKey.key.export({ type: "pkcs8", format: "pem" }) as string,
    clientCertPem: pem("CERTIFICATE", clientCertDer),
    clientKeyPem: clientKey.key.export({ type: "pkcs8", format: "pem" }) as string,
    evilClientCertPem: pem("CERTIFICATE", evilClientCertDer),
    evilClientKeyPem: evilClientKey.key.export({ type: "pkcs8", format: "pem" }) as string,
    ca2CertPem: pem("CERTIFICATE", ca2CertDer),
    client2CertPem: pem("CERTIFICATE", client2CertDer),
    client2KeyPem: client2Key.key.export({ type: "pkcs8", format: "pem" }) as string,
  };
}
