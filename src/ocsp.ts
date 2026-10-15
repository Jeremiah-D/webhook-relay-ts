import { createHash, X509Certificate } from "node:crypto";
import { request as httpsRequest } from "node:https";
import type { ClientRequest } from "node:http";
import { renderOcspBlock, type OcspMetricsInput } from "./metrics.ts";

/**
 * Outbound TLS OCSP revocation checking (WR-101).
 *
 * Certificate pinning (WR-21) answers "is this the server I expect?" —
 * it stops a compromised CA or a MITM holding a valid-but-unexpected
 * certificate. OCSP answers the orthogonal question: "has this
 * certificate been *revoked* since it was issued?" A pinned certificate
 * can still be revoked (key compromise discovered after issuance), and
 * a CA-valid certificate the relay never pinned can be revoked hours
 * before the next renewal — pinning defends against CA compromise,
 * OCSP defends against revocation lag. The two compose: the pin check
 * runs first, the revocation check runs on the pinned (or
 * PKI-verified) peer.
 *
 * Per-endpoint opt-in (`tlsOcsp: { "<exact targetUrl>": { mode, ... } }`,
 * off by default — zero behavior change when unconfigured):
 *
 * - `mode: "fail-open"` (default): a revocation verdict is still fatal,
 *   but when the revocation *status* cannot be determined (no stapled
 *   response, no/failing responder, malformed response) the delivery
 *   proceeds and the operator is alerted (`ocsp_alert`). Use for
 *   endpoints where availability beats freshness.
 * - `mode: "fail-closed"`: an undeterminable status fails the delivery
 *   attempt (`OcspError`) through the normal retry / dead-letter path.
 *   Recommended for pinned endpoints — a pin already says "I know
 *   exactly which key to expect", so failing closed on revocation
 *   telemetry loss is the consistent posture.
 *
 * Check order per handshake (RFC 6960):
 *
 * 1. Stapled response first (`requestOCSP: true` on the TLS handshake +
 *    `socket.getOCSPResponse()`): the server's own freshness claim,
 *    zero extra round-trips. Disabled with `useStapled: false`.
 * 2. Responder fallback: an HTTP POST of the DER OCSPRequest to
 *    `responderUrl`, else the leaf certificate's Authority Information
 *    Access extension, via the pluggable `responderFetcher` (the
 *    default is a plain `node:https` POST; tests inject a stub — no
 *    real OCSP URL is ever touched by the test suite).
 *
 * A `revoked` verdict destroys the request with {@link OcspRevokedError}
 * *before* a single payload byte is written (the pinning.ts precedent:
 * the revoked peer never observes the body), fires the `ocsp_revoked`
 * audit event, fires the alert hook, and counts in
 * `relay_ocsp_total{endpoint,status="revoked"}`. An OCSP *query* failure
 * surfaces as {@link OcspError} and — explicitly — is NOT recorded as a
 * circuit-breaker failure (see the WR-101 bypass in `src/retry.ts`): an
 * unreachable responder is a local telemetry outage, not a sick
 * endpoint. A revoked certificate *does* count: the endpoint is serving
 * a dead credential and the breaker should notice.
 *
 * Keep-alive pool semantics: the check runs on session establishment.
 * A pooled socket that already passed the check for an endpoint is not
 * re-checked while it stays pooled (revocation is a property of the
 * certificate presented at handshake — the peer cannot change
 * underneath a live TLS session), and a socket verified for endpoint A
 * is still checked for endpoint B. OCSP agents disable TLS session
 * resumption (`maxCachedSessions: 0`, the pinned-agent precedent): a
 * resumed TLS 1.3 handshake re-sends no certificate, so there would be
 * nothing to check. Only the HTTP/1.1 path is gated in this round —
 * `wss:` targets and the opt-in HTTP/2 session pool are documented gaps
 * (the H2 pool owns its own handshake; an OCSP-configured endpoint is
 * deliberately kept off the H2 path rather than silently skipping the
 * check).
 *
 * Zero dependencies (`node:crypto` + `node:https` only). The DER
 * reader/writer is hand-rolled — OCSP needs only a small, fixed subset
 * of ASN.1, and a dependency would dwarf the feature.
 */

/* ------------------------------------------------------------------ */
/* Minimal DER toolkit (hand-rolled)                                   */
/* ------------------------------------------------------------------ */

/** A parsed DER tag-length-value node. */
export interface DerNode {
  /** Tag number. */
  tag: number;
  /** Tag class: 0 universal, 1 application, 2 context-specific, 3 private. */
  cls: number;
  constructed: boolean;
  /** Contents octets (without tag/length). */
  value: Buffer;
  /** The full tag+length+contents encoding of this node. */
  der: Buffer;
  /** Parsed children (only meaningful when constructed). */
  children: DerNode[];
}

/** Malformed DER / OCSP structures. Converted to {@link OcspError} at the check boundary. */
export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerError";
  }
}

function parseNode(buf: Buffer, offset: number): { node: DerNode; next: number } {
  if (offset + 2 > buf.length) throw new DerError("truncated DER: missing tag/length");
  const tagByte = buf[offset];
  const cls = (tagByte >> 6) & 0x03;
  const constructed = (tagByte & 0x20) !== 0;
  let tag = tagByte & 0x1f;
  let pos = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    for (;;) {
      if (pos >= buf.length) throw new DerError("truncated DER: unterminated high tag number");
      const b = buf[pos++];
      tag = tag * 128 + (b & 0x7f);
      if ((b & 0x80) === 0) break;
      if (tag > 0xffff) throw new DerError("DER tag number too large");
    }
  }
  if (pos >= buf.length) throw new DerError("truncated DER: missing length");
  const lenByte = buf[pos++];
  let length: number;
  if (lenByte < 0x80) {
    length = lenByte;
  } else if (lenByte === 0x80) {
    throw new DerError("indefinite-length encoding is not valid DER");
  } else {
    const nBytes = lenByte & 0x7f;
    if (nBytes > 4) throw new DerError("DER length too large");
    if (pos + nBytes > buf.length) throw new DerError("truncated DER: length bytes missing");
    length = 0;
    for (let i = 0; i < nBytes; i++) length = length * 256 + buf[pos++];
  }
  if (pos + length > buf.length) throw new DerError("truncated DER: contents missing");
  const value = buf.subarray(pos, pos + length);
  const node: DerNode = {
    tag,
    cls,
    constructed,
    value,
    der: Buffer.from(buf.subarray(offset, pos + length)),
    children: [],
  };
  if (constructed) {
    let cpos = 0;
    while (cpos < value.length) {
      const child = parseNode(value, cpos);
      node.children.push(child.node);
      cpos = child.next;
    }
  }
  return { node, next: pos + length };
}

/** Parse exactly one DER value; the buffer must contain nothing else. */
export function parseDer(buf: Buffer): DerNode {
  const { node, next } = parseNode(buf, 0);
  if (next !== buf.length) throw new DerError("trailing bytes after DER value");
  return node;
}

function encodeLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tagByte: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tagByte]), encodeLength(content.length), content]);
}

/** DER SEQUENCE of already-encoded children. */
export function derSequence(...parts: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(parts));
}

/** DER OCTET STRING. */
export function derOctetString(bytes: Buffer): Buffer {
  return tlv(0x04, bytes);
}

/** DER NULL. */
export function derNull(): Buffer {
  return tlv(0x05, Buffer.alloc(0));
}

/** DER ENUMERATED (small non-negative values — OCSP responseStatus). */
export function derEnumerated(n: number): Buffer {
  if (!Number.isInteger(n) || n < 0 || n > 127) throw new DerError(`ENUMERATED out of range: ${n}`);
  return tlv(0x0a, Buffer.from([n]));
}

/** DER INTEGER from big-endian bytes (a leading 0x00 pad is added when the high bit is set). */
export function derIntegerBytes(bytes: Buffer): Buffer {
  let b = bytes.length === 0 ? Buffer.from([0]) : bytes;
  if ((b[0] & 0x80) !== 0) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}

function base128(n: number): Buffer {
  if (n === 0) return Buffer.from([0]);
  const digits: number[] = [];
  let v = n;
  while (v > 0) {
    digits.unshift(v & 0x7f);
    v = Math.floor(v / 128);
  }
  for (let i = 0; i < digits.length - 1; i++) digits[i] |= 0x80;
  return Buffer.from(digits);
}

/** DER OBJECT IDENTIFIER from dotted form (`"1.3.6.1.5.5.7.48.1"`). */
export function derOid(oid: string): Buffer {
  const arcs = oid.split(".").map((p) => {
    if (!/^\d+$/.test(p)) throw new DerError(`bad OID arc ${JSON.stringify(p)} in ${JSON.stringify(oid)}`);
    const n = Number(p);
    if (!Number.isSafeInteger(n)) throw new DerError(`OID arc out of range in ${JSON.stringify(oid)}`);
    return n;
  });
  if (arcs.length < 2 || arcs[0] > 2 || arcs[1] > 39) throw new DerError(`bad OID ${JSON.stringify(oid)}`);
  const out: Buffer[] = [Buffer.from([arcs[0] * 40 + arcs[1]])];
  for (const arc of arcs.slice(2)) out.push(base128(arc));
  return tlv(0x06, Buffer.concat(out));
}

/** Decode DER OBJECT IDENTIFIER *contents* to dotted form. */
export function derOidToString(bytes: Buffer): string {
  if (bytes.length === 0) throw new DerError("empty OID");
  const first = bytes[0];
  const x = first < 40 ? 0 : first < 80 ? 1 : 2;
  const arcs = [x, first - x * 40];
  let v = 0;
  let open = false;
  for (let i = 1; i < bytes.length; i++) {
    const b = bytes[i];
    v = v * 128 + (b & 0x7f);
    open = true;
    if ((b & 0x80) === 0) {
      arcs.push(v);
      v = 0;
      open = false;
    }
  }
  if (open) throw new DerError("truncated OID");
  return arcs.join(".");
}

/** DER GeneralizedTime from `"YYYYMMDDHHmmssZ"`. */
export function derGeneralizedTime(s: string): Buffer {
  if (!/^\d{14}Z$/.test(s)) throw new DerError(`bad GeneralizedTime ${JSON.stringify(s)}`);
  return tlv(0x18, Buffer.from(s, "ascii"));
}

/** DER BIT STRING; `bits` must already include the unused-bits-count octet. */
export function derBitString(bits: Buffer): Buffer {
  return tlv(0x03, bits);
}

/** DER IA5String (ASCII only). */
export function derIA5String(s: string): Buffer {
  if (!/^[\x00-\x7f]*$/.test(s)) throw new DerError("IA5String must be ASCII");
  return tlv(0x16, Buffer.from(s, "ascii"));
}

/** DER `[n]` EXPLICIT (constructed context tag) wrapping an encoded value. */
export function derExplicit(n: number, inner: Buffer): Buffer {
  if (!Number.isInteger(n) || n < 0 || n > 30) throw new DerError(`bad explicit tag [${n}]`);
  return tlv(0xa0 | n, inner);
}

/** DER `[n]` IMPLICIT primitive context tag with raw contents. */
export function derImplicit(n: number, content: Buffer): Buffer {
  if (!Number.isInteger(n) || n < 0 || n > 30) throw new DerError(`bad implicit tag [${n}]`);
  return tlv(0x80 | n, content);
}

/** DER `[n]` IMPLICIT constructed context tag (e.g. `revoked [1] IMPLICIT RevokedInfo`). */
export function derImplicitConstructed(n: number, content: Buffer): Buffer {
  if (!Number.isInteger(n) || n < 0 || n > 30) throw new DerError(`bad implicit tag [${n}]`);
  return tlv(0xa0 | n, content);
}

function generalizedTimeToIso(node: DerNode, what: string): string {
  if (node.tag !== 0x18 || node.cls !== 0) throw new DerError(`${what}: expected GeneralizedTime`);
  const s = node.value.toString("ascii");
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (!m) throw new DerError(`${what}: bad GeneralizedTime ${JSON.stringify(s)}`);
  const ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  if (Number.isNaN(ms)) throw new DerError(`${what}: bad GeneralizedTime ${JSON.stringify(s)}`);
  return new Date(ms).toISOString();
}

/* ------------------------------------------------------------------ */
/* X.509 navigation                                                    */
/* ------------------------------------------------------------------ */

function tbsCertificate(certDer: Buffer): DerNode {
  let cert: DerNode;
  try {
    cert = parseDer(certDer);
  } catch (err) {
    throw new DerError(`not a certificate: ${(err as Error).message}`);
  }
  if (cert.tag !== 0x10 || cert.cls !== 0 || cert.children.length < 1) {
    throw new DerError("not a certificate SEQUENCE");
  }
  const tbs = cert.children[0];
  if (tbs.tag !== 0x10 || tbs.cls !== 0 || tbs.children.length < 7) {
    throw new DerError("malformed TBSCertificate");
  }
  return tbs;
}

/**
 * DER of the issuer Name (`tbsCertificate.children[3]`) — the exact bytes
 * the OCSP `issuerNameHash` covers (RFC 6960 §4.1.1: hash of the DER
 * encoding of the issuer's Name).
 */
export function issuerNameDer(certDer: Buffer): Buffer {
  const issuer = tbsCertificate(certDer).children[3];
  if (issuer.tag !== 0x10 || issuer.cls !== 0) throw new DerError("TBSCertificate.issuer is not a Name");
  return issuer.der;
}

/** DER of the subject Name (`tbsCertificate.children[5]`). */
export function subjectNameDer(certDer: Buffer): Buffer {
  const subject = tbsCertificate(certDer).children[5];
  if (subject.tag !== 0x10 || subject.cls !== 0) throw new DerError("TBSCertificate.subject is not a Name");
  return subject.der;
}

/** Raw contents bytes of the `serialNumber` INTEGER. */
export function serialNumberBytes(certDer: Buffer): Buffer {
  const serial = tbsCertificate(certDer).children[1];
  if (serial.tag !== 0x02 || serial.cls !== 0) {
    throw new DerError("TBSCertificate.serialNumber is not an INTEGER");
  }
  return serial.value;
}

/**
 * A public key's raw bytes: the SubjectPublicKeyInfo BIT STRING contents
 * minus the unused-bits octet (RFC 6960 §4.1.1: the `issuerKeyHash` input
 * excludes the tag, length, and unused-bits count).
 */
function spkiPublicKeyBytes(spkiDer: Buffer): Buffer {
  const spki = parseDer(spkiDer);
  if (spki.tag !== 0x10 || spki.children.length < 2) throw new DerError("malformed SubjectPublicKeyInfo");
  const bits = spki.children[1];
  if (bits.tag !== 0x03 || bits.value.length < 1 || bits.value[0] !== 0) {
    throw new DerError("SubjectPublicKeyInfo public key is not a clean BIT STRING");
  }
  return bits.value.subarray(1);
}

function stripLeadingZeros(b: Buffer): Buffer {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}

/** INTEGER comparison that ignores a leading 0x00 sign pad. */
function integerEquals(a: Buffer, b: Buffer): boolean {
  return stripLeadingZeros(a).equals(stripLeadingZeros(b));
}

/* ------------------------------------------------------------------ */
/* CertID, OCSP request, AIA                                           */
/* ------------------------------------------------------------------ */

const OID_SHA1 = "1.3.14.3.2.26";
const OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";
const OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";
const OID_AD_OCSP = "1.3.6.1.5.5.7.48.1";

/** The `(hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber)` tuple identifying a certificate to an OCSP responder. */
export interface OcspCertId {
  issuerNameHash: Buffer;
  issuerKeyHash: Buffer;
  serialNumber: Buffer;
}

/**
 * Build the CertID for `leafDer` (RFC 6960 §4.1.1). `issuerDer` is the
 * issuing CA's certificate; when omitted the leaf must be self-signed
 * (issuer Name == subject Name) and the leaf doubles as its own issuer —
 * otherwise there is no honest way to compute `issuerKeyHash` and this
 * throws. Only SHA-1 CertIDs are produced: the one hash every OCSP
 * responder speaks.
 */
export function certIdForLeaf(leafDer: Buffer, issuerDer?: Buffer): OcspCertId {
  const issuerNameHash = createHash("sha1").update(issuerNameDer(leafDer)).digest();
  let ider = issuerDer;
  if (ider === undefined) {
    if (!issuerNameDer(leafDer).equals(subjectNameDer(leafDer))) {
      throw new DerError(
        "issuer certificate required: the leaf is not self-signed and no issuer certificate was provided"
      );
    }
    ider = leafDer;
  }
  let spkiDer: Buffer;
  try {
    const exported = new X509Certificate(ider).publicKey.export({ type: "spki", format: "der" });
    spkiDer = Buffer.isBuffer(exported) ? exported : Buffer.from(exported as string);
  } catch (err) {
    throw new DerError(`cannot read issuer public key: ${(err as Error).message}`);
  }
  const issuerKeyHash = createHash("sha1").update(spkiPublicKeyBytes(spkiDer)).digest();
  return { issuerNameHash, issuerKeyHash, serialNumber: serialNumberBytes(leafDer) };
}

/**
 * Build a minimal interoperable RFC 6960 OCSPRequest for `certId` (no
 * requestorName, no extensions — every responder accepts this shape).
 */
export function buildOcspRequest(certId: OcspCertId): Buffer {
  const certIdDer = derSequence(
    derSequence(derOid(OID_SHA1), derNull()),
    derOctetString(certId.issuerNameHash),
    derOctetString(certId.issuerKeyHash),
    derIntegerBytes(certId.serialNumber)
  );
  // OCSPRequest { tbsRequest { requestList { Request { reqCert } } } } —
  // the Request SEQUENCE wrapper is required by RFC 6960 §4.1.1
  // (requestList is a SEQUENCE *OF Request*).
  const request = derSequence(certIdDer);
  const requestList = derSequence(request);
  const tbsRequest = derSequence(requestList);
  return derSequence(tbsRequest);
}

/**
 * The OCSP responder URL from the leaf's Authority Information Access
 * extension (RFC 5280 §4.2.2.1, access method `id-ad-ocsp`), or
 * `undefined` when the certificate carries none (or it is unparseable
 * / not `http(s)`). Never throws.
 */
export function extractOcspResponderUrl(leafDer: Buffer): string | undefined {
  try {
    const tbs = tbsCertificate(leafDer);
    const extensions = tbs.children.find((c) => c.cls === 2 && c.tag === 3 && c.constructed);
    if (extensions === undefined || extensions.children.length === 0) return undefined;
    const extSeq = extensions.children[0];
    if (extSeq.tag !== 0x10) return undefined;
    for (const ext of extSeq.children) {
      if (ext.tag !== 0x10 || ext.children.length < 2) continue;
      let extnId: string;
      try {
        extnId = derOidToString(ext.children[0].value);
      } catch {
        continue;
      }
      if (extnId !== OID_AUTHORITY_INFO_ACCESS) continue;
      const aia = parseDer(ext.children[ext.children.length - 1].value);
      if (aia.tag !== 0x10) continue;
      for (const ad of aia.children) {
        if (ad.tag !== 0x10 || ad.children.length < 2) continue;
        let method: string;
        try {
          method = derOidToString(ad.children[0].value);
        } catch {
          continue;
        }
        if (method !== OID_AD_OCSP) continue;
        const location = ad.children[1];
        // uniformResourceIdentifier [6] IMPLICIT IA5String
        if (location.cls !== 2 || location.tag !== 6) continue;
        const url = location.value.toString("ascii");
        if (/^https?:\/\//i.test(url)) return url;
      }
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/* ------------------------------------------------------------------ */
/* OCSP response evaluation                                            */
/* ------------------------------------------------------------------ */

/** Mapped revocation verdict of one SingleResponse. */
export type OcspCertStatus = "good" | "revoked" | "unknown";

export interface OcspEvaluation {
  status: OcspCertStatus;
  /** Hex serial of the evaluated certificate (leading pad stripped). */
  serialNumber: string;
  /** ISO-8601 revocation time, present when revoked. */
  revokedAt?: string;
}

const OCSP_RESPONSE_STATUS_NAMES = [
  "successful",
  "malformedRequest",
  "internalError",
  "tryLater",
  "sigRequired",
  "unauthorized",
] as const;

function certIdMatches(node: DerNode, expected: OcspCertId): boolean {
  try {
    if (node.tag !== 0x10 || node.cls !== 0 || node.children.length < 4) return false;
    const hashAlg = node.children[0];
    if (hashAlg.tag !== 0x10 || hashAlg.children.length < 1) return false;
    if (derOidToString(hashAlg.children[0].value) !== OID_SHA1) return false;
    const nameHash = node.children[1];
    const keyHash = node.children[2];
    const serial = node.children[3];
    return (
      nameHash.tag === 0x04 &&
      nameHash.value.equals(expected.issuerNameHash) &&
      keyHash.tag === 0x04 &&
      keyHash.value.equals(expected.issuerKeyHash) &&
      serial.tag === 0x02 &&
      integerEquals(serial.value, expected.serialNumber)
    );
  } catch {
    return false;
  }
}

function readCertStatus(node: DerNode, expected: OcspCertId): OcspEvaluation {
  const serialNumber = stripLeadingZeros(expected.serialNumber).toString("hex");
  if (node.cls !== 2) throw new DerError("SingleResponse.certStatus is not a CHOICE tag");
  if (node.tag === 0) return { status: "good", serialNumber };
  if (node.tag === 2) return { status: "unknown", serialNumber };
  if (node.tag === 1) {
    // revoked [1] IMPLICIT RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, ... }
    if (!node.constructed || node.children.length < 1) throw new DerError("RevokedInfo malformed");
    return {
      status: "revoked",
      serialNumber,
      revokedAt: generalizedTimeToIso(node.children[0], "RevokedInfo.revocationTime"),
    };
  }
  throw new DerError(`unknown certStatus tag [${node.tag}]`);
}

/**
 * Evaluate an RFC 6960 OCSPResponse against `expected`: the response must
 * be `successful`, carry a BasicOCSPResponse, and contain a SingleResponse
 * whose CertID matches (SHA-1 issuerNameHash/issuerKeyHash + serial).
 * Returns the mapped status; throws {@link DerError} on anything
 * malformed, unexpected, or not about this certificate — callers convert
 * that into the endpoint's fail-open/fail-closed handling.
 */
export function evaluateOcspResponse(ocspDer: Buffer, expected: OcspCertId): OcspEvaluation {
  const resp = parseDer(ocspDer);
  if (resp.tag !== 0x10 || resp.cls !== 0 || resp.children.length < 1) {
    throw new DerError("OCSPResponse is not a SEQUENCE");
  }
  const statusNode = resp.children[0];
  if (statusNode.tag !== 0x0a || statusNode.cls !== 0) {
    throw new DerError("OCSPResponse.responseStatus is not an ENUMERATED");
  }
  const responseStatus = statusNode.value.length === 1 ? statusNode.value[0] : -1;
  if (responseStatus !== 0) {
    const name = OCSP_RESPONSE_STATUS_NAMES[responseStatus] ?? `status(${responseStatus})`;
    throw new DerError(`OCSP responder answered ${name} — not a revocation verdict`);
  }
  if (resp.children.length < 2) throw new DerError("OCSPResponse has no responseBytes");
  const rbWrapper = resp.children[1];
  if (rbWrapper.cls !== 2 || rbWrapper.tag !== 0 || !rbWrapper.constructed || rbWrapper.children.length !== 1) {
    throw new DerError("OCSPResponse.responseBytes is not [0] EXPLICIT");
  }
  const responseBytes = rbWrapper.children[0];
  if (responseBytes.tag !== 0x10 || responseBytes.children.length < 2) {
    throw new DerError("ResponseBytes malformed");
  }
  let responseType: string;
  try {
    responseType = derOidToString(responseBytes.children[0].value);
  } catch (err) {
    throw new DerError(`ResponseBytes.responseType malformed: ${(err as Error).message}`);
  }
  if (responseType !== OID_OCSP_BASIC) {
    throw new DerError(`unsupported OCSP responseType ${responseType}`);
  }
  const basic = parseDer(responseBytes.children[1].value);
  if (basic.tag !== 0x10 || basic.children.length < 1) throw new DerError("BasicOCSPResponse malformed");
  const tbs = basic.children[0];
  if (tbs.tag !== 0x10 || tbs.cls !== 0) throw new DerError("BasicOCSPResponse.tbsResponseData malformed");
  // tbsResponseData: [version [0] EXPLICIT], responderID, producedAt,
  // responses, [responseExtensions] — `responses` is the only universal
  // SEQUENCE child, so it is found structurally.
  const responses = tbs.children.find((c) => c.cls === 0 && c.tag === 0x10);
  if (responses === undefined) throw new DerError("BasicOCSPResponse has no responses");
  for (const single of responses.children) {
    if (single.tag !== 0x10 || single.children.length < 3) continue;
    if (!certIdMatches(single.children[0], expected)) continue;
    return readCertStatus(single.children[1], expected);
  }
  throw new DerError("OCSP response carries no SingleResponse for this certificate");
}

/**
 * The first certificate bundled in a BasicOCSPResponse's `certs` field
 * (conventionally the responder's / issuer's certificate), or `undefined`.
 * Lets the stapled path recover the issuer's public key without a chain.
 * Never throws.
 */
export function issuerCertFromOcspResponse(ocspDer: Buffer): Buffer | undefined {
  try {
    const resp = parseDer(ocspDer);
    const basic = parseDer(resp.children[1].children[0].children[1].value);
    const certs = basic.children.find((c) => c.cls === 2 && c.tag === 0);
    const seq = certs?.children[0];
    const first = seq?.children[0];
    if (first === undefined || first.tag !== 0x10 || first.cls !== 0) return undefined;
    return first.der;
  } catch {
    return undefined;
  }
}

export type { OcspMetricsInput };

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

/**
 * The error a delivery fails with when the peer's certificate is revoked.
 * Thrown at the TLS layer before a single payload byte is written — the
 * revoked peer never observes the body. Follows the normal retry /
 * dead-letter path and *does* count as a breaker failure: the endpoint
 * is serving a dead credential.
 */
export class OcspRevokedError extends Error {
  /** The endpoint whose peer presented a revoked certificate. */
  readonly endpoint: string;
  /** Hex serial of the revoked certificate. */
  readonly serialNumber: string;
  /** ISO-8601 revocation time, when the responder supplied one. */
  readonly revokedAt?: string;

  constructor(endpoint: string, serialNumber: string, revokedAt?: string) {
    super(
      `OCSP revoked certificate for ${endpoint}: serial ${serialNumber} is revoked` +
        (revokedAt !== undefined ? ` (revoked at ${revokedAt})` : "")
    );
    this.name = "OcspRevokedError";
    this.endpoint = endpoint;
    this.serialNumber = serialNumber;
    if (revokedAt !== undefined) this.revokedAt = revokedAt;
  }
}

/**
 * The error a delivery fails with when the revocation *status* could not
 * be determined (no stapled response, no/failing responder, malformed
 * response). In fail-closed mode this fails the attempt through the
 * normal retry / dead-letter path. Explicitly NOT recorded as a
 * circuit-breaker failure (see the WR-101 bypass in `src/retry.ts`): an
 * unreachable OCSP responder is a local telemetry outage, not a sick
 * endpoint.
 */
export class OcspError extends Error {
  /** The endpoint whose revocation status could not be determined. */
  readonly endpoint: string;

  constructor(endpoint: string, detail: string) {
    super(`OCSP check failed for ${endpoint}: ${detail}`);
    this.name = "OcspError";
    this.endpoint = endpoint;
  }
}

/* ------------------------------------------------------------------ */
/* Options                                                             */
/* ------------------------------------------------------------------ */

/**
 * Fetch an OCSPResponse (DER) for `requestDer` from `url` (HTTP POST per
 * RFC 6960 §4.3). Pluggable — tests inject a stub, so the suite never
 * touches a real OCSP responder.
 */
export type OcspResponderFetcher = (url: string, requestDer: Buffer) => Promise<Buffer>;

/** Per-endpoint OCSP tuning, as configured under `tlsOcsp`. All fields validated up front. */
export interface OcspEndpointOptions {
  /**
   * `"fail-open"` (default): an undeterminable revocation status lets the
   * delivery proceed after the alert fires. `"fail-closed"`: it fails the
   * attempt with {@link OcspError}. A `revoked` verdict rejects the
   * delivery in both modes. Pinned endpoints should use `"fail-closed"`.
   */
  mode?: "fail-open" | "fail-closed";
  /**
   * Ask the server to staple its OCSP response (`requestOCSP: true` on
   * the handshake) and prefer it over the responder round-trip. Default:
   * `true`. Set `false` for responder-only checking.
   */
  useStapled?: boolean;
  /**
   * OCSP responder URL. Default: the leaf certificate's Authority
   * Information Access extension. Required (one way or another) when no
   * stapled response arrives — otherwise the check degrades to the
   * mode's undeterminable-status handling on every handshake.
   */
  responderUrl?: string;
  /**
   * Custom responder transport. Default: a plain `node:https` POST.
   * Inject a stub in tests — never hit a real responder from the suite.
   */
  responderFetcher?: OcspResponderFetcher;
  /**
   * Timeout for the default responder fetcher, in ms. Default: 3000.
   * Must be a finite number in [100, 30000]. A custom `responderFetcher`
   * owns its own timeouts.
   */
  responderTimeoutMs?: number;
}

/** Validated {@link OcspEndpointOptions} with defaults applied. */
export interface ResolvedOcspEndpointOptions {
  mode: "fail-open" | "fail-closed";
  useStapled: boolean;
  responderUrl: string | undefined;
  responderFetcher: OcspResponderFetcher;
  responderTimeoutMs: number;
}

/** Default responder fetch timeout: 3s. */
export const DEFAULT_OCSP_RESPONDER_TIMEOUT_MS = 3000;

/** Validate OCSP endpoint options the way a constructor would; returns the resolved values. */
export function resolveOcspEndpointOptions(opts: OcspEndpointOptions = {}): ResolvedOcspEndpointOptions {
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new RangeError(`ocsp: endpoint options must be an object, got ${JSON.stringify(opts)}`);
  }
  const mode = opts.mode ?? "fail-open";
  if (mode !== "fail-open" && mode !== "fail-closed") {
    throw new RangeError(
      `ocsp: mode must be "fail-open" or "fail-closed", got ${JSON.stringify(opts.mode)}`
    );
  }
  const useStapled = opts.useStapled ?? true;
  if (typeof useStapled !== "boolean") {
    throw new RangeError(`ocsp: useStapled must be a boolean, got ${JSON.stringify(opts.useStapled)}`);
  }
  let responderUrl: string | undefined;
  if (opts.responderUrl !== undefined) {
    if (typeof opts.responderUrl !== "string" || opts.responderUrl.trim() === "") {
      throw new RangeError(
        `ocsp: responderUrl must be a non-empty string, got ${JSON.stringify(opts.responderUrl)}`
      );
    }
    let parsed: URL;
    try {
      parsed = new URL(opts.responderUrl);
    } catch {
      throw new RangeError(
        `ocsp: responderUrl is not a valid URL: ${JSON.stringify(opts.responderUrl)}`
      );
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new RangeError(
        `ocsp: responderUrl must be http(s), got ${JSON.stringify(opts.responderUrl)}`
      );
    }
    responderUrl = opts.responderUrl;
  }
  const responderTimeoutMs = opts.responderTimeoutMs ?? DEFAULT_OCSP_RESPONDER_TIMEOUT_MS;
  if (
    typeof responderTimeoutMs !== "number" ||
    !Number.isFinite(responderTimeoutMs) ||
    responderTimeoutMs < 100 ||
    responderTimeoutMs > 30000
  ) {
    throw new RangeError(
      `ocsp: responderTimeoutMs must be a finite number in [100, 30000], got ${JSON.stringify(
        opts.responderTimeoutMs
      )}`
    );
  }
  const responderFetcher =
    opts.responderFetcher ?? ((url, body) => defaultResponderFetcher(url, body, responderTimeoutMs));
  if (typeof responderFetcher !== "function") {
    throw new RangeError(
      `ocsp: responderFetcher must be a function, got ${JSON.stringify(opts.responderFetcher)}`
    );
  }
  return { mode, useStapled, responderUrl, responderFetcher, responderTimeoutMs };
}

const OCSP_RESPONSE_MAX_BYTES = 65536;

/**
 * The built-in OCSP responder fetcher: plain `node:https` POST with
 * `Content-Type: application/ocsp-request` (RFC 6960 §4.3). The timeout
 * timer is unref'd so a hung responder never pins process exit; the
 * response is capped at 64 KiB (an OCSP response is small — anything
 * larger is abuse).
 */
function defaultResponderFetcher(url: string, body: Buffer, timeoutMs: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    // Hoisted (never declared inside the try): the V8 binding-visibility
    // trap bites when a try-declared binding is read in a callback.
    let req: ClientRequest | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let settled = false;
    const settle = (fn: () => void): void => {
      if (!settled) {
        settled = true;
        fn();
      }
    };
    const clearTimer = (): void => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
    };
    try {
      req = httpsRequest(url, {
        method: "POST",
        headers: {
          "content-type": "application/ocsp-request",
          "content-length": String(body.length),
        },
      });
    } catch (err) {
      reject(err instanceof Error ? err : new Error(String(err)));
      return;
    }
    const active = req;
    timer = setTimeout(() => {
      settle(() => reject(new Error(`OCSP responder timed out after ${timeoutMs}ms: ${url}`)));
      active.destroy();
    }, timeoutMs);
    timer.unref?.();
    active.on("error", (err) => {
      clearTimer();
      settle(() => reject(err));
    });
    active.on("response", (res) => {
      const chunks: Buffer[] = [];
      let bytes = 0;
      let oversized = false;
      res.on("data", (chunk: Buffer) => {
        if (oversized) return;
        bytes += chunk.length;
        if (bytes > OCSP_RESPONSE_MAX_BYTES) {
          oversized = true;
          clearTimer();
          settle(() => reject(new Error(`OCSP responder response exceeds ${OCSP_RESPONSE_MAX_BYTES} bytes`)));
          active.destroy();
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => {
        clearTimer();
        if (oversized) return;
        const status = res.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          settle(() => reject(new Error(`OCSP responder answered HTTP ${status}: ${url}`)));
          return;
        }
        const out = Buffer.concat(chunks);
        if (out.length === 0) {
          settle(() => reject(new Error(`OCSP responder returned an empty body: ${url}`)));
          return;
        }
        settle(() => resolve(out));
      });
      res.on("error", (err) => {
        clearTimer();
        settle(() => reject(err));
      });
    });
    active.end(body);
  });
}

/* ------------------------------------------------------------------ */
/* Monitor                                                             */
/* ------------------------------------------------------------------ */

/** The audit event fired when a peer certificate is revoked. */
export interface OcspRevokedAuditEvent {
  event: "ocsp_revoked";
  /** The delivery `targetUrl`. */
  endpoint: string;
  /** Hex serial of the revoked certificate. */
  serialNumber: string;
  /** ISO-8601 revocation time, when the responder supplied one. */
  revokedAt?: string;
  /** The endpoint's configured mode. */
  mode: "fail-open" | "fail-closed";
  /** Where the verdict came from. */
  source: "stapled" | "responder";
  /** ISO-8601 timestamp when the verdict was applied. */
  at: string;
}

/**
 * The alert fired on revocation (both modes, delivery rejected) and on
 * fail-open continuations (status undeterminable, delivery proceeded).
 */
export interface OcspAlert {
  kind: "revoked" | "ocsp_unavailable";
  endpoint: string;
  mode: "fail-open" | "fail-closed";
  detail: string;
  outcome: "rejected" | "proceeded";
  at: string;
}

/** The hook surface of {@link OcspMonitor}. */
export interface OcspHooks {
  /** Fired on every revoked verdict (before the delivery is rejected). */
  onRevoked?: (event: OcspRevokedAuditEvent) => void;
  /** Fired on revocation and on fail-open continuations. */
  onAlert?: (alert: OcspAlert) => void;
}

/** Minimal TLS socket surface the check needs (structural, so tests can fake it). */
export interface OcspTlsSocket {
  getPeerCertificate(detailed?: boolean): unknown;
  getOCSPResponse(): Buffer;
}

function issuerDerFromChain(socket: OcspTlsSocket, leafDer: Buffer): Buffer | undefined {
  try {
    const detailed = socket.getPeerCertificate(true) as
      | { issuerCertificate?: { raw?: unknown } }
      | undefined;
    const raw = detailed?.issuerCertificate?.raw;
    if (!(raw instanceof Buffer) && !(raw instanceof Uint8Array)) return undefined;
    const der = Buffer.from(raw as Buffer);
    // A self-signed leaf reports itself as its own issuer — let the
    // name check in certIdForLeaf make that call instead of assuming it.
    if (der.equals(leafDer)) return undefined;
    return der;
  } catch {
    return undefined;
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * OCSP revocation monitor: runs the per-handshake revocation check,
 * counts `relay_ocsp_total{endpoint,status}` outcomes, and fires the
 * revocation / alert hooks. Construct one per relay (or per sender) and
 * share it — the verified-socket cache is keyed by socket, so sharing is
 * safe.
 */
export class OcspMonitor {
  private readonly counts = new Map<string, { endpoint: string; status: OcspMetricsInput["status"]; n: number }>();
  /**
   * Sockets that already passed the check for an endpoint (socket ->
   * endpoint). Revocation is a property of the certificate presented at
   * session establishment — the peer cannot change underneath a live TLS
   * session — so a pooled socket verified once is not re-checked while
   * it stays pooled. The value records the endpoint because two
   * targetUrls can share one origin with different OCSP policies.
   */
  private readonly verified = new WeakMap<object, string>();
  private readonly hooks: OcspHooks;

  constructor(hooks: OcspHooks = {}) {
    this.hooks = hooks;
  }

  /** True when `socket` already passed the OCSP check for `endpoint`. */
  socketVerified(socket: object, endpoint: string): boolean {
    return this.verified.get(socket) === endpoint;
  }

  /** Count one check outcome (also called for query failures: status `"error"`). */
  record(endpoint: string, status: OcspMetricsInput["status"]): void {
    const key = endpoint + "" + status;
    const entry = this.counts.get(key);
    if (entry === undefined) {
      this.counts.set(key, { endpoint, status, n: 1 });
    } else {
      entry.n += 1;
    }
  }

  /**
   * Check the peer certificate of a handshaked TLS socket for `endpoint`.
   * Resolves when the delivery may proceed (`good`, or an undeterminable
   * status in fail-open mode after the alert fired). Throws
   * {@link OcspRevokedError} on revocation and {@link OcspError} on an
   * undeterminable status in fail-closed mode. A throwing hook never
   * breaks the check — the verdict stands on its own.
   */
  async checkPeer(
    socket: OcspTlsSocket,
    endpoint: string,
    cfg: ResolvedOcspEndpointOptions
  ): Promise<void> {
    let leafDer: Buffer;
    try {
      const peer = socket.getPeerCertificate() as { raw?: unknown } | undefined;
      const raw = peer?.raw;
      if (!(raw instanceof Buffer) && !(raw instanceof Uint8Array)) {
        throw new Error("empty peer certificate");
      }
      leafDer = Buffer.from(raw as Buffer);
      // Fail fast on garbage before any hashing.
      new X509Certificate(leafDer);
    } catch (err) {
      return this.queryFailed(endpoint, cfg, `cannot read peer certificate: ${errMessage(err)}`);
    }

    // Stapled first (RFC 6960 §4): the server's own freshness claim costs
    // no round-trip.
    if (cfg.useStapled) {
      let stapled: Buffer | undefined;
      try {
        const resp = socket.getOCSPResponse();
        if (resp !== undefined && resp.length > 0) stapled = Buffer.from(resp);
      } catch {
        stapled = undefined;
      }
      if (stapled !== undefined) {
        const issuerDer = issuerDerFromChain(socket, leafDer) ?? issuerCertFromOcspResponse(stapled);
        let evaluation: OcspEvaluation;
        try {
          evaluation = evaluateOcspResponse(stapled, certIdForLeaf(leafDer, issuerDer));
        } catch (err) {
          return this.queryFailed(endpoint, cfg, `malformed stapled OCSP response: ${errMessage(err)}`);
        }
        return this.applyEvaluation(socket, endpoint, cfg, evaluation, "stapled");
      }
    }

    // Responder fallback: explicit config wins, else the leaf's AIA.
    let responderUrl = cfg.responderUrl;
    if (responderUrl === undefined) responderUrl = extractOcspResponderUrl(leafDer);
    if (responderUrl === undefined) {
      return this.queryFailed(
        endpoint,
        cfg,
        "no stapled response and no OCSP responder URL (configure responderUrl or serve a certificate with an AIA OCSP entry)"
      );
    }
    const issuerDer = issuerDerFromChain(socket, leafDer);
    let certId: OcspCertId;
    try {
      certId = certIdForLeaf(leafDer, issuerDer);
    } catch (err) {
      return this.queryFailed(endpoint, cfg, errMessage(err));
    }
    let respDer: Buffer;
    try {
      respDer = await cfg.responderFetcher(responderUrl, buildOcspRequest(certId));
    } catch (err) {
      return this.queryFailed(endpoint, cfg, `OCSP responder fetch failed: ${errMessage(err)}`);
    }
    let evaluation: OcspEvaluation;
    try {
      evaluation = evaluateOcspResponse(respDer, certId);
    } catch (err) {
      return this.queryFailed(endpoint, cfg, `malformed OCSP response: ${errMessage(err)}`);
    }
    return this.applyEvaluation(socket, endpoint, cfg, evaluation, "responder");
  }

  private applyEvaluation(
    socket: OcspTlsSocket,
    endpoint: string,
    cfg: ResolvedOcspEndpointOptions,
    evaluation: OcspEvaluation,
    source: "stapled" | "responder"
  ): void {
    if (evaluation.status === "good") {
      this.record(endpoint, "good");
      this.verified.set(socket, endpoint);
      return;
    }
    if (evaluation.status === "revoked") {
      this.record(endpoint, "revoked");
      const at = new Date().toISOString();
      const detail =
        `certificate serial ${evaluation.serialNumber} revoked` +
        (evaluation.revokedAt !== undefined ? ` at ${evaluation.revokedAt}` : "");
      try {
        this.hooks.onRevoked?.({
          event: "ocsp_revoked",
          endpoint,
          serialNumber: evaluation.serialNumber,
          revokedAt: evaluation.revokedAt,
          mode: cfg.mode,
          source,
          at,
        });
      } catch {
        // A throwing audit hook must not downgrade a revocation.
      }
      try {
        this.hooks.onAlert?.({ kind: "revoked", endpoint, mode: cfg.mode, detail, outcome: "rejected", at });
      } catch {
        // Same: the verdict stands on its own.
      }
      throw new OcspRevokedError(endpoint, evaluation.serialNumber, evaluation.revokedAt);
    }
    // "unknown": the responder has no verdict for this certificate — a
    // query-quality signal, so the endpoint's mode decides.
    return this.queryFailed(
      endpoint,
      cfg,
      `OCSP responder returned "unknown" for serial ${evaluation.serialNumber}`
    );
  }

  private queryFailed(endpoint: string, cfg: ResolvedOcspEndpointOptions, detail: string): void {
    this.record(endpoint, "error");
    const at = new Date().toISOString();
    if (cfg.mode === "fail-open") {
      // Fail-open (the default): the delivery proceeds — a dead or
      // unreachable responder must not take down deliveries — but the
      // operator is alerted, and the socket is deliberately NOT marked
      // verified, so the next delivery retries the check.
      try {
        this.hooks.onAlert?.({
          kind: "ocsp_unavailable",
          endpoint,
          mode: cfg.mode,
          detail,
          outcome: "proceeded",
          at,
        });
      } catch {
        // Alerting is best-effort; the delivery still proceeds.
      }
      return;
    }
    try {
      this.hooks.onAlert?.({
        kind: "ocsp_unavailable",
        endpoint,
        mode: cfg.mode,
        detail,
        outcome: "rejected",
        at,
      });
    } catch {
      // The rejection stands on its own.
    }
    throw new OcspError(endpoint, detail);
  }

  /** Current counter rows, in first-seen order. */
  series(): OcspMetricsInput[] {
    return [...this.counts.values()].map((e) => ({ endpoint: e.endpoint, status: e.status, count: e.n }));
  }

  /**
   * Prometheus text exposition (0.0.4) of the counter block; `""` when
   * nothing was checked, so `GET /metrics` stays byte-identical for
   * relays that never enabled the feature.
   */
  render(): string {
    const lines = renderOcspBlock(this.series());
    return lines.length === 0 ? "" : lines.join("\n") + "\n";
  }
}
