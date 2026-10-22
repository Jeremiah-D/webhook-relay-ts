/**
 * RFC 9421 HTTP Message Signatures — outbound signing (WR-187).
 *
 * An IETF-standard alternative to the relay's custom outbound stamps
 * (WR-26 `x-relay-signature` HMAC, WR-124 `x-relay-ed25519-signature`):
 * the signer builds a canonical *signature base* from covered message
 * components (`@method`, `@authority`, `@path`, `content-digest`, plain
 * header fields, `@query-param`, ...), signs it, and renders the
 * `Signature-Input` + `Signature` header pair. Any RFC 9421 verifier —
 * not just this relay — can check the delivery, which is the point: bank
 * gateways and partner settlement hooks that speak the standard need no
 * relay-specific code.
 *
 * Algorithms are `hmac-sha256` and `ed25519`, reusing the same
 * `node:crypto` primitives as `verify.ts` (`HmacSha256Verifier`,
 * `Ed25519Verifier`) and `outbound-ed25519.ts` — only the header format
 * and the signed bytes (the signature base) are new. RSA variants from
 * the RFC registry are out of scope (the relay's RSA helper uses
 * RSA-PSS/SHA-256 with a 32-byte salt, which does not match the RFC's
 * `rsa-pss-sha512` parameters).
 *
 * Zero dependencies. `verifyRfc9421` never throws (unverifiable input is
 * `false`), matching the {@link Verifier} contract in `verify.ts`.
 */

import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";

/** Signature algorithms this module implements (RFC 9421 §3.3.3, §3.3.6). */
export type Rfc9421Algorithm = "hmac-sha256" | "ed25519";

/** A covered component of the signature base (RFC 9421 §2). */
export type Rfc9421Component =
  | "@method"
  | "@authority"
  | "@scheme"
  | "@target-uri"
  | "@request-target"
  | "@path"
  | "@query"
  | "@status"
  | { header: string }
  | { queryParam: string };

/** Covered-component constructor for a plain HTTP field. */
export function headerComponent(name: string): Rfc9421Component {
  return { header: name };
}

/** Covered-component constructor for `@query-param`; `name` is the encoded parameter name. */
export function queryParamComponent(name: string): Rfc9421Component {
  return { queryParam: name };
}

/**
 * The signer's view of the HTTP message being signed. Values are used
 * verbatim (after the RFC's normalizations, documented per component) —
 * the verifier must build the same view from the message it received.
 */
export interface Rfc9421Message {
  /** HTTP method, e.g. `"POST"` (no case transformation is applied). */
  method: string;
  /** `host[:port]`, e.g. `"example.com"` (lowercased per RFC §2.2.3). */
  authority: string;
  /** URI scheme, lowercased. Default `"https"`. */
  scheme?: string;
  /** Absolute path without the query string, e.g. `"/foo"` (empty → `"/"`). */
  path: string;
  /** Raw query string *without* the leading `?`, e.g. `"param=Value&Pet=dog"`. */
  query?: string;
  /** Header fields; names are matched case-insensitively. */
  headers: Record<string, string | string[]>;
  /** Response status code (required only when `@status` is covered). */
  status?: number;
}

/** Signature metadata parameters (RFC 9421 §2.3). */
export interface Rfc9421SignatureParams {
  /** Signature creation time, UNIX seconds. Recommended; defaults to now. */
  created?: number;
  /** Signature expiry, UNIX seconds. */
  expires?: number;
  /** Signer-provided unique value (replay protection). */
  nonce?: string;
  /** The signature algorithm, echoed as the `alg` parameter. */
  alg?: Rfc9421Algorithm;
  /** Key identifier, echoed as the `keyid` parameter. */
  keyId?: string;
  /** Application-specific tag. */
  tag?: string;
}

/** Key material for {@link signRfc9421}. */
export interface Rfc9421SigningKey {
  alg: Rfc9421Algorithm;
  /** HMAC secret as raw bytes; a string is interpreted as UTF-8. */
  secret?: Buffer | string;
  /** PEM-encoded Ed25519 private key. */
  privateKeyPem?: string;
}

/** Key material for {@link verifyRfc9421}. */
export interface Rfc9421VerifyKey {
  alg: Rfc9421Algorithm;
  /** HMAC secret as raw bytes; a string is interpreted as UTF-8. */
  secret?: Buffer | string;
  /** PEM-encoded Ed25519 public key. */
  publicKeyPem?: string;
}

function secretBytes(secret: Buffer | string, where: string): Buffer {
  if (Buffer.isBuffer(secret)) {
    if (secret.length === 0) throw new RangeError(`${where}: \`secret\` must not be empty`);
    return secret;
  }
  if (typeof secret !== "string" || secret === "") {
    throw new RangeError(`${where}: \`secret\` must be a non-empty string or Buffer`);
  }
  return Buffer.from(secret, "utf8");
}

function parseEd25519PrivateKey(pem: string, where: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey(pem);
  } catch {
    throw new RangeError(`${where}: \`privateKeyPem\` is not a valid PEM private key`);
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new RangeError(
      `${where}: \`privateKeyPem\` must be an Ed25519 private key, got ${key.asymmetricKeyType ?? "unknown"}`
    );
  }
  return key;
}

function parseEd25519PublicKey(pem: string, where: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPublicKey(pem);
  } catch {
    throw new RangeError(`${where}: \`publicKeyPem\` is not a valid PEM public key`);
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new RangeError(
      `${where}: \`publicKeyPem\` must be an Ed25519 public key, got ${key.asymmetricKeyType ?? "unknown"}`
    );
  }
  return key;
}

/** application/x-www-form-urlencoded "percent-encode after encoding" (RFC 9421 §2.2.8). */
function formUrlEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Decode one form-urlencoded name/value (plus → space, then percent-decoding). */
function formUrlDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

function headerValue(headers: Record<string, string | string[]>, name: string): string {
  const lower = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === lower) {
      const v = headers[k];
      const values = Array.isArray(v) ? v : [v];
      return values
        .map((x) => String(x).replace(/^[ \t]+|[ \t]+$/g, ""))
        .join(", ");
    }
  }
  throw new Error(`rfc9421: header "${name}" is not present in the message`);
}

interface ParsedComponent {
  /** Item name as it appears in the inner list, e.g. `"@query-param"` or `"date"`. */
  item: string;
  /** Item parameters, e.g. `;name="Pet"`. */
  params: { name: string; value: string }[];
  /** The signature-base line value for this component. */
  value: string;
}

function queryValue(message: Rfc9421Message, encodedName: string): string {
  const raw = (message.query ?? "").replace(/^\?/, "");
  const matches: string[] = [];
  for (const pair of raw.split("&")) {
    if (pair === "") continue;
    const eq = pair.indexOf("=");
    const nameEnc = eq === -1 ? pair : pair.slice(0, eq);
    const valueEnc = eq === -1 ? "" : pair.slice(eq + 1);
    if (formUrlEncode(formUrlDecode(nameEnc)) === encodedName) {
      matches.push(formUrlEncode(formUrlDecode(valueEnc)));
    }
  }
  if (matches.length === 0) {
    throw new Error(`rfc9421: query parameter "${encodedName}" is not present in the message`);
  }
  if (matches.length > 1) {
    throw new Error(
      `rfc9421: query parameter "${encodedName}" occurs ${matches.length} times; @query-param must not cover repeated parameters`
    );
  }
  return matches[0];
}

/** Serialize one covered component to its `{ item, value }` pair. */
function resolveComponent(message: Rfc9421Message, component: Rfc9421Component): ParsedComponent {
  const fail = (why: string): never => {
    throw new Error(`rfc9421: ${why}`);
  };
  if (typeof component === "string") {
    const scheme = (message.scheme ?? "https").toLowerCase();
    const authority = message.authority.toLowerCase();
    const path = message.path === "" ? "/" : message.path;
    const query = message.query ?? "";
    switch (component) {
      case "@method":
        if (!message.method) fail("@method requires `message.method`");
        return { item: '"@method"', params: [], value: message.method };
      case "@authority":
        if (!message.authority) fail("@authority requires `message.authority`");
        return { item: '"@authority"', params: [], value: authority };
      case "@scheme":
        return { item: '"@scheme"', params: [], value: scheme };
      case "@target-uri":
        return {
          item: '"@target-uri"',
          params: [],
          value: `${scheme}://${authority}${path}${query === "" ? "" : `?${query}`}`,
        };
      case "@request-target":
        return {
          item: '"@request-target"',
          params: [],
          value: `${path}${query === "" ? "" : `?${query}`}`,
        };
      case "@path":
        return { item: '"@path"', params: [], value: path };
      case "@query":
        return { item: '"@query"', params: [], value: query === "" ? "?" : `?${query}` };
      case "@status": {
        if (message.status === undefined) fail("@status requires `message.status` (a response)");
        if (!Number.isInteger(message.status) || message.status < 100 || message.status > 599) {
          fail(`@status requires a 3-digit status code, got ${message.status}`);
        }
        return { item: '"@status"', params: [], value: String(message.status) };
      }
      default:
        fail(`unknown derived component "${component}"`);
    }
  }
  if ("header" in component) {
    if (typeof component.header !== "string" || component.header === "") {
      fail("header component needs a non-empty field name");
    }
    return {
      item: `"${component.header.toLowerCase()}"`,
      params: [],
      value: headerValue(message.headers, component.header),
    };
  }
  if (typeof component.queryParam !== "string" || component.queryParam === "") {
    fail("queryParam component needs a non-empty parameter name");
  }
  return {
    item: '"@query-param"',
    params: [{ name: "name", value: component.queryParam }],
    value: queryValue(message, component.queryParam),
  };
}

function serializeString(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function serializeItem(item: string, params: { name: string; value: string }[]): string {
  let out = item;
  for (const p of params) out += `;${p.name}=${serializeString(p.value)}`;
  return out;
}

/**
 * The fixed signature-parameter order this module uses when signing:
 * created, expires, nonce, alg, keyid, tag. RFC 9421 lets the signer pick
 * any order ("once an ordering is chosen it cannot be changed"); fixing
 * it here keeps `signRfc9421` output deterministic for a given input.
 */
const PARAM_ORDER = ["created", "expires", "nonce", "alg", "keyid", "tag"] as const;

function serializeParams(params: Rfc9421SignatureParams): string {
  const parts: string[] = [];
  const push = (name: string, value: string | number, quoted: boolean) => {
    parts.push(`;${name}=${quoted ? serializeString(value as string) : String(value)}`);
  };
  if (params.created !== undefined) {
    if (!Number.isInteger(params.created) || params.created < 0) {
      throw new RangeError("rfc9421: `created` must be a non-negative integer (UNIX seconds)");
    }
    push("created", params.created, false);
  }
  if (params.expires !== undefined) {
    if (!Number.isInteger(params.expires) || params.expires < 0) {
      throw new RangeError("rfc9421: `expires` must be a non-negative integer (UNIX seconds)");
    }
    push("expires", params.expires, false);
  }
  if (params.nonce !== undefined) push("nonce", params.nonce, true);
  if (params.alg !== undefined) push("alg", params.alg, true);
  if (params.keyId !== undefined) push("keyid", params.keyId, true);
  if (params.tag !== undefined) push("tag", params.tag, true);
  return parts.join("");
}

function signatureParamsLine(items: ParsedComponent[], paramsTail: string): string {
  const inner = items.map((c) => serializeItem(c.item, c.params)).join(" ");
  return `"@signature-params": (${inner})${paramsTail}`;
}

/**
 * Builds the canonical signature base (RFC 9421 §2.5): one
 * `"<name>": <value>` line per covered component, then the
 * `"@signature-params"` line. This exact byte string is what gets signed.
 */
export function buildSignatureBase(
  message: Rfc9421Message,
  components: Rfc9421Component[],
  params: Rfc9421SignatureParams = {}
): string {
  if (!Array.isArray(components)) {
    throw new RangeError("rfc9421: `components` must be an array");
  }
  const resolved = components.map((c) => resolveComponent(message, c));
  const lines = resolved.map((c) => `${serializeItem(c.item, c.params)}: ${c.value}`);
  lines.push(signatureParamsLine(resolved, serializeParams(params)));
  return lines.join("\n");
}

/**
 * Renders the `Signature-Input` field value (RFC 9421 §4.1):
 * `<label>=(<components>);<params>`.
 */
export function renderSignatureInput(
  label: string,
  components: Rfc9421Component[],
  params: Rfc9421SignatureParams = {}
): string {
  assertLabel(label);
  if (!Array.isArray(components)) {
    throw new RangeError("rfc9421: `components` must be an array");
  }
  // Resolve eagerly so config errors surface here, not at sign time.
  const resolved = components.map((c) => {
    if (typeof c === "string") return { item: `"${c}"`, params: [] as { name: string; value: string }[] };
    if ("header" in c) return { item: `"${c.header.toLowerCase()}"`, params: [] as { name: string; value: string }[] };
    return { item: '"@query-param"', params: [{ name: "name", value: c.queryParam }] };
  });
  const inner = resolved.map((c) => serializeItem(c.item, c.params)).join(" ");
  return `${label}=(${inner})${serializeParams(params)}`;
}

/** Renders the `Signature` field value (RFC 9421 §4.2): `<label>=:<base64>:`. */
export function renderSignature(label: string, signatureBytes: Buffer): string {
  assertLabel(label);
  return `${label}=:${signatureBytes.toString("base64")}:`;
}

function assertLabel(label: string): void {
  if (typeof label !== "string" || !/^[a-z0-9_*][a-z0-9_.*-]*$/i.test(label)) {
    throw new RangeError("rfc9421: `label` must be a non-empty token");
  }
}

/** Options for {@link signRfc9421}. */
export interface Rfc9421SignOptions {
  message: Rfc9421Message;
  /** Covered components, in signature-base order. */
  components: Rfc9421Component[];
  /** Signature label, e.g. `"sig1"`. */
  label: string;
  key: Rfc9421SigningKey;
  /** Passed through to the signature parameters; defaults to the current time. */
  created?: number;
  expires?: number;
  nonce?: string;
  tag?: string;
  keyId?: string;
  /**
   * Echoed as the `alg` signature parameter when set. Opt-in: leaving it
   * unset keeps the parameter list exactly as specified (the RFC's own
   * test vectors carry no `alg`). The signature is always computed with
   * `key.alg` regardless.
   */
  alg?: Rfc9421Algorithm;
}

/** The signed output: both header values plus the signed bytes (for audit/debug). */
export interface Rfc9421Signed {
  /** `Signature-Input` field value (without the field name). */
  signatureInput: string;
  /** `Signature` field value (without the field name). */
  signature: string;
  /** The exact bytes that were signed. */
  signatureBase: string;
}

/**
 * Signs an outbound message per RFC 9421 and renders the
 * `Signature-Input` / `Signature` header pair. Throws `RangeError` on bad
 * config (fail fast at startup, never mid-delivery).
 */
export function signRfc9421(opts: Rfc9421SignOptions): Rfc9421Signed {
  if (opts === null || typeof opts !== "object") {
    throw new RangeError("rfc9421: options must be an object");
  }
  const { message, components, label, key } = opts;
  if (key === null || typeof key !== "object") {
    throw new RangeError("rfc9421: `key` must be an object");
  }
  if (key.alg !== "hmac-sha256" && key.alg !== "ed25519") {
    throw new RangeError('rfc9421: `key.alg` must be "hmac-sha256" or "ed25519"');
  }
  const params: Rfc9421SignatureParams = {
    created: opts.created ?? Math.floor(Date.now() / 1000),
    expires: opts.expires,
    nonce: opts.nonce,
    // `alg` is opt-in only: the signer controls exactly which parameters
    // appear (byte-exact interop with RFC Appendix B vectors needs no
    // `alg`). The crypto still always uses `key.alg`.
    alg: opts.alg,
    keyId: opts.keyId,
    tag: opts.tag,
  };
  const signatureBase = buildSignatureBase(message, components, params);
  const baseBytes = Buffer.from(signatureBase, "utf8");
  let sig: Buffer;
  if (key.alg === "hmac-sha256") {
    if (key.secret === undefined) throw new RangeError("rfc9421: hmac-sha256 needs `key.secret`");
    sig = createHmac("sha256", secretBytes(key.secret, "rfc9421")).update(baseBytes).digest();
  } else {
    if (key.privateKeyPem === undefined) {
      throw new RangeError("rfc9421: ed25519 needs `key.privateKeyPem`");
    }
    sig = cryptoSign(null, baseBytes, parseEd25519PrivateKey(key.privateKeyPem, "rfc9421"));
  }
  return {
    signatureInput: renderSignatureInput(label, components, params),
    signature: renderSignature(label, sig),
    signatureBase,
  };
}

// --- Signature-Input / Signature parsing (for verification) ---

interface ParsedInnerItem {
  item: string;
  params: { name: string; value: string }[];
}

interface ParsedSignatureEntry {
  label: string;
  items: ParsedInnerItem[];
  /** The raw parameter tail after the inner list, e.g. `;created=1;keyid="k"`. */
  paramsTail: string;
  /** The same parameters, parsed (names lowercased). */
  params: { name: string; value: string }[];
}

class FieldParser {
  private pos = 0;
  private readonly input: string;

  constructor(input: string) {
    this.input = input;
  }

  private eof(): boolean {
    return this.pos >= this.input.length;
  }

  private peek(): string {
    return this.input[this.pos];
  }

  skipWs(): void {
    while (!this.eof() && (this.peek() === " " || this.peek() === "\t")) this.pos++;
  }

  expect(ch: string): void {
    if (this.eof() || this.peek() !== ch) {
      throw new Error(`rfc9421: expected "${ch}" at offset ${this.pos}`);
    }
    this.pos++;
  }

  /** Reads a token/label up to a delimiter. */
  readToken(): string {
    const start = this.pos;
    while (!this.eof() && /[A-Za-z0-9_*.\-]/.test(this.peek())) this.pos++;
    if (this.pos === start) throw new Error(`rfc9421: expected token at offset ${start}`);
    return this.input.slice(start, this.pos);
  }

  readQuotedString(): string {
    this.expect('"');
    let out = "";
    while (!this.eof()) {
      const ch = this.peek();
      if (ch === "\\") {
        this.pos++;
        if (this.eof()) break;
        out += this.peek();
        this.pos++;
      } else if (ch === '"') {
        this.pos++;
        return out;
      } else {
        out += ch;
        this.pos++;
      }
    }
    throw new Error("rfc9421: unterminated string");
  }

  /** Reads a parameter value: string, integer, or bare token. */
  readParamValue(): string {
    this.skipWs();
    if (this.eof()) throw new Error("rfc9421: expected parameter value");
    const ch = this.peek();
    if (ch === '"') return this.readQuotedString();
    if (ch === ":") {
      // byte sequence :...: — keep the raw inner text; not interpreted here.
      this.pos++;
      const start = this.pos;
      while (!this.eof() && this.peek() !== ":") this.pos++;
      this.expect(":");
      return this.input.slice(start, this.pos - 1);
    }
    const start = this.pos;
    while (!this.eof() && /[A-Za-z0-9_.\-?\/+]/i.test(this.peek())) this.pos++;
    if (this.pos === start) throw new Error(`rfc9421: bad parameter value at offset ${start}`);
    return this.input.slice(start, this.pos);
  }

  readParams(): { name: string; value: string }[] {
    const params: { name: string; value: string }[] = [];
    for (;;) {
      this.skipWs();
      if (this.eof() || this.peek() !== ";") return params;
      this.pos++;
      this.skipWs();
      const name = this.readToken().toLowerCase();
      this.skipWs();
      this.expect("=");
      this.skipWs();
      params.push({ name, value: this.readParamValue() });
    }
  }

  /** Reads one inner-list item: `"str"` or `"str";p=v ...`. */
  readInnerItem(): ParsedInnerItem {
    this.skipWs();
    const item = this.readQuotedString();
    const params = this.readParams();
    return { item, params };
  }

  readInnerList(): ParsedInnerItem[] {
    this.expect("(");
    const items: ParsedInnerItem[] = [];
    for (;;) {
      this.skipWs();
      if (!this.eof() && this.peek() === ")") {
        this.pos++;
        return items;
      }
      items.push(this.readInnerItem());
      this.skipWs();
    }
  }

  atEnd(): boolean {
    this.skipWs();
    return this.eof();
  }
}

/**
 * Parses a `Signature-Input` field value into its labeled entries. Throws
 * on malformed input (callers that must never throw, like
 * {@link verifyRfc9421}, convert this to `false`).
 */
export function parseSignatureInput(fieldValue: string): ParsedSignatureEntry[] {
  if (typeof fieldValue !== "string" || fieldValue.trim() === "") {
    throw new Error("rfc9421: empty Signature-Input");
  }
  const p = new FieldParser(fieldValue);
  const entries: ParsedSignatureEntry[] = [];
  for (;;) {
    p.skipWs();
    const label = p.readToken();
    p.skipWs();
    p.expect("=");
    p.skipWs();
    const items = p.readInnerList();
    // The parameter tail is everything up to the next top-level comma or
    // end — captured verbatim so the signature base rebuild is byte-exact.
    let depth = 0;
    let inStr = false;
    let i = (p as unknown as { pos: number }).pos;
    const start = i;
    for (; i < fieldValue.length; i++) {
      const ch = fieldValue[i];
      if (inStr) {
        if (ch === "\\") i++;
        else if (ch === '"') inStr = false;
      } else if (ch === '"') {
        inStr = true;
      } else if (ch === "(") {
        depth++;
      } else if (ch === ")") {
        depth--;
      } else if (ch === "," && depth === 0) {
        break;
      }
    }
    const paramsTail = fieldValue.slice(start, i).trim();
    let params: { name: string; value: string }[] = [];
    if (paramsTail !== "") {
      try {
        params = new FieldParser(paramsTail).readParams();
      } catch {
        throw new Error("rfc9421: malformed signature parameters");
      }
    }
    (p as unknown as { pos: number }).pos = i;
    entries.push({ label, items, paramsTail, params });
    p.skipWs();
    if (p.atEnd()) break;
    p.expect(",");
  }
  return entries;
}

/** Extracts the raw signature bytes for `label` from a `Signature` field value. */
function parseSignatureField(fieldValue: string, label: string): Buffer | undefined {
  if (typeof fieldValue !== "string" || fieldValue.trim() === "") return undefined;
  const p = new FieldParser(fieldValue);
  for (;;) {
    p.skipWs();
    let entryLabel: string;
    try {
      entryLabel = p.readToken();
    } catch {
      return undefined;
    }
    p.skipWs();
    try {
      p.expect("=");
      p.skipWs();
      p.expect(":");
    } catch {
      return undefined;
    }
    const start = (p as unknown as { pos: number }).pos;
    const end = fieldValue.indexOf(":", start);
    if (end === -1) return undefined;
    const b64 = fieldValue.slice(start, end).replace(/\s+/g, "");
    (p as unknown as { pos: number }).pos = end + 1;
    if (entryLabel === label) {
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64 === "") return undefined;
      return Buffer.from(b64, "base64");
    }
    p.skipWs();
    if (p.atEnd()) return undefined;
    try {
      p.expect(",");
    } catch {
      return undefined;
    }
  }
}

/** Options for {@link verifyRfc9421}. */
export interface Rfc9421VerifyOptions {
  message: Rfc9421Message;
  /** `Signature-Input` field value (without the field name). */
  signatureInput: string;
  /** `Signature` field value (without the field name). */
  signature: string;
  /**
   * Which labeled signature to verify. Defaults to the only entry when
   * the field carries exactly one signature.
   */
  label?: string;
  key: Rfc9421VerifyKey;
}

/**
 * Verifies an RFC 9421 signature: parses `Signature-Input`, rebuilds the
 * signature base from `message`, and checks the `Signature` bytes. Returns
 * `true` on success, `false` on any failure — malformed fields, unknown
 * labels, missing components, wrong keys, and crypto errors never throw.
 *
 * Freshness (`created`/`expires`) is deliberately not enforced here: the
 * RFC leaves replay policy to the application (see §7.2.2) — check
 * `created` yourself against your clock when it matters.
 */
export function verifyRfc9421(opts: Rfc9421VerifyOptions): boolean {
  try {
    if (opts === null || typeof opts !== "object") return false;
    const { message, signatureInput, signature, key } = opts;
    if (key === null || typeof key !== "object") return false;
    if (key.alg !== "hmac-sha256" && key.alg !== "ed25519") return false;

    const entries = parseSignatureInput(signatureInput);
    let entry: ParsedSignatureEntry | undefined;
    if (opts.label !== undefined) {
      entry = entries.find((e) => e.label === opts.label);
    } else if (entries.length === 1) {
      entry = entries[0];
    }
    if (!entry) return false;

    const sigBytes = parseSignatureField(signature, entry.label);
    if (!sigBytes || sigBytes.length === 0) return false;

    // Fail closed on an algorithm mismatch declared by the signer: a
    // signature that claims alg="hmac-sha256" must not verify under an
    // Ed25519 key and vice versa.
    const declaredAlg = entry.params.find((p) => p.name === "alg")?.value;
    if (declaredAlg !== undefined && declaredAlg !== key.alg) return false;

    const base = rebuildBase(message, entry);
    const baseBytes = Buffer.from(base, "utf8");

    if (key.alg === "hmac-sha256") {
      if (key.secret === undefined) return false;
      const expected = createHmac("sha256", secretBytes(key.secret, "rfc9421"))
        .update(baseBytes)
        .digest();
      return expected.length === sigBytes.length && timingSafeEqual(expected, sigBytes);
    }
    if (key.publicKeyPem === undefined) return false;
    return cryptoVerify(null, baseBytes, parseEd25519PublicKey(key.publicKeyPem, "rfc9421"), sigBytes);
  } catch {
    return false;
  }
}

/** Rebuilds the signature base from parsed Signature-Input items (verify path). */
function rebuildBase(message: Rfc9421Message, entry: ParsedSignatureEntry): string {
  const lines: string[] = [];
  const items: ParsedComponent[] = [];
  for (const it of entry.items) {
    const name = it.item;
    if (name.startsWith("@")) {
      if (name === "@query-param") {
        const nameParam = it.params.find((p) => p.name === "name");
        if (!nameParam) throw new Error('rfc9421: @query-param without a "name" parameter');
        items.push({ item: `"${name}"`, params: it.params });
        lines.push(`${serializeItem(`"${name}"`, it.params)}: ${queryValue(message, nameParam.value)}`);
      } else {
        items.push({ item: `"${name}"`, params: it.params });
        lines.push(`${serializeItem(`"${name}"`, it.params)}: ${derivedValue(message, name)}`);
      }
    } else {
      items.push({ item: `"${name.toLowerCase()}"`, params: it.params });
      lines.push(`${serializeItem(`"${name.toLowerCase()}"`, it.params)}: ${headerValue(message.headers, name)}`);
    }
  }
  lines.push(signatureParamsLine(items, entry.paramsTail));
  return lines.join("\n");
}

function derivedValue(message: Rfc9421Message, name: string): string {
  const scheme = (message.scheme ?? "https").toLowerCase();
  const authority = message.authority.toLowerCase();
  const path = message.path === "" ? "/" : message.path;
  const query = message.query ?? "";
  switch (name) {
    case "@method":
      if (!message.method) throw new Error("rfc9421: @method requires `message.method`");
      return message.method;
    case "@authority":
      if (!message.authority) throw new Error("rfc9421: @authority requires `message.authority`");
      return authority;
    case "@scheme":
      return scheme;
    case "@target-uri":
      return `${scheme}://${authority}${path}${query === "" ? "" : `?${query}`}`;
    case "@request-target":
      return `${path}${query === "" ? "" : `?${query}`}`;
    case "@path":
      return path;
    case "@query":
      return query === "" ? "?" : `?${query}`;
    case "@status": {
      if (message.status === undefined) throw new Error("rfc9421: @status requires `message.status`");
      return String(message.status);
    }
    default:
      throw new Error(`rfc9421: unknown derived component "${name}"`);
  }
}

/**
 * Builds an RFC 9530 `Content-Digest` field value (`sha-512=:<base64>:`)
 * for `body`, so the digest can be covered like any header component.
 */
export function contentDigestSha512(body: Buffer): string {
  const digest = createHash("sha512").update(body).digest("base64");
  return `sha-512=:${digest}:`;
}
