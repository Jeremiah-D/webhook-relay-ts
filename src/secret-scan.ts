/**
 * WR-183: payload secret-leak detection and alerting.
 *
 * Webhooks sometimes carry secrets they should not — a developer pastes a
 * GitHub token into a notification payload, an upstream bug echoes a Stripe
 * key back. `SecretScanner` scans inbound payloads and audit-persisted
 * payloads for well-known secret shapes and reports hits as
 * `{ pattern, path }` pairs. The secret *value* is never returned, never
 * logged, and never written to the audit trail — only the pattern name and
 * the field path where it was seen.
 *
 * Where it runs:
 * - `createRelayServer({ secretScan })` scans the verified, decompressed
 *   inbound body in `admitOneEvent` (after the payload-hash dedup check, so
 *   suppressed duplicates do not re-alert). Default: alert-only. Opt-in
 *   `blockMode` answers 400 `secret_detected` and never enqueues.
 * - `AuditLog` (`new AuditLog(path, { secretScanner })`, or
 *   `setSecretScanner()` — the server installs one when `secretScan` is
 *   enabled) scans the `payload` field of every appended event before the
 *   WR-72 field mask and the WR-11 encryptor run: masking still lands first
 *   on disk, and a `secret_leak_suspected` alert event is appended for each
 *   hit. Alert events carry no payload and are never re-scanned.
 *
 * The default pattern table covers the shapes the backlog item names.
 * A custom table *replaces* the defaults — pass the full table you want.
 * Detection is best-effort (regexes, not entropy analysis); false positives
 * are tolerated by design, which is why the default posture is alert-only.
 */

import { randomBytes } from "node:crypto";

/** One named secret shape. `pattern` is tested against every string leaf. */
export interface SecretPattern {
  /** Stable name surfaced in alerts, e.g. `"github_token"`. */
  name: string;
  /** Compiled regex. Must not carry the `g` flag (stateful lastIndex). */
  pattern: RegExp;
}

/** One detection: which shape, at which dot-separated field path. */
export interface SecretHit {
  /** The `SecretPattern.name` that matched. */
  pattern: string;
  /**
   * Dot-separated path from the payload root (`"payment.card.cvv"`,
   * `"items.0.note"`); `"(raw)"` when the payload was not JSON-shaped
   * and the raw text was scanned.
   */
  path: string;
}

/** Options for {@link SecretScanner}. */
export interface SecretScannerOptions {
  /**
   * Custom pattern table — *replaces* the defaults entirely. Every entry
   * must have a non-empty `name` and a `RegExp` pattern; invalid entries
   * throw `RangeError` at construction, never mid-request.
   */
  patterns?: SecretPattern[];
}

/** Maximum hits reported per scan — bounds alert payloads on hostile input. */
export const MAX_SECRET_HITS = 25;

/**
 * The default pattern table (WR-183): the shapes named in the backlog item.
 * Anchored to reduce false positives, but deliberately broad — detection is
 * alert-first, and `blockMode` is the operator's explicit opt-in.
 */
export const DEFAULT_SECRET_PATTERNS: SecretPattern[] = [
  { name: "aws_access_key_id", pattern: /\bAKI[AD][0-9A-Z]{16}\b/ },
  { name: "github_token", pattern: /\bgh[po]_[A-Za-z0-9]{20,}\b/ },
  { name: "stripe_secret_key", pattern: /\bsk_(live|test)_[A-Za-z0-9]{10,}\b/ },
  { name: "slack_bot_token", pattern: /\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b/ },
  { name: "private_key", pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/ },
];

function checkPatterns(patterns: unknown): SecretPattern[] {
  if (patterns === undefined) return DEFAULT_SECRET_PATTERNS;
  if (!Array.isArray(patterns) || patterns.length === 0) {
    throw new RangeError(
      `secret-scan patterns must be a non-empty array, got ${JSON.stringify(patterns)}`
    );
  }
  const seen = new Set<string>();
  return patterns.map((p, i) => {
    if (p === null || typeof p !== "object" || Array.isArray(p)) {
      throw new RangeError(`secret-scan pattern[${i}] must be an object, got ${JSON.stringify(p)}`);
    }
    const { name, pattern } = p as SecretPattern;
    if (typeof name !== "string" || name.length === 0) {
      throw new RangeError(`secret-scan pattern[${i}] must have a non-empty name`);
    }
    if (seen.has(name)) {
      throw new RangeError(`secret-scan pattern name ${JSON.stringify(name)} is duplicated`);
    }
    seen.add(name);
    if (!(pattern instanceof RegExp)) {
      throw new RangeError(`secret-scan pattern ${JSON.stringify(name)} must be a RegExp`);
    }
    if (pattern.global || pattern.sticky) {
      throw new RangeError(
        `secret-scan pattern ${JSON.stringify(name)} must not carry the g/y flags (stateful matching)`
      );
    }
    return { name, pattern };
  });
}

function tryParseJsonObject(text: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  return parsed !== null && typeof parsed === "object" ? parsed : undefined;
}

/**
 * Best-effort secret-shape scanner. Stateless after construction; safe to
 * share across requests. `scan*` never throws on adversarial input — a
 * poisoned payload must not take down admission.
 */
export class SecretScanner {
  private readonly patterns: SecretPattern[];

  constructor(opts: SecretScannerOptions = {}) {
    this.patterns = checkPatterns(opts.patterns);
  }

  /** The pattern names this scanner looks for (for operator introspection). */
  patternNames(): string[] {
    return this.patterns.map((p) => p.name);
  }

  /**
   * Scan a JSON-shaped value, walking objects and arrays. Returns one hit
   * per (pattern, path) pair, capped at {@link MAX_SECRET_HITS}. Only
   * string leaves are tested — a secret is always text.
   */
  scanJson(value: unknown): SecretHit[] {
    const hits: SecretHit[] = [];
    const seen = new Set<string>();
    const visit = (node: unknown, path: string): void => {
      if (hits.length >= MAX_SECRET_HITS) return;
      if (typeof node === "string") {
        for (const p of this.patterns) {
          let matched = false;
          try {
            matched = p.pattern.test(node);
          } catch {
            continue; // a hostile pattern must not break a scan
          }
          if (matched) {
            const key = `${p.name}\u0000${path}`;
            if (!seen.has(key)) {
              seen.add(key);
              hits.push({ pattern: p.name, path });
            }
          }
        }
        return;
      }
      if (Array.isArray(node)) {
        for (let i = 0; i < node.length; i++) {
          visit(node[i], `${path}[${i}]`);
          if (hits.length >= MAX_SECRET_HITS) return;
        }
        return;
      }
      if (node !== null && typeof node === "object") {
        for (const [k, v] of Object.entries(node)) {
          // Skip the prototype-pollution lanes the same way masking does.
          if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
          visit(v, path.length === 0 ? k : `${path}.${k}`);
          if (hits.length >= MAX_SECRET_HITS) return;
        }
      }
    };
    try {
      visit(value, "");
    } catch {
      // Defensive: a getter throwing mid-walk must not kill admission.
    }
    return hits;
  }

  /**
   * Scan raw text (a non-JSON payload, or a body scanned before parsing).
   * Hits carry the path `"(raw)"`.
   */
  scanText(text: string): SecretHit[] {
    const hits: SecretHit[] = [];
    for (const p of this.patterns) {
      let matched = false;
      try {
        matched = p.pattern.test(text);
      } catch {
        continue;
      }
      if (matched) hits.push({ pattern: p.name, path: "(raw)" });
      if (hits.length >= MAX_SECRET_HITS) break;
    }
    return hits;
  }

  /**
   * Scan an inbound wire body: JSON bodies get field paths, anything else
   * is scanned as raw text. Never throws.
   */
  scanBuffer(body: Buffer): SecretHit[] {
    const text = body.toString("utf8");
    const parsed = tryParseJsonObject(text);
    return parsed === undefined ? this.scanText(text) : this.scanJson(parsed);
  }

  /**
   * Scan an audit event's `payload` field (Buffer, string, or a parsed
   * value). Events without a `payload` field produce no hits. Never
   * throws — a scan failure degrades to "no hits", never a dropped audit
   * line.
   */
  scanEventPayload(event: object): SecretHit[] {
    try {
      const payload = (event as Record<string, unknown>).payload;
      if (payload === undefined) return [];
      if (Buffer.isBuffer(payload)) return this.scanBuffer(payload);
      if (typeof payload === "string") {
        const parsed = tryParseJsonObject(payload);
        return parsed === undefined ? this.scanText(payload) : this.scanJson(parsed);
      }
      if (payload !== null && typeof payload === "object") return this.scanJson(payload);
      return [];
    } catch {
      return [];
    }
  }
}

/** Random hex id helper shared with the audit HMAC chain (WR-184). */
export function randomId(prefix: string): string {
  return `${prefix}-${randomBytes(4).toString("hex")}`;
}
