/**
 * WR-72: field-level masking for audit payloads (PII/PAN hygiene).
 *
 * Some webhook payloads carry fields that must never reach the audit
 * trail in the clear — card numbers, national IDs, tokens. `FieldMask`
 * holds opt-in, per-endpoint masking rules keyed by dot-separated field
 * paths (e.g. `card_number`, `payment.card.number`; numeric segments
 * address array elements, e.g. `items.0.sku`).
 *
 * Masking is *irreversible*: `"full"` replaces the value with `"****"`,
 * `"last4"` keeps only the last four characters of a string
 * (`"4111111111111111"` → `"****1111"`). There is no unmask operation —
 * a masked value cannot be turned back into the original.
 *
 * Where it runs (always *before* the WR-11 payload encryptor seals
 * anything, so the raw values never reach the ciphertext either):
 *
 * - `AuditLog.append` — the `payload` field of any audit event whose
 *   `targetUrl`/`endpoint` has rules, when the payload is JSON-shaped;
 * - `RetryQueue` — the opt-in WR-54 `responseBodyCapture` body, when it
 *   parses as JSON, before it is sealed into `capturedBody`.
 *
 * Non-JSON payloads cannot take field paths and pass through untouched
 * (a documented limitation, not a silent drop). Missing paths are no-ops.
 * The input value is never mutated — masking works on a deep clone.
 */

/** How the matched value is replaced. `"full"` by default. */
export type MaskStrategy = "full" | "last4";

/** One field path to mask for an endpoint. */
export interface FieldMaskRule {
  /**
   * Dot-separated path from the payload root, e.g. `"card_number"` or
   * `"payment.card.number"`. Numeric segments address array elements
   * (`"items.0.sku"`). Empty segments and the prototype-pollution
   * segments `__proto__` / `constructor` / `prototype` are rejected with
   * `RangeError` at construction.
   */
  path: string;
  /** Replacement strategy. Default: `"full"`. */
  strategy?: MaskStrategy;
}

interface CompiledRule {
  segments: string[];
  strategy: MaskStrategy;
}

/** Segments that would allow prototype pollution — never valid in a path. */
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);

function checkPath(path: unknown): string[] {
  if (typeof path !== "string" || path.length === 0) {
    throw new RangeError(`field-mask path must be a non-empty string, got ${JSON.stringify(path)}`);
  }
  const segments = path.split(".");
  for (const seg of segments) {
    if (seg.length === 0) {
      throw new RangeError(
        `invalid field-mask path ${JSON.stringify(path)}: empty segment`
      );
    }
    if (FORBIDDEN_SEGMENTS.has(seg)) {
      throw new RangeError(
        `invalid field-mask path ${JSON.stringify(path)}: forbidden segment ${JSON.stringify(seg)}`
      );
    }
  }
  return segments;
}

function checkStrategy(strategy: unknown): MaskStrategy {
  const s = strategy ?? "full";
  if (s !== "full" && s !== "last4") {
    throw new RangeError(`field-mask strategy must be "full" or "last4", got ${JSON.stringify(strategy)}`);
  }
  return s;
}

/**
 * Replace one leaf value. Short strings and non-strings under `"last4"`
 * fall back to `"****"` — a 3-character secret has no safe "last 4".
 * Non-primitive values (objects/arrays) are always fully masked: a
 * subtree cannot be partially redacted safely.
 */
function maskLeaf(value: unknown, strategy: MaskStrategy): unknown {
  if (strategy === "last4" && typeof value === "string" && value.length > 4) {
    return `****${value.slice(-4)}`;
  }
  return "****";
}

function applyRule(root: unknown, rule: CompiledRule): void {
  let node: unknown = root;
  const segs = rule.segments;
  for (let i = 0; i < segs.length - 1; i++) {
    if (node === null || typeof node !== "object") return;
    node = (node as Record<string, unknown>)[segs[i]];
  }
  if (node === null || typeof node !== "object") return;
  const leaf = segs[segs.length - 1];
  const rec = node as Record<string, unknown>;
  if (!Object.prototype.hasOwnProperty.call(rec, leaf)) return; // missing path: no-op
  rec[leaf] = maskLeaf(rec[leaf], rule.strategy);
}

/**
 * Per-endpoint field-masking rules. Construct once, share between the
 * `AuditLog` and the `RetryQueue` — the same instance may back both.
 */
export class FieldMask {
  private readonly rules = new Map<string, CompiledRule[]>();

  /**
   * `rulesByEndpoint` maps an endpoint (the delivery `targetUrl`) to its
   * masking rules. Endpoints without an entry are never masked. Invalid
   * paths, strategies, or shapes throw `RangeError` at construction —
   * never mid-request.
   */
  constructor(rulesByEndpoint: Record<string, FieldMaskRule[]>) {
    if (
      rulesByEndpoint === null ||
      typeof rulesByEndpoint !== "object" ||
      Array.isArray(rulesByEndpoint)
    ) {
      throw new RangeError(
        `field-mask rules must be an object mapping endpoint to rules, got ${JSON.stringify(rulesByEndpoint)}`
      );
    }
    for (const [endpoint, rules] of Object.entries(rulesByEndpoint)) {
      if (!Array.isArray(rules)) {
        throw new RangeError(
          `field-mask rules for ${JSON.stringify(endpoint)} must be an array, got ${JSON.stringify(rules)}`
        );
      }
      this.rules.set(
        endpoint,
        rules.map((rule) => {
          if (rule === null || typeof rule !== "object" || Array.isArray(rule)) {
            throw new RangeError(
              `field-mask rule must be an object, got ${JSON.stringify(rule)}`
            );
          }
          return {
            segments: checkPath((rule as FieldMaskRule).path),
            strategy: checkStrategy((rule as FieldMaskRule).strategy),
          };
        })
      );
    }
  }

  /** Whether `endpoint` has at least one masking rule. */
  hasRules(endpoint: string): boolean {
    const r = this.rules.get(endpoint);
    return r !== undefined && r.length > 0;
  }

  /**
   * Deep-clone `value` with every rule for `endpoint` applied. Returns
   * `value` itself (uncloned, untouched) when the endpoint has no rules.
   * The clone is JSON-shaped when the input is; `structuredClone` keeps
   * Buffers and other natives intact.
   */
  maskJson(endpoint: string, value: unknown): unknown {
    const rules = this.rules.get(endpoint);
    if (rules === undefined || rules.length === 0) return value;
    const clone = structuredClone(value);
    for (const rule of rules) applyRule(clone, rule);
    return clone;
  }
}
