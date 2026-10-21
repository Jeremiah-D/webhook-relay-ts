import type { DeadLetterEntry } from "./retry.ts";
import type { FailureClass } from "./failure.ts";

/**
 * Dead-letter error-signature clustering (WR-175).
 *
 * Operators staring at a dead-letter queue full of
 * `connect ETIMEDOUT 93.184.216.34:443` and
 * `connect ETIMEDOUT 203.0.113.7:8443` want one line, not two hundred.
 * This module normalizes each entry's `lastError` into a stable
 * *signature* — volatile tokens (numbers, UUIDs, timestamps, hex
 * digests) become placeholders — and groups entries by
 * `(endpoint, failure_class, signature)`.
 *
 * Each cluster reports `count`, `firstSeen`/`lastSeen`, and a sample
 * entry (id + traceId) so the operator can drill into one exemplar.
 * Combined with `RetryQueue.replayDeadLetters` (WR-23), a whole
 * cluster — e.g. every dead letter from one poison payload or one
 * down endpoint — can be re-queued in one call.
 *
 * Pure logic, zero dependencies.
 */

const UUID_RE = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g;
const ISO_TS_RE = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g;
const EPOCH_MS_RE = /\b\d{13}\b/g;
const EPOCH_S_RE = /\b1[5-9]\d{8}\b/g;
const HEX_0X_RE = /0x[0-9a-fA-F]+/g;
const HEX_RUN_RE = /\b[0-9a-fA-F]{8,}\b/g;
// A dotted quad is four numbers, not a decimal: normalize it before the
// generic number rule so `10.0.0.1` becomes `{n}.{n}.{n}.{n}` rather
// than the decimal-greedy `{n}.{n}`.
const IPV4_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
const NUMBER_RE = /-?\b\d+\b/g;

/**
 * Normalize an error message into a stable signature: volatile tokens
 * become placeholders so errors that differ only in incidental values
 * cluster together.
 *
 * Replacement order matters (UUIDs before hex runs, timestamps before
 * bare numbers):
 *
 * - UUIDs → `{uuid}`
 * - ISO-8601 timestamps and epoch ms/s → `{ts}`
 * - `0x…` and long bare hex runs (with at least one digit) → `{hex}`
 * - remaining numbers → `{n}`
 *
 * Examples:
 * - `connect ETIMEDOUT 93.184.216.34:443` →
 *   `connect ETIMEDOUT {n}.{n}.{n}.{n}:{n}`
 * - `request 9f2b1c4d-7e8a-4f1d-9c3e-2a5b6d7e8f90 failed after 3 attempts` →
 *   `request {uuid} failed after {n} attempts`
 */
export function normalizeErrorSignature(message: string): string {
  let s = message.trim();
  s = s.replace(UUID_RE, "{uuid}");
  s = s.replace(ISO_TS_RE, "{ts}");
  s = s.replace(EPOCH_MS_RE, "{ts}");
  s = s.replace(EPOCH_S_RE, "{ts}");
  s = s.replace(HEX_0X_RE, "{hex}");
  s = s.replace(HEX_RUN_RE, (m) => (/\d/.test(m) ? "{hex}" : m));
  s = s.replace(IPV4_RE, "{n}.{n}.{n}.{n}");
  s = s.replace(NUMBER_RE, "{n}");
  return s;
}

/** One error cluster: entries sharing endpoint + failure class + signature. */
export interface DeadLetterCluster {
  /**
   * Stable, reversible cluster identity: base64url of the JSON triple
   * `[endpoint, failureClass, signature]`.
   */
  clusterId: string;
  /** The endpoint the entries were dead-lettered for (`targetUrl`). */
  endpoint: string;
  /** `failure_class` shared by every member (see `src/failure.ts`). */
  failureClass: FailureClass;
  /** Normalized error signature (see {@link normalizeErrorSignature}). */
  signature: string;
  /** Members in this cluster. */
  count: number;
  /** ISO-8601 instant the first member was dead-lettered. */
  firstSeen: string;
  /** ISO-8601 instant the latest member was dead-lettered. */
  lastSeen: string;
  /** The earliest member — a drill-in exemplar for the operator. */
  sample: { id: string; traceId?: string; lastError: string };
}

/** Encode the reversible cluster identity. */
export function clusterIdFor(endpoint: string, failureClass: string, signature: string): string {
  return Buffer.from(JSON.stringify([endpoint, failureClass, signature]), "utf8").toString("base64url");
}

/** Decode a {@link clusterIdFor} identity back to its triple. */
export function clusterIdDecode(clusterId: string): { endpoint: string; failureClass: string; signature: string } {
  // Node's base64 decoder silently skips invalid characters, so
  // validate the charset explicitly — a mangled id must fail loud.
  if (!/^[A-Za-z0-9_-]+$/.test(clusterId)) {
    throw new Error(`deadletter-cluster: malformed cluster id ${JSON.stringify(clusterId)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(clusterId, "base64url").toString("utf8"));
  } catch {
    throw new Error(`deadletter-cluster: malformed cluster id ${JSON.stringify(clusterId)}`);
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length !== 3 ||
    parsed.some((p) => typeof p !== "string")
  ) {
    throw new Error(`deadletter-cluster: malformed cluster id ${JSON.stringify(clusterId)}`);
  }
  const [endpoint, failureClass, signature] = parsed as [string, string, string];
  return { endpoint, failureClass, signature };
}

/**
 * Cluster dead-letter entries by `(endpoint, failure_class,
 * normalized error signature)`. Returns clusters sorted by `count`
 * descending, then `firstSeen` ascending — the loudest, longest-running
 * failure first. Empty input → empty output.
 */
export function clusterDeadLetters(entries: readonly DeadLetterEntry[]): DeadLetterCluster[] {
  const groups = new Map<string, DeadLetterCluster & { members: DeadLetterEntry[] }>();
  for (const entry of entries) {
    const signature = normalizeErrorSignature(entry.lastError);
    const key = `${entry.targetUrl}\n${entry.failureClass}\n${signature}`;
    let g = groups.get(key);
    if (g === undefined) {
      g = {
        clusterId: clusterIdFor(entry.targetUrl, entry.failureClass, signature),
        endpoint: entry.targetUrl,
        failureClass: entry.failureClass,
        signature,
        count: 0,
        firstSeen: entry.deadLetteredAt,
        lastSeen: entry.deadLetteredAt,
        sample: {
          id: entry.id,
          ...(entry.traceId !== undefined ? { traceId: entry.traceId } : {}),
          lastError: entry.lastError,
        },
        members: [],
      };
      groups.set(key, g);
    }
    g.count += 1;
    g.members.push(entry);
    if (entry.deadLetteredAt < g.firstSeen) {
      g.firstSeen = entry.deadLetteredAt;
      g.sample = {
        id: entry.id,
        ...(entry.traceId !== undefined ? { traceId: entry.traceId } : {}),
        lastError: entry.lastError,
      };
    }
    if (entry.deadLetteredAt > g.lastSeen) g.lastSeen = entry.deadLetteredAt;
  }
  const clusters = [...groups.values()].map(({ members: _members, ...cluster }) => cluster);
  clusters.sort((a, b) => b.count - a.count || (a.firstSeen < b.firstSeen ? -1 : a.firstSeen > b.firstSeen ? 1 : 0));
  return clusters;
}

/**
 * Return at most `top` clusters (the head of the count-sorted list).
 * `top` must be a positive integer — fail-fast `RangeError` otherwise.
 */
export function topClusters(clusters: readonly DeadLetterCluster[], top: number): DeadLetterCluster[] {
  if (!Number.isInteger(top) || top < 1) {
    throw new RangeError(`deadletter-cluster: \`top\` must be a positive integer, got ${top}`);
  }
  return [...clusters].slice(0, top);
}
