/**
 * Inbound source baseline anomaly detection (WR-63).
 *
 * A webhook relay's senders are usually stable: the same payment provider
 * posts from the same egress IPs over the same TLS parameters for months.
 * When a *new* (IP, TLS fingerprint) pair shows up on an endpoint for the
 * first time, it is worth an audit line — it may be a provider migrating
 * egress, or it may be someone else's infrastructure talking to your
 * intake. This module learns that baseline per endpoint and reports
 * deviations; it never blocks.
 *
 * - Opt-in per endpoint: `endpoints` lists inbound path patterns (exact
 *   `/hooks/stripe` or prefix `/hooks/*`), matched first-match-wins with
 *   the same semantics as the WR-53 IP ACL. Paths with no matching rule
 *   are never observed, so enabling the feature changes nothing for
 *   unlisted endpoints.
 * - The baseline key is `(sourceIp, tlsFingerprint)`. The source IP is the
 *   one the server resolves (the WR-53 `clientIp` when an IP ACL is
 *   configured, otherwise the direct socket peer). The TLS fingerprint is
 *   approximate by design: the inbound listener is plain HTTP
 *   (`createServer`), so the socket is normally a `net.Socket` and the
 *   fingerprint is the literal string `"plain"`. When the socket looks
 *   like a TLS socket (it exposes `getProtocol()`/`getCipher()` — i.e. a
 *   `tls.TLSSocket`), the fingerprint is `${protocol}:${cipherName}`
 *   (e.g. `"TLSv1.3:TLS_AES_256_GCM_SHA384"`, `"TLSv1.2:unknown"` when the
 *   cipher is unavailable). This is *not* a cryptographic identity of the
 *   peer — it cannot distinguish two clients behind the same terminator —
 *   it only notices when the *transport profile* of a sender changes.
 * - First sighting learns the baseline silently (no audit noise for the
 *   steady state); a later new (IP, fingerprint) pair on a guarded
 *   endpoint returns a `SourceBaselineAnomaly` describing only the
 *   deviating triple (`endpoint`, `path`, `sourceIp`, `fingerprint`,
 *   `at`) — the rest of the learned baseline is never disclosed.
 * - Alert-only, always: `observe()` never rejects, never throws on hostile
 *   input, and never mutates the request. It is orthogonal to the WR-53
 *   IP ACL, which *blocks*; this module only *notices*. The server runs
 *   the check after the IP ACL (a denied IP returns before the check, so
 *   blocked senders never teach the baseline) and before the body is
 *   read, so even the observation costs almost nothing.
 * - Baselines live in memory by default. With `dir` set, every newly
 *   learned triple is appended to `<dir>/source-baseline.jsonl`
 *   (append-only, one JSON object per line) and reloaded at construction,
 *   so baselines survive restarts. Persistence is best-effort like
 *   WR-55/WR-49: a failed append is counted in `writeErrors` and never
 *   throws (a full disk must not fail an intake), and recovery skips torn
 *   or malformed lines instead of aborting.
 * - Invalid config throws `RangeError` at startup (fail fast, never
 *   mid-request), following the project convention.
 *
 * Zero dependencies; hand-written like `src/ip-acl.ts`.
 */

import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { selectEndpointIpAclRule } from "./ip-acl.ts";

/** Baseline file name inside the persistence directory. */
export const SOURCE_BASELINE_FILE = "source-baseline.jsonl";

/** The fingerprint recorded for a non-TLS (plain HTTP) inbound socket. */
export const PLAIN_FINGERPRINT = "plain";

/** Options for {@link SourceBaselineDetector}. */
export interface SourceBaselineOptions {
  /**
   * Inbound path patterns whose sender baselines are learned (exact
   * `/hooks/stripe` or prefix `/hooks/*`; first match wins, same
   * semantics as the WR-53 IP ACL). Unset or empty: nothing is observed
   * and the feature is effectively off.
   */
  endpoints?: string[];
  /**
   * Opt-in persistence directory holding `source-baseline.jsonl`.
   * Created recursively when missing. Unset: baselines live in memory
   * only and are forgotten on restart.
   */
  dir?: string;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** One newly learned (endpoint, IP, fingerprint) triple. */
export interface SourceBaselineRecord {
  /** The matched endpoint pattern (e.g. `"/hooks/*"`). */
  endpoint: string;
  /** The source IP that was first seen. */
  sourceIp: string;
  /** The approximate TLS fingerprint that was first seen. */
  fingerprint: string;
  /** ISO-8601 timestamp of first sighting. */
  at: string;
}

/**
 * A baseline deviation: a (source IP, TLS fingerprint) pair never seen
 * before on this endpoint. Carries only the deviating triple — never the
 * rest of the learned baseline.
 */
export interface SourceBaselineAnomaly {
  /** The matched endpoint pattern (e.g. `"/hooks/*"`). */
  endpoint: string;
  /** The concrete inbound request path that deviated. */
  path: string;
  /** The newly seen source IP. */
  sourceIp: string;
  /** The newly seen approximate TLS fingerprint. */
  fingerprint: string;
  /** ISO-8601 timestamp of detection. */
  at: string;
}

/** Fail with a RangeError naming the offending input. */
function invalid(where: string, detail: string): never {
  throw new RangeError(`sourceBaseline: ${where}: ${detail}`);
}

/**
 * Validate {@link SourceBaselineOptions}. Throws RangeError on a
 * non-object, a non-array `endpoints`, a pattern that is not a
 * `/`-rooted path, a non-string/empty `dir`, or a non-function `now` —
 * fail fast at startup, never mid-request.
 */
export function assertValidSourceBaselineOptions(opts: SourceBaselineOptions): void {
  if (opts === undefined || opts === null) return;
  if (typeof opts !== "object" || Array.isArray(opts)) {
    throw new RangeError("sourceBaseline: expected an options object");
  }
  if (opts.endpoints !== undefined) {
    if (!Array.isArray(opts.endpoints)) {
      throw new RangeError("sourceBaseline.endpoints: expected an array of path patterns");
    }
    opts.endpoints.forEach((pattern, i) => {
      if (typeof pattern !== "string" || pattern === "" || !pattern.startsWith("/")) {
        throw new RangeError(
          `sourceBaseline.endpoints[${i}]: pattern must be a path starting with "/" (exact) or ending with "/*" (prefix)`
        );
      }
    });
  }
  if (opts.dir !== undefined && (typeof opts.dir !== "string" || opts.dir === "")) {
    throw new RangeError("sourceBaseline.dir: expected a non-empty directory path string");
  }
  if (opts.now !== undefined && typeof opts.now !== "function") {
    throw new RangeError("sourceBaseline.now: expected a function returning ms");
  }
}

interface TlsLikeSocket {
  getProtocol(): string | undefined;
  getCipher(): { name?: string } | null | undefined;
}

/**
 * Approximate TLS fingerprint for an inbound socket. The listener is
 * plain HTTP, so the socket is normally a `net.Socket` and this returns
 * `"plain"`. When the socket exposes `getProtocol()`/`getCipher()` (a
 * `tls.TLSSocket`, e.g. behind a TLS-terminating front), it returns
 * `${protocol}:${cipherName}` (`"unknown"` fills either side when
 * unavailable). Duck-typed instead of `instanceof TLSSocket` so test
 * fakes and wrapped sockets work; never throws.
 */
export function tlsFingerprintOf(socket: unknown): string {
  if (socket !== null && typeof socket === "object") {
    const s = socket as Partial<TlsLikeSocket>;
    if (typeof s.getProtocol === "function" && typeof s.getCipher === "function") {
      let protocol = "unknown";
      try {
        const p = s.getProtocol();
        if (typeof p === "string" && p !== "") protocol = p;
      } catch {
        // A hostile or half-closed socket: fall back to "unknown".
      }
      let cipher = "unknown";
      try {
        const c = s.getCipher();
        if (c !== null && c !== undefined && typeof c.name === "string" && c.name !== "") {
          cipher = c.name;
        }
      } catch {
        // Same as above.
      }
      return `${protocol}:${cipher}`;
    }
  }
  return PLAIN_FINGERPRINT;
}

/**
 * Per-endpoint sender baseline: learns (source IP, TLS fingerprint)
 * triples and reports first-time deviations. Construct once at server
 * startup (invalid config throws RangeError there); `observe` is then
 * safe to call on every request — it never throws and never blocks.
 */
export class SourceBaselineDetector {
  private readonly rules: { pattern: string }[];
  /** pattern -> composite key -> the learned record (kept in insertion order). */
  private readonly baselines = new Map<string, Map<string, SourceBaselineRecord>>();
  private readonly file: string | undefined;
  private readonly now: () => number;
  private writeErr = 0;

  constructor(opts: SourceBaselineOptions = {}) {
    assertValidSourceBaselineOptions(opts);
    this.rules = (opts.endpoints ?? []).map((pattern) => ({ pattern }));
    this.now = opts.now ?? Date.now;
    if (opts.dir !== undefined) {
      mkdirSync(opts.dir, { recursive: true });
      this.file = join(opts.dir, SOURCE_BASELINE_FILE);
      this.recover();
    }
  }

  /**
   * Observe one inbound request. The first sighting for an endpoint
   * pattern learns the baseline silently and returns `null`; a later new
   * (source IP, TLS fingerprint) triple on a guarded endpoint returns a
   * {@link SourceBaselineAnomaly} (the caller audits it — alert-only, the
   * request itself is never affected). The deviating triple is absorbed
   * into the baseline, so a persistent new sender alerts exactly once.
   * Paths matching no rule, and repeat sightings of a known triple,
   * return `null`. Never throws.
   */
  observe(pathname: string, sourceIp: string, socket: unknown): SourceBaselineAnomaly | null {
    try {
      const rule = selectEndpointIpAclRule(pathname, this.rules);
      if (rule === undefined) return null;
      const ip = typeof sourceIp === "string" && sourceIp !== "" ? sourceIp : "unknown";
      const fingerprint = tlsFingerprintOf(socket);
      // "\n" cannot appear in an IP literal and is vanishingly unlikely in
      // a cipher name; it keeps the composite key unambiguous.
      const key = `${ip}\n${fingerprint}`;
      let seen = this.baselines.get(rule.pattern);
      if (seen === undefined) {
        seen = new Map();
        this.baselines.set(rule.pattern, seen);
      }
      if (seen.has(key)) return null;
      // A pattern with no baseline yet is still being established: learn
      // silently. Only a deviation *from an established baseline* alerts.
      const establishing = seen.size === 0;
      const record: SourceBaselineRecord = {
        endpoint: rule.pattern,
        sourceIp: ip,
        fingerprint,
        at: new Date(this.now()).toISOString(),
      };
      seen.set(key, record);
      this.persist(record);
      return establishing ? null : { ...record, path: pathname };
    } catch {
      // Observation must never break intake: on any internal failure,
      // stay silent and let the request through.
      return null;
    }
  }

  /** Total number of learned (endpoint, IP, fingerprint) triples. */
  get size(): number {
    let n = 0;
    for (const seen of this.baselines.values()) n += seen.size;
    return n;
  }

  /**
   * Failed persistence appends (counted, never thrown) — a full disk
   * degrades to memory-only baselines instead of failing intake.
   */
  get writeErrors(): number {
    return this.writeErr;
  }

  /**
   * Snapshot of every learned baseline triple (for tests and operator
   * introspection). The returned array is a copy; mutating it changes
   * nothing.
   */
  learned(): SourceBaselineRecord[] {
    const out: SourceBaselineRecord[] = [];
    for (const seen of this.baselines.values()) {
      for (const record of seen.values()) out.push({ ...record });
    }
    return out;
  }

  /** Append one newly learned triple to the JSONL journal (best-effort). */
  private persist(record: SourceBaselineRecord): void {
    if (this.file === undefined) return;
    try {
      appendFileSync(this.file, JSON.stringify(record) + "\n", "utf8");
    } catch {
      this.writeErr += 1;
    }
  }

  /**
   * Reload baselines learned by earlier runs. Torn or malformed lines are
   * skipped (best-effort recovery, like WR-49/WR-55); baselines for
   * endpoints no longer configured are ignored. Recovered triples are
   * *not* re-appended — they are already on disk.
   */
  private recover(): void {
    if (this.file === undefined) return;
    let raw: string;
    try {
      raw = readFileSync(this.file, "utf8");
    } catch {
      return; // No journal yet — nothing to recover.
    }
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (trimmed === "") continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        continue; // Torn write or garbage: skip, keep recovering.
      }
      if (parsed === null || typeof parsed !== "object") continue;
      const rec = parsed as Record<string, unknown>;
      if (
        typeof rec.endpoint !== "string" ||
        typeof rec.sourceIp !== "string" ||
        typeof rec.fingerprint !== "string"
      ) {
        continue;
      }
      if (!this.rules.some((r) => r.pattern === rec.endpoint)) continue;
      let seen = this.baselines.get(rec.endpoint);
      if (seen === undefined) {
        seen = new Map();
        this.baselines.set(rec.endpoint, seen);
      }
      const key = `${rec.sourceIp}\n${rec.fingerprint}`;
      if (!seen.has(key)) {
        seen.set(key, {
          endpoint: rec.endpoint,
          sourceIp: rec.sourceIp,
          fingerprint: rec.fingerprint,
          at: typeof rec.at === "string" ? rec.at : "",
        });
      }
    }
  }
}
