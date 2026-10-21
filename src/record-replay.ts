import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import type {
  RetryItem,
  Sender,
  SenderCallOptions,
  DownstreamResponse,
} from "./retry.ts";

/**
 * Outbound downstream interaction record/replay harness (WR-174).
 *
 * A test harness for the delivery path, orthogonal to the WR-165 chaos
 * drill: chaos *injects* synthetic faults, this module *records* real
 * downstream interactions and *replays* them deterministically.
 *
 * - Record mode wraps a `Sender`: after every attempt settles, it
 *   captures `(method, url, header-names, payload-hash) →
 *   (status/body | transport error, latency)` and keeps it in memory.
 *   The capture contains the payload **hash, never the plaintext** —
 *   sensitive payloads never touch disk — and request header *names*
 *   only (values may carry credentials).
 * - Replay mode builds a `Sender` from a recording file that never
 *   touches the network: matched requests get the recorded response,
 *   unmatched requests throw `ReplayNoMatchError` fail-loud (an
 *   offline CI run must never silently pass through to a real
 *   downstream). Transport-error recordings re-throw an equivalent
 *   error (same `code`), so the queue classifies the replay exactly
 *   like the original failure.
 *
 * The recording file is plain JSON and version-pinned (`version: 1`),
 * so it can be committed next to the tests it drives.
 *
 * Zero dependencies beyond `node:`.
 */

/** The outbound HTTP method. */
export type RecordedMethod = string;

/**
 * What the record side observed about one attempt's request.
 *
 * `method` is informational: the `Sender` contract does not expose the
 * HTTP method (an implementation detail of each sender), so the
 * wrapper records `defaultMethod` (default `"POST"` — exactly what
 * `createDefaultSender` issues). Custom senders that issue other
 * methods should override it.
 */
export interface RecordedRequest {
  method: RecordedMethod;
  /** The attempt's `targetUrl`. */
  url: string;
  /**
   * Request header names only, lower-cased and sorted — values are
   * never persisted (they may carry credentials or PII).
   */
  headerNames: string[];
  /** SHA-256 hex of the exact request payload bytes. */
  payloadSha256: string;
  /** Request payload byte length. */
  payloadBytes: number;
}

/** What the record side observed about one attempt's outcome. */
export type RecordedOutcome =
  | {
      ok: true;
      /** HTTP status the downstream returned. */
      status: number;
      /** Base64 of the captured response body ("" when none). */
      bodyBase64: string;
      bodyBytes: number;
      truncated: boolean;
      /**
       * The wrapped sender returned `void` (transport success, no
       * response observed) — replay resolves `undefined` the same way.
       */
      voidResponse?: boolean;
    }
  | {
      ok: false;
      /** `code` of the thrown error when it had one (`ECONNRESET`, …). */
      errorCode?: string;
      /** The thrown error's message (may embed IPs/ports — see below). */
      errorMessage: string;
    };

/** One recorded attempt. */
export interface RecordedInteraction {
  request: RecordedRequest;
  response: RecordedOutcome;
  /** Attempt latency the wrapper observed, ms. */
  latencyMs: number;
  /** ISO-8601 instant the interaction was recorded. */
  recordedAt: string;
}

/** On-disk recording file shape. `version` pins the schema. */
export interface RecordingFile {
  version: 1;
  generator: string;
  recordedAt: string;
  recordings: RecordedInteraction[];
}

/** How replay picks the recorded answer for an incoming request. */
export type RecordReplayMatchStrategy =
  | "exact-url"
  | "url-prefix"
  | "payload-hash"
  | ((request: RecordedRequest, recordings: readonly RecordedInteraction[]) => RecordedInteraction | undefined);

/** Configuration for the record/replay harness. */
export interface RecordReplayConfig {
  /** `"record"` wraps a sender and captures; `"replay"` builds a network-free sender. */
  mode: "record" | "replay";
  /**
   * Recorded `method` for every request — the `Sender` contract does
   * not expose the HTTP method. Defaults to `"POST"` (what
   * `createDefaultSender` always issues); override for custom senders.
   * Non-empty string.
   */
  defaultMethod?: string;
  /** Replay matching rule. Defaults to `"exact-url"`. */
  matchStrategy?: RecordReplayMatchStrategy;
  /**
   * Cap on in-memory recordings in record mode; the oldest are
   * evicted first. Positive integer, default 10000.
   */
  maxRecordings?: number;
  /** Clock override (tests). Defaults to `Date.now`. */
  now?: () => number;
}

/** A validated `RecordReplayConfig`. */
export interface ResolvedRecordReplayConfig {
  mode: "record" | "replay";
  defaultMethod: string;
  matchStrategy: RecordReplayMatchStrategy;
  maxRecordings: number;
  now: () => number;
}

const RECORDING_VERSION = 1;
const GENERATOR = "webhook-relay-ts/record-replay";

function isRecord(o: unknown): o is Record<string, unknown> {
  return o !== null && typeof o === "object" && !Array.isArray(o);
}

/**
 * Validate a record/replay config the way a constructor would; returns
 * the resolved config. `what` prefixes `RangeError` messages (e.g.
 * `"createReplaySender"`).
 */
export function resolveRecordReplayConfig(
  cfg: RecordReplayConfig | undefined,
  what: string
): ResolvedRecordReplayConfig {
  if (!isRecord(cfg)) {
    throw new RangeError(`${what}: \`recordReplay\` must be an object, got ${cfg === null ? "null" : typeof cfg}`);
  }
  const mode = cfg.mode;
  if (mode !== "record" && mode !== "replay") {
    throw new RangeError(`${what}: \`recordReplay.mode\` must be "record" or "replay", got ${JSON.stringify(mode)}`);
  }
  const defaultMethod = cfg.defaultMethod ?? "POST";
  if (typeof defaultMethod !== "string" || defaultMethod.trim() === "") {
    throw new RangeError(
      `${what}: \`recordReplay.defaultMethod\` must be a non-empty string, got ${JSON.stringify(cfg.defaultMethod)}`
    );
  }
  const matchStrategy = cfg.matchStrategy ?? "exact-url";
  const isNamed =
    matchStrategy === "exact-url" || matchStrategy === "url-prefix" || matchStrategy === "payload-hash";
  if (!isNamed && typeof matchStrategy !== "function") {
    throw new RangeError(
      `${what}: \`recordReplay.matchStrategy\` must be "exact-url" | "url-prefix" | "payload-hash" or a function, got ${String(matchStrategy)}`
    );
  }
  const maxRecordings = cfg.maxRecordings ?? 10000;
  if (!Number.isInteger(maxRecordings) || maxRecordings < 1) {
    throw new RangeError(
      `${what}: \`recordReplay.maxRecordings\` must be a positive integer, got ${cfg.maxRecordings}`
    );
  }
  const now = cfg.now ?? Date.now;
  if (typeof now !== "function") {
    throw new RangeError(`${what}: \`recordReplay.now\` must be a function, got ${typeof cfg.now}`);
  }
  return { mode, defaultMethod: defaultMethod.trim().toUpperCase(), matchStrategy, maxRecordings, now };
}

/** SHA-256 hex digest of the payload bytes. */
export function payloadSha256(payload: Buffer): string {
  return createHash("sha256").update(payload).digest("hex");
}

function headerNamesOf(headers: Record<string, string | string[] | undefined>): string[] {
  return Object.keys(headers)
    .map((h) => h.toLowerCase())
    .sort();
}

/**
 * In-memory recording store. Wrap a sender with {@link wrap} (record
 * mode), then persist with {@link saveToFile} or read the recordings
 * directly with {@link getRecordings}.
 */
export class RecordingStore {
  private readonly recs: RecordedInteraction[] = [];
  private readonly resolved: ResolvedRecordReplayConfig;

  constructor(cfg: Omit<RecordReplayConfig, "mode"> & { mode?: "record" } = {}) {
    this.resolved = resolveRecordReplayConfig({ ...cfg, mode: "record" }, "RecordingStore");
  }

  /**
   * Wrap `sender`: every attempt is recorded after it settles —
   * success and failure alike — and the outcome is passed through
   * unchanged. Recording never alters delivery behavior.
   */
  wrap(sender: Sender): Sender {
    const { defaultMethod, maxRecordings, now } = this.resolved;
    const store = this;
    return async (item: RetryItem, opts?: SenderCallOptions): Promise<DownstreamResponse | void> => {
      const startedAt = now();
      const request: RecordedRequest = {
        method: defaultMethod,
        url: item.targetUrl,
        headerNames: headerNamesOf(item.headers),
        payloadSha256: payloadSha256(item.payload),
        payloadBytes: item.payload.length,
      };
      const record = (response: RecordedOutcome): void => {
        store.recs.push({
          request,
          response,
          latencyMs: Math.max(0, now() - startedAt),
          recordedAt: new Date(now()).toISOString(),
        });
        while (store.recs.length > maxRecordings) store.recs.shift();
      };
      try {
        const resp = await sender(item, opts);
        if (resp === undefined) {
          record({ ok: true, status: 0, bodyBase64: "", bodyBytes: 0, truncated: false, voidResponse: true });
        } else {
          record({
            ok: true,
            status: resp.statusCode,
            bodyBase64: resp.body.toString("base64"),
            bodyBytes: resp.body.length,
            truncated: resp.truncated,
          });
        }
        return resp;
      } catch (err) {
        const e = err as { code?: unknown; message?: unknown };
        record({
          ok: false,
          ...(typeof e.code === "string" ? { errorCode: e.code } : {}),
          errorMessage: typeof e.message === "string" ? e.message : String(err),
        });
        throw err;
      }
    };
  }

  /** A snapshot of the recordings so far (oldest first). */
  getRecordings(): RecordedInteraction[] {
    return [...this.recs];
  }

  /** Persist the recordings as a version-pinned JSON file. */
  async saveToFile(path: string): Promise<void> {
    const file: RecordingFile = {
      version: RECORDING_VERSION,
      generator: GENERATOR,
      recordedAt: new Date(this.resolved.now()).toISOString(),
      recordings: this.getRecordings(),
    };
    await writeFile(path, JSON.stringify(file, null, 2) + "\n", "utf8");
  }

  /**
   * Load recordings from a file written by {@link saveToFile}.
   * Fail-loud: wrong version, non-array `recordings`, or unparseable
   * JSON all throw — a replay harness must never run on a corrupt
   * fixture and look green.
   */
  static async loadFromFile(path: string): Promise<RecordedInteraction[]> {
    let raw: string;
    try {
      raw = await readFile(path, "utf8");
    } catch (err) {
      throw new Error(`record-replay: cannot read recording file ${path}: ${(err as Error).message}`);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(`record-replay: recording file ${path} is not valid JSON: ${(err as Error).message}`);
    }
    return validateRecordingFile(parsed, path);
  }
}

/** Validate a parsed recording file; throws on any schema violation. */
export function validateRecordingFile(parsed: unknown, path: string): RecordedInteraction[] {
  if (!isRecord(parsed)) {
    throw new Error(`record-replay: recording file ${path} must contain a JSON object`);
  }
  if (parsed.version !== RECORDING_VERSION) {
    throw new Error(
      `record-replay: recording file ${path} has version ${JSON.stringify(parsed.version)}, expected ${RECORDING_VERSION}`
    );
  }
  if (!Array.isArray(parsed.recordings)) {
    throw new Error(`record-replay: recording file ${path} must have a "recordings" array`);
  }
  for (const [i, rec] of parsed.recordings.entries()) {
    if (!isRecord(rec) || !isRecord(rec.request) || !isRecord(rec.response)) {
      throw new Error(`record-replay: recording file ${path} has a malformed recording at index ${i}`);
    }
    if (
      typeof rec.request.url !== "string" ||
      typeof rec.request.payloadSha256 !== "string" ||
      !Array.isArray(rec.request.headerNames) ||
      !isRecord(rec.response) ||
      typeof rec.response.ok !== "boolean"
    ) {
      throw new Error(`record-replay: recording file ${path} has a malformed recording at index ${i}`);
    }
  }
  return parsed.recordings as RecordedInteraction[];
}

/** A replay request found no matching recording — always an error, never a network pass-through. */
export class ReplayNoMatchError extends Error {
  readonly method: string;
  readonly url: string;
  readonly payloadSha256: string;
  constructor(method: string, url: string, payloadSha256: string) {
    super(
      `record-replay: no recording matches ${method} ${url} (payload sha256 ${payloadSha256}) — ` +
        `the replay harness never touches the network`
    );
    this.name = "ReplayNoMatchError";
    this.method = method;
    this.url = url;
    this.payloadSha256 = payloadSha256;
  }
}

/** Pick the recorded answer for `request` under `strategy`. */
export function matchRecording(
  request: RecordedRequest,
  recordings: readonly RecordedInteraction[],
  strategy: RecordReplayMatchStrategy
): RecordedInteraction | undefined {
  if (typeof strategy === "function") return strategy(request, recordings);
  if (strategy === "payload-hash") {
    return recordings.find((r) => r.request.payloadSha256 === request.payloadSha256);
  }
  if (strategy === "exact-url") {
    return recordings.find((r) => r.request.method === request.method && r.request.url === request.url);
  }
  // "url-prefix": the longest recorded prefix wins; ties keep
  // insertion order (deterministic across runs).
  let best: RecordedInteraction | undefined;
  for (const rec of recordings) {
    if (!request.url.startsWith(rec.request.url)) continue;
    if (best === undefined || rec.request.url.length > best.request.url.length) best = rec;
  }
  return best;
}

/**
 * Build a network-free sender from recordings. Requests that match
 * nothing throw `ReplayNoMatchError` — fail-loud, so an offline CI
 * regression run can never silently pass through to a real downstream.
 *
 * Matching strategies (see `RecordReplayConfig.matchStrategy`):
 * - `"exact-url"` (default): method + url equality; first recording wins.
 * - `"url-prefix"`: the request url must start with the recorded url;
 *   the longest recorded prefix wins.
 * - `"payload-hash"`: the request payload's SHA-256 must equal the
 *   recorded one; first recording wins (handy when the same event fans
 *   out to many endpoints).
 * - a function: fully custom matching.
 *
 * Recorded transport errors re-throw with the recorded `code` and
 * message, so the queue classifies the replay exactly like the
 * original failure (backoff / circuit / dead-letter).
 */
export function createReplaySender(
  recordings: readonly RecordedInteraction[],
  cfg: Omit<RecordReplayConfig, "mode"> & { mode?: "replay" } = {}
): Sender {
  const { defaultMethod, matchStrategy } = resolveRecordReplayConfig(
    { ...cfg, mode: "replay" },
    "createReplaySender"
  );
  return async (item: RetryItem): Promise<DownstreamResponse | void> => {
    const request: RecordedRequest = {
      method: defaultMethod,
      url: item.targetUrl,
      headerNames: headerNamesOf(item.headers),
      payloadSha256: payloadSha256(item.payload),
      payloadBytes: item.payload.length,
    };
    const rec = matchRecording(request, recordings, matchStrategy);
    if (rec === undefined) {
      throw new ReplayNoMatchError(request.method, request.url, request.payloadSha256);
    }
    const outcome = rec.response;
    if (!outcome.ok) {
      const err = new Error(outcome.errorMessage) as NodeJS.ErrnoException;
      if (outcome.errorCode !== undefined) err.code = outcome.errorCode;
      throw err;
    }
    if (outcome.voidResponse === true) return undefined;
    return {
      statusCode: outcome.status,
      body: Buffer.from(outcome.bodyBase64, "base64"),
      truncated: outcome.truncated ?? false,
    };
  };
}
