import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

import {
  defaultSecretResolver,
  signAwsSigV4,
  type SecretResolver,
} from "./sigv4.ts";

/**
 * Kinesis Data Streams delivery sink (WR-213).
 *
 * Some downstreams are not HTTP endpoints at all: they are Amazon
 * Kinesis streams. Where the SQS sink (WR-210) delivers to an
 * unordered queue, this sink delivers to a *partition-ordered* stream:
 * records sharing a partition key land on the same shard in order,
 * so a consumer can replay one key's events exactly. The two sinks
 * are orthogonal — queue delivery for unordered work, stream delivery
 * for ordered per-key work — and a stream delivery can still be
 * archived by the S3 offloaders like any other delivery.
 *
 * Wire format — the Kinesis `PutRecords` JSON API, POSTed to the
 * stream endpoint as `application/x-amz-json-1.1` with
 * `X-Amz-Target: Kinesis_20131202.PutRecords`:
 *
 *   { "StreamName": "<stream>",
 *     "Records": [{ "Data": "<base64 event JSON>",
 *                   "PartitionKey": "<key>" }] }
 *
 * Signing reuses the WR-116 SigV4 pipeline with service `kinesis`:
 * the config carries `secretRef` (by default an environment variable
 * name), resolved per send through an injected `SecretResolver`, so
 * key material never enters config snapshots, audit logs, or error
 * messages. The signature covers the exact JSON body, after the
 * partition keys are resolved.
 *
 * Partition keys come from the event, never invented: an explicit
 * `partitionKey` wins, then the event `key`, then the `traceId`. A
 * record with none of the three is rejected at build time
 * (fail-closed) — inventing a key would silently serialize unrelated
 * events behind each other on one shard, the same reason the SQS
 * sink refuses to invent a FIFO `MessageGroupId`.
 *
 * Batching follows the WR-213 spec: one `PutRecords` call carries at
 * most 500 records and at most 1 MiB of record bytes (data +
 * partition key). Larger inputs are split greedily into consecutive
 * chunks, preserving order; a single record over 1 MiB is rejected
 * rather than truncated. (The service ceiling is higher — 5 MiB per
 * call — but the sink keeps the stricter WR-213 cap so one batch can
 * never approach the service limit.)
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per record instead of per request:
 *
 * - a non-2xx Kinesis response throws `KinesisSinkError` carrying the
 *   numeric `statusCode`, so `classifyFailure` maps it the same way
 *   it maps an HTTP downstream: 4xx except 408/429 → `non_retryable`,
 *   429/5xx → `retryable` (with `retryAfterMs` when Kinesis answers
 *   `Retry-After`);
 * - a transport error or timeout carries no status, so it classifies
 *   as `retryable` — the normal backoff lane;
 * - a missing secret throws `KinesisSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116 rule);
 * - a per-record `FailedRecord` is *reported*, not thrown: the result
 *   carries each failed record with its retry lane, mapped from the
 *   SQS rules — `ProvisionedThroughputExceededException` (the
 *   throttling analog of HTTP 429) and `InternalFailure` (the 5xx
 *   analog) are `retryable`; any other `ErrorCode` is
 *   `non_retryable`. The caller retries exactly the failed records.
 *
 * Zero new dependencies: `node:http` / `node:https` + `node:crypto`
 * (via WR-116) only.
 */

/** Per-request timeout in ms when `requestTimeoutMs` is unset. */
export const KINESIS_SINK_REQUEST_TIMEOUT_MS = 30_000;

/** `X-Amz-Target` value for the PutRecords JSON API. */
export const KINESIS_PUT_RECORDS_TARGET = "Kinesis_20131202.PutRecords";

/** Content type of the Kinesis JSON API. */
export const KINESIS_JSON_CONTENT_TYPE = "application/x-amz-json-1.1";

/** AWS service name stamped in the SigV4 credential scope. */
export const KINESIS_SIGV4_SERVICE = "kinesis";

/** Max records per `PutRecords` call (WR-213 spec). */
export const KINESIS_PUT_RECORDS_MAX_RECORDS = 500;

/** Max record bytes per `PutRecords` call (WR-213 spec). */
export const KINESIS_PUT_RECORDS_MAX_BYTES = 1024 * 1024;

/**
 * Configuration for one Kinesis stream sink. The endpoint URL is the
 * delivery target; the region feeds the SigV4 credential scope only
 * (it is not cross-checked against the endpoint host, so
 * LocalStack-style custom endpoints keep working).
 */
export interface KinesisSinkConfig {
  /**
   * Stream endpoint, e.g.
   * `https://kinesis.us-east-1.amazonaws.com/` or
   * `http://localhost:4566/` for a local emulator. The JSON API posts
   * to this URL (any path is preserved, so a prefixed emulator path
   * keeps working).
   */
  endpointUrl: string;
  /** Target stream name (1–128 chars, `[A-Za-z0-9_.-]`). */
  streamName: string;
  /** AWS region for the SigV4 credential scope, e.g. `us-east-1`. */
  region: string;
  /** AWS access key id. Not secret — safe to log/audit. */
  accessKeyId: string;
  /**
   * Secret-store reference naming where the secret access key lives
   * (WR-116 convention: an environment variable name with the default
   * resolver). Never the raw secret.
   */
  secretRef: string;
  /**
   * Resolves `secretRef` to key material per send attempt (so a
   * rotation takes effect without a restart). Defaults to
   * `defaultSecretResolver` (environment variable lookup).
   */
  secretResolver?: SecretResolver;
  /** Per-request timeout in ms; default {@link KINESIS_SINK_REQUEST_TIMEOUT_MS}. */
  requestTimeoutMs?: number;
  /**
   * Rehearsal mode: `putRecords()` returns
   * `{ ok: true, sent: 0, failedRecords: [], dryRun: true }` and
   * performs zero network I/O — no secret resolution, no stat
   * changes. Records are still validated and split, so a dry run
   * catches a malformed record or an oversize batch before it
   * reaches production. Mirrors the `dryRun` convention of the S3
   * offloaders.
   */
  dryRun?: boolean;
}

/** One event to send to the stream. */
export interface KinesisRecord {
  /** The event JSON, already serialized by the caller — it becomes the record `Data` (base64) verbatim. */
  data: string;
  /**
   * Explicit partition key. Wins over `key`/`traceId` when set.
   * 1–256 characters when resolved.
   */
  partitionKey?: string;
  /**
   * Event key (e.g. aggregate id): the partition-key source when no
   * explicit `partitionKey` is set. Events sharing a key land on the
   * same shard, in order.
   */
  key?: string;
  /**
   * Trace id: the partition-key fallback when neither `partitionKey`
   * nor `key` is set. Lets the consumer correlate the stream record
   * with the relay's audit trail without opening the data.
   */
  traceId?: string;
}

/** One record as it goes on the wire (partition key resolved). */
export interface KinesisResolvedRecord {
  /** The event JSON, verbatim. */
  data: string;
  /** Resolved partition key (1–256 characters). */
  partitionKey: string;
}

/** One failed record, with its retry lane already mapped. */
export interface KinesisFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Kinesis `ErrorCode`, e.g. `ProvisionedThroughputExceededException`. */
  errorCode: string;
  /** Kinesis `ErrorMessage`, when the response carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: `ProvisionedThroughputExceededException`
   * and `InternalFailure` are retryable, any other code is not.
   */
  retryable: boolean;
}

/** Outcome of one `putRecords()` call. */
export interface KinesisPutRecordsResult {
  /** Always `true` for a returned result — whole-batch failures throw. */
  ok: true;
  /** Records Kinesis accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Per-record failures, in response order, each with its original
   * index and retry lane. Empty when every record was accepted.
   * A non-empty list is a partial success, not a throw: the caller
   * retries exactly these records.
   */
  failedRecords: KinesisFailedRecord[];
  /** `true` only in dry-run mode: no network I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-213). */
export interface KinesisSinkStats {
  /** Records accepted by Kinesis (real sends, not dry runs). */
  sent: number;
  /** Records reported failed by Kinesis (partial failures). */
  failed: number;
  /** Send attempts that failed wholesale (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Kinesis send failures. Carries the Kinesis HTTP status
 * when the failure was a response (`statusCode`), and the
 * downstream's `Retry-After` wait when one was supplied
 * (`retryAfterMs`), so the retry queue can classify without parsing
 * message strings.
 */
export class KinesisSinkError extends Error {
  /** Kinesis HTTP status code, when the failure was a response. */
  readonly statusCode?: number;
  /** Downstream-requested wait before the next attempt, when supplied. */
  readonly retryAfterMs?: number;
  constructor(message: string, statusCode?: number, retryAfterMs?: number) {
    super(message);
    this.name = "KinesisSinkError";
    if (statusCode !== undefined) this.statusCode = statusCode;
    if (retryAfterMs !== undefined) this.retryAfterMs = retryAfterMs;
  }
}

/**
 * Thrown when the sink cannot even build a request — currently: the
 * secret for `secretRef` did not resolve. A config problem, not a
 * downstream verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class KinesisSinkConfigError extends KinesisSinkError {
  readonly secretRef: string;
  constructor(secretRef: string) {
    super(
      `kinesis-sink: secret unavailable (secretRef "${secretRef}" did not resolve)`
    );
    this.name = "KinesisSinkConfigError";
    this.secretRef = secretRef;
  }
}

const REGION_RE = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;
const STREAM_NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 */
export function assertValidKinesisSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is KinesisSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (typeof c.endpointUrl !== "string" || c.endpointUrl === "") {
    throw new RangeError(at("`endpointUrl` must be a non-empty string"));
  }
  let parsed: URL;
  try {
    parsed = new URL(c.endpointUrl);
  } catch {
    throw new RangeError(at("`endpointUrl` is not a valid URL"));
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new RangeError(at("`endpointUrl` must be an http(s) URL"));
  }
  if (typeof c.streamName !== "string" || !STREAM_NAME_RE.test(c.streamName)) {
    throw new RangeError(at("`streamName` must be 1–128 `[A-Za-z0-9_.-]` characters"));
  }
  if (typeof c.region !== "string" || !REGION_RE.test(c.region)) {
    throw new RangeError(at("`region` must look like an AWS region (e.g. `us-east-1`)"));
  }
  if (typeof c.accessKeyId !== "string" || c.accessKeyId === "") {
    throw new RangeError(at("`accessKeyId` must be a non-empty string"));
  }
  if (typeof c.secretRef !== "string" || c.secretRef === "") {
    throw new RangeError(at("`secretRef` must be a non-empty string (a reference, never the raw secret)"));
  }
  if (c.secretResolver !== undefined && typeof c.secretResolver !== "function") {
    throw new RangeError(at("`secretResolver` must be a function when set"));
  }
  if (
    c.requestTimeoutMs !== undefined &&
    (!Number.isFinite(c.requestTimeoutMs) || c.requestTimeoutMs <= 0)
  ) {
    throw new RangeError(at("`requestTimeoutMs` must be a positive finite number"));
  }
}

/**
 * Resolve one record's partition key: explicit `partitionKey`, then
 * `key`, then `traceId`. Throws `RangeError` when none is set, when
 * the resolved key is empty, or when it exceeds 256 characters —
 * the sink never invents a key.
 */
export function resolveKinesisPartitionKey(
  record: KinesisRecord,
  index: number
): string {
  const key = record.partitionKey ?? record.key ?? record.traceId;
  if (typeof key !== "string" || key === "") {
    throw new RangeError(
      `kinesis-sink: record ${index} has no partition key (set partitionKey, key, or traceId)`
    );
  }
  if (key.length > 256) {
    throw new RangeError(
      `kinesis-sink: record ${index} partition key exceeds 256 characters`
    );
  }
  return key;
}

/**
 * Validate one record's data and resolve its wire form. Throws
 * `RangeError` on an empty data string.
 */
export function resolveKinesisRecord(
  record: KinesisRecord,
  index: number
): KinesisResolvedRecord {
  if (typeof record.data !== "string" || record.data === "") {
    throw new RangeError(`kinesis-sink: record ${index} \`data\` must be a non-empty event JSON string`);
  }
  return { data: record.data, partitionKey: resolveKinesisPartitionKey(record, index) };
}

/** Byte size of one resolved record against the per-batch cap. */
function kinesisRecordByteSize(record: KinesisResolvedRecord): number {
  return Buffer.byteLength(record.data, "utf8") + Buffer.byteLength(record.partitionKey, "utf8");
}

/**
 * Split resolved records into consecutive `PutRecords` chunks of at
 * most {@link KINESIS_PUT_RECORDS_MAX_RECORDS} records and
 * {@link KINESIS_PUT_RECORDS_MAX_BYTES} bytes, preserving order.
 * Throws `RangeError` when a single record exceeds the byte cap on
 * its own — it can never fit a batch, and truncating it would
 * corrupt the event.
 */
export function splitKinesisPutRecordsChunks(
  records: KinesisResolvedRecord[]
): KinesisResolvedRecord[][] {
  const chunks: KinesisResolvedRecord[][] = [];
  let current: KinesisResolvedRecord[] = [];
  let currentBytes = 0;
  for (const record of records) {
    const size = kinesisRecordByteSize(record);
    if (size > KINESIS_PUT_RECORDS_MAX_BYTES) {
      throw new RangeError(
        `kinesis-sink: record exceeds the ${KINESIS_PUT_RECORDS_MAX_BYTES} byte batch cap on its own (data ${Buffer.byteLength(record.data, "utf8")} bytes)`
      );
    }
    if (
      current.length >= KINESIS_PUT_RECORDS_MAX_RECORDS ||
      currentBytes + size > KINESIS_PUT_RECORDS_MAX_BYTES
    ) {
      chunks.push(current);
      current = [];
      currentBytes = 0;
    }
    current.push(record);
    currentBytes += size;
  }
  if (current.length > 0) chunks.push(current);
  return chunks;
}

/**
 * Build one `PutRecords` JSON body for a chunk: `Data` is the base64
 * of the event JSON, `PartitionKey` the resolved key. Chunk order is
 * preserved, so response indices map back onto the chunk directly.
 */
export function buildKinesisPutRecordsBody(
  streamName: string,
  chunk: KinesisResolvedRecord[]
): string {
  return JSON.stringify({
    StreamName: streamName,
    Records: chunk.map((r) => ({
      Data: Buffer.from(r.data, "utf8").toString("base64"),
      PartitionKey: r.partitionKey,
    })),
  });
}

/**
 * Map one Kinesis per-record `ErrorCode` onto its retry lane under
 * the WR-210 rules: throttling (`ProvisionedThroughputExceededException`,
 * the 429 analog) and internal failures (the 5xx analog) are
 * retryable; any other code is a poison record, like any other 4xx.
 */
export function classifyKinesisRecordFailure(errorCode: string): boolean {
  return (
    errorCode === "ProvisionedThroughputExceededException" ||
    errorCode === "InternalFailure"
  );
}

/**
 * Parse one `PutRecords` response document into its per-record
 * failures, with indices rebased onto the caller's original array
 * (`baseIndex` is the chunk's first original index). Entries without
 * an `ErrorCode` count as accepted. Throws `KinesisSinkError` when
 * the document is not a `PutRecords` response shape at all — a 2xx
 * that cannot be parsed must not be reported as a silent success.
 */
export function parseKinesisPutRecordsResponse(
  body: string,
  baseIndex: number
): { failedRecords: KinesisFailedRecord[]; accepted: number } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new KinesisSinkError("kinesis-sink: PutRecords response is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || !Array.isArray((parsed as { Records?: unknown }).Records)) {
    throw new KinesisSinkError("kinesis-sink: PutRecords response has no Records array");
  }
  const failedRecords: KinesisFailedRecord[] = [];
  let accepted = 0;
  const records = (parsed as { Records: unknown[] }).Records;
  records.forEach((entry, i) => {
    if (entry === null || typeof entry !== "object") {
      throw new KinesisSinkError("kinesis-sink: PutRecords response entry is not an object");
    }
    const e = entry as { ErrorCode?: unknown; ErrorMessage?: unknown };
    if (typeof e.ErrorCode === "string") {
      const failed: KinesisFailedRecord = {
        index: baseIndex + i,
        errorCode: e.ErrorCode,
        retryable: classifyKinesisRecordFailure(e.ErrorCode),
      };
      if (typeof e.ErrorMessage === "string") failed.errorMessage = e.ErrorMessage;
      failedRecords.push(failed);
    } else if (e.ErrorCode === undefined) {
      accepted += 1;
    } else {
      throw new KinesisSinkError("kinesis-sink: PutRecords response entry has a non-string ErrorCode");
    }
  });
  return { failedRecords, accepted };
}

/** Parse a `Retry-After` header into ms (delay-seconds form only). */
function parseRetryAfterSeconds(value: string | string[] | undefined): number | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) return undefined;
  const seconds = Number(trimmed);
  return Number.isSafeInteger(seconds) ? seconds * 1000 : undefined;
}

/**
 * Kinesis stream sink (WR-213). One instance targets one stream; the
 * caller owns retry/dead-letter policy around `putRecords()` — this
 * class performs one signed `PutRecords` attempt per chunk and
 * reports per-record outcomes. Whole-batch failures throw; partial
 * failures are reported in the result.
 */
export class KinesisSink {
  private readonly cfg: KinesisSinkConfig;
  private readonly secretResolver: SecretResolver;
  private readonly requestTimeoutMs: number;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: KinesisSinkConfig) {
    assertValidKinesisSinkConfig(config, "KinesisSink");
    this.cfg = config;
    this.secretResolver = config.secretResolver ?? defaultSecretResolver;
    this.requestTimeoutMs = config.requestTimeoutMs ?? KINESIS_SINK_REQUEST_TIMEOUT_MS;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): KinesisSinkStats {
    return { sent: this.sent, failed: this.failed, sendFailures: this.sendFailures };
  }

  /**
   * Send records to the stream, split into `PutRecords` chunks.
   * Throws `KinesisSinkConfigError` when the secret cannot be
   * resolved and `KinesisSinkError` for transport failures, timeouts,
   * non-2xx responses, and unparseable 2xx responses (all counted in
   * `stats.sendFailures` before throwing, so the counters stay honest
   * even for callers that only inspect stats). Per-record failures
   * do not throw: they arrive in `result.failedRecords` with their
   * retry lane, and the accepted count in `result.sent`.
   */
  async putRecords(records: KinesisRecord[]): Promise<KinesisPutRecordsResult> {
    const resolved = records.map((r, i) => resolveKinesisRecord(r, i));
    const chunks = splitKinesisPutRecordsChunks(resolved);
    if (this.cfg.dryRun === true) {
      // Validate and split even in rehearsal, so a dry run still
      // catches a malformed record or an oversize batch before it
      // reaches production — but perform zero network I/O.
      return { ok: true, sent: 0, failedRecords: [], dryRun: true };
    }
    const secret = this.secretResolver(this.cfg.secretRef);
    if (secret === undefined || secret === "") {
      throw new KinesisSinkConfigError(this.cfg.secretRef);
    }
    const failedRecords: KinesisFailedRecord[] = [];
    let sent = 0;
    let offset = 0;
    for (const chunk of chunks) {
      const body = Buffer.from(buildKinesisPutRecordsBody(this.cfg.streamName, chunk), "utf8");
      const signed = signAwsSigV4({
        method: "POST",
        url: this.cfg.endpointUrl,
        body,
        credentials: { accessKeyId: this.cfg.accessKeyId, secretAccessKey: secret },
        region: this.cfg.region,
        service: KINESIS_SIGV4_SERVICE,
        extraSignedHeaders: {
          "content-type": KINESIS_JSON_CONTENT_TYPE,
          "x-amz-target": KINESIS_PUT_RECORDS_TARGET,
        },
      });
      let outcome: { status: number; body: string; retryAfterMs: number | undefined };
      try {
        outcome = await this.post(body, signed);
      } catch (err) {
        this.sendFailures += 1;
        throw err;
      }
      if (outcome.status < 200 || outcome.status >= 300) {
        this.sendFailures += 1;
        throw new KinesisSinkError(
          `kinesis-sink: PutRecords ${this.cfg.endpointUrl} -> HTTP ${outcome.status}`,
          outcome.status,
          outcome.retryAfterMs
        );
      }
      let parsed: { failedRecords: KinesisFailedRecord[]; accepted: number };
      try {
        parsed = parseKinesisPutRecordsResponse(outcome.body, offset);
      } catch (err) {
        this.sendFailures += 1;
        throw err;
      }
      sent += parsed.accepted;
      failedRecords.push(...parsed.failedRecords);
      offset += chunk.length;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    return { ok: true, sent, failedRecords };
  }

  private post(
    body: Buffer,
    signed: { authorization: string; amzDate: string }
  ): Promise<{ status: number; body: string; retryAfterMs: number | undefined }> {
    return new Promise((resolve, reject) => {
      const url = new URL(this.cfg.endpointUrl);
      const requestFn = url.protocol === "https:" ? httpsRequest : httpRequest;
      let req;
      try {
        req = requestFn(
          {
            protocol: url.protocol,
            hostname: url.hostname,
            port: url.port === "" ? undefined : Number(url.port),
            path: `${url.pathname}${url.search}`,
            method: "POST",
            headers: {
              authorization: signed.authorization,
              "x-amz-date": signed.amzDate,
              "x-amz-target": KINESIS_PUT_RECORDS_TARGET,
              "content-type": KINESIS_JSON_CONTENT_TYPE,
              "content-length": String(body.length),
            },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c: Buffer) => chunks.push(c));
            res.on("end", () =>
              resolve({
                status: res.statusCode ?? 0,
                body: Buffer.concat(chunks).toString("utf8"),
                retryAfterMs: parseRetryAfterSeconds(res.headers["retry-after"]),
              })
            );
          }
        );
      } catch (err) {
        reject(
          new KinesisSinkError(
            `kinesis-sink: PutRecords transport failed: ${(err as Error).message}`
          )
        );
        return;
      }
      req.on("error", (err) =>
        reject(
          new KinesisSinkError(`kinesis-sink: PutRecords transport failed: ${err.message}`)
        )
      );
      req.setTimeout(this.requestTimeoutMs, () => {
        req.destroy();
        reject(
          new KinesisSinkError(
            `kinesis-sink: PutRecords timed out after ${this.requestTimeoutMs}ms`
          )
        );
      });
      req.end(body);
    });
  }
}
