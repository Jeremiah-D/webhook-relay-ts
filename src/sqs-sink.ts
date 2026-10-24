import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

import {
  defaultSecretResolver,
  signAwsSigV4,
  type SecretResolver,
} from "./sigv4.ts";

/**
 * SQS delivery sink (WR-210).
 *
 * Some downstreams are not HTTP endpoints at all: they are Amazon SQS
 * queues. A relay that can only POST to URLs forces the operator to run
 * a sidecar translator in front of every queue consumer; this module
 * lets the relay deliver straight to the queue instead.
 *
 * The sink is a *delivery target*, not an archive: it sends the live
 * event, whereas `src/archive-s3.ts` (WR-188) stores payload-free
 * delivery-event metadata after the fact and `src/deadletter-s3.ts`
 * (WR-206) archives dead letters for compliance. The three are
 * orthogonal — a queue delivery can still be archived by either, and
 * an archived dead letter is never re-sent through this sink by itself.
 *
 * Wire format — the SQS `SendMessage` Query API action, POSTed to the
 * queue URL as `application/x-www-form-urlencoded`:
 *
 *   Action=SendMessage
 *   MessageBody=<event JSON>
 *   MessageAttribute.1.Name=tenant
 *   MessageAttribute.1.DataType=String
 *   MessageAttribute.1.StringValue=<tenant id>
 *   … (endpoint, then trace, then any caller-supplied attributes)
 *
 * Signing reuses the WR-116 SigV4 pipeline with service `sqs`: the
 * config carries `secretRef` (by default an environment variable name),
 * resolved per send through an injected `SecretResolver`, so key
 * material never enters config snapshots, audit logs, or error messages.
 * The signature covers the exact form-encoded body, after the
 * attributes are attached.
 *
 * Failure handling follows the existing classification in
 * `src/failure.ts` without the sink importing it (the queue keeps the
 * dependency direction one-way, like the other sinks):
 *
 * - a non-2xx SQS response throws `SqsSinkError` carrying the numeric
 *   `statusCode`, so `classifyFailure` maps it the same way it maps an
 *   HTTP downstream: 4xx except 408/429 → `non_retryable`, 429/5xx →
 *   `retryable` (with `retryAfterMs` when SQS answers `Retry-After`);
 * - a transport error or timeout carries no status, so it classifies as
 *   `retryable` — the normal backoff lane;
 * - a missing secret throws `SqsSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable`: retrying a config
 *   problem burns the retry budget for nothing (the WR-116 rule).
 *
 * Standard queues only. A queue URL ending in `.fifo` is rejected at
 * construction: FIFO queues require a `MessageGroupId` per message,
 * which this sink does not invent — silently sending a FIFO message
 * without one would fail every send, and guessing a group id would
 * serialize unrelated events behind each other.
 *
 * Zero new dependencies: `node:http` / `node:https` + `node:crypto`
 * (via WR-116) only.
 */

/** Per-request timeout in ms when `requestTimeoutMs` is unset. */
export const SQS_SINK_REQUEST_TIMEOUT_MS = 30_000;

/** SQS Query API action for sending one message. */
export const SQS_SEND_MESSAGE_ACTION = "SendMessage";

/** AWS service name stamped in the SigV4 credential scope. */
export const SQS_SIGV4_SERVICE = "sqs";

/**
 * Configuration for one SQS queue sink. The queue URL is the delivery
 * target; the region feeds the SigV4 credential scope only (it is not
 * cross-checked against the queue URL's host, so LocalStack-style
 * custom endpoints keep working).
 */
export interface SqsSinkConfig {
  /**
   * Queue URL, e.g.
   * `https://sqs.us-east-1.amazonaws.com/123456789012/events` or
   * `http://localhost:4566/000000000000/events` for a local emulator.
   * Must not end in `.fifo` (FIFO queues are out of scope, see above).
   */
  queueUrl: string;
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
  /** Per-request timeout in ms; default {@link SQS_SINK_REQUEST_TIMEOUT_MS}. */
  requestTimeoutMs?: number;
  /**
   * Rehearsal mode: `send()` returns `{ ok: true, dryRun: true }`
   * and performs zero network I/O — no secret resolution, no stat
   * changes. Mirrors the `dryRun` convention of the S3 offloaders.
   */
  dryRun?: boolean;
}

/** One event to send to the queue. */
export interface SqsDelivery {
  /**
   * The event JSON, already serialized by the caller — it becomes the
   * SQS `MessageBody` verbatim, so the queue consumer sees exactly
   * what the relay delivered.
   */
  body: string;
  /**
   * Tenant id, carried as the `tenant` message attribute (String).
   * Omitted when the delivery has no tenant.
   */
  tenantId?: string;
  /**
   * Delivery endpoint (the logical `targetUrl` the event was bound
   * for), carried as the `endpoint` message attribute (String).
   */
  endpoint?: string;
  /**
   * Trace id, carried as the `trace` message attribute (String).
   * Lets the consumer correlate the queued message with the relay's
   * audit trail without opening the body.
   */
  traceId?: string;
  /**
   * Extra caller-supplied String attributes, appended after the
   * tenant/endpoint/trace trio in insertion order. Attribute names
   * must be non-empty strings; values must be strings.
   */
  attributes?: Record<string, string>;
}

/** Outcome of one `send()` call. */
export interface SqsSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /**
   * The SQS-assigned message id, parsed from the `SendMessage`
   * response XML when present. Absent only when a 2xx response
   * carries no `<MessageId>` (not expected from real SQS).
   */
  messageId?: string;
  /** `true` only in dry-run mode: no network I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-210). */
export interface SqsSinkStats {
  /** Messages accepted by SQS (real sends, not dry runs). */
  sent: number;
  /** Send attempts that failed (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for SQS send failures. Carries the SQS HTTP status when the
 * failure was a response (`statusCode`), and the downstream's
 * `Retry-After` wait when one was supplied (`retryAfterMs`), so the
 * retry queue can classify without parsing message strings.
 */
export class SqsSinkError extends Error {
  /** SQS HTTP status code, when the failure was a response. */
  readonly statusCode?: number;
  /** Downstream-requested wait before the next attempt, when supplied. */
  readonly retryAfterMs?: number;
  constructor(message: string, statusCode?: number, retryAfterMs?: number) {
    super(message);
    this.name = "SqsSinkError";
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
export class SqsSinkConfigError extends SqsSinkError {
  readonly secretRef: string;
  constructor(secretRef: string) {
    super(
      `sqs-sink: secret unavailable (secretRef "${secretRef}" did not resolve)`
    );
    this.name = "SqsSinkConfigError";
    this.secretRef = secretRef;
  }
}

const REGION_RE = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 */
export function assertValidSqsSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is SqsSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (typeof c.queueUrl !== "string" || c.queueUrl === "") {
    throw new RangeError(at("`queueUrl` must be a non-empty string"));
  }
  let parsed: URL;
  try {
    parsed = new URL(c.queueUrl);
  } catch {
    throw new RangeError(at("`queueUrl` is not a valid URL"));
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new RangeError(at("`queueUrl` must be an http(s) URL"));
  }
  if (parsed.pathname === "" || parsed.pathname === "/") {
    throw new RangeError(at("`queueUrl` must carry a queue path"));
  }
  if (c.queueUrl.endsWith(".fifo")) {
    throw new RangeError(
      at("`queueUrl` must not be a FIFO queue (`.fifo`): FIFO delivery needs a MessageGroupId, which this sink does not invent")
    );
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
 * Build the `SendMessage` form body for one delivery. Attribute order
 * is fixed — tenant, endpoint, trace, then caller attributes in
 * insertion order — so the SigV4 payload hash is deterministic for a
 * given delivery.
 */
export function buildSqsSendMessageBody(delivery: SqsDelivery): string {
  if (typeof delivery.body !== "string" || delivery.body === "") {
    throw new RangeError("sqs-sink: `body` must be a non-empty event JSON string");
  }
  const attrs: Array<[string, string]> = [];
  if (delivery.tenantId !== undefined) attrs.push(["tenant", delivery.tenantId]);
  if (delivery.endpoint !== undefined) attrs.push(["endpoint", delivery.endpoint]);
  if (delivery.traceId !== undefined) attrs.push(["trace", delivery.traceId]);
  for (const [name, value] of Object.entries(delivery.attributes ?? {})) {
    if (typeof name !== "string" || name === "") {
      throw new RangeError("sqs-sink: attribute names must be non-empty strings");
    }
    if (typeof value !== "string") {
      throw new RangeError(`sqs-sink: attribute "${name}" must be a string value`);
    }
    attrs.push([name, value]);
  }
  const params = new URLSearchParams();
  params.set("Action", SQS_SEND_MESSAGE_ACTION);
  params.set("MessageBody", delivery.body);
  attrs.forEach(([name, value], i) => {
    const n = i + 1;
    params.set(`MessageAttribute.${n}.Name`, name);
    params.set(`MessageAttribute.${n}.DataType`, "String");
    params.set(`MessageAttribute.${n}.StringValue`, value);
  });
  return params.toString();
}

/** Extract `<MessageId>` from a `SendMessage` response document, if any. */
export function parseSqsSendMessageId(xml: string): string | undefined {
  const m = /<MessageId>([^<]+)<\/MessageId>/.exec(xml);
  return m === null ? undefined : m[1];
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
 * SQS queue sink (WR-210). One instance targets one queue; the caller
 * owns retry/dead-letter policy around `send()` — this class only
 * performs one signed `SendMessage` attempt and reports its outcome.
 */
export class SqsSink {
  private readonly cfg: SqsSinkConfig;
  private readonly secretResolver: SecretResolver;
  private readonly requestTimeoutMs: number;
  private sent = 0;
  private sendFailures = 0;

  constructor(config: SqsSinkConfig) {
    assertValidSqsSinkConfig(config, "SqsSink");
    this.cfg = config;
    this.secretResolver = config.secretResolver ?? defaultSecretResolver;
    this.requestTimeoutMs = config.requestTimeoutMs ?? SQS_SINK_REQUEST_TIMEOUT_MS;
  }

  /** Current counters; dry runs change neither. */
  get stats(): SqsSinkStats {
    return { sent: this.sent, sendFailures: this.sendFailures };
  }

  /**
   * Send one event to the queue. Throws `SqsSinkConfigError` when the
   * secret cannot be resolved and `SqsSinkError` for transport
   * failures and non-2xx SQS responses (both counted in
   * `stats.sendFailures` before throwing, so the counters stay honest
   * even for callers that only inspect stats).
   */
  async send(delivery: SqsDelivery): Promise<SqsSendResult> {
    if (this.cfg.dryRun === true) {
      // Validate the shape even in rehearsal, so a dry run still
      // catches a malformed delivery before it reaches production.
      buildSqsSendMessageBody(delivery);
      return { ok: true, dryRun: true };
    }
    const secret = this.secretResolver(this.cfg.secretRef);
    if (secret === undefined || secret === "") {
      throw new SqsSinkConfigError(this.cfg.secretRef);
    }
    const body = Buffer.from(buildSqsSendMessageBody(delivery), "utf8");
    const signed = signAwsSigV4({
      method: "POST",
      url: this.cfg.queueUrl,
      body,
      credentials: { accessKeyId: this.cfg.accessKeyId, secretAccessKey: secret },
      region: this.cfg.region,
      service: SQS_SIGV4_SERVICE,
      extraSignedHeaders: { "content-type": "application/x-www-form-urlencoded" },
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
      throw new SqsSinkError(
        `sqs-sink: SendMessage ${this.cfg.queueUrl} -> HTTP ${outcome.status}`,
        outcome.status,
        outcome.retryAfterMs
      );
    }
    this.sent += 1;
    const messageId = parseSqsSendMessageId(outcome.body);
    return messageId === undefined ? { ok: true } : { ok: true, messageId };
  }

  private post(
    body: Buffer,
    signed: { authorization: string; amzDate: string }
  ): Promise<{ status: number; body: string; retryAfterMs: number | undefined }> {
    return new Promise((resolve, reject) => {
      const url = new URL(this.cfg.queueUrl);
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
              "content-type": "application/x-www-form-urlencoded",
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
          new SqsSinkError(
            `sqs-sink: SendMessage transport failed: ${(err as Error).message}`
          )
        );
        return;
      }
      req.on("error", (err) =>
        reject(
          new SqsSinkError(`sqs-sink: SendMessage transport failed: ${err.message}`)
        )
      );
      req.setTimeout(this.requestTimeoutMs, () => {
        req.destroy();
        reject(
          new SqsSinkError(
            `sqs-sink: SendMessage timed out after ${this.requestTimeoutMs}ms`
          )
        );
      });
      req.end(body);
    });
  }
}
