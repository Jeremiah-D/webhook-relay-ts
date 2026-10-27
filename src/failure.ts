/**
 * Downstream failure classification (see the `deliver()` failure path in
 * `src/retry.ts`).
 *
 * Not every failed delivery deserves a retry. A `400 Bad Request` means the
 * payload itself is poison — retrying it five times with exponential backoff
 * only burns the retry budget and delays the operator from seeing the real
 * problem in the dead-letter queue. A `503` or a DNS timeout is transient:
 * the normal backoff lane is exactly right for it.
 *
 * Classification rules (deliberately conservative — when in doubt, retry):
 *
 * - HTTP `4xx` **except** `408` and `429` → `"non_retryable"`: the item is
 *   dead-lettered immediately, without consuming further attempts. The
 *   endpoint's circuit breaker is *not* tripped — the downstream answered,
 *   it just said no — and a half-open probe is settled as a success.
 * - `408` (Request Timeout), `429` (Too Many Requests), every `5xx`, and
 *   anything that is not an HTTP response at all (DNS failures, timeouts,
 *   TLS errors, proxy failures) → `"retryable"`: the normal backoff lane.
 *   A `429` additionally honors the downstream's `Retry-After` header when
 *   present.
 * - a WR-115 `PayloadTransformError` → `"non_retryable"`: the wire
 *   request was never built (non-JSON payload under a configured
 *   transform), so no downstream verdict exists and retrying is futile.
 *   The item is dead-lettered immediately and audited as
 *   `transform_failed`.
 * - a WR-117 `OutboundSchemaViolationError` → `"non_retryable"`: the
 *   post-transform payload failed the endpoint's outbound JSON schema
 *   before the wire request was built, so no downstream verdict exists
 *   and retrying is futile. The item is dead-lettered immediately and
 *   audited as `schema_violation`.
 * - a WR-118 `AssertionFailedError` → `"assertion_failed"`: the
 *   downstream answered inside the rule's status whitelist, but the
 *   response body failed the endpoint's declarative assertions. The
 *   item follows the normal retryable path — backoff, circuit
 *   breaker, retry budget — exactly like a transient downstream
 *   failure.
 * - a WR-168 `IntegrityMismatchError` → `"retryable"`: the downstream
 *   answered 2xx but its `Content-Digest` did not match the received
 *   body. The tamper may be transient (a flapping middlebox), so the
 *   item follows the normal backoff / circuit / budget lane and is
 *   audited as `integrity_mismatch`.
 * - a WR-169 `ResponseTooLargeError` → `"retryable"`: the downstream
 *   answered 2xx but its body ran past the endpoint's
 *   `maxResponseBytes`. A recovering downstream deserves another
 *   attempt, so the item follows the normal backoff / circuit / budget
 *   lane and is audited as `response_too_large`.
 *
 * Zero dependencies (`node:` only where the caller's clock is needed).
 */

import { PayloadTransformError } from "./transform.ts";
import { OutboundSchemaViolationError } from "./outbound-schema.ts";
import { SigV4SigningError } from "./sigv4.ts";
import { SqsSinkConfigError } from "./sqs-sink.ts";
import { KinesisSinkConfigError } from "./kinesis-sink.ts";
import { KafkaSinkConfigError } from "./kafka-sink.ts";
import { MqttSinkConfigError } from "./mqtt-sink.ts";
import { AmqpSinkConfigError } from "./amqp-sink.ts";
import { JetStreamSinkConfigError } from "./jetstream-sink.ts";
import { RedisSinkConfigError } from "./redis-sink.ts";
import { PubSubSinkConfigError } from "./pubsub-sink.ts";
import { ServiceBusSinkConfigError } from "./servicebus-sink.ts";
import { EventBridgeSinkConfigError } from "./eventbridge-sink.ts";
import { PulsarSinkConfigError } from "./pulsar-sink.ts";
import { SnsSinkConfigError } from "./sns-sink.ts";
import { EventHubsSinkConfigError } from "./eventhubs-sink.ts";
import { SlackSinkConfigError } from "./slack-sink.ts";
import { DingTalkSinkConfigError } from "./dingtalk-sink.ts";
import { FeishuSinkConfigError } from "./feishu-sink.ts";
import { TelegramSinkConfigError } from "./telegram-sink.ts";
import { DiscordSinkConfigError } from "./discord-sink.ts";
import { TeamsSinkConfigError } from "./teams-sink.ts";
import { WeComSinkConfigError } from "./wecom-sink.ts";
import { GoogleChatSinkConfigError } from "./google-chat-sink.ts";
import { EmailSinkConfigError } from "./email-sink.ts";
import { DigestAuthError } from "./digest-auth.ts";
import { CredentialSecretUnavailableError } from "./outbound-credentials.ts";
import { AssertionFailedError } from "./response-assertions.ts";
import { IntegrityMismatchError } from "./response-integrity.ts";
import { ResponseTooLargeError } from "./response-limit.ts";

/**
 * How a delivery failure should be treated by the retry queue.
 *
 * - `"retryable"`: schedule another attempt (backoff, or the downstream's
 *   `Retry-After` when one was supplied).
 * - `"non_retryable"`: the payload is poison — dead-letter immediately,
 *   without burning more of the retry budget.
 * - `"head_of_line_timeout"`: not a downstream verdict at all — the item
 *   held the head of an ordered-delivery line (WR-113) longer than
 *   `maxHeadOfLineHoldMs` and was parked into the dead-letter list so the
 *   line could advance. Never silently dropped.
 * - `"assertion_failed"`: the downstream answered inside the endpoint's
 *   WR-118 status whitelist, but the response body failed the endpoint's
 *   declarative assertions. Retryable — follows the normal backoff lane,
 *   counts as a failure for the WR-10 breaker, and honors the retry
 *   budget.
 * - `"endpoint_disabled"`: the endpoint is auto-disabled (WR-150) — the
 *   delivery was dead-lettered *without an attempt*. Never a downstream
 *   verdict; only an operator re-enable clears the gate.
 */
export type FailureClass = "retryable" | "non_retryable" | "head_of_line_timeout" | "assertion_failed" | "endpoint_disabled";

/**
 * Structured delivery failure for a non-2xx downstream HTTP response.
 * Thrown by the default sender (`createDefaultSender` in `src/server.ts`)
 * so the retry queue can classify without parsing error message strings.
 * Custom senders may throw it too (or any error with a numeric
 * `statusCode` field — `classifyFailure` duck-types it).
 */
export class HttpDeliveryError extends Error {
  /** The downstream HTTP status code (e.g. 400, 429, 503). */
  readonly statusCode: number;
  /**
   * Milliseconds the downstream asked us to wait before the next attempt,
   * parsed from its `Retry-After` header. Present only when the header was
   * present and parseable.
   */
  readonly retryAfterMs?: number;

  constructor(statusCode: number, retryAfterMs?: number) {
    // Keep the historical message shape so existing log greps and
    // message-matching tests keep working.
    super(`Forward failed with status ${statusCode}`);
    this.name = "HttpDeliveryError";
    this.statusCode = statusCode;
    if (retryAfterMs !== undefined) {
      this.retryAfterMs = retryAfterMs;
    }
  }
}

/**
 * Parse a `Retry-After` header value into milliseconds.
 *
 * Accepts both RFC 9110 forms: delay-seconds (`"120"` → 120000) and an
 * HTTP-date (`"Wed, 21 Oct 2026 07:28:00 GMT"` → ms until that instant,
 * clamped at 0). Returns `undefined` when the value is missing,
 * unparseable, or already in the past — in which case the normal backoff
 * applies instead of a bogus wait.
 */
export function parseRetryAfterMs(
  value: string | string[] | undefined,
  nowMs: () => number = Date.now
): number | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (trimmed === "") return undefined;
  // Delay-seconds: a non-negative integer. (Fractional values are not
  // valid per the RFC; parseInt would silently accept "1.5", so require
  // the whole token to be digits.)
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number(trimmed);
    if (!Number.isSafeInteger(seconds)) return undefined;
    return seconds * 1000;
  }
  // HTTP-date.
  const at = Date.parse(trimmed);
  if (Number.isNaN(at)) return undefined;
  const wait = at - nowMs();
  return wait > 0 ? wait : undefined;
}

/** A classified delivery failure. */
export interface ClassifiedFailure {
  /**
   * How the failure is treated: `"retryable"` (another attempt may be
   * scheduled, including `"assertion_failed"` assertion failures),
   * `"non_retryable"` (the payload is poison — dead-letter immediately),
   * `"head_of_line_timeout"` (WR-113 line parking — dead-letter, never
   * silently dropped), `"assertion_failed"` (WR-118: the downstream
   * answered inside the status whitelist but the body failed the
   * endpoint's declarative assertions; handled exactly like
   * `"retryable"` — normal backoff lane, breaker, budget), or
   * `"endpoint_disabled"` (WR-150: the endpoint is auto-disabled, so the
   * delivery was dead-lettered without an attempt — never a downstream
   * verdict).
   */
  failureClass: FailureClass;
  /** Downstream HTTP status, when the failure was an HTTP response. */
  statusCode?: number;
  /**
   * Downstream-requested wait before the next attempt (ms), when a
   * parseable `Retry-After` was present. Only meaningful for
   * `"retryable"` failures (practically: 429/503).
   */
  retryAfterMs?: number;
}

/**
 * Classify a sender failure per the rules documented above.
 *
 * Reads `statusCode` / `retryAfterMs` structurally (duck-typed), so custom
 * senders do not need to import `HttpDeliveryError` — throwing any error
 * with a numeric `statusCode` field is enough.
 */
export function classifyFailure(err: unknown): ClassifiedFailure {
  // WR-115: a payload-transform failure is a local config/payload
  // problem, not a downstream verdict — the wire request was never
  // built, let alone sent. Retrying can never succeed (same config,
  // same payload), so dead-letter immediately instead of burning the
  // retry budget and the backoff clock.
  if (err instanceof PayloadTransformError) {
    return { failureClass: "non_retryable" };
  }
  // WR-116: a SigV4 signing failure is a local config problem (missing
  // secret, absent signed header, unparsable URL) — the wire request was
  // never built, let alone sent. Retrying can never succeed for this
  // item, so dead-letter immediately instead of burning the retry
  // budget and the backoff clock.
  if (err instanceof SigV4SigningError) {
    return { failureClass: "non_retryable" };
  }
  // WR-210: an unresolvable SQS secret reference is a local config
  // problem — the wire request was never built, let alone sent.
  // Retrying can never succeed for this item, so dead-letter
  // immediately instead of burning the retry budget and the backoff
  // clock (the WR-116 rule, applied to the SQS sink).
  if (err instanceof SqsSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-213: an unresolvable Kinesis secret reference is a local config
  // problem — the wire request was never built, let alone sent.
  // Retrying can never succeed for this item, so dead-letter
  // immediately instead of burning the retry budget and the backoff
  // clock (the WR-116 rule, applied to the Kinesis sink like the SQS
  // sink above).
  if (err instanceof KinesisSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-215: a Kafka sink with no injected producer is a local config
  // problem — the produce was never built, let alone sent. Retrying
  // can never succeed for this item, so dead-letter immediately
  // instead of burning the retry budget and the backoff clock (the
  // WR-116 rule, applied to the Kafka sink like the SQS and Kinesis
  // sinks above).
  if (err instanceof KafkaSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-216: an MQTT sink with no injected client is a local config
  // problem — the publish was never built, let alone sent. Retrying
  // can never succeed for this item, so dead-letter immediately
  // instead of burning the retry budget and the backoff clock (the
  // WR-116 rule, applied to the MQTT sink like the Kafka sink above).
  if (err instanceof MqttSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-217: an AMQP sink with no injected client is a local config
  // problem — the publish was never built, let alone sent. Retrying
  // can never succeed for this item, so dead-letter immediately
  // instead of burning the retry budget and the backoff clock (the
  // WR-116 rule, applied to the AMQP sink like the MQTT sink above).
  if (err instanceof AmqpSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-218: a JetStream sink with no injected client is a local
  // config problem — the publish was never built, let alone sent.
  // Retrying can never succeed for this item, so dead-letter
  // immediately instead of burning the retry budget and the
  // backoff clock (the WR-116 rule, applied to the JetStream sink
  // like the AMQP sink above).
  if (err instanceof JetStreamSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-219: a Redis sink with no injected client is a local config
  // problem — the XADD was never built, let alone sent. Retrying
  // can never succeed for this item, so dead-letter immediately
  // instead of burning the retry budget and the backoff clock
  // (the WR-116 rule, applied to the Redis sink like the JetStream
  // sink above).
  if (err instanceof RedisSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-220: a Pub/Sub sink with no injected client or no configured
  // topic is a local config problem — the publish was never built,
  // let alone sent. Retrying can never succeed for this item, so
  // dead-letter immediately instead of burning the retry budget and
  // the backoff clock (the WR-116 rule, applied to the Pub/Sub sink
  // like the Redis sink above).
  if (err instanceof PubSubSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-221: a Service Bus sink with no injected client or no
  // configured entity is a local config problem — the send was
  // never built, let alone sent. Retrying can never succeed for
  // this item, so dead-letter immediately instead of burning the
  // retry budget and the backoff clock (the WR-116 rule, applied
  // to the Service Bus sink like the Pub/Sub sink above).
  if (err instanceof ServiceBusSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-222: an EventBridge sink with no injected client or no
  // configured event bus is a local config problem — the PutEvents
  // entry was never built, let alone sent. Retrying can never
  // succeed for this item, so dead-letter immediately instead of
  // burning the retry budget and the backoff clock (the WR-116
  // rule, applied to the EventBridge sink like the Service Bus
  // sink above).
  if (err instanceof EventBridgeSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-223: a Pulsar sink with no injected client is a local config
  // problem — the produce was never built, let alone sent. Retrying
  // can never succeed for this item, so dead-letter immediately
  // instead of burning the retry budget and the backoff clock (the
  // WR-116 rule, applied to the Pulsar sink like the EventBridge
  // sink above). A missing topic is not a config error: it selects
  // per-record topic resolution instead.
  if (err instanceof PulsarSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-224: an SNS sink with no injected client is a local config
  // problem — the Publish was never built, let alone sent. Retrying
  // can never succeed for this item, so dead-letter immediately
  // instead of burning the retry budget and the backoff clock (the
  // WR-116 rule, applied to the SNS sink like the Pulsar sink
  // above). A missing topic ARN is not a config error: it selects
  // per-record topic resolution instead.
  if (err instanceof SnsSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-225: an Event Hubs sink with no injected client is a local
  // config problem — the sendBatch was never built, let alone
  // sent. Retrying can never succeed for this item, so dead-letter
  // immediately instead of burning the retry budget and the
  // backoff clock (the WR-116 rule, applied to the Event Hubs
  // sink like the SNS sink above). A missing event hub name is
  // not a config error: it selects per-event hub resolution
  // instead.
  if (err instanceof EventHubsSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-226: a Slack sink with no injected client or no valid
  // webhook URL is a local config problem — the POST was never
  // built, let alone sent. Retrying can never succeed for this
  // item, so dead-letter immediately instead of burning the
  // retry budget and the backoff clock (the WR-116 rule,
  // applied to the Slack sink like the Event Hubs sink above).
  // There is no per-record channel fallback: a missing URL has
  // nowhere to deliver to.
  if (err instanceof SlackSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-228: a DingTalk sink with no injected client, no valid
  // webhook URL, or no access token is a local config problem
  // — the POST was never built, let alone sent. Retrying can
  // never succeed for this item, so dead-letter immediately
  // instead of burning the retry budget and the backoff clock
  // (the WR-116 rule, applied to the DingTalk sink like the
  // Slack sink above). There is no per-record channel
  // fallback: a missing token has nowhere to deliver to.
  if (err instanceof DingTalkSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-229: a Feishu sink with no injected client or no valid
  // webhook URL is a local config problem — the POST was never
  // built, let alone sent. Retrying can never succeed for this
  // item, so dead-letter immediately instead of burning the
  // retry budget and the backoff clock (the WR-116 rule,
  // applied to the Feishu sink like the DingTalk sink above).
  // There is no per-record channel fallback: a missing URL has
  // nowhere to deliver to.
  if (err instanceof FeishuSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-231: a Telegram sink with no injected client or no chat
  // id is a local config problem — the POST was never built,
  // let alone sent. Retrying can never succeed for this item,
  // so dead-letter immediately instead of burning the retry
  // budget and the backoff clock (the WR-116 rule, applied to
  // the Telegram sink like the Feishu sink above). There is no
  // per-record channel fallback: a missing chat id has nowhere
  // to deliver to.
  if (err instanceof TelegramSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-232: a Discord sink with no injected client or no valid
  // webhook URL is a local config problem — the POST was never
  // built, let alone sent. Retrying can never succeed for this
  // item, so dead-letter immediately instead of burning the
  // retry budget and the backoff clock (the WR-116 rule,
  // applied to the Discord sink like the Telegram sink above).
  // There is no per-record channel fallback: a missing URL has
  // nowhere to deliver to.
  if (err instanceof DiscordSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-234: a Teams sink with no injected client or no valid
  // webhook URL is a local config problem — the POST was never
  // built, let alone sent. Retrying can never succeed for this
  // item, so dead-letter immediately instead of burning the
  // retry budget and the backoff clock (the WR-116 rule,
  // applied to the Teams sink like the Discord sink above).
  // There is no per-record channel fallback: a missing URL has
  // nowhere to deliver to.
  if (err instanceof TeamsSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-235: a WeCom sink with no injected client or no valid
  // webhook URL is a local config problem — the POST was never
  // built, let alone sent. Retrying can never succeed for this
  // item, so dead-letter immediately instead of burning the
  // retry budget and the backoff clock (the WR-116 rule,
  // applied to the WeCom sink like the Teams sink above).
  // There is no per-record group fallback: a missing URL has
  // nowhere to deliver to.
  if (err instanceof WeComSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-236: a Google Chat sink with no injected client or no valid
  // webhook URL is a local config problem — the POST was never
  // built, let alone sent. Retrying can never succeed for this
  // item, so dead-letter immediately instead of burning the
  // retry budget and the backoff clock (the WR-116 rule,
  // applied to the Google Chat sink like the WeCom sink above).
  // There is no per-record space fallback: a missing URL has
  // nowhere to deliver to.
  if (err instanceof GoogleChatSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-233: an email sink with no injected client or no
  // recipient is a local config problem — the send was never
  // built, let alone sent. Retrying can never succeed for this
  // item, so dead-letter immediately instead of burning the
  // retry budget and the backoff clock (the WR-116 rule,
  // applied to the email sink like the Discord sink above).
  // There is no per-record channel fallback: a missing
  // recipient has nowhere to deliver to.
  if (err instanceof EmailSinkConfigError) {
    return { failureClass: "non_retryable" };
  }
  // WR-212: a Digest challenge this client cannot answer (unsupported
  // algorithm / qop, malformed challenge, unresolvable password
  // reference) is a local config problem — the wire request was
  // never authenticated, let alone delivered. Retrying can never
  // succeed for this item, so dead-letter immediately instead of
  // burning the retry budget and the backoff clock (the WR-116 rule).
  if (err instanceof DigestAuthError) {
    return { failureClass: "non_retryable" };
  }
  // WR-192: an unresolvable static-credential reference is a local
  // config problem (the relay refused to boot with a missing secret, so
  // this only fires when a resolver breaks mid-run) — the wire request
  // was never built, let alone sent. Retrying can never succeed for
  // this item, so dead-letter immediately instead of burning the retry
  // budget and the backoff clock.
  if (err instanceof CredentialSecretUnavailableError) {
    return { failureClass: "non_retryable" };
  }
  // WR-117: an outbound schema violation is a local config/payload
  // problem, not a downstream verdict — the post-transform payload
  // failed the endpoint's JSON schema before the wire request was
  // built, let alone sent. Retrying can never succeed (same config,
  // same payload), so dead-letter immediately instead of burning the
  // retry budget and the backoff clock. Audited as `schema_violation`.
  if (err instanceof OutboundSchemaViolationError) {
    return { failureClass: "non_retryable" };
  }
  // WR-118: an assertion failure is a retryable delivery failure — the
  // downstream answered inside the rule's status whitelist, but the
  // body failed the endpoint's declarative assertions. It follows the
  // normal backoff lane and trips the circuit breaker like any other
  // retryable failure. The status code rides along so the WR-54
  // response summary on the dead-letter audit event stays honest.
  if (err instanceof AssertionFailedError) {
    return {
      failureClass: "assertion_failed",
      ...(err.statusCode !== undefined ? { statusCode: err.statusCode } : {}),
    };
  }
  // WR-168: a Content-Digest mismatch is retryable — the tamper may be
  // transient — and the numeric statusCode rides along so the
  // dead-letter `response_summary` stays honest (the downstream did
  // answer 2xx). Audited as `integrity_mismatch`.
  if (err instanceof IntegrityMismatchError) {
    return { failureClass: "retryable", statusCode: err.statusCode };
  }
  // WR-169: a response-body overrun is retryable — a recovering
  // downstream deserves another attempt — and the numeric statusCode
  // rides along for the same audit honesty. Audited as
  // `response_too_large`.
  if (err instanceof ResponseTooLargeError) {
    return { failureClass: "retryable", statusCode: err.statusCode };
  }
  let statusCode: number | undefined;
  let retryAfterMs: number | undefined;
  if (err !== null && typeof err === "object") {
    const sc = (err as { statusCode?: unknown }).statusCode;
    if (typeof sc === "number" && Number.isInteger(sc)) {
      statusCode = sc;
    }
    const ra = (err as { retryAfterMs?: unknown }).retryAfterMs;
    if (typeof ra === "number" && Number.isFinite(ra) && ra >= 0) {
      retryAfterMs = ra;
    }
  }
  if (
    statusCode !== undefined &&
    statusCode >= 400 &&
    statusCode <= 499 &&
    statusCode !== 408 &&
    statusCode !== 429
  ) {
    return { failureClass: "non_retryable", statusCode };
  }
  return { failureClass: "retryable", ...(statusCode !== undefined ? { statusCode } : {}), ...(retryAfterMs !== undefined ? { retryAfterMs } : {}) };
}
