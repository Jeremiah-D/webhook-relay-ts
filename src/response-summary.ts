/**
 * WR-54: downstream response summary for the audit trail.
 *
 * Every terminal delivery (`delivered`, `dead_letter`) carries a compact,
 * privacy-safe sketch of what the downstream answered — status code, byte
 * count, time-to-first-byte, and a body fingerprint — so operators can
 * correlate, deduplicate, and sanity-check deliveries from the audit log
 * alone. The full response body is *never* in the summary by default
 * (see `responseBodyCapture` in `src/retry.ts`): summaries are safe to
 * keep, grep, and ship; bodies are opt-in and sealed.
 *
 * Honesty rule: any value that was not measured is the string
 * `"unavailable"` — never a fabricated 0, -1, or empty hash. An absent
 * optional field means "there was nothing to hash", not "we failed to
 * measure".
 */
import { createHash } from "node:crypto";
import type { EncryptedPayload } from "./encrypt.ts";
import type { DownstreamResponse } from "./retry.ts";

/**
 * Bytes of the response body hashed into
 * {@link DownstreamResponseSummary.bodyFingerprintSha256}. 256 bytes is
 * enough to tell responses apart (semantic markers like `{"ok":false}`
 * live in the first bytes) while keeping the summary fixed-size.
 */
export const BODY_FINGERPRINT_PREFIX_BYTES = 256;

/**
 * A privacy-safe sketch of a downstream HTTP response, audited on
 * `delivered` / `dead_letter` events as `response_summary`.
 */
export interface DownstreamResponseSummary {
  /**
   * Downstream HTTP status code. `"unavailable"` when the sender could
   * not see a response at all (a custom sender returning `void`).
   */
  statusCode: number | "unavailable";
  /**
   * Captured response body length in bytes (the sender-captured body —
   * the default sender caps at `RESPONSE_CAPTURE_MAX_BYTES`). `"unavailable"`
   * when there was no response to measure.
   */
  responseBytes: number | "unavailable";
  /**
   * Time-to-first-byte in ms, as measured by the sender (the default
   * sender times request-issued → first response bytes; see
   * `DownstreamResponse.timeToFirstByteMs`). `"unavailable"` when the
   * sender did not measure it.
   */
  timeToFirstByteMs: number | "unavailable";
  /**
   * sha256 hex of the first {@link BODY_FINGERPRINT_PREFIX_BYTES} bytes
   * of the response body. Omitted when there was no body (or no
   * response) — an absent field is honest; a hash of nothing would not be.
   */
  bodyFingerprintSha256?: string;
  /**
   * Full response body sealed with the WR-11 payload encryptor. Present
   * only when the queue's `responseBodyCapture` opt-in is enabled —
   * by default the audit trail carries the summary only, never the body.
   */
  capturedBody?: EncryptedPayload;
  /**
   * WR-62: the downstream's `content-encoding` response header value,
   * when the endpoint opted into response decompression and the
   * downstream sent one. Omitted on the plain path.
   */
  contentEncoding?: string;
  /**
   * WR-89: id of the mTLS client certificate the sender presented
   * during this delivery's handshake (`tlsClientCertRotation`
   * endpoint). Copied from {@link DownstreamResponse.clientCertId};
   * absent for non-rotation endpoints (WR-36 single identities keep
   * the legacy summary shape).
   */
  clientCertId?: string;
}

/**
 * Build the summary for a successful delivery from the sender's
 * {@link DownstreamResponse}. A `void` response (a sender that cannot see
 * the downstream answer) yields an all-`"unavailable"` summary — the
 * honest shape, never fabricated numbers.
 */
export function summarizeDownstreamResponse(
  response: DownstreamResponse | void
): DownstreamResponseSummary {
  if (response === undefined) {
    return {
      statusCode: "unavailable",
      responseBytes: "unavailable",
      timeToFirstByteMs: "unavailable",
    };
  }
  const summary: DownstreamResponseSummary = {
    statusCode: response.statusCode,
    responseBytes: response.body.length,
    timeToFirstByteMs: response.timeToFirstByteMs ?? "unavailable",
    ...(response.contentEncoding !== undefined
      ? { contentEncoding: response.contentEncoding }
      : {}),
    // WR-89: the rotation certificate id rides the summary so the
    // delivery audits can show which identity authenticated the
    // delivery — present only for rotation endpoints.
    ...(response.clientCertId !== undefined ? { clientCertId: response.clientCertId } : {}),
  };
  if (response.body.length > 0) {
    summary.bodyFingerprintSha256 = createHash("sha256")
      .update(response.body.subarray(0, BODY_FINGERPRINT_PREFIX_BYTES))
      .digest("hex");
  }
  return summary;
}

/**
 * Build the summary for a dead-lettered delivery from the last attempt's
 * error. Only the status code survives — duck-typed off the error the
 * same way `classifyFailure` reads it (`HttpDeliveryError` carries it;
 * anything else is not an HTTP response). A failed attempt has no usable
 * body and no meaningful TTFB, so those stay `"unavailable"`.
 */
export function summarizeDeadLetterFailure(err: unknown): DownstreamResponseSummary {
  let statusCode: number | "unavailable" = "unavailable";
  if (err !== null && typeof err === "object") {
    const sc = (err as { statusCode?: unknown }).statusCode;
    if (typeof sc === "number" && Number.isInteger(sc)) {
      statusCode = sc;
    }
  }
  return {
    statusCode,
    responseBytes: "unavailable",
    timeToFirstByteMs: "unavailable",
  };
}
