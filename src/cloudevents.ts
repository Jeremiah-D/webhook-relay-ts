/**
 * CloudEvents 1.0 structured-mode envelope for outbound delivery (WR-207).
 *
 * Knative/EventBridge-style consumers expect the CloudEvents JSON
 * *structured mode*: the whole event — attributes plus payload — rides
 * in the request body as one JSON document, with
 * `content-type: application/cloudevents+json`. This module builds that
 * envelope for a single relay delivery:
 *
 * - required attributes `specversion` (`"1.0"`), `id`, `source`, `type`,
 *   `time` (RFC 3339 / ISO-8601);
 * - optional `subject` and CloudEvents extension attributes
 *   (lowercase alphanumeric, max 20 chars per the spec);
 * - the payload becomes `data` when it parses as JSON (with
 *   `datacontenttype: application/json`), or `data_base64` when it does
 *   not (with `datacontenttype: application/octet-stream`) — the two
 *   are mutually exclusive per the spec, and a binary payload never
 *   corrupts into mojibake;
 * - `id` defaults to the delivery's `traceId` (the relay already
 *   propagates it downstream as `x-trace-id`), falling back to a
 *   random hex id — so the envelope id correlates with the relay's
 *   audit trail without any extra wiring.
 *
 * Orthogonal to the WR-17 batch envelope (the relay's own batch
 * envelope for merged deliveries; this is a *single-event standard*
 * envelope) and to the WR-11 sealed payloads (a sealed E2EE payload is
 * not JSON, so it lands in `data_base64` — the downstream still gets a
 * valid CloudEvents document). Composable with WR-26 `x-relay-signature`:
 * the envelope is applied to the source payload *before* compression /
 * E2EE sealing / signing in `createDefaultSender`, so the signature
 * covers exactly the envelope bytes the downstream receives and
 * verifies.
 *
 * Zero dependencies.
 */

/** Content type for CloudEvents JSON structured mode. */
export const CLOUD_EVENTS_STRUCTURED_CONTENT_TYPE = "application/cloudevents+json";

/** CloudEvents spec version this module emits. */
export const CLOUD_EVENTS_SPEC_VERSION = "1.0";

/** Default `datacontenttype` when the payload parses as JSON. */
export const CLOUD_EVENTS_JSON_DATACONTENTTYPE = "application/json";

/** Default `datacontenttype` when the payload is not JSON. */
export const CLOUD_EVENTS_BINARY_DATACONTENTTYPE = "application/octet-stream";

/** CloudEvents extension attribute names: lowercase alnum, 1–20 chars. */
const EXTENSION_NAME_RE = /^[a-z0-9]{1,20}$/;

/** Extension attribute value types per the CloudEvents spec. */
export type CloudEventsExtensionValue = string | number | boolean;

/**
 * Per-endpoint CloudEvents envelope configuration (WR-207). Keys are
 * exact `targetUrl` strings in the sender's `cloudEvents` record.
 */
export interface CloudEventsEndpointConfig {
  /**
   * `ce-source`: identifies the event producer in the downstream's
   * namespace, e.g. `"https://relay.example.com"`. Required,
   * non-empty.
   */
  source: string;
  /**
   * `ce-type`: the event type, e.g.
   * `"com.example.relay.webhook.delivered"`. Required, non-empty.
   */
  type: string;
  /** Optional `ce-subject` (the event's subject within the source). */
  subject?: string;
  /**
   * Optional prefix for generated envelope ids (e.g. `"evt-"`).
   * The `id` still defaults to the delivery's traceId when one is
   * known — the prefix only applies to the random-id fallback.
   */
  idPrefix?: string;
  /**
   * Override for the `datacontenttype` attribute. Defaults to
   * `application/json` for JSON payloads and
   * `application/octet-stream` otherwise.
   */
  datacontenttype?: string;
  /**
   * CloudEvents extension attributes, stamped verbatim (e.g.
   * `partitionkey`). Names must match `^[a-z0-9]{1,20}$`; values are
   * string | number | boolean. Reserved attribute names
   * (`specversion`, `id`, `source`, `type`, `time`, `data`,
   * `data_base64`, `datacontenttype`, `subject`, `dataschema`) are
   * rejected — they would collide with the envelope itself.
   */
  extensions?: Record<string, CloudEventsExtensionValue>;
  /** Clock for `ce-time`; defaults to `Date.now`. Injected in tests. */
  nowMs?: () => number;
  /**
   * Random id generator for the `id` fallback; defaults to 16 random
   * hex bytes. Injected in tests.
   */
  randomId?: () => string;
}

/** Identity material the envelope builder may draw the `id` from. */
export interface CloudEventsIdentity {
  /** The queue item's id (unused for `ce-id`, kept for API symmetry). */
  id?: string;
  /** Delivery trace id — becomes `ce-id` when present. */
  traceId?: string;
}

/** Reserved attribute names an extension may not shadow. */
const RESERVED_ATTRIBUTES = new Set([
  "specversion",
  "id",
  "source",
  "type",
  "time",
  "subject",
  "data",
  "data_base64",
  "datacontenttype",
  "dataschema",
]);

/**
 * Validate one endpoint's CloudEvents config. Throws `RangeError` on
 * any bad shape — called at startup so a typo fails fast, never
 * mid-delivery.
 */
export function assertValidCloudEventsConfig(
  cfg: unknown,
  label: string
): asserts cfg is CloudEventsEndpointConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (typeof c.source !== "string" || c.source === "") {
    throw new RangeError(at("`source` must be a non-empty string"));
  }
  if (typeof c.type !== "string" || c.type === "") {
    throw new RangeError(at("`type` must be a non-empty string"));
  }
  if (c.subject !== undefined && typeof c.subject !== "string") {
    throw new RangeError(at("`subject` must be a string when set"));
  }
  if (c.idPrefix !== undefined && typeof c.idPrefix !== "string") {
    throw new RangeError(at("`idPrefix` must be a string when set"));
  }
  if (c.datacontenttype !== undefined && typeof c.datacontenttype !== "string") {
    throw new RangeError(at("`datacontenttype` must be a string when set"));
  }
  if (c.extensions !== undefined) {
    if (c.extensions === null || typeof c.extensions !== "object" || Array.isArray(c.extensions)) {
      throw new RangeError(at("`extensions` must be an object when set"));
    }
    for (const [name, value] of Object.entries(c.extensions as Record<string, unknown>)) {
      if (!EXTENSION_NAME_RE.test(name)) {
        throw new RangeError(
          at(`extension name "${name}" must match /^[a-z0-9]{1,20}$/ (CloudEvents spec)`)
        );
      }
      if (RESERVED_ATTRIBUTES.has(name)) {
        throw new RangeError(at(`extension name "${name}" collides with a reserved CloudEvents attribute`));
      }
      const t = typeof value;
      if (t !== "string" && t !== "number" && t !== "boolean") {
        throw new RangeError(at(`extension "${name}" must be string | number | boolean, got ${t}`));
      }
    }
  }
  if (c.nowMs !== undefined && typeof c.nowMs !== "function") {
    throw new RangeError(at("`nowMs` must be a function when set"));
  }
  if (c.randomId !== undefined && typeof c.randomId !== "function") {
    throw new RangeError(at("`randomId` must be a function when set"));
  }
}

function defaultRandomId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("hex");
}

/**
 * Wrap one delivery payload in a CloudEvents 1.0 structured-mode
 * envelope. Returns the serialized JSON document as a Buffer, ready to
 * become the outbound wire body (and therefore covered by the WR-26
 * `x-relay-signature` stamp).
 *
 * A JSON payload becomes `data` (parsed, not re-encoded — key order
 * and number formatting are the JSON parser's, not the relay's); any
 * other payload becomes `data_base64`. A `datacontenttype` override in
 * the config wins over the defaults in both cases.
 */
export function buildCloudEventEnvelope(
  payload: Buffer,
  identity: CloudEventsIdentity,
  config: CloudEventsEndpointConfig
): Buffer {
  assertValidCloudEventsConfig(config, "buildCloudEventEnvelope");
  const nowMs = config.nowMs ?? Date.now;
  const randomId = config.randomId ?? defaultRandomId;
  const id = identity.traceId ?? `${config.idPrefix ?? ""}${randomId()}`;

  const envelope: Record<string, unknown> = {
    specversion: CLOUD_EVENTS_SPEC_VERSION,
    id,
    source: config.source,
    type: config.type,
    time: new Date(nowMs()).toISOString(),
  };
  if (config.subject !== undefined) envelope.subject = config.subject;

  let parsed: unknown;
  let isJson = false;
  try {
    parsed = JSON.parse(payload.toString("utf8"));
    isJson = true;
  } catch {
    isJson = false;
  }
  if (isJson) {
    envelope.datacontenttype = config.datacontenttype ?? CLOUD_EVENTS_JSON_DATACONTENTTYPE;
    envelope.data = parsed;
  } else {
    envelope.datacontenttype = config.datacontenttype ?? CLOUD_EVENTS_BINARY_DATACONTENTTYPE;
    envelope.data_base64 = payload.toString("base64");
  }

  if (config.extensions !== undefined) {
    for (const [name, value] of Object.entries(config.extensions)) {
      envelope[name] = value;
    }
  }
  return Buffer.from(JSON.stringify(envelope));
}
