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

/**
 * WR-440: a live revision patch for one endpoint's CloudEvents
 * envelope config (partial — omitted fields keep their live
 * values). A `null` field clears that optional field back to its
 * default (the field disappears from the envelope); `source` /
 * `type` are required and have no "clear back to a default"
 * semantics — `null` for either is rejected, clearing is
 * whole-entry deletion only (a `null` patch), exactly like
 * WR-437's required-field rule. `extensions` merges per key: a
 * provided key is added or overwritten, a `null` value deletes
 * that key, and keys the patch never mentions are preserved; a
 * `null` `extensions` clears the whole extensions field.
 * `nowMs` / `randomId` are construction-time test hooks and are not
 * revisable — they never appear in this type, and a patch carrying
 * either is rejected.
 */
export interface CloudEventsRevision {
  /** New `ce-source` (required, non-empty; `null` is rejected). */
  source?: string | null;
  /** New `ce-type` (required, non-empty; `null` is rejected). */
  type?: string | null;
  /** New `ce-subject`; `null` clears the field. */
  subject?: string | null;
  /** New id prefix for the random-id fallback; `null` clears it. */
  idPrefix?: string | null;
  /** New `datacontenttype` override; `null` clears it. */
  datacontenttype?: string | null;
  /**
   * Per-key extension changes; `null` as the whole field clears
   * all extensions, a `null` value deletes that one key.
   */
  extensions?: Record<string, CloudEventsExtensionValue | null> | null;
}

/**
 * WR-440: the outcome of merging a {@link CloudEventsRevision}
 * onto the live entry for one endpoint.
 */
export interface CloudEventsRevisionChange {
  /**
   * The entry to store for the endpoint, or `undefined` to delete it
   * (the patch was `null`). `undefined` with `changed: false` means
   * there was no entry and the patch changed nothing.
   */
  entry: CloudEventsEndpointConfig | undefined;
  /** False when the patch leaves the live entry exactly as it was. */
  changed: boolean;
}

function sameExtensions(
  a: Record<string, CloudEventsExtensionValue> | undefined,
  b: Record<string, CloudEventsExtensionValue> | undefined
): boolean {
  if (a === undefined || b === undefined) return a === b;
  const aKeys = Object.keys(a).sort();
  const bKeys = Object.keys(b).sort();
  return (
    aKeys.length === bKeys.length &&
    aKeys.every((k, i) => k === bKeys[i] && a[k] === b[k])
  );
}

function sameCloudEventsConfig(
  a: CloudEventsEndpointConfig,
  b: CloudEventsEndpointConfig
): boolean {
  return (
    a.source === b.source &&
    a.type === b.type &&
    a.subject === b.subject &&
    a.idPrefix === b.idPrefix &&
    a.datacontenttype === b.datacontenttype &&
    sameExtensions(a.extensions, b.extensions) &&
    a.nowMs === b.nowMs &&
    a.randomId === b.randomId
  );
}

/**
 * WR-440: merge one live revision patch onto the stored entry for
 * an endpoint. Pure and unit-testable: the caller owns the live map
 * and only applies the returned `entry` when `changed` is true —
 * the map itself is never mutated here. Validate-first-then-apply —
 * the candidate entry is built and run through
 * {@link assertValidCloudEventsConfig} before anything is returned,
 * so an illegal patch (a missing required field on opt-in, a `null`
 * required field, a bad extension name/value, an empty patch)
 * throws and the live record is untouched. A `null` patch deletes
 * the entry (the endpoint resumes raw-payload delivery); a
 * same-value patch is a silent no-op.
 */
export function reviseCloudEventsMap(
  map: ReadonlyMap<string, CloudEventsEndpointConfig>,
  endpoint: string,
  patch: CloudEventsRevision | null,
  label = `cloudEvents[${endpoint}]`
): CloudEventsRevisionChange {
  const prev = map.get(endpoint);
  if (patch === null) {
    return { entry: undefined, changed: prev !== undefined };
  }
  if (typeof patch !== "object" || Array.isArray(patch)) {
    throw new RangeError(`${label}: patch must be an object`);
  }
  const p = patch as Record<string, unknown>;
  // The construction-time test hooks are not revisable: a patch
  // carrying either fails closed instead of silently dropping it.
  if (p.nowMs !== undefined || p.randomId !== undefined) {
    throw new RangeError(
      `${label}: \`nowMs\` / \`randomId\` are construction-time test hooks and cannot be revised`
    );
  }
  // Required fields have no "clear back to a default" semantics —
  // clearing is whole-entry deletion only (a `null` patch).
  for (const field of ["source", "type"]) {
    if (p[field] === null) {
      throw new RangeError(
        `${label}: \`${field}\` must not be null (clearing is whole-entry deletion only)`
      );
    }
  }
  if (p.extensions !== undefined && p.extensions !== null) {
    if (
      typeof p.extensions !== "object" ||
      Array.isArray(p.extensions)
    ) {
      throw new RangeError(`${label}: \`extensions\` must be an object or null`);
    }
  }
  if (
    p.source === undefined &&
    p.type === undefined &&
    p.subject === undefined &&
    p.idPrefix === undefined &&
    p.datacontenttype === undefined &&
    p.extensions === undefined
  ) {
    throw new Error(`${label}: empty patch — nothing to revise`);
  }
  const candidate: CloudEventsEndpointConfig = { ...(prev ?? {}) };
  if (p.source !== undefined) candidate.source = p.source as string;
  if (p.type !== undefined) candidate.type = p.type as string;
  for (const field of ["subject", "idPrefix", "datacontenttype"] as const) {
    if (p[field] !== undefined) {
      if (p[field] === null) delete candidate[field];
      else candidate[field] = p[field] as string;
    }
  }
  if (p.extensions !== undefined) {
    if (p.extensions === null) {
      delete candidate.extensions;
    } else {
      const merged: Record<string, CloudEventsExtensionValue> = {
        ...(candidate.extensions ?? {}),
      };
      for (const [name, value] of Object.entries(
        p.extensions as Record<string, CloudEventsExtensionValue | null>
      )) {
        if (value === null) delete merged[name];
        else merged[name] = value;
      }
      // Deleting the last extension key removes the field entirely —
      // an empty extensions object would stamp nothing anyway.
      if (Object.keys(merged).length === 0) delete candidate.extensions;
      else candidate.extensions = merged;
    }
  }
  // A clear-only patch on an unconfigured endpoint leaves an empty
  // candidate — a no-op (there was nothing to clear), never an
  // opt-in.
  if (
    prev === undefined &&
    candidate.source === undefined &&
    candidate.type === undefined &&
    candidate.subject === undefined &&
    candidate.idPrefix === undefined &&
    candidate.datacontenttype === undefined &&
    candidate.extensions === undefined
  ) {
    return { entry: undefined, changed: false };
  }
  // The same per-value validator as startup: a missing required
  // field on opt-in, a bad extension name/value, or a bad optional
  // field throws RangeError and the live record is untouched.
  assertValidCloudEventsConfig(candidate, label);
  if (prev !== undefined && sameCloudEventsConfig(prev, candidate)) {
    return { entry: prev, changed: false };
  }
  return { entry: candidate, changed: true };
}
