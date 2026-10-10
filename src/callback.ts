/**
 * Delivery completion callbacks (WR-47).
 *
 * Opt-in: when a delivery reaches a terminal state (`delivered` or
 * `dead_letter`), the relay POSTs a signed receipt to the caller's URL —
 * the active counterpart to the passive `GET /deliveries/:traceId` query
 * (WR-43). Payment-style async notification: the caller learns the final
 * outcome without polling.
 *
 * Receipt shape (JSON):
 *   { id, traceId, targetUrl, terminalState: "delivered"|"dead_letter",
 *     attempts, at, error? }
 *
 * Headers:
 * - `x-trace-id`: the delivery's end-to-end trace ID (WR-18 format).
 * - `x-relay-signature: sha256=<hex>`: HMAC-SHA256 of the receipt body
 *   (WR-26 signing style) when `signingSecret` is set, so the caller can
 *   verify the receipt really came from this relay.
 * - `x-relay-key-id`: the configured key id, when set.
 * - `x-relay-idempotency-key`: derived from (delivery id, callback
 *   attempt) under `idempotencySecret` (WR-44 derivation), so the caller's
 *   deduplicator can collapse retried receipts.
 *
 * Loop protection (a callback POST that re-enters this relay's own intake
 * would ping-pong forever): the target URL's origin is checked twice —
 * once at configuration time against declared `selfOrigins`, and again
 * before every POST against a runtime `selfCheck` the server installs
 * (derived from the actual bound address). A looped target fails fast and
 * is audited as `callback_failed`; it is never POSTed.
 *
 * A failed receipt is retried at most `maxAttempts` times (≤ 3, short
 * backoff) and then reported via `onFailed` (the server audits
 * `callback_failed`). Receipts never enter the retry queue or the
 * dead-letter list — a failing callback must not recurse.
 */

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { deriveIdempotencyKey, IDEMPOTENCY_KEY_HEADER } from "./idempotency-key.ts";
import { signSha256 } from "./verify.ts";
import { TRACE_ID_HEADER } from "./trace.ts";

/** Terminal delivery states that trigger a completion receipt. */
export type TerminalDeliveryState = "delivered" | "dead_letter";

/** The JSON body POSTed to the completion-callback URL. */
export interface CompletionReceipt {
  /** Delivery id (the `id` echoed in the 202 intake response). */
  id: string;
  /** End-to-end trace ID (WR-18), always populated on the delivery path. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Physical downstream target the terminal attempt went to. */
  targetUrl: string;
  terminalState: TerminalDeliveryState;
  /** Attempts consumed (including the successful one for `delivered`). */
  attempts: number;
  /** ISO-8601 timestamp when the terminal state was reached. */
  at: string;
  /** Failure message; present only for `dead_letter`. */
  error?: string;
}

/** Transport result for one receipt POST attempt. */
export interface CallbackPostResult {
  statusCode: number;
}

/**
 * Minimal receipt transport: POST bytes, report the status. The default
 * implementation uses `node:http`/`node:https` directly with a timeout;
 * tests inject a stub.
 */
export type CallbackPostFn = (
  url: string,
  body: Buffer,
  headers: Record<string, string>
) => Promise<CallbackPostResult>;

/** Operator-facing options for delivery completion callbacks. */
export interface CompletionCallbackOptions {
  /**
   * The caller's receipt endpoint. Required; must be `http:` or `https:`.
   * A URL whose origin matches this relay's own inbound origin is
   * rejected — the receipt would re-enter intake and loop forever.
   */
  url: string;
  /**
   * Origins (`scheme://host:port`) of this relay's own inbound listener,
   * for the configuration-time loop check. The runtime check installed by
   * the server (from the actual bound address) runs before every POST
   * regardless; declaring them here additionally fails fast at startup.
   */
  selfOrigins?: string[];
  /**
   * HMAC-SHA256 secret for the `x-relay-signature` receipt header
   * (WR-26 style). Non-empty when set. Keep it out of logs.
   */
  signingSecret?: string;
  /** Stable key identifier surfaced in `x-relay-key-id`. Optional. */
  keyId?: string;
  /**
   * Secret for deriving `x-relay-idempotency-key` from
   * (delivery id, callback attempt) (WR-44 derivation). Non-empty when
   * set. Keep it out of logs.
   */
  idempotencySecret?: string;
  /** Optional prefix prepended to the derived idempotency key. */
  keyPrefix?: string;
  /**
   * Receipt POST attempts per terminal event, including the first.
   * Default 3. Capped at 3 — a receipt that will not land in three tries
   * is reported, not chased.
   */
  maxAttempts?: number;
  /** Backoff between receipt retries in ms (`backoffMs * attempt`). Default 500. */
  backoffMs?: number;
  /** Per-attempt socket timeout in ms. Default 5000. */
  timeoutMs?: number;
  /** Injectable transport for tests; defaults to a real HTTP(S) POST. */
  post?: CallbackPostFn;
  /** Injectable clock for tests; defaults to `Date.now`. */
  now?: () => number;
  /** Injectable timers for tests. */
  setTimer?: (fn: () => void, ms: number) => { clear(): void };
  /** Injectable timers for tests. */
  clearTimer?: (handle: { clear(): void }) => void;
}

/** Validated, ready-to-use completion-callback configuration. */
export interface ResolvedCompletionCallbackConfig {
  url: string;
  signingSecret?: string;
  keyId?: string;
  idempotencySecret?: string;
  keyPrefix: string;
  maxAttempts: number;
  backoffMs: number;
  timeoutMs: number;
  post: CallbackPostFn;
  now: () => number;
  setTimer: (fn: () => void, ms: number) => { clear(): void };
  clearTimer: (handle: { clear(): void }) => void;
}

/** Info passed to the failure hook when a receipt gives up. */
export interface CompletionCallbackFailedInfo {
  id: string;
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  targetUrl: string;
  terminalState: TerminalDeliveryState;
  /** Callback POST attempts made. */
  attempts: number;
  error: string;
}

function originOf(raw: string): string {
  const u = new URL(raw);
  return u.origin;
}

/**
 * True when `url` targets one of `selfOrigins` (origin comparison:
 * scheme + host + port). Used for the configuration-time loop check.
 */
export function isSelfCallbackTarget(url: string, selfOrigins: string[]): boolean {
  let origin: string;
  try {
    origin = originOf(url);
  } catch {
    return false;
  }
  return selfOrigins.some((s) => {
    try {
      return originOf(s) === origin;
    } catch {
      return false;
    }
  });
}

/**
 * Validate `CompletionCallbackOptions` at startup. Returns `undefined`
 * when the feature is off (`opts` unset) — the default — so callers can
 * branch on "configured" with a single check. Throws `RangeError` on
 * invalid values; never mid-delivery.
 */
export function resolveCompletionCallbackConfig(
  opts?: CompletionCallbackOptions
): ResolvedCompletionCallbackConfig | undefined {
  if (opts === undefined) return undefined;
  if (typeof opts.url !== "string" || opts.url === "") {
    throw new RangeError("completionCallback: `url` must be a non-empty string");
  }
  let parsed: URL;
  try {
    parsed = new URL(opts.url);
  } catch {
    throw new RangeError(`completionCallback: \`url\` is not a valid URL: ${opts.url}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new RangeError(
      `completionCallback: \`url\` must be http(s), got ${parsed.protocol}//`
    );
  }
  if (opts.selfOrigins !== undefined) {
    if (!Array.isArray(opts.selfOrigins) || opts.selfOrigins.some((s) => typeof s !== "string")) {
      throw new RangeError("completionCallback: `selfOrigins` must be an array of strings");
    }
    if (isSelfCallbackTarget(opts.url, opts.selfOrigins)) {
      throw new RangeError(
        "completionCallback: `url` targets this relay's own inbound origin — the receipt would re-enter intake and loop forever"
      );
    }
  }
  if (opts.signingSecret !== undefined && opts.signingSecret === "") {
    throw new RangeError("completionCallback: `signingSecret` must be non-empty when set");
  }
  if (opts.keyId !== undefined && opts.keyId === "") {
    throw new RangeError("completionCallback: `keyId` must be non-empty when set");
  }
  if (opts.idempotencySecret !== undefined && opts.idempotencySecret === "") {
    throw new RangeError("completionCallback: `idempotencySecret` must be non-empty when set");
  }
  if (opts.keyPrefix !== undefined && typeof opts.keyPrefix !== "string") {
    throw new RangeError("completionCallback: `keyPrefix` must be a string when set");
  }
  const maxAttempts = opts.maxAttempts ?? 3;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 3) {
    throw new RangeError(
      `completionCallback: \`maxAttempts\` must be an integer in [1, 3], got ${opts.maxAttempts}`
    );
  }
  const backoffMs = opts.backoffMs ?? 500;
  if (!Number.isFinite(backoffMs) || backoffMs < 0) {
    throw new RangeError(`completionCallback: \`backoffMs\` must be >= 0, got ${opts.backoffMs}`);
  }
  const timeoutMs = opts.timeoutMs ?? 5000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError(`completionCallback: \`timeoutMs\` must be > 0, got ${opts.timeoutMs}`);
  }
  if (opts.post !== undefined && typeof opts.post !== "function") {
    throw new TypeError("completionCallback: `post` must be a function when set");
  }
  return {
    url: opts.url,
    signingSecret: opts.signingSecret,
    keyId: opts.keyId,
    idempotencySecret: opts.idempotencySecret,
    keyPrefix: opts.keyPrefix ?? "",
    maxAttempts,
    backoffMs,
    timeoutMs,
    // The default transport gets the configured socket timeout; a custom
    // `post` is trusted to enforce its own.
    post: opts.post ?? ((url, body, headers) => defaultPost(url, body, headers, timeoutMs)),
    now: opts.now ?? Date.now,
    setTimer:
      opts.setTimer ??
      ((fn, ms) => {
        const t = setTimeout(fn, ms);
        return { clear: () => clearTimeout(t) };
      }),
    clearTimer: opts.clearTimer ?? ((h) => h.clear()),
  };
}

/**
 * Build the runtime loop check from the server's actually bound address
 * (WR-47). The predicate is evaluated before every receipt POST, so a
 * callback URL that resolves to this relay — even one not declared in
 * `selfOrigins` — is refused. `getAddress` mirrors
 * `net.Server#address()`: `null` (not listening) or a string (unix
 * socket) means no TCP loop is possible.
 */
export function createBoundAddressSelfCheck(
  getAddress: () => { address: string; port: number } | string | null
): (url: string) => boolean {
  const loopback = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
  return (url: string) => {
    const addr = getAddress();
    if (addr === null || typeof addr === "string") return false;
    let target: URL;
    try {
      target = new URL(url);
    } catch {
      return false;
    }
    const port =
      target.port === "" ? (target.protocol === "https:" ? 443 : 80) : Number(target.port);
    if (!Number.isFinite(port) || port !== addr.port) return false;
    const bound = addr.address;
    if (bound === "0.0.0.0" || bound === "::" || bound === "::ffff:0.0.0.0") {
      // All interfaces: any loopback hostname on this port is us.
      return loopback.has(target.hostname);
    }
    return target.hostname === bound || (loopback.has(target.hostname) && loopback.has(bound));
  };
}

/** Default receipt transport: one HTTP(S) POST with a socket timeout. */
export function defaultPost(
  url: string,
  body: Buffer,
  headers: Record<string, string>,
  timeoutMs = 5000
): Promise<CallbackPostResult> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = (u.protocol === "https:" ? httpsRequest : httpRequest)(
      {
        method: "POST",
        hostname: u.hostname,
        port: u.port === "" ? undefined : Number(u.port),
        path: `${u.pathname}${u.search}`,
        headers: { ...headers, "content-length": String(body.length) },
        // Fail fast instead of hanging a shutdown on a dead caller.
        timeout: timeoutMs,
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ statusCode: res.statusCode ?? 0 }));
      }
    );
    req.on("timeout", () => {
      req.destroy(new Error(`completion callback timed out after ${timeoutMs}ms`));
    });
    req.on("error", reject);
    req.end(body);
  });
}

export interface CompletionCallbackerHooks {
  /** Called once when a receipt exhausts its attempts (audited as `callback_failed`). */
  onFailed: (info: CompletionCallbackFailedInfo) => void;
}

/**
 * Sends completion receipts for terminal deliveries. Constructed from a
 * validated config; the server installs a runtime self-target check via
 * {@link setSelfCheck}. Receipt sends never touch the retry queue, so a
 * failing callback cannot recurse into the delivery machinery.
 */
export class CompletionCallbacker {
  private readonly config: ResolvedCompletionCallbackConfig;
  private readonly hooks: CompletionCallbackerHooks;
  private selfCheck?: (url: string) => boolean;
  private readonly timers = new Set<{ clear(): void }>();
  private stopped = false;

  constructor(config: ResolvedCompletionCallbackConfig, hooks: CompletionCallbackerHooks) {
    this.config = config;
    this.hooks = hooks;
  }

  /**
   * Install (or replace) the runtime loop check. The server derives it
   * from the actually bound address, so a callback URL that resolves to
   * this relay — even one that was not declared in `selfOrigins` — is
   * refused before every POST.
   */
  setSelfCheck(fn: (url: string) => boolean): void {
    this.selfCheck = fn;
  }

  /** Stop retrying in-flight receipts; pending timers are cancelled. */
  stop(): void {
    this.stopped = true;
    for (const t of this.timers) t.clear();
    this.timers.clear();
  }

  /** Queue a receipt for a delivered delivery. Fire-and-forget. */
  notifyDelivered(info: {
    id: string;
    traceId: string;
    tenantId?: string;
    targetUrl: string;
    attempts: number;
  }): void {
    this.send({
      id: info.id,
      traceId: info.traceId,
      ...(info.tenantId !== undefined ? { tenant: info.tenantId } : {}),
      targetUrl: info.targetUrl,
      terminalState: "delivered",
      attempts: info.attempts,
      at: new Date().toISOString(),
    });
  }

  /** Queue a receipt for a dead-lettered delivery. Fire-and-forget. */
  notifyDeadLetter(info: {
    id: string;
    traceId: string;
    tenantId?: string;
    targetUrl: string;
    attempts: number;
    error: string;
  }): void {
    this.send({
      id: info.id,
      traceId: info.traceId,
      ...(info.tenantId !== undefined ? { tenant: info.tenantId } : {}),
      targetUrl: info.targetUrl,
      terminalState: "dead_letter",
      attempts: info.attempts,
      error: info.error,
      at: new Date().toISOString(),
    });
  }

  private send(receipt: CompletionReceipt): void {
    if (this.stopped) return;
    // Runtime loop check (the configuration-time check ran at startup):
    // refuse to POST a receipt back into this relay's own intake.
    if (this.selfCheck?.(this.config.url)) {
      this.hooks.onFailed({
        id: receipt.id,
        traceId: receipt.traceId,
        tenant: receipt.tenant,
        targetUrl: receipt.targetUrl,
        terminalState: receipt.terminalState,
        attempts: 0,
        error: "callback target is this relay's own inbound origin (loop detected)",
      });
      return;
    }
    void this.attempt(receipt, 1);
  }

  private async attempt(receipt: CompletionReceipt, attempt: number): Promise<void> {
    if (this.stopped) return;
    const body = Buffer.from(JSON.stringify(receipt), "utf8");
    const headers: Record<string, string> = {
      "content-type": "application/json",
      [TRACE_ID_HEADER]: receipt.traceId,
    };
    if (this.config.signingSecret !== undefined) {
      headers["x-relay-signature"] = signSha256(body, this.config.signingSecret);
    }
    if (this.config.keyId !== undefined) {
      headers["x-relay-key-id"] = this.config.keyId;
    }
    if (this.config.idempotencySecret !== undefined) {
      headers[IDEMPOTENCY_KEY_HEADER] = deriveIdempotencyKey(
        this.config.idempotencySecret,
        receipt.id,
        attempt,
        this.config.keyPrefix
      );
    }
    let statusCode: number | undefined;
    let failure: string | undefined;
    try {
      const result = await this.raceTimeout(this.config.post(this.config.url, body, headers));
      statusCode = result.statusCode;
      if (statusCode < 200 || statusCode >= 300) {
        failure = `unexpected status ${statusCode}`;
      }
    } catch (err) {
      failure = err instanceof Error ? err.message : String(err);
    }
    if (failure === undefined) return; // Receipt landed.
    if (attempt < this.config.maxAttempts && !this.stopped) {
      const waitMs = this.config.backoffMs * attempt;
      const timer = this.config.setTimer(() => {
        this.timers.delete(timer);
        void this.attempt(receipt, attempt + 1);
      }, waitMs);
      this.timers.add(timer);
      return;
    }
    this.hooks.onFailed({
      id: receipt.id,
      traceId: receipt.traceId,
      tenant: receipt.tenant,
      targetUrl: receipt.targetUrl,
      terminalState: receipt.terminalState,
      attempts: attempt,
      error: failure,
    });
  }

  /** The transport gets its own timeout even when a custom `post` hangs. */
  private raceTimeout(p: Promise<CallbackPostResult>): Promise<CallbackPostResult> {
    const timeoutMs = this.config.timeoutMs;
    return new Promise((resolve, reject) => {
      const timer = this.config.setTimer(
        () => reject(new Error(`completion callback timed out after ${timeoutMs}ms`)),
        timeoutMs
      );
      this.timers.add(timer);
      p.then(
        (r) => {
          this.timers.delete(timer);
          timer.clear();
          resolve(r);
        },
        (e) => {
          this.timers.delete(timer);
          timer.clear();
          reject(e);
        }
      );
    });
  }
}
