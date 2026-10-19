/**
 * WR-146: tail-latency hedging for outbound delivery attempts.
 *
 * Some downstreams answer fast most of the time and stall occasionally —
 * the classic tail-latency shape. Retrying after the fact does not help
 * (the first attempt still owns the delivery's latency), so this module
 * implements *hedged requests*: when the primary attempt has not returned
 * within `hedgeDelayMs`, a second identical attempt is launched in
 * parallel; the first to settle wins and the loser is cancelled.
 *
 * Contract and composition:
 *
 * - Opt-in. The wrapper (`createHedgedSender`) sits *around* any
 *   `Sender` — the default pooled sender (WR-24 keep-alive) or a custom
 *   one — and is invisible when disabled or when the item is not
 *   hedgeable.
 * - Hedgeable only. Hedging duplicates a downstream hit on slow
 *   endpoints, so it is restricted to idempotent-safe methods/endpoints
 *   via the `hedgeable` predicate. The default (no predicate) hedges
 *   nothing: conservative by construction.
 * - Latency only, never errors. A hedge fires only when *no* response
 *   has arrived within `hedgeDelayMs`. A returned 429/5xx settles the
 *   attempt — the queue's normal classify → backoff path owns it and no
 *   hedge is ever launched for it. A fast transport failure (connection
 *   refused) also settles the attempt without a hedge.
 * - First settle wins (fulfil *or* reject). The winner's outcome is the
 *   attempt's outcome; the loser's `AbortController` fires immediately.
 * - Orthogonal to WR-76 (deadline), WR-99 (deadline-budget race) and
 *   WR-143 (phase timeouts): all of those live *inside* the inner
 *   sender's per-attempt call, so each hedge attempt is independently
 *   budgeted — a hedged slow attempt can still be killed by its own
 *   deadline budget or phase budget, and the winner is whoever survives
 *   first.
 * - Cancellation is real on the HTTP/1.1 path: the losing attempt's
 *   `AbortSignal` destroys its in-flight request (typed
 *   `HedgeCancelledError`, swallowed by the wrapper so it never reaches
 *   the queue as a failure). H2/WS attempts ignore the signal (best
 *   effort): the loser is abandoned and reaped by its own timeouts.
 *   Senders that do not accept the `signal` option get the same
 *   abandon-only behavior — documented, not silent.
 *
 * Observability: `relay_hedged_total{endpoint}` counts launched hedges
 * (activity-gated), an `onHedge` hook fires one `hedged` audit event per
 * launched hedge, and a delivery that hedged carries `hedged: true` on
 * its winning response (so the queue stamps it on the `delivered` event)
 * and is retrievable via `takeHedgedFlag(deliveryId)` for the `delivered`
 * audit line.
 *
 * Zero dependencies.
 */

import type { DownstreamResponse, RetryItem, Sender, SenderCallOptions } from "./retry.ts";

/**
 * The error a hedge-cancelling sender rejects with when the losing
 * attempt's `AbortSignal` fires. Typed so the hedged wrapper (and any
 * operator reading logs) can tell "killed because it lost the hedge"
 * apart from a genuine downstream failure. The wrapper swallows it —
 * the queue never classifies a hedge loser as a delivery failure.
 */
export class HedgeCancelledError extends Error {
  /** Physical target the cancelled attempt was bound for. */
  readonly targetUrl: string;
  constructor(targetUrl: string) {
    super(`hedged request to ${targetUrl} cancelled: lost the hedge`);
    this.name = "HedgeCancelledError";
    this.targetUrl = targetUrl;
  }
}

/**
 * Audit event fired once per launched hedge (see the `onHedge` hook on
 * {@link HedgedSenderOptions} — the server appends these as `hedged`).
 */
export interface HedgeAuditEvent {
  event: "hedged";
  /** The endpoint whose attempt is being hedged (the item's targetUrl). */
  endpoint: string;
  /** The delivery's id. */
  id: string;
  /** The delivery's trace id, when the item carries one. */
  traceId?: string;
  /** The configured hedge delay that fired (ms). */
  hedgeDelayMs: number;
}

/**
 * Options for {@link createHedgedSender}.
 */
export interface HedgedSenderOptions {
  /**
   * Master switch. `false` (or absent) makes the wrapper a pure
   * pass-through: no timer, no second attempt, zero behavior change.
   */
  enabled?: boolean;
  /**
   * Milliseconds after the primary attempt is issued with no response
   * before the hedge attempt is launched. Must be a positive integer;
   * anything else throws `RangeError` at wrap time.
   */
  hedgeDelayMs: number;
  /**
   * Whether this item may be hedged. Hedging duplicates a downstream
   * hit when the endpoint is slow, so this must only return true for
   * idempotent-safe methods/endpoints. Absent = nothing is hedgeable
   * (conservative default — explicit opt-in per endpoint).
   */
  hedgeable?: (item: RetryItem) => boolean;
  /** Metrics sink for `relay_hedged_total`; optional. */
  metrics?: HedgeMetrics;
  /**
   * Called once per launched hedge with a {@link HedgeAuditEvent}. The
   * server wires this to the audit log; library users get the hook
   * directly. A throwing hook must not break the delivery — the wrapper
   * lets it throw (the delivery continues; the audit line is lost), so
   * keep it non-throwing in practice.
   */
  onHedge?: (event: HedgeAuditEvent) => void;
}

/**
 * The per-endpoint hedge counter behind `relay_hedged_total{endpoint}`.
 * Activity-gated: `render()` returns `""` until the first hedge fires,
 * so relays that never enable hedging see byte-identical `/metrics`
 * output.
 */
export class HedgeMetrics {
  private readonly hedges = new Map<string, number>();

  /** Record one launched hedge for an endpoint. */
  noteHedged(endpoint: string): void {
    this.hedges.set(endpoint, (this.hedges.get(endpoint) ?? 0) + 1);
  }

  /** Per-endpoint hedge counts, in first-seen endpoint order. */
  stats(): Array<{ endpoint: string; hedges: number }> {
    return [...this.hedges.entries()].map(([endpoint, hedges]) => ({ endpoint, hedges }));
  }

  /** Prometheus exposition for `GET /metrics`. `""` when nothing hedged. */
  render(): string {
    if (this.hedges.size === 0) return "";
    const lines = [
      "# HELP relay_hedged_total Hedged outbound attempts by endpoint (WR-146 tail-latency hedging).",
      "# TYPE relay_hedged_total counter",
    ];
    for (const [endpoint, hedges] of this.hedges) {
      lines.push(`relay_hedged_total{endpoint="${escapeLabelValue(endpoint)}"} ${hedges}`);
    }
    return lines.join("\n") + "\n";
  }
}

/** Minimal Prometheus label escaping (mirrors `src/metrics.ts`). */
function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/**
 * Validate {@link HedgedSenderOptions}. Throws `RangeError` on a bad
 * `hedgeDelayMs` (non-positive, non-integer, or non-finite) — fail fast
 * at startup, never silently mis-hedge at runtime.
 */
export function assertValidHedgedSenderOptions(options: HedgedSenderOptions): void {
  if (options.hedgeDelayMs === undefined || typeof options.hedgeDelayMs !== "number" ||
      !Number.isFinite(options.hedgeDelayMs) || !Number.isInteger(options.hedgeDelayMs) ||
      options.hedgeDelayMs <= 0) {
    throw new RangeError(
      `hedgedRequests: hedgeDelayMs must be a positive integer of milliseconds, got ${String(options.hedgeDelayMs)}`
    );
  }
  if (options.hedgeable !== undefined && typeof options.hedgeable !== "function") {
    throw new RangeError("hedgedRequests: hedgeable must be a function");
  }
}

/**
 * A `Sender` with hedge bookkeeping. `takeHedgedFlag` is take-and-clear
 * (consuming on read keeps the bookkeeping bounded): it returns `true`
 * exactly once per delivery that launched a hedge, so the server can
 * stamp `hedged: true` on that delivery's terminal audit line.
 */
export interface HedgedSender extends Sender {
  takeHedgedFlag?(deliveryId: string): boolean;
}

/**
 * Wrap a `Sender` with tail-latency hedging (see the module doc for the
 * contract). The returned sender has the same contract: it resolves with
 * the winning attempt's response, or rejects with the winning attempt's
 * error. The losing attempt is cancelled via its `AbortController`; the
 * inner sender receives the signal as `SenderCallOptions.signal` and
 * senders that ignore it degrade to abandon-the-loser (documented, not
 * silent).
 *
 * The two attempts share one `RetryItem`: the inner sender builds its
 * wire request per call, so each hedge attempt is a complete independent
 * attempt (own wire request, own keep-alive checkout, own deadline /
 * phase budgets).
 */
export function createHedgedSender(inner: Sender, options: HedgedSenderOptions): HedgedSender {
  assertValidHedgedSenderOptions(options);
  /** Delivery ids that launched a hedge (take-and-clear via takeHedgedFlag). */
  const hedgedIds = new Set<string>();

  const sender = function hedgedSender(
    item: RetryItem,
    callOpts?: SenderCallOptions
  ): Promise<DownstreamResponse | void> {
    if (options.enabled !== true || !(options.hedgeable?.(item) ?? false)) {
      return inner(item, callOpts);
    }
    return new Promise<DownstreamResponse | void>((resolve, reject) => {
      let settled = false;
      const controllers: AbortController[] = [];
      let timer: ReturnType<typeof setTimeout> | undefined;

      /** Fire every loser's AbortController except the winner's. */
      const abortLosers = (winnerIndex: number): void => {
        for (let i = 0; i < controllers.length; i++) {
          if (i !== winnerIndex) controllers[i].abort();
        }
      };

      /**
       * Settle the wrapper with one attempt's outcome. The other attempt
       * is cancelled immediately — a slow loser must not hold a pool
       * slot (or deliver a late duplicate) after the winner decided.
       */
      const settle = (
        winnerIndex: number,
        outcome: { ok: true; value: DownstreamResponse | void } | { ok: false; error: unknown }
      ): void => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) {
          clearTimeout(timer);
          timer = undefined;
        }
        abortLosers(winnerIndex);
        if (outcome.ok) {
          // The delivery hedged (the timer recorded the count and fired
          // onHedge at launch): mark the winning response so the queue
          // stamps `hedged: true` on the `delivered` event. A fast
          // primary that never hedged keeps the legacy shape.
          if (outcome.value !== undefined && hedgedIds.has(item.id)) {
            outcome.value = { ...outcome.value, hedged: true };
          }
          resolve(outcome.value);
        } else {
          reject(outcome.error);
        }
      };

      /** Launch attempt `index` (0 = primary, 1 = hedge). */
      const launch = (index: number): void => {
        const controller = new AbortController();
        controllers[index] = controller;
        // An outer abort (e.g. relay shutdown cancelling the attempt)
        // cancels every hedge attempt, not just the primary.
        const outer = callOpts?.signal;
        if (outer !== undefined && index === 0) {
          if (outer.aborted) controller.abort();
          else outer.addEventListener("abort", () => controller.abort(), { once: true });
        }
        let attempt: Promise<DownstreamResponse | void>;
        try {
          attempt = inner(item, { ...callOpts, signal: controller.signal });
        } catch (err) {
          attempt = Promise.reject(err);
        }
        attempt.then(
          (value) => settle(index, { ok: true, value }),
          (error: unknown) => settle(index, { ok: false, error })
        );
        // The loser's rejection (usually HedgeCancelledError) must never
        // surface as an unhandled rejection once the winner settled.
        attempt.catch(() => {});
      };

      launch(0);
      timer = setTimeout(() => {
        timer = undefined;
        if (settled) return;
        // The hedge fires: count it and audit it now. The winning
        // response is marked at settle time above.
        hedgedIds.add(item.id);
        options.metrics?.noteHedged(item.targetUrl);
        options.onHedge?.({
          event: "hedged",
          endpoint: item.targetUrl,
          id: item.id,
          ...(item.traceId !== undefined ? { traceId: item.traceId } : {}),
          hedgeDelayMs: options.hedgeDelayMs,
        });
        launch(1);
      }, options.hedgeDelayMs);
      // A hedge timer must never pin process exit.
      timer.unref?.();
    });
  } as HedgedSender;

  sender.takeHedgedFlag = (deliveryId: string): boolean => {
    if (!hedgedIds.has(deliveryId)) return false;
    hedgedIds.delete(deliveryId);
    return true;
  };

  return sender;
}
