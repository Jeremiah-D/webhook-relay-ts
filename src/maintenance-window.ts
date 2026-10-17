/**
 * WR-127: per-endpoint one-shot maintenance windows.
 *
 * WR-52 covers *recurring* quiet hours (a daily `"HH:MM-HH:MM"` cycle), but
 * real operations also have one-shot blackout windows — e.g. "2026-11-01
 * 02:00–06:00 the downstream database is cut over". This module holds a
 * per-endpoint table of such windows: each is an `[start, end)` interval
 * written as RFC3339 timestamps (offsets allowed), stored as epoch
 * milliseconds. A delivery due inside a window is *parked*, never failed:
 * it stays queued with its attempt count intact, consumes no quota token,
 * no circuit-breaker verdict, no retry-budget token, and is never
 * dead-lettered for being in a window — the same park semantics as the
 * WR-52 quiet-hours gate, which it sits right after in the queue's gate
 * order. The re-schedule targets the window's end instant, so boundary
 * semantics are "flush at window close" (the close edge is exclusive).
 *
 * Overlapping windows for one endpoint are merged on insert (touching
 * windows — where one's end equals the next one's start — merge too,
 * since a zero gap is semantically identical). Ended windows are pruned
 * lazily: any read or mutation drops windows with `end <= now`, so the
 * table never grows unboundedly. Like the sibling modules, the clock is
 * injectable so tests pin wall-clock time deterministically.
 *
 * Window *transitions* are observable through `onTransition`: the first
 * time a delivery is parked during a window, the module fires
 * `maintenance_window_opened`; when the window leaves the table (lazy
 * prune after its end), it fires `maintenance_window_closed`. The relay
 * server wires these into the audit log (WR-127); the queue itself only
 * records park counts via `noteDelayed`/`delayedCount`.
 */

/**
 * An RFC3339 instant with optional seconds/fraction and a `Z` or
 * `±hh:mm`/`±hhmm` offset. Deliberately strict: `Date.parse` also
 * accepts non-RFC3339 strings ("Nov 1 2026"), which would silently turn a
 * typo'd window into a real blackout, so the shape is checked first.
 */
const RFC3339_RE =
  /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z|[+-](?:[01]\d|2[0-3]):?[0-5]\d)$/;

/** Parse one RFC3339 instant to epoch ms, throwing `RangeError` when invalid. */
function parseRfc3339(value: unknown, field: string, endpoint: string): number {
  if (typeof value !== "string" || !RFC3339_RE.test(value.trim())) {
    throw new RangeError(
      `maintenance window ${field} for ${JSON.stringify(endpoint)} must be an RFC3339 instant, got ${JSON.stringify(value)}`
    );
  }
  const ms = Date.parse(value.trim());
  if (!Number.isFinite(ms)) {
    // Unreachable in practice (the regex already pinned the shape), but
    // kept so a future V8 quirk cannot smuggle a NaN window through.
    throw new RangeError(
      `maintenance window ${field} for ${JSON.stringify(endpoint)} is not a real instant: ${JSON.stringify(value)}`
    );
  }
  return ms;
}

/** A single one-shot maintenance window on an endpoint. */
export interface MaintenanceWindow {
  /** The configured RFC3339 start (kept for observability). */
  start: string;
  /** The configured RFC3339 end (kept for observability). */
  end: string;
  /** Start as epoch ms (inclusive edge). */
  startMs: number;
  /** End as epoch ms (exclusive edge — deliveries flush at this instant). */
  endMs: number;
}

/**
 * Internal window with its announcement flag: whether
 * `maintenance_window_opened` has already been announced. Carried on
 * the window itself (not a side table) so merging overlapping windows
 * cannot orphan the flag — a merge propagates `announced ||` across
 * the merged group.
 */
interface InternalWindow extends MaintenanceWindow {
  announced: boolean;
}

/** What the server needs to audit one window transition. */
export interface MaintenanceWindowTransition {
  endpoint: string;
  window: { start: string; end: string; startMs: number; endMs: number };
  kind: "opened" | "closed";
}

/** Options for {@link EndpointMaintenanceWindow} (WR-127). */
export interface MaintenanceWindowOptions {
  /**
   * Per-endpoint one-shot windows: exact `targetUrl` → array of
   * `{ start, end }` RFC3339 instants (e.g. `{ start:
   * "2026-11-01T02:00:00Z", end: "2026-11-01T06:00:00Z" }`). Endpoints
   * absent from the record are never parked — windows are opt-in per
   * endpoint, unset means off. Invalid entries throw `RangeError` at
   * construction with zero partial application (the whole table is
   * staged before any window is installed).
   */
  windows?: Record<string, Array<{ start: string; end: string }>>;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Fired once per window per transition: `opened` when the first
   * delivery is parked during the window, `closed` when the window is
   * pruned after its end. Never throws into the caller: the module wraps
   * it defensively (an audit-sink failure must not break delivery).
   */
  onTransition?: (transition: MaintenanceWindowTransition) => void;
}

/**
 * Per-endpoint one-shot maintenance windows: `true` from
 * {@link isParked} means the delivery must wait until
 * {@link msUntilOpen}; otherwise it may go now. Ended windows are
 * pruned lazily on every read/mutation.
 */
export class EndpointMaintenanceWindow {
  private readonly windows = new Map<string, MaintenanceWindow[]>();
  private readonly delayed = new Map<string, number>();
  private readonly now: () => number;
  private readonly onTransition?: (transition: MaintenanceWindowTransition) => void;

  constructor(opts: MaintenanceWindowOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.onTransition = opts.onTransition;
    // Stage everything before installing anything, so a bad entry
    // throws with the table untouched.
    const staged = new Map<string, MaintenanceWindow[]>();
    for (const [endpoint, list] of Object.entries(opts.windows ?? {})) {
      this.assertValidEndpoint(endpoint, "constructor");
      if (!Array.isArray(list)) {
        throw new RangeError(
          `constructor: maintenance windows for ${JSON.stringify(endpoint)} must be an array of { start, end }`
        );
      }
      staged.set(endpoint, this.merge(list.map((w, i) => this.parseWindow(endpoint, w, `constructor[${i}]`))));
    }
    for (const [endpoint, list] of staged) this.windows.set(endpoint, list);
  }

  private assertValidEndpoint(endpoint: string, where: string): void {
    if (typeof endpoint !== "string" || endpoint.length === 0) {
      throw new RangeError(`${where}: endpoint must be a non-empty string`);
    }
  }

  private parseWindow(
    endpoint: string,
    w: { start: string; end: string },
    where: string
  ): InternalWindow {
    if (typeof w !== "object" || w === null || Array.isArray(w)) {
      throw new RangeError(
        `${where}: maintenance window for ${JSON.stringify(endpoint)} must be { start, end }`
      );
    }
    const startMs = parseRfc3339((w as { start?: unknown }).start, "start", endpoint);
    const endMs = parseRfc3339((w as { end?: unknown }).end, "end", endpoint);
    if (startMs >= endMs) {
      throw new RangeError(
        `${where}: maintenance window for ${JSON.stringify(endpoint)} must end after it starts`
      );
    }
    return {
      start: (w as { start: string }).start.trim(),
      end: (w as { end: string }).end.trim(),
      startMs,
      endMs,
      announced: false,
    };
  }

  /**
   * Sort windows by start and merge overlapping (or touching) ones: a
   * zero-gap merge is semantically identical to two separate windows,
   * and merging avoids double `opened` audits for back-to-back windows.
   * The announcement flag propagates across the merge (`||`), so a
   * later-arriving window that merges backward into an announced one
   * does not orphan the flag.
   */
  private merge(list: InternalWindow[]): InternalWindow[] {
    const sorted = [...list].sort((a, b) => a.startMs - b.startMs);
    const out: InternalWindow[] = [];
    for (const w of sorted) {
      const last = out[out.length - 1];
      if (last !== undefined && w.startMs <= last.endMs) {
        last.announced = last.announced || w.announced;
        if (w.endMs > last.endMs) {
          last.endMs = w.endMs;
          last.end = w.end;
        }
      } else {
        out.push({ ...w });
      }
    }
    return out;
  }

  /** Fire `closed` for an announced window being dropped. Never throws. */
  private emitTransition(endpoint: string, w: InternalWindow, kind: "opened" | "closed"): void {
    if (this.onTransition === undefined) return;
    try {
      this.onTransition({
        endpoint,
        window: { start: w.start, end: w.end, startMs: w.startMs, endMs: w.endMs },
        kind,
      });
    } catch {
      // An audit-sink failure must never break delivery gating.
    }
  }

  /**
   * Drop windows with `end <= nowMs` from the table. An announced window
   * that ends fires `maintenance_window_closed` exactly once; windows
   * that never parked a delivery (never announced) leave silently.
   */
  private prune(nowMs: number): void {
    for (const [endpoint, list] of this.windows) {
      let dropped = false;
      const kept = list.filter((w) => {
        if (w.endMs > nowMs) return true;
        dropped = true;
        if (w.announced) {
          this.emitTransition(endpoint, w, "closed");
          w.announced = false; // idempotence if the same slot is ever re-seen
        }
        return false;
      });
      if (dropped) {
        if (kept.length === 0) this.windows.delete(endpoint);
        else this.windows.set(endpoint, kept);
      }
    }
  }

  /** The live (unpruned) window `nowMs` falls into, or `undefined`. */
  private activeInternal(endpoint: string, nowMs: number): InternalWindow | undefined {
    return this.windows.get(endpoint)?.find((w) => w.startMs <= nowMs && nowMs < w.endMs);
  }

  /**
   * True when a delivery to `endpoint` must be parked: `nowMs` (default:
   * the injected clock) is inside one of the endpoint's windows
   * (`[start, end)` — the start edge is inclusive so a window opens
   * promptly, the end edge is exclusive so it flushes at the instant).
   * Endpoints without windows are never parked.
   */
  isParked(endpoint: string, nowMs?: number): boolean {
    const at = nowMs ?? this.now();
    this.prune(at);
    return this.activeInternal(endpoint, at) !== undefined;
  }

  /**
   * Milliseconds until the current window ends for `endpoint` (the
   * "flush at window close" re-schedule target), or 0 when the endpoint
   * is not parked — callers only re-schedule on a parked endpoint, so a
   * 0 return never busy-loops. Never negative.
   */
  msUntilOpen(endpoint: string, nowMs?: number): number {
    const at = nowMs ?? this.now();
    this.prune(at);
    const w = this.activeInternal(endpoint, at);
    return w === undefined ? 0 : Math.max(1, w.endMs - at);
  }

  /**
   * Announce the window the current delivery is parked in: fires
   * `maintenance_window_opened` exactly once per window, on the first
   * parked delivery. Called by the queue before parking. Returns `true`
   * when this call announced a fresh opening.
   */
  announcePark(endpoint: string, nowMs?: number): boolean {
    const at = nowMs ?? this.now();
    this.prune(at);
    const w = this.activeInternal(endpoint, at);
    if (w === undefined || w.announced) return false;
    w.announced = true;
    this.emitTransition(endpoint, w, "opened");
    return true;
  }

  /**
   * Add one window for `endpoint` at runtime (e.g. from the operator
   * `POST /maintenance/windows`). Invalid input throws `RangeError` and
   * leaves the current table intact. Returns the window as stored
   * (possibly merged with an existing one).
   */
  addWindow(
    endpoint: string,
    start: string,
    end: string
  ): { start: string; end: string; startMs: number; endMs: number } {
    this.assertValidEndpoint(endpoint, "addWindow");
    const w = this.parseWindow(endpoint, { start, end }, "addWindow");
    const at = this.now();
    this.prune(at);
    const list = this.merge([...(this.windows.get(endpoint) ?? []), w]);
    this.windows.set(endpoint, list);
    const stored = list.find((x) => x.startMs <= w.startMs && w.startMs < x.endMs) ?? w;
    return { start: stored.start, end: stored.end, startMs: stored.startMs, endMs: stored.endMs };
  }

  /**
   * Remove every window for `endpoint` at runtime (hot-reload override —
   * mirrors the WR-32/WR-50 per-endpoint runtime-override convention).
   * Announced-but-active windows being removed fire
   * `maintenance_window_closed` so the audit trail stays complete.
   * Returns `false` when the endpoint had no windows.
   */
  clearEndpoint(endpoint: string): boolean {
    this.assertValidEndpoint(endpoint, "clearEndpoint");
    const list = this.windows.get(endpoint);
    if (list === undefined || list.length === 0) return false;
    const at = this.now();
    for (const w of list) {
      if (w.announced && w.startMs <= at && at < w.endMs) {
        this.emitTransition(endpoint, w, "closed");
      }
    }
    this.windows.delete(endpoint);
    return true;
  }

  /** Endpoints with at least one live window, in first-configured order. */
  endpoints(): string[] {
    this.prune(this.now());
    return [...this.windows.keys()];
  }

  /** Live windows for `endpoint` (copies), in start order. */
  windowsFor(endpoint: string): Array<{ start: string; end: string; startMs: number; endMs: number }> {
    this.prune(this.now());
    return (this.windows.get(endpoint) ?? []).map((w) => ({
      start: w.start,
      end: w.end,
      startMs: w.startMs,
      endMs: w.endMs,
    }));
  }

  /** Record one in-window park for `endpoint` (called by the queue). */
  noteDelayed(endpoint: string): void {
    this.delayed.set(endpoint, (this.delayed.get(endpoint) ?? 0) + 1);
  }

  /** In-window parks recorded for `endpoint`. */
  delayedCount(endpoint: string): number {
    return this.delayed.get(endpoint) ?? 0;
  }
}

/** Per-endpoint one-shot maintenance-window observability. */
export interface MaintenanceWindowStats {
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Live windows, in start order. */
  windows: Array<{ start: string; end: string }>;
  /** Deliveries parked inside a window. */
  delayed: number;
  /** Whether a window is parking the endpoint at the injected clock's time. */
  parked: boolean;
}
