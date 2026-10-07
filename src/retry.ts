export interface RetryItem {
  id: string;
  payload: Buffer;
  targetUrl: string;
  headers: Record<string, string | string[] | undefined>;
}

export type Sender = (item: RetryItem) => Promise<void>;

/**
 * Jitter strategy for the retry backoff.
 *
 * - `"additive"` (default): uniform(0, `jitterMs`) added on top of the
 *   exponential term. Preserves the original behavior.
 * - `"full"`: uniform(0, min(`maxDelayMs`, `baseDelayMs * 2^attempt`)) — the
 *   AWS-style "full jitter". This is the recommended anti-thundering-herd
 *   choice: when many deliveries fail at once (e.g. a downstream outage),
 *   their retry schedules spread across the whole window instead of
 *   clustering on the exponential grid.
 */
export type JitterStrategy = "additive" | "full";

/**
 * A dead-lettered delivery: the original {@link RetryItem} plus the
 * metadata an operator needs to diagnose and replay it.
 */
export interface DeadLetterEntry extends RetryItem {
  /** Attempts consumed before the item was dead-lettered. */
  attempts: number;
  /** Last delivery error message. */
  lastError: string;
  /** ISO-8601 timestamp when the item entered the dead-letter list. */
  deadLetteredAt: string;
}

export interface RetryQueueOptions {
  /** Sender function; defaults to a no-op success sender. Injectable for tests. */
  sender?: Sender;
  /** Base delay in ms for the exponential backoff. Default: 1000. Must be > 0. */
  baseDelayMs?: number;
  /** Maximum delay in ms between attempts. Default: 60000. Must be > 0. */
  maxDelayMs?: number;
  /** Total attempts per item (initial try + retries). Default: 5. Must be >= 1. */
  maxAttempts?: number;
  /** Jitter added to each delay in ms (uniform 0..jitterMs). Default: 100. Must be >= 0. */
  jitterMs?: number;
  /** Jitter strategy; see {@link JitterStrategy}. Default: "additive". */
  jitterStrategy?: JitterStrategy;
  /**
   * Random source in [0, 1) used for jitter; defaults to `Math.random`.
   * Injectable so tests can verify jitter bounds deterministically.
   */
  random?: () => number;
  /**
   * Scheduler factory; defaults to the real setTimeout. Injectable so tests
   * can run deterministically. Returns a handle with an `unref`-style
   * `clear()` method. Also accepts a clearTimer to cancel pending timeouts.
   */
  setTimer?: (fn: () => void, ms: number) => { clear(): void };
  clearTimer?: (handle: { clear(): void }) => void;
  /**
   * Maximum concurrent in-flight deliveries per endpoint (`targetUrl`).
   * Deliveries beyond the limit wait in FIFO order for a slot. Default:
   * `Infinity` (no limit). Must be a positive integer or `Infinity`.
   */
  maxConcurrentPerEndpoint?: number;
  /** Callback when an item exhausts all attempts and moves to dead-letter. */
  onDeadLetter?: (item: RetryItem, attempts: number, lastError: unknown) => void;
  /** Callback when an item is successfully delivered. */
  onDelivered?: (item: RetryItem, attempts: number) => void;
}

interface Scheduled {
  handle: { clear(): void };
}

const noopSender: Sender = async () => {};

/**
 * Per-endpoint concurrency gate: at most `max` deliveries in flight to the
 * same endpoint (`targetUrl`) at once; excess acquisitions wait in FIFO
 * order. This keeps one slow or rate-limited downstream from being hammered
 * by parallel redeliveries, while other endpoints keep their own budget.
 *
 * Callers must check their own liveness after `acquire()` resolves (the
 * queue may have stopped while they waited) and must always call the
 * returned release function exactly once, even when bailing out — releases
 * cascade to the next waiter, so no one hangs.
 */
export class EndpointConcurrencyLimiter {
  private readonly max: number;
  private readonly inFlight = new Map<string, number>();
  private readonly waiters = new Map<string, Array<() => void>>();

  constructor(maxConcurrentPerEndpoint: number = Infinity) {
    if (
      !(
        maxConcurrentPerEndpoint === Infinity ||
        (Number.isInteger(maxConcurrentPerEndpoint) && maxConcurrentPerEndpoint >= 1)
      )
    ) {
      throw new RangeError(
        `maxConcurrentPerEndpoint must be a positive integer or Infinity, got ${maxConcurrentPerEndpoint}`
      );
    }
    this.max = maxConcurrentPerEndpoint;
  }

  /**
   * Resolve when a slot for `endpoint` is free. Always call the returned
   * function exactly once to hand the slot on.
   */
  acquire(endpoint: string): Promise<() => void> {
    const n = this.inFlight.get(endpoint) ?? 0;
    if (n < this.max) {
      this.inFlight.set(endpoint, n + 1);
      return Promise.resolve(() => this.release(endpoint));
    }
    return new Promise<() => void>((resolve) => {
      const wake = (): void => {
        // Slot transfers from the releaser to this waiter; the in-flight
        // count is unchanged (no increment here).
        resolve(() => this.release(endpoint));
      };
      const q = this.waiters.get(endpoint);
      if (q) q.push(wake);
      else this.waiters.set(endpoint, [wake]);
    });
  }

  private release(endpoint: string): void {
    const q = this.waiters.get(endpoint);
    const next = q?.shift();
    if (q && q.length === 0) this.waiters.delete(endpoint);
    if (next) {
      next(); // slot transfers to the waiter; in-flight count unchanged
      return;
    }
    const n = (this.inFlight.get(endpoint) ?? 1) - 1;
    if (n <= 0) this.inFlight.delete(endpoint);
    else this.inFlight.set(endpoint, n);
  }

  /** Current in-flight delivery count for `endpoint`. */
  inFlightCount(endpoint: string): number {
    return this.inFlight.get(endpoint) ?? 0;
  }

  /** Deliveries currently queued waiting for a slot on `endpoint`. */
  queuedCount(endpoint: string): number {
    return this.waiters.get(endpoint)?.length ?? 0;
  }

  /** Snapshot of every endpoint with in-flight or queued deliveries. */
  stats(): Array<{ endpoint: string; inFlight: number; queued: number }> {
    const endpoints = new Set([...this.inFlight.keys(), ...this.waiters.keys()]);
    return [...endpoints].map((endpoint) => ({
      endpoint,
      inFlight: this.inFlightCount(endpoint),
      queued: this.queuedCount(endpoint),
    }));
  }
}

/**
 * RetryQueue holds outbound deliveries and retries them with exponential
 * backoff + jitter. Items that exhaust `maxAttempts` are moved to an
 * in-memory dead-letter list for later inspection.
 */
export class RetryQueue {
  private readonly sender: Sender;
  private readonly baseDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly maxAttempts: number;
  private readonly jitterMs: number;
  private readonly jitterStrategy: JitterStrategy;
  private readonly random: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => { clear(): void };
  private readonly clearTimer: (handle: { clear(): void }) => void;
  private readonly onDeadLetter?: (item: RetryItem, attempts: number, lastError: unknown) => void;
  private readonly onDelivered?: (item: RetryItem, attempts: number) => void;

  private readonly queue = new Map<string, RetryItem & { attempt: number }>();
  private readonly timers = new Map<string, Scheduled>();
  private readonly deadLetter: DeadLetterEntry[] = [];
  private readonly limiter: EndpointConcurrencyLimiter;
  /** Deliveries currently executing (inside `deliver()`), for graceful drain. */
  private readonly inFlight = new Set<Promise<void>>();
  private running = false;

  constructor(opts: RetryQueueOptions = {}) {
    this.sender = opts.sender ?? noopSender;
    this.baseDelayMs = opts.baseDelayMs ?? 1000;
    this.maxDelayMs = opts.maxDelayMs ?? 60000;
    this.maxAttempts = opts.maxAttempts ?? 5;
    this.jitterMs = opts.jitterMs ?? 100;
    this.jitterStrategy = opts.jitterStrategy ?? "additive";
    this.random = opts.random ?? Math.random;
    if (!Number.isFinite(this.baseDelayMs) || this.baseDelayMs <= 0) {
      throw new RangeError(`baseDelayMs must be > 0, got ${this.baseDelayMs}`);
    }
    if (!Number.isFinite(this.maxDelayMs) || this.maxDelayMs <= 0) {
      throw new RangeError(`maxDelayMs must be > 0, got ${this.maxDelayMs}`);
    }
    if (!Number.isInteger(this.maxAttempts) || this.maxAttempts < 1) {
      throw new RangeError(`maxAttempts must be an integer >= 1, got ${this.maxAttempts}`);
    }
    if (!Number.isFinite(this.jitterMs) || this.jitterMs < 0) {
      throw new RangeError(`jitterMs must be >= 0, got ${this.jitterMs}`);
    }
    if (this.jitterStrategy !== "additive" && this.jitterStrategy !== "full") {
      throw new RangeError(`jitterStrategy must be "additive" or "full", got ${this.jitterStrategy}`);
    }
    this.setTimer =
      opts.setTimer ?? ((fn, ms) => {
        const t = setTimeout(fn, ms);
        return { clear: () => clearTimeout(t) };
      });
    this.clearTimer = opts.clearTimer ?? ((h) => h.clear());
    this.onDeadLetter = opts.onDeadLetter;
    this.onDelivered = opts.onDelivered;
    this.limiter = new EndpointConcurrencyLimiter(opts.maxConcurrentPerEndpoint);
  }

  /** Number of items currently pending (queued or awaiting retry). */
  pendingCount(): number {
    return this.queue.size;
  }

  /** Items that exhausted all attempts, in dead-letter order. */
  getDeadLetter(): DeadLetterEntry[] {
    return [...this.deadLetter];
  }

  /**
   * Move a dead-lettered item back into the queue with a fresh attempt
   * budget (attempts reset to 0, scheduled immediately when running).
   * Returns false when no dead-letter entry matches `id`.
   */
  replayDeadLetter(id: string): boolean {
    const idx = this.deadLetter.findIndex((e) => e.id === id);
    if (idx < 0) return false;
    const [entry] = this.deadLetter.splice(idx, 1);
    const { attempts: _attempts, lastError: _lastError, deadLetteredAt: _ts, ...item } = entry;
    this.queue.set(item.id, { ...item, attempt: 0 });
    if (this.running) {
      this.schedule(item.id, 0);
    }
    return true;
  }

  /** Replay every dead-lettered item. Returns the number replayed. */
  replayAllDeadLetters(): number {
    const ids = this.deadLetter.map((e) => e.id);
    let replayed = 0;
    for (const id of ids) {
      if (this.replayDeadLetter(id)) replayed += 1;
    }
    return replayed;
  }

  enqueue(item: RetryItem): void {
    if (this.queue.has(item.id)) {
      throw new Error(`Duplicate item id: ${item.id}`);
    }
    this.queue.set(item.id, { ...item, attempt: 0 });
    if (this.running) {
      this.schedule(item.id, 0);
    }
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    for (const id of this.queue.keys()) {
      this.schedule(id, 0);
    }
  }

  stop(): void {
    this.running = false;
    for (const [id, s] of this.timers) {
      this.clearTimer(s.handle);
      this.timers.delete(id);
    }
  }

  /**
   * Graceful shutdown: stop scheduling new attempts, then wait for the
   * deliveries already in flight to settle. Items still waiting on a backoff
   * timer are dropped (they were never delivered); the caller is expected to
   * exit the process afterwards.
   *
   * @param timeoutMs maximum time to wait for in-flight deliveries.
   * @returns `true` when every in-flight delivery settled within the timeout,
   * `false` on timeout — in which case the caller should force-exit so a hung
   * downstream cannot pin the process forever.
   */
  async shutdown(timeoutMs = 30_000): Promise<boolean> {
    this.running = false;
    for (const [id, s] of this.timers) {
      this.clearTimer(s.handle);
      this.timers.delete(id);
    }
    if (this.inFlight.size === 0) return true;
    let timer: { clear(): void } | undefined;
    try {
      await Promise.race([
        Promise.allSettled([...this.inFlight]),
        new Promise<void>((resolve) => {
          timer = this.setTimer(resolve, timeoutMs);
        }),
      ]);
    } finally {
      if (timer) this.clearTimer(timer);
    }
    return this.inFlight.size === 0;
  }

  /** Number of deliveries currently executing (not just scheduled). */
  inFlightCount(): number {
    return this.inFlight.size;
  }

  /** Backoff for the *next* retry given the completed attempt index (0-based). */
  delayForAttempt(attempt: number): number {
    const cap = Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** attempt);
    if (this.jitterStrategy === "full") {
      return this.random() * cap;
    }
    const jitter = this.jitterMs > 0 ? this.random() * this.jitterMs : 0;
    return Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** attempt + jitter);
  }

  private schedule(id: string, delayMs: number): void {
    if (!this.running || !this.queue.has(id)) return;
    const existing = this.timers.get(id);
    if (existing) {
      this.clearTimer(existing.handle);
    }
    const handle = this.setTimer(() => {
      this.timers.delete(id);
      const p = this.deliver(id);
      // `deliver` never rejects (sender errors are caught internally), but
      // track both outcomes so a bug can never leak a hanging shutdown.
      this.inFlight.add(p);
      p.then(
        () => this.inFlight.delete(p),
        () => this.inFlight.delete(p)
      );
    }, delayMs);
    this.timers.set(id, { handle });
  }

  private async deliver(id: string): Promise<void> {
    const entry = this.queue.get(id);
    if (!entry || !this.running) return;
    const release = await this.limiter.acquire(entry.targetUrl);
    try {
      // The queue may have stopped, or the item may have been settled, while
      // we waited for a concurrency slot. Bail out; the release cascades to
      // the next waiter so nobody hangs.
      if (!this.running || !this.queue.has(id)) return;
      try {
        await this.sender(entry);
        this.queue.delete(id);
        this.onDelivered?.(entry, entry.attempt + 1);
      } catch (err) {
        entry.attempt += 1;
        if (entry.attempt >= this.maxAttempts) {
          this.queue.delete(id);
          this.deadLetter.push({
            id: entry.id,
            payload: entry.payload,
            targetUrl: entry.targetUrl,
            headers: entry.headers,
            attempts: entry.attempt,
            lastError: err instanceof Error ? err.message : String(err),
            deadLetteredAt: new Date().toISOString(),
          });
          this.onDeadLetter?.(entry, entry.attempt, err);
        } else {
          this.schedule(id, this.delayForAttempt(entry.attempt));
        }
      }
    } finally {
      release();
    }
  }

  /** Per-endpoint concurrency snapshot: in-flight and queued deliveries. */
  getConcurrencyStats(): Array<{ endpoint: string; inFlight: number; queued: number }> {
    return this.limiter.stats();
  }
}
