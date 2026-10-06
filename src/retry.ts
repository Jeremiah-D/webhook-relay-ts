export interface RetryItem {
  id: string;
  payload: Buffer;
  targetUrl: string;
  headers: Record<string, string | string[] | undefined>;
}

export type Sender = (item: RetryItem) => Promise<void>;

export interface RetryQueueOptions {
  /** Sender function; defaults to a no-op success sender. Injectable for tests. */
  sender?: Sender;
  /** Base delay in ms for the exponential backoff. Default: 1000. */
  baseDelayMs?: number;
  /** Maximum delay in ms between attempts. Default: 60000. */
  maxDelayMs?: number;
  /** Total attempts per item (initial try + retries). Default: 5. */
  maxAttempts?: number;
  /** Jitter added to each delay in ms (uniform 0..jitterMs). Default: 100. */
  jitterMs?: number;
  /**
   * Scheduler factory; defaults to the real setTimeout. Injectable so tests
   * can run deterministically. Returns a handle with an `unref`-style
   * `clear()` method. Also accepts a clearTimer to cancel pending timeouts.
   */
  setTimer?: (fn: () => void, ms: number) => { clear(): void };
  clearTimer?: (handle: { clear(): void }) => void;
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
  private readonly setTimer: (fn: () => void, ms: number) => { clear(): void };
  private readonly clearTimer: (handle: { clear(): void }) => void;
  private readonly onDeadLetter?: (item: RetryItem, attempts: number, lastError: unknown) => void;
  private readonly onDelivered?: (item: RetryItem, attempts: number) => void;

  private readonly queue = new Map<string, RetryItem & { attempt: number }>();
  private readonly timers = new Map<string, Scheduled>();
  private readonly deadLetter: RetryItem[] = [];
  private running = false;

  constructor(opts: RetryQueueOptions = {}) {
    this.sender = opts.sender ?? noopSender;
    this.baseDelayMs = opts.baseDelayMs ?? 1000;
    this.maxDelayMs = opts.maxDelayMs ?? 60000;
    this.maxAttempts = opts.maxAttempts ?? 5;
    this.jitterMs = opts.jitterMs ?? 100;
    this.setTimer =
      opts.setTimer ?? ((fn, ms) => {
        const t = setTimeout(fn, ms);
        return { clear: () => clearTimeout(t) };
      });
    this.clearTimer = opts.clearTimer ?? ((h) => h.clear());
    this.onDeadLetter = opts.onDeadLetter;
    this.onDelivered = opts.onDelivered;
  }

  /** Number of items currently pending (queued or awaiting retry). */
  pendingCount(): number {
    return this.queue.size;
  }

  /** Items that exhausted all attempts, in dead-letter order. */
  getDeadLetter(): RetryItem[] {
    return [...this.deadLetter];
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

  /** Backoff for the *next* retry given the completed attempt index (0-based). */
  delayForAttempt(attempt: number): number {
    const jitter = this.jitterMs > 0 ? Math.random() * this.jitterMs : 0;
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
      void this.deliver(id);
    }, delayMs);
    this.timers.set(id, { handle });
  }

  private async deliver(id: string): Promise<void> {
    const entry = this.queue.get(id);
    if (!entry || !this.running) return;
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
        });
        this.onDeadLetter?.(entry, entry.attempt, err);
      } else {
        this.schedule(id, this.delayForAttempt(entry.attempt));
      }
    }
  }
}
