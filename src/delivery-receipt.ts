import { mkdirSync, appendFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

/**
 * WR-155: structured delivery receipts — the business-semantic delivery
 * record. Metrics (`src/metrics.ts`) and the audit log answer "how is the
 * relay doing"; a receipt answers "what happened to *this* delivery":
 * which endpoint, on which attempt, how long it took, the last status
 * code, and the terminal outcome. The two layers are complementary, and
 * the receipt channel is strictly opt-in: disabled by default, zero
 * overhead when off.
 */

/** Terminal delivery outcomes a receipt can carry. */
export type DeliveryReceiptOutcome = "delivered" | "dead_letter";

/**
 * One delivery's terminal receipt. `attempt` is 1-based (the attempt that
 * settled it); `latencyMs` runs from queue admission to terminal;
 * `statusCode` is the last attempt's HTTP status, present only when the
 * sender actually saw a response. `traceId` / `tenant` ride along for
 * correlation with audit events and OTLP records.
 */
export interface DeliveryReceipt {
  deliveryId: string;
  endpoint: string;
  attempt: number;
  latencyMs: number;
  statusCode?: number;
  outcome: DeliveryReceiptOutcome;
  /** Terminal timestamp, on the receipt clock (`DeliveryReceiptOptions.now`). */
  at: number;
  traceId?: string;
  tenant?: string;
}

/**
 * Opt-in callbacks fired per terminal delivery. A callback that throws
 * never breaks the delivery path — the store records first and isolates
 * callback failures.
 */
export interface DeliveryReceiptCallbacks {
  onDelivered?: (receipt: DeliveryReceipt) => void;
  onFailed?: (receipt: DeliveryReceipt) => void;
}

export interface DeliveryReceiptOptions extends DeliveryReceiptCallbacks {
  /**
   * How many receipts the in-memory ring keeps; older ones are evicted.
   * Default 1000. Must be a positive integer.
   */
  maxEntries?: number;
  /**
   * Optional persistence: receipts are appended as JSONL to
   * `<journalDir>/delivery-receipts.jsonl`, and the ring is recovered
   * from the file's tail on construction. The directory is created when
   * missing; all journal I/O is best-effort and never throws.
   */
  journalDir?: string;
  /** Receipt clock (for `at` and the `latencyMs` fallback). Defaults to `Date.now`. */
  now?: () => number;
}

/** Query filters for `DeliveryReceiptStore.query`. */
export interface DeliveryReceiptFilter {
  endpoint?: string;
  outcome?: DeliveryReceiptOutcome;
  /** Inclusive lower bound on `at`. */
  since?: number;
  /** Inclusive upper bound on `at`. */
  until?: number;
  /** Maximum receipts returned (newest first). */
  limit?: number;
}

const JOURNAL_FILE = "delivery-receipts.jsonl";

/** Bounded in-memory receipt log with an optional append-only JSONL journal. */
export class DeliveryReceiptStore {
  private readonly maxEntries: number;
  private readonly journalPath: string | undefined;
  private readonly now: () => number;
  private readonly ring: DeliveryReceipt[] = [];
  private dropped = 0;

  constructor(opts?: DeliveryReceiptOptions) {
    const maxEntries = opts?.maxEntries ?? 1000;
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
      throw new RangeError(`deliveryReceipts.maxEntries must be a positive integer, got ${maxEntries}`);
    }
    this.maxEntries = maxEntries;
    this.now = opts?.now ?? Date.now;
    const journalDir = opts?.journalDir;
    if (journalDir !== undefined) {
      if (typeof journalDir !== "string" || journalDir.length === 0) {
        throw new RangeError("deliveryReceipts.journalDir must be a non-empty string");
      }
      try {
        mkdirSync(journalDir, { recursive: true });
      } catch {
        // Best-effort: without a writable directory the journal stays off,
        // the in-memory ring still works.
      }
      this.journalPath = join(journalDir, JOURNAL_FILE);
      this.recover();
    }
  }

  /** Stamp `at`, append to the ring (evicting the oldest past capacity),
   * and append to the journal when configured. Returns the stored receipt. */
  record(input: Omit<DeliveryReceipt, "at">): DeliveryReceipt {
    const receipt: DeliveryReceipt = { ...input, at: this.now() };
    this.ring.push(receipt);
    if (this.ring.length > this.maxEntries) {
      this.ring.splice(0, this.ring.length - this.maxEntries);
      this.dropped += 1;
    }
    if (this.journalPath !== undefined) {
      try {
        appendFileSync(this.journalPath, JSON.stringify(receipt) + "\n");
      } catch {
        // A failed journal write must never break the delivery path.
      }
    }
    return receipt;
  }

  /** Newest-first query over the in-memory ring. */
  query(filter?: DeliveryReceiptFilter): DeliveryReceipt[] {
    const out: DeliveryReceipt[] = [];
    for (let i = this.ring.length - 1; i >= 0; i--) {
      const r = this.ring[i];
      if (filter?.endpoint !== undefined && r.endpoint !== filter.endpoint) continue;
      if (filter?.outcome !== undefined && r.outcome !== filter.outcome) continue;
      if (filter?.since !== undefined && r.at < filter.since) continue;
      if (filter?.until !== undefined && r.at > filter.until) continue;
      out.push({ ...r });
      if (filter?.limit !== undefined && out.length >= filter.limit) break;
    }
    return out;
  }

  /** Export the ring as JSONL (newest last, matching the journal order). */
  exportJsonl(): string {
    return this.ring.map((r) => JSON.stringify(r)).join("\n") + (this.ring.length > 0 ? "\n" : "");
  }

  stats(): { stored: number; dropped: number; journalEnabled: boolean } {
    return { stored: this.ring.length, dropped: this.dropped, journalEnabled: this.journalPath !== undefined };
  }

  /** Load the journal's tail into the ring; malformed lines are skipped. */
  private recover(): void {
    if (this.journalPath === undefined || !existsSync(this.journalPath)) return;
    try {
      const lines = readFileSync(this.journalPath, "utf8")
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const tail = lines.slice(-this.maxEntries);
      for (const line of tail) {
        try {
          const parsed = JSON.parse(line) as DeliveryReceipt;
          if (
            typeof parsed.deliveryId === "string" &&
            typeof parsed.endpoint === "string" &&
            (parsed.outcome === "delivered" || parsed.outcome === "dead_letter")
          ) {
            this.ring.push(parsed);
          }
        } catch {
          // Skip corrupt lines; the journal stays append-only.
        }
      }
    } catch {
      // A failed recovery starts with an empty ring, never a crash.
    }
  }
}
