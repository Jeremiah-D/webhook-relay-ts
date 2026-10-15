/**
 * WR-107: relay mesh forwarding.
 *
 * A mesh is two or more relays chained so an event can hop from relay A
 * to relay B before reaching the final downstream. The forwarding itself
 * needs no new transport: relay A simply targets relay B's inbound
 * endpoint, and the *mutual trust* between the hops rides the existing
 * mechanisms —
 *
 * - relay A signs the outbound delivery with `x-relay-signature`
 *   (WR-26 outbound signing);
 * - relay B verifies it with a registered verifier holding relay A's key
 *   (WR-01 verifier registry, WR-20 rotation, WR-29 per-endpoint rules).
 *
 * What this module adds is the mesh *protocol* on top of that trust:
 *
 * - the `x-relay-hops` header counts how many relays the event has
 *   traversed (0 = arrived directly from a producer);
 * - inbound parsing + a `maxHops` loop guard: an event that already
 *   traversed `maxHops` relays is rejected 400 (`mesh_hop_limit_exceeded`)
 *   instead of looping forever through a misconfigured cycle
 *   (A → B → A → …);
 * - the hop count rides the `RetryItem` (`meshHops`) through enqueue,
 *   retries, dead-letter + replay, and the durable-queue journal, and is
 *   stamped back out as `x-relay-hops: meshHops + 1` on every outbound
 *   wire request;
 * - `traceId` needs no mesh-specific handling: the relay already forces
 *   `x-trace-id` downstream (WR-18), so one trace threads the whole mesh;
 * - the hop count lands on the `accepted` / `delivered` / `dead_letter`
 *   audit events and on two Prometheus counters
 *   (`relay_mesh_forwarded_total`, `relay_mesh_hop_limit_rejections_total`).
 *
 * Trust model (read this before wiring a mesh): `x-relay-hops` is a
 * *cooperative* loop guard, not a security boundary — `x-relay-signature`
 * covers the body, not the header, so a man in the middle could bump the
 * count. Run mesh links over TLS and verify the peer's signature with a
 * registered key; treat the hop count as operator telemetry. A malformed
 * header is fail-closed (400 `mesh_hops_invalid`), and when mesh is
 * disabled (the default) the header is stripped at intake and never
 * stamped — zero behavior change for non-mesh relays.
 */

export const RELAY_HOPS_HEADER = "x-relay-hops";

/** Default hop budget when `maxHops` is not configured. */
export const DEFAULT_MAX_MESH_HOPS = 8;

/** Server option: `mesh?: MeshOptions`. Absent = mesh disabled. */
export interface MeshOptions {
  /**
   * Maximum relay hops an event may traverse. An inbound event whose
   * `x-relay-hops` is already at this count is rejected 400. Must be an
   * integer >= 1. Default: 8.
   */
  maxHops?: number;
}

export interface ResolvedMeshConfig {
  maxHops: number;
}

/**
 * Validate the `mesh` server option. Returns `undefined` when mesh is
 * disabled (option absent) so call sites can branch on a single check.
 * Throws `RangeError` on invalid configuration (fail-fast, the repo's
 * convention for contradictory/illegal options).
 */
export function assertValidMeshOptions(opts?: MeshOptions): ResolvedMeshConfig | undefined {
  if (opts === undefined) return undefined;
  const maxHops = opts.maxHops ?? DEFAULT_MAX_MESH_HOPS;
  if (!Number.isInteger(maxHops) || maxHops < 1) {
    throw new RangeError(`mesh.maxHops must be an integer >= 1, got ${opts.maxHops}`);
  }
  return { maxHops };
}

/**
 * Parse the inbound `x-relay-hops` header. Absent = 0: the event arrived
 * directly from a producer and no relay has forwarded it yet. Throws
 * `RangeError` on malformed values (fail-closed — a forged hop count
 * never enters the mesh accounting).
 */
export function parseRelayHops(raw: string | string[] | undefined): number {
  if (raw === undefined) return 0;
  const first = Array.isArray(raw) ? raw[0] : raw;
  if (typeof first !== "string" || !/^\d+$/.test(first)) {
    throw new RangeError(`invalid ${RELAY_HOPS_HEADER}: ${String(first)}`);
  }
  const n = Number(first);
  if (!Number.isSafeInteger(n)) {
    throw new RangeError(`invalid ${RELAY_HOPS_HEADER}: ${String(first)}`);
  }
  return n;
}

/** The hop count stamped on the outbound wire request for this item. */
export function nextRelayHops(hops: number): number {
  return hops + 1;
}

function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

/**
 * Activity-gated mesh counters. Rendered into the Prometheus exposition
 * by the server's `/metrics` handler; renders `""` while no mesh traffic
 * has been seen, so an untouched relay's exposition is byte-identical.
 */
export class MeshMetrics {
  private readonly forwarded = new Map<string, number>();
  private readonly hopLimitRejections = new Map<string, number>();

  /** One outbound delivery stamped with an incremented `x-relay-hops`. */
  recordForwarded(endpoint: string): void {
    this.forwarded.set(endpoint, (this.forwarded.get(endpoint) ?? 0) + 1);
  }

  /** One inbound event rejected for exceeding `maxHops`. */
  recordHopLimitRejected(endpoint: string): void {
    this.hopLimitRejections.set(endpoint, (this.hopLimitRejections.get(endpoint) ?? 0) + 1);
  }

  render(): string {
    const lines: string[] = [];
    if (this.forwarded.size > 0) {
      lines.push(
        "# HELP relay_mesh_forwarded_total Deliveries forwarded toward the next mesh hop (x-relay-hops stamped)."
      );
      lines.push("# TYPE relay_mesh_forwarded_total counter");
      for (const [endpoint, n] of this.forwarded) {
        lines.push(`relay_mesh_forwarded_total{endpoint="${escapeLabelValue(endpoint)}"} ${n}`);
      }
    }
    if (this.hopLimitRejections.size > 0) {
      lines.push(
        "# HELP relay_mesh_hop_limit_rejections_total Inbound events rejected for exceeding the mesh maxHops loop guard."
      );
      lines.push("# TYPE relay_mesh_hop_limit_rejections_total counter");
      for (const [endpoint, n] of this.hopLimitRejections) {
        lines.push(
          `relay_mesh_hop_limit_rejections_total{endpoint="${escapeLabelValue(endpoint)}"} ${n}`
        );
      }
    }
    return lines.length === 0 ? "" : lines.join("\n") + "\n";
  }
}
