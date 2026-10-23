/**
 * Endpoint dependency graph (WR-199).
 *
 * An endpoint may declare that it *depends on* one or more other endpoints
 * (target URLs). While any (transitive) dependency's circuit breaker is not
 * closed, the dependent endpoint pauses dispatch: deliveries are parked and
 * re-checked, never dispatched, never burning a retry-budget token, never
 * consuming an attempt, and never reported to the dependent's own circuit
 * breaker. When every dependency's circuit is closed again the dependent
 * resumes automatically.
 *
 * Rationale: a fan-out topology where endpoint A enriches data from endpoint
 * B before calling C is only useful while B is reachable — sending to C
 * (and burning retries against it) while B is down just manufactures
 * downstream noise. The dependency gate pauses A at the source.
 *
 * Blocked condition: a dependency counts as unhealthy when its circuit
 * state is anything but `"closed"` — `"open"` (tripped by consecutive
 * failures or the WR-104 error-rate window) or `"half_open"` (a probe is in
 * flight but the endpoint has not proven healthy yet). A dependency with
 * no circuit data (no breaker configured, or never observed) counts as
 * healthy: there is no evidence it is down.
 *
 * Cycle detection is fail-fast at construction: `A dependsOn B` plus
 * `B dependsOn A` (directly or transitively, including self-dependency)
 * throws `RangeError`, because a cycle would deadlock every endpoint in
 * it — nobody could ever become healthy first.
 *
 * Orthogonal to WR-39 failover (primary/standby switching *within* one
 * logical endpoint) and WR-106 quorum (M-of-N fan-out *confirmation*):
 * those decide *where* a delivery for one endpoint goes and *when it
 * counts as done*; the dependency graph decides *whether* a delivery for
 * an endpoint may be dispatched at all, based on *other* endpoints'
 * health.
 *
 * Zero dependencies. No clock needed (health is read from the caller's
 * circuit breakers at dispatch time).
 */

/** Options for the endpoint dependency graph (see `RetryQueueOptions.endpointDependencies`). */
export interface EndpointDependencyOptions {
  /**
   * Endpoint target URL -> the target URL(s) it depends on. A single
   * string is sugar for a one-element list. Dependencies that are not
   * themselves keys are leaf nodes (they can never be blocked, and they
   * terminate transitive walks). An empty record disables the gate
   * entirely.
   */
  dependsOn: Record<string, string | string[]>;
}

/**
 * Validated endpoint dependency DAG. All validation (shapes, self-loops,
 * cycles) happens in the constructor so misconfiguration fails fast at
 * relay startup instead of silently never blocking.
 */
export class EndpointDependencyGraph {
  /** Endpoint -> deduplicated direct dependency list (insertion order). */
  private readonly direct = new Map<string, string[]>();

  constructor(dependsOn: Record<string, string | string[]>) {
    if (dependsOn === null || typeof dependsOn !== "object" || Array.isArray(dependsOn)) {
      throw new TypeError("endpointDependencies.dependsOn must be a record of targetUrl -> targetUrl | targetUrl[]");
    }
    for (const [endpoint, raw] of Object.entries(dependsOn)) {
      if (typeof endpoint !== "string" || endpoint.length === 0) {
        throw new RangeError("endpointDependencies.dependsOn keys must be non-empty target URLs");
      }
      const deps = EndpointDependencyGraph.normalizeDeps(endpoint, raw);
      this.direct.set(endpoint, deps);
    }
    this.assertAcyclic();
  }

  private static normalizeDeps(endpoint: string, raw: string | string[]): string[] {
    const list = typeof raw === "string" ? [raw] : raw;
    if (!Array.isArray(list)) {
      throw new TypeError(
        `endpointDependencies.dependsOn[${JSON.stringify(endpoint)}] must be a target URL or an array of target URLs`
      );
    }
    const seen = new Set<string>();
    const out: string[] = [];
    for (const dep of list) {
      if (typeof dep !== "string" || dep.length === 0) {
        throw new RangeError(
          `endpointDependencies.dependsOn[${JSON.stringify(endpoint)}] entries must be non-empty target URLs`
        );
      }
      if (dep === endpoint) {
        throw new RangeError(
          `endpointDependencies.dependsOn[${JSON.stringify(endpoint)}] must not depend on itself`
        );
      }
      if (!seen.has(dep)) {
        seen.add(dep);
        out.push(dep);
      }
    }
    return out;
  }

  /** Fail-fast cycle detection: DFS with a recursion stack, naming the cycle. */
  private assertAcyclic(): void {
    const color = new Map<string, "gray" | "black">();
    const stack: string[] = [];
    const visit = (node: string): void => {
      color.set(node, "gray");
      stack.push(node);
      for (const dep of this.direct.get(node) ?? []) {
        const c = color.get(dep);
        if (c === "gray") {
          const cycle = [...stack.slice(stack.indexOf(dep)), dep];
          throw new RangeError(
            `endpointDependencies.dependsOn has a dependency cycle: ${cycle.join(" -> ")}`
          );
        }
        if (c === undefined && this.direct.has(dep)) visit(dep);
      }
      stack.pop();
      color.set(node, "black");
    };
    for (const node of this.direct.keys()) {
      if (!color.has(node)) visit(node);
    }
  }

  /** Every endpoint that declares dependencies. */
  configuredEndpoints(): string[] {
    return [...this.direct.keys()];
  }

  /** Whether `endpoint` declares any dependencies. */
  hasDependencies(endpoint: string): boolean {
    return (this.direct.get(endpoint)?.length ?? 0) > 0;
  }

  /** Direct dependencies of `endpoint` (empty when none). */
  dependenciesOf(endpoint: string): string[] {
    return [...(this.direct.get(endpoint) ?? [])];
  }

  /**
   * All transitive dependencies of `endpoint`, deduplicated, in
   * first-seen (depth-first) order. The graph is acyclic by
   * construction, so this always terminates.
   */
  allDependencies(endpoint: string): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    const walk = (node: string): void => {
      for (const dep of this.direct.get(node) ?? []) {
        if (!seen.has(dep)) {
          seen.add(dep);
          out.push(dep);
          walk(dep);
        }
      }
    };
    walk(endpoint);
    return out;
  }
}
