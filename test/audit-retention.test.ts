import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, type AuditRetentionOptions } from "../src/audit.ts";

const DAY_MS = 86400_000;
// Fixed "now" so retention boundaries are deterministic, not wall-clock.
const NOW = Date.parse("2026-10-24T00:00:00.000Z");

function tmpLog(opts?: { auditRetention?: AuditRetentionOptions }): { audit: AuditLog; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "audit-retention-"));
  const path = join(dir, "audit.jsonl");
  return { audit: new AuditLog(path, opts ?? {}), path };
}

function line(obj: object): string {
  return JSON.stringify(obj) + "\n";
}

function daysAgo(days: number): string {
  return new Date(NOW - days * DAY_MS).toISOString();
}

function acceptedIds(audit: AuditLog): string[] {
  return audit.query({ event: "accepted" }).map((e) => (e as { id: string }).id);
}

describe("audit retention (WR-209)", () => {
  it("prunes entries older than the global default, including the exact boundary", () => {
    const { audit, path } = tmpLog({ auditRetention: { defaultDays: 30 } });
    writeFileSync(
      path,
      line({ ts: daysAgo(40), event: "accepted", id: "old-plain" }) +
        line({ ts: daysAgo(40), event: "accepted", id: "old-tenant", tenant: "acme" }) +
        line({ ts: daysAgo(30), event: "accepted", id: "at-boundary" }) +
        line({ ts: daysAgo(1), event: "accepted", id: "recent" })
    );

    const result = audit.pruneExpiredAuditEntries(NOW);
    assert.deepEqual(result, { pruned: 3, prunedByTenant: { acme: 1 }, prunedWithoutTenant: 2 });
    assert.deepEqual(acceptedIds(audit), ["recent"]);
  });

  it("per-tenant override wins over the global default in both directions", () => {
    const { audit, path } = tmpLog({
      auditRetention: { defaultDays: 30, tenants: { short: 7, long: 90 } },
    });
    writeFileSync(
      path,
      line({ ts: daysAgo(10), event: "accepted", id: "short-old", tenant: "short" }) +
        line({ ts: daysAgo(10), event: "accepted", id: "long-young", tenant: "long" }) +
        line({ ts: daysAgo(10), event: "accepted", id: "plain-young" }) +
        line({ ts: daysAgo(40), event: "accepted", id: "long-old", tenant: "long" }) +
        line({ ts: daysAgo(40), event: "accepted", id: "plain-old" })
    );

    const result = audit.pruneExpiredAuditEntries(NOW);
    assert.deepEqual(result, { pruned: 2, prunedByTenant: { short: 1 }, prunedWithoutTenant: 1 });
    assert.deepEqual(acceptedIds(audit), ["long-young", "plain-young", "long-old"]);
  });

  it("keeps unexpired entries, unparseable timestamps, and malformed lines, and stays silent when nothing expires", () => {
    const { audit, path } = tmpLog({ auditRetention: { defaultDays: 30 } });
    const before =
      line({ ts: daysAgo(1), event: "accepted", id: "recent" }) +
      line({ ts: "not-a-date", event: "accepted", id: "no-ts" }) +
      line({ event: "accepted", id: "missing-ts" }) +
      "this is not json\n";
    writeFileSync(path, before);

    const result = audit.pruneExpiredAuditEntries(NOW);
    assert.deepEqual(result, { pruned: 0, prunedByTenant: {}, prunedWithoutTenant: 0 });
    assert.equal(readFileSync(path, "utf8"), before);
    assert.deepEqual(audit.query({ event: "audit_pruned" }), []);
  });

  it("pruning emits an audit_pruned event with counts only, no entry content", () => {
    const { audit, path } = tmpLog({ auditRetention: { defaultDays: 30 } });
    writeFileSync(
      path,
      line({ ts: daysAgo(40), event: "accepted", id: "gone-tenant", tenant: "acme", payload: "secret-stuff" }) +
        line({ ts: daysAgo(40), event: "accepted", id: "gone-plain" })
    );

    const result = audit.pruneExpiredAuditEntries(NOW);
    assert.equal(result.pruned, 2);
    const events = audit.query({ event: "audit_pruned" });
    assert.equal(events.length, 1);
    const event = events[0] as Record<string, unknown>;
    assert.equal(event.pruned, 2);
    assert.deepEqual(event.prunedByTenant, { acme: 1 });
    assert.equal(event.prunedWithoutTenant, 1);
    assert.equal("payload" in event, false);
    assert.equal(JSON.stringify(event).includes("secret-stuff"), false);
    assert.equal(JSON.stringify(event).includes("gone-tenant"), false);
    assert.equal(JSON.stringify(event).includes("gone-plain"), false);
  });

  it("disabled by default: pruning is a no-op that touches neither file nor event stream", () => {
    const { audit, path } = tmpLog();
    const before = line({ ts: daysAgo(400), event: "accepted", id: "ancient" });
    writeFileSync(path, before);

    assert.deepEqual(audit.pruneExpiredAuditEntries(NOW), {
      pruned: 0,
      prunedByTenant: {},
      prunedWithoutTenant: 0,
    });
    assert.equal(readFileSync(path, "utf8"), before);
    assert.deepEqual(audit.query({ event: "audit_pruned" }), []);
  });

  it("rejects invalid retention config at construction (fail-closed)", () => {
    const bad: AuditRetentionOptions[] = [
      { defaultDays: 0 },
      { defaultDays: -5 },
      { defaultDays: Number.NaN },
      { defaultDays: Number.POSITIVE_INFINITY },
      { defaultDays: "30" as unknown as number },
      { tenants: { acme: 0 } },
      { tenants: { acme: Number.NaN } },
      { tenants: { "": 30 } },
      { tenants: "acme" as unknown as Record<string, number> },
    ];
    for (const auditRetention of bad) {
      assert.throws(() => tmpLog({ auditRetention }), RangeError, JSON.stringify(auditRetention));
    }
    assert.throws(
      () => tmpLog({ auditRetention: null as unknown as AuditRetentionOptions }),
      RangeError
    );
    // Valid shapes construct fine.
    tmpLog({ auditRetention: { defaultDays: 30 } });
    tmpLog({ auditRetention: { tenants: { acme: 7 } } });
    tmpLog({ auditRetention: {} });
  });

  it("keeps both chains verifiable across a prune and for later appends", () => {
    const { audit, path } = tmpLog({ auditRetention: { defaultDays: 30 } });
    writeFileSync(
      path,
      line({ ts: daysAgo(40), event: "accepted", id: "gone" }) +
        line({ ts: daysAgo(1), event: "accepted", id: "survivor", tenant: "acme" })
    );

    audit.pruneExpiredAuditEntries(NOW);
    assert.equal(audit.verifyChain().ok, true);
    assert.equal(audit.verifyHmacChain().ok, true);
    assert.deepEqual(acceptedIds(audit), ["survivor"]);

    audit.append({ event: "accepted", id: "after" });
    assert.equal(audit.verifyChain().ok, true);
    assert.equal(audit.verifyHmacChain().ok, true);
    assert.deepEqual(acceptedIds(audit), ["survivor", "after"]);
  });
});
