import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";

function tmpLog(): { audit: AuditLog; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "audit-query-"));
  const path = join(dir, "audit.jsonl");
  return { audit: new AuditLog(path), path };
}

function line(obj: object): string {
  return JSON.stringify(obj) + "\n";
}

describe("audit query", () => {
  it("filters by endpoint and event", () => {
    const { audit } = tmpLog();
    audit.append({ event: "accepted", id: "a1", targetUrl: "http://x/hook" });
    audit.append({ event: "accepted", id: "a2", targetUrl: "http://y/hook" });
    audit.append({ event: "delivered", id: "a1", targetUrl: "http://x/hook" });
    audit.append({ event: "rejected", id: "a3", reason: "invalid_signature" });

    const byEndpoint = audit.query({ endpoint: "http://x/hook" });
    assert.equal(byEndpoint.length, 2);
    assert.deepEqual(
      byEndpoint.map((e) => (e as { id: string }).id),
      ["a1", "a1"]
    );

    const delivered = audit.query({ event: "delivered" });
    assert.equal(delivered.length, 1);
    assert.equal((delivered[0] as { id: string }).id, "a1");

    const both = audit.query({ event: ["accepted", "delivered"], endpoint: "http://y/hook" });
    assert.equal(both.length, 1);
    assert.equal((both[0] as { id: string }).id, "a2");
  });

  it("filters by time range inclusively", () => {
    const { audit, path } = tmpLog();
    writeFileSync(
      path,
      line({ ts: "2026-10-01T00:00:00.000Z", event: "accepted", id: "old" }) +
        line({ ts: "2026-10-05T12:00:00.000Z", event: "accepted", id: "mid" }) +
        line({ ts: "2026-10-07T00:00:00.000Z", event: "accepted", id: "new" })
    );

    const mid = audit.query({ since: "2026-10-05T12:00:00.000Z", until: "2026-10-05T12:00:00.000Z" });
    assert.equal(mid.length, 1);
    assert.equal((mid[0] as { id: string }).id, "mid");

    const range = audit.query({ since: "2026-10-02T00:00:00.000Z", until: "2026-10-06T00:00:00.000Z" });
    assert.equal(range.length, 1);
    assert.equal((range[0] as { id: string }).id, "mid");
  });

  it("skips malformed lines without breaking the index", () => {
    const { audit, path } = tmpLog();
    writeFileSync(
      path,
      line({ ts: "2026-10-05T00:00:00.000Z", event: "accepted", id: "ok1", targetUrl: "http://x/hook" }) +
        "this is not json\n" +
        "{truncated\n" +
        line({ ts: "2026-10-05T01:00:00.000Z", event: "accepted", id: "ok2", targetUrl: "http://x/hook" })
    );

    const all = audit.query({});
    assert.equal(all.length, 2);
    const byEndpoint = audit.query({ endpoint: "http://x/hook" });
    assert.equal(byEndpoint.length, 2);
  });

  it("returns [] for a missing file and picks up later appends", () => {
    const { audit } = tmpLog();
    assert.deepEqual(audit.query({}), []);
    audit.append({ event: "accepted", id: "a1", targetUrl: "http://x/hook" });
    assert.equal(audit.query({}).length, 1);
    audit.append({ event: "accepted", id: "a2", targetUrl: "http://x/hook" });
    // Second query must see the tail the index had not scanned yet.
    assert.equal(audit.query({ endpoint: "http://x/hook" }).length, 2);
  });

  it("limit keeps the most recent matches in chronological order", () => {
    const { audit } = tmpLog();
    for (let i = 0; i < 5; i++) {
      audit.append({ event: "accepted", id: `e${i}`, targetUrl: "http://x/hook" });
    }
    const tail = audit.query({ limit: 2 });
    assert.deepEqual(
      tail.map((e) => (e as { id: string }).id),
      ["e3", "e4"]
    );
  });

  it("rebuilds the index after the file is truncated", () => {
    const { audit, path } = tmpLog();
    audit.append({ event: "accepted", id: "before", targetUrl: "http://x/hook" });
    assert.equal(audit.query({}).length, 1);

    writeFileSync(
      path,
      line({ ts: "2026-10-05T00:00:00.000Z", event: "accepted", id: "after", targetUrl: "http://y/hook" })
    );
    const entries = audit.query({});
    assert.equal(entries.length, 1);
    assert.equal((entries[0] as { id: string }).id, "after");
  });

  it("throws on invalid query parameters", () => {
    const { audit } = tmpLog();
    assert.throws(() => audit.query({ since: "not-a-date" }), /since\/until/);
    assert.throws(() => audit.query({ until: "2026-13-99" }), /since\/until/);
    assert.throws(() => audit.query({ limit: 0 }), /limit/);
    assert.throws(() => audit.query({ limit: 1.5 }), /limit/);
  });
});
