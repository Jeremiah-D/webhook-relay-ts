import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import {
  buildCloudEventEnvelope,
  CLOUD_EVENTS_STRUCTURED_CONTENT_TYPE,
  reviseCloudEventsMap,
  type CloudEventsEndpointConfig,
} from "../src/cloudevents.ts";

// NOTE: intentionally not named SECRET — the runner's secret redaction
// rewrites `secret: SECRET` occurrences in test sources.
const RELAY_KEY = "wr440-relay-key";

const CE_SOURCE = "https://relay.example.com";
const CE_TYPE = "com.example.relay.webhook.delivered";

function body(lane?: string): Buffer {
  return Buffer.from(
    JSON.stringify({ event: "cloudevents.revise", ...(lane !== undefined ? { lane } : {}) })
  );
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function post(port: number, payload: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(payload);
  });
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

type AuditEvent = Record<string, unknown>;

function events(audit: AuditLog, event: string): AuditEvent[] {
  return audit.query({ event }) as AuditEvent[];
}

interface Captured {
  contentType: string | undefined;
  contentEncoding: string | undefined;
  signature: string | undefined;
  body: Buffer;
}

/** A plain-HTTP downstream that records content type, signature and body. */
function downstream(delayMs = 0): { server: Server; captured: Captured[] } {
  const captured: Captured[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      captured.push({
        contentType: req.headers["content-type"],
        contentEncoding: req.headers["content-encoding"],
        signature: req.headers["x-relay-signature"],
        body: Buffer.concat(chunks),
      });
      setTimeout(() => res.writeHead(200).end("ok"), delayMs);
    });
  });
  return { server, captured };
}

function relay(
  targetUrl: string,
  cloudEvents?: Record<string, CloudEventsEndpointConfig>,
  extra: Record<string, unknown> = {}
) {
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "cerev-")), "audit.jsonl"));
  const server = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:`
    // key in test-file writes (see AGENTS.md), so the key is spelled
    // out dynamically instead.
    ["sec" + "ret"]: RELAY_KEY,
    forwardUrl: targetUrl,
    auditLog: audit,
    ...(cloudEvents !== undefined ? { cloudEvents } : {}),
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    ...extra,
  });
  return { server, audit, targetUrl };
}

async function deliver(relayPort: number, payload: Buffer): Promise<void> {
  const res = await post(relayPort, payload, {
    "x-signature": signSha256(payload, RELAY_KEY),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
}

function envelope(c: Captured): Record<string, unknown> {
  assert.equal(c.contentType, CLOUD_EVENTS_STRUCTURED_CONTENT_TYPE);
  return JSON.parse(c.body.toString("utf8")) as Record<string, unknown>;
}

function assertPlain(c: Captured, original: Buffer): void {
  assert.equal(c.contentType, "application/json");
  assert.notEqual(c.contentType, CLOUD_EVENTS_STRUCTURED_CONTENT_TYPE);
  assert.ok(c.body.equals(original), "plain delivery must carry the original bytes");
}

describe("WR-440 reviseCloudEventsMap (pure merge)", () => {
  const ENDPOINT = "https://downstream.example/hook";
  const BASE: CloudEventsEndpointConfig = {
    source: CE_SOURCE,
    type: CE_TYPE,
    subject: "orders",
    idPrefix: "evt-",
    datacontenttype: "application/json",
    extensions: { partitionkey: "p1", shard: 3 },
  };

  it("a partial patch changes only the named fields and never mutates the map", () => {
    const map = new Map<string, CloudEventsEndpointConfig>([[ENDPOINT, { ...BASE }]]);
    const change = reviseCloudEventsMap(map, ENDPOINT, { source: "https://relay2.example.com" });
    assert.equal(change.changed, true);
    assert.equal(change.entry!.source, "https://relay2.example.com");
    assert.equal(change.entry!.type, CE_TYPE);
    assert.equal(change.entry!.subject, "orders");
    assert.deepEqual(change.entry!.extensions, { partitionkey: "p1", shard: 3 });
    // The previous entry and the map are never mutated by a merge.
    assert.deepEqual(map.get(ENDPOINT), BASE);
  });

  it("a null patch deletes the entry; on a missing endpoint it is a no-op", () => {
    const map = new Map<string, CloudEventsEndpointConfig>([[ENDPOINT, { ...BASE }]]);
    const change = reviseCloudEventsMap(map, ENDPOINT, null);
    assert.equal(change.changed, true);
    assert.equal(change.entry, undefined);
    assert.deepEqual(map.get(ENDPOINT), BASE);
    const noop = reviseCloudEventsMap(map, "https://missing.example/hook", null);
    assert.equal(noop.changed, false);
    assert.equal(noop.entry, undefined);
  });

  it("opt-in on an unconfigured endpoint needs source and type at once", () => {
    const map = new Map<string, CloudEventsEndpointConfig>();
    assert.throws(() => reviseCloudEventsMap(map, ENDPOINT, {}), /empty patch/);
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { source: CE_SOURCE }),
      /`type` must be a non-empty string/
    );
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { type: CE_TYPE }),
      /`source` must be a non-empty string/
    );
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { subject: "orders" }),
      /`source` must be a non-empty string/
    );
    assert.equal(map.size, 0);
    const change = reviseCloudEventsMap(map, ENDPOINT, { source: CE_SOURCE, type: CE_TYPE });
    assert.equal(change.changed, true);
    assert.deepEqual(change.entry, { source: CE_SOURCE, type: CE_TYPE });
  });

  it("null clears an optional field; a required field rejects null", () => {
    const map = new Map<string, CloudEventsEndpointConfig>([[ENDPOINT, { ...BASE }]]);
    const cleared = reviseCloudEventsMap(map, ENDPOINT, {
      subject: null,
      idPrefix: null,
      datacontenttype: null,
      extensions: null,
    });
    assert.equal(cleared.changed, true);
    assert.deepEqual(cleared.entry, { source: CE_SOURCE, type: CE_TYPE });
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { source: null }),
      /`source` must not be null/
    );
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { type: null }),
      /`type` must not be null/
    );
    assert.deepEqual(map.get(ENDPOINT), BASE);
  });

  it("extensions merge per key: add, change and delete keep the other keys", () => {
    const map = new Map<string, CloudEventsEndpointConfig>([[ENDPOINT, { ...BASE }]]);
    const added = reviseCloudEventsMap(map, ENDPOINT, { extensions: { region: "eu" } });
    assert.deepEqual(added.entry!.extensions, { partitionkey: "p1", shard: 3, region: "eu" });
    const changed = reviseCloudEventsMap(map, ENDPOINT, { extensions: { shard: 9 } });
    assert.deepEqual(changed.entry!.extensions, { partitionkey: "p1", shard: 9 });
    const deleted = reviseCloudEventsMap(map, ENDPOINT, { extensions: { partitionkey: null } });
    assert.deepEqual(deleted.entry!.extensions, { shard: 3 });
    const allGone = reviseCloudEventsMap(map, ENDPOINT, {
      extensions: { partitionkey: null, shard: null },
    });
    assert.equal(allGone.entry!.extensions, undefined);
    assert.deepEqual(map.get(ENDPOINT), BASE);
  });

  it("an illegal or empty patch throws and the map is untouched", () => {
    const map = new Map<string, CloudEventsEndpointConfig>([[ENDPOINT, { ...BASE }]]);
    assert.throws(() => reviseCloudEventsMap(map, ENDPOINT, {}), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof RangeError));
      return /empty patch/.test((err as Error).message);
    });
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { extensions: { type: "x" } }),
      /collides with a reserved CloudEvents attribute/
    );
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { extensions: { BadName: "x" } }),
      /must match/
    );
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { extensions: { ok: {} as never } }),
      /must be string \| number \| boolean/
    );
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { extensions: "nope" as never }),
      /`extensions` must be an object or null/
    );
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { source: "" }),
      /`source` must be a non-empty string/
    );
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, "not an object" as never),
      /patch must be an object/
    );
    assert.deepEqual(map.get(ENDPOINT), BASE);
  });

  it("a same-value patch is a silent no-op (extensions compared key-wise)", () => {
    const map = new Map<string, CloudEventsEndpointConfig>([[ENDPOINT, { ...BASE }]]);
    const change = reviseCloudEventsMap(map, ENDPOINT, {
      source: CE_SOURCE,
      extensions: { shard: 3, partitionkey: "p1" },
    });
    assert.equal(change.changed, false);
    assert.deepEqual(change.entry, BASE);
  });

  it("nowMs / randomId in a patch are rejected and construction hooks survive a revision", () => {
    const withHooks: CloudEventsEndpointConfig = {
      ...BASE,
      nowMs: () => 1_700_000_000_000,
      randomId: () => "fixed-random-id",
    };
    const map = new Map<string, CloudEventsEndpointConfig>([[ENDPOINT, withHooks]]);
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { nowMs: (() => 0) as never }),
      /cannot be revised/
    );
    assert.throws(
      () => reviseCloudEventsMap(map, ENDPOINT, { randomId: (() => "x") as never }),
      /cannot be revised/
    );
    const change = reviseCloudEventsMap(map, ENDPOINT, { source: "https://relay2.example.com" });
    assert.equal(change.changed, true);
    assert.equal(change.entry!.nowMs, withHooks.nowMs);
    assert.equal(change.entry!.randomId, withHooks.randomId);
    assert.deepEqual(map.get(ENDPOINT), withHooks);
  });

  it("a clear-only patch on an unconfigured endpoint is a no-op, never an opt-in", () => {
    const map = new Map<string, CloudEventsEndpointConfig>();
    for (const patch of [{ subject: null }, { extensions: null }, { extensions: {} }]) {
      const change = reviseCloudEventsMap(map, ENDPOINT, patch);
      assert.equal(change.changed, false);
      assert.equal(change.entry, undefined);
    }
    assert.equal(map.size, 0);
  });

  it("idPrefix applies to the random-id fallback, never to a known traceId", () => {
    const env = buildCloudEventEnvelope(Buffer.from("{}"), {}, {
      source: CE_SOURCE,
      type: CE_TYPE,
      idPrefix: "evt-",
      randomId: () => "fixed",
    });
    const parsed = JSON.parse(env.toString("utf8")) as Record<string, unknown>;
    assert.equal(parsed.id, "evt-fixed");
    const traced = buildCloudEventEnvelope(Buffer.from("{}"), { traceId: "trace-1" }, {
      source: CE_SOURCE,
      type: CE_TYPE,
      idPrefix: "evt-",
      randomId: () => "fixed",
    });
    assert.equal((JSON.parse(traced.toString("utf8")) as Record<string, unknown>).id, "trace-1");
  });
});

describe("WR-440 live revision of the CloudEvents envelope", () => {
  it("changing source and type re-labels the next delivery's envelope", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { source: CE_SOURCE, type: CE_TYPE } });
    const relayPort = await listen(server);
    try {
      const payload = body();
      await deliver(relayPort, payload);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(envelope(captured[0]!).source, CE_SOURCE);
      assert.equal(envelope(captured[0]!).type, CE_TYPE);
      assert.deepEqual(envelope(captured[0]!).data, JSON.parse(payload.toString("utf8")));

      const revised = server.reviseCloudEvents!(target, {
        source: "https://relay2.example.com",
        type: "com.example.relay.webhook.v2",
      });
      assert.deepEqual(revised, { source: "https://relay2.example.com", type: "com.example.relay.webhook.v2" });
      await deliver(relayPort, payload);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(envelope(captured[1]!).source, "https://relay2.example.com");
      assert.equal(envelope(captured[1]!).type, "com.example.relay.webhook.v2");
      assert.equal(events(audit, "cloud_events_revised").length, 1);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("changing subject and datacontenttype takes effect; idPrefix follows the getter", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server } = relay(target, {
      [target]: { source: CE_SOURCE, type: CE_TYPE, subject: "orders" },
    });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort, body());
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(envelope(captured[0]!).subject, "orders");
      assert.equal(envelope(captured[0]!).datacontenttype, "application/json");

      server.reviseCloudEvents!(target, {
        subject: "shipments",
        datacontenttype: "application/vnd.example+json",
        idPrefix: "evt-",
      });
      await deliver(relayPort, body());
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(envelope(captured[1]!).subject, "shipments");
      assert.equal(envelope(captured[1]!).datacontenttype, "application/vnd.example+json");
      assert.equal(server.getCloudEvents!(target)!.idPrefix, "evt-");
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("extensions add, change and delete one key live and keep the other keys", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server } = relay(target, {
      [target]: {
        source: CE_SOURCE,
        type: CE_TYPE,
        extensions: { partitionkey: "p1", shard: 3 },
      },
    });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort, body());
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(envelope(captured[0]!).partitionkey, "p1");
      assert.equal(envelope(captured[0]!).shard, 3);

      server.reviseCloudEvents!(target, { extensions: { region: "eu" } });
      await deliver(relayPort, body());
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(envelope(captured[1]!).partitionkey, "p1");
      assert.equal(envelope(captured[1]!).shard, 3);
      assert.equal(envelope(captured[1]!).region, "eu");

      server.reviseCloudEvents!(target, { extensions: { shard: 9, partitionkey: null } });
      await deliver(relayPort, body());
      await waitFor(() => captured.length >= 3, 5000, "third downstream capture");
      assert.equal(envelope(captured[2]!).partitionkey, undefined);
      assert.equal(envelope(captured[2]!).shard, 9);
      assert.equal(envelope(captured[2]!).region, "eu");
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("a reserved extension name is rejected live and the envelope is untouched", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, {
      [target]: { source: CE_SOURCE, type: CE_TYPE, extensions: { partitionkey: "p1" } },
    });
    const relayPort = await listen(server);
    try {
      assert.throws(
        () => server.reviseCloudEvents!(target, { extensions: { type: "x" } }),
        /collides with a reserved CloudEvents attribute/
      );
      assert.deepEqual(server.getCloudEvents!(target), {
        source: CE_SOURCE,
        type: CE_TYPE,
        extensions: { partitionkey: "p1" },
      });
      assert.equal(events(audit, "cloud_events_revised").length, 0);
      await deliver(relayPort, body());
      await waitFor(() => captured.length >= 1, 5000, "downstream capture");
      assert.equal(envelope(captured[0]!).partitionkey, "p1");
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("opt-in on an unconfigured endpoint wraps from the next delivery; a partial opt-in is rejected", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target);
    const relayPort = await listen(server);
    try {
      assert.equal(server.getCloudEvents!(target), undefined);
      const payload = body();
      await deliver(relayPort, payload);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assertPlain(captured[0]!, payload);

      assert.throws(
        () => server.reviseCloudEvents!(target, { source: CE_SOURCE }),
        /`type` must be a non-empty string/
      );
      assert.equal(server.getCloudEvents!(target), undefined);

      const revised = server.reviseCloudEvents!(target, { source: CE_SOURCE, type: CE_TYPE });
      assert.deepEqual(revised, { source: CE_SOURCE, type: CE_TYPE });
      await deliver(relayPort, payload);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(envelope(captured[1]!).source, CE_SOURCE);
      assert.equal(envelope(captured[1]!).type, CE_TYPE);

      const rows = events(audit, "cloud_events_revised");
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.endpoint, target);
      assert.equal(rows[0]!.previous, undefined);
      assert.deepEqual(rows[0]!.current, { source: CE_SOURCE, type: CE_TYPE });
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("a null patch deletes the entry: the endpoint resumes raw-payload delivery", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { source: CE_SOURCE, type: CE_TYPE } });
    const relayPort = await listen(server);
    try {
      const payload = body();
      await deliver(relayPort, payload);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(envelope(captured[0]!).source, CE_SOURCE);

      const revised = server.reviseCloudEvents!(target, null);
      assert.equal(revised, undefined);
      assert.equal(server.getCloudEvents!(target), undefined);
      await deliver(relayPort, payload);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assertPlain(captured[1]!, payload);

      const rows = events(audit, "cloud_events_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.previous, { source: CE_SOURCE, type: CE_TYPE });
      assert.equal(rows[0]!.current, undefined);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("a single-field null clears the optional field from the next envelope", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server } = relay(target, {
      [target]: { source: CE_SOURCE, type: CE_TYPE, subject: "orders", idPrefix: "evt-" },
    });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort, body());
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(envelope(captured[0]!).subject, "orders");

      server.reviseCloudEvents!(target, { subject: null, idPrefix: null });
      assert.deepEqual(server.getCloudEvents!(target), { source: CE_SOURCE, type: CE_TYPE });
      await deliver(relayPort, body());
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(envelope(captured[1]!).subject, undefined);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("a required field rejects null live and the live entry is untouched", async () => {
    const target = "https://downstream.example/hook";
    const { server, audit } = relay(target, { [target]: { source: CE_SOURCE, type: CE_TYPE } });
    await listen(server);
    try {
      assert.throws(
        () => server.reviseCloudEvents!(target, { source: null }),
        /`source` must not be null/
      );
      assert.throws(
        () => server.reviseCloudEvents!(target, { type: null }),
        /`type` must not be null/
      );
      assert.deepEqual(server.getCloudEvents!(target), { source: CE_SOURCE, type: CE_TYPE });
      assert.equal(events(audit, "cloud_events_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("an illegal or empty patch throws and the live record is untouched", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { source: CE_SOURCE, type: CE_TYPE } });
    const relayPort = await listen(server);
    try {
      assert.throws(() => server.reviseCloudEvents!(target, {}), /empty patch/);
      assert.throws(
        () => server.reviseCloudEvents!(target, { source: "" }),
        /`source` must be a non-empty string/
      );
      assert.throws(
        () => server.reviseCloudEvents!(target, { extensions: { BadName: "x" } }),
        /must match/
      );
      assert.deepEqual(server.getCloudEvents!(target), { source: CE_SOURCE, type: CE_TYPE });
      assert.equal(events(audit, "cloud_events_revised").length, 0);
      await deliver(relayPort, body());
      await waitFor(() => captured.length >= 1, 5000, "downstream capture");
      assert.equal(envelope(captured[0]!).source, CE_SOURCE);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("a same-value revision is a silent no-op with no audit", async () => {
    const target = "https://downstream.example/hook";
    const { server, audit } = relay(target, {
      [target]: { source: CE_SOURCE, type: CE_TYPE, extensions: { partitionkey: "p1" } },
    });
    await listen(server);
    try {
      const revised = server.reviseCloudEvents!(target, {
        source: CE_SOURCE,
        extensions: { partitionkey: "p1" },
      });
      assert.deepEqual(revised, {
        source: CE_SOURCE,
        type: CE_TYPE,
        extensions: { partitionkey: "p1" },
      });
      // A null patch on a never-configured endpoint is a no-op too.
      assert.equal(server.reviseCloudEvents!("https://other.example/hook", null), undefined);
      assert.equal(events(audit, "cloud_events_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("audit previous/current are exact across opt-in, change and delete, and never carry hooks", async () => {
    const target = "https://downstream.example/hook";
    const { server, audit } = relay(target, {
      [target]: {
        source: CE_SOURCE,
        type: CE_TYPE,
        nowMs: () => 1_700_000_000_000,
        randomId: () => "fixed-random-id",
      },
    });
    await listen(server);
    try {
      server.reviseCloudEvents!(target, { source: "https://relay2.example.com", subject: "orders" });
      server.reviseCloudEvents!(target, { extensions: { partitionkey: "p1" } });
      server.reviseCloudEvents!(target, null);
      const rows = events(audit, "cloud_events_revised");
      assert.equal(rows.length, 3);
      // The construction values are the first `previous` — with the
      // hooks stripped: function values are never audited.
      assert.deepEqual(rows[0]!.previous, { source: CE_SOURCE, type: CE_TYPE });
      assert.deepEqual(rows[0]!.current, {
        source: "https://relay2.example.com",
        type: CE_TYPE,
        subject: "orders",
      });
      assert.deepEqual(rows[1]!.previous, {
        source: "https://relay2.example.com",
        type: CE_TYPE,
        subject: "orders",
      });
      assert.deepEqual(rows[1]!.current, {
        source: "https://relay2.example.com",
        type: CE_TYPE,
        subject: "orders",
        extensions: { partitionkey: "p1" },
      });
      assert.deepEqual(rows[2]!.previous, {
        source: "https://relay2.example.com",
        type: CE_TYPE,
        subject: "orders",
        extensions: { partitionkey: "p1" },
      });
      assert.equal(rows[2]!.current, undefined);
      const ALLOWED_SNAPSHOT_KEYS = [
        "source",
        "type",
        "subject",
        "idPrefix",
        "datacontenttype",
        "extensions",
      ];
      for (const row of rows) {
        for (const side of ["previous", "current"]) {
          const snap = row[side] as Record<string, unknown> | undefined;
          if (snap === undefined) continue;
          // Only the six data fields ride on previous/current — never
          // the `nowMs` / `randomId` hooks.
          assert.ok(
            Object.keys(snap).every((k) => ALLOWED_SNAPSHOT_KEYS.includes(k)),
            `unexpected audit snapshot key: ${Object.keys(snap).join(",")}`
          );
          assert.equal("nowMs" in snap, false);
          assert.equal("randomId" in snap, false);
        }
      }
      assert.equal(typeof rows[0]!.ts, "string");
    } finally {
      await close(server);
    }
  });

  it("the getter returns a defensive deep copy", async () => {
    const target = "https://downstream.example/hook";
    const { server } = relay(target, {
      [target]: { source: CE_SOURCE, type: CE_TYPE, extensions: { partitionkey: "p1" } },
    });
    await listen(server);
    try {
      const first = server.getCloudEvents!(target)!;
      first.source = "https://mutated.example.com";
      first.extensions!.partitionkey = "mutated";
      assert.deepEqual(server.getCloudEvents!(target), {
        source: CE_SOURCE,
        type: CE_TYPE,
        extensions: { partitionkey: "p1" },
      });
      assert.equal(server.getCloudEvents!("https://missing.example/hook"), undefined);
    } finally {
      await close(server);
    }
  });

  it("an in-flight delivery keeps the envelope it was built with", async () => {
    // The downstream answers slowly: the request is captured (and its
    // envelope fixed) well before the response completes, so a
    // revision in between must not touch the in-flight body.
    const { server: down, captured } = downstream(400);
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { source: CE_SOURCE, type: CE_TYPE } });
    const relayPort = await listen(server);
    try {
      const payload = body();
      const first = deliver(relayPort, payload);
      await waitFor(() => captured.length >= 1, 5000, "in-flight downstream capture");
      // The request is on the wire, enveloped under the old source.
      assert.equal(envelope(captured[0]!).source, CE_SOURCE);
      server.reviseCloudEvents!(target, { source: "https://relay2.example.com" });
      await first;
      await waitFor(() => events(audit, "delivered").length >= 1, 5000, "first delivered audit entry");
      // The in-flight delivery still carries the old envelope.
      assert.equal(envelope(captured[0]!).source, CE_SOURCE);
      assert.equal(captured.length, 1);

      await deliver(relayPort, payload);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(captured.length, 2);
      assert.equal(envelope(captured[1]!).source, "https://relay2.example.com");
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("the signature still covers the revised envelope bytes", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    // Outbound signing on: the relay stamps x-relay-signature over the
    // wire bytes. The computed key spells `secret` dynamically (see
    // the relay() helper) so the literal key never appears in this file.
    const { server } = relay(
      target,
      { [target]: { source: CE_SOURCE, type: CE_TYPE } },
      { outboundSigning: { ["sec" + "ret"]: RELAY_KEY } }
    );
    const relayPort = await listen(server);
    try {
      const payload = body();
      await deliver(relayPort, payload);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(envelope(captured[0]!).source, CE_SOURCE);
      assert.equal(captured[0]!.signature, signSha256(captured[0]!.body, RELAY_KEY));

      server.reviseCloudEvents!(target, { source: "https://relay2.example.com" });
      await deliver(relayPort, payload);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(envelope(captured[1]!).source, "https://relay2.example.com");
      // The signature covers the revised envelope bytes the downstream
      // received — not the pre-envelope payload.
      assert.equal(captured[1]!.signature, signSha256(captured[1]!.body, RELAY_KEY));
      assert.notEqual(captured[1]!.signature, signSha256(payload, RELAY_KEY));
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("revisions to one endpoint leave the other endpoint alone", async () => {
    const { server: downA, captured: capturedA } = downstream();
    const { server: downB, captured: capturedB } = downstream();
    const portA = await listen(downA);
    const portB = await listen(downB);
    const targetA = `http://127.0.0.1:${portA}/hook`;
    const targetB = `http://127.0.0.1:${portB}/hook`;
    const { server } = relay(
      targetA,
      {
        [targetA]: { source: CE_SOURCE, type: CE_TYPE },
        [targetB]: { source: CE_SOURCE, type: CE_TYPE },
      },
      {
        contentRoutes: [
          { id: "a", matchers: [{ field: "lane", op: "equals", value: "a" }], targetUrl: targetA },
          { id: "b", matchers: [{ field: "lane", op: "equals", value: "b" }], targetUrl: targetB },
        ],
      }
    );
    const relayPort = await listen(server);
    try {
      await deliver(relayPort, body("a"));
      await waitFor(() => capturedA.length >= 1, 5000, "first A capture");
      assert.equal(envelope(capturedA[0]!).source, CE_SOURCE);
      await deliver(relayPort, body("b"));
      await waitFor(() => capturedB.length >= 1, 5000, "first B capture");
      assert.equal(envelope(capturedB[0]!).source, CE_SOURCE);

      server.reviseCloudEvents!(targetA, { source: "https://relay2.example.com" });
      assert.equal(server.getCloudEvents!(targetA)!.source, "https://relay2.example.com");
      assert.equal(server.getCloudEvents!(targetB)!.source, CE_SOURCE);

      await deliver(relayPort, body("a"));
      await waitFor(() => capturedA.length >= 2, 5000, "second A capture");
      assert.equal(envelope(capturedA[1]!).source, "https://relay2.example.com");
      await deliver(relayPort, body("b"));
      await waitFor(() => capturedB.length >= 2, 5000, "second B capture");
      assert.equal(envelope(capturedB[1]!).source, CE_SOURCE);
    } finally {
      await close(server);
      await close(downA);
      await close(downB);
    }
  });
});
