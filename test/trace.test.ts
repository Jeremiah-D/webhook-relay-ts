import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type DeliveryEvent, type RetryItem } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  isValidTraceId,
  newTraceId,
  resolveTraceId,
  TRACE_ID_HEADER,
} from "../src/trace.ts";

const URL = "http://localhost:9999/hook";
const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_123" }));

function fakeClock() {
  let now = 1_000_000;
  const timers = new Map<number, { fn: () => void; at: number }>();
  let nextId = 1;
  return {
    now: () => now,
    setTimer: (fn: () => void, ms: number) => {
      const id = nextId++;
      timers.set(id, { fn, at: now + ms });
      return { clear: () => timers.delete(id) };
    },
    async advance(ms: number) {
      const end = now + ms;
      for (;;) {
        let due: number | undefined;
        for (const [id, t] of timers) {
          if (t.at <= end && (due === undefined || t.at < timers.get(due)!.at)) due = id;
        }
        if (due === undefined) break;
        const t = timers.get(due)!;
        timers.delete(due);
        now = t.at;
        t.fn();
        // The delivery path is async (sender promise chain); let every
        // microtask settle before scanning for the next due timer, or a
        // retry scheduled by the just-fired callback would be missed.
        await new Promise((r) => setImmediate(r));
      }
      now = end;
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, traceId?: string): RetryItem {
  return { id, payload: Buffer.from("x"), targetUrl: URL, headers: {}, traceId };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
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
    r.end(body);
  });
}

async function waitFor<T>(fn: () => T | undefined, timeoutMs = 5000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v !== undefined) return v;
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("trace id resolution", () => {
  it("keeps a valid inbound x-trace-id", () => {
    assert.equal(resolveTraceId("upstream-abc_123"), "upstream-abc_123");
    assert.equal(resolveTraceId(["first", "second"]), "first");
    assert.equal(resolveTraceId("  padded  "), "padded");
  });

  it("mints a fresh id for missing, blank, or invalid headers", () => {
    for (const h of [undefined, "", "   ", "has space", "a".repeat(65), "x\ninjected"]) {
      const id = resolveTraceId(h as string | undefined);
      assert.match(id, /^[0-9a-f]{32}$/, `header ${JSON.stringify(h)}`);
    }
  });

  it("minted ids are unique", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => newTraceId()));
    assert.equal(ids.size, 1000);
  });

  it("isValidTraceId rejects junk but accepts the generated shape", () => {
    assert.ok(isValidTraceId("A9-_x"));
    assert.ok(isValidTraceId(newTraceId()));
    assert.ok(!isValidTraceId(""));
    assert.ok(!isValidTraceId("a b"));
    assert.ok(!isValidTraceId("x\ny"));
  });
});

describe("queue-level trace propagation", () => {
  it("mints a trace id on enqueue and threads it through delivered events", async () => {
    const clock = fakeClock();
    const sent: RetryItem[] = [];
    const events: DeliveryEvent[] = [];
    const delivered: RetryItem[] = [];
    const q = new RetryQueue({
      sender: async (it) => {
        sent.push(it);
      },
      setTimer: clock.setTimer,
      onDelivered: (it) => delivered.push(it),
    });
    const unsub = q.subscribeDeliveryEvents((e) => events.push(e));
    try {
      q.start();
      q.enqueue(item("a"));
      await clock.advance(10);
      assert.equal(sent.length, 1);
      assert.match(sent[0].traceId ?? "", /^[0-9a-f]{32}$/);
      assert.equal(events.length, 1);
      assert.equal(events[0].type, "delivered");
      assert.equal(events[0].traceId, sent[0].traceId);
      assert.equal(delivered[0].traceId, sent[0].traceId);
    } finally {
      unsub();
    }
  });

  it("preserves a caller-supplied trace id through retries, dead letter, and replay", async () => {
    const clock = fakeClock();
    const events: DeliveryEvent[] = [];
    let fail = true;
    const q = new RetryQueue({
      sender: async () => {
        if (fail) throw new Error("down");
      },
      setTimer: clock.setTimer,
      baseDelayMs: 50,
      jitterMs: 0,
      maxAttempts: 2,
    });
    const unsub = q.subscribeDeliveryEvents((e) => events.push(e));
    try {
      q.start();
      q.enqueue(item("a", "keep-me-1"));
      await clock.advance(1000);
      assert.deepEqual(events.map((e) => e.type), ["retrying", "dead_letter"]);
      assert.ok(events.every((e) => e.traceId === "keep-me-1"));
      const dl = q.getDeadLetter();
      assert.equal(dl.length, 1);
      assert.equal(dl[0].traceId, "keep-me-1");
      // A replay keeps the same trace id: the audit trail stays joinable.
      fail = false;
      assert.ok(q.replayDeadLetter("a"));
      await clock.advance(1000);
      assert.equal(events[events.length - 1].type, "delivered");
      assert.equal(events[events.length - 1].traceId, "keep-me-1");
    } finally {
      unsub();
    }
  });

  it("batch flush reports member trace ids and mints a fresh id for the merged item", async () => {
    const clock = fakeClock();
    const sent: RetryItem[] = [];
    const flushed: Array<{ traceIds: string[] }> = [];
    const q = new RetryQueue({
      sender: async (it) => {
        sent.push(it);
      },
      setTimer: clock.setTimer,
      batch: { windowMs: 100, maxBatchSize: 10 },
      onBatch: (info) => flushed.push(info),
    });
    try {
      q.start();
      q.enqueue(item("a", "trace-a"));
      q.enqueue(item("b", "trace-b"));
      await clock.advance(200);
      assert.equal(sent.length, 1);
      assert.equal(flushed.length, 1);
      assert.deepEqual(flushed[0].traceIds, ["trace-a", "trace-b"]);
      // The merged delivery is its own trace; members correlate via traceIds.
      assert.ok(sent[0].traceId !== "trace-a" && sent[0].traceId !== "trace-b");
      assert.match(sent[0].traceId ?? "", /^[0-9a-f]{32}$/);
    } finally {
      q.stop();
    }
  });
});

describe("server-level trace propagation", () => {
  function relay(opts: {
    forwardUrl?: string;
    sender?: (it: RetryItem) => Promise<void>;
    retry?: ConstructorParameters<typeof RetryQueue>[0];
    dedup?: { windowMs: number };
  }) {
    const dir = mkdtempSync(join(tmpdir(), "trace-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const server = createRelayServer({
      secret: SECRET,
      forwardUrl: opts.forwardUrl ?? URL,
      auditLog: audit,
      sender: opts.sender,
      retry: opts.retry,
      operatorToken: "op-token",
      dedup: opts.dedup,
    });
    return { server, audit };
  }

  it("honors inbound x-trace-id in the 202 body, the audit trail, and the sender item", async () => {
    const seen: RetryItem[] = [];
    const { server, audit } = relay({ sender: async (it) => void seen.push(it) });
    const port = await listen(server);
    try {
      const res = await post(port, BODY, {
        "x-signature": signSha256(BODY, SECRET),
        [TRACE_ID_HEADER]: "upstream-trace-42",
      });
      assert.equal(res.status, 202);
      const body = JSON.parse(res.text) as { id: string; traceId: string };
      assert.equal(body.traceId, "upstream-trace-42");
      const accepted = await waitFor(
        () => audit.query({ event: ["accepted"] })[0] as { id: string; traceId: string } | undefined
      );
      assert.equal(accepted.traceId, "upstream-trace-42");
      const sent = await waitFor(() => seen[0]);
      assert.equal(sent.traceId, "upstream-trace-42");
      const delivered = await waitFor(
        () =>
          audit.query({ event: ["delivered"] })[0] as { traceId: string } | undefined
      );
      assert.equal(delivered.traceId, "upstream-trace-42");
    } finally {
      server.close();
    }
  });

  it("mints a trace id when the client sends none, and propagates it downstream over HTTP", async () => {
    const downstreamHeaders: Array<Record<string, string | string[] | undefined>> = [];
    const stub = createServer((req, res) => {
      downstreamHeaders.push(req.headers);
      res.writeHead(200).end("ok");
    });
    const stubPort = await listen(stub);
    // No injected sender: the real defaultSender forwards and sets x-trace-id.
    const { server, audit } = relay({ forwardUrl: `http://127.0.0.1:${stubPort}/hook` });
    const port = await listen(server);
    try {
      const res = await post(port, BODY, { "x-signature": signSha256(BODY, SECRET) });
      assert.equal(res.status, 202);
      const { traceId } = JSON.parse(res.text) as { traceId: string };
      assert.match(traceId, /^[0-9a-f]{32}$/);
      await waitFor(() => downstreamHeaders[0]);
      assert.equal(downstreamHeaders[0][TRACE_ID_HEADER], traceId);
      const accepted = audit.query({ traceId }) as Array<{ event: string }>;
      // One trace id correlates the full trail: accepted + delivered.
      assert.deepEqual(
        accepted.map((e) => e.event).sort(),
        ["accepted", "delivered"]
      );
    } finally {
      server.close();
      stub.close();
    }
  });

  it("rejections and dead letters carry the trace id; ?traceId= filters the audit trail", async () => {
    const { server, audit } = relay({
      sender: async () => {
        throw new Error("always down");
      },
      retry: { maxAttempts: 1, baseDelayMs: 5, jitterMs: 0 },
    });
    const port = await listen(server);
    try {
      // A rejected request still gets a traceable id (resolved pre-verification).
      const bad = await post(port, BODY, {
        "x-signature": "wrong",
        [TRACE_ID_HEADER]: "trace-rejected",
      });
      assert.equal(bad.status, 401);
      const rejected = await waitFor(
        () => audit.query({ event: ["rejected"] })[0] as { traceId: string } | undefined
      );
      assert.equal(rejected.traceId, "trace-rejected");

      // A delivery that exhausts its budget keeps the trace into dead letter.
      const ok = await post(port, BODY, {
        "x-signature": signSha256(BODY, SECRET),
        [TRACE_ID_HEADER]: "trace-doomed",
      });
      assert.equal(ok.status, 202);
      const dead = await waitFor(
        () =>
          audit.query({ event: ["dead_letter"] })[0] as { traceId: string } | undefined
      );
      assert.equal(dead.traceId, "trace-doomed");

      // One trace id pulls its whole trail: accepted + dead_letter, nothing else.
      const trail = audit.query({ traceId: "trace-doomed" }) as Array<{ event: string }>;
      assert.deepEqual(trail.map((e) => e.event).sort(), ["accepted", "dead_letter"]);
    } finally {
      server.close();
    }
  });

  it("duplicate-suppressed events keep the trace id", async () => {
    const seen: RetryItem[] = [];
    const { server, audit } = relay({
      sender: async (it) => void seen.push(it),
      dedup: { windowMs: 60_000 },
    });
    const port = await listen(server);
    try {
      const headers = {
        "x-signature": signSha256(BODY, SECRET),
        [TRACE_ID_HEADER]: "trace-dup",
      };
      assert.equal((await post(port, BODY, headers)).status, 202);
      const dup = await post(port, BODY, headers);
      assert.equal(dup.status, 202);
      assert.equal((JSON.parse(dup.text) as { duplicate: boolean }).duplicate, true);
      const suppressed = await waitFor(
        () =>
          audit.query({ event: ["duplicate_suppressed"] })[0] as
            | { traceId: string }
            | undefined
      );
      assert.equal(suppressed.traceId, "trace-dup");
    } finally {
      server.close();
    }
  });
});
