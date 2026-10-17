import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server, type ClientRequest } from "node:http";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { DeliveryEventArchiver } from "../src/event-archive.ts";
import type { DeliveryEvent } from "../src/retry.ts";
import type { Sender } from "../src/retry.ts";

const SIGN_KEY = "sse-replay-key";
const TOKEN = "op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));
const FORWARD_URL = "http://127.0.0.1:1/hook"; // never called; the sender is injected

type RelayOptions = Parameters<typeof createRelayServer>[0];

function tmpDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
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

function post(port: number, path = "/"): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: { "x-signature": signSha256(BODY, SIGN_KEY) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end(BODY);
  });
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
      );
    });
    r.on("error", reject);
    r.end();
  });
}

interface SseFrame {
  id?: string;
  event?: string;
  data?: string;
  comment?: string;
}

interface Stream {
  req: ClientRequest;
  frames: SseFrame[];
  destroy: () => void;
}

/** Open an SSE stream; frames accumulate in `frames` as they arrive. */
function openStream(port: number, token?: string, lastEventId?: string): Stream {
  const frames: SseFrame[] = [];
  let buf = "";
  const headers: Record<string, string> = {};
  if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
  if (lastEventId !== undefined) headers["last-event-id"] = lastEventId;
  const req = httpRequest({ host: "127.0.0.1", port, path: "/events", method: "GET", headers }, (res) => {
    res.on("data", (c: Buffer) => {
      buf += c.toString();
      let idx: number;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const raw = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const frame: SseFrame = {};
        for (const line of raw.split("\n")) {
          if (line.startsWith(":")) frame.comment = line.slice(1).trim();
          else if (line.startsWith("id:")) frame.id = line.slice(3).trim();
          else if (line.startsWith("event:")) frame.event = line.slice(6).trim();
          else if (line.startsWith("data:")) frame.data = line.slice(5).trim();
        }
        frames.push(frame);
      }
    });
  });
  req.on("error", () => {});
  req.end();
  return { req, frames, destroy: () => req.destroy() };
}

async function waitFor(
  frames: SseFrame[],
  pred: (f: SseFrame) => boolean,
  timeoutMs = 5000
): Promise<SseFrame> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const hit = frames.find(pred);
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("timed out waiting for SSE frame");
}

/** Post events until the archive holds `total` events (polls to sync). */
async function postAndSync(port: number, total: number): Promise<void> {
  const deadline = Date.now() + 10000;
  for (;;) {
    const arch = await get(port, "/events/archive", { authorization: `Bearer ${TOKEN}` });
    assert.equal(arch.status, 200);
    const events = JSON.parse(arch.text) as unknown[];
    if (events.length >= total) return;
    if (Date.now() > deadline) throw new Error(`archive did not reach ${total} events`);
    const res = await post(port);
    assert.equal(res.status, 202);
    await new Promise((r) => setTimeout(r, 10));
  }
}

function makeServer(partial: Partial<RelayOptions> & { sender: Sender }): Server {
  const dir = tmpDir("sse-replay-audit-");
  const { sender, ...rest } = partial;
  return createRelayServer({
    secret: SIGN_KEY,
    forwardUrl: FORWARD_URL,
    auditLog: new AuditLog(join(dir, "audit.jsonl")),
    operatorToken: TOKEN,
    ...rest,
    retry: { sender, baseDelayMs: 10, jitterMs: 0, maxAttempts: 1, ...(rest.retry ?? {}) },
  });
}

function dataIds(frames: SseFrame[]): string[] {
  return frames.filter((f) => f.event === "delivery").map((f) => f.id ?? "?");
}

describe("sse Last-Event-ID resume (WR-123)", () => {
  it("live frames carry the monotonic id: cursor", async () => {
    const archiveDir = tmpDir("sse-replay-arch-");
    const relay = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
      events: { sseReplay: true },
    });
    const port = await listen(relay);
    const stream = openStream(port, TOKEN);
    try {
      await postAndSync(port, 1);
      const f1 = await waitFor(stream.frames, (f) => f.event === "delivery");
      assert.equal(f1.id, "1");
      assert.equal((JSON.parse(f1.data!) as { eventSeq: number }).eventSeq, 1);
      await postAndSync(port, 2);
      const f2 = await waitFor(stream.frames, (f) => f.id === "2");
      assert.equal((JSON.parse(f2.data!) as { eventSeq: number }).eventSeq, 2);
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("reconnect replays the missed range in order, then continues live", async () => {
    const archiveDir = tmpDir("sse-replay-arch-");
    const relay = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
      events: { sseReplay: true },
    });
    const port = await listen(relay);
    const s1 = openStream(port, TOKEN);
    try {
      await postAndSync(port, 2);
      await waitFor(s1.frames, (f) => f.id === "2");
      s1.destroy();
      // Missed while disconnected.
      await postAndSync(port, 4);
      const s2 = openStream(port, TOKEN, "2");
      try {
        await waitFor(s2.frames, (f) => f.id === "4");
        assert.deepEqual(dataIds(s2.frames), ["3", "4"]);
        // And the stream continues live after the replay.
        await postAndSync(port, 5);
        await waitFor(s2.frames, (f) => f.id === "5");
        assert.deepEqual(dataIds(s2.frames), ["3", "4", "5"]);
      } finally {
        s2.destroy();
      }
    } finally {
      await close(relay);
    }
  });

  it("Last-Event-ID: 0 replays everything retained", async () => {
    const archiveDir = tmpDir("sse-replay-arch-");
    const relay = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
      events: { sseReplay: true },
    });
    const port = await listen(relay);
    try {
      await postAndSync(port, 2);
      const s = openStream(port, TOKEN, "0");
      try {
        await waitFor(s.frames, (f) => f.id === "2");
        assert.deepEqual(dataIds(s.frames), ["1", "2"]);
      } finally {
        s.destroy();
      }
    } finally {
      await close(relay);
    }
  });

  it("a fully caught-up cursor replays nothing and stays live", async () => {
    const archiveDir = tmpDir("sse-replay-arch-");
    const relay = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
      events: { sseReplay: true },
    });
    const port = await listen(relay);
    try {
      await postAndSync(port, 1);
      const s = openStream(port, TOKEN, "1");
      try {
        await new Promise((r) => setTimeout(r, 300));
        assert.deepEqual(dataIds(s.frames), []);
        await postAndSync(port, 2);
        await waitFor(s.frames, (f) => f.id === "2");
        assert.deepEqual(dataIds(s.frames), ["2"]);
      } finally {
        s.destroy();
      }
    } finally {
      await close(relay);
    }
  });

  it("a rotated cursor answers 210 Gone", async () => {
    const archiveDir = tmpDir("sse-replay-arch-");
    // Tiny byte budget: old lines are evicted almost immediately.
    const relay = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir, maxBytes: 400 },
      events: { sseReplay: true },
    });
    const port = await listen(relay);
    // Post through a live stream: the archiver subscribes before any SSE
    // connection, so 6 delivered frames on the wire imply 6 archived lines.
    // (The archive itself is retention-capped, so it can never hold 6 —
    // counting the wire frames is the deterministic sync signal here.)
    const s = openStream(port, TOKEN);
    try {
      for (let i = 0; i < 6; i++) {
        assert.equal((await post(port)).status, 202);
      }
      await waitFor(
        s.frames,
        () => s.frames.filter((f) => f.event === "delivery").length >= 6
      );
    } finally {
      s.destroy();
    }
    try {
      const res = await get(port, "/events", {
        authorization: `Bearer ${TOKEN}`,
        "last-event-id": "1",
      });
      assert.equal(res.status, 210);
      const body = JSON.parse(res.text) as { error: string };
      assert.equal(body.error, "events_gone");
    } finally {
      await close(relay);
    }
  });

  it("a future cursor and an empty archive answer 210 Gone", async () => {
    const archiveDir = tmpDir("sse-replay-arch-");
    const relay = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
      events: { sseReplay: true },
    });
    const port = await listen(relay);
    try {
      await postAndSync(port, 1);
      const future = await get(port, "/events", {
        authorization: `Bearer ${TOKEN}`,
        "last-event-id": "999999",
      });
      assert.equal(future.status, 210);

      const emptyDir = tmpDir("sse-replay-empty-");
      const relay2 = makeServer({
        sender: async () => {},
        eventArchive: { dir: emptyDir },
        events: { sseReplay: true },
      });
      const port2 = await listen(relay2);
      try {
        const empty = await get(port2, "/events", {
          authorization: `Bearer ${TOKEN}`,
          "last-event-id": "3",
        });
        assert.equal(empty.status, 210);
      } finally {
        await close(relay2);
      }
    } finally {
      await close(relay);
    }
  });

  it("a malformed cursor answers 400", async () => {
    const archiveDir = tmpDir("sse-replay-arch-");
    const relay = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
      events: { sseReplay: true },
    });
    const port = await listen(relay);
    try {
      const res = await get(port, "/events", {
        authorization: `Bearer ${TOKEN}`,
        "last-event-id": "not-a-number",
      });
      assert.equal(res.status, 400);
    } finally {
      await close(relay);
    }
  });

  it("without sseReplay the header is ignored: live-only, zero behavior change", async () => {
    const archiveDir = tmpDir("sse-replay-arch-");
    const relay = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
      // sseReplay not set — default off.
    });
    const port = await listen(relay);
    try {
      await postAndSync(port, 1);
      const s = openStream(port, TOKEN, "1");
      try {
        await new Promise((r) => setTimeout(r, 300));
        // No replay of the missed event…
        assert.deepEqual(dataIds(s.frames), []);
        // …but the live stream still works.
        await postAndSync(port, 2);
        const live = await waitFor(s.frames, (f) => f.event === "delivery");
        assert.equal((JSON.parse(live.data!) as { eventSeq: number }).eventSeq, 2);
      } finally {
        s.destroy();
      }
    } finally {
      await close(relay);
    }
  });

  it("sseReplay without an archive stays live-only and never crashes", async () => {
    const relay = makeServer({
      sender: async () => {},
      events: { sseReplay: true },
      // no eventArchive
    });
    const port = await listen(relay);
    const s = openStream(port, TOKEN, "1");
    try {
      await post(port);
      const live = await waitFor(s.frames, (f) => f.event === "delivery", 5000);
      // No archive: no cursor on the wire, exactly the old frame shape.
      assert.equal(live.id, undefined);
    } finally {
      s.destroy();
      await close(relay);
    }
  });

  it("the cursor survives a server restart via the archive", async () => {
    const archiveDir = tmpDir("sse-replay-arch-");
    const relay1 = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
      events: { sseReplay: true },
    });
    const port1 = await listen(relay1);
    try {
      await postAndSync(port1, 2);
    } finally {
      await close(relay1);
    }

    // "Restart": a new server on the same archive directory.
    const relay2 = makeServer({
      sender: async () => {},
      eventArchive: { dir: archiveDir },
      events: { sseReplay: true },
    });
    const port2 = await listen(relay2);
    try {
      const s = openStream(port2, TOKEN, "1");
      try {
        await waitFor(s.frames, (f) => f.id === "2");
        assert.deepEqual(dataIds(s.frames), ["2"]);
        // The sequence continues where the old process left off.
        await postAndSync(port2, 3);
        await waitFor(s.frames, (f) => f.id === "3");
        assert.deepEqual(dataIds(s.frames), ["2", "3"]);
      } finally {
        s.destroy();
      }
    } finally {
      await close(relay2);
    }
  });
});

describe("event archive sequence (WR-123)", () => {
  function makeEvent(id: string): DeliveryEvent {
    return {
      type: "delivered",
      id,
      traceId: "t",
      targetUrl: "http://x/hook",
      attempts: 1,
      at: new Date().toISOString(),
    };
  }

  it("record() assigns dense seqs and stamps the event", () => {
    const dir = tmpDir("arch-seq-");
    const archiver = new DeliveryEventArchiver({ dir });
    const e1 = makeEvent("a");
    const e2 = makeEvent("b");
    assert.equal(archiver.record(e1), 1);
    assert.equal(archiver.record(e2), 2);
    assert.equal(e1.eventSeq, 1);
    assert.equal(e2.eventSeq, 2);
    assert.deepEqual(archiver.seqRange(), { minSeq: 1, maxSeq: 2, total: 2 });
    const queried = archiver.query();
    assert.deepEqual(queried.map((e) => e.eventSeq), [1, 2]);
    archiver.close();
  });

  it("eventsAfter() returns the strict suffix in order", () => {
    const dir = tmpDir("arch-seq-");
    const archiver = new DeliveryEventArchiver({ dir });
    for (const id of ["a", "b", "c", "d"]) archiver.record(makeEvent(id));
    const { events, truncated } = archiver.eventsAfter(2);
    assert.equal(truncated, false);
    assert.deepEqual(events.map((e) => e.id), ["c", "d"]);
    assert.deepEqual(events.map((e) => e.eventSeq), [3, 4]);
    assert.deepEqual(archiver.eventsAfter(4).events, []);
    assert.deepEqual(archiver.eventsAfter(0).events.map((e) => e.eventSeq), [1, 2, 3, 4]);
    archiver.close();
  });

  it("the sequence continues across restarts", () => {
    const dir = tmpDir("arch-seq-");
    const a1 = new DeliveryEventArchiver({ dir });
    a1.record(makeEvent("a"));
    a1.record(makeEvent("b"));
    a1.close();
    const a2 = new DeliveryEventArchiver({ dir });
    assert.deepEqual(a2.seqRange(), { minSeq: 1, maxSeq: 2, total: 2 });
    assert.equal(a2.record(makeEvent("c")), 3);
    assert.deepEqual(a2.eventsAfter(1).events.map((e) => e.id), ["b", "c"]);
    a2.close();
  });

  it("pre-WR-123 lines without seq are resequenced once, in file order", () => {
    const dir = tmpDir("arch-seq-");
    const legacy = [
      JSON.stringify({ type: "delivered", id: "l1", traceId: "t", targetUrl: "u", attempts: 1, at: "2026-01-01T00:00:00.000Z" }),
      "not json at all",
      JSON.stringify({ type: "retrying", id: "l2", traceId: "t", targetUrl: "u", attempts: 1, at: "2026-01-01T00:00:01.000Z" }),
    ].join("\n");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "events.jsonl"), legacy + "\n");
    const archiver = new DeliveryEventArchiver({ dir });
    assert.deepEqual(archiver.seqRange(), { minSeq: 1, maxSeq: 2, total: 2 });
    assert.deepEqual(archiver.eventsAfter(0).events.map((e) => e.id), ["l1", "l2"]);
    // The corrupt line survives verbatim for query(), just without a seq.
    assert.equal(archiver.query().length, 2);
    // New records continue the sequence.
    assert.equal(archiver.record(makeEvent("n1")), 3);
    archiver.close();
    // And the file on disk now carries seqs on every parseable line.
    const lines = readFileSync(join(dir, "events.jsonl"), "utf8").trim().split("\n");
    const seqs = lines.map((l) => {
      try {
        return (JSON.parse(l) as { seq?: unknown }).seq;
      } catch {
        return "corrupt";
      }
    });
    assert.deepEqual(seqs, [1, "corrupt", 2, 3]);
  });

  it("retention advances the cursor range", () => {
    const dir = tmpDir("arch-seq-");
    const archiver = new DeliveryEventArchiver({ dir, maxBytes: 400 });
    for (let i = 0; i < 6; i++) archiver.record(makeEvent(`e${i}`));
    const range = archiver.seqRange();
    assert.ok(range.minSeq > 1, `expected rotation, got ${JSON.stringify(range)}`);
    assert.equal(range.maxSeq, 6);
    // A cursor at the rotated seq finds nothing after it that is retained…
    const { events } = archiver.eventsAfter(1);
    assert.ok(events.every((e) => (e.eventSeq ?? 0) > 1));
    archiver.close();
  });
});
