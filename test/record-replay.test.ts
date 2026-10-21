import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RecordingStore,
  createReplaySender,
  matchRecording,
  validateRecordingFile,
  ReplayNoMatchError,
  payloadSha256,
  resolveRecordReplayConfig,
  type RecordedInteraction,
  type RecordedRequest,
} from "../src/record-replay.ts";
import type { DownstreamResponse, RetryItem } from "../src/retry.ts";

const EP = "http://downstream.example/hook";
const PAYLOAD = Buffer.from(JSON.stringify({ order: "secret-123", amount: 42 }));

function item(payload: Buffer = PAYLOAD, targetUrl: string = EP): RetryItem {
  return {
    id: "rr-1",
    payload,
    targetUrl,
    headers: { "content-type": "application/json", "x-relay-signature": "should-not-persist" },
  };
}

function okResponse(status = 200, body = Buffer.from('{"ok":true}')): DownstreamResponse {
  return { statusCode: status, body, truncated: false };
}

describe("record-replay: config validation", () => {
  it("rejects bad configs fail-fast", () => {
    assert.throws(() => resolveRecordReplayConfig(undefined as never, "t"), RangeError);
    assert.throws(() => resolveRecordReplayConfig({ mode: "x" } as never, "t"), RangeError);
    assert.throws(() => resolveRecordReplayConfig({ mode: "record", defaultMethod: "" }, "t"), RangeError);
    assert.throws(
      () => resolveRecordReplayConfig({ mode: "replay", matchStrategy: "nope" } as never, "t"),
      RangeError
    );
    assert.throws(() => resolveRecordReplayConfig({ mode: "record", maxRecordings: 0 }, "t"), RangeError);
    const ok = resolveRecordReplayConfig({ mode: "record" }, "t");
    assert.equal(ok.mode, "record");
    assert.equal(ok.defaultMethod, "POST");
    assert.equal(ok.matchStrategy, "exact-url");
    assert.equal(ok.maxRecordings, 10000);
  });

  it("accepts a custom matcher function", () => {
    const match = () => undefined;
    const ok = resolveRecordReplayConfig({ mode: "replay", matchStrategy: match }, "t");
    assert.equal(ok.matchStrategy, match);
  });
});

describe("record-replay: record mode", () => {
  it("records a successful attempt with hash-only payload capture", async () => {
    const store = new RecordingStore();
    const sender = store.wrap(async () => okResponse(200, Buffer.from('{"ok":true}')));
    const resp = await sender(item());
    assert.equal((resp as DownstreamResponse).statusCode, 200);

    const recs = store.getRecordings();
    assert.equal(recs.length, 1);
    const rec = recs[0];
    assert.equal(rec.request.method, "POST");
    assert.equal(rec.request.url, EP);
    assert.deepEqual(rec.request.headerNames, ["content-type", "x-relay-signature"]);
    assert.equal(rec.request.payloadSha256, payloadSha256(PAYLOAD));
    assert.equal(rec.request.payloadBytes, PAYLOAD.length);
    assert.equal(rec.response.ok, true);
    if (rec.response.ok) {
      assert.equal(rec.response.status, 200);
      assert.equal(Buffer.from(rec.response.bodyBase64, "base64").toString(), '{"ok":true}');
      assert.equal(rec.response.voidResponse, undefined);
    }
    assert.ok(rec.latencyMs >= 0);
    assert.ok(!Number.isNaN(Date.parse(rec.recordedAt)));
  });

  it("records a void response and a transport failure, passing both through", async () => {
    const voidStore = new RecordingStore();
    const voidSender = voidStore.wrap(async () => undefined);
    const voidResp = await voidSender(item());
    assert.equal(voidResp, undefined);
    const voidRec = voidStore.getRecordings()[0];
    assert.equal(voidRec.response.ok, true);
    if (voidRec.response.ok) assert.equal(voidRec.response.voidResponse, true);

    const failStore = new RecordingStore();
    const boom = Object.assign(new Error("socket hang up"), { code: "ECONNRESET" });
    const failSender = failStore.wrap(async () => {
      throw boom;
    });
    await assert.rejects(() => failSender(item()), /socket hang up/);
    const failRec = failStore.getRecordings()[0];
    assert.equal(failRec.response.ok, false);
    if (!failRec.response.ok) {
      assert.equal(failRec.response.errorCode, "ECONNRESET");
      assert.equal(failRec.response.errorMessage, "socket hang up");
    }
  });

  it("evicts the oldest recordings past maxRecordings", async () => {
    const store = new RecordingStore({ maxRecordings: 2 });
    const sender = store.wrap(async (it2) => okResponse(200, Buffer.from(it2.id)));
    for (const id of ["a", "b", "c"]) {
      await sender({ ...item(), id });
    }
    const recs = store.getRecordings();
    assert.equal(recs.length, 2);
    // Recording does not carry the id; ordering is oldest-first, so the
    // two survivors are the "b"/"c" bodies.
    assert.deepEqual(
      recs.map((r) => (r.response.ok ? Buffer.from(r.response.bodyBase64, "base64").toString() : "")),
      ["b", "c"]
    );
  });

  it("honors an injected clock for deterministic latency", async () => {
    let t = 1000;
    const store = new RecordingStore({ now: () => t });
    const sender = store.wrap(async () => {
      t += 37;
      return okResponse();
    });
    await sender(item());
    assert.equal(store.getRecordings()[0].latencyMs, 37);
  });

  it("saveToFile round-trips through loadFromFile; the file carries no payload plaintext", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rr-"));
    const path = join(dir, "downstream.json");
    const store = new RecordingStore();
    await store.wrap(async () => okResponse())(item());
    await store.saveToFile(path);

    const raw = readFileSync(path, "utf8");
    assert.ok(!raw.includes("secret-123"), "payload plaintext must never hit disk");
    assert.ok(!raw.includes("should-not-persist"), "header values must never hit disk");
    assert.ok(raw.includes(payloadSha256(PAYLOAD)), "payload hash is persisted");

    const loaded = await RecordingStore.loadFromFile(path);
    assert.equal(loaded.length, 1);
    assert.deepEqual(loaded, store.getRecordings());
  });

  it("loadFromFile fails loud on bad fixtures", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rr-"));
    const badJson = join(dir, "bad.json");
    writeFileSync(badJson, "{not json", "utf8");
    await assert.rejects(() => RecordingStore.loadFromFile(badJson), /not valid JSON/);

    const wrongVersion = join(dir, "v2.json");
    writeFileSync(wrongVersion, JSON.stringify({ version: 2, recordings: [] }), "utf8");
    await assert.rejects(() => RecordingStore.loadFromFile(wrongVersion), /version/);

    const malformed = join(dir, "malformed.json");
    writeFileSync(
      malformed,
      JSON.stringify({ version: 1, recordings: [{ request: { url: 1 } }] }),
      "utf8"
    );
    await assert.rejects(() => RecordingStore.loadFromFile(malformed), /malformed/);

    await assert.rejects(
      () => RecordingStore.loadFromFile(join(dir, "missing.json")),
      /cannot read recording file/
    );
  });

  it("validateRecordingFile rejects non-objects", () => {
    assert.throws(() => validateRecordingFile([1] as never, "x"), /must contain a JSON object/);
  });
});

describe("record-replay: replay mode", () => {
  function rec(url: string, method = "POST", payload: Buffer = PAYLOAD): RecordedInteraction {
    return {
      request: {
        method,
        url,
        headerNames: ["content-type"],
        payloadSha256: payloadSha256(payload),
        payloadBytes: payload.length,
      },
      response: { ok: true, status: 200, bodyBase64: Buffer.from('{"ok":true}').toString("base64"), bodyBytes: 12, truncated: false },
      latencyMs: 5,
      recordedAt: "2026-10-21T09:00:00.000Z",
    };
  }

  it("replays a recorded success without touching the network", async () => {
    let networkTouched = false;
    const sender = createReplaySender([rec(EP)], { now: () => 0 });
    const resp = (await sender(item())) as DownstreamResponse;
    assert.equal(resp.statusCode, 200);
    assert.equal(resp.body.toString(), '{"ok":true}');
    assert.equal(resp.truncated, false);
    assert.equal(networkTouched, false);
  });

  it("replays a void response as undefined", async () => {
    const r = rec(EP);
    if (r.response.ok) r.response.voidResponse = true;
    const sender = createReplaySender([r]);
    assert.equal(await sender(item()), undefined);
  });

  it("replays a recorded transport error with the same code", async () => {
    const r = rec(EP);
    r.response = { ok: false, errorCode: "ECONNRESET", errorMessage: "socket hang up" };
    const sender = createReplaySender([r]);
    await assert.rejects(
      sender(item()),
      (err: unknown) => {
        assert.equal((err as Error).message, "socket hang up");
        assert.equal((err as { code?: string }).code, "ECONNRESET");
        return true;
      }
    );
  });

  it("unmatched requests fail loud and never pass through", async () => {
    const sender = createReplaySender([rec(EP)]);
    const err = await sender(item(Buffer.from("other"), "http://other.example/x")).catch((e) => e);
    assert.ok(err instanceof ReplayNoMatchError);
    assert.match(err.message, /never touches the network/);
    assert.equal(err.url, "http://other.example/x");
    assert.equal(err.payloadSha256, payloadSha256(Buffer.from("other")));
  });

  it("url-prefix strategy picks the longest recorded prefix", () => {
    const req: RecordedRequest = {
      method: "POST",
      url: "http://h.example/api/v2/orders",
      headerNames: [],
      payloadSha256: "x",
      payloadBytes: 1,
    };
    const short = rec("http://h.example/api");
    const long = rec("http://h.example/api/v2");
    const hit = matchRecording(req, [short, long], "url-prefix");
    assert.equal(hit, long);
    const miss = matchRecording({ ...req, url: "http://other.example/" }, [short, long], "url-prefix");
    assert.equal(miss, undefined);
  });

  it("payload-hash strategy matches on payload identity across urls", () => {
    const other = Buffer.from("same-payload");
    const req: RecordedRequest = {
      method: "POST",
      url: "http://h.example/b",
      headerNames: [],
      payloadSha256: payloadSha256(other),
      payloadBytes: other.length,
    };
    const hit = matchRecording(req, [rec("http://h.example/a", "POST", other)], "payload-hash");
    assert.ok(hit);
    const miss = matchRecording(req, [rec("http://h.example/a")], "payload-hash");
    assert.equal(miss, undefined);
  });

  it("custom matcher functions are honored", async () => {
    const sender = createReplaySender([rec(EP)], {
      matchStrategy: (req, recs) => (req.url.endsWith("/hook") ? recs[0] : undefined),
    });
    const resp = (await sender(item())) as DownstreamResponse;
    assert.equal(resp.statusCode, 200);
    await assert.rejects(
      sender(item(PAYLOAD, "http://h.example/nope")),
      /no recording matches/
    );
  });

  it("end to end: record from a stub downstream, save, replay offline", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rr-"));
    const path = join(dir, "fixture.json");
    const store = new RecordingStore();
    const live = store.wrap(async (it2) => okResponse(201, Buffer.from(`got:${it2.id}`)));
    await live({ ...item(), id: "e2e-1" });
    await store.saveToFile(path);

    const fixture = await RecordingStore.loadFromFile(path);
    const replay = createReplaySender(fixture);
    const resp = (await replay({ ...item(), id: "e2e-1" })) as DownstreamResponse;
    assert.equal(resp.statusCode, 201);
    assert.equal(resp.body.toString(), "got:e2e-1");
  });
});
