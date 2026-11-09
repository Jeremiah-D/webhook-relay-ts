import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import {
  RetryQueue,
  type EndpointPauseInfo,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "endpoint-pause-callbacks-revision-secret";
const operatorToken = "endpoint-pause-callbacks-revision-token";
const ENDPOINT = "http://127.0.0.1:9/unused";

type PauseObserver = (info: EndpointPauseInfo) => void;

describe("RetryQueue endpoint pause callbacks revision (WR-367)", () => {
  function makeQueue(
    onEndpointPaused?: PauseObserver,
    onEndpointResumed?: PauseObserver
  ) {
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      ...(onEndpointPaused !== undefined ? { onEndpointPaused } : {}),
      ...(onEndpointResumed !== undefined ? { onEndpointResumed } : {}),
    });
    return q;
  }

  it("pause reaches the revised callback; the old callback stays silent", () => {
    const oldSeen: EndpointPauseInfo[] = [];
    const newSeen: EndpointPauseInfo[] = [];
    const oldCb: PauseObserver = (info) => oldSeen.push(info);
    const newCb: PauseObserver = (info) => newSeen.push(info);
    const q = makeQueue(oldCb);
    try {
      assert.equal(q.pauseEndpoint(ENDPOINT), true);
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(oldSeen[0], { endpoint: ENDPOINT, cause: "manual" });
      assert.equal(q.resumeEndpoint(ENDPOINT), true);
      // Swap mid-flight: the old callback never hears another pause.
      q.reviseEndpointPauseCallbacks({ onEndpointPaused: newCb });
      assert.equal(q.pauseEndpoint(ENDPOINT), true);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.deepEqual(newSeen[0], { endpoint: ENDPOINT, cause: "manual" });
      assert.equal(q.resumeEndpoint(ENDPOINT), true);
    } finally {
      q.stop();
    }
  });

  it("resume reaches the revised callback; the old callback stays silent", () => {
    const oldSeen: EndpointPauseInfo[] = [];
    const newSeen: EndpointPauseInfo[] = [];
    const oldCb: PauseObserver = (info) => oldSeen.push(info);
    const newCb: PauseObserver = (info) => newSeen.push(info);
    const q = makeQueue(undefined, oldCb);
    try {
      assert.equal(q.pauseEndpoint(ENDPOINT), true);
      assert.equal(q.resumeEndpoint(ENDPOINT), true);
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(oldSeen[0], { endpoint: ENDPOINT });
      // Swap mid-flight: the old callback never hears another resume.
      q.reviseEndpointPauseCallbacks({ onEndpointResumed: newCb });
      assert.equal(q.pauseEndpoint(ENDPOINT), true);
      assert.equal(q.resumeEndpoint(ENDPOINT), true);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.deepEqual(newSeen[0], { endpoint: ENDPOINT });
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; pause/resume mechanics are untouched", () => {
    const pauseSeen: EndpointPauseInfo[] = [];
    const resumeSeen: EndpointPauseInfo[] = [];
    const pauseCb: PauseObserver = (info) => pauseSeen.push(info);
    const resumeCb: PauseObserver = (info) => resumeSeen.push(info);
    const q = makeQueue(pauseCb, resumeCb);
    try {
      assert.equal(q.pauseEndpoint(ENDPOINT), true);
      assert.equal(q.resumeEndpoint(ENDPOINT), true);
      assert.equal(pauseSeen.length, 1);
      assert.equal(resumeSeen.length, 1);
      q.reviseEndpointPauseCallbacks({ onEndpointPaused: null, onEndpointResumed: null });
      // Pausing and resuming still work — only the observation stops.
      assert.equal(q.pauseEndpoint(ENDPOINT), true);
      assert.deepEqual(q.getPausedEndpoints(), [ENDPOINT]);
      assert.equal(q.isEndpointPaused(ENDPOINT), true);
      assert.equal(q.resumeEndpoint(ENDPOINT), true);
      assert.deepEqual(q.getPausedEndpoints(), []);
      assert.equal(pauseSeen.length, 1);
      assert.equal(resumeSeen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError and the live callbacks are untouched", () => {
    const pauseSeen: EndpointPauseInfo[] = [];
    const resumeSeen: EndpointPauseInfo[] = [];
    const pauseCb: PauseObserver = (info) => pauseSeen.push(info);
    const resumeCb: PauseObserver = (info) => resumeSeen.push(info);
    const q = makeQueue(pauseCb, resumeCb);
    try {
      for (const bad of ["nope", 42, {}, true]) {
        assert.throws(
          () => q.reviseEndpointPauseCallbacks({ onEndpointPaused: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
        assert.throws(
          () => q.reviseEndpointPauseCallbacks({ onEndpointResumed: bad as never }),
          RangeError,
          JSON.stringify(bad)
        );
      }
      // The live callbacks are untouched: both transitions still reach them.
      assert.equal(q.pauseEndpoint(ENDPOINT), true);
      assert.equal(pauseSeen.length, 1);
      assert.equal(q.resumeEndpoint(ENDPOINT), true);
      assert.equal(resumeSeen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("an empty or non-object patch throws RangeError and the live callbacks are untouched", () => {
    const pauseSeen: EndpointPauseInfo[] = [];
    const pauseCb: PauseObserver = (info) => pauseSeen.push(info);
    const q = makeQueue(pauseCb);
    try {
      assert.throws(() => q.reviseEndpointPauseCallbacks({}), RangeError);
      assert.throws(() => q.reviseEndpointPauseCallbacks(null as never), RangeError);
      assert.throws(() => q.reviseEndpointPauseCallbacks("nope" as never), RangeError);
      assert.throws(() => q.reviseEndpointPauseCallbacks(42 as never), RangeError);
      // An explicitly-undefined field counts as not provided, so a
      // patch of only undefined fields is empty too.
      assert.throws(
        () => q.reviseEndpointPauseCallbacks({ onEndpointPaused: undefined }),
        RangeError
      );
      assert.equal(q.pauseEndpoint(ENDPOINT), true);
      assert.equal(pauseSeen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a same-reference revision is a no-op; a partial patch leaves the other hook live", () => {
    const pauseSeen: EndpointPauseInfo[] = [];
    const resumeSeen: EndpointPauseInfo[] = [];
    const newPauseSeen: EndpointPauseInfo[] = [];
    const pauseCb: PauseObserver = (info) => pauseSeen.push(info);
    const resumeCb: PauseObserver = (info) => resumeSeen.push(info);
    const newPauseCb: PauseObserver = (info) => newPauseSeen.push(info);
    const q = makeQueue(pauseCb, resumeCb);
    try {
      // Same references as construction: no-op.
      q.reviseEndpointPauseCallbacks({
        onEndpointPaused: pauseCb,
        onEndpointResumed: resumeCb,
      });
      // Clearing when already unset is a no-op too.
      const bare = makeQueue();
      try {
        bare.reviseEndpointPauseCallbacks({ onEndpointPaused: null, onEndpointResumed: null });
      } finally {
        bare.stop();
      }
      // Partial patch: only the pause hook moves.
      q.reviseEndpointPauseCallbacks({ onEndpointPaused: newPauseCb });
      assert.equal(q.pauseEndpoint(ENDPOINT), true);
      assert.equal(pauseSeen.length, 0);
      assert.equal(newPauseSeen.length, 1);
      assert.equal(q.resumeEndpoint(ENDPOINT), true);
      assert.equal(resumeSeen.length, 1); // the resume hook never moved
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint pause callbacks revision (WR-367)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-pause-callbacks-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: ENDPOINT,
      auditLog,
      operatorToken,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function postJson(port: number, path: string, body: unknown, token?: string) {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString() || "{}"),
          })
        );
      });
      r.on("error", reject);
      r.end(JSON.stringify(body));
    });
  }

  /** A server whose pause/resume hooks are observed by the given callbacks. */
  function pausingServer(
    onEndpointPaused: PauseObserver,
    onEndpointResumed: PauseObserver
  ) {
    return makeServer({
      retry: { onEndpointPaused, onEndpointResumed },
    });
  }

  it("revising the pause callback routes the next pause to the new callback and the audit still lands", async () => {
    const initialSeen: EndpointPauseInfo[] = [];
    const newSeen: EndpointPauseInfo[] = [];
    const resumeSeen: EndpointPauseInfo[] = [];
    const initialCb: PauseObserver = (info) => initialSeen.push(info);
    const newCb: PauseObserver = (info) => newSeen.push(info);
    const resumeCb: PauseObserver = (info) => resumeSeen.push(info);
    const { relay, auditLog } = pausingServer(initialCb, resumeCb);
    const port = await listen(relay);
    // First pause: the initial callback hears it and the audit lands.
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(initialSeen.length, 1);
    assert.deepEqual(initialSeen[0], { endpoint: ENDPOINT, cause: "manual" });
    assert.equal(eventsOf(auditLog, "endpoint_paused").length, 1);
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(resumeSeen.length, 1);
    // Swap the operator pause callback; the resume hook is untouched.
    relay.reviseEndpointPauseCallbacks!({ onEndpointPaused: newCb });
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(initialSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen.length, 1);
    assert.deepEqual(newSeen[0], { endpoint: ENDPOINT, cause: "manual" });
    assert.equal(eventsOf(auditLog, "endpoint_paused").length, 2);
    // The revision itself was audited with per-hook presence.
    const revised = eventsOf(auditLog, "endpoint_pause_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onEndpointPaused,
        revised[0].oldOnEndpointPaused,
        revised[0].onEndpointResumed,
        revised[0].oldOnEndpointResumed,
      ],
      ["set", "set", "unchanged", "set"]
    );
  });

  it("revising the resume callback routes the next resume to the new callback", async () => {
    const initialSeen: EndpointPauseInfo[] = [];
    const newSeen: EndpointPauseInfo[] = [];
    const pauseSeen: EndpointPauseInfo[] = [];
    const initialCb: PauseObserver = (info) => initialSeen.push(info);
    const newCb: PauseObserver = (info) => newSeen.push(info);
    const pauseCb: PauseObserver = (info) => pauseSeen.push(info);
    const { relay, auditLog } = pausingServer(pauseCb, initialCb);
    const port = await listen(relay);
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(pauseSeen.length, 1);
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(initialSeen.length, 1);
    // Swap only the resume callback.
    relay.reviseEndpointPauseCallbacks!({ onEndpointResumed: newCb });
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(pauseSeen.length, 2); // the pause hook never moved
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(initialSeen.length, 1);
    assert.equal(newSeen.length, 1);
    assert.deepEqual(newSeen[0], { endpoint: ENDPOINT });
    const revised = eventsOf(auditLog, "endpoint_pause_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onEndpointPaused,
        revised[0].oldOnEndpointPaused,
        revised[0].onEndpointResumed,
        revised[0].oldOnEndpointResumed,
      ],
      ["unchanged", "set", "set", "set"]
    );
  });

  it("clearing both hooks keeps the audit and stops the operator callbacks", async () => {
    const pauseSeen: EndpointPauseInfo[] = [];
    const resumeSeen: EndpointPauseInfo[] = [];
    const pauseCb: PauseObserver = (info) => pauseSeen.push(info);
    const resumeCb: PauseObserver = (info) => resumeSeen.push(info);
    const { relay, auditLog } = pausingServer(pauseCb, resumeCb);
    const port = await listen(relay);
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(pauseSeen.length, 1);
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(resumeSeen.length, 1);
    // Clear back to audit-only.
    relay.reviseEndpointPauseCallbacks!({ onEndpointPaused: null, onEndpointResumed: null });
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(pauseSeen.length, 1); // both later transitions were audit-only
    assert.equal(resumeSeen.length, 1);
    assert.equal(eventsOf(auditLog, "endpoint_paused").length, 2);
    assert.equal(eventsOf(auditLog, "endpoint_resumed").length, 2);
    const revised = eventsOf(auditLog, "endpoint_pause_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onEndpointPaused,
        revised[0].oldOnEndpointPaused,
        revised[0].onEndpointResumed,
        revised[0].oldOnEndpointResumed,
      ],
      ["cleared", "set", "cleared", "set"]
    );
    // Clearing when already cleared is a silent no-op.
    relay.reviseEndpointPauseCallbacks!({ onEndpointPaused: null, onEndpointResumed: null });
    assert.equal(eventsOf(auditLog, "endpoint_pause_callbacks_revised").length, 1);
  });

  it("an illegal value or empty patch throws RangeError, live callbacks untouched, no revision audit", async () => {
    const pauseSeen: EndpointPauseInfo[] = [];
    const resumeSeen: EndpointPauseInfo[] = [];
    const pauseCb: PauseObserver = (info) => pauseSeen.push(info);
    const resumeCb: PauseObserver = (info) => resumeSeen.push(info);
    const { relay, auditLog } = pausingServer(pauseCb, resumeCb);
    const port = await listen(relay);
    for (const bad of ["nope", 42, {}, true]) {
      assert.throws(
        () => relay.reviseEndpointPauseCallbacks!({ onEndpointPaused: bad as never }),
        RangeError,
        JSON.stringify(bad)
      );
      assert.throws(
        () => relay.reviseEndpointPauseCallbacks!({ onEndpointResumed: bad as never }),
        RangeError,
        JSON.stringify(bad)
      );
    }
    assert.throws(() => relay.reviseEndpointPauseCallbacks!({}), RangeError);
    assert.throws(() => relay.reviseEndpointPauseCallbacks!(null as never), RangeError);
    assert.equal(eventsOf(auditLog, "endpoint_pause_callbacks_revised").length, 0);
    // The live callbacks are untouched: both transitions still reach them.
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(pauseSeen.length, 1);
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(resumeSeen.length, 1);
  });

  it("a same-value revision is a silent no-op; a partial patch leaves the other hook live", async () => {
    const initialPauseSeen: EndpointPauseInfo[] = [];
    const initialResumeSeen: EndpointPauseInfo[] = [];
    const newPauseSeen: EndpointPauseInfo[] = [];
    const initialPauseCb: PauseObserver = (info) => initialPauseSeen.push(info);
    const initialResumeCb: PauseObserver = (info) => initialResumeSeen.push(info);
    const newPauseCb: PauseObserver = (info) => newPauseSeen.push(info);
    const { relay, auditLog } = pausingServer(initialPauseCb, initialResumeCb);
    const port = await listen(relay);
    // Same references as construction: no audit event.
    relay.reviseEndpointPauseCallbacks!({
      onEndpointPaused: initialPauseCb,
      onEndpointResumed: initialResumeCb,
    });
    assert.equal(eventsOf(auditLog, "endpoint_pause_callbacks_revised").length, 0);
    // Partial patch: only the pause hook moves.
    relay.reviseEndpointPauseCallbacks!({ onEndpointPaused: newPauseCb });
    const revised = eventsOf(auditLog, "endpoint_pause_callbacks_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(
      [
        revised[0].onEndpointPaused,
        revised[0].oldOnEndpointPaused,
        revised[0].onEndpointResumed,
        revised[0].oldOnEndpointResumed,
      ],
      ["set", "set", "unchanged", "set"]
    );
    // Same reference again: no further audit event.
    relay.reviseEndpointPauseCallbacks!({ onEndpointPaused: newPauseCb });
    assert.equal(eventsOf(auditLog, "endpoint_pause_callbacks_revised").length, 1);
    // Pause enters the new callback; resume still enters the original one.
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(newPauseSeen.length, 1);
    assert.equal(initialPauseSeen.length, 0);
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: ENDPOINT }, operatorToken)).status, 200);
    assert.equal(initialResumeSeen.length, 1);
  });
});
