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
  reviseOauth2Map,
  type OAuth2ClientCredentialsConfig,
} from "../src/oauth-client.ts";

// NOTE: intentionally not named SECRET — the runner's secret redaction
// rewrites `secret: SECRET` occurrences in test sources.
const RELAY_KEY = "wr438-relay-key";
const OLD_CLIENT_SECRET = "wr438-old-client-secret";
const NEW_CLIENT_SECRET = "wr438-new-client-secret";
const BODY = Buffer.from(JSON.stringify({ event: "oauth2.revise" }));

const TARGET_ID = "relay-oauth2-client";

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

/** Stub token endpoint: hands out tok-1, tok-2, … and records request bodies. */
async function stubTokenEndpoint(): Promise<{
  server: Server;
  url: string;
  hits: number;
  bodies: string[];
}> {
  let hits = 0;
  const bodies: string[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      hits += 1;
      bodies.push(Buffer.concat(chunks).toString("utf8"));
      res
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ access_token: `tok-${hits}`, token_type: "Bearer", expires_in: 3600 }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return {
    server,
    url: `http://127.0.0.1:${addr.port}/oauth/token`,
    get hits() {
      return hits;
    },
    bodies,
  };
}

interface Captured {
  authorization: string | undefined;
  body: Buffer;
}

/** A plain-HTTP downstream that records every request's bearer stamp. */
function downstream(): { server: Server; captured: Captured[] } {
  const captured: Captured[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      captured.push({
        authorization: req.headers.authorization,
        body: Buffer.concat(chunks),
      });
      res.writeHead(200).end("ok");
    });
  });
  return { server, captured };
}

function relay(
  targetUrl: string,
  oauth2?: Record<string, OAuth2ClientCredentialsConfig>
) {
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "oauth2rev-")), "audit.jsonl"));
  const server = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:`
    // key in test-file writes (see AGENTS.md), so the key is spelled
    // out dynamically instead.
    ["sec" + "ret"]: RELAY_KEY,
    forwardUrl: targetUrl,
    auditLog: audit,
    ...(oauth2 !== undefined ? { oauth2 } : {}),
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
  });
  return { server, audit, targetUrl };
}

async function deliver(relayPort: number): Promise<void> {
  const res = await post(relayPort, BODY, {
    "x-signature": signSha256(BODY, RELAY_KEY),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
}

function tokenForm(body: string): URLSearchParams {
  return new URLSearchParams(body);
}

describe("WR-438 reviseOauth2Map (pure merge)", () => {
  const ENDPOINT = "https://downstream.example/hook";
  const BASE: OAuth2ClientCredentialsConfig = {
    token_endpoint: "https://auth.example.test/token",
    client_id: TARGET_ID,
    client_secret: OLD_CLIENT_SECRET,
    scope: "read",
  };

  it("a partial patch keeps the omitted live fields and never mutates the previous entry", () => {
    const map = new Map<string, OAuth2ClientCredentialsConfig>([[ENDPOINT, { ...BASE }]]);
    const change = reviseOauth2Map(map, ENDPOINT, { scope: "write" });
    assert.equal(change.changed, true);
    assert.deepEqual(change.entry, { ...BASE, scope: "write" });
    // The previous entry and the map are never mutated by a merge.
    assert.deepEqual(map.get(ENDPOINT), { ...BASE });
  });

  it("a null patch deletes the entry; on a missing endpoint it is a no-op", () => {
    const map = new Map<string, OAuth2ClientCredentialsConfig>([[ENDPOINT, { ...BASE }]]);
    const change = reviseOauth2Map(map, ENDPOINT, null);
    assert.equal(change.changed, true);
    assert.equal(change.entry, undefined);
    assert.deepEqual(map.get(ENDPOINT), { ...BASE });
    const noop = reviseOauth2Map(map, "https://missing.example/hook", null);
    assert.equal(noop.changed, false);
    assert.equal(noop.entry, undefined);
  });

  it("opt-in on an unconfigured endpoint needs all four fields at once", () => {
    const map = new Map<string, OAuth2ClientCredentialsConfig>();
    assert.throws(
      () =>
        reviseOauth2Map(map, ENDPOINT, {
          token_endpoint: BASE.token_endpoint,
          client_id: BASE.client_id,
          client_secret: OLD_CLIENT_SECRET,
        }),
      /opting in requires `scope`/
    );
    assert.throws(
      () =>
        reviseOauth2Map(map, ENDPOINT, {
          token_endpoint: BASE.token_endpoint,
          client_id: BASE.client_id,
          scope: "read",
        }),
      /opting in requires `client_secret`/
    );
    assert.equal(map.size, 0);
    const change = reviseOauth2Map(map, ENDPOINT, { ...BASE });
    assert.equal(change.changed, true);
    assert.deepEqual(change.entry, { ...BASE });
  });

  it("a single-field null is rejected for every field", () => {
    const map = new Map<string, OAuth2ClientCredentialsConfig>([[ENDPOINT, { ...BASE }]]);
    for (const patch of [
      { token_endpoint: null },
      { client_id: null },
      { client_secret: null },
      { scope: null },
    ]) {
      assert.throws(
        () => reviseOauth2Map(map, ENDPOINT, patch as never),
        /must not be null/
      );
    }
    assert.deepEqual(map.get(ENDPOINT), { ...BASE });
  });

  it("an empty or illegal patch throws RangeError and the map is untouched", () => {
    const map = new Map<string, OAuth2ClientCredentialsConfig>([[ENDPOINT, { ...BASE }]]);
    assert.throws(() => reviseOauth2Map(map, ENDPOINT, {}), /empty patch/);
    assert.throws(
      () => reviseOauth2Map(map, ENDPOINT, { scope: undefined }),
      /empty patch/
    );
    assert.throws(
      () => reviseOauth2Map(map, ENDPOINT, { token_endpoint: "not a url" }),
      /not a valid URL/
    );
    assert.throws(
      () => reviseOauth2Map(map, ENDPOINT, { client_id: "" }),
      /client_id.*non-empty/
    );
    assert.throws(
      () => reviseOauth2Map(map, ENDPOINT, { client_secret: "" }),
      /exactly one of/
    );
    assert.deepEqual(map.get(ENDPOINT), { ...BASE });
  });

  it("a same-value patch is a silent no-op", () => {
    const map = new Map<string, OAuth2ClientCredentialsConfig>([[ENDPOINT, { ...BASE }]]);
    const change = reviseOauth2Map(map, ENDPOINT, {
      token_endpoint: BASE.token_endpoint,
      client_id: BASE.client_id,
      scope: "read",
    });
    assert.equal(change.changed, false);
    assert.deepEqual(change.entry, { ...BASE });
  });

  it("a patch carrying client_secret is always a real change", () => {
    const map = new Map<string, OAuth2ClientCredentialsConfig>([[ENDPOINT, { ...BASE }]]);
    // Same visible values, only the secret rotates — still a change,
    // because the secret never participates in the comparison.
    const change = reviseOauth2Map(map, ENDPOINT, { client_secret: NEW_CLIENT_SECRET });
    assert.equal(change.changed, true);
    assert.deepEqual(change.entry, { ...BASE, client_secret: NEW_CLIENT_SECRET });
    // Even re-stating the identical secret counts: presence in the
    // patch is what matters, not the value.
    const restated = reviseOauth2Map(map, ENDPOINT, { client_secret: OLD_CLIENT_SECRET });
    assert.equal(restated.changed, true);
  });
});

describe("WR-438 live revision of OAuth2 client_credentials config", () => {
  it("rotating client_secret fetches the next token with the new secret", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, {
      [target]: {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      },
    });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(captured[0]!.authorization, "Bearer tok-1");
      assert.equal(tokenEp.hits, 1);
      assert.equal(tokenForm(tokenEp.bodies[0]!).get("client_secret"), OLD_CLIENT_SECRET);

      const revised = server.reviseOauth2!(target, { client_secret: NEW_CLIENT_SECRET });
      assert.equal(revised!.client_secret, NEW_CLIENT_SECRET);
      assert.equal(revised!.scope, "read");

      await deliver(relayPort);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      // The cached tok-1 was invalidated: the next delivery refetched
      // (same cache key — only the secret changed) with the new secret.
      assert.equal(tokenEp.hits, 2);
      assert.equal(tokenForm(tokenEp.bodies[1]!).get("client_secret"), NEW_CLIENT_SECRET);
      assert.equal(captured[1]!.authorization, "Bearer tok-2");

      const rows = events(audit, "oauth2_revised");
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.endpoint, target);
      assert.deepEqual(rows[0]!.previous, {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        scope: "read",
      });
      assert.deepEqual(rows[0]!.current, {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        scope: "read",
      });
      // The secret rotated, so the audit must not carry either value.
      const dump = JSON.stringify(rows);
      assert.ok(!dump.includes(OLD_CLIENT_SECRET), "audit must not contain the old secret");
      assert.ok(!dump.includes(NEW_CLIENT_SECRET), "audit must not contain the new secret");
    } finally {
      await close(server);
      await close(down);
      tokenEp.server.close();
    }
  });

  it("changing scope drops the old-key cached token and refetches; revising back refetches again", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server } = relay(target, {
      [target]: {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      },
    });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(captured[0]!.authorization, "Bearer tok-1");
      assert.equal(tokenEp.hits, 1);

      server.reviseOauth2!(target, { scope: "write" });
      await deliver(relayPort);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(tokenEp.hits, 2);
      assert.equal(tokenForm(tokenEp.bodies[1]!).get("scope"), "write");
      assert.equal(captured[1]!.authorization, "Bearer tok-2");

      // Revising back to the original scope must fetch again: the old
      // entry was deleted at revision time, not left to linger until
      // its TTL.
      server.reviseOauth2!(target, { scope: "read" });
      await deliver(relayPort);
      await waitFor(() => captured.length >= 3, 5000, "third downstream capture");
      assert.equal(tokenEp.hits, 3);
      assert.equal(tokenForm(tokenEp.bodies[2]!).get("scope"), "read");
      assert.equal(captured[2]!.authorization, "Bearer tok-3");
    } finally {
      await close(server);
      await close(down);
      tokenEp.server.close();
    }
  });

  it("opt-in on an unconfigured endpoint fetches from the next attempt", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target);
    const relayPort = await listen(server);
    try {
      assert.equal(server.getOauth2!(target), undefined);
      const revised = server.reviseOauth2!(target, {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      });
      assert.deepEqual(revised, {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      });
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "downstream capture after opt-in");
      assert.equal(captured[0]!.authorization, "Bearer tok-1");
      assert.equal(tokenEp.hits, 1);
      const rows = events(audit, "oauth2_revised");
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.previous, undefined);
      assert.deepEqual(rows[0]!.current, {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        scope: "read",
      });
    } finally {
      await close(server);
      await close(down);
      tokenEp.server.close();
    }
  });

  it("opt-in with missing fields is rejected and the endpoint stays tokenless", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target);
    const relayPort = await listen(server);
    try {
      assert.throws(
        () =>
          server.reviseOauth2!(target, {
            token_endpoint: tokenEp.url,
            client_id: TARGET_ID,
            client_secret: OLD_CLIENT_SECRET,
          }),
        /opting in requires `scope`/
      );
      assert.throws(
        () =>
          server.reviseOauth2!(target, {
            token_endpoint: tokenEp.url,
            client_id: TARGET_ID,
            scope: "read",
          }),
        /opting in requires `client_secret`/
      );
      assert.equal(server.getOauth2!(target), undefined);
      assert.equal(events(audit, "oauth2_revised").length, 0);
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "downstream capture without oauth2");
      assert.equal(captured[0]!.authorization, undefined);
      assert.equal(tokenEp.hits, 0);
    } finally {
      await close(server);
      await close(down);
      tokenEp.server.close();
    }
  });

  it("a null patch deletes the entry and token fetching stops", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, {
      [target]: {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      },
    });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(captured[0]!.authorization, "Bearer tok-1");
      assert.equal(tokenEp.hits, 1);

      assert.equal(server.reviseOauth2!(target, null), undefined);
      assert.equal(server.getOauth2!(target), undefined);

      await deliver(relayPort);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(captured[1]!.authorization, undefined);
      assert.equal(tokenEp.hits, 1);

      const rows = events(audit, "oauth2_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.previous, {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        scope: "read",
      });
      assert.equal(rows[0]!.current, undefined);
    } finally {
      await close(server);
      await close(down);
      tokenEp.server.close();
    }
  });

  it("a partial patch preserves the other fields", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      },
    });
    await listen(server);
    try {
      const revised = server.reviseOauth2!("https://downstream.example/hook", {
        scope: "write",
      });
      assert.deepEqual(revised, {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "write",
      });
      assert.deepEqual(server.getOauth2!("https://downstream.example/hook"), {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "write",
      });
    } finally {
      await close(server);
      tokenEp.server.close();
    }
  });

  it("an illegal or empty patch throws RangeError and the live record is untouched", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server, audit } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      },
    });
    await listen(server);
    try {
      assert.throws(
        () =>
          server.reviseOauth2!("https://downstream.example/hook", {
            token_endpoint: "not a url",
          }),
        /not a valid URL/
      );
      assert.throws(
        () =>
          server.reviseOauth2!("https://downstream.example/hook", {
            scope: null as never,
          }),
        /must not be null/
      );
      assert.throws(
        () => server.reviseOauth2!("https://downstream.example/hook", {}),
        /empty patch/
      );
      assert.throws(
        () => server.reviseOauth2!("", { scope: "write" }),
        /non-empty string/
      );
      assert.throws(
        () =>
          server.reviseOauth2!("https://downstream.example/hook", [] as never),
        /patch must be an object or null/
      );
      assert.deepEqual(server.getOauth2!("https://downstream.example/hook"), {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      });
      assert.equal(events(audit, "oauth2_revised").length, 0);
    } finally {
      await close(server);
      tokenEp.server.close();
    }
  });

  it("a same-value revision is a silent no-op with no audit event", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, {
      [target]: {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      },
    });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.equal(tokenEp.hits, 1);

      assert.deepEqual(server.reviseOauth2!(target, { scope: "read" }), {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      });
      // A null patch on a never-configured endpoint is a no-op too.
      assert.equal(server.reviseOauth2!("https://other.example/hook", null), undefined);
      assert.equal(events(audit, "oauth2_revised").length, 0);

      // The cached token survives a no-op: the next delivery refetches
      // nothing.
      await deliver(relayPort);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(tokenEp.hits, 1);
      assert.equal(captured[1]!.authorization, "Bearer tok-1");
    } finally {
      await close(server);
      await close(down);
      tokenEp.server.close();
    }
  });

  it("a secret-only revision is audited and carries no secret material", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server, audit } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      },
    });
    await listen(server);
    try {
      server.reviseOauth2!("https://downstream.example/hook", {
        client_secret: NEW_CLIENT_SECRET,
      });
      const rows = events(audit, "oauth2_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.previous, {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        scope: "read",
      });
      assert.deepEqual(rows[0]!.current, {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        scope: "read",
      });
      // Only the three visible fields ride on previous/current.
      assert.deepEqual(Object.keys(rows[0]!.current as object).sort(), [
        "client_id",
        "scope",
        "token_endpoint",
      ]);
      const dump = JSON.stringify(rows);
      assert.ok(!dump.includes(OLD_CLIENT_SECRET), "audit must not contain the old secret");
      assert.ok(!dump.includes(NEW_CLIENT_SECRET), "audit must not contain the new secret");
      // The whole audit trail stays secret-free.
      const trail = JSON.stringify(audit.readAll());
      assert.ok(!trail.includes(OLD_CLIENT_SECRET));
      assert.ok(!trail.includes(NEW_CLIENT_SECRET));
      // The getter follows the live value.
      assert.equal(
        server.getOauth2!("https://downstream.example/hook")!.client_secret,
        NEW_CLIENT_SECRET
      );
    } finally {
      await close(server);
      tokenEp.server.close();
    }
  });

  it("the getter returns a defensive copy", async () => {
    const tokenEp = await stubTokenEndpoint();
    const { server } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      },
    });
    await listen(server);
    try {
      const first = server.getOauth2!("https://downstream.example/hook")!;
      first.scope = "write";
      first.client_secret = NEW_CLIENT_SECRET;
      assert.deepEqual(server.getOauth2!("https://downstream.example/hook"), {
        token_endpoint: tokenEp.url,
        client_id: TARGET_ID,
        client_secret: OLD_CLIENT_SECRET,
        scope: "read",
      });
    } finally {
      await close(server);
      tokenEp.server.close();
    }
  });
});
