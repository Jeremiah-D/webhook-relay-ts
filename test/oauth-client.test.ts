import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OAUTH2_CLOCK_SKEW_MS,
  OAUTH2_DEFAULT_EXPIRES_IN_MS,
  OAuth2TokenCache,
  OAuth2TokenError,
  defaultOAuth2TokenFetcher,
  resolveOAuth2ClientConfig,
  type OAuth2ClientCredentialsConfig,
  type OAuth2TokenFetchParams,
  type OAuth2TokenResponse,
} from "../src/oauth-client.ts";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import type { RetryItem } from "../src/retry.ts";

const clientSecret = "oauth-test-secret";
const cfgBase: OAuth2ClientCredentialsConfig = {
  token_endpoint: "https://auth.example.test/token",
  client_id: "relay-client",
  client_secret: clientSecret,
};

/** Manual clock for deterministic cache tests. */
function manualClock(startMs = 1_000_000) {
  let now = startMs;
  return {
    nowMs: () => now,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

function stubFetcher(
  responses: OAuth2TokenResponse[],
  seen: OAuth2TokenFetchParams[] = []
): OAuth2TokenCache["fetchToken"] & { calls: OAuth2TokenFetchParams[] } {
  let n = 0;
  const fn = async (params: OAuth2TokenFetchParams): Promise<OAuth2TokenResponse> => {
    seen.push(params);
    const resp = responses[Math.min(n, responses.length - 1)];
    n += 1;
    return resp;
  };
  return Object.assign(fn, { calls: seen });
}

describe("resolveOAuth2ClientConfig", () => {
  it("resolves a valid config", () => {
    const r = resolveOAuth2ClientConfig(
      { ...cfgBase, scope: "webhooks:write" },
      "test"
    );
    assert.equal(r.tokenEndpoint.href, "https://auth.example.test/token");
    assert.equal(r.clientId, "relay-client");
    assert.equal(r.clientSecret, clientSecret);
    assert.equal(r.scope, "webhooks:write");
  });
  it("rejects invalid configs with RangeError", () => {
    const bad: Array<[string, unknown]> = [
      ["empty token_endpoint", { ...cfgBase, token_endpoint: "" }],
      ["bad URL", { ...cfgBase, token_endpoint: "not a url" }],
      ["non-http protocol", { ...cfgBase, token_endpoint: "ftp://x.test/t" }],
      ["empty client_id", { ...cfgBase, client_id: "" }],
      ["empty client_secret", { ...cfgBase, client_secret: "" }],
      ["empty scope", { ...cfgBase, scope: "  " }],
      ["non-object", "nope"],
      ["null", null],
    ];
    for (const [name, v] of bad) {
      assert.throws(
        () => resolveOAuth2ClientConfig(v as OAuth2ClientCredentialsConfig, "test"),
        RangeError,
        name
      );
    }
  });
});

describe("OAuth2TokenCache", () => {
  it("fetches once and serves from cache", async () => {
    const clock = manualClock();
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      nowMs: clock.nowMs,
      fetchToken: stubFetcher([{ access_token: "tok-a", expires_in: 3600 }], seen),
    });
    assert.equal(await cache.tokenFor(cfgBase), "tok-a");
    assert.equal(await cache.tokenFor(cfgBase), "tok-a");
    assert.equal(seen.length, 1);
    assert.equal(cache.size(), 1);
  });
  it("refetches after expires_in minus the 30s clock-skew reserve", async () => {
    const clock = manualClock();
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      nowMs: clock.nowMs,
      fetchToken: stubFetcher(
        [
          { access_token: "tok-old", expires_in: 3600 },
          { access_token: "tok-new", expires_in: 3600 },
        ],
        seen
      ),
    });
    assert.equal(await cache.tokenFor(cfgBase), "tok-old");
    // 3600s - 30s skew = 3570s of freshness.
    clock.advance(3569_000);
    assert.equal(await cache.tokenFor(cfgBase), "tok-old");
    clock.advance(2_000);
    assert.equal(await cache.tokenFor(cfgBase), "tok-new");
    assert.equal(seen.length, 2);
  });
  it("treats sub-skew TTLs as already expired", async () => {
    const clock = manualClock();
    const seen: OAuth2TokenFetchParams[] = [];
    let n = 0;
    const cache = new OAuth2TokenCache({
      nowMs: clock.nowMs,
      fetchToken: async () => {
        n += 1;
        seen.push({} as OAuth2TokenFetchParams);
        return { access_token: `tok-${n}`, expires_in: 10 };
      },
    });
    assert.equal(await cache.tokenFor(cfgBase), "tok-1");
    // expires_in 10s < 30s skew: every call refetches.
    assert.equal(await cache.tokenFor(cfgBase), "tok-2");
    assert.equal(seen.length, 2);
  });
  it("falls back to a default TTL when the endpoint omits expires_in", async () => {
    const clock = manualClock();
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      nowMs: clock.nowMs,
      fetchToken: stubFetcher(
        [{ access_token: "tok-1" }, { access_token: "tok-2" }],
        seen
      ),
    });
    assert.equal(await cache.tokenFor(cfgBase), "tok-1");
    clock.advance(OAUTH2_DEFAULT_EXPIRES_IN_MS - OAUTH2_CLOCK_SKEW_MS - 1000);
    assert.equal(await cache.tokenFor(cfgBase), "tok-1");
    clock.advance(2000);
    assert.equal(await cache.tokenFor(cfgBase), "tok-2");
  });
  it("isolates per (token_endpoint, scope)", async () => {
    const clock = manualClock();
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      nowMs: clock.nowMs,
      fetchToken: stubFetcher(
        [
          { access_token: "tok-scope-a", expires_in: 3600 },
          { access_token: "tok-scope-b", expires_in: 3600 },
          { access_token: "tok-other-ep", expires_in: 3600 },
        ],
        seen
      ),
    });
    const a = { ...cfgBase, scope: "a" };
    const b = { ...cfgBase, scope: "b" };
    const other = { ...cfgBase, token_endpoint: "https://other.example.test/t" };
    assert.equal(await cache.tokenFor(a), "tok-scope-a");
    assert.equal(await cache.tokenFor(b), "tok-scope-b");
    assert.equal(await cache.tokenFor(other), "tok-other-ep");
    // And the first scope is still cached — no cross-contamination.
    assert.equal(await cache.tokenFor(a), "tok-scope-a");
    assert.equal(seen.length, 3);
    assert.equal(cache.size(), 3);
  });
  it("single-flights concurrent fetches", async () => {
    const clock = manualClock();
    let calls = 0;
    const cache = new OAuth2TokenCache({
      nowMs: clock.nowMs,
      fetchToken: async () => {
        calls += 1;
        await new Promise((r) => setTimeout(r, 20));
        return { access_token: "tok-1", expires_in: 3600 };
      },
    });
    const [t1, t2, t3] = await Promise.all([
      cache.tokenFor(cfgBase),
      cache.tokenFor(cfgBase),
      cache.tokenFor(cfgBase),
    ]);
    assert.deepEqual([t1, t2, t3], ["tok-1", "tok-1", "tok-1"]);
    assert.equal(calls, 1);
  });
  it("refreshFor forces a refetch even when fresh", async () => {
    const clock = manualClock();
    const seen: OAuth2TokenFetchParams[] = [];
    const cache = new OAuth2TokenCache({
      nowMs: clock.nowMs,
      fetchToken: stubFetcher(
        [
          { access_token: "tok-1", expires_in: 3600 },
          { access_token: "tok-2", expires_in: 3600 },
        ],
        seen
      ),
    });
    assert.equal(await cache.tokenFor(cfgBase), "tok-1");
    assert.equal(await cache.refreshFor(cfgBase), "tok-2");
    assert.equal(await cache.tokenFor(cfgBase), "tok-2");
    assert.equal(seen.length, 2);
  });
  it("does not cache fetch failures; the next call retries", async () => {
    const clock = manualClock();
    let calls = 0;
    const cache = new OAuth2TokenCache({
      nowMs: clock.nowMs,
      fetchToken: async () => {
        calls += 1;
        if (calls === 1) throw new OAuth2TokenError("boom");
        return { access_token: "tok-ok", expires_in: 3600 };
      },
    });
    await assert.rejects(() => cache.tokenFor(cfgBase), OAuth2TokenError);
    assert.equal(await cache.tokenFor(cfgBase), "tok-ok");
    assert.equal(calls, 2);
    assert.equal(cache.size(), 1);
  });
  it("rejects invalid config and bad timeouts with RangeError", async () => {
    const cache = new OAuth2TokenCache({ fetchToken: async () => ({ access_token: "x" }) });
    await assert.rejects(
      () => cache.tokenFor({ ...cfgBase, client_secret: "" }),
      RangeError
    );
    assert.throws(() => new OAuth2TokenCache({ tokenRequestTimeoutMs: 0 }), RangeError);
    assert.throws(() => new OAuth2TokenCache({ tokenRequestTimeoutMs: -5 }), RangeError);
  });
});

describe("defaultOAuth2TokenFetcher", () => {
  async function stubTokenEndpoint(
    handler: (body: string) => { status: number; json: unknown }
  ): Promise<{ server: Server; port: number; bodies: string[] }> {
    const bodies: string[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        bodies.push(body);
        const { status, json } = handler(body);
        res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(json));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return { server, port: addr.port, bodies };
  }

  it("posts the client_credentials grant form-encoded", async () => {
    const { server, port, bodies } = await stubTokenEndpoint(() => ({
      status: 200,
      json: { access_token: "tok-123", token_type: "Bearer", expires_in: 600 },
    }));
    try {
      const resp = await defaultOAuth2TokenFetcher({
        tokenEndpoint: new URL(`http://127.0.0.1:${port}/oauth/token`),
        clientId: "id-1",
        clientSecret: clientSecret,
        scope: "read write",
        timeoutMs: 5000,
      });
      assert.equal(resp.access_token, "tok-123");
      assert.equal(resp.expires_in, 600);
      const params = new URLSearchParams(bodies[0]);
      assert.equal(params.get("grant_type"), "client_credentials");
      assert.equal(params.get("client_id"), "id-1");
      assert.equal(params.get("client_secret"), clientSecret);
      assert.equal(params.get("scope"), "read write");
    } finally {
      server.close();
    }
  });

  it("maps endpoint failures to OAuth2TokenError without leaking the secret", async () => {
    const cases: Array<[string, (body: string) => { status: number; json: unknown }]> = [
      ["http 500", () => ({ status: 500, json: { error: "server_error" } })],
      ["http 401", () => ({ status: 401, json: { error: "invalid_client" } })],
      [
        "missing access_token",
        () => ({ status: 200, json: { token_type: "Bearer", expires_in: 60 } }),
      ],
      [
        "non-bearer token_type",
        () => ({ status: 200, json: { access_token: "x", token_type: "mac" } }),
      ],
      ["negative expires_in", () => ({ status: 200, json: { access_token: "x", expires_in: -1 } })],
    ];
    for (const [name, handler] of cases) {
      const { server, port } = await stubTokenEndpoint(handler);
      try {
        const err = await defaultOAuth2TokenFetcher({
          tokenEndpoint: new URL(`http://127.0.0.1:${port}/t`),
          clientId: "id-1",
          clientSecret: clientSecret,
          timeoutMs: 5000,
        }).then(
          () => null,
          (e) => e as Error
        );
        assert.ok(err instanceof OAuth2TokenError, `${name}: expected OAuth2TokenError`);
        assert.ok(
          !err.message.includes(clientSecret),
          `${name}: error must not leak the client_secret`
        );
      } finally {
        server.close();
      }
    }
  });

  it("rejects a non-JSON response", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" }).end("not json");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    try {
      await assert.rejects(
        () =>
          defaultOAuth2TokenFetcher({
            tokenEndpoint: new URL(`http://127.0.0.1:${port}/t`),
            clientId: "id-1",
            clientSecret: clientSecret,
            timeoutMs: 5000,
          }),
        OAuth2TokenError
      );
    } finally {
      server.close();
    }
  });
});

interface SeenDelivery {
  authorization: string | undefined;
  relaySignature: string | undefined;
}

/** Stub downstream: records deliveries, 401s when `reject` says so. */
async function stubDownstream(reject: (auth: string | undefined) => boolean): Promise<{
  server: Server;
  url: string;
  seen: SeenDelivery[];
}> {
  const seen: SeenDelivery[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const auth = req.headers["authorization"] as string | undefined;
      seen.push({
        authorization: auth,
        relaySignature: req.headers["x-relay-signature"] as string | undefined,
      });
      if (reject(auth)) {
        res.writeHead(401, { "content-type": "text/plain" }).end("unauthorized");
      } else {
        res.writeHead(200, { "content-type": "text/plain" }).end("ok");
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return { server, url: `http://127.0.0.1:${addr.port}/hook`, seen };
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

function makeSender(
  oauth2: Record<string, OAuth2ClientCredentialsConfig>,
  cache?: OAuth2TokenCache,
  outboundSigning?: { secret: string; keyId?: string }
) {
  const args = Array(33).fill(undefined) as Parameters<typeof createDefaultSender>;
  args[2] = outboundSigning;
  args[31] = oauth2;
  args[32] = cache;
  const sender = createDefaultSender(...args);
  return sender;
}

function deliveryItem(targetUrl: string, id: string, headers: Record<string, string> = {}): RetryItem {
  return { id, payload: Buffer.from(JSON.stringify({ n: id })), targetUrl, headers };
}

describe("createDefaultSender with oauth2", () => {
  it("stamps Bearer, refreshes once on 401, and caches afterwards", async () => {
    const tokenEp = await stubTokenEndpoint();
    const downstream = await stubDownstream((auth) => auth === "Bearer tok-1");
    try {
      const sender = makeSender({
        [downstream.url]: {
          token_endpoint: tokenEp.url,
          client_id: "relay",
          client_secret: clientSecret,
        },
      });
      try {
        const res = await sender(deliveryItem(downstream.url, "d1"));
        assert.equal(res?.statusCode, 200);
        // First attempt went out with tok-1 (401), the forced refresh
        // retried with tok-2 (200) — inside one delivery attempt.
        assert.equal(downstream.seen.length, 2);
        assert.equal(downstream.seen[0].authorization, "Bearer tok-1");
        assert.equal(downstream.seen[1].authorization, "Bearer tok-2");
        assert.equal(tokenEp.hits, 2);
        // The refreshed token is cached: the next delivery needs no fetch.
        const res2 = await sender(deliveryItem(downstream.url, "d2"));
        assert.equal(res2?.statusCode, 200);
        assert.equal(downstream.seen.length, 3);
        assert.equal(downstream.seen[2].authorization, "Bearer tok-2");
        assert.equal(tokenEp.hits, 2);
      } finally {
        sender.destroy();
      }
    } finally {
      tokenEp.server.close();
      downstream.server.close();
    }
  });

  it("strips a forged inbound authorization header", async () => {
    const tokenEp = await stubTokenEndpoint();
    const downstream = await stubDownstream(() => false);
    try {
      const sender = makeSender({
        [downstream.url]: {
          token_endpoint: tokenEp.url,
          client_id: "relay",
          client_secret: clientSecret,
        },
      });
      try {
        const res = await sender(
          deliveryItem(downstream.url, "d1", { authorization: "Bearer forged-by-sender" })
        );
        assert.equal(res?.statusCode, 200);
        assert.equal(downstream.seen.length, 1);
        assert.equal(downstream.seen[0].authorization, "Bearer tok-1");
      } finally {
        sender.destroy();
      }
    } finally {
      tokenEp.server.close();
      downstream.server.close();
    }
  });

  it("composes with the WR-26 HMAC outbound signature", async () => {
    const tokenEp = await stubTokenEndpoint();
    const downstream = await stubDownstream(() => false);
    try {
      const hmacSecret = "hmac-signing-secret";
      const sender = makeSender(
        {
          [downstream.url]: {
            token_endpoint: tokenEp.url,
            client_id: "relay",
            client_secret: clientSecret,
          },
        },
        undefined,
        { secret: hmacSecret, keyId: "k1" }
      );
      try {
        const item = deliveryItem(downstream.url, "d1");
        const res = await sender(item);
        assert.equal(res?.statusCode, 200);
        assert.equal(downstream.seen.length, 1);
        assert.equal(downstream.seen[0].authorization, "Bearer tok-1");
        assert.equal(downstream.seen[0].relaySignature, signSha256(item.payload, hmacSecret));
      } finally {
        sender.destroy();
      }
    } finally {
      tokenEp.server.close();
      downstream.server.close();
    }
  });

  it("leaves endpoints without an oauth2 entry untouched", async () => {
    const tokenEp = await stubTokenEndpoint();
    const downstream = await stubDownstream(() => false);
    try {
      const sender = makeSender({
        "http://other.example.test/hook": {
          token_endpoint: tokenEp.url,
          client_id: "relay",
          client_secret: clientSecret,
        },
      });
      try {
        const res = await sender(deliveryItem(downstream.url, "d1"));
        assert.equal(res?.statusCode, 200);
        assert.equal(downstream.seen[0].authorization, undefined);
        assert.equal(tokenEp.hits, 0);
      } finally {
        sender.destroy();
      }
    } finally {
      tokenEp.server.close();
      downstream.server.close();
    }
  });

  it("rejects invalid oauth2 configs at startup with RangeError", () => {
    const badConfigs: Array<[string, unknown]> = [
      ["empty token_endpoint", { "http://x.test/": { ...cfgBase, token_endpoint: "" } }],
      ["bad URL", { "http://x.test/": { ...cfgBase, token_endpoint: "://" } }],
      ["empty secret", { "http://x.test/": { ...cfgBase, client_secret: "" } }],
      ["non-object", "nope"],
    ];
    for (const [name, oauth2] of badConfigs) {
      assert.throws(
        () =>
          makeSender(oauth2 as Record<string, OAuth2ClientCredentialsConfig>),
        RangeError,
        name
      );
    }
  });
});

describe("createRelayServer oauth2 option", () => {
  it("fetches and stamps a bearer token end to end, secret never audited", async () => {
    const tokenEp = await stubTokenEndpoint();
    const downstream = await stubDownstream(() => false);
    const dir = mkdtempSync(join(tmpdir(), "oauth-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relaySecret = "relay-intake-secret";
    const relay = createRelayServer({
      secret: relaySecret,
      forwardUrl: downstream.url,
      auditLog: audit,
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      oauth2: {
        [downstream.url]: {
          token_endpoint: tokenEp.url,
          client_id: "relay",
          client_secret: clientSecret,
        },
      },
    });
    await new Promise<void>((r) => relay.listen(0, "127.0.0.1", r));
    const port = (relay.address() as { port: number }).port;
    try {
      const payload = Buffer.from(JSON.stringify({ hello: "oauth" }));
      const res = await new Promise<{ status: number }>((resolve, reject) => {
        const req = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: { "x-signature": signSha256(payload, relaySecret) },
          },
          (r) => {
            r.resume();
            r.on("end", () => resolve({ status: r.statusCode ?? 0 }));
          }
        );
        req.on("error", reject);
        req.end(payload);
      });
      assert.equal(res.status, 202);
      const deadline = Date.now() + 10000;
      while (downstream.seen.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(downstream.seen.length, 1);
      assert.equal(downstream.seen[0].authorization, "Bearer tok-1");
      assert.equal(tokenEp.hits, 1);
      // The client_secret lives in memory only: the audit trail must
      // never contain it.
      const auditText = JSON.stringify(audit.readAll());
      assert.ok(!auditText.includes(clientSecret), "audit log must not contain the client_secret");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      tokenEp.server.close();
      downstream.server.close();
    }
  });
});
