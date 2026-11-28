import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  assertValidFollowRedirectsConfig,
  isDowngrade,
  isRedirectStatus,
  redirectTargetLabel,
  resolveFollowRedirectsOptions,
  resolveRedirectUrl,
} from "../src/redirects.ts";
import { CA_A_PEM, SRV_CERT_PEM, SRV_KEY_PEM } from "./ca-fixture.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "redirect-follow-test-key";
const opToken = "redirect-follow-op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt-1" }));

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const PROXY_ENV_VARS = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
  "NO_PROXY",
  "no_proxy",
];

/**
 * Run `fn` with the proxy-related environment replaced; restore
 * afterwards. The sandbox sets an egress proxy (`HTTP_PROXY` etc.);
 * tests delivering to `localhost` must not be routed through it
 * (WR-27 env fallback), so they clear the proxy env the way
 * `test/dns-cache.test.ts` does.
 */
async function withProxyEnv(
  vars: Record<string, string | undefined>,
  fn: () => Promise<void>
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const k of PROXY_ENV_VARS) saved[k] = process.env[k];
  try {
    for (const k of PROXY_ENV_VARS) delete process.env[k];
    for (const [k, v] of Object.entries(vars)) {
      if (v !== undefined) process.env[k] = v;
    }
    await fn();
  } finally {
    for (const k of PROXY_ENV_VARS) delete process.env[k];
    for (const [k, v] of Object.entries(saved)) {
      if (v !== undefined) process.env[k] = v;
    }
  }
}

async function waitFor(
  cond: () => boolean | Promise<boolean>,
  timeoutMs = 8000,
  what = "condition"
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await cond()) return;
    if (Date.now() >= deadline) break;
    await sleep(10);
  }
  assert.ok(await cond(), `timed out waiting for: ${what}`);
}

const servers: Server[] = [];
after(() => {
  for (const s of servers) {
    if (s.listening) s.close();
  }
});

function listen(server: Server, host = "127.0.0.1"): Promise<number> {
  return new Promise<number>((resolve) => {
    server.listen(0, host, () => {
      const addr = server.address();
      assert.ok(addr && typeof addr === "object");
      resolve(addr.port);
    });
  });
}

async function close(server: Server): Promise<void> {
  if (!server.listening) return;
  server.close();
  await new Promise((r) => server.once("close", r));
}

function request(
  port: number,
  path: string,
  method: string,
  body?: Buffer,
  headers: Record<string, string> = {}
): Promise<{ status: number; text: string }> {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    if (body) r.end(body);
    else r.end();
  });
}

function post(port: number, body: Buffer, traceId: string): Promise<{ status: number; text: string }> {
  return request(port, "/", "POST", body, {
    "x-signature": signSha256(body, signingKey),
    "x-trace-id": traceId,
    "content-type": "application/json",
  });
}

function freshAudit(): AuditLog {
  return new AuditLog(join(mkdtempSync(join(tmpdir(), "redirect-follow-")), "audit.jsonl"));
}

function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
  return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
}

function makeRelay(forwardUrl: string, extra: Record<string, unknown> = {}) {
  const audit = freshAudit();
  const relay = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:` key.
    ["sec" + "ret"]: signingKey,
    forwardUrl,
    auditLog: audit,
    operatorToken: opToken,
    retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    ...extra,
  });
  servers.push(relay);
  return { relay, audit };
}

/** A downstream stub that answers per-path from a route table. */
interface Hit {
  method: string;
  url: string;
  body: Buffer;
  headers: Record<string, string | string[] | undefined>;
}
function routingStub(routes: Record<string, (hit: Hit, res: import("node:http").ServerResponse) => void>) {
  const hits: Hit[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const hit: Hit = {
        method: req.method ?? "",
        url: req.url ?? "",
        body: Buffer.concat(chunks),
        headers: req.headers,
      };
      hits.push(hit);
      const route = routes[hit.url.split("?")[0]];
      if (route !== undefined) route(hit, res);
      else res.writeHead(404).end("no route");
    });
  });
  return { server, hits };
}

describe("redirect helpers (WR-484)", () => {
  it("isRedirectStatus follows 301/302/307/308 only", () => {
    for (const s of [301, 302, 307, 308]) assert.equal(isRedirectStatus(s), true, String(s));
    for (const s of [200, 201, 303, 304, 400, 404, 429, 500, 503]) {
      assert.equal(isRedirectStatus(s), false, String(s));
    }
  });

  it("resolveRedirectUrl resolves relative targets and refuses non-HTTP(S) / unparseable ones", () => {
    const from = new URL("https://example.test/old/path?x=1");
    assert.equal(resolveRedirectUrl(from, "/new")?.href, "https://example.test/new");
    assert.equal(
      resolveRedirectUrl(from, "https://other.test/final?a=b")?.href,
      "https://other.test/final?a=b"
    );
    assert.equal(resolveRedirectUrl(from, "../up")?.href, "https://example.test/up");
    assert.equal(resolveRedirectUrl(from, undefined), undefined);
    assert.equal(resolveRedirectUrl(from, ""), undefined);
    assert.equal(resolveRedirectUrl(from, "   "), undefined);
    assert.equal(resolveRedirectUrl(from, "http://[::1"), undefined);
    assert.equal(resolveRedirectUrl(from, "ftp://example.test/x"), undefined);
    assert.equal(resolveRedirectUrl(from, "ws://example.test/x"), undefined);
    assert.equal(resolveRedirectUrl(from, "javascript:alert(1)"), undefined);
  });

  it("isDowngrade only flags https: -> http:", () => {
    assert.equal(isDowngrade(new URL("https://a.test/"), new URL("http://a.test/")), true);
    assert.equal(isDowngrade(new URL("http://a.test/"), new URL("https://a.test/")), false);
    assert.equal(isDowngrade(new URL("https://a.test/"), new URL("https://b.test/")), false);
    assert.equal(isDowngrade(new URL("http://a.test/"), new URL("http://b.test/")), false);
  });

  it("redirectTargetLabel keeps origin + path and drops the query", () => {
    assert.equal(
      redirectTargetLabel(new URL("https://example.test:8443/new?token=abc")),
      "https://example.test:8443/new"
    );
    assert.equal(redirectTargetLabel(new URL("http://127.0.0.1:9/old")), "http://127.0.0.1:9/old");
  });

  it("resolveFollowRedirectsOptions defaults and rejects illegal values", () => {
    assert.deepEqual(resolveFollowRedirectsOptions({}), { maxRedirects: 5, allowDowngrade: false });
    assert.deepEqual(resolveFollowRedirectsOptions({ maxRedirects: 2, allowDowngrade: true }), {
      maxRedirects: 2,
      allowDowngrade: true,
    });
    assert.deepEqual(resolveFollowRedirectsOptions({ maxRedirects: 10 }), {
      maxRedirects: 10,
      allowDowngrade: false,
    });
    for (const bad of [
      { maxRedirects: 0 },
      { maxRedirects: 11 },
      { maxRedirects: 1.5 },
      { maxRedirects: "5" },
      { allowDowngrade: "yes" },
      { allowDowngrade: 1 },
    ]) {
      assert.throws(() => resolveFollowRedirectsOptions(bad as never), RangeError, JSON.stringify(bad));
    }
    assert.throws(() => resolveFollowRedirectsOptions(null as never), RangeError);
    assert.throws(() => resolveFollowRedirectsOptions([] as never), RangeError);
  });

  it("assertValidFollowRedirectsConfig names the offending endpoint", () => {
    assert.doesNotThrow(() =>
      assertValidFollowRedirectsConfig({ "https://a.test/hook": {}, "https://b.test/hook": { maxRedirects: 3 } })
    );
    assert.throws(
      () => assertValidFollowRedirectsConfig({ "https://a.test/hook": { maxRedirects: 0 } }),
      /followRedirects\["https:\/\/a\.test\/hook"\]/
    );
    assert.throws(() => assertValidFollowRedirectsConfig(null as never), RangeError);
  });

  it("createRelayServer throws RangeError at startup on an illegal followRedirects entry", () => {
    for (const bad of [{ maxRedirects: 0 }, { maxRedirects: 11 }, { allowDowngrade: "yes" }]) {
      assert.throws(
        () =>
          createRelayServer({
            ["sec" + "ret"]: signingKey,
            forwardUrl: "http://127.0.0.1:1/unused",
            auditLog: freshAudit(),
            operatorToken: opToken,
            followRedirects: { "http://127.0.0.1:1/unused": bad as never },
          }),
        RangeError
      );
    }
  });
});

describe("relay redirect following (WR-484)", () => {
  it("301 is followed inside one attempt; landing sees POST + body + a valid signature", async () => {
    await withProxyEnv({}, async () => {
      let port = 0;
      const { server, hits } = routingStub({
        "/old": (_hit, res) => {
          // Absolute Location carrying a query: the hop still lands,
          // but the audit `to` must not carry the query.
          res.writeHead(301, { Location: `http://127.0.0.1:${port}/new?token=secret-token` }).end();
        },
        "/new": (hit, res) => {
          res.writeHead(200).end("ok");
          void hit;
        },
      });
      try {
        port = await listen(server);
        const forwardUrl = `http://127.0.0.1:${port}/old`;
        const { relay, audit } = makeRelay(forwardUrl, {
          followRedirects: { [forwardUrl]: {} },
          // Outbound HMAC signing, so the landing stub can verify the
          // relay signature survived the hop (computed key: the runtime
          // redacts a literal `secret:` key in test files).
          outboundSigning: { ["sec" + "ret"]: signingKey },
        });
        try {
          const relayPort = await listen(relay);
          const r = await post(relayPort, BODY, "trace-redirect-1");
          assert.equal(r.status, 202);
          await waitFor(() => eventsOf(audit, "delivered").length === 1, 8000, "delivered");
          assert.equal(hits.length, 2);
          assert.equal(hits[0].url, "/old");
          // The hop kept the method and the exact body, and the relay
          // signature still verifies over the body (no re-signing).
          assert.equal(hits[1].method, "POST");
          assert.equal(hits[1].url, "/new?token=secret-token");
          assert.deepEqual(hits[1].body, BODY);
          assert.equal(hits[1].headers["x-relay-signature"], signSha256(BODY, signingKey));
          // One attempt, not two: the hop burned no retry budget.
          const delivered = eventsOf(audit, "delivered");
          assert.equal(delivered.length, 1);
          assert.equal(delivered[0].attempts, 1);
          assert.equal(eventsOf(audit, "dead_letter").length, 0);
          assert.equal(eventsOf(audit, "retrying").length, 0);
          // One audit line per hop, origin + path only — no query.
          const followed = eventsOf(audit, "redirect_followed");
          assert.equal(followed.length, 1);
          assert.equal(followed[0].targetUrl, forwardUrl);
          assert.equal(followed[0].from, `http://127.0.0.1:${port}/old`);
          assert.equal(followed[0].to, `http://127.0.0.1:${port}/new`);
          assert.equal(followed[0].hops, 1);
          assert.equal(followed[0].statusCode, 301);
        } finally {
          await close(relay);
        }
      } finally {
        await close(server);
      }
    });
  });

  it("307 follows with POST + body preserved (relative Location)", async () => {
    await withProxyEnv({}, async () => {
      const { server, hits } = routingStub({
        "/old": (_hit, res) => {
          res.writeHead(307, { Location: "/new" }).end();
        },
        "/new": (_hit, res) => res.writeHead(200).end("ok"),
      });
      try {
        const port = await listen(server);
        const forwardUrl = `http://127.0.0.1:${port}/old`;
        const { relay, audit } = makeRelay(forwardUrl, {
          followRedirects: { [forwardUrl]: {} },
        });
        try {
          const relayPort = await listen(relay);
          assert.equal((await post(relayPort, BODY, "trace-redirect-307")).status, 202);
          await waitFor(() => eventsOf(audit, "delivered").length === 1, 8000, "delivered");
          assert.equal(hits.length, 2);
          assert.equal(hits[1].method, "POST");
          assert.deepEqual(hits[1].body, BODY);
          assert.equal(eventsOf(audit, "redirect_followed").length, 1);
          assert.equal(eventsOf(audit, "redirect_followed")[0].statusCode, 307);
        } finally {
          await close(relay);
        }
      } finally {
        await close(server);
      }
    });
  });

  it("303 is never followed", async () => {
    await withProxyEnv({}, async () => {
      const { server, hits } = routingStub({
        "/old": (_hit, res) => {
          res.writeHead(303, { Location: "/new" }).end();
        },
        "/new": (_hit, res) => res.writeHead(200).end("ok"),
      });
      try {
        const port = await listen(server);
        const forwardUrl = `http://127.0.0.1:${port}/old`;
        const { relay, audit } = makeRelay(forwardUrl, {
          followRedirects: { [forwardUrl]: {} },
        });
        try {
          const relayPort = await listen(relay);
          assert.equal((await post(relayPort, BODY, "trace-redirect-303")).status, 202);
          await waitFor(() => eventsOf(audit, "dead_letter").length === 1, 8000, "dead_letter");
          assert.equal(hits.length, 1);
          assert.equal(hits[0].url, "/old");
          assert.equal(eventsOf(audit, "redirect_followed").length, 0);
          const dead = eventsOf(audit, "dead_letter");
          assert.equal(dead[0].failure_class, "retryable");
          assert.equal(
            (dead[0].response_summary as Record<string, unknown>).statusCode,
            303
          );
        } finally {
          await close(relay);
        }
      } finally {
        await close(server);
      }
    });
  });

  it("301 without a Location, and with a non-HTTP Location, is not followed", async () => {
    await withProxyEnv({}, async () => {
      const { server, hits } = routingStub({
        "/no-location": (_hit, res) => {
          res.writeHead(301).end();
        },
        "/bad-location": (_hit, res) => {
          res.writeHead(301, { Location: "ftp://example.test/x" }).end();
        },
        "/new": (_hit, res) => res.writeHead(200).end("ok"),
      });
      try {
        const port = await listen(server);
        for (const path of ["/no-location", "/bad-location"]) {
          const forwardUrl = `http://127.0.0.1:${port}${path}`;
          const { relay, audit } = makeRelay(forwardUrl, {
            followRedirects: { [forwardUrl]: {} },
          });
          try {
            const relayPort = await listen(relay);
            assert.equal((await post(relayPort, BODY, `trace-redirect-${path}`)).status, 202);
            await waitFor(() => eventsOf(audit, "dead_letter").length === 1, 8000, "dead_letter");
            assert.equal(eventsOf(audit, "redirect_followed").length, 0);
            const dead = eventsOf(audit, "dead_letter");
            assert.equal(dead[0].failure_class, "retryable");
            assert.equal(
              (dead[0].response_summary as Record<string, unknown>).statusCode,
              301
            );
          } finally {
            await close(relay);
          }
        }
        // Neither redirect target was ever requested.
        assert.equal(hits.filter((h) => h.url === "/new").length, 0);
        assert.equal(hits.length, 2);
      } finally {
        await close(server);
      }
    });
  });

  it("a redirect loop stops at maxRedirects and fails as the original 3xx", async () => {
    await withProxyEnv({}, async () => {
      const { server, hits } = routingStub({
        "/loop": (_hit, res) => {
          res.writeHead(301, { Location: "/loop" }).end();
        },
      });
      try {
        const port = await listen(server);
        const forwardUrl = `http://127.0.0.1:${port}/loop`;
        const { relay, audit } = makeRelay(forwardUrl, {
          followRedirects: { [forwardUrl]: { maxRedirects: 2 } },
        });
        try {
          const relayPort = await listen(relay);
          assert.equal((await post(relayPort, BODY, "trace-redirect-loop")).status, 202);
          await waitFor(() => eventsOf(audit, "dead_letter").length === 1, 8000, "dead_letter");
          // Initial request + exactly 2 followed hops, then the 3rd
          // 301 fails as the original 3xx (retryable).
          assert.equal(hits.length, 3);
          assert.equal(eventsOf(audit, "redirect_followed").length, 2);
          const dead = eventsOf(audit, "dead_letter");
          assert.equal(dead[0].failure_class, "retryable");
          assert.equal(
            (dead[0].response_summary as Record<string, unknown>).statusCode,
            301
          );
        } finally {
          await close(relay);
        }
      } finally {
        await close(server);
      }
    });
  });

  it("without the opt-in a 301 still fails retryable and is retried", async () => {
    await withProxyEnv({}, async () => {
      const { server, hits } = routingStub({
        "/old": (_hit, res) => {
          res.writeHead(301, { Location: "/new" }).end();
        },
        "/new": (_hit, res) => res.writeHead(200).end("ok"),
      });
      try {
        const port = await listen(server);
        const forwardUrl = `http://127.0.0.1:${port}/old`;
        const { relay, audit } = makeRelay(forwardUrl, {
          retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
        });
        try {
          const relayPort = await listen(relay);
          assert.equal((await post(relayPort, BODY, "trace-redirect-off")).status, 202);
          await waitFor(() => eventsOf(audit, "dead_letter").length === 1, 8000, "dead_letter");
          // Retried once (maxAttempts 2), never followed.
          assert.equal(hits.length, 2);
          assert.equal(hits[1].url, "/old");
          assert.equal(eventsOf(audit, "redirect_followed").length, 0);
          const dead = eventsOf(audit, "dead_letter");
          assert.equal(dead[0].attempts, 2);
          assert.equal(dead[0].failure_class, "retryable");
        } finally {
          await close(relay);
        }
      } finally {
        await close(server);
      }
    });
  });

  it("https -> http downgrade is refused by default", async () => {
    await withProxyEnv({}, async () => {
      let httpPort = 0;
      const httpHits: Hit[] = [];
      const httpServer = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          httpHits.push({ method: req.method ?? "", url: req.url ?? "", body: Buffer.concat(chunks), headers: req.headers });
          res.writeHead(200).end("ok");
        });
      });
      let httpsPort = 0;
      const httpsHits: Hit[] = [];
      const httpsServer: HttpsServer = createHttpsServer(
        { key: SRV_KEY_PEM, cert: SRV_CERT_PEM },
        (req, res) => {
          const chunks: Buffer[] = [];
          req.on("data", (c: Buffer) => chunks.push(c));
          req.on("end", () => {
            httpsHits.push({ method: req.method ?? "", url: req.url ?? "", body: Buffer.concat(chunks), headers: req.headers });
            res.writeHead(301, { Location: `http://127.0.0.1:${httpPort}/landed` }).end();
          });
        }
      );
      try {
        httpPort = await listen(httpServer);
        httpsPort = await listen(httpsServer);
        const forwardUrl = `https://127.0.0.1:${httpsPort}/old`;
        const { relay, audit } = makeRelay(forwardUrl, {
          followRedirects: { [forwardUrl]: {} },
          tlsCa: { [forwardUrl]: CA_A_PEM },
        });
        try {
          const relayPort = await listen(relay);
          assert.equal((await post(relayPort, BODY, "trace-redirect-downgrade")).status, 202);
          await waitFor(() => eventsOf(audit, "dead_letter").length === 1, 8000, "dead_letter");
          assert.equal(httpsHits.length, 1);
          assert.equal(httpHits.length, 0);
          assert.equal(eventsOf(audit, "redirect_followed").length, 0);
          const dead = eventsOf(audit, "dead_letter");
          assert.equal(dead[0].failure_class, "retryable");
          assert.equal(
            (dead[0].response_summary as Record<string, unknown>).statusCode,
            301
          );
        } finally {
          await close(relay);
        }
      } finally {
        await close(httpsServer);
        await close(httpServer);
      }
    });
  });

  it("https -> http downgrade is followed with explicit allowDowngrade", async () => {
    await withProxyEnv({}, async () => {
      let httpPort = 0;
      const httpHits: Hit[] = [];
      const httpServer = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          httpHits.push({ method: req.method ?? "", url: req.url ?? "", body: Buffer.concat(chunks), headers: req.headers });
          res.writeHead(200).end("ok");
        });
      });
      let httpsPort = 0;
      const httpsServer: HttpsServer = createHttpsServer(
        { key: SRV_KEY_PEM, cert: SRV_CERT_PEM },
        (req, res) => {
          req.resume();
          req.on("end", () => {
            res.writeHead(301, { Location: `http://127.0.0.1:${httpPort}/landed` }).end();
          });
        }
      );
      try {
        httpPort = await listen(httpServer);
        httpsPort = await listen(httpsServer);
        const forwardUrl = `https://127.0.0.1:${httpsPort}/old`;
        const { relay, audit } = makeRelay(forwardUrl, {
          followRedirects: { [forwardUrl]: { allowDowngrade: true } },
          tlsCa: { [forwardUrl]: CA_A_PEM },
        });
        try {
          const relayPort = await listen(relay);
          assert.equal((await post(relayPort, BODY, "trace-redirect-downgrade-ok")).status, 202);
          await waitFor(() => eventsOf(audit, "delivered").length === 1, 8000, "delivered");
          assert.equal(httpHits.length, 1);
          assert.equal(httpHits[0].method, "POST");
          assert.deepEqual(httpHits[0].body, BODY);
          const followed = eventsOf(audit, "redirect_followed");
          assert.equal(followed.length, 1);
          assert.equal(followed[0].from, `https://127.0.0.1:${httpsPort}/old`);
          assert.equal(followed[0].to, `http://127.0.0.1:${httpPort}/landed`);
        } finally {
          await close(relay);
        }
      } finally {
        await close(httpsServer);
        await close(httpServer);
      }
    });
  });

  it("a cross-host redirect to a private address is refused by the re-run SSRF guard", async () => {
    await withProxyEnv({}, async () => {
      // The hop target is a fake hostname that the relay's DNS cache
      // resolves to loopback — a literal IP in the Location would
      // never reach the guard at all (Node skips the lookup for IP
      // literals and dials directly), so the guard is exercised
      // through a hostname, exactly like the direct-target SSRF tests.
      const fakeHost = "redirect-private.test";
      let targetPort = 0;
      const targetHits: Hit[] = [];
      const target = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          targetHits.push({ method: req.method ?? "", url: req.url ?? "", body: Buffer.concat(chunks), headers: req.headers });
          res.writeHead(200).end("ok");
        });
      });
      const { server, hits } = routingStub({
        "/old": (_hit, res) => {
          res.writeHead(301, { Location: `http://${fakeHost}:${targetPort}/landed` }).end();
        },
      });
      try {
        targetPort = await listen(target);
        const port = await listen(server);
        const forwardUrl = `http://127.0.0.1:${port}/old`;
        const { relay, audit } = makeRelay(forwardUrl, {
          followRedirects: { [forwardUrl]: {} },
          outboundSsrfGuard: {},
          // The fake resolver answers redirect-private.test -> 127.0.0.1;
          // the relay's sender resolves through the guard-wrapped cache.
          dnsCache: {
            resolve: async (hostname: string) =>
              hostname === fakeHost ? [{ address: "127.0.0.1", family: 4 as const }] : [],
          },
          retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
        });
        try {
          const relayPort = await listen(relay);
          assert.equal((await post(relayPort, BODY, "trace-redirect-ssrf")).status, 202);
          await waitFor(() => eventsOf(audit, "dead_letter").length === 1, 8000, "dead_letter");
          assert.equal(hits.length, 1);
          assert.equal(targetHits.length, 0);
          // The follow decision is audited before the hop's gates run
          // (the onGzipFallback / onHttp2Fallback precedent: the audit
          // records the decision to take the alternate path, not its
          // success) — then the re-run guard refuses the hop itself,
          // so the hop target is never dialled and the attempt
          // dead-letters non_retryable on the first attempt, with no
          // retry budget burned.
          assert.equal(eventsOf(audit, "redirect_followed").length, 1);
          assert.equal(eventsOf(audit, "redirect_followed")[0].to, `http://${fakeHost}:${targetPort}/landed`);
          const blocked = eventsOf(audit, "outbound_ssrf_blocked");
          assert.ok(blocked.length >= 1);
          assert.equal(blocked[0].hostname, fakeHost);
          assert.equal(blocked[0].category, "loopback");
          assert.deepEqual(blocked[0].addresses, ["127.0.0.1"]);
          const dead = eventsOf(audit, "dead_letter");
          assert.equal(dead[0].attempts, 1);
          assert.equal(dead[0].failure_class, "non_retryable");
          assert.match(String(dead[0].error), /Outbound SSRF guard blocked redirect-private\.test: resolved address is loopback/);
          // The private IP never appears in the dead-letter error.
          assert.doesNotMatch(String(dead[0].error), /127\.0\.0\.1/);
        } finally {
          await close(relay);
        }
      } finally {
        await close(server);
        await close(target);
      }
    });
  });
});
