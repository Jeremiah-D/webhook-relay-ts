import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

const TEST_KEY = "tls-min-version-revision-key";
const BODY = Buffer.from(JSON.stringify({ event: "tls.min.version.revision" }));

function getJson(port: number, path: string, headers: Record<string, string>) {
  return new Promise<{ status: number; body: unknown; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let body: unknown = text;
        try {
          body = JSON.parse(text);
        } catch { /* plain text (e.g. /metrics) */ }
        resolve({ status: res.statusCode ?? 0, body, text });
      });
    });
    r.on("error", reject);
    r.end();
  });
}

function postSigned(port: number, headers: Record<string, string>) {
  return new Promise<{ status: number }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/hook",
        method: "POST",
        headers: { ...headers, "x-signature": signSha256(BODY, TEST_KEY) },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
      }
    );
    r.on("error", reject);
    r.end(BODY);
  });
}

async function waitFor<T>(fn: () => Promise<T>, pred: (v: T) => boolean, label: string): Promise<T> {
  let last: T | undefined;
  for (let i = 0; i < 200; i++) {
    last = await fn();
    if (pred(last)) return last;
    await new Promise((res) => setTimeout(res, 25));
  }
  assert.fail(`timed out waiting for ${label}: last=${JSON.stringify(last)}`);
}

describe("tls-min-version revision: live floor revision through the relay server (WR-343)", () => {
  let https: HttpsServer;
  let relay: Server;
  let relayPort: number;
  let forwardUrl: string;
  const OPERATOR = "op-tlsminrev-token";
  const auth = { authorization: `Bearer ${OPERATOR}` };
  let received = 0;

  before(async () => {
    // Downstream that negotiates at most TLS 1.2.
    https = createHttpsServer(
      { key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM, maxVersion: "TLSv1.2" },
      (req, res) => {
        req.on("data", () => {});
        req.on("end", () => {
          received += 1;
          res.writeHead(200).end("ok");
        });
      }
    );
    const downstreamPort = await new Promise<number>((resolve) =>
      https.listen(0, "127.0.0.1", () => {
        const addr = https.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      })
    );
    forwardUrl = `https://127.0.0.1:${downstreamPort}/hook`;
    const dir = mkdtempSync(join(tmpdir(), "audit-tlsminrev-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl,
      auditLog: audit,
      operatorToken: OPERATOR,
      // One attempt: the floor rejection is deterministic, no point
      // burning retry budget proving it twice.
      retry: { baseDelayMs: 5, maxDelayMs: 10, maxAttempts: 1 },
      // Pins stand in for chain verification (self-signed fixture).
      tlsPins: { [forwardUrl]: [TLS_FIXTURE_SPKI_PIN] },
      // The downstream negotiates TLS 1.2; the floor starts at 1.2.
      minTlsVersions: { [forwardUrl]: "1.2" },
    });
    relayPort = await new Promise<number>((resolve) =>
      relay.listen(0, "127.0.0.1", () => {
        const addr = relay.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      })
    );
  });

  after(() => {
    relay.close();
    https.close();
  });

  const auditEvents = async (event: string) =>
    (
      ((await getJson(relayPort, "/audit", auth)).body as { event: string }[]) ?? []
    ).filter((e) => e.event === event);
  const deadLetter = async () =>
    ((await getJson(relayPort, "/dead-letter", auth)).body as unknown[]) ?? [];

  it("starts at the construction floor: a TLS 1.2 downstream delivers under a 1.2 floor", async () => {
    assert.ok(relay.getTlsMinVersion);
    assert.equal(relay.getTlsMinVersion!(forwardUrl), "1.2");
    const r = await postSigned(relayPort, {});
    assert.equal(r.status, 202);
    await waitFor(async () => received, (n) => n === 1, "first delivery to land");
    assert.equal((await deadLetter()).length, 0);
  });

  it("tightening to 1.3 rejects the next handshake and audits the revision", async () => {
    const revised = relay.reviseTlsMinVersion(forwardUrl, "1.3");
    assert.equal(revised, "1.3");
    assert.equal(relay.getTlsMinVersion!(forwardUrl), "1.3");
    const r = await postSigned(relayPort, {});
    assert.equal(r.status, 202);
    const dead = await waitFor(deadLetter, (d) => d.length === 1, "tightened delivery to dead-letter");
    assert.match((dead[0] as { lastError: string }).lastError, /below the configured minimum/);
    // The downstream never saw the tightened request's body.
    assert.equal(received, 1);

    const events = await auditEvents("tls_min_version_revised");
    assert.equal(events.length, 1);
    assert.equal((events[0] as { endpoint: string }).endpoint, forwardUrl);
    assert.equal((events[0] as { previous: string }).previous, "1.2");
    assert.equal((events[0] as { current: string }).current, "1.3");
  });

  it("an illegal floor is rejected and the live floor is untouched", async () => {
    const before = await auditEvents("tls_min_version_revised");
    assert.throws(() => relay.reviseTlsMinVersion(forwardUrl, "1.0" as "1.2"), RangeError);
    assert.throws(() => relay.reviseTlsMinVersion(forwardUrl, "TLSv1.3" as "1.3"), RangeError);
    assert.equal(relay.getTlsMinVersion!(forwardUrl), "1.3");
    const after = await auditEvents("tls_min_version_revised");
    assert.equal(after.length, before.length);
  });

  it("a same-value revision is a silent no-op", async () => {
    const before = await auditEvents("tls_min_version_revised");
    assert.equal(relay.reviseTlsMinVersion(forwardUrl, "1.3"), "1.3");
    assert.equal(relay.getTlsMinVersion!(forwardUrl), "1.3");
    const after = await auditEvents("tls_min_version_revised");
    assert.equal(after.length, before.length);
  });

  it("loosening to 1.2 lets a TLS 1.2 handshake through again", async () => {
    assert.equal(relay.reviseTlsMinVersion(forwardUrl, "1.2"), "1.2");
    const r = await postSigned(relayPort, {});
    assert.equal(r.status, 202);
    await waitFor(async () => received, (n) => n === 2, "loosened delivery to land");
    // The earlier dead-letter is still there; no new one appeared.
    assert.equal((await deadLetter()).length, 1);
    const events = await auditEvents("tls_min_version_revised");
    assert.equal(events.length, 2);
    assert.equal((events[1] as { previous: string }).previous, "1.3");
    assert.equal((events[1] as { current: string }).current, "1.2");
  });

  it("a first set on an endpoint without a floor records no previous floor", async () => {
    const other = `${forwardUrl}/other`;
    assert.equal(relay.getTlsMinVersion!(other), undefined);
    assert.equal(relay.reviseTlsMinVersion(other, "1.3"), "1.3");
    assert.equal(relay.getTlsMinVersion!(other), "1.3");
    const events = await auditEvents("tls_min_version_revised");
    assert.equal(events.length, 3);
    assert.equal((events[2] as { endpoint: string }).endpoint, other);
    assert.equal((events[2] as { previous: string | undefined }).previous, undefined);
    assert.equal((events[2] as { current: string }).current, "1.3");
    // Clean up so the removal test below sees only the forwardUrl floor.
    assert.equal(relay.removeTlsMinVersion(other), true);
    assert.equal(relay.getTlsMinVersion!(other), undefined);
  });

  it("removing the floor falls back to unlimited and a second removal is a silent false", async () => {
    assert.equal(relay.removeTlsMinVersion(forwardUrl), true);
    assert.equal(relay.getTlsMinVersion!(forwardUrl), undefined);
    const r = await postSigned(relayPort, {});
    assert.equal(r.status, 202);
    await waitFor(async () => received, (n) => n === 3, "post-removal delivery to land");
    const dl = await deadLetter();
    assert.equal(dl.length, 1);

    // One `tls_min_version_removed` event already exists for the
    // first-set endpoint from the previous test — filter by endpoint.
    const removed = (await auditEvents("tls_min_version_removed")).filter(
      (e) => (e as { endpoint: string }).endpoint === forwardUrl
    );
    assert.equal(removed.length, 1);
    assert.equal((removed[0] as { previous: string }).previous, "1.2");
    assert.equal(relay.removeTlsMinVersion(forwardUrl), false);
    assert.equal(
      (await auditEvents("tls_min_version_removed")).filter(
        (e) => (e as { endpoint: string }).endpoint === forwardUrl
      ).length,
      1
    );
  });
});

describe("tls-min-version revision: unconfigured relay (WR-343)", () => {
  let relay: Server;
  let relayPort: number;

  before(async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-tlsminrev-unconf-"));
    relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl: "https://127.0.0.1:1/hook",
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: "op-tlsminrev-unconf",
    });
    relayPort = await new Promise<number>((resolve) =>
      relay.listen(0, "127.0.0.1", () => {
        const addr = relay.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      })
    );
  });

  after(() => {
    relay.close();
  });

  it("revising without configured floors throws the must-restart Error", () => {
    assert.throws(
      () => relay.reviseTlsMinVersion("https://127.0.0.1:1/hook", "1.3"),
      /TLS minimum versions are not configured — enabling them requires a restart/
    );
  });

  it("the getter is not mounted and removal reports nothing to remove", () => {
    assert.equal(relay.getTlsMinVersion, undefined);
    assert.equal(relay.removeTlsMinVersion("https://127.0.0.1:1/hook"), false);
  });
});
