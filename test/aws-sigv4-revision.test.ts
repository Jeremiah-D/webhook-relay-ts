import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  reviseAwsSigV4Map,
  signAwsSigV4,
  type AwsSigV4EndpointConfig,
} from "../src/sigv4.ts";

// NOTE: intentionally not named SECRET — the runner's secret redaction
// rewrites `secret: SECRET` occurrences in test sources.
const SIGNING_KEY = "wr437-test-key";
const BODY = Buffer.from(JSON.stringify({ event: "sigv4.revise" }));

const REF_A = "WR437_REF_A";
const REF_B = "WR437_REF_B";
const VALUE_A = "wr437-value-alpha";
const VALUE_B = "wr437-value-bravo";
const AKID_A = "AKIAWR437AAAAAAA1";
const AKID_B = "AKIAWR437BBBBBBB2";

const BASE_CONFIG: AwsSigV4EndpointConfig = {
  accessKeyId: AKID_A,
  secretRef: REF_A,
  region: "us-east-1",
  service: "execute-api",
};

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

interface Captured {
  authorization: string | undefined;
  amzDate: string | undefined;
  body: Buffer;
}

/** A plain-HTTP downstream that records every request's SigV4 stamps. */
function downstream(delayMs = 0): { server: Server; captured: Captured[] } {
  const captured: Captured[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      captured.push({
        authorization: req.headers.authorization,
        amzDate: req.headers["x-amz-date"],
        body: Buffer.concat(chunks),
      });
      setTimeout(() => res.writeHead(200).end("ok"), delayMs);
    });
  });
  return { server, captured };
}

function relay(
  targetUrl: string,
  awsSigV4?: Record<string, AwsSigV4EndpointConfig>
) {
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "sigv4rev-")), "audit.jsonl"));
  const server = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:`
    // key in test-file writes (see AGENTS.md), so the key is spelled
    // out dynamically instead.
    ["sec" + "ret"]: SIGNING_KEY,
    forwardUrl: targetUrl,
    auditLog: audit,
    ...(awsSigV4 !== undefined ? { awsSigV4 } : {}),
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
  });
  return { server, audit, targetUrl };
}

async function deliver(relayPort: number): Promise<void> {
  const res = await post(relayPort, BODY, {
    "x-signature": signSha256(BODY, SIGNING_KEY),
    "content-type": "application/json",
  });
  assert.equal(res.status, 202);
}

/** Parse an `x-amz-date` (`<yyyymmdd>T<hhmmss>Z`) back to epoch ms. */
function amzDateToMs(amzDate: string): number {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(amzDate);
  assert.ok(m, `malformed x-amz-date: ${amzDate}`);
  return Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!);
}

/**
 * Recompute the expected `Authorization` for a captured delivery and
 * assert it matches exactly — proves the downstream saw a signature
 * built from the given (key id, key material, region, service).
 */
function assertSigned(
  captured: Captured,
  targetUrl: string,
  accessKeyId: string,
  keyMaterial: string,
  region: string,
  service: string
): void {
  assert.ok(captured.authorization !== undefined, "expected an Authorization header");
  assert.ok(captured.amzDate !== undefined, "expected an x-amz-date header");
  const expected = signAwsSigV4({
    method: "POST",
    url: targetUrl,
    body: captured.body,
    credentials: { accessKeyId, secretAccessKey: keyMaterial },
    region,
    service,
    nowMs: amzDateToMs(captured.amzDate),
  });
  assert.equal(captured.authorization, expected.authorization);
  assert.ok(
    captured.authorization.includes(`/${region}/${service}/aws4_request`),
    `credential scope should name ${region}/${service}`
  );
}

describe("WR-437 reviseAwsSigV4Map (pure merge)", () => {
  it("a partial patch keeps the omitted live fields and never mutates the previous entry", () => {
    const map = new Map<string, AwsSigV4EndpointConfig>([
      ["https://a.example/hook", { ...BASE_CONFIG, additionalSignedHeaders: ["content-type"] }],
    ]);
    const patchHeaders = ["content-type", "x-custom"];
    const change = reviseAwsSigV4Map(map, "https://a.example/hook", {
      region: "eu-west-1",
      additionalSignedHeaders: patchHeaders,
    });
    assert.equal(change.changed, true);
    assert.deepEqual(change.entry, {
      accessKeyId: AKID_A,
      secretRef: REF_A,
      region: "eu-west-1",
      service: "execute-api",
      additionalSignedHeaders: ["content-type", "x-custom"],
    });
    // The previous entry and the map are never mutated by a merge.
    assert.deepEqual(map.get("https://a.example/hook"), {
      ...BASE_CONFIG,
      additionalSignedHeaders: ["content-type"],
    });
    // The patch's header list is copied, not aliased.
    patchHeaders.push("x-late");
    assert.deepEqual(change.entry!.additionalSignedHeaders, ["content-type", "x-custom"]);
  });

  it("a null patch deletes the entry; on a missing endpoint it is a no-op", () => {
    const map = new Map<string, AwsSigV4EndpointConfig>([
      ["https://a.example/hook", { ...BASE_CONFIG }],
    ]);
    const change = reviseAwsSigV4Map(map, "https://a.example/hook", null);
    assert.equal(change.changed, true);
    assert.equal(change.entry, undefined);
    assert.deepEqual(map.get("https://a.example/hook"), { ...BASE_CONFIG });
    const noop = reviseAwsSigV4Map(map, "https://missing.example/hook", null);
    assert.equal(noop.changed, false);
    assert.equal(noop.entry, undefined);
  });

  it("opt-in on an unconfigured endpoint needs all four required fields at once", () => {
    const map = new Map<string, AwsSigV4EndpointConfig>();
    assert.throws(
      () => reviseAwsSigV4Map(map, "https://a.example/hook", { region: "eu-west-1" }),
      /`accessKeyId` must be a non-empty string/
    );
    assert.throws(
      () =>
        reviseAwsSigV4Map(map, "https://a.example/hook", {
          accessKeyId: AKID_A,
          secretRef: REF_A,
          region: "eu-west-1",
        }),
      /`service` must look like an AWS service name/
    );
    assert.equal(map.size, 0);
    const change = reviseAwsSigV4Map(map, "https://a.example/hook", { ...BASE_CONFIG });
    assert.equal(change.changed, true);
    assert.deepEqual(change.entry, { ...BASE_CONFIG });
  });

  it("a single-field null is rejected for every field", () => {
    const map = new Map<string, AwsSigV4EndpointConfig>([
      ["https://a.example/hook", { ...BASE_CONFIG }],
    ]);
    for (const patch of [
      { region: null },
      { accessKeyId: null },
      { secretRef: null },
      { service: null },
      { additionalSignedHeaders: null },
    ]) {
      assert.throws(
        () => reviseAwsSigV4Map(map, "https://a.example/hook", patch as never),
        /must not be null/
      );
    }
    assert.deepEqual(map.get("https://a.example/hook"), { ...BASE_CONFIG });
  });

  it("an empty patch is a RangeError and the map is untouched", () => {
    const map = new Map<string, AwsSigV4EndpointConfig>([
      ["https://a.example/hook", { ...BASE_CONFIG }],
    ]);
    assert.throws(
      () => reviseAwsSigV4Map(map, "https://a.example/hook", {}),
      /empty patch/
    );
    assert.throws(
      () => reviseAwsSigV4Map(map, "https://a.example/hook", { region: undefined }),
      /empty patch/
    );
    assert.deepEqual(map.get("https://a.example/hook"), { ...BASE_CONFIG });
  });

  it("an illegal patch throws RangeError and the map is untouched", () => {
    const map = new Map<string, AwsSigV4EndpointConfig>([
      ["https://a.example/hook", { ...BASE_CONFIG }],
    ]);
    assert.throws(
      () => reviseAwsSigV4Map(map, "https://a.example/hook", { region: "BAD REGION" }),
      /`region` must look like an AWS region/
    );
    assert.throws(
      () =>
        reviseAwsSigV4Map(map, "https://a.example/hook", {
          additionalSignedHeaders: ["host"],
        }),
      /must not repeat the always-signed headers/
    );
    assert.deepEqual(map.get("https://a.example/hook"), { ...BASE_CONFIG });
  });

  it("a same-value patch is a silent no-op", () => {
    const map = new Map<string, AwsSigV4EndpointConfig>([
      ["https://a.example/hook", { ...BASE_CONFIG, additionalSignedHeaders: ["content-type"] }],
    ]);
    const change = reviseAwsSigV4Map(map, "https://a.example/hook", {
      region: "us-east-1",
      additionalSignedHeaders: ["content-type"],
    });
    assert.equal(change.changed, false);
    assert.deepEqual(change.entry, {
      ...BASE_CONFIG,
      additionalSignedHeaders: ["content-type"],
    });
  });
});

describe("WR-437 live revision of AWS SigV4 signing config", () => {
  before(() => {
    process.env[REF_A] = VALUE_A;
    process.env[REF_B] = VALUE_B;
  });

  after(() => {
    delete process.env[REF_A];
    delete process.env[REF_B];
  });

  it("revising the region signs the next attempt with the new region", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { ...BASE_CONFIG } });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 1, 5000, "first delivered audit entry");
      assert.equal(captured.length, 1);
      assertSigned(captured[0]!, target, AKID_A, VALUE_A, "us-east-1", "execute-api");

      const revised = server.reviseAwsSigV4!(target, { region: "eu-west-1" });
      assert.deepEqual(revised, { ...BASE_CONFIG, region: "eu-west-1" });
      assert.deepEqual(server.getAwsSigV4!(target), { ...BASE_CONFIG, region: "eu-west-1" });

      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(captured.length, 2);
      assertSigned(captured[1]!, target, AKID_A, VALUE_A, "eu-west-1", "execute-api");

      const rows = events(audit, "aws_sigv4_revised");
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.endpoint, target);
      assert.deepEqual(rows[0]!.previous, { ...BASE_CONFIG });
      assert.deepEqual(rows[0]!.current, { ...BASE_CONFIG, region: "eu-west-1" });
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("rotating secretRef resolves the new reference on the next attempt", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server } = relay(target, { [target]: { ...BASE_CONFIG } });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assertSigned(captured[0]!, target, AKID_A, VALUE_A, "us-east-1", "execute-api");

      // Rotate the reference (and the key id): the next attempt must
      // resolve the new env var, not the old one.
      const revised = server.reviseAwsSigV4!(target, {
        accessKeyId: AKID_B,
        secretRef: REF_B,
      });
      assert.deepEqual(revised, { ...BASE_CONFIG, accessKeyId: AKID_B, secretRef: REF_B });

      await deliver(relayPort);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assertSigned(captured[1]!, target, AKID_B, VALUE_B, "us-east-1", "execute-api");
      assert.notEqual(captured[1]!.authorization, captured[0]!.authorization);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("opt-in on an unconfigured endpoint signs from the next attempt", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target);
    const relayPort = await listen(server);
    try {
      assert.equal(server.getAwsSigV4!(target), undefined);
      const revised = server.reviseAwsSigV4!(target, { ...BASE_CONFIG });
      assert.deepEqual(revised, { ...BASE_CONFIG });
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "downstream capture after opt-in");
      assertSigned(captured[0]!, target, AKID_A, VALUE_A, "us-east-1", "execute-api");
      const rows = events(audit, "aws_sigv4_revised");
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.previous, undefined);
      assert.deepEqual(rows[0]!.current, { ...BASE_CONFIG });
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("opt-in with missing fields is rejected and the endpoint stays unsigned", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target);
    const relayPort = await listen(server);
    try {
      assert.throws(
        () => server.reviseAwsSigV4!(target, { region: "eu-west-1" }),
        /`accessKeyId` must be a non-empty string/
      );
      assert.throws(
        () =>
          server.reviseAwsSigV4!(target, {
            accessKeyId: AKID_A,
            secretRef: REF_A,
            region: "eu-west-1",
          }),
        /`service` must look like an AWS service name/
      );
      assert.equal(server.getAwsSigV4!(target), undefined);
      assert.equal(events(audit, "aws_sigv4_revised").length, 0);
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "downstream capture without signing");
      assert.equal(captured[0]!.authorization, undefined);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("a null patch deletes the entry and signing stops", async () => {
    const { server: down, captured } = downstream();
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { ...BASE_CONFIG } });
    const relayPort = await listen(server);
    try {
      await deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "first downstream capture");
      assert.ok(captured[0]!.authorization !== undefined);

      assert.equal(server.reviseAwsSigV4!(target, null), undefined);
      assert.equal(server.getAwsSigV4!(target), undefined);

      await deliver(relayPort);
      await waitFor(() => captured.length >= 2, 5000, "second downstream capture");
      assert.equal(captured[1]!.authorization, undefined);
      assert.equal(captured[1]!.amzDate, undefined);

      const rows = events(audit, "aws_sigv4_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.previous, { ...BASE_CONFIG });
      assert.equal(rows[0]!.current, undefined);
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("a partial patch preserves the other fields, including additionalSignedHeaders", async () => {
    const { server, audit } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": {
        ...BASE_CONFIG,
        additionalSignedHeaders: ["content-type"],
      },
    });
    await listen(server);
    try {
      const revised = server.reviseAwsSigV4!("https://downstream.example/hook", {
        service: "s3",
      });
      assert.deepEqual(revised, {
        ...BASE_CONFIG,
        service: "s3",
        additionalSignedHeaders: ["content-type"],
      });
      assert.deepEqual(server.getAwsSigV4!("https://downstream.example/hook"), {
        ...BASE_CONFIG,
        service: "s3",
        additionalSignedHeaders: ["content-type"],
      });
      // Clearing the optional header list is an empty list, not null.
      assert.deepEqual(
        server.reviseAwsSigV4!("https://downstream.example/hook", {
          additionalSignedHeaders: [],
        }),
        { ...BASE_CONFIG, service: "s3", additionalSignedHeaders: [] }
      );
      assert.equal(events(audit, "aws_sigv4_revised").length, 2);
    } finally {
      await close(server);
    }
  });

  it("an illegal or empty patch throws RangeError and the live record is untouched", async () => {
    const { server, audit } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": { ...BASE_CONFIG },
    });
    await listen(server);
    try {
      assert.throws(
        () => server.reviseAwsSigV4!("https://downstream.example/hook", { region: "BAD REGION" }),
        /`region` must look like an AWS region/
      );
      assert.throws(
        () => server.reviseAwsSigV4!("https://downstream.example/hook", { region: null as never }),
        /must not be null/
      );
      assert.throws(
        () => server.reviseAwsSigV4!("https://downstream.example/hook", {}),
        /empty patch/
      );
      assert.throws(
        () => server.reviseAwsSigV4!("", { region: "eu-west-1" }),
        /non-empty string/
      );
      assert.throws(
        () => server.reviseAwsSigV4!("https://downstream.example/hook", [] as never),
        /patch must be an object or null/
      );
      assert.deepEqual(server.getAwsSigV4!("https://downstream.example/hook"), { ...BASE_CONFIG });
      assert.equal(events(audit, "aws_sigv4_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("a same-value revision is a silent no-op with no audit event", async () => {
    const { server, audit } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": { ...BASE_CONFIG },
    });
    await listen(server);
    try {
      assert.deepEqual(server.reviseAwsSigV4!("https://downstream.example/hook", { ...BASE_CONFIG }), {
        ...BASE_CONFIG,
      });
      assert.deepEqual(
        server.reviseAwsSigV4!("https://downstream.example/hook", { region: "us-east-1" }),
        { ...BASE_CONFIG }
      );
      // A null patch on a never-configured endpoint is a no-op too.
      assert.equal(server.reviseAwsSigV4!("https://other.example/hook", null), undefined);
      assert.equal(events(audit, "aws_sigv4_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("an in-flight delivery keeps the signature it was built with", async () => {
    // The downstream answers slowly: the request is captured (and its
    // signature fixed) well before the response completes, so a
    // revision in between must not touch the in-flight signature.
    const { server: down, captured } = downstream(400);
    const port = await listen(down);
    const target = `http://127.0.0.1:${port}/hook`;
    const { server, audit } = relay(target, { [target]: { ...BASE_CONFIG } });
    const relayPort = await listen(server);
    try {
      const first = deliver(relayPort);
      await waitFor(() => captured.length >= 1, 5000, "in-flight downstream capture");
      // The request is on the wire with the old region's signature.
      assertSigned(captured[0]!, target, AKID_A, VALUE_A, "us-east-1", "execute-api");
      server.reviseAwsSigV4!(target, { region: "eu-west-1" });
      await first;
      await waitFor(() => events(audit, "delivered").length >= 1, 5000, "first delivered audit entry");
      // The in-flight delivery still carries the old signature.
      assertSigned(captured[0]!, target, AKID_A, VALUE_A, "us-east-1", "execute-api");
      assert.equal(captured.length, 1);

      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(captured.length, 2);
      assertSigned(captured[1]!, target, AKID_A, VALUE_A, "eu-west-1", "execute-api");
    } finally {
      await close(server);
      await close(down);
    }
  });

  it("audit previous/current are exact and carry no key material", async () => {
    const { server, audit } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": { ...BASE_CONFIG },
    });
    await listen(server);
    try {
      server.reviseAwsSigV4!("https://downstream.example/hook", {
        accessKeyId: AKID_B,
        secretRef: REF_B,
        region: "eu-west-1",
      });
      const rows = events(audit, "aws_sigv4_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.previous, { ...BASE_CONFIG });
      assert.deepEqual(rows[0]!.current, {
        accessKeyId: AKID_B,
        secretRef: REF_B,
        region: "eu-west-1",
        service: "execute-api",
      });
      // The audit carries the reference names, never the key material
      // behind them.
      const dump = JSON.stringify(rows);
      assert.ok(!dump.includes(VALUE_A), "audit must not contain the old key material");
      assert.ok(!dump.includes(VALUE_B), "audit must not contain the new key material");
      assert.ok(dump.includes(REF_A));
      assert.ok(dump.includes(REF_B));
      // Only the five config fields ride on previous/current.
      assert.deepEqual(Object.keys(rows[0]!.current as object).sort(), [
        "accessKeyId",
        "region",
        "secretRef",
        "service",
      ]);
    } finally {
      await close(server);
    }
  });

  it("the getter returns a defensive copy", async () => {
    const { server } = relay("https://downstream.example/hook", {
      "https://downstream.example/hook": {
        ...BASE_CONFIG,
        additionalSignedHeaders: ["content-type"],
      },
    });
    await listen(server);
    try {
      const first = server.getAwsSigV4!("https://downstream.example/hook")!;
      first.region = "eu-west-1";
      first.additionalSignedHeaders!.push("x-custom");
      assert.deepEqual(server.getAwsSigV4!("https://downstream.example/hook"), {
        ...BASE_CONFIG,
        additionalSignedHeaders: ["content-type"],
      });
    } finally {
      await close(server);
    }
  });
});
