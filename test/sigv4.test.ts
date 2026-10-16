import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AMZ_DATE_HEADER,
  AUTHORIZATION_HEADER,
  SigV4SecretUnavailableError,
  SigV4SigningError,
  assertValidAwsSigV4Config,
  buildCanonicalRequest,
  defaultSecretResolver,
  formatAmzDate,
  signAwsSigV4,
  sigV4DateStamp,
  type AwsSigV4EndpointConfig,
  type SecretResolver,
} from "../src/sigv4.ts";
import { createDefaultSender, createRelayServer, type PooledSender } from "../src/server.ts";
import { classifyFailure } from "../src/failure.ts";
import { signSha256, verifySignature } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

// The well-known example key pair from the AWS SigV4 documentation —
// public example material, not a real credential.
const EXAMPLE_AKID = "AKIDEXAMPLE";
const EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const EXAMPLE_DATE_MS = Date.UTC(2015, 7, 30, 12, 36, 0); // 20150830T123600Z

const TEST_KEY_REF = "WR116_TEST_AWS_KEY";
const TEST_KEY_VALUE = "wr116-test-aws-key-material";
const TEST_AKID = "TESTAKID123";
const TEST_REGION = "us-east-1";
const TEST_SERVICE = "execute-api";
const BODY = Buffer.from(JSON.stringify({ event: "sigv4.probe", amount_cents: 1200 }));

function validConfig(overrides?: Partial<AwsSigV4EndpointConfig>): AwsSigV4EndpointConfig {
  return {
    accessKeyId: TEST_AKID,
    secretRef: TEST_KEY_REF,
    region: TEST_REGION,
    service: TEST_SERVICE,
    ...overrides,
  };
}

/** Independent SigV4 reimplementation (raw crypto, separate code path). */
function referenceSign(input: {
  method: string;
  url: string;
  body: Buffer;
  akid: string;
  secret: string;
  region: string;
  service: string;
  amzDate: string;
  extraHeaders?: Array<[string, string]>;
}): string {
  const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  const url = new URL(input.url);
  const host = url.port === "" || (url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")
    ? url.hostname.toLowerCase()
    : `${url.hostname.toLowerCase()}:${url.port}`;
  const path = (url.pathname === "" ? "/" : url.pathname).split("/").map((seg) => {
    try { return enc(decodeURIComponent(seg)); } catch { return enc(seg); }
  }).join("/");
  const params: Array<[string, string]> = [];
  url.searchParams.forEach((v, k) => params.push([k, v]));
  params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  const query = params.map(([k, v]) => `${enc(k)}=${enc(v)}`).join("&");
  const hdrs: Array<[string, string]> = [["host", host], ["x-amz-date", input.amzDate]];
  for (const [n, v] of input.extraHeaders ?? []) hdrs.push([n.toLowerCase(), v.trim().replace(/\s+/g, " ")]);
  hdrs.sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const canonicalHeaders = hdrs.map(([n, v]) => `${n}:${v}\n`).join("");
  const signedHeaders = hdrs.map(([n]) => n).join(";");
  const payloadHash = createHash("sha256").update(input.body).digest("hex");
  const canonicalRequest = [input.method.toUpperCase(), path, query, canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const dateStamp = input.amzDate.slice(0, 8);
  const scope = `${dateStamp}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", input.amzDate, scope, createHash("sha256").update(canonicalRequest, "utf8").digest("hex")].join("\n");
  const kDate = createHmac("sha256", `AWS4${input.secret}`).update(dateStamp).digest();
  const kRegion = createHmac("sha256", kDate).update(input.region).digest();
  const kService = createHmac("sha256", kRegion).update(input.service).digest();
  const kSigning = createHmac("sha256", kService).update("aws4_request").digest();
  const signature = createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");
  return `AWS4-HMAC-SHA256 Credential=${input.akid}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

function parseAmzDate(s: string): number {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  assert.ok(m, `bad amz date: ${s}`);
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

describe("WR-116 SigV4 canonical signing", () => {
  it("matches an independent SigV4 implementation on the canonical GET vector", () => {
    // Values cross-validated byte-for-byte against the independent
    // `aws4` package (v1.13.2) with the clock frozen at the same
    // instant — see the WR-116 work notes. The canonical request below
    // is exactly the one rendered in the AWS documentation walkthrough.
    const out = signAwsSigV4({
      method: "GET",
      url: "https://example.amazonaws.com/?Param1=value1",
      body: Buffer.alloc(0),
      credentials: { accessKeyId: EXAMPLE_AKID, secretAccessKey: EXAMPLE_SECRET },
      region: "us-east-1",
      service: "service",
      nowMs: EXAMPLE_DATE_MS,
    });
    assert.equal(out.amzDate, "20150830T123600Z");
    assert.equal(out.signedHeaders, "host;x-amz-date");
    assert.equal(out.canonicalRequestHash, "1e24db194ed7d0eec2de28d7369675a243488e08526e8c1c73571282f7c517ab");
    assert.equal(
      out.authorization,
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
        "SignedHeaders=host;x-amz-date, " +
        "Signature=a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb"
    );
  });

  it("builds the exact canonical request for a POST with a signed content-type", () => {
    const body = Buffer.from("Param1=value1");
    const { canonicalRequest, signedHeaders } = buildCanonicalRequest({
      method: "post",
      url: "https://example.amazonaws.com/",
      body,
      extraSignedHeaders: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
      amzDate: "20150830T123600Z",
    });
    assert.equal(signedHeaders, "content-type;host;x-amz-date");
    assert.equal(
      canonicalRequest,
      [
        "POST",
        "/",
        "",
        "content-type:application/x-www-form-urlencoded; charset=utf-8",
        "host:example.amazonaws.com",
        "x-amz-date:20150830T123600Z",
        "",
        "content-type;host;x-amz-date",
        createHash("sha256").update(body).digest("hex"),
      ].join("\n")
    );
  });

  it("cross-checks a POST signature against the independent reimplementation", () => {
    const amzDate = "20261016T101500Z";
    const nowMs = parseAmzDate(amzDate);
    const url = "https://api.example.com:8443/stage/hook?z=last&a=first&a=second&sp ace=x%25y";
    const body = Buffer.from(JSON.stringify({ hello: "world", n: 42 }));
    const got = signAwsSigV4({
      method: "POST",
      url,
      body,
      credentials: { accessKeyId: TEST_AKID, secretAccessKey: TEST_KEY_VALUE },
      region: TEST_REGION,
      service: TEST_SERVICE,
      extraSignedHeaders: { "content-type": "application/json" },
      nowMs,
    });
    const expected = referenceSign({
      method: "POST",
      url,
      body,
      akid: TEST_AKID,
      secret: TEST_KEY_VALUE,
      region: TEST_REGION,
      service: TEST_SERVICE,
      amzDate,
      extraHeaders: [["content-type", "application/json"]],
    });
    assert.equal(got.authorization, expected);
    assert.equal(got.amzDate, amzDate);
    assert.equal(got.signedHeaders, "content-type;host;x-amz-date");
  });

  it("changes the signature when the body, key, or instant changes", () => {
    const base = {
      method: "POST",
      url: "https://example.amazonaws.com/hook",
      credentials: { accessKeyId: TEST_AKID, secretAccessKey: TEST_KEY_VALUE },
      region: TEST_REGION,
      service: TEST_SERVICE,
      nowMs: EXAMPLE_DATE_MS,
    };
    const a = signAwsSigV4({ ...base, body: Buffer.from("one") }).authorization;
    const b = signAwsSigV4({ ...base, body: Buffer.from("two") }).authorization;
    const c = signAwsSigV4({
      ...base,
      body: Buffer.from("one"),
      credentials: { accessKeyId: TEST_AKID, secretAccessKey: "different-key" },
    }).authorization;
    const d = signAwsSigV4({ ...base, body: Buffer.from("one"), nowMs: EXAMPLE_DATE_MS + 1000 }).authorization;
    assert.notEqual(a, b);
    assert.notEqual(a, c);
    assert.notEqual(a, d);
  });

  it("formats UTC timestamps correctly", () => {
    assert.equal(formatAmzDate(EXAMPLE_DATE_MS), "20150830T123600Z");
    assert.equal(sigV4DateStamp(EXAMPLE_DATE_MS), "20150830");
    assert.equal(formatAmzDate(Date.UTC(2026, 0, 2, 3, 4, 5)), "20260102T030405Z");
  });

  it("rejects empty credentials loudly", () => {
    assert.throws(
      () =>
        signAwsSigV4({
          method: "POST",
          url: "https://example.amazonaws.com/",
          body: BODY,
          credentials: { accessKeyId: "", secretAccessKey: TEST_KEY_VALUE },
          region: TEST_REGION,
          service: TEST_SERVICE,
        }),
      RangeError
    );
    assert.throws(
      () =>
        signAwsSigV4({
          method: "POST",
          url: "https://example.amazonaws.com/",
          body: BODY,
          credentials: { accessKeyId: TEST_AKID, secretAccessKey: "" },
          region: TEST_REGION,
          service: TEST_SERVICE,
        }),
      RangeError
    );
  });
});

describe("WR-116 config validation", () => {
  it("accepts a well-formed config", () => {
    assert.doesNotThrow(() => assertValidAwsSigV4Config(validConfig(), "awsSigV4[x]"));
    assert.doesNotThrow(() =>
      assertValidAwsSigV4Config(validConfig({ additionalSignedHeaders: ["content-type"] }), "awsSigV4[x]")
    );
  });

  it("rejects malformed configs with RangeError", () => {
    const bad: Array<[string, unknown]> = [
      ["null", null],
      ["empty accessKeyId", validConfig({ accessKeyId: "" })],
      ["empty secretRef", validConfig({ secretRef: "" })],
      ["bad region", validConfig({ region: "US_EAST_1" })],
      ["empty service", validConfig({ service: "" })],
      ["service with slash", validConfig({ service: "execute/api" })],
      ["additionalSignedHeaders not an array", validConfig({ additionalSignedHeaders: "content-type" as never })],
      ["additionalSignedHeaders repeats host", validConfig({ additionalSignedHeaders: ["Host"] })],
      ["additionalSignedHeaders repeats x-amz-date", validConfig({ additionalSignedHeaders: ["x-amz-date"] })],
      ["additionalSignedHeaders duplicates", validConfig({ additionalSignedHeaders: ["content-type", "Content-Type"] })],
      ["additionalSignedHeaders bad name", validConfig({ additionalSignedHeaders: ["not a header!"] })],
    ];
    for (const [name, cfg] of bad) {
      assert.throws(() => assertValidAwsSigV4Config(cfg, "awsSigV4[x]"), RangeError, name);
    }
  });

  it("fails fast at sender construction, never mid-delivery", () => {
    const mk = (cfg: Record<string, AwsSigV4EndpointConfig>) =>
      createDefaultSender(
        undefined, undefined, undefined, undefined, undefined, undefined,
        undefined, undefined, undefined, undefined, undefined, undefined,
        undefined, undefined, undefined, undefined, undefined, undefined,
        undefined, undefined, undefined, undefined, undefined, undefined,
        undefined, undefined, undefined, undefined, cfg
      );
    assert.throws(() => mk({ "http://x/hook": validConfig({ region: "bogus_region!!" }) }), RangeError);
    const sender = mk({ "http://x/hook": validConfig() });
    sender.destroy();
  });
});

describe("WR-116 secret resolution", () => {
  it("defaultSecretResolver reads the environment", () => {
    process.env[TEST_KEY_REF] = TEST_KEY_VALUE;
    try {
      assert.equal(defaultSecretResolver(TEST_KEY_REF), TEST_KEY_VALUE);
      assert.equal(defaultSecretResolver("WR116_DEFINITELY_ABSENT_REF"), undefined);
    } finally {
      delete process.env[TEST_KEY_REF];
    }
  });

  it("SigV4SecretUnavailableError carries endpoint + ref, never key material", () => {
    const err = new SigV4SecretUnavailableError("http://x/hook", TEST_KEY_REF);
    assert.ok(err instanceof SigV4SigningError);
    assert.ok(err instanceof Error);
    assert.equal(err.name, "SigV4SecretUnavailableError");
    assert.equal(err.endpoint, "http://x/hook");
    assert.equal(err.secretRef, TEST_KEY_REF);
    assert.ok(!err.message.includes(TEST_KEY_VALUE));
  });

  it("classifyFailure treats signing failures as non_retryable", () => {
    assert.equal(classifyFailure(new SigV4SecretUnavailableError("http://x/hook", TEST_KEY_REF)).failureClass, "non_retryable");
    assert.equal(classifyFailure(new SigV4SigningError("http://x/hook", "boom")).failureClass, "non_retryable");
  });
});

describe("WR-116 sender integration", () => {
  let stub: Server;
  let stubPort: number;
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
        res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
    const addr = stub.address();
    assert.ok(addr && typeof addr === "object");
    stubPort = addr.port;
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function targetUrl(): string {
    return `http://127.0.0.1:${stubPort}/hook`;
  }

  function senderWith(
    cfg: Record<string, AwsSigV4EndpointConfig>,
    resolver?: SecretResolver,
    outboundSigning?: { secret: string; keyId?: string }
  ): PooledSender {
    return createDefaultSender(
      undefined, false, outboundSigning, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, cfg, resolver
    );
  }

  function item(extraHeaders: Record<string, string> = {}): RetryItem {
    return { id: "sigv4-1", traceId: "trace-sigv4", payload: BODY, targetUrl: targetUrl(), headers: extraHeaders };
  }

  async function deliverAndWait(sender: PooledSender, it: RetryItem) {
    seen.length = 0;
    await sender(it);
    const deadline = Date.now() + 5000;
    while (seen.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(seen.length, 1);
    return seen[0]!;
  }

  it("stamps Authorization + x-amz-date over the exact wire bytes", async () => {
    const resolver: SecretResolver = (ref) => (ref === TEST_KEY_REF ? TEST_KEY_VALUE : undefined);
    const sender = senderWith({ [targetUrl()]: validConfig() }, resolver);
    try {
      const got = await deliverAndWait(sender, item({ "content-type": "application/json" }));
      assert.deepEqual(got.body, BODY);
      const amzDate = String(got.headers[AMZ_DATE_HEADER]);
      assert.match(amzDate, /^\d{8}T\d{6}Z$/);
      const authz = String(got.headers[AUTHORIZATION_HEADER]);
      // Recompute the expected signature from the wire timestamp: the
      // downstream contract, verified independently of the sender path.
      const expected = signAwsSigV4({
        method: "POST",
        url: targetUrl(),
        body: BODY,
        credentials: { accessKeyId: TEST_AKID, secretAccessKey: TEST_KEY_VALUE },
        region: TEST_REGION,
        service: TEST_SERVICE,
        nowMs: parseAmzDate(amzDate),
      });
      assert.equal(authz, expected.authorization);
    } finally {
      sender.destroy();
    }
  });

  it("composes with the WR-26 HMAC stamp (orthogonal, both present)", async () => {
    const hmacKey = "wr116-hmac-key";
    const resolver: SecretResolver = () => TEST_KEY_VALUE;
    const sender = senderWith({ [targetUrl()]: validConfig() }, resolver, { secret: hmacKey, keyId: "k1" });
    try {
      const got = await deliverAndWait(sender, item());
      const relaySig = String(got.headers["x-relay-signature"]);
      assert.equal(relaySig, signSha256(BODY, hmacKey));
      assert.ok(verifySignature(got.body, relaySig, hmacKey));
      assert.match(String(got.headers[AUTHORIZATION_HEADER]), /^AWS4-HMAC-SHA256 Credential=TESTAKID123\//);
      assert.match(String(got.headers[AMZ_DATE_HEADER]), /^\d{8}T\d{6}Z$/);
    } finally {
      sender.destroy();
    }
  });

  it("drops forged inbound authorization / x-amz-date — the relay's stamps win", async () => {
    const resolver: SecretResolver = () => TEST_KEY_VALUE;
    const sender = senderWith({ [targetUrl()]: validConfig() }, resolver);
    try {
      const got = await deliverAndWait(
        sender,
        item({ authorization: "AWS4-HMAC-SHA256 Credential=EVIL", "X-Amz-Date": "19990101T000000Z" })
      );
      assert.match(String(got.headers[AUTHORIZATION_HEADER]), /^AWS4-HMAC-SHA256 Credential=TESTAKID123\//);
      assert.doesNotMatch(String(got.headers[AMZ_DATE_HEADER]), /^19990101/);
    } finally {
      sender.destroy();
    }
  });

  it("fails the attempt loudly when the secret does not resolve", async () => {
    const sender = senderWith({ [targetUrl()]: validConfig() }, () => undefined);
    try {
      await assert.rejects(sender(item()), (err: unknown) => {
        assert.ok(err instanceof SigV4SecretUnavailableError);
        assert.equal((err as SigV4SecretUnavailableError).secretRef, TEST_KEY_REF);
        return true;
      });
    } finally {
      sender.destroy();
    }
  });

  it("signs content-type when listed in additionalSignedHeaders", async () => {
    const resolver: SecretResolver = () => TEST_KEY_VALUE;
    const sender = senderWith(
      { [targetUrl()]: validConfig({ additionalSignedHeaders: ["content-type"] }) },
      resolver
    );
    try {
      const got = await deliverAndWait(sender, item({ "content-type": "application/json" }));
      const authz = String(got.headers[AUTHORIZATION_HEADER]);
      assert.ok(authz.includes("SignedHeaders=content-type;host;x-amz-date"));
      const amzDate = String(got.headers[AMZ_DATE_HEADER]);
      const expected = signAwsSigV4({
        method: "POST",
        url: targetUrl(),
        body: BODY,
        credentials: { accessKeyId: TEST_AKID, secretAccessKey: TEST_KEY_VALUE },
        region: TEST_REGION,
        service: TEST_SERVICE,
        extraSignedHeaders: { "content-type": "application/json" },
        nowMs: parseAmzDate(amzDate),
      });
      assert.equal(authz, expected.authorization);
    } finally {
      sender.destroy();
    }
  });

  it("createRelayServer threads awsSigV4 end-to-end (intake -> signed delivery)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wr116-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const inboundKey = "wr116-inbound-key";
    process.env[TEST_KEY_REF] = TEST_KEY_VALUE;
    const relay = createRelayServer({
      secret: inboundKey,
      forwardUrl: targetUrl(),
      auditLog: audit,
      retry: { baseDelayMs: 50, maxDelayMs: 500, maxAttempts: 2, jitterMs: 0 },
      awsSigV4: { [targetUrl()]: validConfig() },
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const addr = relay.address();
    assert.ok(addr && typeof addr === "object");
    const relayPort = addr.port;
    try {
      seen.length = 0;
      const res = await new Promise<{ status: number }>((resolve, reject) => {
        const req = httpRequest(
          {
            port: relayPort,
            host: "127.0.0.1",
            path: "/hook",
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-signature": signSha256(BODY, inboundKey),
            },
          },
          (r) => resolve({ status: r.statusCode ?? 0 })
        );
        req.on("error", reject);
        req.end(BODY);
      });
      assert.equal(res.status, 202);
      const deadline = Date.now() + 8000;
      while (seen.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(seen.length, 1);
      assert.match(String(seen[0]!.headers[AUTHORIZATION_HEADER]), /^AWS4-HMAC-SHA256 Credential=TESTAKID123\//);
      assert.match(String(seen[0]!.headers[AMZ_DATE_HEADER]), /^\d{8}T\d{6}Z$/);
      assert.deepEqual(seen[0]!.body, BODY);
    } finally {
      delete process.env[TEST_KEY_REF];
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });
});
