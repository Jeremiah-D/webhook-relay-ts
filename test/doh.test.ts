import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { LookupAddress } from "node:dns";
import {
  QTYPE_A,
  QTYPE_AAAA,
  DohProtocolError,
  assertValidDohUrl,
  buildDnsQuery,
  parseDnsResponse,
  createDohResolver,
  createDohAwareResolver,
  resolveDohUrl,
} from "../src/doh.ts";

/* ------------------------------------------------------------------ */
/* Hand-crafted DNS wire fixtures (built byte-by-byte in the test;    */
/* never via buildDnsQuery for the answer section).                   */
/* ------------------------------------------------------------------ */

function dnsName(...labels: string[]): Buffer {
  const parts: Buffer[] = [];
  for (const label of labels) {
    const bytes = Buffer.from(label, "ascii");
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function cannedResponse(id: number, answers: Buffer[], rcode = 0): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x8180 | rcode, 2); // QR=1, RD=1, RA=1
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(answers.length, 6); // ANCOUNT
  const question = Buffer.concat([
    dnsName("example", "com"),
    Buffer.from([0x00, 0x01, 0x00, 0x01]), // QTYPE A, QCLASS IN
  ]);
  return Buffer.concat([header, question, ...answers]);
}

/** RR header (12 bytes) with a compression pointer to the QNAME at offset 12. */
function rrHeader(type: number, rdlen: number): Buffer {
  const h = Buffer.alloc(12);
  h[0] = 0xc0;
  h[1] = 0x0c;
  h.writeUInt16BE(type, 2);
  h.writeUInt16BE(1, 4); // CLASS IN
  h.writeUInt32BE(300, 6); // TTL
  h.writeUInt16BE(rdlen, 10);
  return h;
}

function aRecord(octets: [number, number, number, number]): Buffer {
  return Buffer.concat([rrHeader(1, 4), Buffer.from(octets)]);
}

function aaaaRecord(groups: number[]): Buffer {
  const rdata = Buffer.alloc(16);
  groups.forEach((g, i) => rdata.writeUInt16BE(g, i * 2));
  return Buffer.concat([rrHeader(28, 16), rdata]);
}

function txtRecord(text: string): Buffer {
  const payload = Buffer.from(text, "ascii");
  const rdata = Buffer.concat([Buffer.from([payload.length]), payload]);
  return Buffer.concat([rrHeader(16, rdata.length), rdata]);
}

const A_BYTES: [number, number, number, number] = [93, 184, 216, 34];
const AAAA_GROUPS = [0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946];

function cannedAPlusAaaa(id: number): Buffer {
  return cannedResponse(id, [aRecord(A_BYTES), aaaaRecord(AAAA_GROUPS)]);
}

/* ------------------------------------------------------------------ */
/* Local fake DoH servers (plain http on 127.0.0.1, ephemeral port).   */
/* ------------------------------------------------------------------ */

interface FakeDoh {
  url: string;
  seenContentTypes: (string | undefined)[];
  requestCount: () => number;
  close: () => Promise<void>;
}

const activeServers: FakeDoh[] = [];

afterEach(async () => {
  while (activeServers.length > 0) {
    const fake = activeServers.pop();
    if (fake !== undefined) await fake.close();
  }
});

async function startFakeDoh(
  respond: (reqBody: Buffer) => { status: number; body: Buffer }
): Promise<FakeDoh> {
  const seenContentTypes: (string | undefined)[] = [];
  let requests = 0;
  const server: Server = createServer((req, res) => {
    requests += 1;
    seenContentTypes.push(req.headers["content-type"]);
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const { status, body } = respond(Buffer.concat(chunks));
      res.writeHead(status, { "content-type": "application/dns-message" });
      res.end(body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const fake: FakeDoh = {
    url: `http://127.0.0.1:${port}/dns-query`,
    seenContentTypes,
    requestCount: () => requests,
    close: () =>
      new Promise<void>((resolve, reject) => {
        // The DoH client leaves sockets in the server's keep-alive state
        // (node's default 5s keepAliveTimeout); destroy them first so
        // close() does not wait out the idle timeout.
        server.closeAllConnections();
        server.close((err?: Error) => (err ? reject(err) : resolve()));
      }),
  };
  activeServers.push(fake);
  return fake;
}

/** Echo the query ID back, answering only the RR type the query asked for. */
function echoResponder(reqBody: Buffer): { status: number; body: Buffer } {
  const id = reqBody.length >= 2 ? reqBody.readUInt16BE(0) : 0;
  const qtype = reqBody.length >= 4 ? reqBody.readUInt16BE(reqBody.length - 4) : QTYPE_A;
  const answers = qtype === QTYPE_AAAA ? [aaaaRecord(AAAA_GROUPS)] : [aRecord(A_BYTES)];
  return { status: 200, body: cannedResponse(id, answers) };
}

/* ------------------------------------------------------------------ */

describe("assertValidDohUrl", () => {
  it("accepts an https endpoint and returns the parsed URL", () => {
    const parsed = assertValidDohUrl("https://dns.example/dns-query");
    assert.ok(parsed instanceof URL);
    assert.equal(parsed.hostname, "dns.example");
    assert.equal(parsed.protocol, "https:");
  });

  it("accepts http for local test servers", () => {
    const parsed = assertValidDohUrl("http://127.0.0.1:8080/dns-query");
    assert.equal(parsed.protocol, "http:");
  });

  it("rejects a non-http(s) scheme with RangeError", () => {
    assert.throws(() => assertValidDohUrl("ftp://dns.example/dns-query"), RangeError);
  });

  it("rejects garbage that is not a URL with RangeError", () => {
    assert.throws(() => assertValidDohUrl("not a url at all"), RangeError);
  });

  it("rejects the empty string with RangeError", () => {
    assert.throws(() => assertValidDohUrl(""), RangeError);
  });
});

describe("buildDnsQuery", () => {
  it("encodes header, QNAME, QTYPE and QCLASS for example.com", () => {
    const q = buildDnsQuery("example.com", QTYPE_A);
    // 12-byte header + 13-byte QNAME + 4-byte tail = 29 bytes.
    assert.equal(q.length, 29);
    assert.equal(q.readUInt16BE(2), 0x0100); // flags: QR=0, RD=1
    assert.equal(q.readUInt16BE(4), 1); // QDCOUNT=1
    assert.equal(q.readUInt16BE(6), 0); // ANCOUNT=0
    // QNAME: 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ("example" = 7 chars)
    const expectedName = Buffer.from([
      0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    ]);
    assert.ok(q.subarray(12, 25).equals(expectedName));
    assert.equal(q.readUInt16BE(25), QTYPE_A);
    assert.equal(q.readUInt16BE(27), 1); // QCLASS IN
  });

  it("encodes the AAAA qtype", () => {
    const q = buildDnsQuery("example.com", QTYPE_AAAA);
    assert.equal(q.readUInt16BE(q.length - 4), 28);
  });

  it("rejects empty hostnames and IP literals", () => {
    assert.throws(() => buildDnsQuery("", QTYPE_A), RangeError);
    assert.throws(() => buildDnsQuery("1.2.3.4", QTYPE_A), RangeError);
    assert.throws(() => buildDnsQuery("::1", QTYPE_AAAA), RangeError);
  });

  it("rejects malformed hostnames", () => {
    const bad = [
      "example..com", // empty label
      "example.com.", // trailing dot
      "-example.com", // leading hyphen
      "example-.com", // trailing hyphen
      "exa mple.com", // space
      "exämple.com", // non-ASCII
      `${"a".repeat(64)}.com`, // label > 63
      `${"a".repeat(254)}.com`, // name > 253
    ];
    for (const name of bad) {
      assert.throws(() => buildDnsQuery(name, QTYPE_A), RangeError, name);
    }
  });
});

describe("parseDnsResponse", () => {
  it("parses A + AAAA answers that use compression pointers", () => {
    const records = parseDnsResponse(cannedAPlusAaaa(0x1234));
    assert.deepEqual(records, [
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ]);
  });

  it("throws DohProtocolError on a truncated packet", () => {
    const truncated = cannedAPlusAaaa(0x1234).subarray(0, 20);
    assert.throws(() => parseDnsResponse(truncated), DohProtocolError);
    assert.throws(() => parseDnsResponse(Buffer.alloc(0)), DohProtocolError);
    assert.throws(() => parseDnsResponse(Buffer.alloc(8)), DohProtocolError);
  });

  it("throws DohProtocolError on garbage bytes", () => {
    assert.throws(() => parseDnsResponse(Buffer.alloc(12, 0)), DohProtocolError); // QR clear
    assert.throws(
      () => parseDnsResponse(Buffer.from([0xff, 0xff, 0x81, 0x80, 0x00, 0x09, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04])),
      DohProtocolError // claims 9 questions, packet ends there
    );
  });

  it("throws DohProtocolError on a non-zero RCODE", () => {
    assert.throws(() => parseDnsResponse(cannedResponse(0x1, [], 3)), DohProtocolError); // NXDOMAIN
    assert.throws(() => parseDnsResponse(cannedResponse(0x1, [], 2)), DohProtocolError); // SERVFAIL
  });

  it("ignores non-A/AAAA record types", () => {
    const buf = cannedResponse(0x9, [txtRecord("hello"), aRecord(A_BYTES)]);
    const records = parseDnsResponse(buf);
    assert.deepEqual(records, [{ address: "93.184.216.34", family: 4 }]);
  });

  it("returns an empty list when the answer section is empty", () => {
    assert.deepEqual(parseDnsResponse(cannedResponse(0x7, [])), []);
  });
});

describe("createDohResolver (live, local fake server)", () => {
  it("merges A + AAAA answers and sends application/dns-message", async () => {
    const fake = await startFakeDoh(echoResponder);
    const resolve = createDohResolver({ url: fake.url });
    const records = await resolve("example.com");
    assert.deepEqual(records, [
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ]);
    assert.equal(fake.requestCount(), 2); // A and AAAA in parallel
    assert.ok(fake.seenContentTypes.length > 0);
    for (const ct of fake.seenContentTypes) {
      assert.equal(ct, "application/dns-message");
    }
  });

  it("short-circuits IP literals with no DoH traffic", async () => {
    const fake = await startFakeDoh(echoResponder);
    const resolve = createDohResolver({ url: fake.url });
    assert.deepEqual(await resolve("127.0.0.1"), [{ address: "127.0.0.1", family: 4 }]);
    assert.deepEqual(await resolve("::1"), [{ address: "::1", family: 6 }]);
    assert.equal(fake.requestCount(), 0);
  });

  it("throws an ENOTFOUND-coded error on an empty answer set", async () => {
    const fake = await startFakeDoh((body) => ({
      status: 200,
      body: cannedResponse(body.readUInt16BE(0), []),
    }));
    const resolve = createDohResolver({ url: fake.url });
    await assert.rejects(resolve("example.com"), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal((err as NodeJS.ErrnoException).code, "ENOTFOUND");
      return true;
    });
  });

  it("throws DohProtocolError on a non-2xx response", async () => {
    const fake = await startFakeDoh(() => ({ status: 500, body: Buffer.from("boom") }));
    const resolve = createDohResolver({ url: fake.url });
    await assert.rejects(resolve("example.com"), DohProtocolError);
  });

  it("rejects an invalid endpoint or timeout up front", () => {
    assert.throws(() => createDohResolver({ url: "gopher://x/" }), RangeError);
    assert.throws(() => createDohResolver({ url: "https://dns.example/", timeoutMs: 0 }), RangeError);
    assert.throws(
      () => createDohResolver({ url: "https://dns.example/", timeoutMs: -5 }),
      RangeError
    );
  });
});

describe("createDohAwareResolver", () => {
  it("falls back to system DNS when the DoH server errors", async () => {
    const fake = await startFakeDoh(() => ({ status: 500, body: Buffer.from("boom") }));
    const seen: { hostname: string; error: string; dohUrl: string }[] = [];
    const aware = createDohAwareResolver(fake.url, {
      onFallback: (info) => seen.push(info),
    });
    const records: LookupAddress[] = await aware.resolve("localhost");
    assert.ok(
      records.some((r) => r.address === "127.0.0.1"),
      `expected 127.0.0.1 in ${JSON.stringify(records)}`
    );
    assert.equal(seen.length, 1);
    assert.equal(seen[0].hostname, "localhost");
    assert.equal(seen[0].dohUrl, fake.url);
    assert.ok(seen[0].error.length > 0);
    assert.deepEqual(aware.getStats(), {
      dohQueries: 1,
      dohFailures: 1,
      fallbacks: 1,
      systemQueries: 1,
    });
  });

  it("falls back when the DoH server never responds (timeout)", async () => {
    const seenContentTypes: (string | undefined)[] = [];
    const server: Server = createServer((req, _res) => {
      seenContentTypes.push(req.headers["content-type"]);
      // Never respond: the client timeout must fire.
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const fake: FakeDoh = {
      url: `http://127.0.0.1:${port}/dns-query`,
      seenContentTypes,
      requestCount: () => seenContentTypes.length,
      close: () =>
        new Promise<void>((resolve, reject) => {
          server.closeAllConnections();
          server.close((err?: Error) => (err ? reject(err) : resolve()));
        }),
    };
    activeServers.push(fake);
    const aware = createDohAwareResolver(fake.url, { timeoutMs: 100 });
    const records = await aware.resolve("localhost");
    assert.ok(records.some((r) => r.address === "127.0.0.1"));
    assert.equal(aware.getStats().fallbacks, 1);
  });

  it("swallows a throwing onFallback callback and still resolves", async () => {
    const fake = await startFakeDoh(() => ({ status: 500, body: Buffer.from("boom") }));
    const aware = createDohAwareResolver(fake.url, {
      onFallback: () => {
        throw new Error("telemetry is down");
      },
    });
    const records = await aware.resolve("localhost");
    assert.ok(records.some((r) => r.address === "127.0.0.1"));
    assert.equal(aware.getStats().fallbacks, 1);
  });

  it("serves DoH answers directly when the server is healthy", async () => {
    const fake = await startFakeDoh(echoResponder);
    const aware = createDohAwareResolver(fake.url);
    const records = await aware.resolve("example.com");
    assert.deepEqual(records, [
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ]);
    assert.deepEqual(aware.getStats(), {
      dohQueries: 1,
      dohFailures: 0,
      fallbacks: 0,
      systemQueries: 0,
    });
  });
});

describe("resolveDohUrl", () => {
  it("matches only the exact target URL", () => {
    const doh = { "https://api.example/hook": "https://dns.example/dns-query" };
    assert.equal(resolveDohUrl("https://api.example/hook", doh), "https://dns.example/dns-query");
    assert.equal(resolveDohUrl("https://api.example/hook/", doh), undefined); // trailing slash
    assert.equal(resolveDohUrl("https://api.example/other", doh), undefined);
    assert.equal(resolveDohUrl("https://api.example/hook", {}), undefined);
    assert.equal(resolveDohUrl("https://api.example/hook", undefined), undefined);
  });
});
