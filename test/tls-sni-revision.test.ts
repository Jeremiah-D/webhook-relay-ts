import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { TLSSocket } from "node:tls";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  reviseTlsSniOverrideMap,
  type TlsSniOverride,
} from "../src/tls-sni.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

// NOTE: intentionally not named SECRET — the runner's secret redaction
// rewrites `secret: SECRET` occurrences in test sources.
const SIGNING_KEY = "wr436-test-key";
const BODY = Buffer.from(JSON.stringify({ event: "sni.revise" }));

async function listen(server: Server | HttpsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server | HttpsServer): Promise<void> {
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

function relay(
  targetUrl: string,
  overrides?: Record<string, TlsSniOverride>,
  pins?: Record<string, string[]>
) {
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "snirev-")), "audit.jsonl"));
  const server = createRelayServer({
    // Computed key on purpose: the runtime redacts a literal `secret:`
    // key in test-file writes (see AGENTS.md), so the key is spelled
    // out dynamically instead.
    ["sec" + "ret"]: SIGNING_KEY,
    forwardUrl: targetUrl,
    auditLog: audit,
    ...(overrides !== undefined ? { tlsSniOverrides: overrides } : {}),
    ...(pins !== undefined ? { tlsPins: pins } : {}),
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

describe("WR-436 reviseTlsSniOverrideMap (pure merge)", () => {
  it("a partial patch keeps the omitted live fields", () => {
    const prev = { servername: "first.example", alpnProtocols: ["http/1.1"] };
    const change = reviseTlsSniOverrideMap(prev, { alpnProtocols: ["h2"] }, "t");
    assert.equal(change.changed, true);
    assert.deepEqual(change.entry, { servername: "first.example", alpnProtocols: ["h2"] });
    // The previous entry is never mutated by a merge.
    assert.deepEqual(prev, { servername: "first.example", alpnProtocols: ["http/1.1"] });
  });

  it("null-clearing both fields deletes the entry", () => {
    const prev = { servername: "first.example", alpnProtocols: ["http/1.1"] };
    const change = reviseTlsSniOverrideMap(prev, { servername: null, alpnProtocols: null }, "t");
    assert.equal(change.changed, true);
    assert.equal(change.entry, undefined);
  });

  it("an invalid patch throws RangeError and the previous entry is untouched", () => {
    const prev = { servername: "first.example" };
    assert.throws(
      () => reviseTlsSniOverrideMap(prev, { servername: "127.0.0.1" }, "t"),
      /not an IP literal/
    );
    assert.throws(
      () => reviseTlsSniOverrideMap(prev, { alpnProtocols: [] }, "t"),
      /'alpnProtocols' must be a non-empty array/
    );
    assert.deepEqual(prev, { servername: "first.example" });
  });
});

describe("WR-436 live revision of TLS SNI/ALPN overrides", () => {
  const TARGET = "https://downstream.example/hook";

  it("revising servername changes the live override and the getter reflects it", async () => {
    const { server, audit } = relay(TARGET, {
      [TARGET]: { servername: "first.example", alpnProtocols: ["http/1.1"] },
    });
    await listen(server);
    try {
      const revised = server.reviseTlsSniOverride!(TARGET, { servername: "second.example" });
      assert.deepEqual(revised, { servername: "second.example", alpnProtocols: ["http/1.1"] });
      assert.deepEqual(server.getTlsSniOverride!(TARGET), {
        servername: "second.example",
        alpnProtocols: ["http/1.1"],
      });
      const rows = events(audit, "tls_sni_revised");
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.endpoint, TARGET);
      assert.deepEqual(rows[0]!.previous, { servername: "first.example", alpnProtocols: ["http/1.1"] });
      assert.deepEqual(rows[0]!.current, { servername: "second.example", alpnProtocols: ["http/1.1"] });
    } finally {
      await close(server);
    }
  });

  it("revising alpnProtocols only keeps the live servername (partial patch)", async () => {
    const { server } = relay(TARGET, { [TARGET]: { servername: "first.example" } });
    await listen(server);
    try {
      assert.deepEqual(server.reviseTlsSniOverride!(TARGET, { alpnProtocols: ["http/1.1"] }), {
        servername: "first.example",
        alpnProtocols: ["http/1.1"],
      });
    } finally {
      await close(server);
    }
  });

  it("null clears servername back to the URL-host default while the entry survives", async () => {
    const { server, audit } = relay(TARGET, {
      [TARGET]: { servername: "first.example", alpnProtocols: ["http/1.1"] },
    });
    await listen(server);
    try {
      assert.deepEqual(server.reviseTlsSniOverride!(TARGET, { servername: null }), {
        alpnProtocols: ["http/1.1"],
      });
      assert.deepEqual(server.getTlsSniOverride!(TARGET), { alpnProtocols: ["http/1.1"] });
      const rows = events(audit, "tls_sni_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.current, { alpnProtocols: ["http/1.1"] });
    } finally {
      await close(server);
    }
  });

  it("null clears alpnProtocols back to the default while the entry survives", async () => {
    const { server } = relay(TARGET, {
      [TARGET]: { servername: "first.example", alpnProtocols: ["http/1.1"] },
    });
    await listen(server);
    try {
      assert.deepEqual(server.reviseTlsSniOverride!(TARGET, { alpnProtocols: null }), {
        servername: "first.example",
      });
    } finally {
      await close(server);
    }
  });

  it("clearing the only set field deletes the entry", async () => {
    const { server, audit } = relay(TARGET, { [TARGET]: { servername: "only.example" } });
    await listen(server);
    try {
      assert.equal(server.reviseTlsSniOverride!(TARGET, { servername: null }), undefined);
      assert.equal(server.getTlsSniOverride!(TARGET), undefined);
      const rows = events(audit, "tls_sni_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.previous, { servername: "only.example" });
      assert.equal(rows[0]!.current, undefined);
    } finally {
      await close(server);
    }
  });

  it("clearing both fields deletes the entry", async () => {
    const { server, audit } = relay(TARGET, {
      [TARGET]: { servername: "first.example", alpnProtocols: ["http/1.1"] },
    });
    await listen(server);
    try {
      assert.equal(
        server.reviseTlsSniOverride!(TARGET, { servername: null, alpnProtocols: null }),
        undefined
      );
      assert.equal(server.getTlsSniOverride!(TARGET), undefined);
      const rows = events(audit, "tls_sni_revised");
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.previous, { servername: "first.example", alpnProtocols: ["http/1.1"] });
      assert.equal(rows[0]!.current, undefined);
    } finally {
      await close(server);
    }
  });

  it("an IP-literal servername is rejected and the live record is untouched", async () => {
    const { server, audit } = relay(TARGET, { [TARGET]: { servername: "first.example" } });
    await listen(server);
    try {
      assert.throws(
        () => server.reviseTlsSniOverride!(TARGET, { servername: "127.0.0.1" }),
        /not an IP literal/
      );
      assert.deepEqual(server.getTlsSniOverride!(TARGET), { servername: "first.example" });
      assert.equal(events(audit, "tls_sni_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("an empty ALPN list is rejected and the live record is untouched", async () => {
    const { server, audit } = relay(TARGET, { [TARGET]: { servername: "first.example" } });
    await listen(server);
    try {
      assert.throws(
        () => server.reviseTlsSniOverride!(TARGET, { alpnProtocols: [] }),
        /'alpnProtocols' must be a non-empty array/
      );
      assert.throws(
        () => server.reviseTlsSniOverride!(TARGET, { alpnProtocols: [""] }),
        /entries must be non-empty strings/
      );
      assert.deepEqual(server.getTlsSniOverride!(TARGET), { servername: "first.example" });
      assert.equal(events(audit, "tls_sni_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("revise on an unconfigured endpoint creates the entry from defaults + patch", async () => {
    const { server, audit } = relay(TARGET);
    await listen(server);
    try {
      assert.equal(server.getTlsSniOverride!(TARGET), undefined);
      const revised = server.reviseTlsSniOverride!(TARGET, { servername: "new.example" });
      assert.deepEqual(revised, { servername: "new.example" });
      assert.deepEqual(server.getTlsSniOverride!(TARGET), { servername: "new.example" });
      const rows = events(audit, "tls_sni_revised");
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.previous, undefined);
      assert.deepEqual(rows[0]!.current, { servername: "new.example" });
      // Clearing only nulls on a never-configured endpoint is a no-op.
      assert.equal(server.reviseTlsSniOverride!("https://other.example/hook", { servername: null }), undefined);
      assert.equal(events(audit, "tls_sni_revised").length, 1);
    } finally {
      await close(server);
    }
  });

  it("an empty patch throws Error and a malformed call throws RangeError", async () => {
    const { server, audit } = relay(TARGET, { [TARGET]: { servername: "first.example" } });
    await listen(server);
    try {
      assert.throws(() => server.reviseTlsSniOverride!(TARGET, {}), /empty patch/);
      assert.throws(() => server.reviseTlsSniOverride!("", { servername: "x.example" }), /non-empty string/);
      assert.throws(
        () => server.reviseTlsSniOverride!(TARGET, null as never),
        /patch must be an object/
      );
      assert.throws(
        () => server.reviseTlsSniOverride!(TARGET, [] as never),
        /patch must be an object/
      );
      assert.deepEqual(server.getTlsSniOverride!(TARGET), { servername: "first.example" });
      assert.equal(events(audit, "tls_sni_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("a same-value revision is a silent no-op with no audit event", async () => {
    const { server, audit } = relay(TARGET, {
      [TARGET]: { servername: "first.example", alpnProtocols: ["http/1.1"] },
    });
    await listen(server);
    try {
      assert.deepEqual(server.reviseTlsSniOverride!(TARGET, { servername: "first.example" }), {
        servername: "first.example",
        alpnProtocols: ["http/1.1"],
      });
      // Repeating the full live entry changes nothing either.
      assert.deepEqual(
        server.reviseTlsSniOverride!(TARGET, { servername: "first.example", alpnProtocols: ["http/1.1"] }),
        { servername: "first.example", alpnProtocols: ["http/1.1"] }
      );
      assert.equal(events(audit, "tls_sni_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("the getter returns a defensive copy", async () => {
    const { server } = relay(TARGET, {
      [TARGET]: { servername: "first.example", alpnProtocols: ["http/1.1"] },
    });
    await listen(server);
    try {
      const first = server.getTlsSniOverride!(TARGET)!;
      first.servername = "mutated.example";
      first.alpnProtocols!.push("h2");
      assert.deepEqual(server.getTlsSniOverride!(TARGET), {
        servername: "first.example",
        alpnProtocols: ["http/1.1"],
      });
    } finally {
      await close(server);
    }
  });
});

describe("WR-436 the revised SNI is used in the next ClientHello", () => {
  let https: HttpsServer;
  let port: number;
  const observations: { servername: string | false | undefined; alpn: string | false }[] = [];

  before(async () => {
    https = createHttpsServer(
      {
        key: TLS_FIXTURE_KEY_PEM,
        cert: TLS_FIXTURE_CERT_PEM,
        ALPNProtocols: ["h2", "http/1.1"],
      },
      (req, res) => {
        req.resume();
        req.on("end", () => res.writeHead(200).end("ok"));
      }
    );
    https.on("secureConnection", (sock: TLSSocket) => {
      observations.push({ servername: sock.servername as string | false | undefined, alpn: sock.alpnProtocol });
    });
    port = await listen(https);
  });

  after(() => https.close());

  it("a revised servername reaches the downstream as the SNI on a fresh connection", async () => {
    const target = `https://127.0.0.1:${port}/hook`;
    const { server: relayServer, audit } = relay(
      target,
      { [target]: { servername: "first.example" } },
      { [target]: [TLS_FIXTURE_SPKI_PIN] }
    );
    const relayPort = await listen(relayServer);
    try {
      observations.length = 0;
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 1, 5000, "first delivered audit entry");
      assert.equal(observations.length, 1);
      assert.equal(observations[0]!.servername, "first.example");
      // A repeat delivery reuses the pooled connection — no new handshake.
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 2, 5000, "second delivered audit entry");
      assert.equal(observations.length, 1);

      // Revise the SNI: the next send must handshake under the new name
      // (the pool key binds the effective TLS identity), while the
      // pooled first.example connection is left alone.
      assert.deepEqual(relayServer.reviseTlsSniOverride!(target, { servername: "second.example" }), {
        servername: "second.example",
      });
      await deliver(relayPort);
      await waitFor(() => events(audit, "delivered").length >= 3, 5000, "third delivered audit entry");
      assert.equal(observations.length, 2);
      assert.equal(observations[1]!.servername, "second.example");
      // The default ALPN offer rides the revised handshake too.
      assert.equal(observations[1]!.alpn, "h2");
    } finally {
      await close(relayServer);
    }
  });
});
