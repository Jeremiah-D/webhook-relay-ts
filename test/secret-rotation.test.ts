import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RotatingEndpointSecret,
  assertValidSecretRotationRules,
  compileSecretRotationRules,
  selectSecretRotation,
  DEFAULT_SECRET_GRACE_SECONDS,
  type SecretRotationConfig,
} from "../src/secret-rotation.ts";
import { signSha256, HmacSha256Verifier, type Verifier } from "../src/verify.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

const OLD_SECRET = "old-rotating-secret";
const NEW_SECRET = "new-rotating-secret";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));

const T0 = 1_700_000_000_000;
const nowT0 = () => T0;

function cfg(overrides: Partial<SecretRotationConfig> = {}): SecretRotationConfig {
  return {
    currentSecret: NEW_SECRET,
    previousSecret: OLD_SECRET,
    graceSeconds: 60,
    previousRetiredAtMs: T0,
    nowMs: nowT0,
    ...overrides,
  };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
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

describe("RotatingEndpointSecret", () => {
  it("fails fast on invalid config", () => {
    assert.throws(() => new RotatingEndpointSecret({ currentSecret: "" } as SecretRotationConfig), RangeError);
    assert.throws(
      () => new RotatingEndpointSecret(cfg({ previousSecret: "" })),
      RangeError
    );
    assert.throws(() => new RotatingEndpointSecret(cfg({ graceSeconds: -1 })), RangeError);
    assert.throws(() => new RotatingEndpointSecret(cfg({ graceSeconds: NaN })), RangeError);
    assert.throws(
      () => new RotatingEndpointSecret(cfg({ previousRetiredAtMs: -5 })),
      RangeError
    );
  });

  it("tries current first, then previous inside grace", () => {
    const rot = new RotatingEndpointSecret(cfg());
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, NEW_SECRET)), { ok: true, version: "current" });
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, OLD_SECRET)), { ok: true, version: "previous" });
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, "wrong")), { ok: false });
  });

  it("rejects previous outside its grace window (inclusive boundary)", () => {
    // Exactly at the deadline: still valid (inclusive, WR-20 convention).
    const atDeadline = new RotatingEndpointSecret(
      cfg({ nowMs: () => T0 + 60 * 1000 })
    );
    assert.ok(atDeadline.previousInGrace());
    assert.deepEqual(atDeadline.verify(BODY, signSha256(BODY, OLD_SECRET)), {
      ok: true,
      version: "previous",
    });
    // One millisecond past: dead.
    const past = new RotatingEndpointSecret(cfg({ nowMs: () => T0 + 60 * 1000 + 1 }));
    assert.ok(!past.previousInGrace());
    assert.deepEqual(past.verify(BODY, signSha256(BODY, OLD_SECRET)), { ok: false });
    // Current is unaffected by the expired grace.
    assert.deepEqual(past.verify(BODY, signSha256(BODY, NEW_SECRET)), { ok: true, version: "current" });
    assert.ok(past.isRotationComplete());
  });

  it("honors the x-signature-version hint without fallback", () => {
    const rot = new RotatingEndpointSecret(cfg());
    // Hint "current": old-key signature fails, no fallback to previous.
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, OLD_SECRET), { version: "current" }), {
      ok: false,
    });
    // Hint "previous": new-key signature fails, no fallback to current.
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, NEW_SECRET), { version: "previous" }), {
      ok: false,
    });
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, OLD_SECRET), { version: "previous" }), {
      ok: true,
      version: "previous",
    });
    // Unknown hint fails closed.
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, OLD_SECRET), { version: "v3" }), { ok: false });
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, NEW_SECRET), { version: "next" }), { ok: false });
    // Case/whitespace-insensitive.
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, OLD_SECRET), { version: " Previous " }), {
      ok: true,
      version: "previous",
    });
  });

  it("hint 'previous' fails when the previous key is not configured or expired", () => {
    const noPrev = new RotatingEndpointSecret(cfg({ previousSecret: undefined }));
    assert.ok(!noPrev.previousInGrace());
    assert.deepEqual(noPrev.verify(BODY, signSha256(BODY, OLD_SECRET), { version: "previous" }), {
      ok: false,
    });
    assert.ok(!noPrev.isRotationComplete()); // nothing to complete
    const expired = new RotatingEndpointSecret(cfg({ nowMs: () => T0 + 61 * 1000 }));
    assert.deepEqual(expired.verify(BODY, signSha256(BODY, OLD_SECRET), { version: "previous" }), {
      ok: false,
    });
  });

  it("never throws from verify", () => {
    const rot = new RotatingEndpointSecret(cfg());
    assert.deepEqual(rot.verify(BODY, "not-a-signature", { version: "current" }), { ok: false });
    assert.deepEqual(rot.verify(BODY, "", {}), { ok: false });
    assert.deepEqual(rot.verify(BODY, signSha256(BODY, NEW_SECRET), { version: undefined }), {
      ok: true,
      version: "current",
    });
  });

  it("defaults the grace to one hour and the retirement to construction time", () => {
    assert.equal(DEFAULT_SECRET_GRACE_SECONDS, 3600);
    let now = T0;
    const rot = new RotatingEndpointSecret({ currentSecret: NEW_SECRET, previousSecret: OLD_SECRET, nowMs: () => now });
    // Construction at T0: just-retired, one hour of grace.
    now = T0 + 3599 * 1000;
    assert.ok(rot.previousInGrace());
    now = T0 + 3600 * 1000;
    assert.ok(rot.previousInGrace()); // inclusive
    now = T0 + 3600 * 1000 + 1;
    assert.ok(!rot.previousInGrace());
    assert.ok(rot.isRotationComplete());
  });
});

describe("secret rotation rule selection and validation", () => {
  it("matches exact and prefix patterns, first rule wins", () => {
    const compiled = compileSecretRotationRules([
      { pattern: "/hooks/*", rotation: cfg() },
      { pattern: "/hooks/stripe", rotation: cfg({ currentSecret: "other" }) },
    ])!;
    assert.ok(selectSecretRotation("/hooks/stripe", compiled) !== undefined);
    assert.equal(selectSecretRotation("/hooks/stripe", compiled), compiled[0].secret);
    assert.equal(selectSecretRotation("/hooks", compiled), compiled[0].secret);
    assert.equal(selectSecretRotation("/hooksx", compiled), undefined);
    assert.equal(selectSecretRotation("/other", compiled), undefined);
    assert.equal(selectSecretRotation("/hooks/stripe", undefined), undefined);
  });

  it("fails fast on bad rules", () => {
    assert.throws(() => assertValidSecretRotationRules("nope" as never), RangeError);
    assert.throws(
      () => assertValidSecretRotationRules([{ pattern: "no-slash", rotation: cfg() }]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidSecretRotationRules([
          { pattern: "/hooks/x", rotation: { currentSecret: "" } as SecretRotationConfig },
        ]),
      RangeError
    );
  });
});

describe("server dual-secret rotation", () => {
  let stub: Server;
  let stubPort: number;

  before(async () => {
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function makeRelay(rotationCfg: SecretRotationConfig, extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "global-secret",
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      secretRotation: [{ pattern: "/hooks/rot", rotation: rotationCfg }],
      ...extra,
    });
    return { relay, audit };
  }

  async function withRelay(rotationCfg: SecretRotationConfig, extra: Record<string, unknown> = {}) {
    const { relay, audit } = makeRelay(rotationCfg, extra);
    const port = await listen(relay as unknown as Server);
    return {
      port,
      audit,
      close: async () => {
        (relay as unknown as Server).close();
        await new Promise((r) => (relay as unknown as Server).once("close", r));
      },
    };
  }

  it("accepts both secrets inside the grace window and audits previous-key use", async () => {
    const r = await withRelay(cfg());
    try {
      const cur = await post(r.port, "/hooks/rot", BODY, { "x-signature": signSha256(BODY, NEW_SECRET) });
      assert.equal(cur.status, 202);
      const prev = await post(r.port, "/hooks/rot", BODY, { "x-signature": signSha256(BODY, OLD_SECRET) });
      assert.equal(prev.status, 202);

      const events = r.audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 2);
      const rotEvents = events.filter((e) => e.event === "secret_rotation_previous_used");
      assert.equal(rotEvents.length, 1);
      assert.equal(rotEvents[0].endpoint, "/hooks/rot");
      // Unmatched paths still use the global secret.
      const globalOk = await post(r.port, "/hooks/other", BODY, { "x-signature": signSha256(BODY, "global-secret") });
      assert.equal(globalOk.status, 202);
      const globalOld = await post(r.port, "/hooks/other", BODY, { "x-signature": signSha256(BODY, OLD_SECRET) });
      assert.equal(globalOld.status, 401);
    } finally {
      await r.close();
    }
  });

  it("honors x-signature-version: explicit selection, no fallback, fail closed", async () => {
    const r = await withRelay(cfg());
    try {
      const mismatch = await post(r.port, "/hooks/rot", BODY, {
        "x-signature": signSha256(BODY, OLD_SECRET),
        "x-signature-version": "current",
      });
      assert.equal(mismatch.status, 401);
      const unknown = await post(r.port, "/hooks/rot", BODY, {
        "x-signature": signSha256(BODY, NEW_SECRET),
        "x-signature-version": "v3",
      });
      assert.equal(unknown.status, 401);
      const explicitPrev = await post(r.port, "/hooks/rot", BODY, {
        "x-signature": signSha256(BODY, OLD_SECRET),
        "x-signature-version": "previous",
      });
      assert.equal(explicitPrev.status, 202);
      const events = r.audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.filter((e) => e.event === "rejected");
      assert.equal(rejected.length, 2);
      assert.ok(rejected.every((e) => e.reason === "invalid_signature"));
    } finally {
      await r.close();
    }
  });

  it("rejects the previous secret after its grace window elapses", async () => {
    const r = await withRelay(cfg({ nowMs: () => T0 + 61 * 1000 }));
    try {
      const prev = await post(r.port, "/hooks/rot", BODY, { "x-signature": signSha256(BODY, OLD_SECRET) });
      assert.equal(prev.status, 401);
      const cur = await post(r.port, "/hooks/rot", BODY, { "x-signature": signSha256(BODY, NEW_SECRET) });
      assert.equal(cur.status, 202);
    } finally {
      await r.close();
    }
  });

  it("a per-endpoint verifier rule takes precedence over the rotation rule", async () => {
    const ed = new HmacSha256Verifier("path-secret") as Verifier;
    const r = await withRelay(cfg(), { endpointVerifiers: [{ pattern: "/hooks/rot", verifier: ed }] });
    try {
      const rotOk = await post(r.port, "/hooks/rot", BODY, { "x-signature": signSha256(BODY, NEW_SECRET) });
      assert.equal(rotOk.status, 401); // rotation rule ignored on this path
      const pathOk = await post(r.port, "/hooks/rot", BODY, { "x-signature": signSha256(BODY, "path-secret") });
      assert.equal(pathOk.status, 202);
    } finally {
      await r.close();
    }
  });

  it("rejects invalid rotation rules at startup", async () => {
    assert.throws(
      () =>
        createRelayServer({
          secret: "global-secret",
          forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
          secretRotation: [{ pattern: "/hooks/rot", rotation: { currentSecret: "" } as SecretRotationConfig }],
        }),
      RangeError
    );
  });
});
