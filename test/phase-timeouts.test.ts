/**
 * WR-143: per-endpoint phase timeout budgets for outbound delivery attempts.
 *
 * Hermetic and fast: every stub is a localhost server and every budget is
 * 100-200ms. No test depends on wall-clock sleeps longer than the budget
 * under test plus a small margin.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PhaseTimeoutError,
  assertValidPhaseTimeoutBudgets,
  resolvePhaseTimeouts,
  type PhaseTimeoutBudgets,
} from "../src/phase-timeouts.ts";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import { RetryQueue, type Sender, type SloMissInfo } from "../src/retry.ts";
import { classifyFailure } from "../src/failure.ts";
import { AuditLog } from "../src/audit.ts";

/**
 * `createDefaultSender` takes its per-endpoint records positionally and
 * `phaseTimeouts` is the last parameter, so this helper fills the rest
 * with `undefined`. The firstByte integration test below guards the slot
 * behaviorally (a timeout really fires), so a future signature change
 * fails loudly instead of silently testing the wrong parameter.
 */
const senderWithPhaseTimeouts = (record: Record<string, PhaseTimeoutBudgets>) =>
  createDefaultSender(...(new Array(34).fill(undefined) as never[]), record);

async function listen(server: { listen(port: number, host: string, cb: () => void): unknown }): Promise<void> {
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
}

function portOf(server: { address(): unknown }): number {
  const addr = server.address();
  assert.ok(addr !== null && typeof addr === "object" && "port" in addr);
  return (addr as { port: number }).port;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

describe("phase timeout budgets (WR-143)", () => {
  describe("config validation", () => {
    it("accepts a single phase and all four phases", () => {
      assert.doesNotThrow(() => assertValidPhaseTimeoutBudgets({ firstByteMs: 1 }));
      assert.doesNotThrow(() =>
        assertValidPhaseTimeoutBudgets({ connectMs: 100, tlsMs: 200, firstByteMs: 300, bodyMs: 400 })
      );
    });

    it("rejects invalid entries with RangeError", () => {
      const bad: Array<[unknown, string]> = [
        [{}, "empty — at least one phase required"],
        [{ firstByteMs: 0 }, "zero"],
        [{ firstByteMs: -5 }, "negative"],
        [{ firstByteMs: 1.5 }, "non-integer"],
        [{ firstByteMs: Number.NaN }, "NaN"],
        [{ firstByteMs: Number.POSITIVE_INFINITY }, "infinite"],
        [{ firstByteMs: "100" }, "non-number"],
        [{ connectMs: 100, dnsMs: 50 }, "unknown phase (dns is never budgeted)"],
        [{ bogusMs: 50 }, "unknown phase key"],
        [null, "null"],
        ["100", "string"],
        [[], "array"],
      ];
      for (const [value, label] of bad) {
        assert.throws(() => assertValidPhaseTimeoutBudgets(value), RangeError, label);
      }
    });

    it("createDefaultSender fails fast, naming the endpoint", () => {
      assert.throws(
        () => senderWithPhaseTimeouts({ "http://127.0.0.1:1/hook": { firstByteMs: 0 } }),
        /invalid phaseTimeouts for http:\/\/127\.0\.0\.1:1\/hook/
      );
      assert.throws(
        () => senderWithPhaseTimeouts({ "http://127.0.0.1:1/hook": { dnsMs: 50 } as never }),
        RangeError
      );
    });
  });

  describe("resolvePhaseTimeouts", () => {
    it("matches exact targetUrl, misses otherwise", () => {
      const record = { "http://a/hook": { firstByteMs: 100 } };
      assert.deepEqual(resolvePhaseTimeouts("http://a/hook", record), { firstByteMs: 100 });
      assert.equal(resolvePhaseTimeouts("http://b/hook", record), undefined);
      assert.equal(resolvePhaseTimeouts("http://a/hook", undefined), undefined);
    });
  });

  describe("failure routing", () => {
    it("classifies retryable via the default fallthrough, carrying no payload", () => {
      const err = new PhaseTimeoutError("http://127.0.0.1:9/hook", "firstByte", 150);
      assert.equal(err.name, "PhaseTimeoutError");
      assert.equal(err.phase, "firstByte");
      assert.equal(err.timeoutMs, 150);
      assert.equal(err.targetUrl, "http://127.0.0.1:9/hook");
      const classified = classifyFailure(err);
      assert.equal(classified.failureClass, "retryable");
      assert.equal(classified.statusCode, undefined);
    });
  });

  describe("sender integration", () => {
    it("firstByte budget fires on a stub that accepts TCP but never responds", async () => {
      const stub = createHttpServer(() => {
        // Accept the request, never send a byte back.
      });
      await listen(stub);
      const target = `http://127.0.0.1:${portOf(stub)}/hook`;
      const sender = senderWithPhaseTimeouts({ [target]: { firstByteMs: 120 } });
      try {
        const err = await sender({
          id: "pt-firstbyte-1",
          payload: Buffer.from("phase-timeout-probe-body"),
          targetUrl: target,
          headers: {},
        }).then(
          () => {
            throw new Error("expected the attempt to reject");
          },
          (e: unknown) => e
        );
        assert.ok(err instanceof PhaseTimeoutError);
        assert.equal(err.phase, "firstByte");
        assert.equal(err.timeoutMs, 120);
        assert.equal(classifyFailure(err).failureClass, "retryable");
        // Zero payload bytes leaked into the failure.
        assert.ok(!err.message.includes("phase-timeout-probe-body"));
      } finally {
        sender.destroy();
        stub.close();
      }
    });

    it("tls budget fires when the handshake never completes, with zero payload bytes on the wire", async () => {
      const received: Buffer[] = [];
      const stub = createTcpServer((socket) => {
        socket.on("data", (chunk) => received.push(chunk));
        // Accept TCP, never complete the TLS handshake.
      });
      await listen(stub);
      const target = `https://127.0.0.1:${portOf(stub)}/hook`;
      const sender = senderWithPhaseTimeouts({ [target]: { tlsMs: 150 } });
      try {
        const err = await sender({
          id: "pt-tls-1",
          payload: Buffer.from("phase-timeout-probe-body"),
          targetUrl: target,
          headers: {},
        }).then(
          () => {
            throw new Error("expected the attempt to reject");
          },
          (e: unknown) => e
        );
        assert.ok(err instanceof PhaseTimeoutError);
        assert.equal(err.phase, "tls");
        // The stub must have seen the ClientHello — and nothing but
        // handshake records: no application-data record (0x17) may ever
        // appear, i.e. zero payload bytes reached the wire.
        const bytes = Buffer.concat(received);
        assert.ok(bytes.length > 0, "expected the stub to see a ClientHello");
        let off = 0;
        while (off + 5 <= bytes.length) {
          const recordType = bytes[off];
          const recordLen = bytes.readUInt16BE(off + 3);
          assert.equal(
            recordType,
            0x16,
            `expected only TLS handshake records, got record type 0x${recordType.toString(16)}`
          );
          off += 5 + recordLen;
        }
      } finally {
        sender.destroy();
        stub.close();
      }
    });

    it("body budget fires on a stub that sends headers then stalls", async () => {
      const stub = createHttpServer((req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.write("partial-body");
        // Never end the response.
      });
      await listen(stub);
      const target = `http://127.0.0.1:${portOf(stub)}/hook`;
      const sender = senderWithPhaseTimeouts({ [target]: { bodyMs: 120 } });
      try {
        const err = await sender({
          id: "pt-body-1",
          payload: Buffer.from("phase-timeout-probe-body"),
          targetUrl: target,
          headers: {},
        }).then(
          () => {
            throw new Error("expected the attempt to reject");
          },
          (e: unknown) => e
        );
        assert.ok(err instanceof PhaseTimeoutError);
        assert.equal(err.phase, "body");
        assert.equal(classifyFailure(err).failureClass, "retryable");
      } finally {
        sender.destroy();
        stub.close();
      }
    });

    it("an endpoint without phaseTimeouts keeps the current behavior", async () => {
      const stub = createHttpServer(() => {
        // Never respond.
      });
      await listen(stub);
      const target = `http://127.0.0.1:${portOf(stub)}/hook`;
      const sender = createDefaultSender();
      try {
        const pending = sender({
          id: "pt-plain-1",
          payload: Buffer.from("x"),
          targetUrl: target,
          headers: {},
        });
        // Swallow the eventual settlement (destroy below) so a late
        // rejection never surfaces as unhandled.
        pending.then(
          () => {},
          () => {}
        );
        const outcome = await Promise.race([
          pending.then(
            () => "settled",
            () => "rejected"
          ),
          sleep(400).then(() => "pending"),
        ]);
        // No phase timer armed: the attempt is still in flight well past
        // the budgets the configured endpoints above already tripped.
        assert.equal(outcome, "pending");
      } finally {
        sender.destroy();
        stub.close();
      }
    });

    it("connect/tls budgets never arm on pooled socket reuse", async () => {
      let connections = 0;
      const stub = createHttpServer((req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("ok");
      });
      stub.on("connection", () => {
        connections += 1;
      });
      await listen(stub);
      const target = `http://127.0.0.1:${portOf(stub)}/hook`;
      // Absurdly tight connect budget: if it ever armed against a reused
      // socket, a spurious timeout would fail the delivery.
      const sender = senderWithPhaseTimeouts({ [target]: { connectMs: 5 } });
      try {
        for (let i = 0; i < 3; i++) {
          const res = await sender({
            id: `pt-reuse-${i}`,
            payload: Buffer.from("x"),
            targetUrl: target,
            headers: {},
          });
          assert.equal(res?.statusCode, 200);
        }
        // All three deliveries rode one pooled socket — the reuse path
        // was genuinely exercised.
        assert.equal(connections, 1);
      } finally {
        sender.destroy();
        stub.close();
      }
    });
  });

  describe("slo_missed attribution", () => {
    it("attributes the timed-out phase into slo_missed, and omits it otherwise", async () => {
      const target = "http://127.0.0.1:9/hook";
      let attempts = 0;
      const misses: SloMissInfo[] = [];
      const flaky: Sender = async (item) => {
        attempts += 1;
        if (attempts === 1) {
          throw new PhaseTimeoutError(item.targetUrl, "firstByte", 50);
        }
        await sleep(30);
        return { statusCode: 200, body: Buffer.from("ok"), truncated: false };
      };
      const q = new RetryQueue({
        sender: flaky,
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 3,
        latency: { sloMs: 1, onSloMiss: (info) => misses.push(info) },
      });
      q.start();
      try {
        q.enqueue({ id: "pt-slo-1", payload: Buffer.from("x"), targetUrl: target, headers: {} });
        const deadline = Date.now() + 5000;
        while (misses.length === 0 && Date.now() < deadline) await sleep(10);
        assert.equal(misses.length, 1);
        // The SLO miss says which phase blew the budget — the phase
        // name only, never fabricated durations.
        assert.equal(misses[0].phaseTimeout, "firstByte");

        // A delivery with no phase timeout carries no attribution.
        q.enqueue({ id: "pt-slo-2", payload: Buffer.from("x"), targetUrl: target, headers: {} });
        const deadline2 = Date.now() + 5000;
        while (misses.length < 2 && Date.now() < deadline2) await sleep(10);
        assert.equal(misses.length, 2);
        assert.equal(misses[1].phaseTimeout, undefined);
      } finally {
        q.stop();
      }
    });
  });

  describe("createRelayServer plumbing", () => {
    it("accepts valid phaseTimeouts and fails fast on invalid ones", async () => {
      const dir = await mkdtemp(join(tmpdir(), "pt-"));
      const audit = new AuditLog(join(dir, "audit.jsonl"));
      const target = "http://127.0.0.1:9/hook";
      const base = {
        secret: "s",
        forwardUrl: target,
        auditLog: audit,
        retry: { baseDelayMs: 10, maxAttempts: 3 },
      };
      assert.throws(
        () =>
          createRelayServer({
            ...base,
            phaseTimeouts: { [target]: { firstByteMs: 0 } },
          }),
        RangeError
      );
      const relay = createRelayServer({
        ...base,
        phaseTimeouts: { [target]: { firstByteMs: 100 } },
      });
      relay.close();
    });
  });
});
