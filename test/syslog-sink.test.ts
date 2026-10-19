import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createSocket, type Socket as UdpSocket } from "node:dgram";
import { createServer, type Server as TcpServer, type Socket as TcpSocket } from "node:net";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.ts";
import {
  SyslogAuditSink,
  buildSyslogFrame,
  cefLine,
  resolveSyslogFacility,
  syslogSeverity,
  SYSLOG_DEFAULT_PORT,
  SYSLOG_MAX_UDP_FRAME_BYTES,
  type SyslogAuditSinkOptions,
  type SyslogFrameOptions,
} from "../src/syslog-sink.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/HOST-style names here.
const fixedNow = 1_700_000_000_000;
const appName = "test-relay";
const hostName = "testhost";

function tmpAudit(): { dir: string; log: AuditLog } {
  const dir = mkdtempSync(join(tmpdir(), "syslog-sink-"));
  return { dir, log: new AuditLog(join(dir, "audit.jsonl")) };
}

function sinkOpts(extra: Partial<SyslogAuditSinkOptions> = {}): SyslogAuditSinkOptions {
  return {
    host: "127.0.0.1",
    pollIntervalMs: 10,
    initialBackoffMs: 5,
    maxBackoffMs: 20,
    sendTimeoutMs: 2000,
    connectTimeoutMs: 1000,
    now: () => fixedNow,
    appName,
    hostname: hostName,
    ...extra,
  };
}

function frameOpts(extra: Partial<SyslogFrameOptions> = {}): SyslogFrameOptions {
  return {
    facility: 16,
    format: "rfc5424",
    appName,
    hostname: hostName,
    productVersion: "0.1.0",
    now: () => fixedNow,
    transport: "udp",
    ...extra,
  };
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (cond()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

/** Parse `<PRI>1 <ts> <host> <app> <pid> <msgid> - <msg>`. */
function parseFrame(frame: Buffer): {
  pri: number;
  ts: string;
  host: string;
  app: string;
  msgid: string;
  msg: string;
} {
  const text = frame.toString("utf8");
  const m = text.match(/^<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) - ([\s\S]*)$/);
  assert.ok(m, `frame does not match RFC 5424 shape: ${text.slice(0, 120)}`);
  return {
    pri: Number(m[1]),
    ts: m[2],
    host: m[3],
    app: m[4],
    msgid: m[6],
    msg: m[7],
  };
}

/** Query audit entries of one event as plain records. */
function audit_query(log: AuditLog, event: string): Record<string, unknown>[] {
  return log.query({ event }) as Record<string, unknown>[];
}

interface TcpRx {
  server: TcpServer;
  port: number;
  frames: Buffer[];
  sockets: TcpSocket[];
}

/** TCP receiver that parses RFC 5425 octet-counted frames. */
async function tcpReceiver(): Promise<TcpRx> {
  const frames: Buffer[] = [];
  const sockets: TcpSocket[] = [];
  const server = createServer((sock) => {
    sockets.push(sock);
    let buf = Buffer.alloc(0);
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        const sp = buf.indexOf(0x20);
        if (sp < 0) break;
        const n = Number(buf.subarray(0, sp).toString("ascii"));
        if (!Number.isInteger(n) || n < 0) break; // desync: stop parsing
        if (buf.length < sp + 1 + n) break;
        frames.push(buf.subarray(sp + 1, sp + 1 + n));
        buf = buf.subarray(sp + 1 + n);
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr !== null ? addr.port : 0;
  return { server, port, frames, sockets };
}

/** A port that is (almost surely) closed: bind, read, close. */
async function closedPort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const addr = probe.address();
  const port = typeof addr === "object" && addr !== null ? addr.port : 0;
  await new Promise<void>((resolve) => probe.close(resolve));
  return port;
}

/**
 * Whether this environment permits UDP sendto to loopback. The
 * sandbox denies it with EPERM at the syscall level (DNS-over-UDP to
 * the sandbox resolver still works). Probe once; UDP live-send tests
 * skip when blocked.
 */
let udpLoopbackProbe: boolean | null = null;
async function udpLoopbackWorks(): Promise<boolean> {
  if (udpLoopbackProbe !== null) return udpLoopbackProbe;
  udpLoopbackProbe = await new Promise<boolean>((resolve) => {
    const tx = createSocket("udp4");
    let done = false;
    const finish = (ok: boolean): void => {
      if (done) return;
      done = true;
      try {
        tx.close();
      } catch {
        // Best-effort close of the probe socket.
      }
      resolve(ok);
    };
    tx.send(Buffer.from("probe"), 9999, "127.0.0.1", (err) => finish(!err));
    setTimeout(() => finish(false), 2000).unref();
  });
  return udpLoopbackProbe;
}

describe("syslog sink config (WR-157)", () => {
  it("rejects invalid config fail-fast", () => {
    const { log } = tmpAudit();
    assert.throws(() => new SyslogAuditSink(log, sinkOpts({ host: "" })), RangeError);
    assert.throws(() => new SyslogAuditSink(log, sinkOpts({ port: 0 })), RangeError);
    assert.throws(() => new SyslogAuditSink(log, sinkOpts({ port: 65536 })), RangeError);
    assert.throws(() => new SyslogAuditSink(log, sinkOpts({ port: 1.5 })), RangeError);
    assert.throws(
      () => new SyslogAuditSink(log, sinkOpts({ transport: "sctp" as never })),
      RangeError
    );
    assert.throws(() => new SyslogAuditSink(log, sinkOpts({ facility: 24 })), RangeError);
    assert.throws(() => new SyslogAuditSink(log, sinkOpts({ facility: "local9" })), RangeError);
    assert.throws(
      () => new SyslogAuditSink(log, sinkOpts({ format: "json" as never })),
      RangeError
    );
    assert.throws(() => new SyslogAuditSink(log, sinkOpts({ maxAttempts: 0 })), RangeError);
  });

  it("resolves facility names and numbers; defaults are sane", () => {
    assert.equal(resolveSyslogFacility("local0"), 16);
    assert.equal(resolveSyslogFacility("LOCAL7"), 23);
    assert.equal(resolveSyslogFacility("daemon"), 3);
    assert.equal(resolveSyslogFacility(5), 5);
    assert.throws(() => resolveSyslogFacility("nope"), RangeError);
    const { log } = tmpAudit();
    const sink = new SyslogAuditSink(log, { host: "127.0.0.1" });
    assert.equal(SYSLOG_DEFAULT_PORT, 514);
    sink.stop();
  });

  it("maps severities by tier; unknown events are informational", () => {
    assert.equal(syslogSeverity("ocsp_revoked"), 2);
    assert.equal(syslogSeverity("dead_letter"), 3);
    assert.equal(syslogSeverity("rejected"), 4);
    assert.equal(syslogSeverity("api_key_revoked"), 5);
    assert.equal(syslogSeverity("operator_key_revoked"), 5);
    assert.equal(syslogSeverity("delivered"), 6);
    assert.equal(syslogSeverity("some_future_event"), 6);
  });
});

describe("syslog frame building (pure, no I/O)", () => {
  it("builds RFC 5424 frames: PRI, envelope, msgid, raw JSON msg", () => {
    const line = Buffer.from('{"event":"delivered","tenant":"t1","traceId":"tr-1"}');
    const frame = buildSyslogFrame(frameOpts(), "delivered", line, { event: "delivered" });
    const f = parseFrame(frame);
    // local0(16)*8 + informational(6) = 134
    assert.equal(f.pri, 134);
    assert.equal(f.host, hostName);
    assert.equal(f.app, appName);
    assert.equal(f.msgid, "delivered");
    // The timestamp round-trips to the injected clock.
    assert.equal(Date.parse(f.ts), fixedNow);
    assert.equal(f.msg, line.toString("utf8"));

    const warn = buildSyslogFrame(frameOpts(), "rejected", line, { event: "rejected" });
    // local0(16)*8 + warning(4) = 132
    assert.equal(parseFrame(warn).pri, 132);
  });

  it("formats CEF records with mapped extensions and escaping", () => {
    const rec = {
      event: "api_key_revoked",
      tenant: "t9",
      traceId: "tr-9",
      keyId: "old",
      reason: "leak=suspected\\urgent",
    };
    const out = cefLine("api_key_revoked", rec, "0.1.0");
    // notice(5) -> CEF 10 - round(50/7) = 3
    assert.ok(
      out.startsWith("CEF:0|Jeremiah-D|webhook-relay|0.1.0|api_key_revoked|api_key_revoked|3|"),
      `CEF header wrong: ${out.slice(0, 100)}`
    );
    assert.ok(out.includes("cs1=t9 cs1Label=tenant"), "tenant extension");
    assert.ok(out.includes("cs2=tr-9 cs2Label=traceId"), "traceId extension");
    assert.ok(out.includes("cs3=old cs3Label=keyId"), "keyId extension");
    assert.ok(out.includes("reason=leak\\=suspected\\\\urgent"), `reason escaping wrong: ${out}`);
  });

  it("escapes newlines and pipes in CEF fields", () => {
    const out = cefLine("rejected", { event: "rejected", reason: "line1\nline2" }, "0.1.0");
    assert.ok(out.includes("reason=line1\\nline2"), `newline escaping wrong: ${out}`);
    assert.ok(!out.includes("line1\nline2"), "raw newline must not leak into the record");
    const piped = cefLine("a|b", { event: "a|b" }, "0.1.0");
    assert.ok(piped.includes("a\\|b"), `pipe escaping wrong: ${piped}`);
  });

  it("truncates oversized UDP frames to one datagram; TCP frames are not truncated", () => {
    const big = Buffer.alloc(100_000, 0x78);
    const udp = buildSyslogFrame(frameOpts(), "delivered", big, { event: "delivered" });
    assert.ok(udp.length <= SYSLOG_MAX_UDP_FRAME_BYTES, `UDP frame too large: ${udp.length}`);
    assert.equal(parseFrame(udp).msgid, "delivered");
    const tcp = buildSyslogFrame(frameOpts({ transport: "tcp" }), "delivered", big, {
      event: "delivered",
    });
    assert.ok(tcp.length > SYSLOG_MAX_UDP_FRAME_BYTES, "TCP must not truncate");
  });

  it("embeds the CEF record in the RFC 5424 envelope when format is cef", () => {
    const frame = buildSyslogFrame(
      frameOpts({ format: "cef", facility: resolveSyslogFacility("local7") }),
      "api_key_revoked",
      Buffer.from('{"event":"api_key_revoked"}'),
      { event: "api_key_revoked", tenant: "t9" }
    );
    const f = parseFrame(frame);
    // local7(23)*8 + notice(5) = 189
    assert.equal(f.pri, 189);
    assert.equal(f.msgid, "api_key_revoked");
    assert.ok(f.msg.startsWith("CEF:0|"), `expected CEF payload, got: ${f.msg.slice(0, 40)}`);
  });
});

describe("syslog sink live UDP send", () => {
  const sockets: UdpSocket[] = [];
  const sinks: SyslogAuditSink[] = [];
  afterEach(() => {
    for (const s of sinks.splice(0)) s.stop();
    for (const sock of sockets.splice(0)) sock.close();
  });

  it("delivers datagrams to a live collector (skipped where the sandbox blocks UDP loopback)", async function () {
    if (!(await udpLoopbackWorks())) {
      this.skip("UDP sendto to 127.0.0.1 is blocked here (EPERM at the syscall level)");
      return;
    }
    const messages: Buffer[] = [];
    const rx = createSocket("udp4");
    sockets.push(rx);
    rx.on("message", (m) => messages.push(m));
    await new Promise<void>((resolve) => rx.bind(0, "127.0.0.1", resolve));
    const port = (rx.address() as { port: number }).port;

    const { log } = tmpAudit();
    const sink = new SyslogAuditSink(log, sinkOpts({ port }));
    sinks.push(sink);
    sink.start();
    log.append({ event: "delivered", n: 1 });
    await waitFor(() => messages.length === 1, 5000, "UDP datagram");
    const f = parseFrame(messages[0]);
    assert.equal(f.msgid, "delivered");
    assert.deepEqual(sink.stats(), { sent: 1, failedAttempts: 0, deadLetters: 0 });
  });
});

describe("syslog sink over TCP", () => {
  const receivers: TcpRx[] = [];
  const sinks: SyslogAuditSink[] = [];
  afterEach(() => {
    for (const s of sinks.splice(0)) s.stop();
    for (const r of receivers.splice(0)) {
      for (const sock of r.sockets) sock.destroy();
      r.server.close();
    }
  });

  it("sends RFC 5425 octet-counted frames in order", async () => {
    const rx = await tcpReceiver();
    receivers.push(rx);
    const { log } = tmpAudit();
    const sink = new SyslogAuditSink(log, sinkOpts({ port: rx.port, transport: "tcp" }));
    sinks.push(sink);
    sink.start();

    log.append({ event: "accepted", n: 1 });
    log.append({ event: "delivered", n: 2 });
    log.append({ event: "rejected", n: 3 });
    await waitFor(() => rx.frames.length === 3, 5000, "3 TCP frames");

    const parsed = rx.frames.map(parseFrame);
    assert.deepEqual(
      parsed.map((p) => p.msgid),
      ["accepted", "delivered", "rejected"]
    );
    assert.deepEqual(
      parsed.map((p) => (JSON.parse(p.msg) as { n: number }).n),
      [1, 2, 3]
    );
    assert.deepEqual(sink.stats(), { sent: 3, failedAttempts: 0, deadLetters: 0 });
  });

  it("dead-letters after maxAttempts on refused TCP and never re-forwards the dead letter", async () => {
    const port = await closedPort();
    const { log } = tmpAudit();
    const sink = new SyslogAuditSink(
      log,
      sinkOpts({
        port,
        transport: "tcp",
        maxAttempts: 2,
        connectTimeoutMs: 200,
      })
    );
    sinks.push(sink);
    sink.start();

    log.append({ event: "delivered", n: 1 });
    await waitFor(() => sink.stats().deadLetters === 1, 10000, "dead letter");
    assert.deepEqual(sink.stats(), { sent: 0, failedAttempts: 2, deadLetters: 1 });

    const dead = audit_query(log, "audit_sink_dead_letter");
    assert.equal(dead.length, 1);
    assert.equal(dead[0].eventName, "delivered");
    assert.equal(dead[0].sink, "syslog");
    assert.equal(dead[0].transport, "tcp");

    // The dead-letter bookkeeping line itself is skipped, not
    // re-forwarded: no second dead letter appears.
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(sink.stats().deadLetters, 1);
  });

  it("stop() halts forwarding; the cursor lets a new sink resume without redelivery", async () => {
    const rx = await tcpReceiver();
    receivers.push(rx);
    const { dir, log } = tmpAudit();
    const cursorFile = join(dir, "syslog-sink.cursor");
    const first = new SyslogAuditSink(
      log,
      sinkOpts({ port: rx.port, transport: "tcp", cursorFile })
    );
    first.start();
    log.append({ event: "delivered", n: 1 });
    await waitFor(() => rx.frames.length === 1, 5000, "first frame");
    first.stop();

    // Appending while stopped forwards nothing.
    log.append({ event: "delivered", n: 2 });
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(rx.frames.length, 1);

    // A new sink on the same log + cursor resumes after the cursor:
    // n:1 is not redelivered, n:2 is.
    const second = new SyslogAuditSink(
      log,
      sinkOpts({ port: rx.port, transport: "tcp", cursorFile })
    );
    sinks.push(second);
    second.start();
    await waitFor(() => rx.frames.length === 2, 5000, "resumed frame");
    const bodies = rx.frames.map((m) => JSON.parse(parseFrame(m).msg) as { n: number });
    assert.deepEqual(
      bodies.map((b) => b.n),
      [1, 2]
    );
  });
});

describe("syslog sink via createRelayServer", () => {
  const servers: Server[] = [];
  const receivers: TcpRx[] = [];
  afterEach(async () => {
    for (const s of servers.splice(0)) {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
    for (const r of receivers.splice(0)) {
      for (const sock of r.sockets) sock.destroy();
      r.server.close();
    }
  });

  it("the server builds, starts and stops the sink; intake audits flow to the collector", async () => {
    const rx = await tcpReceiver();
    receivers.push(rx);
    const dir = mkdtempSync(join(tmpdir(), "syslog-it-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      forwardUrl: "http://127.0.0.1:1/hook",
      auditLog: audit,
      apiKeys: { rules: [{ pattern: "/hooks/it", keys: [{ id: "k", key: "real-key" }] }] },
      syslogSink: {
        host: "127.0.0.1",
        port: rx.port,
        transport: "tcp",
        pollIntervalMs: 10,
        appName: "it-relay",
        hostname: "ithost",
      },
    });
    servers.push(relay);
    const port = await new Promise<number>((resolve) => {
      relay.listen(0, "127.0.0.1", () => {
        resolve((relay.address() as { port: number }).port);
      });
    });

    // Wrong API key -> 401 + `rejected` audit -> syslog frame.
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hooks/it",
          method: "POST",
          headers: { "content-type": "application/json", "x-api-key": "wrong-key" },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      req.on("error", reject);
      req.end("{}");
    });
    assert.equal(status, 401);

    await waitFor(() => rx.frames.length >= 1, 5000, "syslog frame from server");
    const frames = rx.frames.map(parseFrame);
    const rejected = frames.find((f) => f.msgid === "rejected");
    assert.ok(rejected, `no rejected frame among: ${frames.map((f) => f.msgid).join(",")}`);
    assert.equal(rejected.host, "ithost");
    assert.equal(rejected.app, "it-relay");
    const body = JSON.parse(rejected.msg) as Record<string, unknown>;
    assert.equal(body.reason, "api_key_invalid");
  });
});
