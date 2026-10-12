import { createHash, X509Certificate } from "node:crypto";
import {
  renderCertExpiryBlock,
  type CertExpiryMetricsInput,
} from "./metrics.ts";

/**
 * Downstream + own TLS certificate expiry warning (WR-73).
 *
 * Webhook relays die quietly at 3am when a downstream rotates (or forgets
 * to rotate) its TLS certificate: deliveries start failing with TLS
 * errors and the first signal is the outage itself. This module captures
 * the peer certificate's `notAfter` at handshake time — reusing the
 * `getPeerCertificate` read the WR-21 pin check and the WR-36 mTLS path
 * already perform on every new TLS connection — and warns *before* the
 * cliff:
 *
 * - when a certificate expires within the configurable threshold, one
 *   edge-triggered `cert_expiring` audit event fires (per certificate,
 *   not per handshake — a keep-alive pool serving a thousand deliveries
 *   over one connection alerts once);
 * - the current seconds-until-expiry per endpoint is exposed as the
 *   `relay_cert_expiry_seconds{endpoint,kind}` Prometheus gauge, so
 *   dashboards and alert rules can watch the countdown;
 * - the relay's own mTLS client certificates (`tlsClientCerts`) get the
 *   same treatment: they are checked at config load, because a relay
 *   presenting an expired client identity fails *every* handshake with
 *   no retry ever fixing it.
 *
 * Off by default (`enabled: false`): the monitor is constructed inert and
 * every observation method is a no-op, so the delivery path is
 * byte-identical to the pre-WR-73 relay when the feature is off.
 *
 * A monitor never breaks a delivery: unparseable certificates, empty peer
 * certificates (resumed TLS 1.3 sessions re-send no certificate), and
 * throwing observer hooks are all swallowed — expiry telemetry is an
 * observer, never a gate.
 *
 * Zero dependencies (`node:crypto` only).
 */

/** Default warning threshold: 14 days, in seconds. */
export const DEFAULT_CERT_EXPIRY_THRESHOLD_SECONDS = 14 * 24 * 3600;

/** Tuning for {@link CertExpiryMonitor}. All values are validated up front. */
export interface CertExpiryOptions {
  /**
   * Master switch for expiry monitoring. Default: `false` — off unless
   * explicitly enabled, so an unconfigured relay behaves exactly as
   * before. Must be a boolean.
   */
  enabled?: boolean;
  /**
   * Warn when a certificate expires within this many seconds (0 warns
   * only for already-expired certificates). Default: 14 days
   * (1_209_600). Must be a finite number >= 0.
   */
  thresholdSeconds?: number;
  /** Clock in ms epoch; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Validated {@link CertExpiryOptions} with defaults applied. */
export interface ResolvedCertExpiryOptions {
  enabled: boolean;
  thresholdSeconds: number;
  now: () => number;
}

/** Validate cert-expiry options the way a constructor would; returns the resolved values. */
export function resolveCertExpiryOptions(opts: CertExpiryOptions = {}): ResolvedCertExpiryOptions {
  const enabled = opts.enabled ?? false;
  if (typeof enabled !== "boolean") {
    throw new RangeError(`cert-expiry: enabled must be a boolean, got ${enabled}`);
  }
  const thresholdSeconds = opts.thresholdSeconds ?? DEFAULT_CERT_EXPIRY_THRESHOLD_SECONDS;
  if (
    typeof thresholdSeconds !== "number" ||
    !Number.isFinite(thresholdSeconds) ||
    thresholdSeconds < 0
  ) {
    throw new RangeError(
      `cert-expiry: thresholdSeconds must be a finite number >= 0, got ${thresholdSeconds}`
    );
  }
  const now = opts.now ?? Date.now;
  if (typeof now !== "function") {
    throw new RangeError(`cert-expiry: now must be a function, got ${typeof now}`);
  }
  return { enabled, thresholdSeconds, now };
}

/** The audit event fired once per certificate that enters the warning window. */
export interface CertExpiringAuditEvent {
  event: "cert_expiring";
  /** `"downstream"` = the peer's certificate; `"client"` = the relay's own mTLS client certificate. */
  kind: "downstream" | "client";
  /** The delivery `targetUrl` (downstream) or the `tlsClientCerts` key (client). */
  endpoint: string;
  /** ISO-8601 `notAfter` of the expiring certificate. */
  notAfter: string;
  /** Seconds until expiry (< 0 when already expired), floored. */
  expirySeconds: number;
  /** The configured warning threshold, in seconds. */
  thresholdSeconds: number;
  /** ISO-8601 timestamp when the warning fired. */
  at: string;
}

interface CertRecord {
  kind: "downstream" | "client";
  endpoint: string;
  notAfterMs: number;
}

/** The hook surface of {@link CertExpiryMonitor}. */
export interface CertExpiryHooks {
  /** Fired edge-triggered — once per certificate entering the warning window. */
  onCertExpiring?: (event: CertExpiringAuditEvent) => void;
}

/**
 * Certificate expiry monitor: observes DER/PEM certificates (handshake
 * peer certs and the relay's own mTLS client certs), fires one
 * `cert_expiring` audit event per certificate that is within the warning
 * threshold, and renders the `relay_cert_expiry_seconds` gauge rows.
 */
export class CertExpiryMonitor {
  private readonly opts: ResolvedCertExpiryOptions;
  private readonly onCertExpiring?: (event: CertExpiringAuditEvent) => void;
  /** Latest observed certificate per (kind, endpoint), in first-seen order. */
  private readonly latest = new Map<string, CertRecord>();
  /**
   * Alert keys already fired: `${kind}:${endpoint}:${fingerprint}` — the
   * edge trigger. A keep-alive connection serving a thousand deliveries
   * alerts once; a renewed certificate (new fingerprint) alerts again,
   * because a fresh cert already near expiry deserves its own warning.
   */
  private readonly alerted = new Set<string>();

  constructor(opts: ResolvedCertExpiryOptions, hooks: CertExpiryHooks = {}) {
    this.opts = opts;
    this.onCertExpiring = hooks.onCertExpiring;
  }

  /** Whether the feature is switched on. Observation is a no-op when false. */
  get enabled(): boolean {
    return this.opts.enabled;
  }

  /**
   * Observe the peer certificate of a TLS socket for `endpoint` (kind
   * `"downstream"`): reads `getPeerCertificate().raw`, the same read the
   * WR-21 pin check performs. No-op when the socket has no readable
   * certificate (a resumed TLS 1.3 session re-sends none) or the
   * certificate is unparseable — telemetry never breaks a delivery.
   */
  observePeerCertificate(socket: { getPeerCertificate(): unknown }, endpoint: string): void {
    if (!this.opts.enabled) return;
    let raw: unknown;
    try {
      raw = (socket.getPeerCertificate() as { raw?: unknown } | undefined)?.raw;
    } catch {
      return;
    }
    if (raw === undefined) return;
    this.observe(raw as Buffer, endpoint, "downstream");
  }

  /**
   * Observe a DER-encoded peer certificate for `endpoint` (kind
   * `"downstream"`). Lets handshake paths that already read the peer
   * certificate (e.g. the pin check in `verifyFreshPin`) feed the
   * monitor without a second `getPeerCertificate` call.
   */
  observePeerCertificateDer(raw: Buffer, endpoint: string): void {
    if (!this.opts.enabled) return;
    this.observe(raw, endpoint, "downstream");
  }

  /**
   * Check the relay's own mTLS client certificate for `endpoint` (kind
   * `"client"`): PEM string (as held by `tlsClientCerts`) or DER. Run at
   * config load — an expired client identity fails every handshake and
   * no retry ever fixes it.
   */
  checkClientCertificate(certPem: string | Buffer, endpoint: string): void {
    if (!this.opts.enabled) return;
    this.observe(certPem, endpoint, "client");
  }

  private observe(data: Buffer | string, endpoint: string, kind: "downstream" | "client"): void {
    let cert: X509Certificate;
    try {
      cert = new X509Certificate(data);
    } catch {
      // Fail-soft: an unreadable certificate is not worth an alert, and
      // a monitor must never break the delivery path.
      return;
    }
    const notAfterMs = Date.parse(cert.validTo);
    if (Number.isNaN(notAfterMs)) return;
    const key = `${kind}:${endpoint}`;
    this.latest.set(key, { kind, endpoint, notAfterMs });
    const expirySeconds = Math.floor((notAfterMs - this.opts.now()) / 1000);
    if (expirySeconds > this.opts.thresholdSeconds) return;
    // SHA-256 over the DER bytes (PEM decodes deterministically, so the
    // fingerprint is stable across encodings of the same certificate).
    const fingerprint = createHash("sha256").update(cert.raw).digest("hex");
    const alertKey = `${key}:${fingerprint}`;
    if (this.alerted.has(alertKey)) return;
    this.alerted.add(alertKey);
    this.onCertExpiring?.({
      event: "cert_expiring",
      kind,
      endpoint,
      notAfter: new Date(notAfterMs).toISOString(),
      expirySeconds,
      thresholdSeconds: this.opts.thresholdSeconds,
      at: new Date(this.opts.now()).toISOString(),
    });
  }

  /**
   * Current gauge rows — one per (kind, endpoint) ever observed,
   * first-seen order. `expirySeconds` is computed at call time against
   * the monitor's clock, so a scrape always sees the live countdown
   * (negative when already expired).
   */
  series(): CertExpiryMetricsInput[] {
    if (!this.opts.enabled) return [];
    const nowMs = this.opts.now();
    return [...this.latest.values()].map((r) => ({
      endpoint: r.endpoint,
      kind: r.kind,
      expirySeconds: Math.floor((r.notAfterMs - nowMs) / 1000),
    }));
  }

  /**
   * Prometheus text exposition (0.0.4) of the gauge block; `""` when
   * nothing was observed, so `GET /metrics` stays byte-identical for
   * relays that never enabled the feature or never handshaked TLS.
   */
  render(): string {
    const lines = renderCertExpiryBlock(this.series());
    return lines.length === 0 ? "" : lines.join("\n") + "\n";
  }
}
