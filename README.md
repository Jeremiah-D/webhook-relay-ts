# webhook-relay-ts

> **Portfolio reconstruction.** This is a small project built to demonstrate
> webhook-signature verification and delivery-reliability engineering. It is
> not employer production code and re-implements no proprietary system.

A dependency-free TypeScript webhook relay: verify an incoming webhook through
a pluggable verifier interface (HMAC-SHA256 default, Ed25519 and RSA-PSS
included),
enqueue it into a retry queue with exponential backoff, forward it to a
downstream URL, and record everything in an append-only audit log.

## Inspiration

The author's public LinkedIn profile includes this line (the only external
reference for this project):

> "Developed wallet-signature verification (EIP-712)"

EIP-712 itself is **out of scope** here. This repo demonstrates the general
pattern on the webhook side instead: HMAC-SHA256 request signing, constant-time
verification, replay protection via timestamped signatures, at-least-once
delivery with backoff + dead-lettering, and JSONL audit logging — the same
reliability primitives that matter for any signed-payload pipeline.

## What it does

- `src/verify.ts` — pluggable signature verification. The `Verifier` interface
  (`verify(rawBody, header, opts)`, never throws) plus a name registry
  (`registerVerifier` / `getVerifier` / `verifyWith`) lets you add schemes
  without touching the server. Built in: `HmacSha256Verifier` (default —
  `sha256=<hex>` and `t=<unix_ts>,v1=<hex>` formats, the timestamped one
  covers `<ts>.<rawBody>`), `Ed25519Verifier` (`ed25519=<hex>` over the
  raw body, PEM public key), and `RsaPssVerifier` (WR-110 — `rsa-sha256=<base64>`
  over the raw body, SHA-256 with a 32-byte PSS salt, PEM RSA public key;
  `signRsaPss` builds the header). Uses `crypto.timingSafeEqual` on the HMAC path
  and enforces a timestamp tolerance window (default 300s).
  `RotatingHmacVerifier` (also in `src/verify.ts`) layers key rotation on
  top: several HMAC keys coexist with one primary for new signatures,
  retired keys stay verifiable inside a grace window (default 24h), and
  `verifyDetailed` reports which key id verified for the audit trail.
  `RotatingRsaPssVerifier` (WR-110) is the asymmetric counterpart: several
  RSA public keys are tried in order so the old and new key both verify in
  parallel during a rotation window, and `verifyDetailed` reports the
  SHA-256 fingerprint of the matching key (surfaced as `keyId` in the
  accepted-audit event, like the HMAC rotation).
  `selectEndpointVerifier` / `assertValidEndpointVerifierRules` implement
  per-endpoint verifier selection: inbound paths match `{ pattern,
  verifier }` rules (exact `/hooks/stripe` or prefix `/hooks/*`, first
  match wins, unmatched paths fall back to the global verifier), so one
  relay can trust Ed25519 for one upstream and HMAC-SHA256 for another.
- `src/secret-rotation.ts` — inbound HMAC secret dual-version
  zero-downtime rotation (`RotatingEndpointSecret`, WR-67): one endpoint
  carries `currentSecret` + `previousSecret` in parallel while the
  sender migrates, so in-flight webhooks signed with the old key keep
  verifying instead of 401-storming. Senders declare the signing side
  with the `x-signature-version` header (`"current"` / `"previous"`);
  without it the server tries `current` first and falls back to
  `previous` inside its grace window (default 1h, inclusive boundary,
  matching the WR-20 convention). An unknown version value fails closed;
  a per-endpoint verifier rule (WR-29), a custom global `verifier`, or
  `signingKeys` (WR-20) takes precedence and the rotation rule is
  ignored there. Wired into the server via `secretRotation:
  [{ pattern, rotation }]` (same exact/prefix path semantics as the
  verifier rules); invalid rules throw `RangeError` at startup. Every
  `previous`-verified webhook is audited as
  `secret_rotation_previous_used` — the operator's signal for when the
  rotation is ready to complete — and
  `RotatingEndpointSecret#isRotationComplete()` reports when the grace
  window has elapsed so `previousSecret` can be cleared. Orthogonal to
  WR-65: in API-key-only mode the key gate authenticates; in
  `requireSignature` mode the dual-secret check is the signature leg.
- `src/version.ts` — inbound API version routing (`ApiVersionRouter`).
  Version prefixes in the inbound path (`/v1/...`, `/v2/...`, segment
  boundaries only, longest prefix wins) route the payload through a
  pluggable `ApiVersionAdapter` that reshapes it into the current schema
  *after* signature verification (the signature covers the raw body the
  sender signed) and *before* dedup/enqueue — so dedup hashes the
  adapted payload and the same event sent as `v1` and `v2` suppresses to
  one delivery. An adapter that throws answers 400 (audited as `rejected`
  with reason `version_adapt_failed`; it never touches the retry queue).
  The matched version lands on `accepted` audit events (`version`) and in
  `relay_inbound_version_total{version,status}` (unversioned requests
  count under `version="none"`); paths without a registered prefix are
  untouched — no `version` field anywhere, exactly the legacy behavior.
  Invalid routes throw `RangeError` at startup.
  - WR-144 per-version sunset (opt-in): a route's `sunsetAt` (epoch-ms or
    ISO-8601) retires the version — once reached, matching intakes are
    answered `410 Gone` with the RFC 8594 `Sunset` header and audited as
    `rejected` with reason `version_sunset`; they never reach the adapter
    or the retry queue. Sunsets are hot-updatable (immediate effect, no
    restart) via `POST /config/version-sunset` (operator, admin scope;
    body `{ prefix, sunsetAt }`, `null` clears) and audited as
    `version_sunset_updated`; `GET /config/version-sunset` (operator,
    read scope) inspects every route's effective sunset. Invalid moments
    throw `RangeError` at startup and 400 on the operator endpoint —
    a 400 always means "nothing changed".
- `src/schema.ts` — inbound payload JSON schema registry
  (`selectEndpointSchema`). Per-endpoint pluggable shape validation, off
  by default: inbound paths match `{ pattern, schema }` rules (exact
  `/hooks/stripe` or prefix `/hooks/*`, first match wins; unmatched paths
  skip validation entirely). The check runs on the *verified, adapted*
  body — after signature verification and `src/version.ts` adaptation, so
  a v1 payload reshaped into the current schema validates against the
  current schema — and *before* the replay guard and dedup (ordering:
  verify → version-adapt → schema → replay → dedup → enqueue). A payload
  that fails is answered 400 and audited as `rejected` with reason
  `schema_failed`; it never enters the queue, so it burns no retry
  budget and never trips the breaker. Schemas validate JSON (a non-JSON
  body fails), and a throwing validator is fail-closed. When a version
  route matched, rules are first tried against the version-stripped path
  (one `/hooks/*` rule covers `/v1/hooks/...` and `/v2/hooks/...`), then
  the full inbound path (so per-version rules like `/v1/admin/*` work).
  The schema's name and version ride on `accepted`
  (`schema`/`schemaVersion`) and `rejected` audit events, so version
  changes are visible in the audit trail, and intakes render as
  `relay_inbound_schema_total{schema,status}`. Ships a minimal built-in
  `createRequiredFieldsSchema(name, version, fields)` for the common
  required-fields gate; bring your own `PayloadSchema` for types, enums,
  or ranges. Invalid rules throw `RangeError` at startup. The opt-in
  WR-96 compatibility gate (`compatibilityCorpus` on a rule) guards
  schema evolution: manually registered sample payloads the endpoint
  historically accepted, and/or auto-accumulated accepted payloads
  (bounded, oldest-first eviction), are all run through the new
  validator at registration time — any rejected or throwing sample fails
  registration with `RangeError` and registers nothing, leaving the
  currently serving schema for the pattern untouched (EB-95 convention);
  registering a newer schema version for the same pattern is gated the
  same way, against samples accumulated while older versions served.
  Per-schema gate results (`'passed'` / `'not-tested'`) and corpus sizes
  are exposed via `InboundSchemaRegistry.getStats()` and on `/metrics`
  (`relay_inbound_schema_compat_gate`, `relay_inbound_schema_corpus_size`).
- `src/retry.ts` — `RetryQueue` with exponential backoff (`base * 2^attempt`)
  plus jitter, a `maxDelay` cap, a dead-letter list after `maxAttempts`, and an
  injectable sender/timer for deterministic testing. Jitter is configurable:
  `"additive"` (uniform(0, `jitterMs`) on top, default) or `"full"` (AWS-style
  uniform(0, min(cap, base*2^attempt)) — the recommended anti-thundering-herd
  choice when many deliveries fail at once); the random source is injectable
  (`random`) so jitter bounds are testable, and invalid configs
  (non-positive base/cap, `maxAttempts < 1`, negative jitter) throw
  `RangeError`. The opt-in adaptive backoff (`adaptiveBackoff`, WR-59,
  off by default) scales the backoff *base* per endpoint from recent
  delivery outcomes — consecutive retryable failures double it toward
  `maxBaseMs`, successes halve it back toward `minBaseMs` — while the
  exponent, jitter strategy, and cap keep working as before; it composes
  orthogonally with the global retry budget (WR-38, which gates first),
  and `getAdaptiveBackoffStats()` exposes each endpoint's current base.
  The opt-in adaptive concurrency (`adaptiveConcurrency`, WR-94, off by
  default) adds an outcome-driven AIMD cap per endpoint — additive
  increase per healthy outcome window, multiplicative decrease per
  congested one — and the effective per-endpoint limit becomes
  `min(maxConcurrentPerEndpoint, adaptive)`: the adaptive cap can only
  ever tighten the fixed cap, never exceed it. 429/5xx/timeout outcomes
  heat the controller; answering rejections (including non-retryable 4xx)
  cool it; `getAdaptiveConcurrencyStats()` exposes each endpoint's
  current limit, and `relay_adaptive_concurrency_limit{endpoint}` exports
  it to Prometheus.
  Dead-lettered items carry `attempts`, `lastError`, and
  `deadLetteredAt`, and can be re-queued with a fresh attempt budget via
  `replayDeadLetter(id)` / `replayAllDeadLetters()`. Per-endpoint concurrency
  is capped with `maxConcurrentPerEndpoint` (default unlimited): at most N
  deliveries in flight to the same `targetUrl`, excess waits FIFO for a slot,
  and `getConcurrencyStats()` reports in-flight/queued counts per endpoint.
  Urgent deliveries (`priority: "urgent"`, mapped from the inbound
  `x-priority: urgent` header) take an independent fast lane: they skip the
  exponential backoff (a fixed `urgent.retryDelayMs`, default 0) and bypass
  the per-endpoint concurrency limiter, so an urgent delivery never waits
  behind queued normal deliveries. Each urgent attempt costs one token from
  a per-endpoint bucket (`urgent.maxUrgentPerSecond`, default 100/s, burst
  of one second) — an empty bucket degrades the item to the normal lane
  instead of dropping it, which is the lane's abuse guard.
  `getUrgentStats()` reports per-endpoint `delivered` / `retried` /
  `throttled` counters. Under sustained urgent load a per-endpoint
  deficit round-robin scheduler (WR-35, `urgent.minNormalShare`, default
  20%, per-endpoint overridable via `setEndpointMinNormalShare()`)
  guarantees the normal lane at least that share of dispatch turns while
  normal deliveries are backlogged: each normal dispatch earns the urgent
  lane its proportional turns, and urgent turns beyond that wait. The
  scheduler is work-conserving (a lone lane is never delayed) and
  ordering-only — it never sheds, never burns urgent tokens, and never
  touches the retry budget, so it composes with the token bucket without
  double rate-limiting. Guard activations are counted in
  `relay_starvation_guard_activations{endpoint}` and audited as
  `starvation_guard_activated`; `getLaneStats()` reports per-endpoint
  turns granted per lane. A second, admission-side guard caps how long the
  fast lane may stay occupied in a row (WR-121,
  `urgent.maxConsecutiveUrgent`, disabled by default): after that many
  *consecutive* urgent admissions per endpoint, the next urgent item is
  force-downgraded to the normal lane — audited per occurrence as
  `urgent_downgraded` and counted in `getUrgentStats().downgraded` — without
  consuming a token. Any normal admission (or any downgrade) resets the
  streak, so genuinely interleaved demand never trips the guard; under a
  sustained urgent flood the normal lane keeps at least
  `1 / (maxConsecutiveUrgent + 1)` of the admission slots. Invalid values
  (non-integer, < 1) throw `RangeError` at construction.
- `src/quota.ts` — per-endpoint delivery quota (`EndpointQuota`): a token
  bucket sized to one minute of budget (`deliveriesPerMinute`), refilled
  lazily. An attempt that finds an empty bucket is rescheduled for the next
  token refill — never dropped, and never counted against the retry budget
  or the circuit breaker — so one tenant's flood auto-throttles instead of
  hammering the downstream. Wired into `RetryQueue` via
  `retry: { quota: { deliveriesPerMinute } }` (unlimited by default);
  `getQuotaStats()` reports per-endpoint `delayed` counts. Injectable clock
  for deterministic tests.
- `src/retry-budget.ts` — *global* retry budget (`RetryBudget`): one token
  bucket for the whole queue, sized to `retriesPerMinute` per minute
  (default 6000 — a guard rail, not a throttle). Every *scheduled retry*
  (first attempts are never gated) costs one token; when the bucket is
  empty the retry is parked until the next token refill — never dropped,
  and the parking itself consumes neither the item's attempt budget nor a
  circuit event. Retries resume automatically on refill, so a fleet-wide
  downstream outage spreads its retry storm over the refill window instead
  of stampeding a recovering downstream. Wired into `RetryQueue` via
  `retry: { retryBudget: { retriesPerMinute } }` (disabled by default);
  `getRetryBudgetStats()` reports the budget and the `depleted` park count,
  parkings are audited as `retry_budget_depleted`, and
  `relay_retry_budget_depleted_total` exposes the count to Prometheus.
  Injectable clock for deterministic tests. WR-125 adds opt-in
  per-endpoint overrides — `retry: { retryBudget: { perEndpointRetriesPerMinute:
  { "<targetUrl>": n } } }`: an overridden endpoint gates on its own
  bucket first, then on the global bucket, so one endpoint's retry storm
  parks only that endpoint's retries instead of starving the shared
  budget; endpoints without an override use the global budget only.
  `getRetryBudgetStats().endpoints` exposes each override's budget, park
  count, and remaining tokens, `relay_retry_budget_depleted_total` gains
  one `{endpoint}`-labeled series per parked endpoint (the unlabeled
  global row is retained), and the `retry_budget_depleted` audit event
  records which budget parked the retry (`budgetScope:
  "endpoint" | "global"`). Illegal values throw `RangeError` at
  construction; without overrides the relay is byte-identical to before.
- `src/delivery-window.ts` — per-endpoint delivery time windows ("quiet
  hours", WR-52): `retry: { deliveryWindow: { windows: { "<targetUrl>":
  "HH:MM-HH:MM" } } }` in UTC (open edge inclusive, close edge
  exclusive, may cross midnight). A delivery due outside its window is
  parked until the window opens — never dropped, never consuming the
  retry budget, a quota token, or a circuit-breaker verdict, and never
  dead-lettered for being out of window ("flush at window open").
  WR-126 adds opt-in per-endpoint IANA time zones —
  `deliveryWindow: { tzWindows: { "<targetUrl>": { window, timezone } } }`
  — evaluated against the zone's local wall clock (e.g. repayment
  reminders that must go out 09:00–18:00 in the *borrower's* zone);
  a UTC window and a timezone window are mutually exclusive per
  endpoint (`RangeError` at construction, as are unknown IANA zones).
  DST is handled honestly against wall-clock minutes (a spring-forward
  gap hour never matches; a fall-back repeated hour is indistinguishable
  from its first occurrence), via `Intl.DateTimeFormat` with zero new
  dependencies. `getDeliveryWindowStats()` reports per-endpoint
  `delayed` counts plus the effective `timezone`; runtime overrides via
  `setEndpointDeliveryWindow()` / `setEndpointTzDeliveryWindow()` /
  `deleteEndpointDeliveryWindow()`. Injectable clock for deterministic
  tests.
- `src/maintenance-window.ts` — per-endpoint one-shot maintenance
  windows (WR-127): `retry: { maintenanceWindow: { windows: {
  "<targetUrl>": [{ start: "2026-11-01T02:00:00Z", end:
  "2026-11-01T06:00:00Z" }] } } }` — a downstream cutover's blackout
  window, orthogonal to WR-52's *recurring* quiet hours (either gate
  parks the item). A delivery due inside a window is parked until the
  window ends ("flush at window close", close edge exclusive) with the
  same no-burn semantics as quiet hours: no quota token, no
  circuit-breaker verdict, no retry-budget token, never dead-lettered
  for being in a window. Overlapping (or touching) windows merge on
  insert; ended windows are pruned lazily. Window transitions are
  observable via `onTransition` — the server audits them as
  `maintenance_window_opened` / `maintenance_window_closed`.
  `getMaintenanceWindows()` reports live windows, park counts, and
  whether the endpoint is parked now; operators list and add windows at
  `GET` / `POST /maintenance/windows` (operator token required).
  RFC3339 validation is strict (`RangeError` on bad input); the clock
  is injectable for deterministic tests.
- `src/latency.ts` — accepted→delivered latency SLO tracking
  (`LatencyTracker`): `enqueue()` starts each delivery's clock, a successful
  delivery samples it into a bounded per-endpoint rolling window (default
  1024 samples), and dead-lettered items are discarded without sampling.
  `getLatencyStats()` — also served to operators at `GET /latency`
  (bearer-guarded, optional `?endpoint=` filter) — exposes per-endpoint
  count/min/max/mean plus nearest-rank p50/p95/p99 and the SLO attainment
  rate (`withinSlo / count` against `sloMs`, default 5000ms). Deliveries
  slower than the budget fire `onSloMiss` and are audited as `slo_missed`.
  The clock is injectable for deterministic tests.
- `src/latency-phases.ts` — delivery-latency phase breakdown
  (`LatencyPhasesTracker`), opt-in under `retry.latencyPhases` (disabled by
  default, zero overhead). The sender decomposes each delivery into
  dns/connect/tls/firstByte/body phases (HTTP/1.1 path; `createRelayServer`
  enables measurement exactly when the option is set) and the queue samples
  them into bounded per-endpoint rolling windows (nearest-rank p50/p95,
  WR-13 convention). A phase the sender could not measure is reported as
  *unavailable* — never fabricated: DNS is never attributable per-request
  (it resolves inside the connection machinery), connect/TLS need a fresh
  direct socket (pooled reuse and proxied tunnels report unavailable), and
  H2/WebSocket paths report all phases unavailable. On every SLO miss the
  dominant phase (largest measured duration) is attributed into the
  `slo_missed` audit event (`dominantPhase` + `phaseBreakdown`) and the
  OTLP `slo_missed` record. `getLatencyPhaseStats()` exposes the
  per-endpoint phase distributions.
- `src/slo-risk.ts` — SLO-breach prediction and early warning
  (`SloRiskPredictor`), opt-in under `retry.latency.sloRisk` (disabled by
  default). Every `enqueue` and every delivered sample feeds a per-endpoint
  observation; the score is `max(latencyPressure, backlogPressure)` where
  latency pressure is the rolling p95 against `sloMs` and backlog pressure
  is a forward queueing projection (backlog EWMA + smoothed trend ×
  unloaded service time ÷ endpoint concurrency — 0 when concurrency is
  unbounded). A score of 1.0 is a predicted breach; crossing `warnRatio`
  (default 0.8) fires `onSloRisk` with `state: "elevated"`, audited as
  `slo_risk`, and recovery below `warnRatio * clearRatio` (default 0.7)
  fires `state: "cleared"` — hysteresis, so a hovering score never flaps.
  Cold start (fewer than `minSamples` delivered samples, default 3) never
  fires. `getSloRiskStats()` — also served at `GET /slo-risk`
  (Bearer <redacted>-guarded, optional `?tenant=`) — exposes the snapshot, and
  `relay_slo_risk_seconds{endpoint}` reports the predicted headroom in
  seconds while an endpoint is elevated. Event-driven (no timers), so the
  whole thing is deterministic under an injected clock.
- `src/audit.ts` — append-only JSONL audit log (`append` / `readAll`) plus an
  indexed query (`query({ event, endpoint, since, until, limit })`): a lazily
  maintained line-offset index maps each complete line to its `ts`/`event`/
  `endpoint` fields and byte span, so only matching lines are read back from
  disk; appends are indexed incrementally and truncation/rotation rebuilds the
  index. Malformed lines are skipped by the index. Every line also carries a
  tamper-evident hash-chain link (`prevHash` / `hash`): SHA-256 over the
  previous link's hash plus a canonical JSON of the line body — the LG-11
  convention from ledger-api-go — computed over the sealed line, so a WR-11
  encrypted `payload` envelope is covered by the chain, never the plaintext.
  `verifyChain()` recomputes the chain and reports the first break (rewritten
  line, deleted line, or spliced foreign lines) with its 1-based line number;
  corrupt lines are reported but skipped without breaking continuity,
  orthogonally to the index. `GET /audit/verify` (operator token; 404 when no
  token is configured) returns the verification report — the payment-fintech
  compliance control that makes post-hoc log edits detectable.
- `src/masking.ts` — field-level masking for audit payloads (`FieldMask`):
  opt-in per-endpoint rules like `{ path: "card_number", strategy: "last4" }`
  (`"4111111111111111"` → `"****1111"`, irreversible; `"full"` → `"****"`).
  Paths are dot-separated from the payload root (`payment.card.number`,
  numeric segments address arrays); invalid paths throw `RangeError` at
  construction, `__proto__`/`constructor`/`prototype` segments are refused.
  Masking always runs *before* the WR-11 encryptor seals anything: the
  `AuditLog` masks JSON-shaped `payload` fields on `append` (per the
  event's `targetUrl`/`endpoint`), and the queue masks JSON response bodies
  before they are sealed into `response_summary.capturedBody` — raw values
  never reach disk, masked or not. `bodyFingerprintSha256` still covers the
  original bytes. Non-JSON payloads pass through untouched. One mask backs
  both paths via `createRelayServer({ fieldMask })` (also `new AuditLog(path,
  { fieldMask })` and `retry.fieldMask` directly).
- `src/replay.ts` — `ReplayGuard`: nonce + timestamp-window replay protection
  for inbound webhooks. A unique `x-nonce` per delivery is remembered for the
  window (`windowSec`, default 300s); resends are rejected as `duplicate_nonce`,
  a missing nonce or an `x-timestamp` (unix seconds) outside ±window is
  rejected as `missing_nonce` / `expired_timestamp` / `future_timestamp`.
  Memory-bounded: nonces expire with the window (lazy sweep per check) and a
  `maxEntries` cap evicts oldest-first. Injectable clock for deterministic
  tests. The duplicate check is scoped by `(scope, nonce)` — the server
  passes the resolved `targetUrl`, so the same nonce value reused for an
  unrelated target is not a false-positive replay; unscoped callers keep the
  legacy global-nonce behavior. Crash-safe mode: `new ReplayGuard({
  journalDir })` journals every accepted nonce to append-only JSONL
  (`nonces.jsonl`, keyed by `(scope, nonce)`) and rebuilds the window from
  disk at construction, so a restart does not reopen the replay window.
  Journal writes are async and batched — `check()` never blocks on disk —
  so a crash can lose the unflushed tail; call `await guard.flush()` before
  a planned restart when the tail must be durable. Corrupt lines are
  skipped, expired entries are dropped at recovery, journal I/O never
  throws on the hot path (failures are counted in `journalStats()`).
- `src/dedup.ts` — idempotent delivery dedup (`DeliveryDeduplicator`): within
  `windowMs` (default 5 min), a `(targetUrl, sha256(payload))` pair already
  accepted is answered 202 with `duplicate: true` and never delivered — the
  payment-callback guard, so an upstream retry of the same event cannot cause
  a duplicate business action. Same payload to a different endpoint stays a
  different delivery. Suppressions are audited as `duplicate_suppressed`.
  Complements `ReplayGuard` (header-based exact replays) with
  payload-identity dedup across re-ids. Memory-bounded: entries expire out of
  the window lazily and `maxEntries` (default 10k) evicts oldest-first.
  Opt-in via `dedup: {...}` (off by default); injectable clock for tests.
  Crash-safe mode: `dedup: { journalDir: "/var/lib/relay/dedup" }` journals
  every first-sight pair to append-only JSONL (fsync'd per line, same
  convention as the durable queue journal) and restores unexpired pairs on
  construction — a restart no longer re-delivers duplicates, so the
  payment-callback guard survives crashes. Corrupt lines are skipped and
  counted (`stats().journal.corruptLines`), recovery always compacts, and
  an optional `journalEncryptor` (WR-11 `PayloadEncryptor`) seals the
  journaled keys at rest.
- `src/ip-acl.ts` — inbound IP allowlist/denylist (`InboundIpAcl`, WR-53):
  per-endpoint CIDR gates on the sender's IP — the outermost admission
  check, before the body is read, before rate limiting, before signature
  verification, so a hostile IP costs zero bandwidth and zero downstream
  state (a denial never enqueues: no retry budget burned, no breaker
  tripped). Rules match the inbound request path (exact `/hooks/stripe`
  or prefix `/hooks/*`, first match wins, same semantics as the endpoint
  verifier/schema rules); each rule carries either an `allow` or a `deny`
  list of IPv4/IPv6 CIDRs (both on one rule is a `RangeError` at startup —
  allow/deny are mutually exclusive), checked deny-first. Denials are
  answered 403 (with `connection: close`, so the client cannot keep
  streaming into a dead request), audited as `rejected` (reason
  `ip_denied`), and counted as
  `relay_inbound_ip_denied_total{endpoint}`. Client IP resolution honors
  `x-forwarded-for` only through configured `trustedProxies` (CIDR):
  with none configured (the default) only the direct socket peer is
  trusted, so a spoofed XFF is ignored; behind a trusted proxy the chain
  is stripped from the right to the leftmost untrusted hop. An
  unparseable peer IP on a guarded endpoint is denied (fail closed).
  Zero dependencies — IPv4/IPv6 CIDR parsing and prefix matching are
  hand-written (IPv4 compares in IPv4-mapped `::ffff:0:0/96` space, so a
  dual-stack `::ffff:127.0.0.1` remoteAddress matches a `127.0.0.1/32`
  rule). Wired into the server via `ipAcl: { rules, trustedProxies }`
  (off by default); invalid CIDRs throw `RangeError` at startup.
- `src/source-baseline.ts` — inbound source baseline anomaly detection
  (`SourceBaselineDetector`, WR-63): opt-in per-endpoint learning of the
  sender baseline — (source IP, approximate TLS fingerprint) triples. The
  fingerprint is `"plain"` for the normal plain-HTTP listener, or
  `${tlsProtocol}:${cipherName}` when the socket looks like a
  `tls.TLSSocket` (duck-typed `getProtocol()`/`getCipher()`); it is an
  *approximate* transport-profile fingerprint by design, not a
  cryptographic peer identity. The first sighting for an endpoint pattern
  learns the baseline silently; a later new triple is audited as
  `source_anomaly` (`endpoint` = matched pattern, `path`, `sourceIp`,
  `fingerprint`, `at`, plus `id`/`traceId` for correlation — only the
  deviating triple is disclosed, never the rest of the baseline).
  Alert-only, never blocks: the check runs after the WR-53 IP ACL (a
  denied IP never teaches the baseline) and before the body is read, and
  the request continues through every remaining gate unchanged — it is
  orthogonal to IP ACL blocking. The source IP reuses the WR-53 `clientIp`
  resolution when an IP ACL is configured (honoring `x-forwarded-for`
  through trusted proxies), otherwise the direct socket peer. Baselines
  live in memory by default; `dir` opts into append-only JSONL
  persistence (`source-baseline.jsonl`, recovered at startup, torn or
  malformed lines skipped, failed appends counted and never thrown — a
  full disk degrades to memory-only, never fails intake). Wired into the
  server via `sourceBaseline: { endpoints, dir? }` (off by default);
  invalid config throws `RangeError` at startup; injectable clock for
  deterministic tests.
- `src/api-key.ts` — inbound per-endpoint API key authentication
  (`InboundApiKeyAuth`, WR-65): a bearer-key admission gate for senders
  that cannot do HMAC. Rules match the inbound request path (exact
  `/hooks/legacy` or prefix `/hooks/*`, first match wins, same semantics
  as the endpoint verifier/schema rules and the WR-53 IP ACL); each rule
  lists one or more `{ id, key }` entries and the `x-api-key` header is
  compared in constant time (`crypto.timingSafeEqual`, no early exit, so
  timing reveals neither the key nor which entry matched). Several keys
  coexist per rule so rotation is overlap-safe: deploy the new key
  alongside the old (both verify), cut the sender over, then remove the
  old entry — each entry's `id` is the stable identifier that rides on
  `accepted` audit events as `keyId`. The check runs in the intake gates
  before the body is read (right after the WR-53 IP ACL, before the
  WR-63 baseline and WR-22 rate limiting), so an unauthenticated caller
  costs zero bandwidth and zero downstream state: a missing or
  non-matching key is answered 401 (`connection: close`) and audited as
  `rejected` with reason `api_key_missing` / `api_key_invalid` (and
  `keyId: "unknown"`, following the WR-20 rotation convention) — it never
  enqueues, burns no retry budget, and never trips the breaker.
  Orthogonal to signature verification: by default (`requireSignature`
  unset/false) the API key alone authenticates the endpoint — the
  signature check is skipped for requests that passed the key gate; set
  `requireSignature: true` on the rule to demand BOTH the key and a valid
  signature (the normal global/per-endpoint verifier check still runs).
  When both factors are in play, the accepted audit's `keyId` names the
  API key (the admission credential). Endpoints with no matching rule are
  untouched — signature behavior there is exactly the legacy one.
  `x-api-key` is the caller's inbound credential, not part of the event:
  it is stripped from the headers forwarded downstream. Wired into the
  server via `apiKeys: { rules }` (off by default — with no `rules`,
  intake behavior is exactly the legacy one); invalid rules (empty key
  list, empty id/key, duplicate key ids, bad pattern) throw `RangeError`
  at startup.
- `src/ratelimit.ts` — inbound rate limiting (`InboundRateLimiter`):
  dual-dimension token buckets — per-sender IP and per-endpoint — guarding
  the webhook intake. Each dimension is a per-second bucket refilled lazily
  (burst = one second of budget, clock-skew clamped at zero so a backward
  clock never grants extra budget); a request must hold a token in *both*
  buckets, and the check is peek-then-consume so a rejection never burns the
  other dimension's token. Wired into the server via `rateLimit: {...}`
  (off by default); over-budget requests are answered 429 with `retry-after`
  and audited as `rejected` (reason `rate_limited`). The opt-in
  `rateLimit.adaptiveInbound` (WR-136) scales the per-endpoint budget with the
  retry queue's pending depth: past `queueDepthHigh` the budget throttles
  toward `minPerEndpointPerSecond` (linear in depth), and the full budget is
  restored only after depth falls back below `queueDepthLow` (hysteresis — the
  band between keeps the current state, so the budget never flaps at the
  threshold). A wide downstream outage thus slows the intake instead of
  piling the backlog deeper; the IP dimension is untouched. 429 /
  `retry-after` semantics are unchanged (computed against the effective
  budget), and the current effective budget is exposed via
  `InboundRateLimiter.adaptiveStats()` and the operator `GET /health/summary`
  (`inboundRateLimit`). Injectable clock for
  deterministic tests.
- `src/tenant-inbound-ratelimit.ts` — per-tenant inbound rate limiting
  (`InboundTenantRateLimiter`): one token bucket per `x-tenant-id`
  guarding the webhook intake — the inbound counterpart to the WR-22
  limiter and orthogonal to the WR-97 per-(tenant, endpoint) *outbound*
  limiter. Checked after the WR-22 limiter and before signature
  verification, so one abusive tenant's flood is rejected before it burns
  verifier CPU. Same lazy-refill / peek-then-consume / clock-skew-clamped
  mechanics as `src/ratelimit.ts`; invalid budgets throw `RangeError` at
  construction; injectable clock for deterministic tests. Wired into the
  server via `inboundTenantRateLimit: {...}` (off by default); over-budget
  requests are answered 429 with `retry-after` and audited as `rejected`
  (reason `tenant_rate_limited`), and denials are exported as
  `relay_inbound_tenant_limited_total{tenant}` (activity-gated — absent
  until the first denial).
- Inbound request body limit (`maxBodyBytes`, `DEFAULT_MAX_BODY_BYTES` = 1 MiB):
  a POST whose body exceeds the budget is answered 413 and audited as
  `rejected` (reason `body_too_large`). Two lines of defense: the declared
  `content-length` is checked before a single body byte is read, and
  chunked or lying bodies are capped while streaming — the response closes
  the connection (`connection: close`) so a flood cannot keep streaming
  into a dead request. The budget can be overridden per inbound path with
  `endpointBodyLimits` (see *Per-endpoint body size limits* below) —
  tighter or looser, first matching rule wins, and the gzip-bomb cap
  follows the endpoint's own budget. Invalid values throw `RangeError`
  at startup.
- Outbound request signing (`outboundSigning`, off by default): every delivery
  made by the default sender stamps `x-relay-signature: sha256=<hex>` — the
  HMAC-SHA256 of the forwarded body — plus `x-relay-key-id` when a `keyId`
  is given, so the downstream can prove the request really came from this
  relay (verify with `verifySignature(body, header, secret)` from
  `src/verify.ts`). The opt-in `ed25519` sub-config (WR-124) additionally
  stamps `x-relay-ed25519-signature: ed25519=<hex>` — the relay signs with
  an Ed25519 private key (`node:crypto`, no dependencies) and the
  downstream verifies with the public key alone (`Ed25519Verifier` /
  `RotatingEd25519Verifier` from `src/outbound-ed25519.ts`, which keeps a
  retired key verifiable inside a grace window); the delivery is accepted
  when either signature verifies. Inbound `x-relay-signature` /
  `x-relay-key-id` / `x-relay-ed25519-signature` /
  `x-relay-ed25519-key-id` headers are always stripped from the forwarded
  header set, so a sender can never smuggle a forged relay signature
  downstream. The config applies to the default sender only — an injected
  sender signs (or doesn't) on its own. Invalid values throw `RangeError`
  at startup.
- AWS SigV4 outbound signing (`awsSigV4`, off by default, WR-116): per
  endpoint, `{ "<exact targetUrl>": { accessKeyId, secretRef, region,
  service } }` stamps `Authorization` + `x-amz-date` per the AWS
  Signature Version 4 spec over the final wire bytes (after
  transform/compression/E2EE). The secret is never in the config —
  `secretRef` resolves per attempt through `awsSecretResolver`
  (default: an environment variable name), so snapshots and the
  operator API can't leak key material and rotation needs no restart.
  Orthogonal to `outboundSigning` above (both may be enabled); see
  *AWS SigV4 outbound signing (opt-in)*. Invalid values throw
  `RangeError` at startup.
- Outbound OAuth2 `client_credentials` (`oauth2`, off by default,
  WR-129): per endpoint, `{ "<exact targetUrl>": { token_endpoint,
  client_id, client_secret, scope? } }` makes the relay fetch, cache,
  and refresh a bearer token for the downstream and stamp
  `Authorization: Bearer <token>` on every delivery (http/https only).
  Tokens are isolated per `(token_endpoint, scope)`, expire 30s before
  `expires_in` (clock-skew reserve), and a downstream 401 triggers one
  forced refresh + redelivery inside the same attempt. The secret stays
  in memory only — never logged or audited. Composes with the HMAC /
  Ed25519 / SigV4 stamps; see *Outbound OAuth2 client_credentials
  (opt-in)*. Invalid values throw `RangeError` at startup.
- Outbound end-to-end encryption (`outboundEncryption`, off by default,
  WR-58; key rotation WR-81): per endpoint, `{ "<exact targetUrl>": { publicKey } }` with the
  downstream's base64 X25519 public key (mint with `generateX25519KeyPair()`
  from `src/e2ee.ts`; the private half never leaves the downstream).
  Rotating endpoints add `keyId` + `previousKeys` (envelope `kid`,
  grace-windowed retired keys, `e2ee_key_rotated` audit).
  Sealed deliveries carry `x-relay-encryption: x25519-hkdf-sha256/aes-256-gcm`
  and a JSON envelope (fresh ephemeral X25519 keypair + HKDF-SHA256 +
  AES-256-GCM per delivery); the downstream opens it with
  `unsealOutboundPayload()`. Sealing runs after compression and before
  signing, so `x-relay-signature` covers the ciphertext wire bytes —
  authenticity from the relay, secrecy for the downstream, orthogonal by
  design. Endpoints without a key are sent exactly as before. Invalid keys
  throw `RangeError` at startup.
- Outbound idempotency-key stamping (`outboundIdempotencyKey`, off by default,
  WR-44): when `enabled`, every delivery made by the default sender carries
  `x-relay-idempotency-key` — the HMAC-SHA256 of `(event id, attempt)` under
  the configured `secret`, prefixed with `keyPrefix` (default `""`). The
  downstream integration contract: use the header as the dedup key in your
  own idempotency store — the same attempt of the same event always yields
  the same key (transport-level redeliveries collapse), a new attempt gets a
  fresh key (genuine retries stay distinguishable), a dead-letter replay
  restarts at attempt 1 and reproduces the *original* keys (the replay never
  looks like a new event), and batch deliveries key off the `batch_id`
  (one key per merged envelope). The key is unforgeable without the relay
  secret, so a downstream deduplicator can trust it. Inbound
  `x-relay-idempotency-key` headers are always stripped, so a sender can
  never smuggle a forged relay-derived key downstream. Applies to the
  default sender only. Invalid values throw `RangeError` at startup.
- `src/circuit.ts` — per-endpoint circuit breaker (`EndpointCircuitBreaker`,
  `closed` / `open` / `half_open`): `failureThreshold` (default 5)
  consecutive delivery failures trip the circuit open for `cooldownMs`
  (default 30s); attempts made while open are parked — rescheduled without
  consuming the retry budget — instead of hammering a down endpoint. After
  the cooldown a single half-open probe is let through (one in flight at a
  time): success closes the circuit, failure re-opens it and restarts the
  cooldown. A success on a closed circuit resets the failure count. Wired
  into `RetryQueue` via `retry: { circuitBreaker: {...} }` (off by default);
  `getCircuitStats()` reports per-endpoint `state` / `consecutiveFailures` /
  `trips` / `tripMode` / `errorRate` / `errorRateSamples`,
  `circuitBlockedCount()` counts parked attempts, and every
  transition is audited as `circuit_open` / `circuit_half_open` /
  `circuit_closed` with the endpoint. Injectable clock for deterministic
  tests. WR-104 adds an opt-in `tripMode: "error-rate"`: a rolling window
  of the last `errorRateWindowSize` outcomes (default 20) trips the
  circuit once the window holds at least `errorRateMinSamples` outcomes
  (default 10, always ≥ 2) and the failure rate reaches
  `errorRateThreshold` (default 0.5) — a lone 1/1 failure can never trip
  it, which stops jittery endpoints from flapping the breaker. Half-open
  probe semantics are unchanged, and the mode is switchable per endpoint
  at runtime via `setEndpointThresholds` (also through the hot-reload
  `circuitBreaker` patch); the window and the consecutive counter are
  maintained in both modes, so a switch trips on live history instead of
  a cold start. `relay_endpoint_circuit_error_rate{endpoint}` exposes the
  rolling-window rate per error-rate-mode endpoint.
- `src/downstream-probe.ts` — opt-in *active* downstream health probing
  (`DownstreamProber`), wired into `RetryQueue` via `retry: { probe: {
  endpoints, intervalMs, method, timeoutMs } }` (off by default). Each
  listed endpoint gets a timed `HEAD` (or `GET`) request every
  `intervalMs` (default 30s) on a lightweight path — raw reachability,
  no keep-alive pool, no proxy, no TLS pins — so probes never consume the
  retry budget and never touch the latency tracker, quota, or batching.
  Each probe outcome is reported to the circuit breaker exactly like a
  delivery outcome: `failureThreshold` consecutive probe failures trip the
  circuit open *before* real deliveries have to fail, and a success
  resets the counter like any success (a success never closes an open
  circuit early — recovery still flows through cooldown → half-open).
  Outcomes are audited as `probe_failed` (every failure, with the
  consecutive-failure streak) / `probe_recovered` (once, when a failing
  endpoint answers again; steady-state healthy probes stay quiet) and
  counted as `relay_probe_total{endpoint,result}` /
  `relay_probe_consecutive_failures{endpoint}`; `getProbeStats()` reports
  per-endpoint counters. A throwing probe implementation counts as a
  failure, never a crash. Invalid configs throw `RangeError` at startup.
  (Not to be confused with the keep-alive pool's *connection* health
  probing, `OutboundConnectionPool({ healthProbe })`, which culls dead
  idle sockets before reuse.)
- `src/encrypt.ts` — pluggable payload encryption (`PayloadEncryptor`
  interface: `encrypt` / `decrypt`, never silently returns garbage).
  Built in: `AesGcmEncryptor` (AES-256-GCM via `node:crypto`, zero
  dependencies — fresh random 12-byte IV per encryption, 16-byte auth tag,
  32-byte key validated at construction, `randomAes256Key()` helper) and
  `NoopEncryptor` (passthrough for tests/fixtures only). Dead-letter
  payloads are sealed at rest via `RetryQueue({ payloadEncryptor })` —
  `replayDeadLetter` decrypts transparently before re-queueing — and
  `AuditLog(path, { payloadEncryptor })` seals `payload` fields (Buffer or
  string) into JSON-serializable envelopes before the JSONL line hits disk,
  decrypting them back on `readAll` / `query` (wrong-key reads throw loudly).
  `createRelayServer({ payloadEncryptor, auditPayloads: true })` opts the
  `accepted` audit events into carrying the body; the operator
  `GET /dead-letter` listing reports `payloadBytes` and `encrypted` without
  ever exposing raw payloads.
- `src/pinning.ts` — outbound TLS certificate pinning: a per-endpoint SPKI
  fingerprint whitelist (`tlsPins: { "<exact targetUrl>": ["sha256/<base64>", ...] }`,
  also accepts `sha256:<base64>` and bare base64 spellings). When pins are
  configured for an endpoint, the whitelist *replaces* the PKI chain
  verification — the pin is the trust anchor, which stops a MITM holding a
  valid-but-unexpected certificate and also works for self-signed / private-CA
  downstreams. The peer certificate's SPKI is verified on the socket's
  `secureConnect` *before* a single payload byte is written (a mismatch cannot
  even observe the request body); a mismatch destroys the request with
  `TlsPinMismatchError`, fails the delivery attempt, and the attempt follows
  the normal retry / dead-letter path — the mismatch is audited as
  `dead_letter` with the pin error. Endpoints without pins keep Node's default
  TLS verification. Empty whitelists and malformed pins throw `RangeError` at
  startup, never mid-delivery. Zero dependencies (`node:crypto` only).
- `src/mtls.ts` — outbound mTLS client certificates: a per-endpoint client
  identity (`tlsClientCerts: { "<exact targetUrl>": { cert, key, passphrase? } }`,
  also exposed as `createRelayServer({ tlsClientCerts })` and the fifth
  `createDefaultSender(pins, keepAlive, outboundSigning, proxies, tlsClientCerts)`
  argument). The `cert`/`key` are PEM *strings* held in memory — no file paths,
  so rotation is a config change. The relay presents the certificate during the
  TLS handshake, proving to the downstream that the request comes from this
  relay (the downstream verifies it, typically with `requestCert: true` and its
  own CA list). Off by default: endpoints without an entry send no client
  certificate. Composes with `tlsPins` (pins verify the *server*, the client
  cert proves the *relay*) and with the keep-alive pool (agents are keyed per
  `(origin, cert)`, so a connection authenticated as one identity can never
  serve an endpoint configured with a different one; a handshake that fails
  destroys the socket, and the checkout probe culls it, so it is never handed
  to another delivery). Empty cert/key, unparseable PEM, and cert/key mismatch
  throw `RangeError` at startup. Zero dependencies (`node:crypto` + `node:tls`).
- `src/inbound-mtls.ts` — inbound mTLS client-certificate authentication
  (WR-103): `createRelayServer({ inboundMtls: { key, cert, ca,
  requireCert?, clientFingerprints?, operatorMtls? } })` turns the
  listeners that can require a client certificate into Node `https`
  servers (`requestCert: true`, `rejectUnauthorized: false`), so
  enforcement happens at request time: a missing certificate is answered
  401 (`client_cert_required`), an untrusted or non-whitelisted one 401
  (`client_cert_invalid`), both audited as `rejected`; a verified
  caller's `clientCertFingerprint` / `clientCertSubject` ride the
  `accepted` / `rejected` audit events. `requireCert: false` +
  `operatorMtls: true` locks down only the operator routes while ingest
  stays open (with a split operator plane the intake listener stays
  plain HTTP). `server.updateInboundMtlsConfig(patch)` hot-swaps the CA,
  key/cert, whitelist, and policy for new handshakes (audited as
  `inbound_mtls_config_updated`); enabling/disabling needs a restart —
  documented, not faked. Invalid values throw `RangeError` at startup;
  unset means plain HTTP and zero behavior change. Zero dependencies
  (`node:crypto` + `node:tls`).
- `src/tls-sni.ts` — per-endpoint outbound TLS SNI/ALPN overrides (WR-60):
  `tlsSniOverrides: { "<exact targetUrl>": { servername?, alpnProtocols? } }`
  (also exposed as `createRelayServer({ tlsSniOverrides })` and the eleventh
  `createDefaultSender(...)` argument). `servername` is the SNI name sent in
  the TLS ClientHello and defaults to the target URL's host — set it
  explicitly for CDN / multi-tenant-fronting setups, either to present the
  real service name to the front or to keep the default SNI from leaking the
  real backend host. `alpnProtocols` is the ALPN offer in preference order
  and defaults to `["h2", "http/1.1"]`. Endpoints without an entry keep the
  exact current behavior (no `servername`/`ALPNProtocols` set — Node's
  defaults apply untouched). The override changes only the SNI/ALPN wire
  values: certificate verification still anchors on the target URL's host
  (or the `tlsPins` whitelist — the pin is verified on the overridden-SNI
  connection), and the keep-alive pool plus the H2 session pool key
  connections by the effective TLS identity (`|sni:<hash>`), so a connection
  handshaked with one SNI can never serve an endpoint configured with a
  different one. Composes with `tlsPins`, `tlsClientCerts` (the client
  certificate rides the same handshake), the H2 pool, and proxied endpoints
  (the handshake runs over the CONNECT tunnel). Applies to `https:` targets;
  empty servernames, IP-literal servernames, and empty/malformed
  `alpnProtocols` throw `RangeError` at startup. Zero dependencies
  (`node:net` + `node:crypto`).
- `src/cert-expiry.ts` — downstream + own TLS certificate expiry warning (WR-73):
  `createRelayServer({ tlsCertExpiry: { enabled: true, thresholdSeconds? } })`
  (also exposed as the fourteenth `createDefaultSender(...)` argument). When
  enabled, every `https:`/`wss:` handshake feeds the peer certificate's
  `notAfter` into the monitor — reusing the `getPeerCertificate` read the
  WR-21 pin check performs, across the keep-alive pool, proxied CONNECT
  tunnels, the H2 session pool, and the WebSocket pool — and a certificate
  expiring within `thresholdSeconds` (default 14 days) fires one
  edge-triggered `cert_expiring` audit event per certificate (not per
  handshake: a pooled connection serving a thousand deliveries alerts once;
  a renewed certificate alerts again), plus a
  `relay_cert_expiry_seconds{endpoint,kind}` gauge in `GET /metrics`
  (`kind` = `downstream` for the peer, `client` for the relay's own mTLS
  client certificates, which are checked at config load — an expired client
  identity fails every handshake and no retry ever fixes it). Off by
  default: an unconfigured relay behaves exactly as before, and `GET /metrics`
  stays byte-identical until the first certificate is observed. The monitor
  is an observer, never a gate: unreadable or empty peer certificates
  (resumed TLS 1.3 sessions re-send none) are skipped silently. Invalid
  values throw `RangeError` at startup. Zero dependencies (`node:crypto`
  only).
- `src/tls-version.ts` — outbound per-endpoint TLS minimum version (WR-74):
  `createRelayServer({ minTlsVersions: { "<exact targetUrl>": "1.2" | "1.3" } })`
  (also exposed as the fifteenth `createDefaultSender(...)` argument). The
  floor is enforced *observationally*: the handshake runs at whatever the
  downstream negotiates and the negotiated version is compared against the
  floor on the socket's `secureConnect`, *before* a single payload byte is
  written — deliberately not via `minVersion` on the socket, because a
  socket-level floor fails the handshake with a generic OpenSSL error and
  the relay could never attribute the failure. A negotiation below the
  floor destroys the request with `TlsVersionRejectedError`; the attempt
  follows the normal retry / dead-letter path and the rejection is audited
  as `tls_version_rejected` (with `negotiatedVersion` / `requiredMinVersion`)
  plus `relay_tls_version_rejections_total{endpoint,version}` in
  `GET /metrics`. Endpoints without an entry keep the exact historical
  behavior (Node defaults — `"1.2"` is the default floor and needs no
  entry); an unparseable negotiated protocol fails closed. The keep-alive
  pool and the H2 session pool bind the floor into their keys
  (`|tlsmin:<version>`), so a connection handshaked under one floor can
  never serve an endpoint configured with another. Orthogonal to
  `tlsClientCerts` (WR-36, client identity) and the WR-73 expiry monitor
  (warns about expiry; this rejects weak negotiation). Applies to `https:`
  targets; `wss:` targets are not covered in this round (the WebSocket pool
  owns its own handshake). Invalid floors throw `RangeError` at startup.
  Zero dependencies.
- `src/ocsp.ts` — outbound per-endpoint TLS OCSP revocation checking (WR-101):
  `createRelayServer({ tlsOcsp: { "<exact targetUrl>": { mode?, useStapled?,
  responderUrl?, responderFetcher?, responderTimeoutMs? } } })` (also
  exposed as the twenty-fourth/twenty-fifth `createDefaultSender(...)`
  arguments). After the handshake the relay checks whether the peer's
  certificate was revoked — the stapled OCSP response first
  (`requestOCSP: true` on the handshake, zero extra round-trips),
  responder fallback second (explicit `responderUrl`, else the leaf's
  Authority Information Access extension, via the pluggable
  `responderFetcher`; the default is a plain `node:https` POST). A
  `revoked` verdict destroys the request with `OcspRevokedError`
  *before* a single payload byte is written (the revoked peer never
  observes the body); the attempt follows the normal retry /
  dead-letter path, an `ocsp_revoked` audit event fires, the alert hook
  fires, and the outcome counts in
  `relay_ocsp_total{endpoint,status}` (`good` / `revoked` / `unknown` /
  `error`). `mode` (default `"fail-open"`) governs only the
  *undeterminable* case (no stapled response, no/failing responder,
  malformed response): `"fail-open"` proceeds after the alert,
  `"fail-closed"` fails the attempt with `OcspError` — a `revoked`
  verdict rejects in both modes. **Pinned endpoints should use
  `"fail-closed"`** (a pin already says which key to expect; failing
  closed on revocation-telemetry loss is the consistent posture).
  Orthogonal to `tlsPins`: pinning anchors *identity* (compromised CA /
  MITM), OCSP checks *revocation freshness*; the pin check runs first.
  An OCSP *query* failure explicitly does **not** count as a
  circuit-breaker failure (local telemetry outage, not a sick endpoint);
  a revocation does. The keep-alive pool binds OCSP endpoints to their
  own agents (`|ocsp`: stapling requested, session resumption disabled —
  a resumed handshake carries no certificate to check); the check runs
  on session establishment and pooled reuse skips it. Applies to
  `https:` on the HTTP/1.1 path — OCSP endpoints are kept off the
  opt-in HTTP/2 path rather than silently skipping, and `wss:` is not
  covered in this round. Off by default: zero behavior change and no
  `relay_ocsp_*` series until an endpoint opts in. Invalid values throw
  `RangeError` at startup. Zero dependencies (`node:crypto` +
  `node:https`; the DER reader/writer is hand-rolled).
- `src/keepalive.ts` — outbound keep-alive connection pool: deliveries reuse
  TCP/TLS connections per `(scheme, host, port)` instead of paying a handshake
  per attempt. One `http.Agent`/`https.Agent` per origin, with
  `maxSocketsPerHost` (default 64; extra requests queue FIFO inside the agent)
  and idle reaping after `idleTimeoutMs` (default 30s) on an unref'd timer —
  an idle pool never pins process exit, and a failed connection is never
  handed to another delivery. Endpoints with a TLS pin whitelist get a
  dedicated agent per pin set (so a connection pinned for one whitelist can
  never serve another endpoint's), endpoints with a `tlsSniOverrides` entry
  get a dedicated agent per effective TLS identity (so a connection
  handshaked with one SNI can never serve an endpoint configured with a
  different one), and the pin is still verified on
  `secureConnect` for every new connection; a reused connection re-checks its
  cached handshake fingerprint against the request's whitelist as a
  poisoned-socket guard. Pinned agents disable TLS session resumption
  (`maxCachedSessions: 0`): on a resumed handshake the server does not
  re-send its certificate, so the pin check would see an empty peer
  certificate and fail a healthy endpoint under concurrent handshakes —
  every pinned connection does a full handshake instead. Health probing (WR-28): every idle socket is probed
  *before* the agent hands it to a delivery, in the same tick — sockets the
  kernel already knows are dead (destroyed, closed, or half-closed by the
  peer) are culled on the spot and never serve a delivery, and on pinned
  agents the cached SPKI fingerprint is re-verified against the whitelist
  (a pooled socket without a verified pin is fail-closed). The probe is
  passive (no bytes sent — an active ping would corrupt HTTP/1.1 framing),
  so a death the kernel has not observed yet stays with TCP keep-alives
  and the retry layer. `getStats()` exposes per-origin created / reused /
  reaped / probeHits / probeMisses counters plus live socket counts.
  Enabled by default; `healthProbe: false` hands the agent's free list
  through untouched (`createRelayServer({ outboundKeepAlive })`,
  `createDefaultSender(pins, keepAlive, outboundSigning, proxies)`); pass
  `false` for one fresh connection per
  delivery (the legacy
  opt-out; note Node 24's global agent pools by default, so the opt-out passes
  `agent: false` explicitly). Pooled connections close with the server
  (`close` → `queue.stop()` → pool `destroy()`), covering the
  graceful-shutdown drain path. Invalid option values throw `RangeError` at
  startup.
- Adaptive per-origin socket-cap sizing (WR-134, opt-in): pass
  `adaptiveSockets: { minSockets, maxSockets, scaleUpQueueDepth, cooldownMs }`
  inside `outboundKeepAlive` and the fixed `maxSocketsPerHost` becomes the
  *initial* cap (clamped into `[minSockets, maxSockets]`). A background
  evaluator (unref'd, at most once per second and no slower than the
  cooldown) moves each origin's cap from the agent's queued-request
  pressure — requests waiting for a socket inside Node's agent: scale up
  (doubling, at least +1) when the queue reaches `scaleUpQueueDepth`,
  scale down (halving) toward `minSockets` when the queue drains, with
  `cooldownMs` between moves on one origin as the flap guard. Shrinking
  only reaps *idle* sockets — in-flight deliveries are never touched.
  `getStats()` exposes `currentMaxSockets`, `scaleUps`, and `scaleDowns`
  per origin. Note: raising the cap applies to new socket decisions
  immediately; requests already queued inside the agent drain as sockets
  free (Node does not re-evaluate queued requests on a cap change), so a
  scale-up shortens the queue for what comes next. Unset = the fixed cap,
  byte-identical behavior to before.
- `src/warmup.ts` — outbound connection warm-up (WR-70): pre-connects the
  keep-alive pool to configured origins at startup so the first deliveries
  skip the TCP/TLS handshake. `warmupOutboundPool(pool, endpoints, cfg)`
  resolves the exact pool agent each delivery would use (same pin
  whitelist, proxy, mTLS identity, and TLS SNI override), opens
  `socketsPerOrigin` sockets per origin (default 1) through the agent's own
  connection funnel, and parks them idle in the agent's free list — no
  application bytes are ever sent. TLS pins *are* verified during warm-up
  against the endpoint's whitelist (the verified SPKI fingerprint is cached
  on the pooled socket, which the health probe requires before a pinned
  socket may serve a delivery); a mismatch fails that endpoint's warm-up
  with `pin_mismatch` and the socket is destroyed, never parked. Warm-ups
  run with bounded concurrency, a per-connection `timeoutMs` (default 5s),
  and per-endpoint error isolation (one endpoint's failure — refused,
  timeout, DNS, TLS error — never throws and never blocks the others);
  every result is auditable via `warmup_completed` / `warmup_failed` events
  when wired through `createRelayServer({ warmup: { endpoints, timeoutMs?,
  concurrency?, socketsPerOrigin? } })`, which validates the shape with a
  `RangeError` at startup. Measured numbers in the `bench/warmup-bench.ts`
  bullet below (localhost: first-delivery p50 0.96 ms → 0.54 ms for HTTP,
  4.36 ms → 0.85 ms for HTTPS with TLS pinning — the handshake moves from
  the first delivery into startup, where it is paid once per origin
  instead of once per cold burst).
- `src/http2.ts` — outbound HTTP/2 session reuse (WR-42): on top of the
  keep-alive pool, per-origin H2 sessions multiplex high-concurrency
  deliveries over a single connection — one session per `(scheme, host,
  port)` instead of `maxSocketsPerHost` TCP/TLS handshakes. Opt-in per host
  (`createRelayServer({ outboundHttp2: { enabled: true, hosts:
  ["relay.example.com"] } })`, also the seventh `createDefaultSender(...)`
  argument); off by default, so existing deployments keep their exact
  current behavior. `http:` targets use h2c, `https:` targets use TLS: SPKI
  pins (WR-21) keep their trust-anchor semantics — verified on the session
  socket's `secureConnect` before the first stream, with the verified
  fingerprint re-checked on reuse as a poisoned-session guard — and mTLS
  client certificates (WR-36) ride the handshake; sessions are keyed per
  origin + pin set + client identity + effective TLS identity (WR-60
  `tlsSniOverrides`: a session handshaked with one SNI never serves an
  endpoint configured with another), so a session pinned or authenticated
  for one endpoint can never serve another's. A failed or refused H2 session
  never loses a delivery: the sender falls back to the HTTP/1.1 keep-alive
  pool (the origin sits out H2 for `fallbackCooldownMs`, default 30s), and
  a server GOAWAY drains in-flight streams gracefully while new deliveries
  establish a fresh session. H2 is bypassed for proxied endpoints — proxy
  traffic rides the HTTP/1.1 CONNECT tunnel (`src/proxy.ts`), never H2, so
  the two transports are never composed by hand. `getStats()` exposes the
  live per-origin sessions plus `established` / `reused` / `fallback`
  counters; idle sessions are closed by an unref'd reaper
  (`sessionIdleTimeoutMs`, default 60s), and an idle session's socket never
  pins process exit (re-ref'd per stream). Invalid option values throw
  `RangeError` at startup. Zero dependencies (`node:http2` only).
- `src/websocket.ts` — outbound WebSocket downstream delivery (WR-45):
  `ws:` / `wss:` targets speak RFC 6455 with zero dependencies
  (`node:net` + `node:tls` + `node:crypto` only — no `ws` package, so the
  handshake, masking, and frame codec are hand-rolled and covered by
  `test/websocket.test.ts` against a raw-socket test server). One delivery
  borrows a pooled connection exclusively, sends the payload as a single
  masked text frame (client frames are always masked, RFC 6455 §5.3), and
  waits for the downstream's reply — a text frame becomes the response body
  (surfaced with status 200), a clean close with no reply counts as accepted
  (fire-and-forget endpoints close right after reading). Pings are
  auto-ponged; unsolicited frames on an idle pooled connection destroy it
  (fail-safe — a stray frame must never be mistaken for a later delivery's
  response). `x-relay-*` headers (idempotency key, trace, signature, …)
  ride the upgrade request as plain HTTP headers — the handshake *is* an
  HTTP request — with one honest caveat: the handshake is connection-scoped,
  so a reused pooled connection keeps the opening delivery's headers; read
  per-delivery metadata from the handshake, per-message bytes from the text
  frames. Failure mapping keeps the retry layer honest: a completed
  handshake with a non-101 status becomes `HttpDeliveryError` with that
  status code (WR-30 classification applies — 4xx-except-408/429
  dead-letters immediately, `Retry-After` honored); anything else (refused
  connection, TLS error, handshake timeout, no reply before the timeout) is
  a plain `Error`, so the classifier treats it as retryable. Composes with
  SPKI pinning (WR-21: for `wss:` the whitelist replaces PKI verification
  and the peer's SPKI is checked *before* the handshake bytes are written —
  a MITM never sees the payload; a mismatch fails the attempt with
  `TlsPinMismatchError` through the normal retry path) and with the
  keep-alive pool (WR-24: connections pooled per `(scheme, host, port,
  pin-whitelist)`, idle sockets ping/pong-probed every `pingIntervalMs`
  (default 30s, `0` disables) and reaped after `idleTimeoutMs` (default
  60s), so a dead socket never serves a delivery; `timeoutMs` (default 10s)
  bounds the TCP+TLS+handshake phase and the reply wait separately).
  Invalid option values throw `RangeError` at startup. WR-105 adds
  per-origin gateway observability: `getStats().origins` /
  `getOriginStats()` report one row per `<scheme>//<host>` origin —
  `activeConnections` (live pooled conns right now), `messagesOut` /
  `messagesIn` (delivery frames sent / replies received), `created` /
  `reused` (pool checkout results), `deflatedOut` / `deflatedIn`,
  `pingRttMs` (mean recent keep-alive ping RTT, once a probe completes),
  and `compressionRatio` (mean deflate wire/plain byte ratio, once
  something is compressed). The same rows render into `GET /metrics` as
  `relay_websocket_connections{origin}`,
  `relay_websocket_messages_{out,in}_total{origin}`,
  `relay_websocket_checkouts_total{origin,result}`,
  `relay_websocket_ping_rtt_seconds{origin}` and
  `relay_websocket_deflate_ratio{origin}` — the block is empty until the
  first WebSocket delivery runs, so non-WebSocket relays see no new
  series. Also hardened: `destroy()` during an in-flight handshake now
  kills the fresh connection instead of leaking an orphan socket (the
  handshake future resolves after the pool is gone, so `checkout`
  re-checks `destroyed` before the connection can enter the pool).
- `src/inbound-ws.ts` — inbound WebSocket event intake (WR-130): a
  `ws(s)://` upgrade endpoint (opt-in via `RelayServerOptions.inboundWs`,
  default path `/ingest/ws`) so producers can push events over one
  long-lived connection instead of one HTTP POST per event. Zero
  dependencies — the RFC 6455 server-side handshake and frame codec are
  hand-rolled (`node:crypto` only) and covered by
  `test/inbound-ws.test.ts` against raw sockets; the frame encoder is
  shared with the WR-45 outbound client but every semantic is
  server-side (inbound client frames MUST be masked — an unmasked frame
  is a 1002 protocol error; no extensions, so any RSV bit is a 1002;
  fragmented messages reassemble with a byte cap, 1009 past it). Wire
  protocol: one text frame per event, a JSON envelope shaped exactly
  like a WR-61 batch item (`{ "payload": "<base64>", "headers": {
  "x-signature": "…", … } }`); the server answers each event with a text
  frame `{ "type": "event-ack", "status": "accepted" | "rejected", … }`
  mirroring the HTTP 202 / 4xx outcome. Each event walks the full intake
  pipeline — HMAC/Ed25519 signature verification, per-endpoint API keys,
  the WR-22 inbound rate limiter (per event, before verification),
  dedup, schema validation, the `maxBodyBytes` / `endpointBodyLimits`
  budget (413 + close on overflow), tenant, gzip, replay guard — and
  lands in the normal `RetryQueue`, so retry / dead-letter / replay
  semantics are unchanged. `x-relay-*` and other connection-level headers
  ride the upgrade request and apply to every event (the relay-namespace
  strip still applies); the envelope's per-event headers overlay them.
  Keep-alive: the server pings every `pingIntervalMs` (default 30s, `0`
  disables), answers client pings with pongs, and closes connections
  idle longer than `idleTimeoutMs` (default 120s); a client whose
  outbound buffer passes 1MiB is disconnected like a slow SSE `/events`
  consumer. A TLS-terminating intake listener serves `wss://` on the same
  port — no second listener. In split-plane mode the endpoint lives on
  the intake plane only. Invalid option values throw `RangeError` at
  startup; connect/disconnect and every admission decision are audited
  (`ws_connected` / `ws_disconnected` / `rejected` / `accepted`).
- `src/deflate.ts` — WebSocket permessage-deflate (RFC 7692, WR-46),
  opt-in per pool via the `permessageDeflate` WebSocket option (`true` for
  defaults, `{ thresholdBytes? }` to tune the payload size at which
  compression kicks in, default 1024). When enabled, the upgrade request
  offers `permessage-deflate` with both no-context-takeover parameters
  **required** (`client_no_context_takeover; server_no_context_takeover`);
  a downstream that answers without them fails the handshake (plain
  `Error` → retryable) instead of negotiating parameters the relay cannot
  honor — per RFC 7692 §7.1.2.2 a server must not select the extension
  while rejecting the client's required parameters. Requiring
  `server_no_context_takeover` keeps decompression to one independent
  inflate per message: no persistent inflater state rides pooled
  connections. Compression is opportunistic per message: payloads below
  the threshold go out untouched, and a payload whose compressed form is
  not smaller than the original also goes out untouched — deflate never
  expands the wire. Wire form follows RFC 7692 §7.2.1 exactly (raw DEFLATE
  + `Z_SYNC_FLUSH`, trailing `00 00 ff ff` stripped, RSV1 set); inbound
  RSV1 frames are inflated after the final fragment, and RSV1 on a
  connection without negotiated deflate, on a continuation frame, or on a
  control frame fails the delivery as a protocol violation. A compressed
  reply truncated at `maxMessageBytes` fails the delivery — a partial
  deflate stream can neither be inflated nor truncated safely, so the
  truncation contract applies to plain text only. `getStats()` exposes
  `deflatedOut` / `deflatedIn` counters. Covered by
  `test/websocket-deflate.test.ts` (negotiation matrix, RFC 7692 wire-form
  round-trips, threshold/never-expand rules, and a raw-socket stub server
  for the delivery path).
- `src/proxy.ts` — outbound HTTP(S) proxy support: per-endpoint proxy URLs
  (`proxies: { "<exact targetUrl>": "http://user:pass@proxy:8080" }`, also
  exposed as `createRelayServer({ proxies })` and the fourth
  `createDefaultSender(pins, keepAlive, outboundSigning, proxies)` argument).
  Endpoints without an entry fall back to `HTTPS_PROXY` / `HTTP_PROXY` /
  `ALL_PROXY` (lowercase variants honored, `NO_PROXY` bypasses the env
  fallback only — an explicit entry always wins), read per delivery so proxy
  rotation needs no restart. Deliveries ride a `CONNECT` tunnel — proxy
  basic-auth credentials come from the proxy URL's userinfo, and only
  plain-HTTP proxies are supported (proxy-over-TLS is rejected at
  validation). For `https:` targets the TLS handshake runs over the tunnel,
  so end-to-end encryption and `tlsPins` verification behave exactly as
  without a proxy: the proxy sees only the CONNECT line, never the payload.
  Tunneled sockets join the keep-alive pool keyed per (proxy, origin, pins),
  so one CONNECT serves many deliveries and a tunnel through proxy A can
  never serve an endpoint routed through proxy B; with pooling disabled each
  delivery opens its own tunnel. A failed CONNECT (`ProxyConnectError`,
  carrying the proxy's status — e.g. 407 on bad credentials) fails the
  delivery through the normal retry / dead-letter path and lands in the audit
  trail. Invalid proxy URLs throw `RangeError` at startup. Zero dependencies
  (`node:net` + `node:tls`).
- `bench/keepalive-bench.ts` (`npm run bench:keepalive`) — sequential
  deliveries to a localhost stub, before/after numbers (50 warmup deliveries
  per scenario; connection counts include warmup). Measured 2026-10-08,
  Node v24.20.0, AMD EPYC 9D25, linux x64:

  | scenario | deliveries | connections | total | mean | p50 | p99 |
  |---|---|---|---|---|---|---|
  | HTTP, no pool | 2000 | 2050 | 897 ms | 0.45 ms | 0.32 ms | 2.34 ms |
  | HTTP, keep-alive pool | 2000 | 1 | 272 ms | 0.14 ms | 0.11 ms | 0.51 ms |
  | HTTPS+pins, no pool | 400 | 450 | 1537 ms | 3.84 ms | 3.71 ms | 6.55 ms |
  | HTTPS+pins, keep-alive pool | 400 | 1 | 92 ms | 0.23 ms | 0.19 ms | 0.50 ms |

  A second run gave HTTP 3.0x and HTTPS+pins 9.9x (run-to-run variance: the
  pooled arm is fast enough that a few slow iterations move p99). Takeaway:
  the handshake is the whole cost at this scale — ~3x on plain HTTP,
  ~10–17x when every delivery pays a TLS handshake.
- `bench/http2-bench.ts` (`npm run bench:http2`) — high-concurrency
  deliveries to localhost stubs: the HTTP/1.1 keep-alive pool vs. HTTP/2
  session reuse (1500 deliveries at 100-way concurrency over HTTP; 400 at
  50-way over HTTPS with TLS pinning; 50 warmup deliveries per scenario;
  connection counts include warmup). Measured 2026-10-09, Node v24.20.0,
  AMD EPYC 9D64, linux x64:

  | scenario | deliveries | concurrency | connections | total | mean | p50 | p99 |
  |---|---|---|---|---|---|---|---|
  | HTTP/1.1 keep-alive pool | 1500 | 100 | 64 | 577.50 ms | 0.39 ms | 14.76 ms | 91.88 ms |
  | HTTP/2 (h2c) | 1500 | 100 | 1 | 263.03 ms | 0.18 ms | 14.97 ms | 29.53 ms |
  | HTTPS+pins, HTTP/1.1 pool | 400 | 50 | 50 | 327.34 ms | 0.82 ms | 11.34 ms | 172.08 ms |
  | HTTPS+pins, HTTP/2 | 400 | 50 | 1 | 92.85 ms | 0.23 ms | 7.04 ms | 26.76 ms |

  Speedup (total time): HTTP 2.2x, HTTPS+pins 3.5x (a second run gave 2.1x
  / 5.7x — localhost noise; p50/p99 move around under batch scheduling).
  Takeaway: under concurrency the H1.1 pool is capped by
  `maxSocketsPerHost` (64 connections here, one TLS handshake each on the
  HTTPS arm) while H2 multiplexes everything over a single connection —
  ~2x on plain HTTP, ~3–6x when every H1.1 connection also pays a TLS
  handshake.
- `bench/warmup-bench.ts` (`npm run bench:warmup`) — first-delivery latency
  to a cold origin vs. a warmed origin: each iteration builds a fresh
  default sender (fresh keep-alive pool), optionally warms it with
  `warmupOutboundPool`, then times exactly one delivery to a localhost
  stub. Measured 2026-10-11, Node v24.20.0, AMD EPYC 9D25, linux x64:

  | scenario | iterations | mean | p50 | p99 |
  |---|---|---|---|---|
  | HTTP first delivery, cold | 200 | 1.26 ms | 0.96 ms | 5.81 ms |
  | HTTP first delivery, warmed | 200 | 0.59 ms | 0.54 ms | 2.39 ms |
  | HTTPS+pins first delivery, cold | 100 | 4.81 ms | 4.36 ms | 12.74 ms |
  | HTTPS+pins first delivery, warmed | 100 | 0.95 ms | 0.85 ms | 6.11 ms |

  Takeaway: on localhost the TCP handshake is ~0.4 ms and the pinned TLS
  handshake ~3.5 ms at p50 — warm-up moves that cost from the first
  delivery into startup, where it is paid once per origin instead of once
  per cold burst. (An earlier run gave HTTP p50 1.22 → 0.67 ms and
  HTTPS+pins p50 4.18 → 0.87 ms; localhost numbers, not a WAN claim.)
- `src/server.ts` — a minimal `node:http` receiver: read the raw body, verify
  the `x-signature` header with the injected `verifier` (defaults to
  HMAC-SHA256 with `secret`; pass e.g. `new Ed25519Verifier(pem)` or
  `new RsaPssVerifier(pem)` to change schemes), or opt into key rotation with `signingKeys` (primary + retired
  keys, grace via `keyGraceMs`, senders name their key with the `x-key-id`
  header; accepted/rejected audit events carry the verifying `keyId`),
  or select the verifier per inbound path with `endpointVerifiers:
  [{ pattern: "/hooks/solana", verifier: new Ed25519Verifier(pem) }]` —
  first matching rule wins, unmatched paths fall back to the global
  verifier, mismatches answer 401 and never touch the circuit breaker,
  and accepted/rejected audit events name the verifier that decided,
  optionally enforce replay protection (`replay: new ReplayGuard()`
  — replays answer 409, bad/missing nonces and out-of-window timestamps
  answer 400, all audited as `rejected`), and optionally rate-limit the
  intake (`rateLimit: { perIpPerSecond, perEndpointPerSecond }` — dual
  token-bucket admission, per-sender IP + per-endpoint; over-budget requests
  are answered 429 with a `retry-after` header and audited as `rejected`
  with reason `rate_limited` and the exhausted `dimension`. The check runs
  before the body is read and before signature verification, so a flood
  costs almost nothing), optionally per-tenant intake rate limiting
  (`inboundTenantRateLimit: { perTenantPerSecond }` — one token bucket per
  `x-tenant-id`, checked after the WR-22 limiter and before verification so
  one abusive tenant's flood is rejected before it burns verifier CPU;
  over-budget requests are answered 429 and audited as `rejected` with
  reason `tenant_rate_limited`), enqueue for forwarding to
  `forwardUrl`, audit accept / delivered / dead-letter events. A failed verification returns 401 + audit entry.
  Operator endpoints `GET /dead-letter` (list dead letters with
  attempts/lastError/timestamp metadata, no raw payloads),
  `POST /dead-letter/:id/replay` (manually re-queue a dead letter, audited as
  `dead_letter_replayed`), and `GET /deliveries/:traceId` (per-trace delivery
  lifecycle snapshot: state machine timeline, retry trajectory with per-attempt
  errors, latency, replay records) are guarded by an `operatorToken` bearer token and
  disabled (404, fail closed) when it is unset. `GET /openapi.json` serves the
  full operator API as an OpenAPI 3.1 document — generated from the server's own
  route registry (`src/operator-routes.ts`), which also drives the 404/405
  dispatch, so the published spec cannot drift from the live routes (WR-111).
  It carries the same operator authentication (fail-closed 404 without a
  credential) and needs only the `read` scope. For reconciliation workflows,
  `POST /dead-letter/replay` batch-replays dead letters: the JSON body takes
  `{ endpoint?, tenant?, ids?, dryRun?, approvalToken? }` — `endpoint` limits the replay to one
  downstream, `tenant` to one tenant's dead letters (WR-86; omitting it keeps
  the pre-tenant behavior), `ids` to an explicit subset, and `dryRun: true`
  returns only a metadata preview (`{ dryRun: true, entries: [...] }` with
  id/endpoint/tenant/attempts/lastError/deadLetteredAt/payloadBytes, never the
  payload) with zero side effects: nothing is re-queued, nothing is audited,
  and sealed payloads are never decrypted. A real replay processes the
  matched entries grouped by endpoint, each entry independently (one failure
  cannot stop the others; failures stay dead-lettered), responds
  `{ replayed: [...], failed: [{ id, error }], throttled: [...] }`, and is
  audited as `dead_letter_batch_replayed`. The opt-in `replayEgress`
  server/queue option (see *Replay egress throttling* below) caps the
  re-queue rate per endpoint so a large backlog replays at a bounded rate
  instead of stampeding the downstream — entries held back stay
  dead-lettered (nothing dropped) and are reported in `throttled` plus the
  cumulative `throttled` counter on `GET /dead-letter/stats`. The opt-in
  `replayApproval` server/queue option (WR-135) adds a second pair of eyes
  for payment pipelines: a replay re-fires the downstream handler (real funds
  movement), so a real (non-dry-run) `POST /dead-letter/replay` or
  `POST /dead-letter/:id/replay` consumes a one-shot `approvalToken` issued
  by `POST /dead-letter/replay/approve-request` — the token is bound to the
  requested `endpoint`/`tenant`/`ids` scope (an empty scope approves anything),
  expires after 5 minutes by default (configurable), and a missing, expired,
  reused, or scope-mismatched token answers 403. Token consumption is audited
  as `replay_approved`; executing with an expired token is audited as
  `replay_approval_expired`. The token rides the JSON body or the
  `x-replay-approval-token` header and is never written to the audit log.
  Dry-run previews never need approval, and programmatic paths
  (`RetryQueue.replayDeadLetter` / `replayDeadLetters`) keep an explicit
  `bypassApproval: true` escape hatch (the operator HTTP layer never passes
  it; the WR-31 auto-replayer uses it). The opt-in
  `autoReplay` server option (see *Dead-letter auto-replay* below) replays
  the whole list on a timer with identical fresh-budget semantics, controlled by
  `POST /dead-letter/auto-replay/pause|resume|trigger` and observed via
  `GET /dead-letter/auto-replay/status`. The opt-in `deadLetterRetention`
  server option (see *Dead-letter retention* below) auto-purges dead
  letters past their per-endpoint TTL on a background sweep — each purge
  audited as `dead_letter_purged` with metadata only, never the payload —
  and exposes `{ total, purged, throttled, byEndpoint }` at
  `GET /dead-letter/stats`. For reconciliation against downstream systems,
  `GET /dead-letter/export` streams dead letters *with* their payloads as
  JSONL (`?format=jsonl`, default) or CSV (`?format=csv`, fixed 11-column
  set): `?endpoint=` / `?tenant=` / `?since=` / `?until=` filter (since/until
  are inclusive bounds on `deadLetteredAt`, ms epoch or ISO-8601), sealed
  payloads (WR-11) are transparently decrypted, and per-row payloads are
  truncated past 64 KiB (CSV cells carry a `...[truncated]` marker, JSONL
  rows a `payloadTruncated` flag) so one giant payload cannot blow the
  export's memory. One response carries at most 10,000 rows: a larger
  export answers 409 `export_exceeds_row_limit` and asks the operator to
  page with `?cursor=` (an inclusive start id; `x-export-has-more` /
  `x-export-next-cursor` headers chain the pages). Each completed export
  is audited as `dead_letter_exported` with the row count, filter,
  format, and operator key id — never the payloads. The same guard protects
  `GET /audit` (`?endpoint=`, `?event=` repeatable, `?since=`/`?until=` ISO-8601,
  `?limit=`), which queries the audit log through its index — delivery
  forensics per endpoint and time range.
- `src/shutdown.ts` — `installGracefulShutdown(server, drain, opts)`:
  one-shot SIGTERM/SIGINT handling. On the first signal the HTTP server stops
  accepting new connections (idle keep-alives are dropped; in-flight requests
  still finish), `drain()` runs, then the process exits 0 when drained, 1 on
  drain timeout. `RetryQueue.shutdown(timeoutMs)` stops scheduling new
  attempts, cancels pending backoff timers, and waits for in-flight
  deliveries to settle. Opt in per server with
  `createRelayServer({ ..., gracefulShutdown: { timeoutMs: 30_000 } })`
  (off by default; the `exit` hook is overridable for embedding/tests).

## HMAC secret rotation (zero-downtime)

Rotate an inbound endpoint's signing secret without a 401 storm: deploy
the new key as `currentSecret` while the old key keeps verifying inside
its grace window, cut the sender over, then clear `previousSecret`.

```ts
const server = createRelayServer({
  secret, // global fallback for paths with no rotation rule
  forwardUrl,
  secretRotation: [
    {
      pattern: "/hooks/payments", // exact path or "/hooks/*" prefix
      rotation: {
        currentSecret: NEW_SECRET,
        previousSecret: OLD_SECRET, // clear this once the rotation completes
        graceSeconds: 3600, // default 3600; 0 disables previous entirely
        // previousRetiredAtMs: <epoch ms> — pin this for rotations that
        // span deploys, otherwise the window is assumed to start at
        // server startup
      },
    },
  ],
});
```

Senders declare which key they used with `x-signature-version:
"current" | "previous"`; without the header the server tries `current`
first and falls back to `previous` inside the grace window. An unknown
version fails closed (401). Every webhook that verified with the old key
is audited as `secret_rotation_previous_used` (with the endpoint path) —
watch that event stream to know when rotation traffic has drained.
`new RotatingEndpointSecret(cfg).isRotationComplete()` reports when the
grace window has fully elapsed; clearing `previousSecret` then finishes
the rotation. A matching `endpointVerifiers` rule, a custom global
`verifier`, or `signingKeys` takes precedence over the rotation rule on
the same path. Invalid rules throw `RangeError` at startup. Orthogonal
to WR-65 API-key authentication: key-only endpoints never consult the
secrets; with `requireSignature: true` the dual-secret check is the
signature leg.

## Graceful shutdown

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  gracefulShutdown: { timeoutMs: 30_000 }, // SIGTERM/SIGINT → drain → exit
});
```

Shutdown sequence on the first signal:

1. **Stop accepting** — `server.close()`; idle keep-alive connections are
   dropped, in-flight requests run to completion.
2. **Drain deliveries** — `queue.shutdown(timeoutMs)`: no new attempts are
   scheduled, pending backoff timers are cancelled, and in-flight `sender()`
   calls are awaited (a delivery parked on a concurrency slot bails out
   instead of hanging).
3. **Exit** — 0 when everything settled, 1 when the timeout expired, so a
   hung downstream cannot pin the process forever.

Items still waiting on a backoff timer are dropped — they were never
delivered, and the queue is in-memory. For at-least-once across restarts,
either replay the dead-letter list after the process comes back, or enable
the durable delivery queue below.

## Durable delivery queue

Opt-in crash recovery for the retry queue (`durableQueueDir`, also
available as `retry.durableQueueDir`): pending and backoff-waiting
deliveries plus the dead-letter list are journaled to
`<dir>/queue.jsonl` (append-only JSONL, fsync'd per append) and restored
when the process restarts. A restored retry resumes with its *remaining*
backoff — the journal records each armed timer's absolute fire time — and
consumed attempts are never reset, so a crash cannot silently grant a
delivery extra attempts.

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  durableQueueDir: "/var/lib/relay/queue", // opt-in; unset = in-memory
  payloadEncryptor,                        // payloads sealed at rest (WR-11)
});
```

- **Payload secrecy** follows the dead-letter rule: sealed with the
  `payloadEncryptor` when one is configured, base64-encoded in the clear
  otherwise. Configure an encryptor in production.
- **At-least-once**: journal lines are written *before* the in-memory
  mutation they describe, so a crash between the two can only redeliver,
  never lose. Delivered and replayed items are terminal — they are never
  restored.
- **Recovery is audited**: every boot with the journal enabled appends a
  `queue_restored` event (`restoredItems`, `restoredDeadLetters`,
  `restoredRetries`, `skippedLines`). Corrupt lines (torn writes, payloads
  whose key was rotated) are skipped and counted, never fatal.
- **Compaction**: superseded lines are rewritten away amortized (and on
  every recovery and shutdown), so the journal stays proportional to live
  state.
- **Cost**: one fsync'd append per enqueue, per armed retry, and per
  terminal transition. That is the durability price — leave the option off
  when you don't need crash recovery.
- `queue.getDurableQueueStats()` reports the journal (`enabled`, `dir`,
  `liveItems`, `deadLetters`, `journalAppends`, `journalWriteErrors`,
  restore counts). Batch-buffered items (inside a `batch` window) are not
  journaled — the window is sub-second by default and `shutdown()` flushes
  it into the queue first.

Opt-in crash recovery for *scheduled* (`deliver_at`) deliveries (WR-133,
`durableScheduledDir`, also available as `retry.durableScheduledDir`):
one-shot parked deliveries are journaled to `<dir>/scheduled.jsonl`
(append-only JSONL, fsync'd per append) and restored when the process
restarts. Items still in the future resume parked with their remaining
delay; items past-due at recovery skip the delay queue and go straight to
the normal delivery path (past-due semantics match the live intake).
Nothing is attempted while parked, so a recovered item always carries zero
consumed attempts.

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  durableScheduledDir: "/var/lib/relay/scheduled", // opt-in; unset = in-memory parking
  payloadEncryptor,                                 // payloads sealed at rest (WR-11)
});
```

- **Payload secrecy** follows the WR-49 rule: sealed with the
  `payloadEncryptor` when one is configured, base64-encoded in the clear
  otherwise. Configure an encryptor in production.
- **At-least-once**: `park` and `cancel` lines are written *before* the
  in-memory mutation they describe, so a crash between the two can only
  redeliver, never lose. `fired` is the deliberate exception — written
  *after* the item entered the normal path, so a crash in between re-parks
  instead of losing the delivery.
- **Recovery is audited**: every boot with the journal enabled appends a
  `scheduled_restored` event (`restoredParked`, `restoredPastDue`,
  `skippedLines`). Corrupt lines (torn writes, payloads whose key was
  rotated) are skipped and counted, never fatal.
- **Compaction**: superseded lines are rewritten away amortized (and on
  every recovery and shutdown), so the journal stays proportional to live
  parked state. Compaction rewrites the original `park` lines verbatim —
  payloads are never re-encrypted, so a rotated key cannot strand live
  items.
- **Recurring cron schedules (WR-80) are not journaled**: future
  occurrences do not exist yet as deliveries; registrations stay
  in-memory. `shutdown()` with the journal enabled keeps the parked set
  (disarmed) instead of dropping it, so a restart resumes it via the
  journal.
- **Cost**: one fsync'd append per park, cancel, and fire. That is the
  durability price — leave the option off when you don't need crash
  recovery for scheduled deliveries.

## Runtime config hot reload

Delivery policy can be retuned without restarting the process:

```ts
queue.updateEndpointConfig("https://downstream/hook", {
  maxConcurrentPerEndpoint: 8,              // per endpoint; raise grants queued waiters now
  circuitBreaker: { failureThreshold: 3, cooldownMs: 10_000 }, // per endpoint
  quota: { deliveriesPerMinute: 300 },      // per endpoint
  retry: { baseDelayMs: 500, maxAttempts: 8 }, // queue-global backoff
});
```

- **Atomic validation** — the whole patch is validated first; an illegal
  value throws `RangeError` and the previous configuration is left
  completely intact (no partial application). Patching `circuitBreaker` or
  `quota` while that subsystem is disabled is also a `RangeError`.
- **In-flight is never touched** — already-scheduled retry timers keep the
  delay they were scheduled with (backoff is read at schedule time);
  lowering a concurrency limit below the current in-flight count only gates
  *new* acquisitions until the count drains.
- **Audited** — every applied change fires `onConfigChange` with a
  before/after diff; `createRelayServer` writes it to the audit log as
  `endpoint_config_updated`, and operators can apply patches over HTTP:

```sh
curl -X POST http://127.0.0.1:PORT/config/endpoint \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{"endpoint":"https://downstream/hook","maxConcurrentPerEndpoint":8}'
# → 200 { endpoint, changes } · 400 on illegal values · 403 without the
# token · 404 when operator endpoints are disabled (fail closed)
```

## Declarative config snapshots (export / apply / rollback)

The hot-reload layer above is imperative; the snapshot layer
(`src/config-snapshot.ts`) makes it declarative — export what is running,
review it, and converge back to it later:

```sh
curl http://127.0.0.1:PORT/config/snapshot \
  -H "Authorization: Bearer $OPERATOR_TOKEN" > config.json   # GET: export (read scope)
curl -X POST http://127.0.0.1:PORT/config/snapshot \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{"snapshot":'"$(cat config.json | jq .snapshot)"',"dryRun":true}'  # POST: apply (admin scope)
```

- **Exported** — `exportConfig()` captures the hot-reloadable config per
  `(tenant, endpoint)`: concurrency limit, circuit-breaker thresholds,
  quota budget, weighted targets, plus the queue-global backoff
  parameters — and a declarative *inventory* of the wiring the imperative
  setter cannot change: content-routing rules, signing-key **ids**,
  mTLS client-cert identity fingerprints, TLS pins, proxy presence,
  outbound compression, observed tenants.
- **Apply** — `applyConfig(snapshot, { dryRun })` diffs the snapshot
  against live config, applies value changes through
  `updateEndpointConfig`, and *removes* overrides the snapshot no longer
  carries (the endpoint falls back to the queue defaults). `dryRun: true`
  returns the plan without mutating anything.
- **Rollback** — if any step throws mid-apply, every applied item is
  rolled back to its exact pre-apply state (overrides that did not exist
  are removed again, not frozen to their effective value) and a
  `ConfigApplyError` is thrown. Successful applies audit as
  `config_applied`, rolled-back ones as `config_rolled_back`.
- **Fail-closed secrets** — snapshots carry identifiers only, never key
  bytes, PEM blocks, or proxy credentials. A snapshot that claims to
  carry secret material is refused outright, and an apply is refused
  (zero mutation) when the live secret-bearing inventory (signing keys,
  mTLS identities, proxies) diverged from the snapshot — rotate
  out-of-band and re-export.
- **Drift detection** — `detectConfigDrift(queue, snapshot)` reports the
  live-vs-snapshot diff without touching anything; inventory-only diffs
  (routing rules, pins, compression, tenants) are reported as `pending`
  on apply since they need a restart or a separate operator action.
- **Endpoint contract** — `GET /config/snapshot` needs the `read` scope,
  `POST` needs `admin` (WR-82 convention); both answer 404 fail-closed
  when operator auth is not configured and 403 without valid credentials.
  A malformed snapshot is a 400 (`invalid_snapshot`,
  `secret_material_refused`, `unsupported`); an unexpected mid-apply
  failure is a 500 after rollback (`apply_failed`).

## Endpoint pause/resume (operator switch)

An operator hold on a downstream: while an endpoint is paused, its
deliveries are parked — queued items stay queued with their attempt
counts intact, no delivery attempt is scheduled, no retry budget is
consumed, the circuit breaker is not touched, and nothing moves to
dead-letter. Newly accepted events for a paused endpoint park as well.
Resuming re-arms every parked item with its remaining delay, so a
backoff window interrupted by the pause continues instead of restarting.

```ts
queue.pauseEndpoint("https://downstream/hook");   // → true on a real transition
queue.resumeEndpoint("https://downstream/hook");  // parked items resume automatically
queue.getPausedEndpoints();                        // currently paused, in pause order
```

```sh
curl -X POST http://127.0.0.1:PORT/endpoints/pause \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{"endpoint":"https://downstream/hook"}'
# → 200 { endpoint, paused: true } · 400 on a bad body · 403 without the
# token · 404 for an unknown endpoint or when operator endpoints are
# disabled (fail closed)
```

- **Orthogonal to the circuit breaker** — pausing never changes breaker
  state, and breaker transitions never unpause. A pause is keyed by the
  logical `targetUrl` (it covers failover standbys too) and applies
  across tenants.
- **Pre-emptive holds** — `queue.pauseEndpoint` accepts a never-seen
  endpoint: any future delivery to it parks immediately (useful to hold a
  downstream before a deploy). The HTTP layer is stricter and answers 404
  for endpoints the server doesn't know, so a typo is loud, not a silent
  no-op.
- **In-flight is never cancelled** — a delivery already past the dispatch
  point settles normally; only future scheduling is held.
- **Idempotent and audited** — pausing an already-paused endpoint (or
  resuming a live one) is a no-op that audits nothing; real transitions
  fire `onEndpointPaused` / `onEndpointResumed` and are written to the
  audit log as `endpoint_paused` / `endpoint_resumed` (queryable via
  `GET /audit?event=endpoint_paused`).
- **Parked timing is in-memory** — a restart resumes parked items promptly
  (attempt counts survive through the durable queue; the remaining
  backoff does not).

## Delivery dry-run drill mode (opt-in)

Rehearse the whole delivery pipeline against a downstream without
touching it: per-endpoint opt-in drill mode dispatches through the
normal intake-to-dispatch path, but instead of a physical outbound
request the queue answers with a configurable canned response
(`status`/`body`/`delayMs`). Useful before a new downstream contract
goes live, or to verify retry/backoff wiring after an incident.

```ts
createRelayServer({
  deliveryDryRun: {
    "https://downstream/hook": { canned: { status: 200 } },          // the happy path
    "https://flaky/hook": { canned: { status: 503, delayMs: 150 } },  // drill the backoff lane
  },
});
```

```sh
curl -X POST http://127.0.0.1:PORT/endpoints/dry-run \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{"endpoint":"https://downstream/hook","enabled":true,"canned":{"status":200}}'
# → 200 { endpoint, dryRun: true, canned } · `enabled: false` removes the drill ·
# 400 on an illegal canned response (a 400 always means "nothing changed")
```

- **Control-plane isolation** — a drill never writes the circuit
  breaker, the dead-letter queue, the retry budget, quotas, or the
  urgent lane (control plane: read zero, write zero). A canned 2xx
  audits `delivered`, canned 408/429/5xx ride the normal backoff lane
  (audited `retrying`) without consuming retry budget, exhaustion
  audits `dry_run_exhausted` — never the dead-letter queue — and other
  canned 4xx audit `failed` with reason `dry_run_failed`. Every drill
  audit event carries `dry_run: true`, and drill outcomes count in the
  isolated `relay_dry_run_deliveries_total{endpoint,outcome}` dimension
  instead of the real-traffic counters.
- **Operational parking still applies** — endpoint pause, delivery
  windows, maintenance windows, and the delivery deadline gate a drill
  exactly like a real delivery; only the physical request and the
  control-plane writes are skipped.
- **Runtime toggle and audit** — `POST /endpoints/dry-run` (operator,
  admin scope) installs or removes a drill config with immediate
  effect; transitions audit `endpoint_dry_run_enabled` /
  `endpoint_dry_run_disabled` with the operator's `keyId`.
  `queue.setEndpointDryRun` / `getEndpointDryRun` /
  `dryRunEndpoints` / `getDryRunStats` are the library-level API.
- **Honest drill semantics** — the canned delay holds the delivery
  in-flight (keep it small); a drill never emits completion receipts
  (WR-47), never feeds the fan-out quorum (WR-106), and never samples
  the real latency trackers — a rehearsal is not a delivery.

## Outbound hedged requests (opt-in)

Cut tail latency without waiting for retries: when a delivery attempt
to a hedgeable endpoint has not returned within `hedgeDelayMs`, the
relay issues a second identical attempt in parallel — first to settle
wins, the loser is cancelled (`AbortController`; the HTTP/1.1 path
destroys the losing request, H2/WS attempts are abandoned best-effort).

```ts
createRelayServer({
  hedgedRequests: {
    enabled: true,
    hedgeDelayMs: 250,
    hedgeableEndpoints: ["https://payments/hook"], // exact targetUrl match
  },
});
```

- **Hedgeable only** — hedging duplicates a downstream hit on slow
  endpoints, so it only ever fires for idempotent-safe endpoints you
  list explicitly (or a `hedgeable(item)` predicate you supply).
  Nothing hedges by default: omit the list and the wrapper is a pure
  pass-through.
- **Latency-gated, never error-gated** — a returned 429/5xx settles the
  attempt, so it never triggers a hedge; it rides the normal
  classify → backoff path. A fast transport failure (connection
  refused) settles the attempt the same way. Only "no response within
  `hedgeDelayMs`" launches the hedge.
- **Orthogonal composition** — each hedge attempt is an independent
  full attempt: its own keep-alive checkout (WR-24), its own WR-76
  delivery deadline, its own WR-99 deadline-budget race, and its own
  WR-143 phase budgets. The winner is whoever settles first; the loser
  is cancelled immediately so it never holds a pool slot or delivers a
  late duplicate.
- **Observability** — every launched hedge audits `hedged`
  (`targetUrl`, `hedgeDelayMs`); `relay_hedged_total{endpoint}`
  counts hedges (activity-gated, absent when the feature never fires);
  a delivery that hedged carries `hedged: true` on its `delivered`
  delivery event and audit line.
- **Also a library primitive** — `createHedgedSender(inner, opts)`
  wraps any `Sender` (the default sender or a custom one); custom
  senders that ignore the `signal` option degrade to abandon-the-loser
  semantics, documented in `src/hedged.ts`. Invalid `hedgeDelayMs`
  throws `RangeError` at startup.

## Downstream error-budget burn-rate alerting (opt-in)

Watch how fast each downstream is spending its error budget, Google
SRE style: the relay tracks per-endpoint delivery outcomes in two
sliding windows — a fast window (default 1h) that catches a sudden
spike, and a slow window (default 6h) that confirms it is real — and
alerts when *both* windows' burn rates (observed error rate ÷ budgeted
error rate) exceed the threshold.

```ts
createRelayServer({
  retry: {
    errorBudget: {
      budgetErrorRate: 0.01,  // 1% of attempts may fail
      alertThreshold: 2,      // alert past 2x the budgeted rate
      onBurnRateAlert: (info) => pageOnCall(info),
    },
  },
});
```

- **Alert only, never gate** — the alert notifies; it never blocks,
  delays, or reroutes a delivery. It is orthogonal to the circuit
  breaker (WR-10), which *does* gate dispatches on its own terms, and
  to active probing (WR-34): a burning endpoint keeps receiving
  deliveries until the breaker trips.
- **Edge-triggered with re-arm** — a sustained breach alerts exactly
  once per episode; the monitor re-arms only after both windows recover
  below the threshold, so a flapping endpoint does not page on every
  outcome. A `minEvents` floor (default 10) keeps a lone failure from
  looking like a catastrophe.
- **Callback-safe** — a throwing `onBurnRateAlert` is swallowed by the
  monitor: the alert is lost, the delivery is not.
- **Observability** — every fired alert audits `error_budget_burn`
  (endpoint, burn rates, windows, budget); `relay_error_budget_burn_ratio{endpoint}`
  gauges the current fast-window burn rate (1.0 = exactly at budget;
  activity-gated, absent until the first outcome).
- Invalid configs (`slowWindowMs <= fastWindowMs`, `budgetErrorRate`
  outside (0, 1), non-positive thresholds) throw `RangeError` at
  startup. Library users drive `ErrorBudgetMonitor` directly with an
  injectable clock (`now`) for deterministic tests.

## Dynamic endpoint registry (opt-in)

Manage the *set* of downstream endpoints without restarting the relay:
register a new downstream with its full delivery policy, rotate a
proxy or TLS pins, or retire an endpoint once its in-flight deliveries
have drained. The registry is an opt-in config overlay — with no
endpoints registered, behavior is exactly the static-config default.

```ts
createRelayServer({
  endpoints: [
    {
      targetUrl: "https://downstream/hook",
      circuitBreaker: { failureThreshold: 3, cooldownMs: 30_000 },
      quota: { maxPerMinute: 500 },
      maxConcurrentPerEndpoint: 8,
      tlsPins: ["sha256/…"],
    },
  ],
});
```

```sh
# register (admin scope)
curl -X POST http://127.0.0.1:PORT/endpoints \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{"targetUrl":"https://downstream/hook","quota":{"maxPerMinute":500}}'
# → 201 { id, targetUrl, endpoint } (metadata only — no secrets)

# update · delete (drains first unless ?force=true)
curl -X PUT http://127.0.0.1:PORT/endpoints/https%3A%2F%2Fdownstream%2Fhook …
curl -X DELETE 'http://127.0.0.1:PORT/endpoints/<id>?force=true' …
# GET /endpoints lists records (read scope, metadata only)
```

- **Validated before anything is stored** — startup and each CRUD call
  validate the full config first; a 400 always means "nothing changed".
- **Hot-reload semantics** — deliver-policy fields (`circuitBreaker`,
  `quota`, `maxConcurrentPerEndpoint`) apply through the WR-32 path:
  in-flight deliveries keep the config they started with; only future
  scheduling sees the new values. Sender-side fields (`verifier` outbound
  signing, `proxy`, `tlsPins`) resolve per delivery *attempt*, so an
  attempt already on the wire is likewise unaffected. Every change is
  audited as `endpoint_config_updated` (secrets rendered `[redacted]`).
- **`ordered` is startup-only** — the queue builds its ordered-delivery
  tracker once at construction, so runtime `ordered` changes are
  rejected with a clear 400.
- **Retire safely** — `DELETE` first drains in-flight deliveries
  (configurable `endpointDrainTimeoutMs`, default 30s); a timeout answers
  409 with the remaining count, and `?force=true` skips the drain.
- **Fail-closed** — without an operator credential all four routes are
  404; `read` keys may `GET`, mutations need `admin`.

## Stale-endpoint auto-pause (opt-in)

Configuration-rot hygiene for downstreams that quietly stopped working:
when a logical endpoint has seen **no successful delivery** for
`staleAfterDays` (default 30) **and** has nothing pending, a background
sweep auto-pauses it through the exact operator-switch mechanics above —
parking, no retry-budget burn, no breaker verdict, no dead-letter,
in-flight untouched. Resume with the ordinary `resumeEndpoint` /
`POST /endpoints/resume` path; resuming restarts the idle clock.

```ts
const queue = new RetryQueue({
  sender,
  stalePause: { staleAfterDays: 30 }, // off by default; present = enabled
});
queue.sweepStaleEndpoints(); // manual sweep; the timer also sweeps every sweepIntervalMs (60s)
queue.getStalePauseStats();  // per-endpoint idleDays / pending / paused / autoPauses
```

- **Idle means idle** — the clock is stamped on every genuinely
  successful delivery (`delivered`). A validator-rejected response
  (semantic failure) or a non-retryable 4xx does **not** count as
  success, so a downstream answering "no" forever still goes stale. An
  endpoint that never delivered is measured from its first sighting.
- **Nothing pending, ever stranded** — queued, retrying,
  batch-window-buffered, and `deliver_at`-parked items (across all
  tenants) all block the pause. The sweep also never re-processes an
  already-paused endpoint: a manual operator hold wins silently, with no
  duplicate audit.
- **Pause ≠ discard** — while auto-paused, inbound events are still
  accepted; they park in the (durable, when enabled) queue and resume
  with their remaining delays on resume.
- **Not the circuit breaker** — the WR-10 breaker is transient fault
  handling (fast fail, half-open recovery) driven by consecutive
  failures; auto-pause is rot hygiene driven by the *absence* of
  success. They never interact: pausing doesn't trip the breaker and
  breaker transitions don't unpause.
- **Operator alerting** — each auto-pause is audited as
  `endpoint_auto_paused` (endpoint/idleDays/staleAfterDays/
  lastSuccessfulDeliveryAt — never the payload; queryable via
  `GET /audit?event=endpoint_auto_paused`). The event is edge-triggered
  (one per transition) and is the alert channel for this feature; pair
  it with the `relay_endpoint_auto_pauses_total{endpoint}` Prometheus
  counter. Manual pauses keep auditing as `endpoint_paused` — one
  transition, one event, the cause in the name.

## Scheduled delivery (deliver_at)

Timed delivery: an inbound event may declare a future delivery time via
the `x-deliver-at` header — a decimal epoch-ms integer or an HTTP-date
(IMF-fixdate / RFC 850 / asctime, e.g. `Sun, 11 Oct 2026 09:00:00 GMT`).
Until that instant arrives the delivery is *parked* in an in-memory delay
queue (a min-heap ordered by `deliverAt`, with exactly one timer armed
for the head). A past-due value takes the normal delivery path, like any
other event.

```sh
curl -X POST http://127.0.0.1:PORT/ \
  -H "x-signature: <hmac>" \
  -H "x-deliver-at: 1791234000000" \
  -H "content-type: application/json" \
  -d '{"order":"ord_123"}'
# → 202 { id, traceId, status: "accepted", scheduled: true,
#         deliverAt: "2026-10-11T09:00:00.000Z" }
```

```ts
queue.cancelScheduled("evt_123"); // → true: parked item dropped, never delivered
queue.cancelScheduled("unknown"); // → false
queue.getScheduled();             // pending items, earliest deliverAt first
queue.getScheduledStats();        // { pending, scheduled, due, canceled }
```

```sh
curl http://127.0.0.1:PORT/scheduled \
  -H "Authorization: Bearer $OPERATOR_TOKEN"
# → 200 [{ id, targetUrl, deliverAt, deliverAtIso, traceId, tenant?, priority? }]
# 403 without the token · 404 when operator endpoints are disabled (fail closed)
```

- **Parking consumes nothing** — a parked delivery is not attempted and
  costs no attempt, no retry-budget token (WR-38), no quota token (WR-15),
  no circuit-breaker verdict (WR-10), and no backoff timer or jitter
  (WR-02). Attempt counting starts at the first *actual* dispatch, so a
  delivery parked for a day still gets its full `maxAttempts` when its
  instant arrives.
- **Due means normal** — when the instant arrives the item enters the
  standard path, so retry, dead-letter, circuit, quota, retry budget, and
  the SSE delivery events (`delivered` / `retrying` / `dead_letter`) all
  apply from the first real attempt. An invalid `x-deliver-at` is a sender
  bug: answered 400 fail-fast, audited as `rejected` with reason
  `invalid_deliver_at`, never enqueued.
- **Operator visibility** — `GET /scheduled` lists pending scheduled
  deliveries as metadata only (the payload is never exposed); parking is
  audited as `scheduled` (queryable via `GET /audit?event=scheduled`).
  `queue.cancelScheduled(id)` drops a parked item; unknown ids return
  `false`.
- **In-memory only, honestly** — the delay queue is *not* journaled by
  default: a restart does not recover parked deliveries (orthogonal to the
  WR-49 durable queue, which still journals a delivery once its instant
  arrives and it enters the normal path). Opt-in with `durableScheduledDir`
  (WR-133) to journal parked one-shot deliveries and resume them after a
  restart. `stop()` keeps parked items and re-arms on `start()`; `shutdown()`
  without the journal drops parked-but-not-due items exactly like
  backoff-waiting ones — they were never delivered (with the journal, the
  parked set is kept disarmed and compacted instead).
- **Timer hygiene** — the single arming timer is unref'd, so a far-future
  `deliver_at` never pins the process open; delays beyond `2^31 - 1` ms
  are clamped and re-armed instead of overflowing `setTimeout`. The clock
  is injectable (`retry.scheduled.now` / `setTimer` / `clearTimer`) for
  deterministic tests.
- **Observability** — `relay_scheduled_total`,
  `relay_scheduled_due_total`, and `relay_scheduled_canceled_total`
  (present once a delivery has actually been parked); scheduled items
  bypass batching, since a batch window would blur the per-event
  deliver_at.

### Recurring scheduled delivery (cron)

One-shot `x-deliver-at` covers a single future instant; for periodic
jobs an inbound event may instead carry an `x-schedule-cron` header with
a 5-field cron expression (`minute hour day-of-month month
day-of-week`, e.g. `*/15 9-18 * * 1-5` — every 15 minutes during
business hours, Monday–Friday). The request registers a *schedule* and
returns a `scheduleId`; every cycle the relay emits one delivery event
with a freshly generated `traceId`. Field shapes are `*`, `*/n`, `n`,
`n-m`, `n-m/s`, and comma lists of those atoms (numeric only — month
and weekday names are rejected, so a typo like `mon` fails loudly
instead of misfiring). Day matching follows classic cron semantics
(day-of-month OR day-of-week when both are restricted), and all
evaluation is in UTC. The next occurrence is the first fire instant
*strictly after* the registration (or resume) moment, at second 0 of
the matching minute.

```sh
curl -X POST http://127.0.0.1:PORT/ \
  -H "x-signature: <hmac>" \
  -H "x-schedule-cron: */15 9-18 * * 1-5" \
  -H "content-type: application/json" \
  -d '{"report":"daily_sales"}'
# → 202 { id, traceId, status: "accepted", scheduleId: "sched_<id>",
#         cron: "*/15 9-18 * * 1-5", nextAt: "2026-10-12T09:15:00.000Z" }
```

- **Invalid is 400, never half-registered** — a malformed expression is
  a sender bug: answered 400 fail-fast (`invalid_schedule_cron` /
  `conflicting_schedule` when `x-deliver-at` is also present),
  audited as `rejected`, nothing enqueued. The cron parser
  (`src/cron.ts`) is zero-dependency and fully covered by its own
  unit suite (`test/cron.test.ts`).
- **Per-cycle independence** — each firing walks the normal delivery
  path on its own: attempt counting, retry, dead-letter, circuit,
  quota, retry budget, batching bypass, and the SSE delivery events
  (`delivered` / `retrying` / `dead_letter`) all apply per cycle.
  Per-cycle deadlines (WR-76) are evaluated independently, so a slow
  cycle cannot eat the next cycle's SLO budget.
- **Pause / resume** — `POST /scheduled/:id/pause` stops occurrence
  generation (already-emitted deliveries are unaffected);
  `POST /scheduled/:id/resume` recomputes the next occurrence from
  *now* — missed cycles are skipped, never backfilled. Unknown ids
  are a fail-closed 404; transitions are audited as
  `schedule_paused` / `schedule_resumed`. `GET /scheduled` lists
  recurring schedules with `recurring: true` plus `cron`, `nextAt`,
  and `paused`.
- **Observability** — every firing is audited as `scheduled_fired`
  (wrapped through the caller's `onScheduledFired`, so custom hooks
  keep working); `relay_scheduled_fired_total` counts cycles. The
  schedules are in-memory only, like the one-shot delay queue —
  a restart does not resurrect them (documented limitation, not a
  bug).
- **The clock is injectable** — the recurring scheduler takes its time
  from the same injectable clock as the delay queue, so tests drive
  cycles deterministically without wall-clock waits.

## Relay-level global concurrency cap

`maxConcurrentPerEndpoint` bounds in-flight deliveries *per downstream*;
`globalMaxConcurrent` (`retry.globalMaxConcurrent`) bounds them *across
the whole relay* — at most N deliveries executing concurrently, no matter
how many endpoints or tenants they fan out to. The two gates compose: a
dispatch needs a slot from each. When the cap is hit, excess dispatches
wait FIFO for a slot — never dropped, never burning retry budget, never
touching the circuit breaker.

```ts
const queue = new RetryQueue({
  maxConcurrentPerEndpoint: 8, // per endpoint (WR-06)
  globalMaxConcurrent: 64,      // relay-wide (WR-51); default Infinity
});
queue.getGlobalConcurrencyStats();
// → { maxConcurrent: 64, inFlight: 12, queuedDepth: 3, waitsTotal: 41 }
```

- **Dispatch-point placement** — the gate is the last acquisition before
  the sender is invoked (after the lane turn, the per-endpoint limiter,
  and the liveness/pause re-check) and is released when the attempt
  settles (success, failure-scheduled, or dead-lettered). Quota, circuit,
  and budget verdicts are all settled before a global slot is taken, so
  waiting on the gate disturbs nothing; lane ordering from the WR-35
  scheduler is preserved.
- **The urgent lane bypasses the per-endpoint limiter but not this gate**
  — the cap is relay-level capacity (sockets, memory, file descriptors),
  not per-endpoint policy.
- **Paused endpoints hold no slots** — a paused delivery never reaches
  the gate (it parks before), so an operator hold can't starve the relay.
- **Observability** — `getGlobalConcurrencyStats()` reports the cap, the
  current in-flight count, the FIFO waiter depth, and the cumulative
  waiter count; the cumulative count is also exported as
  `relay_global_concurrency_wait_total` (present only when the cap is
  configured). Invalid values throw `RangeError` at construction.
- **Shutdown-safe** — the gate is promise-FIFO only (no timers, nothing
  to unref); `stop()`/`shutdown()` wake every waiter, whose liveness
  check bails it out instead of dispatching, so a shutdown waits only
  for genuinely in-flight deliveries.

## Per-tenant outbound concurrency cap

`globalMaxConcurrent` bounds in-flight deliveries across the whole
relay; `tenantMaxConcurrent` (`retry.tenantMaxConcurrent`) bounds them
*per tenant across all of that tenant's endpoints* — the fairness valve
between tenants. Each tenant gets an independent gate (WR-48 isolation,
created lazily), so one tenant's flood queues against its own cap and
never occupies another tenant's slots.

```ts
const queue = new RetryQueue({
  tenantMaxConcurrent: 16, // per tenant (WR-140); default Infinity
});
queue.getTenantConcurrencyStats();
// → [{ tenant: "acme", maxConcurrent: 16, inFlight: 3, queuedDepth: 1, waitsTotal: 9 }]
```

- **Placement** — the gate sits inside the WR-51 global gate and outside
  the per-endpoint limiter: a dispatch takes the global slot, then its
  tenant's slot, then the per-endpoint slot; releases run in reverse
  order. The urgent lane bypasses it like the per-endpoint limiter
  (both are tenant policy, not relay-level capacity) but not the global
  gate.
- **Waiting is neutral** — excess dispatches wait FIFO: never dropped,
  never burning retry budget, never touching the circuit breaker.
- **Tenant-less deliveries skip it entirely** — with no `x-tenant-id`
  the dispatch path is byte-for-byte the pre-WR-140 behavior.
- **Observability** — `getTenantConcurrencyStats()` reports one row per
  tenant in first-seen order; tenants that actually waited also export
  `relay_tenant_concurrency_wait_total{tenant}` (activity-gated —
  absent until a tenant waits, and only when the cap is configured).
  Invalid values throw `RangeError` at construction.
- **Shutdown-safe** — promise-FIFO only (no timers, nothing to unref);
  `stop()`/`shutdown()` wake every tenant's waiters.

## Adaptive outbound concurrency (AIMD)

The fixed per-endpoint cap (`maxConcurrentPerEndpoint`, WR-06) is static:
the same number that is right for a healthy downstream over-commits
against a struggling one and throttles a strong one below its real
capacity. `retry.adaptiveConcurrency` (opt-in, off by default) adds a
second, *outcome-driven* cap per endpoint using classic AIMD:

```ts
const queue = new RetryQueue({
  maxConcurrentPerEndpoint: 32, // fixed cap (WR-06)
  adaptiveConcurrency: {
    minLimit: 1,               // floor; default 1
    maxLimit: 32,              // ceiling; default = the fixed cap above
    initialLimit: 32,          // start; default = maxLimit (behave like
                               // the fixed cap until congestion is seen)
    increaseStep: 1,           // +N per healthy window; default 1
    decreaseFactor: 0.5,       // ×N per congested window; default 0.5
    failureRateThreshold: 0.2, // window failure rate that marks
                               // congestion; default 0.2
    windowSize: 20,            // outcomes per adjustment step; default 20
  },
});
```

- **AIMD** — outcomes accumulate in a rolling window of `windowSize` per
  endpoint. A full window whose failure rate stays below the threshold
  grows the limit additively (`+increaseStep`, clamped at `maxLimit`); a
  full window at or above the threshold cuts it multiplicatively
  (`×decreaseFactor`, floored at `minLimit`). Each full window triggers
  exactly one step, then clears — the same failures never punish twice.
  No clock, no randomness: the same outcome sequence always yields the
  same limits.
- **What counts as failure** — the same convention as the circuit
  breaker, WR-59, failover, and weighted dispatch: retryable failures
  (429/5xx/timeout/DNS) heat the controller; successes — including a
  downstream that answered with a *non-retryable* rejection (an answering
  endpoint is a healthy endpoint) — cool it. WR-30 4xx semantic
  rejections are never congestion signals.
- **Composition** — the effective per-endpoint limit is
  `min(maxConcurrentPerEndpoint, adaptive)`: the adaptive cap can only
  tighten the fixed cap, never exceed it. A WR-32 hot-reload that lowers
  the fixed cap takes effect through the same `min`. Urgent deliveries
  bypass the limiter (their bound stays the token bucket), but their
  outcomes still feed the controller. Orthogonal to WR-59 (backoff tunes
  *delay*, AIMD tunes *concurrency*) — both read the same outcome
  stream, and both record leader-only under WR-91 coalescing.
- **Observability** — `getAdaptiveConcurrencyStats()` exposes each
  endpoint's current limit plus window fill (`windowOutcomes` /
  `windowFailures` / `windowSize`); `relay_adaptive_concurrency_limit{endpoint[,tenant]}`
  exports finite limits to Prometheus (activity-gated — absent until the
  first outcome is recorded; a gauge cannot hold Infinity). Invalid
  options throw `RangeError` at construction.

## Slow-start recovery ramp (opt-in)

When a circuit breaker trips, the endpoint is known-down; when it
recovers (half-open probe succeeds → closed), restoring the full
concurrency limit at once risks a thundering herd against a downstream
that just came back to life. `retry.slowStart` (opt-in, off by default)
paces the recovery: the breaker's close event starts a per-endpoint
ramp at `floor` (default 1) that climbs toward the ceiling — the fixed
`maxConcurrentPerEndpoint` cap unless you set `maxLimit` explicitly:

```ts
const queue = new RetryQueue({
  maxConcurrentPerEndpoint: 32, // fixed cap (WR-06); the ramp ceiling
  circuitBreaker: { failureThreshold: 5, cooldownMs: 30_000 },
  slowStart: {
    curve: "exponential", // 1 -> 2 -> 4 -> ... per success (default);
                          // "additive" for 1 -> 2 -> 3 -> ...
    floor: 1,             // start/fallback concurrency; default 1
    maxLimit: 32,         // ceiling; default = the fixed cap above
  },
});
```

- **Ramp** — a success steps the limit up the curve; reaching the
  ceiling completes the ramp and the endpoint runs at the full limit
  again. A failure mid-ramp drops the limit back to the floor
  *instantly* and the ramp restarts — the endpoint must re-prove
  itself. A fresh breaker-close always restarts the ramp at the floor,
  even if the previous ramp was still climbing.
- **What counts as success/failure** — the same convention as the
  breaker and the WR-94 controller: retryable failures (429/5xx/
  timeout) are failures; successes — including a downstream that
  answered with a *non-retryable* rejection (an answering endpoint is
  not a sick endpoint) — step the ramp up. Outcomes are recorded
  leader-only under WR-91 coalescing.
- **Composition** — the effective per-endpoint limit is
  `min(fixed, adaptive, ramp)`: the ramp can only pace a recovery, never
  exceed the steady-state limits. Orthogonal to WR-94 AIMD (AIMD is
  *outcome-driven* window adjustment of the steady-state limit; the
  ramp is *event-driven* recovery pacing on the breaker-close event)
  and to the WR-10 breaker state machine (it decides open/closed; the
  ramp only starts on its close event). Without a `circuitBreaker`
  configured no close event can ever fire, so `slowStart` alone is a
  complete no-op.
- **Observability** — `getSlowStartStats()` exposes each mid-ramp
  endpoint's current limit, floor, ceiling, and curve (`tenant` only
  when set; absent rows run at the full limit). Invalid options throw
  `RangeError` at construction.

## Per-tenant outbound rate limiting

One tenant's flood must not starve the shared downstream or crowd out
another tenant's deliveries. `retry.tenantRateLimit` (opt-in, off by
default; also accepted as a server-level `tenantRateLimit`, which wins)
adds a token bucket per **(tenant, endpoint)** scope — `burst` capacity
refilled at `refillPerSecond` — with per-endpoint overrides of the
tenant-level defaults:

```ts
const queue = new RetryQueue({
  tenantRateLimit: {
    burst: 50,              // default burst per (tenant, endpoint); required
    refillPerSecond: 5,     // default refill rate; required
    endpoints: {
      // endpoint-level overrides win over the tenant-level defaults,
      // per field — unset fields fall back to the defaults
      "https://payments.example.test/hook": { burst: 200 },
    },
    mode: "queue",          // or "reject-429"; default "queue"
  },
});
```

- **Two over-limit modes** — `"queue"` (default) enforces at *dispatch*:
  an over-limit attempt is rescheduled for the next token refill, never
  dropped, never charged to the retry budget, and never reported to the
  circuit breaker as an outcome — the WR-15 quota pattern, tenant-scoped.
  `"reject-429"` enforces at *intake*: an over-limit webhook is answered
  `429` with a `retry-after` header (the WR-22 convention) and audited
  as `rejected` with reason `rate_limited`, before it ever enters the
  queue — the sender gets honest backpressure. The token is consumed at
  admission in this mode, so the dispatch path never re-checks: one
  delivery, one token.
- **WR-91 composition** — in `queue` mode the rescheduled delivery keeps
  its full lifecycle: it still dispatches through the coalescing sender
  and may merge with an in-flight identical attempt. Like the WR-15
  quota, the gate charges per logical delivery dispatch (followers
  included) — it runs before the coalescer decides leader/follower.
- **Orthogonal to WR-94 AIMD** — this paces *rate* (deliveries per
  second), AIMD paces *concurrency* (simultaneous in-flight attempts). A
  rate-limited wait is never a delivery outcome: it feeds neither the
  AIMD controller, nor the WR-59 adaptive backoff, nor the circuit
  breaker.
- **Observability** — every denial bumps the scope's counter, exported
  to Prometheus as `relay_tenant_ratelimited_total{endpoint[,tenant]}`
  (activity-gated — absent until the first denial; the `tenant` label is
  omitted for the default tenant, per the WR-48 convention) and to OTLP
  as a `rate_limited` event carrying `relay.retry_after_ms`.
  `getTenantRateLimitStats()` exposes per-scope denial counts plus the
  override-resolved `burst` / `refillPerSecond`. Invalid options throw
  `RangeError` at construction; the clock is injectable for
  deterministic tests.

## Per-tenant monthly delivery budgets

Usage-based billing needs a ceiling, not just a meter. `retry.budget`
(opt-in; unlimited by default) adds a per-tenant monthly delivery budget
enforcement layer on top of the WR-78 usage metering:

```ts
const queue = new RetryQueue({
  budget: {
    budgets: { acme: 10_000 }, // tenant -> deliveries per UTC month
  },
});
queue.setTenantBudget("globex", { deliveriesPerMonth: 500 }); // runtime change, immediate
```

- **What counts** — terminal `delivered` outcomes only (the WR-78 billing
  vocabulary; `failed === retried + dead_letter`, so `delivered` is the
  only terminal-success counter), counted per UTC calendar month. The
  enforcer keeps its own monthly buckets — the UsageMeter's window is
  rolling, so it cannot serve a calendar-month budget — fed from the same
  `delivered` events. Orthogonal to the WR-15 quota counts.
- **Over budget** — an over-budget tenant's dispatch is rescheduled for
  the next UTC month boundary (plus a little jitter): never dropped,
  never charged to the retry budget, never shown to the circuit breaker —
  the WR-15 quota pattern, tenant-scoped. The gate runs before the quota
  gate, so an over-budget tenant consumes no quota tokens either.
- **One audit event per month** — the first over-budget dispatch per
  tenant per month fires `budget_exceeded` (tenant, allowance, usage,
  month); the month rollover re-arms it — never an audit flood.
- **Opt-in, unlimited by default** — a tenant without a configured budget
  is unlimited; the default relay behaves byte-identically to the
  pre-WR-137 one.
- **Observability** — `getTenantBudgetStats()` exposes per-tenant month,
  usage, allowance, the over flag, and the cumulative parked-reschedule
  count; `relay_tenant_budget_deliveries_total{tenant}` (gauge: this
  month's counted deliveries) and
  `relay_tenant_budget_deliveries_limit{tenant}` (gauge: the allowance)
  export usage against budget to Prometheus (activity-gated — absent
  until the first budget is configured). Invalid budgets throw
  `RangeError` at configuration; the clock is injectable for
  deterministic tests.

## Endpoint failover (active/standby)

One logical endpoint (the configured primary `targetUrl`) can own an
ordered list of physical targets. The queue resolves the active target on
every dispatch — a switch never touches queued items, and in-flight
deliveries keep the target they were dispatched with:

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  retry: {
    failover: {
      "https://primary/hook": {
        standbys: ["https://standby-1/hook", "https://standby-2/hook"],
        failureThreshold: 3,      // default 5; consecutive failures → switch
        autoFailback: true,       // default true
        failbackIntervalMs: 30_000, // default 30s; quiet period before a canary
      },
    },
  },
});
```

- **Switch triggers** — the active target's circuit breaker opens, *or* it
  fails `failureThreshold` times in a row (the manager's own counter, so it
  works with the breaker disabled). A downstream that *answers* — even with
  a 4xx — counts as healthy; only retryable failures count. Standbys are
  tried in order; when every target is down the queue keeps trying the last
  one and the normal retry / dead-letter machinery owns the outcome.
- **Failback is a probationary canary, never blind trust** — once the quiet
  period passes, the next dispatch goes to the primary; its first outcome
  alone decides (success keeps it, failure re-switches immediately). With
  `autoFailback: false` the relay stays on the standby until
  `queue.resetFailover(endpoint)` moves it back manually.
- **Observability** — every switch is audited as `failover_switched`
  (`endpoint` = logical endpoint, `from`/`to`, `reason` =
  `circuit_open`/`failure_threshold`/`failback`/`manual`) and counted in
  `relay_failover_switches_total{endpoint,from,to}`. Delivery counters,
  latency histograms, and circuit gauges are keyed by the *physical*
  target that served the attempt; `queue.getFailoverStats()` shows the
  current active target per logical endpoint.
- **Dead letters** record the physical target they died on
  (`failoverEndpoint` remembers the logical endpoint), so a replay
  re-resolves against the *current* active target instead of pinning to
  the standby. A per-endpoint response validator configured for the
  primary still applies to standby traffic (exact standby match wins).
- **Invalid configs throw `RangeError` at startup** — empty standby
  lists, a standby equal to the primary, duplicates, chained primaries,
  and illegal thresholds.

## Weighted multi-target dispatch (opt-in)

Where failover (above) answers "which target is *up*", weighted mode
answers "how is traffic *shared*": one logical endpoint spreads every
dispatch across several physical targets with a smooth weighted
round-robin — hand-written, zero dependencies, nginx-style (each pick adds
the target's weight to its accumulator, takes the max, and subtracts the
pool total from the winner). Weights are relative shares, not
percentages; 5:3:2 over ten dispatches yields exactly 5/3/2, and the
sequence stays smooth so no target starves for a whole cycle:

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  retry: {
    weighted: {
      "https://api/hook": {
        targets: [
          { targetUrl: "https://ingest-1/hook", weight: 5 },
          { targetUrl: "https://ingest-2/hook", weight: 3 },
          { targetUrl: "https://ingest-3/hook", weight: 2 },
        ],
        failureThreshold: 5,      // default 5; consecutive failures → excluded
        recoveryIntervalMs: 30_000, // default 30s; quiet period before rejoining
      },
    },
  },
});
```

- **Only healthy targets join the rotation** — the signals are the ones
  the relay already has: an open circuit breaker excludes the target, a
  half-open breaker re-includes it so the probe delivery can settle (its
  outcome re-admits or re-excludes), and the dispatcher's own
  per-target consecutive-failure counter excludes sick targets even with
  the breaker disabled. A downstream that *answers* — even with a 4xx —
  counts as healthy. An excluded target rejoins once the recovery
  interval passes since its last failure — its next outcome alone
  decides (success resets, failure re-excludes for another interval). When
  *every* target is unhealthy the first configured target is pinned and
  the normal retry / dead-letter machinery owns the outcome.
- **Mutually exclusive with failover per endpoint** — configuring
  `weighted` and `failover` for the same endpoint throws `RangeError` at
  startup ("share traffic" and "ordered standby" must never both claim an
  endpoint). Different endpoints may use different modes.
- **Runtime retuning** — `queue.updateEndpointConfig(endpoint, {
  weighted: { targets: [...] } })` replaces the whole target list
  atomically (validated before apply, zero partial application), resets
  the round-robin accumulators, and keeps health counters and cumulative
  dispatch counts. It fires `onConfigChange` like any hot-reload patch,
  so the server audits it as `endpoint_config_updated` and operators can
  apply it over `POST /config/endpoint`.
- **Observability** — `relay_weighted_dispatch_total{endpoint,target}`
  counts dispatches per physical target (present only when weighted mode
  is in use); delivery counters, latency histograms, and circuit gauges
  are keyed by the physical target that served the attempt;
  `queue.getWeightedStats()` shows per-target
  `{ weight, effectiveWeight, dispatched, consecutiveFailures, healthy }`.
- **Invalid configs throw `RangeError` at startup** — empty target
  lists, empty/duplicate `targetUrl`s, and non-positive or non-finite
  weights.

## Quorum fan-out: M-of-N downstream acknowledgement (opt-in)

Where weighted mode answers "how is traffic *shared*", quorum fan-out
answers "how many confirmations is *enough*": the multi-settlement-channel /
redundant-notification scenario. One admitted event fans out to N
downstream targets, and M successful acknowledgements settle the fan-out
as delivered — the remaining targets keep their own delivery lifecycle
(at-least-once is never revoked by the quorum verdict).

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  quorum: {
    "https://api/payments/hook": {
      targets: [
        "https://settle-a/hook",
        "https://settle-b/hook",
        "https://notify-c/hook",
      ],
      quorum: 2,   // 1 <= quorum <= targets.length
    },
  },
});
```

- **One admission, N member deliveries** — the event is admitted and
  audited once; each target gets its own queue item (`<id>:quorum:<i>`)
  carrying the admitted priority (WR-12: an urgent admission puts every
  member on the fast lane), headers, trace id, and tenant. Members are
  never batched: a batch merge rewrites the item id and would destroy
  ack attribution.
- **Normal per-endpoint machinery per member** — each member rides the
  relay's standard retry/backoff, circuit breaker, quota, global retry
  budget, and dead-letter machinery as its own delivery. The quorum layer
  never schedules its own retries: an unacknowledged member is retried by
  the queue, and a member that exhausts its budget (or fails non-retryable
  per WR-30) dead-letters individually. The fan-out itself never becomes a
  single dead-letter entry.
- **Terminal semantics** — `satisfied`: M targets acknowledged (late acks
  are still recorded but never change the settled state). `failed`: M
  became unreachable (`acked + live < M`); live members still finish
  their own lifecycle. `partial`: at least one target dead-lettered
  while M is still reachable — degraded, still working.
- **Observability** — `GET /quorum` shows per-fanout
  `{ fanoutId, endpoint, targets, acked, status, deadLettered }`; audited
  as `quorum_dispatched` / `quorum_acknowledged` / `quorum_satisfied` /
  `quorum_failed` / `quorum_target_dead_lettered`; counted in
  `relay_quorum_total{endpoint,status}`,
  `relay_quorum_acknowledged_total{endpoint}`, and
  `relay_quorum_target_dead_letters_total{endpoint}` (all activity-gated:
  absent until the first ack or loss).
- **Retention window (WR-109)** — settled fan-outs do not accumulate
  unboundedly in memory. A settled fan-out is evicted once its verdict is
  older than `quorumRetentionMs` (default 1h), or — when more settled
  fan-outs are retained than `quorumMaxFanouts` (default 10_000) — oldest
  verdict first. Each eviction is archived as a `quorum_evicted` audit
  line (operator metadata only: fan-out id, endpoint, terminal status,
  acked/targets/lost-target counts, dispatch/verdict/eviction timestamps,
  eviction reason; no payloads) and counted in the activity-gated
  `relay_quorum_evicted_total`. The eviction count is also exposed via
  `GET /quorum/stats` as `{ fanouts, evicted }` — the object-shaped
  companion to the array-shaped `GET /quorum` (whose array response is
  kept for backward compatibility). In-progress fan-outs are never
  evicted; a delivery outcome that arrives after its fan-out was evicted
  is silently ignored (the verdict, once reached, is terminal).
- **Invalid configs throw `RangeError` at startup** — empty/duplicate/
  non-`http(s)` targets, fanning out to the logical endpoint itself
  (double-delivery), or a quorum outside `[1, targets.length]`. Absent =
  zero behavior change.

## Relay mesh forwarding (opt-in)

Chain relays so an event hops relay → relay before reaching the final
downstream — e.g. an edge relay that fans in to a central relay that owns
the downstream credentials. The forwarding itself is just a `forwardUrl`
(or content route) pointing at the next relay's inbound; the mesh layer
adds hop accounting, a loop guard, and peer authentication on top:

```ts
// Relay A (edge): signs every outbound delivery with the shared relay key.
const relayA = createRelayServer({
  secret, forwardUrl: "https://relay-b.example.com/hook", auditLog,
  mesh: {},                                   // enabled, maxHops defaults to 8
  outboundSigning: { secret: "mesh-shared-relay-secret" },  // WR-26
});
// Relay B (core): verifies the peer signature and enforces the hop budget.
const relayB = createRelayServer({
  secret: "mesh-shared-relay-secret",          // the verifier holds the shared key
  forwardUrl: "https://downstream/hook", auditLog,
  mesh: { maxHops: 5 },
});
```

- **`x-relay-hops` header** — counts traversed relays (0 = arrived
  directly from a producer). Inbound is parsed at admission (absent = 0,
  malformed = fail-closed 400 `mesh_hops_invalid`); the count rides the
  queue item through retries, dead-letter + replay, and the durable-queue
  journal, and every outbound wire request stamps
  `x-relay-hops: meshHops + 1`.
- **Loop guard** — an inbound event already at `maxHops` is rejected 400
  (`mesh_hop_limit_exceeded`) instead of cycling A → B → A forever.
  Malformed and over-budget rejections are audited as `rejected`.
- **Peer authentication** — a mesh hop proves itself with
  `x-relay-signature` (the WR-26 outbound signature), verified against the
  relay's configured verifier as a fallback when the producer
  `x-signature` is absent. The mesh runs on a shared relay secret, so this
  grants no new capability beyond what `x-signature` already allows — it
  only names the trust domain (`meshPeer: true` on the `accepted` audit
  event). Run mesh links over TLS; the hop count itself is cooperative
  telemetry, not a security boundary.
- **Observability** — `accepted` / `delivered` / `dead_letter` audit events
  carry `meshHops`; `relay_mesh_forwarded_total{endpoint}` and
  `relay_mesh_hop_limit_rejections_total{endpoint}` render into
  `GET /metrics` (activity-gated: absent until the first forward or
  rejection). `x-trace-id` threads the whole mesh untouched (WR-18), so
  one trace correlates every hop.
- **Mutual TLS on the mesh link (opt-in, WR-112)** — `mesh: { mtls: {} }`
  upgrades the cooperative `x-relay-signature` trust to real mutual TLS.
  Inbound: a request presenting `x-relay-signature` (i.e. claiming to be a
  mesh peer) must also present a client certificate verified through the
  `inboundMtls` chain (WR-103: CA chain + fingerprint whitelist, required
  on the mesh path) — a missing/invalid certificate is answered 401,
  audited as `rejected` with reason `mesh_mtls_reject`, and counted on
  `relay_mesh_mtls_rejects_total{path}`; the verified peer identity rides
  the `accepted` audit as `clientCertFingerprint`. Plain producers (no
  `x-relay-signature`) are untouched. Outbound: a mesh hop is only
  forwarded over `https:` and only with a client identity configured for
  the peer endpoint (WR-36 `tlsClientCerts`) — anything else is refused
  locally and fails the delivery through the normal retry/dead-letter
  path instead of sending an unauthenticated hop. Enabling it requires
  `inboundMtls` with TLS terminated on the intake listener
  (`requireCert`, or `operatorMtls` on the single-plane listener);
  otherwise the server throws `RangeError` at startup — a client
  certificate cannot be verified without a TLS handshake, so this is a
  fail-fast, never a silent no-op. Off by default: zero behavior change.
- **Disabled = zero behavior change** — without `mesh`, the header is
  stripped at intake and never stamped. Invalid `maxHops` throws
  `RangeError` at startup. Shadow-target mirrors (WR-85) never stamp hops:
  a mirror is not a mesh traversal.

## Pluggable dedup store (opt-in)

The payload-hash deduplicator (WR-14) suppresses repeat deliveries of the
same business event inside a time window — e.g. a retried payment callback
that must not charge twice. Its backing window is now pluggable, so a
fleet of relay processes can share one dedup window (Redis, …) instead of
each keeping a private in-memory one:

```ts
import { createRelayServer } from "./src/server.ts";
import type { DedupStore } from "./src/dedup.ts";

const redisStore: DedupStore = {
  // Return true when `key` was seen inside [nowMs - windowMs, nowMs].
  async checkAndRemember(key, nowMs, windowMs) { /* SETNX + PEXPIRE … */ },
  async size() { /* DBSIZE … */ },
};
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  dedup: { windowMs: 300_000, maxEntries: 10_000, store: redisStore },
});
```

- **Contract** — `checkAndRemember(key, nowMs, windowMs)` owns expiry and
  eviction and must honor the caller-supplied `nowMs` (never its own
  clock), so behavior stays deterministic and testable; `size()` feeds
  observability. Both may be async. The deduplicator keeps the key shape
  (`<endpoint>\n<sha256(payload)>`, tenant-scoped upstream) and the
  checked/suppressed counters, so WR-14 semantics, window, and TTL are
  unchanged.
- **Default unchanged** — without `store`, the built-in
  `InMemoryDedupStore` behaves exactly as before (same keys, same
  oldest-eviction, same lazy expiry), including the WR-79 crash journal.
- **`store` and `journalDir` are mutually exclusive** — a custom store
  owns its own durability (Redis persistence, …); combining both throws
  `RangeError` at startup, as does a `store` that does not implement the
  interface (`TypeError`).

## Payload gzip compression

Outbound deliveries can be gzipped per endpoint (opt-in), and inbound
gzipped webhooks are accepted transparently:

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  compressOutbound: {
    "https://downstream/hook": { thresholdBytes: 2048 }, // default 1024
  },
});
```

- **Outbound** — payloads at or above the threshold are gzipped when (and
  only when) the compressed form is actually smaller; `Content-Encoding:
  gzip` is stamped and `Content-Length` reflects the compressed size.
  `x-relay-signature` covers the compressed wire bytes — exactly what the
  downstream receives and verifies.
- **Guarded compression (`compressThreshold`)** — a stricter per-endpoint
  variant for downstreams that may not speak gzip:

  ```ts
  const server = createRelayServer({
    secret, forwardUrl, auditLog,
    compressThreshold: {
      "https://downstream/hook": {
        thresholdBytes: 2048, // default 1024
        contentTypeWhitelist: ["application/json"], // default; matched on the media type
      },
    },
  });
  ```

  Beyond the threshold rule, the payload must pass the content-type
  whitelist (default `application/json` — batch envelopes and relay
  payloads are JSON by contract), and when a guarded delivery is answered
  `415`, the sender resends it once as plaintext *inside the same
  delivery attempt* — no retry budget consumed, no circuit event — and
  audits `gzip_fallback_plaintext`. A `415` on the plaintext resend (or
  any other failure) follows the normal retry / dead-letter path.
  Compressed bytes saved per endpoint are counted in
  `relay_compressed_bytes_saved_total`. When both `compressOutbound` and
  `compressThreshold` configure an endpoint, the guarded path wins. The
  guarded path engages on the HTTP/1.1 and HTTP/2 transports only —
  WebSocket deliveries keep their RFC 7692 permessage-deflate story and
  never pass through here. Invalid values throw `RangeError` at startup.
- **Inbound** — a webhook posted with `Content-Encoding: gzip` is
  decompressed *after* signature verification (the signature covers the
  raw wire bytes the sender signed) and *before* version routing, replay
  guard, dedup, and enqueue, so everything downstream sees the canonical
  plain payload. The stale `content-encoding` header is stripped from the
  forwarded headers, and the `accepted` audit event notes
  `contentEncoding: "gzip"`.
- **Bomb-proof** — decompression is streaming and capped at
  `maxBodyBytes`: a gzip bomb is answered `413` (`rejected` /
  `body_too_large`) exactly like an oversized plain body, and corrupt
  gzip is answered `400` (`rejected` / `decompression_failed`).

Measured wire savings (`bench/gzip-bench.ts`, realistic ~3.4 KiB
payment-webhook JSON, Node v24.20.0 / AMD EPYC 9D25):

| | bytes |
|---|---|
| original payload | 3422 |
| gzipped | 780 |
| ratio | 0.228 (**4.4x smaller**) |

gzip p50: ~34µs per payload — negligible next to a network round trip.

## Outbound brotli compression

Outbound deliveries can be brotli-compressed per endpoint (opt-in),
independent of the gzip options above:

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  compressBrotli: {
    "https://downstream/hook": { thresholdBytes: 2048 }, // default 1024
  },
});
```

- **Outbound** — payloads at or above the threshold are brotli-compressed
  when (and only when) the compressed form is actually smaller;
  `Content-Encoding: br` is stamped and `Content-Length` reflects the
  compressed size. `x-relay-signature` covers the compressed wire bytes
  — exactly what the downstream receives and verifies.
- **Precedence** — when an endpoint is configured in `compressBrotli`,
  the brotli path wins over *both* gzip paths (`compressOutbound` and
  `compressThreshold`) for that endpoint: the compressions are never
  stacked, and the gzip records are never consulted. The two transports
  behave like the gzip paths — the compression engages on the HTTP/1.1
  and HTTP/2 delivery paths only, and WebSocket deliveries keep their
  RFC 7692 permessage-deflate story (`src/deflate.ts`) and never pass
  through here.
- **Pipeline position** — brotli compresses at the same position as
  gzip: after the WR-115 payload transform and the WR-117 outbound
  schema validation, before WR-58 E2EE sealing (a sealed envelope
  carries the pre-seal encoding as `innerEncoding: "br"`, with no
  `content-encoding` header on the wire) and before WR-26 signing, so
  the signature always covers the brotli bytes the downstream receives.
- **Fire-and-forget** — like `compressOutbound` and unlike the guarded
  path, there is no content-type whitelist and no 415→plaintext fallback:
  a downstream that rejects `br` answers `415` like any other delivery
  failure (retry / dead-letter as usual). An endpoint whose downstream
  may reject compressed bodies should use `compressThreshold` instead.
- **Shared accounting** — byte savings feed the same
  `OutboundCompressionTracker` (and the same
  `relay_compressed_bytes_saved_total` exposition) as the gzip paths.
- **Inbound** — `Content-Encoding: br` on a downstream *response* is
  already decoded by the WR-62 `decodeResponseBody` path
  (`src/response-encoding.ts`); nothing new was added for inbound
  *request* brotli decode (that belongs to WR-62's inbound-decode work).

Measured wire savings (`bench/brotli-bench.ts`, same ~3.4 KiB
payment-webhook JSON as the gzip bench, Node v24.20.0 / x64):

| | bytes |
|---|---|
| original payload | 3422 |
| brotli-compressed | 607 |
| ratio | 0.177 (**5.6x smaller**) |

brotli p50: ~6.9ms per payload — the quality-11 default trades CPU for
size (brotli ships ~22% smaller than gzip on this payload: 607 vs 780
bytes); the cost still lands far below a network round trip.

Invalid values throw `RangeError` at startup, like every other module.

## Per-endpoint body size limits

`endpointBodyLimits` overrides the global `maxBodyBytes` on selected
inbound paths — tighter *or* looser — using the same rule convention as the
WR-29 per-endpoint verifiers (exact or `path/*` prefix patterns, first
matching rule wins, unmatched paths keep the exact global behavior):

```ts
const server = createRelayServer({
  maxBodyBytes: 1_048_576, // global budget: 1 MiB
  endpointBodyLimits: [
    { pattern: "/hooks/ledger", maxBodyBytes: 5_242_880 }, // fat settlement webhooks
    { pattern: "/hooks/*", maxBodyBytes: 262_144 },         // everything else under /hooks/*
  ],
});
```

- **One budget, three enforcement points** — the matched rule's budget is
  resolved from headers alone (before a single body byte is read) and
  governs the declared `Content-Length` pre-check, the `readRawBody`
  streaming cap, and the `gunzipCapped` decompression cap. A gzip bomb on
  a tightened endpoint is answered `413` under that endpoint's own budget,
  exactly like an oversized plain body.
- **Operators see which cap fired** — over-limit bodies are answered `413`
  with `connection: close` and audited as `rejected` (reason
  `body_too_large`) carrying the *effective* `maxBodyBytes`, so the audit
  trail distinguishes a per-endpoint cap from the global one.
- **Orthogonal to WR-41 schema validation** — this is the transport layer
  (byte budget, enforced before signature verification and before schema
  validation); schema is semantic validation (payload shape, runs after
  decompression). The batch envelope (`POST /ingest/batch`) is gated by
  its own rule, so per-item payloads are bounded by the outer envelope —
  no per-item budget is needed or applied.
- Invalid rules (non-array, pattern not starting with `/`,
  non-positive-integer `maxBodyBytes`) throw `RangeError` at startup, so
  a bad config can never fail a request mid-flight.

## Inbound signature algorithm negotiation (opt-in)

Upstreams name the algorithm they signed with in the `x-signature-alg`
header (`hmac-sha256` / `ed25519`) and the relay verifies with the
matching verifier from the operator-configured allowlist instead of the
global default — one relay can front producers that sign differently
(e.g. HMAC-SHA256 for a legacy PSP, Ed25519 for a Solana program's
callbacks) without weakening either:

```ts
createRelayServer({
  secret,
  signatureAlgorithms: [
    { alg: "hmac-sha256", verifier: new HmacSha256Verifier(secret) },
    { alg: "ed25519", verifier: new Ed25519Verifier(solanaProgramPubkeyPem) },
  ],
});
```

```bash
curl -X POST http://relay/hooks/solana \
  -H "x-signature-alg: ed25519" \
  -H "x-signature: ed25519=<hex>" \
  -d '{"event":"program.callback"}'
# → 202; accepted audit events carry algorithm: "ed25519"
```

- **Allowlist, fail-closed** — a negotiated name that is not listed is
  answered `400` and audited as `rejected` with reason
  `unsupported_algorithm`; it is never enqueued. Invalid rules throw
  `RangeError` at startup.
- **Default is backward compatible** — unset `signatureAlgorithms`
  disables negotiation entirely: the header is ignored and the legacy
  default verifier applies (effectively "only hmac-sha256").
- **Never widens pinned trust** — a per-endpoint verifier rule
  (`endpointVerifiers`) keeps its verifier; the header is ignored on
  pinned paths.
- Works on single webhooks and on every `POST /batch` item (each item
  negotiates independently).

## Batch inbound ingestion

`POST /ingest/batch` accepts one JSON envelope carrying many events, so a
producer — e.g. a payment provider pushing a batch of callbacks — pays one
HTTP round trip instead of one per event:

```bash
# envelope: { "events": [{ "payload": "<base64>", "headers": {...} }, ...] }
# x-signature: HMAC of the whole raw envelope body (same secret/verifier)
curl -X POST http://relay/ingest/batch \
  -H "x-signature: sha256=<envelope-signature>" \
  -d '{"events":[{"payload":"eyJvcmRlciI6IjEyMyJ9","headers":{"x-signature":"sha256=<item-signature>"}}]}'
# → 202 { batchId, traceId, results: [{ index, status: 202, id, traceId }, ...] }
# → 207 Multi-Status when items have mixed outcomes
```

- **Envelope signature first** — the batch `x-signature` is verified over
  the whole raw envelope body *before* the batch is split, so dropping,
  reordering, or tampering with items invalidates the batch (`401`).
  Per-endpoint verifier rules and key rotation apply to the batch path.
- **Full per-item pipeline** — each item then walks the same admission as
  a single webhook: per-item signature → tenant → gzip → version
  adaptation → schema → content routing → replay guard → dedup → enqueue. Item `payload` is
  base64 of the exact bytes the per-item `x-signature` covers, so per-item
  trust semantics are identical to a single `POST`. An item without a
  verifiable signature is rejected `401` exactly like an unsigned webhook.
- **Failure isolation** — one bad item never affects the rest: per-item
  `{ index, status, id, traceId, reason? }` results, `207` when mixed.
  A malformed envelope is `400` and never touches per-item admission.
- **Independent trace IDs** — each item carries its own trace ID (its own
  `x-trace-id` or a fresh one), never the batch's.
- **Audit** — one `batch_ingested` event (totals) plus the normal
  per-item `accepted` / `rejected` / `duplicate_suppressed` events, each
  carrying `batchId` for correlation. A batch-level `x-tenant-id` is
  validated once and inherited; a per-item `x-tenant-id` overrides it.

## Lightweight batch ingestion (`POST /batch`)

Same envelope shape as `/ingest/batch`, but **no envelope signature**:
the batcher is authenticated by the intake gates (IP allowlist, API key,
mTLS — auth follows the inbound rules) and each event authenticates
itself with its own `x-signature`. For producers that aggregate events
but cannot hold a batch-signing key; `/ingest/batch` stays the choice
when the batcher itself must be authenticated.

```bash
curl -X POST http://relay/batch \
  -d '{"events":[{"payload":"eyJvcmRlciI6IjEyMyJ9","headers":{"x-signature":"sha256=<item-signature>"}}]}'
# → 202 { batchId, traceId, accepted: 1, rejected: [] }
# → 207 { batchId, traceId, accepted: 1, rejected: [{ index: 1, reason: "invalid_signature" }] }
```

- **Full per-item pipeline** — every item walks the same admission as a
  single webhook: signature (including `x-signature-alg` negotiation) →
  tenant → gzip → version adaptation → schema → replay guard → dedup →
  rate limit → enqueue. Per-item header names are lowercased before
  admission (HTTP semantics).
- **Fail-fast size gate** — any single item whose decoded body exceeds
  the global per-event body budget rejects the *whole* batch with `413`
  before any per-item admission runs (zero side effects, no partial
  processing; audited as `rejected` with reason `item_too_large`).
  The envelope itself is still capped by the resolved (possibly
  per-endpoint) budget, so an `endpointBodyLimits` rule can widen
  `/batch` transport for big batches without letting one oversized
  event through.
- **Per-item failure isolation** — malformed items are reported per item
  (`{ index, reason: "invalid_item" }`) and never fail the batch; only
  the size gate and a malformed envelope (`400`) fail the whole batch.
- **Audit** — one `batch_received` event (totals) plus the normal
  per-item `accepted` / `rejected` / `duplicate_suppressed` events, each
  carrying `batchId` for correlation.

## Content-based routing

Route an inbound webhook to a target endpoint by matching rules against
payload JSON fields, instead of sending everything to `forwardUrl`:

```ts
createRelayServer({
  secret, forwardUrl, auditLog,
  contentRoutes: [
    {
      id: "express-orders",
      matchers: [{ field: "order.type", op: "equals", value: "express" }],
      targetUrl: "https://team-a.example.com/hooks",
      priority: 10, // optional, default 100 — lower wins
    },
    {
      id: "big-tickets",
      matchers: [{ field: "amount", op: "range", min: 1000 }],
      targetUrl: "https://team-b.example.com/hooks",
    },
  ],
  contentRouteDefault: "https://fallback.example.com/hooks", // optional
});
```

- **Rule shape** — `{ id, matchers: [{ field, op, value?, min?, max? }], targetUrl, priority? }`.
  `field` is a dot-path into the parsed JSON (e.g. `"order.type"`).
  Ops: `equals` (JSON compare, deep-ish for arrays), `contains`
  (substring for strings, element compare for arrays), `regex` (strings
  only — non-string fields never match), `exists` (present and not
  null/undefined), `range` (numeric field, `min <= x <= max`, at least one
  bound). A rule matches when *all* its matchers match.
- **Resolution** — rules are sorted by `priority` ascending (stable, ties
  keep config order); the first fully-matching rule wins. No match →
  `contentRouteDefault` when configured, otherwise `forwardUrl`. Routing
  never throws and never rejects an event: a non-JSON body, a missing
  field, or a throwing matcher just falls through to the fallback.
- **Placement** — routing runs *after* signature verification (and tenant /
  gzip / version adaptation / schema) and *before* the replay guard and
  dedup, on the canonical payload — so dedup is keyed on the routed
  target (WR-14 semantics unchanged: the same business event suppresses
  per target, not globally). Batch-ingest items walk the same admission
  (`admitOneEvent`), so routing applies to them too.
- **Validation** — illegal rules (empty/duplicate id, unknown op, empty
  field path, bad regex, bad range bounds, empty targetUrl, empty
  matchers) throw `RangeError` at startup; a bad
  `contentRouteDefault` does too.
- **Hot update** — `GET /routing/rules` lists the live table (read scope);
  `POST /routing/rules` with `{ rules: [...], defaultTargetUrl?: string }`
  replaces it wholesale (admin scope): a `RangeError` surfaces as `400`
  and changes nothing (validate-then-apply), success is `200` plus an
  audited `routing_rules_updated` event with the operator's `keyId`. Like
  every operator path, it answers `404` fail-closed when no operator
  credentials are configured.
- **Audit** — every admitted event with routing configured emits a
  `routed` event carrying `ruleId` (the matched rule, or `"default"`)
  and `targetUrl`; the `accepted` event already carries the routed
  `targetUrl`.

## Downstream response compression negotiation

Per-endpoint opt-in: the relay advertises `Accept-Encoding: gzip,
deflate, br` on outbound deliveries, and a compressed downstream response
is transparently decoded *before* the response validator and the audit
summary see the body:

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  responseCompression: {
    "https://downstream/hook": {}, // or { acceptEncoding: "gzip", maxDecompressedBytes: 65536 }
  },
  retry: {
    responseValidators: {
      "https://downstream/hook": (r) => JSON.parse(r.body.toString()).ok === true,
      // ^ sees the DECODED body — write validators against plain JSON,
      // whether the downstream compressed or not.
    },
  },
});
```

- **Negotiation** — opted-in endpoints send `Accept-Encoding: gzip,
  deflate, br` (overridable per endpoint) on the HTTP/1.1 and HTTP/2
  delivery paths. Stacked codings decode in reverse application order;
  `identity` is a no-op.
- **Bomb-proof** — every decode stage is hard-capped at
  `maxDecompressedBytes` (default 64 KiB, the sender's response capture
  cap): a compression bomb fails the attempt as a *retryable* delivery
  failure instead of blowing up the process. Corrupt compressed bodies
  fail the same way.
- **Never loses a delivery** — a downstream that ignores
  `Accept-Encoding` and answers plaintext works exactly as before, and an
  unknown coding is passed through untouched for the validator to judge.
  A wire capture cut at the cap cannot be decoded, so the raw bytes travel
  on with `truncated: true` like the uncompressed path.
- **Observability** — the decoded `contentEncoding` rides
  `DownstreamResponse` into the WR-37 validator and the audit
  `response_summary`, so operators can see which downstreams compress.
- Endpoints without an entry send no `Accept-Encoding` and behave
  byte-identically to before.

## Per-endpoint response assertions (opt-in)

Some downstreams answer `200 OK` with a body that still means failure —
a payment gateway's error code, `{"ok":false}`. WR-37 covers this with a
programmatic validator; response assertions cover it *declaratively*, for
operators who would rather write config than code:

```ts
const queue = new RetryQueue({
  responseAssertions: [
    {
      targetUrl: "https://downstream.example/hook",
      expectedStatuses: [200, 201], // default: every 2xx
      assertions: [
        { path: "$.status", op: "eq", value: "ok" },
        { path: "$.data.latencyMs", op: "lt", value: 5000 },
        { path: "$.code", op: "matches", value: "^PAY-[0-9]+$" },
        { path: "$.traceId", op: "exists" },
      ],
    },
  ],
});
queue.getDeliveryStats(); // per-endpoint rows incl. `assertionFailures`
```

- **Tiny, safe expression language** — a strict path (`$` for the whole
  document, then `.name` / `[index]` segments) plus one operator:
  `eq` / `ne` (strict equality, no coercion), `gt` / `gte` / `lt` /
  `lte` (finite numbers only), `exists`, `matches` (regex on strings).
  No `eval()`, no general expressions.
- **Fail-fast config** — a bad path, an unknown operator, a missing
  `value`, an empty status whitelist, or a duplicate `targetUrl` throws
  `RangeError` at construction, with zero partial application: a bad
  rule never silently disables the good ones.
- **Fail-closed evaluation** — assertions run on the *decoded* response
  body (post-decompression, like the WR-37 validator). A body that is
  not JSON, a path that resolves to nothing, or an evaluation error
  counts as a failure, never a silent pass.
- **Failure semantics** — assertions apply to responses that would
  otherwise be delivered (status inside the whitelist). A failing
  assertion is a *retryable* delivery failure with
  `failure_class: "assertion_failed"`: the normal backoff lane, the
  WR-10 breaker counts it like any retryable failure, and it honors the
  retry budget. A non-whitelisted status keeps the WR-30 classification
  (a 404 is still `non_retryable`, never an assertion failure). Each
  failure fires `onAssertionFailure` and is audited as `failed` with
  `reason: "assertion_failed"`.
- **Observability** — per-endpoint `assertionFailures` via
  `queue.getDeliveryStats()` and the `relay_assertion_failures_total`
  Prometheus counter (activity-gated: absent entirely when the feature
  is off). Endpoints without a rule behave byte-identically to before.

## Outbound header forwarding allowlist

Per-endpoint opt-in gate on the inbound headers the relay forwards
downstream (`src/forward-headers.ts`). By default the relay forwards the
inbound request's headers (minus the relay-owned strips the intake
applies: `host`, `content-length`, stale `content-encoding`, `x-relay-*`,
`x-tenant-id`, `x-api-key`) — convenient for trace correlation, but it
also means a caller's `authorization` or `cookie` header reaches a
downstream that never asked for it.

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  forwardHeaders: {
    "https://downstream/hook": {
      allow: ["^x-", "content-type"], // strings are case-insensitive regexes
      deny: ["x-internal-secret"],    // deny always wins over allow
    },
  },
});
```

- **Precedence** — explicit `deny` > explicit `allow` > default deny >
  absent `allow` (= forward everything the deny lists do not block). An
  explicit `allow: []` forwards nothing but the relay-forced headers.
- **Default deny** — with a rule configured, `authorization` and `cookie`
  are never forwarded unless the operator explicitly allowlists them (an
  explicit allow overrides the *default* deny, never an explicit one).
  Endpoints without a rule keep the exact current pass-through behavior.
- **Relay-forced headers always survive** — the rule only filters the
  inbound passthrough set; `x-trace-id`, `x-relay-signature` /
  `x-relay-key-id` (WR-26), the WR-44 idempotency key, and the
  WR-40/WR-62 encoding stamps are applied *after* the gate and can
  neither be dropped by it nor confused by it.
- **Composes** with WR-26 (signing stamps after the gate, always
  retained) and WR-36 (mTLS is transport-level, orthogonal); WR-65's
  `x-api-key` never reaches the gate at all — stripped at intake.
- Matching is case-insensitive; `RegExp` patterns are rebuilt without
  the stateful `g`/`y` flags so forwarding is deterministic. Invalid
  rules throw `RangeError` at startup — never mid-delivery.

## Per-endpoint payload transform (opt-in)

Rewrite the JSON payload just before delivery, per endpoint
(`src/transform.ts`). Some downstreams speak a different dialect than the
producer — a payment gateway that wants `amount_cents` instead of
`amount`, a ledger hook that requires a static `x-tenant` header, an
event bus that needs the delivery id echoed back as a header:

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  outboundSigning: { secret: signSecret }, // WR-26
  payloadTransforms: {
    "https://payments.example/hook": {
      fieldRenames: { amount: "amount_cents" },   // move: source deleted
      fieldMaps: { "meta.order_id": "order" },    // copy: source kept
      fieldDeletes: ["internal.debug"],
      constants: { source: "relay", "meta.v": 1 },
      headerInjections: {
        "x-event-id": "evt-{{event_id}}",
        "x-attempt": "{{attempt}}",
        "x-tenant": "acme",
      },
    },
  },
});
```

- **Pipeline order** — the transform runs first, on the raw payload
  bytes: transform → gzip (WR-40/WR-75) → E2EE sealing (WR-58) → signing
  (WR-26). Compression and sealing produce non-JSON wire bytes, so the
  transform must precede them; the signature always covers the
  transformed bytes — exactly what the downstream receives and verifies.
  For WR-09 batched deliveries the merged envelope is transformed as
  one JSON document.
- **Templates** — header values (and only header values) may use
  `{{event_id}}` (the delivery id), `{{endpoint}}`, `{{attempt}}`
  (1-based, per attempt), and `{{timestamp}}` (ISO-8601, rendered per
  attempt). Unclosed `{{`, stray `}}`, or unknown variables throw
  `TemplateError` at startup — never mid-delivery.
- **Failure is never silent** — a non-JSON payload under a configured
  transform (or any runtime transform failure) throws
  `PayloadTransformError`, classified `"non_retryable"`: the item
  dead-letters on the first attempt without burning the retry budget,
  and the audit log gets a dedicated `transform_failed` event (delivery
  id, error, endpoint) alongside the usual `dead_letter`. The endpoint
  was never contacted, so the circuit breaker and the adaptive
  controllers learn nothing from it.
- **Anti-forgery** — injected headers are relay-computed: any inbound
  header with the same name is stripped before stamping (the WR-26
  pattern). Relay-owned and transport names (`x-relay-signature`,
  `x-trace-id`, `traceparent`, `content-length`, …) are rejected at
  construction; `x-`-prefixed names are recommended by convention.
- **Paths** — dot-separated with numeric segments for array elements
  (`items.0.sku`); `__proto__` / `constructor` / `prototype` are
  rejected. Missing sources are no-ops; sets create intermediate
  objects (arrays for numeric segments). Transformed payloads are
  emitted as canonical JSON (`JSON.stringify`); endpoints without rules
  pass bytes through untouched. Invalid rules throw `RangeError` /
  `TemplateError` at startup — never mid-delivery.

## Outbound payload schema validation (opt-in)

The mirror image of the WR-41 inbound schema registry: a per-endpoint,
pluggable admission gate on the payload shape *after* the WR-115
transform and *before* delivery (`src/outbound-schema.ts`). A
misconfigured transform can silently drop a field the downstream
requires — without this gate, that poisoned payload burns retry budget
and backoff slots on a delivery that could never succeed:

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  outboundSchemas: {
    "https://payments.example/hook": paymentSchema, // a PayloadSchema: { name, version, validate }
  },
});
```

The `PayloadSchema` shape is shared with the inbound registry
(`{ name, version, validate }`), so one schema implementation can guard
both directions; the built-in `createRequiredFieldsSchema` from
`src/schema.ts` works unchanged.

- **Pipeline order** — validation runs on the post-transform JSON
  payload: transform (WR-115) → schema → gzip (WR-40/WR-75) → E2EE
  sealing (WR-58) → signing (WR-26). Compression and sealing produce
  non-JSON wire bytes, so the schema must precede them; `x-relay-signature`
  always covers the validated bytes — exactly what the downstream
  receives and verifies.
- **Exact-targetUrl keys** — rules are keyed by exact `targetUrl`, no
  prefix matching (the outbound config convention: WR-60
  `tlsSniOverrides`, WR-42 H2 pool keys). Endpoints without a rule keep
  byte-exact current behavior.
- **Failure is never silent** — a violation throws
  `OutboundSchemaViolationError`, classified `"non_retryable"`: the item
  dead-letters on the first attempt without burning the retry budget,
  the endpoint's circuit breaker is untouched, and the audit log gets a
  dedicated `schema_violation` event (delivery id, error, endpoint,
  schema name/version) alongside the usual `dead_letter`. A non-JSON
  payload under a configured rule fails validation (a JSON schema has
  nothing to say about opaque bytes — the WR-41 convention); a throwing
  validator is fail-closed. Invalid rules throw `RangeError` at
  startup — never mid-delivery.
- **Observability** — per-schema/per-endpoint counters render into
  `GET /metrics` as `relay_outbound_schema_total{schema,version,endpoint,status="valid"|"invalid"}`;
  the exposition renders empty until the first validated delivery, so
  `/metrics` stays byte-identical for relays that never enable the
  feature.

## AWS SigV4 outbound signing (opt-in)

Some downstreams (API Gateway with IAM auth, AWS-service webhook sinks)
require AWS Signature Version 4 instead of — or in addition to — the
relay's own `x-relay-signature` HMAC. `awsSigV4` (off by default, WR-116;
`src/sigv4.ts`, zero new dependencies) signs per endpoint:

```ts
createRelayServer({
  // ...
  awsSigV4: {
    "https://abc123.execute-api.us-east-1.amazonaws.com/prod/hook": {
      accessKeyId: "AKIA…",        // public id — safe in snapshots/audit
      secretRef: "AWS_HOOK_KEY",   // reference, never the raw secret
      region: "us-east-1",
      service: "execute-api",
      additionalSignedHeaders: ["content-type"], // optional
    },
  },
  // optional: defaults to process.env[ref]
  awsSecretResolver: (ref) => vault.read(ref),
});
```

Each delivery attempt to a configured endpoint stamps `Authorization`
(`AWS4-HMAC-SHA256 Credential=…/aws4_request, SignedHeaders=…,
Signature=…`) and `x-amz-date`, computed over the **final** wire bytes —
after transform (WR-115), compression (WR-40/WR-75) and E2EE sealing
(WR-58) — so the payload hash authenticates exactly what the downstream
receives. Signed headers are always `host` + `x-amz-date`; anything in
`additionalSignedHeaders` is read from the wire headers (an absent one
fails the attempt loudly instead of signing a lie).

- **Secret handling** — the config carries only `secretRef`; the secret
  itself is resolved per attempt through `awsSecretResolver` (default:
  the ref names an environment variable), so config snapshots, the
  operator API and audit logs can never leak plaintext key material,
  and rotation works without a restart. A missing secret fails the
  attempt as `SigV4SecretUnavailableError` (classified `non_retryable`:
  retrying a config problem burns the budget for nothing).
- **Orthogonal to WR-26** — both stamps may be enabled for one
  endpoint; SigV4 never signs `x-relay-signature`, so the two never
  order-depend. Inbound `authorization` / `x-amz-date` headers are
  stripped before stamping (relay-owned stamps always win).
- HTTP only — the WebSocket delivery path is never signed.
- Invalid configs throw `RangeError` at startup. The signer is a pure
  function (`signAwsSigV4`) cross-validated against an independent
  SigV4 implementation on GET/POST/PUT/DELETE vectors (query sorting,
  RFC 3986 path encoding, duplicate params, non-default ports).

## Outbound OAuth2 client_credentials (opt-in)

Some downstreams (a bank's API gateway, a partner's token-gated webhook
receiver) require OAuth2 bearer tokens instead of — or in addition to —
the relay's own request signatures. `oauth2` (off by default, WR-129;
`src/oauth-client.ts`, zero new dependencies) makes the relay act as the
OAuth2 client on the downstream's behalf, per endpoint:

```ts
createRelayServer({
  // ...
  oauth2: {
    "https://partner.example.com/hook": {
      token_endpoint: "https://auth.partner.example.com/oauth/token",
      client_id: "relay-client",
      client_secret: process.env.PARTNER_OAUTH_SECRET!,
      scope: "webhooks:write", // optional
    },
  },
});
```

Every delivery to a configured endpoint (http/https only) carries
`Authorization: Bearer <token>`, fetched from the token endpoint with
the RFC 6749 `client_credentials` grant (`node:https`, form-encoded
POST) and cached in memory. The cache is isolated per
`(token_endpoint, scope)` and treats tokens as expired 30s before
`expires_in` (clock-skew reserve); concurrent deliveries share one
in-flight fetch. A downstream 401 triggers exactly one forced refresh
plus redelivery inside the same attempt — the queue still sees a single
attempt, so the refresh consumes no retry budget; a second 401 follows
the normal retry / dead-letter path.

- **Secret handling** — `client_secret` lives in memory only: it is
  never logged, never audited, and `OAuth2TokenError` messages never
  carry it (only the endpoint host and status).
- **Orthogonal to WR-26/WR-124/WR-116** — HMAC, Ed25519, SigV4, and the
  bearer token may all coexist on one delivery (the downstream picks
  either or requires several). Inbound `authorization` headers are
  stripped before stamping, so a sender can never smuggle a forged
  bearer token downstream.
- Invalid configs throw `RangeError` at startup — never mid-delivery.

## W3C trace-context propagation (opt-in)

Distributed-tracing glue between the relay's own end-to-end trace IDs
(`x-trace-id`, always minted at intake) and the W3C `traceparent` /
`tracestate` headers the downstream ecosystem speaks
(`src/trace-context.ts`):

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  traceContext: {
    sampled: true, // default; the sampled flag on relay-generated traceparents
  },
});
```

- **Inbound** — a valid `traceparent` is parsed and its trace-id becomes
  the event's trace ID, so the relay's OTLP span, audit trail, and the
  downstream trace share one trace id; the sampled flag and a
  well-formed `tracestate` ride along for propagation. An invalid
  `traceparent` is ignored outright — never a 400, never a behavior
  change. A valid `traceparent` with a malformed `tracestate` still
  propagates; only the `tracestate` is dropped.
- **Outbound** — every HTTP delivery stamps `traceparent` (forced, like
  `x-trace-id`: a stale inbound value in the passthrough set is
  overridden) with a fresh child span id per attempt — each attempt is
  its own span in the downstream trace. A caller-propagated context
  keeps its trace id and sampled flag untouched and forwards
  `tracestate` verbatim; otherwise the traceparent is generated from the
  delivery's trace ID (32-hex values pass through, anything else is
  mapped with the same deterministic SHA-256 the OTLP export applies,
  so the injected trace id always equals the relay span's OTLP
  `trace_id`) with the configured `sampled` flag.
- **Span correlation** — the span id is derived deterministically from
  (trace id, 1-based attempt), so delivery events and the OTLP export
  name the exact span the wire carried: events carry it as `traceSpan`,
  and OTLP log records render `trace.trace_id` / `trace.span_id` /
  `trace.sampled` attributes (2xx and failed attempts alike — a
  `dead_letter` record points at the span of its final attempt).
- **Zero overhead when off** — unset (the default) means no inbound
  parsing, no outbound stamping, no extra allocations on the delivery
  path; the wire shape is byte-identical to before.
- **Composes** with WR-69 (the forced stamp is applied after the
  forwarding gate, like the other relay-owned headers), the WR-85
  shadow senders (mirrored requests propagate identically), and the
  durable journal (a propagated context survives restarts). Invalid
  option values throw `RangeError` at startup — never mid-delivery.

## Outbound end-to-end encryption

Deliveries to sensitive downstreams can be sealed end-to-end per endpoint
(opt-in), so the payload is opaque to everything between the relay and the
downstream — including TLS-terminating proxies:

```ts
import { generateX25519KeyPair } from "./src/e2ee.ts";

// once, on the downstream's side — the private half never leaves it
const downstream = generateX25519KeyPair();

const server = createRelayServer({
  secret, forwardUrl, auditLog,
  outboundEncryption: {
    "https://downstream/hook": { publicKey: downstream.publicKey }, // base64 X25519
  },
});
```

- **Seal** — per delivery, the sender mints a fresh ephemeral X25519
  keypair, runs ECDH against the downstream's public key, expands the
  shared secret with HKDF-SHA256 into an AES-256-GCM content key, and
  seals the (possibly gzipped) wire body under a fresh random IV. The
  sealed body is a JSON envelope stamped with
  `x-relay-encryption: x25519-hkdf-sha256/aes-256-gcm`; the downstream
  opens it with its private key via `unsealOutboundPayload()` (same
  module). `node:crypto` only — zero dependencies.
- **Order** — sealing happens *after* compression (the envelope records
  the pre-seal `content-encoding`, so the HTTP `content-encoding` header
  is dropped — the wire bytes are the envelope, not the gzip stream) and
  *before* signing, so `x-relay-signature` (WR-26) covers the ciphertext
  wire bytes: authenticity from the relay, secrecy for the downstream,
  orthogonal as designed.
- **Fail-fast** — an invalid configured key (bad base64, wrong length,
  not an X25519 point) throws `RangeError` at startup, never
  mid-delivery; endpoints without a key are sent exactly as before.
- **Tamper-evident** — the AES-GCM auth tag makes any modification (or a
  wrong private key) fail `unsealOutboundPayload` loudly; it never
  returns garbage silently.
- **Key rotation (WR-81)** — when the downstream rotates its keypair, the
  endpoint config carries `keyId` plus the retired keys
  (`previousKeys`, newest first):
  ```ts
  outboundEncryption: {
    "https://downstream/hook": {
      publicKey: newKeypair.publicKey,
      keyId: "k-2026-10",
      previousKeys: [{ id: "k-2026-09", publicKey: oldKeypair.publicKey }],
      // graceMs: 86_400_000, // default 24h, same as WR-20
    },
  },
  ```
  The primary key seals every new delivery and its id is stamped as the
  envelope `kid`, so the downstream picks the right private key
  directly; on the wire the downstream opens kid envelopes with that
  single key (unknown `kid` throws — no silent fallback) and tries
  kid-less legacy envelopes newest-first (`unsealOutboundPayloadWithKeys`).
  Retired keys stay in-rotation inside `graceMs` (default 24h, same as
  WR-20 signing rotation); picking up a rotation emits one
  `e2ee_key_rotated` audit event per endpoint (primary kid, retired kids,
  grace window). Invalid configs throw `RangeError` at startup.

### E2EE key rotation

Downstreams rotate their keys the same way signing keys do (WR-20):
several X25519 public keys coexist per endpoint, one primary seals new
deliveries, and the retired key stays usable for decryption inside a
grace window (default 24h, configurable):

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  outboundEncryption: {
    "https://downstream/hook": {
      publicKey: newKey.publicKey,  // base64 X25519 — seals new deliveries
      keyId: "k-2026-10",          // stamped as the envelope `kid`
      previousKeys: [
        { id: "k-2026-09", publicKey: oldKey.publicKey }, // retiredAtMs defaults to now
      ],
      graceMs: 86_400_000,          // optional; 24h default, same as WR-20
    },
  },
});
```

- **Seal with the newest** — `RotatingE2eeSealer` (in `src/e2ee.ts`,
  mirroring `RotatingHmacVerifier`) seals with the current key and
  stamps its id as the envelope `kid`, so the downstream picks the
  right private key directly. Plain `{ publicKey }` endpoints keep the
  WR-58 behavior byte-for-byte: no `kid`, no rotation bookkeeping.
- **Grace window, inclusive** — a retired key counts as in-rotation for
  `graceMs` after `retiredAtMs`, boundary *inclusive* (exactly
  `graceMs` old is still in), same as WR-20. While any retired key is
  inside its window the rotation reports `rotationInProgress`, surfaced
  in the startup audit.
- **Downstream opening** — `unsealOutboundPayloadWithKeys(bytes,
  keyRing)`: an envelope carrying `kid` opens with that kid's key
  *only* — an unknown `kid` throws, with no fallback to other keys (a
  silent fallback would let a mis-provisioned downstream decrypt with
  the wrong key and never notice). A pre-rotation envelope without
  `kid` tries the ring newest-first, the first key that opens wins.
- **Audited** — every configured rotation emits one `e2ee_key_rotated`
  audit event at startup (`targetUrl`, `primaryKeyId`,
  `previousKeyIds`, `graceMs`, `rotationInProgress`), so a rotation is
  a visible operator action, not a silent config change.
- **Fail-fast** — the full key set is parsed and validated at
  construction; an invalid key, duplicate id, missing `keyId`, a
  retired primary, or a negative `graceMs` throws `RangeError` at
  startup, never mid-delivery. Only the relay-visible rule changes are
  in the relay — the downstream holds its own private keys, and the
  relay never sees them.

## OTLP event export (opt-in)

Delivery lifecycle events can be exported to an OTLP collector as logs
JSON over HTTP (`Content-Type: application/json`), for operators who
already run OpenTelemetry infrastructure:

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  otlp: {
    endpoint: "http://collector:4318/v1/logs", // full collector URL; required
    sampleRate: 1.0,      // default 1.0 = export everything
    maxBuffered: 1000,    // default 1000; local buffer bound
    serviceName: "webhook-relay-ts", // default; service.name attribute
  },
});
```

- **What is exported** — the `delivered` / `retrying` / `dead_letter`
  delivery events, `slo_missed` latency events, and `rate_limited`
  per-tenant rate-limit decisions (WR-97). Each becomes one
  OTLP log record: `severityNumber` 9 (`INFO`), 13 (`WARN`) for
  `dead_letter`; `traceId` is the delivery's trace ID (32-hex values pass
  through, client-supplied IDs are mapped through SHA-256 to a valid
  32-hex OTLP trace ID); attributes carry `relay.event_id`,
  `relay.event_type`, `relay.endpoint`, `relay.attempts`, `relay.error`
  (failures), `relay.tenant` (multi-tenant only),
  `relay.slo_ms` / `relay.latency_ms` (SLO misses),
  `relay.retry_after_ms` (rate-limit decisions), and — when W3C
  trace-context propagation is enabled — `trace.trace_id` /
  `trace.span_id` / `trace.sampled`, naming the exact downstream span
  the attempt stamped on the wire (see "W3C trace-context propagation").
- **Never disturbs delivery** — export is off by default; when enabled,
  `record()` is synchronous buffer work that never throws, the flush
  runs on an unref'd background timer, and a hung collector cannot pin
  shutdown (a best-effort flush races a 1s timeout). Failed exports stay
  in a bounded in-memory buffer (drop-oldest past `maxBuffered`,
  counted in `getOtlpStats().dropped`) and are retried with capped
  exponential backoff.
- **Fail-fast** — a bad endpoint URL, a `sampleRate` outside [0, 1], or a
  `maxBuffered` below 1 throws `RangeError` at construction.
- **Observability** — `queue.getOtlpStats()` returns
  `{ enabled, buffered, dropped, exported, lastError? }`; `GET /metrics`
  adds `relay_otlp_exports_total{event_type,status}` and
  `relay_otlp_buffered` only when OTLP export is enabled.

## Audit event webhook sink (opt-in)

The audit log can stream itself to an external webhook as signed JSON
(`src/audit-sink.ts`, the LG-67 convention from ledger-api-go), for
operators who want every `accepted` / `delivered` / `dead_letter` /
`rejected` / operator action in their own SIEM without polling
`GET /audit`:

```ts
const server = createRelayServer({
  secret, forwardUrl, auditLog,
  auditSink: {
    url: "https://siem.example.com/relay-audit", // required
    secret: "shared-hmac-secret",                 // required; signs every delivery
    tenantSinks: {                               // optional per-tenant URLs (WR-48)
      acme: { url: "https://acme.example.com/audit", secret: "acme-key" },
    },
    maxAttempts: 10,        // default 10; backoff 1s doubling to 60s
    pollIntervalMs: 1000,   // default 1000
    httpTimeoutMs: 10000,   // default 10000
  },
});
```

- **Signed** — every delivery carries
  `x-relay-audit-signature: sha256=<hex>` (HMAC-SHA256 over the exact
  log line, the WR-26 convention) plus `x-relay-audit-event` (the audit
  event name) and `x-relay-audit-tenant` (tenant-scoped events only).
  The body is the exact JSONL audit line — hash-chain fields included —
  so the downstream can verify authenticity and chain continuity.
  Sealed (WR-11) payloads stay sealed in transit; the sink never
  decrypts. An empty secret fails fast at startup: unsigned webhooks can
  be forged.
- **Never disturbs delivery** — off by default; when enabled, a
  background worker tails the log file on unref'd timers, so a slow or
  dead sink only delays the cursor, never a webhook. It stops with the
  server.
- **At-least-once, in order** — an event is delivered (HTTP 2xx), then
  the byte-offset cursor advances (atomic tmp+rename, survives
  restarts). A stop mid-retry abandons the event without dead-lettering,
  so the next start redelivers it. The first start begins at the current
  log tail: history is not replayed. Head-of-line blocking is honest:
  one poison URL delays every event behind it until it dead-letters.
- **Dead letters** — an event that exhausts `maxAttempts` is recorded
  as `audit_sink_dead_letter` in the audit log (event name, attempts,
  last status/error, tenant, sink URL) and skipped. Dead-letter lines
  are never re-forwarded. Alert on `sink.stats().deadLetters`.
- **Observability** — `sink.stats()` returns
  `{ sent, failedAttempts, deadLetters }`; `sink.cursorOffset()` is the
  last forwarded byte offset.
- **Fail-fast** — a bad URL, empty secret, `maxAttempts < 1`, negative
  durations, or a bad tenant id throws `RangeError` at construction.

Do not point the sink at this relay's own intake: forwarded events
carry no valid webhook signature, each rejection audits a new line, and
the sink would chase its own tail.

## In-flight request coalescing (opt-in)

When a burst of deliveries carries the identical logical request — same
tenant, same physical `targetUrl`, same payload bytes — and their
attempts overlap in time, the relay sends **one** physical request
instead of N (`src/coalesce.ts`). The first delivery's attempt is the
*leader*; the rest *attach* to it and settle with its outcome (response
or error). This is the retry-storm case: a fan-out retry wave or a
replayed dead-letter batch must not bombard the downstream N times for
one logical request.

```ts
const queue = new RetryQueue({
  sender,
  coalesce: true,                    // or { maxFollowers: 512 }
});
```

- **Independent books** — every member still runs its own delivery
  bookkeeping: its own audit events, its own `relay_deliveries_total`
  counter, its own accepted→delivered latency sample, its own attempt
  counter and retry schedule. The downstream is hit once; the relay's
  books still show N deliveries.
- **Honest control plane** — the circuit breaker, failover / weighted
  routing, and adaptive backoff are recorded **once per physical
  attempt, by the leader**. N followers recording the same failure would
  trip the circuit N× faster than the downstream actually failed. A
  follower that was granted a half-open probe permit releases it via
  `cancelProbe` the moment it learns it is a follower (the breaker's
  settle-exactly-once contract).
- **Cancellation isolation** — the physical attempt is owned by the
  coalescer, never by a member. A delivery that never reaches the sender
  never joins; a joined member always rides the attempt to settlement.
  Cancelling one delivery cannot cancel or poison the merged attempt for
  the others.
- **Tenant boundary** — the coalescing key includes the tenant id, so
  one tenant's deliveries never ride another tenant's attempt (the WR-48
  isolation invariant; breaker attribution stays inside the tenant).
- **Bounded** — `maxFollowers` (default `Infinity`) caps how many
  deliveries may ride one attempt; overflow starts its own physical
  attempt instead of joining. Never drops, never waits.
- **Combinations** — coalescing wraps the fully composed sender, so the
  merged attempt is the one that checks out a WR-24 keep-alive pooled
  connection (N logical deliveries, one socket); the WR-21 pin check runs
  on the physical attempt's TLS handshake before any payload byte, so
  followers' bytes only ever travel over a pin-verified socket.
- **Observability** — `queue.getCoalesceStats()` returns
  `{ physicalAttempts, mergedDeliveries, inFlightKeys }`
  (`undefined` when disabled).
- **Fail-fast** — an invalid `maxFollowers` throws `RangeError` at
  construction. Disabled by default: `coalesce: false` (or absent) keeps
  one physical attempt per delivery, exactly the pre-WR-91 behavior.

## Per-endpoint ordered delivery (opt-in)

Some downstreams cannot tolerate reordering — a ledger that applies
credits before debits, a cache invalidator racing its own refill. When
`retry: { ordered }` is enabled for an endpoint, its deliveries leave
the relay **in receive order**: the head of the line must reach a
terminal state (`delivered` / `dead_letter`) before the next item
dispatches. A head that is retrying, backing off, or parked behind the
circuit breaker / quota / rate limiter holds every follower behind it —
followers held this way consume **no** attempt, no retry-budget token,
no quota token, and no circuit verdict.

```ts
const queue = new RetryQueue({
  sender,
  ordered: true, // every endpoint, strict head-of-line
  // or per endpoint (exact targetUrl, like tlsPins/responseValidators):
  // ordered: { "https://ledger.example/hook": { maxHeadOfLineHoldMs: 30_000 } },
});
```

- **Forms** — `true` orders every endpoint; an `OrderedModeOptions`
  object (`{ enabled?, maxHeadOfLineHoldMs?, now? }`) tunes every
  endpoint; a record maps exact `targetUrl` → `boolean |
  OrderedModeOptions` so only the endpoints that need ordering pay for
  it. Absent = unordered, exactly the pre-WR-113 behavior.
- **Poison-message policy** — a head that never settles would wedge the
  line forever, so `maxHeadOfLineHoldMs` bounds the hold: past the
  bound the head is parked into the dead-letter list (failure class
  `"head_of_line_timeout"`, audited as `head_of_line_parked`) and the
  line advances. It is **never silently dropped** — the entry keeps its
  honest attempt count, rides the normal dead-letter machinery
  (retention sweep, replay), and no circuit verdict is recorded (the
  endpoint was never attempted on that dispatch). Default:
  **`Infinity`** — the head is held until it settles and ordering is
  never broken by a timer. The default is deliberate: a feature whose
  contract is "in order" must not dead-letter a never-attempted head on
  a clock unless the operator explicitly opts into the bound.
- **Urgent bypass** — the urgent lane (WR-12) skips the ordered gate by
  default: low-latency semantics win over ordering. Every bypass is
  audited as `ordered_bypassed` (with the delivery's trace id), so the
  ordering gap is visible, never silent. A later urgent→normal
  degradation (empty token bucket) does not re-enter the line — the
  bypass verdict is made at the gate.
- **Batching** — a flushed batch (WR-17) is one `RetryItem`, so the
  ordered gate applies at item level; the batch takes its line position
  at flush time (the batching delay precedes ordering, by design).
  Urgent items skip batching as before.
- **Replays** — a dead-letter replay starts a fresh delivery cycle, so
  it takes the **tail** of the ordered line, not its original position.

**Combination matrix** — the ordered gate is the **first** gate in
`deliver()`, ahead of the deadline, pause, delivery-window, quota, rate
limit, circuit, lane-scheduler, and concurrency gates. Rationale: the
hold is about line position, not about *why* the head is waiting — a
head parked by an open circuit or an empty quota bucket holds its
followers with identical semantics, and a held follower must not touch
anything a later gate would consume. Consequences:

| Feature | Ordered interaction |
|---|---|
| Retry budget (WR-38) | Only the head's retries consume budget; held followers never burn it. |
| Circuit breaker | Head parked by an open circuit still holds followers; no verdict is recorded for held items. |
| Quota / tenant rate limit (WR-97) | Same: a quota-throttled head holds the line; held items consume no tokens. |
| Concurrency (WR-06/51/94) | Held followers take no limiter slots; the head's in-flight attempt holds the line. |
| Urgent lane (WR-12) | Bypasses by default, audited per bypass (`ordered_bypassed`). |
| Batch (WR-17) | Item-level ordering; line position taken at flush. |
| Delivery deadline (WR-76) | A follower's deadline is evaluated when it becomes head — never while held. |
| Pause (WR-50) / delivery window (WR-52) | The gate runs first; a paused head still holds the line, and resume wakes the head, whose settlement wakes the next. |
| Failover (WR-39) / weighted (WR-66) | The gate keys on the logical endpoint, before target resolution. |
| Coalescing (WR-91) | Only head attempts (and urgent bypasses) reach the coalescer. |

**Latency / SLO accounting** — head-of-line waiting is inside the
accepted→delivered clock (WR-13): the latency tracker starts at
`enqueue()`, so a follower's sample includes the full time it waited
behind the head, and it counts toward `sloMs` attainment like any other
queue wait. Poison-parked heads are dead letters and are discarded
without sampling, exactly like every other dead letter. The SLO-risk
predictor (WR-71) sees held followers as ordinary pending backlog.

**Observability** — `queue.getOrderedStats()` returns per-endpoint
`{ queued, headId, headBlockedCount, headOfLineParked, urgentBypassed }`
(empty when disabled); Prometheus exposes
`relay_ordered_head_blocked_total{endpoint}`,
`relay_ordered_head_of_line_parked_total{endpoint}`, and
`relay_ordered_urgent_bypassed_total{endpoint}` — activity-gated, so a
relay with the feature off exposes no `relay_ordered_*` series at all.
`onOrderedAudit` (audited by the server as `ordered_bypassed` /
`head_of_line_parked`) is the per-event channel; `getOrderedStats` is
the per-endpoint channel.

**Fail-fast** — an illegal `ordered` value (bad shape, non-positive
`maxHeadOfLineHoldMs`, …) throws `RangeError` at construction.

## Outbound DNS resolution cache (opt-in)

Every new connection pays a DNS lookup, and under high fan-out to a
small set of downstreams that lookup is pure overhead — worse, a
resolver hiccup can fail deliveries for a reason that has nothing to do
with the downstream. The cache sits between the relay and the resolver
(`src/dns-cache.ts`, `node:dns` only): per-hostname entries with a
configurable TTL (default 60s), served stale-while-revalidate so an
expired entry keeps working while a background refresh runs.

```ts
const server = createRelayServer({
  dnsCache: { ttlMs: 30_000 },   // or a compiled `new DnsCache({...})`
});
```

- **Stale-while-revalidate** — an expired entry is still served while
  exactly one background refresh runs (single-flight: concurrent
  expired lookups trigger one refresh, never N). A refresh that fails —
  or resolves empty — never evicts the stale entry; the relay keeps
  serving it and counts `staleServed` / `refreshFailures`. A DNS error
  reaches the delivery only when the cache holds *no* entry at all, in
  which case it follows the normal retry / dead-letter path.
- **Bounded** — `maxHosts` (default 1024); when full, the soonest-expiring
  entry is evicted. `ttlMs` / `refreshBackoffMs` (backoff between failed
  refreshes during a resolver outage, default 5s) validate fail-fast.
- **Combinations** — the shared instance feeds the WR-24 keep-alive
  pool (pooled agents resolve through it; the pool key stays the logical
  `(scheme, host, port)` while sockets are built against the resolved
  IP), one-off (unpooled) requests, and the WR-34 downstream probes
  (`probe.lookup`). The opt-in HTTP/2 pool and the WebSocket pool manage
  their own connections and keep the OS resolver — the DNS cache covers
  the HTTP/1.1 path and the probes only. One counter set is shared by
  the main and shadow senders.
- **Observability** — `GET /metrics` renders `relay_dns_cache_*`
  (`lookups_total{result="hit"|"miss"|"stale"}`,
  `refresh_failures_total`, `hosts` gauge), and
  `sender.dnsCache.getStats()` exposes `hits/misses/staleServed` plus the
  `hitRate` (share of lookups that avoided a synchronous resolution).
- **Fail-fast** — invalid `ttlMs` / `refreshBackoffMs` / `maxHosts`
  throw `RangeError` at startup. Absent by default: with no `dnsCache`
  configured, every connection uses the OS resolver.

## Outbound TLS OCSP revocation checking (opt-in)

TLS certificate pinning (`tlsPins`) answers "is this the server I
expect?" — it stops a compromised CA or a MITM holding a
valid-but-unexpected certificate. It does not answer "has this
certificate been *revoked* since it was issued?" A pinned certificate
can still be revoked (key compromise discovered after issuance), and a
CA-valid certificate the relay never pinned can be revoked hours before
anyone renews it. OCSP (`src/ocsp.ts`) covers that orthogonal risk:
after the handshake, the relay asks the certificate's OCSP responder
(RFC 6960) for a freshness verdict and refuses to deliver to a revoked
peer.

```ts
const server = createRelayServer({
  tlsPins: { "https://payments.example.com/hook": ["sha256/<base64>"] },
  tlsOcsp: {
    "https://payments.example.com/hook": {
      mode: "fail-closed",   // default "fail-open"; pinned endpoints should fail closed
      // useStapled: true,   // default: prefer the server's stapled response
      // responderUrl: "https://ocsp.example.com/",  // default: the leaf's AIA extension
    },
  },
});
```

- **Stapled first, responder fallback** — the handshake requests a
  stapled OCSP response (`requestOCSP: true`); when the server staples
  one, it is evaluated with zero extra round-trips. Otherwise the relay
  POSTs a DER OCSPRequest to `responderUrl` (or the leaf certificate's
  Authority Information Access extension) via the pluggable
  `responderFetcher` — the default is a plain `node:https` POST with a
  3s timeout (`responderTimeoutMs`, 100ms–30s); tests inject a stub and
  never touch a real responder. Set `useStapled: false` for
  responder-only checking.
- **Revoked means rejected, before any payload byte** — a `revoked`
  verdict destroys the request with `OcspRevokedError` on the TLS layer,
  *before* a single payload byte is written (the pinning precedent: the
  revoked peer never observes the body). The attempt follows the normal
  retry / dead-letter path, an `ocsp_revoked` audit event fires
  (endpoint, serial, revocation time, mode, source), the alert hook
  fires, and `relay_ocsp_total{endpoint,status="revoked"}` counts it.
- **fail-open / fail-closed governs the *unknown*, not the revoked** —
  when the revocation *status* cannot be determined (no stapled
  response, no/failing responder, malformed response, responder answers
  `unknown`), `"fail-open"` (default) lets the delivery proceed after
  firing the `ocsp_alert` alert, while `"fail-closed"` fails the attempt
  with `OcspError`. **Guidance:** pinned endpoints should use
  `"fail-closed"` — a pin already says "I know exactly which key to
  expect", so failing closed on revocation-telemetry loss is the
  consistent posture; unpinned endpoints typically stay `"fail-open"`
  so a dead OCSP responder cannot take down deliveries.
- **Orthogonal to pinning, honest with the breaker** — the pin check
  runs first (identity), OCSP runs on the pinned or PKI-verified peer
  (freshness). An OCSP *query* failure explicitly does **not** count as
  a circuit-breaker failure — an unreachable responder is a local
  telemetry outage, not a sick endpoint — while a revoked certificate
  counts normally (the endpoint is serving a dead credential).
- **Keep-alive semantics** — the check runs on session establishment:
  OCSP endpoints get their own pool agents (`|ocsp`) with stapling
  requested and TLS session resumption disabled (a resumed TLS 1.3
  handshake re-sends no certificate, so there would be nothing to
  check), and a pooled socket already verified for an endpoint is not
  re-checked while it stays pooled. Only the HTTP/1.1 path is gated in
  this round: an OCSP-configured endpoint is kept off the opt-in HTTP/2
  path rather than silently skipping the check, and `wss:` targets are
  not covered (the WebSocket pool owns its own handshake).
- **Observability** — `GET /metrics` renders
  `relay_ocsp_total{endpoint,status}` (`good` / `revoked` / `unknown` /
  `error`); revocations audit as `ocsp_revoked` and revocations plus
  fail-open continuations audit as `ocsp_alert`.
- **Fail-fast** — a bad `mode`, non-boolean `useStapled`, non-http(s)
  `responderUrl`, non-function `responderFetcher`, or out-of-range
  `responderTimeoutMs` throws `RangeError` at startup. Off by default:
  endpoints without an entry behave exactly as before, and no
  `relay_ocsp_*` series appears until the first check runs.

## Inbound mTLS (opt-in)

Outbound mTLS (`tlsClientCerts`) proves the *relay's* identity to a
downstream; inbound mTLS proves the *caller's* identity to the relay.
`createRelayServer({ inboundMtls })` (`src/inbound-mtls.ts`) turns the
relay's listeners into client-certificate gates:

```ts
createRelayServer({
  // ... secret, forwardUrl, auditLog ...
  inboundMtls: {
    key: SERVER_KEY_PEM,      // relay's own TLS identity (PEM strings,
    cert: SERVER_CERT_PEM,     // in memory — no file paths)
    ca: CLIENT_CA_PEM,         // client CA chain (string or string[])
    requireCert: true,         // default: every route needs a cert
    clientFingerprints: ["sha256/<base64>", /* … */], // optional whitelist
    operatorMtls: false,       // default: operator routes follow requireCert
  },
});
```

- **Request-time enforcement, not handshake aborts** — the listeners run
  Node `https` with `requestCert: true` and `rejectUnauthorized: false`,
  so the handshake *requests* a certificate but never aborts on a
  missing/invalid one. A missing certificate is answered **401**
  (`reason: "client_cert_required"`); a certificate whose chain does not
  verify against `ca`, or whose fingerprint is not whitelisted, is
  answered **401** (`reason: "client_cert_invalid"`). Both are audited as
  `rejected` like the other intake gates (a presented certificate's
  fingerprint/subject ride along), and both close the connection — the
  caller must re-handshake with a different certificate anyway.
- **Identity on the audit trail** — a verified caller's
  `clientCertFingerprint` (base64 SHA-256 of the DER certificate) and
  `clientCertSubject` (e.g. `CN=relay-client`) are recorded on the
  `accepted` / `rejected` audit events.
- **Operator routes can require mTLS independently** —
  `requireCert: false` + `operatorMtls: true` locks down `/dead-letter`,
  `/metrics`, `/events`, … while webhook ingest stays open without a
  certificate. With a split operator plane (`operatorPort`) the operator
  listener alone becomes HTTPS and the intake plane stays plain HTTP;
  on the legacy single plane the shared listener becomes HTTPS but
  ingest routes still accept cert-less requests.
- **Hot-reload** — `server.updateInboundMtlsConfig(patch)` swaps the CA
  chain, server key/cert, fingerprint whitelist, and the
  `requireCert` / `operatorMtls` policy at runtime (validated before
  apply; illegal patches throw `RangeError` and leave the live config
  untouched; changes audit as `inbound_mtls_config_updated` with field
  names only — key material never lands in the audit trail). Two honest
  limitations: TLS material is pushed via `setSecureContext()`, so it
  takes effect on *new* handshakes only (established keep-alive
  connections keep the previous context until they reconnect), and
  *enabling/disabling* inbound mTLS needs a restart — a bound listener
  cannot change between plain HTTP and HTTPS at runtime.
- **Fail-fast** — empty/garbage `key`/`cert`/`ca` PEM, a key/cert
  mismatch, a non-boolean `requireCert`/`operatorMtls`, or a malformed
  (or empty) `clientFingerprints` whitelist throws `RangeError` at
  startup. Off by default: unset means plain-HTTP listeners and zero
  behavior change. Zero dependencies (`node:crypto` + `node:tls`).

## Sender reputation (opt-in)

Not every sender deserves the same trust. `createRelayServer({
senderReputation })` (`src/reputation.ts`) scores each inbound sender —
keyed by the WR-65 API key id, or `"anonymous"` when no key guards the
endpoint — on their historical behavior:

```ts
createRelayServer({
  // ... secret, forwardUrl, auditLog ...
  senderReputation: {
    halfLifeMs: 600_000,        // demerit half-life: 10 min of quiet halves it
    lowThreshold: 40,           // score < 40 -> downgraded (tightened)
    highThreshold: 70,          // score > 70 -> upgraded back (relaxed)
    verifyFailurePenalty: 25,   // per signature verification failure
    rateLimitPenalty: 5,        // per inbound rate-limit hit
    schemaViolationPenalty: 10, // per inbound schema validation failure
  },
});
```

- **Weighted penalties, exponential recovery** — the three intake
  failure kinds above accumulate weighted demerit against the sender;
  the score is `100 - demerit`, clamped to `[0, 100]` (100 = pristine).
  The demerit decays exponentially with `halfLifeMs`, so a sender that
  stops misbehaving recovers on its own — no manual intervention, and
  no "good behavior" events to game: silence is what heals.
- **Hysteresis, not flapping** — the score must fall *strictly below*
  `lowThreshold` to downgrade and climb *strictly above*
  `highThreshold` to upgrade, so a sender oscillating around one line
  cannot flap between states.
- **Automatic tightening while degraded** — a downgraded sender gets
  (a) a halved per-sender rate-limit budget on top of the configured
  inbound limiter (no limiter configured = this tightening is a
  documented no-op), (b) forced signature verification even where the
  API key alone would authenticate (the same as `requireSignature: true`
  on the rule; only meaningful where a verifier is configured — the
  relay always configures one, the default HMAC verifier over `secret`,
  so the forced check always takes effect), and (c) a doubled dedup
  window (only when dedup itself is configured; the widened window is
  in-memory and never shares the base window's journal).
- **Observable** — crossings audit as `reputation_downgraded` /
  `reputation_upgraded` (key id + score only, never a secret), and the
  operator `/metrics` exposes `relay_sender_reputation_score{key}` (gauge)
  plus `relay_sender_reputation_degraded_total{key}` (counter of
  downgrade transitions, only for senders that actually downgraded).
- **Fail-fast** — a non-positive `halfLifeMs`, thresholds outside
  `[0, 100]`, a missing `low < high` gap, or negative penalties throw
  `RangeError` at startup. Off by default: unset means zero behavior
  change. Zero dependencies.

## Delivery lifecycle

Every accepted webhook walks the same state machine; each transition is
written to the audit log, so the log is the machine's trace.

**Inbound (receiver side):**

- `received` → the raw body is read and the `x-signature` header is checked.
- `received` → **`rejected`** (`invalid_signature`, HTTP 401) when
  verification fails. The payload is never forwarded.
- `received` → **`rejected`** (`duplicate_nonce` → HTTP 409, or
  `missing_nonce` / `expired_timestamp` / `future_timestamp` → HTTP 400)
  when replay protection is enabled and the guard says no.
- `received` → **`duplicate_suppressed`** (HTTP 202 with `duplicate: true`)
  when idempotent dedup is enabled and the `(endpoint, payload-hash)` pair
  was already accepted inside the window. The event is acknowledged, not
  delivered — upstream treats it as handled, so a retried payment callback
  cannot charge twice.
- `received` → **`accepted`** (HTTP 202) when the webhook verifies. The item
  is enqueued for delivery.

**Outbound (delivery side):**

- `accepted` → **`delivering`**: the first attempt starts (a delivery may
  park briefly on a per-endpoint concurrency slot first — still
  `delivering`, just waiting its turn). When the per-endpoint delivery
  quota is enabled and the endpoint's budget is exhausted, the attempt
  waits for the next token refill instead of sending — still `delivering`,
  never dropped, never counted against the retry budget. When the inbound
  request carried `x-priority: urgent`, the item takes the **fast lane**
  instead: it starts immediately without queueing for a concurrency slot,
  and its retries use a fixed delay rather than the exponential backoff
  below; an empty urgent token bucket degrades it back to this normal path
  (still `delivering`, never dropped).
- `delivering` → **`delivered`** when the downstream answers 2xx. Done —
  audited with the total attempt count and a `response_summary` (see
  *Downstream response summary* below). When latency tracking is enabled
  (`retry.latency`), the accepted→delivered delay is sampled into the
  endpoint's distribution, and a delivery slower than `sloMs` is additionally
  audited as `slo_missed` with the measured `latencyMs`; when phase
  tracking is also enabled (`retry.latencyPhases`), the miss is attributed
  to the dominant latency phase (`dominantPhase` + `phaseBreakdown`, see
  *Delivery-latency phase breakdown* above).
- `delivering` → **`retrying`** when the attempt fails (non-2xx, timeout,
  or connection error). The next attempt is scheduled after
  `baseDelayMs * 2^attempt` plus jitter, capped at `maxDelayMs`, then the
  item goes back to `delivering`. With the opt-in adaptive backoff
  (`retry.adaptiveBackoff`), the *base* itself adapts per endpoint:
  consecutive retryable failures double it toward `maxBaseMs` (a sick
  downstream is retried progressively less often), successes halve it
  back toward `minBaseMs` (recovery is quick); the current base per
  endpoint is exposed via `queue.getAdaptiveBackoffStats()`. When the circuit breaker is enabled and
  the endpoint's circuit is open, the attempt is *parked* instead: it is
  rescheduled after the remaining cooldown without consuming the retry
  budget (still `delivering`, audited via `circuit_open` on the trip).
- `delivering` → **`dead_letter`** when `maxAttempts` is exhausted. The
  entry keeps `attempts`, `lastError`, and `deadLetteredAt` — everything an
  operator needs to diagnose it, without the raw payload on the operator
  endpoint. With `payloadEncryptor` configured the payload is additionally
  sealed at rest (`encryptedPayload` envelope) and transparently decrypted
  on replay. Every dead-letter entry also carries `failure_class` (also
  audited on the `dead_letter` event): `"retryable"` means every attempt was
  spent against a transient failure, `"non_retryable"` means the payload was
  poison and was dead-lettered on the first attempt without burning the
  retry budget (see *Failure classification* below), and
  `"assertion_failed"` means the downstream answered inside the
  endpoint's status whitelist but the response body failed the
  endpoint's declarative response assertions (see *Per-endpoint response
  assertions* below) — handled exactly like `"retryable"`. The `dead_letter` audit
  event also carries a `response_summary` with the last attempt's HTTP
  status code (the only thing a failed attempt can honestly report — see
  *Downstream response summary* below).
- `dead_letter` → **`delivering`** (fresh attempt budget) when an operator
  replays it via `POST /dead-letter/:id/replay`, audited as
  `dead_letter_replayed`. A replayed item that fails again walks the same
  `delivering` → `retrying` → `dead_letter` path. The opt-in
  auto-replay scheduler (see *Dead-letter auto-replay* below) replays the
  whole list on a timer with identical fresh-budget semantics.

### Downstream response summary

Every terminal delivery audits a compact, privacy-safe sketch of what the
downstream answered — `src/response-summary.ts`, no new dependencies:

```jsonc
// on `delivered` / `dead_letter` audit events, as `response_summary`
{
  "statusCode": 200,                 // number, or "unavailable"
  "responseBytes": 128,              // captured body length, or "unavailable"
  "timeToFirstByteMs": 42,           // request-issued → first response bytes, or "unavailable"
  "bodyFingerprintSha256": "2cf2…"   // sha256 hex of the first 256 body bytes; omitted when empty
}
```

- `timeToFirstByteMs` is measured by the default sender (request issued →
  the `'response'` event) — a 首响应头到达耗时 (first-response-header
  arrival) approximation covering connection setup + request write +
  server think time, not kernel-to-user dispatch. Custom senders that
  return `void`, and the WebSocket/H2 paths, leave it unset.
- Any value that was not measured is the string `"unavailable"` — never a
  fabricated 0 or -1. A custom sender returning `void` yields an
  all-`"unavailable"` summary; a dead letter reports only the last
  attempt's status code (duck-typed off the error, e.g. `HttpDeliveryError`),
  since a failed attempt has no usable body or TTFB.
- By default the summary never includes the response body — downstream
  payloads can carry tokens and PII, and the audit log is not their home.
  Opt in per queue with `new RetryQueue({ responseBodyCapture: true,
  payloadEncryptor })`: the full captured body is sealed with the WR-11
  encryptor and stored as `response_summary.capturedBody` (an
  `EncryptedPayload` envelope) on every `delivered` audit event.
  Enabling capture **without** a `payloadEncryptor` throws `RangeError`
  at construction — fail-fast, so a body can never be logged in the clear
  by misconfiguration. Dead-letter events never carry a body.

### Completion callbacks

`GET /deliveries/:traceId` is the *passive* way to learn a delivery's
outcome; completion callbacks are the *active* one. When
`completionCallback` is set (off by default), every terminal transition —
`delivering` → `delivered` and `delivering` → `dead_letter` — also POSTs a
signed receipt to the caller's URL:

```json
{
  "id": "evt-1",
  "traceId": "…",
  "targetUrl": "https://downstream.example/hook",
  "terminalState": "delivered",
  "attempts": 3,
  "at": "2026-10-10T10:00:00.000Z",
  "error": "downstream exploded"
}
```

(`error` only appears on `dead_letter`.) The receipt carries the same
trust headers as a normal delivery: `x-trace-id` (the delivery's
end-to-end trace ID), `x-relay-signature: sha256=<hex>` (HMAC-SHA256 of the
receipt body under `signingSecret`, so the caller can verify the receipt
really came from this relay), `x-relay-key-id` (when `keyId` is set), and
`x-relay-idempotency-key` derived from (delivery id, callback attempt)
under `idempotencySecret` (WR-44 derivation, so the caller's deduplicator
collapses retried receipts).

A receipt that fails to land is retried with a short backoff — at most
`maxAttempts` times (default 3, capped at 3) — then reported once via the
`onCompletionCallbackFailed` hook and audited as `callback_failed`.
Receipts never enter the retry queue or the dead-letter list: a failing
callback cannot recurse into the delivery machinery.

**Loop protection.** A callback URL that resolves to this relay's own
inbound listener would re-enter intake on every terminal delivery and
ping-pong forever. The target is checked twice: at configuration time
against declared `selfOrigins` (a match throws `RangeError` at startup),
and again before every POST against the actually bound address (so even an
undeclared self-target is refused). A refused target fails fast and is
audited as `callback_failed` — it is never POSTed.

### Dead-letter storm escalation

Completion callbacks (above) are *per-delivery* receipts to the *caller's*
URL — one signed POST per terminal delivery. Dead-letter storm escalation
is the *aggregate* counterpart: it notifies the *operator's* URL once per
storm, so an operator drowning in per-delivery `dead_letter` receipts gets
one alert instead of a thousand.

When `deadLetterEscalation` is set (off by default), the relay watches the
dead-letter count per (tenant, endpoint) inside a sliding window
(`windowMs`, default 10 minutes). The first crossing of `threshold`
(default 20) dispatches one signed JSON alert to the operator's `url`:

```json
{
  "event": "dead_letter_escalation",
  "endpoint": "https://downstream.example/hook",
  "deadLetters": 20,
  "threshold": 20,
  "windowMs": 600000,
  "alertedAt": "2026-10-13T12:00:00.000Z"
}
```

(`tenant` appears when the storming scope is tenant-scoped.) The alert
carries the WR-26 trust headers — `x-relay-signature: sha256=<hex>`
(HMAC-SHA256 of the body under `signingSecret`, **required** so the
operator side can verify the alert really came from this relay) and
`x-relay-key-id` when `keyId` is set. A failed alert is retried with a
short backoff (`maxAttempts`, default 2, capped at 3), then reported once
and audited as `dead_letter_escalation_failed`; a dispatched alert is
audited as `dead_letter_escalated`. Alerts never enter the retry queue or
the dead-letter list — a failing alert cannot recurse into the machinery
it observes.

**Edge-triggered with a cooldown.** One storm produces one alert: while a
scope is `alerted`, further dead letters are silent. The scope rearms when
the operator acknowledges it (`RetryQueue.acknowledgeDeadLetterEscalation`)
or when the sliding-window count falls back below the threshold on its
own. `cooldownMs` (default 1 hour) is the anti-flap guard between
episodes: a new episode starting inside the previous alert's cooldown stays
silent.

**Loop protection** works exactly like completion callbacks: the operator
URL is checked at configuration time against declared `selfOrigins` and
again before every POST against the actually bound address — an alert
posted back into this relay's own intake would amplify the storm it
reports.

Observability: `RetryQueue.getEscalationStats()` returns one row per scope
(endpoint, tenant, in-window count, threshold, alerted state, last alert,
cumulative escalations), and `GET /metrics` exposes
`relay_dead_letter_escalations_total{endpoint[,tenant]}` (activity-gated —
absent until the first alert fires).

### Multi-tenant isolation

One relay can serve many tenants without them stepping on each other. An
inbound webhook claims its tenant with the `x-tenant-id` header (1–64
chars, `[A-Za-z0-9_-]`); an invalid value is answered `400` and audited as
`rejected` / `invalid_tenant_id`. No header means the default tenant, and
everything behaves exactly as before — the default tenant's metrics
exposition is byte-identical to the pre-tenant relay.

Per (tenant, endpoint), the relay isolates:

- **concurrency limiter** — one tenant's slow downstream never starves
  another's deliveries;
- **outbound concurrency gate** — per-tenant in-flight cap across the
  tenant's endpoints (`tenantMaxConcurrent`); one tenant's flood queues
  against its own cap;
- **inbound rate limiter** — per-`x-tenant-id` token bucket at intake
  (`inboundTenantRateLimit`), checked before signature verification so
  one tenant's flood never burns verifier CPU meant for others;
- **delivery quota** — token buckets are per tenant;
- **circuit breaker** — a tripped breaker only parks its own tenant's
  attempts (probes still feed every tenant's breaker, so shared-downstream
  outages are visible everywhere);
- **latency tracker** — SLO stats and histograms are per tenant;
- **outbound rate limiter** — token buckets are per (tenant, endpoint),
  with per-endpoint overrides (`queue` mode paces at dispatch,
  `reject-429` mode answers 429 at intake).

Deliberately shared: the urgent-lane token bucket, the DRR lane
scheduler, the global retry budget, failover routing, downstream probes,
and batch merging. Dedup keys are tenant-scoped (one tenant's push never
suppresses another's identical event), and `x-tenant-id` is stripped from
the headers forwarded downstream.

Tenant shows up as a label wherever the relay reports: audit events carry
`tenant`, Prometheus series gain `tenant="…"`, the SSE `/events` stream
emits it per delivery event, and the operator endpoints
(`/audit`, `/latency`, `/dead-letter`, `/events`) all accept `?tenant=` to
filter to one tenant. Dead letters are tenant-scoped end to end: each
entry carries its `tenant`, `GET /dead-letter?tenant=` lists one tenant's
entries, `GET /dead-letter/stats` adds per-(tenant, endpoint) counts in
`byTenantEndpoint`, and `POST /dead-letter/replay` accepts `tenant` in the
body so a replay re-queues only that tenant's dead letters (omitting it
keeps the pre-tenant behavior of replaying everything). Completion-callback receipts carry the tenant too.
`POST /config/endpoint` accepts an optional `tenant` to hot-reload one
tenant's endpoint config.

### Tenant usage metering

Usage-based billing needs counters, not gates. Opt in with
`usage: { windowMs }` (default window: 1 hour) and the relay meters every
tenant in a rolling window — `x-tenant-id` selects the tenant, requests
without it bill to the `default` tenant:

- `delivered` / `failed` / `retried` / `dead_letter` — delivery outcomes
  per tenant (`failed === retried + dead_letter`: a failed attempt either
  schedules a retry or lands in the dead-letter queue);
- `bytes_in` — inbound payload bytes accepted at intake (rejections and
  dedup-suppressed duplicates never bill);
- `bytes_out` — outbound payload bytes on successful deliveries;
- `urgent` — accepted `x-priority: urgent` fast-lane admissions.

Read back via the operator `GET /usage` endpoint (`?tenant=` filters to
one tenant; Bearer `operatorToken`, 404 fail-closed when unconfigured or
when metering is off) or scrape the Prometheus exposition:
`relay_tenant_deliveries_total{tenant,outcome}`,
`relay_tenant_bytes_in_total{tenant}`,
`relay_tenant_bytes_out_total{tenant}`,
`relay_tenant_urgent_total{tenant}`. The meter never gates, delays, or
drops anything — it is orthogonal to the delivery quota (WR-15), which is
the protective gate. To *enforce* a monthly ceiling on top of the meter,
see per-tenant monthly delivery budgets (WR-137). Memory-bounded: per-tenant samples are capped
(`maxEventsPerTenant`, oldest dropped first) and the tenant population is
capped (`maxTenants`, least-recently-active evicted).

### Health summary dashboard

One human-readable call for on-call diagnosis: the operator
`GET /health/summary` endpoint (Bearer `operatorToken` / scoped `read` key,
404 fail-closed when operator auth is unconfigured) aggregates every
health signal the relay already tracks, so a 3 AM page turns into one JSON
read instead of correlating five series by hand:

- `endpoints` — one row per (tenant, endpoint) with any health signal:
  WR-10 circuit state + `consecutiveFailures` streak + trip count, WR-15
  quota `delayed` count, and WR-34 downstream probe state (the prober is
  endpoint-scoped, so the same probe object repeats on every tenant row of
  that endpoint). Rows absent from the list are healthy and silent.
- `retryBudget` — the WR-38 global retry-budget headroom
  (`retriesPerMinute` / `depleted`); absent when the budget is disabled.
- `tenantUsageTop` — the top-10 tenants by delivery volume in the WR-78
  usage window (empty when usage metering is unconfigured).

Pure read aggregation with zero write impact — fetching the summary
emits no audit event — and the machine-readable complement of the
`/metrics` exposition (people read the summary, dashboards scrape the
metrics).

### Failure classification

Not every failed delivery deserves a retry (`src/failure.ts`):

| Failure | Class | Behavior |
|---|---|---|
| HTTP 4xx except 408/429 (e.g. 400, 422) | `non_retryable` | Immediate dead letter — one attempt, no backoff waits. A poison payload can never succeed, so the retry budget is not burned on it. The endpoint's circuit is *not* tripped: the downstream answered, it just said no. |
| HTTP 408, 429, any 5xx | `retryable` | Normal backoff lane. A `429` honors the downstream's `Retry-After` header (delay-seconds or HTTP-date) for the next attempt — on both the normal and urgent lanes — instead of the computed backoff. |
| Timeouts, DNS failures, TLS/proxy errors | `retryable` | Normal backoff lane. |

The default sender throws a structured `HttpDeliveryError` (status code +
parsed `Retry-After`) instead of a bare `Error`, so classification never
parses message strings; custom senders get the same treatment by throwing
any error with a numeric `statusCode` field. When in doubt the classifier
retries: an unknown failure is always `"retryable"`.

**Response semantic validation:** some downstreams answer `200 OK` with a
body that still means failure — `{"ok":false}`, an `"error"` field, a
payment gateway's error code. A per-endpoint `responseValidator` (in
`retry: { responseValidators }`, either one validator for every endpoint
or an exact-`targetUrl` record) runs after the 2xx transport success and
judges the body: `true` means genuinely delivered, `false` a generic
semantic failure, a `string` a failure with that reason, and a throw is
fail-closed (treated as a failure). A semantic failure follows the normal
retry / dead-letter / circuit path (classified `"retryable"`, so
consecutive semantic failures trip the circuit breaker and the
accepted→delivered latency clock keeps running) and is audited as
`failed` with `reason: "semantic_failed"`. The default sender captures up
to 64 KiB of the response body for the validator (`truncated: true` when
cut); a custom sender that returns no response skips validation.

**Response assertions:** the declarative sibling of the validators above
(see *Per-endpoint response assertions*). Per-endpoint rules in
`retry: { responseAssertions }` bind an exact `targetUrl` to a status
whitelist (default: all 2xx) plus JSON-body assertions (`$.status == "ok"`
style, no `eval()`). A failing assertion is a *retryable* delivery failure
with `failure_class: "assertion_failed"` — normal backoff lane, the WR-10
breaker counts it like any retryable failure, and it honors the retry
budget; evaluation is fail-closed (a non-JSON body or an evaluation error
counts as a failure). Illegal rules throw `RangeError` at construction.
A status outside the whitelist keeps the WR-30 classification above.

**Batching:** when `retry.batch` is enabled, `accepted` →
**`batching`** instead of straight to `delivering`: normal-priority items
for the same endpoint are held for `windowMs` (or until `maxBatchSize` is
reached) and merged into one delivery whose payload is a JSON envelope
(`batch_id`, `batched_at`, `events[]` with base64 payloads and each event's
own headers — so per-event `x-signature`s stay verifiable downstream).
The merged batch is one delivery unit: retries and dead-lettering apply to
the whole batch, and every flush is audited as `batch_flushed` with its
size. Urgent items skip batching entirely (the fast lane must not wait).
`stop()` flushes pending batches into the queue unscheduled (a later
`start()` delivers them); `shutdown()` flushes them and grants each batch
one immediate attempt before draining in-flight deliveries.

**Live event stream:** with an `operatorToken` set, `GET /events` opens a
Server-Sent Events stream pushing `delivered` / `retrying` / `dead_letter`
frames as JSON in real time (`event: delivery`), so an operator can watch
the delivery flow without polling. A `: ping` heartbeat comment goes out
every `heartbeatMs` (default 15s, unref'd), and a subscriber whose kernel
buffer exceeds 1 MiB is disconnected instead of buffering without bound.
Live-only — no replay of past events. For history, use the persistent
**delivery event archive** (`GET /events/archive`, opt-in) — the archive
records the same event stream durably, while the audit log (`GET /audit`)
records operator actions; the three surfaces are complementary, not
redundant.

**Stream resume (`Last-Event-ID`, opt-in):** with `eventArchive` configured
*and* `events: { sseReplay: true }`, every frame carries an `id:` field with
the archiver-assigned monotonic `eventSeq` (dense, strictly increasing
across restarts — note this is *not* `DeliveryEvent.id`, which is a
per-delivery UUID). A client that reconnects with the standard SSE
`Last-Event-ID` header gets the missed events replayed in order before the
live stream continues. `Last-Event-ID: 0` replays everything retained. When
the cursor is older than the retained archive (retention-rotated), newer
than anything produced, the archive is empty, or the gap exceeds the
per-reconnect cap (10,000 events), the server answers `210 Gone` with an
`events_gone` body — the client rebuilds from `GET /events/archive`
instead of silently missing events. A malformed cursor answers `400`.
Off by default: the header is then ignored and the stream stays live-only,
zero behavior change.

**Shutdown:** SIGTERM moves every `retrying` item straight out of the
machine (dropped, never delivered) while `delivering` items are awaited;
see Graceful shutdown above.

**Trace IDs:** every event carries an end-to-end `traceId` threading
`received` → `accepted` → `delivering` → `delivered` / `retrying` /
`dead_letter` (and `rejected` / `duplicate_suppressed` too). The inbound
client may supply one via the `x-trace-id` header (kept when it is 1–64
chars of alnum/dash/underscore, minted fresh otherwise), and the same
value is:

- echoed in the 202 response body (`{"id", "traceId", "status"}`),
- written on every audit line (`accepted`, `delivered`, `dead_letter`,
  `rejected`, `duplicate_suppressed`, `slo_missed`, `slo_risk`,
  `batch_flushed`, plus `retrying` — one line per failed attempt,
  carrying the error and the scheduled delay) —
  `GET /audit?traceId=<id>` pulls one event's whole trail,
- attached to every SSE delivery event frame,
- forwarded downstream as the `x-trace-id` header, so the next hop can
  correlate with this relay's audit trail.

Merged batches get a fresh trace ID of their own; the `batch_flushed`
audit line carries the members' `traceIds` for the reverse lookup.

**Delivery status snapshot:** `GET /deliveries/:traceId` (same
`operatorToken` bearer guard, 404 fail-closed when unset) aggregates one
trace ID's audit trail into a lifecycle snapshot — no full-file scan, the
builder reads through the audit log's line-offset index, matching only
lines that carry the trace ID (dead-letter replay records are matched by
delivery `id` since `dead_letter_replayed` is an operator action, not a
delivery event). The response:

```json
{
  "traceId": "a3f9…",
  "id": "delivery-uuid",
  "endpoint": "https://downstream/hook",
  "state": "delivered",
  "acceptedAt": "2026-10-10T12:00:00.000Z",
  "timeline": [
    { "state": "accepted", "at": "…" },
    { "state": "retrying", "at": "…", "attempts": 1, "lastError": "…", "nextDelayMs": 100 },
    { "state": "delivered", "at": "…", "attempts": 2, "latencyMs": 312 }
  ],
  "attempts": 2,
  "retryCount": 1,
  "lastError": "…",
  "latencyMs": 312,
  "signals": [],
  "replayed": []
}
```

`state` is the latest terminal event (`delivered` / `dead_letter` /
`rejected` / `duplicate_suppressed`), or `delivering` while no terminal
event exists; `timeline` walks the state machine in order; `signals`
holds contextual non-state-machine events (`failed` semantic
validations, `retry_budget_depleted` parks, `slo_missed`); `replayed`
lists operator dead-letter replays for the delivery. An unknown trace ID
returns 404 with an `unknown traceId` error plus a hint to query
`GET /audit?traceId=<id>` for the raw trail. Built for payment-style
reconciliation: paste a trace ID from a callback dispute and see the
whole trajectory — every retry's error and delay, the final outcome,
and any replay — in one call.

**Prometheus metrics:** with an `operatorToken` set, `GET /metrics` serves
the queue's counters in Prometheus text exposition format (hand-written,
zero dependencies), behind the same bearer token as the other operator
endpoints (404 when disabled):

- `relay_deliveries_total{endpoint,status}` — `delivered` / `failed`
  (every failed attempt) / `retried` (failures followed by a scheduled
  retry) / `dead_letter`,
- `relay_endpoint_circuit_state{endpoint}` — 0 closed, 1 half_open,
  2 open (only endpoints that tripped),
- `relay_endpoint_circuit_error_rate{endpoint}` — rolling-window failure
  rate in [0, 1] (WR-104 error-rate trip mode; only error-rate-mode
  endpoints with at least one recorded outcome),
- `relay_websocket_connections{origin}` — active pooled WebSocket
  connections (WR-105); `relay_websocket_messages_out_total{origin}` /
  `relay_websocket_messages_in_total{origin}` — delivery messages sent /
  replies received; `relay_websocket_checkouts_total{origin,result}` —
  pool checkouts (`created` / `reused`); `relay_websocket_ping_rtt_seconds
  {origin}` — mean recent keep-alive ping RTT (only origins with a
  completed probe); `relay_websocket_deflate_ratio{origin}` — mean
  permessage-deflate wire/plain byte ratio (only origins with a
  compressed delivery). The whole block is absent until the first
  WebSocket delivery runs,
- `relay_delivery_latency_seconds_{bucket,sum,count}{endpoint}` —
  accepted→delivered latency histogram, only when `retry.latency` is
  enabled; bucket bounds via `retry.metrics.histogramBucketsMs`
  (default 50ms…10s),
- `relay_inbound_version_total{version,status}` — inbound intake by API
  version (`accepted` / `rejected`; `version="none"` for unversioned
  requests), only when `versions` is configured,
- `relay_inbound_ip_denied_total{endpoint}` — inbound requests rejected
  by the IP allowlist/denylist, by endpoint path pattern, only when
  `ipAcl` is configured,
- `relay_probe_total{endpoint,result}` — downstream health-probe
  outcomes (`success` / `failure`), only when `probe` is configured,
- `relay_probe_consecutive_failures{endpoint}` — current consecutive
  probe-failure streak per endpoint (0 = healthy), only when `probe` is
  configured,
- `relay_tls_version_rejections_total{endpoint,version}` — outbound
  deliveries rejected because the negotiated TLS version was below the
  endpoint's `minTlsVersions` floor (`version` = negotiated, e.g.
  `TLSv1.2`), only once a rejection has happened,
- `relay_starvation_guard_activations{endpoint}` — starvation-guard
  activation episodes (urgent dispatches deferred while normal demand was
  backlogged), only for endpoints where the guard engaged,
- `relay_retry_budget_depleted_total` — retries parked because the global
  retry budget was exhausted (no endpoint label — the budget is global),
  only when `retry.retryBudget` is enabled,
- `relay_slo_risk_seconds{endpoint}` — predicted SLO headroom remaining
  before breach, in seconds (0 = breach predicted now), only for endpoints
  currently elevated by the SLO-risk predictor, only when
  `retry.latency.sloRisk` is enabled.

### Dead-letter auto-replay

Opt-in timed replays of the dead-letter list (`src/autoreplay.ts`): with
`autoReplay` enabled — `createRelayServer({ ..., autoReplay: { enabled:
true, intervalMs: 60_000, maxRounds: 10, maxIntervalMs: 3_600_000 } })` (or
`retry.autoReplay` on a raw queue) — a `DeadLetterAutoReplayer` runs
rounds that replay the whole dead letter with the **same fresh-budget
semantics as a manual replay**: a replayed entry re-enters the queue with
its attempt counter reset to 0 and walks the normal delivery path
(exponential backoff, circuit breaker, quota, downstream `Retry-After`
honoring). A replayed item that delivers leaves the dead letter for good;
one that fails again walks back into the dead letter through the normal
path. Off by default — nothing is ever replayed automatically unless the
operator opts in — and invalid option values throw `RangeError`.

**Rounds counting.** `maxRounds` counts *consecutive* rounds with zero
successfully replayed items; entries that fail to re-queue (e.g. a sealed
payload with no decryptor configured) do not count as successes. Any
round replaying >= 1 item resets the counter to 0. Reaching `maxRounds`
stops the scheduler permanently and audits `dead_letter_auto_replay`
with `{ reason: "rounds_exhausted", consecutiveEmptyRounds, totalReplayed,
lastRunAt }`. Between rounds the wait backs off exponentially:
`min(intervalMs * 2^consecutiveEmptyRounds, maxIntervalMs)` — a backlog
that keeps replaying stays on the base interval, a persistently empty (or
poison-only) dead letter stops being polled aggressively.

**Operator controls** (same Bearer <redacted>, fail closed to 404 without
`operatorToken`):

- `POST /dead-letter/auto-replay/pause` — freeze the schedule; a pending
  round is cancelled but counters and totals are retained.
- `POST /dead-letter/auto-replay/resume` — continue where it left off;
  after an exhaustion stop this is the operator's explicit "try again" and
  resets the counter to 0, restarting the schedule
  (`{ paused: false, restarted: true }`).
- `POST /dead-letter/auto-replay/trigger` — run one round immediately,
  outside the schedule. It goes through the same accounting as a
  scheduled round: an empty trigger increments the empty-rounds counter, a
  successful one resets it, and it can itself trigger the exhaustion stop
  (audited). It does not unpause a paused scheduler, and a stopped
  scheduler ignores it.
- `GET /dead-letter/auto-replay/status` — `{ enabled, paused, stopped,
  consecutiveEmptyRounds, totalReplayed, lastRunAt, nextRunAt }`. Readable
  even when the scheduler was never configured (`enabled: false`); the
  control endpoints answer 404 in that case.

The round timer is unref'd, so a configured scheduler never pins the
process open, and `RetryQueue.stop()` / `shutdown()` cancel any pending
round — a round never fires mid-shutdown and re-queues dead letters the
operator expected to stay parked.

### Dead-letter replay idempotency guard (opt-in)

The payment-callback nightmare: the downstream *did* process the event,
but the response was lost, so the relay retried, exhausted its budget,
and dead-lettered the item. Replaying that dead letter now would repeat
the business action (a duplicate charge, a duplicate payout). WR-14
dedup only guards *inbound* duplicates — it cannot see replays.

`retry.replayIdempotency` (opt-in, off by default) keeps a bounded,
in-memory index of delivered events keyed by `(endpoint,
sha256(payload))` with their delivery timestamps. Before
`replayDeadLetter(s)` re-queues an entry, the queue checks the index:
when the same (endpoint, payload) was delivered *strictly after* the
entry was dead-lettered, the downstream already holds a newer copy, so
the replay is **suppressed** — the entry stays dead-lettered for
operator review instead of re-firing the business action:

```ts
const queue = new RetryQueue({
  sender,
  replayIdempotency: {
    windowMs: 86_400_000, // how long a delivered record suppresses a
                           // replay; default 24h, must be > 0
    maxEntries: 10_000,    // tracked pairs cap, oldest evicted first;
                           // default 10_000, integer >= 1
  },
});
```

- **Single replay** — `replayDeadLetter(id)` returns `false` and the
  entry stays in the dead-letter list when suppressed; pass
  `{ force: true }` to replay anyway (audited as `replay_forced`).
- **Batch replay** — `replayDeadLetters()` returns suppressed ids in a
  new `skipped` array (alongside `replayed` / `failed` / `throttled`);
  `{ force: true }` overrides the guard for the whole batch. Dry-run
  previews mark suppressible rows with `will_skip: true` and never
  touch payloads.
- **Operator endpoints** — `POST /dead-letter/replay` accepts
  `force: true` in the body and reports `skipped` in both the response
  and the `dead_letter_batch_replayed` audit event;
  `POST /dead-letter/{id}/replay` accepts `force: true` and answers
  `200 { id, replayed: false, skipped: true, reason:
  "replay_suppressed_delivered" }` when the guard suppresses (404 stays
  for genuinely unknown ids).
- **Audit** — suppressions fire `onReplaySkipped` (audited as
  `replay_skipped_delivered`); forced overrides fire `onReplayForced`
  (audited as `replay_forced`, only when a newer delivered copy
  actually existed).
- **Observability** — `getReplayIdempotencyStats()` exposes each
  tenant's indexed pair count and oldest record (activity-gated; absent
  rows never delivered anything).
- **Failure semantics** — the index is in-memory and bounded, so a
  restart clears it: after a crash the guard degrades to plain replay
  (fail-open by design — a missing record never *blocks* a replay, it
  only fails to *suppress* one). Sealed (WR-11 encrypted) payloads are
  decrypted for hashing, so the guard works on encrypted dead letters
  too; an undecryptable entry fails the replay like any other replay
  failure. Invalid options throw `RangeError` at construction.

### Dead-letter retention

Opt-in TTL-based cleanup of the dead-letter list (`src/deadletter-retention.ts`):
with `deadLetterRetention` configured —
`createRelayServer({ ..., deadLetterRetention: { retentionMs: { "https://pay.example/hook": 86_400_000 } } })`
(or `retry.deadLetterRetention` on a raw queue) — a background sweep every
`sweepIntervalMs` (default 60s, unref'd) purges entries dead-lettered longer
ago than their endpoint's TTL. `retentionMs` is per-endpoint opt-in: a
record of exact `targetUrl` → TTL purges only the listed endpoints (the
same exact-match convention as `responseValidators`), a plain number applies
one TTL to every endpoint. Off by default — dead letters live until
replayed manually — and invalid values throw `RangeError` at construction.

**Safety.** Each purge is audited as `dead_letter_purged` carrying only
operator metadata — `id`, `endpoint`, `attempts`, `deadLetteredAt` — plus
the standard correlation fields (`traceId`, `tenant`); the payload is
never exposed, not even as metadata, and sealed entries are purged sealed.
The TTL is keyed by the *logical* endpoint (an entry dead-lettered on a
failover standby is governed by its configured primary's TTL, the same
convention as the batch-replay filter). A purge skips entries currently
claimed by an in-progress WR-23 batch replay or WR-31 auto-replay round,
so a sweep never deletes an entry out from under a replay — the next
sweep picks it up if it is still expired. With the durable queue enabled
the purge is journaled, so a purged entry never resurrects after a
restart. `RetryQueue.stop()` / `shutdown()` disarm the sweep: nothing is
purged mid-shutdown.

**Operator surface** (same Bearer <redacted>, fail closed to 404 without
`operatorToken`):

- `GET /dead-letter/stats` — `{ total, purged, throttled, byEndpoint, byTenantEndpoint }`: live
  entries, entries auto-purged since startup, entries held back by the
  WR-68 replay egress throttle since startup (cumulative — each is still
  live in the list until a later replay re-queues it), live entries per
  logical endpoint, and (WR-86) live entries per (tenant, endpoint) pair
  (default-tenant rows carry no `tenant` field; the unscoped `byEndpoint`
  row stays the sum across tenants).
- `GET /audit?event=dead_letter_purged` — the per-purge audit trail.

### Replay egress throttling

Opt-in per-endpoint rate cap on dead-letter *re-queue* admission
(`src/replay-egress.ts`): with `replayEgress: { replaysPerSecond: 5 }`
(or `retry.replayEgress` on a raw queue), every replay path — manual
`replayDeadLetters`, operator `POST /dead-letter/replay`, and the WR-31
auto-replayer — draws from one shared per-endpoint token bucket
(`failoverEndpoint ?? targetUrl`, the same logical-endpoint key the
`/dead-letter/stats` grouping uses), so a big backlog replays at a
bounded rate instead of stampeding the downstream. The single-id
`replayDeadLetter(id)` operator escape hatch is deliberately not gated:
an operator replaying one entry by hand is not a storm.

**Burst semantics.** A replay that matches more entries than the bucket
currently holds does not drop anything: held-back entries stay in the
dead-letter list (FIFO position preserved) and are reported in the batch
result's `throttled` id list and the cumulative `throttled` counter on
`GET /dead-letter/stats`; the next replay call — manual or an auto-replay
round — picks them up. Once an entry is re-queued it walks the normal
delivery path (circuit breaker, quota, weighted dispatch, failover)
untouched and independent. A WR-31 round that only throttled entries
counts as progress for the empty-round accounting, so a
throttled-but-healthy backlog never trips the rounds-exhausted stop.
Off by default; a present-but-empty object uses the default
`replaysPerSecond` of 10; invalid values throw `RangeError` at
construction.

### Delivery deadline (end-to-end SLO)

Opt-in per-endpoint deadline from queue admission to delivery
confirmation (`src/retry.ts`, `deliveryDeadline` on `retry` options) —
the full chain, not a connection or read timeout:

```ts
const queue = new RetryQueue({
  sender,
  deliveryDeadline: {
    deadlines: { "https://pay.example/hook": 30_000 }, // exact targetUrl match
    now: () => Date.now(), // injectable clock for tests
  },
});
```

The deadline is an end-to-end SLO, orthogonal to the retry backoff: a
delivery may retry normally while inside its deadline, and the moment
the deadline passes the item stops — it is audited as
`delivery_deadline_exceeded` and dead-lettered immediately with its
actual attempt count, no further backoff is scheduled, and the remaining
retry budget is untouched. Time parked in the urgent fast lane, the
quota hold, the circuit-breaker hold, the manual pause, and the delivery
window all counts toward the deadline; only the by-design holds before
queue admission (the batch window, the `deliver_at` delay) do not — the
same convention as the accepted→delivered latency clock. The expired
dead-letter entry carries a normal `deadLetteredAt`, so it participates
in the dead-letter retention sweep like any other dead letter, and
expirations are counted in
`relay_delivery_deadline_exceeded_total{endpoint[,tenant]}`. A
dead-letter replay starts a fresh delivery cycle with a fresh deadline.
Off by default; invalid values throw `RangeError` at construction.

#### Deadline-budget propagation (WR-99)

The WR-76 deadline above expires a delivery at the next dispatch once
the budget is gone — but it never bounded the downstream call itself:
a delivery dispatched 1ms before its deadline could still run a
30-second attempt. With `propagateBudget` (default `true` when
deadlines are configured) the queue stamps the *remaining* budget
(`deadlineMs - elapsedMs`) on each dispatch's wire copy as
`RetryItem.deadlineBudgetMs`, and the default sender caps the
per-attempt downstream call at it — queue wait and the call share one
SLO pool:

- The HTTP/1.1 path destroys the in-flight request when the budget
  fires (that path has no other per-attempt timeout); a uniform race in
  the sender bounds the H2/WS paths. The rejection is a typed
  `DeadlineBudgetTimeoutError`, routed to the deadline-expiry path
  (audit + dead letter, actual attempt count, no backoff, no breaker
  verdict) — never the retry path.
- When the remaining budget at dispatch is at or below
  `minAttemptBudgetMs` (default `0`) the delivery expires *without*
  issuing the outbound call — a call that cannot usefully finish inside
  its budget is a wasted downstream hit.
- Budget exhaustion (queued or mid-call) is attributed into the
  `slo_missed` channel with `deadlineBudgetExhausted: true` and the
  dominant latency phase (WR-95), so operators see *why* the SLO
  burned, not just that a dead letter exists.

Custom (injected) senders ignore `deadlineBudgetMs` — the queue-side
expiry still bounds the delivery, only the per-attempt cap is lost.
Set `propagateBudget: false` to keep the exact WR-76 behavior.

#### Per-endpoint phase timeout budgets (WR-143)

The deadline above is one end-to-end pool; sometimes you want to budget
*where* inside the attempt the time goes. `phaseTimeouts`
(`src/phase-timeouts.ts`) is an opt-in per-endpoint record —
`{ "<exact targetUrl>": { connectMs?, tlsMs?, firstByteMs?, bodyMs? } }`
— that arms one timer per configured WR-95 phase on every delivery
attempt:

```ts
const relay = createRelayServer({
  // ...secret, forwardUrl, auditLog
  phaseTimeouts: {
    "https://slow-tls.example/hook": { tlsMs: 800, firstByteMs: 5_000 },
  },
});
```

The four phases: `connect` (socket-assigned → TCP established),
`tls` (TCP established → TLS handshake complete, `https:` only),
`firstByte` (request-issued → first response bytes), `body` (first
response bytes → response end, 2xx only). `dns` is never budgeted —
per-request DNS timing is not attributable (WR-95 convention). When a
phase's budget expires before the sender observes that phase's
completion, the attempt fails with a typed `PhaseTimeoutError{phase,
timeoutMs}` — classified `"retryable"` by the default fallthrough, so
it takes the normal backoff / dead-letter path, and a `connect`/`tls`
budget firing destroys the request before a single payload byte is
written (the pinning/OCSP zero-leak standard).

Layering: the phase budgets are per-attempt allocations *inside* one
attempt; the delivery deadline stays end-to-end — both may be
configured, and they compose (a phase budget can fail an attempt long
before the deadline; the deadline can expire a delivery whose attempts
never hit a phase budget).

Pooled-socket rule: `connect`/`tls` are only measurable on a fresh
direct socket (WR-95) — on pooled reuse or behind a proxy they report
unavailable, so their timers simply never arm there; budgets fire
against measured phases only. The budgets apply on the HTTP/1.1 path;
phase-timeout endpoints are kept off the opt-in HTTP/2 path
(per-request phases don't exist on a multiplexed session — the OCSP
precedent), and `wss:` targets are not covered.

Attribution: the phase whose budget fired is recorded per delivery, so
a later SLO miss carries `phaseTimeout` ("firstByte blew the budget")
in the `slo_missed` audit event — the phase name only, never fabricated
durations — alongside the usual `dominantPhase`/`phaseBreakdown`.

Off by default: endpoints without an entry keep the current single
attempt-total-timeout behavior untouched. All values are positive
integer milliseconds with at least one phase per entry; invalid
entries throw `RangeError` at startup.

### Shadow-target dry-run mirroring

Opt-in per-endpoint dry-run mirroring for the downstream-migration /
contract-verification scenario (`src/shadow.ts`, `shadowTargets` server
option or `retry.shadowTargets`): after every main delivery attempt
completes (success or failure), the relay asynchronously mirrors the
identical wire request to each shadow target — same payload, same
`x-relay-signature` / `x-relay-key-id`, same `x-relay-idempotency-key`,
same compression encoding. Each shadow target is served by an
independent sender copy (own keep-alive pools, own `tlsPins` / mTLS
client identity per target), so the shadow downstream sees the same
bytes the production downstream got.

```ts
const server = createRelayServer({
  // ...,
  shadowTargets: {
    "https://api.example/hook": [
      {
        targetUrl: "https://staging.example/hook",
        tlsPins: ["sha256/<base64>"], // independent pinning per shadow target
      },
    ],
  },
});
```

Shadow outcomes are only *observed*: audited as `shadow_delivered` /
`shadow_failed` and counted in
`relay_shadow_total{endpoint,shadow_target,result}`. A shadow copy never
triggers a main retry, never dead-letters, never trips the circuit
breaker, never consumes a quota token, and never pollutes the main
delivery counters — a failing shadow is silent (recorded, never
retried). Off by default; invalid values throw `RangeError` at startup.

### Delivery event archive

Opt-in persistent history for the delivery lifecycle events
(`delivered` / `retrying` / `dead_letter`, the same events the `GET
/events` SSE stream carries live). Set `eventArchive: { dir }` and the
server subscribes a `DeliveryEventArchiver` to its queue: every event is
appended as one JSON line to `<dir>/events.jsonl`
(`{type, id, traceId, tenant?, targetUrl, attempts, at, error?}`) and
survives process restarts — reopening the same directory re-reads the
history.

`GET /events/archive?since=&until=&endpoint=&event=` (same
`operatorToken` Bearer <redacted> as the other operator endpoints; 404
fail-closed when no `operatorToken` is configured, 403 on a wrong bearer,
and 404 — leaking no existence — when the archive itself is not
configured) returns the matching events as a JSON array sorted by `at`
ascending. `event` must be one of `delivered` / `retrying` /
`dead_letter` (anything else is 400); `since` / `until` must be valid
ISO-8601 timestamps (else 400); `endpoint` is an **exact** match on
`targetUrl`, no substring matching.

Rolling retention is opt-in via `maxAgeMs` (drop lines whose event `at`
is older than `now - maxAgeMs`) and `maxBytes` (drop the oldest lines
first when the file exceeds that size; the newest line is always kept).
Retention runs amortized on the append path and once at startup, and
rewrites through a temp file + atomic rename — a crash before the rename
leaves the previous complete file, so retention is never half-applied.

Crash semantics are at-least-once, honestly not exactly-once: appends are
synchronous and never throw (a failed write is counted and swallowed, so
archiving can never fail a delivery), but they are not fsync'd, so an OS
crash may lose the unwritten tail; the archive never dedupes, so a
double-recorded event appears twice and queries return it twice. Corrupt
(torn) lines are skipped on read. Decoupled from the audit log by design:
audit = operator actions, archive = delivery event stream.

### Operator/intake plane split

Opt-in network segmentation for the control plane:
`operatorPort: { port, host? }` makes the relay listen on **two** ports.
The intake plane (the server `createRelayServer` returns, bound by the
caller with `listen()`) accepts only webhooks; the operator plane (bound
by the relay itself at creation, exposed as `server.operatorServer`)
serves only the operator endpoints (`/dead-letter`, `/audit`, `/metrics`,
`/events`, `/config/endpoint`, `/deliveries/:traceId`, ...).

Cross-plane requests are answered with a plain `404 Not found` that
reveals nothing about the other plane: operator paths hit on the intake
plane are indistinguishable from unknown paths, and webhook posts hit on
the operator plane are rejected without ever entering the queue. The
operator plane binds `127.0.0.1` by default — never `0.0.0.0` — so it is
not reachable from the network unless the operator explicitly opts in
with `host`. Without `operatorPort` the relay keeps the legacy behavior:
one listener serves both planes. Invalid values (`port` outside 0–65535
or non-integer, empty `host`) throw `RangeError` at startup. Closing the
returned server also closes the operator plane; graceful shutdown stops
the operator plane before draining in-flight deliveries, so no manual
replays or config changes can land mid-drain.

### Scoped operator API keys

The operator plane used to be all-or-nothing: one shared `operatorToken`
guarded both the read-only endpoints and the mutating ones. `operatorKeys`
upgrades it to a key ring of `{ id, key, scopes? }` entries (see
`src/operator-keys.ts`) with exactly two case-sensitive scopes:

- `read` — every read-only operator path: `GET /metrics`, `GET /audit`,
  `GET /audit/verify`, `GET /latency`, `GET /slo-risk`, `GET /usage`,
  `GET /events`, `GET /events/archive`, `GET /deliveries/:traceId`,
  `GET /dead-letter`, `GET /dead-letter/stats`,
  `GET /dead-letter/auto-replay/status`, `GET /scheduled`.
- `admin` — everything `read` covers **plus** every mutating operator
  path: dead-letter replays (`POST /dead-letter/:id/replay`,
  `POST /dead-letter/replay`), auto-replay `pause` / `resume` /
  `trigger`, `POST /config/endpoint`, endpoint `pause` / `resume`,
  schedule `pause` / `resume`.

```ts
createRelayServer({
  // ...,
  operatorKeys: [
    { id: "monitor", key: "<prometheus-scrape-key>", scopes: ["read"] },
    { id: "oncall", key: "<human-operator-key>", scopes: ["admin"] },
    // no `scopes` → fail-closed: authenticates, authorized for nothing.
    { id: "retired", key: "<revoked-but-still-deployed-key>" },
  ],
});
```

Semantics, deliberately conservative:

- The legacy single `operatorToken` keeps working with full `admin`
  semantics when set; when both are configured, either credential
  authenticates. When neither is configured, the operator endpoints stay
  disabled and answer 404 (fail closed) — exactly the legacy behavior.
  A non-matching bearer always answers 403; key comparison is
  constant-time (`crypto.timingSafeEqual`, no early exit on a match).
- An entry with no `scopes` (or an empty array) is fail-closed: it
  authenticates but every operator path answers 403.
- Every operator call's audit event carries the key's `keyId` (the legacy
  token audits as `"legacy"`), so an incident review can tell the
  monitoring key apart from the human operator. Read-only requests under
  a `read`-scoped key return the exact same response bodies as the legacy
  token.
- Invalid config — a scope other than `"read"` / `"admin"` (exact,
  case-sensitive), an empty `id` or `key`, a duplicate key id, or a
  duplicate key value — throws `RangeError` at startup (fail fast, never
  mid-request).

## Run

```sh
npm test
```

Requires Node 24+ (runs `.ts` directly via type stripping; zero dependencies).

## Test

`npm test` runs the `node:test` suites in `test/`:

- `test/audit.test.ts` — the indexed query: endpoint + event + time-range
  filters, malformed-line skipping, missing-file behavior, `limit` keeping the
  most recent matches, index rebuild after truncation, and invalid parameters
  throwing.
- `test/verify.test.ts` — valid signatures pass; tampered body, wrong secret,
  expired timestamp, and missing headers fail. Covers the pluggable layer:
  `HmacSha256Verifier` parity with `verifySignature`, `Ed25519Verifier`
  accept/reject/wrong-key/malformed, registry dispatch (unknown names fail
  closed), and `verifyWith` never throwing on misbehaving verifiers.
- `test/replay.test.ts` — `ReplayGuard`: fresh nonce accepted, replay rejected
  as `duplicate_nonce`; missing/empty nonce, stale and far-future timestamps
  (with window-edge inclusivity), non-numeric timestamps, nonce expiry after
  the window, oldest-first eviction beyond `maxEntries`, and `RangeError` on
  invalid configs. WR-122: durable journal — accepted nonces journaled and
  flushed, restart recovery still 409s a replayed nonce, expired entries
  dropped at recovery, corrupt lines skipped, `(scope, nonce)` isolation,
  and a server-level restart test (new server + new guard, same journal
  dir → replay is still 409).
- `test/autoreplay.test.ts` — the opt-in dead-letter auto-replay
  scheduler: `triggerOnce` replays dead letters with fresh-budget semantics
  (a replayed item leaves the dead letter and delivers on attempt 1),
  consecutive-empty-round counting with exponential backoff
  (`intervalMs * 2^n` capped by `maxIntervalMs`), a success resetting the
  counter, failed re-queues not counting as successes, permanent stop at
  `maxRounds` with the `dead_letter_auto_replay` audit event (fired exactly
  once), pause/resume state retention, `RangeError` on invalid configs,
  shutdown clearing the round timer, and the operator endpoints
  (`status` / `pause` / `resume` / `trigger`, fail-closed 404 without
  `operatorToken`, 403 on a wrong bearer, 405 on method mismatch, and an
  end-to-end trigger replaying a real dead letter).
- `test/hotreload.test.ts` — `updateEndpointConfig` runtime retuning:
  backoff changes apply to future scheduled retries while already-scheduled
  timers keep their old delay; raising a concurrency limit immediately grants
  queued waiters and lowering never revokes in-flight deliveries; circuit
  threshold/cooldown overrides take effect on the next trip decision and
  cooldown check; per-endpoint quota budgets update in place; illegal values
  throw `RangeError` with no partial application (including patching a
  disabled subsystem); the `POST /config/endpoint` operator endpoint applies
  patches with bearer auth (400 on illegal values, 403 without the token,
  404 fail-closed without `operatorToken`) and audits
  `endpoint_config_updated`.
- `test/config-snapshot.test.ts` — declarative config snapshots (WR-88):
  `exportConfig` captures hot-reloadable config per `(tenant, endpoint)`
  plus the inventory-only wiring (key ids, never key bytes; `Infinity`
  JSON-safe); `applyConfig` converges through `updateEndpointConfig`,
  removes dropped overrides, supports `dryRun`, refuses secret-bearing
  snapshots and diverged secret inventory fail-closed (`400`), refuses
  disabled-subsystem patches (`unsupported`), and rolls back applied items
  to the exact pre-apply state on a mid-apply failure (audited as
  `config_rolled_back`); `detectConfigDrift` reports live-vs-snapshot
  diffs read-only; `GET/POST /config/snapshot` operator endpoints (read /
  admin scopes, 404 fail-closed, 403 without credentials).
- `test/retry.test.ts` — a flaky sender (fails twice, then succeeds) delivers
  on the third attempt with increasing backoff; a permanently failing sender
  ends in the dead-letter list. Covers the jitter layer: additive jitter with
  an injected random source, full-jitter bounds within the cap, and
  `RangeError` on invalid configs. Covers dead-letter replay: entries carry
  attempts/lastError/timestamp, `replayDeadLetter` re-queues with a fresh
  attempt budget (unknown ids return false), and `replayAllDeadLetters`
  returns the replayed count. Covers the concurrency layer:
  `maxConcurrentPerEndpoint` caps in-flight deliveries per endpoint (FIFO
  slot queueing, independent budgets per endpoint, `RangeError` on invalid
  configs, `getConcurrencyStats()` observability), and `stop()` unblocks
  queued waiters without losing items (restart resumes where it left off).
- `test/e2e.test.ts` — end-to-end over real HTTP with the default sender: a
  flaky stub (500, 500, then 200) proves retries happen with visibly growing
  backoff and the payload arrives byte-identical (audit records `delivered`
  with `attempts: 3`); an always-500 stub proves exhaustion lands on the
  operator `GET /dead-letter` endpoint with `attempts: 3`.
- `test/shutdown.test.ts` — graceful shutdown: `RetryQueue.shutdown` waits for
  an in-flight delivery before resolving `true`, cancels pending backoff
  timers (no new attempts start), reports `false` on a hung sender after the
  timeout, and never hangs on a delivery parked on a concurrency slot.
  `installGracefulShutdown` stops accepting connections, drains, exits 0
  (events in order: `signal` → `server-closed` → `drained`), exits 1 on drain
  timeout, lets an in-flight HTTP request finish first, ignores a second
  signal, and uninstalls cleanly. The server wiring drains a real in-flight
  delivery on SIGTERM before exiting 0.
- `test/server.test.ts` — end-to-end against a local stub HTTP server: a
  valid webhook is forwarded byte-for-byte and audited as delivered; an
  invalid signature returns 401 and is never forwarded. Also proves the
  injected `verifier` option is honored (accept-all / reject-all). Also covers
  the dead-letter operator surface: endpoints are disabled without
  `operatorToken`, require the bearer token when set, and support listing plus
  manual replay of dead letters (audited as `dead_letter_replayed`). Also
  covers `GET /audit`: fail-closed without the token, endpoint/event/time-range
  filters, `limit`, and 400 on invalid query parameters. Also covers replay
  protection: replays answer 409 and are never forwarded twice, missing
  nonces and out-of-window timestamps answer 400, all rejections are audited
  with machine-readable reasons, and the receiver stays backward-compatible
  when no guard is injected. Also covers the urgent lane: `x-priority: urgent`
  (case-insensitive) is mapped onto the fast lane and recorded on the
  `accepted` audit event, while requests without the header stay normal.
  Also covers `GET /latency`: the operator-token guard, per-endpoint
  percentile stats with `?endpoint=` filtering, and `slo_missed` audit
  events when a delivery exceeds the latency budget.
- `test/urgent.test.ts` — the fast lane: `UrgentRateLimiter`
  burst/refill/per-endpoint isolation and `RangeError` on non-positive
  rates; urgent retries use the fixed delay instead of exponential backoff;
  an urgent delivery completes while a normal one still holds the only
  concurrency slot; an empty token bucket degrades the item to normal
  backoff (never drops); admission without a token degrades immediately;
  replayed dead-letter items keep their priority (this caught a real bug —
  the dead-letter push dropped `priority`); normal items are unaffected;
  invalid configs throw.
- `test/starvation-guard.test.ts` — the WR-35 lane scheduler: `LaneScheduler`
  deficit round-robin pacing under a deterministic urgent flood (normal
  keeps ≥ `minNormalShare` of dispatch turns, each urgent batch waits for
  the next normal dispatch), work-conserving release when the backlog
  drains, pass-through with no urgent pressure, composition with the
  urgent token bucket (no double rate-limiting), `RangeError` on invalid
  shares, per-endpoint share overrides, and activation auditing +
  `relay_starvation_guard_activations` metrics.
- `test/urgent-starvation-guard.test.ts` — the WR-121 fast-lane
  consecutive-occupancy guard: `RangeError` on invalid
  `maxConsecutiveUrgent`, complete no-op when disabled, the (N+1)-th
  consecutive urgent force-downgraded to normal (audited as
  `urgent_downgraded`, counted in `getUrgentStats().downgraded`), strict
  alternation at bound 1 (normal keeps 1/2 of the slots), streak reset by
  normal admissions and by WR-12 empty-bucket degrades (no
  double-downgrade), per-endpoint streak isolation, composition with the
  WR-35 deficit round-robin (guard fires at admission while DRR paces
  turns — no deadlock, normal keeps its share), and an end-to-end run
  through the WR-27 CONNECT proxy tunnel (one pooled CONNECT, five
  deliveries, one downgrade, nothing dropped).
- `test/latency.test.ts` — `LatencyTracker`: percentiles and SLO attainment
  over known samples, per-endpoint isolation and filtering, bounded rolling
  window eviction, discard/unknown-id no-ops, re-accept restarts the clock,
  backward clock jumps clamped to zero, and `RangeError` on invalid
  configs. Queue integration: accepted→delivered sampling with `onSloMiss`
  firing past the budget, dead-lettered items discarded without sampling,
  and tracking disabled by default.
- `test/ordered.test.ts` — per-endpoint ordered delivery (WR-113):
  `OrderedTracker` head advance + hold-clock restart on settle,
  per-endpoint isolation, `assertValidOrderedConfig` / `resolveOrderedConfig`
  (boolean / options / exact-targetUrl record forms, `RangeError` on
  illegal values at construction); queue integration: receive-order
  dispatch with a slow head, followers held behind a retrying head with
  no attempt consumed, per-endpoint scoping (unordered endpoints
  unaffected), poison-head park into the dead letter with
  `failureClass: "head_of_line_timeout"` + `head_of_line_parked` audit
  and line advance, urgent bypass audited as `ordered_bypassed`,
  `relay_ordered_*` series activity-gated (zero series when disabled),
  and the `Infinity` default holding the head without a timer.
- `test/dedup.test.ts` — `DeliveryDeduplicator`: deterministic hashing,
  repeat-inside-window suppression, payload/endpoint independence, window
  expiry re-delivering, oldest-first eviction past `maxEntries`, and
  `RangeError` on invalid configs. Server integration: a repeated payment
  callback answers 202 `duplicate: true` and is delivered exactly once
  (audited as `duplicate_suppressed`); a different payload is a different
  event; dedup stays off by default; signature verification still runs
  before the dedup check.
- `test/quota.test.ts` — `EndpointQuota`: full-bucket start, lazy refill,
  per-endpoint isolation, backward-clock clamping, and `RangeError` on
  invalid configs. Queue integration: over-budget attempts are delayed
  (rescheduled at the refill, never dropped) and counted in
  `getQuotaStats()`; a delayed item still burns no retry budget (a
  `maxAttempts: 1` flood delivers everything exactly once); budgets stay
  isolated per endpoint; quota is unlimited by default.
- `test/sse.test.ts` — the `GET /events` SSE stream: guarded like the other
  operator endpoints (404 without `operatorToken`, 403 on a wrong token,
  405 on non-GET); `delivered` frames carry the delivery id and attempt
  count; `retrying` then `dead_letter` frames fire with the failure message
  on persistent failure; heartbeat comments arrive on idle connections; a
  disconnected client stops receiving without breaking the server for the
  remaining subscribers.
- `test/sse-replay.test.ts` — `Last-Event-ID` reconnect resume (WR-123):
  live frames carry the monotonic `id:` cursor; reconnect replays the missed
  range in order then continues live; `0` replays everything retained; a
  caught-up cursor replays nothing; rotated/future/empty cursors answer
  `210 Gone`; malformed cursor answers `400`; without `sseReplay` the header
  is ignored (live-only); `sseReplay` without an archive never crashes;
  the cursor survives a server restart via the archive. Plus
  `DeliveryEventArchiver` sequence unit tests: dense seq assignment +
  event stamping, `eventsAfter`, cross-restart continuation, one-time
  resequence of pre-WR-123 lines, retention advancing the cursor range.
- `test/operator-keys.test.ts` — scoped operator API keys (`operatorKeys`):
  `read` keys reach every read-only operator path with byte-identical
  response bodies but get 403 on every mutating path; `admin` keys read and
  mutate; the legacy `operatorToken` keeps full admin semantics (audited as
  `keyId: "legacy"`) and coexists with the ring; scopeless keys are
  fail-closed (403 everywhere); unknown bearers get 403; no credentials
  configured stays 404 fail-closed; `405` still precedes the scope check and
  operator-prefix unknown paths still 404; operator audits
  (`dead_letter_batch_replayed`, `endpoint_paused` / `endpoint_resumed`)
  carry the key's `keyId`; `RangeError` at startup on bad scopes, duplicate
  ids, duplicate key values, and empty ids/keys.
- `test/response-audit.test.ts` — downstream response summaries on
  `delivered` / `dead_letter` audit events: `statusCode` / `responseBytes` /
  `timeToFirstByteMs` / `bodyFingerprintSha256` fields, `"unavailable"`
  honesty for unmeasured fields, opt-in `responseBodyCapture` sealing the
  body through the WR-11 encryptor, `RangeError` when capture is enabled
  without an encryptor.
- `test/event-archive.test.ts` — the `DeliveryEventArchiver`: archives
  `delivered` / `retrying` / `dead_letter` events to `<dir>/events.jsonl`
  and queries them sorted by `at`; `since` / `until` / `endpoint` (exact
  match on `targetUrl`) / `event` filters; invalid `since` / `until`
  throws; `RangeError` on invalid retention options; `maxBytes` evicts
  oldest-first keeping the newest line; `maxAgeMs` evicts expired events;
  restart re-reads history from the same directory; appends never throw
  (failures counted); source subscribe/unsubscribe; corrupt lines skipped.
  `GET /events/archive` end to end: serves archived deliveries with
  filters, 404 fail-closed when unconfigured, guarded like the other
  operator endpoints (404 without `operatorToken`, 403 on a wrong token,
  405 on non-GET), 400 on an invalid `event` filter or bad
  `since` / `until`.
- `test/batch.test.ts` — batch delivery merging: same-endpoint items inside
  the window merge into one delivery with the JSON envelope (arrival order,
  base64 payloads, per-event headers preserved); endpoints stay separate;
  `maxBatchSize` flushes early; urgent items bypass batching and go out raw;
  custom envelopes plug in; a failed batch retries as one unit with an
  identical body; a dead-lettered batch keeps the envelope for replay;
  `RangeError` on invalid configs; duplicate ids rejected while buffered;
  `stop()` flushes pending batches into the queue; `shutdown()` grants each
  buffered batch one immediate attempt before draining. Server integration:
  three inbound webhooks become one downstream request, audited as
  `batch_flushed`.
- `test/keepalive.test.ts` — the outbound keep-alive pool (13 tests):
  `RangeError` on invalid pool options (also via `createDefaultSender`);
  options reaching the underlying agent; sequential deliveries sharing one
  connection by default (`created: 1`, `reused: 4`) with `getStats()`
  observability; `keepAlive: false` opening a fresh connection per delivery
  (the legacy opt-out); `maxSocketsPerHost` capping concurrent connections;
  idle reaping after `idleTimeoutMs`; a failed connection never reused;
  separate pools per origin and `destroy()` closing idle connections; TLS
  pinning over pooled connections — one handshake for three pinned
  deliveries, every pin-mismatch attempt failing with `TlsPinMismatchError`
  on a fresh (never pooled) connection, and pinned/unpinned endpoints on the
  same origin never sharing a pool; concurrent pinned handshakes never
  resuming TLS sessions (every pinned handshake is full, so the pin check
  always sees the peer certificate).
- `test/probe.test.ts` — the keep-alive health probe (9 tests):
  `RangeError` on non-boolean `healthProbe`; `isSocketReusable` unit checks
  (live socket passes, destroyed and peer half-closed sockets fail);
  pinned-entry SPKI re-verification (no verified pin → fail-closed);
  checkout culling a dead idle socket before reuse (`created: 2`,
  `reused: 0`, `probeMisses >= 1`) and healthy reuse resuming with
  `probeHits`; a server FIN idle-timeout socket never handed to a delivery;
  `healthProbe: false` leaving the free list untouched; the background
  sweep culling a poisoned-pin socket with no traffic; pinned TLS reuse
  passing the probe.
- `test/http2.test.ts` — outbound HTTP/2 session reuse (18 tests):
  `RangeError` on invalid `outboundHttp2` options (also via
  `createDefaultSender`); H2 off by default (`http2Pool` undefined unless
  `enabled` with eligible hosts); h2c multiplexing ten deliveries over one
  TCP connection (`established: 1`, `reused: 9`); query-string preservation
  in `:path`; re-establishment after a server-side session close; idle
  session reaping after `sessionIdleTimeoutMs`; ineligible hosts and
  `host:port` mismatch falling through to HTTP/1.1 with no fallback
  counted; HTTPS H2 with TLS pinning (one session, pin re-verified) and
  pin mismatch failing loudly as `TlsPinMismatchError` via the H1.1
  fallback; mTLS client certificate presented on the H2 handshake with the
  server pin verified; fallback to HTTP/1.1 never losing a delivery when
  H2 is refused (`fallback` counted, H1.1 pool reusing); non-2xx over H2
  surfacing `HttpDeliveryError` with no fallback; proxied endpoints
  bypassing H2 for the CONNECT tunnel (zero H2 sessions); `getStats()`
  shape and `destroy()` closing sessions.
