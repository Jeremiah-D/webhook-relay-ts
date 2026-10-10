# webhook-relay-ts

> **Portfolio reconstruction.** This is a small project built to demonstrate
> webhook-signature verification and delivery-reliability engineering. It is
> not employer production code and re-implements no proprietary system.

A dependency-free TypeScript webhook relay: verify an incoming webhook through
a pluggable verifier interface (HMAC-SHA256 default, Ed25519 included),
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
  covers `<ts>.<rawBody>`), and `Ed25519Verifier` (`ed25519=<hex>` over the
  raw body, PEM public key). Uses `crypto.timingSafeEqual` on the HMAC path
  and enforces a timestamp tolerance window (default 300s).
  `RotatingHmacVerifier` (also in `src/verify.ts`) layers key rotation on
  top: several HMAC keys coexist with one primary for new signatures,
  retired keys stay verifiable inside a grace window (default 24h), and
  `verifyDetailed` reports which key id verified for the audit trail.
  `selectEndpointVerifier` / `assertValidEndpointVerifierRules` implement
  per-endpoint verifier selection: inbound paths match `{ pattern,
  verifier }` rules (exact `/hooks/stripe` or prefix `/hooks/*`, first
  match wins, unmatched paths fall back to the global verifier), so one
  relay can trust Ed25519 for one upstream and HMAC-SHA256 for another.
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
  or ranges. Invalid rules throw `RangeError` at startup.
- `src/retry.ts` — `RetryQueue` with exponential backoff (`base * 2^attempt`)
  plus jitter, a `maxDelay` cap, a dead-letter list after `maxAttempts`, and an
  injectable sender/timer for deterministic testing. Jitter is configurable:
  `"additive"` (uniform(0, `jitterMs`) on top, default) or `"full"` (AWS-style
  uniform(0, min(cap, base*2^attempt)) — the recommended anti-thundering-herd
  choice when many deliveries fail at once); the random source is injectable
  (`random`) so jitter bounds are testable, and invalid configs
  (non-positive base/cap, `maxAttempts < 1`, negative jitter) throw
  `RangeError`. Dead-lettered items carry `attempts`, `lastError`, and
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
  turns granted per lane.
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
  Injectable clock for deterministic tests.
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
- `src/audit.ts` — append-only JSONL audit log (`append` / `readAll`) plus an
  indexed query (`query({ event, endpoint, since, until, limit })`): a lazily
  maintained line-offset index maps each complete line to its `ts`/`event`/
  `endpoint` fields and byte span, so only matching lines are read back from
  disk; appends are indexed incrementally and truncation/rotation rebuilds the
  index. Malformed lines are skipped by the index.
- `src/replay.ts` — `ReplayGuard`: nonce + timestamp-window replay protection
  for inbound webhooks. A unique `x-nonce` per delivery is remembered for the
  window (`windowSec`, default 300s); resends are rejected as `duplicate_nonce`,
  a missing nonce or an `x-timestamp` (unix seconds) outside ±window is
  rejected as `missing_nonce` / `expired_timestamp` / `future_timestamp`.
  Memory-bounded: nonces expire with the window (lazy sweep per check) and a
  `maxEntries` cap evicts oldest-first. Injectable clock for deterministic
  tests.
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
- `src/ratelimit.ts` — inbound rate limiting (`InboundRateLimiter`):
  dual-dimension token buckets — per-sender IP and per-endpoint — guarding
  the webhook intake. Each dimension is a per-second bucket refilled lazily
  (burst = one second of budget, clock-skew clamped at zero so a backward
  clock never grants extra budget); a request must hold a token in *both*
  buckets, and the check is peek-then-consume so a rejection never burns the
  other dimension's token. Wired into the server via `rateLimit: {...}`
  (off by default); over-budget requests are answered 429 with `retry-after`
  and audited as `rejected` (reason `rate_limited`). Injectable clock for
  deterministic tests.
- Inbound request body limit (`maxBodyBytes`, `DEFAULT_MAX_BODY_BYTES` = 1 MiB):
  a POST whose body exceeds the budget is answered 413 and audited as
  `rejected` (reason `body_too_large`). Two lines of defense: the declared
  `content-length` is checked before a single body byte is read, and
  chunked or lying bodies are capped while streaming — the response closes
  the connection (`connection: close`) so a flood cannot keep streaming
  into a dead request. Invalid values throw `RangeError` at startup.
- Outbound request signing (`outboundSigning`, off by default): every delivery
  made by the default sender stamps `x-relay-signature: sha256=<hex>` — the
  HMAC-SHA256 of the forwarded body — plus `x-relay-key-id` when a `keyId`
  is given, so the downstream can prove the request really came from this
  relay (verify with `verifySignature(body, header, secret)` from
  `src/verify.ts`). Inbound `x-relay-signature` / `x-relay-key-id` headers
  are always stripped from the forwarded header set, so a sender can never
  smuggle a forged relay signature downstream. The config applies to the
  default sender only — an injected sender signs (or doesn't) on its own.
  Invalid values throw `RangeError` at startup.
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
  `trips`, `circuitBlockedCount()` counts parked attempts, and every
  transition is audited as `circuit_open` / `circuit_half_open` /
  `circuit_closed` with the endpoint. Injectable clock for deterministic
  tests.
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
- `src/keepalive.ts` — outbound keep-alive connection pool: deliveries reuse
  TCP/TLS connections per `(scheme, host, port)` instead of paying a handshake
  per attempt. One `http.Agent`/`https.Agent` per origin, with
  `maxSocketsPerHost` (default 64; extra requests queue FIFO inside the agent)
  and idle reaping after `idleTimeoutMs` (default 30s) on an unref'd timer —
  an idle pool never pins process exit, and a failed connection is never
  handed to another delivery. Endpoints with a TLS pin whitelist get a
  dedicated agent per pin set (so a connection pinned for one whitelist can
  never serve another endpoint's), and the pin is still verified on
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
  origin + pin set + client identity, so a session pinned or authenticated
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
  Invalid option values throw `RangeError` at startup.
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
- `src/server.ts` — a minimal `node:http` receiver: read the raw body, verify
  the `x-signature` header with the injected `verifier` (defaults to
  HMAC-SHA256 with `secret`; pass e.g. `new Ed25519Verifier(pem)` to change
  schemes), or opt into key rotation with `signingKeys` (primary + retired
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
  costs almost nothing), enqueue for forwarding to
  `forwardUrl`, audit accept / delivered / dead-letter events. A failed verification returns 401 + audit entry.
  Operator endpoints `GET /dead-letter` (list dead letters with
  attempts/lastError/timestamp metadata, no raw payloads),
  `POST /dead-letter/:id/replay` (manually re-queue a dead letter, audited as
  `dead_letter_replayed`), and `GET /deliveries/:traceId` (per-trace delivery
  lifecycle snapshot: state machine timeline, retry trajectory with per-attempt
  errors, latency, replay records) are guarded by an `operatorToken` bearer token and
  disabled (404, fail closed) when it is unset. For reconciliation workflows,
  `POST /dead-letter/replay` batch-replays dead letters: the JSON body takes
  `{ endpoint?, ids?, dryRun? }` — `endpoint` limits the replay to one
  downstream, `ids` to an explicit subset, and `dryRun: true` returns only a
  metadata preview (`{ dryRun: true, entries: [...] }` with
  id/endpoint/attempts/lastError/deadLetteredAt/payloadBytes, never the
  payload) with zero side effects: nothing is re-queued, nothing is audited,
  and sealed payloads are never decrypted. A real replay processes the
  matched entries grouped by endpoint, each entry independently (one failure
  cannot stop the others; failures stay dead-lettered), responds
  `{ replayed: [...], failed: [{ id, error }] }`, and is audited as
  `dead_letter_batch_replayed`. The opt-in `autoReplay` server option
  (see *Dead-letter auto-replay* below) replays the whole list on a timer
  with identical fresh-budget semantics, controlled by
  `POST /dead-letter/auto-replay/pause|resume|trigger` and observed via
  `GET /dead-letter/auto-replay/status`. The same guard protects
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
replay the dead-letter list after the process comes back.

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
  audited with the total attempt count. When latency tracking is enabled
  (`retry.latency`), the accepted→delivered delay is sampled into the
  endpoint's distribution, and a delivery slower than `sloMs` is additionally
  audited as `slo_missed` with the measured `latencyMs`.
- `delivering` → **`retrying`** when the attempt fails (non-2xx, timeout,
  or connection error). The next attempt is scheduled after
  `baseDelayMs * 2^attempt` plus jitter, capped at `maxDelayMs`, then the
  item goes back to `delivering`. When the circuit breaker is enabled and
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
  retry budget (see *Failure classification* below).
- `dead_letter` → **`delivering`** (fresh attempt budget) when an operator
  replays it via `POST /dead-letter/:id/replay`, audited as
  `dead_letter_replayed`. A replayed item that fails again walks the same
  `delivering` → `retrying` → `dead_letter` path. The opt-in
  auto-replay scheduler (see *Dead-letter auto-replay* below) replays the
  whole list on a timer with identical fresh-budget semantics.

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
Live-only — no replay of past events; `GET /audit` holds the history.

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
  `rejected`, `duplicate_suppressed`, `slo_missed`, `batch_flushed`,
  plus `retrying` — one line per failed attempt, carrying the error and
  the scheduled delay) — `GET /audit?traceId=<id>` pulls one event's
  whole trail,
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
- `relay_delivery_latency_seconds_{bucket,sum,count}{endpoint}` —
  accepted→delivered latency histogram, only when `retry.latency` is
  enabled; bucket bounds via `retry.metrics.histogramBucketsMs`
  (default 50ms…10s),
- `relay_inbound_version_total{version,status}` — inbound intake by API
  version (`accepted` / `rejected`; `version="none"` for unversioned
  requests), only when `versions` is configured,
- `relay_probe_total{endpoint,result}` — downstream health-probe
  outcomes (`success` / `failure`), only when `probe` is configured,
- `relay_probe_consecutive_failures{endpoint}` — current consecutive
  probe-failure streak per endpoint (0 = healthy), only when `probe` is
  configured,
- `relay_starvation_guard_activations{endpoint}` — starvation-guard
  activation episodes (urgent dispatches deferred while normal demand was
  backlogged), only for endpoints where the guard engaged,
- `relay_retry_budget_depleted_total` — retries parked because the global
  retry budget was exhausted (no endpoint label — the budget is global),
  only when `retry.retryBudget` is enabled.

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
  invalid configs.
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
- `test/latency.test.ts` — `LatencyTracker`: percentiles and SLO attainment
  over known samples, per-endpoint isolation and filtering, bounded rolling
  window eviction, discard/unknown-id no-ops, re-accept restarts the clock,
  backward clock jumps clamped to zero, and `RangeError` on invalid
  configs. Queue integration: accepted→delivered sampling with `onSloMiss`
  firing past the budget, dead-lettered items discarded without sampling,
  and tracking disabled by default.
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
