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
- `src/server.ts` — a minimal `node:http` receiver: read the raw body, verify
  the `x-signature` header with the injected `verifier` (defaults to
  HMAC-SHA256 with `secret`; pass e.g. `new Ed25519Verifier(pem)` to change
  schemes), optionally enforce replay protection (`replay: new ReplayGuard()`
  — replays answer 409, bad/missing nonces and out-of-window timestamps
  answer 400, all audited as `rejected`), enqueue for forwarding to
  `forwardUrl`, audit accept / delivered / dead-letter events. A failed verification returns 401 + audit entry.
  Operator endpoints `GET /dead-letter` (list dead letters with
  attempts/lastError/timestamp metadata, no raw payloads) and
  `POST /dead-letter/:id/replay` (manually re-queue a dead letter, audited as
  `dead_letter_replayed`) are guarded by an `operatorToken` bearer token and
  disabled (404, fail closed) when it is unset. The same guard protects
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
- `received` → **`accepted`** (HTTP 202) when the webhook verifies. The item
  is enqueued for delivery.

**Outbound (delivery side):**

- `accepted` → **`delivering`**: the first attempt starts (a delivery may
  park briefly on a per-endpoint concurrency slot first — still
  `delivering`, just waiting its turn).
- `delivering` → **`delivered`** when the downstream answers 2xx. Done —
  audited with the total attempt count.
- `delivering` → **`retrying`** when the attempt fails (non-2xx, timeout,
  or connection error). The next attempt is scheduled after
  `baseDelayMs * 2^attempt` plus jitter, capped at `maxDelayMs`, then the
  item goes back to `delivering`.
- `delivering` → **`dead_letter`** when `maxAttempts` is exhausted. The
  entry keeps `attempts`, `lastError`, and `deadLetteredAt` — everything an
  operator needs to diagnose it, without the raw payload on the operator
  endpoint.
- `dead_letter` → **`delivering`** (fresh attempt budget) when an operator
  replays it via `POST /dead-letter/:id/replay`, audited as
  `dead_letter_replayed`. A replayed item that fails again walks the same
  `delivering` → `retrying` → `dead_letter` path.

**Shutdown:** SIGTERM moves every `retrying` item straight out of the
machine (dropped, never delivered) while `delivering` items are awaited;
see Graceful shutdown above.

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
  when no guard is injected.
