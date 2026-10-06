# webhook-relay-ts

> **Portfolio reconstruction.** This is a small project built to demonstrate
> webhook-signature verification and delivery-reliability engineering. It is
> not employer production code and re-implements no proprietary system.

A dependency-free TypeScript webhook relay: verify an incoming webhook with
HMAC-SHA256, enqueue it into a retry queue with exponential backoff, forward
it to a downstream URL, and record everything in an append-only audit log.

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

- `src/verify.ts` — parse and verify signature headers in two formats:
  `sha256=<hex>` and `t=<unix_ts>,v1=<hex>` (signature covers `<ts>.<rawBody>`).
  Uses `crypto.timingSafeEqual` and enforces a timestamp tolerance window
  (default 300s).
- `src/retry.ts` — `RetryQueue` with exponential backoff (`base * 2^attempt`)
  plus jitter, a `maxDelay` cap, a dead-letter list after `maxAttempts`, and an
  injectable sender/timer for deterministic testing.
- `src/audit.ts` — append-only JSONL audit log (`append` / `readAll`).
- `src/server.ts` — a minimal `node:http` receiver: read the raw body, verify
  the `x-signature` header (401 + audit entry on failure), enqueue for
  forwarding to `forwardUrl`, audit accept / delivered / dead-letter events.

## Run

```sh
npm test
```

Requires Node 24+ (runs `.ts` directly via type stripping; zero dependencies).

## Test

`npm test` runs the `node:test` suites in `test/`:

- `test/verify.test.ts` — valid signatures pass; tampered body, wrong secret,
  expired timestamp, and missing headers fail.
- `test/retry.test.ts` — a flaky sender (fails twice, then succeeds) delivers
  on the third attempt with increasing backoff; a permanently failing sender
  ends in the dead-letter list.
- `test/server.test.ts` — end-to-end against a local stub HTTP server: a
  valid webhook is forwarded byte-for-byte and audited as delivered; an
  invalid signature returns 401 and is never forwarded.
