/**
 * WR-142 benchmark: brotli wire savings on a realistic webhook payload.
 *
 * Run: `node bench/brotli-bench.ts`
 *
 * Builds the same deterministic Stripe-style payment webhook as
 * `bench/gzip-bench.ts` (~3.5 KiB JSON — representative of a payment
 * callback with nested objects), brotli-compresses it, and reports
 * before/after bytes, the compression ratio, and brotli CPU cost
 * (median of N runs). Numbers quoted in the README come from this
 * script on the machine it ran on.
 */
import { brotliCompressSync, brotliDecompressSync } from "node:zlib";

function buildPayload(): Buffer {
  const items = [];
  for (let i = 0; i < 12; i++) {
    items.push({
      id: `li_3P${i}abcdef${i}`,
      object: "line_item",
      amount: 1999 + i * 137,
      currency: "usd",
      description: `Premium plan — seat ${i + 1} (annual billing, renewed)`,
      quantity: 1,
      metadata: { tenant: `acme-${i % 3}`, region: "us-east-1" },
    });
  }
  const event = {
    id: "evt_3P9xYzAbCdEfGhIjKlMnOpQr",
    object: "event",
    api_version: "2024-06-20",
    created: 1728300000,
    type: "payment_intent.succeeded",
    livemode: false,
    data: {
      object: {
        id: "pi_3P9xYzAbCdEfGhIjKlMnOpQr",
        object: "payment_intent",
        amount: 24988,
        amount_received: 24988,
        currency: "usd",
        customer: "cus_9xYzAbCdEfGhIjK",
        description: "Invoice INV-2024-0917 — Acme Corp annual plan",
        status: "succeeded",
        payment_method: "pm_1P9xYzAbCdEfGhIjK",
        charges: {
          object: "list",
          data: [
            {
              id: "ch_3P9xYzAbCdEfGhIjKlMnOpQr",
              amount: 24988,
              currency: "usd",
              paid: true,
              receipt_url: "https://pay.example.com/receipts/acct_123/ch_3P9xYzAbCdEfGhIjKlMnOpQr",
              billing_details: {
                address: {
                  city: "San Francisco",
                  country: "US",
                  line1: "123 Market Street",
                  postal_code: "94103",
                  state: "CA",
                },
                email: "billing@acme-corp.example.com",
                name: "Acme Corporation",
              },
            },
          ],
        },
        metadata: { invoice_id: "INV-2024-0917", tenant: "acme", plan: "premium-annual" },
      },
    },
    items,
  };
  return Buffer.from(JSON.stringify(event), "utf8");
}

const payload = buildPayload();
// Sanity: round-trip must be byte-identical.
const br = brotliCompressSync(payload);
if (!brotliDecompressSync(br).equals(payload)) throw new Error("brotli round-trip mismatch");

const RUNS = 2000;
const times: number[] = [];
for (let i = 0; i < RUNS; i++) {
  const t0 = process.hrtime.bigint();
  brotliCompressSync(payload);
  times.push(Number(process.hrtime.bigint() - t0) / 1000);
}
times.sort((a, b) => a - b);
const p50 = times[Math.floor(times.length * 0.5)];

console.log(`node ${process.version} · ${process.arch}`);
console.log(`payload: ${payload.length} bytes -> brotli: ${br.length} bytes`);
console.log(`ratio: ${(br.length / payload.length).toFixed(3)} (${(payload.length / br.length).toFixed(1)}x smaller)`);
console.log(`brotli p50: ${p50.toFixed(1)} us`);
