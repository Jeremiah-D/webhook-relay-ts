import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FieldMask } from "../src/masking.ts";
import { AuditLog } from "../src/audit.ts";
import {
  AesGcmEncryptor,
  randomAes256Key,
  isEncryptedPayload,
  type EncryptedPayload,
} from "../src/encrypt.ts";

const URL = "http://127.0.0.1:9999/hook";
const PAN = "4111111111111111";
const SSN = "123-45-6789";

function jsonMask(rules: Array<{ jsonpath?: string; path?: string; strategy?: "full" | "last4" }>) {
  return new FieldMask({ [URL]: rules });
}

describe("JSONPath parser (WR-191)", () => {
  it("accepts the documented subset", () => {
    const forms = [
      "$",
      "$.payment.card.number",
      "$['a']['b']",
      '$["a"]["b"]',
      "$['a'].b",
      "$.items[0].pan",
      "$.items[*].pan",
      "$.users.*.token",
      "$[*]",
      "$['x-y'].z",
      "$['a.b'].c",
      "$.a[007].b",
    ];
    for (const jsonpath of forms) {
      assert.doesNotThrow(
        () => jsonMask([{ jsonpath }]),
        `valid expression must parse: ${jsonpath}`
      );
    }
  });

  it("rejects mutual exclusion violations between path and jsonpath", () => {
    assert.throws(
      () => jsonMask([{ path: "a", jsonpath: "$.a" } as never]),
      RangeError,
      "both set"
    );
    assert.throws(
      () => jsonMask([{} as never]),
      RangeError,
      "neither set"
    );
    assert.throws(
      () => jsonMask([{ path: undefined, jsonpath: undefined } as never]),
      RangeError,
      "explicitly undefined"
    );
  });

  it("rejects the invalid-expression matrix at construction", () => {
    const bad = [
      "a.b", // must start with $
      "", // empty
      "$x", // junk after root
      "$..a", // recursive descent
      "$..", // recursive descent at end
      "$.", // empty dot segment
      "$.a.", // trailing empty segment
      "$.a..b", // empty middle segment
      "$.a[-1]", // negative index
      "$.a[1:2]", // slice
      "$.a[?(@.x > 1)]", // filter
      "$.a[*].", // trailing dot after wildcard
      "$[", // unclosed bracket
      "$['a", // unclosed quote
      '$["a]', // mismatched quote then junk
      "$[]", // empty brackets
      "$['']", // empty quoted name
      "$.a[ ]", // whitespace-only brackets
      "$.a[ 1]", // whitespace before index
      "$['a'x]", // junk after quoted name
      "$['__proto__']", // forbidden segment (bracket form)
      "$.constructor.x", // forbidden segment (dot form)
      "$.a.prototype", // forbidden segment (leaf form)
      "$.a]", // stray bracket in dot form
    ];
    for (const jsonpath of bad) {
      assert.throws(
        () => jsonMask([{ jsonpath }]),
        RangeError,
        `must reject: ${JSON.stringify(jsonpath)}`
      );
    }
    assert.throws(
      () => jsonMask([{ jsonpath: 42 as unknown as string }]),
      RangeError,
      "non-string expression"
    );
    assert.throws(
      () => jsonMask([{ jsonpath: "$.a", strategy: "sha256" as never }]),
      RangeError,
      "invalid strategy still rejected with jsonpath rules"
    );
  });
});

describe("JSONPath evaluation", () => {
  it("masks nested fields with dot, bracket, and index forms", () => {
    const mask = jsonMask([
      { jsonpath: "$.payment.card.number", strategy: "last4" },
      { jsonpath: "$['meta']['api-key']" },
      { jsonpath: "$.items[1].sku", strategy: "last4" },
    ]);
    const input = {
      payment: { card: { number: PAN, cvv: "123" } },
      meta: { "api-key": "live-key-abc" },
      items: [{ sku: "A1" }, { sku: "SKU-B2-SECRET" }],
    };
    const out = mask.maskJson(URL, input) as Record<string, any>;
    assert.equal(out.payment.card.number, "****1111");
    assert.equal(out.payment.card.cvv, "123");
    assert.equal(out.meta["api-key"], "****");
    assert.equal(out.items[0].sku, "A1");
    assert.equal(out.items[1].sku, "****CRET");
    // Input is never mutated.
    assert.equal(input.payment.card.number, PAN);
    assert.equal(input.items[1].sku, "SKU-B2-SECRET");
  });

  it("expands [*] over array elements and .* over object values", () => {
    const mask = jsonMask([
      { jsonpath: "$.items[*].pan", strategy: "last4" },
      { jsonpath: "$.users.*.token" },
      { jsonpath: "$.tags[*]" },
    ]);
    const input = {
      items: [{ pan: PAN, id: 1 }, { pan: "5555555555554444", id: 2 }, { id: 3 }],
      users: { alice: { token: "tok-alice" }, bob: { token: "tok-bob", role: "admin" } },
      tags: ["alpha", "beta"],
      notes: "not an array",
    };
    const out = mask.maskJson(URL, input) as Record<string, any>;
    assert.equal(out.items[0].pan, "****1111");
    assert.equal(out.items[1].pan, "****4444");
    assert.equal(out.items[0].id, 1);
    assert.equal(out.items[2].id, 3); // no pan: untouched
    assert.equal(out.users.alice.token, "****");
    assert.equal(out.users.bob.token, "****");
    assert.equal(out.users.bob.role, "admin");
    assert.deepEqual(out.tags, ["****", "****"]);
    assert.equal(out.notes, "not an array");
    assert.equal(input.items[0].pan, PAN);
  });

  it("masks a bare [*] over a top-level array and $ over the whole payload", () => {
    const arr = jsonMask([{ jsonpath: "$[*]" }]);
    assert.deepEqual(arr.maskJson(URL, ["a", "b"]), ["****", "****"]);
    const root = jsonMask([{ jsonpath: "$", strategy: "last4" }]);
    assert.equal(root.maskJson(URL, { secret: "x" }), "****");
    const rootStr = jsonMask([{ jsonpath: "$", strategy: "last4" }]);
    assert.equal(rootStr.maskJson(URL, "123456789"), "****6789");
  });

  it("treats missing paths and non-object intermediates as no-ops", () => {
    const mask = jsonMask([
      { jsonpath: "$.missing.deep.path" },
      { jsonpath: "$.items[*].pan" },
      { jsonpath: "$.plain.nested" },
      { jsonpath: "$.items[9].sku" },
    ]);
    const input = {
      plain: "a string, not an object",
      items: [{ sku: "x" }],
    };
    const out = mask.maskJson(URL, input);
    assert.deepEqual(out, input);
    assert.notEqual(out, input); // still a clone
  });

  it("coexists with WR-72 dot-path rules on the same endpoint", () => {
    const mask = new FieldMask({
      [URL]: [
        { path: "card_number", strategy: "last4" },
        { jsonpath: "$.items[*].pan", strategy: "last4" },
      ],
    });
    const out = mask.maskJson(URL, {
      card_number: PAN,
      items: [{ pan: "5555555555554444" }],
    }) as Record<string, any>;
    assert.equal(out.card_number, "****1111");
    assert.equal(out.items[0].pan, "****4444");
  });

  it("last4 degrades safely on short strings, non-strings, and subtrees", () => {
    const mask = jsonMask([
      { jsonpath: "$.short", strategy: "last4" },
      { jsonpath: "$.num", strategy: "last4" },
      { jsonpath: "$.sub", strategy: "last4" },
      { jsonpath: "$.nil" },
    ]);
    const out = mask.maskJson(URL, {
      short: "abc",
      num: 12345,
      sub: { x: 1 },
      nil: null,
    });
    assert.deepEqual(out, { short: "****", num: "****", sub: "****", nil: "****" });
  });

  it("does not mutate or pollute through wildcard expansion", () => {
    const mask = jsonMask([{ jsonpath: "$.*" }]);
    const input = { a: 1 };
    mask.maskJson(URL, input);
    assert.deepEqual(input, { a: 1 });
    assert.equal(({} as Record<string, unknown>).polluted, undefined);
  });
});

describe("AuditLog JSONPath masking (WR-191)", () => {
  function tmpAudit() {
    const dir = mkdtempSync(join(tmpdir(), "jsonmask-"));
    return join(dir, "audit.jsonl");
  }

  it("masks JSONPath-matched PII before plaintext persistence", () => {
    const path = tmpAudit();
    const audit = new AuditLog(path, {
      fieldMask: jsonMask([
        { jsonpath: "$.payment.card.number", strategy: "last4" },
        { jsonpath: "$.users[*].ssn" },
      ]),
    });
    audit.append({
      event: "accepted",
      targetUrl: URL,
      payload: JSON.stringify({
        payment: { card: { number: PAN } },
        users: [{ ssn: SSN }, { name: "plain" }],
      }),
    });
    const raw = readFileSync(path, "utf8");
    assert.ok(!raw.includes(PAN), "raw PAN must never hit disk");
    assert.ok(!raw.includes(SSN), "raw SSN must never hit disk");
    assert.ok(raw.includes("****1111"));
  });

  it("composes with WR-11 encryption: sealed envelope holds masked values only", () => {
    const path = tmpAudit();
    const enc = new AesGcmEncryptor(randomAes256Key());
    const audit = new AuditLog(path, {
      payloadEncryptor: enc,
      fieldMask: jsonMask([
        { jsonpath: "$.payment.card.number", strategy: "last4" },
        { jsonpath: "$.users[*].ssn" },
      ]),
    });
    audit.append({
      event: "accepted",
      targetUrl: URL,
      payload: Buffer.from(
        JSON.stringify({
          payment: { card: { number: PAN } },
          users: [{ ssn: SSN }],
        })
      ),
    });
    // The raw values appear nowhere in the JSONL line — masking ran
    // before the encryptor sealed the envelope.
    const raw = readFileSync(path, "utf8");
    assert.ok(!raw.includes(PAN), "raw PAN must never hit disk");
    assert.ok(!raw.includes(SSN), "raw SSN must never hit disk");
    assert.ok(raw.includes('"payloadEncrypted":true'));
    // readAll transparently decrypts: the payload comes back masked.
    const [entry] = audit.readAll() as Array<Record<string, unknown>>;
    assert.equal(entry.payloadEncrypted, true);
    const buf = Buffer.from((entry.payload as { data: number[] }).data);
    const body = JSON.parse(buf.toString("utf8"));
    assert.equal(body.payment.card.number, "****1111");
    assert.equal(body.users[0].ssn, "****");
    // Belt and braces: the decrypted plaintext itself has no raw value.
    assert.ok(!buf.toString("utf8").includes(PAN));
    assert.ok(!buf.toString("utf8").includes(SSN));
  });

  it("leaves other endpoints and non-JSON payloads alone", () => {
    const path = tmpAudit();
    const audit = new AuditLog(path, {
      fieldMask: jsonMask([{ jsonpath: "$.payment.card.number", strategy: "last4" }]),
    });
    audit.append({
      event: "accepted",
      targetUrl: "http://other/hook",
      payload: JSON.stringify({ payment: { card: { number: PAN } } }),
    });
    audit.append({ event: "accepted", targetUrl: URL, payload: "not json at all" });
    const raw = readFileSync(path, "utf8");
    assert.ok(raw.includes(PAN), "unmasked events still carry the raw value");
    assert.equal(audit.readAll().length, 2);
  });
});
