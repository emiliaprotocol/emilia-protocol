// SPDX-License-Identifier: Apache-2.0
// Unit tests for the JavaScript CAID port: host values, the strict JSON text
// decoder, limits, definitions, reason order, verify details, parse, and the
// mapping profile. Run with: node --test caid/impl/js/unit-tests.mjs
//
// The file is not named *.test.mjs so the repository's Vitest collector
// leaves it to Node's built-in runner.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  CAID_SPEC,
  canonicalize,
  computeCaid,
  computeCaidJson,
  decodeCaidDocument,
  decodeCaidJson,
  definitionSha256,
  parseCaid,
  resolveCaidDefinition,
  toCaidData,
  verifyCaid,
  verifyCaidJson,
} from "./caid.mjs";
import { compareMappedActions, mapAction, mappingProfileHash } from "./mapping.mjs";

const ROOT = new URL("../../../", import.meta.url);
const S = "jcs-sha256";
const DEF = {
  action_type: "test.unit.1",
  required_fields: [{ name: "a", type: "string" }],
  optional_fields: [
    { name: "n", type: "integer" },
    { name: "o", type: "object" },
    { name: "l", type: "array" },
  ],
};
const DEFS = [DEF];
const OPTS = { suite: S, definitions: DEFS };
const text = (s) => Buffer.from(s, "utf8");
const bare = (extra = {}) => ({ action_type: "test.unit.1", a: "x", ...extra });
const refusalsOf = (r) => r.refusals;

// ---------------------------------------------------------------------------
// Host values
// ---------------------------------------------------------------------------

test("a cyclic object or array refuses as unsupported_value and never throws", () => {
  const o = bare();
  o.o = { self: null };
  o.o.self = o.o;
  assert.deepEqual(refusalsOf(computeCaid(o, OPTS)), ["unsupported_value"]);
  const arr = [];
  arr.push(arr);
  assert.deepEqual(refusalsOf(computeCaid(bare({ l: arr }), OPTS)), ["unsupported_value"]);
  const top = bare();
  top.o = top;
  // The declared object field holds the cycle itself, so it is also mistyped.
  assert.deepEqual(refusalsOf(computeCaid(top, OPTS)), ["mistyped_field:o", "unsupported_value"]);
  assert.deepEqual(canonicalize(top), { ok: false, refusals: ["unsupported_value"] });
  const v = verifyCaid(top, "caid:1:test.unit.1:jcs-sha256:" + "A".repeat(43), { definitions: DEFS });
  assert.deepEqual(v.reasons, ["invalid_object"]);
});

test("Map, Set, Date, typed arrays, boxed primitives and class instances are refused, never rewritten", () => {
  const plain = computeCaid(bare({ o: {} }), OPTS);
  assert.ok(plain.caid);
  class K {
    constructor() {
      this.a = 1;
    }
  }
  for (const host of [new Map([["k", "v"]]), new Set([1]), new Date(0), new Uint8Array([1, 2]), new K(), new String("s"), Object(1n)]) {
    const r = computeCaid(bare({ o: host }), OPTS);
    assert.deepEqual(r.refusals, ["mistyped_field:o", "unsupported_value"], String(host));
    assert.deepEqual(refusalsOf(computeCaid(host, OPTS)), ["invalid_action_type"]);
    assert.deepEqual(canonicalize({ x: host }), { ok: false, refusals: ["unsupported_value"] });
  }
  // A Map as an undeclared member refuses the value too; it never becomes {}.
  assert.deepEqual(refusalsOf(computeCaid(bare({ extra: new Map([["k", "v"]]) }), OPTS)), ["unsupported_value"]);
});

test("getters are never invoked; a throwing getter refuses without throwing", () => {
  let calls = 0;
  const counting = bare();
  Object.defineProperty(counting, "extra", { enumerable: true, get() { calls += 1; return 1; } });
  assert.deepEqual(refusalsOf(computeCaid(counting, OPTS)), ["unsupported_value"]);
  assert.equal(calls, 0);
  const throwing = bare();
  Object.defineProperty(throwing, "a", { enumerable: true, get() { throw new Error("boom"); } });
  const r = computeCaid(throwing, OPTS);
  assert.deepEqual(r.refusals, ["mistyped_field:a", "unsupported_value"]);
  const v = verifyCaid(throwing, "caid:1:test.unit.1:jcs-sha256:" + "A".repeat(43), { definitions: DEFS });
  assert.deepEqual(v.reasons, ["invalid_object"]);
  assert.deepEqual(v.details, [
    { reason: "mistyped_field:a", field: "a", rule: "field-type", observed: "unsupported" },
    { reason: "unsupported_value", field: null, rule: "data-model", observed: null },
  ]);
});

test("a Proxy refuses without throwing, whether its traps throw, lie, or are transparent", () => {
  const throwing = new Proxy(bare(), { ownKeys() { throw new Error("trap"); } });
  assert.deepEqual(refusalsOf(computeCaid(throwing, OPTS)), ["invalid_action_type"]);
  const transparent = new Proxy(bare(), {});
  assert.deepEqual(refusalsOf(computeCaid(transparent, OPTS)), ["unsupported_value"]);
  const nested = bare({ o: new Proxy({ k: 1 }, {}) });
  assert.deepEqual(refusalsOf(computeCaid(nested, OPTS)), ["unsupported_value"]);
  const lyingMap = new Proxy(new Map([["k", "v"]]), { getPrototypeOf: () => Object.prototype });
  assert.deepEqual(refusalsOf(computeCaid(bare({ o: lyingMap }), OPTS)), ["unsupported_value"]);
  const revocable = Proxy.revocable({}, {});
  revocable.revoke();
  assert.deepEqual(refusalsOf(computeCaid(bare({ o: revocable.proxy }), OPTS)), ["mistyped_field:o", "unsupported_value"]);
  assert.doesNotThrow(() => computeCaid(bare(), new Proxy({}, { getOwnPropertyDescriptor() { throw new Error("x"); } })));
});

test("non-enumerable, symbol-keyed, sparse and decorated values are refused", () => {
  const hidden = bare();
  Object.defineProperty(hidden, "h", { value: 1, enumerable: false });
  assert.deepEqual(refusalsOf(computeCaid(hidden, OPTS)), ["unsupported_value"]);
  const hiddenField = bare();
  Object.defineProperty(hiddenField, "n", { value: 1, enumerable: false });
  assert.deepEqual(refusalsOf(computeCaid(hiddenField, OPTS)), ["mistyped_field:n", "unsupported_value"]);
  assert.deepEqual(refusalsOf(computeCaid({ ...bare(), [Symbol("s")]: 1 }, OPTS)), ["invalid_action_type"]);
  assert.deepEqual(refusalsOf(computeCaid(bare({ o: { [Symbol("s")]: 1 } }), OPTS)), ["mistyped_field:o", "unsupported_value"]);
  // eslint-disable-next-line no-sparse-arrays
  assert.deepEqual(refusalsOf(computeCaid(bare({ l: [1, , 3] }), OPTS)), ["unsupported_value"]);
  const decorated = [1];
  decorated.extra = 2;
  assert.deepEqual(refusalsOf(computeCaid(bare({ l: decorated }), OPTS)), ["mistyped_field:l", "unsupported_value"]);
  for (const junk of [() => 1, Symbol("s"), 1n]) {
    assert.deepEqual(refusalsOf(computeCaid(bare({ extra: junk }), OPTS)), ["unsupported_value"]);
  }
});

test("an undefined member is absent; an undefined array element is unsupported_value", () => {
  assert.equal(computeCaid(bare({ n: undefined }), OPTS).caid, computeCaid(bare(), OPTS).caid);
  assert.deepEqual(refusalsOf(computeCaid(bare({ l: [undefined] }), OPTS)), ["unsupported_value"]);
});

test("__proto__ is an ordinary own member in both entry points", () => {
  const fromText = decodeCaidJson(text('{"action_type":"test.unit.1","a":"x","__proto__":{"p":1}}'));
  assert.equal(fromText.ok, true);
  assert.ok(Object.prototype.hasOwnProperty.call(fromText.value, "__proto__"));
  assert.equal(Object.getPrototypeOf(fromText.value), Object.prototype);
  const native = bare();
  Object.defineProperty(native, "__proto__", { value: { p: 1 }, enumerable: true, writable: true, configurable: true });
  const a = computeCaid(native, OPTS);
  const b = computeCaidJson(text('{"action_type":"test.unit.1","a":"x","__proto__":{"p":1}}'), OPTS);
  assert.ok(a.caid);
  assert.deepEqual(a, b);
  assert.notEqual(a.caid, computeCaid(bare(), OPTS).caid);
  assert.equal(canonicalize(native).canonical, '{"__proto__":{"p":1},"a":"x","action_type":"test.unit.1"}');
});

test("null-prototype objects are plain objects", () => {
  const o = Object.assign(Object.create(null), bare());
  assert.equal(computeCaid(o, OPTS).caid, computeCaid(bare(), OPTS).caid);
});

test("nesting: depth 64 computes, 65 is unsupported_value, 5000 never throws", () => {
  const nest = (n) => {
    let v = 0;
    for (let i = 0; i < n; i++) v = [v];
    return v;
  };
  // The action object is depth 1, so its member may nest 63 more levels.
  assert.ok(computeCaid(bare({ l: nest(63) }), OPTS).caid);
  assert.deepEqual(refusalsOf(computeCaid(bare({ l: nest(64) }), OPTS)), ["unsupported_value"]);
  assert.deepEqual(refusalsOf(computeCaid(bare({ l: nest(5000) }), OPTS)), ["unsupported_value"]);
  assert.deepEqual(canonicalize(nest(64)), { ok: true, canonical: "[".repeat(64) + "0" + "]".repeat(64) });
  assert.deepEqual(canonicalize(nest(65)), { ok: false, refusals: ["unsupported_value"] });
});

test("a host value whose shared references fan out is refused in bounded time", () => {
  let v = { leaf: "x".repeat(64) };
  for (let i = 0; i < 40; i++) v = { a: v, b: v };
  const t0 = Date.now();
  assert.deepEqual(refusalsOf(computeCaid(bare({ o: v }), OPTS)), ["unsupported_value"]);
  assert.ok(Date.now() - t0 < 20000);
});

test("toCaidData copies the data model and refuses anything outside it", () => {
  const r = toCaidData({ a: [1, "b", null, { c: true }] });
  assert.deepEqual(r, { ok: true, value: { a: [1, "b", null, { c: true }] } });
  assert.deepEqual(toCaidData({ d: new Date(0) }), { ok: false, refusals: ["unsupported_value"] });
});

// ---------------------------------------------------------------------------
// JSON text
// ---------------------------------------------------------------------------

const refusedJson = { ok: false, refusals: ["malformed_json"] };

test("byte entry points take octets only", () => {
  assert.deepEqual(computeCaidJson('{"action_type":"test.unit.1","a":"x"}', OPTS), { refusals: ["malformed_json"] });
  assert.deepEqual(decodeCaidJson(new ArrayBuffer(2)), refusedJson);
  assert.deepEqual(decodeCaidJson(new DataView(new ArrayBuffer(2))), refusedJson);
  assert.deepEqual(decodeCaidJson(new Uint16Array(2)), refusedJson);
  assert.deepEqual(decodeCaidJson(undefined), refusedJson);
  assert.deepEqual(decodeCaidJson(new Proxy(new Uint8Array(text("1")), {})), refusedJson);
  assert.deepEqual(decodeCaidJson(new Uint8Array(text("1"))), { ok: true, value: 1 });
  assert.deepEqual(decodeCaidJson(text("1")), { ok: true, value: 1 });
});

test("the decoder refuses every departure from the profile as malformed_json", () => {
  const bad = [
    '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"x":{"b":1,"b":1}}',
    '{"a":"\\ud800"}', '{"a":"\\udc00"}', '{"a":"\\ud800\\u0041"}', '{"a":"\\ud800"', '{"a":"\\uD800x"}',
    '{"a":"\\uffff"}', '{"a":"\\ufdd0"}', '{"\\ufffe":1}', '{"a":"\\ud83f\\udffe"}', '{"a":"\\udbff\\udfff"}',
    '{"a":"\u0001"}', '{"a":1} x', "{} {}", '{"a":1,}', "[1,]", '{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}',
    '{"a":01}', '{"a":1.}', '{"a":.5}', '{"a":+1}', '{"a":1e}', "", " ", "{'a':1}", '{"a":tru}', '{"a"1}',
    '{"a":"\\x"}', '{"a":"\\u12G4"}', "[" + "[".repeat(64) + "]".repeat(65),
  ];
  for (const s of bad) assert.deepEqual(decodeCaidJson(text(s)), refusedJson, JSON.stringify(s));
  const bytes = [
    [0xef, 0xbb, 0xbf, ...text("{}")], // byte order mark
    [...Buffer.from("{}", "utf16le")],
    [...text('{"a":"'), 0xe9, ...text('"}')], // invalid UTF-8
    [...text('{"a":"'), 0xc0, 0xaf, ...text('"}')], // overlong
    [...text('{"a":"'), 0xed, 0xa0, 0x80, ...text('"}')], // encoded surrogate
    [...text('{"a":"'), 0xf4, 0x90, 0x80, 0x80, ...text('"}')], // above U+10FFFF
    [...text('{"a":"'), 0xef, 0xb7, 0x90, ...text('"}')], // U+FDD0 literal
    [...text('{"a":"'), 0xf0, 0x9f, 0xbf, 0xbf, ...text('"}')], // U+1FFFF literal
    [...text('{"a":"'), 0xe2, 0x82], // truncated sequence
  ];
  for (const b of bytes) assert.deepEqual(decodeCaidJson(new Uint8Array(b)), refusedJson, JSON.stringify(b));
});

test("the decoder accepts what the profile allows", () => {
  const ok = (s, v) => assert.deepEqual(decodeCaidJson(text(s)), { ok: true, value: v });
  ok(' \t\r\n{"a":[1,true,false,null,"s"]} \n', { a: [1, true, false, null, "s"] });
  ok('"\\ud83d\\ude00"', "\u{1F600}");
  ok('"\\"\\\\\\/\\b\\f\\n\\r\\t\\u0000"', "\"\\/\b\f\n\r\t\u0000");
  ok('"é😀"', "é😀");
  ok("[" + "[".repeat(63) + "]".repeat(64), JSON.parse("[" + "[".repeat(63) + "]".repeat(64)));
  ok("-0", -0);
  ok("1e400", Infinity);
  ok("1e-400", 0);
  ok("1".repeat(5000), Infinity);
});

test("JSON text size: the cap applies to action objects, not to documents", () => {
  const cap = CAID_SPEC.limits.json_text_octets;
  const at = Buffer.alloc(cap, 0x20);
  at[0] = 0x30; // "0" followed by whitespace
  assert.deepEqual(decodeCaidJson(at), { ok: true, value: 0 });
  const over = Buffer.alloc(cap + 1, 0x20);
  over[0] = 0x30;
  assert.deepEqual(decodeCaidJson(over), refusedJson);
  assert.deepEqual(decodeCaidDocument(over), { ok: true, value: 0 });
});

test("numbers follow the value rule on both paths", () => {
  const withN = (lit) => computeCaidJson(text(`{"action_type":"test.unit.1","a":"x","n":${lit}}`), OPTS);
  assert.equal(withN("-0").caid, withN("0").caid);
  assert.equal(withN("1e-400").caid, withN("0").caid);
  assert.equal(withN("1.2e1").caid, withN("12").caid);
  assert.equal(withN("12.0").caid, withN("12").caid);
  assert.deepEqual(withN("1e400").refusals, ["mistyped_field:n", "unsupported_number"]);
  assert.deepEqual(withN("1".repeat(5000)).refusals, ["mistyped_field:n", "unsupported_number"]);
  assert.deepEqual(withN("1.5").refusals, ["mistyped_field:n", "unsupported_number"]);
  assert.deepEqual(withN("9007199254740992").refusals, ["unsupported_number"]);
  assert.ok(withN("9007199254740991").caid);
  assert.equal(withN("0.99999999999999999999").caid, withN("1").caid);
});

test("byte and native paths agree on every decodable text", () => {
  const texts = [
    '{"action_type":"test.unit.1","a":"x"}',
    '{"action_type":"test.unit.1","a":"x","o":{"z":[1,{"y":null}]},"l":[]}',
    '{"action_type":"test.unit.1","a":1}',
    '{"action_type":"test.unit.1"}',
    "[]",
    '{"action_type":"Bad"}',
  ];
  for (const s of texts) {
    const decoded = decodeCaidJson(text(s));
    assert.deepEqual(computeCaidJson(text(s), OPTS), computeCaid(decoded.value, OPTS), s);
  }
});

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

test("a malformed definition refuses as invalid_definition", () => {
  const cases = [
    { action_type: "test.unit.1" },
    { action_type: "test.unit.1", required_fields: [] },
    { action_type: "test.unit.1", required_fields: "a" },
    { action_type: "test.unit.1", required_fields: ["a"] },
    { action_type: "test.unit.1", required_fields: [{ nmae: "a", type: "string" }] },
    { action_type: "test.unit.1", required_fields: [{ name: 1, type: "string" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "a:b", type: "string" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "", type: "string" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "action_type", type: "string" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "\ud800", type: "string" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "a", type: "string" }], optional_fields: [{ name: "a", type: "integer" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "a", type: "string", pattern: "x" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "a" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "a", type: "string" }], optional_fields: {} },
    { action_type: "test.unit.1", required_fields: [{ name: "a", type: "code", code_system: "urn:x" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "a", type: "code", code_system: "no colon", format: "cpt" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "a", type: "code", code_system: "urn:x", format: "CPT" }] },
    { action_type: "test.unit.1", required_fields: [{ name: "a", type: "enum", values: [1.5] }] },
  ];
  for (const d of cases) {
    assert.deepEqual(computeCaid(bare(), { suite: S, definitions: [d] }), { refusals: ["invalid_definition"] }, JSON.stringify(d));
    assert.deepEqual(definitionSha256(d), { refusals: ["invalid_definition"] }, JSON.stringify(d));
  }
});

test("field names: any scalar values except ':', not action_type", () => {
  for (const name of ["@version", "café", "a b", "__proto__", "toString", "x\n", "\u{1F600}"]) {
    const d = { action_type: "test.unit.1", required_fields: [{ name, type: "string" }] };
    const o = { action_type: "test.unit.1" };
    Object.defineProperty(o, name, { value: "v", enumerable: true, writable: true, configurable: true });
    assert.ok(computeCaid(o, { suite: S, definitions: [d] }).caid, name);
    assert.deepEqual(computeCaid({ action_type: "test.unit.1" }, { suite: S, definitions: [d] }).refusals, ["missing_material_field:" + name]);
  }
});

test("conflicting definitions refuse in either order; equal projections resolve once", () => {
  const other = { action_type: "test.unit.1", required_fields: [{ name: "a", type: "integer" }] };
  assert.deepEqual(computeCaid(bare(), { suite: S, definitions: [DEF, other] }), { refusals: ["invalid_definition"] });
  assert.deepEqual(computeCaid(bare(), { suite: S, definitions: [other, DEF] }), { refusals: ["invalid_definition"] });
  const annotated = {
    ...DEF,
    status: "deprecated",
    summary: "s",
    superseded_by: "test.unit.2",
    required_fields: [{ ...DEF.required_fields[0], notes: "differs" }],
  };
  const a = computeCaid(bare(), { suite: S, definitions: [DEF, annotated] });
  assert.deepEqual(a, computeCaid(bare(), OPTS));
  assert.equal(definitionSha256(annotated).definition_sha256, definitionSha256(DEF).definition_sha256);
  // A nonconforming candidate refuses even beside a conforming one.
  assert.deepEqual(computeCaid(bare(), { suite: S, definitions: [DEF, { action_type: "test.unit.1" }] }), { refusals: ["invalid_definition"] });
  // Entries for other types never matter.
  assert.ok(computeCaid(bare(), { suite: S, definitions: [{ action_type: "other.1" }, DEF] }).caid);
});

test("an unregistered field type conforms and refuses only when present", () => {
  const d = { action_type: "test.unit.1", required_fields: [{ name: "a", type: "string" }], optional_fields: [{ name: "q", type: "future-type", anything: 1 }] };
  assert.ok(computeCaid(bare(), { suite: S, definitions: [d] }).caid);
  assert.deepEqual(computeCaid(bare({ q: "v" }), { suite: S, definitions: [d] }).refusals, ["mistyped_field:q"]);
});

test("definition_sha256 matches caid/registry/digests.json for every registered type", () => {
  const registry = JSON.parse(readFileSync(new URL("caid/registry/action-types.json", ROOT), "utf8"));
  const digests = JSON.parse(readFileSync(new URL("caid/registry/digests.json", ROOT), "utf8"));
  const table = new Map((digests.types ?? digests.digests ?? []).map((e) => [e.action_type, e.definition_sha256]));
  assert.equal(table.size, registry.types.length);
  for (const t of registry.types) {
    assert.deepEqual(definitionSha256(t), { definition_sha256: table.get(t.action_type) }, t.action_type);
    const resolved = resolveCaidDefinition(t.action_type, registry.types);
    assert.equal(resolved.ok, true, t.action_type);
    assert.equal(resolved.definition_sha256, table.get(t.action_type));
  }
});

test("compute and verify report definition_sha256", () => {
  const c = computeCaid(bare(), OPTS);
  assert.deepEqual(Object.keys(c), ["caid", "digest", "definition_sha256"]);
  assert.equal(c.definition_sha256, definitionSha256(DEF).definition_sha256);
  const v = verifyCaid(bare(), c.caid, { definitions: DEFS });
  assert.deepEqual(v, { valid: true, reasons: [], details: [], definition_sha256: c.definition_sha256 });
  const pinned = verifyCaid(bare(), c.caid, { definitions: DEFS, expectedDefinitionSha256: c.definition_sha256 });
  assert.equal(pinned.valid, true);
  const wrong = verifyCaid(bare(), c.caid, { definitions: DEFS, expectedDefinitionSha256: "sha256:" + "0".repeat(64) });
  assert.deepEqual(wrong.reasons, ["definition_mismatch"]);
  assert.deepEqual(wrong.details, [{ reason: "definition_mismatch", field: null, rule: "definition-sha256", observed: null }]);
  // No resolved definition: no definition_sha256 and no definition_mismatch.
  const unknown = verifyCaid(bare(), c.caid, { definitions: [], expectedDefinitionSha256: c.definition_sha256 });
  assert.deepEqual(unknown.reasons, ["invalid_object"]);
  assert.equal("definition_sha256" in unknown, false);
});

// ---------------------------------------------------------------------------
// Field types
// ---------------------------------------------------------------------------

test("code fields: named formats, exact string, no normalization", () => {
  const d = {
    action_type: "test.code.1",
    required_fields: [{ name: "dx", type: "code", code_system: "http://hl7.org/fhir/sid/icd-10-cm", format: "icd-10-cm" }],
    optional_fields: [
      { name: "ndc", type: "code", code_system: "http://hl7.org/fhir/sid/ndc", format: "ndc-11" },
      { name: "later", type: "code", code_system: "urn:example", format: "not-yet-registered" },
    ],
  };
  const run = (o) => computeCaid({ action_type: "test.code.1", ...o }, { suite: S, definitions: [d] });
  assert.ok(run({ dx: "E11.9" }).caid);
  assert.ok(run({ dx: "E11" }).caid);
  for (const bad of ["e11.9", " E11.9", "E11.9 ", "E119.", "E11.12345", "", "E1"]) {
    assert.deepEqual(run({ dx: bad }).refusals, ["invalid_code:dx"], bad);
  }
  assert.deepEqual(run({ dx: 119 }).refusals, ["mistyped_field:dx"]);
  assert.deepEqual(run({ dx: "E11", ndc: "0002-8215-01" }).refusals, ["invalid_code:ndc"]);
  assert.deepEqual(run({ dx: "E11", later: "A" }).refusals, ["mistyped_field:later"]);
  assert.ok(run({ dx: "E11", ndc: "00002821501" }).caid);
});

test("timestamps: uppercase T and Z, no second 60, day within the month", () => {
  const d = { action_type: "test.ts.1", required_fields: [{ name: "t", type: "timestamp" }] };
  const run = (t) => computeCaid({ action_type: "test.ts.1", t }, { suite: S, definitions: [d] });
  assert.ok(run("2024-02-29T00:00:00Z").caid);
  assert.ok(run("0000-01-01T23:59:59.000Z").caid);
  assert.notEqual(run("2024-01-01T00:00:00.000Z").caid, run("2024-01-01T00:00:00Z").caid);
  for (const bad of ["2023-02-29T00:00:00Z", "2024-04-31T00:00:00Z", "2024-01-01t00:00:00Z", "2024-01-01T00:00:00z", "2024-01-01T00:00:60Z", "2024-01-01T00:00:00+00:00"]) {
    assert.deepEqual(run(bad).refusals, ["mistyped_field:t"], bad);
  }
});

test("enum values: inline, embedded and snapshot forms", () => {
  const inline = { action_type: "test.e.1", required_fields: [{ name: "c", type: "enum", values_ref: "inline: red | blue" }] };
  assert.ok(computeCaid({ action_type: "test.e.1", c: "red" }, { suite: S, definitions: [inline] }).caid);
  assert.deepEqual(computeCaid({ action_type: "test.e.1", c: "green" }, { suite: S, definitions: [inline] }).refusals, ["mistyped_field:c"]);
  const iso = JSON.parse(readFileSync(new URL("caid/registry/value-sets/iso-4217-alpha-3.2026-09-17.json", ROOT), "utf8"));
  const pinned = { action_type: "test.e.2", required_fields: [{ name: "c", type: "enum", values_ref: iso.values_ref, values_snapshot: iso.values_snapshot, values_sha256: iso.values_sha256 }] };
  assert.ok(computeCaid({ action_type: "test.e.2", c: "EUR" }, { suite: S, definitions: [pinned], enumSnapshots: [iso] }).caid);
  assert.deepEqual(computeCaid({ action_type: "test.e.2", c: "EUR" }, { suite: S, definitions: [pinned] }).refusals, ["mistyped_field:c"]);
});

// ---------------------------------------------------------------------------
// Reason order
// ---------------------------------------------------------------------------

test("gates yield one reason; every later check runs in rank then field order", () => {
  const d = {
    action_type: "test.order.1",
    required_fields: [
      { name: "m", type: "string" },
      { name: "amt", type: "amount-string" },
      { name: "code", type: "code", code_system: "urn:x", format: "nacha-sec" },
    ],
    optional_fields: [{ name: "i", type: "integer" }],
  };
  const o = { action_type: "test.order.1", amt: "1.", code: "ppd", i: "7", deep: [1.5, "\ud800"] };
  assert.deepEqual(computeCaid(o, { suite: "x", definitions: [d] }).refusals, [
    "missing_material_field:m", "invalid_amount:amt", "invalid_code:code", "mistyped_field:i",
    "unknown_suite", "unsupported_number", "unsupported_value",
  ]);
  assert.deepEqual(computeCaid({ action_type: "Bad", amt: 1.5 }, { suite: "x", definitions: [d] }).refusals, ["invalid_action_type"]);
  assert.deepEqual(computeCaid({ action_type: "no.such.1", amt: 1.5 }, { suite: "x", definitions: [d] }).refusals, ["unknown_action_type"]);
});

test("unsupported_number precedes unsupported_value whatever the traversal order", () => {
  const o = bare({ o: { "\ud800": 1, "": 1.5 } });
  assert.deepEqual(computeCaid(o, OPTS).refusals, ["unsupported_number", "unsupported_value"]);
  const p = bare({ o: { "": "\ud800", "\ud800": 1.5 } });
  assert.deepEqual(computeCaid(p, OPTS).refusals, ["unsupported_number", "unsupported_value"]);
});

test("options of the wrong type count as absent and never throw", () => {
  assert.deepEqual(computeCaid(bare(), { suite: ["jcs-sha256"], definitions: DEFS }).refusals, ["unknown_suite"]);
  assert.deepEqual(computeCaid(bare(), { suite: S, definitions: "x" }).refusals, ["unknown_action_type"]);
  assert.deepEqual(computeCaid(bare(), null).refusals, ["unknown_action_type"]);
  const tricky = {};
  Object.defineProperty(tricky, "definitions", { enumerable: true, get() { throw new Error("no"); } });
  assert.deepEqual(computeCaid(bare(), tricky).refusals, ["unknown_action_type"]);
});

// ---------------------------------------------------------------------------
// Parse and verify
// ---------------------------------------------------------------------------

test("parse: grammar, then suite registration, then digest syntax", () => {
  const d = "A".repeat(43);
  assert.deepEqual(parseCaid(`caid:1:a.1:jcs-sha512:${d}`), { ok: false, refusals: ["unknown_suite"] });
  assert.deepEqual(parseCaid(`caid:1:a.1:foo:${d}`), { ok: false, refusals: ["unknown_suite"] });
  assert.deepEqual(parseCaid(`caid:1:a.1:jcs-sha512:x`), { ok: false, refusals: ["unknown_suite"] });
  assert.deepEqual(parseCaid(`caid:1:a.1:jcs-sha256:x`), { ok: false, refusals: ["malformed_caid"] });
  assert.deepEqual(parseCaid(`caid:1:a.1:jcs-sha256:${"A".repeat(42)}B`), { ok: false, refusals: ["malformed_caid"] });
  assert.deepEqual(parseCaid(`CAID:1:a.1:jcs-sha256:${d}`), { ok: false, refusals: ["malformed_caid"] });
  assert.deepEqual(parseCaid(`caid:1:a.1:jcs-sha256:${d}\n`), { ok: false, refusals: ["malformed_caid"] });
  assert.deepEqual(parseCaid(`caid:1:a.1:cbor-sha256:${d}`), { ok: true, caid: { version: "1", action_type: "a.1", suite: "cbor-sha256", digest: d } });
  assert.deepEqual(parseCaid(42), { ok: false, refusals: ["malformed_caid"] });
});

test("verify: gates, closed-shape details, and the byte path", () => {
  const c = computeCaid(bare(), OPTS);
  assert.deepEqual(verifyCaid(bare(), 7, { definitions: DEFS }), {
    valid: false, reasons: ["malformed_caid"], details: [{ reason: "malformed_caid", field: null, rule: "caid", observed: "number" }],
  });
  assert.deepEqual(verifyCaid(bare(), `caid:1:test.unit.1:jcs-sha512:${"A".repeat(43)}`, { definitions: DEFS }), {
    valid: false, reasons: ["unknown_suite"], details: [{ reason: "unknown_suite", field: null, rule: "suite", observed: null }],
  });
  assert.deepEqual(verifyCaid("str", c.caid, { definitions: DEFS }), {
    valid: false, reasons: ["invalid_object"], details: [{ reason: "invalid_action_type", field: "action_type", rule: "action-type", observed: "string" }],
  });
  const r = verifyCaid({ action_type: "test.unit.1", n: 1.5 }, c.caid, { definitions: DEFS });
  // The object does not canonicalize, so no digest comparison is made.
  assert.deepEqual(r.reasons, ["invalid_object"]);
  assert.deepEqual(r.details, [
    { reason: "missing_material_field:a", field: "a", rule: "required-field", observed: "absent" },
    { reason: "mistyped_field:n", field: "n", rule: "field-type", observed: "number" },
    { reason: "unsupported_number", field: null, rule: "number", observed: null },
  ]);
  const cbor = verifyCaid(bare(), c.caid.replace(S, "cbor-sha256"), { definitions: DEFS });
  assert.deepEqual(cbor.reasons, ["unknown_suite"]);
  const other = verifyCaid(bare({ n: 1 }), c.caid, { definitions: DEFS });
  assert.deepEqual(other.reasons, ["digest_mismatch"]);
  // Byte path: parse first, then decode.
  assert.deepEqual(verifyCaidJson(text("{"), "bad", { definitions: DEFS }).reasons, ["malformed_caid"]);
  assert.deepEqual(verifyCaidJson(text('{"a":1,"a":1}'), c.caid, { definitions: DEFS }), {
    valid: false, reasons: ["malformed_json"], details: [{ reason: "malformed_json", field: null, rule: "json-text", observed: null }],
  });
  assert.deepEqual(verifyCaidJson(text(JSON.stringify(bare())), c.caid, { definitions: DEFS }), verifyCaid(bare(), c.caid, { definitions: DEFS }));
});

test("verify details carry exactly the four members for every reason", () => {
  for (const code of CAID_SPEC.reasons) {
    if (code === "invalid_object") continue;
    assert.ok(CAID_SPEC.verify_details.reasons[code], code);
  }
  const r = verifyCaid({ action_type: 5 }, computeCaid(bare(), OPTS).caid, { definitions: DEFS });
  for (const d of r.details) assert.deepEqual(Object.keys(d), ["reason", "field", "rule", "observed"]);
});

test("canonical size: at most 16 MiB of RFC 8785 output", () => {
  const cap = CAID_SPEC.limits.canonical_octets;
  const base = canonicalize(bare({ o: { b: "" } })).canonical.length;
  const at = bare({ o: { b: "y".repeat(cap - base) } });
  assert.ok(computeCaid(at, OPTS).caid);
  const over = bare({ o: { b: "y".repeat(cap - base + 1) } });
  assert.deepEqual(computeCaid(over, OPTS).refusals, ["unsupported_value"]);
  // canonicalize itself is for any document and has no size cap.
  assert.equal(canonicalize(over).ok, true);
  // The size is checked only when nothing else refused.
  assert.deepEqual(computeCaid(bare({ o: { b: "y".repeat(cap), n: 1.5 } }), OPTS).refusals, ["unsupported_number"]);
});

// ---------------------------------------------------------------------------
// Mapping profile
// ---------------------------------------------------------------------------

const MAP_DEF = {
  action_type: "map.unit.1",
  required_fields: [{ name: "amount", type: "amount-string" }, { name: "ref", type: "digest" }],
  optional_fields: [{ name: "memo", type: "string" }],
};
const PROFILE = () => ({
  "@version": "CAID-MAPPING-PROFILE-v1",
  profile_id: "unit",
  source_format: { media_type: "application/json", schema: "unit", version: "1" },
  target_action_type: "map.unit.1",
  loss_policy: "no-material-field-loss",
  material_source_paths: ["/amt", "/h"],
  rules: [
    { source_path: "/amt", target_field: "amount", transform: "copy" },
    { source_path: "/h", target_field: "ref", transform: "sha256-hex-to-digest" },
  ],
});
const SOURCE = { amt: "1.00", h: "a".repeat(64), noise: 1 };
const map = (profile, source = SOURCE, extra = {}) => mapAction(source, {
  profile,
  sourceDescriptor: profile.source_format,
  expectedProfileHash: mappingProfileHash(profile),
  nativeVerified: true,
  definitions: [MAP_DEF],
  ...extra,
});
const reasons = (r) => (r.ok ? [] : r.reasons);

test("mapping: a valid profile maps and computes", () => {
  const r = map(PROFILE());
  assert.equal(r.ok, true);
  assert.deepEqual(r.action, { action_type: "map.unit.1", amount: "1.00", ref: "sha256:" + "a".repeat(64) });
});

test("mapping: D2 null member, D5 non-string target_field, D6 path set, duplicate paths", () => {
  assert.deepEqual(reasons(map({ ...PROFILE(), omitted_source_fields: null })), ["invalid_mapping_profile"]);
  for (const target of [["memo"], ["action_type"], "action_type", 7]) {
    const p = PROFILE();
    p.rules.push({ source_path: "/m", target_field: target, transform: "copy" });
    p.material_source_paths.push("/m");
    assert.deepEqual(reasons(map(p, { ...SOURCE, m: "x" })), ["invalid_mapping_profile"], JSON.stringify(target));
  }
  const joined = PROFILE();
  joined.rules = [{ source_path: "/amt\n/h", target_field: "amount", transform: "copy" }];
  assert.deepEqual(reasons(map(joined)), ["invalid_mapping_profile", "unmapped_material_field:ref"]);
  const twice = PROFILE();
  twice.rules.push({ source_path: "/amt", target_field: "memo", transform: "copy" });
  assert.deepEqual(reasons(map(twice)), ["invalid_mapping_profile"]);
});

test("mapping: limits are UTF-8 octets", () => {
  const ok = { ...PROFILE(), profile_id: "é".repeat(256) }; // 512 octets
  assert.equal(map(ok).ok, true);
  assert.deepEqual(reasons(map({ ...PROFILE(), profile_id: "é".repeat(257) })), ["invalid_mapping_profile"]);
  assert.deepEqual(reasons(map({ ...PROFILE(), profile_id: "\u{1F600}".repeat(129) })), ["invalid_mapping_profile"]);
  assert.deepEqual(reasons(map({ ...PROFILE(), target_action_type: "a".repeat(513) })), ["invalid_mapping_profile"]);
  assert.deepEqual(reasons(map({ ...PROFILE(), profile_id: "\ud800" })), ["invalid_mapping_profile", "mapping_profile_unpinned"]);
  const longPath = "/" + "p".repeat(2048);
  const p = PROFILE();
  p.rules[0].source_path = longPath;
  p.material_source_paths[0] = longPath;
  assert.deepEqual(reasons(map(p)), ["invalid_mapping_profile"]);
  const many = PROFILE();
  for (let i = 0; i < 127; i++) {
    many.rules.push({ source_path: `/x${i}`, target_field: `f${i}`, transform: "copy" });
    many.material_source_paths.push(`/x${i}`);
  }
  assert.deepEqual(reasons(map(many)), ["invalid_mapping_profile"]);
});

test("mapping: target_field names beyond snake_case, and __proto__ stays a member", () => {
  const d = { ...MAP_DEF, optional_fields: [{ name: "@version", type: "string" }, { name: "__proto__", type: "string" }] };
  const p = PROFILE();
  p.rules.push({ source_path: "/v", target_field: "@version", transform: "copy" }, { source_path: "/p", target_field: "__proto__", transform: "copy" });
  p.material_source_paths.push("/v", "/p");
  const r = map(p, { ...SOURCE, v: "1", p: "q" }, { definitions: [d] });
  assert.equal(r.ok, true);
  assert.ok(Object.prototype.hasOwnProperty.call(r.action, "__proto__"));
  assert.equal(Object.getPrototypeOf(r.action), Object.prototype);
});

test("mapping: sha256-hex-to-digest refuses anything but 64 lowercase hex", () => {
  for (const h of ["A".repeat(64), "a".repeat(63), 7, "g".repeat(64)]) {
    assert.deepEqual(reasons(map(PROFILE(), { ...SOURCE, h })), ["source_value_type_mismatch:/h"], String(h));
  }
});

test("mapping: stages A and B sort by rank, C follows rule order, D follows compute order", () => {
  const p = { ...PROFILE(), target_action_type: "no.such.1" };
  const r = mapAction(SOURCE, { profile: p, sourceDescriptor: { x: 1 }, definitions: [MAP_DEF] });
  assert.deepEqual(r.reasons, ["unknown_action_type", "native_verification_required", "mapping_profile_unpinned", "source_format_mismatch"]);
  assert.deepEqual(reasons(map(PROFILE(), { h: 7 })), ["missing_source_field:/amt", "source_value_type_mismatch:/h"]);
  assert.deepEqual(reasons(map(PROFILE(), { amt: "1.", h: "a".repeat(64) })), ["mapped_action:invalid_amount:amount"]);
  assert.deepEqual(reasons(map(PROFILE(), SOURCE, { suite: "" })), ["mapped_action:unknown_suite"]);
  assert.deepEqual(reasons(map(PROFILE(), [1])), ["source_not_object", "source_not_canonicalizable"]);
  assert.deepEqual(reasons(map(PROFILE(), { ...SOURCE, d: new Date(0) })), ["source_not_canonicalizable"]);
});

test("mapping: declared-source-semantic-loss always abstains", () => {
  const p = { ...PROFILE(), loss_policy: "declared-source-semantic-loss", omitted_source_fields: [{ source_path: "/noise", reason: "not modeled" }] };
  assert.deepEqual(reasons(map(p)), ["declared_source_semantic_loss"]);
  const empty = { ...PROFILE(), loss_policy: "declared-source-semantic-loss", omitted_source_fields: [] };
  assert.deepEqual(reasons(map(empty)), ["invalid_mapping_profile", "declared_source_semantic_loss"]);
  const overlap = { ...PROFILE(), omitted_source_fields: [{ source_path: "/amt", reason: "x" }] };
  assert.deepEqual(reasons(map(overlap)), ["invalid_mapping_profile"]);
});

test("mapping comparison: left, then right, then the verdict reasons", () => {
  const side = (source, extra = {}) => ({
    source,
    profile: PROFILE(),
    source_descriptor: PROFILE().source_format,
    expected_profile_hash: mappingProfileHash(PROFILE()),
    native_verified: true,
    ...extra,
  });
  assert.equal(compareMappedActions(side(SOURCE), side({ ...SOURCE, noise: 2 }), { definitions: [MAP_DEF] }).verdict, "EQUIVALENT_UNDER_PROFILE");
  assert.deepEqual(compareMappedActions(side(SOURCE), side({ ...SOURCE, amt: "2.00" }), { definitions: [MAP_DEF] }).reasons, ["material_projection_mismatch"]);
  const r = compareMappedActions(side({}, { native_verified: false }), side(SOURCE, { expected_profile_hash: "x" }), { definitions: [MAP_DEF] });
  assert.deepEqual(r.reasons, ["left:native_verification_required", "right:mapping_profile_unpinned"]);
  assert.equal(r.verdict, "INDETERMINATE");
});
