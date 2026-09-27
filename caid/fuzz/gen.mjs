// SPDX-License-Identifier: Apache-2.0
// CAID differential fuzz case generator (deterministic, seeded).
//
// Writes <out>/cases.jsonl and <out>/tables.json. Every case is one JSON
// line. Objects under test travel as raw bytes (base64 in "obj"/"src"), and
// every implementation receives the SAME bytes at its JSON text entry
// point; native-lane objects travel in "native" (the encoding of
// caid/conformance/runners/native.mjs) and go to the native entry points.
// Definitions, options, profiles and sides travel as ordinary JSON in the
// line.
//
// The cases come from this checkout's corpora and registry and never from
// the tree under test, so a pre-04 tree is measured against the same cases.
// Expected outcomes are not computed here; run.mjs asks the spec oracle
// (caid/conformance/tools/oracle.mjs, built from the generated caid/spec
// constants) for each case.
//
// Families:
//   vec-core   structured mutations of every core corpus v5 vector
//   vec-map    structured mutations of every mapping vector (v2 + interop)
//   registry   a valid object per registry type, then per-field mutations
//   grammar    every ASCII char at every position of short identifiers,
//              control chars, Unicode separators, confusables, long strings
//   code       every named code format: samples, per-position edits,
//              confusables, case changes, long and adversarial strings
//   number     number literal edge cases in typed and untyped positions
//   json       JSON-level edge cases over raw bytes
//   native     host values the JSON decoder never produces
//   caidstr    CAID strings: suite forms, digest lengths, unused bits, case
//   defs       definition / enum-form / code-field / option shape mutations
//   map-craft  hand-built mapping-profile edge cases
//
// Usage: node gen.mjs --out <dir> [--seed N] [--quick]

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { render } from "./render.mjs";
import * as oracle from "../conformance/tools/oracle.mjs";
import { mappingProfileHash } from "../conformance/tools/mapping-oracle.mjs";

const args = process.argv.slice(2);
const arg = (n, d) => {
  const i = args.indexOf(n);
  return i === -1 ? d : args[i + 1];
};
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const OUT = path.resolve(arg("--out"));
const SEED = Number(arg("--seed", "20260926"));
const QUICK = args.includes("--quick");
mkdirSync(OUT, { recursive: true });

const readJson = (p) => JSON.parse(readFileSync(path.join(ROOT, p), "utf8"));
const coreCorpus = readJson("caid/conformance/vectors.json");
const mapCorpus = readJson("caid/conformance/mapping-vectors.json");
const interopCorpus = readJson("caid/interop/consequential-action-v1/mapping-vectors.json");
const registry = readJson("caid/registry/action-types.json");
const V4_IDS = new Set(readJson("caid/conformance/history/vectors.v4.json").vectors.map((v) => v.id));

// ---------------------------------------------------------------- PRNG
let s0 = SEED >>> 0;
function rnd() {
  s0 = (s0 + 0x6d2b79f5) >>> 0;
  let t = s0;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = (a) => a[Math.floor(rnd() * a.length)];
const pickN = (a, n) => {
  const c = [...a];
  const out = [];
  while (out.length < n && c.length) out.push(c.splice(Math.floor(rnd() * c.length), 1)[0]);
  return out;
};
const clone = (v) => structuredClone(v);

// ---------------------------------------------------------------- output
const cases = [];
const counters = {};
let MUT = "";
const M = (label) => { MUT = label; return true; };
function emit(fam, c) {
  counters[fam] = (counters[fam] || 0) + 1;
  cases.push({ id: `${fam}:${counters[fam]}`, fam, mut: c.mut ?? c.note ?? MUT, ...c });
}
const b64 = (text) => Buffer.from(text, "utf8").toString("base64");
const b64buf = (buf) => Buffer.from(buf).toString("base64");

// ---------------------------------------------------------------- tables
const tables = { defs: {}, snaps: { iso: coreCorpus.enum_snapshots } };
const regSnapshots = coreCorpus.enum_snapshots;
const ISO4217 = regSnapshots.find((s) => s.values_ref === "ISO 4217 alpha-3");
for (const t of registry.types) tables.defs["reg:" + t.action_type] = [t];

// ---------------------------------------------------------------- pools
const HEX64 = "a".repeat(64);
const DIGEST_OK = "sha256:" + "0123456789abcdef".repeat(4);
const CONTROL = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i)).concat(["\x7f", "\x80", "\x85", "\x9f"]);
const SEPARATORS = [" ", " ", " ", " ", " ", " ", " ", " ", " ", "　", "﻿", "​", "‌", "‍", "⁠", "᠎"];
const CONFUSABLES = ["а", "е", "о", "с", "і", "K", "ſ", "ı", "ａ", "‐", "‑", "‒", "–", "−", "﹣", "－", "𝟎", "٠", "１", "¹", "₁", "́", "é", "é"];
const SURROGATES = ["\ud800", "\udfff", "\udc00\ud800", "\ud83d", "\ude00"];
const ASTRAL = ["😀", "\u{10ffff}", "\u{1f600}\u{1f600}"];
const SPECIAL_CHARS = [...CONTROL, ...SEPARATORS, ...CONFUSABLES, ...SURROGATES, ...ASTRAL];

const NUMBER_LITERALS = [
  "0", "-0", "0.0", "-0.0", "0e0", "-0e0", "0E+0", "0e-0", "0e999999999", "1", "-1", "1e0", "1E0", "1e+0", "1e-0", "10e-1", "0.1e1",
  "100e-2", "1.0", "1.00000000000000000000001", "2.0", "1e3", "1E3", "1230e-1", "123e-2", "1.5", "-1.5", "0.5", "1e-400", "-1e-400",
  "5e-324", "2.4703282292062328e-324", "2.4703282292062327e-324", "4.9e-324",
  "9007199254740991", "-9007199254740991", "9007199254740992", "-9007199254740992", "9007199254740993", "-9007199254740993",
  "9007199254740991.0", "9007199254740991.4", "9007199254740991.5", "9007199254740991.9999999999", "-9007199254740991.4",
  "9007199254740992.0", "9.007199254740991e15", "9.007199254740992e15", "90071992547409910e-1", "4503599627370495.5",
  "1e15", "1e16", "1e21", "1e22", "1e308", "1.7976931348623157e308", "1.7976931348623159e308", "1e309", "-1e309", "1e400",
  "1" + "0".repeat(400), "1" + "0".repeat(4300), "1" + "0".repeat(4301), "1" + "0".repeat(5000), "-" + "9".repeat(5000),
  "1" + "0".repeat(400) + ".0", "0." + "0".repeat(400) + "1", "1e99999999999999999999", "123456789012345678901234567890",
  // invalid JSON number forms
  "01", "-01", "00", "+1", ".5", "1.", "-", "1e", "1e+", "0x10", "NaN", "Infinity", "-Infinity", "1_000", "１", "١",
];

// ---------------------------------------------------------------- helpers
function computeRef(obj, defs, suite = "jcs-sha256", snaps = regSnapshots) {
  return oracle.compute(obj, { suite, definitions: defs, enum_snapshots: snaps });
}
function b64urlDigest(obj) {
  const c = oracle.reference.canonicalize(obj);
  if (!c.ok) return null;
  return createHash("sha256").update(Buffer.from(c.canonical, "utf8")).digest("base64url");
}
function emitCompute(fam, objNode, defs, suite, extra = {}) {
  const text = typeof objNode === "string" ? objNode : render(objNode, extra.style || {});
  const c = { op: "compute", obj: b64(text) };
  if (typeof defs === "string") c.defs_ref = defs;
  else c.defs = defs;
  c.snaps_ref = "iso";
  if (suite !== undefined) c.suite = suite;
  emit(fam, c);
}
function emitVerify(fam, objNode, caid, defs, extra = {}) {
  const text = typeof objNode === "string" ? objNode : render(objNode, extra.style || {});
  const c = { op: "verify", obj: b64(text), caid };
  if (typeof defs === "string") c.defs_ref = defs;
  else c.defs = defs;
  c.snaps_ref = "iso";
  emit(fam, c);
}
// -04 specifies compute, verify and parse, not a separate canonicalize
// entry point; canonical bytes are checked through the CAID digest.
/** @param {string} _fam @param {string} _text */
function emitCanon(_fam, _text) {}
function emitParse(fam, caid) {
  emit(fam, { op: "parse", caid });
}
function emitRawObj(fam, op, buf, defs, more = {}) {
  /** @type {Record<string, any>} */
  const c = { op, obj: b64buf(buf), ...more };
  if (typeof defs === "string") c.defs_ref = defs;
  else if (defs !== undefined) c.defs = defs;
  c.snaps_ref = "iso";
  emit(fam, c);
}

const VALUE_POOL = [
  null, true, false, 0, { $raw: "-0" }, 1, { $raw: "1.5" }, { $raw: "1e0" }, { $raw: "2.0" }, { $raw: "9007199254740992" },
  { $raw: "9007199254740993" }, { $raw: "1e400" }, "", " ", "x", [], {}, "0", "-0", "1.50", "01.5", "1e3", DIGEST_OK,
  DIGEST_OK.toUpperCase(), "sha256:" + "A".repeat(64), "2026-01-01T00:00:00Z", "2026-02-29T00:00:00Z", "2024-02-29T23:59:59.123Z",
  "2026-01-01T00:00:00z", "2026-01-01T24:00:00Z", "2026-01-01t00:00:00Z", "2026-01-01T00:00:60Z", "\ud800", "a\n", "USD", "usd",
  "USD\n", " USD", "EUR", "XXX", [1, 2], { a: 1 }, "1.00", "-0.00", "١.00",
];

function stringMutants(s) {
  const out = [s + "\n", "\n" + s, " " + s, s + " ", s + "\u0000", s.toUpperCase(), s.toLowerCase(), s + "\ud800", "\udc00" + s, s + " ", s + " ", s + "​", s.normalize("NFD"), s.normalize("NFC"), s + "😀", s.slice(1), s + s.slice(-1)];
  if (s.length) out.push(s.slice(0, -1), pick(CONFUSABLES) + s.slice(1), s.slice(0, Math.floor(s.length / 2)) + pick(SPECIAL_CHARS) + s.slice(Math.floor(s.length / 2)));
  return out;
}

function numberStyles(n) {
  if (!Number.isInteger(n)) return [];
  const s = String(n);
  const lits = [s + ".0", s + "e0", s + "E+0", n === 0 ? "-0" : s + "0e-1", s + ".000000000000000000001"];
  if (n > 0) lits.push(s.length > 1 ? s[0] + "." + s.slice(1) + "e" + (s.length - 1) : s + "e0");
  return lits.map((l) => ({ $raw: l }));
}

const ACTION_TYPE_VARIANTS = (t) => {
  const segs = t.split(".");
  return [
    t.toUpperCase(), t + ".", "." + t, t.replace(".", ".."), segs.slice(0, -1).join("."), t + "0", segs.slice(0, -1).join(".") + ".0",
    segs.slice(0, -1).join(".") + ".01", segs.slice(0, -1).join(".") + ".1a", t.replace(/\.(\d+)$/, ".9007199254740993"), "-" + t,
    t.replace(/^([a-z]+)/, "$1-"), t.replace(/^([a-z]+)/, "$1--x"), t.replace(/^([a-z])/, "1"), t.replace("-", "_"), t + "\n", t + " ",
    t.replace("a", "а"), t.replace(".", "․"), t + "\u0000", t + "\ud800", t.replace(/\d+$/, "１"), "a".repeat(100000) + ".1",
    t.replace(/\.(\d+)$/, "." + "9".repeat(400)), null, 1, [t], { t },
  ];
};

// ================================================================ vec-core
function familyVecCore() {
  for (const v of coreCorpus.vectors) {
    const defs = v.definitions;
    if (v.kind === "definition") continue;
    if (v.kind === "decode") {
      // Decode vectors: the same octets at compute and verify.
      if (v.input.json_repeat) continue;
      const buf = v.input.json !== undefined ? Buffer.from(v.input.json, "utf8") : Buffer.from(v.input.json_b64, "base64");
      emitRawObj("vec-core", "compute", buf, "a1", { suite: "jcs-sha256", note: "decode vector " + v.id });
      emitRawObj("vec-core", "verify", buf, "a1", { caid: computeRef(A1_OBJ, DEF_A1).caid, note: "decode vector " + v.id });
      continue;
    }
    if (v.input.native !== undefined) {
      M("native vector") && emit("vec-core", { op: v.kind, native: v.input.native, defs, snaps_ref: "iso", ...(v.kind === "compute" ? { suite: v.input.suite } : { caid: v.input.caid }) });
      continue;
    }
    if (v.kind === "parse") {
      const s = v.input.caid;
      emitParse("vec-core", s);
      if (typeof s !== "string") continue;
      for (const m of stringMutants(s)) emitParse("vec-core", m);
      for (let k = 0; k < (QUICK ? 5 : 30); k++) {
        const pos = Math.floor(rnd() * (s.length + 1));
        emitParse("vec-core", s.slice(0, pos) + pick(SPECIAL_CHARS.concat(["=", ":", ".", "-", "_", "+", "/", "A", "z", "0"])) + s.slice(pos + (rnd() < 0.5 ? 1 : 0)));
      }
      continue;
    }
    if (v.input.json === undefined) {
      // json_b64 and json_repeat inputs run as given (large inputs once).
      if (v.input.json_b64 !== undefined) emitRawObj("vec-core", v.kind, Buffer.from(v.input.json_b64, "base64"), defs, v.kind === "compute" ? { suite: v.input.suite, note: v.id } : { caid: v.input.caid, note: v.id });
      continue;
    }
    // The exact version 5 text first, then structured mutations of the
    // decoded object where it survives a JSON round trip.
    const exact = Buffer.from(v.input.json, "utf8");
    emitRawObj("vec-core", v.kind, exact, defs, v.kind === "compute" ? { suite: v.input.suite, note: "exact " + v.id } : { caid: v.input.caid, note: "exact " + v.id });
    let obj;
    try {
      obj = JSON.parse(v.input.json);
    } catch {
      continue;
    }
    if (JSON.stringify(obj) === undefined || /null/.test(JSON.stringify(obj)) !== /null/.test(v.input.json)) continue;
    // Full structured mutation for the version 4 vectors; the version 5
    // additions run exact (above) plus the definition and suite mutations.
    if (!V4_IDS.has(v.id) && rnd() < 0.85) continue;
    const suite = v.input.suite;
    const isVerify = v.kind === "verify";
    const e = (node, extra = {}) => (isVerify ? emitVerify("vec-core", node, extra.caid ?? v.input.caid, extra.defs ?? defs, extra) : emitCompute("vec-core", node, extra.defs ?? defs, "suite" in extra ? extra.suite : suite, extra));
    M("identity") && e(obj);
    M("whitespace-style");
    for (const ws of ["pretty", "tabs", "crlf", "spaced"]) e(obj, { style: { ws } });
    M("escape-style");
    for (const escape of ["all", "upper", "slash"]) e(obj, { style: { escape } });
    if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
      M("non-object-input");
      for (const val of VALUE_POOL.slice(0, 20)) e(val);
      continue;
    }
    const keys = Object.keys(obj);
    for (const k of keys) {
      const without = clone(obj);
      delete without[k];
      M("delete-member") && e(without);
      for (const val of [null, ...pickN(VALUE_POOL, QUICK ? 2 : 7)]) M("set-member:" + (val === null ? "null" : Array.isArray(val) ? "array" : typeof val === "object" ? ("$raw" in val ? "raw-number" : "object") : typeof val)) && e({ ...obj, [k]: val });
      const cur = obj[k];
      if (typeof cur === "string") for (const m of pickN(stringMutants(cur), QUICK ? 2 : 6)) M("string-mutant") && e({ ...obj, [k]: m });
      if (typeof cur === "number") for (const lit of numberStyles(cur)) M("number-literal-form") && e({ ...obj, [k]: lit });
      // duplicate member name, first and last occurrence differing
      const pairs = Object.entries(obj);
      M("duplicate-name:last-differs") && e({ $pairs: [...pairs, [k, pick(VALUE_POOL)]] });
      M("duplicate-name:first-differs") && e({ $pairs: [[k, pick(VALUE_POOL)], ...pairs] });
      M("duplicate-name:same-value") && e({ $pairs: [...pairs, [k, cur]] });
      // escape-equivalent duplicate name
      M("duplicate-name:escaped-spelling") && e({ $pairs: [...pairs, [{ $raw: render(k, { escape: "all" }) }, cur]] });
    }
    for (const extraKey of ["__proto__", "constructor", "toString", "hasOwnProperty", "", "\ud800", "😀", "￿", " ", "A", "a\u0000"]) {
      M("extra-member") && e({ ...Object.fromEntries(Object.entries(obj)), [extraKey]: "x" });
    }
    M("__proto__-member") && e({ $pairs: [["__proto__", { action_type: obj.action_type }], ...Object.entries(obj).filter(([k]) => k !== "action_type")] });
    if (typeof obj.action_type === "string") for (const t of pickN(ACTION_TYPE_VARIANTS(obj.action_type), QUICK ? 4 : 12)) M("action-type-variant") && e({ ...obj, action_type: t });
    if (!isVerify) {
      for (const s of ["JCS-SHA256", "jcs-sha256 ", "cbor-sha256", "", "jcs_sha256", "jcs‐sha256", null, 1, [], ["jcs-sha256"], { a: 1 }, true]) M("suite:" + (typeof s === "string" ? JSON.stringify(s) : Array.isArray(s) ? "array" : s === null ? "null" : typeof s)) && e(obj, { suite: s });
    } else {
      const c = v.input.caid;
      if (typeof c === "string") {
        const variants = [c.slice(0, -1) + (c.endsWith("A") ? "E" : "A"), c.slice(0, -1) + "B", c.replace("jcs-sha256", "cbor-sha256"), c.toUpperCase(), c + "=", c.replace(":1:", ":2:"), c.replace("caid:", "CAID:")];
        M("caid-variant");
        for (const cv of variants) emitVerify("vec-core", obj, cv, defs);
      }
      const good = computeRef(obj, defs);
      if (good.caid) M("recomputed-caid") && emitVerify("vec-core", obj, good.caid, defs);
    }
    // definition mutations
    if (Array.isArray(defs) && defs.length && defs[0] && typeof defs[0] === "object") {
      const d0 = defs[0];
      const listOf = (x) => (Array.isArray(x) ? x.filter((f) => f && typeof f === "object" && !Array.isArray(f)) : []);
      const fields = [...listOf(d0.required_fields), ...listOf(d0.optional_fields)];
      for (const f of pickN(fields, QUICK ? 1 : 4)) {
        for (const ty of ["string", "amount-string", "digest", "enum", "timestamp", "integer", "boolean", "object", "array", "number", "String", null, 1]) {
          const nd = clone(defs);
          for (const list of ["required_fields", "optional_fields"]) for (const ff of listOf(nd[0][list])) if (ff.name === f.name) ff.type = ty;
          M("def-field-type:" + JSON.stringify(ty)) && e(obj, { defs: nd });
        }
      }
      M("def-shape") && e(obj, { defs: [...clone(defs), clone(d0)] });
      e(obj, { defs: [{ ...clone(d0), required_fields: null }] });
      e(obj, { defs: [{ ...clone(d0), required_fields: [null, 1, "x", { name: 1, type: "string" }, ...(d0.required_fields || [])] }] });
      e(obj, { defs: [null, 1, "x", ...clone(defs)] });
      e(obj, { defs: {} });
      e(obj, { defs: null });
    }
  }
}

// ================================================================ registry
function sampleValue(f) {
  switch (f.type) {
    case "string": return "v";
    case "amount-string": return "12.50";
    case "digest": return DIGEST_OK;
    case "timestamp": return "2026-09-26T12:00:00Z";
    case "integer": return 3;
    case "boolean": return true;
    case "object": return { k: "v" };
    case "array": return ["v"];
    case "code": return CODE_SAMPLES[f.format] ?? "X";
    case "enum": {
      if (Array.isArray(f.values) && !("values_ref" in f)) return f.values[0];
      if (typeof f.values_ref === "string" && f.values_ref.startsWith("inline:")) return f.values_ref.slice(7).split("|")[0].trim();
      const snap = regSnapshots.find((s) => s.values_ref === f.values_ref && s.values_sha256 === f.values_sha256);
      return snap ? snap.values.includes("USD") ? "USD" : snap.values[0] : "X";
    }
    default: return "v";
  }
}
function familyRegistry() {
  for (const t of registry.types) {
    const ref = "reg:" + t.action_type;
    const fields = [...(t.required_fields || []), ...(t.optional_fields || [])];
    const obj = { action_type: t.action_type };
    for (const f of t.required_fields || []) obj[f.name] = sampleValue(f);
    M("registry: required fields only") && emitCompute("registry", obj, ref, "jcs-sha256");
    const full = { ...obj };
    for (const f of t.optional_fields || []) full[f.name] = sampleValue(f);
    M("registry: all fields") && emitCompute("registry", full, ref, "jcs-sha256");
    const good = computeRef(obj, [t]);
    if (good.caid) {
      M("registry: verify");
      emitVerify("registry", obj, good.caid, ref);
      emitVerify("registry", { ...obj, extra: 1 }, good.caid, ref);
    }
    for (const f of fields) {
      const n = QUICK ? 1 : 3;
      M("registry: field value from pool");
      for (const val of pickN(VALUE_POOL, n)) emitCompute("registry", { ...full, [f.name]: val }, ref, "jcs-sha256");
      if (f.type === "enum") {
        const v0 = sampleValue(f);
        M("registry: enum value variant");
        for (const m of [v0 + " ", " " + v0, v0.toLowerCase(), v0 + "\n", v0.replace(/./, "а"), "", v0 + "\u0000"]) emitCompute("registry", { ...full, [f.name]: m }, ref, "jcs-sha256");
      }
    }
  }
}

// ================================================================ code
const CODE_SYSTEM = "http://example.org/code-system";
const CODE_SAMPLES = {
  "icd-10-cm": "S72.001A", "ndc-11": "00002322730", "ndc-10-hyphenated": "12345-678-90", cpt: "0001F", "hcpcs-level-ii": "J1234",
  hcpcs: "99213", "iso-3166-1-alpha-2": "US", "iso-3166-2": "GB-ENG", "iso20022-external-code": "AC01", "nacha-sec": "PPD",
};
function familyCode() {
  for (const [format, sample] of Object.entries(CODE_SAMPLES)) {
    const at = `code.${format.replace(/[^a-z0-9]/g, "-")}.1`;
    const defs = [{ action_type: at, required_fields: [{ name: "c", type: "code", code_system: CODE_SYSTEM, format }], optional_fields: [{ name: "o", type: "code", code_system: CODE_SYSTEM, format }] }];
    const ref = "code:" + format;
    tables.defs[ref] = defs;
    const e = (v, note) => { M("code " + format + ": " + note); emitCompute("code", { action_type: at, c: v }, ref, "jcs-sha256"); };
    e(sample, "sample");
    for (const other of Object.values(CODE_SAMPLES)) e(other, "another format's sample");
    for (let pos = 0; pos <= sample.length; pos++) {
      for (let ch = 32; ch < 127; ch += QUICK ? 5 : 1) {
        const c = String.fromCharCode(ch);
        if (pos < sample.length) e(sample.slice(0, pos) + c + sample.slice(pos + 1), "replace at " + pos);
        if (!QUICK || pos % 3 === 0) e(sample.slice(0, pos) + c + sample.slice(pos), "insert at " + pos);
      }
      if (pos < sample.length) e(sample.slice(0, pos) + sample.slice(pos + 1), "delete at " + pos);
    }
    for (const m of stringMutants(sample)) e(m, "string mutant");
    for (const ch of SPECIAL_CHARS) e(sample.slice(0, 1) + ch + sample.slice(1), "special char");
    for (const v of [sample.toLowerCase(), sample.repeat(2), "", " ", null, 1, [sample], { c: sample }, true]) e(v, "shape " + JSON.stringify(v));
    for (const [unit, n] of /** @type {Array<[string, number]>} */ ([["A", 1 << 16], ["0", 1 << 16], ["0-", 1 << 15], [sample, 4096]])) e(unit.repeat(n) + "!", "adversarial " + n);
    M("code " + format + ": optional field") && emitCompute("code", { action_type: at, c: sample, o: sample.toLowerCase() }, ref, "jcs-sha256");
    const good = computeRef({ action_type: at, c: sample }, defs);
    if (good.caid) {
      M("code " + format + ": verify");
      emitVerify("code", { action_type: at, c: sample }, good.caid, ref);
      emitVerify("code", { action_type: at, c: sample.toLowerCase() }, good.caid, ref);
    }
  }
  // Definition-level code-field shapes.
  const obj = { action_type: "code.shape.1", c: "US" };
  const shapes = [
    { code_system: CODE_SYSTEM, format: "iso-3166-1-alpha-2" }, { format: "iso-3166-1-alpha-2" }, { code_system: CODE_SYSTEM }, {},
    { code_system: "not a uri", format: "iso-3166-1-alpha-2" }, { code_system: CODE_SYSTEM + "#f", format: "iso-3166-1-alpha-2" },
    { code_system: CODE_SYSTEM, format: "ISO-3166-1-ALPHA-2" }, { code_system: CODE_SYSTEM, format: "unregistered-format" },
    { code_system: CODE_SYSTEM, format: "iso-3166-1-alpha-2", values: ["US"] }, { code_system: 1, format: "iso-3166-1-alpha-2" },
    { code_system: CODE_SYSTEM, format: null }, { code_system: CODE_SYSTEM, format: "iso-3166-1-alpha-2", notes: "n" },
    { code_system: "urn:iso:std:iso:3166", format: "iso-3166-1-alpha-2" }, { code_system: CODE_SYSTEM, format: "a".repeat(300) },
  ];
  for (const shape of shapes) {
    M("code field shape " + JSON.stringify(shape).slice(0, 100));
    for (const where of ["required_fields", "optional_fields"]) {
      const d = { action_type: "code.shape.1", required_fields: [{ name: "k", type: "string" }], optional_fields: [] };
      d[where].push({ name: "c", type: "code", ...shape });
      emitCompute("code", { ...obj, k: "v" }, [d], "jcs-sha256");
      emitCompute("code", { action_type: "code.shape.1", k: "v" }, [d], "jcs-sha256");
    }
  }
}

// ================================================================ native
function familyNative() {
  const defs = [{ action_type: "n.native.1", required_fields: [{ name: "s", type: "string" }], optional_fields: [{ name: "o", type: "object" }, { name: "a", type: "array" }, { name: "n", type: "integer" }] }];
  tables.defs.native = defs;
  const base = [["action_type", "n.native.1"], ["s", "x"]];
  /** @type {Array<[string, any]>} */
  const HOSTS = [
    ["lone high", { $units: [0xd800] }], ["lone low", { $units: [0xdc00] }], ["reversed pair", { $units: [0xdc00, 0xd800] }],
    ["pair", { $units: [0xd83d, 0xde00] }], ["noncharacter", { $units: [0xffff] }], ["noncharacter fdd0", { $units: [0xfdd0] }],
    ["nan", { $host: "nan" }], ["infinity", { $host: "infinity" }], ["-infinity", { $host: "-infinity" }], ["negative zero", { $host: "negative_zero" }],
    ["cyclic", { $host: "cyclic" }], ["opaque", { $host: "opaque" }], ["deep 63", { $nest: { depth: 63, container: "array", leaf: 0 } }],
    ["deep 64", { $nest: { depth: 64, container: "array", leaf: 0 } }], ["deep 65 objects", { $nest: { depth: 65, container: "object", leaf: 0 } }],
    ["deep 3000", { $nest: { depth: 3000, container: "array", leaf: 0 } }], ["1.5", 1.5], ["2^53", 9007199254740992],
  ];
  const caid = computeRef({ action_type: "n.native.1", s: "x" }, defs).caid;
  for (const [label, host] of HOSTS) {
    for (const [where, build] of /** @type {Array<[string, () => any]>} */ ([
      ["undeclared member", () => ({ $object: [...base, ["m", host]] })],
      ["member name", () => (host.$units ? { $object: [...base, [host, "v"]] } : null)],
      ["string field", () => ({ $object: [["action_type", "n.native.1"], ["s", host]] })],
      ["object field", () => ({ $object: [...base, ["o", host]] })],
      ["integer field", () => ({ $object: [...base, ["n", host]] })],
      ["inside array field", () => ({ $object: [...base, ["a", [1, host]]] })],
      ["action_type", () => ({ $object: [["action_type", host], ["s", "x"]] })],
    ])) {
      const native = build();
      if (!native) continue;
      M("native " + label + " in " + where);
      emit("native", { op: "compute", native, defs_ref: "native", snaps_ref: "iso", suite: "jcs-sha256" });
      emit("native", { op: "verify", native, defs_ref: "native", snaps_ref: "iso", caid });
    }
  }
  M("native pairs of refusals");
  for (let k = 0; k < (QUICK ? 20 : 120); k++) {
    const picks = pickN(HOSTS, 2);
    const members = [...base];
    for (const [label, host] of picks) members.push([pick(["m1", "m2", "", "", "zz"]) + label.length, host]);
    if (rnd() < 0.5) members.push(["n", pick(["x", 1.5, null, 1])]);
    emit("native", { op: "compute", native: { $object: members }, defs_ref: "native", snaps_ref: "iso", suite: pick(["jcs-sha256", "jcs-sha512"]) });
  }
  M("native top level");
  for (const top of [{ $host: "opaque" }, { $units: [0xd800] }, { $host: "nan" }, [1], "n.native.1", null]) {
    emit("native", { op: "compute", native: top, defs_ref: "native", snaps_ref: "iso", suite: "jcs-sha256" });
    emit("native", { op: "verify", native: top, defs_ref: "native", snaps_ref: "iso", caid });
  }
}

// ================================================================ grammar
// -04 refuses a definition with no required field, so a.1 has one.
const DEF_A1 = [{ action_type: "a.1", status: "active", required_fields: [{ name: "k", type: "string" }], optional_fields: [] }];
const A1_OBJ = { action_type: "a.1", k: "v" };
const DEF_ALL = [{
  action_type: "t.all.1", status: "active",
  required_fields: [
    { name: "s", type: "string" }, { name: "amt", type: "amount-string" }, { name: "d", type: "digest" },
    { name: "e", type: "enum", values: ["x", "y", "x y", "é"] }, { name: "ts", type: "timestamp" },
    { name: "n", type: "integer" }, { name: "b", type: "boolean" }, { name: "o", type: "object" }, { name: "arr", type: "array" },
  ],
  optional_fields: [{ name: "memo", type: "string" }, { name: "e2", type: "enum", values_ref: "inline: p | q r |s" }],
}];
const OBJ_ALL = { action_type: "t.all.1", s: "hello", amt: "10.00", d: DIGEST_OK, e: "x", ts: "2026-09-26T00:00:00Z", n: 7, b: false, o: {}, arr: [] };
tables.defs.a1 = DEF_A1;
tables.defs.all = DEF_ALL;

function familyGrammar() {
  const digest = b64urlDigest({ action_type: "a.1" });
  const base = `caid:1:a.1:jcs-sha256:${digest}`;
  M("every ASCII at every position of a CAID");
  for (let pos = 0; pos <= base.length; pos++) {
    for (let ch = 0; ch < 128; ch++) {
      const c = String.fromCharCode(ch);
      if (pos < base.length && !QUICK) emitParse("grammar", base.slice(0, pos) + c + base.slice(pos + 1));
      if (!QUICK || pos % 8 === 0) emitParse("grammar", base.slice(0, pos) + c + base.slice(pos));
    }
  }
  M("every ASCII at every position of action_type a.1");
  const at = "a.1";
  for (let pos = 0; pos <= at.length; pos++) {
    for (let ch = 0; ch < 128; ch++) {
      const c = String.fromCharCode(ch);
      if (pos < at.length) emitCompute("grammar", { action_type: at.slice(0, pos) + c + at.slice(pos + 1), k: "v" }, "a1", "jcs-sha256");
      emitCompute("grammar", { action_type: at.slice(0, pos) + c + at.slice(pos), k: "v" }, "a1", "jcs-sha256");
    }
  }
  M("every ASCII at every position of the suite");
  const su = "jcs-sha256";
  for (let pos = 0; pos < su.length; pos++) for (let ch = 0; ch < 128; ch += QUICK ? 7 : 1) emitCompute("grammar", A1_OBJ, "a1", su.slice(0, pos) + String.fromCharCode(ch) + su.slice(pos + 1));
  M("special char at CAID structural position");
  const cuts = [0, 4, 5, 6, 7, 8, 10, 11, 14, 21, 22, 40, base.length - 1, base.length];
  for (const ch of SPECIAL_CHARS) for (const pos of cuts) emitParse("grammar", base.slice(0, pos) + ch + base.slice(pos));
  M("special char in typed field value");
  for (const ch of SPECIAL_CHARS) {
    for (const [field, val] of [["amt", "10.00"], ["ts", "2026-09-26T00:00:00Z"], ["d", DIGEST_OK], ["e", "x"], ["s", "hello"]]) {
      emitCompute("grammar", { ...OBJ_ALL, [field]: val + ch }, "all", "jcs-sha256");
      emitCompute("grammar", { ...OBJ_ALL, [field]: ch + val }, "all", "jcs-sha256");
    }
    emitCompute("grammar", { ...OBJ_ALL, action_type: "t.all" + ch + ".1" }, "all", "jcs-sha256");
    emitCompute("grammar", { ...OBJ_ALL, ["k" + ch]: "v" }, "all", "jcs-sha256");
    emitCompute("grammar", { ...OBJ_ALL, e2: "q" + ch + "r" }, "all", "jcs-sha256");
  }
  M("compact inline enum member");
  for (const v of ["p", "q r", "s", " p", "q  r", "q", "r", "s ", "|s"]) emitCompute("grammar", { ...OBJ_ALL, e2: v }, "all", "jcs-sha256");
  M("key ordering");
  const keys = ["￿", "😀", "", "\u{10000}", "a", "A", "é", "é", "\u0000", "\x7f", " "];
  for (let k = 0; k < 20; k++) {
    const o = { ...A1_OBJ };
    for (const key of pickN(keys, 5)) o[key] = key;
    emitCompute("grammar", o, "a1", "jcs-sha256");
    emitCanon("grammar", render(o));
  }
  M("very long string");
  const long = (n, c = "a") => c.repeat(n);
  emitParse("grammar", `caid:1:${long(100000)}.1:jcs-sha256:${digest}`);
  emitParse("grammar", `caid:1:a.1:jcs-sha256:${long(1000000, "A")}`);
  emitParse("grammar", `caid:1:a.1:${long(100000)}:${digest}`);
  emitCompute("grammar", { ...OBJ_ALL, amt: "1" + long(100000, "0") + ".5" }, "all", "jcs-sha256");
  emitCompute("grammar", { ...OBJ_ALL, s: long(1000000, "é") }, "all", "jcs-sha256");
  emitCompute("grammar", { ...OBJ_ALL, [long(100000, "k")]: 1 }, "all", "jcs-sha256");
  emitCompute("grammar", { ...OBJ_ALL, ts: "2026-09-26T00:00:00." + long(100000, "9") + "Z" }, "all", "jcs-sha256");
  M("special char canonicalization");
  for (const ch of SPECIAL_CHARS) emitCanon("grammar", render({ v: ch, [ch]: 1 }));
}

// ================================================================ number
const DEF_NUM = [{ action_type: "n.1", required_fields: [{ name: "n", type: "integer" }], optional_fields: [{ name: "s", type: "string" }, { name: "amt", type: "amount-string" }] }];
tables.defs.num = DEF_NUM;
function familyNumber() {
  const lits = [...NUMBER_LITERALS];
  // random literals around the 2^53 boundary and zero
  for (let k = 0; k < (QUICK ? 30 : 250); k++) {
    const base = pick(["9007199254740991", "9007199254740992", "9007199254740993", "4503599627370496", "0", "1", "18014398509481984"]);
    const frac = rnd() < 0.5 ? "" : "." + Math.floor(rnd() * 1e6).toString().padStart(pick([1, 3, 6, 20]), "0");
    const exp = rnd() < 0.5 ? "" : pick(["e", "E"]) + pick(["", "+", "-"]) + Math.floor(rnd() * 25);
    lits.push((rnd() < 0.3 ? "-" : "") + base + frac + exp);
  }
  for (const lit of lits) {
    const raw = { $raw: lit };
    M("number in integer field") && emitCompute("number", { action_type: "n.1", n: raw }, "num", "jcs-sha256");
    M("number in undeclared member") && emitCompute("number", { action_type: "n.1", n: 1, x: raw }, "num", "jcs-sha256");
    M("number nested in array") && emitCompute("number", { action_type: "n.1", n: 1, x: [0, { y: raw }] }, "num", "jcs-sha256");
    M("number in string field") && emitCompute("number", { action_type: "n.1", n: 1, s: raw }, "num", "jcs-sha256");
    M("number in amount-string field") && emitCompute("number", { action_type: "n.1", n: 1, amt: raw }, "num", "jcs-sha256");
    M("number canonicalize") && emitCanon("number", render({ v: raw }));
    const good = computeRef({ action_type: "n.1", n: 1 }, DEF_NUM);
    M("number verify") && emitVerify("number", { action_type: "n.1", n: raw }, good.caid, "num");
  }
}

// ================================================================ json
function familyJson() {
  const T = (s) => Buffer.from(s, "utf8");
  const cat = (...parts) => Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : typeof p === "string" ? T(p) : Buffer.from(p))));
  const A = '{"action_type":"a.1","k":"v"';
  const texts = [
    ["empty", T("")], ["ws-only", T(" \n\t ")], ["null", T("null")], ["array", T("[]")], ["string", T('"a.1"')], ["number", T("1")],
    ["ok", T(A + "}")], ["bom", cat([0xef, 0xbb, 0xbf], A + "}")], ["bom2", cat([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf], A + "}")],
    ["utf16le-bom", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(A + "}", "utf16le")])], ["utf16le", Buffer.from(A + "}", "utf16le")],
    ["utf16be-bom", Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(A + "}", "utf16le").swap16()])], ["utf16be", Buffer.from(A + "}", "utf16le").swap16()],
    ["utf32le", Buffer.from([...(A + "}")].flatMap((c) => [c.charCodeAt(0), 0, 0, 0]))],
    ["dup-type-same", T(A + ',"action_type":"a.1"}')], ["dup-type-diff", T('{"action_type":"zz.1","action_type":"a.1"}')], ["dup-type-diff-rev", T(A + ',"action_type":"zz.1"}')],
    ["dup-extra", T(A + ',"x":1,"x":2}')], ["dup-escaped", T(A + ',"x":1,"\\u0078":2}')], ["dup-nested", T(A + ',"o":{"k":1,"k":1}}')], ["dup-in-array", T(A + ',"a":[{"k":1,"k":2}]}')],
    ["lone-high", T(A + ',"x":"\\ud800"}')], ["lone-low", T(A + ',"x":"\\udc00"}')], ["lone-reversed", T(A + ',"x":"\\udc00\\ud800"}')], ["lone-high-end", T(A + ',"x":"a\\ud800"}')],
    ["lone-high-then-bmp", T(A + ',"x":"\\ud800\\u0041"}')], ["lone-key", T(A + ',"\\ud800":1}')], ["pair-ok", T(A + ',"x":"\\ud83d\\ude00"}')], ["pair-upper", T(A + ',"x":"\\uD83D\\uDE00"}')],
    ["lone-in-type", T('{"action_type":"a.1\\ud800"}')],
    ["wtf8-high", cat(A + ',"x":"', [0xed, 0xa0, 0x80], '"}')], ["wtf8-pair", cat(A + ',"x":"', [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80], '"}')], ["overlong-slash", cat(A + ',"x":"', [0xc0, 0xaf], '"}')],
    ["overlong-quote", cat(A + ',"x":"', [0xc0, 0xa2], '"}')], ["bad-cont", cat(A + ',"x":"', [0xe2, 0x28, 0xa1], '"}')], ["lone-cont", cat(A + ',"x":"', [0x80], '"}')], ["five-byte", cat(A + ',"x":"', [0xf8, 0x88, 0x80, 0x80, 0x80], '"}')],
    ["above-10ffff", cat(A + ',"x":"', [0xf4, 0x90, 0x80, 0x80], '"}')], ["latin1", cat(A + ',"x":"', [0xe9], '"}')], ["invalid-in-key", cat(A + ',"', [0xff], '":1}')], ["invalid-outside", cat(A + "}", [0xff])],
    ["raw-nul-in-string", cat(A + ',"x":"a', [0x00], 'b"}')], ["raw-ctrl-in-string", T(A + ',"x":"a\u0001b"}')], ["raw-tab-in-string", T(A + ',"x":"a\tb"}')], ["raw-lf-in-string", T(A + ',"x":"a\nb"}')],
    ["raw-del", T(A + ',"x":"a\u007fb"}')], ["raw-u2028", T(A + ',"x":"a b"}')], ["raw-nbsp-ws", T("{ \"action_type\":\"a.1\"}")], ["vt-ws", T('{\u000b"action_type":"a.1"}')], ["ff-ws", T('{\f"action_type":"a.1"}')],
    ["nul-ws", cat("{", [0], '"action_type":"a.1"}')], ["trailing-comma", T(A + ",}")], ["trailing-garbage", T(A + "}x")], ["two-values", T(A + "}" + A + "}")], ["trailing-nul", cat(A + "}", [0])],
    ["comment", T(A + "/*c*/}")], ["line-comment", T(A + "}//c")], ["single-quote", T("{'action_type':'a.1'}")], ["unquoted-key", T("{action_type:\"a.1\"}")],
    ["nan", T(A + ',"x":NaN}')], ["inf", T(A + ',"x":Infinity}')], ["neg-inf", T(A + ',"x":-Infinity}')], ["TRUE", T(A + ',"x":TRUE}')], ["escape-x", T(A + ',"x":"\\x41"}')], ["escape-U", T(A + ',"x":"\\U0041"}')],
    ["escape-short-u", T(A + ',"x":"\\u41"}')], ["escape-apos", T(A + ',"x":"\\\'"}')], ["escape-slash", T(A + ',"x":"\\/"}')], ["escape-nul", T(A + ',"x":"\\u0000"}')], ["escape-all-type", T('{"\\u0061ction_type":"\\u0061.1"}')],
    ["big-int-4300", T(A + ',"x":1' + "0".repeat(4299) + "}")], ["big-int-4301", T(A + ',"x":1' + "0".repeat(4300) + "}")], ["big-int-10000", T(A + ',"x":' + "9".repeat(10000) + "}")],
    ["big-float-digits", T(A + ',"x":1' + "0".repeat(5000) + ".0}")], ["big-exp", T(A + ',"x":1e99999999999999999999999}')],
    ["neg-zero", T(A + ',"x":-0}')], ["leading-zero", T(A + ',"x":01}')], ["plus", T(A + ',"x":+1}')],
    ["big-array-1e5", T(A + ',"x":[' + Array(100000).fill("0").join(",") + "]}")], ["big-array-1e6", T(A + ',"x":[' + Array(1000000).fill("1").join(",") + "]}")],
    ["big-string-1e6", T(A + ',"x":"' + "a".repeat(1000000) + '"}')], ["many-keys-1e4", T(A + "," + Array.from({ length: 10000 }, (_, i) => `"k${i}":${i}`).join(",") + "}")],
    ["many-keys-1e5", T(A + "," + Array.from({ length: 100000 }, (_, i) => `"k${i}":${i}`).join(",") + "}")],
  ];
  for (const d of [63, 64, 65, 500, 900, 950, 990, 999, 1000, 1001, 1500, 3000, 5000, 7000, 9000, 9998, 9999, 10000, 10001, 20000, 100000]) {
    texts.push(["deep-array-" + d, T(A + ',"x":' + "[".repeat(d - 1) + "]".repeat(d - 1) + "}")]);
    texts.push(["deep-object-" + d, T(A + ',"x":' + '{"a":'.repeat(d - 1) + "0" + "}".repeat(d - 1) + "}")]);
  }
  const good = computeRef(A1_OBJ, DEF_A1);
  for (const [name, buf] of texts) {
    emitRawObj("json", "compute", buf, "a1", { suite: "jcs-sha256", note: name });
    emitRawObj("json", "verify", buf, "a1", { caid: good.caid, note: name });
  }
  return texts.length;
}

// ================================================================ caidstr
function familyCaidStr() {
  const obj = { action_type: "payment.release.1", amount: "1.00", currency: "USD", beneficiary_account: DIGEST_OK, payment_instruction_id: "p1" };
  const ptype = registry.types.find((t) => t.action_type === "payment.release.1");
  tables.defs.pay = [ptype];
  const good = computeRef(obj, [ptype]);
  if (!good.caid) throw new Error("gen: the payment reference object must compute");
  const goodCaid = good.caid;
  const dig = goodCaid.split(":")[4];
  const suites = ["jcs-sha256", "cbor-sha256", "sha256", "x", "a", "1x", "9", "0", "x--y", "x-", "-x", "x-1", "a1-b2", "jcs-sha256-", "jcs--sha256", "JCS-SHA256", "Jcs-sha256", "jcs-sha256 ", " jcs-sha256",
    "jcs_sha256", "", "jcs‐sha256", "jcs-sha512", "ｊcs-sha256", "jcs-sha256\n", "jcs-sha256\u0000", "jcs.sha256", "cbor", "unknown-suite", "a".repeat(300)];
  const types = ["a.1", "payment.release.1", "a.b.c.1", "a-.1", "a--b.1", "-a.1", "a.01", "a.0", "a..1", ".a.1", "a.1.", "a", "1", "a.b", "A.1", "a_b.1", "a.1a", "a.9007199254740993", "a1.1", "1a.1", "é.1", "a.1\n", "a.１"];
  const prefixes = ["caid", "CAID", "Caid", "cAid", " caid", "caid ", "﻿caid", "cai", "caidd", ""];
  const versions = ["1", "01", "2", "0", "1 ", "", "1.0", "１", "+1", "-1", "11"];
  const lastChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const digests = [dig, dig.toUpperCase(), dig.toLowerCase(), dig + "=", dig + "==", dig.replace(/[-_]/g, (c) => (c === "-" ? "+" : "/")), dig.slice(0, 42), dig + "A", "", "=", dig.slice(0, 40) + "===", dig + "\n", " " + dig];
  for (let n = 0; n <= 90; n++) digests.push(("ABCDEFGHIJ".repeat(10)).slice(0, n));
  for (const n of [42, 43, 44, 86, 128]) for (let k = 0; k < 4; k++) digests.push(Array.from({ length: n }, () => pick([...lastChars])).join(""));
  for (const ch of lastChars) digests.push(dig.slice(0, 42) + ch);
  const assemble = (p, v, t, s, d) => `${p}:${v}:${t}:${s}:${d}`;
  M("suite x digest");
  for (const s of suites) for (const d of digests) emitParse("caidstr", assemble("caid", "1", "payment.release.1", s, d));
  M("action type x suite");
  for (const t of types) for (const s of ["jcs-sha256", "cbor-sha256", "x", "1x"]) emitParse("caidstr", assemble("caid", "1", t, s, dig));
  M("prefix x version");
  for (const p of prefixes) for (const v of versions) emitParse("caidstr", assemble(p, v, "payment.release.1", "jcs-sha256", dig));
  M("leading/trailing content");
  for (const extra of ["", ":", "::", ":x", " ", "\n", "\r\n", "\t", "\u0000", "#frag", "?q"]) {
    emitParse("caidstr", good.caid + extra);
    emitParse("caidstr", extra + good.caid);
  }
  emitParse("caidstr", goodCaid.replace("payment.release.1", "payment:release.1"));
  emitParse("caidstr", goodCaid.replace(":", "::"));
  // verify against the correct object for a sample of the strings
  const pool = [];
  for (const s of suites) for (const d of [dig, dig.slice(0, 42) + "B", dig.slice(0, 42) + "E", dig + "=", "AAAA"]) pool.push(assemble("caid", "1", "payment.release.1", s, d));
  for (const ch of lastChars) pool.push(assemble("caid", "1", "payment.release.1", "jcs-sha256", dig.slice(0, 42) + ch));
  for (const ch of lastChars) pool.push(assemble("caid", "1", "payment.release.1", "cbor-sha256", dig.slice(0, 42) + ch));
  M("verify with CAID string variant");
  for (const cstr of pool) emitVerify("caidstr", obj, cstr, "pay");
  M("random CAID combination");
  for (let k = 0; k < (QUICK ? 100 : 1500); k++) {
    emitParse("caidstr", assemble(rnd() < 0.8 ? "caid" : pick(prefixes), rnd() < 0.8 ? "1" : pick(versions), rnd() < 0.6 ? "payment.release.1" : pick(types), pick(suites), pick(digests)));
  }
}

// ================================================================ defs
function familyDefs() {
  const ENUM_FORMS = [
    { values: ["x", "y"] }, { values: null }, { values: [] }, { values: [""] }, { values: ["x", "x"] }, { values: ["x", 1] }, { values: "x" }, { values: { 0: "x" } },
    { values_ref: null }, { values_ref: "" }, { values_ref: "inline:" }, { values_ref: "inline:x" }, { values_ref: "inline: x | y" }, { values_ref: "inline:x||y" },
    { values_ref: "inline:\tx|y" }, { values_ref: "inline: x | y" }, { values_ref: "inline: x | x" }, { values_ref: "inline: x |" }, { values_ref: "Inline: x | y" },
    { values_ref: " inline: x | y" }, { values_ref: "inline: x | y", values: ["x", "y"] }, { values_ref: "inline: x | y", values: ["y", "x"] }, { values_ref: "inline: x | y", values: null },
    { values_ref: "inline: x | y", values: ["x"] }, { values: ["x", "y"], values_ref: "ISO 4217 alpha-3" }, { values_ref: "inline: x　| y" }, { values_ref: "inline: x\u0085| y" },
    { values_ref: "inline: x\r| y" }, { values_ref: "inline:  x  |  y  " }, { values_ref: "inline: x | y", values: "x" }, { values_ref: 5 }, { values_ref: ["inline: x"] },
  ];
  const snap = regSnapshots[0];
  const EXTERNAL = [
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot, values_sha256: snap.values_sha256 },
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot, values_sha256: snap.values_sha256.toUpperCase() },
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot, values_sha256: snap.values_sha256.replace("sha256:", "SHA256:") },
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot + " ", values_sha256: snap.values_sha256 },
    { values_ref: snap.values_ref, values_snapshot: "", values_sha256: snap.values_sha256 },
    { values_ref: snap.values_ref, values_snapshot: null, values_sha256: snap.values_sha256 },
    { values_ref: snap.values_ref, values_sha256: snap.values_sha256 },
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot },
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot, values_sha256: snap.values_sha256, values: snap.values },
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot, values_sha256: snap.values_sha256, values: [...snap.values].reverse() },
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot, values_sha256: snap.values_sha256, values: null },
    { values_ref: snap.values_ref + " ", values_snapshot: snap.values_snapshot, values_sha256: snap.values_sha256 },
    { values_ref: "ISO 4217", values_snapshot: snap.values_snapshot, values_sha256: snap.values_sha256 },
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot, values_sha256: "sha256:" + createHash("sha256").update(JSON.stringify(["x", "y"])).digest("hex"), values: ["x", "y"] },
    { values_ref: snap.values_ref, values_snapshot: snap.values_snapshot, values_sha256: snap.values_sha256 + "\n" },
  ];
  const SNAP_SETS = [
    regSnapshots, null, [], [null, 1, ...regSnapshots], [{ ...snap, values: [...snap.values, "ZZZ"] }], [{ ...snap, values: [...snap.values, "ZZZ"] }, snap],
    [snap, { ...snap, values: ["ZZZ"] }], [{ ...snap, values_sha256: snap.values_sha256.toUpperCase() }], { 0: snap }, [{ ...snap, values: null }],
  ];
  for (const form of [...ENUM_FORMS, ...EXTERNAL]) {
    M("enum form " + JSON.stringify(form).slice(0, 120));
    const def = [{ action_type: "e.1", required_fields: [{ name: "c", type: "enum", ...form }] }];
    for (const v of ["x", "y", "USD", "ZZZ", "x ", "", null, 1, "p"]) {
      emit("defs", { op: "compute", obj: b64(render({ action_type: "e.1", c: v })), defs: def, snaps_ref: "iso", suite: "jcs-sha256" });
    }
    for (const snaps of SNAP_SETS) {
      emit("defs", { op: "compute", obj: b64(render({ action_type: "e.1", c: "USD" })), defs: def, snaps, suite: "jcs-sha256" });
      emit("defs", { op: "compute", obj: b64(render({ action_type: "e.1", c: "ZZZ" })), defs: def, snaps, suite: "jcs-sha256" });
    }
  }
  // definition shapes
  const shapes = [
    null, 1, "x", {}, [], [null], [1], [{}], [{ action_type: "a.1" }], [{ action_type: ["a.1"] }], [{ action_type: "a.1", required_fields: {} }],
    [{ action_type: "a.1", required_fields: [{ name: "x" }] }], [{ action_type: "a.1", required_fields: [{ name: "x", type: null }] }],
    [{ action_type: "a.1", required_fields: [{ name: null, type: "string" }] }], [{ action_type: "a.1", required_fields: [{ name: "__proto__", type: "object" }] }],
    [{ action_type: "a.1", required_fields: [{ name: "toString", type: "string" }] }], [{ action_type: "a.1", required_fields: [{ name: "constructor", type: "string" }] }],
    [{ action_type: "a.1", required_fields: [{ name: "x", type: "string" }, { name: "x", type: "integer" }] }],
    [{ action_type: "a.1", optional_fields: [{ name: "x", type: "integer" }], required_fields: [{ name: "x", type: "string" }] }],
    [{ action_type: "a.1", required_fields: [{ name: "", type: "string" }] }], [{ action_type: "a.1", required_fields: [{ name: "\ud800", type: "string" }] }],
    [{ action_type: "a.1", required_fields: null, optional_fields: [{ name: "x", type: "string" }] }],
  ];
  const objs = [{ action_type: "a.1" }, { action_type: "a.1", x: "s" }, { action_type: "a.1", x: 1 }, { action_type: "a.1", "": "s" }, { action_type: "a.1", __proto__: null }];
  for (const d of shapes) for (const o of objs) {
    M("definition shape " + JSON.stringify(d).slice(0, 120));
    emit("defs", { op: "compute", obj: b64(render(o)), defs: d, snaps_ref: "iso", suite: "jcs-sha256" });
    emit("defs", { op: "verify", obj: b64(render(o)), defs: d, snaps_ref: "iso", caid: computeRef(A1_OBJ, DEF_A1).caid });
  }
  M("__proto__ as declared field");
  emit("defs", { op: "compute", obj: b64(render({ action_type: "a.1", __proto__: "x" })), defs: [{ action_type: "a.1", required_fields: [{ name: "__proto__", type: "string" }] }], suite: "jcs-sha256" });
  emit("defs", { op: "compute", obj: b64('{"action_type":"a.1","__proto__":"x"}'), defs: [{ action_type: "a.1", required_fields: [{ name: "__proto__", type: "string" }] }], suite: "jcs-sha256" });
  emit("defs", { op: "compute", obj: b64('{"action_type":"a.1"}'), defs: [{ action_type: "a.1", required_fields: [{ name: "__proto__", type: "object" }] }], suite: "jcs-sha256" });
  M("compute option suite shape");
  for (const suite of [null, 1, true, [], ["jcs-sha256"], { a: 1 }, "jcs-sha256", "JCS-SHA256"]) {
    emit("defs", { op: "compute", obj: b64(render(A1_OBJ)), defs_ref: "a1", suite });
  }
}

// ================================================================ vec-map
function segments(pointer) {
  return pointer.slice(1).split("/").map((p) => p.replaceAll("~1", "/").replaceAll("~0", "~"));
}
function mutateAt(root, op) {
  const parts = segments(op.path);
  let parent = root;
  for (const part of parts.slice(0, -1)) parent = parent[Array.isArray(parent) ? Number(part) : part];
  const key = Array.isArray(parent) ? Number(parts.at(-1)) : parts.at(-1);
  if (op.op === "delete") {
    if (Array.isArray(parent)) parent.splice(key, 1);
    else delete parent[key];
  } else parent[key] = clone(op.value);
}
function buildSide(corpus, d) {
  const profile = clone(corpus.profiles[d.profile]);
  return {
    source: clone(corpus.sources[d.source]),
    profile,
    source_descriptor: clone(profile.source_format),
    expected_profile_hash: d.pin === "profile" ? mappingProfileHash(profile) : d.pin,
    native_verified: d.native_verified !== false,
  };
}
function vectorSides(corpus, v) {
  const left = buildSide(corpus, v.left);
  const right = buildSide(corpus, v.right);
  for (const op of v.mutations || []) mutateAt(op.side === "left" ? left[op.target] : right[op.target], op);
  for (const s of v.repin_after_mutation || []) {
    const side = s === "left" ? left : right;
    side.expected_profile_hash = mappingProfileHash(side.profile);
  }
  return { left, right };
}
const LONG_STRINGS = ["a".repeat(512), "a".repeat(513), "é".repeat(256), "é".repeat(257), "é".repeat(300), "é".repeat(512), "😀".repeat(128), "😀".repeat(129), "😀".repeat(256), "😀".repeat(300), "€".repeat(171), "€".repeat(200)];
function profileMutants(p) {
  const out = [];
  const set = (label, f) => {
    const q = clone(p);
    try {
      f(q);
    } catch {
      return;
    }
    out.push([label, q]);
  };
  set("omitted_source_fields=null", (q) => { q.omitted_source_fields = null; });
  set("omitted_source_fields absent", (q) => { delete q.omitted_source_fields; });
  set("omitted_source_fields=[{}]", (q) => { q.omitted_source_fields = [{}]; });
  set("omitted_source_fields one entry, no-loss policy", (q) => { q.omitted_source_fields = [{ source_path: "/__omitted__", reason: "r" }]; });
  set("omitted_source_fields one entry, declared-loss policy", (q) => { q.omitted_source_fields = [{ source_path: "/__omitted__", reason: "r" }]; q.loss_policy = "declared-source-semantic-loss"; });
  set("material_source_paths duplicate", (q) => { q.material_source_paths = [...q.material_source_paths, q.material_source_paths[0]]; });
  set("material_source_paths=[{}]", (q) => { q.material_source_paths = [{}]; });
  set("material_source_paths=[[]]", (q) => { q.material_source_paths = [[]]; });
  set("material_source_paths=[1]", (q) => { q.material_source_paths = [1]; });
  set("material_source_paths + {}", (q) => { q.material_source_paths = [...q.material_source_paths, {}]; });
  set("material_source_paths=null", (q) => { q.material_source_paths = null; });
  set("material_source_paths=[]", (q) => { q.material_source_paths = []; });
  set("loss_policy=[..]", (q) => { q.loss_policy = ["no-material-field-loss"]; });
  set("loss_policy={}", (q) => { q.loss_policy = { a: 1 }; });
  set("loss_policy=null", (q) => { q.loss_policy = null; });
  set("transform=[..]", (q) => { q.rules[0].transform = ["copy"]; });
  set("transform={}", (q) => { q.rules[0].transform = { a: 1 }; });
  set("transform=COPY", (q) => { q.rules[0].transform = "COPY"; });
  for (const tf of [null, true, false, ["memo"], "null", "Amount", "a-b", "action_type", 1, "a\n", ""]) set("target_field=" + JSON.stringify(tf), (q) => { q.rules[0].target_field = tf; });
  set("source_path + LF", (q) => { q.rules[0].source_path = q.rules[0].source_path + "\n"; });
  set("source_path=~", (q) => { q.rules[0].source_path = "~"; });
  set("source_path=/~2", (q) => { q.rules[0].source_path = "/~2"; });
  set("source_path=[..]", (q) => { q.rules[0].source_path = ["/a"]; });
  set("rules=[]", (q) => { q.rules = []; });
  set("rules=null", (q) => { q.rules = null; });
  set("rules + null", (q) => { q.rules.push(null); });
  set("rule extra member", (q) => { q.rules[0].extra = 1; });
  set("profile extra member", (q) => { q.extra = 1; });
  set("@version v2", (q) => { q["@version"] = "CAID-MAPPING-PROFILE-v2"; });
  for (const s of pickN(LONG_STRINGS, 4)) set("profile_id long " + describeLong(s), (q) => { q.profile_id = s; });
  for (const s of pickN(LONG_STRINGS, 2)) set("source_format.schema long " + describeLong(s), (q) => { q.source_format.schema = s; });
  set("target_action_type 600 chars", (q) => { q.target_action_type = "a".repeat(600); });
  set("target_action_type empty", (q) => { q.target_action_type = ""; });
  set("target_action_type=1", (q) => { q.target_action_type = 1; });
  set("source_format=null", (q) => { q.source_format = null; });
  set("source_format extra member", (q) => { q.source_format.extra = "x"; });
  return out;
}
function describeLong(s) {
  return `${[...s][0].codePointAt(0).toString(16)}: ${s.length} UTF-16 units, ${[...s].length} code points, ${Buffer.byteLength(s)} UTF-8 bytes`;
}
function familyVecMap() {
  for (const corpus of [mapCorpus, interopCorpus]) {
    tables.defs["mapdefs:" + corpus["@version"]] = corpus.definitions;
    const defsRef = "mapdefs:" + corpus["@version"];
    const snaps = corpus.enum_snapshots;
    for (const v of corpus.vectors) {
      const { left, right } = vectorSides(corpus, v);
      const emitCmp = (l, r, extra = {}) => {
        /** @type {Record<string, any>} */
        const c = { op: "compare", left: l, right: r, defs_ref: defsRef, suite: corpus.suite, ...extra };
        if (snaps) c.snaps_ref = "iso";
        emit("vec-map", c);
      };
      M("identity") && emitCmp(left, right);
      const n = QUICK ? 3 : corpus === interopCorpus ? 10 : 30;
      const muts = profileMutants(left.profile);
      for (const [label, pm] of pickN(muts, n)) {
        M("profile: " + label);
        const l = clone(left);
        l.profile = pm;
        l.source_descriptor = pm && typeof pm === "object" && pm.source_format && typeof pm.source_format === "object" ? clone(pm.source_format) : l.source_descriptor;
        if (rnd() < 0.8) l.expected_profile_hash = mappingProfileHash(pm);
        emitCmp(l, right);
      }
      M("pin-variant");
      for (const pin of [left.expected_profile_hash?.toUpperCase?.(), (left.expected_profile_hash || "") + " ", null, 1, ""]) emitCmp({ ...clone(left), expected_profile_hash: pin }, right);
      M("native_verified-variant");
      for (const nv of [true, false, "true", 1, null]) emitCmp({ ...clone(left), native_verified: nv }, right);
      for (const suite of ["", "cbor-sha256", "JCS-SHA256", undefined]) {
        M("compare suite=" + JSON.stringify(suite));
        const c = { op: "compare", left, right, defs_ref: defsRef };
        if (snaps) c.snaps_ref = "iso";
        if (suite !== undefined) c.suite = suite;
        emit("vec-map", c);
      }
      // source mutations at mapped pointers
      const rules = Array.isArray(left.profile?.rules) ? left.profile.rules : [];
      for (const rule of pickN(rules, QUICK ? 1 : 3)) {
        if (typeof rule?.source_path !== "string") continue;
        for (const val of pickN([null, "\ud800", "x ", 1, { $raw: "1.5" }, [], {}, "1.50", "USD ", "😀", "A".repeat(64), "a".repeat(64), 9007199254740993], QUICK ? 2 : 5)) {
          const l = clone(left);
          M("source value=" + (typeof val === "string" ? (val.length > 20 ? "long string" : JSON.stringify(val)) : JSON.stringify(val)));
          try {
            if (val && typeof val === "object" && "$raw" in val) continue;
            mutateAt(l.source, { op: "set", path: rule.source_path, value: val });
          } catch {
            continue;
          }
          emitCmp(l, right);
        }
        const l = clone(left);
        M("source member deleted");
        try {
          mutateAt(l.source, { op: "delete", path: rule.source_path });
          emitCmp(l, right);
        } catch {}
      }
      // map op with the left side's source as raw text variants
      const srcText = render(left.source);
      const mapCase = (buf, note) => {
        const c = { op: "map", src: b64buf(buf), profile: left.profile, desc: left.source_descriptor, pin: left.expected_profile_hash, nv: left.native_verified, defs_ref: defsRef, suite: corpus.suite, note };
        if (snaps) c.snaps_ref = "iso";
        emit("vec-map", c);
      };
      mapCase(Buffer.from(srcText), "as-is");
      if (srcText.startsWith("{") && srcText.length > 2) {
        const firstKey = Object.keys(left.source)[0];
        mapCase(Buffer.from("{" + JSON.stringify(firstKey) + ':"dup",' + srcText.slice(1)), "dup-first-key");
        mapCase(Buffer.from(srcText.slice(0, -1) + "," + JSON.stringify(firstKey) + ':"dup"}'), "dup-last-key");
        mapCase(Buffer.from(srcText.slice(0, -1) + ',"zz":"\\ud800"}'), "lone-surrogate-extra");
        mapCase(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(srcText)]), "bom");
        mapCase(Buffer.from(srcText.slice(0, -1) + ',"zz":1' + "0".repeat(4400) + "}"), "big-int-extra");
      }
    }
  }
}

// ================================================================ map-craft
function familyMapCraft() {
  const def = { action_type: "m.1", required_fields: [{ name: "a", type: "string" }, { name: "b", type: "string" }], optional_fields: [{ name: "memo", type: "string" }] };
  tables.defs.m1 = [def];
  /** @returns {any} */
  const baseProfile = () => ({
    "@version": "CAID-MAPPING-PROFILE-v1",
    profile_id: "urn:x:m:1",
    source_format: { media_type: "application/json", schema: "urn:x:s:1", version: "1" },
    target_action_type: "m.1",
    loss_policy: "no-material-field-loss",
    material_source_paths: ["/a", "/b"],
    rules: [
      { source_path: "/a", target_field: "a", transform: "copy" },
      { source_path: "/b", target_field: "b", transform: "copy" },
    ],
  });
  const source = { a: "x", b: "y", c: "z", "a\n": "NL", n: [0, 1, 2], "~": "tilde", "/": "slash", h: "a".repeat(64), H: "A".repeat(64), e: "😀" };
  const mc = (profile, extra = {}) => {
    const c = {
      op: "map", source: extra.source ?? source, profile,
      desc: extra.desc ?? (profile && typeof profile === "object" ? profile.source_format : null),
      pin: "pin" in extra ? extra.pin : mappingProfileHash(profile), nv: "nv" in extra ? extra.nv : true, defs: extra.defs ?? [def],
    };
    if ("suite" in extra) c.suite = extra.suite;
    if (extra.src) {
      delete c.source;
      c.src = extra.src;
    }
    emit("map-craft", c);
  };
  M("identity") && mc(baseProfile());
  // newline-joined material list collision (JS compares sorted lists joined with "\n")
  { const p = baseProfile(); p.rules = [{ source_path: "/a\n/b", target_field: "a", transform: "copy" }, { source_path: "/c", target_field: "b", transform: "copy" }]; p.material_source_paths = ["/a", "/b", "/c"]; M("rule source LF-joined vs material list (join collision)") && mc(p); }
  { const p = baseProfile(); p.rules = [{ source_path: "/a\n/b", target_field: "a", transform: "copy" }, { source_path: "/c", target_field: "b", transform: "copy" }]; p.material_source_paths = ["/a\n/b", "/c"]; M("rule source with LF, material matches") && mc(p); }
  // LF-join collision where the JS check passes and the mapping succeeds
  {
    M("LF-joined rule source maps while material_source_paths lists other paths");
    const p = baseProfile();
    p.rules = [{ source_path: "/a\n/b", target_field: "a", transform: "copy" }, { source_path: "/c", target_field: "b", transform: "copy" }];
    p.material_source_paths = ["/a", "/b", "/c"];
    mc(p, { source: { "a\n": { b: "from-a-newline-b" }, a: "x", b: "y", c: "z" } });
  }
  // non-string suite through the mapping layer
  for (const suite of [[], {}, null, 1]) M("map suite=" + JSON.stringify(suite)) && mc(baseProfile(), { suite });
  // target_field coercion
  for (const tf of [null, true, false, ["memo"], "null", ["b"]]) { M("extra rule target_field=" + JSON.stringify(tf)); const p = baseProfile(); p.rules.push({ source_path: "/c", target_field: tf, transform: "copy" }); p.material_source_paths.push("/c"); mc(p); }
  { M("required rule target_field=[\"b\"]"); const p = baseProfile(); p.rules[1].target_field = ["b"]; mc(p); }
  { M("target_field=null + definition field name=null"); const d2 = { ...def, required_fields: [...def.required_fields, { name: null, type: "string" }] }; const p = baseProfile(); p.rules.push({ source_path: "/c", target_field: null, transform: "copy" }); p.material_source_paths.push("/c"); mc(p, { defs: [d2] }); }
  // omitted_source_fields null vs absent vs []
  for (const om of [null, [], undefined, [{ source_path: "/c", reason: "r" }]]) { M("omitted_source_fields=" + JSON.stringify(om)); const p = baseProfile(); if (om !== undefined) p.omitted_source_fields = om; mc(p); }
  // unhashable members where a set/dict lookup happens
  { M("material_source_paths=[{}]"); const p = baseProfile(); p.material_source_paths = [{}]; mc(p); }
  { M("material_source_paths=[\"/a\",[\"/b\"]]"); const p = baseProfile(); p.material_source_paths = ["/a", ["/b"]]; mc(p); }
  { M("loss_policy=[]"); const p = baseProfile(); p.loss_policy = []; mc(p); }
  { M("transform=[]"); const p = baseProfile(); p.rules[0].transform = []; mc(p); }
  { M("transform={}"); const p = baseProfile(); p.rules[0].transform = {}; mc(p); }
  // string-length limits in UTF-16 units / code points / UTF-8 bytes
  for (const s of LONG_STRINGS) {
    for (const where of ["profile_id", "media_type", "schema", "version"]) {
      M(where + " long " + describeLong(s));
      const p = baseProfile();
      if (where === "profile_id") p.profile_id = s;
      else p.source_format[where] = s;
      mc(p);
    }
    M("omission reason long " + describeLong(s.repeat(4)));
    const p = baseProfile();
    p.omitted_source_fields = [{ source_path: "/c", reason: s.repeat(4) }];
    p.loss_policy = "declared-source-semantic-loss";
    mc(p);
  }
  // target_action_type longer than 512 with a matching definition
  for (const n of [512, 513, 600]) {
    M("target_action_type " + n + " chars with matching definition");
    const t = "m" + "a".repeat(n - 4) + ".1";
    const p = baseProfile();
    p.target_action_type = t;
    mc(p, { defs: [{ ...def, action_type: t }] });
  }
  { M("target_action_type 300 x U+00E9 with matching definition"); const t = "é".repeat(300); const p = baseProfile(); p.target_action_type = t; mc(p, { defs: [{ ...def, action_type: t }] }); }
  // suite handling
  for (const suite of ["", "jcs-sha256", "cbor-sha256", "JCS-SHA256"]) M("map suite=" + JSON.stringify(suite)) && mc(baseProfile(), { suite });
  // pointers
  for (const sp of ["/n/01", "/n/-1", "/n/99999999999999999999", "/n/1", "/n/3", "/~0", "/~1", "/~01", "/~2", "/a~", "", "a", "/", "/a/b", "/n/1/x", "/e", "/" + "é".repeat(1024), "/" + "é".repeat(1025), "/" + "a".repeat(2047), "/" + "a".repeat(2048)]) {
    M("pointer " + JSON.stringify(sp.length > 30 ? sp.slice(0, 12) + "...(" + Buffer.byteLength(sp) + " bytes)" : sp));
    const p = baseProfile();
    p.rules[1].source_path = sp;
    p.material_source_paths = ["/a", sp];
    mc(p);
  }
  // transforms
  for (const [sp, tr] of [["/h", "sha256-hex-to-digest"], ["/H", "sha256-hex-to-digest"], ["/e", "sha256-utf8"], ["/n", "sha256-jcs"], ["/n", "sha256-utf8"], ["/n", "copy"], ["/a", "sha256-utf8"]]) {
    M("transform " + tr + " on " + sp);
    const p = baseProfile();
    p.rules[1] = { source_path: sp, target_field: "b", transform: tr };
    p.material_source_paths = ["/a", sp];
    mc(p);
    const p2 = baseProfile();
    p2.rules.push({ source_path: sp === "/a" ? "/c" : sp, target_field: "memo", transform: tr });
    p2.material_source_paths.push(sp === "/a" ? "/c" : sp);
    mc(p2);
  }
  // raw source texts
  const P = baseProfile();
  for (const [note, text] of [["dup-a", '{"a":"x","a":"y","b":"y"}'], ["dup-a-rev", '{"a":"y","a":"x","b":"y"}'], ["lone", '{"a":"x\\ud800","b":"y"}'], ["lone-unmapped", '{"a":"x","b":"y","z":"\\udfff"}'],
    ["num-1.0", '{"a":"x","b":"y","memo":1.0}'], ["big", '{"a":"x","b":"y","z":1' + "0".repeat(4400) + "}"], ["nan", '{"a":"x","b":"y","z":NaN}']]) {
    mc(P, { src: Buffer.from(text).toString("base64") });
  }
  mc(P, { src: Buffer.concat([Buffer.from('{"a":"x","b":"'), Buffer.from([0xed, 0xa0, 0x80]), Buffer.from('"}')]).toString("base64") });
  // descriptor / pin / nv shapes
  M("descriptor reordered") && mc(P, { desc: { version: "1", schema: "urn:x:s:1", media_type: "application/json" } });
  M("descriptor extra member") && mc(P, { desc: { ...P.source_format, extra: 1 } });
  M("descriptor null") && mc(P, { desc: null });
  M("descriptor array") && mc(P, { desc: [] });
  M("pin uppercase") && mc(P, { pin: String(mappingProfileHash(P)).toUpperCase() });
  M("pin null") && mc(P, { pin: null });
  M("pin empty") && mc(P, { pin: "" });
  M("nv string") && mc(P, { nv: "true" });
  M("nv 1") && mc(P, { nv: 1 });
  M("profile null") && mc(null, { pin: null });
  M("profile array") && mc([], { pin: null });
  M("profile string") && mc("x", { pin: null });
  M("source array") && mc(P, { source: [] });
  M("source null") && mc(P, { source: null });
  M("source string") && mc(P, { source: "x" });
  // compare with non-object sides
  for (const side of [null, [], "x", 1, {}]) {
    M("compare side=" + JSON.stringify(side));
    emit("map-craft", { op: "compare", left: side, right: side, defs: [def] });
    emit("map-craft", { op: "compare", left: { source, profile: P, source_descriptor: P.source_format, expected_profile_hash: mappingProfileHash(P), native_verified: true }, right: side, defs: [def] });
  }
  const sideP = { source, profile: P, source_descriptor: P.source_format, expected_profile_hash: mappingProfileHash(P), native_verified: true };
  M("compare identical") && emit("map-craft", { op: "compare", left: sideP, right: sideP, defs: [def] });
  M("compare different") && emit("map-craft", { op: "compare", left: sideP, right: { ...sideP, source: { ...source, a: "other" } }, defs: [def] });
  M("compare suite=\"\"") && emit("map-craft", { op: "compare", left: sideP, right: sideP, defs: [def], suite: "" });
}

// ================================================================ run
familyVecCore();
familyRegistry();
familyGrammar();
familyCode();
familyNative();
familyNumber();
const jsonTexts = familyJson();
familyCaidStr();
familyDefs();
familyVecMap();
familyMapCraft();

writeFileSync(path.join(OUT, "tables.json"), JSON.stringify(tables));
const lines = cases.map((c) => JSON.stringify(c)).join("\n") + "\n";
writeFileSync(path.join(OUT, "cases.jsonl"), lines);
const byOp = {};
for (const c of cases) byOp[c.op] = (byOp[c.op] || 0) + 1;
writeFileSync(path.join(OUT, "gen-stats.json"), JSON.stringify({ seed: SEED, quick: QUICK, total: cases.length, byFamily: counters, byOp, jsonTexts, bytes: lines.length }, null, 2));
console.log(JSON.stringify({ total: cases.length, byFamily: counters, byOp }));
