// run-vectors.mjs - runs the CAID core corpus (conformance/vectors.json,
// version 5) against caid.mjs. Prints PASS or FAIL per vector and exits
// nonzero on any failure.
//
// Usage: node run-vectors.mjs [--corpus FILE]
//
// The corpus file is read with this port's own strict decoder
// (decodeCaidDocument), never with JSON.parse.
//
// Vector kinds:
//   decode      decodeCaidJson(bytes); expect {ok: true} (optionally with
//               value) or {ok: false, refusals: ["malformed_json"]}
//   parse       parseCaid(input.caid)
//   compute     computeCaidJson(bytes, {suite, definitions, enumSnapshots})
//   verify      verifyCaidJson(bytes, input.caid, {definitions,
//               enumSnapshots, expectedDefinitionSha256})
//   definition  definitionSha256(input.definition), or of the decoded
//               document when the input is JSON text
//
// JSON text inputs take exactly one form: input.json (a string, encoded as
// UTF-8), input.json_b64 (exact octets, base64) or input.json_repeat
// ({prefix, unit, count, suffix}, for inputs of a mebibyte and more).
//
// Native lane: for compute and verify, when the text decodes, the runner
// also calls computeCaid or verifyCaid on the decoded value and requires
// the identical result (-04 Section 2.5). A vector may instead carry a host
// value that no conforming JSON text decoder produces, passed to the native
// entry point only, in one of two forms:
//   input.native       the corpus native-lane encoding: any JSON value,
//                      read as itself, except objects whose only member
//                      starts with "$": {"$units": [u, ...]} (a string of
//                      these UTF-16 code units), {"$object": [[k, v], ...]}
//                      (members in order; k may be a $units string),
//                      {"$nest": {depth, container, leaf}}, and
//                      {"$host": "nan" | "infinity" | "-infinity" |
//                      "negative_zero" | "cyclic" | "opaque"}
//   input.native_json  JSON text parsed with the host parser (JSON.parse
//                      keeps lone-surrogate escapes)
//
// Optional per-vector "relation" cross-checks over the computed values:
//   same_caid_as        this vector's CAID must equal that vector's
//   different_caid_from this vector's CAID must differ from that vector's

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import {
  computeCaid,
  computeCaidJson,
  decodeCaidDocument,
  decodeCaidJson,
  definitionSha256,
  parseCaid,
  verifyCaid,
  verifyCaidJson,
} from "./caid.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const corpusIndex = argv.indexOf("--corpus");
const vectorsPath = corpusIndex >= 0
  ? resolve(argv[corpusIndex + 1] ?? "")
  : join(here, "..", "..", "conformance", "vectors.json");

const decodedCorpus = decodeCaidDocument(readFileSync(vectorsPath));
if (!decodedCorpus.ok) {
  console.log("FAIL corpus: " + vectorsPath + " is not a strict JSON text");
  process.exit(1);
}
const corpus = decodedCorpus.value;
if (corpus.version !== 5) {
  console.log("FAIL corpus: this runner reads core corpus version 5, got " + JSON.stringify(corpus.version));
  process.exit(1);
}

// Key-order-insensitive comparison: objects compare by sorted members.
function stable(value) {
  return JSON.stringify(value, (key, v) => (v && typeof v === "object" && !Array.isArray(v)
    ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]]))
    : v));
}

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

// The exact octets of a vector's JSON text input, or null when it has none.
function inputBytes(input) {
  const forms = ["json", "json_b64", "json_repeat"].filter((k) => hasOwn(input, k));
  if (forms.length > 1) throw new Error("more than one JSON text form");
  if (forms.length === 0) return null;
  if (forms[0] === "json") return Buffer.from(input.json, "utf8");
  if (forms[0] === "json_b64") return Buffer.from(input.json_b64, "base64");
  const r = input.json_repeat;
  return Buffer.concat([
    Buffer.from(r.prefix ?? "", "utf8"),
    Buffer.from(String(r.unit).repeat(r.count), "utf8"),
    Buffer.from(r.suffix ?? "", "utf8"),
  ]);
}

// The host value a native-lane encoding denotes (see the header).
function nativeTag(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return null;
  const keys = Object.keys(v);
  return keys.length === 1 && keys[0].startsWith("$") ? keys[0] : null;
}
function buildNative(encoded) {
  const own = (obj, key, value) => {
    Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
  };
  const build = (v, enclosing) => {
    const tag = nativeTag(v);
    if (tag === "$units") return String.fromCharCode(...v.$units);
    if (tag === "$object") {
      const out = {};
      for (const [k, x] of v.$object) {
        const key = typeof k === "string" ? k : build(k, enclosing);
        own(out, key, undefined);
        out[key] = build(x, out);
      }
      return out;
    }
    if (tag === "$nest") {
      const { depth, container, leaf } = v.$nest;
      let value = build(leaf, enclosing);
      for (let i = 0; i < depth; i++) value = container === "object" ? { a: value } : [value];
      return value;
    }
    if (tag === "$host") {
      switch (v.$host) {
        case "nan": return NaN;
        case "infinity": return Infinity;
        case "-infinity": return -Infinity;
        case "negative_zero": return -0;
        case "cyclic": return enclosing;
        case "opaque": return new Map();
        default: throw new Error("unknown $host " + v.$host);
      }
    }
    if (tag !== null) throw new Error("unknown native tag " + tag);
    if (Array.isArray(v)) {
      const out = [];
      for (const x of v) out.push(build(x, out));
      return out;
    }
    if (v !== null && typeof v === "object") {
      const out = {};
      for (const k of Object.keys(v)) {
        own(out, k, undefined);
        out[k] = build(v[k], out);
      }
      return out;
    }
    return v;
  };
  return build(encoded, undefined);
}

let pass = 0;
let fail = 0;
const actualCaids = new Map();

function report(id, ok, detail) {
  if (ok) {
    pass++;
    console.log("PASS " + id);
  } else {
    fail++;
    console.log("FAIL " + id);
    if (detail) console.log("     " + detail);
  }
}

function run(v) {
  const input = v.input ?? {};
  const definitions = v.definitions;
  const enumSnapshots = corpus.enum_snapshots;
  const bytes = inputBytes(input);
  const nativeValue = hasOwn(input, "native") ? { value: buildNative(input.native) }
    : hasOwn(input, "native_json") ? { value: JSON.parse(input.native_json) } : null;
  if (v.kind === "decode") {
    const r = decodeCaidJson(bytes);
    if (!hasOwn(v.expect, "value") && r.ok) return { actual: { ok: true } };
    return { actual: r };
  }
  if (v.kind === "parse") return { actual: parseCaid(input.caid) };
  if (v.kind === "definition") {
    if (bytes === null) return { actual: definitionSha256(input.definition) };
    const d = decodeCaidDocument(bytes);
    return { actual: d.ok ? definitionSha256(d.value) : d };
  }
  if (v.kind === "compute") {
    const options = { suite: input.suite, definitions, enumSnapshots };
    if (nativeValue) return { actual: computeCaid(nativeValue.value, options) };
    const actual = computeCaidJson(bytes, options);
    const decoded = decodeCaidJson(bytes);
    return { actual, native: decoded.ok ? computeCaid(decoded.value, options) : undefined };
  }
  if (v.kind === "verify") {
    const options = { definitions, enumSnapshots };
    if (hasOwn(input, "expected_definition_sha256")) options.expectedDefinitionSha256 = input.expected_definition_sha256;
    if (nativeValue) return { actual: verifyCaid(nativeValue.value, input.caid, options) };
    const actual = verifyCaidJson(bytes, input.caid, options);
    const decoded = decodeCaidJson(bytes);
    return { actual, native: decoded.ok ? verifyCaid(decoded.value, input.caid, options) : undefined };
  }
  throw new Error("unknown vector kind: " + v.kind);
}

for (const v of corpus.vectors) {
  let result;
  try {
    result = run(v);
  } catch (error) {
    report(v.id, false, "runner error: " + (error && error.message));
    continue;
  }
  const { native } = result;
  const actual = /** @type {any} */ (result.actual);
  if (v.kind === "compute" && actual && typeof actual.caid === "string") actualCaids.set(v.id, actual.caid);
  const ok = stable(actual) === stable(v.expect);
  report(v.id, ok, ok ? null : "expected " + stable(v.expect) + " got " + stable(actual));
  if (native !== undefined) {
    const same = stable(native) === stable(actual);
    report(v.id + " (native parity)", same, same ? null : "native " + stable(native) + " byte " + stable(actual));
  }
}

for (const v of corpus.vectors) {
  if (!v.relation) continue;
  const targetId = v.relation.same_caid_as || v.relation.different_caid_from;
  const mine = actualCaids.get(v.id);
  const theirs = actualCaids.get(targetId);
  if (mine === undefined || theirs === undefined) {
    report(v.id + " (relation)", false, "missing computed caid for relation");
    continue;
  }
  if (v.relation.same_caid_as) {
    report(v.id + " same_caid_as " + targetId, mine === theirs, mine === theirs ? null : mine + " != " + theirs);
  } else {
    report(v.id + " different_caid_from " + targetId, mine !== theirs, mine !== theirs ? null : "caids unexpectedly equal: " + mine);
  }
}

console.log("");
console.log(pass + " passed, " + fail + " failed, " + corpus.vectors.length + " vectors");
process.exit(fail > 0 ? 1 : 0);
