// run-grammar-vectors.mjs - runs a CAID grammar case list through this
// port's PUBLIC entry points, never through the generated matchers
// directly, so a port that keeps hand-written logic beside or instead of the
// generated constants fails here.
//
// Usage: node run-grammar-vectors.mjs --corpus FILE [--quiet]
//
// FILE is a CAID-GRAMMAR-CASES-v1 list, the full list that
// `node caid/spec/abnf-check.mjs --out FILE` writes: each case names a rule
// and says whether the ABNF interpreter accepts the input. The runner maps
// every rule onto the API that enforces it:
//
//   pattern:caid            parseCaid(input): malformed_caid unless it
//                           matches within the length limits; then the
//                           registry and the digest syntax, derived here
//                           from the formula of Appendix A.2, decide
//   pattern:action_type     parseCaid of an identifier carrying it, and
//                           computeCaid of an object of that type under a
//                           one-field definition; accepted exactly when it
//                           matches within the length limit
//   pattern:suite           parseCaid: not malformed_caid exactly when it
//                           matches
//   pattern:digest          parseCaid under an unregistered suite:
//                           unknown_suite exactly when it matches, else
//                           malformed_caid
//   suite_digest:<suite>    parseCaid succeeds exactly when it matches
//   pattern:amount_string   computeCaid, amount-string field
//   pattern:digest_field    computeCaid, digest field
//   pattern:timestamp       computeCaid, timestamp field (a matching value
//                           outside the month's days still refuses)
//   pattern:format_name     definition conformance of a code field's format
//   pattern:code_system     definition conformance of its code_system,
//                           within the length limit
//   code_format:<format>    computeCaid, code field of that format
//   pattern:array_index     mapAction with a source path through an array
//   pattern:hex_sha256      mapAction with the sha256-hex-to-digest transform
//
// It exits nonzero when any case disagrees.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { CAID_SPEC, computeCaid, parseCaid } from "./caid.mjs";
import { mapAction, mappingProfileHash } from "./mapping.mjs";

const argv = process.argv.slice(2);
const corpusIndex = argv.indexOf("--corpus");
const quiet = argv.includes("--quiet");
if (corpusIndex < 0 || !argv[corpusIndex + 1]) {
  console.log("usage: node run-grammar-vectors.mjs --corpus FILE [--quiet]   (FILE from node caid/spec/abnf-check.mjs --out FILE;"
    + " the committed grammar-vectors.json runs through caid/conformance/runners/run.mjs)");
  process.exit(2);
}
const corpusPath = resolve(argv[corpusIndex + 1]);

// The case list deliberately carries lone-surrogate escapes (the grammar
// must refuse them), which the strict decoder refuses by design, so it is
// read with the host parser. It is test data, never an action object.
let decoded;
try {
  decoded = { value: JSON.parse(readFileSync(corpusPath, "utf8")) };
} catch {
  decoded = { value: null };
}
if (!decoded.value || !Array.isArray(decoded.value.cases) || decoded.value["@version"] !== "CAID-GRAMMAR-CASES-v1") {
  console.log("FAIL corpus: " + corpusPath + " is not a CAID-GRAMMAR-CASES-v1 document");
  process.exit(1);
}

const DIGEST = "A".repeat(43); // 32 zero octets in jcs-sha256 digest syntax
const TYPE = "grammar.check.1";
const CODE_SYSTEM = "urn:example:grammar";
const UNREGISTERED_SUITE = "zz-unregistered";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
// The registered suites and the length limits (Section 2.6) come from the
// spec data; the digest syntax is derived independently here, from the
// formula of Appendix A.2, never from the generated matcher.
const SUITE_OCTETS = new Map(CAID_SPEC.suites.map((s) => [s.suite, s.digest_octets]));
const MAX = CAID_SPEC.pattern_max_octets;
if (SUITE_OCTETS.has(UNREGISTERED_SUITE)) throw new Error(`${UNREGISTERED_SUITE} is registered`);

// Appendix A.2: c = ceil(8n/6) base64url characters, the last with
// u = 6c - 8n zero low bits.
function digestSyntax(digest, octets) {
  const chars = Math.ceil((8 * octets) / 6);
  const unused = 6 * chars - 8 * octets;
  return digest.length === chars && [...digest].every((ch) => B64URL.includes(ch))
    && B64URL.indexOf(digest[digest.length - 1]) % (1 << unused) === 0;
}

// The parse result the grammar verdict and the registry predict for a CAID.
function expectedParse(input, match) {
  if (!match || input.length > MAX.caid) return "malformed_caid";
  const [, , actionType, suite, digest] = input.split(":");
  if (actionType.length > MAX.action_type) return "malformed_caid";
  if (!SUITE_OCTETS.has(suite)) return "unknown_suite";
  return digestSyntax(digest, SUITE_OCTETS.get(suite)) ? null : "malformed_caid";
}

const oneField = (field, actionType = TYPE) => [{ action_type: actionType, required_fields: [field] }];
const computeField = (field, value) => computeCaid(
  { action_type: TYPE, v: value },
  { suite: "jcs-sha256", definitions: oneField({ name: "v", ...field }) },
);
/** @param {{caid?: string}} r */
const isCaid = (r) => typeof r.caid === "string";
/** @param {{refusals?: string[]}} r */
const first = (r) => (r.refusals ? r.refusals[0] : undefined);

function daysInMonth(year, month) {
  if (month === 2) return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

// Maps one source path through a minimal pinned profile and returns the
// mapping's reasons ([] on success).
function mapThrough(sourcePath, source, transform) {
  const profile = {
    "@version": "CAID-MAPPING-PROFILE-v1",
    profile_id: "grammar",
    source_format: { media_type: "application/json", schema: "grammar", version: "1" },
    target_action_type: TYPE,
    loss_policy: "no-material-field-loss",
    material_source_paths: [sourcePath],
    rules: [{ source_path: sourcePath, target_field: "v", transform }],
  };
  const r = mapAction(source, {
    profile,
    sourceDescriptor: profile.source_format,
    expectedProfileHash: mappingProfileHash(profile),
    nativeVerified: true,
    definitions: oneField({ name: "v", type: transform === "copy" ? "integer" : "digest" }),
  });
  return r.ok ? [] : r.reasons;
}

const pointerEscape = (s) => s.replaceAll("~", "~0").replaceAll("/", "~1");

// Returns null when the port agrees with the grammar's verdict, else a
// description of the disagreement.
function check(rule, input, match) {
  const colon = rule.indexOf(":");
  const family = rule.slice(0, colon);
  const name = rule.slice(colon + 1);
  if (family === "suite_digest") {
    const r = parseCaid(`caid:1:${TYPE}:${name}:${input}`);
    return r.ok === match ? null : `parseCaid ok=${r.ok}`;
  }
  if (family === "code_format") {
    const r = computeField({ type: "code", code_system: CODE_SYSTEM, format: name }, input);
    if (match) return isCaid(r) ? null : `computeCaid refused ${JSON.stringify(r.refusals)}`;
    return !isCaid(r) && first(r) === "invalid_code:v" ? null : `computeCaid gave ${JSON.stringify(r)}`;
  }
  switch (name) {
    case "caid": {
      const r = parseCaid(input);
      const want = expectedParse(input, match);
      return (want === null ? r.ok : !r.ok && first(r) === want) ? null : `parseCaid gave ${JSON.stringify(r)}, want ${want ?? "ok"}`;
    }
    case "action_type": {
      const accepted = match && input.length <= MAX.action_type;
      const parsed = parseCaid(`caid:1:${input}:jcs-sha256:${DIGEST}`);
      if (parsed.ok !== accepted) return `parseCaid ok=${parsed.ok}`;
      const r = computeCaid({ action_type: input }, {
        suite: "jcs-sha256",
        definitions: [{ action_type: input, required_fields: [{ name: "v", type: "string" }] }],
      });
      const refusal = isCaid(r) ? null : first(r);
      if (accepted) return refusal === "missing_material_field:v" ? null : `computeCaid gave ${JSON.stringify(r)}`;
      return refusal === "invalid_action_type" ? null : `computeCaid gave ${JSON.stringify(r)}`;
    }
    case "suite": {
      const r = parseCaid(`caid:1:${TYPE}:${input}:${DIGEST}`);
      const malformed = !r.ok && first(r) === "malformed_caid";
      return malformed === !match ? null : `parseCaid gave ${JSON.stringify(r)}`;
    }
    case "digest": {
      // Under an unregistered suite the digest rule alone decides: a match
      // reaches the registry check (unknown_suite), anything else is
      // malformed_caid.
      const r = parseCaid(`caid:1:${TYPE}:${UNREGISTERED_SUITE}:${input}`);
      const want = match ? "unknown_suite" : "malformed_caid";
      return !r.ok && first(r) === want ? null : `parseCaid gave ${JSON.stringify(r)}, want ${want}`;
    }
    case "amount_string": {
      const r = computeField({ type: "amount-string" }, input);
      if (match) return isCaid(r) ? null : `computeCaid refused ${JSON.stringify(r.refusals)}`;
      return !isCaid(r) && first(r) === "invalid_amount:v" ? null : `computeCaid gave ${JSON.stringify(r)}`;
    }
    case "digest_field": {
      const r = computeField({ type: "digest" }, input);
      if (match) return isCaid(r) ? null : `computeCaid refused ${JSON.stringify(r.refusals)}`;
      return !isCaid(r) && first(r) === "mistyped_field:v" ? null : `computeCaid gave ${JSON.stringify(r)}`;
    }
    case "timestamp": {
      const r = computeField({ type: "timestamp" }, input);
      if (!match) return !isCaid(r) && first(r) === "mistyped_field:v" ? null : `computeCaid gave ${JSON.stringify(r)}`;
      const inMonth = Number(input.slice(8, 10)) <= daysInMonth(Number(input.slice(0, 4)), Number(input.slice(5, 7)));
      if (inMonth) return isCaid(r) ? null : `computeCaid refused ${JSON.stringify(r.refusals)}`;
      return !isCaid(r) && first(r) === "mistyped_field:v" ? null : `computeCaid accepted a day outside the month`;
    }
    case "format_name":
    case "code_system": {
      const field = { type: "code", code_system: CODE_SYSTEM, format: "nacha-sec" };
      field[name === "format_name" ? "format" : "code_system"] = input;
      const r = computeCaid({ action_type: TYPE }, { suite: "jcs-sha256", definitions: oneField({ name: "v", ...field }) });
      const invalid = !isCaid(r) && first(r) === "invalid_definition";
      const accepted = match && (name !== "code_system" || input.length <= MAX.code_system);
      return invalid === !accepted ? null : `computeCaid gave ${JSON.stringify(r)}`;
    }
    case "array_index": {
      const reasons = mapThrough(`/list/${pointerEscape(input)}`, { list: [1, 2, 3] }, "copy");
      const notIndex = reasons.some((x) => x === "invalid_source_path:" + `/list/${pointerEscape(input)}`
        || x === "invalid_mapping_profile");
      return notIndex === !match ? null : `mapAction gave ${JSON.stringify(reasons)}`;
    }
    case "hex_sha256": {
      const reasons = mapThrough("/h", { h: input }, "sha256-hex-to-digest");
      const mismatch = reasons.some((x) => x.startsWith("source_value_type_mismatch:")
        || x === "source_not_canonicalizable");
      return mismatch === !match ? null : `mapAction gave ${JSON.stringify(reasons)}`;
    }
    default:
      return `no public entry point is mapped for rule ${rule}`;
  }
}

let pass = 0;
let fail = 0;
const perRule = new Map();
for (const c of decoded.value.cases) {
  let problem;
  try {
    problem = check(c.rule, c.input, c.match);
  } catch (error) {
    problem = "runner error: " + (error && error.message);
  }
  const counts = perRule.get(c.rule) ?? { pass: 0, fail: 0 };
  if (problem === null) {
    pass++;
    counts.pass++;
  } else {
    fail++;
    counts.fail++;
    if (fail <= 50) console.log(`FAIL ${c.rule} ${JSON.stringify(c.input.slice(0, 120))} match=${c.match}: ${problem}`);
  }
  perRule.set(c.rule, counts);
}
if (!quiet) for (const [rule, counts] of perRule) console.log(`${counts.fail ? "FAIL" : "PASS"} ${rule}: ${counts.pass} cases`);
console.log(`${pass} passed, ${fail} failed, ${decoded.value.cases.length} grammar cases`);
process.exit(fail > 0 ? 1 : 0);
