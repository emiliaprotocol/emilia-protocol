// caid.mjs - CAID v1 reference implementation (JavaScript, ESM).
//
// Conforms to DESIGN.md (the normative core of this package).
// Suite support: jcs-sha256 only. cbor-sha256 is defined in the suite
// registry but is NOT implemented here; this implementation refuses it
// as unknown_suite. Say so honestly everywhere.
//
// Scope (from DESIGN.md section 5): CAID carries no trust semantics.
// It commits an identifier to canonical typed content. It does not
// prove the action was authorized, executed, safe, or wise. Nothing in
// this module verifies signatures, identity, or authorization.
//
// Fail-closed: junk input returns refusals with reasons, never throws.
//
// Dependencies: node:crypto only.

import { createHash } from "node:crypto";

const CAID_VERSION = "1";
const SUPPORTED_SUITES = new Set(["jcs-sha256"]);
// Suites that are defined in the registry and use a SHA-256 digest
// (43 unpadded base64url characters). Used for strict digest-length
// checking at parse time.
const SHA256_SUITES = new Set(["jcs-sha256", "cbor-sha256"]);
const SHA256_B64URL_LEN = 43;

// Grammar (strict, per DESIGN.md section 2 and 3).
const TYPE_SEGMENT_RE = /^[a-z][a-z0-9-]*$/;
const TYPE_VERSION_RE = /^[1-9][0-9]*$/;
const SUITE_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const AMOUNT_RE = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/;
const DIGEST_FIELD_RE = /^sha256:[0-9a-f]{64}$/;
// RFC 3339, UTC, trailing Z required. Optional fractional seconds.
const TIMESTAMP_RE =
  /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?Z$/;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isValidActionType(t) {
  if (typeof t !== "string") return false;
  const segments = t.split(".");
  if (segments.length < 2) return false;
  const version = segments[segments.length - 1];
  if (!TYPE_VERSION_RE.test(version)) return false;
  for (let i = 0; i < segments.length - 1; i++) {
    if (!TYPE_SEGMENT_RE.test(segments[i])) return false;
  }
  return true;
}

function daysInMonth(year, month) {
  // month is 1-12
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function isValidTimestamp(s) {
  const m = TIMESTAMP_RE.exec(s);
  if (!m) return false;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  return day <= daysInMonth(year, month);
}

function resolveDefinition(actionType, definitions) {
  if (!Array.isArray(definitions)) return null;
  for (const entry of definitions) {
    if (isPlainObject(entry) && entry.action_type === actionType) return entry;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Canonicalization: RFC 8785 JCS, implemented inline.
//
// DESIGN.md section 1 forbids non-integer JSON numbers anywhere in an
// action object, so the only numbers this canonicalizer must serialize
// are integers. For integers, JSON.stringify implements the ECMAScript
// Number-to-string algorithm that RFC 8785 requires, so it is
// JCS-correct here. JSON.stringify's string escaping (short escapes for
// control characters, lowercase \u00xx otherwise, literal UTF-8 for
// everything else) is also the RFC 8785 form. Object keys are sorted by
// UTF-16 code units, which is exactly the default JS string comparison.
// ---------------------------------------------------------------------------

/**
 * canonicalize(value) -> {ok: true, canonical: string}
 *                      | {ok: false, refusals: [string]}
 *
 * Refusals:
 *   unsupported_number - a number whose IEEE 754 double value is not an
 *                        integer with magnitude at most 2^53-1
 *                        (fractional, NaN, infinite, or out of range)
 *   unsupported_value  - a value outside the I-JSON data model: a string
 *                        or member name containing an unpaired UTF-16
 *                        surrogate (RFC 8785 section 3.2.2.2 requires a
 *                        JCS implementation to refuse it; JSON.parse
 *                        preserves "\ud800" escapes as lone surrogates),
 *                        or a value not representable in JSON at all
 *                        (undefined, function, symbol, bigint), so junk
 *                        JS input fails closed instead of being silently
 *                        dropped or rewritten.
 *
 * @param {*} value
 * @returns {{ok: true, canonical: string} | {ok: false, refusals: string[]}}
 */
export function canonicalize(value) {
  const refusals = [];
  const canonical = serialize(value, refusals);
  if (refusals.length > 0) {
    return { ok: false, refusals: dedupe(refusals) };
  }
  return { ok: true, canonical };
}

function serialize(v, refusals) {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") {
    // Value-based rule (DESIGN.md section 1): accepted iff the IEEE 754
    // double value is an integer with magnitude <= 2^53-1. Out-of-range
    // integers refuse here exactly as they do in the Python and Go
    // implementations; in-range integers stringify as plain decimal.
    if (
      !Number.isFinite(v) ||
      !Number.isInteger(v) ||
      Math.abs(v) > Number.MAX_SAFE_INTEGER
    ) {
      refusals.push("unsupported_number");
      return "";
    }
    return JSON.stringify(v);
  }
  if (t === "string") {
    if (hasUnpairedSurrogate(v)) {
      refusals.push("unsupported_value");
      return "";
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    return "[" + v.map((x) => serialize(x, refusals)).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(v).sort(); // UTF-16 code unit order
    const parts = keys.map((k) => {
      if (hasUnpairedSurrogate(k)) refusals.push("unsupported_value");
      return JSON.stringify(k) + ":" + serialize(v[k], refusals);
    });
    return "{" + parts.join(",") + "}";
  }
  refusals.push("unsupported_value");
  return "";
}

function dedupe(arr) {
  return [...new Set(arr)];
}

// True when s contains a UTF-16 surrogate code unit that is not half of a
// well-formed high/low pair. Such a string is not a sequence of Unicode
// scalar values, so it has no UTF-8 encoding and no RFC 8785 form.
function hasUnpairedSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Material-field validation (DESIGN.md sections 3 and 4).
// Returns refusals in deterministic order: all missing_material_field
// (definition order), then all mistyped_field / invalid_amount
// (definition order, required fields then optional fields).
// ---------------------------------------------------------------------------

function fieldList(def, key) {
  return Array.isArray(def[key]) ? def[key].filter(isPlainObject) : [];
}

// A field is present only as an own member of the action object. The `in`
// operator would also find names on Object.prototype (`__proto__`,
// `constructor`, `toString`, ...), which a JSON object never carries.
function hasOwnField(obj, name) {
  return Object.prototype.hasOwnProperty.call(obj, name) && obj[name] !== undefined;
}

function validateAgainstDefinition(obj, def, enumSnapshots) {
  const refusals = [];
  const required = fieldList(def, "required_fields");
  const optional = fieldList(def, "optional_fields");
  for (const f of required) {
    if (typeof f.name !== "string") continue;
    if (!hasOwnField(obj, f.name)) {
      refusals.push("missing_material_field:" + f.name);
    }
  }
  for (const f of [...required, ...optional]) {
    if (typeof f.name !== "string") continue;
    if (!hasOwnField(obj, f.name)) continue;
    const code = checkFieldType(obj[f.name], f, enumSnapshots);
    if (code) refusals.push(code + ":" + f.name);
  }
  return refusals;
}

// Resolve the closed value set declared by an enum field (DESIGN.md
// section 3). Presence is key presence: a member written as null is present
// and malformed, never the same as an absent member.
//
// - `values: [...]` without values_ref is the inline form.
// - `values_ref: "inline: a | b"` is the registry's compact inline form:
//   the text after "inline:" is split on "|" and each member is trimmed of
//   leading and trailing U+0020 SPACE only. A `values` member beside it must
//   equal the parsed list exactly.
// - An external values_ref is usable only with a non-empty values_snapshot
//   label and the SHA-256 digest of the JCS values array, resolved from an
//   embedded `values` array or an exactly matching local snapshot. A mutable
//   name or URL by itself never constrains an enum.
function resolveEnumValues(field, enumSnapshots) {
  const hasRef = Object.prototype.hasOwnProperty.call(field, "values_ref");
  const hasValues = Object.prototype.hasOwnProperty.call(field, "values");
  const ref = hasRef ? field.values_ref : undefined;
  let declared = hasValues ? field.values : undefined;

  if (typeof ref === "string" && ref.startsWith("inline:")) {
    const values = ref
      .slice("inline:".length)
      .split("|")
      .map(trimInlineMember);
    if (!validEnumValues(values)) return null;
    if (hasValues && !sameStringArray(declared, values)) return null;
    return values;
  }

  // A values array with no values_ref member is the inline form.
  if (!hasRef) return validEnumValues(declared) ? declared : null;

  if (
    typeof ref !== "string" ||
    ref.length === 0 ||
    typeof field.values_snapshot !== "string" ||
    field.values_snapshot.length === 0 ||
    typeof field.values_sha256 !== "string" ||
    !DIGEST_FIELD_RE.test(field.values_sha256)
  ) {
    return null;
  }

  // An embedded `values` member is the snapshot and must verify on its own;
  // only a definition without one resolves from the supplied snapshots.
  if (!hasValues && Array.isArray(enumSnapshots)) {
    const resolved = enumSnapshots.find(
      (snapshot) =>
        isPlainObject(snapshot) &&
        snapshot.values_ref === ref &&
        snapshot.values_snapshot === field.values_snapshot &&
        snapshot.values_sha256 === field.values_sha256
    );
    declared = resolved?.values;
  }
  if (!validEnumValues(declared)) return null;

  const canonical = canonicalize(declared);
  if (!canonical.ok) return null;
  const actual = "sha256:" + sha256(canonical.canonical).toString("hex");
  return actual === field.values_sha256 ? declared : null;
}

// Trim only U+0020 SPACE from both ends of an inline enum member. Every
// implementation trims exactly this set; other whitespace or control
// characters stay part of the member.
function trimInlineMember(value) {
  let start = 0;
  let end = value.length;
  while (start < end && value.charCodeAt(start) === 0x20) start++;
  while (end > start && value.charCodeAt(end - 1) === 0x20) end--;
  return value.slice(start, end);
}

function validEnumValues(values) {
  return (
    Array.isArray(values) &&
    values.length > 0 &&
    values.every((value) => typeof value === "string" && value.length > 0) &&
    new Set(values).size === values.length
  );
}

function sameStringArray(left, right) {
  return (
    Array.isArray(left) &&
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

// Returns null when valid, else "mistyped_field" or "invalid_amount".
function checkFieldType(value, field, enumSnapshots) {
  switch (field.type) {
    case "string":
      return typeof value === "string" ? null : "mistyped_field";
    case "amount-string":
      if (typeof value !== "string") return "mistyped_field";
      return AMOUNT_RE.test(value) ? null : "invalid_amount";
    case "digest":
      if (typeof value !== "string") return "mistyped_field";
      return DIGEST_FIELD_RE.test(value) ? null : "mistyped_field";
    case "enum":
      if (typeof value !== "string") return "mistyped_field";
      return resolveEnumValues(field, enumSnapshots)?.includes(value)
        ? null
        : "mistyped_field";
    case "timestamp":
      if (typeof value !== "string") return "mistyped_field";
      return isValidTimestamp(value) ? null : "mistyped_field";
    case "integer":
      return typeof value === "number" && Number.isInteger(value)
        ? null
        : "mistyped_field";
    case "boolean":
      return typeof value === "boolean" ? null : "mistyped_field";
    case "object":
      return isPlainObject(value) ? null : "mistyped_field";
    case "array":
      return Array.isArray(value) ? null : "mistyped_field";
    default:
      // Unknown declared field type in the definition: fail closed.
      return "mistyped_field";
  }
}

function sha256(canonical) {
  // CAID content-addressing commitment, not password or credential storage.
  // codeql[js/insufficient-password-hash]
  return createHash("sha256").update(Buffer.from(canonical, "utf8")).digest();
}

// ---------------------------------------------------------------------------
// computeCaid (DESIGN.md section 4, conforming issuer)
// ---------------------------------------------------------------------------

/**
 * computeCaid(actionObject, {suite, definitions, enumSnapshots})
 *   -> {caid: string, digest: string}   on success
 *   -> {refusals: [string]}             on any failure (never throws)
 *
 * digest is "sha256:" + lowercase hex of the digest bytes.
 */
export function computeCaid(actionObject, options) {
  const opts = isPlainObject(options) ? options : {};

  // Step 1: action_type present and grammar-valid.
  if (!isPlainObject(actionObject)) {
    return { refusals: ["invalid_action_type"] };
  }
  const actionType = actionObject.action_type;
  if (!isValidActionType(actionType)) {
    return { refusals: ["invalid_action_type"] };
  }

  // Step 2: type resolvable in the configured definitions.
  const def = resolveDefinition(actionType, opts.definitions);
  if (def === null) {
    return { refusals: ["unknown_action_type"] };
  }

  const refusals = [];

  // Steps 3-4: material fields present and type-valid.
  refusals.push(...validateAgainstDefinition(actionObject, def, opts.enumSnapshots));

  // Step 5: suite known (and implemented here).
  const suite = opts.suite;
  if (!SUPPORTED_SUITES.has(suite)) {
    refusals.push("unknown_suite");
  }

  // Step 6: no non-integer number and no unpaired surrogate anywhere in
  // the object (unsupported_number / unsupported_value).
  const canon = canonicalize(actionObject);
  if (!canon.ok) {
    refusals.push(...canon.refusals);
  }

  if (refusals.length > 0) {
    return { refusals };
  }

  // Step 7: canonicalize, digest, emit.
  // canon.ok is guaranteed true here: canonicalize() only returns
  // ok:false with a non-empty refusals array, which was just pushed
  // into `refusals` above and would have triggered the early return.
  const okCanon = /** @type {{ok: true, canonical: string}} */ (canon);
  const digestBytes = sha256(okCanon.canonical);
  const b64 = digestBytes.toString("base64url");
  return {
    caid: `caid:${CAID_VERSION}:${actionType}:${suite}:${b64}`,
    digest: "sha256:" + digestBytes.toString("hex"),
  };
}

// ---------------------------------------------------------------------------
// parseCaid (strict parser, DESIGN.md section 2)
// ---------------------------------------------------------------------------

/**
 * parseCaid(input)
 *   -> {ok: true, caid: {version, action_type, suite, digest}}
 *   -> {ok: false, refusals: ["malformed_caid"]}
 *
 * Strict: refuses padding, uppercase in type or suite, empty segments,
 * trailing content, unknown version, and (for known sha256 suites) a
 * digest of the wrong length. Unknown version is a refusal, never a
 * guess.
 */
export function parseCaid(input) {
  const refuse = { ok: false, refusals: ["malformed_caid"] };
  if (typeof input !== "string") return refuse;
  const parts = input.split(":");
  if (parts.length !== 5) return refuse; // trailing content adds parts
  const [prefix, version, actionType, suite, digest] = parts;
  if (prefix !== "caid") return refuse;
  if (version !== CAID_VERSION) return refuse;
  if (!isValidActionType(actionType)) return refuse;
  if (!SUITE_RE.test(suite)) return refuse;
  if (!B64URL_RE.test(digest)) return refuse; // refuses padding and junk
  if (SHA256_SUITES.has(suite) && digest.length !== SHA256_B64URL_LEN) {
    return refuse;
  }
  return {
    ok: true,
    caid: { version, action_type: actionType, suite, digest },
  };
}

// ---------------------------------------------------------------------------
// verifyCaid (DESIGN.md section 4, conforming verifier)
// ---------------------------------------------------------------------------

/**
 * verifyCaid(actionObject, caidString, {definitions})
 *   -> {valid: bool, reasons: [string]}
 *
 * Same inputs, same reasons, same order, replayable offline. Reason
 * order: malformed_caid (alone), else action_type_mismatch, then
 * unknown_suite or digest_mismatch, then invalid_object.
 *
 * Note: a valid CAID establishes only that this object recomputes to the
 * supplied content identifier under the selected suite. It establishes no
 * claim about
 * authorization, execution, or trust.
 */
export function verifyCaid(actionObject, caidString, options) {
  const opts = isPlainObject(options) ? options : {};

  // Step 1: strict-parse the string.
  const parsed = parseCaid(caidString);
  if (!parsed.ok) {
    return { valid: false, reasons: ["malformed_caid"] };
  }

  // A non-object cannot carry an action_type or be recomputed: fail
  // closed as an invalid object.
  if (!isPlainObject(actionObject)) {
    return { valid: false, reasons: ["invalid_object"] };
  }

  const reasons = [];

  // Step 2: in-object action_type equals the CAID's type. This check is
  // where cross-context reinterpretation dies (no domain-separation
  // prefix exists by design); skipping it re-opens that attack.
  if (actionObject.action_type !== parsed.caid.action_type) {
    reasons.push("action_type_mismatch");
  }

  // Step 3: recompute under the CAID's suite.
  const canon = canonicalize(actionObject);
  if (!SUPPORTED_SUITES.has(parsed.caid.suite)) {
    // cbor-sha256 is defined in the registry but not implemented here.
    reasons.push("unknown_suite");
  } else if (canon.ok) {
    const b64 = sha256(canon.canonical).toString("base64url");
    if (b64 !== parsed.caid.digest) {
      reasons.push("digest_mismatch");
    }
  }
  // If canonicalization refused, the digest cannot be recomputed; the
  // material validation below reports the object as invalid.

  // Step 4: the SAME material validation as compute. A CAID whose
  // object fails validation is invalid_object, not merely mismatched.
  const validationRefusals = [];
  if (!isValidActionType(actionObject.action_type)) {
    validationRefusals.push("invalid_action_type");
  } else {
    const def = resolveDefinition(actionObject.action_type, opts.definitions);
    if (def === null) {
      validationRefusals.push("unknown_action_type");
    } else {
      validationRefusals.push(
        ...validateAgainstDefinition(actionObject, def, opts.enumSnapshots)
      );
    }
  }
  if (!canon.ok) {
    validationRefusals.push(...canon.refusals);
  }
  if (validationRefusals.length > 0) {
    reasons.push("invalid_object");
  }

  return { valid: reasons.length === 0, reasons };
}
