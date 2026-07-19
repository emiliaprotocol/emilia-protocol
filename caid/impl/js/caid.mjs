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
 *   unsupported_value  - a value not representable in JSON (undefined,
 *                        function, symbol, bigint). Cannot arise from
 *                        JSON.parse input; exists so junk JS input fails
 *                        closed instead of being silently dropped.
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
  if (t === "string") return JSON.stringify(v);
  if (Array.isArray(v)) {
    return "[" + v.map((x) => serialize(x, refusals)).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(v).sort(); // UTF-16 code unit order
    const parts = keys.map(
      (k) => JSON.stringify(k) + ":" + serialize(v[k], refusals)
    );
    return "{" + parts.join(",") + "}";
  }
  refusals.push("unsupported_value");
  return "";
}

function dedupe(arr) {
  return [...new Set(arr)];
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

function validateAgainstDefinition(obj, def) {
  const refusals = [];
  const required = fieldList(def, "required_fields");
  const optional = fieldList(def, "optional_fields");
  for (const f of required) {
    if (typeof f.name !== "string") continue;
    if (!(f.name in obj) || obj[f.name] === undefined) {
      refusals.push("missing_material_field:" + f.name);
    }
  }
  for (const f of [...required, ...optional]) {
    if (typeof f.name !== "string") continue;
    if (!(f.name in obj) || obj[f.name] === undefined) continue;
    const code = checkFieldType(obj[f.name], f);
    if (code) refusals.push(code + ":" + f.name);
  }
  return refusals;
}

// Returns null when valid, else "mistyped_field" or "invalid_amount".
function checkFieldType(value, field) {
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
      if (Array.isArray(field.values) && !field.values.includes(value)) {
        return "mistyped_field";
      }
      return null;
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
  return createHash("sha256").update(Buffer.from(canonical, "utf8")).digest();
}

// ---------------------------------------------------------------------------
// computeCaid (DESIGN.md section 4, conforming issuer)
// ---------------------------------------------------------------------------

/**
 * computeCaid(actionObject, {suite, definitions})
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
  refusals.push(...validateAgainstDefinition(actionObject, def));

  // Step 5: suite known (and implemented here).
  const suite = opts.suite;
  if (!SUPPORTED_SUITES.has(suite)) {
    refusals.push("unknown_suite");
  }

  // Step 6: no non-integer number anywhere in the object.
  const canon = canonicalize(actionObject);
  if (!canon.ok) {
    refusals.push(...canon.refusals);
  }

  if (refusals.length > 0) {
    return { refusals };
  }

  // Step 7: canonicalize, digest, emit.
  const digestBytes = sha256(canon.canonical);
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
      validationRefusals.push(...validateAgainstDefinition(actionObject, def));
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
