# caid.py - CAID v1 reference implementation (Python, stdlib only).
#
# Conforms to DESIGN.md (the normative core of this package) and mirrors
# the JavaScript reference implementation impl/js/caid.mjs. Suite
# support: jcs-sha256 only. cbor-sha256 is defined in the suite registry
# but is NOT implemented here; this implementation refuses it as
# unknown_suite. Say so honestly everywhere.
#
# Scope (from DESIGN.md section 5): CAID carries no trust semantics.
# It proves that artifacts reference the same typed content. It does not
# prove the action was authorized, executed, safe, or wise. Nothing in
# this module verifies signatures, identity, or authorization.
#
# Fail-closed: junk input returns refusals with reasons, never throws.
#
# Dependencies: hashlib, base64, re (Python standard library only).

import base64
import hashlib
import math
import re

CAID_VERSION = "1"
SUPPORTED_SUITES = frozenset(["jcs-sha256"])
# Suites that are defined in the registry and use a SHA-256 digest
# (43 unpadded base64url characters). Used for strict digest-length
# checking at parse time.
SHA256_SUITES = frozenset(["jcs-sha256", "cbor-sha256"])
SHA256_B64URL_LEN = 43

# Grammar (strict, per DESIGN.md sections 2 and 3).
TYPE_SEGMENT_RE = re.compile(r"^[a-z][a-z0-9-]*$")
TYPE_VERSION_RE = re.compile(r"^[1-9][0-9]*$")
SUITE_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
AMOUNT_RE = re.compile(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?$")
DIGEST_FIELD_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# RFC 3339, UTC, trailing Z required. Optional fractional seconds.
TIMESTAMP_RE = re.compile(
    r"^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?Z$"
)

# ECMAScript integer safe range. Normative number rule (DESIGN.md
# section 1): a JSON number is accepted iff its IEEE 754 double value is
# an integer with magnitude at most 2^53-1; anything else refuses as
# unsupported_number in every conforming implementation. Inside the
# range all implementations emit identical plain decimal.
MAX_SAFE_INTEGER = 2**53 - 1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_plain_object(v):
    return isinstance(v, dict)


def _is_valid_action_type(t):
    if not isinstance(t, str):
        return False
    segments = t.split(".")
    if len(segments) < 2:
        return False
    if not TYPE_VERSION_RE.match(segments[-1]):
        return False
    for seg in segments[:-1]:
        if not TYPE_SEGMENT_RE.match(seg):
            return False
    return True


def _days_in_month(year, month):
    # month is 1-12
    if month == 2:
        leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0
        return 29 if leap else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _is_valid_timestamp(s):
    m = TIMESTAMP_RE.match(s)
    if not m:
        return False
    year = int(m.group(1))
    month = int(m.group(2))
    day = int(m.group(3))
    return day <= _days_in_month(year, month)


def _resolve_definition(action_type, definitions):
    if not isinstance(definitions, list):
        return None
    for entry in definitions:
        if _is_plain_object(entry) and entry.get("action_type") == action_type:
            return entry
    return None


# ---------------------------------------------------------------------------
# Canonicalization: RFC 8785 JCS, implemented inline.
#
# DESIGN.md section 1: a JSON number is accepted iff its IEEE 754
# double value is an integer with magnitude at most 2^53-1 (so "1e3"
# and "2.0" are the integer 1000 and 2; "1.5", NaN, infinities, and
# out-of-range values refuse). Integers within the ECMAScript
# safe range serialize as plain decimal, which is exactly the RFC 8785
# (ECMAScript) form. String escaping is the RFC 8785 minimal form:
# short escapes for backspace, tab, newline, form feed, carriage return,
# quote, and backslash; lowercase \u00xx for the remaining control
# characters; literal UTF-8 for everything else. Object keys are sorted
# by UTF-16 code units, as RFC 8785 requires; Python's default str
# ordering is by code point, which differs for supplementary-plane
# characters, so keys are compared via their UTF-16 big-endian bytes.
# ---------------------------------------------------------------------------

_SHORT_ESCAPES = {
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
    '"': '\\"',
    "\\": "\\\\",
}


def _quote(s):
    out = ['"']
    for ch in s:
        esc = _SHORT_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
            continue
        cp = ord(ch)
        if cp < 0x20:
            out.append("\\u%04x" % cp)
        elif 0xD800 <= cp <= 0xDFFF:
            # Lone surrogate (possible via json.loads of an escaped
            # surrogate). ECMAScript JSON.stringify emits these as
            # lowercase \u escapes; matching that keeps the canonical
            # text pure ASCII here and UTF-8 encodable.
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s):
    # UTF-16 code unit order == lexicographic order of UTF-16BE bytes.
    # surrogatepass so a lone-surrogate key still sorts (it is escaped
    # at serialization time, matching JSON.stringify).
    return s.encode("utf-16-be", "surrogatepass")


def _serialize_int(n, refusals):
    # Normative number rule (DESIGN.md section 1): a number is accepted
    # iff its IEEE 754 double value is an integer with magnitude at most
    # 2^53-1, and it serializes as that integer in plain decimal. Out of
    # range refuses in every conforming implementation.
    if -MAX_SAFE_INTEGER <= n <= MAX_SAFE_INTEGER:
        return str(n)
    refusals.append("unsupported_number")
    return ""


def canonicalize(value):
    """canonicalize(value) -> {"ok": True, "canonical": str}
                            | {"ok": False, "refusals": [str]}

    Refusals:
      unsupported_number - a number whose IEEE 754 double value is not
                           an integer with magnitude at most 2^53-1
                           (fractional, NaN, infinite, or out of range)
      unsupported_value  - a value not representable in JSON (bytes,
                           set, tuple, arbitrary object, non-string
                           dict key). Cannot arise from json.loads
                           input; exists so junk Python input fails
                           closed instead of being silently dropped.
    """
    refusals = []
    canonical = _serialize(value, refusals)
    if refusals:
        return {"ok": False, "refusals": _dedupe(refusals)}
    return {"ok": True, "canonical": canonical}


def _serialize(v, refusals):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return _serialize_int(v, refusals)
    if isinstance(v, float):
        # Value-based rule: an integral double within the safe range is
        # the same abstract value JavaScript sees for literals like
        # "1e3" or "2.0" after JSON.parse, so it is accepted and
        # serialized as its integer. Fractional, NaN, infinite, or
        # out-of-range values refuse.
        if math.isfinite(v) and v.is_integer():
            return _serialize_int(int(v), refusals)
        refusals.append("unsupported_number")
        return ""
    if isinstance(v, str):
        return _quote(v)
    if isinstance(v, list):
        return "[" + ",".join(_serialize(x, refusals) for x in v) + "]"
    if isinstance(v, dict):
        keys = list(v.keys())
        for k in keys:
            if not isinstance(k, str):
                refusals.append("unsupported_value")
                return ""
        keys.sort(key=_utf16_key)  # UTF-16 code unit order
        parts = [_quote(k) + ":" + _serialize(v[k], refusals) for k in keys]
        return "{" + ",".join(parts) + "}"
    refusals.append("unsupported_value")
    return ""


def _dedupe(arr):
    seen = set()
    out = []
    for x in arr:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ---------------------------------------------------------------------------
# Material-field validation (DESIGN.md sections 3 and 4).
# Returns refusals in deterministic order: all missing_material_field
# (definition order), then all mistyped_field / invalid_amount
# (definition order, required fields then optional fields).
# ---------------------------------------------------------------------------


def _field_list(definition, key):
    v = definition.get(key)
    if not isinstance(v, list):
        return []
    return [f for f in v if _is_plain_object(f)]


def _validate_against_definition(obj, definition):
    refusals = []
    required = _field_list(definition, "required_fields")
    optional = _field_list(definition, "optional_fields")
    for f in required:
        name = f.get("name")
        if not isinstance(name, str):
            continue
        if name not in obj:
            refusals.append("missing_material_field:" + name)
    for f in required + optional:
        name = f.get("name")
        if not isinstance(name, str):
            continue
        if name not in obj:
            continue
        code = _check_field_type(obj[name], f)
        if code:
            refusals.append(code + ":" + name)
    return refusals


def _check_field_type(value, field):
    # Returns None when valid, else "mistyped_field" or "invalid_amount".
    ftype = field.get("type")
    if ftype == "string":
        return None if isinstance(value, str) else "mistyped_field"
    if ftype == "amount-string":
        if not isinstance(value, str):
            return "mistyped_field"
        return None if AMOUNT_RE.match(value) else "invalid_amount"
    if ftype == "digest":
        if not isinstance(value, str):
            return "mistyped_field"
        return None if DIGEST_FIELD_RE.match(value) else "mistyped_field"
    if ftype == "enum":
        if not isinstance(value, str):
            return "mistyped_field"
        values = field.get("values")
        if isinstance(values, list) and value not in values:
            return "mistyped_field"
        return None
    if ftype == "timestamp":
        if not isinstance(value, str):
            return "mistyped_field"
        return None if _is_valid_timestamp(value) else "mistyped_field"
    if ftype == "integer":
        # bool is a subclass of int in Python; a JSON boolean is not an
        # integer, matching the JS typeof check.
        if isinstance(value, bool) or not isinstance(value, int):
            return "mistyped_field"
        return None
    if ftype == "boolean":
        return None if isinstance(value, bool) else "mistyped_field"
    if ftype == "object":
        return None if _is_plain_object(value) else "mistyped_field"
    if ftype == "array":
        return None if isinstance(value, list) else "mistyped_field"
    # Unknown declared field type in the definition: fail closed.
    return "mistyped_field"


def _sha256(canonical):
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def _b64url(digest_bytes):
    return base64.urlsafe_b64encode(digest_bytes).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# compute_caid (DESIGN.md section 4, conforming issuer)
# ---------------------------------------------------------------------------


def compute_caid(action_object, options=None):
    """compute_caid(action_object, {"suite": ..., "definitions": [...]})
      -> {"caid": str, "digest": str}     on success
      -> {"refusals": [str]}              on any failure (never throws)

    digest is "sha256:" + lowercase hex of the digest bytes.
    """
    opts = options if _is_plain_object(options) else {}

    # Step 1: action_type present and grammar-valid.
    if not _is_plain_object(action_object):
        return {"refusals": ["invalid_action_type"]}
    action_type = action_object.get("action_type")
    if not _is_valid_action_type(action_type):
        return {"refusals": ["invalid_action_type"]}

    # Step 2: type resolvable in the configured definitions.
    definition = _resolve_definition(action_type, opts.get("definitions"))
    if definition is None:
        return {"refusals": ["unknown_action_type"]}

    refusals = []

    # Steps 3-4: material fields present and type-valid.
    refusals.extend(_validate_against_definition(action_object, definition))

    # Step 5: suite known (and implemented here).
    suite = opts.get("suite")
    if suite not in SUPPORTED_SUITES:
        refusals.append("unknown_suite")

    # Step 6: no non-integer number anywhere in the object.
    canon = canonicalize(action_object)
    if not canon["ok"]:
        refusals.extend(canon["refusals"])

    if refusals:
        return {"refusals": refusals}

    # Step 7: canonicalize, digest, emit.
    digest_bytes = _sha256(canon["canonical"])
    b64 = _b64url(digest_bytes)
    return {
        "caid": "caid:%s:%s:%s:%s" % (CAID_VERSION, action_type, suite, b64),
        "digest": "sha256:" + digest_bytes.hex(),
    }


# ---------------------------------------------------------------------------
# parse_caid (strict parser, DESIGN.md section 2)
# ---------------------------------------------------------------------------


def parse_caid(caid_input):
    """parse_caid(caid_input)
      -> {"ok": True, "caid": {"version", "action_type", "suite", "digest"}}
      -> {"ok": False, "refusals": ["malformed_caid"]}

    Strict: refuses padding, uppercase in type or suite, empty segments,
    trailing content, unknown version, and (for known sha256 suites) a
    digest of the wrong length. Unknown version is a refusal, never a
    guess.
    """
    refuse = {"ok": False, "refusals": ["malformed_caid"]}
    if not isinstance(caid_input, str):
        return refuse
    parts = caid_input.split(":")
    if len(parts) != 5:  # trailing content adds parts
        return refuse
    prefix, version, action_type, suite, digest = parts
    if prefix != "caid":
        return refuse
    if version != CAID_VERSION:
        return refuse
    if not _is_valid_action_type(action_type):
        return refuse
    if not SUITE_RE.match(suite):
        return refuse
    if not B64URL_RE.match(digest):  # refuses padding and junk
        return refuse
    if suite in SHA256_SUITES and len(digest) != SHA256_B64URL_LEN:
        return refuse
    return {
        "ok": True,
        "caid": {
            "version": version,
            "action_type": action_type,
            "suite": suite,
            "digest": digest,
        },
    }


# ---------------------------------------------------------------------------
# verify_caid (DESIGN.md section 4, conforming verifier)
# ---------------------------------------------------------------------------


def verify_caid(action_object, caid_string, options=None):
    """verify_caid(action_object, caid_string, {"definitions": [...]})
      -> {"valid": bool, "reasons": [str]}

    Same inputs, same reasons, same order, replayable offline. Reason
    order: malformed_caid (alone), else action_type_mismatch, then
    unknown_suite or digest_mismatch, then invalid_object.

    Note: a valid CAID proves only that this object is the typed content
    the identifier was computed over. It proves nothing about
    authorization, execution, or trust.
    """
    opts = options if _is_plain_object(options) else {}

    # Step 1: strict-parse the string.
    parsed = parse_caid(caid_string)
    if not parsed["ok"]:
        return {"valid": False, "reasons": ["malformed_caid"]}

    # A non-object cannot carry an action_type or be recomputed: fail
    # closed as an invalid object.
    if not _is_plain_object(action_object):
        return {"valid": False, "reasons": ["invalid_object"]}

    reasons = []

    # Step 2: in-object action_type equals the CAID's type. This check is
    # where cross-context reinterpretation dies (no domain-separation
    # prefix exists by design); skipping it re-opens that attack.
    if action_object.get("action_type") != parsed["caid"]["action_type"]:
        reasons.append("action_type_mismatch")

    # Step 3: recompute under the CAID's suite.
    canon = canonicalize(action_object)
    if parsed["caid"]["suite"] not in SUPPORTED_SUITES:
        # cbor-sha256 is defined in the registry but not implemented here.
        reasons.append("unknown_suite")
    elif canon["ok"]:
        b64 = _b64url(_sha256(canon["canonical"]))
        if b64 != parsed["caid"]["digest"]:
            reasons.append("digest_mismatch")
    # If canonicalization refused, the digest cannot be recomputed; the
    # material validation below reports the object as invalid.

    # Step 4: the SAME material validation as compute. A CAID whose
    # object fails validation is invalid_object, not merely mismatched.
    validation_refusals = []
    if not _is_valid_action_type(action_object.get("action_type")):
        validation_refusals.append("invalid_action_type")
    else:
        definition = _resolve_definition(
            action_object.get("action_type"), opts.get("definitions")
        )
        if definition is None:
            validation_refusals.append("unknown_action_type")
        else:
            validation_refusals.extend(
                _validate_against_definition(action_object, definition)
            )
    if not canon["ok"]:
        validation_refusals.extend(canon["refusals"])
    if validation_refusals:
        reasons.append("invalid_object")

    return {"valid": len(reasons) == 0, "reasons": reasons}
