# SPDX-License-Identifier: Apache-2.0
"""emilia_verify — zero-infrastructure verification of EMILIA Protocol receipts.

A pure-Python port of @emilia-protocol/verify. Verifies EP-RECEIPT-v1 documents:
recursive canonical JSON + Ed25519 (SPKI-DER public key) + sorted-pair Merkle
anchors. Byte-compatible with the JavaScript verifier — a receipt signed on the
Node side verifies here, and vice versa. No EP account, no API key. Just math.

    from emilia_verify import verify_receipt
    result = verify_receipt(doc, public_key_base64url)
    assert result.valid

Requires: cryptography
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

__all__ = [
    "canonicalize", "is_canonicalizable", "verify_receipt", "verify_merkle_anchor",
    "VerifyResult", "evaluate_agent_binding",
    # EP-RESOLUTION-v1
    "compute_binding_moment_hash", "compute_resolution_response_hash",
    "verify_resolution_receipt", "RESOLUTION_VERSION",
    "RESOLUTION_CONTEXT_TYPE", "RESOLUTION_OUTCOMES",
    # EP-CURRENCY-v1
    "evaluate_currency", "CURRENCY_VERSION", "CURRENCY_STATUS", "CURRENCY_REASON",
    # EP-WITNESS-v1
    "verify_witness_cosignature", "require_witness_quorum", "witness_signing_digest",
    "WITNESS_VERSION", "WITNESS_DOMAIN_TAG",
    # Checkpoint consistency (EP-MERKLE-v2)
    "verify_checkpoint_consistency", "build_consistency_proof", "CONSISTENCY_ALG",
    # EP-SMT-CONSUME-v1
    "verify_consumption_proof", "ReferenceConsumptionTree",
    "CONSUMPTION_PROFILE", "CONSUMPTION_LEAF_DOMAIN", "SMT_DEPTH",
    # EP-INITIATOR-ATTESTATION-v1
    "validate_initiator_attestation", "neutralize_statement", "normalize_digest", "bind_into",
    "INITIATOR_ATTESTATION_VERSION", "INITIATOR_ATTESTATION_FIELD", "INITIATOR_STATEMENT_MAX",
]

SUPPORTED_VERSIONS = ("EP-RECEIPT-v1",)
_SAFE_INT = 2 ** 53 - 1


def _jcs_key_sort_key(key: str) -> bytes:
    """Sort object member names by UTF-16 code units, matching ECMAScript/JCS."""
    return str(key).encode("utf-16-be", "surrogatepass")


def _canonical_number(value: int | float) -> str:
    """Render the JSON-number subset EP signs exactly like JSON.stringify.

    EP allows only safe integers in signed material. Because JSON has one
    "number" type, Python may decode an integer-valued token such as ``1.0`` as
    float; normalize that to ``1``. Non-integer or unsafe numbers remain outside
    the profile and are rejected by verify_receipt before signing bytes are used.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if not math.isfinite(value):
            return "null"
        if value == 0:
            return "0"
        if value.is_integer() and abs(value) <= _SAFE_INT:
            return str(int(value))
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def canonicalize(value: Any) -> str:
    """Recursive canonical JSON — depth-first key sort at every level.

    Matches @emilia-protocol/verify `canonicalize()` byte-for-byte:
    objects -> UTF-16/JCS-sorted keys, arrays preserved, scalars via
    JSON.stringify semantics.
    """
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + canonicalize(value[k])
            for k in sorted(value.keys(), key=_jcs_key_sort_key)
        ) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _canonical_number(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def is_canonicalizable(value: Any) -> bool:
    """EP canonicalization I-JSON profile predicate (mirrors JS isCanonicalizable).

    True iff every scalar is a string, bool, None, or safe integer. Non-integer
    reals (Python float) are OUT of profile: json.dumps emits "2400000.0" where
    ECMAScript emits "2400000", breaking byte-identical cross-language
    canonicalization. Encode non-integer quantities as strings before signing.
    """
    if value is None or isinstance(value, str):
        return True
    if isinstance(value, bool):  # bool is a subclass of int — check before int
        return True
    if isinstance(value, float):
        return math.isfinite(value) and value.is_integer() and abs(value) <= _SAFE_INT
    if isinstance(value, int):
        return -_SAFE_INT <= value <= _SAFE_INT
    if isinstance(value, (list, tuple)):
        return all(is_canonicalizable(v) for v in value)
    if isinstance(value, dict):
        return all(is_canonicalizable(v) for v in value.values())
    return False


def _b64url_decode(s: str) -> bytes:
    if (not isinstance(s, str) or not s
            or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for ch in s)
            or len(s) % 4 == 1):
        raise ValueError("value is not canonical base64url")
    decoded = base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != s:
        raise ValueError("value is not canonical base64url")
    return decoded


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# EP-MERKLE-v1 (legacy): sorted-pair, no domain separation. Kept for already-
# anchored receipts; never used for new anchors.
def _hash_pair(a: str, b: str) -> str:
    lo, hi = sorted((a, b))
    return _sha256_hex(lo + hi)


# EP-MERKLE-v2: domain-separated + positional. Leaf = SHA-256(0x00 || canonical),
# branch = SHA-256(0x01 || leftHex || rightHex). Selected per-anchor via
# anchor["alg"] == MERKLE_V2_ALG; the leaf is bound to the receipt payload.
MERKLE_V2_ALG = "EP-MERKLE-v2"


def _leaf_hash_v2(canonical_payload: str) -> str:
    return hashlib.sha256(b"\x00" + canonical_payload.encode("utf-8")).hexdigest()


def _hash_pair_v2(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + left.encode("utf-8") + right.encode("utf-8")).hexdigest()


def verify_merkle_anchor(leaf_hash: Any, proof: Any, expected_root: Any, v2: bool = False) -> bool:
    """Verify a Merkle inclusion proof. v1 (default): sorted-pair SHA-256.
    v2: domain-separated positional SHA-256 (0x01 branch tag)."""
    if not isinstance(leaf_hash, str) or not leaf_hash:
        return False
    if not isinstance(expected_root, str) or not expected_root:
        return False
    if not isinstance(proof, list) or len(proof) > 20:
        return False
    pair = _hash_pair_v2 if v2 else _hash_pair
    current = leaf_hash
    for step in proof:
        if not isinstance(step, dict) or not isinstance(step.get("hash"), str):
            return False
        pos = step.get("position")
        if pos not in ("left", "right"):
            return False
        current = pair(step["hash"], current) if pos == "left" else pair(current, step["hash"])
    return current == expected_root


@dataclass
class VerifyResult:
    valid: bool
    checks: dict
    error: Optional[str] = None


def verify_receipt(
    doc: Any,
    public_key_base64url: str,
    strict: bool = False,
    allow_legacy_merkle: bool = False,
) -> VerifyResult:
    """Verify an EP-RECEIPT-v1 document against a signer's Ed25519 public key.

    Checks version, Ed25519 signature over the canonical payload, and (if
    present) the Merkle anchor. For a v2 anchor (alg == EP-MERKLE-v2) the leaf is
    required to equal SHA-256(0x00 || canonical(payload)) — the anchor is bound to
    THIS receipt. By default (and in every production gate) a legacy v1 anchor is
    refused; pass ``allow_legacy_merkle=True`` to verify pre-v2 artifacts
    ("receipts verify forever" without live v1 risk). Returns a VerifyResult;
    never raises on bad input.
    """
    checks: dict = {"version": False, "signature": False, "anchor": None}

    version = doc.get("@version") if isinstance(doc, dict) else None
    if version not in SUPPORTED_VERSIONS:
        return VerifyResult(False, checks, f"Unsupported version: {version}")
    checks["version"] = True

    sig = doc.get("signature") or {}
    if not doc.get("payload") or not sig.get("value") or not sig.get("algorithm"):
        return VerifyResult(False, checks, "Missing payload or signature")
    if not is_canonicalizable(doc["payload"]):
        return VerifyResult(
            False,
            checks,
            "Payload is outside the EP canonicalization profile; use strings or safe integers in signed material",
        )

    try:
        payload_bytes = canonicalize(doc["payload"]).encode("utf-8")
        pub = load_der_public_key(_b64url_decode(public_key_base64url))
        if not isinstance(pub, Ed25519PublicKey):
            return VerifyResult(False, checks, "Public key is not Ed25519")
        try:
            pub.verify(_b64url_decode(sig["value"]), payload_bytes)
            checks["signature"] = True
        except InvalidSignature:
            checks["signature"] = False
    except Exception as e:  # noqa: BLE001 - report any decode/key error as a failed check
        return VerifyResult(False, checks, f"Signature verification failed: {e}")

    anchor = doc.get("anchor") or {}
    # Empty proof arrays are valid for a one-leaf Merkle tree. Do not use
    # truthiness here: JavaScript treats [] as truthy, Python as false, and that
    # split would silently skip anchor verification for single-leaf receipts.
    has_anchor = (
        isinstance(anchor.get("merkle_proof"), list)
        and isinstance(anchor.get("leaf_hash"), str)
        and isinstance(anchor.get("merkle_root"), str)
    )
    if has_anchor:
        if anchor.get("alg") == MERKLE_V2_ALG:
            expected_leaf = _leaf_hash_v2(canonicalize(doc["payload"]))
            checks["anchor"] = (anchor["leaf_hash"] == expected_leaf) and verify_merkle_anchor(
                anchor["leaf_hash"], anchor["merkle_proof"], anchor["merkle_root"], v2=True
            )
        elif allow_legacy_merkle:
            # Dormant legacy path: pre-v2 anchors verify only on explicit opt-in.
            checks["anchor"] = verify_merkle_anchor(
                anchor["leaf_hash"], anchor["merkle_proof"], anchor["merkle_root"]
            )
        else:
            # Default (and every production gate): require EP-MERKLE-v2.
            checks["anchor"] = False

    valid = checks["version"] and checks["signature"] and checks["anchor"] in (None, True)
    return VerifyResult(valid, checks)


# =============================================================================
# EP-SIGNOFF-v1 — WebAuthn (ECDSA P-256) device signoff  (cross-lang parity)
# =============================================================================
from cryptography.hazmat.primitives.asymmetric import ec as _ec  # noqa: E402
from cryptography.hazmat.primitives import hashes as _hashes  # noqa: E402

_FLAG_UP = 0x01
_FLAG_UV = 0x04


def _reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object member name")
        result[key] = value
    return result


def _strict_json_loads(raw: str):
    return json.loads(raw, object_pairs_hook=_reject_duplicate_members)


def verify_webauthn_signoff(signoff: Any, approver_public_key_spki_b64u: str, opts: Optional[dict] = None) -> dict:
    """Verify a Class-A WebAuthn device signoff (ECDSA P-256). Mirrors the JS
    verifyWebAuthnSignoff byte-for-byte; never raises — returns {valid, checks}."""
    opts = opts or {}
    checks = {"challenge_binding": False, "client_data_type": False, "user_present": False,
              "user_verified": False, "rp_id_hash": None, "signature": False}
    try:
        ctx = signoff.get("context"); wa = signoff.get("webauthn")
        if not ctx or not wa:
            return {"valid": False, "checks": checks}
        ad_b64, cd_b64, sig_b64 = wa.get("authenticator_data"), wa.get("client_data_json"), wa.get("signature")
        if not ad_b64 or not cd_b64 or not sig_b64:
            return {"valid": False, "checks": checks}
        client_bytes = _b64url_decode(cd_b64)
        client = _strict_json_loads(client_bytes.decode("utf-8"))
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(canonicalize(ctx).encode("utf-8")).digest()).decode().rstrip("=")
        checks["challenge_binding"] = client.get("challenge") == expected
        checks["client_data_type"] = client.get("type") == "webauthn.get"
        ad = _b64url_decode(ad_b64)
        if len(ad) < 37:
            return {"valid": False, "checks": checks}
        flags = ad[32]
        checks["user_present"] = (flags & _FLAG_UP) == _FLAG_UP
        checks["user_verified"] = (flags & _FLAG_UV) == _FLAG_UV
        rp = opts.get("rpId")
        if rp:
            checks["rp_id_hash"] = hashlib.sha256(rp.encode("utf-8")).digest() == ad[:32]
        allowed_origins = opts.get("allowedOrigins")
        if allowed_origins is not None:
            if (not isinstance(allowed_origins, list) or not allowed_origins
                    or client.get("origin") not in allowed_origins
                    or client.get("crossOrigin") is True):
                return {"valid": False, "checks": checks}
        signed = ad + hashlib.sha256(client_bytes).digest()
        pub = load_der_public_key(_b64url_decode(approver_public_key_spki_b64u))
        try:
            pub.verify(_b64url_decode(sig_b64), signed, _ec.ECDSA(_hashes.SHA256()))
            checks["signature"] = True
        except Exception:
            checks["signature"] = False
    except Exception:
        return {"valid": False, "checks": checks}
    valid = (checks["challenge_binding"] and checks["client_data_type"] and checks["user_present"]
             and checks["user_verified"] and checks["signature"]
             and (checks["rp_id_hash"] is None or checks["rp_id_hash"] is True))
    return {"valid": valid, "checks": checks}


# =============================================================================
# EP-RESOLUTION-v1 -- four-outcome binding-moment resolution
# =============================================================================
RESOLUTION_VERSION = "EP-RESOLUTION-v1"
RESOLUTION_CONTEXT_TYPE = "ep.resolution.v1"
RESOLUTION_OUTCOMES = ("approved", "declined", "amended", "rejected")


def _resolution_is_hash(value: Any) -> bool:
    import re
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _resolution_hash(value: Any):
    try:
        if not is_canonicalizable(value):
            return None
        return "sha256:" + hashlib.sha256(canonicalize(value).encode("utf-8")).hexdigest()
    except Exception:
        return None


def compute_binding_moment_hash(binding_moment: Any):
    """Hash the exact value of the Morrison draft's binding_moment field."""
    return _resolution_hash(binding_moment) if isinstance(binding_moment, dict) else None


def compute_resolution_response_hash(response: Any):
    """Hash a principal-authored amendment or objection without disclosing it."""
    return _resolution_hash(response)


def _resolution_exact_keys(value: Any, allowed: set, required=None) -> bool:
    if not isinstance(value, dict):
        return False
    required = allowed if required is None else required
    return set(value.keys()).issubset(allowed) and set(required).issubset(value.keys())


def _resolution_binding_moment_shape_valid(binding_moment: Any) -> bool:
    outer_allowed = {"synopsis", "findings", "recommendations", "offer", "question", "meta"}
    outer_required = {"synopsis", "findings", "recommendations", "offer", "question"}
    if not _resolution_exact_keys(binding_moment, outer_allowed, outer_required):
        return False
    if (not isinstance(binding_moment.get("synopsis"), str)
            or not isinstance(binding_moment.get("findings"), list)
            or not all(isinstance(x, str) for x in binding_moment["findings"])
            or not isinstance(binding_moment.get("recommendations"), list)
            or not all(isinstance(x, str) for x in binding_moment["recommendations"])
            or not isinstance(binding_moment.get("offer"), str)):
        return False
    question = binding_moment.get("question")
    question_keys = {"stem", "options", "recommended_idx", "hatches"}
    if not _resolution_exact_keys(question, question_keys) or not isinstance(question.get("stem"), str):
        return False
    options = question.get("options")
    option_keys = {"label", "reasoning"}
    if (not isinstance(options, list) or not 2 <= len(options) <= 4
            or not all(_resolution_exact_keys(option, option_keys)
                       and isinstance(option.get("label"), str)
                       and isinstance(option.get("reasoning"), str) for option in options)):
        return False
    recommended = question.get("recommended_idx")
    if (not isinstance(recommended, int) or isinstance(recommended, bool)
            or recommended < 0 or recommended >= len(options)):
        return False
    hatches = question.get("hatches")
    hatch_keys = {"free_text", "dialogue"}
    if (not _resolution_exact_keys(hatches, hatch_keys)
            or not isinstance(hatches.get("free_text"), bool)
            or not isinstance(hatches.get("dialogue"), bool)):
        return False
    if "meta" in binding_moment:
        meta = binding_moment.get("meta")
        if (not _resolution_exact_keys(meta, {"decision_class", "calibration_note"}, set())
                or not all(isinstance(value, str) for value in meta.values())):
            return False
    return True


def _resolution_signed_origin(signoff: Any):
    try:
        encoded = signoff["webauthn"]["client_data_json"]
        client = _strict_json_loads(_b64url_decode(encoded).decode("utf-8"))
        origin = client.get("origin") if isinstance(client, dict) else None
        return origin if isinstance(origin, str) and origin else None
    except Exception:
        return None


def _resolution_shape_valid(resolution: Any, binding_moment: Any, current_envelope_hash: str) -> bool:
    if not isinstance(resolution, dict) or resolution.get("outcome") not in RESOLUTION_OUTCOMES:
        return False
    outcome = resolution["outcome"]
    allowed = {
        "approved": {"outcome", "selected_option"},
        "declined": {"outcome"},
        "amended": {"outcome", "response_hash", "successor_envelope_hash"},
        "rejected": {"outcome", "objection_hash", "successor_envelope_hash"},
    }[outcome]
    if not set(resolution.keys()).issubset(allowed):
        return False
    if outcome == "approved":
        selected = resolution.get("selected_option")
        options = ((binding_moment or {}).get("question") or {}).get("options") if isinstance(binding_moment, dict) else None
        return (isinstance(selected, int) and not isinstance(selected, bool) and selected >= 0
                and isinstance(options, list) and selected < len(options))
    if outcome == "declined":
        return set(resolution.keys()) == {"outcome"}
    if outcome == "amended" and not _resolution_is_hash(resolution.get("response_hash")):
        return False
    if outcome == "rejected" and "objection_hash" in resolution and not _resolution_is_hash(resolution.get("objection_hash")):
        return False
    if "successor_envelope_hash" in resolution:
        successor = resolution.get("successor_envelope_hash")
        if not _resolution_is_hash(successor) or successor == current_envelope_hash:
            return False
    return True


def _resolution_structure_valid(receipt: Any) -> bool:
    receipt_keys = {"profile", "signoff"}
    signoff_keys = {"@type", "context", "webauthn"}
    context_keys = {
        "ep_version", "context_type", "envelope_hash", "action_hash", "principal",
        "principal_key_id", "initiator", "nonce", "issued_at", "expires_at", "resolution",
    }
    webauthn_keys = {"authenticator_data", "client_data_json", "signature"}
    if not _resolution_exact_keys(receipt, receipt_keys) or receipt.get("profile") != RESOLUTION_VERSION:
        return False
    signoff = receipt.get("signoff")
    if not _resolution_exact_keys(signoff, signoff_keys) or signoff.get("@type") != "ep.signoff":
        return False
    context = signoff.get("context")
    if not _resolution_exact_keys(context, context_keys):
        return False
    if not _resolution_exact_keys(signoff.get("webauthn"), webauthn_keys):
        return False
    return (context.get("ep_version") == "1.0"
            and context.get("context_type") == RESOLUTION_CONTEXT_TYPE
            and _resolution_is_hash(context.get("envelope_hash"))
            and _resolution_is_hash(context.get("action_hash"))
            and all(isinstance(context.get(k), str) and context.get(k)
                    for k in ("principal", "principal_key_id", "initiator", "nonce")))


def _resolution_refuse(reason: str, checks: dict, outcome=None) -> dict:
    return {"valid": False, "authorizes_action": False, "outcome": outcome,
            "requires_successor": False, "checks": checks, "reason": reason}


def verify_resolution_receipt(receipt: Any, opts: Optional[dict] = None) -> dict:
    """Verify EP-RESOLUTION-v1 against RP-supplied envelope, action, RP ID,
    and role-pinned principal keys. Never raises; all hostile input refuses."""
    opts = opts or {}
    checks = {k: False for k in (
        "structure", "outcome_shape", "envelope_binding", "action_binding",
        "canonical_profile", "binding_moment_shape", "principal_pin",
        "selected_option_binding", "authorization_context", "initiator_binding",
        "nonce_binding", "time_window", "evaluation_time", "rp_id", "origin", "webauthn",
    )}
    try:
        checks["structure"] = _resolution_structure_valid(receipt)
        if not checks["structure"]:
            return _resolution_refuse("malformed_resolution_receipt", checks)
        signoff = receipt["signoff"]
        context = signoff["context"]
        outcome = (context.get("resolution") or {}).get("outcome")

        checks["canonical_profile"] = (is_canonicalizable(context)
                                         and is_canonicalizable(opts.get("bindingMoment")))
        if not checks["canonical_profile"]:
            return _resolution_refuse("resolution_outside_canonicalization_profile", checks, outcome)

        checks["binding_moment_shape"] = _resolution_binding_moment_shape_valid(opts.get("bindingMoment"))
        if not checks["binding_moment_shape"]:
            return _resolution_refuse("malformed_binding_moment", checks, outcome)

        envelope_hash = compute_binding_moment_hash(opts.get("bindingMoment"))
        checks["outcome_shape"] = _resolution_shape_valid(
            context.get("resolution"), opts.get("bindingMoment"), context.get("envelope_hash"))
        if not checks["outcome_shape"]:
            return _resolution_refuse("invalid_outcome_shape", checks, outcome)

        checks["envelope_binding"] = envelope_hash is not None and context.get("envelope_hash") == envelope_hash
        if not checks["envelope_binding"]:
            return _resolution_refuse("envelope_binding_mismatch", checks, outcome)

        expected_action = opts.get("expectedActionHash")
        checks["action_binding"] = _resolution_is_hash(expected_action) and context.get("action_hash") == expected_action
        if not checks["action_binding"]:
            return _resolution_refuse("action_binding_mismatch", checks, outcome)

        expected_option = opts.get("expectedSelectedOption")
        checks["selected_option_binding"] = (outcome != "approved"
                                               or (isinstance(expected_option, int)
                                                   and not isinstance(expected_option, bool)
                                                   and expected_option >= 0
                                                   and context["resolution"].get("selected_option") == expected_option))

        pins = opts.get("principalKeys")
        pin = pins.get(context.get("principal_key_id")) if isinstance(pins, dict) else None
        checks["principal_pin"] = (isinstance(pin, dict)
                                   and isinstance(pin.get("public_key"), str) and bool(pin.get("public_key"))
                                   and pin.get("principal") == context.get("principal"))
        if not checks["principal_pin"]:
            return _resolution_refuse("principal_key_not_pinned_for_role", checks, outcome)

        expected_initiator = opts.get("expectedInitiator")
        initiator_pinned = isinstance(expected_initiator, str) and bool(expected_initiator)
        checks["initiator_binding"] = ("expectedInitiator" not in opts
                                       or (initiator_pinned and context.get("initiator") == expected_initiator))
        if not checks["initiator_binding"]:
            return _resolution_refuse("initiator_binding_mismatch", checks, outcome)
        expected_nonce = opts.get("expectedNonce")
        nonce_pinned = isinstance(expected_nonce, str) and bool(expected_nonce)
        checks["nonce_binding"] = ("expectedNonce" not in opts
                                   or (nonce_pinned and context.get("nonce") == expected_nonce))
        if not checks["nonce_binding"]:
            return _resolution_refuse("nonce_binding_mismatch", checks, outcome)

        import datetime as _dt
        import re as _regex
        ts_re = _regex.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
        def parse_ts(value):
            if not isinstance(value, str) or not ts_re.fullmatch(value):
                return None
            try:
                return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000
            except Exception:
                return None
        issued, expires = parse_ts(context.get("issued_at")), parse_ts(context.get("expires_at"))
        checks["time_window"] = issued is not None and expires is not None and issued < expires
        if checks["time_window"] and "evaluationTime" in opts:
            value = opts.get("evaluationTime")
            evaluation = value if isinstance(value, (int, float)) and not isinstance(value, bool) else parse_ts(value)
            checks["evaluation_time"] = evaluation is not None and issued <= evaluation <= expires
            if not checks["evaluation_time"]:
                return _resolution_refuse("resolution_outside_validity_window", checks, outcome)
        if not checks["time_window"]:
            return _resolution_refuse("resolution_outside_validity_window", checks, outcome)

        rp_id = opts.get("rpId")
        checks["rp_id"] = isinstance(rp_id, str) and bool(rp_id)
        if not checks["rp_id"]:
            return _resolution_refuse("rp_id_required", checks, outcome)

        allowed_origins = opts.get("allowedOrigins")
        origin = _resolution_signed_origin(signoff)
        checks["origin"] = (isinstance(allowed_origins, list) and bool(allowed_origins)
                            and all(isinstance(item, str) and bool(item) for item in allowed_origins)
                            and origin in allowed_origins)
        if not checks["origin"]:
            return _resolution_refuse("webauthn_origin_not_allowed", checks, outcome)

        webauthn = verify_webauthn_signoff(signoff, pin["public_key"], {
            "rpId": rp_id,
            "allowedOrigins": allowed_origins,
        })
        checks["webauthn"] = webauthn.get("valid") is True
        if not checks["webauthn"]:
            return _resolution_refuse("webauthn_verification_failed", checks, outcome)
        checks["authorization_context"] = (checks["selected_option_binding"]
                                             and initiator_pinned and nonce_pinned
                                             and checks["evaluation_time"])
        return {"valid": True, "authorizes_action": outcome == "approved" and checks["authorization_context"], "outcome": outcome,
                "requires_successor": outcome in ("amended", "rejected"), "checks": checks}
    except Exception:
        return _resolution_refuse("malformed_resolution_receipt", checks)


def verify_quorum(quorum: Any, opts: Optional[dict] = None) -> dict:
    """Verify an EP-QUORUM-v1 multi-party approval. Mirrors JS quorum.js;
    fail-closed; composes verify_webauthn_signoff per member."""
    opts = opts or {}
    checks = {"all_signatures_valid": False, "action_binding": False, "distinct_humans": False,
              "distinct_keys": False, "initiator_excluded": False, "roles_admitted": False,
              "threshold_met": False, "order_satisfied": False, "chain_linked": False,
              "within_window": False}
    members_out = []
    try:
        policy = quorum.get("policy") if isinstance(quorum, dict) else None
        members = quorum.get("members") if isinstance(quorum, dict) else None
        action_hash = quorum.get("action_hash") if isinstance(quorum, dict) else None
        if not policy or not isinstance(members, list) or not members or not isinstance(action_hash, str) or not action_hash:
            return {"valid": False, "checks": checks, "members": members_out}
        mode = policy.get("mode")
        if mode not in ("ordered", "threshold"):
            return {"valid": False, "checks": checks, "members": members_out}
        distinct_humans = policy.get("distinct_humans") is not False
        _ws = policy.get("window_sec")
        # exclude bool: isinstance(True,(int,float)) is True in Python, so a JSON
        # boolean window_sec would be read as 1/0 seconds instead of the 900 default.
        window_sec = _ws if isinstance(_ws, (int, float)) and not isinstance(_ws, bool) else 900
        eligible = policy.get("approvers") if isinstance(policy.get("approvers"), list) else []
        _req = policy.get("required")
        if mode == "ordered":
            required = len(eligible)
        elif isinstance(_req, bool):
            required = None  # a JSON boolean is not a valid threshold (True is not 1)
        elif isinstance(_req, (int, float)) and float(_req).is_integer() and _req >= 1:
            required = int(_req)  # integer or integral float (2.0 -> 2); rejects 2.5
        else:
            required = None
        if not isinstance(required, int) or required <= 0 or not eligible:
            return {"valid": False, "checks": checks, "members": members_out}

        import datetime as _dt
        def _parse(ts):
            try:
                return _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() * 1000
            except Exception:
                return None

        all_sigs, all_bound, issued = True, True, []
        for m in members:
            r = verify_webauthn_signoff(m.get("signoff"), m.get("approver_public_key"), opts)
            ctx = (m.get("signoff") or {}).get("context") or {}
            members_out.append({"approver": ctx.get("approver"), "role": m.get("role"), "valid": bool(r["valid"])})
            if not r["valid"]:
                all_sigs = False
            if ctx.get("action_hash") != action_hash:
                all_bound = False
            issued.append(_parse(ctx.get("issued_at")))
        checks["all_signatures_valid"] = all_sigs
        checks["action_binding"] = all_bound

        counted = [(i, m) for i, m in enumerate(members)
                   if members_out[i]["valid"] and ((m.get("signoff") or {}).get("context") or {}).get("action_hash") == action_hash]
        counted_apprs = [((m.get("signoff") or {}).get("context") or {}).get("approver") for _, m in counted]
        checks["distinct_humans"] = (len(set(counted_apprs)) == len(counted_apprs)) if distinct_humans else True
        # Distinct device keys: no single public key may fill two counted slots.
        # Key-uniqueness is a cryptographic floor, NOT a separation-of-duties
        # preference: it holds UNCONDITIONALLY, even when distinct_humans is
        # disabled. One key in two counted seats is one signer, never a quorum.
        # Mirrors quorum.js.
        counted_keys = [m.get("approver_public_key") for _, m in counted]
        checks["distinct_keys"] = len(set(counted_keys)) == len(counted_keys)
        # Initiator excluded (separation of duties): the human/agent that
        # INITIATED the action must never also approve it. Require context.initiator
        # to be present, the SAME across all counted members, and to differ from
        # every counted member's own approver identity. Mirrors quorum.js and
        # verifyTrustReceipt's initiator SoD check.
        counted_initiators = [((m.get("signoff") or {}).get("context") or {}).get("initiator") for _, m in counted]
        initiator = counted_initiators[0] if counted_initiators else None
        checks["initiator_excluded"] = (len(counted) > 0
                                        and isinstance(initiator, str) and len(initiator) > 0
                                        and all(v == initiator for v in counted_initiators)
                                        and initiator not in counted_apprs)
        eligible_set = {f"{e.get('role')} {e.get('approver')}" for e in eligible}
        checks["roles_admitted"] = len(counted) > 0 and all(
            f"{m.get('role')} {((m.get('signoff') or {}).get('context') or {}).get('approver')}" in eligible_set for _, m in counted)
        distinct_elig = {((m.get('signoff') or {}).get('context') or {}).get('approver')
                         for _, m in counted
                         if f"{m.get('role')} {((m.get('signoff') or {}).get('context') or {}).get('approver')}" in eligible_set}
        checks["threshold_met"] = len(distinct_elig) >= required
        if mode == "ordered":
            seq_ok = all(idx < len(members)
                         and members[idx].get("role") == e.get("role")
                         and ((members[idx].get("signoff") or {}).get("context") or {}).get("approver") == e.get("approver")
                         for idx, e in enumerate(eligible))
            times = issued[:len(eligible)]
            times_ok = all(t is not None and (idx == 0 or t > times[idx - 1]) for idx, t in enumerate(times))
            checks["order_satisfied"] = len(members) >= len(eligible) and seq_ok and times_ok
        else:
            checks["order_satisfied"] = True
        if mode == "ordered" and policy.get("ordered_chain") is True:
            seq = members[:len(eligible)]
            linked = len(seq) == len(eligible)
            for idx, mem in enumerate(seq):
                prev = ((mem.get("signoff") or {}).get("context") or {}).get("prev_context_hash")
                if idx == 0:
                    if prev is not None:
                        linked = False
                else:
                    prev_ctx = (seq[idx - 1].get("signoff") or {}).get("context") or {}
                    if prev != _sha256_hex(canonicalize(prev_ctx)):
                        linked = False
            checks["chain_linked"] = linked
        else:
            checks["chain_linked"] = True
        ts = [issued[i] for i, _ in counted if issued[i] is not None]
        checks["within_window"] = len(ts) == len(counted) and len(counted) > 0 and (max(ts) - min(ts)) <= window_sec * 1000
    except Exception:
        return {"valid": False, "checks": checks, "members": members_out}
    valid = all([checks["all_signatures_valid"], checks["action_binding"], checks["distinct_humans"],
                 checks["distinct_keys"], checks["initiator_excluded"], checks["roles_admitted"],
                 checks["threshold_met"], checks["order_satisfied"], checks["chain_linked"],
                 checks["within_window"]])
    return {"valid": valid, "checks": checks, "members": members_out}


# ── EP-REVOCATION-v1 + EP-TIME-ATTESTATION-v1 (mirror packages/verify) ────────

REVOCATION_VERSION = "EP-REVOCATION-v1"
TIME_ATTESTATION_VERSION = "EP-TIME-ATTESTATION-v1"
_TARGET_TYPES = ("receipt", "commit", "delegation")
_REVOCATION_KEYS = {"@version", "target_type", "target_id", "action_hash",
                    "revoker_id", "revoked_at", "reason", "proof"}
_REVOCATION_PROOF_KEYS = {"algorithm", "revoker_key_id", "signature_b64u", "public_key"}
import re as _re
_SHA256_HEX = _re.compile(r"^[0-9a-f]{64}$")


def _hex_of(h: Any) -> str:
    if not isinstance(h, str):
        return ""
    value = h[7:] if h.startswith("sha256:") else h
    value = value.lower()
    return value if _SHA256_HEX.fullmatch(value) else ""


# Canonical EP timestamp profile: RFC 3339 with an explicit UTC offset ("Z" or
# ±hh:mm). No-timezone ("2026-07-01T12:00:00") and date-only ("2026-07-01") forms
# are REJECTED — they are ambiguous (UTC vs local) and must never satisfy a
# validity window. Single profile, parsed and rejected identically by JS/Py/Go.
_RFC3339_OFFSET = _re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")
_FULL_REVOKER_KEY_ID = _re.compile(r"^ep:revoker-key:sha256:[0-9a-f]{64}$")
_LEGACY_REVOKER_KEY_ID = _re.compile(r"^(?!ep:revoker-key:sha256:)[A-Za-z0-9._:#-]{1,128}$")


def _instant_ms(s: Any):
    import datetime as _dt
    if not isinstance(s, str) or not _RFC3339_OFFSET.match(s):
        return None
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000
    except Exception:
        return None


def _ed25519_verify(data: bytes, pub_b64u: Any, sig_b64u: Any) -> bool:
    try:
        if not data or not pub_b64u or not sig_b64u:
            return False
        key = load_der_public_key(_b64url_decode(pub_b64u))
        key.verify(_b64url_decode(sig_b64u), data)
        return True
    except Exception:
        return False


def _revoker_key_id(public_key_b64u: Any) -> str:
    try:
        if not isinstance(public_key_b64u, str) or not public_key_b64u:
            return ""
        der = _b64url_decode(public_key_b64u)
        canonical = base64.urlsafe_b64encode(der).rstrip(b"=").decode("ascii")
        if not der or canonical != public_key_b64u:
            return ""
        key = load_der_public_key(der)
        if not isinstance(key, Ed25519PublicKey):
            return ""
        return "ep:revoker-key:sha256:" + hashlib.sha256(der).hexdigest()
    except Exception:
        return ""


def _revocation_signed_payload(stmt: dict) -> bytes:
    return canonicalize({
        "@version": REVOCATION_VERSION,
        "action_hash": stmt.get("action_hash"),
        "reason": stmt.get("reason"),
        "revoked_at": stmt.get("revoked_at"),
        "revoker_id": stmt.get("revoker_id"),
        "target_id": stmt.get("target_id"),
        "target_type": stmt.get("target_type"),
    }).encode("utf-8")


def verify_revocation(target: Any, statement: Any, opts: Optional[dict] = None) -> dict:
    """Mirror of packages/verify/revocation.js verifyRevocation. Fail-closed."""
    opts = opts if isinstance(opts, dict) else {}
    revoker_keys = opts.get("revokerKeys")
    revoker_keys = revoker_keys if isinstance(revoker_keys, dict) else {}
    checks = {"version": True, "structure": True, "target_bound": True,
              "revoker_key_pinned": True, "revoker_key_bound": True,
              "revoked_at_present": True, "revoker_signature_valid": True,
              "effective_at_or_before_T": True,
              "signature_binds_statement": True}
    errors = []

    def fail(k, m):
        checks[k] = False
        errors.append(m)

    if not isinstance(statement, dict):
        fail("signature_binds_statement", "no revocation statement presented (fail-closed)")
        fail("revoker_signature_valid", "no revocation statement presented (fail-closed)")
        return {"valid": False, "checks": checks, "errors": errors}

    if statement.get("@version") != REVOCATION_VERSION:
        fail("version", f"unsupported version: {statement.get('@version')}")
    raw_proof = statement.get("proof")
    proof = raw_proof if isinstance(raw_proof, dict) else {}
    if set(statement.keys()) != _REVOCATION_KEYS or set(proof.keys()) != _REVOCATION_PROOF_KEYS:
        fail("structure", "revocation statement and proof must use the exact closed EP-REVOCATION-v1 schema")

    if not isinstance(target, dict):
        fail("target_bound", "no target handed to the verifier (fail-closed)")
    else:
        held_hash = _hex_of(target.get("action_hash"))
        statement_hash = _hex_of(statement.get("action_hash"))
        if (target.get("target_type") not in _TARGET_TYPES
                or not isinstance(target.get("target_id"), str)
                or not target.get("target_id") or not held_hash):
            fail("target_bound", "handed target is incomplete or malformed")
        if (statement.get("target_type") not in _TARGET_TYPES
                or not isinstance(statement.get("target_id"), str)
                or not statement.get("target_id") or not statement_hash):
            fail("target_bound", "revocation statement target is incomplete or malformed")
        elif statement.get("target_type") != target.get("target_type"):
            fail("target_bound", "target_type mismatch")
        elif statement.get("target_id") != target.get("target_id"):
            fail("target_bound", "target_id mismatch")
        elif statement_hash != held_hash:
            fail("target_bound", "action_hash mismatch (revoke-A-presented-for-B)")

    revoker_id = statement.get("revoker_id")
    revoker_id_valid = isinstance(revoker_id, str) and bool(revoker_id)
    pin_entry = revoker_keys.get(revoker_id) if revoker_id_valid else None
    pin_entry = pin_entry if isinstance(pin_entry, dict) else {}
    pinned = pin_entry.get("public_key")
    presented = proof.get("public_key")
    if not revoker_id_valid or not pinned:
        fail("revoker_key_pinned", f"no pinned key for revoker {revoker_id}")
    elif not isinstance(presented, str) or not presented or pinned != presented:
        fail("revoker_key_pinned", "presented revoker key != pinned key")
    derived_key_id = _revoker_key_id(presented)
    proof_key_id = proof.get("revoker_key_id")
    full_profile = (
        isinstance(proof_key_id, str)
        and bool(_FULL_REVOKER_KEY_ID.fullmatch(proof_key_id))
        and proof_key_id == derived_key_id
        and (pin_entry.get("key_id") is None or pin_entry.get("key_id") == derived_key_id)
    )
    legacy_profile = (
        isinstance(proof_key_id, str)
        and bool(_LEGACY_REVOKER_KEY_ID.fullmatch(proof_key_id))
        and isinstance(presented, str) and bool(presented)
        and pinned == presented
        and (pin_entry.get("key_id") is None or pin_entry.get("key_id") == proof_key_id)
    )
    if not derived_key_id or not (full_profile or legacy_profile):
        fail("revoker_key_bound", "revoker_key_id is neither a full SPKI digest nor an exact-pinned historical v1 label")
    if proof.get("algorithm") != "Ed25519":
        fail("revoker_signature_valid", "revocation proof algorithm must be Ed25519")
    if statement.get("reason") is not None and not isinstance(statement.get("reason"), str):
        fail("signature_binds_statement", "reason must be a string or null")

    revoked_ms = _instant_ms(statement.get("revoked_at"))
    if revoked_ms is None:
        fail("revoked_at_present", "revoked_at absent or malformed")

    now = opts.get("now")
    if now is None:
        import time as _t
        now_ms = _t.time() * 1000
    elif isinstance(now, (int, float)) and not isinstance(now, bool):
        import math as _math
        now_ms = float(now) if _math.isfinite(float(now)) else None
    elif isinstance(now, str):
        now_ms = _instant_ms(now)
    else:
        now_ms = None
    if revoked_ms is None or now_ms is None or revoked_ms > now_ms:
        fail("effective_at_or_before_T", "revoked_at must be at or before decision time")

    recomputed = None
    try:
        recomputed = _revocation_signed_payload(statement)
    except Exception:
        fail("signature_binds_statement", "revocation statement fields cannot be canonicalized")
    sig = proof.get("signature_b64u")
    sig_binds_pinned = (
        recomputed is not None
        and bool(pinned)
        and _ed25519_verify(recomputed, pinned, sig)
    )
    if recomputed is None:
        fail("revoker_signature_valid", "revocation statement cannot be verified without canonical signed bytes")
    elif not sig_binds_pinned:
        verify_key = pinned or presented
        sig_over_recomputed = bool(verify_key) and _ed25519_verify(recomputed, verify_key, sig)
        if not sig or not verify_key:
            fail("revoker_signature_valid", "revocation proof signature or key missing")
        elif not sig_over_recomputed:
            fail("signature_binds_statement", "revoker signature does not bind the presented statement bytes")
            fail("revoker_signature_valid", "revoker signature does not verify under the pinned key")

    # maxAgeSeconds is intentionally ignored. A terminal negative fact never
    # ages out; freshness belongs to separately authenticated status evidence.

    return {"valid": all(checks.values()), "checks": checks, "errors": errors}


def is_revoked(target: Any, statements: Any, opts: Optional[dict] = None) -> bool:
    if not isinstance(statements, list):
        return False
    return any(verify_revocation(target, s, opts)["valid"] for s in statements)


def _time_signed_payload(att: dict) -> bytes:
    return canonicalize({
        "@version": TIME_ATTESTATION_VERSION,
        "hashed": att.get("hashed"),
        "time": att.get("time"),
        "ts_authority_id": att.get("ts_authority_id"),
    }).encode("utf-8")


def verify_time_attestation(att: Any, opts: Optional[dict] = None) -> dict:
    """Mirror of packages/verify/time-attestation.js verifyTimeAttestation."""
    opts = opts or {}
    tsa_keys = opts.get("tsaKeys") or {}
    checks = {"version": True, "tsa_key_pinned": True, "time_present": True,
              "signature_valid": True, "hash_bound": True, "within_bounds": True}
    errors = []

    def fail(k, m):
        checks[k] = False
        errors.append(m)

    if not isinstance(att, dict):
        fail("signature_valid", "no time attestation presented (fail-closed)")
        return {"valid": False, "checks": checks, "errors": errors}
    if att.get("@version") != TIME_ATTESTATION_VERSION:
        fail("version", f"unsupported version: {att.get('@version')}")

    proof = att.get("proof") or None
    pinned = (tsa_keys.get(att.get("ts_authority_id")) or {}).get("public_key")
    presented = (proof or {}).get("public_key")
    if not pinned:
        fail("tsa_key_pinned", f"no pinned key for ts_authority {att.get('ts_authority_id')}")
    elif presented and pinned != presented:
        fail("tsa_key_pinned", "presented TSA key != pinned key")

    ms = _instant_ms(att.get("time"))
    if ms is None:
        fail("time_present", "time absent or malformed")

    if not (pinned and _ed25519_verify(_time_signed_payload(att), pinned, (proof or {}).get("signature_b64u"))):
        fail("signature_valid", "TSA signature does not verify under the pinned key")

    if isinstance(opts.get("expectedHash"), str):
        if _hex_of(att.get("hashed")) != _hex_of(opts.get("expectedHash")):
            fail("hash_bound", "attestation hashed != expected")

    if ms is not None:
        nb = _instant_ms(opts.get("notBefore")) if isinstance(opts.get("notBefore"), str) else None
        na = _instant_ms(opts.get("notAfter")) if isinstance(opts.get("notAfter"), str) else None
        if nb is not None and ms < nb:
            fail("within_bounds", "attested time before notBefore")
        if na is not None and ms > na:
            fail("within_bounds", "attested time after notAfter")

    return {"valid": all(checks.values()), "checks": checks, "errors": errors}


# ── EP §6.2 Trust Receipt offline verifier (I-D §6.3) — mirror packages/verify ─

def _coerce_required_approvals(value: Any):
    """Canonical required_approvals coercion (fail-closed; mirrors packages/verify
    coerceRequiredApprovals and the Go verifier). Accepts an integer or an
    integral-valued JSON number (2.0 -> 2, since JS JSON.parse cannot distinguish
    2.0 from 2). A string ("2"), a non-integral float (2.5), a bool, or < 1 is
    malformed and returns None (forcing the receipt to fail). Missing/None -> 1.
    NEVER raises (bool excluded because it subclasses int)."""
    if value is None:
        return 1
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not float(value).is_integer() or value < 1:
        return None
    value = int(value)
    return value


def _within_window(t: Any, frm: Any, to: Any) -> bool:
    ms = _instant_ms(t)
    if ms is None:
        return False
    if frm:
        f = _instant_ms(frm)
        if f is None or ms < f:
            return False
    if to:
        tt = _instant_ms(to)
        if tt is None or ms > tt:
            return False
    return True


def _verify_class_a_over_digest(webauthn: dict, digest_bytes: bytes, pub_spki_b64u: str, opts: Optional[dict] = None) -> bool:
    try:
        opts = opts or {}
        cd = _b64url_decode(webauthn["client_data_json"])
        client = _strict_json_loads(cd.decode("utf-8"))
        if client.get("type") != "webauthn.get":
            return False
        if client.get("challenge") != base64.urlsafe_b64encode(digest_bytes).decode().rstrip("="):
            return False
        rp_id = opts.get("rpId")
        allowed_origins = opts.get("allowedOrigins")
        ad = _b64url_decode(webauthn["authenticator_data"])
        if len(ad) < 37 or (ad[32] & _FLAG_UP) != _FLAG_UP or (ad[32] & _FLAG_UV) != _FLAG_UV:
            return False
        if rp_id and hashlib.sha256(rp_id.encode("utf-8")).digest() != ad[:32]:
            return False
        if allowed_origins is not None:
            if (not isinstance(allowed_origins, list) or not allowed_origins
                    or client.get("origin") not in allowed_origins
                    or client.get("crossOrigin") is True):
                return False
        signed = ad + hashlib.sha256(cd).digest()
        pub = load_der_public_key(_b64url_decode(pub_spki_b64u))
        pub.verify(_b64url_decode(webauthn["signature"]), signed, _ec.ECDSA(_hashes.SHA256()))
        return True
    except Exception:
        return False


def _verify_ed25519_over_digest(sig_b64u: Any, digest_bytes: bytes, pub_spki_b64u: str) -> bool:
    try:
        key = load_der_public_key(_b64url_decode(pub_spki_b64u))
        key.verify(_b64url_decode(sig_b64u), digest_bytes)
        return True
    except Exception:
        return False


def _trust_receipt_canonical_profile_error(receipt: dict) -> Optional[str]:
    leaf_content = {k: v for k, v in receipt.items() if k not in ("log_proof", "approver_key_proofs")}
    if not is_canonicalizable(leaf_content):
        return "Trust Receipt body"
    log_proof = receipt.get("log_proof")
    checkpoint = log_proof.get("checkpoint") if isinstance(log_proof, dict) else None
    if isinstance(checkpoint, dict):
        signed_cp = {k: v for k, v in checkpoint.items() if k != "log_signature"}
        if not is_canonicalizable(signed_cp):
            return "Trust Receipt checkpoint"
    return None


def _context_authorizes(context: dict) -> bool:
    """Legacy contexts implicitly approve; typed decisions must say approved."""
    return "decision" not in context or context.get("decision") == "approved"


def verify_trust_receipt(receipt: Any, opts: Optional[dict] = None) -> dict:
    """Offline EP §6.2 Trust Receipt verifier (I-D §6.3). Mirrors packages/verify
    verifyTrustReceipt; the PIP-007 attestation report is advisory and omitted
    (it never affects validity). Fail-closed."""
    opts = opts or {}
    checks = {"action_hash": False, "context_commitments": False, "signoff_signatures": False,
              "sod": False, "inclusion": False, "checkpoint_signature": False, "windows": False}
    errors = []

    def fail(msg):
        errors.append(msg)
        return {"valid": False, "checks": checks, "errors": errors}

    if not isinstance(receipt, dict):
        return fail("Missing receipt")
    approver_keys = opts.get("approverKeys") or {}
    log_public_key = opts.get("logPublicKey")
    contexts = receipt.get("contexts") if isinstance(receipt.get("contexts"), list) else []
    signoffs = receipt.get("signoffs") if isinstance(receipt.get("signoffs"), list) else []
    if not receipt.get("action") or not receipt.get("action_hash"):
        return fail("Missing action or action_hash")
    if not contexts or not signoffs:
        return fail("Missing contexts or signoffs")
    profile_error = _trust_receipt_canonical_profile_error(receipt)
    if profile_error:
        return fail(f"{profile_error} is outside the EP canonicalization profile; encode non-integer quantities as strings")

    # I-JSON canonicalization gate (fail-closed) — identical guard to verify_receipt.
    # Every field folded into a signed digest below is re-canonicalized; a value
    # outside the profile canonicalizes differently across JS/Py/Go, so reject it
    # here. Signature/proof fields are excluded from the check.
    canonical_scope = {k: v for k, v in receipt.items() if k not in ("signoffs", "log_proof", "approver_key_proofs")}
    if not is_canonicalizable(canonical_scope):
        return fail("Receipt contains a value outside the EP canonicalization profile; use strings or safe integers in signed material")

    action_hash_hex = _sha256_hex(canonicalize(receipt["action"]))
    checks["action_hash"] = action_hash_hex == _hex_of(receipt.get("action_hash"))

    context_by_hash = {}
    commitments_ok = True
    policy_hashes = set()
    for ctx in contexts:
        context_by_hash[_sha256_hex(canonicalize(ctx))] = ctx
        if _hex_of(ctx.get("action_hash")) != action_hash_hex:
            commitments_ok = False
        if not ctx.get("policy_hash"):
            commitments_ok = False
        else:
            policy_hashes.add(_hex_of(ctx.get("policy_hash")))
        if not ctx.get("approver"):
            commitments_ok = False
    if len(policy_hashes) > 1:
        commitments_ok = False
    checks["context_commitments"] = commitments_ok

    valid_signoffs = []
    valid_approvals = []
    signatures_ok = len(signoffs) > 0
    for s in signoffs:
        ctx = context_by_hash.get(_hex_of(s.get("context_hash")))
        if not ctx:
            signatures_ok = False
            continue
        key_entry = approver_keys.get(s.get("approver_key_id"))
        if not key_entry or not key_entry.get("public_key"):
            signatures_ok = False
            continue
        # The pinned directory entry must bind this key to the approver named by
        # the signed context. Otherwise any pinned key can impersonate any named
        # approver while still producing a valid cryptographic signature.
        if not isinstance(key_entry.get("approver_id"), str) or not key_entry.get("approver_id"):
            signatures_ok = False
            continue
        if key_entry.get("approver_id") != ctx.get("approver"):
            signatures_ok = False
            continue
        if not _within_window(ctx.get("issued_at"), key_entry.get("valid_from"), key_entry.get("valid_to")):
            signatures_ok = False
            continue
        digest_bytes = bytes.fromhex(_hex_of(s.get("context_hash")))
        # The PINNED key entry's class is authoritative and takes precedence over
        # the attacker-controlled signoff's declared key_class. Otherwise an
        # attacker pins a Class-A (WebAuthn, user-presence/user-verification)
        # approver but declares key_class:'B' and supplies a bare Ed25519
        # signature over the digest, downgrading to raw-signature verification
        # with NO WebAuthn proof. A pinned Class-A key MUST be satisfied by a
        # real WebAuthn assertion and is rejected if it only carries a raw
        # signature. Mirrors index.js verifyTrustReceipt.
        # Key class is a relying-party directory fact. A missing class defaults
        # to B; the presented signoff cannot promote its own key to Class A.
        key_class = "A" if key_entry.get("key_class") == "A" else "B"
        if key_class == "A":
            sig_ok = bool(s.get("webauthn")) and _verify_class_a_over_digest(s["webauthn"], digest_bytes, key_entry["public_key"], opts)
        else:
            sig_ok = _verify_ed25519_over_digest(s.get("signature"), digest_bytes, key_entry["public_key"])
        if not sig_ok:
            signatures_ok = False
            continue
        verified_signoff = {"approver": ctx.get("approver"), "signed_at": s.get("signed_at"), "ctx": ctx}
        valid_signoffs.append(verified_signoff)
        if _context_authorizes(ctx):
            valid_approvals.append(verified_signoff)
        elif ctx.get("decision") == "denied":
            errors.append(f"signed denial by {ctx.get('approver')} does not authorize the action")
        else:
            errors.append(f"signed decision by {ctx.get('approver')} is not a recognized approval outcome")
    checks["signoff_signatures"] = signatures_ok

    initiator = receipt["action"].get("initiator")
    approvers = [a["approver"] for a in valid_approvals]
    coerced = [_coerce_required_approvals(c.get("required_approvals")) for c in contexts]
    sod_ok = True
    if any(n is None for n in coerced):
        sod_ok = False  # non-integer threshold is malformed -> fail-closed
    required = max([1] + [n for n in coerced if n is not None])
    if initiator and initiator in approvers:
        sod_ok = False
    if len(set(approvers)) != len(approvers):
        sod_ok = False
    if len(valid_approvals) < required:
        sod_ok = False
    checks["sod"] = sod_ok

    lp = receipt.get("log_proof")
    if lp and lp.get("checkpoint") and isinstance(lp.get("inclusion_path"), list):
        leaf_content = {k: v for k, v in receipt.items() if k not in ("log_proof", "approver_key_proofs")}
        canonical_leaf = canonicalize(leaf_content)
        # EP-MERKLE-v2 (default): domain-separated, payload-bound leaf + positional
        # proof; when log_proof carries leaf_hash it must bind this receipt.
        merkle_alg = lp.get("alg") or (lp.get("checkpoint") or {}).get("merkle_alg")
        # Degenerate empty-path rule (fail-closed): with an empty inclusion_path
        # the Merkle fold collapses to leaf_hash == root_hash, which is only a
        # true inclusion statement for a SINGLE-LEAF tree. Without this gate, a
        # forged checkpoint whose root_hash simply repeats the leaf hash would
        # "include" the receipt at ANY claimed tree_size. An empty path is
        # therefore accepted ONLY when checkpoint.tree_size is exactly 1 (and,
        # since this shape carries an index, leaf_index, when present, is 0; a
        # null leaf_index counts as present and refuses). Missing or non-numeric
        # tree_size refuses. Applies to v2 AND opt-in legacy folds, evaluated
        # before the Merkle fold. Mirrors packages/verify (JS) verifyTrustReceipt
        # exactly (JSON numbers: an integer-valued 1.0 token equals 1, a bool
        # does not).
        empty_path_refusal = None
        if len(lp["inclusion_path"]) == 0:
            ts = lp["checkpoint"].get("tree_size")
            ts_is_one = isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts == 1
            li = lp.get("leaf_index")
            if not ts_is_one:
                empty_path_refusal = "empty inclusion_path requires checkpoint tree_size 1 (single-leaf tree)"
            elif "leaf_index" in lp and (isinstance(li, bool) or not isinstance(li, (int, float)) or li != 0):
                empty_path_refusal = "empty inclusion_path requires leaf_index 0 in a single-leaf tree"
        if empty_path_refusal:
            checks["inclusion"] = False
            errors.append(empty_path_refusal)
        elif merkle_alg == MERKLE_V2_ALG:
            leaf_hash = _leaf_hash_v2(canonical_leaf)
            presented_leaf = _hex_of(lp.get("leaf_hash")) if lp.get("leaf_hash") else leaf_hash
            checks["inclusion"] = (presented_leaf == leaf_hash) and verify_merkle_anchor(
                leaf_hash, lp["inclusion_path"], _hex_of(lp["checkpoint"].get("root_hash")), v2=True)
        elif opts.get("allowLegacyMerkle") is True or opts.get("allow_legacy_merkle") is True or opts.get("allowLegacyTrustReceiptMerkle") is True:
            # Dormant legacy path: pre-v2 sorted-pair inclusion, opt-in only.
            leaf_hash = _sha256_hex(canonical_leaf)
            checks["inclusion"] = verify_merkle_anchor(leaf_hash, lp["inclusion_path"], _hex_of(lp["checkpoint"].get("root_hash")))
        else:
            # Default (and every production gate): require EP-MERKLE-v2.
            checks["inclusion"] = False
        if log_public_key and lp["checkpoint"].get("log_signature"):
            signed_cp = {k: v for k, v in lp["checkpoint"].items() if k != "log_signature"}
            checks["checkpoint_signature"] = _verify_ed25519_over_digest(
                str(lp["checkpoint"]["log_signature"]).replace("b64u:", ""),
                hashlib.sha256(canonicalize(signed_cp).encode("utf-8")).digest(),
                log_public_key)

    windows_ok = len(valid_signoffs) > 0
    for a in valid_signoffs:
        if not _within_window(a["signed_at"], a["ctx"].get("issued_at"), a["ctx"].get("expires_at")):
            windows_ok = False
    committed_at = (receipt.get("consumption") or {}).get("committed_at")
    if not committed_at:
        windows_ok = False
    else:
        for ctx in contexts:
            if not _within_window(committed_at, ctx.get("issued_at"), ctx.get("expires_at")):
                windows_ok = False
                break
    checks["windows"] = windows_ok

    return {"valid": all(checks.values()), "checks": checks, "errors": errors}


# ── EP-PROVENANCE-CHAIN-v1 offline verifier — mirror packages/verify/provenance.js

PROVENANCE_VERSION = "EP-PROVENANCE-CHAIN-v1"
_DEFAULT_HUMAN_KEY_CLASSES = ["A"]
_DELEGATION_PROOF_FIELDS = ["delegation_id", "delegator", "delegatee", "scope", "max_value_usd", "expires_at", "constraints"]


def _has_human_signoff(receipt, human_classes):
    s = set(human_classes)
    return any((so or {}).get("key_class") in s for so in (receipt or {}).get("signoffs") or [])


def _receipt_approvers(receipt):
    ids = set()
    for ctx in (receipt or {}).get("contexts") or []:
        if ctx.get("approver"):
            ids.add(ctx["approver"])
    for so in (receipt or {}).get("signoffs") or []:
        if so.get("approver_key_id"):
            ids.add(so["approver_key_id"])
    return ids


def _latest_context_expiry(receipt):
    mx = None
    for ctx in (receipt or {}).get("contexts") or []:
        t = _instant_ms(ctx.get("expires_at"))
        if t is not None and (mx is None or t > mx):
            mx = t
    return mx


def _scope_permits(scope, action_type):
    if not isinstance(scope, list) or not action_type:
        return False
    for grant in scope:
        if grant == "*" or grant == action_type:
            return True
        if isinstance(grant, str) and grant.endswith(".*"):
            prefix = grant[:-2]
            if action_type == prefix or action_type.startswith(prefix + "."):
                return True
    return False


def _num(v):
    """Mirror JS Number() / Go toFloat() for the numeric fields the verifier compares:
    numbers and numeric strings coerce to float; anything else (including a
    non-numeric string) becomes NaN so comparisons are false rather than raising.
    Attacker-controlled caps must never crash a verify path (max_value_usd:'abc')."""
    if isinstance(v, bool):
        return float("nan")
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return 0.0
        try:
            return float(s)
        except ValueError:
            return float("nan")
    return float("nan")


def _js_min(a, b):
    """Math.min parity: NaN if either operand is NaN. Python's builtin min is
    order-dependent with NaN; JS Math.min always propagates NaN."""
    if a != a or b != b:
        return float("nan")
    return a if a < b else b


def _scope_containment_violations(parent, child):
    viol = []
    for token in child.get("scope") or []:
        probe = token[:-2] if isinstance(token, str) and token.endswith(".*") else token
        if not _scope_permits(parent.get("scope"), probe):
            viol.append("scope exceeds parent")
    # Cap containment, fail-closed on a non-numeric child cap (parity with JS/Go).
    # When the parent has a finite cap, the child must be absent/None (inherits) OR a
    # finite number <= parent. A present-but-non-numeric child cap coerces to NaN;
    # previously NaN > parent was False so it PASSED containment (fail-open). Now it
    # is a violation.
    parent_cap = parent.get("max_value_usd")
    parent_cap_num = _num(parent_cap) if parent_cap is not None else float("nan")
    if parent_cap is not None and math.isfinite(parent_cap_num):
        child_cap = child.get("max_value_usd")
        if child_cap is not None:
            child_cap_num = _num(child_cap)
            if not math.isfinite(child_cap_num) or child_cap_num > parent_cap_num:
                viol.append("cap exceeds parent")
    p_exp = _instant_ms(parent.get("expires_at"))
    c_exp = _instant_ms(child.get("expires_at"))
    if p_exp is not None and c_exp is not None and c_exp > p_exp:
        viol.append("expiry after parent")
    return viol


def _constraints_monotonic(parent_c, child_c):
    p = parent_c or {}
    c = child_c or {}
    for k, pv in p.items():
        if k not in c:
            return False
        cv = c[k]
        if isinstance(pv, (int, float)) and not isinstance(pv, bool) and isinstance(cv, (int, float)) and not isinstance(cv, bool):
            if cv > pv:
                return False
        elif isinstance(pv, list) and isinstance(cv, list):
            pset = {canonicalize(x) for x in pv}
            if not all(canonicalize(x) in pset for x in cv):
                return False
        elif canonicalize(pv) != canonicalize(cv):
            return False
    return True


def _verify_detached_signature(att):
    try:
        if not att or not att.get("signed_payload_b64u") or not att.get("signature_b64u") or not att.get("public_key"):
            return False
        if att.get("algorithm") and att["algorithm"] != "Ed25519":
            return False
        return _ed25519_verify(_b64url_decode(att["signed_payload_b64u"]), att["public_key"], att["signature_b64u"])
    except Exception:
        return False


def _delegation_proof_bytes(link):
    return canonicalize({f: link.get(f) for f in _DELEGATION_PROOF_FIELDS}).encode("utf-8")


def verify_provenance_offline(doc, opts=None):
    """Mirror of packages/verify/provenance.js verifyProvenanceOffline. Fail-closed."""
    opts = opts or {}
    human_classes = opts.get("humanKeyClasses") or _DEFAULT_HUMAN_KEY_CLASSES
    allow_unsigned = opts.get("allowUnsignedDelegations") is True
    import time as _time
    now = opts.get("now") if isinstance(opts.get("now"), (int, float)) else _time.time() * 1000
    require_always = opts.get("requireActionApprovalAlways") is True
    checks = {"version": False, "root_receipt_valid": False, "root_human_signoff": False,
              "per_action_required": True, "action_receipt_valid": True, "action_human_signoff": True,
              "execution_binding": True, "chain_anchored": True, "chain_links_bound": True,
              "delegations_signed": True, "proof_key_bound": True, "delegations_not_expired": True,
              "scope_containment": True, "constraints_monotonic": True, "leaf_permits_action": True, "temporal_containment": True}
    errors = []

    def fail(k, m):
        checks[k] = False
        errors.append(m)

    def valid_verification_profile(profile):
        return (isinstance(profile, dict)
                and isinstance(profile.get("approver_keys"), dict)
                and isinstance(profile.get("log_public_key"), str)
                and bool(profile.get("log_public_key"))
                and isinstance(profile.get("rp_id"), str)
                and bool(profile.get("rp_id"))
                and isinstance(profile.get("allowed_origins"), list)
                and bool(profile.get("allowed_origins"))
                and all(isinstance(origin, str) and bool(origin)
                        for origin in profile.get("allowed_origins")))

    if not isinstance(doc, dict) or doc.get("@version") != PROVENANCE_VERSION:
        return {"valid": False, "checks": checks, "errors": [f"unsupported version: {doc.get('@version') if isinstance(doc, dict) else None}"],
                "links": [], "agent_identity": None, "liability": None}
    checks["version"] = True

    root = doc.get("root_signoff")
    root_verification = opts.get("rootVerification") or opts.get("root_verification")
    if not root or not root.get("receipt"):
        fail("root_receipt_valid", "missing root_signoff")
    elif not valid_verification_profile(root_verification):
        fail("root_receipt_valid", "relying-party root verification profile is required")
    else:
        r0 = verify_trust_receipt(root["receipt"], {
            "approverKeys": root_verification.get("approver_keys"),
            "logPublicKey": root_verification.get("log_public_key"),
            "rpId": root_verification.get("rp_id"),
            "allowedOrigins": root_verification.get("allowed_origins"),
        })
        checks["root_receipt_valid"] = r0["valid"]
        checks["root_human_signoff"] = _has_human_signoff(root["receipt"], human_classes)

    exec_ = doc.get("execution") or {}
    reversibility_asserted = False  # opts.reversibilityAsserted is a predicate; absent in serialized vectors
    need_approval = require_always or not reversibility_asserted
    approval = doc.get("action_approval")
    action_verification = opts.get("actionVerification") or opts.get("action_verification")
    if need_approval and not (approval or {}).get("receipt"):
        fail("per_action_required", "no action_approval present")
    if (approval or {}).get("receipt"):
        if not valid_verification_profile(action_verification):
            fail("action_receipt_valid", "relying-party action verification profile is required")
        else:
            ra = verify_trust_receipt(approval["receipt"], {
                "approverKeys": action_verification.get("approver_keys"),
                "logPublicKey": action_verification.get("log_public_key"),
                "rpId": action_verification.get("rp_id"),
                "allowedOrigins": action_verification.get("allowed_origins"),
            })
            checks["action_receipt_valid"] = ra["valid"]
        if exec_.get("irreversible") is True:
            checks["action_human_signoff"] = _has_human_signoff(approval["receipt"], human_classes)
        checks["execution_binding"] = _hex_of(exec_.get("action_hash")) == _hex_of(approval["receipt"].get("action_hash"))

    chain = sorted(list(doc.get("delegation_chain") or []), key=lambda x: x.get("sequence") or 0)
    delegation_keys = opts.get("delegationKeys") or {}
    root_approvers = _receipt_approvers((doc.get("root_signoff") or {}).get("receipt")) if doc.get("root_signoff") else set()
    root_expiry = _latest_context_expiry((doc.get("root_signoff") or {}).get("receipt"))
    root_at = (((doc.get("root_signoff") or {}).get("receipt") or {}).get("action") or {}).get("action_type")
    root_scope = [root_at] if isinstance(root_at, str) and root_at else []
    from datetime import datetime, timezone
    parent = {"scope": root_scope, "max_value_usd": None,
              "expires_at": (datetime.fromtimestamp(root_expiry / 1000, timezone.utc).isoformat().replace("+00:00", "Z") if root_expiry is not None else None)}

    if chain:
        head = chain[0]
        # Anchor ONLY on the SIGNED delegator. parent_ref is not in
        # _DELEGATION_PROOF_FIELDS (unsigned, attacker-controlled).
        checks["chain_anchored"] = head.get("delegator") in root_approvers
        if not checks["chain_anchored"]:
            errors.append("chain head not anchored to a root approver")

    prev_delegatee = None
    for link in chain:
        if prev_delegatee is not None:
            if link.get("parent_ref") != prev_delegatee or link.get("delegator") != prev_delegatee:
                fail("chain_links_bound", "inter-hop link broken")
        exp = _instant_ms(link.get("expires_at"))
        if exp is None or exp < now:
            fail("delegations_not_expired", "delegation expired")
        if link.get("proof"):
            sig_ok = _verify_detached_signature(link["proof"])
            try:
                presented = _b64url_decode(link["proof"].get("signed_payload_b64u") or "")
            except Exception:
                presented = b""
            if not sig_ok or presented != _delegation_proof_bytes(link):
                fail("delegations_signed", "delegation proof invalid or not over own fields")
            bound_key = (delegation_keys.get(link.get("delegator")) or {}).get("public_key")
            if not bound_key:
                fail("proof_key_bound", "no pinned delegator key")
            elif bound_key != link["proof"].get("public_key"):
                fail("proof_key_bound", "proof key not bound to delegator")
        elif not allow_unsigned:
            fail("delegations_signed", "unsigned delegation (fail-closed)")
        if _scope_containment_violations(parent, link):
            fail("scope_containment", "scope containment violation")
        if not _constraints_monotonic(parent.get("constraints"), link.get("constraints")):
            fail("constraints_monotonic", "constraints relax a parent restriction")
        if link.get("max_value_usd") is None:
            eff = parent.get("max_value_usd")
        elif parent.get("max_value_usd") is None:
            eff = link.get("max_value_usd")
        else:
            eff = _js_min(_num(link["max_value_usd"]), _num(parent["max_value_usd"]))
        parent = {**link, "max_value_usd": eff}
        prev_delegatee = link.get("delegatee")

    action_type = (((doc.get("action_approval") or {}).get("receipt") or {}).get("action") or {}).get("action_type")
    if not action_type:
        fail("leaf_permits_action", "cannot determine executed action_type")
    elif not _scope_permits(parent.get("scope"), action_type):
        fail("leaf_permits_action", "leaf/root scope does not permit executed action")

    commit = _instant_ms((((doc.get("action_approval") or {}).get("receipt") or {}).get("consumption") or {}).get("committed_at")) if (doc.get("action_approval") or {}).get("receipt") else None
    leaf_exp = _instant_ms(parent.get("expires_at"))
    if commit is not None and leaf_exp is not None and commit > leaf_exp:
        fail("temporal_containment", "approval committed after leaf expiry")

    return {"valid": all(checks.values()), "checks": checks, "errors": errors, "links": [], "agent_identity": None, "liability": None}


# ── EP-EVIDENCE-RECORD-v1 (RFC 4998-style renewal chain) — mirror packages/verify ─

EVIDENCE_RECORD_VERSION = "EP-EVIDENCE-RECORD-v1"
_SUPPORTED_HASH = {"sha256", "sha384", "sha512"}


def _alg_of(hashed):
    s = str(hashed if hashed is not None else "")
    i = s.find(":")
    if i < 0:
        return ("sha256", s.lower())
    return (s[:i].lower(), s[i + 1:].lower())


def verify_evidence_record(record, opts=None):
    """Mirror of packages/verify/evidence-record.js verifyEvidenceRecord. Fail-closed."""
    opts = opts or {}
    tsa_keys = opts.get("tsaKeys") or {}
    checks = {"version": False, "protected_bound": True, "chain_nonempty": False,
              "all_timestamps_valid": True, "chain_linked": True, "monotonic_time": True}
    errors = []

    def fail(k, m):
        checks[k] = False
        errors.append(m)

    try:
        if not isinstance(record, dict) or record.get("@version") != EVIDENCE_RECORD_VERSION:
            return {"valid": False, "checks": checks, "errors": [f"unsupported version: {record.get('@version') if isinstance(record, dict) else None}"]}
        checks["version"] = True
        ats = record.get("archive_timestamps") if isinstance(record.get("archive_timestamps"), list) else []
        checks["chain_nonempty"] = len(ats) > 0
        if not checks["chain_nonempty"]:
            return {"valid": False, "checks": checks, "errors": ["no archive timestamps"]}

        if isinstance(opts.get("protectedHash"), str):
            if _alg_of(record.get("protected_hash"))[1] != _alg_of(opts["protectedHash"])[1]:
                fail("protected_bound", "record protected_hash does not match the supplied artifact hash")

        prev_time = None
        first_time = None
        for i, at in enumerate(ats):
            ta = (at or {}).get("time_attestation")
            r = verify_time_attestation(ta, {"tsaKeys": tsa_keys})
            if not r["valid"]:
                fail("all_timestamps_valid", f"archive timestamp {i} TSA attestation does not verify")
            alg, hex_ = _alg_of((ta or {}).get("hashed"))
            if i == 0:
                if hex_ != _alg_of(record.get("protected_hash"))[1]:
                    fail("chain_linked", "first archive timestamp does not cover protected_hash")
            elif alg not in _SUPPORTED_HASH:
                fail("chain_linked", f"renewal {i} uses an unsupported hash algorithm {alg}")
            else:
                expected = hashlib.new(alg, canonicalize(ats[i - 1].get("time_attestation")).encode("utf-8")).hexdigest()
                if hex_ != expected:
                    fail("chain_linked", f"renewal {i} does not cover the previous attestation")
            t = _instant_ms((ta or {}).get("time"))
            if t is None:
                fail("monotonic_time", f"archive timestamp {i} has no parseable time")
            else:
                if prev_time is not None and not (t > prev_time):
                    fail("monotonic_time", f"renewal {i} time is not after the previous")
                if first_time is None:
                    first_time = (ta or {}).get("time")
                prev_time = t
        return {"valid": all(checks.values()), "checks": checks, "errors": errors,
                "protected_since": first_time, "last_renewed": (ats[-1].get("time_attestation") or {}).get("time")}
    except Exception:
        return {"valid": False, "checks": checks, "errors": errors}


# ── EP-AEC-v1 — Authorization Evidence Chain (composition verifier) ──────────
AEC_VERSION = "EP-AEC-v1"
_AEC_MAX_COMPONENTS = 64
_AEC_MAX_REQUIREMENT_LENGTH = 4096
_AEC_MAX_REQUIREMENT_TOKENS = 256
_AEC_MAX_REQUIREMENT_DEPTH = 32
_AEC_MAX_QUORUM_MEMBERS = 32
_AEC_MAX_JSON_DEPTH = 64
_AEC_MAX_JSON_NODES = 50000
_AEC_MAX_JSON_STRING_BYTES = 1024 * 1024
_AEC_RESERVED_TYPES = {"ep-quorum", "ep-receipt"}
_AEC_IDENT = _re.compile(r"^[A-Za-z0-9_.:-]+$")
_AEC_IDENT_CHAR = _re.compile(r"[A-Za-z0-9_.:-]")
_AEC_HEX_256 = _re.compile(r"^[0-9a-f]{64}$")


def action_digest(action: Any) -> str:
    """Canonical action digest (hex) — sha256 of JCS(action). Mirrors JS actionDigest()."""
    return hashlib.sha256(canonicalize(action).encode("utf-8")).hexdigest()


def _norm_digest(d: Any) -> Optional[str]:
    if not isinstance(d, str):
        return None
    bare = d[7:].lower() if d.lower().startswith("sha256:") else d.lower()
    return bare if _AEC_HEX_256.fullmatch(bare) else None


def _aec_fresh_at(context: Any, verification_time: Any, max_age_sec: Any) -> bool:
    if (not isinstance(context, dict) or isinstance(max_age_sec, bool)
            or not isinstance(max_age_sec, int) or max_age_sec < 0):
        return False
    at = _instant_ms(verification_time)
    issued = _instant_ms(context.get("issued_at"))
    expires = _instant_ms(context.get("expires_at"))
    return (at is not None and issued is not None and expires is not None
            and issued <= at <= expires and at - issued <= max_age_sec * 1000)


def _aec_fresh_registry_snapshot(profile: Any, verification_time: Any) -> bool:
    if (not isinstance(profile, dict) or isinstance(profile.get("max_registry_age_sec"), bool)
            or not isinstance(profile.get("max_registry_age_sec"), int)
            or profile.get("max_registry_age_sec") < 0):
        return False
    at = _instant_ms(verification_time)
    checked = _instant_ms(profile.get("registry_checked_at"))
    return (at is not None and checked is not None and checked <= at
            and at - checked <= profile["max_registry_age_sec"] * 1000)


def _aec_active_directory_entry(entry: Any, verification_time: Any) -> bool:
    if not isinstance(entry, dict) or entry.get("status") != "active":
        return False
    at = _instant_ms(verification_time)
    start = _instant_ms(entry.get("valid_from"))
    end = _instant_ms(entry.get("valid_to"))
    if at is None or start is None or end is None or at < start or at > end:
        return False
    if entry.get("revoked_at") is None:
        return True
    revoked = _instant_ms(entry.get("revoked_at"))
    return revoked is not None and at < revoked


def _aec_allowed_origins(profile: Any):
    origins = profile.get("allowed_origins") if isinstance(profile, dict) else None
    if (not isinstance(origins, list) or not origins or len(origins) > 16
            or any(not isinstance(origin, str) or not origin or len(origin) > 2048 for origin in origins)):
        return None
    return set(origins)


def _aec_webauthn_origin(webauthn: Any):
    try:
        if not isinstance(webauthn, dict):
            return None
        encoded = webauthn.get("client_data_json")
        if not isinstance(encoded, str) or not encoded or any(
                ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for ch in encoded):
            return None
        client_data = _strict_json_loads(_b64url_decode(encoded).decode("utf-8"))
        origin = client_data.get("origin") if isinstance(client_data, dict) else None
        return origin if isinstance(origin, str) else None
    except Exception:
        return None


def _aec_bounded_json(value: Any) -> bool:
    stack = [(value, 0)]
    seen = set()
    nodes = 0
    string_bytes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _AEC_MAX_JSON_NODES or depth > _AEC_MAX_JSON_DEPTH:
            return False
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, str):
            try:
                string_bytes += len(current.encode("utf-8"))
            except UnicodeEncodeError:
                return False
            if string_bytes > _AEC_MAX_JSON_STRING_BYTES:
                return False
            continue
        if isinstance(current, int) and not isinstance(current, bool):
            if abs(current) > _SAFE_INT:
                return False
            continue
        if isinstance(current, float):
            if not math.isfinite(current) or not current.is_integer() or abs(current) > _SAFE_INT:
                return False
            continue
        if not isinstance(current, (dict, list)):
            return False
        marker = id(current)
        if marker in seen:
            return False
        seen.add(marker)
        if isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        else:
            for key, child in current.items():
                if not isinstance(key, str):
                    return False
                try:
                    string_bytes += len(key.encode("utf-8"))
                except UnicodeEncodeError:
                    return False
                if string_bytes > _AEC_MAX_JSON_STRING_BYTES:
                    return False
                stack.append((child, depth + 1))
    return True


def _builtin_aec_verifiers() -> dict:
    def ep_quorum(ev, ctx):
        # Internal quorum consistency is not acceptance. Require an RP-owned
        # profile that pins the exact policy, WebAuthn RP ID, context policy, and
        # key -> approver -> role directory.
        profile = (ctx.get("policiesByType") or {}).get("ep-quorum") or {}
        allowed_origins = _aec_allowed_origins(profile)
        members = (ev or {}).get("members")
        if (not isinstance(profile, dict) or not isinstance(profile.get("policy"), dict)
                or not isinstance(profile.get("rp_id"), str) or not profile.get("rp_id")
                or not isinstance(profile.get("context_policy"), str) or not profile.get("context_policy")
                or allowed_origins is None
                or isinstance(profile.get("max_age_sec"), bool)
                or not isinstance(profile.get("max_age_sec"), int) or profile.get("max_age_sec") < 0
                or not _aec_fresh_registry_snapshot(profile, ctx.get("verificationTime"))
                or not isinstance(profile.get("approvers"), dict)
                or not isinstance(members, list) or not members or len(members) > _AEC_MAX_QUORUM_MEMBERS):
            return {"valid": False, "action_digest": None}

        policy = profile["policy"]
        mode = policy.get("mode")
        if mode not in ("threshold", "ordered"):
            return {"valid": False, "action_digest": None}
        req = len(policy.get("approvers") or []) if mode == "ordered" else policy.get("required")
        if (isinstance(req, bool) or not isinstance(req, int) or req < 2
                or policy.get("distinct_humans") is not True
                or (mode == "ordered" and policy.get("ordered_chain") is not True)):
            return {"valid": False, "action_digest": None}
        try:
            if not isinstance((ev or {}).get("policy"), dict) or canonicalize(ev["policy"]) != canonicalize(policy):
                return {"valid": False, "action_digest": None}
        except Exception:
            return {"valid": False, "action_digest": None}

        for m in members:
            if not isinstance(m, dict) or not isinstance(m.get("signoff"), dict) or not isinstance(m["signoff"].get("context"), dict):
                return {"valid": False, "action_digest": None}
            k = m.get("approver_public_key")
            entry = profile["approvers"].get(k) if isinstance(k, str) else None
            signed_ctx = m["signoff"]["context"]
            if (not _aec_active_directory_entry(entry, ctx.get("verificationTime")) or entry.get("public_key") != k
                    or not isinstance(entry.get("approver_id"), str)
                    or entry.get("approver_id") != signed_ctx.get("approver")
                    or not isinstance(entry.get("roles"), list) or m.get("role") not in entry.get("roles")
                    or signed_ctx.get("policy") != profile["context_policy"]
                    or _aec_webauthn_origin(m["signoff"].get("webauthn")) not in allowed_origins
                    or not _aec_fresh_at(signed_ctx, ctx.get("verificationTime"), profile["max_age_sec"])):
                return {"valid": False, "action_digest": None}
        r = verify_quorum(ev, {
            "rpId": profile["rp_id"],
            "allowedOrigins": list(allowed_origins),
        }) or {}
        valid = bool(r.get("valid"))
        return {"valid": valid, "action_digest": ((ev or {}).get("action_hash") if valid else None)}

    def ep_receipt(ev, ctx):
        # A bare operator-signed envelope is not human authorization. Require the
        # Section 6.2 Trust Receipt's Class-A WebAuthn ceremony and RP-owned pins.
        profile = (ctx.get("policiesByType") or {}).get("ep-receipt") or {}
        allowed_origins = _aec_allowed_origins(profile)
        contexts = ev.get("contexts") if isinstance(ev, dict) else None
        signoffs = ev.get("signoffs") if isinstance(ev, dict) else None
        if (not isinstance(profile, dict) or not isinstance(profile.get("approver_keys"), dict)
                or not isinstance(profile.get("log_public_key"), str) or not profile.get("log_public_key")
                or not isinstance(profile.get("rp_id"), str) or not profile.get("rp_id")
                or allowed_origins is None
                or _norm_digest(profile.get("expected_policy_hash")) is None
                or isinstance(profile.get("max_age_sec"), bool)
                or not isinstance(profile.get("max_age_sec"), int) or profile.get("max_age_sec") < 0
                or not _aec_fresh_registry_snapshot(profile, ctx.get("verificationTime"))
                or not isinstance(contexts, list) or not contexts
                or not isinstance(signoffs, list) or not signoffs):
            return {"valid": False, "action_digest": None}

        try:
            context_by_hash = {}
            for receipt_context in contexts:
                if (not isinstance(receipt_context, dict)
                        or _norm_digest(receipt_context.get("policy_hash"))
                        != _norm_digest(profile["expected_policy_hash"])):
                    return {"valid": False, "action_digest": None}
                context_by_hash[_sha256_hex(canonicalize(receipt_context))] = receipt_context
        except Exception:
            return {"valid": False, "action_digest": None}

        expected_rp_hash = hashlib.sha256(profile["rp_id"].encode("utf-8")).digest()
        for signoff in signoffs:
            if not isinstance(signoff, dict):
                return {"valid": False, "action_digest": None}
            key_entry = profile["approver_keys"].get(signoff.get("approver_key_id"))
            signed_context = context_by_hash.get(_norm_digest(signoff.get("context_hash")))
            try:
                auth_data = _b64url_decode(((signoff.get("webauthn") or {}).get("authenticator_data")))
            except Exception:
                auth_data = b""
            if (not _aec_active_directory_entry(key_entry, ctx.get("verificationTime")) or key_entry.get("key_class") != "A"
                    or not isinstance(signed_context, dict)
                    or key_entry.get("approver_id") != signed_context.get("approver")
                    or len(auth_data) < 37 or auth_data[:32] != expected_rp_hash
                    or _aec_webauthn_origin(signoff.get("webauthn")) not in allowed_origins
                    or not _aec_fresh_at(signed_context, ctx.get("verificationTime"), profile["max_age_sec"])):
                return {"valid": False, "action_digest": None}

        r = verify_trust_receipt(ev, {
            "approverKeys": profile["approver_keys"],
            "logPublicKey": profile["log_public_key"],
            "rpId": profile["rp_id"],
            "allowedOrigins": list(allowed_origins),
        })
        valid = isinstance(r, dict) and r.get("valid") is True
        return {"valid": valid, "action_digest": (ev.get("action_hash") if valid else None)}

    return {"ep-quorum": ep_quorum, "ep-receipt": ep_receipt}


def _tokenize_aec_requirement(expr: Any):
    if not isinstance(expr, str) or not expr or len(expr) > _AEC_MAX_REQUIREMENT_LENGTH:
        return None
    toks = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch in " \t\r\n":
            i += 1
            continue
        if ch in "()":
            toks.append(ch)
            i += 1
        elif ch in "&|" and i + 1 < len(expr) and expr[i + 1] == ch:
            toks.append(ch + ch)
            i += 2
        elif _AEC_IDENT_CHAR.fullmatch(ch):
            j = i + 1
            while j < len(expr) and _AEC_IDENT_CHAR.fullmatch(expr[j]):
                j += 1
            toks.append(expr[i:j])
            i = j
        else:
            return None
        if len(toks) > _AEC_MAX_REQUIREMENT_TOKENS:
            return None
    return toks or None


def _eval_requirement(expr: str, satisfied: set) -> dict:
    toks = _tokenize_aec_requirement(expr)
    if toks is None:
        return {"valid": False, "value": False}
    pos = {"i": 0}

    def peek():
        return toks[pos["i"]] if pos["i"] < len(toks) else None

    def eat():
        t = peek()
        pos["i"] += 1
        return t

    def parse_expr(depth=0):
        if depth > _AEC_MAX_REQUIREMENT_DEPTH:
            raise ValueError("requirement nesting limit exceeded")
        v = parse_term(depth)
        while peek() in ("AND", "OR", "&&", "||"):
            op = eat()
            r = parse_term(depth)
            v = (v and r) if op in ("AND", "&&") else (v or r)
        return v

    def parse_term(depth):
        if peek() == "(":
            eat()
            v = parse_expr(depth + 1)
            if peek() != ")":
                raise ValueError("unclosed requirement group")
            eat()
            return v
        ident = eat()
        if ident is None or ident in (")", "AND", "OR", "&&", "||") or not _AEC_IDENT.fullmatch(ident):
            raise ValueError("invalid requirement term")
        return ident in satisfied

    try:
        v = parse_expr()
        valid = pos["i"] == len(toks)
        return {"valid": valid, "value": bool(v) if valid else False}
    except Exception:
        return {"valid": False, "value": False}


def verify_authorization_chain(aec: Any, verifiers: Optional[dict] = None,
                                keys_by_type: Optional[dict] = None,
                                requirement: Optional[str] = None,
                                policies_by_type: Optional[dict] = None,
                                expected_action_digest: Optional[str] = None,
                                expected_action: Optional[dict] = None,
                                verification_time: Optional[str] = None) -> dict:
    """Verify an EP-AEC chain offline. Fail-closed. Mirrors JS verifyAuthorizationChain().

    TRUST BOUNDARY: the chain document's ``requirement`` is PRESENTER-supplied — a
    claim of what the bundle satisfies, never the relying party's bar. Pass
    ``requirement=`` to pin the RELYING PARTY's own requirement. Without it,
    the presenter expression is descriptive only and ``satisfied`` remains false.

    ``policies_by_type`` follows ``requirement`` to preserve the original
    positional API; callers should pass both by keyword.

    ``keys_by_type`` is retained for compatibility and custom verifiers. Built-in
    human acceptance is profile-scoped through ``policies_by_type``: ep-receipt
    requires a fresh Class-A Trust Receipt profile and ep-quorum an exact fresh
    quorum policy, audience, and enrolled approver directory.
    """
    reasons: list = []
    pinned = requirement if isinstance(requirement, str) and requirement.strip() else None
    requirement_source = "relying_party" if pinned else "presenter"

    def fail(why):
        reasons.append(why)
        return {"satisfied": False, "allow": False, "action_digest": None, "expected_action_bound": False,
                "components": [], "reasons": reasons,
                "requirement_source": requirement_source}

    if not isinstance(aec, dict):
        return fail("chain is not an object")
    if not _aec_bounded_json(aec):
        return fail("chain exceeds the canonical JSON safety profile or resource limits")
    if aec.get("@version") != AEC_VERSION:
        return fail("unexpected @version")
    if not isinstance(aec.get("action"), dict):
        return fail("missing action object")
    comps_in = aec.get("components")
    if not isinstance(comps_in, list) or not comps_in:
        return fail("no components")
    if len(comps_in) > _AEC_MAX_COMPONENTS:
        return fail(f"too many components (maximum {_AEC_MAX_COMPONENTS})")
    req = pinned if pinned is not None else aec.get("requirement")
    if not isinstance(req, str) or not req.strip():
        return fail("missing requirement expression")
    if len(req) > _AEC_MAX_REQUIREMENT_LENGTH:
        return fail("requirement expression exceeds size limit")

    try:
        chain_digest = action_digest(aec["action"])
    except Exception:
        return fail("action is not canonicalizable")

    # Components agreeing with one another does not bind them to the action the
    # executor is actually about to perform. Require a relying-party-owned
    # expected action or digest before allow can become true.
    expected_digest = None
    if expected_action is not None:
        if not isinstance(expected_action, dict) or not _aec_bounded_json(expected_action):
            return fail("expected_action is not a bounded canonical JSON object")
        try:
            expected_digest = action_digest(expected_action)
        except Exception:
            return fail("expected_action is not canonicalizable")
    if expected_action_digest is not None:
        supplied = _norm_digest(expected_action_digest)
        if supplied is None:
            return fail("expected_action_digest is malformed")
        if expected_digest is not None and supplied != expected_digest:
            return fail("expected_action and expected_action_digest disagree")
        expected_digest = supplied
    if expected_digest is not None and expected_digest != chain_digest:
        return fail("chain action does not match the relying-party expected action")
    if aec.get("action_digest") is not None and _norm_digest(aec.get("action_digest")) != chain_digest:
        return fail("declared action_digest does not match canonical digest of the action")

    vmap = dict(_builtin_aec_verifiers())
    if isinstance(verifiers, dict):
        vmap.update({k: v for k, v in verifiers.items()
                     if k not in _AEC_RESERVED_TYPES and callable(v)})
    satisfied: set = set()
    components = []
    for idx, c in enumerate(comps_in):
        if not isinstance(c, dict):
            components.append({"type": None, "label": f"#{idx}", "valid": False,
                               "bound": False, "reason": "component is not an object"})
            continue
        label = c.get("label") or c.get("type") or f"#{idx}"
        row = {"type": c.get("type"), "label": label, "valid": False, "bound": False, "reason": None}
        typ = c.get("type")
        if (not isinstance(typ, str) or len(typ) > 128 or not _AEC_IDENT.fullmatch(typ)
                or not isinstance(c.get("evidence"), dict)):
            row["reason"] = "component type or evidence is malformed"
            components.append(row)
            continue
        v = vmap.get(typ)
        if not callable(v):
            row["reason"] = f'no verifier registered for type "{c.get("type")}"'
            components.append(row)
            continue
        try:
            res = v(c.get("evidence"), {"keysByType": keys_by_type,
                                        "policiesByType": policies_by_type,
                                        "verificationTime": verification_time,
                                        "action": aec["action"]}) or {}
        except Exception as e:
            row["reason"] = f"verifier raised: {e}"
            components.append(row)
            continue
        row["valid"] = isinstance(res, dict) and res.get("valid") is True
        row["bound"] = _norm_digest(res.get("action_digest")) == chain_digest
        if not row["valid"]:
            row["reason"] = "component evidence did not verify"
        elif not row["bound"]:
            row["reason"] = "component binds a DIFFERENT action than the chain"
        if row["valid"] and row["bound"]:
            satisfied.add(typ)
            # Presenter-controlled labels are display metadata only.
        components.append(row)

    evaluated = _eval_requirement(req, satisfied)
    satisfied_result = (requirement_source == "relying_party" and expected_digest is not None
                        and evaluated["valid"] and evaluated["value"])
    if not evaluated["valid"]:
        reasons.append("requirement expression is malformed or exceeds parser limits")
    elif not evaluated["value"]:
        reasons.append(f'requirement not satisfied: "{req}"')
    if requirement_source != "relying_party":
        reasons.append("presenter requirement is descriptive only; relying-party requirement is required for satisfaction")
    if expected_digest is None:
        reasons.append("relying-party expected action is required for satisfaction")
    presenter_req = aec.get("requirement")
    if pinned and isinstance(presenter_req, str) and presenter_req.strip() and presenter_req != pinned:
        reasons.append(
            f'presenter requirement ignored in favor of relying-party requirement (presenter claimed: "{presenter_req}")')
    return {"satisfied": satisfied_result,
            "allow": satisfied_result,  # Compatibility alias; AEC is not the policy decision.
            "action_digest": chain_digest,
            "expected_action_bound": expected_digest == chain_digest,
            "components": components, "reasons": reasons,
            "requirement_source": requirement_source}


# =============================================================================
# PIP-008 §2.1 — L4 -> L7 binding (record relied-on agent evidence + freshness)
# =============================================================================
def evaluate_agent_binding(context, max_age_sec=None, at=None):
    """Surface the external agent-identity / delegation evidence (L4) a decision
    (L7 PDP) relied on, and OPTIONALLY enforce its freshness. Mirrors
    @emilia-protocol/verify evaluateAgentBinding byte-for-byte in behavior.

    EP does NOT resolve or trust the L4 identity — ``agent_binding`` is a signed
    CLAIM (PIP-008). This lets a Policy Decision Point RECORD which upstream
    evidence backed a human authorization and detect a stale or absent upstream
    attestation after the fact. Pass a context whose signature has ALREADY been
    verified.

    Returns a dict: {present, agent_id?, delegation?, evidence_hash, observed_at,
    fresh (bool|None), age_seconds (int|None), reason}.
    """
    from datetime import datetime, timezone

    def _parse(s):
        return datetime.fromisoformat(s.replace("Z", "+00:00"))

    binding = context.get("agent_binding") if isinstance(context, dict) else None
    if not isinstance(binding, dict):
        return {"present": False, "fresh": None, "age_seconds": None, "reason": "no_agent_binding"}

    d = binding.get("delegation") if isinstance(binding.get("delegation"), dict) else None
    delegation = None
    if d is not None:
        delegation = {"scheme": d.get("scheme"), "ref": d.get("ref")}
        if d.get("hash"):
            delegation["hash"] = d.get("hash")
        if d.get("observed_at"):
            delegation["observed_at"] = d.get("observed_at")
    observed = d.get("observed_at") if d else None
    out = {
        "present": True,
        "agent_id": binding.get("agent_id"),
        "delegation": delegation,
        "evidence_hash": (d.get("hash") if d else None) or None,
        "observed_at": observed,
        "fresh": None,
        "age_seconds": None,
        "reason": "recorded",
    }
    if isinstance(max_age_sec, (int, float)) and not isinstance(max_age_sec, bool) and max_age_sec >= 0:
        if not observed:
            out["fresh"] = False
            out["reason"] = "freshness_required_but_no_observed_at"
            return out
        try:
            obs = _parse(observed)
            ref = _parse(at) if at else datetime.now(timezone.utc)
        except Exception:
            out["fresh"] = False
            out["reason"] = "unparseable_observed_at"
            return out
        age = (ref - obs).total_seconds()
        out["age_seconds"] = round(age)
        if age < -60:                       # observed in the future (allow 60s clock skew)
            out["fresh"] = False
            out["reason"] = "observed_at_in_future"
        elif age > max_age_sec:
            out["fresh"] = False
            out["reason"] = f"stale: L4 evidence observed {out['age_seconds']}s ago (max {int(max_age_sec)}s)"
        else:
            out["fresh"] = True
            out["reason"] = "fresh"
    return out


# =============================================================================
# EP-CURRENCY-v1 — two-valued verification result (currency.js port)
# =============================================================================
# Mirrors packages/verify/currency.js byte-for-byte. Offline verification alone
# yields currency status 'unknown' (the honest, fail-safe default). 'fresh' is
# reachable ONLY with a policy-satisfying freshHead. Honesty is a security
# property: an offline-only check must NEVER report 'fresh'.

CURRENCY_VERSION = "EP-CURRENCY-v1"
CURRENCY_STATUS = ("fresh", "stale", "unknown")

CURRENCY_REASON = {
    # status: 'unknown'
    "offline_only_no_fresh_head": "offline_only_no_fresh_head",
    "fresh_head_malformed": "fresh_head_malformed",
    "now_invalid": "now_invalid",
    # status: 'stale'
    "fresh_head_stale": "fresh_head_stale",
    "fresh_head_in_future": "fresh_head_in_future",
    "fresh_head_required_but_absent": "fresh_head_required_but_absent",
    "revoked_by_fresh_head": "revoked_by_fresh_head",
    "max_staleness_invalid": "max_staleness_invalid",
    # status: 'fresh'
    "fresh_head_within_window": "fresh_head_within_window",
}

# 64-char SHA-256 validator: malformed -> '' so comparisons fail closed (never
# match a real digest). Mirrors currency.js hexOf() exactly (leading "sha256:"
# stripped once, lowercased, must be exactly 64 hex).
_CURRENCY_HEX64 = _re.compile(r"^[0-9a-f]{64}$")


def _currency_hex_of(h: Any) -> str:
    s = str(h if h is not None else "")
    if s.startswith("sha256:"):
        s = s[len("sha256:"):]
    s = s.lower()
    return s if _CURRENCY_HEX64.match(s) else ""


# currency.js uses JS Date.parse (lenient). We accept the RFC 3339 forms that
# new Date(...).toISOString() emits (always "Z") plus explicit-offset forms, and
# return None on anything unparseable — matching currency.js for every realistic
# head/now value (all produced by toISOString) and for the 'not-a-time' edge.
_CURRENCY_RFC3339 = _re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def _currency_instant_ms(s: Any):
    import datetime as _dt
    if not isinstance(s, str) or not _CURRENCY_RFC3339.match(s):
        return None
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000
    except Exception:
        return None


def _currency_iso(ms: float) -> str:
    """Format epoch ms as new Date(ms).toISOString() does: millisecond-precision
    UTC ("YYYY-MM-DDTHH:MM:SS.sssZ")."""
    import datetime as _dt
    dt = _dt.datetime.fromtimestamp(ms / 1000, _dt.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(round(ms)) % 1000:03d}Z"


def _head_revokes_receipt(fresh_head: Any, receipt: Any) -> bool:
    """Does this signed head revoke the given receipt? Fail-safe: any malformed
    revocation field is treated as NON-revoking (mirrors currency.js)."""
    if isinstance(fresh_head, dict) and fresh_head.get("revoked") is True:
        return True
    lst = fresh_head.get("revoked_target_hashes") if isinstance(fresh_head, dict) else None
    if isinstance(lst, list) and len(lst) > 0:
        targets = {t for t in (_currency_hex_of(x) for x in lst) if t}
        if not targets:
            return False
        receipt_action_hash = _currency_hex_of((receipt or {}).get("action_hash")) if isinstance(receipt, dict) else ""
        explicit_target = _currency_hex_of(fresh_head.get("target_hash")) if isinstance(fresh_head, dict) else ""
        if receipt_action_hash and receipt_action_hash in targets:
            return True
        if explicit_target and explicit_target in targets:
            return True
    return False


def evaluate_currency(args: Optional[dict] = None) -> dict:
    """Compute the two-valued verification result: authentic_as_of_commit (from
    the offline check the caller already ran) and currency_at_T (which offline
    CANNOT establish and which is therefore 'unknown' by default).

    Mirrors packages/verify/currency.js evaluateCurrency(args). Fail-closed:
    anything not strictly ``authentic_as_of_commit is True`` records False; an
    unparseable ``now`` yields 'unknown'; a freshHead with no policy bound yields
    'stale'; only a recent, non-revoking head within the policy window is 'fresh'.
    """
    if not isinstance(args, dict):
        args = {}
    receipt = args.get("receipt")
    now = args.get("now", _CURRENCY_NOW_SENTINEL)
    max_staleness_seconds = args.get("maxStalenessSeconds")
    fresh_head = args.get("freshHead", _CURRENCY_ABSENT)
    fresh_head_required = args.get("freshHeadRequired")

    # Pass the offline result through verbatim, fail-safe to False.
    authentic = args.get("authentic_as_of_commit") is True

    # Resolve reference time T. An unparseable now yields 'unknown'.
    if now is _CURRENCY_NOW_SENTINEL:
        import time as _t
        now_ms: Optional[float] = _t.time() * 1000
    elif isinstance(now, (int, float)) and not isinstance(now, bool):
        now_ms = float(now)
    else:
        now_ms = _currency_instant_ms(now)
    now_finite = now_ms is not None and math.isfinite(now_ms)
    evaluated_at = _currency_iso(now_ms) if now_finite else None

    def result(status: str, reason: str) -> dict:
        return {
            "authentic_as_of_commit": authentic,
            "currency_at_T": {"status": status, "evaluated_at": evaluated_at, "reason": reason},
        }

    # No fresh head: offline CANNOT prove currency. Fail-safe path.
    if fresh_head is _CURRENCY_ABSENT or fresh_head is None:
        if fresh_head_required is True:
            return result("stale", CURRENCY_REASON["fresh_head_required_but_absent"])
        return result("unknown", CURRENCY_REASON["offline_only_no_fresh_head"])

    # A fresh head was supplied. If T is unusable, we cannot compute age -> 'unknown'.
    if not now_finite:
        return result("unknown", CURRENCY_REASON["now_invalid"])

    # The head must be a usable object carrying a well-formed observation instant.
    if not isinstance(fresh_head, dict):
        return result("unknown", CURRENCY_REASON["fresh_head_malformed"])
    head_ms = _currency_instant_ms(fresh_head.get("observed_at"))
    if head_ms is None:
        head_ms = _currency_instant_ms(fresh_head.get("issued_at"))
    if head_ms is None:
        return result("unknown", CURRENCY_REASON["fresh_head_malformed"])

    # maxStalenessSeconds is the action-policy bound; without a valid bound we
    # refuse to certify freshness (fail-safe to 'stale').
    if (not isinstance(max_staleness_seconds, (int, float))
            or isinstance(max_staleness_seconds, bool)
            or not math.isfinite(max_staleness_seconds)
            or max_staleness_seconds < 0):
        return result("stale", CURRENCY_REASON["max_staleness_invalid"])

    # A future-dated head cannot certify current status.
    age_seconds = (now_ms - head_ms) / 1000
    if age_seconds < 0:
        return result("stale", CURRENCY_REASON["fresh_head_in_future"])

    # Revocation shown by the head dominates.
    if _head_revokes_receipt(fresh_head, receipt):
        return result("stale", CURRENCY_REASON["revoked_by_fresh_head"])

    # Age gate.
    if age_seconds > max_staleness_seconds:
        return result("stale", CURRENCY_REASON["fresh_head_stale"])

    return result("fresh", CURRENCY_REASON["fresh_head_within_window"])


# Sentinels distinguishing "now omitted" (use wall clock) from an explicit value,
# and "freshHead absent" from an explicit None (both map to the same 'unknown').
_CURRENCY_NOW_SENTINEL = object()
_CURRENCY_ABSENT = object()


# =============================================================================
# EP-WITNESS-v1 — witness cosignature verification (witness.js port)
# =============================================================================
# A witness re-signs the SAME committed checkpoint bytes the log signed, under a
# DISTINCT domain tag, so several independent witnesses cosigning divergent heads
# make a split view (equivocation) detectable. Byte-identical to witness.js: the
# same EP-WITNESS-COSIGN-v1 domain tag and preimage construction, so a JS-produced
# cosignature verifies here and vice versa. Ed25519 over the SHA-256 digest, with
# the pinned key as base64url SPKI-DER. FAIL-CLOSED throughout.

WITNESS_VERSION = "EP-WITNESS-v1"

# Domain-separation tag prepended to the SHA-256 pre-image a witness signs. A
# UTF-8 label with a trailing 0x00 (so it can never prefix the canonical JSON,
# which begins with '{' 0x7b). The log's own signature has NO such prefix.
WITNESS_DOMAIN_TAG = "EP-WITNESS-COSIGN-v1\x00"


def _witness_committed_checkpoint(checkpoint: Any):
    """The committed bytes: the checkpoint the log signed, i.e. WITHOUT its own
    log_signature. Copy so we never mutate the caller's object. Returns None on a
    non-object / array checkpoint (fail-closed)."""
    if not isinstance(checkpoint, dict):
        return None
    signed = dict(checkpoint)
    signed.pop("log_signature", None)
    return signed


def witness_signing_digest(checkpoint: Any):
    """The exact bytes a witness signs / a verifier re-derives: the domain tag
    followed by the canonical committed checkpoint, then SHA-256'd to a 32-byte
    digest. Ed25519 is applied over this digest (matching the log-signature
    convention). Returns the 32-byte digest, or None (fail-closed)."""
    signed = _witness_committed_checkpoint(checkpoint)
    if signed is None:
        return None
    preimage = WITNESS_DOMAIN_TAG.encode("utf-8") + canonicalize(signed).encode("utf-8")
    return hashlib.sha256(preimage).digest()


def _witness_hex_of(h: Any) -> str:
    return _re.sub(r"^sha256:", "", str(h or ""), flags=_re.IGNORECASE).lower()


def _ed25519_verify_bytes(digest: bytes, pub_b64u: Any) -> bool:
    """Ed25519 verify the RAW 32-byte digest under a base64url SPKI-DER key. This
    mirrors crypto.verify(null, digest, key) in witness.js (which signs/verifies
    the digest, not the message)."""
    def _inner(sig_b64u: Any) -> bool:
        try:
            if not pub_b64u or not sig_b64u:
                return False
            key = load_der_public_key(_b64url_decode(pub_b64u))
            if not isinstance(key, Ed25519PublicKey):
                return False
            key.verify(_b64url_decode(sig_b64u), digest)
            return True
        except Exception:
            return False
    return _inner


def verify_witness_cosignature(checkpoint: Any, cosignature: Any, pinned_witness_key: Any) -> dict:
    """Verify a single witness cosignature over a checkpoint. Mirrors witness.js
    verifyWitnessCosignature. Returns {verified, witness_id, reason?}. FAIL-CLOSED:
    an unknown/unpinned witness refuses; a signature over different bytes refuses;
    a cosignature echoed for a different checkpoint refuses before the crypto runs."""
    def refuse(reason: str) -> dict:
        return {"verified": False, "witness_id": None, "reason": reason}

    if not isinstance(checkpoint, dict):
        return refuse("checkpoint is missing or not an object")
    if not isinstance(cosignature, dict):
        return refuse("cosignature is missing or not an object")
    if not isinstance(pinned_witness_key, dict):
        return refuse("pinnedWitnessKey is missing")

    pinned_id = pinned_witness_key.get("witness_id")
    pinned_pub = pinned_witness_key.get("public_key")
    if not isinstance(pinned_id, str) or not pinned_id:
        return refuse("pinnedWitnessKey.witness_id is missing")
    if not isinstance(pinned_pub, str) or not pinned_pub:
        return refuse("pinnedWitnessKey.public_key is missing")

    co_id = cosignature.get("witness_id")
    if not isinstance(co_id, str) or not co_id:
        return refuse("cosignature.witness_id is missing")
    if co_id != pinned_id:
        return refuse("cosignature witness_id is not the pinned witness (unpinned witness refused)")

    if cosignature.get("alg") is not None and cosignature.get("alg") != WITNESS_VERSION:
        return refuse(f"cosignature alg must be {WITNESS_VERSION} when present")

    sig = cosignature.get("signature")
    if not isinstance(sig, str) or not sig:
        return refuse("cosignature.signature is missing")

    # Echoed-head guards: a present-and-wrong echoed field refuses even before the
    # crypto runs (absent is allowed — the signed digest already binds all bytes).
    if "tree_size" in cosignature and cosignature.get("tree_size") is not None \
            and cosignature.get("tree_size") != checkpoint.get("tree_size"):
        return refuse("cosignature tree_size does not match the checkpoint (cosignature for a different head)")
    if "root_hash" in cosignature and cosignature.get("root_hash") is not None \
            and _witness_hex_of(cosignature.get("root_hash")) != _witness_hex_of(checkpoint.get("root_hash")):
        return refuse("cosignature root_hash does not match the checkpoint (cosignature for a different head)")
    if "log_key_id" in cosignature and cosignature.get("log_key_id") is not None \
            and cosignature.get("log_key_id") != checkpoint.get("log_key_id"):
        return refuse("cosignature log_key_id does not match the checkpoint (cosignature for a different log)")

    digest = witness_signing_digest(checkpoint)
    if digest is None:
        return refuse("checkpoint could not be canonicalized")

    if not _ed25519_verify_bytes(digest, pinned_pub)(sig):
        return refuse("cosignature does not verify over the checkpoint committed bytes")
    return {"verified": True, "witness_id": co_id}


def require_witness_quorum(checkpoint: Any, cosignatures: Any, pinned_witness_keys: Any, k: Any) -> dict:
    """Require >= k DISTINCT pinned witnesses to have validly cosigned the SAME
    head. Mirrors witness.js requireWitnessQuorum. Duplicate witness_ids count
    ONCE; unpinned / different-head / non-verifying cosignatures are ignored and
    recorded in ``reasons``. FAIL-CLOSED: bad inputs return ok False."""
    reasons: list = []

    if not (isinstance(k, int) and not isinstance(k, bool)) or k < 1:
        reasons.append("k must be an integer >= 1")
        return {"ok": False, "met": 0, "required": (k if isinstance(k, (int, float)) and not isinstance(k, bool) else 0),
                "witness_ids": [], "reasons": reasons}
    if not isinstance(checkpoint, dict):
        reasons.append("checkpoint is missing or not an object")
        return {"ok": False, "met": 0, "required": k, "witness_ids": [], "reasons": reasons}
    if not isinstance(cosignatures, list):
        reasons.append("cosignatures must be an array")
        return {"ok": False, "met": 0, "required": k, "witness_ids": [], "reasons": reasons}
    if not isinstance(pinned_witness_keys, list):
        reasons.append("pinnedWitnessKeys must be an array")
        return {"ok": False, "met": 0, "required": k, "witness_ids": [], "reasons": reasons}

    # Build the pinned-witness directory. A duplicated witness_id is ambiguous and
    # is dropped rather than trusted (fail-closed).
    pinned_by_id: dict = {}
    seen_pinned: set = set()
    dup_pinned: set = set()
    for w in pinned_witness_keys:
        wid = w.get("witness_id") if isinstance(w, dict) else None
        if not isinstance(wid, str) or not wid:
            reasons.append("a pinned witness entry is missing witness_id (dropped)")
            continue
        if wid in seen_pinned:
            dup_pinned.add(wid)
            continue
        seen_pinned.add(wid)
        pinned_by_id[wid] = w
    for wid in dup_pinned:
        pinned_by_id.pop(wid, None)
        reasons.append(f'pinned witness_id "{wid}" appears more than once (dropped as ambiguous)')

    met: set = set()
    for cosig in cosignatures:
        cid = cosig.get("witness_id") if isinstance(cosig, dict) else None
        if not isinstance(cid, str) or not cid:
            reasons.append("a cosignature is missing witness_id (ignored)")
            continue
        if cid in met:
            reasons.append(f'duplicate cosignature from witness "{cid}" (counted once)')
            continue
        pinned = pinned_by_id.get(cid)
        if not pinned:
            reasons.append(f'cosignature from unpinned witness "{cid}" (ignored)')
            continue
        res = verify_witness_cosignature(checkpoint, cosig, pinned)
        if res["verified"]:
            met.add(res["witness_id"])
        else:
            reasons.append(f'cosignature from "{cid}" did not verify: {res.get("reason")}')

    witness_ids = sorted(met)
    return {"ok": len(met) >= k, "met": len(met), "required": k, "witness_ids": witness_ids, "reasons": reasons}


# =============================================================================
# Checkpoint CONSISTENCY proofs (consistency.js port) — EP-MERKLE-v2
# =============================================================================
# RFC 6962 §2.1.2 append-only consistency verifier + reference prover. Reused by
# the consumption-proof profile below. Byte-identical to consistency.js: same
# EP-MERKLE-v2 branch construction (SHA-256(0x01 || leftHex || rightHex) -> hex).

CONSISTENCY_ALG = "EP-MERKLE-v2"


def _consistency_hex_of(h: Any) -> str:
    return _re.sub(r"^sha256:", "", str(h or ""), flags=_re.IGNORECASE).lower()


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _largest_power_of_two_less_than(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def verify_checkpoint_consistency(old_root: Any, old_size: Any, new_root: Any, new_size: Any, proof: Any) -> bool:
    """Verify an RFC 6962 §2.1.2 checkpoint consistency proof: the size-newSize
    tree is a prefix-preserving append-only extension of the size-oldSize tree.
    Mirrors consistency.js verifyCheckpointConsistency. FAIL-CLOSED."""
    if not (isinstance(old_size, int) and not isinstance(old_size, bool)):
        return False
    if not (isinstance(new_size, int) and not isinstance(new_size, bool)):
        return False
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if not isinstance(proof, list):
        return False
    if len(proof) > 64:
        return False
    old_r = _consistency_hex_of(old_root)
    new_r = _consistency_hex_of(new_root)
    if not old_r or not new_r:
        return False

    if old_size == new_size:
        return len(proof) == 0 and old_r == new_r
    if old_size == 0:
        return False
    if len(proof) == 0:
        return False

    path = [_consistency_hex_of(h) for h in proof]
    if any(not h for h in path):
        return False

    node = path
    if _is_power_of_two(old_size):
        seed = old_r
    else:
        seed = node[0]
        node = node[1:]

    fn = old_size - 1
    sn = new_size - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2

    fr = seed
    sr = seed

    for c in node:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = _hash_pair_v2(c, fr)
            sr = _hash_pair_v2(c, sr)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            sr = _hash_pair_v2(sr, c)
        fn //= 2
        sn //= 2

    return sn == 0 and fr == old_r and sr == new_r


def _consistency_merkle_root(leaves: list) -> str:
    """Reference EP-MERKLE-v2 root over already-hashed leaf hex. EXPERIMENTAL —
    test/tooling helper (mirrors consistency.js merkleRoot)."""
    d = [_consistency_hex_of(x) for x in leaves]
    if len(d) == 0:
        raise ValueError("merkleRoot: empty tree has no defined EP root")
    if len(d) == 1:
        return d[0]
    k = _largest_power_of_two_less_than(len(d))
    return _hash_pair_v2(_consistency_merkle_root(d[:k]), _consistency_merkle_root(d[k:]))


def _consistency_subproof(m: int, d: list, b: bool) -> list:
    n = len(d)
    if m == n:
        return [] if b else [_consistency_merkle_root(d)]
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return _consistency_subproof(m, d[:k], b) + [_consistency_merkle_root(d[k:n])]
    return _consistency_subproof(m - k, d[k:n], False) + [_consistency_merkle_root(d[:k])]


def build_consistency_proof(m: int, n: int, leaves: list) -> list:
    """Reference RFC 6962 consistency proof between two sizes (test/tooling helper;
    mirrors consistency.js buildConsistencyProof). EXPERIMENTAL."""
    if not isinstance(leaves, list) or len(leaves) < n:
        raise ValueError("buildConsistencyProof: need at least n leaf hashes")
    if not (m >= 1 and m <= n):
        raise ValueError("buildConsistencyProof: require 1 <= m <= n")
    if m == n:
        return []
    return _consistency_subproof(m, [_consistency_hex_of(x) for x in leaves[:n]], True)


# =============================================================================
# EP-SMT-CONSUME-v1 — third-party consumption proofs (consumption-proof.js port)
# =============================================================================
# Sparse-Merkle-over-nonce one-time consumption. Proves a nonce transitioned
# ABSENT -> PRESENT exactly once between two append-only-linked heads, so
# double-consumption becomes offline-detectable. Byte-identical to
# consumption-proof.js: REUSES the EP-MERKLE-v2 branch hashing above (does NOT
# invent a second scheme) and the same distinct 0x02 (present) / 0x03 (default)
# leaf domains. FAIL-CLOSED with a DISTINCT reason per failure.

CONSUMPTION_PROFILE = "EP-SMT-CONSUME-v1"
CONSUMPTION_LEAF_DOMAIN = "EP-SMT-CONSUME-v1"
SMT_DEPTH = 32

_SMT_HEX_ONLY = _re.compile(r"^[0-9a-f]+$")


def _smt_hex_of(h: Any) -> str:
    return _re.sub(r"^sha256:", "", str("" if h is None else h), flags=_re.IGNORECASE).lower()


def _smt_is_hex64(h: Any) -> bool:
    return isinstance(h, str) and len(h) == 64 and bool(_SMT_HEX_ONLY.match(h))


# EP-MERKLE-v2 branch hash: SHA-256(0x01 || leftHex || rightHex) -> hex. Byte-
# identical to _hash_pair_v2 above (kept in sync deliberately, not re-derived).
def _smt_hash_branch(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + left.encode("utf-8") + right.encode("utf-8")).hexdigest()


def _smt_present_leaf(key_hex: str, value_hex: str) -> str:
    # PRESENT leaf: SHA-256(0x02 || keyHex || valueHex) -> hex.
    return hashlib.sha256(b"\x02" + key_hex.encode("utf-8") + value_hex.encode("utf-8")).hexdigest()


def _smt_default_leaf() -> str:
    # DEFAULT (absent) leaf: SHA-256(0x03) -> hex.
    return hashlib.sha256(b"\x03").hexdigest()


def _smt_nonce_key_hex(nonce: Any) -> str:
    return hashlib.sha256(str(nonce).encode("utf-8")).hexdigest()


def _smt_path_bit(key_hex: str, i: int) -> int:
    byte_index = i >> 3
    byte = int(key_hex[byte_index * 2:byte_index * 2 + 2], 16)
    return (byte >> (7 - (i & 7))) & 1


def _smt_fold_to_root(leaf_hex: str, siblings: Any, key_hex: str, depth: int):
    if not _smt_is_hex64(leaf_hex):
        return None
    if not isinstance(siblings, list) or len(siblings) != depth:
        return None
    node = leaf_hex
    for level in range(depth - 1, -1, -1):
        sib = _smt_hex_of(siblings[level])
        if not _smt_is_hex64(sib):
            return None
        bit = _smt_path_bit(key_hex, level)
        node = _smt_hash_branch(node, sib) if bit == 0 else _smt_hash_branch(sib, node)
    return node


def _smt_check_sub(sub: Any, key_hex: str, label: str) -> dict:
    if not isinstance(sub, dict):
        return {"ok": False, "reason": f"{label}_missing"}
    root = _smt_hex_of(sub.get("root"))
    if not _smt_is_hex64(root):
        return {"ok": False, "reason": f"{label}_root_malformed"}
    if not isinstance(sub.get("siblings"), list) or len(sub.get("siblings")) != SMT_DEPTH:
        return {"ok": False, "reason": f"{label}_siblings_wrong_length"}
    if sub.get("present") is True:
        value = _smt_hex_of(sub.get("value"))
        if not _smt_is_hex64(value):
            return {"ok": False, "reason": f"{label}_present_value_malformed"}
        leaf = _smt_present_leaf(key_hex, value)
    elif sub.get("present") is False:
        leaf = _smt_default_leaf()
    else:
        return {"ok": False, "reason": f"{label}_present_flag_missing"}
    reconstructed = _smt_fold_to_root(leaf, sub.get("siblings"), key_hex, SMT_DEPTH)
    if reconstructed is None:
        return {"ok": False, "reason": f"{label}_sibling_malformed"}
    if reconstructed != root:
        return {"ok": False, "reason": f"{label}_does_not_reconstruct_root"}
    return {"ok": True}


def verify_consumption_proof(bundle: Any) -> dict:
    """Verify a third-party CONSUMPTION proof bundle: a nonce transitioned ABSENT
    -> PRESENT exactly once between two witnessed, append-only-linked heads.
    Mirrors consumption-proof.js verifyConsumptionProof. FAIL-CLOSED with a
    distinct reason; the ``present`` flag is never inferred."""
    checks = {"non_inclusion": False, "inclusion": False, "consistency": False}

    def fail(reason: str) -> dict:
        return {"valid": False, "checks": checks, "reason": reason}

    if not isinstance(bundle, dict):
        return fail("bundle_missing")
    if not isinstance(bundle.get("nonce"), str) or len(bundle.get("nonce")) == 0:
        return fail("nonce_missing")

    key_hex = _smt_nonce_key_hex(bundle["nonce"])

    ni = bundle.get("non_inclusion_proof")
    if not isinstance(ni, dict):
        return fail("non_inclusion_proof_missing")
    if ni.get("present") is not False:
        return fail("non_inclusion_proof_must_assert_absent")
    ni_res = _smt_check_sub(ni, key_hex, "non_inclusion")
    if not ni_res["ok"]:
        return fail(ni_res["reason"])
    checks["non_inclusion"] = True

    inc = bundle.get("inclusion_proof")
    if not isinstance(inc, dict):
        return fail("inclusion_proof_missing")
    if inc.get("present") is not True:
        return fail("inclusion_proof_must_assert_present")
    inc_res = _smt_check_sub(inc, key_hex, "inclusion")
    if not inc_res["ok"]:
        return fail(inc_res["reason"])
    checks["inclusion"] = True

    if _smt_hex_of(ni.get("root")) == _smt_hex_of(inc.get("root")):
        return fail("smt_root_unchanged_no_transition")

    cps = bundle.get("checkpoints")
    if not isinstance(cps, dict) or not cps.get("h1") or not cps.get("h2"):
        return fail("checkpoints_missing")
    h1 = cps.get("h1")
    h2 = cps.get("h2")
    h1_size = h1.get("tree_size") if isinstance(h1, dict) else None
    h2_size = h2.get("tree_size") if isinstance(h2, dict) else None
    h1_root = _smt_hex_of(h1.get("root_hash")) if isinstance(h1, dict) else ""
    h2_root = _smt_hex_of(h2.get("root_hash")) if isinstance(h2, dict) else ""
    if not (isinstance(h1_size, int) and not isinstance(h1_size, bool)) or h1_size < 1 or not _smt_is_hex64(h1_root):
        return fail("checkpoint_h1_malformed")
    if not (isinstance(h2_size, int) and not isinstance(h2_size, bool)) or h2_size < 1 or not _smt_is_hex64(h2_root):
        return fail("checkpoint_h2_malformed")
    if not (h1_size < h2_size):
        return fail("checkpoint_h1_not_before_h2")
    if not isinstance(bundle.get("consistency_proof"), list):
        return fail("consistency_proof_missing")
    if not verify_checkpoint_consistency(h1_root, h1_size, h2_root, h2_size, bundle.get("consistency_proof")):
        return fail("consistency_proof_not_append_only")
    checks["consistency"] = True

    return {"valid": True, "checks": checks, "reason": None}


# --- Reference sparse consumption tree (test/tooling ONLY) -------------------
# Mirrors consumption-proof.js ReferenceConsumptionTree. NOT a production ledger.

def _smt_build_empty_levels(depth: int) -> list:
    empty = [None] * (depth + 1)
    empty[depth] = _smt_default_leaf()
    for level in range(depth - 1, -1, -1):
        empty[level] = _smt_hash_branch(empty[level + 1], empty[level + 1])
    return empty


class ReferenceConsumptionTree:
    """Reference sparse Merkle tree over SMT_DEPTH bits (keys = hex SHA-256(nonce);
    only PRESENT leaves stored). EXPERIMENTAL — tests/tooling only."""

    def __init__(self, depth: int = SMT_DEPTH):
        self.depth = depth
        self.empty = _smt_build_empty_levels(depth)
        self.present: dict = {}

    def insert(self, nonce: Any, value: Any = None) -> dict:
        key_hex = _smt_nonce_key_hex(nonce)
        vh = _smt_hex_of(value)
        if vh and _smt_is_hex64(vh):
            value_hex = vh
        else:
            src = value if value is not None else nonce
            value_hex = hashlib.sha256(str(src).encode("utf-8")).hexdigest()
        self.present[key_hex] = value_hex
        return {"keyHex": key_hex, "valueHex": value_hex}

    def _bits_of(self, key_hex: str, n: int) -> str:
        return "".join(str(_smt_path_bit(key_hex, i)) for i in range(n))

    def _root_rec(self, level: int, prefix_bits: str) -> str:
        if level == self.depth:
            for key_hex, value_hex in self.present.items():
                if self._bits_of(key_hex, self.depth) == prefix_bits:
                    return _smt_present_leaf(key_hex, value_hex)
            return self.empty[self.depth]
        any_present = False
        for key_hex in self.present:
            if self._bits_of(key_hex, level).startswith(prefix_bits) or prefix_bits == "":
                any_present = True
                break
        if not any_present:
            return self.empty[level]
        left = self._root_rec(level + 1, prefix_bits + "0")
        right = self._root_rec(level + 1, prefix_bits + "1")
        return _smt_hash_branch(left, right)

    def root(self) -> str:
        return self._root_rec(0, "")

    def prove(self, nonce: Any) -> dict:
        key_hex = _smt_nonce_key_hex(nonce)
        siblings = [None] * self.depth
        for level in range(self.depth):
            bit = _smt_path_bit(key_hex, level)
            prefix = self._bits_of(key_hex, level)
            sibling_prefix = prefix + ("1" if bit == 0 else "0")
            siblings[level] = self._root_rec(level + 1, sibling_prefix)
        value_hex = self.present.get(key_hex)
        if value_hex is None:
            return {"root": self.root(), "siblings": siblings, "present": False}
        return {"root": self.root(), "siblings": siblings, "present": True, "value": value_hex}


# =============================================================================
# EP-INITIATOR-ATTESTATION-v1 — WHICH software asked (initiator-attestation.js)
# =============================================================================
# Field validation + HOSTILE free-text neutralization (strip/escape bidi + C0/C1
# controls + zero-width/BOM; FLAG homoglyph risk). Byte-identical to
# initiator-attestation.js. FAIL-CLOSED: any missing required field, wrong type,
# unknown member, or malformed digest rejects; a malformed attestation is never
# repaired into a passing one; a non-string statement is the empty statement.

INITIATOR_ATTESTATION_VERSION = "EP-INITIATOR-ATTESTATION-v1"
INITIATOR_ATTESTATION_FIELD = "initiator_software"
INITIATOR_STATEMENT_MAX = 280

_ATTESTATION_MEMBERS = ("@version", "model_id", "model_version", "tool_chain_digest", "statement")
_ATTESTATION_MEMBER_SET = set(_ATTESTATION_MEMBERS)
_REQUIRED_STRING_MEMBERS = ("model_id", "model_version")

_INITIATOR_HEX64 = _re.compile(r"^[0-9a-f]{64}$")

# Bidi controls (UBA formatting + isolates + marks): LRE RLE PDF LRO RLO (202A-E),
# LRI RLI FSI PDI (2066-9), LRM RLM ALM (200E, 200F, 061C).
_BIDI_CODEPOINTS = frozenset({
    0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
    0x2066, 0x2067, 0x2068, 0x2069,
    0x200e, 0x200f, 0x061c,
})
# Zero-width / joiners / BOM: ZWSP ZWNJ ZWJ (200B-D), WORD JOINER (2060), BOM (FEFF).
_INVISIBLE_CODEPOINTS = frozenset({0x200b, 0x200c, 0x200d, 0x2060, 0xfeff})


def normalize_digest(h: Any) -> str:
    """Normalize a claimed SHA-256 to bare lowercase hex, or '' when malformed.
    Accepts an OPTIONAL "sha256:" prefix. Mirrors initiator-attestation.js
    normalizeDigest (fail-closed: a bad digest never compares-equal to a real one)."""
    s = _re.sub(r"^sha256:", "", str("" if h is None else h), flags=_re.IGNORECASE).lower()
    return s if _INITIATOR_HEX64.match(s) else ""


def neutralize_statement(statement: Any) -> dict:
    """Render a HOSTILE free-text statement into a form safe to place in front of a
    human. Mirrors initiator-attestation.js neutralizeStatement. Non-string ->
    empty. Dangerous codepoints are ESCAPED (visible ``<U+XXXX>``), not dropped;
    a homoglyph / mixed-script risk is FLAGGED. Caps by codepoints BEFORE escaping."""
    import unicodedata as _ud

    raw = statement if isinstance(statement, str) else ""

    cps = list(raw)  # Python iterates str by code point already
    truncated = len(cps) > INITIATOR_STATEMENT_MAX
    bounded = cps[:INITIATOR_STATEMENT_MAX] if truncated else cps

    escaped: list = []
    changed = False
    has_non_ascii_letter = False
    has_ascii_letter = False
    has_confusable_script = False

    out_chars: list = []
    for ch in bounded:
        cp = ord(ch)

        if ("A" <= ch <= "Z") or ("a" <= ch <= "z"):
            has_ascii_letter = True
        if cp > 0x7f and _ud.category(ch).startswith("L"):
            has_non_ascii_letter = True
        # Cyrillic U+0400-04FF or Greek U+0370-03FF (matches CYRILLIC_RE/GREEK_RE).
        if (0x0400 <= cp <= 0x04ff) or (0x0370 <= cp <= 0x03ff):
            has_confusable_script = True

        is_bidi = cp in _BIDI_CODEPOINTS
        is_invisible = cp in _INVISIBLE_CODEPOINTS
        # C0 controls 0x00-0x1F and C1 controls 0x80-0x9F, minus tab/newline/cr.
        is_control = ((cp <= 0x1f and cp not in (0x09, 0x0a, 0x0d)) or (0x7f <= cp <= 0x9f))

        if is_bidi or is_invisible or is_control:
            changed = True
            escaped.append(cp)
            out_chars.append("<U+" + format(cp, "X").rjust(4, "0") + ">")
        else:
            out_chars.append(ch)

    homoglyph_risk = has_confusable_script or (has_non_ascii_letter and has_ascii_letter)

    return {
        "safe": "".join(out_chars),
        "changed": changed,
        "homoglyph_risk": homoglyph_risk,
        "escaped_codepoints": escaped,
        "truncated": truncated,
    }


def validate_initiator_attestation(att: Any) -> dict:
    """FAIL-CLOSED structural validation. Mirrors initiator-attestation.js
    validateInitiatorAttestation. Enforces object shape, the closed member set
    (unknown member => reject), required non-empty model_id/model_version, correct
    @version when present, well-formed tool_chain_digest, and a string statement
    within the cap. The ``normalized`` form carries a "sha256:"-prefixed digest and
    the NEUTRALIZED statement. On any error: ok False, normalized None."""
    errors: list = []

    def fail() -> dict:
        return {"ok": False, "normalized": None, "errors": errors, "statement_report": None}

    if not isinstance(att, dict):
        errors.append("initiator attestation must be a non-array object")
        return fail()

    for key in att.keys():
        if key not in _ATTESTATION_MEMBER_SET:
            errors.append(f'unknown member "{key}" (allowed: {", ".join(_ATTESTATION_MEMBERS)})')

    if att.get("@version") is not None and att.get("@version") != INITIATOR_ATTESTATION_VERSION:
        errors.append(f"@version must be {INITIATOR_ATTESTATION_VERSION} when present")

    for key in _REQUIRED_STRING_MEMBERS:
        v = att.get(key)
        if not isinstance(v, str) or len(v) == 0:
            errors.append(f"{key} is required and must be a non-empty string")

    digest_hex = normalize_digest(att.get("tool_chain_digest"))
    if att.get("tool_chain_digest") is None:
        errors.append("tool_chain_digest is required")
    elif digest_hex == "":
        errors.append('tool_chain_digest must be a well-formed SHA-256 (optionally "sha256:"-prefixed 64-hex)')

    statement_report = None
    if "statement" in att and att.get("statement") is not None:
        stmt = att.get("statement")
        if not isinstance(stmt, str):
            errors.append("statement, when present, must be a string")
        elif len(list(stmt)) > INITIATOR_STATEMENT_MAX:
            errors.append(f"statement exceeds the {INITIATOR_STATEMENT_MAX}-character cap")

    if errors:
        return fail()

    if "statement" in att and att.get("statement") is not None:
        statement_report = neutralize_statement(att.get("statement"))

    normalized = {
        "@version": INITIATOR_ATTESTATION_VERSION,
        "model_id": att.get("model_id"),
        "model_version": att.get("model_version"),
        "tool_chain_digest": f"sha256:{digest_hex}",
    }
    if statement_report:
        normalized["statement"] = statement_report["safe"]

    return {"ok": True, "normalized": normalized, "errors": errors, "statement_report": statement_report}


def bind_into(action: Any, att: Any) -> dict:
    """Bind a validated initiator attestation into the ACTION digest domain so
    model_id/model_version/tool_chain_digest are covered by the human's signature.
    Mirrors initiator-attestation.js bindInto. Does NOT change the frozen action
    hash: returns a NEW action with the normalized attestation under the reserved
    member and a digest_preview computed the SAME way ("sha256:"+sha256(canonicalize)).
    FAIL CLOSED: raises on a non-object action, an invalid attestation, or an
    action already carrying a DIFFERENT value under the reserved member."""
    if not isinstance(action, dict):
        raise TypeError("bindInto requires the canonical Action Object")
    v = validate_initiator_attestation(att)
    if not v["ok"]:
        raise ValueError(f"bindInto: invalid initiator attestation: {'; '.join(v['errors'])}")
    existing = action.get(INITIATOR_ATTESTATION_FIELD)
    if existing is not None and canonicalize(existing) != canonicalize(v["normalized"]):
        raise ValueError(
            f"bindInto: action already carries a different {INITIATOR_ATTESTATION_FIELD}; refusing to overwrite"
        )
    bound = dict(action)
    bound[INITIATOR_ATTESTATION_FIELD] = v["normalized"]
    digest_preview = f"sha256:{_sha256_hex(canonicalize(bound))}"
    return {"action": bound, "attestation": v["normalized"], "digest_preview": digest_preview}


# =============================================================================
# EP timestamp-proof (RFC 3161) — Python port of packages/verify/timestamp-proof.js
# =============================================================================
#
# An INDEPENDENT proof of WHEN: verify a standards-track RFC 3161 TimeStampToken
# (a CMS/PKCS#7 SignedData carrying a TSTInfo) minted by an EXTERNAL TSA, against
# a PINNED TSA public key. Same contract as the JS reference: ASYMMETRIC,
# key-PINNED, FAIL-CLOSED. An unpinned/unknown TSA REFUSES; a messageImprint that
# is not the caller's expected digest REFUSES; a signature that does not verify
# under the pinned key REFUSES; an unparseable token REFUSES. Nothing defaults to
# "trusted".
#
# PARSING BOUNDARY (honest, identical to the JS reference): this is a
# PURPOSE-BUILT minimal DER/CMS reader. `cryptography` (this package's only
# dependency) exposes no RFC 3161 TimeStampToken / TSTInfo / generic CMS
# SignedData API that returns the signed bytes for the id-ct-TSTInfo eContent, so
# the structural parse is hand-rolled here in pure Python (no new dependency) and
# `cryptography` is used only for the RSA/ECDSA signature verification. Supports
# a single SignerInfo, RSA (RSASSA-PKCS1-v1_5) or ECDSA over a SHA-2 digest, with
# OR without CMS signed attributes. Does NOT implement X.509 path building
# (caller PINS the exact key), RSASSA-PSS, or multi-signer tokens; anything
# outside the supported shape REFUSES with a distinct reason.
#
# WHAT THIS PROVES (and only this): a TSA the caller chose to pin asserted, with
# its signature, that `expected_digest` existed at gen_time (the bytes PREDATE
# gen_time). It does NOT prove the action was correct/authorized, does not prove
# the TSA clock was accurate, and — like every offline check here — says nothing
# about CURRENT validity or revocation of the TSA certificate.

from cryptography.hazmat.primitives.asymmetric import padding as _rsa_padding  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import utils as _asym_utils  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey as _RSAPublicKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ec import (  # noqa: E402
    EllipticCurvePublicKey as _ECPublicKey,
    ECDSA as _ECDSA,
)

TIMESTAMP_PROOF_ALG = "RFC3161"

# ── OIDs we recognize (dotted string form) ───────────────────────────────────
_TSP_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"        # pkcs7-signedData
_TSP_OID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"    # id-ct-TSTInfo (eContentType)
_TSP_OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"       # id-contentType signed attr
_TSP_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"     # id-messageDigest signed attr
_TSP_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_TSP_OID_SHA384 = "2.16.840.1.101.3.4.2.2"
_TSP_OID_SHA512 = "2.16.840.1.101.3.4.2.3"
_TSP_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"     # rsaEncryption (PKCS1 v1.5)
_TSP_OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
_TSP_OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
_TSP_OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4"

# SHA-2 only, deliberately (a TSA still issuing SHA-1 tokens is itself a refuse
# signal): a SHA-1 digest OID refuses with unsupported_digest_algorithm.
_TSP_DIGEST_OID_TO_NAME = {
    _TSP_OID_SHA256: "sha256",
    _TSP_OID_SHA384: "sha384",
    _TSP_OID_SHA512: "sha512",
}
_TSP_HASHLIB = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
_TSP_HASH_CLS = {"sha256": _hashes.SHA256, "sha384": _hashes.SHA384, "sha512": _hashes.SHA512}


class _TspDerError(Exception):
    """Any structural malformation — caught at the top level as a fail-closed
    unparseable_token refusal (mirrors DerError in the JS reference)."""


class _TspNode:
    __slots__ = ("cls", "constructed", "tag", "header_len", "content_start", "content_end", "buf")

    def __init__(self, cls, constructed, tag, header_len, content_start, content_end, buf):
        self.cls = cls
        self.constructed = constructed
        self.tag = tag
        self.header_len = header_len
        self.content_start = content_start
        self.content_end = content_end
        self.buf = buf

    def content(self) -> bytes:
        return self.buf[self.content_start:self.content_end]

    def raw(self) -> bytes:
        # header + content bytes (used to re-hash eContent / re-encode signedAttrs)
        return self.buf[self.content_start - self.header_len:self.content_end]


def _tsp_read_tlv(buf: bytes, offset: int) -> _TspNode:
    """Minimal DER TLV reader; every bound validated so a truncated/over-long
    field raises _TspDerError (mirrors readTLV in the JS reference)."""
    if offset + 2 > len(buf):
        raise _TspDerError("truncated TLV header")
    first = buf[offset]
    cls = (first & 0xC0) >> 6
    constructed = (first & 0x20) != 0
    tag = first & 0x1F
    p = offset + 1
    if tag == 0x1F:
        # high-tag-number form: parse but EP tokens do not use it.
        tag = 0
        while True:
            if p >= len(buf):
                raise _TspDerError("truncated high tag")
            b = buf[p]
            p += 1
            tag = (tag << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    if p >= len(buf):
        raise _TspDerError("truncated length")
    length = buf[p]
    p += 1
    if length & 0x80:
        num_bytes = length & 0x7F
        if num_bytes == 0:
            raise _TspDerError("indefinite length not allowed in DER")
        if num_bytes > 4:
            raise _TspDerError("length too large")
        if p + num_bytes > len(buf):
            raise _TspDerError("truncated long length")
        length = 0
        for _ in range(num_bytes):
            length = (length << 8) | buf[p]
            p += 1
    content_start = p
    content_end = p + length
    if content_end > len(buf):
        raise _TspDerError("content exceeds buffer")
    return _TspNode(cls, constructed, tag, content_start - offset, content_start, content_end, buf)


def _tsp_children(node: _TspNode):
    p = node.content_start
    while p < node.content_end:
        child = _tsp_read_tlv(node.buf, p)
        yield child
        p = child.content_end


def _tsp_decode_oid(node: _TspNode) -> str:
    if node.tag != 0x06 or node.cls != 0:
        raise _TspDerError("expected OID")
    b = node.content()
    if len(b) == 0:
        raise _TspDerError("empty OID")
    first = b[0]
    parts = [first // 40, first % 40]
    value = 0
    for i in range(1, len(b)):
        value = (value << 7) | (b[i] & 0x7F)
        if not (b[i] & 0x80):
            parts.append(value)
            value = 0
    return ".".join(str(x) for x in parts)


def _tsp_decode_generalized_time(node: _TspNode):
    """GeneralizedTime (0x18) / UTCTime (0x17) -> RFC 3339 UTC iso string, or None
    (fail-closed) on any non-conforming form. Mirrors decodeGeneralizedTime."""
    import re as _re
    s = node.content().decode("latin-1")
    if node.tag == 0x18:
        m = _re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$", s)
        if m:
            frac = m.group(7) or ""
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}:{m.group(5)}:{m.group(6)}{frac}Z"
    if node.tag == 0x17:
        m = _re.match(r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$", s)
        if m:
            yy = int(m.group(1))
            year = 2000 + yy if yy < 50 else 1900 + yy
            return f"{year}-{m.group(2)}-{m.group(3)}T{m.group(4)}:{m.group(5)}:{m.group(6)}Z"
    return None


def _tsp_hex_of(h: Any) -> str:
    """Normalize a digest input ("sha256:<hex>" | "<hex>" | bytes) to lowercase
    hex, or "" when malformed (comparisons fail closed). Mirrors hexOf."""
    if isinstance(h, (bytes, bytearray)):
        return bytes(h).hex().lower()
    s = "" if h is None else str(h)
    for pfx in ("sha256:", "sha384:", "sha512:"):
        if s.lower().startswith(pfx):
            s = s[len(pfx):]
            break
    s = s.lower()
    import re as _re
    if _re.fullmatch(r"[0-9a-f]+", s) and len(s) % 2 == 0 and len(s) >= 40:
        return s
    return ""


def _tsp_key_id_of_spki(spki_der: bytes) -> str:
    return "sha256:" + hashlib.sha256(spki_der).hexdigest()


def _tsp_load_pinned_key(pinned: Any):
    """Load one pinned TSA key. Accepts base64/base64url SPKI DER or a PEM string.
    Returns (public_key, spki_der) or None (fail-closed). Mirrors loadPinnedKey."""
    try:
        if not pinned:
            return None
        if isinstance(pinned, str) and "-----BEGIN" in pinned:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_public_key as _load_pem,
                Encoding as _Enc,
                PublicFormat as _PF,
            )
            key = _load_pem(pinned.encode("utf-8"))
            return (key, key.public_bytes(_Enc.DER, _PF.SubjectPublicKeyInfo))
        # base64 / base64url SPKI DER
        raw = "".join(str(pinned).split())
        try:
            der = base64.b64decode(raw, validate=True)
        except Exception:
            der = _b64url_decode(raw)
        if len(der) == 0:
            return None
        key = load_der_public_key(der)
        from cryptography.hazmat.primitives.serialization import Encoding as _Enc, PublicFormat as _PF
        return (key, key.public_bytes(_Enc.DER, _PF.SubjectPublicKeyInfo))
    except Exception:
        return None


def _tsp_der_set_header(length: int) -> bytes:
    if length < 0x80:
        return bytes([0x31, length])
    body = []
    n = length
    while n > 0:
        body.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x31, 0x80 | len(body)] + body)


def _tsp_parse_attributes(set_node: _TspNode) -> dict:
    """SET OF Attribute -> { oid: [value_nodes...] }. Mirrors parseAttributes."""
    out: dict = {}
    for attr in _tsp_children(set_node):
        if attr.tag != 0x10:
            continue
        kids = list(_tsp_children(attr))
        if len(kids) < 2:
            continue
        oid = _tsp_decode_oid(kids[0])
        out[oid] = list(_tsp_children(kids[1]))
    return out


def _tsp_parse_tstinfo(der: bytes):
    """Mirrors parseTstInfo. Returns dict with messageImprintHex / genTime or
    {'error': ...}."""
    try:
        seq = _tsp_read_tlv(der, 0)
        if seq.tag != 0x10:
            return {"error": "unparseable_token"}
        kids = list(_tsp_children(seq))
        if len(kids) < 5:
            return {"error": "unparseable_token"}
        mi = kids[2]
        if mi.tag != 0x10:
            return {"error": "unparseable_token"}
        mi_kids = list(_tsp_children(mi))
        if len(mi_kids) < 2:
            return {"error": "unparseable_token"}
        hash_alg_seq = mi_kids[0]
        hash_alg_oid = _tsp_decode_oid(list(_tsp_children(hash_alg_seq))[0])
        hashed_message = mi_kids[1]
        if hashed_message.tag != 0x04:
            return {"error": "unparseable_token"}
        message_imprint_hex = hashed_message.content().hex().lower()
        gen_time = None
        for i in range(3, len(kids)):
            if kids[i].tag in (0x18, 0x17):
                t = _tsp_decode_generalized_time(kids[i])
                if t:
                    gen_time = t
                break
        return {"messageImprintHex": message_imprint_hex, "imprintAlgOid": hash_alg_oid, "genTime": gen_time}
    except _TspDerError:
        return {"error": "unparseable_token"}


def _tsp_parse_signer_info(node: _TspNode):
    """Mirrors parseSignerInfo."""
    try:
        if node.tag != 0x10:
            return {"error": "unparseable_token"}
        kids = list(_tsp_children(node))
        idx = 0
        if idx >= len(kids) or kids[idx].tag != 0x02:
            return {"error": "unparseable_token"}
        idx += 1  # version
        if idx >= len(kids):
            return {"error": "unparseable_token"}
        idx += 1  # sid (IssuerAndSerialNumber SEQ or [0] SubjectKeyIdentifier)
        if idx >= len(kids) or kids[idx].tag != 0x10:
            return {"error": "unparseable_token"}
        digest_alg = kids[idx]
        idx += 1
        digest_alg_oid = _tsp_decode_oid(list(_tsp_children(digest_alg))[0])
        signed_attrs = None
        if idx < len(kids) and kids[idx].cls == 2 and kids[idx].tag == 0 and kids[idx].constructed:
            signed_attrs = kids[idx]
            idx += 1
        if idx >= len(kids) or kids[idx].tag != 0x10:
            return {"error": "unparseable_token"}
        sig_alg = kids[idx]
        idx += 1
        sig_alg_oid = _tsp_decode_oid(list(_tsp_children(sig_alg))[0])
        if idx >= len(kids) or kids[idx].tag != 0x04:
            return {"error": "unparseable_token"}
        signature = kids[idx].content()
        return {
            "digestAlgOid": digest_alg_oid,
            "digestName": _TSP_DIGEST_OID_TO_NAME.get(digest_alg_oid),
            "signedAttrs": signed_attrs,
            "sigAlgOid": sig_alg_oid,
            "signature": signature,
        }
    except _TspDerError:
        return {"error": "unparseable_token"}


def _tsp_parse_token(der: bytes):
    """Mirrors parseTimeStampToken. Returns dict {tstInfo, signerInfo,
    eContentRaw} or {'error': ...}."""
    content_info = _tsp_read_tlv(der, 0)
    if content_info.tag != 0x10 or not content_info.constructed:
        return {"error": "unparseable_token"}
    ci_kids = list(_tsp_children(content_info))
    if len(ci_kids) < 2:
        return {"error": "unparseable_token"}
    if _tsp_decode_oid(ci_kids[0]) != _TSP_OID_SIGNED_DATA:
        return {"error": "not_signed_data"}
    explicit0 = ci_kids[1]
    if explicit0.cls != 2 or explicit0.tag != 0 or not explicit0.constructed:
        return {"error": "unparseable_token"}
    sd_list = list(_tsp_children(explicit0))
    signed_data = sd_list[0] if sd_list else None
    if not signed_data or signed_data.tag != 0x10:
        return {"error": "unparseable_token"}
    sd_kids = list(_tsp_children(signed_data))
    if len(sd_kids) < 4:
        return {"error": "unparseable_token"}
    encap = sd_kids[2]
    signer_infos = None
    for i in range(len(sd_kids) - 1, 2, -1):
        if sd_kids[i].tag == 0x11 and sd_kids[i].cls == 0:
            signer_infos = sd_kids[i]
            break
    if not encap or encap.tag != 0x10:
        return {"error": "unparseable_token"}
    if not signer_infos:
        return {"error": "unparseable_token"}
    encap_kids = list(_tsp_children(encap))
    if len(encap_kids) < 2:
        return {"error": "unparseable_token"}
    if _tsp_decode_oid(encap_kids[0]) != _TSP_OID_CT_TSTINFO:
        return {"error": "not_a_timestamp_token"}
    e_content_explicit = encap_kids[1]
    if e_content_explicit.cls != 2 or e_content_explicit.tag != 0:
        return {"error": "unparseable_token"}
    octet_list = list(_tsp_children(e_content_explicit))
    octet = octet_list[0] if octet_list else None
    if not octet or octet.tag != 0x04:
        return {"error": "unparseable_token"}
    e_content_raw = octet.content()
    tst_info = _tsp_parse_tstinfo(e_content_raw)
    if tst_info.get("error"):
        return {"error": tst_info["error"]}
    si_list = list(_tsp_children(signer_infos))
    if len(si_list) != 1:
        return {"error": "unsupported_signerinfo_count"}
    signer_info = _tsp_parse_signer_info(si_list[0])
    if signer_info.get("error"):
        return {"error": signer_info["error"]}
    return {"tstInfo": tst_info, "signerInfo": signer_info, "eContentRaw": e_content_raw}


def _tsp_verify_one(pub_key, sig_alg_oid: str, digest_name: str, signed_bytes: bytes, signature: bytes) -> bool:
    """Verify signature under one pinned key. Enforces the same
    signatureAlgorithm/key-type consistency guard as the JS reference."""
    try:
        is_rsa = isinstance(pub_key, _RSAPublicKey)
        is_ec = isinstance(pub_key, _ECPublicKey)
        if sig_alg_oid == _TSP_OID_RSA_ENCRYPTION or is_rsa:
            if not is_rsa:
                return False
            halg = _TSP_HASH_CLS.get(digest_name)
            if halg is None:
                return False
            pub_key.verify(signature, signed_bytes, _rsa_padding.PKCS1v15(), halg())
            return True
        ec_oids = (_TSP_OID_ECDSA_SHA256, _TSP_OID_ECDSA_SHA384, _TSP_OID_ECDSA_SHA512)
        if sig_alg_oid in ec_oids:
            if not is_ec:
                return False
            ec_hash = {
                _TSP_OID_ECDSA_SHA256: "sha256",
                _TSP_OID_ECDSA_SHA384: "sha384",
                _TSP_OID_ECDSA_SHA512: "sha512",
            }[sig_alg_oid]
            pub_key.verify(signature, signed_bytes, _ECDSA(_TSP_HASH_CLS[ec_hash]()))
            return True
        return False
    except InvalidSignature:
        return False
    except Exception:
        return False


def _tsp_verify_signer_info(signer_info: dict, e_content_raw: bytes, loaded_keys: list):
    """Mirrors verifySignerInfo. Returns {'ok': True, 'tsaKeyId': ...} or
    {'ok': False, 'reason': ...}."""
    digest_name = signer_info["digestName"]
    signed_attrs = signer_info["signedAttrs"]
    sig_alg_oid = signer_info["sigAlgOid"]
    signature = signer_info["signature"]
    if not digest_name:
        return {"ok": False, "reason": "unsupported_digest_algorithm"}

    if signed_attrs is not None:
        attrs = _tsp_parse_attributes(signed_attrs)
        ct_nodes = attrs.get(_TSP_OID_CONTENT_TYPE)
        if not ct_nodes or len(ct_nodes) != 1:
            return {"ok": False, "reason": "missing_content_type_attr"}
        try:
            ct_oid = _tsp_decode_oid(ct_nodes[0])
        except _TspDerError:
            return {"ok": False, "reason": "unparseable_token"}
        if ct_oid != _TSP_OID_CT_TSTINFO:
            return {"ok": False, "reason": "content_type_attr_mismatch"}
        md_nodes = attrs.get(_TSP_OID_MESSAGE_DIGEST)
        if not md_nodes or len(md_nodes) != 1 or md_nodes[0].tag != 0x04:
            return {"ok": False, "reason": "missing_message_digest_attr"}
        attr_digest = md_nodes[0].content()
        e_content_digest = _TSP_HASHLIB[digest_name](e_content_raw).digest()
        if attr_digest != e_content_digest:
            return {"ok": False, "reason": "message_digest_attr_mismatch"}
        # Signature input: DER re-encoding of the attributes as an explicit SET
        # (0x31), NOT the [0] IMPLICIT tag (RFC 5652 §5.4).
        attrs_body = signed_attrs.raw()[signed_attrs.header_len:]
        signed_bytes = _tsp_der_set_header(len(attrs_body)) + attrs_body
    else:
        signed_bytes = e_content_raw

    for pub_key, spki_der in loaded_keys:
        if _tsp_verify_one(pub_key, sig_alg_oid, digest_name, signed_bytes, signature):
            return {"ok": True, "tsaKeyId": _tsp_key_id_of_spki(spki_der)}
    return {"ok": False, "reason": "bad_signature"}


def verify_timestamp_proof(timestamp_proof: Any, expected_digest: Any, pinned_tsa_keys: Any) -> dict:
    """Parse + verify an RFC 3161 TimeStampToken against a PINNED TSA key.

    Byte-for-byte behavioral parity with verifyTimestampProof in
    packages/verify/timestamp-proof.js. FAIL-CLOSED: returns
    {'verified': False, 'tsa_key_id': None, 'gen_time': None, 'reason': <str>} on
    any refusal, and {'verified': True, 'tsa_key_id': <fp>, 'gen_time': <iso>} on
    success. Never raises.

    :param timestamp_proof: DER TimeStampToken as base64/base64url str or bytes.
    :param expected_digest: the digest the token MUST timestamp ("sha256:<hex>",
        bare hex, or raw digest bytes).
    :param pinned_tsa_keys: the caller-supplied trust set — a single SPKI-DER key
        (base64/base64url) or PEM, a list of such, or a dict {id: key}. The token
        REFUSES unless its signature verifies under one of these pinned keys.
    """
    def refuse(reason):
        return {"verified": False, "tsa_key_id": None, "gen_time": None, "reason": reason}

    # Input gates (fail-closed on anything missing/blank).
    if timestamp_proof is None or not isinstance(timestamp_proof, (str, bytes, bytearray)) \
            or (isinstance(timestamp_proof, str) and timestamp_proof.strip() == ""):
        return refuse("missing_token")
    want_digest = _tsp_hex_of(expected_digest)
    if not want_digest:
        return refuse("missing_or_malformed_expected_digest")

    # Assemble the pinned key set. An empty/absent set is an UNPINNED TSA.
    pinned_list = []
    if isinstance(pinned_tsa_keys, (list, tuple)):
        pinned_list.extend(pinned_tsa_keys)
    elif isinstance(pinned_tsa_keys, dict):
        pinned_list.extend(pinned_tsa_keys.values())
    elif pinned_tsa_keys:
        pinned_list.append(pinned_tsa_keys)
    loaded_keys = [k for k in (_tsp_load_pinned_key(p) for p in pinned_list) if k]
    if len(loaded_keys) == 0:
        return refuse("unpinned_tsa")

    # Decode DER.
    try:
        if isinstance(timestamp_proof, (bytes, bytearray)):
            der = bytes(timestamp_proof)
        else:
            raw = "".join(timestamp_proof.split())
            try:
                der = base64.b64decode(raw, validate=True)
            except Exception:
                der = _b64url_decode(raw)
        if len(der) == 0:
            return refuse("unparseable_token")
    except Exception:
        return refuse("unparseable_token")

    try:
        parsed = _tsp_parse_token(der)
    except _TspDerError:
        return refuse("unparseable_token")
    except Exception:
        return refuse("unparseable_token")
    if parsed.get("error"):
        return refuse(parsed["error"])

    tst_info = parsed["tstInfo"]
    signer_info = parsed["signerInfo"]
    e_content_raw = parsed["eContentRaw"]

    # messageImprint must equal the caller's expected digest (bound BEFORE the
    # signature verdict is trusted).
    if tst_info["messageImprintHex"] != want_digest:
        return refuse("digest_mismatch")

    if not tst_info["genTime"]:
        return refuse("unparseable_token")

    sig_result = _tsp_verify_signer_info(signer_info, e_content_raw, loaded_keys)
    if not sig_result["ok"]:
        return refuse(sig_result["reason"])

    return {"verified": True, "tsa_key_id": sig_result["tsaKeyId"], "gen_time": tst_info["genTime"]}


__all__.append("verify_timestamp_proof")
__all__.append("TIMESTAMP_PROOF_ALG")

# EP-AUTHORITY-DOC-PROOF-JOIN-v1 lives in a focused module so the trust join,
# document-chain state machine, and proof-signature split remain reviewable.
from .authority_join import (  # noqa: E402
    AUTHORITY_DOCUMENT_VERSION,
    AUTHORITY_PROOF_DOMAIN,
    AUTHORITY_PROOF_VERSION,
    authority_document_core_digest,
    authority_issuer_key_id,
    verify_authority_proof_via_document,
)

__all__.extend([
    "AUTHORITY_DOCUMENT_VERSION",
    "AUTHORITY_PROOF_DOMAIN",
    "AUTHORITY_PROOF_VERSION",
    "authority_document_core_digest",
    "authority_issuer_key_id",
    "verify_authority_proof_via_document",
])

# EP-OUTCOME-ATTESTATION-v1 + EP-OUTCOME-BINDING-v1. Imported last so the
# dedicated module can reuse this package's canonicalizer and Trust Receipt
# verifier without creating an initialization cycle.
from .outcome_binding import (  # noqa: E402,F401
    MAX_EFFECT_STRING_LENGTH,
    MAX_OBSERVED_EFFECTS,
    MAX_PREDICTED_EFFECTS,
    OUTCOME_ATTESTATION_DOMAIN,
    OUTCOME_ATTESTATION_VERSION,
    OUTCOME_BINDING_OUTCOMES,
    OUTCOME_BINDING_VERSION,
    PREDICATE_OPS,
    compare_decimal_strings,
    evaluate_predicted_effects,
    is_decimal_string,
    observed_effects_digest,
    predicted_effects_digest,
    trust_receipt_digest,
    validate_predicted_effects,
    verify_outcome_attestation,
    verify_outcome_binding,
    verify_outcome_binding_core,
)
from .outcome_binding import __all__ as _outcome_binding_exports  # noqa: E402

__all__.extend(_outcome_binding_exports)
