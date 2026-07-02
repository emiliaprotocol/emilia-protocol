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

__all__ = ["canonicalize", "is_canonicalizable", "verify_receipt", "verify_merkle_anchor", "VerifyResult", "evaluate_agent_binding"]

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
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


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
        client = json.loads(client_bytes.decode("utf-8"))
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


def verify_quorum(quorum: Any, opts: Optional[dict] = None) -> dict:
    """Verify an EP-QUORUM-v1 multi-party approval. Mirrors JS quorum.js;
    fail-closed; composes verify_webauthn_signoff per member."""
    opts = opts or {}
    checks = {"all_signatures_valid": False, "action_binding": False, "distinct_humans": False,
              "distinct_keys": False, "roles_admitted": False, "threshold_met": False,
              "order_satisfied": False, "chain_linked": False, "within_window": False}
    members_out = []
    try:
        policy = quorum.get("policy") if isinstance(quorum, dict) else None
        members = quorum.get("members") if isinstance(quorum, dict) else None
        action_hash = quorum.get("action_hash") if isinstance(quorum, dict) else None
        if not policy or not isinstance(members, list) or not members or not isinstance(action_hash, str) or not action_hash:
            return {"valid": False, "checks": checks, "members": members_out}
        mode = "ordered" if policy.get("mode") == "ordered" else "threshold"
        distinct_humans = policy.get("distinct_humans") is not False
        window_sec = policy["window_sec"] if isinstance(policy.get("window_sec"), (int, float)) else 900
        eligible = policy.get("approvers") if isinstance(policy.get("approvers"), list) else []
        if mode == "ordered":
            required = len(eligible)
        else:
            required = policy.get("required") if isinstance(policy.get("required"), int) and policy.get("required") > 0 else None
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
        counted_keys = [m.get("approver_public_key") for _, m in counted]
        checks["distinct_keys"] = (len(set(counted_keys)) == len(counted_keys)) if distinct_humans else True
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
                 checks["distinct_keys"], checks["roles_admitted"], checks["threshold_met"],
                 checks["order_satisfied"], checks["chain_linked"], checks["within_window"]])
    return {"valid": valid, "checks": checks, "members": members_out}


# ── EP-REVOCATION-v1 + EP-TIME-ATTESTATION-v1 (mirror packages/verify) ────────

REVOCATION_VERSION = "EP-REVOCATION-v1"
TIME_ATTESTATION_VERSION = "EP-TIME-ATTESTATION-v1"
_TARGET_TYPES = ("receipt", "commit", "delegation")


def _hex_of(h: Any) -> str:
    return str(h if h is not None else "").replace("sha256:", "").lower()


# Canonical EP timestamp profile: RFC 3339 with an explicit UTC offset ("Z" or
# ±hh:mm). No-timezone ("2026-07-01T12:00:00") and date-only ("2026-07-01") forms
# are REJECTED — they are ambiguous (UTC vs local) and must never satisfy a
# validity window. Single profile, parsed and rejected identically by JS/Py/Go.
import re as _re
_RFC3339_OFFSET = _re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


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
    opts = opts or {}
    revoker_keys = opts.get("revokerKeys") or {}
    checks = {"version": True, "target_bound": True, "revoker_key_pinned": True,
              "revoked_at_present": True, "revoker_signature_valid": True,
              "signature_binds_statement": True, "freshness": True}
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

    if not isinstance(target, dict):
        fail("target_bound", "no target handed to the verifier (fail-closed)")
    else:
        if target.get("target_type") and target.get("target_type") not in _TARGET_TYPES:
            fail("target_bound", f"unknown target_type {target.get('target_type')}")
        if statement.get("target_type") != target.get("target_type"):
            fail("target_bound", "target_type mismatch")
        if statement.get("target_id") != target.get("target_id"):
            fail("target_bound", "target_id mismatch")
        elif _hex_of(statement.get("action_hash")) != _hex_of(target.get("action_hash")):
            fail("target_bound", "action_hash mismatch (revoke-A-presented-for-B)")

    proof = statement.get("proof") or None
    revoker_id = statement.get("revoker_id")
    pinned = (revoker_keys.get(revoker_id) or {}).get("public_key")
    presented = (proof or {}).get("public_key")
    if not pinned:
        fail("revoker_key_pinned", f"no pinned key for revoker {revoker_id}")
    elif presented and pinned != presented:
        fail("revoker_key_pinned", "presented revoker key != pinned key")

    revoked_ms = _instant_ms(statement.get("revoked_at"))
    if revoked_ms is None:
        fail("revoked_at_present", "revoked_at absent or malformed")

    recomputed = _revocation_signed_payload(statement)
    sig = (proof or {}).get("signature_b64u")
    sig_binds_pinned = bool(pinned) and _ed25519_verify(recomputed, pinned, sig)
    if not sig_binds_pinned:
        verify_key = pinned or presented
        sig_over_recomputed = bool(verify_key) and _ed25519_verify(recomputed, verify_key, sig)
        if not sig or not verify_key:
            fail("revoker_signature_valid", "revocation proof signature or key missing")
        elif not sig_over_recomputed:
            fail("signature_binds_statement", "revoker signature does not bind the presented statement bytes")
            fail("revoker_signature_valid", "revoker signature does not verify under the pinned key")

    max_age = opts.get("maxAgeSeconds")
    if isinstance(max_age, (int, float)) and revoked_ms is not None:
        now = opts.get("now")
        now_ms = (_instant_ms(now) if isinstance(now, str) else (now if isinstance(now, (int, float)) else None))
        if now_ms is None:
            import time as _t
            now_ms = _t.time() * 1000
        if (now_ms - revoked_ms) / 1000 > max_age:
            fail("freshness", "revoked_at older than the freshness window")

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
    coerceRequiredApprovals and the Go verifier). The threshold MUST be an
    integer-typed JSON number. A string ("2"), float, bool, or any non-integer is
    malformed and returns None (forcing the receipt to fail). Missing/None -> 1.
    NEVER raises (bool excluded because it subclasses int)."""
    if value is None:
        return 1
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
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


def _verify_class_a_over_digest(webauthn: dict, digest_bytes: bytes, pub_spki_b64u: str) -> bool:
    try:
        cd = _b64url_decode(webauthn["client_data_json"])
        client = json.loads(cd.decode("utf-8"))
        if client.get("type") != "webauthn.get":
            return False
        if client.get("challenge") != base64.urlsafe_b64encode(digest_bytes).decode().rstrip("="):
            return False
        ad = _b64url_decode(webauthn["authenticator_data"])
        if len(ad) < 37 or (ad[32] & _FLAG_UP) != _FLAG_UP or (ad[32] & _FLAG_UV) != _FLAG_UV:
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
        if not _within_window(ctx.get("issued_at"), key_entry.get("valid_from"), key_entry.get("valid_to")):
            signatures_ok = False
            continue
        digest_bytes = bytes.fromhex(_hex_of(s.get("context_hash")))
        key_class = s.get("key_class") or key_entry.get("key_class") or "B"
        if key_class == "A":
            sig_ok = bool(s.get("webauthn")) and _verify_class_a_over_digest(s["webauthn"], digest_bytes, key_entry["public_key"])
        else:
            sig_ok = _verify_ed25519_over_digest(s.get("signature"), digest_bytes, key_entry["public_key"])
        if not sig_ok:
            signatures_ok = False
            continue
        valid_approvals.append({"approver": ctx.get("approver"), "signed_at": s.get("signed_at"), "ctx": ctx})
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
        merkle_alg = lp.get("alg") or (lp.get("checkpoint") or {}).get("merkle_alg")
        if merkle_alg == MERKLE_V2_ALG:
            leaf_hash = _leaf_hash_v2(canonicalize(leaf_content))
            presented_leaf = _hex_of(lp.get("leaf_hash")) if lp.get("leaf_hash") else ""
            checks["inclusion"] = (presented_leaf == leaf_hash) and verify_merkle_anchor(
                leaf_hash, lp["inclusion_path"], _hex_of(lp["checkpoint"].get("root_hash")), v2=True)
        elif opts.get("allowLegacyMerkle") is True or opts.get("allow_legacy_merkle") is True or opts.get("allowLegacyTrustReceiptMerkle") is True:
            leaf_hash = _sha256_hex(canonicalize(leaf_content))
            checks["inclusion"] = verify_merkle_anchor(leaf_hash, lp["inclusion_path"], _hex_of(lp["checkpoint"].get("root_hash")))
        else:
            checks["inclusion"] = False
        if log_public_key and lp["checkpoint"].get("log_signature"):
            signed_cp = {k: v for k, v in lp["checkpoint"].items() if k != "log_signature"}
            checks["checkpoint_signature"] = _verify_ed25519_over_digest(
                str(lp["checkpoint"]["log_signature"]).replace("b64u:", ""),
                hashlib.sha256(canonicalize(signed_cp).encode("utf-8")).digest(),
                log_public_key)

    windows_ok = len(valid_approvals) > 0
    for a in valid_approvals:
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


def _scope_containment_violations(parent, child):
    viol = []
    for token in child.get("scope") or []:
        probe = token[:-2] if isinstance(token, str) and token.endswith(".*") else token
        if not _scope_permits(parent.get("scope"), probe):
            viol.append("scope exceeds parent")
    parent_cap = parent.get("max_value_usd")
    child_cap = child.get("max_value_usd")
    if child_cap is None:
        child_cap = parent_cap
    if parent_cap is not None:
        if child_cap is None or float(child_cap) > float(parent_cap):
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

    if not isinstance(doc, dict) or doc.get("@version") != PROVENANCE_VERSION:
        return {"valid": False, "checks": checks, "errors": [f"unsupported version: {doc.get('@version') if isinstance(doc, dict) else None}"],
                "links": [], "agent_identity": None, "liability": None}
    checks["version"] = True

    root = doc.get("root_signoff")
    if not root or not root.get("receipt") or not root.get("verification"):
        fail("root_receipt_valid", "missing root_signoff")
    else:
        r0 = verify_trust_receipt(root["receipt"], {"approverKeys": root["verification"].get("approver_keys"), "logPublicKey": root["verification"].get("log_public_key")})
        checks["root_receipt_valid"] = r0["valid"]
        checks["root_human_signoff"] = _has_human_signoff(root["receipt"], human_classes)

    exec_ = doc.get("execution") or {}
    reversibility_asserted = False  # opts.reversibilityAsserted is a predicate; absent in serialized vectors
    need_approval = require_always or not reversibility_asserted
    approval = doc.get("action_approval")
    if need_approval and not (approval or {}).get("receipt"):
        fail("per_action_required", "no action_approval present")
    if (approval or {}).get("receipt"):
        ra = verify_trust_receipt(approval["receipt"], {"approverKeys": (approval.get("verification") or {}).get("approver_keys"), "logPublicKey": (approval.get("verification") or {}).get("log_public_key")})
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
        checks["chain_anchored"] = head.get("parent_ref") in root_approvers or head.get("delegator") in root_approvers
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
            eff = min(float(link["max_value_usd"]), float(parent["max_value_usd"]))
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


def action_digest(action: Any) -> str:
    """Canonical action digest (hex) — sha256 of JCS(action). Mirrors JS actionDigest()."""
    return hashlib.sha256(canonicalize(action).encode("utf-8")).hexdigest()


def _norm_digest(d: Any) -> Optional[str]:
    if not isinstance(d, str):
        return None
    return d[7:].lower() if d.lower().startswith("sha256:") else d.lower()


def _builtin_aec_verifiers() -> dict:
    def ep_quorum(ev, ctx):
        r = verify_quorum(ev) or {}
        return {"valid": bool(r.get("valid")), "action_digest": (ev or {}).get("action_hash")}

    def ep_receipt(ev, ctx):
        key = (ctx.get("keys") or {}).get((ev or {}).get("operator_public_key")) or (ev or {}).get("operator_public_key")
        try:
            r = verify_receipt(ev, key)
            valid = bool(r.get("valid") if isinstance(r, dict) else getattr(r, "valid", False))
        except Exception:
            valid = False
        return {"valid": valid, "action_digest": (ev or {}).get("action_hash")}

    return {"ep-quorum": ep_quorum, "ep-receipt": ep_receipt}


def _eval_requirement(expr: str, satisfied: set) -> bool:
    import re as _re
    toks = _re.findall(r"\(|\)|[A-Za-z0-9_.:-]+", str(expr))
    pos = {"i": 0}

    def peek():
        return toks[pos["i"]] if pos["i"] < len(toks) else None

    def eat():
        t = peek()
        pos["i"] += 1
        return t

    def parse_expr():
        v = parse_term()
        while peek() in ("AND", "OR", "&&", "||"):
            op = eat()
            r = parse_term()
            v = (v and r) if op in ("AND", "&&") else (v or r)
        return v

    def parse_term():
        if peek() == "(":
            eat()
            v = parse_expr()
            if peek() == ")":
                eat()
            return v
        ident = eat()
        return False if ident is None else (ident in satisfied)

    try:
        v = parse_expr()
        return bool(v) if pos["i"] == len(toks) else False
    except Exception:
        return False


def verify_authorization_chain(aec: Any, verifiers: Optional[dict] = None, keys: Optional[dict] = None) -> dict:
    """Verify an EP-AEC chain offline. Fail-closed. Mirrors JS verifyAuthorizationChain()."""
    reasons: list = []

    def fail(why):
        reasons.append(why)
        return {"allow": False, "action_digest": None, "components": [], "reasons": reasons}

    if not isinstance(aec, dict):
        return fail("chain is not an object")
    if aec.get("@version") != AEC_VERSION:
        return fail("unexpected @version")
    if not isinstance(aec.get("action"), dict):
        return fail("missing action object")
    comps_in = aec.get("components")
    if not isinstance(comps_in, list) or not comps_in:
        return fail("no components")
    req = aec.get("requirement")
    if not isinstance(req, str) or not req.strip():
        return fail("missing requirement expression")

    chain_digest = action_digest(aec["action"])
    if aec.get("action_digest") is not None and _norm_digest(aec.get("action_digest")) != chain_digest:
        return fail("declared action_digest does not match canonical digest of the action")

    vmap = dict(_builtin_aec_verifiers())
    vmap.update(verifiers or {})
    satisfied: set = set()
    components = []
    for idx, c in enumerate(comps_in):
        label = c.get("label") or c.get("type") or f"#{idx}"
        row = {"type": c.get("type"), "label": label, "valid": False, "bound": False, "reason": None}
        v = vmap.get(c.get("type"))
        if not callable(v):
            row["reason"] = f'no verifier registered for type "{c.get("type")}"'
            components.append(row)
            continue
        try:
            res = v(c.get("evidence"), {"keys": keys, "action": aec["action"]}) or {}
        except Exception as e:
            row["reason"] = f"verifier raised: {e}"
            components.append(row)
            continue
        row["valid"] = bool(res.get("valid"))
        row["bound"] = _norm_digest(res.get("action_digest")) == chain_digest
        if not row["valid"]:
            row["reason"] = "component evidence did not verify"
        elif not row["bound"]:
            row["reason"] = "component binds a DIFFERENT action than the chain"
        if row["valid"] and row["bound"]:
            satisfied.add(c.get("type"))
            if c.get("label"):
                satisfied.add(c.get("label"))
        components.append(row)

    allow = _eval_requirement(req, satisfied)
    if not allow:
        reasons.append(f'requirement not satisfied: "{req}"')
    return {"allow": allow, "action_digest": chain_digest, "components": components, "reasons": reasons}


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
