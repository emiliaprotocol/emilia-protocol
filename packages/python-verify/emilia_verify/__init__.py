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
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

__all__ = ["canonicalize", "verify_receipt", "verify_merkle_anchor", "VerifyResult"]

SUPPORTED_VERSIONS = ("EP-RECEIPT-v1",)


def canonicalize(value: Any) -> str:
    """Recursive canonical JSON — depth-first key sort at every level.

    Matches @emilia-protocol/verify `canonicalize()` byte-for-byte:
    objects -> sorted keys, arrays preserved, scalars via JSON.stringify
    semantics (json.dumps with ensure_ascii=False to mirror JS UTF-8 output).
    """
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonicalize(value[k])
            for k in sorted(value.keys())
        ) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _hash_pair(a: str, b: str) -> str:
    lo, hi = sorted((a, b))
    return _sha256_hex(lo + hi)


def verify_merkle_anchor(leaf_hash: Any, proof: Any, expected_root: Any) -> bool:
    """Verify a Merkle inclusion proof (hex leaf, sorted-pair SHA-256, hex root)."""
    if not isinstance(leaf_hash, str) or not leaf_hash:
        return False
    if not isinstance(expected_root, str) or not expected_root:
        return False
    if not isinstance(proof, list) or len(proof) > 20:
        return False
    current = leaf_hash
    for step in proof:
        if not isinstance(step, dict) or not isinstance(step.get("hash"), str):
            return False
        pos = step.get("position")
        if pos not in ("left", "right"):
            return False
        current = _hash_pair(step["hash"], current) if pos == "left" else _hash_pair(current, step["hash"])
    return current == expected_root


@dataclass
class VerifyResult:
    valid: bool
    checks: dict
    error: Optional[str] = None


def verify_receipt(doc: Any, public_key_base64url: str) -> VerifyResult:
    """Verify an EP-RECEIPT-v1 document against a signer's Ed25519 public key.

    Checks version, Ed25519 signature over the canonical payload, and (if
    present) the Merkle anchor. Returns a VerifyResult; never raises on bad input.
    """
    checks: dict = {"version": False, "signature": False, "anchor": None}

    version = doc.get("@version") if isinstance(doc, dict) else None
    if version not in SUPPORTED_VERSIONS:
        return VerifyResult(False, checks, f"Unsupported version: {version}")
    checks["version"] = True

    sig = doc.get("signature") or {}
    if not doc.get("payload") or not sig.get("value") or not sig.get("algorithm"):
        return VerifyResult(False, checks, "Missing payload or signature")

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
    if anchor.get("merkle_proof") and anchor.get("leaf_hash") and anchor.get("merkle_root"):
        checks["anchor"] = verify_merkle_anchor(
            anchor["leaf_hash"], anchor["merkle_proof"], anchor["merkle_root"]
        )

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


def _instant_ms(s: Any):
    import datetime as _dt
    if not isinstance(s, str) or not s:
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

def _within_window(t: Any, frm: Any, to: Any) -> bool:
    ms = _instant_ms(t)
    if ms is None:
        return False
    if frm:
        f = _instant_ms(frm)
        if f is not None and ms < f:
            return False
    if to:
        tt = _instant_ms(to)
        if tt is not None and ms > tt:
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
        if len(ad) < 37 or (ad[32] & _FLAG_UV) != _FLAG_UV:
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
    required = max([1] + [int(c.get("required_approvals") or 1) for c in contexts])
    sod_ok = True
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
        leaf_hash = _sha256_hex(canonicalize(leaf_content))
        checks["inclusion"] = verify_merkle_anchor(leaf_hash, lp["inclusion_path"], _hex_of(lp["checkpoint"].get("root_hash")))
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
