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
