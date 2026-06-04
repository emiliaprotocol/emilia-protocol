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
