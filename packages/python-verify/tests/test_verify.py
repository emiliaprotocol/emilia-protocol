# SPDX-License-Identifier: Apache-2.0
"""Cross-language verification test.

Verifies a receipt that was SIGNED on the JavaScript side
(scripts/gen-python-fixture.mjs) using this pure-Python verifier — proving the
two implementations agree byte-for-byte. Also confirms tampering, a wrong key,
and a broken anchor are all rejected.

    python packages/python-verify/tests/test_verify.py      # direct
    pytest packages/python-verify                            # or via pytest
"""
import base64
import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from emilia_verify import canonicalize, is_canonicalizable, verify_receipt  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _load():
    with open(os.path.join(FIX, "receipt.json")) as f:
        doc = json.load(f)
    with open(os.path.join(FIX, "pubkey.txt")) as f:
        pub = f.read().strip()
    return doc, pub


def _random_pubkey_b64url():
    der = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.urlsafe_b64encode(der).decode().rstrip("=")


def test_valid_receipt_from_js():
    # Shared cross-language fixture now carries an EP-MERKLE-v2 (domain-separated,
    # payload-bound) anchor, so it verifies by default — no legacy opt-in needed.
    doc, pub = _load()
    r = verify_receipt(doc, pub)
    assert r.valid is True, r
    assert r.checks["version"] and r.checks["signature"] and r.checks["anchor"] is True


def test_canonicalize_consensus_split_edge_vector_matches_js():
    payload = {
        "@version": "EP-RECEIPT-v1",
        "action": {"action_type": "payment.release", "amount_usd": 1.0, "risk_score": -0.0},
        "context": {"\uFFFD": "replacement_char", "🙂": "slight_smile"},
        "entity_id": "ep_entity_poc_test",
        "signoffs": [],
    }
    canonical = canonicalize(payload)
    assert canonical == (
        '{"@version":"EP-RECEIPT-v1","action":{"action_type":"payment.release",'
        '"amount_usd":1,"risk_score":0},"context":{"🙂":"slight_smile",'
        '"�":"replacement_char"},"entity_id":"ep_entity_poc_test","signoffs":[]}'
    )
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == (
        "49c642930186d4ed0324c6099f077c38a16cac19e327c2f58bb76f19a33351b2"
    )
    assert is_canonicalizable(payload) is True
    assert is_canonicalizable({"unsafe": 1e20}) is False
    assert is_canonicalizable({"fractional": 1.25}) is False


def test_tampered_payload_fails():
    doc, pub = _load()
    bad = copy.deepcopy(doc)
    bad["payload"]["claim"]["context"]["amount"] = 1  # change after signing
    r = verify_receipt(bad, pub)
    assert r.valid is False
    assert r.checks["signature"] is False


def test_wrong_key_fails():
    doc, _ = _load()
    r = verify_receipt(doc, _random_pubkey_b64url())
    assert r.valid is False
    assert r.checks["signature"] is False


def test_tampered_anchor_fails():
    doc, pub = _load()
    bad = copy.deepcopy(doc)
    bad["anchor"]["merkle_root"] = "0" * 64
    r = verify_receipt(bad, pub)
    assert r.valid is False
    assert r.checks["anchor"] is False


def test_scope_containment_nonnumeric_cap_does_not_crash():
    """Regression (surface audit P0): a non-numeric max_value_usd must not raise
    an uncaught ValueError in the verifier. It coerces to NaN (JS Number() /
    Go toFloat() parity) so the comparison is false rather than crashing."""
    import math
    from emilia_verify import _num, _js_min, _scope_containment_violations
    assert math.isnan(_num("abc"))
    assert _num("1850") == 1850.0
    assert _num("") == 0.0
    assert (_num("abc") > _num(100)) is False
    assert math.isnan(_js_min(_num("abc"), 100.0))
    assert _js_min(50.0, 100.0) == 50.0
    # end to end through the containment check: attacker cap must not crash
    parent = {"scope": ["*"], "max_value_usd": 100}
    child = {"scope": ["*"], "max_value_usd": "not-a-number"}
    viol = _scope_containment_violations(parent, child)  # must return, not raise
    assert isinstance(viol, list)


if __name__ == "__main__":
    test_valid_receipt_from_js()
    test_canonicalize_consensus_split_edge_vector_matches_js()
    test_tampered_payload_fails()
    test_wrong_key_fails()
    test_tampered_anchor_fails()
    test_scope_containment_nonnumeric_cap_does_not_crash()
    print("ALL PASS — JS-signed receipt verified in Python; tamper / wrong-key / bad-anchor rejected.")
