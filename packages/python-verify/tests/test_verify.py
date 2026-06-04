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
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from emilia_verify import verify_receipt  # noqa: E402

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
    doc, pub = _load()
    r = verify_receipt(doc, pub)
    assert r.valid is True, r
    assert r.checks["version"] and r.checks["signature"] and r.checks["anchor"] is True


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


if __name__ == "__main__":
    test_valid_receipt_from_js()
    test_tampered_payload_fails()
    test_wrong_key_fails()
    test_tampered_anchor_fails()
    print("ALL PASS — JS-signed receipt verified in Python; tamper / wrong-key / bad-anchor rejected.")
