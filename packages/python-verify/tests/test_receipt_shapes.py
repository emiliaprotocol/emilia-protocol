# SPDX-License-Identifier: Apache-2.0
"""Malformed nested receipt values return VerifyResult, never exceptions."""

import hashlib
import json
from pathlib import Path

import pytest
from emilia_verify import canonicalize, verify_merkle_anchor, verify_receipt

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("field,value", [
    ("signature", ["bad"]), ("signature", 1), ("signature", "bad"),
    ("signature", None), ("payload", ["bad"]), ("payload", 1),
    ("payload", None), ("anchor", ["bad"]), ("anchor", 1),
    ("anchor", "bad"),
])
def test_nested_field_types_fail_closed(field, value):
    doc = json.loads((FIXTURES / "receipt.json").read_text())
    public_key = (FIXTURES / "pubkey.txt").read_text().strip()
    doc[field] = value
    result = verify_receipt(doc, public_key)
    assert result.valid is False


@pytest.mark.parametrize("invalid_hash", [chr(0xD800), chr(0xDFFF)])
def test_malformed_anchor_proof_unicode_returns_structured_failure(invalid_hash):
    # JSON decoders accept escaped lone surrogates. The valid signed payload
    # must not let malformed, unsigned Merkle material escape as an exception.
    doc = json.loads((FIXTURES / "receipt.json").read_text())
    public_key = (FIXTURES / "pubkey.txt").read_text().strip()
    leaf = hashlib.sha256(b"\x00" + canonicalize(doc["payload"]).encode("utf-8")).hexdigest()
    proof = [{"position": "right", "hash": invalid_hash}]
    doc["anchor"] = {
        "alg": "EP-MERKLE-v2",
        "leaf_hash": leaf,
        "merkle_proof": proof,
        "merkle_root": "0" * 64,
    }
    result = verify_receipt(doc, public_key)
    assert result.valid is False
    assert result.checks["signature"] is True
    assert result.checks["anchor"] is False
    assert verify_merkle_anchor(leaf, proof, "0" * 64, v2=True) is False
    assert verify_merkle_anchor(leaf, proof, "0" * 64, v2=False) is False
