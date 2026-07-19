# SPDX-License-Identifier: Apache-2.0
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from emilia_verify import _context_authorizes, verify_trust_receipt  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
VECTORS = os.path.join(ROOT, "conformance", "vectors", "trust-receipt.exec.v1.json")


def _load_vector(vector_id):
    with open(VECTORS, encoding="utf-8") as corpus_file:
        corpus = json.load(corpus_file)
    return next(vector for vector in corpus["vectors"] if vector["id"] == vector_id)


def test_only_approved_or_legacy_contexts_authorize():
    assert _context_authorizes({}) is True
    assert _context_authorizes({"decision": "approved"}) is True
    for decision in ("denied", "pending", None, 1, {"outcome": "approved"}):
        assert _context_authorizes({"decision": decision}) is False


def test_cryptographically_valid_signed_denial_does_not_authorize():
    vector = _load_vector("reject_signed_denial_as_authorization")
    verification = vector["verification"]
    result = verify_trust_receipt(vector["trust_receipt"], {
        "approverKeys": verification["approver_keys"],
        "logPublicKey": verification["log_public_key"],
    })

    assert result["checks"]["context_commitments"] is True
    assert result["checks"]["signoff_signatures"] is True
    assert result["checks"]["windows"] is True
    assert result["checks"]["sod"] is False
    assert result["valid"] is False
    assert any("signed denial" in error for error in result["errors"])
