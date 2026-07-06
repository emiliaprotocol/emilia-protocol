# SPDX-License-Identifier: Apache-2.0
"""RFC 3161 timestamp-proof Python port coverage.

Runs the SHARED conformance/vectors/timestamp-proof.v1.json (the same file the
JS and Go lanes consume, produced by conformance/vectors/generate-timestamp-proof.mjs)
through verify_timestamp_proof and asserts every vector's expect.valid, plus the
DISTINCT refusal reason per reject vector so the Python port refuses along the
same path as the JS/Go references (not merely "some" refusal).

    pytest packages/python-verify -k timestamp_proof
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from emilia_verify import verify_timestamp_proof, TIMESTAMP_PROOF_ALG  # noqa: E402

_VECTORS = os.path.join(
    os.path.dirname(__file__), "..", "..", "..",
    "conformance", "vectors", "timestamp-proof.v1.json",
)


def _load():
    with open(_VECTORS) as f:
        return json.load(f)["vectors"]


def _by_id():
    return {v["id"]: v for v in _load()}


def test_alg_identifier():
    assert TIMESTAMP_PROOF_ALG == "RFC3161"


def test_every_vector_matches_expected():
    vectors = _load()
    assert len(vectors) >= 13
    for v in vectors:
        r = verify_timestamp_proof(v["timestamp_proof"], v.get("expected_digest"), v.get("pinned_tsa_keys"))
        assert r["verified"] == v["expect"]["valid"], f"{v['id']}: got {r}"


def test_accept_reports_key_id_and_gen_time():
    v = _by_id()["accept_authentic_pinned_rsa_sha256"]
    r = verify_timestamp_proof(v["timestamp_proof"], v["expected_digest"], v["pinned_tsa_keys"])
    assert r["verified"] is True, r
    assert "reason" not in r  # success carries no reason (parity with JS)
    assert r["tsa_key_id"].startswith("sha256:")
    assert len(r["tsa_key_id"]) == len("sha256:") + 64
    assert r["gen_time"].endswith("Z")


def test_reject_reasons_are_distinct():
    byid = _by_id()
    expected = {
        "reject_missing_token": "missing_token",
        "reject_malformed_expected_digest": "missing_or_malformed_expected_digest",
        "reject_unpinned_tsa_empty": "unpinned_tsa",
        "reject_unloadable_pinned_key": "unpinned_tsa",
        "reject_digest_mismatch": "digest_mismatch",
        "reject_wrong_pinned_key": "bad_signature",
        "reject_tampered_signature": "bad_signature",
        "reject_unparseable_garbage": "unparseable_token",
        "reject_not_signed_data": "not_signed_data",
    }
    for vid, want in expected.items():
        v = byid[vid]
        r = verify_timestamp_proof(v["timestamp_proof"], v.get("expected_digest"), v.get("pinned_tsa_keys"))
        assert r["verified"] is False, f"{vid}: expected refusal"
        assert r["reason"] == want, f"{vid}: reason={r['reason']} want {want}"


def test_digest_binds_before_signature():
    # Correct signer key, but the caller expected a different digest: must refuse
    # with digest_mismatch, never leak a signature-based verdict first.
    v = _by_id()["accept_authentic_pinned_rsa_sha256"]
    wrong = "sha256:" + ("a" * 64)
    r = verify_timestamp_proof(v["timestamp_proof"], wrong, v["pinned_tsa_keys"])
    assert r["verified"] is False
    assert r["reason"] == "digest_mismatch"


def test_never_raises_on_garbage_inputs():
    for bad in (None, "", "   ", b"", 12345, {"not": "a token"}):
        r = verify_timestamp_proof(bad, "sha256:" + ("a" * 64), "not-a-key")
        assert r["verified"] is False
        assert isinstance(r["reason"], str)
