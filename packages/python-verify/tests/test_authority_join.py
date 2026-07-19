# SPDX-License-Identifier: Apache-2.0
"""Parity tests for EP-AUTHORITY-DOC-PROOF-JOIN-v1."""

import copy
import json
from pathlib import Path

from emilia_verify import verify_authority_proof_via_document
from emilia_verify.authority_join import _resolve_issuer_key_at, _stable_identifier


FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "conformance"
    / "vectors"
    / "authority-document-proof-join.exec.v1.json"
)


def _suite():
    with FIXTURE_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _vector(vector_id):
    return next(vector for vector in _suite()["vectors"] if vector["id"] == vector_id)


def test_exact_shared_26_case_fixture_parity():
    suite = _suite()
    assert suite["suite"] == "EP-AUTHORITY-DOC-PROOF-JOIN-v1"
    assert len(suite["vectors"]) == 26

    for vector in suite["vectors"]:
        result = verify_authority_proof_via_document(
            vector["proof"],
            vector["docs"],
            vector["opts"],
        )
        assert result["accepted"] is vector["expect"]["accepted"], (
            vector["id"],
            result,
        )
        assert result["issuer_accepted"] is vector["expect"]["accepted"]
        if "reason" in vector["expect"]:
            assert result["reason"] == vector["expect"]["reason"], (
                vector["id"],
                result,
            )


def test_verified_is_not_collapsed_into_accepted():
    vector = _vector("reject_no_document_anchor")
    result = verify_authority_proof_via_document(
        vector["proof"],
        vector["docs"],
        vector["opts"],
    )
    assert result["verified"] is True
    assert result["accepted"] is False
    assert result["issuer_accepted"] is False
    assert result["checks"]["proof_signature"] is True
    assert result["checks"]["document_chain"] is True
    assert result["checks"]["continuity"] is True


def test_acceptance_requires_every_join_check_and_preserves_scope_limits():
    vector = _vector("accept_anchored_document_key_at_issuance")
    result = verify_authority_proof_via_document(
        vector["proof"],
        vector["docs"],
        vector["opts"],
    )
    assert result["accepted"] is True
    assert all(result["checks"].values())
    assert result["authority_evaluated"] is False
    assert result["delegation_evaluated"] is False
    assert result["document_head"] == vector["opts"]["expectedDocumentHead"]
    assert result["bootstrap_digest"] == vector["opts"]["expectedBootstrapDigest"]


def test_newest_effective_document_is_complete_state_and_omission_removes_key():
    vector = _vector("accept_anchored_document_key_at_issuance")
    kid = vector["proof"]["authority_document"]["issuer_kid"]
    documents = copy.deepcopy(vector["docs"])
    documents[-1]["issuer_keys"] = []

    assert _resolve_issuer_key_at(
        documents,
        kid,
        vector["opts"]["expectedProofIssuedAt"],
    ) is None


def test_terminal_revocation_cannot_be_resurrected_by_a_later_document():
    vector = _vector("accept_anchored_document_key_at_issuance")
    kid = vector["proof"]["authority_document"]["issuer_kid"]
    entry = copy.deepcopy(vector["docs"][-1]["issuer_keys"][0])
    revoked = copy.deepcopy(entry)
    revoked["revoked_at"] = "2026-07-01T00:00:00.000Z"
    resurrected = copy.deepcopy(entry)
    documents = [
        {
            "issued_at": "2026-06-01T00:00:00.000Z",
            "seq": 0,
            "issuer_keys": [revoked],
        },
        {
            "issued_at": "2026-07-05T00:00:00.000Z",
            "seq": 1,
            "issuer_keys": [resurrected],
        },
    ]

    assert _resolve_issuer_key_at(
        documents,
        kid,
        "2026-07-10T00:00:00.000Z",
    ) is None


def test_unstable_relying_party_identifiers_fail_closed_after_verification():
    vector = _vector("accept_anchored_document_key_at_issuance")
    options = copy.deepcopy(vector["opts"])
    options["expectedOrganizationId"] = "org 1"
    result = verify_authority_proof_via_document(
        vector["proof"],
        vector["docs"],
        options,
    )
    assert result["verified"] is True
    assert result["accepted"] is False
    assert result["reason"] == "authority_document_organization_mismatch"


def test_stable_identifier_bound_counts_unicode_code_points():
    assert _stable_identifier("😀" * 512) is True
    assert _stable_identifier("😀" * 513) is False


def test_malformed_native_inputs_never_raise():
    for documents in (None, {}, [None], [42], [{"@version": "EP-AUTHORITY-DOC-v1"}]):
        result = verify_authority_proof_via_document({}, documents, {})
        assert result["verified"] is False
        assert result["issuer_accepted"] is False
        assert result["reason"] == "authority_document_chain_invalid"
