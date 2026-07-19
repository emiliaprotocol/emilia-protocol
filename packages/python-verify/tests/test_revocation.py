# SPDX-License-Identifier: Apache-2.0
"""Fail-closed regression coverage for EP-REVOCATION-v1."""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from emilia_verify import REVOCATION_VERSION, canonicalize, verify_revocation


def _valid_vector():
    vectors_path = (
        Path(__file__).resolve().parents[3]
        / "conformance"
        / "vectors"
        / "revocation.exec.v2.json"
    )
    with vectors_path.open(encoding="utf-8") as handle:
        return json.load(handle)["vectors"][0]


def _base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _signed_statement(revoked_at):
    target = {
        "target_type": "receipt",
        "target_id": "rcpt_fractional_seconds",
        "action_hash": "sha256:" + "a" * 64,
    }
    revoker_id = "ep:revoker:fractional-seconds"
    private_key = Ed25519PrivateKey.generate()
    public_key_der = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    public_key = _base64url(public_key_der)
    signed = {
        "@version": REVOCATION_VERSION,
        "action_hash": target["action_hash"],
        "reason": "grammar boundary",
        "revoked_at": revoked_at,
        "revoker_id": revoker_id,
        "target_id": target["target_id"],
        "target_type": target["target_type"],
    }
    statement = {
        "@version": REVOCATION_VERSION,
        "target_type": target["target_type"],
        "target_id": target["target_id"],
        "action_hash": target["action_hash"],
        "revoker_id": revoker_id,
        "revoked_at": revoked_at,
        "reason": signed["reason"],
        "proof": {
            "algorithm": "Ed25519",
            "revoker_key_id": (
                "ep:revoker-key:sha256:"
                + hashlib.sha256(public_key_der).hexdigest()
            ),
            "public_key": public_key,
            "signature_b64u": _base64url(
                private_key.sign(canonicalize(signed).encode("utf-8"))
            ),
        },
    }
    return target, statement, {revoker_id: {"public_key": public_key}}


def test_malformed_uncanonicalizable_revoker_id_fails_closed_without_exception():
    vector = _valid_vector()
    vector["revocation"]["revoker_id"] = {"nested": {1, 2}}

    result = verify_revocation(
        vector["target"],
        vector["revocation"],
        {
            "revokerKeys": vector["revoker_keys"],
            "now": "2026-06-20T12:00:01Z",
        },
    )

    assert result["valid"] is False
    assert result["checks"]["revoker_key_pinned"] is False
    assert result["checks"]["signature_binds_statement"] is False


@pytest.mark.parametrize(
    "revoked_at",
    [
        "2026-06-20T12:00:00.1Z",
        "2026-06-20T12:00:00.123456789Z",
    ],
)
def test_accepts_one_through_nine_fractional_second_digits(revoked_at):
    target, statement, revoker_keys = _signed_statement(revoked_at)

    result = verify_revocation(
        target,
        statement,
        {"revokerKeys": revoker_keys, "now": "2026-06-20T12:00:01Z"},
    )

    assert result["valid"] is True, result["errors"]
