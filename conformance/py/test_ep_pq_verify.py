# SPDX-License-Identifier: Apache-2.0
"""Conformance tests for the Python EP hybrid post-quantum verifier.

Run:
    python3 -m pytest conformance/py/test_ep_pq_verify.py -q

These tests consume the SAME checked-in vector files the JavaScript side
consumes; nothing here re-derives its own expectations from the Python
implementation, which would only prove Python agrees with itself.

The suite is honest about the ML-DSA backend. With one installed, every
recorded verdict is enforced exactly. Without one, every post-quantum leg must
refuse with pq_backend_unavailable, and the tests that would otherwise be
vacuous say so by asserting the refusal instead of skipping.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_pq  # noqa: E402
from ep_pq_verify import (  # noqa: E402
    AGILE_SIGNATURE_ALGORITHMS,
    HYBRID_DOMAIN,
    HYBRID_RECEIPT_REQUIRED_ALGORITHMS,
    MldsaBackend,
    hybrid_signed_bytes,
    hybrid_signing_input,
    load_default_mldsa_backend,
    node_base64url_decode,
    strict_base64url_decode,
    verify_agile_signature,
    verify_agile_signature_set,
    verify_hybrid,
    verify_hybrid_receipt,
)

BACKEND = load_default_mldsa_backend()
HAS_BACKEND = BACKEND is not None
NO_BACKEND = {"mldsa_backend_loader": lambda: None}
LIVE = {} if BACKEND is None else {"mldsa_backend": BACKEND}


def _load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


AGILITY = _load(run_pq.AGILITY_VECTORS)
RECEIPTS = _load(run_pq.RECEIPT_VECTORS)
ENVELOPES = _load(run_pq.ENVELOPE_VECTORS)


# ---------------------------------------------------------------------------
# The vector files are shared with JS, so the shared bytes must be identical
# ---------------------------------------------------------------------------

def test_python_canonicalization_reproduces_pinned_agility_digest():
    """The agility message bytes are the EP canonical form of the payload."""
    from emilia_verify import canonicalize

    canonical = canonicalize(AGILITY["payload"])
    assert canonical == AGILITY["canonical_payload"]
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == \
        AGILITY["canonical_payload_sha256"]


def test_python_reproduces_pinned_hybrid_receipt_signed_bytes():
    """EP-RECEIPT-HYBRID-v1 signed bytes rebuilt in Python match the pinned digest.

    This is the anti-stripping commitment itself: the required algorithm set is
    inside these bytes.
    """
    rebuilt = hybrid_signed_bytes(RECEIPTS["payload"], HYBRID_RECEIPT_REQUIRED_ALGORITHMS)
    assert hashlib.sha256(rebuilt).hexdigest() == RECEIPTS["signed_bytes_sha256"]
    assert json.loads(rebuilt.decode("utf-8")) == RECEIPTS["signed_material"]


def test_hybrid_signing_input_matches_the_documented_construction():
    message = b"payload-bytes"
    built = hybrid_signing_input(message, list(AGILE_SIGNATURE_ALGORITHMS))
    expected = (
        HYBRID_DOMAIN.encode("utf-8") + b"\x00"
        + b'["Ed25519","ML-DSA-65"]' + b"\x00"
        + message
    )
    assert built == expected


def test_narrowing_the_algorithm_set_changes_the_signed_bytes():
    """Anti-stripping, stated as bytes rather than as a claim.

    Removing an algorithm from the committed set produces different signing
    input, so any signature made over the full set cannot cover it.
    """
    full = hybrid_signing_input(b"m", ["Ed25519", "ML-DSA-65"])
    narrowed = hybrid_signing_input(b"m", ["Ed25519"])
    reordered = hybrid_signing_input(b"m", ["ML-DSA-65", "Ed25519"])
    assert full != narrowed
    assert full != reordered


# ---------------------------------------------------------------------------
# Every vector in every shared file
# ---------------------------------------------------------------------------

def _row_ids(rows):
    return [r["id"] for r in rows]


@pytest.mark.parametrize("row", run_pq.run_agility(BACKEND), ids=_row_ids(run_pq.run_agility(BACKEND)))
def test_agility_vectors(row):
    assert row["ok"], f"{row['id']}: want {row['want']}, got {row['got']}"


@pytest.mark.parametrize(
    "row", run_pq.run_hybrid_receipts(BACKEND), ids=_row_ids(run_pq.run_hybrid_receipts(BACKEND))
)
def test_hybrid_receipt_vectors(row):
    assert row["ok"], f"{row['id']}: want {row['want']}, got {row['got']}"


@pytest.mark.parametrize(
    "row", run_pq.run_hybrid_envelope(BACKEND), ids=_row_ids(run_pq.run_hybrid_envelope(BACKEND))
)
def test_hybrid_envelope_vectors(row):
    assert row["ok"], f"{row['id']}: want {row['want']}, got {row['got']}"


@pytest.mark.parametrize("row", run_pq.run_hostile(BACKEND), ids=_row_ids(run_pq.run_hostile(BACKEND)))
def test_fail_closed_on_hostile_input(row):
    assert row["ok"], f"{row['id']}: want {row['want']}, got {row['got']}"


def test_every_vector_file_is_actually_exercised():
    """Guard against a vector file growing entries no runner reads."""
    assert len(run_pq.run_agility(BACKEND)) == len(AGILITY["vectors"])
    assert len(run_pq.run_hybrid_receipts(BACKEND)) == len(RECEIPTS["vectors"])
    assert len(run_pq.run_hybrid_envelope(BACKEND)) == len(ENVELOPES["vectors"])


# ---------------------------------------------------------------------------
# The named refusals, asserted one by one against the JS vocabulary
# ---------------------------------------------------------------------------

def _envelope_case(vector_id):
    vector = next(v for v in ENVELOPES["vectors"] if v["id"] == vector_id)
    keys = {
        "ed25519PublicKey": ENVELOPES["keys"][vector["keys"]["ed25519"]]["spki_b64url"],
        "mldsaPublicKey": ENVELOPES["keys"][vector["keys"]["mldsa"]]["public_key_b64url"],
    }
    return vector, keys


def test_refusal_algorithm_key_mismatch_curve_pin():
    """Ed448 key in the Ed25519 slot. The curve pin refuses before any verify call.

    Without it, crypto verification picks the algorithm from the key object and
    the attacker verifies a real Ed448 signature under their own curve.
    """
    vector, keys = _envelope_case("pq-hybrid-ed448-key-masquerade")
    result = verify_hybrid(vector["message"], vector["envelope"], keys, LIVE)
    assert result["verified"] is False
    assert result["reason"] == "algorithm_key_mismatch"


def test_refusal_signature_length_invalid_is_the_other_half_of_the_pin():
    """The same Ed448 leg against the pinned Ed25519 key: 114 bytes, not 64."""
    vector, keys = _envelope_case("pq-hybrid-ed448-signature-length")
    assert len(node_base64url_decode(vector["envelope"]["sigs"]["Ed25519"])) == 114
    result = verify_hybrid(vector["message"], vector["envelope"], keys, LIVE)
    assert result["verified"] is False
    assert result["reason"] == "signature_length_invalid"


def test_refusal_missing_required_algorithm_never_narrows_to_what_was_presented():
    """The required set defaults to the FULL registry and never narrows itself."""
    message = AGILITY["canonical_payload"].encode("utf-8")
    ed_only = [next(s for s in
                    next(v for v in AGILITY["vectors"] if v["id"] == "hybrid-all-valid")["signatures"]
                    if s["alg"] == "Ed25519")]
    keys = [
        {"alg": "Ed25519", "public_key": AGILITY["keys"]["ed25519"]["public_key"]},
        {"alg": "ML-DSA-65", "public_key": AGILITY["keys"]["ml_dsa_65"]["public_key"]},
    ]
    result = verify_agile_signature_set(message, ed_only, keys, {**LIVE, "policy": "hybrid_all"})
    assert result["verified"] is False
    assert result["reason"] == "missing_required_algorithm"


def test_refusal_malformed_signature_on_strict_base64url():
    """The agility decoder is strict: lenient decoding would mask a tampering class."""
    message = AGILITY["canonical_payload"].encode("utf-8")
    key = {"alg": "Ed25519", "public_key": AGILITY["keys"]["ed25519"]["public_key"]}
    for bad in ("", "has spaces", "padded==", "plus+slash/"):
        result = verify_agile_signature(message, {"alg": "Ed25519", "sig": bad}, key, LIVE)
        assert result["verified"] is False
        assert result["reason"] == "malformed_signature", bad
        assert strict_base64url_decode(bad) is None


def test_refusal_pq_backend_unavailable_is_a_refusal_not_a_skip():
    """A fully valid envelope with no backend must NOT verify.

    This is the whole rule: absence of the post-quantum implementation is a
    refusal, never a skipped check, and a valid classical leg never carries the
    artifact on its own.
    """
    vector, keys = _envelope_case("pq-hybrid-valid")
    result = verify_hybrid(vector["message"], vector["envelope"], keys, NO_BACKEND)
    assert result["verified"] is False
    assert result["reason"] == "pq_backend_unavailable"
    # The classical leg genuinely passed; the envelope still refuses.
    assert result["checks"]["classical_signature"] is True
    assert result["checks"]["pq_signature"] is None


def test_backend_absent_refuses_the_valid_hybrid_receipt_too():
    vector = next(v for v in RECEIPTS["vectors"] if v["id"] == "hybrid-valid")
    keys = {
        "ed25519PublicKey": RECEIPTS["keys"]["Ed25519"]["public_key"],
        "mldsaPublicKey": RECEIPTS["keys"]["ML-DSA-65"]["public_key"],
    }
    result = verify_hybrid_receipt(vector["receipt"], keys, NO_BACKEND)
    assert result["verified"] is False
    assert result["reason"] == "pq_backend_unavailable"
    assert result["failed_algorithm"] == "ML-DSA-65"


def test_backend_absent_refuses_a_single_ml_dsa_signature():
    message = AGILITY["canonical_payload"].encode("utf-8")
    vector = next(v for v in AGILITY["vectors"] if v["id"] == "ml-dsa-65-valid")
    key = {"alg": "ML-DSA-65", "public_key": AGILITY["keys"]["ml_dsa_65"]["public_key"]}
    result = verify_agile_signature(message, vector["signature"], key, NO_BACKEND)
    assert result["verified"] is False
    assert result["reason"] == "pq_backend_unavailable"
    # The key was well-formed; the refusal is about the missing implementation.
    assert result["checks"]["key_wellformed"] is True
    assert result["checks"]["signature_valid"] is None


# ---------------------------------------------------------------------------
# A dishonest backend buys nothing but the leg it owns
# ---------------------------------------------------------------------------

_ALWAYS_TRUE = MldsaBackend(lambda sig, msg, pk: True, "always-true")


def test_bogus_backend_cannot_defeat_the_classical_leg_or_the_set_commitment():
    """An injected always-true backend makes the PQ leg vacuous and nothing else.

    The caller owns that leg's honesty; the classical leg, the algorithm-set
    commitment, and every length pin are enforced independently.
    """
    options = {"mldsa_backend": _ALWAYS_TRUE}
    for vector_id, reason in [
        ("pq-hybrid-classical-signature-invalid", "classical_signature_invalid"),
        ("pq-hybrid-algo-set-narrowed", "algo_set_mismatch"),
        ("pq-hybrid-ed448-key-masquerade", "algorithm_key_mismatch"),
        ("pq-hybrid-pq-signature-length", "signature_length_invalid"),
        ("pq-hybrid-pq-public-key-length", "public_key_length_invalid"),
        ("pq-hybrid-pq-leg-stripped", "missing_signature"),
    ]:
        vector, keys = _envelope_case(vector_id)
        result = verify_hybrid(vector["message"], vector["envelope"], keys, options)
        assert result["verified"] is False, vector_id
        assert result["reason"] == reason, vector_id


def test_bogus_backend_does_verify_the_leg_it_owns():
    """Stated plainly so the boundary above is not mistaken for a stronger claim."""
    vector, keys = _envelope_case("pq-hybrid-pq-signature-invalid")
    result = verify_hybrid(vector["message"], vector["envelope"], keys,
                           {"mldsa_backend": _ALWAYS_TRUE})
    assert result["verified"] is True


# ---------------------------------------------------------------------------
# Set policy: per_algorithm never collapses
# ---------------------------------------------------------------------------

def test_per_algorithm_policy_never_collapses_to_a_single_verdict():
    message = AGILITY["canonical_payload"].encode("utf-8")
    vector = next(v for v in AGILITY["vectors"] if v["id"] == "per-algorithm-never-collapses")
    keys = [
        {"alg": "Ed25519", "public_key": AGILITY["keys"]["ed25519"]["public_key"]},
        {"alg": "ML-DSA-65", "public_key": AGILITY["keys"]["ml_dsa_65"]["public_key"]},
    ]
    result = verify_agile_signature_set(
        message, vector["signatures"], keys, {**LIVE, "policy": "per_algorithm"}
    )
    assert result["verified"] is None
    assert result["reason"] is None
    per_alg = {r["alg"]: r for r in result["results"]}
    assert per_alg["Ed25519"]["verified"] is True
    if HAS_BACKEND:
        assert per_alg["ML-DSA-65"]["verified"] is True
    else:
        assert per_alg["ML-DSA-65"]["verified"] is False
        assert per_alg["ML-DSA-65"]["reason"] == "pq_backend_unavailable"


# ---------------------------------------------------------------------------
# The receipt verifier rebuilds bytes from the REGISTERED set, not the claimed one
# ---------------------------------------------------------------------------

def test_narrowed_receipt_set_is_refused_structurally_and_the_bytes_would_differ():
    vector = next(v for v in RECEIPTS["vectors"] if v["id"] == "ml-dsa-leg-stripped-and-set-narrowed")
    keys = {
        "ed25519PublicKey": RECEIPTS["keys"]["Ed25519"]["public_key"],
        "mldsaPublicKey": RECEIPTS["keys"]["ML-DSA-65"]["public_key"],
    }
    result = verify_hybrid_receipt(vector["receipt"], keys, LIVE)
    assert result["verified"] is False
    assert result["reason"] == "algorithm_set_mismatch"

    # The independent half: the surviving Ed25519 leg does not cover the bytes
    # the narrowed receipt implies, because the set is inside the signed bytes.
    from emilia_verify import canonicalize

    narrowed_material = {
        "@version": "EP-RECEIPT-HYBRID-v1",
        "payload": vector["receipt"]["payload"],
        "required_algorithms": ["Ed25519"],
    }
    narrowed_bytes = canonicalize(narrowed_material).encode("utf-8")
    registered_bytes = hybrid_signed_bytes(
        vector["receipt"]["payload"], HYBRID_RECEIPT_REQUIRED_ALGORITHMS
    )
    assert narrowed_bytes != registered_bytes

    surviving_leg = vector["receipt"]["signatures"][0]
    over_narrowed = verify_agile_signature(
        narrowed_bytes, surviving_leg,
        {"alg": "Ed25519", "public_key": RECEIPTS["keys"]["Ed25519"]["public_key"]},
        LIVE,
    )
    assert over_narrowed["verified"] is False
    assert over_narrowed["reason"] == "signature_invalid"


def test_receipt_cannot_choose_what_it_is_checked_against():
    """A widened claimed set is refused; the verifier never adopts it."""
    vector = next(v for v in RECEIPTS["vectors"] if v["id"] == "hybrid-valid")
    tampered = copy.deepcopy(vector["receipt"])
    tampered["profile"]["required_algorithms"] = ["Ed25519", "ML-DSA-65", "RSA-PSS"]
    keys = {
        "ed25519PublicKey": RECEIPTS["keys"]["Ed25519"]["public_key"],
        "mldsaPublicKey": RECEIPTS["keys"]["ML-DSA-65"]["public_key"],
    }
    result = verify_hybrid_receipt(tampered, keys, LIVE)
    assert result["verified"] is False
    assert result["reason"] == "algorithm_set_mismatch"


# ---------------------------------------------------------------------------
# Decoder parity with node's Buffer, which decides which reason a blob earns
# ---------------------------------------------------------------------------

# Ground truth captured from node:
#   node -e "console.log(Buffer.from(<text>,'base64url').toString('hex'))"
@pytest.mark.parametrize("text,expected_hex", [
    ("AAAA", "000000"),
    ("AQAB", "010001"),
    ("_w", "ff"),         # 2-character trailing group: one byte
    ("_", ""),            # 1-character trailing group: no byte, as node does
    ("A", ""),
    ("", ""),
    ("AAAA=", "000000"),  # padding ignored
    ("AA*AA", "000000"),  # characters outside the alphabet ignored, not fatal
    ("AA AA", "000000"),
    ("abc", "69b7"),
    ("abcde", "69b71d"),
    ("-_-_", "fbffbf"),
])
def test_node_base64url_decoder_parity(text, expected_hex):
    assert node_base64url_decode(text).hex() == expected_hex


def test_strict_decoder_rejects_what_the_agility_regex_rejects():
    assert strict_base64url_decode("AAAA") == bytes.fromhex("000000")
    for bad in ("", "AAAA=", "AA*AA", "AA AA", "AA+A", "AA/A", None, 5):
        assert strict_base64url_decode(bad) is None, bad
