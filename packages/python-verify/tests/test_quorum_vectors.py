# SPDX-License-Identifier: Apache-2.0
"""Cross-language quorum regression coverage over the shared live vectors.

Every EP-QUORUM-v1 vector must produce the same verdict here as in the JS and
Go runtimes. Verdict parity is the parity claim."""
import json
from pathlib import Path

import pytest

from emilia_verify import verify_quorum


ROOT = Path(__file__).resolve().parents[3]
SUITE = json.loads((ROOT / "conformance/vectors/quorum.v1.json").read_text(encoding="utf-8"))
OPTS = {"rpId": "emiliaprotocol.ai", "allowedOrigins": ["https://www.emiliaprotocol.ai"]}


def _vector(vector_id):
    return next(vector for vector in SUITE["vectors"] if vector["id"] == vector_id)


@pytest.mark.parametrize("vector", SUITE["vectors"], ids=[v["id"] for v in SUITE["vectors"]])
def test_every_vector_matches_expect(vector):
    result = verify_quorum(vector["quorum"], OPTS)
    assert result["valid"] is vector["expect"]["valid"], (vector["id"], result["checks"], result.get("reason"))


def test_accepts_ordered_prefix_quorum_two_of_three():
    result = verify_quorum(_vector("accept_ordered_2of3")["quorum"], OPTS)
    assert result["valid"] is True


def test_non_canonical_spki_cannot_fill_a_seat():
    result = verify_quorum(_vector("reject_noncanonical_spki_second_seat")["quorum"], OPTS)
    assert result["valid"] is False
    assert result["checks"]["all_signatures_valid"] is False


@pytest.mark.parametrize("vector_id, reason", [
    ("reject_required_algorithms_malformed", "required_algorithms_malformed"),
    ("reject_required_algorithms_unknown", "required_algorithms_unknown:RS256"),
])
def test_required_algorithms_refused_by_name(vector_id, reason):
    result = verify_quorum(_vector(vector_id)["quorum"], OPTS)
    assert result["valid"] is False
    assert result.get("reason") == reason
