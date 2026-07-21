# SPDX-License-Identifier: Apache-2.0
"""Cross-language quorum regression coverage over the shared live vectors."""
import json
from pathlib import Path

from emilia_verify import verify_quorum


ROOT = Path(__file__).resolve().parents[3]
SUITE = json.loads((ROOT / "conformance/vectors/quorum.v1.json").read_text(encoding="utf-8"))


def _vector(vector_id):
    return next(vector for vector in SUITE["vectors"] if vector["id"] == vector_id)


def test_accepts_ordered_prefix_quorum_two_of_three():
    vector = _vector("accept_ordered_2of3")
    result = verify_quorum(vector["quorum"], {
        "rpId": "emiliaprotocol.ai",
        "allowedOrigins": ["https://www.emiliaprotocol.ai"],
    })
    assert result["valid"] is True

