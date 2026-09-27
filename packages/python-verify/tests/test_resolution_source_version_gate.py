# SPDX-License-Identifier: Apache-2.0
"""Published -02 verifier must not silently accept an unpublished -04 option."""

import json
from copy import deepcopy
from pathlib import Path

from emilia_verify import verify_resolution_receipt


ROOT = Path(__file__).resolve().parents[3]
SUITE = json.loads((ROOT / "conformance/vectors/resolution.v1.json").read_text(encoding="utf-8"))
APPROVED = next(vector for vector in SUITE["vectors"] if vector["id"] == "accept_approved")


def _options(vector):
    return {
        "bindingMoment": vector["binding_moment"],
        "expectedActionHash": vector["expected_action_hash"],
        "expectedSelectedOption": vector["expected_selected_option"],
        "expectedNonce": vector["expected_nonce"],
        "expectedInitiator": vector["expected_initiator"],
        "evaluationTime": vector["evaluation_time"],
        "rpId": vector["rp_id"],
        "allowedOrigins": vector["allowed_origins"],
        "principalKeys": vector["principal_keys"],
    }


def test_unpublished_option_binding_and_profile_relabel_refuse_under_v1():
    vector = deepcopy(APPROVED)
    receipt = vector["resolution_receipt"]
    options = _options(vector)
    assert verify_resolution_receipt(receipt, options)["authorizes_action"] is True

    relabeled = deepcopy(receipt)
    relabeled["profile"] = "EP-RESOLUTION-BME04-CANDIDATE-v1"
    result = verify_resolution_receipt(relabeled, options)
    assert result["valid"] is False
    assert result["reason"] == "malformed_resolution_receipt"

    options["bindingMoment"]["question"]["options"][0]["action_digest"] = vector["expected_action_hash"]
    options["bindingMoment"]["question"]["options"][1]["action_digest"] = "sha256:" + "b" * 64
    result = verify_resolution_receipt(receipt, options)
    assert result["valid"] is False
    assert result["authorizes_action"] is False
    assert result["reason"] == "malformed_binding_moment"
