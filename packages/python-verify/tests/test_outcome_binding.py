# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

from emilia_verify import (
    MAX_EFFECT_STRING_LENGTH,
    MAX_OBSERVED_EFFECTS,
    MAX_PREDICTED_EFFECTS,
    compare_decimal_strings,
    evaluate_predicted_effects,
    validate_predicted_effects,
    verify_outcome_attestation,
    verify_outcome_binding,
)


ROOT = Path(__file__).resolve().parents[3]
SEMANTIC_SUITE = json.loads(
    (ROOT / "conformance/vectors/outcome-binding.v1.json").read_text(encoding="utf-8")
)
EXEC_SUITE = json.loads(
    (ROOT / "conformance/vectors/outcome-binding.exec.v1.json").read_text(encoding="utf-8")
)

def _exec_result(vector):
    common = EXEC_SUITE["common"]
    options = {
        "receiptOptions": common["receipt_options"],
        "executorKeys": vector.get("executor_keys", common["executor_keys"]),
        "now": common["now"],
    }
    if "policy_predicted_effects" in vector:
        options["policyPredictedEffects"] = vector["policy_predicted_effects"]
    return verify_outcome_binding(common["receipt"], vector["attestation"], options)


def test_existing_predicate_vectors_match_exact_outcomes_and_reasons():
    predicate_vectors = [
        vector for vector in SEMANTIC_SUITE["vectors"] if vector["kind"] == "predicate"
    ]
    assert len(predicate_vectors) == 24
    for vector in predicate_vectors:
        result = evaluate_predicted_effects(
            vector.get("predicted_effects"), vector.get("observed_effects")
        )
        assert result["outcome"] == vector["expect"]["outcome"], vector["id"]
        if "reason_contains" in vector["expect"]:
            assert vector["expect"]["reason_contains"] in " ".join(result["reasons"])


def test_existing_real_crypto_vectors_match_js_verdicts_and_result_digests():
    assert EXEC_SUITE["count"] == 10
    for vector in EXEC_SUITE["vectors"]:
        first = _exec_result(vector)
        second = _exec_result(vector)
        expected_outcome = vector["expect"]["outcome"]
        assert first["valid"] is (expected_outcome == "in_bounds"), vector["id"]
        assert first["outcome_binding"]["outcome"] == expected_outcome, vector["id"]
        assert first["result_digest"] == vector["expect"]["result_digest"], vector["id"]
        assert second["result_digest"] == first["result_digest"], vector["id"]


def test_receipt_action_nonce_and_executor_key_bindings_fail_independently():
    expected = {
        "reject_resigned_receipt_id_swap": ("receipt_bound", "receipt_id_mismatch"),
        "reject_resigned_receipt_bytes_swap": (
            "receipt_digest_bound",
            "receipt_digest_mismatch",
        ),
        "reject_resigned_action_swap": ("action_bound", "action_hash_mismatch"),
        "reject_resigned_consumption_nonce_swap": (
            "consumption_bound",
            "consumption_nonce_mismatch",
        ),
        "reject_unpinned_executor": (
            "attestation_verified",
            "executor_key_not_pinned",
        ),
    }
    vectors = {vector["id"]: vector for vector in EXEC_SUITE["vectors"]}
    for vector_id, (check, error) in expected.items():
        result = _exec_result(vectors[vector_id])
        assert result["checks"][check] is False
        assert error in result["errors"]


def test_policy_is_an_additional_gate_and_never_replaces_signed_intent():
    vectors = {vector["id"]: vector for vector in EXEC_SUITE["vectors"]}
    signed_divergence = _exec_result(vectors["reject_signed_effect_divergence"])
    assert signed_divergence["outcome_binding"]["evaluations"][0]["source"] == "signed_receipt"
    assert signed_divergence["outcome_binding"]["evaluations"][0]["outcome"] == "divergent"

    tightened = _exec_result(vectors["reject_policy_tightening_divergence"])
    evaluations = tightened["outcome_binding"]["evaluations"]
    assert [(item["source"], item["outcome"]) for item in evaluations] == [
        ("signed_receipt", "in_bounds"),
        ("relying_party_policy", "divergent"),
    ]


def test_decimal_ordering_is_exact_beyond_floats_and_rejects_noncanonical_forms():
    assert compare_decimal_strings("9007199254740993", "9007199254740992") == 1
    assert compare_decimal_strings("0.1", "0.10") == 0
    assert compare_decimal_strings("-2", "-1.99") == -1
    assert compare_decimal_strings("-0", "0.000") == 0
    assert compare_decimal_strings("01", "1") is None
    assert compare_decimal_strings("1e3", "1000") is None


def test_closed_members_and_resource_limits_refuse_before_crypto_credit():
    common = EXEC_SUITE["common"]
    base = copy.deepcopy(EXEC_SUITE["vectors"][0]["attestation"])
    opts = {"executorKeys": common["executor_keys"], "now": common["now"]}

    hostile_top = copy.deepcopy(base)
    hostile_top["predicted_effects"] = []
    result = verify_outcome_attestation(hostile_top, opts)
    assert result["valid"] is False
    assert "malformed_outcome_attestation" in result["errors"]

    hostile_observed = copy.deepcopy(base)
    hostile_observed["observed_effects"][0]["ignored_limit"] = "999999.00"
    result = verify_outcome_attestation(hostile_observed, opts)
    assert result["valid"] is False
    assert "not an exact observed-effect object" in " ".join(result["errors"])

    oversized_observed = copy.deepcopy(base)
    oversized_observed["observed_effects"] = [
        {"effect_type": "payment", "target": "acct:x", "value": "1.00"}
        for _ in range(MAX_OBSERVED_EFFECTS + 1)
    ]
    result = verify_outcome_attestation(oversized_observed, opts)
    assert f"{MAX_OBSERVED_EFFECTS}-entry limit" in " ".join(result["errors"])

    oversized_value = copy.deepcopy(base)
    oversized_value["observed_effects"][0]["value"] = "x" * (
        MAX_EFFECT_STRING_LENGTH + 1
    )
    result = verify_outcome_attestation(oversized_value, opts)
    assert "bounded string" in " ".join(result["errors"])

    too_many_predictions = [
        {
            "effect_type": "payment",
            "target": f"acct:{index}",
            "predicate": {"op": "absent"},
        }
        for index in range(MAX_PREDICTED_EFFECTS + 1)
    ]
    prediction_result = validate_predicted_effects(too_many_predictions)
    assert prediction_result["ok"] is False
    assert f"{MAX_PREDICTED_EFFECTS}-entry limit" in " ".join(
        prediction_result["reasons"]
    )


def test_unknown_predicate_and_observation_members_are_not_ignored():
    prediction = [
        {
            "effect_type": "payment",
            "target": "acct:a",
            "predicate": {"op": "lte", "value": "1", "tolerance": "0.1"},
        }
    ]
    assert validate_predicted_effects(prediction)["ok"] is False
    result = evaluate_predicted_effects(
        [{"effect_type": "payment", "target": "acct:a", "predicate": {"op": "lte", "value": "1"}}],
        [{"effect_type": "payment", "target": "acct:a", "value": "1", "ignored": "2"}],
    )
    assert result["outcome"] == "incomparable"
    assert "unknown member" in " ".join(result["reasons"])
