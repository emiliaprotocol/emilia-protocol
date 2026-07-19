# SPDX-License-Identifier: Apache-2.0
# Python conformance runner: emits exact typed result rows. argv[1] = vectors path.
# Polymorphic: receipt (document) | signoff | quorum.
import sys, json, os, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "packages", "python-verify"))
from emilia_verify import (verify_receipt, verify_webauthn_signoff, verify_quorum,
                            verify_revocation, verify_time_attestation, verify_trust_receipt,
                            verify_provenance_offline, verify_evidence_record,
                            canonicalize, is_canonicalizable,
                            evaluate_currency, validate_initiator_attestation,
                            verify_consumption_proof, require_witness_quorum,
                            verify_timestamp_proof, verify_authorization_chain,
                            verify_resolution_receipt,
                            verify_authority_proof_via_document,
                            evaluate_predicted_effects, predicted_effects_digest,
                            trust_receipt_digest, verify_outcome_binding)
# EP-CANONICALIZATION-v1 differential branch. Same gate as the JS runner
# (conformance/runners/strict-json.mjs) and the Go runner: standard parse, then
# duplicate member names / unpaired surrogates / depth > 64 reject, then the EP
# I-JSON profile predicate, then SHA-256 over the UTF-8 canonical bytes compared
# to the pinned digest. Python's json module decodes valid surrogate-pair
# escapes into astral code points and leaves UNPAIRED surrogates in the str, so
# the surrogate gate scans decoded strings; duplicate names are caught with
# object_pairs_hook (decoded names, per RFC 8785 s3.1). Fail-closed throughout.
_CANON_MAX_DEPTH = 64

def _canon_dup_hook(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError("duplicate object member name")
        seen.add(k)
    return dict(pairs)

def _canon_lone_surrogate(v):
    if isinstance(v, str):
        return any(0xD800 <= ord(ch) <= 0xDFFF for ch in v)
    if isinstance(v, dict):
        return any(_canon_lone_surrogate(k) or _canon_lone_surrogate(x) for k, x in v.items())
    if isinstance(v, list):
        return any(_canon_lone_surrogate(x) for x in v)
    return False

def _canon_depth(v):
    if isinstance(v, dict):
        return 1 + max([_canon_depth(x) for x in v.values()] + [0])
    if isinstance(v, list):
        return 1 + max([_canon_depth(x) for x in v] + [0])
    return 0

with open(sys.argv[1], encoding="utf-8") as corpus_file:
    corpus = json.loads(corpus_file.read(), object_pairs_hook=_canon_dup_hook)
if _canon_lone_surrogate(corpus) or _canon_depth(corpus) > _CANON_MAX_DEPTH:
    raise ValueError("strict corpus JSON refused")
vectors = corpus.get("vectors")
if not isinstance(vectors, list):
    raise ValueError("conformance corpus must contain a vectors array")
common = corpus.get("common") if isinstance(corpus.get("common"), dict) else {}

def run_canonicalization(c):
    if not isinstance(c, dict):
        return False
    raw = c.get("input_json")
    if not isinstance(raw, str):
        return False
    try:
        value = json.loads(raw, object_pairs_hook=_canon_dup_hook)
    except Exception:
        return False
    if _canon_lone_surrogate(value) or _canon_depth(value) > _CANON_MAX_DEPTH:
        return False
    if not is_canonicalizable(value):
        return False
    digest = hashlib.sha256(canonicalize(value).encode("utf-8", "strict")).hexdigest()
    return digest == c.get("expected_digest")

def _digest(value):
    return "sha256:" + hashlib.sha256(
        canonicalize(value).encode("utf-8", "strict")
    ).hexdigest()

def _valid(value):
    return {"valid": bool(value)}

def _authority_result(v):
    result = dict(verify_authority_proof_via_document(
        v["proof"], v["docs"], v["opts"]
    ))
    result.pop("limitations", None)
    result["proof_input_digest"] = _digest(v["proof"])
    result["document_chain_digest"] = _digest(v["docs"])
    result["result_digest"] = _digest(result)
    return result

def _revocation_result(v):
    result = verify_revocation(v["target"], v["revocation"], {
        "revokerKeys": v.get("revoker_keys"),
        "maxAgeSeconds": v.get("max_age_seconds"),
        "now": v.get("now"),
    })
    exact = {
        "valid": result["valid"],
        "checks": result["checks"],
        "reasons": [
            check for check, passed in result["checks"].items() if not passed
        ],
        "target_digest": _digest(v["target"]),
        "revocation_digest": _digest(v["revocation"]),
    }
    return {**exact, "result_digest": _digest(exact)}

def _outcome_exec_result(v):
    outcome_opts = {
        "receiptOptions": common.get("receipt_options"),
        "executorKeys": v.get("executor_keys", common.get("executor_keys")),
        "now": common.get("now"),
    }
    if "policy_predicted_effects" in v:
        outcome_opts["policyPredictedEffects"] = v.get("policy_predicted_effects")
    result = verify_outcome_binding(common["receipt"], v["attestation"], outcome_opts)
    return {
        "outcome": result["outcome_binding"]["outcome"],
        "valid": result["valid"],
        "checks": result["checks"],
        "reasons": result["outcome_binding"]["reasons"],
        "receipt_digest": trust_receipt_digest(common["receipt"]),
        "attestation_digest": _digest(v["attestation"]),
        "result_digest": result["result_digest"],
    }

_GRAPH_ACTION = "sha256:" + ("a" * 64)

def _outcome_graph_result(v):
    attestation = v.get("attestation") if isinstance(v.get("attestation"), dict) else {}
    approved = v.get("approved") if isinstance(v.get("approved"), dict) else None
    policy = v.get("policy") if isinstance(v.get("policy"), dict) else {}
    reasons = []
    approval_bound = (
        approved is not None
        and (
            "action_digest" not in approved
            or approved.get("action_digest") == _GRAPH_ACTION
        )
    )

    if "observed_effects" in attestation:
        if not approval_bound or not isinstance(approved.get("predicted_effects"), list):
            reasons.append("effect_commitment_missing")
        else:
            bound = approved.get("predicted_effects_digest")
            if bound != predicted_effects_digest(approved["predicted_effects"]):
                reasons.append("effect_incomparable")
            else:
                evaluated = evaluate_predicted_effects(
                    approved["predicted_effects"], attestation.get("observed_effects")
                )
                if evaluated["outcome"] == "divergent":
                    reasons.append("effect_divergence")
                elif evaluated["outcome"] == "incomparable":
                    reasons.append("effect_incomparable")
        if "predicted_effects" in policy:
            policy_predictions = policy.get("predicted_effects")
            if not isinstance(policy_predictions, list):
                reasons.append("effect_incomparable")
            else:
                evaluated = evaluate_predicted_effects(
                    policy_predictions, attestation.get("observed_effects")
                )
                if evaluated["outcome"] == "divergent":
                    reasons.append("effect_divergence")
                elif evaluated["outcome"] == "incomparable":
                    reasons.append("effect_incomparable")

    if "observed_effect_digest" in attestation:
        if not approval_bound:
            reasons.append("effect_commitment_missing")
        elif not isinstance(approved.get("committed_effect_digest"), str):
            reasons.append("effect_commitment_missing")
        elif approved["committed_effect_digest"].lower() != str(
            attestation.get("observed_effect_digest")
        ).lower():
            reasons.append("effect_divergence")

    return {
        "verdict": "conflicted" if reasons else "admissible",
        **({"reasons": reasons} if v.get("expect", {}).get("reason_contains") else {}),
    }

def _run(v):
    if "proof" in v and "docs" in v and "opts" in v:
        return _authority_result(v)
    if v.get("kind") == "predicate" and "predicted_effects" in v:
        result = evaluate_predicted_effects(
            v.get("predicted_effects"), v.get("observed_effects")
        )
        return {
            "outcome": result["outcome"],
            **({"reasons": result["reasons"]}
               if v.get("expect", {}).get("reason_contains") else {}),
        }
    if v.get("kind") == "graph":
        return _outcome_graph_result(v)
    if "attestation" in v and isinstance(common.get("receipt"), dict):
        return _outcome_exec_result(v)
    if "document" in v: return _valid(verify_receipt(v["document"], v["public_key"]).valid)
    if "resolution_receipt" in v or "resolution_authorization" in v:
        receipt = v.get("resolution_receipt", v.get("resolution_authorization"))
        resolution_opts = {
            "bindingMoment": v.get("binding_moment"),
            "expectedActionHash": v.get("expected_action_hash"),
            "principalKeys": v.get("principal_keys"),
            "rpId": v.get("rp_id"),
            "allowedOrigins": v.get("allowed_origins"),
        }
        for wire_name, option_name in (
            ("expected_selected_option", "expectedSelectedOption"),
            ("expected_nonce", "expectedNonce"),
            ("expected_initiator", "expectedInitiator"),
            ("evaluation_time", "evaluationTime"),
        ):
            if wire_name in v:
                resolution_opts[option_name] = v.get(wire_name)
        result = verify_resolution_receipt(receipt, resolution_opts)
        return _valid(bool(result["valid"] and result["authorizes_action"]) if "resolution_authorization" in v else result["valid"])
    if "signoff" in v: return _valid(verify_webauthn_signoff(v["signoff"], v["approver_public_key"], {"rpId": v.get("rp_id"), "allowedOrigins": v.get("allowed_origins")})["valid"])
    if "quorum" in v: return _valid(verify_quorum(v["quorum"], {"rpId": "emiliaprotocol.ai", "allowedOrigins": ["https://www.emiliaprotocol.ai"]})["valid"])
    if "revocation" in v:
        if "result_digest" in v.get("expect", {}):
            return _revocation_result(v)
        return _valid(verify_revocation(v["target"], v["revocation"], {
            "revokerKeys": v.get("revoker_keys"),
            "maxAgeSeconds": v.get("max_age_seconds"),
            "now": v.get("now"),
        })["valid"])
    if "time_attestation" in v: return _valid(verify_time_attestation(v["time_attestation"], {"tsaKeys": v.get("tsa_keys"), "expectedHash": v.get("expected_hash"), "notBefore": v.get("not_before"), "notAfter": v.get("not_after")})["valid"])
    if "trust_receipt" in v: return _valid(verify_trust_receipt(v["trust_receipt"], {"approverKeys": v["verification"]["approver_keys"], "logPublicKey": v["verification"]["log_public_key"], **(v.get("verify_opts") or {})})["valid"])
    if "provenance_chain" in v: return _valid(verify_provenance_offline(v["provenance_chain"], {"delegationKeys": v.get("delegation_keys"), "rootVerification": v.get("root_verification"), "actionVerification": v.get("action_verification"), "now": v.get("now_ms")})["valid"])
    if "evidence_record" in v: return _valid(verify_evidence_record(v["evidence_record"], {"tsaKeys": v.get("tsa_keys"), "protectedHash": v.get("protected_hash")})["valid"])
    if "canonicalization" in v: return _valid(run_canonicalization(v["canonicalization"]))
    # EP-CURRENCY-v1: valid iff the two-valued currency status equals expect_status.
    if "currency" in v: return _valid(evaluate_currency(v["currency"]["args"])["currency_at_T"]["status"] == v["currency"]["expect_status"])
    # EP-INITIATOR-ATTESTATION-v1: valid iff the attestation validates (fail-closed).
    if "initiator_attestation" in v: return _valid(validate_initiator_attestation(v["initiator_attestation"])["ok"])
    # EP-SMT-CONSUME-v1: valid iff the sparse-Merkle absent->present transition verifies.
    if "consumption_proof" in v: return _valid(verify_consumption_proof(v["consumption_proof"])["valid"])
    # EP-WITNESS-v1: valid iff k distinct pinned witnesses validly cosigned the head.
    if "witness_quorum" in v:
        w = v["witness_quorum"]
        return _valid(require_witness_quorum(w["checkpoint"], w["cosignatures"], w["pinned"], w["k"])["ok"])
    # EP-TIMESTAMP-PROOF-v1 (RFC 3161): valid iff the pinned TSA's TimeStampToken
    # verifies over the expected digest (fail-closed on any refusal).
    if "timestamp_proof" in v:
        return _valid(verify_timestamp_proof(v["timestamp_proof"], v.get("expected_digest"), v.get("pinned_tsa_keys"))["verified"])
    # EP-AEC-ROLE-v1: valid iff the evidence requirement is SATISFIED, with the built-in
    # ep-receipt using role-scoped pins (keys_by_type) and a permissive stub for each
    # stub_type. Exercises real signatures, role scoping, and signed action binding.
    if "aec_chain" in v:
        def _stub(ev, ctx):
            return {"valid": (ev or {}).get("valid") is not False, "action_digest": (ev or {}).get("action_digest")}
        verifiers = {t: _stub for t in (v.get("stub_types") or [])}
        return _valid(verify_authorization_chain(v["aec_chain"], verifiers=verifiers,
                                                keys_by_type=v.get("keys_by_type"),
                                                policies_by_type=v.get("policies_by_type"),
                                                requirement=v.get("requirement"),
                                                expected_action_digest=v.get("expected_action_digest"),
                                                verification_time=v.get("verification_time"))["satisfied"])
    return _valid(False)

def run(v):
    # A conformance verifier must turn every hostile input into a typed refusal,
    # never terminate the whole batch. Individual library functions are also
    # hardened, but this boundary is the final availability guard.
    try:
        return _run(v)
    except Exception:
        return _valid(False)
print(json.dumps([{"id": v["id"], **run(v)} for v in vectors]))
