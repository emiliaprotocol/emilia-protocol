# SPDX-License-Identifier: Apache-2.0
# Python conformance runner: emits [{id, valid}] per vector. argv[1] = vectors path.
# Polymorphic: receipt (document) | signoff | quorum.
import sys, json, os, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "packages", "python-verify"))
from emilia_verify import (verify_receipt, verify_webauthn_signoff, verify_quorum,
                            verify_revocation, verify_time_attestation, verify_trust_receipt,
                            verify_provenance_offline, verify_evidence_record,
                            canonicalize, is_canonicalizable,
                            evaluate_currency, validate_initiator_attestation,
                            verify_consumption_proof, require_witness_quorum,
                            verify_timestamp_proof, verify_authorization_chain)
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
def _run(v):
    if "document" in v: return verify_receipt(v["document"], v["public_key"]).valid
    if "signoff" in v: return verify_webauthn_signoff(v["signoff"], v["approver_public_key"], {"rpId": v.get("rp_id")})["valid"]
    if "quorum" in v: return verify_quorum(v["quorum"], {"rpId": "emiliaprotocol.ai"})["valid"]
    if "revocation" in v: return verify_revocation(v["target"], v["revocation"], {"revokerKeys": v.get("revoker_keys"), "maxAgeSeconds": v.get("max_age_seconds"), "now": v.get("now")})["valid"]
    if "time_attestation" in v: return verify_time_attestation(v["time_attestation"], {"tsaKeys": v.get("tsa_keys"), "expectedHash": v.get("expected_hash"), "notBefore": v.get("not_before"), "notAfter": v.get("not_after")})["valid"]
    if "trust_receipt" in v: return verify_trust_receipt(v["trust_receipt"], {"approverKeys": v["verification"]["approver_keys"], "logPublicKey": v["verification"]["log_public_key"], **(v.get("verify_opts") or {})})["valid"]
    if "provenance_chain" in v: return verify_provenance_offline(v["provenance_chain"], {"delegationKeys": v.get("delegation_keys"), "now": v.get("now_ms")})["valid"]
    if "evidence_record" in v: return verify_evidence_record(v["evidence_record"], {"tsaKeys": v.get("tsa_keys"), "protectedHash": v.get("protected_hash")})["valid"]
    if "canonicalization" in v: return run_canonicalization(v["canonicalization"])
    # EP-CURRENCY-v1: valid iff the two-valued currency status equals expect_status.
    if "currency" in v: return evaluate_currency(v["currency"]["args"])["currency_at_T"]["status"] == v["currency"]["expect_status"]
    # EP-INITIATOR-ATTESTATION-v1: valid iff the attestation validates (fail-closed).
    if "initiator_attestation" in v: return validate_initiator_attestation(v["initiator_attestation"])["ok"]
    # EP-SMT-CONSUME-v1: valid iff the sparse-Merkle absent->present transition verifies.
    if "consumption_proof" in v: return verify_consumption_proof(v["consumption_proof"])["valid"]
    # EP-WITNESS-v1: valid iff k distinct pinned witnesses validly cosigned the head.
    if "witness_quorum" in v:
        w = v["witness_quorum"]
        return require_witness_quorum(w["checkpoint"], w["cosignatures"], w["pinned"], w["k"])["ok"]
    # EP-TIMESTAMP-PROOF-v1 (RFC 3161): valid iff the pinned TSA's TimeStampToken
    # verifies over the expected digest (fail-closed on any refusal).
    if "timestamp_proof" in v:
        return verify_timestamp_proof(v["timestamp_proof"], v.get("expected_digest"), v.get("pinned_tsa_keys"))["verified"]
    # EP-AEC-ROLE-v1: valid iff verify_authorization_chain ALLOWs, with the built-in
    # ep-receipt using role-scoped pins (keys_by_type) and a permissive stub for each
    # stub_type. Exercises real signatures, role scoping, and signed action binding.
    if "aec_chain" in v:
        def _stub(ev, ctx):
            return {"valid": (ev or {}).get("valid") is not False, "action_digest": (ev or {}).get("action_digest")}
        verifiers = {t: _stub for t in (v.get("stub_types") or [])}
        return verify_authorization_chain(v["aec_chain"], verifiers=verifiers,
                                          keys_by_type=v.get("keys_by_type"),
                                          requirement=v.get("requirement"))["allow"]
    return False

def run(v):
    # A conformance verifier must turn every hostile input into a typed refusal,
    # never terminate the whole batch. Individual library functions are also
    # hardened, but this boundary is the final availability guard.
    try:
        return bool(_run(v))
    except Exception:
        return False
print(json.dumps([{"id": v["id"], "valid": run(v)} for v in vectors]))
