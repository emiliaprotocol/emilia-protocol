# SPDX-License-Identifier: Apache-2.0
# AEC -08 requirement expressions over the frozen corpus
# conformance/vectors/aec-expression.v1.json (the file the JS and Go tests run).
# This covers requirement-expression evaluation and the legacy
# verify_authorization_chain wrapper only. This package does not implement the
# structured -07/-08 requirement and replay contract, and passing these cases
# is not a claim that it does.
import hashlib
import json
import os

from emilia_verify import (action_digest, compile_aec_requirement_expression,
                           evaluate_aec_requirement_expression, verify_authorization_chain)

HERE = os.path.dirname(__file__)
CORPUS_DIR = os.path.join(HERE, "..", "..", "..", "conformance", "vectors")
with open(os.path.join(CORPUS_DIR, "aec-expression.v1.json"), "rb") as fh:
    CORPUS_BYTES = fh.read()
CORPUS = json.loads(CORPUS_BYTES)
ASSERTIONS = ("syntax", "invalid_class", "value", "result", "canonical_parse", "parse_identity")
ACTION = {"action_type": "payment.release", "amount": 100}
DIGEST = "sha256:" + action_digest(ACTION)


def test_corpus_is_frozen():
    with open(os.path.join(CORPUS_DIR, "aec-expression.v1.SHA256SUMS"), encoding="ascii") as fh:
        sums = fh.read()
    assert sums == hashlib.sha256(CORPUS_BYTES).hexdigest() + "  aec-expression.v1.json\n"
    assert CORPUS["evaluator_revision"] == "EP-AEC-EVALUATOR-08-v1"


def test_each_assertion_separately():
    failures = []
    for v in CORPUS["vectors"]:
        got = evaluate_aec_requirement_expression(v["aec_expression"]["expression"], v["aec_expression"]["eligible_types"])
        assert sorted(got) == sorted(ASSERTIONS)
        failures += [f'{v["id"]}.{k}' for k in ASSERTIONS if got[k] != v["expect"][k]]
    assert failures == []


def test_compiled_tree_is_reused():
    compiled = compile_aec_requirement_expression("a OR b AND c")
    assert compiled.canonical_parse == "((a OR b) AND c)"
    assert compiled.token_count == 5
    assert compiled.evaluate({"a"})["value"] is False
    assert compiled.evaluate({"a", "c"})["value"] is True
    refused = compile_aec_requirement_expression("a OR (b AND)")
    assert (refused.valid, refused.invalid_class, refused.parse_identity) == (False, "syntax", None)


def test_legacy_wrapper_over_corpus():
    def stub(ev, ctx):
        return {"valid": True, "action_digest": ev.get("action_digest")}
    for v in CORPUS["vectors"]:
        expr = v["aec_expression"]["expression"]
        eligible = v["aec_expression"]["eligible_types"]
        if len(eligible) > 64 or any(len(t) > 128 for t in eligible):
            continue  # the legacy wrapper caps components and type length
        comps = [{"type": t, "evidence": {"action_digest": DIGEST}} for t in eligible] or \
            [{"type": "unrelated", "evidence": {"action_digest": DIGEST}}]
        r = verify_authorization_chain({"@version": "EP-AEC-v1", "action": ACTION, "components": comps},
                                       verifiers={t: stub for t in eligible + ["unrelated"]},
                                       requirement=expr, expected_action_digest=DIGEST)
        assert r["satisfied"] is (v["expect"]["value"] is True), v["id"]


def test_legacy_pinned_requirement_is_not_trimmed():
    def stub(ev, ctx):
        return {"valid": True, "action_digest": ev.get("action_digest")}
    chain = {"@version": "EP-AEC-v1", "action": ACTION, "components": [{"type": "a", "evidence": {"action_digest": DIGEST}}]}

    def run(req):
        return verify_authorization_chain(chain, verifiers={"a": stub}, requirement=req, expected_action_digest=DIGEST)
    assert run(" \ta\r\n")["satisfied"] is True
    for padded in ("\u00a0a", "a\u00a0", "\u2028a", "\ufeffa", "a\u000b", "\u000ca"):
        r = run(padded)
        assert r["satisfied"] is False, repr(padded)
        assert r["requirement_source"] == "relying_party"
    assert "requirement expression exceeds size limit" in run("a" * 4095 + "\u00a0")["reasons"]
