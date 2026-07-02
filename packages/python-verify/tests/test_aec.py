# SPDX-License-Identifier: Apache-2.0
# EP-AEC composition conformance — Python runner over the shared conformance/vectors/aec.json
# (the same file the JS and Go runners use), proving cross-language agreement.
import copy
import json
import os

from emilia_verify import verify_authorization_chain, action_digest

HERE = os.path.dirname(__file__)
SUITE = json.load(open(os.path.join(HERE, "..", "..", "..", "conformance", "vectors", "aec.json")))
D = action_digest(SUITE["action"])
OTHER = "sha256:" + "f" * 64


def _subst(x):
    if x == "SAME":
        return "sha256:" + D
    if x == "OTHER":
        return OTHER
    return x


def _stub(ev, ctx):
    return {"valid": ev.get("valid") is not False, "action_digest": ev.get("action_digest")}


VERIFIERS = {t: _stub for t in SUITE["stub_types"]}


def _hydrate(chain):
    c = copy.deepcopy(chain)
    if "action" not in c:
        c["action"] = SUITE["action"]
    if "action_digest" in c:
        c["action_digest"] = _subst(c["action_digest"])
    for comp in c.get("components", []):
        ev = comp.get("evidence")
        if isinstance(ev, dict) and "action_digest" in ev:
            ev["action_digest"] = _subst(ev["action_digest"])
    return c


def test_aec_vectors():
    for v in SUITE["vectors"]:
        r = verify_authorization_chain(_hydrate(v["chain"]), verifiers=VERIFIERS,
                                       requirement=v.get("relying_party_requirement"))
        assert r["allow"] == v["expect_allow"], f'{v["name"]}: allow={r["allow"]}; {r["reasons"]}'
        if v.get("expect_requirement_source"):
            assert r["requirement_source"] == v["expect_requirement_source"], v["name"]
