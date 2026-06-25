# SPDX-License-Identifier: Apache-2.0
# PIP-008 §2.1 — evaluate_agent_binding records relied-on agent evidence and
# enforces freshness. Mirrors packages/verify/agent-binding.test.js.
from emilia_verify import evaluate_agent_binding


def _ctx(observed_at=None, with_delegation=True):
    delegation = {"scheme": "WIMSE", "ref": "x"}
    if observed_at is not None:
        delegation["observed_at"] = observed_at
    binding = {"agent_id": "did:agent:42"}
    if with_delegation:
        binding["delegation"] = delegation
    return {"agent_binding": binding}


def test_absent_binding():
    r = evaluate_agent_binding({})
    assert r["present"] is False
    assert r["fresh"] is None
    assert r["reason"] == "no_agent_binding"


def test_records_evidence_without_freshness():
    r = evaluate_agent_binding(_ctx("2026-06-24T18:00:00Z"))
    assert r["present"] is True
    assert r["agent_id"] == "did:agent:42"
    assert r["delegation"]["scheme"] == "WIMSE"
    assert r["observed_at"] == "2026-06-24T18:00:00Z"
    assert r["fresh"] is None          # not evaluated without max_age_sec


def test_fresh_within_window():
    r = evaluate_agent_binding(_ctx("2026-06-24T18:00:00Z"), max_age_sec=600, at="2026-06-24T18:05:00Z")
    assert r["fresh"] is True
    assert r["age_seconds"] == 300


def test_stale_beyond_window():
    r = evaluate_agent_binding(_ctx("2026-06-24T18:00:00Z"), max_age_sec=60, at="2026-06-24T18:05:00Z")
    assert r["fresh"] is False
    assert "stale" in r["reason"]


def test_freshness_required_but_no_observed_at():
    r = evaluate_agent_binding(_ctx(None), max_age_sec=600)
    assert r["fresh"] is False
    assert r["reason"] == "freshness_required_but_no_observed_at"


def test_observed_at_in_future():
    r = evaluate_agent_binding(_ctx("2026-06-24T18:10:00Z"), max_age_sec=600, at="2026-06-24T18:00:00Z")
    assert r["fresh"] is False
    assert r["reason"] == "observed_at_in_future"


if __name__ == "__main__":  # run without pytest: python tests/test_agent_binding.py
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)}/{len(fns)} passed")
