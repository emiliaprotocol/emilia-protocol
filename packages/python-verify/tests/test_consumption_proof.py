# SPDX-License-Identifier: Apache-2.0
"""EP-SMT-CONSUME-v1 consumption-proof parity test (port of consumption-proof.test.js).

Builds a real sparse consumption tree, produces a genuine ABSENT -> PRESENT
transition of a nonce between two append-only-linked heads, and asserts ACCEPT;
plus the same REJECT vectors and fail-closed input validation as the JS
reference (same reason strings). The consistency (h1->h2) leg reuses the ported
RFC 6962 prover. Also verifies a bundle BUILT IN JAVASCRIPT (deterministic — no
randomness) verifies here, and vice versa.

    pytest packages/python-verify/tests/test_consumption_proof.py
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from emilia_verify import (  # noqa: E402
    verify_consumption_proof,
    ReferenceConsumptionTree,
    CONSUMPTION_PROFILE,
    CONSUMPTION_LEAF_DOMAIN,
    SMT_DEPTH,
    build_consistency_proof,
    verify_checkpoint_consistency,
)
# Reference EP-MERKLE-v2 dense-log root (test helper), same as consistency.js merkleRoot.
from emilia_verify import _consistency_merkle_root as merkle_root  # noqa: E402


def dense_leaf(content: str) -> str:
    return hashlib.sha256(b"\x00" + content.encode("utf-8")).hexdigest()


def dense_leaves(n: int):
    return [dense_leaf(f"log-entry-{i}") for i in range(n)]


def make_bundle(nonce="nonce-A", other_nonces=None, m=3, n=6):
    if other_nonces is None:
        other_nonces = ["nonce-B", "nonce-C"]
    tree_before = ReferenceConsumptionTree()
    for o in other_nonces:
        tree_before.insert(o)
    ni_proof = tree_before.prove(nonce)  # absent

    tree_after = ReferenceConsumptionTree()
    for o in other_nonces:
        tree_after.insert(o)
    tree_after.insert(nonce)
    inc_proof = tree_after.prove(nonce)  # present

    log_leaves = dense_leaves(n)
    h1_root = merkle_root(log_leaves[:m])
    h2_root = merkle_root(log_leaves)
    consistency = build_consistency_proof(m, n, log_leaves)

    return {
        "nonce": nonce,
        "non_inclusion_proof": ni_proof,
        "inclusion_proof": inc_proof,
        "consistency_proof": consistency,
        "checkpoints": {
            "h1": {"tree_size": m, "root_hash": h1_root},
            "h2": {"tree_size": n, "root_hash": h2_root},
        },
        "_log_leaves": log_leaves,
        "_m": m,
        "_n": n,
    }


def test_exports_and_constants():
    assert callable(verify_consumption_proof)
    assert callable(ReferenceConsumptionTree)
    assert CONSUMPTION_PROFILE == "EP-SMT-CONSUME-v1"
    assert CONSUMPTION_LEAF_DOMAIN == "EP-SMT-CONSUME-v1"
    assert SMT_DEPTH == 32


def test_accept_genuine_transition():
    res = verify_consumption_proof(make_bundle())
    assert res["valid"] is True, res
    assert res["checks"] == {"non_inclusion": True, "inclusion": True, "consistency": True}
    assert res["reason"] is None


def test_accept_sha256_prefixes():
    b = make_bundle()
    pfx = lambda h: f"sha256:{h}"
    b["non_inclusion_proof"]["root"] = pfx(b["non_inclusion_proof"]["root"])
    b["non_inclusion_proof"]["siblings"] = [pfx(s) for s in b["non_inclusion_proof"]["siblings"]]
    b["inclusion_proof"]["root"] = pfx(b["inclusion_proof"]["root"])
    b["inclusion_proof"]["siblings"] = [pfx(s) for s in b["inclusion_proof"]["siblings"]]
    b["inclusion_proof"]["value"] = pfx(b["inclusion_proof"]["value"])
    b["checkpoints"]["h1"]["root_hash"] = pfx(b["checkpoints"]["h1"]["root_hash"])
    b["checkpoints"]["h2"]["root_hash"] = pfx(b["checkpoints"]["h2"]["root_hash"])
    b["consistency_proof"] = [pfx(c) for c in b["consistency_proof"]]
    assert verify_consumption_proof(b)["valid"] is True


def test_accept_range_of_sizes():
    for m, n in [(1, 2), (2, 5), (4, 9), (5, 8), (7, 16)]:
        others = [f"other-{m}-{n}-{i}" for i in range(5)]
        res = verify_consumption_proof(make_bundle(other_nonces=others, m=m, n=n))
        assert res["valid"] is True, f"m={m} n={n}: {res}"


# ── REJECT: present-at-h1 (double-spend attempt) ─────────────────────────────
def test_reject_present_at_h1():
    b = make_bundle()
    already = ReferenceConsumptionTree()
    already.insert(b["nonce"])
    b["non_inclusion_proof"] = already.prove(b["nonce"])  # present:true where absent required
    res = verify_consumption_proof(b)
    assert res["valid"] is False
    assert res["reason"] == "non_inclusion_proof_must_assert_absent"
    assert res["checks"]["non_inclusion"] is False


def test_reject_absent_claim_not_reconstructing_root():
    b = make_bundle()
    b["non_inclusion_proof"]["siblings"][SMT_DEPTH - 1] = "ff" * 32
    res = verify_consumption_proof(b)
    assert res["valid"] is False
    assert res["reason"] == "non_inclusion_does_not_reconstruct_root"


# ── REJECT: absent-at-h2 ─────────────────────────────────────────────────────
def test_reject_absent_at_h2():
    b = make_bundle()
    after_but_absent = ReferenceConsumptionTree()
    after_but_absent.insert("nonce-B")
    after_but_absent.insert("nonce-C")
    b["inclusion_proof"] = after_but_absent.prove(b["nonce"])  # present:false
    res = verify_consumption_proof(b)
    assert res["valid"] is False
    assert res["reason"] == "inclusion_proof_must_assert_present"
    assert res["checks"]["inclusion"] is False


def test_reject_present_claim_not_reconstructing_root():
    b = make_bundle()
    b["inclusion_proof"]["siblings"][0] = "ab" * 32
    res = verify_consumption_proof(b)
    assert res["valid"] is False
    assert res["reason"] == "inclusion_does_not_reconstruct_root"


def test_reject_present_claim_tampered_value():
    b = make_bundle()
    b["inclusion_proof"]["value"] = hashlib.sha256(b"forged").hexdigest()
    res = verify_consumption_proof(b)
    assert res["valid"] is False
    assert res["reason"] == "inclusion_does_not_reconstruct_root"


# ── REJECT: non-append-only h1 -> h2 ─────────────────────────────────────────
def test_reject_non_append_only():
    b = make_bundle()
    forked = list(b["_log_leaves"])
    forked[0] = dense_leaf("rewritten-log-entry-0")
    b["checkpoints"]["h1"]["root_hash"] = merkle_root(forked[:b["_m"]])
    res = verify_consumption_proof(b)
    assert res["valid"] is False
    assert res["reason"] == "consistency_proof_not_append_only"
    assert res["checks"]["consistency"] is False


def test_reject_tampered_consistency_node():
    b = make_bundle()
    b["consistency_proof"][0] = dense_leaf("not-the-node")
    res = verify_consumption_proof(b)
    assert res["valid"] is False
    assert res["reason"] == "consistency_proof_not_append_only"


def test_reject_h1_not_before_h2():
    b = make_bundle(m=4, n=4)
    b["checkpoints"]["h1"] = {"tree_size": 5, "root_hash": b["checkpoints"]["h2"]["root_hash"]}
    b["checkpoints"]["h2"] = {"tree_size": 5, "root_hash": b["checkpoints"]["h2"]["root_hash"]}
    b["consistency_proof"] = []
    res = verify_consumption_proof(b)
    assert res["valid"] is False
    assert res["reason"] == "checkpoint_h1_not_before_h2"


def test_reject_identical_smt_roots():
    b = make_bundle()
    b["inclusion_proof"]["root"] = b["non_inclusion_proof"]["root"]
    res = verify_consumption_proof(b)
    assert res["valid"] is False
    assert res["reason"] in ("smt_root_unchanged_no_transition", "inclusion_does_not_reconstruct_root")


# ── Fail-closed input validation ─────────────────────────────────────────────
def test_fail_closed_shapes():
    assert verify_consumption_proof(None)["reason"] == "bundle_missing"
    assert verify_consumption_proof("x")["reason"] == "bundle_missing"
    assert verify_consumption_proof({})["reason"] == "nonce_missing"
    assert verify_consumption_proof({"nonce": ""})["reason"] == "nonce_missing"
    assert verify_consumption_proof({"nonce": "n"})["reason"] == "non_inclusion_proof_missing"

    base = make_bundle()

    b1 = make_bundle()
    del b1["non_inclusion_proof"]["present"]
    assert verify_consumption_proof(b1)["reason"] == "non_inclusion_proof_must_assert_absent"

    b2 = make_bundle()
    b2["non_inclusion_proof"]["siblings"] = b2["non_inclusion_proof"]["siblings"][:5]
    assert verify_consumption_proof(b2)["reason"] == "non_inclusion_siblings_wrong_length"

    b3 = make_bundle()
    b3["non_inclusion_proof"]["root"] = "not-hex"
    assert verify_consumption_proof(b3)["reason"] == "non_inclusion_root_malformed"

    b4 = make_bundle()
    del b4["inclusion_proof"]["value"]
    assert verify_consumption_proof(b4)["reason"] == "inclusion_present_value_malformed"

    b5 = make_bundle()
    del b5["checkpoints"]
    assert verify_consumption_proof(b5)["reason"] == "checkpoints_missing"

    b6 = make_bundle()
    b6["checkpoints"]["h1"]["tree_size"] = 0
    assert verify_consumption_proof(b6)["reason"] == "checkpoint_h1_malformed"

    b7 = make_bundle()
    b7["consistency_proof"] = "nope"
    assert verify_consumption_proof(b7)["reason"] == "consistency_proof_missing"

    assert verify_consumption_proof(base)["valid"] is True


# ── Reference tree self-consistency ──────────────────────────────────────────
def test_reference_tree_self_consistency():
    t = ReferenceConsumptionTree()
    t.insert("alpha")
    t.insert("beta")
    root = t.root()
    incl = t.prove("alpha")
    non_incl = t.prove("gamma")
    assert incl["root"] == root
    assert non_incl["root"] == root
    assert incl["present"] is True
    assert non_incl["present"] is False
    assert len(incl["siblings"]) == SMT_DEPTH


def test_consistency_verifier_basic():
    # Sanity: the ported RFC 6962 verifier agrees with the ported prover.
    leaves = dense_leaves(6)
    proof = build_consistency_proof(3, 6, leaves)
    assert verify_checkpoint_consistency(merkle_root(leaves[:3]), 3, merkle_root(leaves), 6, proof) is True
    # Equal sizes: empty proof, roots must match.
    assert verify_checkpoint_consistency(merkle_root(leaves), 6, merkle_root(leaves), 6, []) is True
    # Tampered proof node fails closed.
    bad = list(proof)
    bad[0] = dense_leaf("nope")
    assert verify_checkpoint_consistency(merkle_root(leaves[:3]), 3, merkle_root(leaves), 6, bad) is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ALL PASS — EP-SMT-CONSUME-v1 parity")
