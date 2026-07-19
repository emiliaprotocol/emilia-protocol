# run_vectors.py - runs every vector in conformance/vectors.json against
# caid.py. Prints pass/fail per vector and exits nonzero on any failure.
#
# Usage: python3 run_vectors.py
#
# Vector kinds:
#   compute - compute_caid(input.object, {suite: input.suite, definitions})
#   verify  - verify_caid(input.object, input.caid, {definitions})
#   parse   - parse_caid(input.caid)
#
# Optional per-vector "relation" cross-checks:
#   same_caid_as        - actual computed caid must equal that vector's
#   different_caid_from - actual computed caid must differ from that vector's

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from caid import compute_caid, verify_caid, parse_caid  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(HERE, "..", "..", "conformance", "vectors.json")

with open(VECTORS_PATH, "r", encoding="utf-8") as fh:
    suite = json.load(fh)


def deep_equal(a, b):
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


counts = {"pass": 0, "fail": 0}
actual_caids = {}  # id -> caid string (successful computes only)


def report(vector_id, ok, detail=None):
    if ok:
        counts["pass"] += 1
        print("PASS " + vector_id)
    else:
        counts["fail"] += 1
        print("FAIL " + vector_id)
        if detail:
            print("     " + detail)


for v in suite["vectors"]:
    kind = v.get("kind")
    if kind == "compute":
        actual = compute_caid(
            v["input"]["object"],
            {"suite": v["input"].get("suite"), "definitions": v["definitions"]},
        )
        if isinstance(actual, dict) and isinstance(actual.get("caid"), str):
            actual_caids[v["id"]] = actual["caid"]
    elif kind == "verify":
        actual = verify_caid(
            v["input"]["object"],
            v["input"]["caid"],
            {"definitions": v["definitions"]},
        )
    elif kind == "parse":
        actual = parse_caid(v["input"]["caid"])
    else:
        report(v["id"], False, "unknown vector kind: " + str(kind))
        continue
    ok = deep_equal(actual, v["expect"])
    report(
        v["id"],
        ok,
        None
        if ok
        else "expected "
        + json.dumps(v["expect"])
        + " got "
        + json.dumps(actual),
    )

# Relation cross-checks over ACTUAL computed values, not just the
# expectations written in the file.
for v in suite["vectors"]:
    relation = v.get("relation")
    if not relation:
        continue
    target_id = relation.get("same_caid_as") or relation.get("different_caid_from")
    mine = actual_caids.get(v["id"])
    theirs = actual_caids.get(target_id)
    if mine is None or theirs is None:
        report(v["id"] + " (relation)", False, "missing computed caid for relation")
        continue
    if relation.get("same_caid_as"):
        report(
            v["id"] + " same_caid_as " + target_id,
            mine == theirs,
            None if mine == theirs else mine + " != " + theirs,
        )
    else:
        report(
            v["id"] + " different_caid_from " + target_id,
            mine != theirs,
            None if mine != theirs else "caids unexpectedly equal: " + mine,
        )

print("")
print(
    "%d passed, %d failed, %d vectors"
    % (counts["pass"], counts["fail"], len(suite["vectors"]))
)
sys.exit(1 if counts["fail"] > 0 else 0)
