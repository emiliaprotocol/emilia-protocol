#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import copy
import json
import os
import sys

from mapping import compare_mapped_actions, mapping_profile_hash

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.abspath(os.path.join(HERE, "..", "..", "conformance", "mapping-vectors.json"))


def _segments(pointer):
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _mutate(root, operation):
    parts = _segments(operation["path"])
    parent = root
    for part in parts[:-1]:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    key = int(parts[-1]) if isinstance(parent, list) else parts[-1]
    if operation["op"] == "delete":
        if isinstance(parent, list):
            parent.pop(key)
        else:
            del parent[key]
    elif operation["op"] == "set":
        parent[key] = copy.deepcopy(operation["value"])
    else:
        raise ValueError("unsupported vector mutation: " + operation["op"])


def _build_side(corpus, descriptor):
    profile = copy.deepcopy(corpus["profiles"][descriptor["profile"]])
    return {
        "source": copy.deepcopy(corpus["sources"][descriptor["source"]]),
        "profile": profile,
        "source_descriptor": copy.deepcopy(profile["source_format"]),
        "expected_profile_hash": (
            mapping_profile_hash(profile) if descriptor["pin"] == "profile" else descriptor["pin"]
        ),
        "native_verified": descriptor.get("native_verified", True),
    }


def run_mapping_vectors(corpus):
    results = []
    for vector in corpus["vectors"]:
        left = _build_side(corpus, vector["left"])
        right = _build_side(corpus, vector["right"])
        for operation in vector.get("mutations", []):
            side = left if operation["side"] == "left" else right
            _mutate(side[operation["target"]], operation)
        for side_name in vector.get("repin_after_mutation", []):
            side = left if side_name == "left" else right
            side["expected_profile_hash"] = mapping_profile_hash(side["profile"])
        result = compare_mapped_actions(
            left, right, definitions=corpus["definitions"], suite=corpus["suite"]
        )
        expected = vector["expect"]
        verdict_ok = result["verdict"] == expected["verdict"]
        if "reason_contains" in expected:
            reasons_ok = expected["reason_contains"] in result["reasons"]
        else:
            reasons_ok = result["reasons"] == expected.get("reasons", [])
        results.append(
            {
                "id": vector["id"],
                "pass": verdict_ok and reasons_ok,
                "verdict": result["verdict"],
                "reasons": result["reasons"],
            }
        )
    return results


with open(VECTORS, "r", encoding="utf-8") as handle:
    results = run_mapping_vectors(json.load(handle))

if "--json" in sys.argv:
    print(json.dumps(results, separators=(",", ":")))
else:
    for result in results:
        print(("PASS" if result["pass"] else "FAIL") + " " + result["id"] + " " + result["verdict"])

if any(not result["pass"] for result in results):
    raise SystemExit(1)
