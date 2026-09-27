#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Runs a CAID mapping corpus against mapping.py.

Usage: python3 run_mapping_vectors.py [--corpus PATH] [--json]

The corpus is read with this port's strict decoder. A vector's expectation
is a verdict plus the exact reason list ("reasons"); a version 1 vector may
instead name one reason the list must contain ("reason_contains"). A set
mutation carries its value as "value", or as "units", the UTF-16 code units
of a string no strict JSON text can hold. With --json each result also
carries both sides' definition_sha256 (None for a failed side).
"""

import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import caid  # noqa: E402
from mapping import compare_mapped_actions, mapping_profile_hash  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.abspath(os.path.join(HERE, "..", "..", "conformance", "mapping-vectors.json"))


def _corpus_path(argv):
    if "--corpus" not in argv:
        return VECTORS
    index = argv.index("--corpus")
    if index + 1 >= len(argv):
        raise ValueError("--corpus requires a path")
    return os.path.abspath(argv[index + 1])


def _segments(pointer):
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _units_to_str(units):
    out = []
    i = 0
    while i < len(units):
        u = units[i]
        if 0xD800 <= u <= 0xDBFF and i + 1 < len(units) and 0xDC00 <= units[i + 1] <= 0xDFFF:
            out.append(chr(0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00)))
            i += 2
            continue
        out.append(chr(u))
        i += 1
    return "".join(out)


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
        parent[key] = _units_to_str(operation["units"]) if "units" in operation else copy.deepcopy(operation["value"])
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
            left,
            right,
            definitions=corpus["definitions"],
            enum_snapshots=corpus.get("enum_snapshots"),
            suite=vector["suite"] if "suite" in vector else corpus["suite"],
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
                "definition_sha256": [
                    result[side]["definition_sha256"] if result[side]["ok"] else None for side in ("left", "right")
                ],
            }
        )
    return results


with open(_corpus_path(sys.argv[1:]), "rb") as handle:
    loaded = caid.decode_json_document(handle.read())
if not loaded["ok"]:
    raise SystemExit("mapping corpus does not decode with the strict decoder")
results = run_mapping_vectors(loaded["value"])

if "--json" in sys.argv:
    print(json.dumps(results, separators=(",", ":")))
else:
    for result in results:
        print(("PASS" if result["pass"] else "FAIL") + " " + result["id"] + " " + result["verdict"])

if any(not result["pass"] for result in results):
    raise SystemExit(1)
