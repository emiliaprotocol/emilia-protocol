#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Runs the CAID core corpus (caid/conformance/vectors.json) against caid.py.

Usage: python3 run_vectors.py [--corpus PATH] [--json]

Prints PASS or FAIL per vector and exits nonzero on any failure. The corpus
is read with this port's strict decoder.

Input forms (corpus version 5):
  input.json         a string; the runner encodes it as UTF-8
  input.json_b64     the exact octets, base64
  input.json_repeat  {"prefix", "unit", "count", "suffix"}: prefix, then unit
                     count times, then suffix, encoded as UTF-8
  input.native_json  JSON text decoded with the corpus decoder, which keeps
                     unpaired-surrogate escapes, and passed to the native
                     entry point only (the native lane)
  input.object       a value passed to the native entry point only

Kinds:
  decode      decode_caid_json(bytes); {"ok": true} or {"ok": false, "refusals"}
  parse       parse_caid(input.caid)
  compute     compute_caid_json(bytes, {suite, definitions, enum_snapshots})
  verify      verify_caid_json(bytes, input.caid, {definitions, enum_snapshots,
              expected_definition_sha256})
  definition  definition_sha256(input.definition), or of input.json decoded
              with decode_json_document

For compute and verify over text, whenever the text decodes the runner also
calls the native entry point on the decoded value and requires an identical
result: native/byte parity.

A corpus before version 5 carries input.object only and predates
definition_sha256 and verify details; its results are compared on the
members each expectation names.

Per-vector relations cross-check actual computed CAIDs:
  same_caid_as / different_caid_from
"""

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import caid  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CORPUS = os.path.join(HERE, "..", "..", "conformance", "vectors.json")


def _arg(argv, name, default=None):
    if name not in argv:
        return default
    index = argv.index(name)
    if index + 1 >= len(argv):
        raise SystemExit(name + " requires a value")
    return argv[index + 1]


def _canonical(value):
    result = caid.canonicalize(value)
    return result["canonical"] if result["ok"] else repr(value)


def _encode(text):
    return text.encode("utf-8", "surrogatepass")


def _input_bytes(spec):
    if "json" in spec:
        return _encode(spec["json"])
    if "json_b64" in spec:
        return base64.b64decode(spec["json_b64"], validate=True)
    if "json_repeat" in spec:
        r = spec["json_repeat"]
        return _encode(r.get("prefix", "")) + _encode(r["unit"]) * r["count"] + _encode(r.get("suffix", ""))
    return None


def _native_value(spec):
    if "native_json" in spec:
        decoded = caid._decode_corpus_json(_encode(spec["native_json"]))
        if not decoded["ok"]:
            raise ValueError("input.native_json is not JSON text")
        return True, decoded["value"]
    if "object" in spec:
        return True, spec["object"]
    return False, None


def _options(corpus, vector, kind):
    spec = vector["input"]
    options = {
        "definitions": vector.get("definitions", []),
        "enum_snapshots": corpus.get("enum_snapshots", []),
    }
    if kind == "compute" and "suite" in spec:
        options["suite"] = spec["suite"]
    if kind == "verify" and "expected_definition_sha256" in spec:
        options["expected_definition_sha256"] = spec["expected_definition_sha256"]
    for extra in (vector.get("options"), spec.get("options")):
        if isinstance(extra, dict):
            options.update(extra)
    return options


def _project(actual, expect, legacy):
    """Legacy corpora name only the members they predate."""
    if not legacy or not isinstance(actual, dict) or not isinstance(expect, dict):
        return actual
    return {k: v for k, v in actual.items() if k in expect}


def run_vector(corpus, vector, legacy):
    """Returns (actual, problem) where problem is None or a parity message."""
    kind = vector.get("kind")
    spec = vector.get("input", {})
    data = _input_bytes(spec)
    has_native, native = _native_value(spec)
    if kind == "parse":
        return caid.parse_caid(spec.get("caid")), None
    if kind == "decode":
        result = caid.decode_caid_json(data)
        if result["ok"] and "value" not in vector.get("expect", {}):
            result = {"ok": True}
        return result, None
    if kind == "definition":
        if "definition" in spec:
            return caid.definition_sha256(spec["definition"]), None
        decoded = caid.decode_json_document(data)
        if not decoded["ok"]:
            return {"refusals": decoded["refusals"]}, None
        return caid.definition_sha256(decoded["value"]), None
    if kind not in ("compute", "verify"):
        raise ValueError("unknown vector kind: " + str(kind))
    options = _options(corpus, vector, kind)
    if data is None:
        if not has_native:
            raise ValueError("vector has no input form")
        if kind == "compute":
            return caid.compute_caid(native, options), None
        return caid.verify_caid(native, spec.get("caid"), options), None
    if kind == "compute":
        actual = caid.compute_caid_json(data, options)
    else:
        actual = caid.verify_caid_json(data, spec.get("caid"), options)
    decoded = caid.decode_caid_json(data)
    problem = None
    if decoded["ok"]:
        if kind == "compute":
            native_result = caid.compute_caid(decoded["value"], options)
        else:
            native_result = caid.verify_caid(decoded["value"], spec.get("caid"), options)
        if _canonical(native_result) != _canonical(actual):
            problem = "native/byte parity: native " + json.dumps(native_result) + " vs bytes " + json.dumps(actual)
    return actual, problem


def main(argv):
    path = os.path.abspath(_arg(argv, "--corpus", DEFAULT_CORPUS))
    with open(path, "rb") as fh:
        raw = fh.read()
    loaded = caid.decode_json_document(raw)
    strict = loaded["ok"]
    if not strict:
        loaded = caid._decode_corpus_json(raw)
        if not loaded["ok"]:
            raise SystemExit("corpus is not JSON text: " + path)
    corpus = loaded["value"]
    version = corpus.get("version")
    legacy = not isinstance(version, int) or version < 5
    counts = {"pass": 0, "fail": 0}
    results = []
    actual_caids = {}

    def report(vector_id, ok, detail=None, actual=None):
        counts["pass" if ok else "fail"] += 1
        results.append({"id": vector_id, "pass": ok, "actual": actual})
        if "--json" not in argv:
            print(("PASS " if ok else "FAIL ") + vector_id)
            if not ok and detail:
                print("     " + detail)

    if not strict and not legacy:
        report("corpus-strict-decode", False, "a version 5 corpus must decode with the strict decoder")

    for vector in corpus["vectors"]:
        try:
            actual, problem = run_vector(corpus, vector, legacy)
        except (ValueError, KeyError, TypeError) as error:
            report(vector.get("id", "?"), False, "runner error: " + repr(error))
            continue
        if vector.get("kind") == "compute" and isinstance(actual, dict) and "caid" in actual:
            actual_caids[vector["id"]] = actual["caid"]
        expect = vector.get("expect")
        compared = _project(actual, expect, legacy)
        ok = _canonical(compared) == _canonical(expect) and problem is None
        detail = None
        if not ok:
            detail = problem or ("expected " + json.dumps(expect) + " got " + json.dumps(actual))
        report(vector["id"], ok, detail, actual)

    for vector in corpus["vectors"]:
        relation = vector.get("relation")
        if not relation:
            continue
        target = relation.get("same_caid_as") or relation.get("different_caid_from")
        mine = actual_caids.get(vector["id"])
        theirs = actual_caids.get(target)
        label = vector["id"] + (" same_caid_as " if relation.get("same_caid_as") else " different_caid_from ") + str(target)
        if mine is None or theirs is None:
            report(label, False, "missing computed caid for relation")
        elif relation.get("same_caid_as"):
            report(label, mine == theirs, None if mine == theirs else mine + " != " + theirs)
        else:
            report(label, mine != theirs, None if mine != theirs else "caids unexpectedly equal: " + mine)

    if "--json" in argv:
        print(json.dumps(results, ensure_ascii=True, separators=(",", ":")))
    else:
        print("")
        print("%d passed, %d failed, %d vectors (corpus version %s%s)" % (
            counts["pass"], counts["fail"], len(corpus["vectors"]), version, ", legacy comparison" if legacy else ""))
    return 1 if counts["fail"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
