#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Runs a CAID grammar case list against the Python port's public API.

Usage: python3 run_grammar_vectors.py [--corpus PATH] [--json]

The case list is what `node caid/spec/abnf-check.mjs --out FILE` writes:
{"@version": "CAID-GRAMMAR-CASES-v1", "cases": [{"rule", "abnf_rule",
"input", "match"}]}, where match is the ABNF interpreter's verdict.

Each case goes through parse_caid, compute_caid or map_action with a
one-field definition or profile, never through the generated regular
expressions, so hand-written logic around the generated constants cannot
hide. Checks per rule:

  pattern:caid            parse_caid(s): not matching is malformed_caid;
                          matching is unknown_suite for an unregistered suite,
                          else ok exactly when the digest has the suite's
                          digest syntax (derived from the Appendix A.2 prose,
                          not from the generated pattern), else malformed_caid
  pattern:action_type     compute_caid({"action_type": s}) is anything but
                          invalid_action_type exactly when s matches
  pattern:suite           parse_caid("caid:1:a.b.1:<s>:<43 x A>") is not
                          malformed_caid exactly when s matches
  pattern:digest          parse_caid under an unregistered suite is
                          unknown_suite exactly when s matches
  suite_digest:<suite>    parse_caid("caid:1:a.b.1:<suite>:<s>") is ok exactly
                          when s matches
  pattern:amount_string   an amount-string field computes exactly when s
  pattern:digest_field    matches; likewise digest; timestamp also needs the
  pattern:timestamp       day within the month
  pattern:format_name     a code field declaring format s (or code_system s)
  pattern:code_system     conforms exactly when s matches
  code_format:<format>    a code field of that format computes exactly when s
                          matches
  pattern:array_index     a mapping rule path /a/<s> over an array is not
                          invalid_source_path exactly when s matches
  pattern:hex_sha256      sha256-hex-to-digest maps exactly when s matches

A rule this runner does not know is a failure, so a new grammar rule cannot
go untested. Exits nonzero on any mismatch.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import caid  # noqa: E402
import mapping  # noqa: E402

DEFAULT_CORPUS = os.path.join(HERE, "..", "..", "conformance", "grammar-vectors.json")
B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
CODE_SYSTEM = "http://example.org/code-system"
REGISTERED_SUITES = caid.REGISTERED_SUITE_DIGEST_OCTETS
UNREGISTERED_SUITE = "zz-unregistered"
assert UNREGISTERED_SUITE not in REGISTERED_SUITES
VALID_DIGEST = "A" * 43
MAX_POINTER_OCTETS = caid.LIMITS["mapping_pointer_octets_max"]
# The length limits of Section 2.6, checked before any pattern runs.
MAX = caid.SPEC["pattern_max_octets"]


def _arg(argv, name, default=None):
    if name not in argv:
        return default
    index = argv.index(name)
    if index + 1 >= len(argv):
        raise SystemExit(name + " requires a value")
    return argv[index + 1]


def _digest_syntax(digest, octets):
    """Appendix A.2: c = ceil(8n/6) base64url characters; the final one has
    u = 6c - 8n zero low bits."""
    chars = -(-8 * octets // 6)
    unused = 6 * chars - 8 * octets
    return (
        len(digest) == chars
        and all(ch in B64URL for ch in digest)
        and B64URL.index(digest[-1]) % (1 << unused) == 0
    )


def _within_month(s):
    year, month, day = int(s[0:4]), int(s[5:7]), int(s[8:10])
    if month == 2:
        days = 29 if (year % 4 == 0 and year % 100 != 0) or year % 400 == 0 else 28
    else:
        days = 30 if month in (4, 6, 9, 11) else 31
    return day <= days


def _one_field(field_type, value, **members):
    field = dict(name="f", type=field_type, **members)
    definitions = [{"action_type": "t.grammar.1", "required_fields": [field]}]
    return caid.compute_caid({"action_type": "t.grammar.1", "f": value}, {"suite": "jcs-sha256", "definitions": definitions})


def _code_definition_conforms(code_system, format_name):
    definitions = [{
        "action_type": "t.grammar.1",
        "required_fields": [{"name": "g", "type": "string"}],
        "optional_fields": [{"name": "f", "type": "code", "code_system": code_system, "format": format_name}],
    }]
    result = caid.compute_caid({"action_type": "t.grammar.1", "g": "x"}, {"suite": "jcs-sha256", "definitions": definitions})
    return "caid" in result


def _map(source, source_path, transform, field_type):
    definitions = [{"action_type": "t.map.1", "required_fields": [{"name": "x", "type": field_type}]}]
    profile = {
        "@version": mapping.MAPPING_PROFILE_VERSION,
        "profile_id": "grammar",
        "source_format": {"media_type": "application/json", "schema": "grammar", "version": "1"},
        "target_action_type": "t.map.1",
        "loss_policy": "no-material-field-loss",
        "material_source_paths": [source_path],
        "rules": [{"source_path": source_path, "target_field": "x", "transform": transform}],
    }
    return mapping.map_action(
        source,
        profile=profile,
        source_descriptor=dict(profile["source_format"]),
        expected_profile_hash=mapping.mapping_profile_hash(profile),
        native_verified=True,
        definitions=definitions,
    )


def _escape_token(s):
    return s.replace("~", "~0").replace("/", "~1")


def probe(rule, s, match):
    """Returns (agrees, skipped, detail)."""
    kind, _, name = rule.partition(":")
    if kind == "pattern" and name == "caid":
        result = caid.parse_caid(s)
        if not match or len(s) > MAX["caid"] or len(s.split(":")[2]) > MAX["action_type"]:
            expected = {"ok": False, "refusals": ["malformed_caid"]}
        else:
            _, _, _, suite, digest = s.split(":")
            if suite not in REGISTERED_SUITES:
                expected = {"ok": False, "refusals": ["unknown_suite"]}
            elif _digest_syntax(digest, REGISTERED_SUITES[suite]):
                expected = None  # ok
            else:
                expected = {"ok": False, "refusals": ["malformed_caid"]}
        if expected is None:
            return result["ok"], False, result
        return result == expected, False, result
    if kind == "pattern" and name == "action_type":
        result = caid.compute_caid({"action_type": s}, {"suite": "jcs-sha256", "definitions": []})
        return (result.get("refusals") != ["invalid_action_type"]) == (match and len(s) <= MAX["action_type"]), False, result
    if kind == "pattern" and name == "suite":
        result = caid.parse_caid("caid:1:a.b.1:" + s + ":" + VALID_DIGEST)
        return (result.get("refusals") != ["malformed_caid"]) == match, False, result
    if kind == "pattern" and name == "digest":
        result = caid.parse_caid("caid:1:a.b.1:" + UNREGISTERED_SUITE + ":" + s)
        return (result.get("refusals") == ["unknown_suite"]) == match, False, result
    if kind == "suite_digest":
        result = caid.parse_caid("caid:1:a.b.1:" + name + ":" + s)
        return result["ok"] == match, False, result
    if kind == "pattern" and name in ("amount_string", "digest_field", "timestamp"):
        field_type = {"amount_string": "amount-string", "digest_field": "digest", "timestamp": "timestamp"}[name]
        result = _one_field(field_type, s)
        expected = match and (name != "timestamp" or _within_month(s))
        return ("caid" in result) == expected, False, result
    if kind == "pattern" and name == "format_name":
        return _code_definition_conforms(CODE_SYSTEM, s) == match, False, None
    if kind == "pattern" and name == "code_system":
        return _code_definition_conforms(s, "nacha-sec") == (match and len(s) <= MAX["code_system"]), False, None
    if kind == "code_format":
        result = _one_field("code", s, code_system=CODE_SYSTEM, format=name)
        return ("caid" in result) == match, False, result
    if kind == "pattern" and name == "array_index":
        source_path = "/a/" + _escape_token(s)
        octets = caid._utf8_octets(source_path)
        if octets is not None and octets > MAX_POINTER_OCTETS:
            return True, True, None  # the pointer limit, not this rule, decides
        result = _map({"a": ["v0", "v1", "v2"]}, source_path, "copy", "string")
        reasons = result.get("reasons", [])
        refused = any(r.startswith("invalid_source_path:") for r in reasons) or "invalid_mapping_profile" in reasons
        return (not refused) == match, False, result
    if kind == "pattern" and name == "hex_sha256":
        result = _map({"h": s}, "/h", "sha256-hex-to-digest", "digest")
        return result["ok"] == match, False, result
    return False, False, "no public-API probe for rule " + rule


def main(argv):
    path = os.path.abspath(_arg(argv, "--corpus", DEFAULT_CORPUS))
    if not os.path.exists(path):
        raise SystemExit("grammar corpus not found: " + path + " (generate it with node caid/spec/abnf-check.mjs --out FILE)")
    with open(path, "rb") as fh:
        loaded = caid._decode_corpus_json(fh.read())  # cases carry lone surrogates as escapes
    if not loaded["ok"]:
        raise SystemExit("grammar corpus is not JSON text: " + path)
    corpus = loaded["value"]
    per_rule = {}
    failures = []
    for case in corpus["cases"]:
        rule = case["rule"]
        stats = per_rule.setdefault(rule, {"cases": 0, "accepted": 0, "skipped": 0, "mismatches": 0})
        agrees, skipped, detail = probe(rule, case["input"], case["match"])
        stats["cases"] += 1
        stats["accepted"] += 1 if case["match"] else 0
        stats["skipped"] += 1 if skipped else 0
        if not agrees:
            stats["mismatches"] += 1
            if len(failures) < 20:
                failures.append({"rule": rule, "input": case["input"], "match": case["match"], "result": detail})
    mismatches = sum(s["mismatches"] for s in per_rule.values())
    summary = {"cases": len(corpus["cases"]), "rules": len(per_rule), "mismatches": mismatches, "per_rule": per_rule}
    if "--json" in argv:
        print(json.dumps(summary, ensure_ascii=True, separators=(",", ":")))
    else:
        for rule in sorted(per_rule):
            s = per_rule[rule]
            print("%s %s: %d cases, %d matching, %d skipped" % ("FAIL" if s["mismatches"] else "PASS", rule, s["cases"], s["accepted"], s["skipped"]))
        for failure in failures:
            print("MISMATCH " + json.dumps(failure, ensure_ascii=True)[:400])
        print("")
        print("%d cases over %d rules, %d mismatches" % (summary["cases"], summary["rules"], mismatches))
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
