#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Python CAID port (standard library unittest only).

Run: python3 caid/impl/python/test_caid.py
"""

import gc
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import caid  # noqa: E402
import mapping  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
MALFORMED = {"ok": False, "refusals": ["malformed_json"]}
SUITE = "jcs-sha256"


def _load(relative):
    with open(os.path.join(ROOT, relative), "rb") as fh:
        loaded = caid.decode_json_document(fh.read())
    assert loaded["ok"], relative
    return loaded["value"]


REGISTRY = _load("caid/registry/action-types.json")
SNAPSHOTS = [_load(os.path.join("caid/registry", e["path"])) for e in REGISTRY["enum_snapshot_files"]]
DIGESTS = _load("caid/registry/digests.json")
REG_OPTS = {"suite": SUITE, "definitions": REGISTRY["types"], "enum_snapshots": SNAPSHOTS}

STRING_DEF = [{"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "string"}],
               "optional_fields": [{"name": "n", "type": "integer"}, {"name": "free", "type": "object"}]}]
OPTS = {"suite": SUITE, "definitions": STRING_DEF}


def decode(text):
    return caid.decode_caid_json(text.encode("utf-8") if isinstance(text, str) else text)


class DecoderTest(unittest.TestCase):
    def test_5000_digit_literal_is_unsupported_number(self):
        text = '{"action_type":"t.a.1","a":"x","free":{"big":' + "1" * 5000 + "}}"
        self.assertEqual(caid.compute_caid_json(text.encode(), OPTS), {"refusals": ["unsupported_number"]})
        self.assertEqual(decode("1" * 5000)["value"], float("inf"))
        self.assertEqual(decode("-" + "9" * 5000)["value"], float("-inf"))

    def test_5000_digit_literal_in_integer_field(self):
        text = '{"action_type":"t.a.1","a":"x","n":' + "1" * 5000 + "}"
        self.assertEqual(caid.compute_caid_json(text.encode(), OPTS), {"refusals": ["mistyped_field:n", "unsupported_number"]})

    def test_nan_and_infinity_are_malformed(self):
        for literal in ("NaN", "Infinity", "-Infinity", "nan", "inf"):
            self.assertEqual(decode('{"a":' + literal + "}"), MALFORMED, literal)

    def test_byte_order_mark_is_malformed(self):
        self.assertEqual(decode(b"\xef\xbb\xbf{}"), MALFORMED)
        self.assertEqual(decode(b"{}")["ok"], True)

    def test_utf16_and_utf32_are_malformed(self):
        for encoding in ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le"):
            self.assertEqual(decode('{"a":"b"}'.encode(encoding)), MALFORMED, encoding)

    def test_invalid_utf8_is_malformed(self):
        for raw in (b'"\xe9"', b'"\xc0\xaf"', b'"\xed\xa0\x80"', b'"\xf4\x90\x80\x80"', b'"\xe2\x82"', b"\xff"):
            self.assertEqual(decode(raw), MALFORMED, raw)

    def test_only_bytes_are_accepted(self):
        self.assertEqual(caid.decode_caid_json("{}"), MALFORMED)
        self.assertEqual(caid.decode_caid_json(None), MALFORMED)
        self.assertEqual(caid.decode_caid_json(memoryview(b"{}")), MALFORMED)
        self.assertEqual(caid.decode_caid_json(bytearray(b"{}")), {"ok": True, "value": {}})

    def test_duplicate_member_names(self):
        self.assertEqual(decode('{"a":1,"a":2}'), MALFORMED)
        self.assertEqual(decode('{"a":1,"\\u0061":2}'), MALFORMED)
        self.assertEqual(decode('{"x":{"a":1,"b":{"a":1}},"y":{"a":2}}')["ok"], True)
        self.assertEqual(decode('{"\\ud83d\\ude00":1,"\U0001F600":2}'), MALFORMED)

    def test_surrogate_escapes(self):
        self.assertEqual(decode('"\\ud800"'), MALFORMED)
        self.assertEqual(decode('"\\udc00"'), MALFORMED)
        self.assertEqual(decode('"\\ud800\\u0041"'), MALFORMED)
        self.assertEqual(decode('"\\ud800\\ud800"'), MALFORMED)
        self.assertEqual(decode('{"\\ud800":1}'), MALFORMED)
        self.assertEqual(decode('"\\ud83d\\ude00"'), {"ok": True, "value": "\U0001F600"})

    def test_noncharacters_are_malformed(self):
        for text in ('"\\uffff"', '"\\ufdd0"', '"\\ud83f\\udffe"', '"\ufdef"', '"\U0010FFFF"', '{"\\ufffe":1}'):
            self.assertEqual(decode(text), MALFORMED, text)
        self.assertEqual(decode('"\ufffd\ufeff\ufdcf\ufdf0"')["ok"], True)

    def test_text_structure(self):
        for text in ("", " ", "{} {}", "{},", "[1,]", '{"a":1,}', "[01]", "[1.]", "[.5]", "[+1]", "[-]",
                     "[1e]", '{"a" 1}', "{'a':1}", "[\u00a01]", "[\f1]", '"a\u0001"', '"a\\x"', '"\\u12"', "tru", "nul"):
            self.assertEqual(decode(text), MALFORMED, repr(text))
        for text in (" \t\r\n{} \t\r\n", '"\\/\\b\\f\\n\\r\\t\\"\\\\"', "[-0, 0.5e1, 1E2, 1e+2, 1e-2]", "true", "null"):
            self.assertEqual(decode(text)["ok"], True, repr(text))

    def test_depth_limit(self):
        self.assertEqual(decode("[" * 64 + "]" * 64)["ok"], True)
        self.assertEqual(decode("[" * 65 + "]" * 65), MALFORMED)
        self.assertEqual(decode('{"a":' * 64 + "1" + "}" * 64)["ok"], True)
        self.assertEqual(decode('{"a":' * 65 + "1" + "}" * 65), MALFORMED)
        self.assertEqual(decode("[" * 64 + "{}" + "]" * 64), MALFORMED)
        self.assertEqual(decode("[" * 100000), MALFORMED)  # iterative: no RecursionError

    def test_size_limit(self):
        cap = caid.MAX_JSON_TEXT_OCTETS
        self.assertEqual(caid.decode_caid_json(b'"' + b"a" * (cap - 2) + b'"')["ok"], True)
        self.assertEqual(caid.decode_caid_json(b'"' + b"a" * (cap - 1) + b'"'), MALFORMED)
        self.assertEqual(caid.decode_json_document(b'"' + b"a" * (cap - 1) + b'"')["ok"], True)

    def test_collector_state_is_never_touched(self):
        # The decoder leaves the process-wide collector alone, whatever its
        # state, so no other thread of the application sees it change.
        large_ok = b"[" + b"0," * (1 << 20) + b"0]"
        large_bad = large_ok + b"x"
        calls = []
        saved = (gc.disable, gc.enable)
        gc.disable, gc.enable = (lambda: calls.append("disable")), (lambda: calls.append("enable"))
        try:
            self.assertTrue(caid.decode_caid_json(large_ok)["ok"])
            self.assertEqual(caid.decode_caid_json(large_bad), MALFORMED)
        finally:
            gc.disable, gc.enable = saved
        self.assertEqual(calls, [])

    def test_bytearray_size_is_checked_before_any_copy(self):
        cap = caid.MAX_JSON_TEXT_OCTETS

        class NoCopy(bytearray):
            def __bytes__(self):
                raise AssertionError("copied")

        self.assertEqual(caid.decode_caid_json(bytearray(cap + 1)), MALFORMED)
        self.assertEqual(caid.decode_caid_json(memoryview(b"{}")), MALFORMED)  # not bytes or bytearray

    def test_number_values(self):
        values = decode("[1e-400, -0, 12.0, 1.2e1, 0.99999999999999999999, 9007199254740993, 1e400, 1.5]")["value"]
        self.assertEqual(values[:5], [0, 0, 12, 12, 1])
        self.assertTrue(all(type(v) is int for v in values[:5]))
        self.assertEqual(values[5], 9007199254740992.0)
        self.assertEqual(values[6], float("inf"))
        self.assertEqual(values[7], 1.5)
        mid = "1.000000000000000111022302462515654042363166809082031250001"
        self.assertEqual(decode(mid)["value"], 1.0000000000000002)

    def test_underflow_is_the_integer_zero(self):
        a = caid.compute_caid_json(b'{"action_type":"t.a.1","a":"x","n":1e-400}', OPTS)
        b = caid.compute_caid_json(b'{"action_type":"t.a.1","a":"x","n":0}', OPTS)
        self.assertEqual(a, b)
        self.assertIn("caid", a)


class HostValueTest(unittest.TestCase):
    def compute(self, free):
        return caid.compute_caid({"action_type": "t.a.1", "a": "x", "free": free}, OPTS)

    def test_values_outside_the_model_are_refused(self):
        for value in ((1, 2), {1, 2}, b"ab", object(), 1j, frozenset(), range(2)):
            self.assertEqual(self.compute({"v": value}), {"refusals": ["unsupported_value"]}, repr(value))
        self.assertEqual(self.compute({1: "a"}), {"refusals": ["unsupported_value"]})
        self.assertEqual(self.compute({("a",): "a"}), {"refusals": ["unsupported_value"]})
        self.assertEqual(self.compute({"v": float("nan")}), {"refusals": ["unsupported_number"]})
        self.assertEqual(self.compute({"v": "\ud800"}), {"refusals": ["unsupported_value"]})
        self.assertEqual(self.compute({"v": "\uffff"}), {"refusals": ["unsupported_value"]})

    def test_tuple_in_a_declared_field_is_mistyped(self):
        definitions = [{"action_type": "t.b.1", "required_fields": [{"name": "xs", "type": "array"}]}]
        result = caid.compute_caid({"action_type": "t.b.1", "xs": (1, 2)}, {"suite": SUITE, "definitions": definitions})
        self.assertEqual(result, {"refusals": ["mistyped_field:xs", "unsupported_value"]})

    def test_bool_is_never_an_integer(self):
        result = caid.compute_caid({"action_type": "t.a.1", "a": "x", "n": True}, OPTS)
        self.assertEqual(result, {"refusals": ["mistyped_field:n"]})
        self.assertEqual(caid.canonicalize([True, 1])["canonical"], "[true,1]")

    def test_cycles_are_refused_without_error(self):
        loop = []
        loop.append(loop)
        loop.append(loop)
        self.assertEqual(self.compute({"v": loop}), {"refusals": ["unsupported_value"]})
        d = {}
        d["self"] = d
        self.assertEqual(caid.compute_caid({"action_type": "t.a.1", "a": "x", "free": d}, OPTS), {"refusals": ["unsupported_value"]})
        result = caid.verify_caid(d, "canactid:1:t.a.1:jcs-sha256:" + "A" * 43, OPTS)
        self.assertEqual(result["reasons"], ["action_type_mismatch", "invalid_object"])

    def test_shared_substructure_is_not_a_cycle(self):
        shared = {"k": [1, 2]}
        a = self.compute({"x": shared, "y": shared})
        b = self.compute({"x": {"k": [1, 2]}, "y": {"k": [1, 2]}})
        self.assertIn("caid", a)
        self.assertEqual(a, b)

    def test_shared_containers_cost_their_distinct_containers(self):
        # 2^40 values in the expansion, 41 distinct containers: the value
        # budget refuses it (unsupported_value alone) without walking the
        # expansion, as in JavaScript and Go.
        dag = "x"
        for _ in range(40):
            dag = [dag, dag]
        start = time.time()
        self.assertEqual(self.compute({"v": dag}), {"refusals": ["unsupported_value"]})
        self.assertLess(time.time() - start, 2)
        # Under the budget, a shared value canonicalizes exactly as its copy,
        # including where one path reaches it near the depth limit.
        shared = {"k": ["\u00e9\U0001f600", 1, {"z": [True, None]}]}
        deep = {"leaf": shared}
        for _ in range(58):
            deep = [deep]
        self.assertEqual(
            caid.canonicalize({"a": shared, "b": [shared, shared], "d": deep}),
            caid.canonicalize({"a": {"k": ["\u00e9\U0001f600", 1, {"z": [True, None]}]},
                               "b": [{"k": ["\u00e9\U0001f600", 1, {"z": [True, None]}]}] * 2, "d": deep}),
        )
        too_deep = {"leaf": shared}
        for _ in range(61):
            too_deep = [too_deep]
        self.assertEqual(caid.canonicalize({"a": shared, "d": too_deep}), {"ok": False, "refusals": ["unsupported_value"]})
        flagged = {"n": 7.5, "s": "\ufdd0"}
        self.assertEqual(caid.canonicalize([flagged, flagged]), {"ok": False, "refusals": ["unsupported_number", "unsupported_value"]})

    def test_value_budget_stops_exponential_sharing(self):
        saved = caid._VALUE_BUDGET
        caid._VALUE_BUDGET = 10000
        try:
            value = [0]
            for _ in range(60):
                value = [value, value]
            start = time.time()
            self.assertEqual(self.compute({"v": value}), {"refusals": ["unsupported_value"]})
            self.assertLess(time.time() - start, 5)
            # Past the budget the value is unsupported_value alone (Section
            # 2.6): a fractional number read before the budget ran out is
            # not reported, since which values are read first is not fixed.
            self.assertEqual(self.compute({"a": 1.5, "v": value}), {"refusals": ["unsupported_value"]})
            self.assertEqual(caid.canonicalize({"a": 1.5, "v": value}), {"ok": False, "refusals": ["unsupported_value"]})
            # Phases 1 through 5 still see the whole object.
            self.assertEqual(caid.compute_caid({"action_type": "t.a.1", "n": "x", "free": {"v": value}}, OPTS)["refusals"],
                             ["missing_material_field:a", "mistyped_field:n", "unsupported_value"])
        finally:
            caid._VALUE_BUDGET = saved

    def test_budget_counts_values_not_characters(self):
        # A 34-million-character string is one value: the object is oversized,
        # and the fractional number makes it unsupported_number alone.
        big = {"action_type": "t.a.1", "a": "x" * 34000000, "free": {"c": [7.5]}}
        self.assertEqual(caid.compute_caid(big, OPTS), {"refusals": ["unsupported_number"]})

    def test_spoofed_class_is_refused_without_raising(self):
        from unittest import mock

        spoofs = [mock.Mock(spec=dict), mock.Mock(spec=str), mock.Mock(spec=list), mock.Mock(spec=int), mock.MagicMock(spec=dict)]
        caid_string = "canactid:1:t.a.1:jcs-sha256:" + "A" * 43
        for spoof in spoofs:
            self.assertEqual(caid.compute_caid(spoof, OPTS), {"refusals": ["invalid_action_type"]}, repr(spoof))
            self.assertEqual(caid.verify_caid(spoof, caid_string, OPTS)["reasons"], ["invalid_object"], repr(spoof))
            self.assertEqual(caid.canonicalize(spoof), {"ok": False, "refusals": ["unsupported_value"]}, repr(spoof))
            self.assertEqual(caid.compute_caid({"action_type": "t.a.1", "a": "x", "free": {"k": spoof}}, OPTS), {"refusals": ["unsupported_value"]})
            self.assertEqual(caid.compute_caid({"action_type": "t.a.1", "a": spoof}, OPTS), {"refusals": ["mistyped_field:a", "unsupported_value"]})
            self.assertEqual(caid.compute_caid({"action_type": "t.a.1", "a": "x"}, spoof), {"refusals": ["unknown_action_type"]})
            self.assertEqual(caid.compute_caid({"action_type": "t.a.1", "a": "x"}, {"suite": spoof, "definitions": STRING_DEF}), {"refusals": ["unknown_suite"]})
            self.assertEqual(caid.compute_caid({"action_type": "t.a.1", "a": "x"}, {"suite": SUITE, "definitions": [spoof]}), {"refusals": ["unknown_action_type"]})
            self.assertEqual(caid.definition_sha256(spoof), {"refusals": ["invalid_definition"]})
            self.assertEqual(caid.parse_caid(spoof), {"ok": False, "refusals": ["malformed_caid"]})
            self.assertEqual(caid.decode_caid_json(spoof), MALFORMED)
            pinned = caid.verify_caid({"action_type": "t.a.1", "a": "x"}, caid_string, {"definitions": STRING_DEF, "expected_definition_sha256": spoof})
            self.assertEqual(pinned["reasons"][0], "definition_mismatch")

    def test_native_depth_limit(self):
        value = 1
        for _ in range(63):  # free's own object is at depth 2 of the action object
            value = {"k": value}
        self.assertIn("caid", self.compute(value))  # depth 64
        self.assertEqual(self.compute({"k": value}), {"refusals": ["unsupported_value"]})  # depth 65
        deep = 1
        for _ in range(5000):
            deep = [deep]
        self.assertEqual(self.compute({"deep": deep, "n": 1.5}), {"refusals": ["unsupported_number", "unsupported_value"]})

    def test_subclasses_are_read_through_base_methods(self):
        class Evil(dict):
            def items(self):
                raise RuntimeError("items")

            def __iter__(self):
                raise RuntimeError("iter")

            def get(self, *a):
                raise RuntimeError("get")

        class EvilList(list):
            def __iter__(self):
                raise RuntimeError("iter")

        class EvilStr(str):
            def __eq__(self, other):
                raise RuntimeError("eq")

            __hash__ = str.__hash__

        class EvilInt(int):
            def __int__(self):
                raise RuntimeError("int")

        plain = self.compute({"k": [1, "t"], "n": 5})
        evil = caid.compute_caid(Evil(action_type=EvilStr("t.a.1"), a=EvilStr("x"), free=Evil(k=EvilList([1, EvilStr("t")]), n=EvilInt(5))), OPTS)
        self.assertEqual(plain, evil)

    def test_colliding_str_subclass_keys_are_refused(self):
        class Key(str):
            def __hash__(self):
                return id(self)

            def __eq__(self, other):
                return self is other

        self.assertEqual(self.compute({Key("k"): 1, Key("k"): 2}), {"refusals": ["unsupported_value"]})

    def test_native_matches_bytes(self):
        texts = [
            '{"action_type":"t.a.1","a":"x","free":{"z":[1,2.0,-0,"\\u00e9"],"a":null}}',
            '{"action_type":"t.a.1","a":5,"free":{"n":1.5}}',
            '{"action_type":"t.a.1","free":{}}',
            '[1]',
        ]
        for text in texts:
            value = decode(text)["value"]
            self.assertEqual(caid.compute_caid(value, OPTS), caid.compute_caid_json(text.encode(), OPTS), text)
            c = "canactid:1:t.a.1:jcs-sha256:" + "A" * 43
            self.assertEqual(caid.verify_caid(value, c, OPTS), caid.verify_caid_json(text.encode(), c, OPTS), text)


class OptionGuardTest(unittest.TestCase):
    def test_unhashable_suite_is_unknown_suite(self):
        obj = {"action_type": "t.a.1", "a": "x"}
        for suite in ([], ["jcs-sha256"], {}, 5, None, b"jcs-sha256"):
            self.assertEqual(caid.compute_caid(obj, {"suite": suite, "definitions": STRING_DEF}), {"refusals": ["unknown_suite"]}, repr(suite))

    def test_wrong_typed_options_count_as_absent(self):
        obj = {"action_type": "t.a.1", "a": "x"}
        for options in (None, "x", [], 5, {"suite": SUITE, "definitions": "x"}, {"suite": SUITE, "definitions": {"a": 1}}):
            result = caid.compute_caid(obj, options)
            self.assertIn(result["refusals"][0], ("unknown_action_type",), repr(options))
        result = caid.compute_caid(obj, {"suite": SUITE, "definitions": STRING_DEF, "enum_snapshots": [[], {}, 5]})
        self.assertIn("caid", result)
        # A supplied pin is never absent: any value but the digest itself,
        # of any type, is definition_mismatch (Section 6).
        right = caid.definition_sha256(STRING_DEF[0])["definition_sha256"]
        for pin in (["x"], [right], None, 5, b"sha256:" + right[7:].encode(), right.upper(), {"x": 1}, True):
            result = caid.verify_caid(obj, "canactid:1:t.a.1:jcs-sha256:" + "A" * 43, {"definitions": STRING_DEF, "expected_definition_sha256": pin})
            self.assertEqual(result["reasons"], ["definition_mismatch", "digest_mismatch"], repr(pin))
        result = caid.verify_caid(obj, "canactid:1:t.a.1:jcs-sha256:" + "A" * 43, {"definitions": STRING_DEF, "expected_definition_sha256": right})
        self.assertEqual(result["reasons"], ["digest_mismatch"])
        result = caid.verify_caid(obj, "canactid:1:t.a.1:jcs-sha256:" + "A" * 43, {"definitions": STRING_DEF})
        self.assertEqual(result["reasons"], ["digest_mismatch"])


class ParseTest(unittest.TestCase):
    def test_new_issuance_and_explicit_legacy_v04_verification(self):
        obj = {"action_type": "t.a.1", "a": "x"}
        computed = caid.compute_caid(obj, OPTS)
        self.assertTrue(computed["caid"].startswith("canactid:1:t.a.1:jcs-sha256:"))
        self.assertTrue(caid.parse_caid(computed["caid"])["ok"])

        legacy = "caid:" + computed["caid"].split(":", 1)[1]
        self.assertEqual(caid.parse_caid(legacy), {"ok": False, "refusals": ["malformed_caid"]})
        self.assertFalse(caid.verify_caid(obj, legacy, OPTS)["valid"])
        self.assertTrue(caid.parse_legacy_caid_v04(legacy)["ok"])
        self.assertTrue(caid.verify_legacy_caid_v04(obj, legacy, OPTS)["valid"])
        self.assertTrue(caid.verify_legacy_caid_v04_json(b'{"action_type":"t.a.1","a":"x"}', legacy, OPTS)["valid"])
        self.assertEqual(caid.parse_legacy_caid_v04(computed["caid"]), {"ok": False, "refusals": ["malformed_caid"]})

    def test_parse_order(self):
        good = "canactid:1:payment.release.1:jcs-sha256:liLG9pKgkLt3silrjf1wa0xIHz5YFrBB9HI-arxrO1Y"
        self.assertTrue(caid.parse_caid(good)["ok"])
        self.assertTrue(caid.parse_caid(good.replace("jcs-sha256", "cbor-sha256"))["ok"])
        self.assertEqual(caid.parse_caid(good.replace("jcs-sha256", "zz-unregistered")), {"ok": False, "refusals": ["unknown_suite"]})
        self.assertEqual(caid.parse_caid("canactid:1:a.1:foo:x"), {"ok": False, "refusals": ["unknown_suite"]})
        for bad in (good.upper(), "Canactid" + good[len("canactid"):], good + "\n", good[:-1] + "Z", good[:-1], good + "A", good.replace("jcs-sha256", "Jcs"),
                    good.replace(":1:", ":2:"), None, 5, "", good.replace("payment.release.1", "payment.release.01")):
            self.assertEqual(caid.parse_caid(bad), {"ok": False, "refusals": ["malformed_caid"]}, repr(bad))


class DefinitionTest(unittest.TestCase):
    def test_registry_digests(self):
        expected = {t["action_type"]: t["definition_sha256"] for t in DIGESTS["types"]}
        for t in REGISTRY["types"]:
            self.assertEqual(caid.definition_sha256(t), {"definition_sha256": expected[t["action_type"]]}, t["action_type"])

    def test_malformed_definitions(self):
        obj = {"action_type": "t.a.1", "a": "x"}
        shapes = [
            {"action_type": "t.a.1"},
            {"action_type": "t.a.1", "required_fields": "a"},
            {"action_type": "t.a.1", "required_fields": []},
            {"action_type": "t.a.1", "required_fields": ["a"]},
            {"action_type": "t.a.1", "required_fields": [{"name": "amuont", "typ": "string"}]},
            {"action_type": "t.a.1", "required_fields": [{"name": 1, "type": "string"}]},
            {"action_type": "t.a.1", "required_fields": [{"name": "a:b", "type": "string"}]},
            {"action_type": "t.a.1", "required_fields": [{"name": "", "type": "string"}]},
            {"action_type": "t.a.1", "required_fields": [{"name": "action_type", "type": "string"}]},
            {"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "string"}], "optional_fields": [{"name": "a", "type": "string"}]},
            {"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "string"}], "optional_fields": None},
            {"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "string", "values": ["x"]}]},
            {"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "code", "format": "icd-10-cm"}]},
            {"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "code", "code_system": "x:y", "format": "ICD"}]},
            {"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "string", 5: "x"}]},
        ]
        for shape in shapes:
            self.assertEqual(caid.compute_caid(obj, {"suite": SUITE, "definitions": [shape]}), {"refusals": ["invalid_definition"]}, shape)
            self.assertEqual(caid.definition_sha256(shape), {"refusals": ["invalid_definition"]}, shape)

    def test_resolution(self):
        obj = {"action_type": "t.a.1", "a": "x"}
        d1 = {"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "string"}]}
        d2 = {"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "integer"}]}
        d3 = {"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "string", "notes": "n"}], "status": "deprecated"}
        for defs in ([d1, d2], [d2, d1]):
            self.assertEqual(caid.compute_caid(obj, {"suite": SUITE, "definitions": defs}), {"refusals": ["invalid_definition"]})
        a = caid.compute_caid(obj, {"suite": SUITE, "definitions": [d1, d3]})
        b = caid.compute_caid(obj, {"suite": SUITE, "definitions": [d3]})
        self.assertEqual(a, b)
        self.assertEqual(a["definition_sha256"], caid.definition_sha256(d1)["definition_sha256"])
        self.assertEqual(caid.compute_caid(obj, {"suite": SUITE, "definitions": [{"action_type": "t.b.1", "required_fields": [{"name": "a", "type": "string"}]}]}), {"refusals": ["unknown_action_type"]})

    def test_unregistered_types_fail_only_when_present(self):
        defs = [{"action_type": "t.a.1", "required_fields": [{"name": "a", "type": "string"}],
                 "optional_fields": [{"name": "d", "type": "decimal", "precision": 2},
                                     {"name": "c", "type": "code", "code_system": "http://x.test/c", "format": "zz-top"}]}]
        opts = {"suite": SUITE, "definitions": defs}
        self.assertIn("caid", caid.compute_caid({"action_type": "t.a.1", "a": "x"}, opts))
        self.assertEqual(caid.compute_caid({"action_type": "t.a.1", "a": "x", "d": "1", "c": "A"}, opts), {"refusals": ["mistyped_field:d", "mistyped_field:c"]})


class ComputeTest(unittest.TestCase):
    def test_reason_order(self):
        defs = [{"action_type": "t.o.1", "required_fields": [{"name": "b", "type": "amount-string"}, {"name": "a", "type": "string"}, {"name": "c", "type": "integer"}]}]
        result = caid.compute_caid({"action_type": "t.o.1", "c": "x", "b": "1.", "z": {"\ud800": 1, "\ue000": 1.5}}, {"suite": "cbor-sha256", "definitions": defs})
        self.assertEqual(result, {"refusals": ["missing_material_field:a", "invalid_amount:b", "mistyped_field:c", "unknown_suite", "unsupported_number", "unsupported_value"]})

    def test_gates_yield_one_reason(self):
        self.assertEqual(caid.compute_caid([], OPTS), {"refusals": ["invalid_action_type"]})
        self.assertEqual(caid.compute_caid({"action_type": "T.a.1", "n": 1.5}, OPTS), {"refusals": ["invalid_action_type"]})
        self.assertEqual(caid.compute_caid({"action_type": "t.z.1", "n": 1.5}, OPTS), {"refusals": ["unknown_action_type"]})

    def test_canonical_size_limit(self):
        cap = caid.MAX_CANONICAL_OCTETS
        overhead = len(caid.canonicalize({"action_type": "t.a.1", "a": ""})["canonical"])
        fits = {"action_type": "t.a.1", "a": "x" * (cap - overhead)}
        self.assertIn("caid", caid.compute_caid(fits, OPTS))
        over = {"action_type": "t.a.1", "a": "x" * (cap - overhead + 1)}
        self.assertEqual(caid.compute_caid(over, OPTS), {"refusals": ["unsupported_value"]})
        self.assertTrue(caid.canonicalize(over)["ok"])  # the limit is on action objects
        over["free"] = {"n": 1.5}
        self.assertEqual(caid.compute_caid(over, OPTS), {"refusals": ["unsupported_number"]})

    def test_code_fields(self):
        base = {"action_type": "prior.auth.approve.2"}
        t = next(t for t in REGISTRY["types"] if t["action_type"] == "prior.auth.approve.2")
        for f in t["required_fields"]:
            base[f["name"]] = _candidate(f)
        self.assertIn("caid", caid.compute_caid(base, REG_OPTS))
        for bad in ("e11.9", "E11.", "E11.12345", " E11.9", "E11.9\n", "\uff25\uff211"):
            result = caid.compute_caid(dict(base, diagnosis_code=bad), REG_OPTS)
            self.assertEqual(result, {"refusals": ["invalid_code:diagnosis_code"]}, bad)
        self.assertEqual(caid.compute_caid(dict(base, diagnosis_code=5), REG_OPTS), {"refusals": ["mistyped_field:diagnosis_code"]})

    def test_code_formats_are_linear_time(self):
        adversarial = ["A" * (1 << 20), "0" * (1 << 20), "A0" * (1 << 19), "AB-" + "1" * (1 << 20)]
        for name, matcher in list(caid.CODE_FORMATS.items()) + list(caid.PATTERNS.items()):
            for text in adversarial:
                start = time.perf_counter()
                matcher.match(text + "!")
                self.assertLess(time.perf_counter() - start, 0.25, name)

    def test_every_active_registry_type_computes(self):
        active = [t for t in REGISTRY["types"] if t["status"] == "active"]
        unresolved = set((u["action_type"], u["field"]) for u in REGISTRY["unresolved_external_enums"])
        self.assertEqual(len(active), 53)
        for t in REGISTRY["types"]:
            obj = {"action_type": t["action_type"]}
            for f in t["required_fields"] + t.get("optional_fields", []):
                obj[f["name"]] = _candidate(f)
            result = caid.compute_caid(obj, REG_OPTS)
            blocked = [f["name"] for f in t["required_fields"] if (t["action_type"], f["name"]) in unresolved]
            if blocked:
                self.assertEqual(t["status"], "deprecated")
                self.assertEqual(result["refusals"], ["mistyped_field:" + name for name in blocked], t["action_type"])
            else:
                self.assertIn("caid", result, t["action_type"])
                self.assertEqual(result["definition_sha256"], caid.definition_sha256(t)["definition_sha256"])


class VerifyTest(unittest.TestCase):
    CAID = "canactid:1:t.a.1:jcs-sha256:" + "A" * 43

    def test_valid_and_details(self):
        obj = {"action_type": "t.a.1", "a": "x"}
        computed = caid.compute_caid(obj, OPTS)
        result = caid.verify_caid(obj, computed["caid"], OPTS)
        self.assertEqual(result, {"valid": True, "reasons": [], "details": [], "definition_sha256": computed["definition_sha256"]})
        result = caid.verify_caid({"action_type": "t.b.1", "a": 5}, computed["caid"], OPTS)
        self.assertEqual(result["reasons"], ["action_type_mismatch", "digest_mismatch", "invalid_object"])
        self.assertEqual(result["details"], [
            {"reason": "action_type_mismatch", "field": "action_type", "rule": "action-type-equal", "observed": "string"},
            {"reason": "digest_mismatch", "field": None, "rule": "digest-equal", "observed": None},
            {"reason": "unknown_action_type", "field": None, "rule": "definition-resolution", "observed": None},
        ])
        self.assertNotIn("definition_sha256", result)

    def test_field_details(self):
        result = caid.verify_caid({"action_type": "t.a.1", "n": (1,)}, self.CAID, OPTS)
        self.assertEqual(result["reasons"], ["invalid_object"])
        self.assertEqual(result["details"], [
            {"reason": "missing_material_field:a", "field": "a", "rule": "required-field", "observed": "absent"},
            {"reason": "mistyped_field:n", "field": "n", "rule": "field-type", "observed": "unsupported"},
            {"reason": "unsupported_value", "field": None, "rule": "data-model", "observed": None},
        ])

    def test_non_object(self):
        for value, kind in (([], "array"), (None, "null"), ("x", "string"), ((), "unsupported")):
            result = caid.verify_caid(value, self.CAID, OPTS)
            self.assertEqual(result, {"valid": False, "reasons": ["invalid_object"], "details": [
                {"reason": "invalid_action_type", "field": "action_type", "rule": "action-type", "observed": kind}]})

    def test_parse_failures(self):
        self.assertEqual(caid.verify_caid({}, "canactid:1:t.a.1:foo:x", OPTS)["details"],
                         [{"reason": "unknown_suite", "field": None, "rule": "suite", "observed": None}])
        self.assertEqual(caid.verify_caid({})["details"][0]["observed"], "absent")
        self.assertEqual(caid.verify_caid({}, 5)["details"][0]["observed"], "number")
        self.assertEqual(caid.verify_caid_json(b"not json", "bad")["reasons"], ["malformed_caid"])
        self.assertEqual(caid.verify_caid_json(b"not json", self.CAID), {"valid": False, "reasons": ["malformed_json"], "details": [
            {"reason": "malformed_json", "field": None, "rule": "json-text", "observed": None}]})

    def test_expected_definition_sha256(self):
        obj = {"action_type": "t.a.1", "a": "x"}
        computed = caid.compute_caid(obj, OPTS)
        pinned = dict(OPTS, expected_definition_sha256=computed["definition_sha256"])
        self.assertTrue(caid.verify_caid(obj, computed["caid"], pinned)["valid"])
        wrong = dict(OPTS, expected_definition_sha256="sha256:" + "0" * 64)
        result = caid.verify_caid(obj, computed["caid"], wrong)
        self.assertEqual(result["reasons"], ["definition_mismatch"])
        self.assertEqual(result["details"], [{"reason": "definition_mismatch", "field": None, "rule": "definition-sha256", "observed": None}])
        unresolved = caid.verify_caid({"action_type": "t.z.1"}, computed["caid"], wrong)
        self.assertNotIn("definition_mismatch", unresolved["reasons"])

    def test_unimplemented_registered_suite(self):
        obj = {"action_type": "t.a.1", "a": "x"}
        result = caid.verify_caid(obj, self.CAID.replace("jcs-sha256", "cbor-sha256"), OPTS)
        self.assertEqual(result["reasons"], ["unknown_suite"])


def _candidate(field):
    samples = {"icd-10-cm": "E11.9", "ndc-11": "00002143380", "hcpcs": "J1234", "nacha-sec": "PPD",
               "iso20022-external-code": "AC04", "cpt": "99213", "iso-3166-1-alpha-2": "US"}
    t = field["type"]
    if t == "string":
        return "x"
    if t == "amount-string":
        return "1.00"
    if t == "digest":
        return "sha256:" + "0" * 64
    if t == "timestamp":
        return "2026-02-28T00:00:00Z"
    if t == "integer":
        return 1
    if t == "boolean":
        return True
    if t == "object":
        return {}
    if t == "array":
        return []
    if t == "code":
        return samples[field["format"]]
    if t == "enum":
        if "values" in field:
            return field["values"][0]
        ref = field.get("values_ref", "")
        if ref.startswith("inline:"):
            return ref[len("inline:"):].split("|")[0].strip()
        for s in SNAPSHOTS:
            if s["values_ref"] == ref and s["values_snapshot"] == field.get("values_snapshot"):
                return s["values"][0]
        return "UNRESOLVED"
    return None


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------

MAP_DEFS = [{"action_type": "t.m.1", "required_fields": [{"name": "x", "type": "string"}, {"name": "y", "type": "string"}],
             "optional_fields": [{"name": "d", "type": "digest"}, {"name": "@version", "type": "string"}]}]
SOURCE = {"a": "1", "b": "2", "h": "0" * 64, "list": ["p", "q"]}


def _profile(**changes):
    profile = {
        "@version": mapping.MAPPING_PROFILE_VERSION,
        "profile_id": "p",
        "source_format": {"media_type": "application/json", "schema": "s", "version": "1"},
        "target_action_type": "t.m.1",
        "loss_policy": "no-material-field-loss",
        "material_source_paths": ["/a", "/b"],
        "rules": [{"source_path": "/a", "target_field": "x", "transform": "copy"},
                  {"source_path": "/b", "target_field": "y", "transform": "copy"}],
    }
    profile.update(changes)
    return profile


def _map(profile, source=SOURCE, pin=True, native=True, suite="jcs-sha256", descriptor=None):
    return mapping.map_action(
        source, profile=profile,
        source_descriptor=descriptor if descriptor is not None else (profile.get("source_format") if isinstance(profile, dict) else None),
        expected_profile_hash=mapping.mapping_profile_hash(profile) if pin else None,
        native_verified=native, definitions=MAP_DEFS, suite=suite)


class MappingTest(unittest.TestCase):
    def reasons(self, *args, **kwargs):
        result = _map(*args, **kwargs)
        return result["reasons"] if not result["ok"] else []

    def test_happy_path(self):
        result = _map(_profile())
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], {"action_type": "t.m.1", "x": "1", "y": "2"})

    def test_success_carries_definition_sha256(self):
        result = _map(_profile())
        self.assertEqual(result["definition_sha256"], caid.definition_sha256(MAP_DEFS[0])["definition_sha256"])

    def test_profile_outside_the_data_model_is_a_shape_failure(self):
        # A profile with no digest fails the stage A gate: exactly
        # invalid_mapping_profile, and no later stage A check runs.
        for profile_id in ("\uffff", "\ud800", "\U0010FFFF"):
            profile = _profile(profile_id=profile_id, rules=[{"source_path": "/a", "target_field": "x", "transform": "copy"}],
                               material_source_paths=["/a"])
            self.assertEqual(self.reasons(profile), ["invalid_mapping_profile", "mapping_profile_unpinned"], repr(profile_id))

    def test_d2_null_omissions(self):
        self.assertEqual(self.reasons(_profile(omitted_source_fields=None)), ["invalid_mapping_profile"])
        self.assertEqual(self.reasons(_profile(omitted_source_fields=[])), [])

    def test_d3_lengths_are_utf8_octets(self):
        self.assertEqual(self.reasons(_profile(profile_id="\u00e9" * 256)), [])
        self.assertEqual(self.reasons(_profile(profile_id="\u00e9" * 257)), ["invalid_mapping_profile"])
        self.assertEqual(self.reasons(_profile(profile_id="\U0001F600" * 128)), [])
        self.assertEqual(self.reasons(_profile(profile_id="\U0001F600" * 129)), ["invalid_mapping_profile"])
        self.assertEqual(self.reasons(_profile(target_action_type="t." * 300 + "1")), ["invalid_mapping_profile"])
        long_path = "/" + "a" * 2047
        self.assertEqual(self.reasons(_profile(material_source_paths=[long_path, "/b"],
                                               rules=[{"source_path": long_path, "target_field": "x", "transform": "copy"},
                                                      {"source_path": "/b", "target_field": "y", "transform": "copy"}])),
                         ["missing_source_field:" + long_path])
        too_long = "/" + "a" * 2048
        self.assertEqual(self.reasons(_profile(material_source_paths=[too_long, "/b"],
                                               rules=[{"source_path": too_long, "target_field": "x", "transform": "copy"},
                                                      {"source_path": "/b", "target_field": "y", "transform": "copy"}])),
                         ["invalid_mapping_profile"])

    def test_d5_target_field_type(self):
        rules = [{"source_path": "/a", "target_field": ["x"], "transform": "copy"}, {"source_path": "/b", "target_field": "y", "transform": "copy"}]
        self.assertEqual(self.reasons(_profile(rules=rules)), ["invalid_mapping_profile"])
        rules[0]["target_field"] = "action_type"
        self.assertEqual(self.reasons(_profile(rules=rules)), ["invalid_mapping_profile"])

    def test_d6_coverage_is_a_set_comparison(self):
        rules = [{"source_path": "/x\n/y", "target_field": "x", "transform": "copy"}]
        self.assertEqual(self.reasons(_profile(rules=rules, material_source_paths=["/x", "/y"])), ["invalid_mapping_profile", "unmapped_material_field:y"])

    def test_d8_unhashable_members(self):
        for changes in ({"loss_policy": ["x"]}, {"material_source_paths": [["/a"], "/b"]},
                        {"rules": [{"source_path": "/a", "target_field": "x", "transform": ["copy"]},
                                   {"source_path": "/b", "target_field": "y", "transform": "copy"}]},
                        {"source_format": {"media_type": ["a"], "schema": "s", "version": "1"}}):
            result = _map(_profile(**changes))
            self.assertEqual(result["reasons"], ["invalid_mapping_profile"], changes)
            self.assertIsNotNone(result["profile_hash"])

    def test_d9_shape_gate(self):
        self.assertEqual(self.reasons(_profile(material_source_paths=[123], target_action_type="t.unknown.1")), ["invalid_mapping_profile"])

    def test_d10_empty_suite(self):
        self.assertEqual(self.reasons(_profile(), suite=""), ["mapped_action:unknown_suite"])
        self.assertEqual(self.reasons(_profile(), suite=["jcs-sha256"]), ["mapped_action:unknown_suite"])

    def test_exactly_one_rule_per_path(self):
        rules = [{"source_path": "/a", "target_field": "x", "transform": "copy"}, {"source_path": "/a", "target_field": "y", "transform": "copy"}]
        self.assertEqual(self.reasons(_profile(rules=rules, material_source_paths=["/a"])), ["invalid_mapping_profile"])

    def test_limits_and_members(self):
        many = [{"source_path": "/r%d" % i, "target_field": "f%d" % i, "transform": "copy"} for i in range(129)]
        self.assertEqual(self.reasons(_profile(rules=many, material_source_paths=[r["source_path"] for r in many])), ["invalid_mapping_profile"])
        self.assertEqual(self.reasons(_profile(extra=1)), ["invalid_mapping_profile"])
        self.assertEqual(self.reasons(_profile(profile_id=None)), ["invalid_mapping_profile"])
        bad_rule = [{"source_path": "/a", "target_field": "x", "transform": "copy", "note": "n"}, {"source_path": "/b", "target_field": "y", "transform": "copy"}]
        self.assertEqual(self.reasons(_profile(rules=bad_rule)), ["invalid_mapping_profile"])
        self.assertEqual(self.reasons(_profile(**{"@version": "CAID-MAPPING-PROFILE-v2"})), ["invalid_mapping_profile"])
        self.assertEqual(self.reasons(_profile(material_source_paths=["/a", "/b~2"])), ["invalid_mapping_profile"])

    def test_loss_policies(self):
        omission = [{"source_path": "/c", "reason": "dropped"}]
        self.assertEqual(self.reasons(_profile(omitted_source_fields=omission)), ["invalid_mapping_profile"])
        self.assertEqual(self.reasons(_profile(loss_policy="declared-source-semantic-loss", omitted_source_fields=omission)), ["declared_source_semantic_loss"])
        self.assertEqual(self.reasons(_profile(loss_policy="declared-source-semantic-loss")), ["invalid_mapping_profile", "declared_source_semantic_loss"])
        overlap = [{"source_path": "/a", "reason": "dropped"}]
        self.assertEqual(self.reasons(_profile(loss_policy="declared-source-semantic-loss", omitted_source_fields=overlap)), ["invalid_mapping_profile", "declared_source_semantic_loss"])

    def test_stage_a_and_b_sort_by_rank(self):
        result = self.reasons(_profile(target_action_type="t.unknown.1"), pin=False, native=False, source=[], descriptor={})
        self.assertEqual(result, ["unknown_action_type", "native_verification_required", "mapping_profile_unpinned",
                                  "source_format_mismatch", "source_not_object", "source_not_canonicalizable"])
        result = self.reasons(_profile(rules=[{"source_path": "/a", "target_field": "x", "transform": "copy"}], material_source_paths=["/a"]), native=False)
        self.assertEqual(result, ["unmapped_material_field:y", "native_verification_required"])

    def test_stage_c_is_rule_order(self):
        rules = [{"source_path": "/missing", "target_field": "x", "transform": "copy"},
                 {"source_path": "/list/01", "target_field": "y", "transform": "copy"},
                 {"source_path": "/list/1", "target_field": "d", "transform": "sha256-hex-to-digest"}]
        result = self.reasons(_profile(rules=rules, material_source_paths=[r["source_path"] for r in rules]))
        self.assertEqual(result, ["missing_source_field:/missing", "invalid_source_path:/list/01", "source_value_type_mismatch:/list/1"])

    def test_stage_d_and_transforms(self):
        rules = [{"source_path": "/a", "target_field": "x", "transform": "copy"},
                 {"source_path": "/b", "target_field": "y", "transform": "sha256-utf8"},
                 {"source_path": "/h", "target_field": "d", "transform": "sha256-hex-to-digest"},
                 {"source_path": "/list", "target_field": "@version", "transform": "sha256-jcs"}]
        result = _map(_profile(rules=rules, material_source_paths=[r["source_path"] for r in rules]))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["action"]["d"], "sha256:" + "0" * 64)
        rules = [{"source_path": "/a", "target_field": "d", "transform": "copy"},
                 {"source_path": "/b", "target_field": "x", "transform": "copy"},
                 {"source_path": "/list", "target_field": "y", "transform": "copy"}]
        result = _map(_profile(rules=rules, material_source_paths=[r["source_path"] for r in rules]))
        self.assertEqual(result["reasons"], ["mapped_action:mistyped_field:y", "mapped_action:mistyped_field:d"])

    def test_comparison(self):
        left = {"source": SOURCE, "profile": _profile(), "source_descriptor": _profile()["source_format"],
                "expected_profile_hash": mapping.mapping_profile_hash(_profile()), "native_verified": True}
        right = dict(left, source=dict(SOURCE, a="9"))
        self.assertEqual(mapping.compare_mapped_actions(left, left, definitions=MAP_DEFS)["verdict"], mapping.EQUIVALENT_UNDER_PROFILE)
        different = mapping.compare_mapped_actions(left, right, definitions=MAP_DEFS)
        self.assertEqual((different["verdict"], different["reasons"]), (mapping.NOT_EQUIVALENT, ["material_projection_mismatch"]))
        broken = dict(left, native_verified=False)
        both = mapping.compare_mapped_actions(broken, dict(broken, expected_profile_hash=None), definitions=MAP_DEFS)
        self.assertEqual(both["reasons"], ["left:native_verification_required", "right:native_verification_required", "right:mapping_profile_unpinned"])
        self.assertEqual(mapping.compare_mapped_actions(None, [], definitions=MAP_DEFS)["verdict"], mapping.INDETERMINATE)

    def test_never_throws(self):
        class Evil(dict):
            def items(self):
                raise RuntimeError("items")
        for profile in (None, 5, [], Evil(), {"@version": Evil()}, _profile(rules=[Evil()])):
            result = _map(profile)
            self.assertFalse(result["ok"])
            self.assertNotIn("unexpected_mapping_error", result["reasons"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
