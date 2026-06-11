# SPDX-License-Identifier: Apache-2.0
"""Cross-language digest parity.

Expected values were produced by the JS canonicalize() in packages/verify
(node, 2026-06-11). If these ever fail, the executor-side binding has drifted
from the verifier — that is a protocol bug, not a test to update casually.
"""
from langchain_emilia import action_digest, canonicalize

VECTORS = [
    (
        {"tool": "wire_transfer", "args": {"amount": 82000, "currency": "USD", "beneficiary": "Northwind Logistics LLC"}},
        '{"args":{"amount":82000,"beneficiary":"Northwind Logistics LLC","currency":"USD"},"tool":"wire_transfer"}',
        "b9307902bb8f12376650bc1ada045cc4a5a758f08eae296408bd1ea5dcbe7e2b",
    ),
    (
        {"tool": "send_email", "args": {"to": ["a@x.com", "b@y.com"], "subject": "Q3 — résumé ✓", "body": None}},
        '{"args":{"body":null,"subject":"Q3 — résumé ✓","to":["a@x.com","b@y.com"]},"tool":"send_email"}',
        "9670795b22e40364a7323a55cc0265fda5de2f51c0c8b9a73bb2a383a15425b7",
    ),
    (
        {"tool": "update_record", "args": {"id": 42, "fields": {"nested": {"z": True, "a": 1.5}, "empty": []}}},
        '{"args":{"fields":{"empty":[],"nested":{"a":1.5,"z":true}},"id":42},"tool":"update_record"}',
        "821dad9bae87effe01b48ce8235ea5474e7f9e55662efbb938094bddc3f5d6ca",
    ),
]


def test_canonical_strings_match_js_byte_for_byte():
    for envelope, expected_canonical, _ in VECTORS:
        assert canonicalize(envelope) == expected_canonical


def test_action_digest_matches_js_sha256():
    for envelope, _, expected_sha in VECTORS:
        assert action_digest(envelope["tool"], envelope["args"]) == expected_sha


def test_digest_changes_when_one_field_changes():
    base = action_digest("wire_transfer", {"amount": 82000, "beneficiary": "Northwind"})
    tampered = action_digest("wire_transfer", {"amount": 820000, "beneficiary": "Northwind"})
    assert base != tampered


def test_key_order_is_irrelevant():
    a = action_digest("t", {"b": 1, "a": 2})
    b = action_digest("t", {"a": 2, "b": 1})
    assert a == b
