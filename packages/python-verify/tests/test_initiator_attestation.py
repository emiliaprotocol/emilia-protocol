# SPDX-License-Identifier: Apache-2.0
"""EP-INITIATOR-ATTESTATION-v1 parity test (port of initiator-attestation.test.js).

All hostile / invisible codepoints are constructed via chr(...) so the SOURCE
stays pure ASCII (no literal bidi or control bytes to smuggle past review). Same
accepts/refuses and the same neutralization behavior as the JS reference.

    pytest packages/python-verify/tests/test_initiator_attestation.py
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from emilia_verify import (  # noqa: E402
    canonicalize,
    INITIATOR_ATTESTATION_VERSION,
    INITIATOR_ATTESTATION_FIELD,
    INITIATOR_STATEMENT_MAX,
    validate_initiator_attestation,
    neutralize_statement,
    normalize_digest,
    bind_into,
)

RLO = chr(0x202e)   # right-to-left override (bidi)
NUL = chr(0x0000)   # C0 control
BEL = chr(0x0007)   # C0 control
NEL = chr(0x0085)   # C1 control
ZWSP = chr(0x200b)  # zero-width space
BOM = chr(0xfeff)   # BOM / ZWNBSP
CYR_A = chr(0x0430)  # Cyrillic "а" homoglyph of Latin "a"

DIGEST = "sha256:" + hashlib.sha256(b"tool-context").hexdigest()


def valid_att():
    return {
        "model_id": "anthropic/claude-opus",
        "model_version": "2026-01-05",
        "tool_chain_digest": DIGEST,
    }


# ── validation: happy path ────────────────────────────────────────────────────
def test_valid_attestation_normalizes():
    r = validate_initiator_attestation(valid_att())
    assert r["ok"] is True
    assert r["errors"] == []
    assert r["normalized"]["@version"] == INITIATOR_ATTESTATION_VERSION
    assert r["normalized"]["model_id"] == "anthropic/claude-opus"
    assert r["normalized"]["model_version"] == "2026-01-05"
    assert r["normalized"]["tool_chain_digest"] == DIGEST.lower()
    assert "statement" not in r["normalized"]


def test_bare_uppercase_hex_normalizes():
    bare = hashlib.sha256(b"ctx").hexdigest()
    r = validate_initiator_attestation({**valid_att(), "tool_chain_digest": bare.upper()})
    assert r["ok"] is True
    assert r["normalized"]["tool_chain_digest"] == f"sha256:{bare}"


# ── validation: fail-closed rejections ────────────────────────────────────────
def test_missing_model_id_rejected():
    att = valid_att()
    del att["model_id"]
    r = validate_initiator_attestation(att)
    assert r["ok"] is False
    assert r["normalized"] is None
    assert "model_id is required" in " ".join(r["errors"])


def test_empty_model_version_rejected():
    r = validate_initiator_attestation({**valid_att(), "model_version": ""})
    assert r["ok"] is False
    assert "model_version is required" in " ".join(r["errors"])


def test_malformed_digest_rejected():
    for bad in ["sha256:xyz", "deadbeef", "sha256:" + "a" * 63, 123, None]:
        r = validate_initiator_attestation({**valid_att(), "tool_chain_digest": bad})
        assert r["ok"] is False, f"expected reject for {bad!r}"
        assert r["normalized"] is None


def test_missing_digest_rejected():
    att = valid_att()
    del att["tool_chain_digest"]
    r = validate_initiator_attestation(att)
    assert r["ok"] is False
    assert "tool_chain_digest is required" in " ".join(r["errors"])


def test_unknown_member_rejected():
    r = validate_initiator_attestation({**valid_att(), "evil": "x"})
    assert r["ok"] is False
    assert 'unknown member "evil"' in " ".join(r["errors"])


def test_wrong_version_rejected():
    r = validate_initiator_attestation({**valid_att(), "@version": "EP-OTHER-v9"})
    assert r["ok"] is False
    assert "@version must be" in " ".join(r["errors"])


def test_non_object_rejected():
    for bad in [None, 42, "str", ["a"]]:
        r = validate_initiator_attestation(bad)
        assert r["ok"] is False
        assert r["normalized"] is None


def test_statement_wrong_type_rejected():
    r = validate_initiator_attestation({**valid_att(), "statement": {"not": "a string"}})
    assert r["ok"] is False
    assert "statement, when present, must be a string" in " ".join(r["errors"])


def test_statement_over_cap_rejected():
    r = validate_initiator_attestation({**valid_att(), "statement": "a" * (INITIATOR_STATEMENT_MAX + 1)})
    assert r["ok"] is False
    assert "exceeds the" in " ".join(r["errors"]) and "cap" in " ".join(r["errors"])


# ── hostile-text neutralization ───────────────────────────────────────────────
def test_bidi_and_controls_neutralized():
    hostile = f"send {RLO}{NUL}000,1${BEL} pay{NEL} now"
    r = validate_initiator_attestation({**valid_att(), "statement": hostile})
    assert r["ok"] is True
    safe = r["normalized"]["statement"]
    for codepoint in [0x202e, 0x0000, 0x0007, 0x0085]:
        assert chr(codepoint) not in safe, f"codepoint U+{codepoint:x} survived"
    assert "<U+202E>" in safe
    assert "<U+0000>" in safe
    assert "<U+0007>" in safe
    assert "<U+0085>" in safe
    rep = r["statement_report"]
    assert rep["changed"] is True
    assert sorted(rep["escaped_codepoints"]) == [0x0000, 0x0007, 0x0085, 0x202e]


def test_ordinary_whitespace_preserved():
    r = neutralize_statement("line1\n\tline2\r ok")
    assert r["safe"] == "line1\n\tline2\r ok"
    assert r["changed"] is False
    assert r["homoglyph_risk"] is False


def test_zero_width_and_bom_escaped():
    r = neutralize_statement(f"a{ZWSP}b{BOM}c")
    assert ZWSP not in r["safe"]
    assert BOM not in r["safe"]
    assert "<U+200B>" in r["safe"]
    assert "<U+FEFF>" in r["safe"]
    assert r["changed"] is True


def test_homoglyph_flagged():
    r = neutralize_statement(f"p{CYR_A}y now")
    assert r["homoglyph_risk"] is True


def test_non_string_is_empty_statement():
    for bad in [None, 42, {"a": 1}, ["x"]]:
        r = neutralize_statement(bad)
        assert r["safe"] == ""
        assert r["changed"] is False


def test_caps_by_codepoints_and_flags_truncation():
    r = neutralize_statement("x" * (INITIATOR_STATEMENT_MAX + 50))
    assert len(list(r["safe"])) == INITIATOR_STATEMENT_MAX
    assert r["truncated"] is True


def test_normalize_digest_edges():
    assert normalize_digest("sha256:zz") == ""
    assert normalize_digest(None) == ""
    good = "a" * 64
    assert normalize_digest(f"SHA256:{good.upper()}") == good


# ── bind_into: composition with the frozen action hash ────────────────────────
def test_bind_into_places_neutralized_and_changes_digest():
    action = {"action_type": "wire.transfer", "amount": 100, "initiator": "ep:entity:agent-7"}
    baseline = "sha256:" + hashlib.sha256(canonicalize(action).encode("utf-8")).hexdigest()

    out = bind_into(action, {**valid_att(), "statement": f"ok {RLO}spoof"})
    bound = out["action"]
    assert bound[INITIATOR_ATTESTATION_FIELD]["@version"] == INITIATOR_ATTESTATION_VERSION
    assert RLO not in bound[INITIATOR_ATTESTATION_FIELD]["statement"]
    assert "<U+202E>" in bound[INITIATOR_ATTESTATION_FIELD]["statement"]
    assert out["attestation"]["model_id"] == "anthropic/claude-opus"

    assert out["digest_preview"] != baseline
    assert out["digest_preview"] == "sha256:" + hashlib.sha256(canonicalize(bound).encode("utf-8")).hexdigest()


def test_bind_into_throws_on_invalid():
    try:
        bind_into({"action_type": "wire.transfer"}, {"model_id": "x"})
        assert False, "expected raise"
    except ValueError as e:
        assert "invalid initiator attestation" in str(e)


def test_bind_into_refuses_overwrite_of_different_member():
    action = {"action_type": "x", INITIATOR_ATTESTATION_FIELD: {"model_id": "other"}}
    try:
        bind_into(action, valid_att())
        assert False, "expected raise"
    except ValueError as e:
        assert "refusing to overwrite" in str(e)


def test_bind_into_idempotent_when_equal():
    action = {"action_type": "x"}
    once = bind_into(action, valid_att())
    twice = bind_into(once["action"], valid_att())
    assert twice["digest_preview"] == once["digest_preview"]


def test_bind_into_requires_plain_object():
    for bad in [None, ["a"]]:
        try:
            bind_into(bad, valid_att())
            assert False, "expected raise"
        except TypeError as e:
            assert "requires the canonical Action Object" in str(e)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ALL PASS — EP-INITIATOR-ATTESTATION-v1 parity")
