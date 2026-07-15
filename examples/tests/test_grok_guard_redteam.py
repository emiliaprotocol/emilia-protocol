# SPDX-License-Identifier: Apache-2.0
"""Permanent red-team regression suite for examples/grok_guard.py.

Re-runs all six adversarial vectors the red-team found, plus the genuine
happy-path control, against the OFFLINE verification gate (`_verify_evidence_offline`
and the `EmiliaGuard.verify_receipt_offline` path). NO network, NO Supabase, NO
prod: the genuine fixture is the JS-signed receipt the cross-language conformance
suite uses, and attacker keys are generated locally with `cryptography` exactly as
packages/python-verify/tests/test_verify.py does.

    # direct (mirrors test_verify.py):
    PYTHONPATH=packages/python-verify python3 examples/tests/test_grok_guard_redteam.py
    # or via pytest:
    PYTHONPATH=packages/python-verify pytest examples/tests/test_grok_guard_redteam.py

The six vectors (red-team finding -> expected verdict after hardening):
  1. tampered action under the enrolled key            -> signature_invalid
  2. attacker self-signs, serves own pubkey (unpinned) -> untrusted_signer
  3. genuinely-signed DIFFERENT receipt (id/amount)    -> claim_mismatch
  5a. anchor stripped/partial when require_anchor=True  -> anchor_required
  5b. same receipt presented twice / consumed status    -> replay / already_consumed
  6. hostile evidence bodies (str/int/list/junk/raise)  -> verified=False, never raises
Plus CONTROL: genuine fixture + matching expected + fixture key pinned (+ anchor)
   -> verified/proceed True.
"""
import base64
import copy
import json
import os
import sys

# Put the pure-Python verifier and the examples/ package on the path so this
# runs both directly and under pytest, from the repo root.
_THIS = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_THIS, "..", ".."))
sys.path.insert(0, os.path.join(_REPO, "packages", "python-verify"))
sys.path.insert(0, _REPO)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from emilia_verify import canonicalize  # noqa: E402

from examples.grok_guard import (  # noqa: E402
    InMemoryReplayStore,
    VerifiedReceipt,
    _verify_evidence_offline,
    expected_from_args,
    load_trusted_signer_keys,
)

FIX = os.path.join(_REPO, "packages", "python-verify", "tests", "fixtures")


# ── Fixtures + helpers ───────────────────────────────────────────────────────
def _load_fixture():
    """The genuine JS-signed EP-RECEIPT-v1 + its base64url SPKI public key."""
    with open(os.path.join(FIX, "receipt.json")) as f:
        doc = json.load(f)
    with open(os.path.join(FIX, "pubkey.txt")) as f:
        pub = f.read().strip()
    return doc, pub


def _evidence(doc, pub):
    """Wrap a signed document the way /evidence serves it."""
    return {
        "document": doc,
        "public_key": pub,
        "signed": True,
        "verify_with": "@emilia-protocol/verify",
    }


# The request the agent actually made — must match the genuine fixture's claim.
# Field paths: receipt_id=payload.receipt_id, amount/currency/destination=
# payload.claim.context.*, approver=payload.claim.approver.
GENUINE_ARGS = {
    "action_type": "large_payment_release",
    "amount": 50000,
    "currency": "USD",
    "target_resource_id": "acct_9f12",
    "approver_id": "operator:iman.schrock",
}
GENUINE_EXPECTED = expected_from_args(GENUINE_ARGS, "ep_demo_8c1f2a")


def _attacker_keypair():
    priv = Ed25519PrivateKey.generate()
    der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.urlsafe_b64encode(der).decode().rstrip("=")
    return priv, pub_b64


def _sign_doc(payload, priv, anchor=None):
    """Build an EP-RECEIPT-v1 document signed over `payload` with `priv`,
    canonicalizing exactly as emilia_verify does."""
    sig = priv.sign(canonicalize(payload).encode("utf-8"))
    doc = {
        "@version": "EP-RECEIPT-v1",
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "value": base64.urlsafe_b64encode(sig).decode().rstrip("="),
        },
    }
    if anchor is not None:
        doc["anchor"] = anchor
    return doc


# ── CONTROL: genuine receipt proceeds ────────────────────────────────────────
def test_control_genuine_receipt_proceeds():
    """Genuine fixture + matching expected + fixture key pinned + anchor required
    -> verified True. This is the happy path that MUST keep working."""
    doc, pub = _load_fixture()
    pinned = load_trusted_signer_keys([pub])
    r = _verify_evidence_offline(
        _evidence(doc, pub),
        expected=GENUINE_EXPECTED,
        trusted_signer_keys=pinned,
        require_anchor=True,  # the genuine fixture carries a valid Merkle anchor
        replay_store=InMemoryReplayStore(),
    )
    assert isinstance(r, VerifiedReceipt)
    assert r.verified is True, r
    assert r.status == "verified"
    assert r.checks.get("signature") is True
    assert r.checks.get("anchor") is True


def test_control_proceeds_via_fingerprint_pin():
    """Pinning by SHA-256 fingerprint (not the raw key) also proceeds — the
    server-independent trust root can be a fingerprint."""
    doc, pub = _load_fixture()
    from examples.grok_guard import _spki_fingerprint

    pinned = load_trusted_signer_keys([_spki_fingerprint(pub)])
    r = _verify_evidence_offline(
        _evidence(doc, pub),
        expected=GENUINE_EXPECTED,
        trusted_signer_keys=pinned,
        replay_store=InMemoryReplayStore(),
    )
    assert r.verified is True, r


# ── Vector 1: tampered action under the enrolled key ─────────────────────────
def test_vector1_tampered_action_signature_invalid():
    """The amount is changed AFTER signing under the genuine enrolled key. The
    signature no longer covers these bytes -> signature_invalid (the gate never
    even reaches the binding/pinning checks)."""
    doc, pub = _load_fixture()
    tampered = copy.deepcopy(doc)
    tampered["payload"]["claim"]["context"]["amount"] = 82000  # tamper
    pinned = load_trusted_signer_keys([pub])
    r = _verify_evidence_offline(
        _evidence(tampered, pub),
        expected=GENUINE_EXPECTED,
        trusted_signer_keys=pinned,
        replay_store=InMemoryReplayStore(),
    )
    assert r.verified is False
    assert r.status == "signature_invalid", r
    assert r.checks.get("signature") is False


# ── Vector 2: attacker self-signs and serves its own pubkey ──────────────────
def test_vector2_attacker_key_untrusted_signer():
    """A fully compromised server forges a document, signs it with its OWN key,
    and serves its OWN pubkey. The signature is internally valid, but the key is
    not in the pinned set -> untrusted_signer. THIS is the FIX-2 defense."""
    doc, pub = _load_fixture()  # pin the GENUINE key only
    priv_atk, pub_atk = _attacker_keypair()
    # Attacker forges an $82k release that otherwise looks legitimate.
    payload = copy.deepcopy(doc["payload"])
    payload["claim"]["context"]["amount"] = 82000
    forged = _sign_doc(payload, priv_atk)
    pinned = load_trusted_signer_keys([pub])  # attacker key NOT pinned
    r = _verify_evidence_offline(
        _evidence(forged, pub_atk),  # server also serves attacker's pubkey
        expected=None,  # even with no binding, pinning blocks it
        trusted_signer_keys=pinned,
        replay_store=InMemoryReplayStore(),
    )
    assert r.verified is False
    assert r.status == "untrusted_signer", r


def test_vector2b_no_pinned_set_fails_closed():
    """Secure-by-default: with NO pinned set at all, even the genuine receipt is
    rejected -> untrusted_signer. The guard NEVER falls back to trusting the
    inline key."""
    doc, pub = _load_fixture()
    r = _verify_evidence_offline(
        _evidence(doc, pub),
        expected=GENUINE_EXPECTED,
        trusted_signer_keys=None,  # nothing configured
        replay_store=InMemoryReplayStore(),
    )
    assert r.verified is False
    assert r.status == "untrusted_signer", r
    assert "no trusted signer keys configured" in (r.detail or "")


# ── Vector 3: genuinely-signed DIFFERENT receipt ─────────────────────────────
def test_vector3_different_amount_claim_mismatch():
    """A genuinely-signed $50k receipt (the fixture) is presented to authorize an
    $82k wire. The signature and signer are fine, but the signed amount != the
    requested amount -> claim_mismatch. THIS is the FIX-1 defense."""
    doc, pub = _load_fixture()
    pinned = load_trusted_signer_keys([pub])
    expected_82k = expected_from_args({**GENUINE_ARGS, "amount": 82000}, "ep_demo_8c1f2a")
    r = _verify_evidence_offline(
        _evidence(doc, pub),
        expected=expected_82k,
        trusted_signer_keys=pinned,
        replay_store=InMemoryReplayStore(),
    )
    assert r.verified is False
    assert r.status == "claim_mismatch", r
    assert "amount mismatch" in (r.detail or "")


def test_vector3b_different_receipt_id_claim_mismatch():
    """A genuinely-signed receipt for a DIFFERENT receipt_id cannot be substituted
    for the one this agent minted -> claim_mismatch on the PRIMARY binding."""
    doc, pub = _load_fixture()
    pinned = load_trusted_signer_keys([pub])
    expected_other = expected_from_args(GENUINE_ARGS, "ep_some_other_receipt")
    r = _verify_evidence_offline(
        _evidence(doc, pub),
        expected=expected_other,
        trusted_signer_keys=pinned,
        replay_store=InMemoryReplayStore(),
    )
    assert r.verified is False
    assert r.status == "claim_mismatch", r
    assert "receipt_id mismatch" in (r.detail or "")


def test_vector3c_different_destination_claim_mismatch():
    """Same amount + same id, but the destination account differs from what the
    agent requested -> claim_mismatch (money-destination binding)."""
    doc, pub = _load_fixture()
    pinned = load_trusted_signer_keys([pub])
    expected_dest = expected_from_args(
        {**GENUINE_ARGS, "target_resource_id": "acct_attacker"}, "ep_demo_8c1f2a"
    )
    r = _verify_evidence_offline(
        _evidence(doc, pub),
        expected=expected_dest,
        trusted_signer_keys=pinned,
        replay_store=InMemoryReplayStore(),
    )
    assert r.verified is False
    assert r.status == "claim_mismatch", r
    assert "destination mismatch" in (r.detail or "")


def test_vector3d_missing_material_fields_and_action_substitution_fail_closed():
    """Signed omission is not a wildcard: every expected material field and
    the mapped action type must be present and equal."""
    fixture, _fixture_pub = _load_fixture()
    cases = []

    missing_currency = copy.deepcopy(fixture["payload"])
    del missing_currency["claim"]["context"]["currency"]
    cases.append((missing_currency, "currency mismatch"))

    missing_destination = copy.deepcopy(fixture["payload"])
    del missing_destination["claim"]["context"]["destination"]
    cases.append((missing_destination, "destination mismatch"))

    missing_approver = copy.deepcopy(fixture["payload"])
    del missing_approver["claim"]["approver"]
    cases.append((missing_approver, "approver mismatch"))

    wrong_action = copy.deepcopy(fixture["payload"])
    wrong_action["claim"]["action"] = "database.delete"
    cases.append((wrong_action, "action_type mismatch"))

    for payload, expected_detail in cases:
        private_key, public_key = _attacker_keypair()
        signed = _sign_doc(payload, private_key)
        result = _verify_evidence_offline(
            _evidence(signed, public_key),
            expected=GENUINE_EXPECTED,
            trusted_signer_keys=load_trusted_signer_keys([public_key]),
            replay_store=InMemoryReplayStore(),
        )
        assert result.verified is False, result
        assert result.status == "claim_mismatch", result
        assert expected_detail in (result.detail or ""), result


def test_vector3e_amount_comparison_does_not_round_through_float():
    """Adjacent integers above binary-float precision cannot compare equal."""
    fixture, _fixture_pub = _load_fixture()
    payload = copy.deepcopy(fixture["payload"])
    payload["claim"]["context"]["amount"] = "9007199254740993"
    private_key, public_key = _attacker_keypair()
    signed = _sign_doc(payload, private_key)
    expected = {**GENUINE_EXPECTED, "amount": "9007199254740992"}
    result = _verify_evidence_offline(
        _evidence(signed, public_key),
        expected=expected,
        trusted_signer_keys=load_trusted_signer_keys([public_key]),
        replay_store=InMemoryReplayStore(),
    )
    assert result.verified is False, result
    assert result.status == "claim_mismatch", result
    assert "amount mismatch" in (result.detail or ""), result


# ── Vector 5a: anchor stripped/partial when required ─────────────────────────
def test_vector5a_anchor_stripped_anchor_required():
    """With require_anchor=True, a receipt whose Merkle anchor was stripped is
    rejected -> anchor_required. The signature still verifies; the missing
    inclusion proof is what blocks it."""
    doc, pub = _load_fixture()
    no_anchor = copy.deepcopy(doc)
    no_anchor.pop("anchor", None)  # strip the inclusion proof
    pinned = load_trusted_signer_keys([pub])
    r = _verify_evidence_offline(
        _evidence(no_anchor, pub),
        expected=GENUINE_EXPECTED,
        trusted_signer_keys=pinned,
        require_anchor=True,
        replay_store=InMemoryReplayStore(),
    )
    assert r.verified is False
    assert r.status == "anchor_required", r


def test_vector5a_anchor_optional_still_proceeds():
    """When require_anchor=False (the default), the SAME anchorless-but-genuine
    receipt still proceeds — anchor enforcement is opt-in so the happy path with
    pre-anchor receipts is not default-broken."""
    doc, pub = _load_fixture()
    no_anchor = copy.deepcopy(doc)
    no_anchor.pop("anchor", None)
    pinned = load_trusted_signer_keys([pub])
    r = _verify_evidence_offline(
        _evidence(no_anchor, pub),
        expected=GENUINE_EXPECTED,
        trusted_signer_keys=pinned,
        require_anchor=False,
        replay_store=InMemoryReplayStore(),
    )
    assert r.verified is True, r


def test_vector5a_tampered_anchor_blocked():
    """A present-but-INVALID anchor (merkle_root flipped) is rejected. Note: the
    verifier's OWN overall-validity gate fails closed on a bad anchor
    (valid = signature AND anchor in (None, True)), so this surfaces as
    signature_invalid with checks[anchor] is False — and it blocks REGARDLESS of
    require_anchor. Both the stripped-anchor (-> anchor_required) and the
    tampered-anchor (-> signature_invalid) paths fail closed; the point is that a
    bad inclusion proof can never proceed."""
    doc, pub = _load_fixture()
    bad = copy.deepcopy(doc)
    bad["anchor"]["merkle_root"] = "0" * 64
    pinned = load_trusted_signer_keys([pub])
    # Even with require_anchor=False it must block — a tampered anchor is never OK.
    for require_anchor in (False, True):
        r = _verify_evidence_offline(
            _evidence(bad, pub),
            expected=GENUINE_EXPECTED,
            trusted_signer_keys=pinned,
            require_anchor=require_anchor,
            replay_store=InMemoryReplayStore(),
        )
        assert r.verified is False, r
        assert r.status == "signature_invalid", r
        assert r.checks.get("anchor") is False


# ── Vector 5b: replay (same receipt twice) + consumed ────────────────────────
def test_vector5b_replay_second_presentation_blocked():
    """The genuine receipt verifies the FIRST time and is rejected the SECOND
    time from the SAME replay store -> replay. Single-use is enforced on the
    SIGNED receipt_id."""
    doc, pub = _load_fixture()
    pinned = load_trusted_signer_keys([pub])
    store = InMemoryReplayStore()
    first = _verify_evidence_offline(
        _evidence(doc, pub),
        expected=GENUINE_EXPECTED,
        trusted_signer_keys=pinned,
        replay_store=store,
    )
    assert first.verified is True, first
    second = _verify_evidence_offline(
        _evidence(doc, pub),
        expected=GENUINE_EXPECTED,
        trusted_signer_keys=pinned,
        replay_store=store,  # same store -> id already recorded
    )
    assert second.verified is False
    assert second.status == "replay", second


def test_vector5b_in_memory_test_and_set_is_thread_safe():
    """Concurrent presentations cannot all observe an unused receipt."""
    from concurrent.futures import ThreadPoolExecutor

    store = InMemoryReplayStore()
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _n: store.seen("rcpt_concurrent"), range(128)))
    assert results.count(False) == 1, results
    assert results.count(True) == 127, results


def test_vector5b_consumed_status_blocked():
    """A receipt_status of 'consumed' (already spent) is NOT an approval to act
    on — wait_for_approval routes it to already_consumed, verified=False. We
    assert the status partition directly: 'consumed' is no longer in
    APPROVED_STATUSES and is its own non-approval terminal."""
    from examples.grok_guard import (
        APPROVED_STATUSES,
        CONSUMED_STATUSES,
        TERMINAL_STATUSES,
    )

    assert "consumed" not in APPROVED_STATUSES
    assert "consumed" in CONSUMED_STATUSES
    assert "consumed" in TERMINAL_STATUSES
    assert "approved_pending_consume" in APPROVED_STATUSES


# ── Vector 6: hostile evidence bodies never raise ────────────────────────────
def test_vector6_hostile_bodies_fail_closed_never_raise():
    """Document as str/int/list, junk public_key, missing fields, and a verifier
    that RAISES — every one yields verified=False and NONE raises."""
    doc, pub = _load_fixture()
    pinned = load_trusted_signer_keys([pub])

    hostile_evidences = [
        {"document": "not-a-dict", "public_key": pub},
        {"document": 12345, "public_key": pub},
        {"document": ["a", "list"], "public_key": pub},
        {"document": doc, "public_key": ["not", "a", "str"]},
        {"document": doc, "public_key": ""},
        {"document": doc, "public_key": "!!!not-base64!!!"},
        {"document": doc},  # no public_key
        {"public_key": pub},  # no document
        {},  # empty
        {"document": None, "public_key": None},
        "the whole evidence packet is a string",
        12345,
        ["evidence", "as", "list"],
        None,
    ]
    for ev in hostile_evidences:
        r = _verify_evidence_offline(
            ev,
            expected=GENUINE_EXPECTED,
            trusted_signer_keys=pinned,
            replay_store=InMemoryReplayStore(),
        )
        assert isinstance(r, VerifiedReceipt)
        assert r.verified is False, (ev, r)
        assert r.verified is not True  # strict: never a truthy non-True


def test_vector6_verifier_raise_is_verifier_error():
    """If the underlying verifier RAISES, the gate returns verifier_error,
    verified=False — never propagates the exception to the agent."""
    import examples.grok_guard as g

    doc, pub = _load_fixture()
    pinned = load_trusted_signer_keys([pub])
    original = g._verify_receipt

    def _boom(*_a, **_k):
        raise RuntimeError("verifier exploded")

    g._verify_receipt = _boom
    try:
        r = _verify_evidence_offline(
            _evidence(doc, pub),
            expected=GENUINE_EXPECTED,
            trusted_signer_keys=pinned,
            replay_store=InMemoryReplayStore(),
        )
    finally:
        g._verify_receipt = original
    assert r.verified is False
    assert r.status == "verifier_error", r
    assert "verifier raised" in (r.detail or "")


# ── Direct runner (mirrors packages/python-verify/tests/test_verify.py) ──────
def _run_all():
    tests = [
        ("CONTROL: genuine receipt proceeds", test_control_genuine_receipt_proceeds),
        ("CONTROL: fingerprint pin proceeds", test_control_proceeds_via_fingerprint_pin),
        ("Vector 1: tampered action -> signature_invalid", test_vector1_tampered_action_signature_invalid),
        ("Vector 2: attacker key -> untrusted_signer", test_vector2_attacker_key_untrusted_signer),
        ("Vector 2b: no pinned set -> untrusted_signer (fail closed)", test_vector2b_no_pinned_set_fails_closed),
        ("Vector 3: wrong amount -> claim_mismatch", test_vector3_different_amount_claim_mismatch),
        ("Vector 3b: wrong receipt_id -> claim_mismatch", test_vector3b_different_receipt_id_claim_mismatch),
        ("Vector 3c: wrong destination -> claim_mismatch", test_vector3c_different_destination_claim_mismatch),
        ("Vector 3d: signed omission/action swap -> claim_mismatch", test_vector3d_missing_material_fields_and_action_substitution_fail_closed),
        ("Vector 3e: amount precision collision -> claim_mismatch", test_vector3e_amount_comparison_does_not_round_through_float),
        ("Vector 5a: anchor stripped -> anchor_required", test_vector5a_anchor_stripped_anchor_required),
        ("Vector 5a: anchor optional still proceeds", test_vector5a_anchor_optional_still_proceeds),
        ("Vector 5a: tampered anchor -> blocked", test_vector5a_tampered_anchor_blocked),
        ("Vector 5b: replay -> blocked", test_vector5b_replay_second_presentation_blocked),
        ("Vector 5b: concurrent test-and-set -> one winner", test_vector5b_in_memory_test_and_set_is_thread_safe),
        ("Vector 5b: consumed status partition", test_vector5b_consumed_status_blocked),
        ("Vector 6: hostile bodies fail closed", test_vector6_hostile_bodies_fail_closed_never_raise),
        ("Vector 6: verifier raise -> verifier_error", test_vector6_verifier_raise_is_verifier_error),
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failures += 1
            print(f"  FAIL  {name}\n        {e}")
    if failures:
        print(f"\n{failures} test(s) FAILED.")
        sys.exit(1)
    print(f"\nALL {len(tests)} PASS — red-team vectors blocked, control proceeds.")


if __name__ == "__main__":
    _run_all()
