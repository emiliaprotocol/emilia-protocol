"""emilia-crewai — RR-1 unit suite (offline, no network).

Mints real EP-RECEIPT-v1 receipts with `cryptography` (Ed25519 over the same
canonical JSON the verifier uses) and proves the four normative behaviors plus
per-call binding, age, outcome, and retryability. Runs under pytest OR directly:
    PYTHONPATH=../python-verify:.. python3 tests/test_crewai.py
"""
import base64
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from emilia_verify import canonicalize
from emilia_crewai import (
    ReceiptGate,
    ReceiptRequired,
    require_receipt,
    guard_crewai_tool,
    using_receipt,
)

_SK = Ed25519PrivateKey.generate()
_PK_DER = _SK.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
TRUSTED_KEY = base64.urlsafe_b64encode(_PK_DER).decode().rstrip("=")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def mint(action, outcome="allow_with_signoff", created_at=None):
    payload = {
        "receipt_id": "rcpt_" + uuid.uuid4().hex,
        "subject": "alice@futureenterprises.example",
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "claim": {"action_type": action, "outcome": outcome, "approver": "alice@futureenterprises.example"},
    }
    sig = _SK.sign(canonicalize(payload).encode("utf-8"))
    return {
        "@version": "EP-RECEIPT-v1",
        "payload": payload,
        "signature": {"algorithm": "Ed25519", "value": _b64u(sig)},
        "public_key": TRUSTED_KEY,
    }


def gate(action="payment.release", **kw):
    return ReceiptGate(action, trusted_keys=[TRUSTED_KEY], **kw)


# ── ReceiptGate: the four normative behaviors ────────────────────────────────

def test_missing_receipt_refused():
    g = gate()
    try:
        g.run(None, lambda: "ran")
        assert False, "expected ReceiptRequired"
    except ReceiptRequired as e:
        assert e.reason == "receipt_required"


def test_valid_receipt_runs():
    g = gate()
    out = g.run(mint("payment.release"), lambda: "ran")
    assert out == "ran"


def test_replay_refused():
    g = gate()
    r = mint("payment.release")
    assert g.run(r, lambda: "ran") == "ran"
    try:
        g.run(r, lambda: "ran-again")
        assert False, "expected replay refusal"
    except ReceiptRequired as e:
        assert e.reason == "replay_refused"


def test_forged_action_refused():
    # Tampering the action_type AFTER signing breaks the signature, so it is
    # refused by the signature check (which fires before action-binding). The
    # validly-signed wrong-action case is covered by test_per_call_target_binding.
    g = gate()
    forged = mint("payment.release")
    forged["payload"]["claim"]["action_type"] = "payment.release.tampered"
    try:
        g.run(forged, lambda: "ran")
        assert False, "expected forged receipt to be refused"
    except ReceiptRequired as e:
        assert e.reason == "untrusted_or_invalid_signature"


def test_forged_signature_refused():
    g = gate()
    forged = mint("payment.release")
    # mutate a signed field WITHOUT re-signing -> signature no longer verifies
    forged["payload"]["subject"] = "mallory@evil.example"
    try:
        g.run(forged, lambda: "ran")
        assert False, "expected signature failure"
    except ReceiptRequired as e:
        assert e.reason == "untrusted_or_invalid_signature"


def test_untrusted_issuer_refused():
    other = Ed25519PrivateKey.generate()
    other_key = _b64u(other.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
    g = ReceiptGate("payment.release", trusted_keys=[other_key])
    try:
        g.run(mint("payment.release"), lambda: "ran")
        assert False, "expected untrusted refusal"
    except ReceiptRequired as e:
        assert e.reason == "untrusted_or_invalid_signature"


def test_expired_receipt_refused():
    g = gate(max_age_sec=60)
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    try:
        g.run(mint("payment.release", created_at=old), lambda: "ran")
        assert False, "expected receipt_expired"
    except ReceiptRequired as e:
        assert e.reason == "receipt_expired"


def test_outcome_not_accepted_refused():
    g = gate()
    try:
        g.run(mint("payment.release", outcome="deny"), lambda: "ran")
        assert False, "expected outcome rejection"
    except ReceiptRequired as e:
        assert e.reason == "outcome_not_accepted"


def test_transient_failure_does_not_consume():
    g = gate()
    r = mint("payment.release")
    attempts = {"n": 0}

    def flaky():
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("transient downstream error")
        return "ran"

    try:
        g.run(r, flaky)
        assert False, "expected the transient error to propagate"
    except RuntimeError:
        pass
    # approval was NOT burned -> same receipt now succeeds
    assert g.run(r, flaky) == "ran"


def test_per_call_target_binding():
    g = gate()
    rA = mint("payment.release:acct_A")
    assert g.run(rA, lambda: "ran", target="acct_A") == "ran"
    rA2 = mint("payment.release:acct_A")
    try:
        g.run(rA2, lambda: "ran", target="acct_B")
        assert False, "receipt for A must not drive B"
    except ReceiptRequired as e:
        assert e.reason == "action_mismatch"


# ── decorator + context var ──────────────────────────────────────────────────

def test_require_receipt_decorator_with_contextvar():
    @require_receipt("payment.release", trusted_keys=[TRUSTED_KEY])
    def send_payment(to, amount):
        return f"sent {amount} to {to}"

    # no receipt in context -> refused
    try:
        send_payment("acct_1", 100)
        assert False, "expected refusal without a receipt"
    except ReceiptRequired:
        pass
    # with a receipt bound in context -> runs
    with using_receipt(mint("payment.release")):
        assert send_payment("acct_1", 100) == "sent 100 to acct_1"


# ── CrewAI BaseTool duck-typed wrapper ───────────────────────────────────────

def test_guard_crewai_tool_duck_typed():
    class FakeTool:
        name = "wire_transfer"
        calls = 0

        def _run(self, to, amount):
            type(self).calls += 1
            return {"ok": True, "to": to, "amount": amount}

    tool = FakeTool()
    guard_crewai_tool(tool, "payment.release", trusted_keys=[TRUSTED_KEY])

    # missing receipt -> refused, underlying never runs
    try:
        tool._run("acct_1", 50)
        assert False, "expected refusal"
    except ReceiptRequired:
        pass
    assert FakeTool.calls == 0

    # valid receipt -> runs once
    with using_receipt(mint("payment.release")):
        out = tool._run("acct_1", 50)
    assert out == {"ok": True, "to": "acct_1", "amount": 50}
    assert FakeTool.calls == 1


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"✔ {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"✘ {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
