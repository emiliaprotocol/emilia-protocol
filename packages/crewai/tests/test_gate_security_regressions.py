# SPDX-License-Identifier: Apache-2.0
"""Provider-entry validity and malformed-input regression tests."""

import base64
from datetime import datetime, timedelta, timezone

import emilia_crewai as ep
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from emilia_verify import canonicalize

KEY = Ed25519PrivateKey.generate()
PUBLIC_KEY = base64.urlsafe_b64encode(
    KEY.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
).decode().rstrip("=")
START = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)


def receipt(payload=None):
    payload = payload if payload is not None else {
        "receipt_id": "security-regression",
        "created_at": START.isoformat(),
        "expires_at": (START + timedelta(seconds=60)).isoformat(),
        "claim": {"action_type": "payment.release", "outcome": "allow"},
    }
    signature = base64.urlsafe_b64encode(KEY.sign(canonicalize(payload).encode())).decode().rstrip("=")
    return {"@version": "EP-RECEIPT-v1", "payload": payload,
            "signature": {"algorithm": "Ed25519", "value": signature}}


@pytest.mark.parametrize("delay_at", ["reserve", "assurance"])
@pytest.mark.parametrize("expiry_kind", ["absolute", "relative"])
def test_expiry_is_rechecked_after_pre_entry_work(monkeypatch, delay_at, expiry_kind):
    now = [START.timestamp()]
    monkeypatch.setattr(ep, "_now", lambda: now[0])
    state = {}

    class Store:
        def reserve(self, receipt_id):
            if receipt_id in state:
                return False
            state[receipt_id] = "reserved"
            if delay_at == "reserve":
                now[0] += 120
            return True

        def commit(self, receipt_id):
            state[receipt_id] = "committed"
            return True

        def release(self, receipt_id):
            del state[receipt_id]
            return True

    def assurance(_receipt, _tier):
        if delay_at == "assurance":
            now[0] += 120
        return {"ok": True, "tier": "class_a"}

    gate = ep.ReceiptGate("payment.release", trusted_keys=[PUBLIC_KEY], store=Store(),
                          assurance_class="class_a", verify_assurance=assurance,
                          max_age_sec=60 if expiry_kind == "relative" else None)
    payload = receipt()["payload"]
    if expiry_kind == "relative":
        del payload["expires_at"]
    calls = []
    with pytest.raises(ep.ReceiptRequired) as error:
        gate.run(receipt(payload), lambda: calls.append("effect"))
    assert error.value.reason == "receipt_expired"
    assert calls == []
    assert state == {}


def test_expired_receipt_failed_release_never_enters_provider(monkeypatch):
    now = [START.timestamp()]
    monkeypatch.setattr(ep, "_now", lambda: now[0])

    class Store(ep._InMemoryStore):
        def reserve(self, receipt_id):
            reserved = super().reserve(receipt_id)
            now[0] += 120
            return reserved

        def release(self, receipt_id):
            return False

    store = Store()
    gate = ep.ReceiptGate("payment.release", trusted_keys=[PUBLIC_KEY], store=store)
    calls = []
    with pytest.raises(ep.ReceiptRequired) as error:
        gate.run(receipt(), lambda: calls.append("effect"))
    assert error.value.reason == "consumption_store_unavailable"
    assert store._states == {"security-regression": "reserved"}
    assert calls == []


@pytest.mark.parametrize("field,value", [
    ("signature", ["bad"]), ("signature", 1), ("signature", "bad"),
    ("signature", None), ("payload", ["bad"]), ("payload", 1),
    ("payload", None), ("anchor", ["bad"]), ("anchor", 1),
])
def test_nested_malformed_receipts_return_refusal(monkeypatch, field, value):
    monkeypatch.setattr(ep, "_now", lambda: START.timestamp())
    doc = receipt()
    doc[field] = value
    result = ep.ReceiptGate("payment.release", trusted_keys=[PUBLIC_KEY]).check(doc)
    assert result["ok"] is False


@pytest.mark.parametrize("claim", [["bad"], "bad", 42, None])
def test_signed_malformed_claim_is_refused(monkeypatch, claim):
    monkeypatch.setattr(ep, "_now", lambda: START.timestamp())
    payload = receipt()["payload"]
    payload["claim"] = claim
    result = ep.ReceiptGate("payment.release", trusted_keys=[PUBLIC_KEY]).check(receipt(payload))
    assert result["ok"] is False


def test_async_callable_is_refused_before_reservation(monkeypatch):
    monkeypatch.setattr(ep, "_now", lambda: START.timestamp())
    gate = ep.ReceiptGate("payment.release", trusted_keys=[PUBLIC_KEY])

    async def effect():
        return "effect"

    with pytest.raises((TypeError, ep.ReceiptRequired)):
        gate.run(receipt(), effect)
    assert gate._store._states == {}


def test_async_decorator_is_refused_when_configured():
    with pytest.raises(TypeError):
        @ep.require_receipt("payment.release", trusted_keys=[PUBLIC_KEY])
        async def effect():
            return "effect"


def test_generator_callable_is_refused_before_reservation(monkeypatch):
    monkeypatch.setattr(ep, "_now", lambda: START.timestamp())
    gate = ep.ReceiptGate("payment.release", trusted_keys=[PUBLIC_KEY])

    def effect():
        yield "effect"

    with pytest.raises((TypeError, ep.ReceiptRequired)):
        gate.run(receipt(), effect)
    assert gate._store._states == {}


@pytest.mark.parametrize("kind", ["coroutine", "generator"])
def test_lazy_result_never_escapes_and_receipt_stays_consumed(monkeypatch, kind):
    monkeypatch.setattr(ep, "_now", lambda: START.timestamp())
    gate = ep.ReceiptGate("payment.release", trusted_keys=[PUBLIC_KEY])
    calls = []

    async def delayed():
        calls.append("late effect")

    def stream():
        calls.append("late effect")
        yield "done"

    def effect():
        return delayed() if kind == "coroutine" else stream()

    doc = receipt()
    with pytest.raises(TypeError):
        gate.run(doc, effect)
    assert calls == []
    with pytest.raises(ep.ReceiptRequired) as error:
        gate.run(doc, lambda: calls.append("retry"))
    assert error.value.reason == "replay_refused"
    assert calls == []
