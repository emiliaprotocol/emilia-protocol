# SPDX-License-Identifier: Apache-2.0
"""Gate-flow semantics against a scripted transport — no network, fail-closed."""
import pytest

from langchain_emilia import EmiliaGateClient, EmiliaConfigError, EmiliaUnreachable


ACTION_HASH = "sha256:" + "a" * 64
CANONICAL_ACTION = {"action_type": "ai_agent_payment_action", "target_resource_id": "tool#digest"}


def mint(receipt_id, *, signoff_required=False, decision="allow"):
    return {
        "decision": decision,
        "signoff_required": signoff_required,
        "receipt_id": receipt_id,
        "action_hash": ACTION_HASH,
        "canonical_action": CANONICAL_ACTION,
    }


def consumed(receipt_id):
    return {"receipt_id": receipt_id, "status": "consumed"}


class ScriptedClient(EmiliaGateClient):
    """EmiliaGateClient whose transport replays a scripted response sequence."""

    def __init__(self, script, **kwargs):
        kwargs.setdefault("api_key", "ep_test_key")
        kwargs.setdefault("org_id", "org-test")
        kwargs.setdefault("poll_interval_s", 0.0)
        super().__init__(**kwargs)
        self.script = list(script)
        self.calls = []

    def _request(self, path, body=None):
        self.calls.append((path, body))
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def test_policy_allow_no_signoff():
    c = ScriptedClient([mint("tr_abc"), consumed("tr_abc")])
    r = c.gate("ai_agent_payment_action", "wire_transfer#deadbeef")
    assert r.decision == "allow" and r.receipt_id == "tr_abc" and not r.approved_by_human
    assert r.consumed and r.action_hash == ACTION_HASH and r.canonical_action == CANONICAL_ACTION
    assert c.calls[-1][0] == "/api/v1/trust-receipts/tr_abc/consume"


def test_policy_deny():
    c = ScriptedClient([{"decision": "deny", "reasons": ["amount over threshold"], "receipt_id": "tr_d"}])
    r = c.gate("large_payment_release", "t#1")
    assert r.decision == "deny" and "amount over threshold" in r.reasons


def test_signoff_approved_after_polling():
    c = ScriptedClient([
        mint("tr_s1", signoff_required=True),
        {"signoff_id": "sig_abc123"},
        {"receipt_status": "pending"},
        {"receipt_status": "approved"},
        consumed("tr_s1"),
    ])
    r = c.gate("vendor_bank_account_change", "t#2", amount=82000.0)
    assert r.decision == "allow" and r.approved_by_human
    assert r.signoff_url.endswith("/signoff/sig_abc123")
    # mint, signoff request, two polls, atomic consume
    assert len(c.calls) == 5
    assert c.calls[-1][0].endswith("/tr_s1/consume")


def test_signoff_rejected_by_human():
    c = ScriptedClient([
        mint("tr_s2", signoff_required=True),
        {"signoff_id": "sig_r"},
        {"receipt_status": "rejected"},
    ])
    r = c.gate("ai_agent_payment_action", "t#3")
    assert r.decision == "deny" and "rejected by the named approver" in r.reasons


def test_signoff_timeout_is_pending_not_allow():
    c = ScriptedClient(
        [mint("tr_s3", signoff_required=True), {"signoff_id": "sig_t"},
         {"receipt_status": "pending"}, {"receipt_status": "pending"}],
        signoff_timeout_s=0.0,
    )
    r = c.gate("ai_agent_payment_action", "t#4")
    assert r.decision == "pending" and r.signoff_url


def test_no_wait_returns_pending_with_url():
    c = ScriptedClient([
        mint("tr_s4", signoff_required=True),
        {"signoff_id": "sig_now"},
    ])
    r = c.gate("ai_agent_payment_action", "t#5", wait_for_approval=False)
    assert r.decision == "pending" and r.signoff_url.endswith("/signoff/sig_now")
    assert len(c.calls) == 2  # no polling


def test_malformed_receipt_id_fails_closed():
    c = ScriptedClient([{"signoff_required": True, "receipt_id": "../../etc/passwd"}])
    r = c.gate("ai_agent_payment_action", "t#6")
    assert r.decision == "deny"


def test_preconsumed_receipt_is_not_treated_as_executor_authority():
    c = ScriptedClient([
        mint("tr_used", signoff_required=True),
        {"signoff_id": "sig_used"},
        {"receipt_status": "consumed"},
    ])
    r = c.gate("ai_agent_payment_action", "t#used")
    assert r.decision == "deny"
    assert "already consumed" in r.reasons[0]


def test_execution_attestation_is_bound_to_consumed_canonical_action():
    c = ScriptedClient([{
        "status": "executed",
        "binding_status": "match",
        "receipt_id": "tr_exec",
    }])
    from langchain_emilia import GateResult
    result = GateResult(
        "allow",
        "tr_exec",
        action_hash=ACTION_HASH,
        canonical_action=CANONICAL_ACTION,
        execution_reference_id="langchain-emilia:sha256:" + "b" * 64,
        consumed=True,
    )
    attestation = c.attest_execution(result)
    assert attestation["binding_status"] == "match"
    path, body = c.calls[0]
    assert path == "/api/v1/trust-receipts/tr_exec/execution"
    assert body["executed_action"] == CANONICAL_ACTION
    assert body["observed_action"] == CANONICAL_ACTION


def test_transport_failure_raises_unreachable():
    c = ScriptedClient([EmiliaUnreachable("connection refused")])
    with pytest.raises(EmiliaUnreachable):
        c.gate("ai_agent_payment_action", "t#7")


def test_missing_creds_is_config_error():
    c = EmiliaGateClient(api_key="", org_id="")
    with pytest.raises(EmiliaConfigError):
        c.gate("ai_agent_payment_action", "t#8")


def test_unsafe_base_url_falls_back_to_default():
    c = EmiliaGateClient(api_key="k", org_id="o", base_url="file:///etc")
    assert c.base_url == "https://www.emiliaprotocol.ai"
