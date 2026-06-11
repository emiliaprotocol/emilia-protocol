# SPDX-License-Identifier: Apache-2.0
"""Gate-flow semantics against a scripted transport — no network, fail-closed."""
import pytest

from langchain_emilia import EmiliaClient, EmiliaConfigError, EmiliaUnreachable


class ScriptedClient(EmiliaClient):
    """EmiliaClient whose transport replays a scripted response sequence."""

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
    c = ScriptedClient([{"decision": "allow", "signoff_required": False, "receipt_id": "tr_abc"}])
    r = c.gate("ai_agent_payment_action", "wire_transfer#deadbeef")
    assert r.decision == "allow" and r.receipt_id == "tr_abc" and not r.approved_by_human


def test_policy_deny():
    c = ScriptedClient([{"decision": "deny", "reasons": ["amount over threshold"], "receipt_id": "tr_d"}])
    r = c.gate("large_payment_release", "t#1")
    assert r.decision == "deny" and "amount over threshold" in r.reasons


def test_signoff_approved_after_polling():
    c = ScriptedClient([
        {"signoff_required": True, "receipt_id": "tr_s1"},
        {"signoff_id": "sig_abc123"},
        {"receipt_status": "pending"},
        {"receipt_status": "approved"},
    ])
    r = c.gate("vendor_bank_account_change", "t#2", amount=82000.0)
    assert r.decision == "allow" and r.approved_by_human
    assert r.signoff_url.endswith("/signoff/sig_abc123")
    # mint, signoff request, two polls
    assert len(c.calls) == 4


def test_signoff_rejected_by_human():
    c = ScriptedClient([
        {"signoff_required": True, "receipt_id": "tr_s2"},
        {"signoff_id": "sig_r"},
        {"receipt_status": "rejected"},
    ])
    r = c.gate("ai_agent_payment_action", "t#3")
    assert r.decision == "deny" and "rejected by the named approver" in r.reasons


def test_signoff_timeout_is_pending_not_allow():
    c = ScriptedClient(
        [{"signoff_required": True, "receipt_id": "tr_s3"}, {"signoff_id": "sig_t"},
         {"receipt_status": "pending"}, {"receipt_status": "pending"}],
        signoff_timeout_s=0.0,
    )
    r = c.gate("ai_agent_payment_action", "t#4")
    assert r.decision == "pending" and r.signoff_url


def test_no_wait_returns_pending_with_url():
    c = ScriptedClient([
        {"signoff_required": True, "receipt_id": "tr_s4"},
        {"signoff_id": "sig_now"},
    ])
    r = c.gate("ai_agent_payment_action", "t#5", wait_for_approval=False)
    assert r.decision == "pending" and r.signoff_url.endswith("/signoff/sig_now")
    assert len(c.calls) == 2  # no polling


def test_malformed_receipt_id_fails_closed():
    c = ScriptedClient([{"signoff_required": True, "receipt_id": "../../etc/passwd"}])
    r = c.gate("ai_agent_payment_action", "t#6")
    assert r.decision == "deny"


def test_transport_failure_raises_unreachable():
    c = ScriptedClient([EmiliaUnreachable("connection refused")])
    with pytest.raises(EmiliaUnreachable):
        c.gate("ai_agent_payment_action", "t#7")


def test_missing_creds_is_config_error():
    c = EmiliaClient(api_key="", org_id="")
    with pytest.raises(EmiliaConfigError):
        c.gate("ai_agent_payment_action", "t#8")


def test_unsafe_base_url_falls_back_to_default():
    c = EmiliaClient(api_key="k", org_id="o", base_url="file:///etc")
    assert c.base_url == "https://www.emiliaprotocol.ai"
