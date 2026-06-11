# SPDX-License-Identifier: Apache-2.0
"""Wrapped-tool behavior: the precondition is executor-side and fail-closed."""
import asyncio

import pytest
from langchain_core.tools import StructuredTool, tool

from langchain_emilia import (
    EmiliaClient,
    EmiliaGuard,
    EmiliaUnreachable,
    GateResult,
    guard_tools,
    wrap_tool,
)


class FakeGate(EmiliaClient):
    """Client whose gate() is scripted — exercises guard/tool layers only."""

    def __init__(self, results):
        super().__init__(api_key="ep_test", org_id="org-test")
        self.results = list(results)
        self.gate_calls = []

    def gate(self, action_type, target, amount=None, comment="", wait_for_approval=True):
        self.gate_calls.append({"action_type": action_type, "target": target, "amount": amount})
        step = self.results.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def make_transfer(executed):
    def transfer_funds(amount: float, beneficiary: str) -> str:
        """Transfer funds to a beneficiary."""
        executed.append((amount, beneficiary))
        return f"sent ${amount} to {beneficiary}"
    return StructuredTool.from_function(transfer_funds)


def test_allow_executes_and_records_receipt():
    executed = []
    fake = FakeGate([GateResult("allow", "tr_ok", approved_by_human=True)])
    guard = EmiliaGuard(client=fake)
    wrapped = wrap_tool(make_transfer(executed), guard)

    out = wrapped.invoke({"amount": 82000.0, "beneficiary": "Northwind"})
    assert out == "sent $82000.0 to Northwind"
    assert executed == [(82000.0, "Northwind")]
    assert guard.records[-1]["event"] == "allowed"
    assert guard.records[-1]["receipt_id"] == "tr_ok"
    # the gate saw the digest-bound target and the extracted amount
    assert fake.gate_calls[0]["target"].startswith("transfer_funds#")
    assert fake.gate_calls[0]["amount"] == 82000.0


def test_deny_blocks_execution_and_reports_to_model():
    executed = []
    fake = FakeGate([GateResult("deny", "tr_no", reasons=["over policy threshold"])])
    wrapped = wrap_tool(make_transfer(executed), EmiliaGuard(client=fake))

    out = wrapped.invoke({"amount": 999999.0, "beneficiary": "Unknown LLC"})
    assert executed == []                      # fail closed: tool body never ran
    assert "BLOCKED" in out and "NOT executed" in out


def test_pending_blocks_and_surfaces_signoff_url():
    executed = []
    fake = FakeGate([GateResult("pending", "tr_p", "sig_1",
                                "https://www.emiliaprotocol.ai/signoff/sig_1")])
    wrapped = wrap_tool(make_transfer(executed), EmiliaGuard(client=fake))

    out = wrapped.invoke({"amount": 50000.0, "beneficiary": "Acme"})
    assert executed == []
    assert "signoff/sig_1" in out


def test_gate_unreachable_fails_closed():
    executed = []
    fake = FakeGate([EmiliaUnreachable("dns失败")])
    wrapped = wrap_tool(make_transfer(executed), EmiliaGuard(client=fake))

    out = wrapped.invoke({"amount": 10.0, "beneficiary": "X"})
    assert executed == []
    assert "failing closed" in out


def test_unmatched_tool_passes_through_without_gate():
    fake = FakeGate([])  # any gate call would IndexError

    @tool
    def calculator(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    wrapped = wrap_tool(calculator, EmiliaGuard(client=fake))
    assert wrapped.invoke({"a": 2, "b": 3}) == 5
    assert fake.gate_calls == []


def test_observe_mode_never_blocks_and_needs_no_creds():
    executed = []
    guard = EmiliaGuard(mode="observe")  # keyless — zero setup
    wrapped = wrap_tool(make_transfer(executed), guard)

    out = wrapped.invoke({"amount": 82000.0, "beneficiary": "Northwind"})
    assert "sent" in out and executed       # ran
    rec = guard.records[-1]
    assert rec["event"] == "observed" and len(rec["digest"]) == 64


def test_schema_and_identity_preserved():
    inner = make_transfer([])
    wrapped = wrap_tool(inner, EmiliaGuard(mode="observe"))
    assert wrapped.name == inner.name
    assert wrapped.description == inner.description
    assert wrapped.args == inner.args        # model-facing schema unchanged


def test_action_type_mapping_and_bankish_default():
    executed = []
    fake = FakeGate([GateResult("allow", "tr_1"), GateResult("allow", "tr_2")])
    guard = EmiliaGuard(client=fake, action_types={"transfer_funds": "large_payment_release"})
    wrap_tool(make_transfer(executed), guard).invoke({"amount": 1.0, "beneficiary": "b"})
    assert fake.gate_calls[0]["action_type"] == "large_payment_release"

    def update_payee_bank(account: str) -> str:
        """Update payee bank account."""
        executed.append(account)
        return "ok"
    wrap_tool(StructuredTool.from_function(update_payee_bank), guard).invoke({"account": "4021"})
    assert fake.gate_calls[1]["action_type"] == "vendor_bank_account_change"


def test_async_path_allow():
    executed = []
    fake = FakeGate([GateResult("allow", "tr_async")])
    wrapped = wrap_tool(make_transfer(executed), EmiliaGuard(client=fake))

    out = asyncio.run(wrapped.ainvoke({"amount": 5.0, "beneficiary": "Async LLC"}))
    assert "Async LLC" in out and executed


def test_async_path_deny_fails_closed():
    executed = []
    fake = FakeGate([GateResult("deny", "tr_nope", reasons=["nope"])])
    wrapped = wrap_tool(make_transfer(executed), EmiliaGuard(client=fake))

    out = asyncio.run(wrapped.ainvoke({"amount": 5.0, "beneficiary": "Y"}))
    assert executed == [] and "BLOCKED" in out


def test_guard_tools_wraps_list_with_shared_guard():
    fake = FakeGate([GateResult("allow", "tr_l")])
    guard = EmiliaGuard(client=fake)

    @tool
    def calculator(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    executed = []
    tools = guard_tools([make_transfer(executed), calculator], guard)
    assert [t.name for t in tools] == ["transfer_funds", "calculator"]
    tools[0].invoke({"amount": 2.0, "beneficiary": "Z"})
    tools[1].invoke({"a": 1, "b": 1})
    assert len(fake.gate_calls) == 1          # only the money tool hit the gate


def test_on_event_callback_fires_and_cannot_break_the_gate():
    seen = []
    def boom(event):
        seen.append(event["event"])
        raise RuntimeError("observer crashed")
    guard = EmiliaGuard(mode="observe", on_event=boom)
    wrapped = wrap_tool(make_transfer([]), guard)
    wrapped.invoke({"amount": 1.0, "beneficiary": "b"})   # must not raise
    assert seen == ["observed"]


def test_raise_mode_when_return_errors_false():
    from langchain_emilia import EmiliaDenied
    fake = FakeGate([GateResult("deny", "tr_x", reasons=["no"])])
    wrapped = wrap_tool(make_transfer([]), EmiliaGuard(client=fake, return_errors=False))
    with pytest.raises(EmiliaDenied):
        wrapped.invoke({"amount": 1.0, "beneficiary": "b"})
