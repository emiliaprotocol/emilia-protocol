# SPDX-License-Identifier: Apache-2.0
"""The policy-response example must not turn failure or signoff into approval."""

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("example_guard", Path(__file__).parents[1] / "emilia_guard.py")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


@pytest.mark.parametrize("response", [
    {}, {"error": "unavailable"}, {"decision": "DENY"}, {"decision": "unknown"},
    {"allowed": True}, {"decision": "allow", "verdict": "deny"},
    {"decision": "allow", "allowed": "false"}, [], None,
    {"decision": "allow", "allowed": False},
    {"decision": "allow", "signoff_required": True},
    {"decision": "deny", "allowed": True},
    {"decision": "signoff_required", "allowed": True},
    {"decision": "allow", "error": "unavailable"},
    {"decision": "allow", "signoff_required": "false"},
    {"decision": "allow", "reason": []},
    {"decision": "allow", "verdict": None},
    {"decision": ["allow"]},
])
def test_invalid_gate_response_never_invokes_tool(response):
    calls = []
    wrapped = helper.guard("payment.release", lambda args: args, lambda body: response)(
        lambda **kwargs: calls.append(kwargs)
    )
    with pytest.raises(RuntimeError):
        wrapped(amount=42)
    assert calls == []


@pytest.mark.parametrize("answer", [False, None, {"approved": False}, True])
def test_acquisition_callback_is_not_a_verified_signoff(answer):
    calls = []
    wrapped = helper.guard("payment.release", lambda args: args,
                           lambda body: {"decision": "signoff_required"},
                           on_signoff=lambda decision, arguments: answer)(
        lambda **kwargs: calls.append(kwargs)
    )
    with pytest.raises(RuntimeError):
        wrapped(amount=42)
    assert calls == []


def test_explicit_policy_allow_still_runs():
    wrapped = helper.guard("payment.release", lambda args: args, lambda body: {"decision": "allow"})(
        lambda **kwargs: kwargs
    )
    assert wrapped(amount=42) == {"amount": 42}


def test_fetch_failure_returns_closed_decision_and_never_invokes_tool():
    def unavailable(_body):
        raise OSError("offline")

    calls = []
    decision = helper.guard_action("payment.release", unavailable)
    assert decision["deny"] is True
    assert decision["allow"] is False
    wrapped = helper.guard("payment.release", lambda args: args, unavailable)(
        lambda **kwargs: calls.append(kwargs)
    )
    with pytest.raises(RuntimeError):
        wrapped(amount=42)
    assert calls == []


@pytest.mark.parametrize("response", [
    {"verdict": "allow"},
    {"decision": "allow", "verdict": "allow", "allowed": True, "signoff_required": False},
])
def test_consistent_recognized_policy_allow_runs(response):
    wrapped = helper.guard("payment.release", lambda args: args, lambda body: response)(
        lambda **kwargs: kwargs
    )
    assert wrapped(amount=42) == {"amount": 42}


@pytest.mark.parametrize("verification", [False, None, 1, {"approved": True}, {"ok": True}])
def test_signoff_verifier_requires_explicit_success(verification):
    calls = []
    wrapped = helper.guard(
        "payment.release", lambda args: args,
        lambda body: {"decision": "signoff_required"},
        on_signoff=lambda decision, arguments: {"receipt": "fixture"},
        verify_signoff=lambda evidence, action, arguments: verification,
    )(lambda **kwargs: calls.append(kwargs))
    with pytest.raises(RuntimeError):
        wrapped(amount=42)
    assert calls == []


def test_constructor_pinned_verifier_receives_exact_action_and_all_defaulted_arguments():
    checked = []

    def verify(evidence, action, arguments):
        checked.append((evidence, action, arguments))
        return evidence == {"fixture": "verified"} and action == "payment.release" and arguments == {
            "amount": 42, "destination": "acct_known",
        }

    @helper.guard(
        "payment.release", lambda args: {"amount": args["amount"]},
        lambda body: {"decision": "signoff_required"},
        on_signoff=lambda decision, arguments: {"fixture": "verified"},
        verify_signoff=verify,
    )
    def transfer(amount, destination="acct_known"):
        return {"amount": amount, "destination": destination}

    assert transfer(amount=42) == {"amount": 42, "destination": "acct_known"}
    assert len(checked) == 1


@pytest.mark.parametrize("evidence", [
    {"action": "payment.refund", "arguments": {"amount": 42}},
    {"action": "payment.release", "arguments": {"amount": 1}},
])
def test_signoff_for_other_action_or_arguments_is_refused(evidence):
    calls = []
    wrapped = helper.guard(
        "payment.release", lambda args: args,
        lambda body: {"decision": "signoff_required"},
        on_signoff=lambda decision, arguments: evidence,
        verify_signoff=lambda acquired, action, arguments: acquired == {
            "action": action, "arguments": arguments,
        },
    )(lambda **kwargs: calls.append(kwargs))
    with pytest.raises(RuntimeError):
        wrapped(amount=42)
    assert calls == []


def test_callbacks_cannot_mutate_the_action_arguments_seen_by_later_stages():
    caller = {"destination": "acct_known"}
    verified = []

    def context(arguments):
        arguments["payment"]["destination"] = "context_attacker"
        return {"amount": 42}

    def acquire(decision, arguments):
        arguments["payment"]["destination"] = "acquisition_attacker"
        caller["destination"] = "caller_mutated_after_snapshot"
        decision["signoff_required"] = False
        return {"fixture": "evidence"}

    def verify(evidence, action, arguments):
        verified.append(arguments["payment"]["destination"])
        arguments["payment"]["destination"] = "verifier_attacker"
        return evidence == {"fixture": "evidence"} and action == "payment.release"

    wrapped = helper.guard(
        "payment.release", context, lambda body: {"decision": "signoff_required"},
        on_signoff=acquire, verify_signoff=verify,
    )(lambda **kwargs: kwargs)
    assert wrapped(payment=caller) == {"payment": {"destination": "acct_known"}}
    assert verified == ["acct_known"]


@pytest.mark.parametrize("stage", ["context", "acquire", "verify"])
def test_callback_failures_never_invoke_tool(stage):
    calls = []

    def fail(*_args):
        raise ValueError("callback failed")

    wrapped = helper.guard(
        "payment.release", fail if stage == "context" else lambda args: args,
        lambda body: {"decision": "signoff_required"},
        on_signoff=fail if stage == "acquire" else lambda decision, args: {},
        verify_signoff=fail if stage == "verify" else lambda evidence, action, args: True,
    )(lambda **kwargs: calls.append(kwargs))
    with pytest.raises(RuntimeError):
        wrapped(amount=42)
    assert calls == []
