"""Native smolagents integration tests. Real signatures; no model or network."""

import base64
import copy
import json
import pickle
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

import emilia_crewai
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from emilia_smolagents import (
    ReceiptRequired,
    ToolExecutionIndeterminate,
    bind_call_action,
    guard_smolagents_tool,
    using_receipt,
)
from emilia_verify import canonicalize
from smolagents import Model, Tool, ToolCallingAgent, tool
from smolagents.models import (
    ChatMessage,
    ChatMessageToolCall,
    ChatMessageToolCallFunction,
    MessageRole,
)


def b64u(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


KEY = Ed25519PrivateKey.generate()
PUBLIC_KEY = b64u(
    KEY.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
)


def mint(
    action, *, key=KEY, created_at=None, expires_at=None, outcome="allow_with_signoff"
):
    payload = {
        "receipt_id": f"receipt_{uuid.uuid4().hex}",
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "subject": "demo-operator@example.invalid",
        "claim": {"action_type": action, "outcome": outcome},
    }
    if expires_at is not None:
        payload["expires_at"] = expires_at
    return {
        "@version": "EP-RECEIPT-v1",
        "payload": payload,
        "signature": {
            "algorithm": "Ed25519",
            "value": b64u(key.sign(canonicalize(payload).encode())),
        },
        "public_key": b64u(
            key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        ),
    }


class RefundTool(Tool):
    name = "issue_refund"
    description = "Record a simulated refund. No money moves."
    inputs: ClassVar[dict] = {
        "order_id": {"type": "string", "description": "Order identifier"},
        "amount_cents": {"type": "integer", "description": "Refund amount"},
        "memo": {"type": "string", "description": "Refund memo", "nullable": True},
    }
    output_type = "object"
    output_schema: ClassVar[dict] = {
        "type": "object",
        "properties": {"recorded": {"type": "boolean"}},
    }

    def __init__(self):
        self.inputs = copy.deepcopy(type(self).inputs)
        self.output_schema = copy.deepcopy(type(self).output_schema)
        self.calls = []
        self.setup_calls = 0
        super().__init__()

    def setup(self):
        self.setup_calls += 1
        super().setup()

    def forward(
        self, order_id: str, amount_cents: int, memo: str = "customer request"
    ) -> dict:
        self.calls.append(
            {"order_id": order_id, "amount_cents": amount_cents, "memo": memo}
        )
        return {"recorded": True}


class NestedTool(Tool):
    name = "apply_change"
    description = "Apply a simulated nested change."
    inputs: ClassVar[dict] = {
        "change": {"type": "object", "description": "Complete change"}
    }
    output_type = "object"

    def __init__(self):
        self.calls = []
        super().__init__()

    def forward(self, change: dict) -> dict:
        self.calls.append(copy.deepcopy(change))
        return change


def wrap(raw=None, **kwargs):
    return guard_smolagents_tool(
        raw or RefundTool(), action="refund.issue", trusted_keys=[PUBLIC_KEY], **kwargs
    )


ARGS = {"order_id": "order-42", "amount_cents": 2500}


def assert_refused(guarded, reason, *, receipt=None, arguments=None):
    with using_receipt(receipt), pytest.raises(ReceiptRequired) as caught:
        guarded(**(ARGS if arguments is None else arguments))
    assert caught.value.reason == reason


def test_native_tool_metadata_is_preserved_without_authority_inputs():
    raw = RefundTool()
    guarded = wrap(raw)
    assert isinstance(guarded, Tool)
    guarded.validate_arguments()
    for field in ("name", "description", "inputs", "output_type", "output_schema"):
        assert getattr(guarded, field) == getattr(raw, field)
    assert "receipt" not in guarded.inputs
    assert "get_receipt" not in guarded.inputs
    assert "issue_refund" in guarded.to_code_prompt()
    assert "issue_refund" in guarded.to_tool_calling_prompt()


def test_missing_receipt_never_initializes_or_calls_provider():
    raw = RefundTool()
    guarded = wrap(raw)
    assert_refused(guarded, "receipt_required")
    guarded.setup()
    assert raw.setup_calls == 0
    assert raw.calls == []


@pytest.mark.parametrize("entry", ["call", "forward", "dictionary", "sanitize"])
def test_authorized_call_uses_complete_defaults_and_consumes_once(entry):
    raw = RefundTool()
    guarded = wrap(raw)
    expected = bind_call_action(
        "refund.issue", "issue_refund", {**ARGS, "memo": "customer request"}
    )
    assert guarded.bound_action_for(**ARGS) == expected
    assert guarded.bound_action_for("order-42", 2500) == expected
    receipt = mint(expected)
    with using_receipt(receipt):
        if entry == "forward":
            result = guarded.forward(**ARGS)
        elif entry == "dictionary":
            result = guarded(ARGS)
        elif entry == "sanitize":
            result = guarded(**ARGS, sanitize_inputs_outputs=True)
        else:
            result = guarded(**ARGS)
    assert result == {"recorded": True}
    assert raw.calls == [{**ARGS, "memo": "customer request"}]
    assert raw.setup_calls == 1
    assert_refused(guarded, "replay_refused", receipt=receipt)


def test_receipt_cannot_move_to_changed_arguments_or_omitted_default_digest():
    raw = RefundTool()
    guarded = wrap(raw)
    receipt = mint(guarded.bound_action_for(**ARGS))
    assert_refused(
        guarded,
        "action_mismatch",
        receipt=receipt,
        arguments={**ARGS, "amount_cents": 5000},
    )
    assert_refused(
        guarded, "action_mismatch", receipt=receipt, arguments={**ARGS, "memo": "other"}
    )
    assert_refused(
        guarded,
        "action_mismatch",
        receipt=mint(bind_call_action("refund.issue", raw.name, ARGS)),
    )
    assert raw.calls == []
    with using_receipt(receipt):
        assert guarded(**ARGS) == {"recorded": True}


@pytest.mark.parametrize(
    "mutation",
    ["forged", "untrusted", "expired_age", "expired_signed", "deny", "future"],
)
def test_invalid_authority_refuses_before_provider_entry(mutation):
    raw = RefundTool()
    guarded = wrap(raw)
    action = guarded.bound_action_for(**ARGS)
    receipt = mint(action)
    if mutation == "forged":
        receipt["payload"]["subject"] = "changed@example.invalid"
    elif mutation == "untrusted":
        receipt = mint(action, key=Ed25519PrivateKey.generate())
    elif mutation == "expired_age":
        receipt = mint(
            action,
            created_at=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        )
    elif mutation == "expired_signed":
        receipt = mint(
            action,
            expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        )
    elif mutation == "deny":
        receipt = mint(action, outcome="deny")
    elif mutation == "future":
        receipt = mint(
            action,
            created_at=(datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        )
    with using_receipt(receipt), pytest.raises(ReceiptRequired):
        guarded(**ARGS)
    assert raw.calls == []
    assert raw.setup_calls == 0


def test_signed_expiry_still_applies_with_age_check_disabled():
    guarded = wrap(max_age_sec=None)
    receipt = mint(guarded.bound_action_for(**ARGS), expires_at="2000-01-01T00:00:00Z")
    assert_refused(guarded, "receipt_expired", receipt=receipt)


@pytest.mark.parametrize(
    "receipt", ["secret-receipt", {}, [], {"@version": "EP-RECEIPT-v1", "payload": []}]
)
def test_malformed_receipt_does_not_leak_material(receipt):
    guarded = wrap(get_receipt=lambda arguments: receipt)
    with pytest.raises(ReceiptRequired) as caught:
        guarded(**ARGS)
    assert "secret-receipt" not in str(caught.value)


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {**ARGS, "extra": 1},
        {**ARGS, "amount_cents": float("nan")},
        {**ARGS, "memo": object()},
    ],
)
def test_invalid_call_binding_refuses_cleanly(arguments):
    raw = RefundTool()
    guarded = wrap(raw)
    assert_refused(guarded, "action_binding_invalid", arguments=arguments)
    assert raw.calls == []


@pytest.mark.parametrize(
    "amount", [0.000001, 1.5, 2**53, -(2**53), float("inf"), float("-inf")]
)
def test_cross_language_unsafe_numeric_inputs_refuse_before_receipt_lookup(amount):
    raw = RefundTool()
    guarded = wrap(
        raw,
        get_receipt=lambda arguments: pytest.fail(
            "Do not request approval for unbindable input"
        ),
    )
    assert_refused(
        guarded, "action_binding_invalid", arguments={**ARGS, "amount_cents": amount}
    )
    assert raw.calls == []


def test_lone_surrogate_is_a_clean_binding_refusal():
    guarded = wrap()
    assert_refused(
        guarded, "action_binding_invalid", arguments={**ARGS, "memo": "\ud800"}
    )


def test_fractional_default_is_rejected_at_construction():
    raw = RefundTool()

    def fractional(order_id: str, amount_cents: int, memo: float = 0.000001):
        return True

    raw.forward = fractional
    with pytest.raises(TypeError, match="defaults"):
        wrap(raw)


def test_resolver_cannot_mutate_bound_nested_arguments_or_caller_input():
    raw = NestedTool()
    requested = {"nested": {"payee": "alice"}, "amount": 2500}
    receipt = mint(bind_call_action("refund.issue", raw.name, {"change": requested}))

    def resolver(arguments):
        arguments["change"]["nested"]["payee"] = "mallory"
        requested["nested"]["payee"] = "changed elsewhere"
        return receipt

    guarded = wrap(raw, get_receipt=resolver)
    result = guarded(change=requested)
    assert result["nested"]["payee"] == "alice"
    assert raw.calls == [{"nested": {"payee": "alice"}, "amount": 2500}]


def test_receipt_resolver_failure_is_sanitized_and_does_not_enter_provider():
    raw = RefundTool()

    def resolver(arguments):
        raise ValueError("credential=secret-123")

    guarded = wrap(raw, get_receipt=resolver)
    with pytest.raises(ReceiptRequired) as caught:
        guarded(**ARGS)
    assert caught.value.reason == "receipt_resolution_failed"
    assert "secret-123" not in "".join(traceback.format_exception(caught.value))
    assert raw.calls == []
    assert raw.setup_calls == 0


def test_host_receipt_resolver_works_from_worker_thread():
    received = []
    receipt = None

    def resolver(arguments):
        received.append(arguments)
        return receipt

    guarded = wrap(get_receipt=resolver)
    receipt = mint(guarded.bound_action_for(**ARGS))
    with ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(guarded, **ARGS).result() == {"recorded": True}
    assert received == [{**ARGS, "memo": "customer request"}]


def test_real_tool_calling_agent_parallel_duplicate_is_refused_offline():
    raw = RefundTool()
    resolver_threads = []
    receipt = None

    def resolver(arguments):
        resolver_threads.append(threading.get_ident())
        return receipt

    guarded = wrap(raw, get_receipt=resolver)
    receipt = mint(guarded.bound_action_for(**ARGS))

    class ScriptedModel(Model):
        def __init__(self):
            super().__init__(model_id="offline-scripted-test")
            self.turn = 0

        def generate(self, messages, **kwargs):
            self.turn += 1
            if self.turn == 1:
                calls = [
                    ChatMessageToolCall(
                        function=ChatMessageToolCallFunction(
                            name=guarded.name, arguments=dict(ARGS)
                        ),
                        id=f"duplicate-{index}",
                        type="function",
                    )
                    for index in range(2)
                ]
            else:
                calls = [
                    ChatMessageToolCall(
                        function=ChatMessageToolCallFunction(
                            name="final_answer", arguments={"answer": "checked"}
                        ),
                        id="final",
                        type="function",
                    )
                ]
            return ChatMessage(role=MessageRole.ASSISTANT, tool_calls=calls)

    agent = ToolCallingAgent(
        tools=[guarded], model=ScriptedModel(), max_steps=3, verbosity_level=0
    )
    assert (
        agent.run("Run the scripted duplicate calls; no network or model inference.")
        == "checked"
    )
    assert len(raw.calls) == 1
    assert len(resolver_threads) == 2
    assert all(thread_id != threading.get_ident() for thread_id in resolver_threads)
    assert any(
        "replay_refused" in str(getattr(step, "error", ""))
        for step in agent.memory.steps
    )


def test_context_receipt_is_not_silently_assumed_to_cross_worker_threads():
    guarded = wrap()
    receipt = mint(guarded.bound_action_for(**ARGS))
    with (
        using_receipt(receipt),
        ThreadPoolExecutor(max_workers=1) as executor,
        pytest.raises(ReceiptRequired) as caught,
    ):
        executor.submit(guarded, **ARGS).result()
    assert caught.value.reason == "receipt_required"


def test_concurrent_replay_allows_one_provider_entry():
    raw = RefundTool()
    barrier = threading.Barrier(12)
    receipt = None
    guarded = wrap(raw, get_receipt=lambda arguments: receipt)
    receipt = mint(guarded.bound_action_for(**ARGS))

    def run():
        barrier.wait()
        try:
            guarded(**ARGS)
            return "ran"
        except ReceiptRequired as error:
            return error.reason

    with ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(lambda _: run(), range(12)))
    assert results.count("ran") == 1
    assert results.count("replay_refused") == 11
    assert len(raw.calls) == 1


def test_metadata_schema_and_callable_are_captured_at_construction():
    raw = RefundTool()
    guarded = wrap(raw)
    action = guarded.bound_action_for(**ARGS)
    raw.name = "different_tool"
    raw.description = "different"
    raw.inputs["memo"]["description"] = "different"
    guarded.inputs["memo"]["description"] = "ignored"
    raw.output_schema["type"] = "string"
    raw.forward = lambda **kwargs: {"bypassed": True}
    assert guarded.name == "issue_refund"
    assert guarded.inputs["memo"]["description"] == "Refund memo"
    assert guarded.output_schema["type"] == "object"
    assert guarded.bound_action_for(**ARGS) == action
    with pytest.raises(AttributeError):
        guarded.forward = raw.forward
    with using_receipt(mint(action)):
        assert guarded(**ARGS) == {"recorded": True}
    assert len(raw.calls) == 1


def test_mutable_default_is_frozen_and_copied_for_each_invocation():
    default = {"payee": "alice"}

    @tool
    def change_payee(change: dict = default) -> dict:
        """Return a test change.

        Args:
            change: Complete change.
        """
        return change

    guarded = wrap(change_payee)
    action = guarded.bound_action_for()
    default["payee"] = "mallory"
    with using_receipt(mint(action)):
        result = guarded()
    assert result == {"payee": "alice"}
    result["payee"] = "changed result"
    assert guarded.bound_action_for() == action


def test_response_loss_is_indeterminate_sanitized_and_not_reusable():
    raw = RefundTool()
    original = raw.forward

    def response_lost(order_id: str, amount_cents: int, memo: str = "customer request"):
        original(order_id, amount_cents, memo)
        raise TimeoutError("token=provider-secret; response lost")

    raw.forward = response_lost
    guarded = wrap(raw)
    receipt = mint(guarded.bound_action_for(**ARGS))
    with using_receipt(receipt), pytest.raises(ToolExecutionIndeterminate) as caught:
        guarded(**ARGS)
    assert caught.value.reason == "provider_outcome_unknown"
    assert "provider-secret" not in "".join(traceback.format_exception(caught.value))
    assert_refused(guarded, "replay_refused", receipt=receipt)
    assert len(raw.calls) == 1


def test_setup_failure_consumes_attempt_without_calling_forward():
    raw = RefundTool()

    def failed_setup():
        raise RuntimeError("secret setup connection")

    raw.setup = failed_setup
    guarded = wrap(raw)
    receipt = mint(guarded.bound_action_for(**ARGS))
    with using_receipt(receipt), pytest.raises(ToolExecutionIndeterminate):
        guarded.forward(**ARGS)
    assert_refused(guarded, "replay_refused", receipt=receipt)
    assert raw.calls == []


def test_lazy_setup_result_is_not_awaited_and_consumes_attempt():
    raw = RefundTool()
    advanced = []

    async def deferred_setup():
        advanced.append("advanced")

    raw.setup = lambda: deferred_setup()
    guarded = wrap(raw)
    receipt = mint(guarded.bound_action_for(**ARGS))
    with using_receipt(receipt), pytest.raises(ToolExecutionIndeterminate) as caught:
        guarded(**ARGS)
    assert caught.value.reason == "unsupported_lazy_output"
    assert advanced == []
    assert raw.calls == []
    assert_refused(guarded, "replay_refused", receipt=receipt)


def test_receipt_expiring_during_setup_is_rechecked_before_forward(monkeypatch):
    now = [datetime.now(timezone.utc).timestamp()]
    monkeypatch.setattr(emilia_crewai, "_now", lambda: now[0])
    raw = RefundTool()

    def slow_setup():
        raw.setup_calls += 1
        now[0] += 120

    raw.setup = slow_setup
    guarded = wrap(raw, max_age_sec=None)
    receipt = mint(
        guarded.bound_action_for(**ARGS),
        expires_at=datetime.fromtimestamp(now[0] + 60, timezone.utc).isoformat(),
    )
    with using_receipt(receipt), pytest.raises(ToolExecutionIndeterminate) as caught:
        guarded(**ARGS)
    assert caught.value.reason == "receipt_expired_after_admission"
    assert raw.calls == []
    assert raw.setup_calls == 1
    # Put the clock back only to prove the reserved identifier was consumed;
    # production callers must not change their trusted clock to revive authority.
    now[0] -= 120
    assert_refused(guarded, "replay_refused", receipt=receipt)


def test_receipt_expiring_while_waiting_for_setup_lock_never_runs_setup(monkeypatch):
    now = [datetime.now(timezone.utc).timestamp()]
    monkeypatch.setattr(emilia_crewai, "_now", lambda: now[0])
    raw = RefundTool()
    guarded = wrap(raw, max_age_sec=None)
    receipt = mint(
        guarded.bound_action_for(**ARGS),
        expires_at=datetime.fromtimestamp(now[0] + 60, timezone.utc).isoformat(),
    )

    class DelayedLock:
        def __enter__(self):
            now[0] += 120

        def __exit__(self, *args):
            return False

    guarded._setup_lock = DelayedLock()
    with using_receipt(receipt), pytest.raises(ToolExecutionIndeterminate) as caught:
        guarded(**ARGS)
    assert caught.value.reason == "receipt_expired_after_admission"
    assert raw.setup_calls == 0
    assert raw.calls == []


@pytest.mark.parametrize("slow_verification", [2, 3])
@pytest.mark.parametrize("validity", ["signed_expiry", "maximum_age"])
def test_slow_assurance_recheck_cannot_extend_provider_entry_validity(
    monkeypatch, slow_verification, validity
):
    now = [datetime.now(timezone.utc).timestamp()]
    monkeypatch.setattr(emilia_crewai, "_now", lambda: now[0])
    verification_count = 0

    def verify_assurance(receipt, required):
        nonlocal verification_count
        verification_count += 1
        if verification_count == slow_verification:
            now[0] += 120
        return {"ok": True, "tier": required}

    raw = RefundTool()
    guarded = wrap(
        raw,
        max_age_sec=60 if validity == "maximum_age" else None,
        assurance_class="class_a",
        verify_assurance=verify_assurance,
    )
    receipt = mint(
        guarded.bound_action_for(**ARGS),
        created_at=datetime.fromtimestamp(now[0], timezone.utc).isoformat(),
        expires_at=(
            datetime.fromtimestamp(now[0] + 60, timezone.utc).isoformat()
            if validity == "signed_expiry"
            else None
        ),
    )
    with using_receipt(receipt), pytest.raises(ToolExecutionIndeterminate) as caught:
        guarded(**ARGS)
    assert caught.value.reason == "receipt_expired_after_admission"
    assert raw.calls == []
    assert raw.setup_calls == (1 if slow_verification == 3 else 0)
    # Move only this test clock back to verify admission remains consumed.
    now[0] -= 120
    assert_refused(guarded, "replay_refused", receipt=receipt)


@pytest.mark.parametrize("kind", ["async", "generator", "async_generator"])
def test_declared_async_and_generator_tools_rejected_before_entry(kind):
    raw = RefundTool()

    async def async_call(
        order_id: str, amount_cents: int, memo: str = "customer request"
    ):
        return True

    def generator_call(
        order_id: str, amount_cents: int, memo: str = "customer request"
    ):
        yield True

    async def async_generator_call(
        order_id: str, amount_cents: int, memo: str = "customer request"
    ):
        yield True

    raw.forward = {
        "async": async_call,
        "generator": generator_call,
        "async_generator": async_generator_call,
    }[kind]
    with pytest.raises(TypeError, match="synchronous"):
        wrap(raw)
    assert raw.calls == []


@pytest.mark.parametrize(
    "kind", ["coroutine", "generator", "iterator", "async_iterator"]
)
def test_lazy_return_is_never_advanced_and_receipt_is_consumed(kind):
    raw = RefundTool()
    advanced = []

    async def deferred():
        advanced.append("advanced")

    def generator():
        advanced.append("advanced")
        yield "result"

    class AsyncResults:
        def __aiter__(self):
            return self

        async def __anext__(self):
            advanced.append("advanced")
            return "result"

    def lazy_call(order_id: str, amount_cents: int, memo: str = "customer request"):
        raw.calls.append(order_id)
        return {
            "coroutine": deferred,
            "generator": generator,
            "iterator": lambda: iter([1]),
            "async_iterator": AsyncResults,
        }[kind]()

    raw.forward = lazy_call
    guarded = wrap(raw)
    receipt = mint(guarded.bound_action_for(**ARGS))
    with using_receipt(receipt), pytest.raises(ToolExecutionIndeterminate) as caught:
        guarded(**ARGS)
    assert caught.value.reason == "unsupported_lazy_output"
    assert advanced == []
    assert_refused(guarded, "replay_refused", receipt=receipt)
    assert len(raw.calls) == 1


def test_class_a_is_not_satisfied_by_software_signature_or_diagnostic_string():
    for verifier in (
        None,
        lambda receipt, tier: "class_a",
        lambda receipt, tier: {"ok": False, "tier": "class_a"},
    ):
        raw = RefundTool()
        guarded = wrap(raw, assurance_class="class_a", verify_assurance=verifier)
        with (
            using_receipt(mint(guarded.bound_action_for(**ARGS))),
            pytest.raises(ReceiptRequired),
        ):
            guarded(**ARGS)
        assert raw.calls == []


def test_shared_store_covers_multiple_wrappers_and_commit_failure_is_closed():
    class Store:
        def __init__(self):
            self.states = set()

        def reserve(self, receipt_id):
            if receipt_id in self.states:
                return False
            self.states.add(receipt_id)
            return True

        def commit(self, receipt_id):
            return False

        def release(self, receipt_id):
            raise AssertionError("Must not release a post-entry attempt")

    store = Store()
    raw = RefundTool()
    first, second = wrap(raw, store=store), wrap(raw, store=store)
    receipt = mint(first.bound_action_for(**ARGS))
    with using_receipt(receipt), pytest.raises(ToolExecutionIndeterminate) as caught:
        first(**ARGS)
    assert caught.value.reason == "consumption_state_unknown"
    assert_refused(second, "replay_refused", receipt=receipt)
    assert len(raw.calls) == 1


@pytest.mark.parametrize("operation", ["to_dict", "save", "push_to_hub", "pickle"])
def test_configured_tool_cannot_be_serialized_or_uploaded(
    operation, tmp_path, monkeypatch
):
    guarded = wrap(get_receipt=lambda arguments: {"private": "secret"})
    monkeypatch.setattr(
        Tool, "_initialize_hub_repo", lambda *args: pytest.fail("No Hub write allowed")
    )
    with pytest.raises(TypeError):
        if operation == "to_dict":
            guarded.to_dict()
        elif operation == "save":
            guarded.save(tmp_path / "tool")
        elif operation == "push_to_hub":
            guarded.push_to_hub("example/never-created")
        else:
            pickle.dumps(guarded)
    assert not list(tmp_path.iterdir())


def test_shared_tool_binding_vectors():
    path = (
        Path(__file__).resolve().parents[3]
        / "conformance/vectors/tool-call-binding.v1.json"
    )
    for vector in json.loads(path.read_text())["vectors"]:
        assert (
            bind_call_action(vector["base_action"], vector["tool"], vector["args"])
            == vector["expected_caid"]
        )


def test_unsupported_signature_schema_and_nested_wrapping_are_rejected():
    guarded = wrap()
    with pytest.raises(TypeError, match="unwrapped"):
        wrap(guarded)
    raw = RefundTool()
    raw.forward = lambda **kwargs: "unexpected"
    with pytest.raises(TypeError, match="explicit"):
        wrap(raw)
    raw = RefundTool()
    raw.inputs["extra"] = {"type": "string", "description": "Not in actual signature"}
    try:
        with pytest.raises(TypeError, match="schema"):
            wrap(raw)
    finally:
        del raw.inputs["extra"]
