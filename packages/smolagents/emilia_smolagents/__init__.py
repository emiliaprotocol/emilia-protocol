"""Require exact-action authorization receipts on covered smolagents calls.

This in-process adapter is not a sandbox or a credential-owning gateway. It uses
the shared Python ReceiptGate for verification and atomic receipt consumption.
"""

from __future__ import annotations

import inspect
import json
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Iterator
from typing import Any

from emilia_crewai import (
    ReceiptGate,
    ReceiptRequired,
    bind_call_action,
    current_receipt,
    using_receipt,
)
from emilia_verify import canonicalize, is_canonicalizable
from smolagents import Tool
from smolagents.agent_types import handle_agent_input_types, handle_agent_output_types

__all__ = [
    "GuardedTool",
    "ReceiptRequired",
    "ToolExecutionIndeterminate",
    "bind_call_action",
    "guard_smolagents_tool",
    "using_receipt",
]


class ToolExecutionIndeterminate(RuntimeError):
    """An admitted attempt did not return a usable result. Do not blind-retry.

    ``reason`` is safe to show to the agent. The underlying provider exception
    is deliberately omitted because it may contain credentials or request data.
    This local exception is not a signed execution or reconciliation record.
    """

    def __init__(self, reason: str = "provider_outcome_unknown"):
        self.reason = reason
        super().__init__(
            f"EMILIA tool attempt is indeterminate: {reason}; do not retry this receipt"
        )


class _AttemptFailed(Exception):
    def __init__(self, reason: str):
        self.reason = reason


class _RecheckRefused(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def _copy_json(value: Any) -> Any:
    # The shared canonicalizer mirrors JSON.stringify, including NaN -> null.
    # Refuse non-JSON numbers before canonicalization so an invalid request
    # cannot silently become a different, valid-looking provider argument.
    json.dumps(value, allow_nan=False)
    encoded = canonicalize(value)
    encoded.encode("utf-8")
    return json.loads(encoded)


def _copy_input(value: Any) -> Any:
    # Use the shared verifier's cross-language safe-number profile. Fractional
    # decimal quantities belong in strings or integer minor units, not floats.
    if not is_canonicalizable(value):
        raise ValueError("Input is outside the canonical JSON profile")
    return _copy_json(value)


def _reject_lazy(result: Any):
    if isinstance(result, (Awaitable, Iterator, AsyncIterator)):
        if inspect.iscoroutine(result) or inspect.isgenerator(result):
            result.close()
        raise _AttemptFailed("unsupported_lazy_output")


class GuardedTool(Tool):
    """A native smolagents Tool with host-owned, out-of-band authorization.

    ``get_receipt`` receives a separate copy of the complete, default-expanded
    argument dictionary. It must retrieve already granted authority, not mint
    approval merely because the model requested a call. Without a resolver,
    receipts come from ``using_receipt`` in the current execution context.

    Only synchronous, explicitly named, JSON-valued inputs are supported.
    Shared/remote execution needs an appropriate atomic consumption store and
    credential-owning enforcement outside an untrusted agent process.
    """

    # The wrapper is intentionally generic. Validate the captured signature and
    # input schema ourselves while still using Tool's metadata validation.
    skip_forward_signature_validation = True
    _protected = frozenset(
        {"name", "description", "inputs", "output_type", "output_schema", "forward"}
    )

    def __init__(
        self,
        tool: Tool,
        *,
        action: str,
        trusted_keys: Iterable[str],
        get_receipt: Callable[[dict], dict | None] | None = None,
        store: Any = None,
        max_age_sec: float | None = 900,
        assurance_class: str = "software",
        verify_assurance: Callable[[Any, str], Any] | None = None,
        max_future_skew_sec: float = 60,
    ):
        if not isinstance(tool, Tool) or isinstance(tool, GuardedTool):
            raise TypeError("Expected an unwrapped smolagents.Tool")
        if get_receipt is not None and not callable(get_receipt):
            raise TypeError("get_receipt must be a host-owned callable")
        original_forward = tool.forward
        original_setup = tool.setup
        if any(
            inspect.iscoroutinefunction(fn)
            or inspect.isasyncgenfunction(fn)
            or inspect.isgeneratorfunction(fn)
            for fn in (original_forward, original_setup)
        ):
            raise TypeError("Only synchronous, non-generator tools are supported")
        signature = inspect.signature(original_forward)
        # smolagents' @tool uses a staticmethod but advertises an artificial
        # `self` in its signature for source export. Bind the original function
        # signature, which is the one its forwarding wrapper actually invokes.
        if (
            "self" in signature.parameters
            and "self" not in tool.inputs
            and isinstance(inspect.getattr_static(type(tool), "forward"), staticmethod)
            and hasattr(original_forward, "__wrapped__")
        ):
            signature = inspect.signature(original_forward.__wrapped__)
        if any(
            p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
            for p in signature.parameters.values()
        ):
            raise TypeError("Tool inputs must have an explicit forward signature")
        if "sanitize_inputs_outputs" in signature.parameters:
            raise TypeError("sanitize_inputs_outputs is reserved by smolagents")
        if set(signature.parameters) != set(tool.inputs):
            raise TypeError("Tool input schema must match its forward signature")
        # Validate defaults now and detach mutable defaults from the source tool.
        frozen_parameters = []
        for parameter in signature.parameters.values():
            if parameter.default is not inspect.Parameter.empty:
                try:
                    parameter = parameter.replace(
                        default=_copy_input(parameter.default)
                    )
                except Exception:  # noqa: BLE001 - invalid host defaults must not leak object data
                    raise TypeError("Tool defaults must be canonical JSON") from None
            frozen_parameters.append(parameter)
        self._signature = signature.replace(parameters=frozen_parameters)
        self._name = tool.name
        self._description = tool.description
        self._inputs = _copy_json(tool.inputs)
        self._output_type = tool.output_type
        self._output_schema = _copy_json(getattr(tool, "output_schema", None))
        self._action = action
        # Validate action and name at construction, including length bounds.
        bind_call_action(action, self._name, {})
        self._receipt_resolver = get_receipt
        self._provider_forward = original_forward
        self._provider_setup = original_setup
        self._provider_initialized = bool(getattr(tool, "is_initialized", False))
        self._setup_lock = threading.Lock()
        self._gate = ReceiptGate(
            action=lambda exact_action: exact_action,
            trusted_keys=tuple(trusted_keys),
            allow_inline_key=False,
            max_age_sec=max_age_sec,
            store=store,
            assurance_class=assurance_class,
            verify_assurance=verify_assurance,
            max_future_skew_sec=max_future_skew_sec,
        )
        # Reuse the non-reserving verifier after waiting/setup, then check the
        # clock again after any blocking assurance callback. The dependency is
        # bounded to the tested minor version and regression-tested here.
        self._reverify = self._gate._verify
        self._freshness_reason = self._gate._freshness_reason
        super().__init__()
        self._frozen = True

    def __setattr__(self, name: str, value: Any):
        if getattr(self, "_frozen", False) and name in self._protected:
            raise AttributeError(
                "Guarded tool metadata and forward method are fixed at construction"
            )
        super().__setattr__(name, value)

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @property
    def inputs(self):
        return _copy_json(self._inputs)

    @property
    def output_type(self):
        return self._output_type

    @property
    def output_schema(self):
        return _copy_json(self._output_schema)

    def setup(self):
        # Tool setup can run provider code. Defer the captured provider setup
        # until AFTER receipt reservation, even on a direct forward() call.
        self.is_initialized = True

    def _snapshot(self, args: tuple, kwargs: dict):
        try:
            bound = self._signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = _copy_input(dict(bound.arguments))
            for key in bound.arguments:
                bound.arguments[key] = arguments[key]
            return arguments, bound.args, bound.kwargs
        except Exception:  # noqa: BLE001 - refuse arbitrary malformed tool input without leaking it
            raise ReceiptRequired("action_binding_invalid") from None

    def bound_action_for(self, *args, **kwargs) -> str:
        """Compute the host's approval target, including omitted defaults.

        Pass normal Python arguments, not smolagents' single-dictionary shorthand.
        This computes an identifier; it does not grant or consume authority.
        """
        arguments, _, _ = self._snapshot(args, kwargs)
        return bind_call_action(self._action, self._name, arguments)

    def _run(self, args: tuple, kwargs: dict, sanitize: bool):
        try:
            if sanitize:
                args, kwargs = handle_agent_input_types(*args, **kwargs)
        except Exception:  # noqa: BLE001 - framework conversion errors must refuse before entry
            raise ReceiptRequired("action_binding_invalid") from None
        arguments, invocation_args, invocation_kwargs = self._snapshot(args, kwargs)
        exact_action = bind_call_action(self._action, self._name, arguments)
        try:
            receipt = (
                self._receipt_resolver(_copy_json(arguments))
                if self._receipt_resolver
                else current_receipt()
            )
            if receipt is not None:
                receipt = _copy_json(receipt)
        except Exception:  # noqa: BLE001 - host lookup failures must not expose receipt data
            raise ReceiptRequired("receipt_resolution_failed") from None

        def recheck():
            ok, reason, _ = self._reverify(receipt, exact_action)
            if not ok:
                raise _RecheckRefused(reason)
            reason = self._freshness_reason(receipt["payload"])
            if reason is not None:
                raise _RecheckRefused(reason)

        def invoke():
            try:
                with self._setup_lock:
                    recheck()
                    if not self._provider_initialized:
                        _reject_lazy(self._provider_setup())
                        self._provider_initialized = True
                recheck()
                result = self._provider_forward(*invocation_args, **invocation_kwargs)
                # Never advance or await lazy output after admission.
                _reject_lazy(result)
                return (
                    handle_agent_output_types(result, self._output_type)
                    if sanitize
                    else result
                )
            except (_AttemptFailed, _RecheckRefused):
                raise
            except Exception:  # noqa: BLE001 - provider errors may contain credentials
                raise _AttemptFailed("provider_outcome_unknown") from None

        try:
            return self._gate.run(receipt, invoke, target=exact_action)
        except ReceiptRequired as error:
            raise ReceiptRequired(error.reason, error.action) from None
        except _RecheckRefused as error:
            # run() commits the reservation even though forward was refused.
            # The setup attempt may itself have touched the provider.
            raise ToolExecutionIndeterminate(
                f"{error.reason}_after_admission"
            ) from None
        except _AttemptFailed as error:
            raise ToolExecutionIndeterminate(error.reason) from None
        except Exception:  # noqa: BLE001 - every unclassified gate failure stays closed
            # Includes a commit failure after a provider attempt. The shared
            # gate retains the reservation; no success or retry-safe claim.
            raise ToolExecutionIndeterminate("consumption_state_unknown") from None

    def forward(self, *args, **kwargs):
        return self._run(args, kwargs, sanitize=False)

    def __call__(self, *args, sanitize_inputs_outputs: bool = False, **kwargs):
        # Match native Tool's single-dictionary convention without invoking its
        # pre-forward setup path. Binding uses the frozen schema.
        if (
            len(args) == 1
            and not kwargs
            and isinstance(args[0], dict)
            and all(key in self._inputs for key in args[0])
        ):
            args, kwargs = (), args[0]
        return self._run(args, kwargs, sanitize=sanitize_inputs_outputs)

    def to_dict(self):
        raise TypeError(
            "GuardedTool cannot be serialized; configure authority in the host"
        )

    def save(self, *args, **kwargs):
        raise TypeError(
            "GuardedTool cannot be saved; distribute source without host authority"
        )

    def push_to_hub(self, *args, **kwargs):
        raise TypeError(
            "GuardedTool cannot be uploaded; distribute an unconfigured example instead"
        )

    def __reduce_ex__(self, protocol):
        raise TypeError(
            "GuardedTool cannot be pickled; configure authority in the host"
        )


def guard_smolagents_tool(tool: Tool, **configuration) -> GuardedTool:
    """Wrap a native synchronous Tool. See ``GuardedTool`` for configuration."""
    return GuardedTool(tool, **configuration)
