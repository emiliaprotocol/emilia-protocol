# SPDX-License-Identifier: Apache-2.0
"""EMILIA guard for LangChain tools — an executor-side precondition.

Design rule (learned the hard way in the cookbook review): approval is NOT a
tool the model calls. It is a precondition the executor enforces. The wrapper
computes the action digest from the ACTUAL arguments at execution time and
gates on those — so "model forgets to ask", "approve A, execute B", and
"continue past a denial" are structurally impossible, not just discouraged.

    from langchain_emilia import EmiliaGuard, guard_tools

    guard = EmiliaGuard()                  # enforce mode, creds from env
    tools = guard_tools([transfer, send_email, calculator], guard)
    # ... hand `tools` to your agent exactly as before.

Modes:
    enforce — matched tools are held for the EP gate (policy allow / deny /
              named-human Face ID signoff). Fail-closed: transport failure,
              timeout, or denial never executes the tool.
    observe — zero-setup local dry run ("Eye"): nothing is blocked, no
              network, no account; every would-be-gated call is recorded with
              its action digest so you can see what enforcement would cover.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Callable, Iterable, Optional

from langchain_core.tools import BaseTool, ToolException

from .client import EmiliaClient, EmiliaConfigError, EmiliaUnreachable, GateResult
from .digest import action_digest

# Same irreversible-action heuristic as the Claude Agent SDK hook.
DEFAULT_MATCH = re.compile(
    r"(pay|transfer|wire|withdraw|payout|charge|refund|send|email|message|post"
    r"|publish|deploy|delete|terminate|disable|revoke|grant|trade|order|invoice"
    r"|bank|beneficiary|payee)", re.I)

_BANKISH = re.compile(r"bank|account|payee|beneficiary|remittance", re.I)
_AMOUNT_KEYS = ("amount", "value", "total", "amount_usd")


class EmiliaDenied(ToolException):
    """The action was blocked — by policy or by the named human approver."""

    def __init__(self, message: str, result: Optional[GateResult] = None) -> None:
        super().__init__(message)
        self.result = result


class EmiliaApprovalPending(ToolException):
    """A human signoff is required and was not granted in time. Fail closed."""

    def __init__(self, message: str, result: Optional[GateResult] = None) -> None:
        super().__init__(message)
        self.result = result
        self.signoff_url = result.signoff_url if result else None


class EmiliaGuard:
    """Configuration + decision engine shared by all wrapped tools."""

    def __init__(
        self,
        client: Optional[EmiliaClient] = None,
        mode: str = "enforce",
        match: Optional[Callable[[str], bool]] = None,
        action_types: Optional[dict[str, str]] = None,
        wait_for_approval: bool = True,
        return_errors: bool = True,
        on_event: Optional[Callable[[dict], None]] = None,
    ) -> None:
        if mode not in ("enforce", "observe"):
            raise ValueError("mode must be 'enforce' or 'observe'")
        self.mode = mode
        self.client = client or (EmiliaClient() if mode == "enforce" else None)
        self.match = match or (lambda name: bool(DEFAULT_MATCH.search(name)))
        self.action_types = dict(action_types or {})
        self.wait_for_approval = wait_for_approval
        # When True (default), denials/holds are returned to the model as the
        # tool's output (LangChain handle_tool_error) so the agent loop can
        # explain itself instead of crashing. The action still never runs.
        self.return_errors = return_errors
        self.on_event = on_event
        self.records: list[dict] = []
        if mode == "enforce" and self.client is not None:
            self.client.require_creds()

    # -- helpers ---------------------------------------------------------------

    def _emit(self, event: dict) -> None:
        self.records.append(event)
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:  # noqa: BLE001 — observer must never break the gate
                pass

    def _action_type_for(self, tool_name: str) -> str:
        if tool_name in self.action_types:
            return self.action_types[tool_name]
        if _BANKISH.search(tool_name):
            return "vendor_bank_account_change"
        return "ai_agent_payment_action"

    @staticmethod
    def _amount_from(args: Any) -> Optional[float]:
        if isinstance(args, dict):
            for key in _AMOUNT_KEYS:
                v = args.get(key)
                if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
                    return float(v)
        return None

    # -- the precondition --------------------------------------------------------

    def check(self, tool_name: str, args: Any) -> Optional[GateResult]:
        """Enforce the precondition for one concrete invocation.

        Returns a GateResult on allow (or None when the tool is unmatched /
        observe mode). Raises EmiliaDenied / EmiliaApprovalPending otherwise —
        the tool body must not run.
        """
        if not self.match(tool_name):
            return None
        digest = action_digest(tool_name, args)

        if self.mode == "observe":
            self._emit({"event": "observed", "tool": tool_name, "digest": digest, "ts": time.time(),
                        "note": "would be gated in enforce mode"})
            return None

        try:
            result = self.client.gate(
                action_type=self._action_type_for(tool_name),
                target=f"{tool_name}#{digest[:32]}",
                amount=self._amount_from(args),
                comment=f"LangChain tool {tool_name}",
                wait_for_approval=self.wait_for_approval,
            )
        except EmiliaConfigError:
            raise
        except EmiliaUnreachable as err:
            self._emit({"event": "unreachable", "tool": tool_name, "digest": digest, "error": str(err)})
            raise EmiliaApprovalPending(
                f"EMILIA — gate unreachable ({err}); failing closed. {tool_name} was NOT executed."
            ) from err

        if result.decision == "allow":
            who = "a named human on their own device" if result.approved_by_human else "policy"
            self._emit({"event": "allowed", "tool": tool_name, "digest": digest,
                        "receipt_id": result.receipt_id, "approved_by_human": result.approved_by_human})
            # The receipt is the evidence: offline-verifiable, forever.
            result.reasons = [f"approved by {who}; receipt {result.receipt_id}"]
            return result
        if result.decision == "deny":
            self._emit({"event": "denied", "tool": tool_name, "digest": digest,
                        "receipt_id": result.receipt_id, "reasons": result.reasons})
            raise EmiliaDenied(
                f"EMILIA — BLOCKED: {'; '.join(result.reasons) or 'denied'}. {tool_name} was NOT executed.",
                result,
            )
        self._emit({"event": "pending", "tool": tool_name, "digest": digest,
                    "receipt_id": result.receipt_id, "signoff_url": result.signoff_url})
        where = f" Approve at {result.signoff_url} and run the action again." if result.signoff_url else ""
        raise EmiliaApprovalPending(
            f"EMILIA — held for human approval; {'; '.join(result.reasons) or 'signoff pending'}."
            f" {tool_name} was NOT executed.{where}",
            result,
        )


class GuardedTool(BaseTool):
    """A LangChain tool wrapped in the EMILIA precondition.

    Preserves the inner tool's name, description, and argument schema, so the
    model-facing surface is unchanged — only the executor gains the gate.
    """

    inner: Any = None
    guard: Any = None

    def _payload(self, args: tuple, kwargs: dict) -> Any:
        if kwargs:
            return kwargs
        if args:
            return args[0]
        return {}

    def _forward(self, payload: Any, run_manager: Any = None) -> Any:
        callbacks = run_manager.get_child() if run_manager is not None else None
        return self.inner.run(payload if payload != {} else "", callbacks=callbacks)

    async def _aforward(self, payload: Any, run_manager: Any = None) -> Any:
        callbacks = run_manager.get_child() if run_manager is not None else None
        return await self.inner.arun(payload if payload != {} else "", callbacks=callbacks)

    def _run(self, *args: Any, run_manager: Any = None, **kwargs: Any) -> Any:
        payload = self._payload(args, kwargs)
        self.guard.check(self.name, payload)  # raises on deny/pending — fail closed
        return self._forward(payload, run_manager)

    async def _arun(self, *args: Any, run_manager: Any = None, **kwargs: Any) -> Any:
        payload = self._payload(args, kwargs)
        # The gate blocks (it may wait on a human); never stall the event loop.
        await asyncio.to_thread(self.guard.check, self.name, payload)
        return await self._aforward(payload, run_manager)


def wrap_tool(tool: BaseTool, guard: EmiliaGuard) -> BaseTool:
    """Wrap one LangChain tool in the EMILIA precondition."""
    return GuardedTool(
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        return_direct=getattr(tool, "return_direct", False),
        handle_tool_error=guard.return_errors,
        inner=tool,
        guard=guard,
    )


def guard_tools(tools: Iterable[BaseTool], guard: Optional[EmiliaGuard] = None) -> list[BaseTool]:
    """Wrap a list of tools. Unmatched tools pass through ungated at call time."""
    g = guard or EmiliaGuard()
    return [wrap_tool(t, g) for t in tools]
