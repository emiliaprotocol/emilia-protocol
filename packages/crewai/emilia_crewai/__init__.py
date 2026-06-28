"""emilia-crewai — guard CrewAI tools with EMILIA Protocol.

Require an offline-verifiable EMILIA authorization receipt (EP-RECEIPT-v1) before
an irreversible CrewAI tool runs. Four normative behaviors (RR-1):

    missing  -> refused (raises ReceiptRequired)
    valid    -> runs
    replay   -> refused (one-time consumption)
    forged   -> refused

Verification is offline Ed25519 over canonical JSON via ``emilia_verify`` — zero
network, no vendor in the loop. The approval becomes portable evidence an auditor
can check without trusting the operator. Necessary-not-sufficient: this composes
with — never replaces — the tool owner's own checks.

This mirrors, in Python, the canonical @emilia-protocol/require-receipt
``makeReceiptGate`` + ``verifyEmiliaReceipt`` semantics:
  * TARGET BINDING   — a receipt binds the exact action ("action" or "action:target").
  * AGE / OUTCOME    — reject stale receipts and non-allow outcomes.
  * REPLAY SAFETY    — reserve on check, commit on success, release on failure.
  * SANITIZED REASON — refusals expose only a reason code, never signer detail.

CrewAI is an OPTIONAL peer: the gate and decorator are pure Python and work with
any callable; ``guard_crewai_tool`` duck-types a BaseTool's ``_run``.

License: Apache-2.0
See: draft-schrock-ep-authorization-receipts, draft-schrock-ep-enforcement-point
"""
from __future__ import annotations

import contextlib
import contextvars
import functools
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

from emilia_verify import verify_receipt

__all__ = [
    "ReceiptGate",
    "ReceiptRequired",
    "require_receipt",
    "guard_crewai_tool",
    "set_current_receipt",
    "using_receipt",
    "current_receipt",
]

DEFAULT_MAX_AGE_SEC = 900
DEFAULT_ALLOWED_OUTCOMES = ("allow", "allow_with_signoff")
RECEIPT_VERSION = "EP-RECEIPT-v1"

# The receipt is out-of-band call metadata (the LLM controls the tool args, not
# the authorization). Carry it on a context variable the caller sets around the
# agent step, or pass an explicit get_receipt resolver.
_current_receipt: "contextvars.ContextVar[Optional[dict]]" = contextvars.ContextVar(
    "emilia_receipt", default=None
)


def set_current_receipt(receipt: Optional[dict]):
    """Set the receipt for the current context. Returns the token (for reset)."""
    return _current_receipt.set(receipt)


def current_receipt() -> Optional[dict]:
    return _current_receipt.get()


@contextlib.contextmanager
def using_receipt(receipt: Optional[dict]):
    """Context manager: bind a receipt for tool calls made inside the block."""
    token = _current_receipt.set(receipt)
    try:
        yield
    finally:
        _current_receipt.reset(token)


class ReceiptRequired(Exception):
    """Raised when an action is refused: missing, invalid, replayed, or unbound."""

    def __init__(self, reason: str, action: Optional[str] = None):
        super().__init__(f"EMILIA receipt required/refused for {action!r}: {reason}")
        self.reason = reason
        self.action = action


class _InMemoryStore:
    """Process-local consumed-receipt store. Pass a shared/durable store
    ({has, add}) for one-time consumption across instances/restarts."""

    def __init__(self):
        self._consumed: set = set()

    def has(self, receipt_id: str) -> bool:
        return receipt_id in self._consumed

    def add(self, receipt_id: str) -> None:
        self._consumed.add(receipt_id)


def _normalize_target(target: Any) -> Optional[str]:
    if target is None:
        return None
    if isinstance(target, (list, tuple)):
        return ",".join(sorted(map(str, target)))
    return str(target)


def _parse_iso_epoch(s: Any) -> Optional[float]:
    if not isinstance(s, str) or not s:
        return None
    try:
        v = s[:-1] + "+00:00" if s.endswith("Z") else s
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def _now() -> float:
    return datetime.now(timezone.utc).timestamp()


class ReceiptGate:
    """Offline Receipt-Required gate for one action type.

    Prefer ``run(receipt, fn, target=...)`` — it orchestrates verify -> reserve ->
    run -> commit/release so a caller cannot get the ordering wrong. Use the
    lower-level ``check``/``commit``/``release`` only to gate and act in separate
    steps.
    """

    def __init__(
        self,
        action: "str | Callable[[Any], str]",
        trusted_keys: Iterable[str] = (),
        allow_inline_key: bool = False,
        max_age_sec: int = DEFAULT_MAX_AGE_SEC,
        allowed_outcomes: Iterable[str] = DEFAULT_ALLOWED_OUTCOMES,
        store: Any = None,
    ):
        if not action:
            raise ValueError("ReceiptGate: `action` is required")
        self._action = action
        self._trusted = list(trusted_keys)
        self._allow_inline = allow_inline_key
        self._max_age = max_age_sec
        self._outcomes = tuple(allowed_outcomes) if allowed_outcomes else None
        self._store = store if store is not None else _InMemoryStore()
        self._inflight: set = set()

    def bound_action_for(self, target: Any = None) -> str:
        if callable(self._action):
            return self._action(target)
        t = _normalize_target(target)
        return self._action if t is None else f"{self._action}:{t}"

    def _verify(self, receipt: Any, bound_action: str):
        if (
            not isinstance(receipt, dict)
            or receipt.get("@version") != RECEIPT_VERSION
            or not receipt.get("payload")
            or not (receipt.get("signature") or {}).get("value")
        ):
            return (False, "malformed_receipt", None)

        candidates = list(self._trusted)
        if self._allow_inline and receipt.get("public_key"):
            candidates.append(receipt["public_key"])
        if not candidates:
            return (False, "no_trusted_keys_configured", None)

        signer_ok = False
        for key in candidates:
            try:
                if verify_receipt(receipt, key).valid:
                    signer_ok = True
                    break
            except Exception:
                continue
        if not signer_ok:
            return (False, "untrusted_or_invalid_signature", None)

        payload = receipt["payload"]
        claim = payload.get("claim") or {}

        if self._max_age and payload.get("created_at"):
            created = _parse_iso_epoch(payload["created_at"])
            if created is not None and (_now() - created) > self._max_age:
                return (False, "receipt_expired", None)

        if claim.get("action_type") != bound_action:
            return (False, "action_mismatch", None)

        if self._outcomes and claim.get("outcome") not in self._outcomes:
            return (False, "outcome_not_accepted", None)

        return (True, None, payload.get("receipt_id"))

    def check(self, receipt: Any, target: Any = None) -> dict:
        """Verify + reserve a receipt WITHOUT consuming it. On ok, the caller MUST
        later call commit(receipt_id) on success or release(receipt_id) on failure.
        """
        bound = self.bound_action_for(target)
        if receipt is None:
            return {"ok": False, "reason": "receipt_required", "action": bound}
        ok, reason, receipt_id = self._verify(receipt, bound)
        if not ok:
            return {"ok": False, "reason": reason, "action": bound}
        if self._store.has(receipt_id) or receipt_id in self._inflight:
            return {"ok": False, "reason": "replay_refused", "action": bound}
        self._inflight.add(receipt_id)
        return {"ok": True, "receipt_id": receipt_id, "action": bound}

    def commit(self, receipt_id: str) -> None:
        """Finalize one-time consumption after the action SUCCEEDS."""
        self._inflight.discard(receipt_id)
        self._store.add(receipt_id)

    def release(self, receipt_id: str) -> None:
        """Release the reservation after the action FAILS — approval stays retryable."""
        self._inflight.discard(receipt_id)

    def run(self, receipt: Any, fn: Callable[[], Any], target: Any = None) -> Any:
        """Verify+reserve, run ``fn``, then commit on success / release on failure.
        ``fn`` MUST raise on failure (so the approval is not consumed). Raises
        ReceiptRequired on a refused/missing receipt."""
        c = self.check(receipt, target)
        if not c["ok"]:
            raise ReceiptRequired(c["reason"], c["action"])
        try:
            result = fn()
        except Exception:
            self.release(c["receipt_id"])
            raise
        self.commit(c["receipt_id"])
        return result


def require_receipt(
    action: str,
    *,
    target_for: Optional[Callable[..., str]] = None,
    trusted_keys: Iterable[str] = (),
    allow_inline_key: bool = False,
    max_age_sec: int = DEFAULT_MAX_AGE_SEC,
    get_receipt: Optional[Callable[..., Optional[dict]]] = None,
    store: Any = None,
):
    """Decorator: gate a tool function behind an offline EMILIA receipt.

    The receipt is taken from ``get_receipt(*args, **kwargs)`` if provided, else
    from the current-receipt context variable (see ``using_receipt``). Pass
    ``target_for(*args, **kwargs) -> str`` to bind per call (e.g. the recipient),
    so one receipt cannot be reused across distinct calls.
    """
    gate = ReceiptGate(
        action,
        trusted_keys=trusted_keys,
        allow_inline_key=allow_inline_key,
        max_age_sec=max_age_sec,
        store=store,
    )

    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            receipt = get_receipt(*args, **kwargs) if get_receipt else _current_receipt.get()
            target = target_for(*args, **kwargs) if target_for else None
            return gate.run(receipt, lambda: fn(*args, **kwargs), target=target)

        wrapper.emilia_gate = gate  # type: ignore[attr-defined]
        return wrapper

    return deco


def guard_crewai_tool(
    tool: Any,
    action: str,
    *,
    target_for: Optional[Callable[..., str]] = None,
    trusted_keys: Iterable[str] = (),
    allow_inline_key: bool = False,
    max_age_sec: int = DEFAULT_MAX_AGE_SEC,
    get_receipt: Optional[Callable[..., Optional[dict]]] = None,
    store: Any = None,
):
    """Wrap a CrewAI BaseTool *instance* so its ``_run`` requires a receipt.

    Duck-typed: works with any object exposing a callable ``_run``. Returns the
    same tool (its ``_run`` is replaced with a gated version). The receipt is
    resolved exactly as in ``require_receipt``.
    """
    original = getattr(tool, "_run", None)
    if not callable(original):
        raise TypeError("guard_crewai_tool: tool must expose a callable `_run`")
    deco = require_receipt(
        action,
        target_for=target_for,
        trusted_keys=trusted_keys,
        allow_inline_key=allow_inline_key,
        max_age_sec=max_age_sec,
        get_receipt=get_receipt,
        store=store,
    )
    tool._run = deco(original)  # instance attribute shadows the class method
    return tool
