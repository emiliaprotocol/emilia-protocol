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
  * REPLAY SAFETY    — reserve before execution; commit after any execution attempt.
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
import re
import threading
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
_RFC3339_INSTANT = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)

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
    """Process-local atomic receipt store. Production fleets pass a shared,
    ownership-fenced ``{reserve, commit, release}`` implementation."""

    def __init__(self):
        self._states: dict = {}
        self._lock = threading.Lock()

    def reserve(self, receipt_id: str) -> bool:
        with self._lock:
            if receipt_id in self._states:
                return False
            self._states[receipt_id] = "reserved"
            return True

    def commit(self, receipt_id: str) -> bool:
        with self._lock:
            if self._states.get(receipt_id) != "reserved":
                raise RuntimeError("consumption reservation not owned")
            self._states[receipt_id] = "committed"
            return True

    def release(self, receipt_id: str) -> bool:
        with self._lock:
            if self._states.get(receipt_id) != "reserved":
                raise RuntimeError("consumption reservation not owned")
            del self._states[receipt_id]
            return True


def _normalize_target(target: Any) -> Optional[str]:
    if target is None:
        return None
    if isinstance(target, (list, tuple)):
        return ",".join(sorted(map(str, target)))
    return str(target)


def _parse_iso_epoch(s: Any) -> Optional[float]:
    if not isinstance(s, str) or not _RFC3339_INSTANT.fullmatch(s):
        return None
    try:
        v = s[:-1] + "+00:00" if s.endswith("Z") else s
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None or dt.utcoffset() is None:
            return None
        return dt.timestamp()
    except Exception:
        return None


def _now() -> float:
    return datetime.now(timezone.utc).timestamp()


class ReceiptGate:
    """Offline Receipt-Required gate for one action type.

    Prefer ``run(receipt, fn, target=...)`` — it orchestrates verify -> reserve ->
    run -> commit after any invocation attempt so a caller cannot get the
    ordering wrong. Use the lower-level ``check``/``commit``/``release`` only
    when the caller can prove whether execution began.
    """

    def __init__(
        self,
        action: "str | Callable[[Any], str]",
        trusted_keys: Iterable[str] = (),
        allow_inline_key: bool = False,
        max_age_sec: int = DEFAULT_MAX_AGE_SEC,
        allowed_outcomes: Iterable[str] = DEFAULT_ALLOWED_OUTCOMES,
        store: Any = None,
        assurance_class: str = "software",
        verify_assurance: Optional[Callable[[Any, str], Any]] = None,
        max_future_skew_sec: int = 60,
    ):
        if not action:
            raise ValueError("ReceiptGate: `action` is required")
        self._action = action
        self._trusted = list(trusted_keys)
        self._allow_inline = allow_inline_key
        if max_age_sec is not None and (
            isinstance(max_age_sec, bool) or not isinstance(max_age_sec, (int, float)) or max_age_sec <= 0
        ):
            raise ValueError("ReceiptGate: max_age_sec must be positive or None")
        if isinstance(max_future_skew_sec, bool) or not isinstance(max_future_skew_sec, (int, float)) or max_future_skew_sec < 0:
            raise ValueError("ReceiptGate: max_future_skew_sec must be non-negative")
        if assurance_class not in ("software", "class_a", "quorum"):
            raise ValueError("ReceiptGate: assurance_class must be software, class_a, or quorum")
        self._max_age = max_age_sec
        self._max_future_skew = max_future_skew_sec
        self._outcomes = tuple(allowed_outcomes) if allowed_outcomes else None
        self._store = store if store is not None else _InMemoryStore()
        for method in ("reserve", "commit", "release"):
            if not callable(getattr(self._store, method, None)):
                raise ValueError(
                    f"ReceiptGate: store must implement atomic {method}(); legacy {{has, add}} stores are not fleet-safe"
                )
        self._assurance_class = assurance_class
        self._verify_assurance = verify_assurance

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

        receipt_id = payload.get("receipt_id")
        if not isinstance(receipt_id, str) or not receipt_id:
            return (False, "receipt_id_required", None)

        if self._max_age is not None:
            created = _parse_iso_epoch(payload.get("created_at"))
            if created is None:
                return (False, "receipt_timestamp_invalid", None)
            age = _now() - created
            if age < -self._max_future_skew:
                return (False, "receipt_from_future", None)
            if age > self._max_age:
                return (False, "receipt_expired", None)

        if claim.get("action_type") != bound_action:
            return (False, "action_mismatch", None)

        if self._outcomes and claim.get("outcome") not in self._outcomes:
            return (False, "outcome_not_accepted", None)

        if self._assurance_class != "software":
            if not callable(self._verify_assurance):
                return (False, "assurance_verifier_required", None)
            try:
                result = self._verify_assurance(receipt, self._assurance_class)
            except Exception:
                return (False, "assurance_verification_failed", None)
            if isinstance(result, str):
                have, assurance_ok = result, True
            elif isinstance(result, dict):
                have = result.get("tier") or result.get("have") or result.get("assurance_class")
                assurance_ok = result.get("ok") is True
            else:
                have, assurance_ok = None, False
            rank = {"software": 0, "class_a": 1, "quorum": 2}
            if not assurance_ok or have not in rank or rank[have] < rank[self._assurance_class]:
                return (False, "assurance_too_low", None)

        return (True, None, receipt_id)

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
        try:
            reserved = self._store.reserve(receipt_id)
        except Exception:
            return {"ok": False, "reason": "consumption_store_unavailable", "action": bound}
        if reserved is not True:
            return {"ok": False, "reason": "replay_refused", "action": bound}
        return {"ok": True, "receipt_id": receipt_id, "action": bound}

    def commit(self, receipt_id: str) -> None:
        """Finalize one-time consumption after an execution attempt begins."""
        try:
            committed = self._store.commit(receipt_id)
        except Exception as error:
            raise RuntimeError("consumption commit failed closed") from error
        if committed is not True:
            raise RuntimeError("consumption commit failed closed")

    def release(self, receipt_id: str) -> None:
        """Release only when the caller can prove execution never began."""
        try:
            released = self._store.release(receipt_id)
        except Exception as error:
            raise RuntimeError("consumption release failed closed") from error
        if released is not True:
            raise RuntimeError("consumption release failed closed")

    def run(self, receipt: Any, fn: Callable[[], Any], target: Any = None) -> Any:
        """Verify, reserve, invoke ``fn``, then commit after any attempt.

        An exception cannot prove the external effect did not happen before its
        response was lost, so the receipt is burned rather than retried. Raises
        ReceiptRequired on a refused or missing receipt.
        """
        c = self.check(receipt, target)
        if not c["ok"]:
            raise ReceiptRequired(c["reason"], c["action"])
        try:
            result = fn()
        except BaseException as effect_error:
            try:
                self.commit(c["receipt_id"])
            except Exception as commit_error:
                if hasattr(effect_error, "add_note"):
                    effect_error.add_note(f"EMILIA consumption remains closed: {commit_error}")
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
    assurance_class: str = "software",
    verify_assurance: Optional[Callable[[Any, str], Any]] = None,
    max_future_skew_sec: int = 60,
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
        assurance_class=assurance_class,
        verify_assurance=verify_assurance,
        max_future_skew_sec=max_future_skew_sec,
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
    assurance_class: str = "software",
    verify_assurance: Optional[Callable[[Any, str], Any]] = None,
    max_future_skew_sec: int = 60,
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
        assurance_class=assurance_class,
        verify_assurance=verify_assurance,
        max_future_skew_sec=max_future_skew_sec,
    )
    tool._run = deco(original)  # instance attribute shadows the class method
    return tool
