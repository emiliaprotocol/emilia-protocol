# SPDX-License-Identifier: Apache-2.0
"""Small, synchronous policy-response example. Stdlib only; no receipt crypto.

`fetch` is a caller-pinned policy function returning a closed decision record.
Only an explicit `allow` runs immediately. Malformed responses and failures
refuse. A signoff decision stays blocked unless a constructor-pinned
`verify_signoff(evidence, action, arguments)` independently returns True.
`on_signoff` only acquires evidence; its return value never grants authority.

For production receipt enforcement use `emilia_crewai.require_receipt` or
`ReceiptGate` with pinned issuer keys, an atomic durable store, and an
independent Class-A verifier when human-held-key evidence is required. This
example itself supplies neither cryptographic verification nor replay storage.
`demo_policy` is an offline policy stub, not proof of human approval.
"""
from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Callable
from typing import Any

GATE_URL = "https://www.emiliaprotocol.ai/api/trust/gate"
_DECISIONS = {"allow", "deny", "allow_with_signoff", "signoff_required"}
_RESPONSE_FIELDS = {"decision", "verdict", "allowed", "signoff_required", "reason"}


def _snapshot(value):
    """Detach JSON material without coercing keys or executable Python objects."""
    def validate(item):
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("non-string material key")
            for child in item.values():
                validate(child)
        elif type(item) is list:
            for child in item:
                validate(child)
        elif item is not None and type(item) not in (str, int, float, bool):
            raise ValueError("non-JSON action material")
    validate(value)
    return json.loads(json.dumps(value, allow_nan=False))


def _refusal(reason):
    return {"allow": False, "deny": True, "signoff_required": False, "reason": reason, "raw": None}


def guard_action(
    action: str,
    fetch: Callable[[bytes], dict],
    actor: str | None = None,
    context: dict | None = None,
) -> dict:
    if not action:
        raise ValueError("guard_action: `action` is required")
    if not callable(fetch):
        raise TypeError("guard_action: pass `fetch=<callable(body_bytes)->dict>` (see module docstring)")

    try:
        material = _snapshot({"actor": actor, "action": action, "context": context if context is not None else {}})
        if type(material["context"]) is not dict:
            return _refusal("policy_context_invalid")
        body = json.dumps(material, allow_nan=False).encode("utf-8")
        raw = _snapshot(fetch(body))
    except Exception:  # noqa: BLE001 - injected policy failures must always refuse
        return _refusal("policy_unavailable_or_invalid")

    if type(raw) is not dict or set(raw) - _RESPONSE_FIELDS:
        return _refusal("policy_response_invalid")
    decisions = [raw[key] for key in ("decision", "verdict") if key in raw]
    if (not decisions or any(type(value) is not str or value not in _DECISIONS for value in decisions)
            or any(value != decisions[0] for value in decisions)):
        return _refusal("policy_response_invalid")
    decision = decisions[0]
    signoff = decision in ("allow_with_signoff", "signoff_required")
    allow = decision == "allow"
    if (any(key in raw and type(raw[key]) is not bool for key in ("allowed", "signoff_required"))
            or ("allowed" in raw and raw["allowed"] is not allow)
            or ("signoff_required" in raw and raw["signoff_required"] is not signoff)
            or (raw.get("reason") is not None and type(raw["reason"]) is not str)):
        return _refusal("policy_response_invalid")
    return {
        "allow": allow,
        "deny": decision == "deny",
        "signoff_required": signoff,
        "reason": raw.get("reason"),
        "raw": raw,
    }


def guard(action: str, context_fn: Callable[[dict], dict], fetch: Callable[[bytes], dict],
          on_signoff=None, actor=None, *, verify_signoff=None):
    """Guard a synchronous JSON-argument tool using caller-pinned policy callbacks.

    `verify_signoff` is a trust input, not model or acquisition output. It MUST
    verify the exact action and complete arguments against pinned human receipt
    evidence, including validity and single-use enforcement. Only literal True
    authorizes; this helper cannot implement those checks on the caller's behalf.
    """
    def deco(fn: Callable[..., Any]):
        signature = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapped(**kwargs):
            try:
                bound = signature.bind(**kwargs)
                bound.apply_defaults()
                arguments = {}
                for name, value in bound.arguments.items():
                    kind = signature.parameters[name].kind
                    if kind is inspect.Parameter.VAR_KEYWORD:
                        arguments.update(value)
                    elif kind is not inspect.Parameter.VAR_POSITIONAL:
                        arguments[name] = value
                arguments = _snapshot(arguments)
                context = _snapshot(context_fn(_snapshot(arguments)))
            except Exception as error:
                raise RuntimeError(f'EMILIA blocked "{action}": action_context_invalid') from error
            d = guard_action(action, fetch, actor=actor or fn.__name__, context=context)
            if d["deny"]:
                raise RuntimeError(f'EMILIA blocked "{action}"' + (f': {d["reason"]}' if d["reason"] else ""))
            if d["signoff_required"]:
                if not callable(on_signoff) or not callable(verify_signoff):
                    raise RuntimeError(f'EMILIA requires verified human signoff for "{action}" before it can run')
                try:
                    evidence = _snapshot(on_signoff(_snapshot(d), _snapshot(arguments)))
                    verified = verify_signoff(evidence, action, _snapshot(arguments))
                except Exception as error:
                    raise RuntimeError(f'EMILIA blocked "{action}": signoff_verification_failed') from error
                if verified is not True:
                    raise RuntimeError(f'EMILIA blocked "{action}": signoff_not_verified')
            elif not d["allow"]:
                raise RuntimeError(f'EMILIA blocked "{action}": no_explicit_allow')
            return fn(**arguments)
        return wrapped
    return deco


def demo_policy(body: bytes) -> dict:
    """A local stand-in for the gate so the examples run offline. Delete in production."""
    ctx = json.loads(body).get("context", {})
    if "sanctioned" in str(ctx.get("destination", "")):
        return {"decision": "deny", "reason": "destination on blocklist"}
    if (ctx.get("amount") or 0) >= 50000:
        return {"decision": "allow_with_signoff", "reason": "large payment release"}
    return {"decision": "allow"}
