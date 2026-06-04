# SPDX-License-Identifier: Apache-2.0
"""emilia_guard — gate an irreversible action through the EMILIA trust gate.

The Python counterpart to @emilia-protocol/langchain's guardAction(): hand the
action + context to the gate, interpret the decision. Stdlib only.

HTTP is dependency-injected (no bundled client, no SSRF surface) — pass a
`fetch` callable that POSTs the JSON body to your gate and returns the response
dict. Live wiring is a one-liner with requests or httpx:

    import requests
    def post(body):
        return requests.post(
            "https://www.emiliaprotocol.ai/api/trust/gate",
            data=body, headers={"content-type": "application/json"},
        ).json()

    d = guard_action("payment.release", context={"amount": 50000}, fetch=post)
    if d["deny"]: raise RuntimeError(d["reason"])
    if d["signoff_required"]: wait_for_human(d)   # block until a named human approves
    # ... else proceed

For tests/demos, pass the local `demo_policy` (below) as `fetch` to run offline.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Optional

GATE_URL = "https://www.emiliaprotocol.ai/api/trust/gate"


def guard_action(
    action: str,
    fetch: Callable[[bytes], dict],
    actor: Optional[str] = None,
    context: Optional[dict] = None,
) -> dict:
    if not action:
        raise ValueError("guard_action: `action` is required")
    if not callable(fetch):
        raise ValueError("guard_action: pass `fetch=<callable(body_bytes)->dict>` (see module docstring)")

    body = json.dumps({"actor": actor, "action": action, "context": context or {}}).encode("utf-8")
    raw: dict = fetch(body)

    decision = str(raw.get("decision") or raw.get("verdict") or "")
    deny = decision == "deny" or raw.get("allowed") is False
    signoff = raw.get("signoff_required") is True or decision in ("allow_with_signoff", "signoff_required")
    return {
        "allow": not deny and not signoff,
        "deny": deny,
        "signoff_required": signoff,
        "reason": raw.get("reason"),
        "raw": raw,
    }


def guard(action: str, context_fn: Callable[[dict], dict], fetch: Callable[[bytes], dict], on_signoff=None, actor=None):
    """Decorator: gate a plain tool function (works for CrewAI tools and AutoGen
    registered functions alike — both are just Python callables)."""
    def deco(fn: Callable[..., Any]):
        def wrapped(**kwargs):
            d = guard_action(action, fetch, actor=actor or fn.__name__, context=context_fn(kwargs))
            if d["deny"]:
                raise RuntimeError(f'EMILIA blocked "{action}"' + (f': {d["reason"]}' if d["reason"] else ""))
            if d["signoff_required"]:
                if on_signoff:
                    on_signoff(d, kwargs)
                else:
                    raise RuntimeError(f'EMILIA requires human signoff for "{action}" before it can run')
            return fn(**kwargs)
        wrapped.__name__ = getattr(fn, "__name__", "guarded")
        wrapped.__doc__ = fn.__doc__
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
