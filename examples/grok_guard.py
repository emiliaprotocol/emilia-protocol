# SPDX-License-Identifier: Apache-2.0
"""
grok_guard — gate a Grok (xAI) agent's irreversible actions with EMILIA Class A.

This matches the endpoints EMILIA actually ships. There is NO single /approve
call that hands the agent a passkey challenge: WebAuthn (Touch ID / security
key) happens on the *human's* device, in a *browser*, out of band. The agent's
job is to request the signoff and wait for the named human.

The real flow:

  1. mint     POST /api/v1/trust-receipts      (Bearer EP_API_KEY)
                -> { receipt_id, signoff_required, decision, action_hash }
  2. request  POST /api/v1/signoffs/request     (Bearer EP_API_KEY)
                -> { signoff_id }    ; approval URL = {base}/signoff/{id}?approver=...
  3. HUMAN    opens the approval URL, reviews the exact action, Touch ID
  4. poll     GET  /api/v1/trust-receipts/{id}  (Bearer EP_API_KEY)
                -> receipt_status: approved_pending_consume | rejected | expired
                   signoff_key_class: "A" (device key) | "C" (legacy bearer)
  5. The agent executes the irreversible action ONLY on approval.

Offline verification of the resulting receipt is a separate, account-free
step: `npm i @emilia-protocol/verify` (Node) or `pip install emilia-verify`.

Stdlib only — no pip install. Swap the _http helper for `requests`/`httpx` if
you prefer; the shapes are identical.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

# Silent by default (library convention); your app configures handlers/level.
# Treasury/ops want the trail: "minted tr_… -> signoff requested -> approved".
logger = logging.getLogger("emilia.grok_guard")


class EmiliaAPIError(Exception):
    """A transport-level failure reaching the EMILIA API (DNS/TLS/connection).

    HTTP *status codes* are deliberately returned as data, not raised: a policy
    `deny` or a 4xx is a normal outcome the caller turns into a structured tool
    result, not an exception. Only when there is no response at all do we raise.
    """


# ── Minimal HTTP (stdlib). Replace with requests/httpx in your backend. ──────
def _http(method: str, url: str, api_key: str, body: Optional[dict] = None, timeout: int = 15) -> tuple[int, dict]:
    # urllib honors file:// and other schemes — pin to http(s) so a misconfigured
    # base_url can never turn into an arbitrary-file read (CWE-939).
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"refusing non-http(s) URL: {url!r}")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {api_key}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    # The scheme is pinned to http(s) above; `url` is operator config
    # (EMILIA_BASE_URL) + server-issued ids, never end-user input.
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosemgrep  # noqa: S310
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        # A 4xx/5xx is a normal outcome the callers interpret (e.g. a policy
        # deny). Return it as data, never raise — the agent gets a structured
        # "blocked", not a crash.
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {"error": "http_error"}
    except urllib.error.URLError as e:
        # No response at all (network/DNS/TLS) — surface a typed error instead
        # of a bare urllib exception so backends can catch one thing.
        raise EmiliaAPIError(f"cannot reach EMILIA at {url}: {e.reason}") from e


@dataclass
class GuardResult:
    allowed: bool                 # True only when no human signoff is needed
    decision: str                 # allow | allow_with_signoff | deny
    receipt_id: Optional[str] = None
    signoff_id: Optional[str] = None
    approval_url: Optional[str] = None   # send this to the human
    reason: Optional[str] = None
    raw: dict = field(default_factory=dict)


class EmiliaGuard:
    """Drop-in guard for a Grok/xAI (or any) agent backend."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        # Use the www host: the apex 307-redirects and fetch/urllib would drop
        # the Authorization header on the cross-origin hop.
        self.base_url = (base_url or os.environ.get("EMILIA_BASE_URL", "https://www.emiliaprotocol.ai")).rstrip("/")
        self.api_key = api_key or os.environ.get("EP_API_KEY", "")
        if not self.api_key:
            raise ValueError("EmiliaGuard: set EP_API_KEY (env) or pass api_key=...")

    # 1+2: mint a pre-action receipt and, if the policy demands it, open a signoff.
    def guard(
        self,
        action_type: str,                 # e.g. "large_payment_release", "vendor_bank_account_change"
        target_resource_id: str,          # the thing being acted on, e.g. "wire/8841"
        organization_id: str,
        amount: Optional[float] = None,
        currency: str = "USD",
        risk_flags: Optional[list[str]] = None,
        target_changed_fields: Optional[list[str]] = None,
        approver_id: Optional[str] = None,   # strongly recommended — named accountability is the whole point
    ) -> GuardResult:
        status, mint = _http("POST", f"{self.base_url}/api/v1/trust-receipts", self.api_key, {
            "organization_id": organization_id,
            "action_type": action_type,
            "target_resource_id": target_resource_id,
            "amount": amount,
            "currency": currency,
            "risk_flags": risk_flags or [],
            "target_changed_fields": target_changed_fields or [],
        })
        if status != 201:
            return GuardResult(False, "deny", reason=f"mint failed ({status}): {mint.get('detail') or mint.get('error')}", raw=mint)

        decision = mint.get("decision", "deny")
        logger.info("emilia: minted %s decision=%s signoff_required=%s",
                    mint.get("receipt_id"), decision, bool(mint.get("signoff_required")))
        if not mint.get("signoff_required"):
            # allow or deny outright — no human needed.
            return GuardResult(decision == "allow", decision, receipt_id=mint.get("receipt_id"),
                               reason=("denied by policy" if decision == "deny" else None), raw=mint)

        # Signoff required: open the request and build the human-facing URL.
        status, sreq = _http("POST", f"{self.base_url}/api/v1/signoffs/request", self.api_key,
                             {"receipt_id": mint["receipt_id"]})
        if status != 201:
            return GuardResult(False, decision, receipt_id=mint.get("receipt_id"),
                               reason=f"signoff request failed ({status}): {sreq.get('detail')}", raw=sreq)

        url = f"{self.base_url}/signoff/{sreq['signoff_id']}"
        if approver_id:
            url += "?approver=" + urllib.parse.quote(approver_id, safe="")
        logger.info("emilia: signoff %s opened for %s", sreq.get("signoff_id"), mint["receipt_id"])
        return GuardResult(False, decision, receipt_id=mint["receipt_id"],
                           signoff_id=sreq["signoff_id"], approval_url=url,
                           reason="human signoff required", raw={"mint": mint, "request": sreq})

    # 4: poll until a named human decides (or the window closes).
    def wait_for_signoff(self, receipt_id: str, timeout_s: int = 600, interval_s: int = 3) -> dict:
        deadline = time.time() + timeout_s
        terminal = {"approved_pending_consume", "consumed", "rejected", "denied", "expired"}
        while time.time() < deadline:
            status, rec = _http("GET", f"{self.base_url}/api/v1/trust-receipts/{receipt_id}", self.api_key)
            st = rec.get("receipt_status")
            if status == 200 and st in terminal:
                approved = st in ("approved_pending_consume", "consumed")
                logger.info("emilia: signoff for %s resolved status=%s approved=%s key_class=%s",
                            receipt_id, st, approved, rec.get("signoff_key_class"))
                return {"approved": approved, "status": st, "key_class": rec.get("signoff_key_class"), "raw": rec}
            time.sleep(interval_s)
        logger.info("emilia: signoff for %s timed out after %ss", receipt_id, timeout_s)
        return {"approved": False, "status": "timeout", "key_class": None, "raw": {}}


# ── xAI / OpenAI-compatible tool schema. Register this with Grok. ────────────
# Grok calls this tool *instead of* executing the irreversible action directly;
# your dispatcher (below) runs EmiliaGuard and only returns "proceed" on a
# real human approval.
EMILIA_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "emilia_require_human_signoff",
        "description": (
            "REQUIRED before any irreversible high-stakes action (releasing a "
            "large payment, changing a payee bank account, deleting records). "
            "Returns 'proceed' only after a named human cryptographically "
            "approves on their own device; otherwise 'blocked'. Never execute "
            "the action unless this returns proceed=true."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action_type": {"type": "string", "enum": [
                    "large_payment_release", "vendor_bank_account_change",
                    "benefit_bank_account_change", "ai_agent_payment_action",
                ]},
                "organization_id": {"type": "string"},
                "target_resource_id": {"type": "string", "description": "what is being acted on, e.g. wire/8841"},
                "amount": {"type": "number"},
                "currency": {"type": "string", "default": "USD"},
                "risk_flags": {"type": "array", "items": {"type": "string"}},
                "approver_id": {"type": "string", "description": "the named human to route the signoff to"},
            },
            "required": ["action_type", "organization_id", "target_resource_id"],
        },
    },
}


def dispatch_emilia_tool(args: dict, guard: Optional[EmiliaGuard] = None, notify=None) -> dict:
    """Run the guard for a Grok tool call. `notify(approval_url)` is how you
    reach the human (Slack/SMS/email); defaults to printing the URL."""
    guard = guard or EmiliaGuard()
    res = guard.guard(
        action_type=args["action_type"],
        target_resource_id=args["target_resource_id"],
        organization_id=args["organization_id"],
        amount=args.get("amount"),
        currency=args.get("currency", "USD"),
        risk_flags=args.get("risk_flags"),
        approver_id=args.get("approver_id"),
    )
    if res.allowed:
        return {"proceed": True, "reason": "allowed by policy (no signoff needed)", "receipt_id": res.receipt_id}
    if res.decision == "deny":
        return {"proceed": False, "reason": res.reason, "receipt_id": res.receipt_id}

    (notify or (lambda u: print(f"[emilia] approve this action: {u}")))(res.approval_url)
    outcome = guard.wait_for_signoff(res.receipt_id)
    return {
        "proceed": bool(outcome["approved"]),
        "reason": f"signoff {outcome['status']}" + (f" (key class {outcome['key_class']})" if outcome["key_class"] else ""),
        "receipt_id": res.receipt_id,
        "signoff_id": res.signoff_id,
    }


# ── Wiring into a real Grok (xAI) agent loop ────────────────────────────────
# xAI is OpenAI-compatible, so this is the standard tool-calling loop. The only
# EMILIA-specific part is: when Grok calls the tool, run dispatch_emilia_tool
# and feed the {"proceed": bool} result back — Grok proceeds with the
# irreversible action ONLY when proceed is true.
#
#   from openai import OpenAI
#   client = OpenAI(api_key=os.environ["XAI_API_KEY"], base_url="https://api.x.ai/v1")
#   guard = EmiliaGuard()
#
#   messages = [{"role": "user", "content": "Pay the $82k Acme invoice to the new account."}]
#   resp = client.chat.completions.create(
#       model="grok-4", messages=messages,
#       tools=[EMILIA_TOOL_SCHEMA, release_payment_schema],
#       tool_choice="auto",
#   )
#   for call in (resp.choices[0].message.tool_calls or []):
#       if call.function.name == "emilia_require_human_signoff":
#           args = json.loads(call.function.arguments)
#           result = dispatch_emilia_tool(args, guard=guard, notify=send_to_slack)
#           messages.append({"role": "tool", "tool_call_id": call.id,
#                            "content": json.dumps(result)})
#           # result["proceed"] is True only after a named human signed on their
#           # device. release_payment(...) must check it before executing.
#
# The guarantee holds end-to-end only if release_payment refuses to run unless
# it sees proceed=true (ideally: re-verify the receipt at the executor — that
# is the EP-Verified Execution conformance class).


if __name__ == "__main__":
    # Smoke demo against a running EMILIA. Needs EP_API_KEY (+ optional
    # EMILIA_BASE_URL). Mints an $82k release, opens a signoff, prints the
    # approval URL, and polls — approve it in the browser to see proceed=true.
    g = EmiliaGuard()
    print(f"EMILIA: {g.base_url}")
    result = dispatch_emilia_tool({
        "action_type": "large_payment_release",
        "organization_id": "org-demo",
        "target_resource_id": "wire/demo-001",
        "amount": 82000,
        "risk_flags": ["new_destination", "after_hours"],
        "approver_id": "ep:approver:demo-controller",
    }, guard=g)
    print(json.dumps(result, indent=2))
