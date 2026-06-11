# SPDX-License-Identifier: Apache-2.0
"""EMILIA Guard for the Claude Agent SDK (Python) — a PreToolUse hook.

Gives any claude-agent-sdk application the same gate as the Claude Code plugin:
money/external MCP tool calls are HELD until a named human approves on their
own device (Face ID / passkey), and proceed only with an offline-verifiable
Trust Receipt. Destructive local commands fall back to permissionDecision
"ask". FAIL-CLOSED: any error, timeout, or denial → ask/deny, never allow.

Usage:

    pip install claude-agent-sdk
    export EP_API_KEY=ep_live_...   EP_ORG_ID=your-org

    from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, HookMatcher
    from guard_hook import emilia_pretooluse

    options = ClaudeAgentOptions(
        hooks={"PreToolUse": [HookMatcher(matcher=None, hooks=[emilia_pretooluse])]},
    )
    async with ClaudeSDKClient(options=options) as client:
        await client.query("…")

Hook contract per https://code.claude.com/docs/en/agent-sdk/hooks
"""
from __future__ import annotations

import asyncio
import http.client
import json
import os
import re
import time

def _safe_base_url() -> str:
    """EP_BASE_URL must be https (or http://localhost for dev) — never file://
    or any other scheme, even if the environment is tampered with."""
    url = os.environ.get("EP_BASE_URL", "https://www.emiliaprotocol.ai").rstrip("/")
    if url.startswith("https://") or url.startswith("http://localhost") or url.startswith("http://127.0.0.1"):
        return url
    return "https://www.emiliaprotocol.ai"


BASE_URL = _safe_base_url()
API_KEY = os.environ.get("EP_API_KEY", "")
ORG_ID = os.environ.get("EP_ORG_ID", "")
TIMEOUT_S = min(int(os.environ.get("EP_SIGNOFF_TIMEOUT_S", "280")), 590)

_DESTRUCTIVE = re.compile(
    r"\brm\s+-[a-z]*[rf][a-z]*[rf]?|\bgit\s+push\s+(-f\b|--force)|\bgit\s+reset\s+--hard"
    r"|\b(drop|truncate)\s+(table|database)\b|\bdelete\s+from\b|\bdd\s+if=|\bmkfs\b"
    r"|\bcurl\b[^|]*\|\s*(sudo\s+)?(ba)?sh|\bnpm\s+publish\b|\bterraform\s+(apply|destroy)"
    r"|\bkubectl\s+delete|\bsudo\b", re.I)
_MONEY_TOOL = re.compile(
    r"(pay|transfer|wire|withdraw|payout|charge|refund|send|email|message|post"
    r"|publish|deploy|delete|terminate|disable|revoke|grant|trade|order|invoice)", re.I)


def _decision(decision: str, reason: str) -> dict:
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}


_SAFE_ID = re.compile(r"^[A-Za-z0-9_:.-]{1,128}$")  # receipt/signoff ids only


def _ep(path: str, body: dict | None = None) -> dict:
    # http.client with an explicit HTTPS connection: structurally incapable of
    # file:// or other schemes, unlike urllib's scheme-dispatching openers.
    scheme, _, rest = BASE_URL.partition("://")
    hostport = rest.split("/", 1)[0]
    host, _, port = hostport.partition(":")
    conn = (http.client.HTTPConnection if scheme == "http" else http.client.HTTPSConnection)(
        host, int(port) if port else None, timeout=15)
    try:
        conn.request(
            "POST" if body is not None else "GET",
            path,
            body=json.dumps(body) if body is not None else None,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"},
        )
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"{}")
        if resp.status >= 400:
            raise RuntimeError(data.get("detail") or data.get("title") or f"HTTP {resp.status}")
        return data
    finally:
        conn.close()


def _guard_money_action(tool_name: str, tool_input: dict) -> dict:
    """Mint → signoff → poll. Runs in a thread (urllib is blocking)."""
    amount = next((float(v) for v in (tool_input.get("amount"), tool_input.get("value"))
                   if isinstance(v, (int, float)) and v > 0), None)
    mint = _ep("/api/v1/trust-receipts", {
        "organization_id": ORG_ID,
        "action_type": ("vendor_bank_account_change"
                        if re.search(r"bank|account|payee", tool_name, re.I)
                        else "ai_agent_payment_action"),
        "target_resource_id": tool_name[:200],
        "amount": amount, "currency": "USD",
        "risk_flags": ["external_or_money_action"],
    })
    if mint.get("decision") == "deny":
        return _decision("deny", f"EMILIA — BLOCKED by policy: {'; '.join(mint.get('reasons', []) or ['denied'])}")
    if not mint.get("signoff_required"):
        return _decision("allow", f"EMILIA — allowed by policy. receipt {mint['receipt_id']} (verifiable offline)")

    sig = _ep("/api/v1/signoffs/request", {"receipt_id": mint["receipt_id"], "comment": tool_name})
    url = f"{BASE_URL}/signoff/{sig['signoff_id']}"
    if not _SAFE_ID.match(str(mint["receipt_id"])):
        return _decision("ask", "EMILIA — malformed receipt id from server; failing closed.")
    deadline = time.time() + TIMEOUT_S
    while time.time() < deadline:
        time.sleep(3)
        rec = _ep(f"/api/v1/trust-receipts/{mint['receipt_id']}")
        st = rec.get("receipt_status") or rec.get("status", "pending")
        if st in ("approved_pending_consume", "approved", "consumed", "fulfilled"):
            return _decision("allow", f"EMILIA — APPROVED by a named human on their device. receipt {mint['receipt_id']}")
        if st in ("denied", "rejected", "revoked"):
            return _decision("deny", f"EMILIA — a named human REJECTED this action. receipt {mint['receipt_id']}")
    return _decision("ask", f"EMILIA — signoff timed out. Approve at {url}. Failing closed.")


async def emilia_pretooluse(input_data, tool_use_id, context) -> dict:
    """PreToolUse hook: hold irreversible tool calls for a human signoff."""
    if input_data.get("hook_event_name") != "PreToolUse":
        return {}
    tool, ti = input_data.get("tool_name", ""), input_data.get("tool_input", {}) or {}

    if tool == "Bash" and _DESTRUCTIVE.search(ti.get("command", "")):
        return _decision("ask", f"EMILIA — destructive command: confirm a human intends `{ti.get('command', '')[:120]}`")

    if tool.startswith("mcp__") and _MONEY_TOOL.search(tool):
        if not (API_KEY and ORG_ID):
            return _decision("ask", f"EMILIA — money/external action {tool}: confirm a human intends this. "
                                    "(Set EP_API_KEY + EP_ORG_ID for device signoff + receipts.)")
        try:
            return await asyncio.to_thread(_guard_money_action, tool, ti)
        except Exception as err:  # noqa: BLE001 — fail closed on anything
            return _decision("ask", f"EMILIA unreachable ({err}) — failing closed. Confirm a human intends {tool}.")

    return {}
