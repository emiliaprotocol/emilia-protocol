# SPDX-License-Identifier: Apache-2.0
"""claude_guard — EMILIA human-signoff gate for a Claude (Anthropic API) agent.

The Anthropic-native counterpart to grok_guard.py: register one extra tool with
Claude, and when the model decides an action is irreversible it calls
`emilia_require_human_signoff` *instead of* the destructive tool. The dispatcher
mints a pre-action Trust Receipt against EMILIA's policy engine, routes a
signoff to a named human's device (Face ID / passkey), and returns
`proceed=true` only on a real signature — with a receipt that verifies offline.

The guard core (EmiliaGuard, dispatch_emilia_tool) is backend-agnostic and
lives in grok_guard.py; this file adds the Anthropic tool schema and the
Messages-API tool-use loop.

Run a live demo (mints real receipts; needs both keys):

    pip install anthropic
    export ANTHROPIC_API_KEY=sk-ant-...
    export EP_API_KEY=ep_live_...
    python examples/claude_guard.py

Claude Code users: prefer the plugin (integrations/claude-code-plugin) — it
gates tool calls without any agent-loop code.
"""
from __future__ import annotations

import json
import os

from grok_guard import EmiliaGuard, dispatch_emilia_tool

# ── Anthropic tool schema (input_schema, not OpenAI's nested function) ───────
EMILIA_TOOL_ANTHROPIC = {
    "name": "emilia_require_human_signoff",
    "description": (
        "REQUIRED before any irreversible high-stakes action (releasing a large "
        "payment, changing a payee bank account, deleting records). Returns "
        "proceed=true only after a named human cryptographically approves on "
        "their own device; otherwise blocked. Never execute the action unless "
        "this returns proceed=true."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action_type": {"type": "string", "enum": [
                "large_payment_release", "vendor_bank_account_change",
                "benefit_bank_account_change", "ai_agent_payment_action",
            ]},
            "organization_id": {"type": "string"},
            "target_resource_id": {"type": "string", "description": "what is being acted on, e.g. wire/8841"},
            "amount": {"type": "number"},
            "currency": {"type": "string"},
            "risk_flags": {"type": "array", "items": {"type": "string"}},
            "approver_id": {"type": "string", "description": "the named human to route the signoff to"},
        },
        "required": ["action_type", "organization_id", "target_resource_id"],
    },
}

# The irreversible tool itself — in production this wires real money, which is
# exactly why its description tells the model to gate it through EMILIA first.
RELEASE_PAYMENT_TOOL = {
    "name": "release_payment",
    "description": (
        "Releases a vendor payment (irreversible). You MUST call "
        "emilia_require_human_signoff first and may only call this if it "
        "returned proceed=true."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "wire_id": {"type": "string"},
            "amount": {"type": "number"},
        },
        "required": ["wire_id", "amount"],
    },
}


def run_agent(prompt: str, model: str = "claude-fable-5", max_turns: int = 6) -> str:
    """Standard Messages-API tool-use loop with the EMILIA gate wired in."""
    import anthropic  # pip install anthropic

    client = anthropic.Anthropic()
    guard = EmiliaGuard()  # EP_API_KEY from env
    messages = [{"role": "user", "content": prompt}]

    for _ in range(max_turns):
        resp = client.messages.create(
            model=model,
            max_tokens=1024,
            tools=[EMILIA_TOOL_ANTHROPIC, RELEASE_PAYMENT_TOOL],
            messages=messages,
        )
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text")

        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            if block.name == "emilia_require_human_signoff":
                # Blocks here while a named human approves on their device.
                out = dispatch_emilia_tool(block.input, guard=guard)
            elif block.name == "release_payment":
                # Demo stub — your real payout call goes here.
                out = {"released": True, "wire_id": block.input["wire_id"]}
            else:
                out = {"error": f"unknown tool {block.name}"}
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(out),
            })
        messages.append({"role": "user", "content": results})
    return "max turns reached"


if __name__ == "__main__":
    if not (os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("EP_API_KEY")):
        raise SystemExit(
            "Set ANTHROPIC_API_KEY and EP_API_KEY, then re-run.\n"
            "The agent will be asked to wire $82,000 — EMILIA holds it for a "
            "named human's device signoff before release_payment can run."
        )
    print(run_agent(
        "Release wire/8841 for $82,000 to Vendor 8841 for org org-claude-demo. "
        "Follow the required approval process."
    ))
