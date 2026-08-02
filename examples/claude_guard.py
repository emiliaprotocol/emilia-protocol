# SPDX-License-Identifier: Apache-2.0
"""Claude proposes; an executor-side EMILIA gate owns irreversible authority.

The model is deliberately given no payment, delete, or send tool. It can only
propose an exact action. The handler starts the approval flow and returns an
opaque approval URL. A separate executor later calls the neutral resume path,
which verifies the receipt offline, binds it to the pending action, enforces
freshness and single-use, and only then invokes the real side effect.

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

try:
    from examples.executor_approval_gate import EmiliaGuard, dispatch_emilia_tool
except ModuleNotFoundError:  # direct execution from examples/
    from executor_approval_gate import EmiliaGuard, dispatch_emilia_tool

# ── Anthropic tool schema (input_schema, not OpenAI's nested function) ───────
PROPOSE_IRREVERSIBLE_ACTION_TOOL = {
    "name": "propose_irreversible_action",
    "description": (
        "Propose an irreversible high-stakes action for executor-side review. "
        "This tool cannot execute the action. It starts a named-human approval "
        "flow and returns an opaque approval URL; the executor independently "
        "verifies and consumes any resulting exact-action receipt."
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

REGISTERED_AGENT_TOOLS = [PROPOSE_IRREVERSIBLE_ACTION_TOOL]


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
            tools=REGISTERED_AGENT_TOOLS,
            messages=messages,
        )
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text")

        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            if block.name == "propose_irreversible_action":
                # Non-blocking: mint the receipt and return the approval URL.
                # No irreversible callback is reachable from this agent loop.
                out = dispatch_emilia_tool(block.input, guard=guard, wait=False)
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
            "The agent will propose an $82,000 wire. This process cannot move "
            "money; a separate executor must verify and consume the receipt."
        )
    print(run_agent(
        "Release wire/8841 for $82,000 to Vendor 8841 for org org-claude-demo. "
        "Follow the required approval process."
    ))
