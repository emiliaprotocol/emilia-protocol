# SPDX-License-Identifier: Apache-2.0
"""EMILIA x OpenAI Agents SDK — gate a function tool the agent can call.

Runs offline with a local policy stub:  python examples/openai_agents_guard.py

For the real OpenAI Agents SDK (`pip install openai-agents`), the guard composes
with @function_tool — EMILIA runs before the tool body, so a named human signs
off on the irreversible action before the agent's call goes through:

    import requests
    from agents import Agent, function_tool
    def post(body):
        return requests.post("https://www.emiliaprotocol.ai/api/trust/gate",
                             data=body, headers={"content-type": "application/json"}).json()

    @function_tool
    @guard("payment.release",
           context_fn=lambda kw: {"amount": kw["amount"], "destination": kw["destination"]},
           fetch=post, on_signoff=wait_for_human)
    def wire_transfer(amount: int, destination: str) -> str: ...

    agent = Agent(name="Treasury", tools=[wire_transfer])
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from emilia_guard import guard, demo_policy  # noqa: E402


def approve(decision, _kwargs):
    print(f"   signoff required ({decision['reason']}) — simulating approver…")


@guard(
    "payment.release",
    context_fn=lambda kw: {"amount": kw["amount"], "destination": kw["destination"]},
    fetch=demo_policy,
    on_signoff=approve,
)
def wire_transfer(amount, destination):
    """OpenAI Agents SDK function tool: release a wire transfer."""
    return f"wired ${amount:,} to {destination}"


def run(label, **kw):
    print(f"\n{label}\n  agent -> wire_transfer({kw})")
    try:
        print("  " + wire_transfer(**kw))
    except RuntimeError as e:
        print(f"  BLOCKED: {e}")


if __name__ == "__main__":
    print("EMILIA x OpenAI Agents SDK — guard a @function_tool")
    run("1) small payment -> allowed", amount=200, destination="acct_known")
    run("2) large payment -> human signoff -> released", amount=50000, destination="acct_new")
    run("3) blocked destination -> denied", amount=1000, destination="acct_sanctioned")
    print("\nWrap the tool with guard(), then hand it to Agent(tools=[...]).\n")
