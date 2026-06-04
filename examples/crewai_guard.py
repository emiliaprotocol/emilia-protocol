# SPDX-License-Identifier: Apache-2.0
"""EMILIA x CrewAI — gate a CrewAI tool before an irreversible action.

Runs offline with a local policy stub:  python examples/crewai_guard.py

For real CrewAI, the guard composes with the @tool decorator and a live `fetch`:

    import requests
    from crewai.tools import tool
    def post(body):
        return requests.post("https://www.emiliaprotocol.ai/api/trust/gate",
                             data=body, headers={"content-type": "application/json"}).json()

    @tool("wire_transfer")
    @guard("payment.release",
           context_fn=lambda kw: {"amount": kw["amount"], "destination": kw["destination"]},
           fetch=post, on_signoff=wait_for_human)
    def wire_transfer(amount, destination): ...
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from emilia_guard import guard, demo_policy  # noqa: E402


def approve(decision, _kwargs):
    print(f"   signoff required ({decision['reason']}) — simulating CFO approval…")


@guard(
    "payment.release",
    context_fn=lambda kw: {"amount": kw["amount"], "destination": kw["destination"]},
    fetch=demo_policy,
    on_signoff=approve,
)
def wire_transfer(amount, destination):
    """CrewAI tool: release a wire transfer."""
    return f"wired ${amount:,} to {destination}"


def run(label, **kw):
    print(f"\n{label}\n  agent -> wire_transfer({kw})")
    try:
        print("  " + wire_transfer(**kw))
    except RuntimeError as e:
        print(f"  BLOCKED: {e}")


if __name__ == "__main__":
    print("EMILIA x CrewAI — one decorator guards a tool")
    run("1) small payment -> allowed", amount=200, destination="acct_known")
    run("2) large payment -> human signoff -> released", amount=50000, destination="acct_new")
    run("3) blocked destination -> denied", amount=1000, destination="acct_sanctioned")
    print("\nSwap demo_policy for a live `fetch`. Same guard, every irreversible tool.\n")
