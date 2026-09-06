# SPDX-License-Identifier: Apache-2.0
"""EMILIA x OpenAI Agents SDK — gate a function tool the agent can call.

Runs offline with a local policy stub:  python examples/openai_agents_guard.py

For receipt-backed OpenAI Agents SDK tools, compose the receipt-enforcing
package with @function_tool:

    from agents import Agent, function_tool
    from emilia_crewai import require_receipt

    @function_tool
    @require_receipt("payment.release", trusted_keys=TRUSTED_ISSUER_KEYS,
                     store=CONSUMPTION_STORE, assurance_class="class_a",
                     verify_assurance=verify_human_receipt)
    def wire_transfer(amount: int, destination: str) -> str: ...

    agent = Agent(name="Treasury", tools=[wire_transfer])

The pins, durable store, and independent human-evidence verifier are deployment
configuration. See examples/README.md. This offline demo has no human verifier,
so its large payment remains blocked. It never moves money.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from emilia_guard import demo_policy, guard


@guard(
    "payment.release",
    context_fn=lambda kw: {"amount": kw["amount"], "destination": kw["destination"]},
    fetch=demo_policy,
)
def wire_transfer(amount, destination):
    """OpenAI function-tool shape: simulate a payment without moving funds."""
    return f"simulated ${amount:,} payment to {destination}"


def run(label, **kw):
    print(f"\n{label}\n  agent -> wire_transfer({kw})")
    try:
        print("  " + wire_transfer(**kw))
    except RuntimeError as e:
        print(f"  BLOCKED: {e}")


if __name__ == "__main__":
    print("EMILIA x OpenAI Agents SDK — guard a @function_tool")
    run("1) small payment -> allowed", amount=200, destination="acct_known")
    run("2) large payment -> blocked pending verified human evidence", amount=50000, destination="acct_new")
    run("3) blocked destination -> denied", amount=1000, destination="acct_sanctioned")
    print("\nOffline policy demo. Use the receipt-enforced tool in Agent(tools=[...]).\n")
