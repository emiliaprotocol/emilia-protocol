# SPDX-License-Identifier: Apache-2.0
"""EMILIA x AutoGen — gate a function the assistant is allowed to call.

Runs offline with a local policy stub:  python examples/autogen_guard.py

For real AutoGen, wrap the callable, then register it as usual — AutoGen calls
the guarded function normally; EMILIA runs first:

    import requests
    def post(body):
        return requests.post("https://www.emiliaprotocol.ai/api/trust/gate",
                             data=body, headers={"content-type": "application/json"}).json()

    guarded = guard("payment.release",
                    context_fn=lambda kw: {"amount": kw["amount"], "destination": kw["destination"]},
                    fetch=post, on_signoff=wait_for_human)(wire_transfer)
    user_proxy.register_function(function_map={"wire_transfer": guarded})
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from emilia_guard import guard, demo_policy  # noqa: E402


def approve(decision, _kwargs):
    print(f"   signoff required ({decision['reason']}) — simulating approver…")


def wire_transfer(amount, destination):
    """AutoGen-registered function: release a wire transfer."""
    return f"wired ${amount:,} to {destination}"


guarded_wire_transfer = guard(
    "payment.release",
    context_fn=lambda kw: {"amount": kw["amount"], "destination": kw["destination"]},
    fetch=demo_policy,
    on_signoff=approve,
)(wire_transfer)


def run(label, **kw):
    print(f"\n{label}\n  assistant -> wire_transfer({kw})")
    try:
        print("  " + guarded_wire_transfer(**kw))
    except RuntimeError as e:
        print(f"  BLOCKED: {e}")


if __name__ == "__main__":
    print("EMILIA x AutoGen — guard a registered function")
    run("1) small payment -> allowed", amount=200, destination="acct_known")
    run("2) large payment -> human signoff -> released", amount=50000, destination="acct_new")
    run("3) blocked destination -> denied", amount=1000, destination="acct_sanctioned")
    print("\nRegister `guarded_wire_transfer` instead of the raw function.\n")
