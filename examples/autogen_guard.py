# SPDX-License-Identifier: Apache-2.0
"""EMILIA x AutoGen — gate a function the assistant is allowed to call.

Runs offline with a local policy stub:  python examples/autogen_guard.py

For receipt-backed AutoGen tools, wrap the callable with the receipt-enforcing
package, then register it as usual:

    from emilia_crewai import require_receipt

    guarded = require_receipt("payment.release", trusted_keys=TRUSTED_ISSUER_KEYS,
                              store=CONSUMPTION_STORE, assurance_class="class_a",
                              verify_assurance=verify_human_receipt)(wire_transfer)
    user_proxy.register_function(function_map={"wire_transfer": guarded})

The pins, durable store, and independent human-evidence verifier are deployment
configuration. See examples/README.md. This offline demo has no human verifier,
so its large payment remains blocked. It never moves money.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from emilia_guard import demo_policy, guard


def wire_transfer(amount, destination):
    """AutoGen function shape: simulate a payment without moving funds."""
    return f"simulated ${amount:,} payment to {destination}"


guarded_wire_transfer = guard(
    "payment.release",
    context_fn=lambda kw: {"amount": kw["amount"], "destination": kw["destination"]},
    fetch=demo_policy,
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
    run("2) large payment -> blocked pending verified human evidence", amount=50000, destination="acct_new")
    run("3) blocked destination -> denied", amount=1000, destination="acct_sanctioned")
    print("\nOffline policy demo. Register the receipt-enforced function for protected tools.\n")
