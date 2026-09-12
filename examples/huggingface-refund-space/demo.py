"""Synthetic refunds through a real smolagents Tool; no model or provider account."""

import argparse
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import ClassVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from emilia_smolagents import (
    ReceiptRequired,
    ToolExecutionIndeterminate,
    guard_smolagents_tool,
)
from emilia_verify import canonicalize
from smolagents import Tool

SCENARIOS = {
    "approved": "The approved refund",
    "missing": "No approval",
    "amount_changed": "A larger refund",
    "recipient_changed": "A different recipient",
    "replay": "The same approval used twice",
    "response_lost": "The provider responds too late",
}
APPROVED = {"account": "customer_alice_demo", "amount_cents": 4200, "currency": "USD"}


class RefundTool(Tool):
    name = "issue_refund"
    description = "Record a synthetic refund. No money moves."
    inputs: ClassVar[dict] = {
        "account": {"type": "string", "description": "Synthetic customer account."},
        "amount_cents": {"type": "integer", "description": "Refund in whole cents."},
        "currency": {
            "type": "string",
            "description": "Currency code.",
            "nullable": True,
        },
    }
    output_type = "string"

    def __init__(self, *, lose_response=False):
        super().__init__()
        self.refunds = []
        self.lose_response = lose_response

    def forward(self, account: str, amount_cents: int, currency: str = "USD") -> str:
        if account not in {"customer_alice_demo", "customer_bob_demo"}:
            raise ValueError("Use a synthetic customer.")
        if (
            type(amount_cents) is not int
            or not 1 <= amount_cents <= 100_000
            or currency != "USD"
        ):
            raise ValueError("Use a positive USD amount in whole cents.")
        result = {
            "account": account,
            "amount_cents": amount_cents,
            "currency": currency,
        }
        self.refunds.append(result)
        if self.lose_response:
            raise TimeoutError("Synthetic response lost after recording the refund.")
        return json.dumps(result, sort_keys=True)


def _b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _demo_receipt(key, public_key, action):
    """A software-issued test receipt, not a verified human approval ceremony."""
    now = datetime.now(timezone.utc)
    payload = {
        "receipt_id": "hf_demo_" + uuid.uuid4().hex,
        "subject": "demo_operator",
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "claim": {"action_type": action, "outcome": "allow"},
    }
    return {
        "@version": "EP-RECEIPT-v1",
        "payload": payload,
        "signature": {
            "algorithm": "Ed25519",
            "value": _b64(key.sign(canonicalize(payload).encode())),
        },
        "public_key": public_key,
    }


def run_scenario(scenario):
    """Each run owns its temporary issuer, receipt store, and synthetic provider."""
    if scenario not in SCENARIOS:
        raise ValueError("Unknown demonstration scenario.")
    key = Ed25519PrivateKey.generate()
    public_key = _b64(
        key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )
    provider = RefundTool(lose_response=scenario == "response_lost")
    receipt = None
    guarded = guard_smolagents_tool(
        provider,
        action="refund.issue",
        trusted_keys=[public_key],
        get_receipt=lambda _arguments: receipt,
    )
    action = guarded.bound_action_for(**APPROVED)
    if scenario != "missing":
        receipt = _demo_receipt(key, public_key, action)
    requested = dict(APPROVED)
    if scenario == "amount_changed":
        requested["amount_cents"] = 8400
    elif scenario == "recipient_changed":
        requested["account"] = "customer_bob_demo"

    events = []
    for attempt in range(2 if scenario in {"replay", "response_lost"} else 1):
        try:
            guarded(**requested, sanitize_inputs_outputs=True)
            events.append(
                {
                    "attempt": attempt + 1,
                    "status": "completed",
                    "reason": "provider_returned",
                }
            )
        except ReceiptRequired as error:
            events.append(
                {"attempt": attempt + 1, "status": "refused", "reason": error.reason}
            )
        except ToolExecutionIndeterminate as error:
            events.append(
                {"attempt": attempt + 1, "status": "unknown", "reason": error.reason}
            )

    return {
        "scenario": scenario,
        "approved_request": dict(APPROVED) if receipt else None,
        "requested_call": requested,
        "bound_action": action,
        "events": events,
        "synthetic_refunds": list(provider.refunds),
        "provider_entries": len(provider.refunds),
        "scope": "Synthetic in-process demo. No money, real human ceremony, or durable store.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["all", *SCENARIOS], default="all")
    args = parser.parse_args()
    results = (
        [run_scenario(name) for name in SCENARIOS]
        if args.scenario == "all"
        else [run_scenario(args.scenario)]
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
