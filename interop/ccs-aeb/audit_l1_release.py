#!/usr/bin/env python3
"""Reproduce the security-relevant CCS 1.1.1 L1 release observations."""

from __future__ import annotations

from dataclasses import asdict
import importlib.metadata
import json

from ccs_verifier.ccs_verifier_l1 import (
    L1Receipt,
    L1ReceiptBuilder,
    canonical_json,
    generate_ed25519_key,
    get_public_key,
)
from ccs_verifier.protocol import Verdict


def main() -> None:
    key = generate_ed25519_key()
    public_key = get_public_key(key)
    receipt = (
        L1ReceiptBuilder("ccs-aeb-l1-audit", Verdict.ALLOW)
        .tool("release_payment")
        .args_digest({"amount_minor": 1000, "currency": "USD"})
        .build(key)
    )

    with_unknown = asdict(receipt)
    with_unknown["future_security_critical_field"] = "presenter-controlled"
    reparsed = L1Receipt.from_dict(with_unknown)

    result = {
        "distribution_version": importlib.metadata.version("ccs-verifier"),
        "signature_verifies": receipt.verify_signature(public_key),
        "signed_default_fields": {
            "action": receipt.action,
            "audience": receipt.audience,
            "issuer": receipt.issuer,
            "issuance_bound": receipt.issuance_bound,
            "expiry_bound": receipt.expiry_bound,
        },
        "args_digest_hex_length": len(receipt.args_digest),
        "unknown_field_dropped": not hasattr(
            reparsed, "future_security_critical_field"
        ),
        "signature_verifies_after_unknown_field_drop": reparsed.verify_signature(
            public_key
        ),
        "python_canonical_unicode_order": canonical_json(
            {"\U0001f600": 1, "\ufffd": 2}
        ).decode("utf-8"),
        "python_canonical_float": canonical_json({"n": 0.000001}).decode("utf-8"),
    }
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
