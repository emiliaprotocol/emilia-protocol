#!/usr/bin/env python3
"""Generate the checked-in CCS L0 fixture with the installed native package."""

from __future__ import annotations

import importlib.metadata
import json

import ccs_verifier
from ccs_verifier.protocol import Command, RuleResult, Verdict, sign_receipt


SECRET = b"ccs-aeb-public-test-secret-32-bytes!!"
TRACE_ID = "0011223344556677"
VERIFIED_AT = 1786388399


def main() -> None:
    distribution_version = importlib.metadata.version("ccs-verifier")
    runtime_version = getattr(ccs_verifier, "__version__", None)
    if distribution_version != "1.1.0" or runtime_version != "0.4.1":
        raise SystemExit(
            "source lock mismatch: expected distribution 1.1.0 and runtime 0.4.1, "
            f"got {distribution_version!r} and {runtime_version!r}"
        )

    command = Command(
        agent_id="agent-overnight-1",
        tool="release_payment",
        params={"amount_minor": 12550, "currency": "USD", "payee": "merchant-7"},
        timestamp=1786388398,
        trace_id=TRACE_ID,
    )
    rules = (
        RuleResult("ssrf_protection", Verdict.ALLOW, "", 7, -32000),
        RuleResult("rce_protection", Verdict.ALLOW, "", 8, -32000),
    )
    summary = "|".join(f"{rule.rule_name}={rule.verdict.value}" for rule in rules)
    receipt = sign_receipt(
        trace_id=TRACE_ID,
        verdict=Verdict.ALLOW,
        timestamp=VERIFIED_AT,
        secret=SECRET,
        tool=command.tool,
        params_hash=command.params_hash(),
        rule_summary=summary,
    )
    artifact = {
        "@version": "CCS-PYPI-0.4.1-RESULT-v1",
        "command": {
            "agent_id": command.agent_id,
            "tool": command.tool,
            "params": command.params,
            "timestamp": command.timestamp,
            "trace_id": command.trace_id,
        },
        "result": {
            "trace_id": TRACE_ID,
            "verdict": Verdict.ALLOW.value,
            "block_reason": "",
            "rule_results": [
                {
                    "rule_name": rule.rule_name,
                    "verdict": rule.verdict.value,
                    "reason": rule.reason,
                    "latency_us": rule.latency_us,
                    "error_code": rule.error_code,
                }
                for rule in rules
            ],
            "receipt": receipt,
            "verified_at": VERIFIED_AT,
            "tool": command.tool,
            "params_hash": command.params_hash(),
            "error_code": -32000,
        },
    }
    print(json.dumps(artifact, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
