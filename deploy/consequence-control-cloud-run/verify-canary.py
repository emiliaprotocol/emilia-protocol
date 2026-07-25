#!/usr/bin/env python3
"""Validate closed canary evidence for exact split-service revisions."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DIGEST_IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.@-]{3,256}$")


def load_config(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise ValueError(f"invalid config line {number}")
        key, value = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"invalid config key on line {number}")
        result[key] = value
    return result


def exact_keys(value: object, expected: set[str], name: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{name} must contain exactly {sorted(expected)}")
    return value


def require_equal(value: object, expected: object, name: str) -> None:
    if value != expected:
        raise ValueError(f"{name} must equal {expected!r}")


def validate(config: dict[str, str], evidence: object) -> None:
    root = exact_keys(
        evidence,
        {
            "evidence_status",
            "actuator_revision",
            "decision_revision",
            "actuator_image",
            "decision_image",
            "checks",
        },
        "evidence",
    )
    require_equal(root["evidence_status"], "observed", "evidence_status")
    expected_actuator_revision = (
        f"{config['ACTUATOR_SERVICE']}-{config['RELEASE_ID']}"
    )
    expected_decision_revision = (
        f"{config['DECISION_SERVICE']}-{config['RELEASE_ID']}"
    )
    require_equal(
        root["actuator_revision"],
        expected_actuator_revision,
        "actuator_revision",
    )
    require_equal(
        root["decision_revision"],
        expected_decision_revision,
        "decision_revision",
    )
    for key in ("ACTUATOR_IMAGE", "DECISION_IMAGE"):
        if not DIGEST_IMAGE.fullmatch(config[key]):
            raise ValueError(f"{key} is not digest pinned")
    require_equal(root["actuator_image"], config["ACTUATOR_IMAGE"], "actuator_image")
    require_equal(root["decision_image"], config["DECISION_IMAGE"], "decision_image")

    checks = exact_keys(
        root["checks"],
        {"exact_execution", "timeout", "replay", "reconciliation"},
        "checks",
    )
    execution = exact_keys(
        checks["exact_execution"],
        {
            "http_status",
            "outcome",
            "action_digest",
            "attempt_id",
            "provider_reference",
        },
        "checks.exact_execution",
    )
    require_equal(execution["http_status"], 200, "exact_execution.http_status")
    require_equal(execution["outcome"], "COMMITTED", "exact_execution.outcome")
    if not isinstance(execution["action_digest"], str) or not DIGEST.fullmatch(
        execution["action_digest"]
    ):
        raise ValueError("exact_execution.action_digest must be sha256")
    if not isinstance(execution["attempt_id"], str) or not IDENTIFIER.fullmatch(
        execution["attempt_id"]
    ):
        raise ValueError("exact_execution.attempt_id is invalid")
    if not isinstance(execution["provider_reference"], str) or not execution[
        "provider_reference"
    ].startswith("github:issue:"):
        raise ValueError("exact_execution.provider_reference is invalid")

    timeout = exact_keys(
        checks["timeout"],
        {"http_status", "outcome", "effect_boundary_entered"},
        "checks.timeout",
    )
    require_equal(timeout["http_status"], 202, "timeout.http_status")
    require_equal(timeout["outcome"], "INDETERMINATE", "timeout.outcome")
    require_equal(
        timeout["effect_boundary_entered"],
        True,
        "timeout.effect_boundary_entered",
    )

    replay = exact_keys(
        checks["replay"],
        {"http_status", "reason", "provider_invocations"},
        "checks.replay",
    )
    require_equal(replay["http_status"], 409, "replay.http_status")
    require_equal(replay["reason"], "envelope_replayed", "replay.reason")
    require_equal(replay["provider_invocations"], 1, "replay.provider_invocations")

    reconciliation = exact_keys(
        checks["reconciliation"],
        {"http_status", "valid", "outcome", "reason", "reexecuted"},
        "checks.reconciliation",
    )
    require_equal(
        reconciliation["http_status"], 200, "reconciliation.http_status"
    )
    require_equal(reconciliation["valid"], True, "reconciliation.valid")
    require_equal(
        reconciliation["outcome"], "ESCALATED", "reconciliation.outcome"
    )
    require_equal(
        reconciliation["reason"],
        "github_attempt_attribution_unavailable",
        "reconciliation.reason",
    )
    require_equal(
        reconciliation["reexecuted"], False, "reconciliation.reexecuted"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
        validate(config, evidence)
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"canary evidence refused: {error}", file=sys.stderr)
        return 1
    print("canary evidence accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
