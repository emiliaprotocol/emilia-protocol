#!/usr/bin/env python3
"""Rewrite or verify one IAM role binding without disturbing other roles."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_policy(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("IAM policy must be an object")
    bindings = value.get("bindings", [])
    if not isinstance(bindings, list):
        raise ValueError("IAM policy bindings must be an array")
    for binding in bindings:
        if not isinstance(binding, dict):
            raise ValueError("IAM policy binding must be an object")
        if not isinstance(binding.get("role"), str):
            raise ValueError("IAM policy binding role must be a string")
        members = binding.get("members", [])
        if not isinstance(members, list) or not all(
            isinstance(member, str) for member in members
        ):
            raise ValueError("IAM policy binding members must be strings")
    return value


def expected_members(values: list[str]) -> list[str]:
    if not values or any(not value or "\n" in value or "\r" in value for value in values):
        raise ValueError("at least one closed IAM member is required")
    if len(values) != len(set(values)):
        raise ValueError("duplicate expected IAM member")
    return sorted(values)


def rewrite(policy: dict, role: str, members: list[str]) -> dict:
    if not role.startswith("roles/"):
        raise ValueError("IAM role must be fully qualified")
    result = dict(policy)
    preserved = [
        binding
        for binding in policy.get("bindings", [])
        if binding.get("role") != role
    ]
    preserved.append({"role": role, "members": expected_members(members)})
    result["bindings"] = preserved
    return result


def verify(policy: dict, role: str, members: list[str]) -> None:
    matches = [
        binding
        for binding in policy.get("bindings", [])
        if binding.get("role") == role
    ]
    expected = expected_members(members)
    if len(matches) != 1:
        raise ValueError(f"{role} must have exactly one binding")
    if "condition" in matches[0]:
        raise ValueError(f"{role} binding must not be conditional")
    if sorted(matches[0].get("members", [])) != expected:
        raise ValueError(f"{role} members do not match the closed allowlist")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("rewrite", "check"))
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--role", required=True)
    parser.add_argument("--member", action="append", default=[])
    args = parser.parse_args()
    try:
        policy = load_policy(args.input)
        if args.mode == "rewrite":
            if args.output is None:
                raise ValueError("--output is required in rewrite mode")
            updated = rewrite(policy, args.role, args.member)
            args.output.write_text(
                json.dumps(updated, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
        else:
            verify(policy, args.role, args.member)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"IAM policy refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
