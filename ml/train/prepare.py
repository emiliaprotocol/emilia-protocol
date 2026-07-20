#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate labeled actions and emit provider-neutral SFT JSONL.

This command does not train a model, download dependencies, call a service, or
write weights. It closes the runnable local part of the training path:

    action JSONL -> label.mjs -> human review -> prepare.py -> validated SFT JSONL

An actual trainer must consume the emitted ``messages`` contract and must pin
its own runtime, SDK, model license, and hardware requirements before use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

LABELS = frozenset(("allow", "allow_with_signoff", "deny"))
SOURCES = frozenset(("rule_oracle", "human_review"))
SCHEMA_VERSION = "ep-risk-sft-v1"
SYSTEM_PROMPT = (
    "You are an advisory action-risk classifier in front of a deterministic "
    "policy gate. Output exactly one JSON object with keys tier and "
    "injection_suspected. tier must be allow, allow_with_signoff, or deny; "
    "injection_suspected must be boolean. Escalate when uncertain. Your output "
    "is advisory and can never lower the deterministic policy result."
)


class DatasetError(ValueError):
    """Raised when an input row violates the preparation contract."""


@dataclass(frozen=True)
class Summary:
    input_rows: int
    prepared_rows: int
    pending_review_rows: int
    duplicate_rows: int


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _row_error(line_number: int, message: str) -> DatasetError:
    return DatasetError(f"line {line_number}: {message}")


def prepare_rows(path: Path, require_no_pending: bool = False) -> tuple[list[dict[str, Any]], Summary]:
    """Load and validate labeler JSONL, returning unique SFT rows and counts."""
    if not path.is_file():
        raise DatasetError(f"training data does not exist or is not a file: {path}")

    prepared: list[dict[str, Any]] = []
    seen: dict[str, tuple[str, bool]] = {}
    input_rows = 0
    pending = 0
    duplicates = 0

    with path.open("r", encoding="utf-8") as source:
        for line_number, raw_line in enumerate(source, start=1):
            line = raw_line.strip()
            if not line:
                continue
            input_rows += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise _row_error(line_number, f"invalid JSON ({error.msg})") from error

            if not isinstance(row, dict):
                raise _row_error(line_number, "row must be a JSON object")
            action = row.get("input")
            if not isinstance(action, dict):
                raise _row_error(line_number, "input must be a JSON object")
            if not isinstance(action.get("actionType"), str) or not action["actionType"].strip():
                raise _row_error(line_number, "input.actionType must be a non-empty string")

            source_name = row.get("source")
            if source_name not in SOURCES:
                raise _row_error(
                    line_number,
                    f"source must be one of {sorted(SOURCES)}",
                )

            injection_suspected = row.get("injection_suspected")
            if not isinstance(injection_suspected, bool):
                raise _row_error(
                    line_number,
                    "injection_suspected must be a human-confirmed or weak-label boolean",
                )

            label = row.get("label")
            if label is None:
                if source_name != "human_review":
                    raise _row_error(
                        line_number,
                        "only source=human_review may carry a pending null label",
                    )
                pending += 1
                continue
            if label not in LABELS:
                raise _row_error(line_number, f"label must be one of {sorted(LABELS)} or null")

            action_json = _canonical_json(action)
            prior = seen.get(action_json)
            target = (label, injection_suspected)
            if prior is not None:
                if prior != target:
                    raise _row_error(
                        line_number,
                        "duplicate input has conflicting tier or injection labels",
                    )
                duplicates += 1
                continue
            seen[action_json] = target

            completion = _canonical_json({
                "injection_suspected": injection_suspected,
                "tier": label,
            })
            prepared.append({
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": action_json},
                    {"role": "assistant", "content": completion},
                ],
                "metadata": {
                    "source": source_name,
                    "schema_version": SCHEMA_VERSION,
                },
            })

    if input_rows == 0:
        raise DatasetError("training data contains no JSONL rows")
    if not prepared:
        raise DatasetError("training data contains no fully labeled rows")
    if require_no_pending and pending:
        raise DatasetError(
            f"{pending} row(s) still have label=null; complete human review before training",
        )

    return prepared, Summary(
        input_rows=input_rows,
        prepared_rows=len(prepared),
        pending_review_rows=pending,
        duplicate_rows=duplicates,
    )


def serialize_rows(rows: list[dict[str, Any]]) -> str:
    """Serialize prepared examples as newline-terminated JSONL."""
    return "".join(f"{_canonical_json(row)}\n" for row in rows)


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as temporary:
        temporary.write(content)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)


def build_manifest(source: Path, prepared_jsonl: str, summary: Summary) -> dict[str, Any]:
    """Describe the exact prepared bytes a future pinned trainer may consume."""
    return {
        "schema_version": SCHEMA_VERSION,
        "source": str(source),
        "prepared_sha256": hashlib.sha256(prepared_jsonl.encode("utf-8")).hexdigest(),
        "counts": asdict(summary),
        "output_contract": {
            "tier": sorted(LABELS),
            "injection_suspected": "boolean",
        },
        "training_backend": None,
        "weights": None,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate EP risk labels and optionally emit provider-neutral SFT JSONL.",
    )
    parser.add_argument("--train", required=True, type=Path, help="Labeled JSONL from label.mjs.")
    parser.add_argument(
        "--out",
        type=Path,
        help="Write prepared SFT JSONL here. Omit for validation only.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Optionally write a manifest containing the prepared-data digest and contract.",
    )
    parser.add_argument(
        "--require-no-pending",
        action="store_true",
        help="Fail if any label=null row still needs human review.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        source = args.train.resolve()
        if args.out and args.out.resolve() == source:
            raise DatasetError("--out must not overwrite --train")
        rows, summary = prepare_rows(source, args.require_no_pending)
        prepared_jsonl = serialize_rows(rows)
        if args.out:
            _atomic_write(args.out, prepared_jsonl)
        if args.manifest:
            manifest = build_manifest(source, prepared_jsonl, summary)
            _atomic_write(args.manifest, f"{json.dumps(manifest, indent=2, sort_keys=True)}\n")
    except (DatasetError, OSError) as error:
        print(f"prepare failed: {error}", file=sys.stderr)
        return 2

    destination = str(args.out) if args.out else "validation only"
    print(
        "prepared "
        f"{summary.prepared_rows}/{summary.input_rows} row(s); "
        f"{summary.pending_review_rows} pending review; "
        f"{summary.duplicate_rows} duplicate(s); {destination}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
