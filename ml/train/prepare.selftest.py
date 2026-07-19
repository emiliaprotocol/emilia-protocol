#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("ep_ml_prepare", HERE / "prepare.py")
assert SPEC and SPEC.loader
PREPARE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PREPARE
SPEC.loader.exec_module(PREPARE)


def row(action_type: str, label: str | None, injection: bool, source: str) -> dict:
    return {
        "input": {"actionType": action_type, "targetChangedFields": [], "riskFlags": []},
        "label": label,
        "injection_suspected": injection,
        "source": source,
    }


class PrepareTests(unittest.TestCase):
    def write_rows(self, directory: Path, rows: list[dict]) -> Path:
        path = directory / "train.jsonl"
        path.write_text(
            "".join(f"{json.dumps(item)}\n" for item in rows),
            encoding="utf-8",
        )
        return path

    def test_prepares_complete_rows_and_counts_pending_review(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = self.write_rows(Path(name), [
                row("update_profile", "allow", False, "rule_oracle"),
                row("send_email", None, True, "human_review"),
            ])
            prepared, summary = PREPARE.prepare_rows(path)

        self.assertEqual(summary.prepared_rows, 1)
        self.assertEqual(summary.pending_review_rows, 1)
        completion = json.loads(prepared[0]["messages"][2]["content"])
        self.assertEqual(completion, {
            "injection_suspected": False,
            "tier": "allow",
        })

    def test_strict_mode_rejects_pending_human_review(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = self.write_rows(Path(name), [
                row("update_profile", "allow", False, "rule_oracle"),
                row("send_email", None, True, "human_review"),
            ])
            with self.assertRaisesRegex(PREPARE.DatasetError, "complete human review"):
                PREPARE.prepare_rows(path, require_no_pending=True)

    def test_rejects_missing_injection_label(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            malformed = row("update_profile", "allow", False, "rule_oracle")
            del malformed["injection_suspected"]
            path = self.write_rows(Path(name), [malformed])
            with self.assertRaisesRegex(PREPARE.DatasetError, "injection_suspected"):
                PREPARE.prepare_rows(path)

    def test_rejects_conflicting_duplicate_labels(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = self.write_rows(Path(name), [
                row("update_profile", "allow", False, "rule_oracle"),
                row("update_profile", "deny", False, "human_review"),
            ])
            with self.assertRaisesRegex(PREPARE.DatasetError, "conflicting"):
                PREPARE.prepare_rows(path)

    def test_cli_validates_sample_and_emits_no_weights(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            labeled = Path(name) / "labeled.jsonl"
            output = Path(name) / "prepared.jsonl"
            manifest = Path(name) / "manifest.json"
            label_result = subprocess.run(
                [
                    "node",
                    str(HERE / "label.mjs"),
                    str(HERE / "sample-actions.jsonl"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(label_result.returncode, 0, label_result.stderr)
            labeled.write_text(label_result.stdout, encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "prepare.py"),
                    "--train",
                    str(labeled),
                    "--out",
                    str(output),
                    "--manifest",
                    str(manifest),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            contract = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertIsNone(contract["training_backend"])
            self.assertIsNone(contract["weights"])
            self.assertEqual(contract["counts"]["prepared_rows"], 5)
            self.assertEqual(contract["counts"]["pending_review_rows"], 3)


if __name__ == "__main__":
    unittest.main()
