from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


LANE_DIR = Path(__file__).resolve().parents[1]
SCRIPT = LANE_DIR / "verify-secret-versions.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_secret_versions", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load secret verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SecretVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_accepts_enabled_numeric_versions(self) -> None:
        inventory = {
            "versions": [
                {"secret": "alpha", "version": "1", "state": "ENABLED"},
                {
                    "secret": "beta",
                    "version": "23",
                    "state": "ENABLED",
                    "destroyTime": None,
                },
            ]
        }

        result = self.module.verify_inventory(
            [self.module.SecretReference("alpha", "1"), self.module.SecretReference("beta", "23")],
            inventory,
        )

        self.assertEqual(result["verified"], 2)
        self.assertEqual(result["references"], ["alpha:1", "beta:23"])

    def test_rejects_latest_zero_and_injection_shaped_references(self) -> None:
        for value in (
            "alpha:latest",
            "alpha:0",
            "alpha:1;secretmanager.versions.access",
            "../alpha:1",
            "alpha:01",
        ):
            with self.subTest(value=value):
                with self.assertRaises(self.module.VerificationError):
                    self.module.parse_secret_reference(value)

    def test_rejects_missing_disabled_and_destroyed_versions(self) -> None:
        references = [
            self.module.SecretReference("missing", "1"),
            self.module.SecretReference("disabled", "2"),
            self.module.SecretReference("destroyed", "3"),
        ]
        inventory = {
            "versions": [
                {"secret": "disabled", "version": "2", "state": "DISABLED"},
                {
                    "secret": "destroyed",
                    "version": "3",
                    "state": "ENABLED",
                    "destroyTime": "2026-07-25T12:00:00Z",
                },
            ]
        }

        with self.assertRaises(self.module.VerificationError) as context:
            self.module.verify_inventory(references, inventory)

        message = str(context.exception)
        self.assertIn("missing:1 is missing", message)
        self.assertIn("disabled:2 state is DISABLED", message)
        self.assertIn("destroyed:3 has a destruction timestamp", message)

    def test_rejects_duplicate_inventory_records(self) -> None:
        inventory = {
            "versions": [
                {"secret": "alpha", "version": "1", "state": "ENABLED"},
                {"secret": "alpha", "version": "1", "state": "DESTROYED"},
            ]
        }

        with self.assertRaises(self.module.VerificationError) as context:
            self.module.verify_inventory(
                [self.module.SecretReference("alpha", "1")],
                inventory,
            )

        self.assertIn("duplicate inventory record", str(context.exception))

    def test_config_loader_does_not_execute_shell_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            config = Path(directory) / "config.env"
            config.write_text(
                "GOOD_SECRET=alpha:1\n"
                f"HOSTILE_SECRET=beta:2;touch {marker}\n"
                "NOT_A_REFERENCE=value\n",
                encoding="utf-8",
            )

            with self.assertRaises(self.module.VerificationError):
                self.module.load_config_references(config)

            self.assertFalse(marker.exists())

    def test_live_lookup_uses_metadata_describe_never_payload_access(self) -> None:
        calls: list[list[str]] = []

        def runner(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(
                    {
                        "name": "projects/p/secrets/alpha/versions/1",
                        "state": "ENABLED",
                    }
                ),
                stderr="",
            )

        result = self.module.fetch_live_version(
            "project-id",
            self.module.SecretReference("alpha", "1"),
            runner=runner,
        )

        self.assertEqual(result["state"], "ENABLED")
        flat = " ".join(calls[0])
        self.assertIn("versions describe 1", flat)
        self.assertNotIn("versions access", flat)
        self.assertNotIn("payload", json.dumps(result).lower())

    def test_cli_rejects_payload_shaped_inventory_without_echoing_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "versions": [
                            {
                                "secret": "alpha",
                                "version": "1",
                                "state": "ENABLED",
                                "payload": "must-never-be-emitted",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--project",
                    "project-id",
                    "--reference",
                    "alpha:1",
                    "--inventory",
                    str(inventory),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("must-never-be-emitted", result.stdout)
        self.assertNotIn("must-never-be-emitted", result.stderr)
        self.assertIn("unsupported fields", result.stderr)


if __name__ == "__main__":
    unittest.main()
