from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


LANE = Path(__file__).resolve().parents[1]
SCRIPT = LANE / "emit-effective-iam-manifest.py"
SPEC = importlib.util.spec_from_file_location("emit_effective_iam_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
emitter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(emitter)

DECISION = "serviceAccount:decision@test-project.iam.gserviceaccount.com"
ACTUATOR = "serviceAccount:actuator@test-project.iam.gserviceaccount.com"
COMPUTE_AGENT = (
    "serviceAccount:service-123456789@compute-system.iam.gserviceaccount.com"
)
RUN_AGENT = (
    "serviceAccount:"
    "service-123456789@serverless-robot-prod.iam.gserviceaccount.com"
)


class EffectiveIamManifestTests(unittest.TestCase):
    def test_manifest_is_closed_and_deterministic(self) -> None:
        value = emitter.manifest(
            project="test-project",
            project_number="123456789",
            region="us-central1",
            actuator_service="emilia-consequence-actuator",
            decision_principal=DECISION,
            secrets=[
                f"shared-token={DECISION},{ACTUATOR}",
                f"actuator-key={ACTUATOR}",
            ],
        )
        self.assertEqual(value["version"], "emilia-effective-iam/v1")
        self.assertEqual(value["projectId"], "test-project")
        self.assertEqual(value["projectNumber"], "123456789")
        self.assertEqual(
            [target["name"] for target in value["targets"]],
            ["actuator", "secret:actuator-key", "secret:shared-token"],
        )
        self.assertEqual(
            value["targets"][0]["allowedPrincipals"],
            sorted([DECISION, COMPUTE_AGENT, RUN_AGENT]),
        )
        self.assertEqual(
            value["targets"][2]["allowedPrincipals"],
            sorted([ACTUATOR, DECISION, COMPUTE_AGENT, RUN_AGENT]),
        )
        self.assertTrue(
            value["targets"][0]["resource"].endswith(
                "/services/emilia-consequence-actuator"
            )
        )

    def test_managed_principals_are_derived_from_the_pinned_project_number(self) -> None:
        self.assertEqual(
            emitter.managed_control_plane_principals("123456789"),
            (COMPUTE_AGENT, RUN_AGENT),
        )

    def test_explicit_organization_scope_is_applied_to_every_target(self) -> None:
        value = emitter.manifest(
            project="test-project",
            project_number="123456789",
            region="us-central1",
            actuator_service="emilia-consequence-actuator",
            decision_principal=DECISION,
            secrets=[f"actuator-key={ACTUATOR}"],
            analyzer_scope="organizations/987654321",
        )
        self.assertEqual(
            {target["scope"] for target in value["targets"]},
            {"organizations/987654321"},
        )

    def test_folder_or_mismatched_project_scope_is_refused(self) -> None:
        for scope in ("folders/123456789", "projects/other-project"):
            with self.subTest(scope=scope):
                with self.assertRaisesRegex(
                    emitter.ManifestError, "scope"
                ):
                    emitter.manifest(
                        project="test-project",
                        project_number="123456789",
                        region="us-central1",
                        actuator_service="emilia-consequence-actuator",
                        decision_principal=DECISION,
                        secrets=[f"actuator-key={ACTUATOR}"],
                        analyzer_scope=scope,
                    )

    def test_aggregate_or_user_principal_is_refused(self) -> None:
        for candidate in ("allUsers", "user:owner@example.com"):
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(emitter.ManifestError, "service account"):
                    emitter.manifest(
                        project="test-project",
                        project_number="123456789",
                        region="us-central1",
                        actuator_service="emilia-consequence-actuator",
                        decision_principal=DECISION,
                        secrets=[f"secret={candidate}"],
                    )

    def test_duplicate_secret_is_refused(self) -> None:
        with self.assertRaisesRegex(emitter.ManifestError, "duplicate"):
            emitter.manifest(
                project="test-project",
                project_number="123456789",
                region="us-central1",
                actuator_service="emilia-consequence-actuator",
                decision_principal=DECISION,
                secrets=[f"secret={ACTUATOR}", f"secret={ACTUATOR}"],
            )

    def test_cli_writes_private_atomic_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            result = subprocess.run(
                [
                    str(SCRIPT),
                    "--project=test-project",
                    "--project-number=123456789",
                    "--region=us-central1",
                    "--actuator-service=emilia-consequence-actuator",
                    f"--decision-principal={DECISION}",
                    "--analyzer-scope=organizations/987654321",
                    "--secret",
                    f"actuator-key={ACTUATOR}",
                    "--output",
                    str(output),
                ],
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["version"],
                "emilia-effective-iam/v1",
            )
            self.assertEqual(
                {
                    target["scope"]
                    for target in json.loads(
                        output.read_text(encoding="utf-8")
                    )["targets"]
                },
                {"organizations/987654321"},
            )


if __name__ == "__main__":
    unittest.main()
