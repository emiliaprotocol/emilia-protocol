from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

LANE = Path(__file__).resolve().parents[1]
BOOTSTRAP = LANE / "bootstrap-stable.sh"
VERIFIER = LANE / "verify-stable-release.py"
FIXTURE_CONFIG = LANE / "tests" / "fixture.env"
PLACEHOLDER_IMAGE = (
    "us-central1-docker.pkg.dev/test-project/runtime/bootstrap@sha256:"
    + "9" * 64
)
ACTUATOR_SERVICE = "emilia-consequence-actuator"
DECISION_SERVICE = "emilia-consequence-control"
ACTUATOR_REVISION = f"{ACTUATOR_SERVICE}-bootstrap1"
DECISION_REVISION = f"{DECISION_SERVICE}-bootstrap1"


class StableBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="emilia-stable-bootstrap-")
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.config = self.root / "config.env"
        self.config.write_text(FIXTURE_CONFIG.read_text(encoding="utf-8"))
        self.private_key = self.root / "stable-private.pem"
        self.public_key = self.root / "stable-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(self.private_key),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.private_key.chmod(0o600)
        self.output = self.root / "stable.json"
        self.state_path = self.root / "state.json"
        self.log_path = self.root / "gcloud.log"
        self.state_path.write_text(
            json.dumps({"deployed": []}),
            encoding="utf-8",
        )
        self.write_fake_gcloud()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write_fake_gcloud(self) -> None:
        executable = self.bin / "gcloud"
        executable.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
state_path = pathlib.Path(os.environ["FAKE_STATE"])
state = json.loads(state_path.read_text())
with pathlib.Path(os.environ["FAKE_LOG"]).open("a") as handle:
    handle.write(json.dumps(args) + "\\n")
if args[:2] == ["services", "enable"]:
    raise SystemExit(0)
if args[:3] == ["run", "services", "list"]:
    print("\\n".join(state["deployed"]))
    raise SystemExit(0)
if args[:2] == ["run", "deploy"]:
    service = args[2]
    if service in state["deployed"]:
        print("service already exists", file=sys.stderr)
        raise SystemExit(8)
    state["deployed"].append(service)
    state_path.write_text(json.dumps(state))
    raise SystemExit(0)
if args[:3] == ["run", "revisions", "describe"]:
    revision = args[3]
    service = revision.rsplit("-", 1)[0]
    if service not in state["deployed"]:
        raise SystemExit(4)
    account = (
        "emilia-actuator@test-project.iam.gserviceaccount.com"
        if service.endswith("actuator")
        else "emilia-decision@test-project.iam.gserviceaccount.com"
    )
    print(json.dumps({
        "metadata": {
            "name": revision,
            "labels": {"serving.knative.dev/service": service},
            "annotations": {
                "run.googleapis.com/network-interfaces": json.dumps([{
                    "network": "runtime",
                    "subnetwork": "runtime-us-central1",
                }], separators=(",", ":")),
                "run.googleapis.com/vpc-access-egress": "all-traffic",
            },
        },
        "spec": {
            "serviceAccountName": account,
            "containers": [{"image": os.environ["PLACEHOLDER_IMAGE"], "env": []}],
        },
    }))
    raise SystemExit(0)
if args[:3] == ["run", "services", "describe"]:
    service = args[3]
    if service not in state["deployed"]:
        raise SystemExit(4)
    ingress = "internal" if service.endswith("actuator") else "all"
    print(json.dumps({
        "metadata": {
            "name": service,
            "annotations": {"run.googleapis.com/ingress": ingress},
        },
    }))
    raise SystemExit(0)
print("unexpected gcloud arguments: " + repr(args), file=sys.stderr)
raise SystemExit(2)
""",
            encoding="utf-8",
        )
        executable.chmod(0o755)

    def environment(self, **extra: str) -> dict[str, str]:
        return {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "FAKE_STATE": str(self.state_path),
            "FAKE_LOG": str(self.log_path),
            "PLACEHOLDER_IMAGE": PLACEHOLDER_IMAGE,
            **extra,
        }

    def arguments(self) -> list[str]:
        return [
            "--config",
            str(self.config),
            "--bootstrap-id",
            "bootstrap1",
            "--placeholder-image",
            PLACEHOLDER_IMAGE,
            "--private-key",
            str(self.private_key),
            "--public-key",
            str(self.public_key),
            "--key-id",
            "stable-test-key",
            "--output",
            str(self.output),
        ]

    def test_render_creates_two_health_only_deny_all_stable_revisions(self) -> None:
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--render"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("gcloud run deploy"), 2)
        self.assertNotIn("--no-traffic", result.stdout)
        self.assertNotIn("--set-secrets", result.stdout)
        self.assertEqual(result.stdout.count("--no-allow-unauthenticated"), 2)
        self.assertEqual(result.stdout.count("emilia-deny-all=true"), 2)
        self.assertIn("httpGet.path=/v1/ready", result.stdout)
        self.assertIn("verify-stable-release.py record", result.stdout)

    def test_fresh_project_bootstraps_without_prior_stable_and_signs_manifest(self) -> None:
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(DEPLOYMENT_APPROVED="true"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.is_file())
        value = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(
            value["services"]["actuator"]["revision"],
            ACTUATOR_REVISION,
        )
        self.assertEqual(
            value["services"]["decision"]["revision"],
            DECISION_REVISION,
        )
        self.assertEqual(value["services"]["actuator"]["secret_bindings"], [])
        self.assertEqual(value["services"]["decision"]["secret_bindings"], [])

        verify = subprocess.run(
            [
                str(VERIFIER),
                "verify",
                "--config",
                str(self.config),
                "--manifest",
                str(self.output),
                "--public-key",
                str(self.public_key),
                "--live",
            ],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(),
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        deploys = [call for call in calls if call[:2] == ["run", "deploy"]]
        self.assertEqual(
            [call[2] for call in deploys],
            [ACTUATOR_SERVICE, DECISION_SERVICE],
        )
        self.assertTrue(all("--no-traffic" not in call for call in deploys))

    def test_bootstrap_refuses_candidate_revision_reuse(self) -> None:
        arguments = self.arguments()
        arguments[arguments.index("bootstrap1")] = "r20260725b"
        result = subprocess.run(
            [str(BOOTSTRAP), *arguments, "--render"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must differ", result.stderr)

    def test_existing_service_is_refused_before_any_deployment(self) -> None:
        self.state_path.write_text(
            json.dumps({"deployed": [ACTUATOR_SERVICE]}),
            encoding="utf-8",
        )
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(DEPLOYMENT_APPROVED="true"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires both Cloud Run services to be absent", result.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(any(call[:2] == ["run", "deploy"] for call in calls))


if __name__ == "__main__":
    unittest.main()
