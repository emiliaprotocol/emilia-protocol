from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

LANE = Path(__file__).resolve().parents[1]
VERIFIER = LANE / "verify-stable-release.py"
TRAFFIC = LANE / "traffic.sh"
FIXTURE_CONFIG = LANE / "tests" / "fixture.env"
ACTUATOR_SERVICE = "emilia-consequence-actuator"
DECISION_SERVICE = "emilia-consequence-control"
ACTUATOR_REVISION = f"{ACTUATOR_SERVICE}-bootstrap1"
DECISION_REVISION = f"{DECISION_SERVICE}-bootstrap1"
ACTUATOR_IMAGE = (
    "us-central1-docker.pkg.dev/test-project/runtime/actuator@sha256:"
    + "1" * 64
)
DECISION_IMAGE = (
    "us-central1-docker.pkg.dev/test-project/runtime/decision@sha256:"
    + "2" * 64
)


def revision(
    service: str,
    revision_name: str,
    image: str,
    service_account: str,
) -> dict:
    return {
        "metadata": {
            "name": revision_name,
            "labels": {"serving.knative.dev/service": service},
            "annotations": {
                "run.googleapis.com/network-interfaces": json.dumps(
                    [{"network": "runtime", "subnetwork": "runtime-us-central1"}],
                    separators=(",", ":"),
                ),
                "run.googleapis.com/vpc-access-egress": "all-traffic",
            },
        },
        "spec": {
            "serviceAccountName": service_account,
            "containers": [{"image": image, "env": []}],
        },
    }


def initial_state() -> dict:
    return {
        "services": {
            ACTUATOR_SERVICE: {
                "metadata": {
                    "name": ACTUATOR_SERVICE,
                    "annotations": {"run.googleapis.com/ingress": "internal"},
                }
            },
            DECISION_SERVICE: {
                "metadata": {
                    "name": DECISION_SERVICE,
                    "annotations": {"run.googleapis.com/ingress": "all"},
                }
            },
        },
        "revisions": {
            ACTUATOR_REVISION: revision(
                ACTUATOR_SERVICE,
                ACTUATOR_REVISION,
                ACTUATOR_IMAGE,
                "emilia-actuator@test-project.iam.gserviceaccount.com",
            ),
            DECISION_REVISION: revision(
                DECISION_SERVICE,
                DECISION_REVISION,
                DECISION_IMAGE,
                "emilia-decision@test-project.iam.gserviceaccount.com",
            ),
        },
    }


class StableReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="emilia-stable-release-")
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state_path = self.root / "state.json"
        self.log_path = self.root / "gcloud.log"
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
        self.manifest = self.root / "stable.json"
        self.write_state(initial_state())
        self.write_fake_gcloud()
        record = self.run_verifier(
            "record",
            "--config",
            str(self.config),
            "--actuator-revision",
            ACTUATOR_REVISION,
            "--decision-revision",
            DECISION_REVISION,
            "--private-key",
            str(self.private_key),
            "--key-id",
            "stable-test-key",
            "--output",
            str(self.manifest),
        )
        self.assertEqual(record.returncode, 0, record.stderr)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write_state(self, state: dict) -> None:
        self.state_path.write_text(
            json.dumps(state, sort_keys=True),
            encoding="utf-8",
        )

    def write_fake_gcloud(self) -> None:
        executable = self.bin / "gcloud"
        executable.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
state = json.loads(pathlib.Path(os.environ["FAKE_STATE"]).read_text())
with pathlib.Path(os.environ["FAKE_LOG"]).open("a") as handle:
    handle.write(json.dumps(args) + "\\n")
if args[:3] == ["run", "revisions", "describe"]:
    value = state["revisions"].get(args[3])
elif args[:3] == ["run", "services", "describe"]:
    value = state["services"].get(args[3])
elif args[:3] == ["run", "services", "update-traffic"]:
    raise SystemExit(0)
else:
    print("unexpected gcloud arguments: " + repr(args), file=sys.stderr)
    raise SystemExit(2)
if value is None:
    raise SystemExit(4)
print(json.dumps(value))
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
            **extra,
        }

    def run_verifier(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VERIFIER), *arguments],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(),
        )

    def verify(self, *, live: bool = False) -> subprocess.CompletedProcess[str]:
        return self.run_verifier(
            "verify",
            "--config",
            str(self.config),
            "--manifest",
            str(self.manifest),
            "--public-key",
            str(self.public_key),
            *(["--live"] if live else []),
        )

    def test_canonical_signed_manifest_records_complete_configuration(self) -> None:
        result = self.verify(live=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(
            set(value),
            {
                "@version",
                "project_id",
                "region",
                "recorded_at",
                "services",
                "signature",
            },
        )
        self.assertEqual(value["services"]["actuator"]["revision"], ACTUATOR_REVISION)
        self.assertEqual(value["services"]["decision"]["revision"], DECISION_REVISION)
        self.assertEqual(value["services"]["actuator"]["image"], ACTUATOR_IMAGE)
        self.assertEqual(
            value["services"]["decision"]["service_account"],
            "emilia-decision@test-project.iam.gserviceaccount.com",
        )
        self.assertEqual(
            value["services"]["actuator"]["vpc"],
            {
                "network": "runtime",
                "subnet": "runtime-us-central1",
                "egress": "all-traffic",
            },
        )
        self.assertEqual(value["services"]["decision"]["secret_bindings"], [])
        self.assertEqual(value["signature"]["algorithm"], "Ed25519")

    def test_forged_manifest_is_refused(self) -> None:
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        value["services"]["actuator"]["image"] = (
            "us-central1-docker.pkg.dev/test-project/runtime/actuator@sha256:"
            + "f" * 64
        )
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature is invalid", result.stderr)

    def test_live_image_sa_secret_and_config_drift_are_refused(self) -> None:
        mutations = {
            "image": lambda state: state["revisions"][ACTUATOR_REVISION]["spec"][
                "containers"
            ][0].update(
                {
                    "image": (
                        "us-central1-docker.pkg.dev/test-project/runtime/"
                        "actuator@sha256:" + "f" * 64
                    )
                }
            ),
            "service_account": lambda state: state["revisions"][ACTUATOR_REVISION][
                "spec"
            ].update(
                {"serviceAccountName": "attacker@test-project.iam.gserviceaccount.com"}
            ),
            "secret": lambda state: state["revisions"][ACTUATOR_REVISION]["spec"][
                "containers"
            ][0].update(
                {
                    "env": [
                        {
                            "name": "UNEXPECTED_SECRET",
                            "valueFrom": {
                                "secretKeyRef": {"name": "rogue", "key": "1"}
                            },
                        }
                    ]
                }
            ),
            "vpc": lambda state: state["revisions"][ACTUATOR_REVISION]["metadata"][
                "annotations"
            ].update(
                {
                    "run.googleapis.com/network-interfaces": json.dumps(
                        [{"network": "rogue", "subnetwork": "runtime-us-central1"}]
                    )
                }
            ),
            "ingress": lambda state: state["services"][ACTUATOR_SERVICE]["metadata"][
                "annotations"
            ].update({"run.googleapis.com/ingress": "all"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                state = deepcopy(initial_state())
                mutate(state)
                self.write_state(state)
                result = self.verify(live=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("live services.actuator", result.stderr)

    def test_candidate_cannot_be_recorded_as_stable(self) -> None:
        state = initial_state()
        actuator_candidate = f"{ACTUATOR_SERVICE}-r20260725b"
        decision_candidate = f"{DECISION_SERVICE}-r20260725b"
        state["revisions"][actuator_candidate] = revision(
            ACTUATOR_SERVICE,
            actuator_candidate,
            ACTUATOR_IMAGE,
            "emilia-actuator@test-project.iam.gserviceaccount.com",
        )
        state["revisions"][decision_candidate] = revision(
            DECISION_SERVICE,
            decision_candidate,
            DECISION_IMAGE,
            "emilia-decision@test-project.iam.gserviceaccount.com",
        )
        self.write_state(state)
        result = self.run_verifier(
            "record",
            "--config",
            str(self.config),
            "--actuator-revision",
            actuator_candidate,
            "--decision-revision",
            decision_candidate,
            "--private-key",
            str(self.private_key),
            "--key-id",
            "stable-test-key",
            "--output",
            str(self.root / "candidate.json"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must differ from the candidate", result.stderr)

    def test_rollback_requires_manifest_then_validates_live_before_traffic(self) -> None:
        missing = subprocess.run(
            [
                str(TRAFFIC),
                "--config",
                str(self.config),
                "--apply-rollback",
            ],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(DEPLOYMENT_APPROVED="true"),
        )
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("--stable-manifest", missing.stderr)

        self.log_path.write_text("", encoding="utf-8")
        accepted = subprocess.run(
            [
                str(TRAFFIC),
                "--config",
                str(self.config),
                "--stable-manifest",
                str(self.manifest),
                "--stable-public-key",
                str(self.public_key),
                "--apply-rollback",
            ],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(DEPLOYMENT_APPROVED="true"),
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        traffic_calls = [
            call for call in calls if call[:3] == ["run", "services", "update-traffic"]
        ]
        self.assertEqual(
            [call[3] for call in traffic_calls],
            [ACTUATOR_SERVICE, DECISION_SERVICE],
        )
        self.assertIn(
            f"--to-revisions={ACTUATOR_REVISION}=100",
            traffic_calls[0],
        )

        drifted = initial_state()
        drifted["revisions"][ACTUATOR_REVISION]["spec"]["serviceAccountName"] = (
            "attacker@test-project.iam.gserviceaccount.com"
        )
        self.write_state(drifted)
        self.log_path.write_text("", encoding="utf-8")
        refused = subprocess.run(
            [
                str(TRAFFIC),
                "--config",
                str(self.config),
                "--stable-manifest",
                str(self.manifest),
                "--stable-public-key",
                str(self.public_key),
                "--apply-rollback",
            ],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(DEPLOYMENT_APPROVED="true"),
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("drifted", refused.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(
            any(call[:3] == ["run", "services", "update-traffic"] for call in calls)
        )


if __name__ == "__main__":
    unittest.main()
