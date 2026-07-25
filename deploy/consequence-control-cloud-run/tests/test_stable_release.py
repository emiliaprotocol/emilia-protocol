from __future__ import annotations

import json
import hashlib
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
ACTUATOR_REVISION = f"{ACTUATOR_SERVICE}-r20260724a"
DECISION_REVISION = f"{DECISION_SERVICE}-r20260724a"
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
    def service(name: str, ingress: str, stable_revision: str) -> dict:
        return {
            "apiVersion": "serving.knative.dev/v1",
            "kind": "Service",
            "metadata": {
                "name": name,
                "generation": 7,
                "resourceVersion": "rv-7",
                "annotations": {"run.googleapis.com/ingress": ingress},
            },
            "spec": {
                "traffic": [
                    {"revisionName": stable_revision, "percent": 100}
                ]
            },
            "status": {
                "observedGeneration": 7,
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "lastTransitionTime": "2026-07-25T12:00:00Z",
                    }
                ],
                "traffic": [
                    {
                        "revisionName": stable_revision,
                        "percent": 100,
                        "url": f"https://{stable_revision}.example.test",
                    }
                ],
            },
        }

    return {
        "services": {
            ACTUATOR_SERVICE: service(
                ACTUATOR_SERVICE,
                "internal",
                ACTUATOR_REVISION,
            ),
            DECISION_SERVICE: service(
                DECISION_SERVICE,
                "all",
                DECISION_REVISION,
            ),
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
        public_key_hash = hashlib.sha256(self.public_key.read_bytes()).hexdigest()
        self.config.write_text(
            FIXTURE_CONFIG.read_text(encoding="utf-8")
            + "\n"
            + "\n".join(
                [
                    "STABLE_RELEASE_KEY_ID=stable-test-key",
                    f"STABLE_RELEASE_PUBLIC_KEY_FILE={self.public_key}",
                    f"STABLE_RELEASE_PUBLIC_KEY_SHA256={public_key_hash}",
                    "STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT=bootstrap-actuator",
                    "STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT=bootstrap-decision",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
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
import base64
import json
import os
import pathlib
import subprocess
import sys

args = sys.argv[1:]
state = json.loads(pathlib.Path(os.environ["FAKE_STATE"]).read_text())
with pathlib.Path(os.environ["FAKE_LOG"]).open("a") as handle:
    handle.write(json.dumps(args) + "\\n")
if args[:5] == ["kms", "keys", "versions", "describe", "3"]:
    value = {
        "state": "ENABLED",
        "algorithm": "EC_SIGN_ED25519",
        "protectionLevel": "HSM",
    }
elif args[:5] == ["kms", "keys", "versions", "get-public-key", "3"]:
    print(pathlib.Path(os.environ["FAKE_KMS_PUBLIC"]).read_text(), end="")
    raise SystemExit(0)
elif args[:2] == ["kms", "asymmetric-sign"]:
    input_path = pathlib.Path(next(
        value.split("=", 1)[1]
        for value in args
        if value.startswith("--input-file=")
    ))
    signature_path = pathlib.Path(next(
        value.split("=", 1)[1]
        for value in args
        if value.startswith("--signature-file=")
    ))
    raw_signature = signature_path.with_suffix(".raw")
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            os.environ["FAKE_KMS_PRIVATE"],
            "-rawin",
            "-in",
            input_path,
            "-out",
            raw_signature,
        ],
        check=True,
    )
    signature_path.write_bytes(base64.b64encode(raw_signature.read_bytes()))
    raise SystemExit(0)
elif args[:3] == ["run", "revisions", "describe"]:
    value = state["revisions"].get(args[3])
elif args[:3] == ["run", "services", "describe"]:
    value = state["services"].get(args[3])
elif args[:3] == ["secrets", "versions", "describe"]:
    version = args[3]
    secret = next(
        value.split("=", 1)[1] for value in args if value.startswith("--secret=")
    )
    value = {
        "name": f"projects/test-project/secrets/{secret}/versions/{version}",
        "state": state.get("secret_state", "ENABLED"),
    }
    if "--format=json(name,state,destroyTime)" not in args:
        value["createTime"] = "2026-07-25T11:00:00Z"
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
            "FAKE_KMS_PRIVATE": str(self.private_key),
            "FAKE_KMS_PUBLIC": str(self.public_key),
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
                "lineage",
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
        self.assertEqual(
            value["lineage"],
            {
                "kind": "configured-stable",
                "actuator_revision": ACTUATOR_REVISION,
                "decision_revision": DECISION_REVISION,
            },
        )
        self.assertIn("revision_spec", value["services"]["actuator"]["configuration"])
        self.assertEqual(
            value["services"]["actuator"]["rollout"]["traffic"][0]["percent"],
            100,
        )
        self.assertEqual(value["signature"]["algorithm"], "Ed25519")
        self.assertEqual(value["signature"]["key_id"], "stable-test-key")
        self.assertEqual(value["signature"]["trust"]["provider"], "file")

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
                self.assertIn("stable-release manifest refused", result.stderr)

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
        self.assertIn("candidate", result.stderr)

    def test_zero_traffic_or_unconfigured_revision_cannot_be_recorded(self) -> None:
        state = initial_state()
        arbitrary = f"{ACTUATOR_SERVICE}-arbitrary"
        state["revisions"][arbitrary] = revision(
            ACTUATOR_SERVICE,
            arbitrary,
            ACTUATOR_IMAGE,
            "emilia-actuator@test-project.iam.gserviceaccount.com",
        )
        state["services"][ACTUATOR_SERVICE]["status"]["traffic"].append(
            {"revisionName": arbitrary, "percent": 0, "tag": "attacker"}
        )
        self.write_state(state)
        result = self.run_verifier(
            "record",
            "--config",
            str(self.config),
            "--actuator-revision",
            arbitrary,
            "--decision-revision",
            DECISION_REVISION,
            "--private-key",
            str(self.private_key),
            "--key-id",
            "stable-test-key",
            "--output",
            str(self.root / "arbitrary.json"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stable lineage", result.stderr)

    def test_caller_supplied_key_cannot_replace_configured_trust(self) -> None:
        attacker_private = self.root / "attacker-private.pem"
        attacker_public = self.root / "attacker-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", attacker_private],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                attacker_private,
                "-pubout",
                "-out",
                attacker_public,
            ],
            check=True,
            capture_output=True,
        )
        result = self.run_verifier(
            "verify",
            "--config",
            str(self.config),
            "--manifest",
            str(self.manifest),
            "--public-key",
            str(attacker_public),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match configured trust", result.stderr)

    def test_signed_key_identity_cannot_be_relabelled(self) -> None:
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        value["signature"]["key_id"] = "attacker-key"
        value["signature"]["trust"]["key_id"] = "attacker-key"
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(
            "signature.key_id" in result.stderr
            or "signature is invalid" in result.stderr
        )

    def test_configured_kms_uri_and_key_id_establish_trust(self) -> None:
        kms_uri = (
            "gcp-kms://projects/test-project/locations/us-central1/"
            "keyRings/stable/cryptoKeys/release/cryptoKeyVersions/3"
        )
        kms_config = self.root / "kms-config.env"
        lines = [
            line
            for line in self.config.read_text(encoding="utf-8").splitlines()
            if not line.startswith("STABLE_RELEASE_PUBLIC_KEY_")
            and not line.startswith("STABLE_RELEASE_KEY_ID=")
        ]
        lines.extend(
            [
                "STABLE_RELEASE_KEY_ID=kms-stable-key",
                f"STABLE_RELEASE_KMS_KEY_URI={kms_uri}",
            ]
        )
        kms_config.write_text("\n".join(lines) + "\n", encoding="utf-8")
        manifest = self.root / "kms-stable.json"
        record = self.run_verifier(
            "record",
            "--config",
            str(kms_config),
            "--actuator-revision",
            ACTUATOR_REVISION,
            "--decision-revision",
            DECISION_REVISION,
            "--kms-key-uri",
            kms_uri,
            "--key-id",
            "kms-stable-key",
            "--output",
            str(manifest),
        )
        self.assertEqual(record.returncode, 0, record.stderr)
        verify = self.run_verifier(
            "verify",
            "--config",
            str(kms_config),
            "--manifest",
            str(manifest),
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)
        value = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(value["signature"]["trust"]["provider"], "gcp-kms")
        self.assertEqual(value["signature"]["trust"]["kms_key_uri"], kms_uri)
        self.assertEqual(value["signature"]["trust"]["protection_level"], "HSM")

        rollback = subprocess.run(
            [
                str(TRAFFIC),
                "--config",
                str(kms_config),
                "--stable-manifest",
                str(manifest),
                "--apply-rollback",
            ],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(DEPLOYMENT_APPROVED="true"),
        )
        self.assertEqual(rollback.returncode, 0, rollback.stderr)

        caller_key = subprocess.run(
            [
                str(TRAFFIC),
                "--config",
                str(kms_config),
                "--stable-manifest",
                str(manifest),
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
        self.assertNotEqual(caller_key.returncode, 0)
        self.assertIn("forbidden when KMS trust is configured", caller_key.stderr)

    def test_secret_version_identity_and_enabled_state_are_witnessed(self) -> None:
        state = initial_state()
        state["revisions"][ACTUATOR_REVISION]["spec"]["containers"][0]["env"] = [
            {
                "name": "PINNED_SECRET",
                "valueFrom": {
                    "secretKeyRef": {"name": "stable-secret", "key": "7"}
                },
            }
        ]
        self.write_state(state)
        output = self.root / "secret-stable.json"
        result = self.run_verifier(
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
            str(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        binding = json.loads(output.read_text(encoding="utf-8"))["services"][
            "actuator"
        ]["secret_bindings"][0]
        self.assertEqual(binding["version"], "7")
        self.assertEqual(binding["state"], "ENABLED")
        self.assertEqual(
            binding["resource"],
            "projects/test-project/secrets/stable-secret/versions/7",
        )

        state["secret_state"] = "DISABLED"
        self.write_state(state)
        refused = self.run_verifier(
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
            str(self.root / "disabled-secret.json"),
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("state", refused.stderr)

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
            traffic_calls,
            [],
            "already-stable rollback must be an idempotent no-op",
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
