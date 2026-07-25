from __future__ import annotations

import json
import hashlib
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
        self.provenance = self.root / "bootstrap-provenance.json"
        self.provenance.write_text(
            json.dumps(
                {
                    "@version": "EP-CONSEQUENCE-BOOTSTRAP-PROVENANCE-v1",
                    "image": PLACEHOLDER_IMAGE,
                    "digest": PLACEHOLDER_IMAGE.rsplit("@", 1)[1],
                    "predicate_type": "https://slsa.dev/provenance/v1",
                    "builder_id": "https://cloudbuild.googleapis.com/test-builder",
                    "source": {
                        "repository": "https://github.com/example/bootstrap",
                        "commit_sha": "a" * 40,
                    },
                    "verification": {
                        "result": "VERIFIED",
                        "verifier": "trusted-build-policy",
                        "key_id": "provenance-test-key",
                        "verified_at": "2026-07-25T10:00:00Z",
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        public_key_hash = hashlib.sha256(self.public_key.read_bytes()).hexdigest()
        provenance_hash = hashlib.sha256(self.provenance.read_bytes()).hexdigest()
        self.config.write_text(
            FIXTURE_CONFIG.read_text(encoding="utf-8")
            + "\n"
            + "\n".join(
                [
                    "STABLE_RELEASE_KEY_ID=stable-test-key",
                    f"STABLE_RELEASE_PUBLIC_KEY_FILE={self.public_key}",
                    f"STABLE_RELEASE_PUBLIC_KEY_SHA256={public_key_hash}",
                    (
                        "STABLE_BOOTSTRAP_ALLOWED_DIGESTS="
                        + PLACEHOLDER_IMAGE.rsplit("@", 1)[1]
                    ),
                    f"STABLE_BOOTSTRAP_PROVENANCE_FILE={self.provenance}",
                    f"STABLE_BOOTSTRAP_PROVENANCE_SHA256={provenance_hash}",
                    "STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT=bootstrap-actuator",
                    "STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT=bootstrap-decision",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.output = self.root / "stable.json"
        self.state_path = self.root / "state.json"
        self.log_path = self.root / "gcloud.log"
        self.state_path.write_text(
            json.dumps(
                {
                    "deployed": [],
                    "service_accounts": [
                        "bootstrap-actuator",
                        "bootstrap-decision",
                    ],
                    "promoted": [],
                }
            ),
            encoding="utf-8",
        )
        self.write_fake_gcloud()
        self.write_fake_curl()

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
if args[:2] == ["projects", "describe"]:
    print("123456789012")
    raise SystemExit(0)
if args[:2] == ["projects", "get-ancestors"]:
    print(os.environ.get(
        "FAKE_ANCESTRY_JSON",
        '[{"type":"project","id":"test-project"}]',
    ))
    raise SystemExit(0)
if args[:3] == ["iam", "service-accounts", "describe"]:
    account = args[3].split("@", 1)[0]
    raise SystemExit(0 if account in state["service_accounts"] else 4)
if args[:3] == ["iam", "service-accounts", "create"]:
    account = args[3]
    if account not in state["service_accounts"]:
        state["service_accounts"].append(account)
        state_path.write_text(json.dumps(state))
    raise SystemExit(0)
if args[:2] == ["asset", "analyze-iam-policy"]:
    print(json.dumps({
        "mainAnalysis": {
            "fullyExplored": not bool(os.environ.get("FAKE_INCOMPLETE_IAM")),
            "analysisResults": (
                [{
                    "role": "roles/secretmanager.secretAccessor",
                    "fullyExplored": True,
                }]
                if os.environ.get("FAKE_EFFECTIVE_IAM")
                else []
            ),
        },
        "fullyExplored": not bool(os.environ.get("FAKE_PARTIAL_IAM")),
    }))
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
if args[:3] == ["run", "services", "update-traffic"]:
    service = args[3]
    state["promoted"].append(service)
    state_path.write_text(json.dumps(state))
    raise SystemExit(0)
if args[:3] == ["run", "revisions", "describe"]:
    revision = args[3]
    service = revision.rsplit("-", 1)[0]
    if service not in state["deployed"]:
        raise SystemExit(4)
    account = (
        "bootstrap-actuator@test-project.iam.gserviceaccount.com"
        if service.endswith("actuator")
        else "bootstrap-decision@test-project.iam.gserviceaccount.com"
    )
    print(json.dumps({
        "metadata": {
            "name": revision,
            "labels": {
                "serving.knative.dev/service": service,
                "emilia-plane": "bootstrap",
                "emilia-deny-all": "true",
                "emilia-permissionless": "true",
            },
            "annotations": {
                "run.googleapis.com/execution-environment": "gen2",
                "autoscaling.knative.dev/minScale": "0",
                "autoscaling.knative.dev/maxScale": "1",
            },
        },
        "spec": {
            "serviceAccountName": account,
            "containerConcurrency": 1,
            "timeoutSeconds": 5,
            "containers": [{
                "image": os.environ["PLACEHOLDER_IMAGE"],
                "env": [],
                "ports": [{"containerPort": 8080}],
                "resources": {"limits": {"cpu": "1", "memory": "256Mi"}},
            }],
        },
    }))
    raise SystemExit(0)
if args[:3] == ["run", "services", "describe"]:
    service = args[3]
    if service not in state["deployed"]:
        raise SystemExit(4)
    if "--format=value(status.url)" in args:
        print("https://" + service + ".example.test")
        raise SystemExit(0)
    ingress = "internal" if service.endswith("actuator") else "all"
    revision = service + "-bootstrap1"
    percent = 100 if service in state["promoted"] else 0
    print(json.dumps({
        "metadata": {
            "name": service,
            "generation": 1,
            "annotations": {"run.googleapis.com/ingress": ingress},
        },
        "status": {
            "url": "https://" + service + ".example.test",
            "observedGeneration": 1,
            "conditions": [{
                "type": "Ready",
                "status": "True",
                "lastTransitionTime": "2026-07-25T12:00:00Z",
            }],
            "traffic": [{
                "revisionName": revision,
                "percent": percent,
                "tag": "stable-bootstrap-bootstrap1",
                "url": "https://" + revision + ".example.test",
            }],
        },
    }))
    raise SystemExit(0)
if args[:2] == ["auth", "print-identity-token"]:
    print("test-identity-token")
    raise SystemExit(0)
print("unexpected gcloud arguments: " + repr(args), file=sys.stderr)
raise SystemExit(2)
""",
            encoding="utf-8",
        )
        executable.chmod(0o755)

    def write_fake_curl(self) -> None:
        executable = self.bin / "curl"
        executable.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
output = pathlib.Path(args[args.index("-o") + 1])
url = args[-1]
authenticated = any("Authorization: Bearer " in value for value in args)
health = url.endswith("/v1/live") or url.endswith("/v1/ready")
if authenticated and health and not os.environ.get("FAKE_HEALTH_FAILURE"):
    output.write_text(json.dumps({
        "status": "healthy",
        "mode": "deny-all-bootstrap",
    }))
    print("200", end="")
else:
    output.write_text(json.dumps({
        "status": "refused",
        "reason": "bootstrap_deny_all",
    }))
    print("403", end="")
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
            "DEPLOYER_PRINCIPAL": (
                "serviceAccount:emilia-deployer@"
                "test-project.iam.gserviceaccount.com"
            ),
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
            "--provenance",
            str(self.provenance),
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
        self.assertEqual(result.stdout.count("--no-traffic"), 2)
        self.assertNotIn("--set-secrets", result.stdout)
        self.assertNotIn("--network=", result.stdout)
        self.assertNotIn("--subnet=", result.stdout)
        self.assertNotIn("--vpc-egress", result.stdout)
        self.assertEqual(result.stdout.count("--no-allow-unauthenticated"), 2)
        self.assertEqual(result.stdout.count("emilia-deny-all=true"), 2)
        self.assertIn("verify-bootstrap", result.stdout)
        self.assertIn("asset analyze-iam-policy", result.stdout)
        self.assertIn("projects get-ancestors test-project", result.stdout)
        self.assertEqual(
            result.stdout.count("iam service-accounts describe"),
            2,
        )
        self.assertNotIn("iam service-accounts create", result.stdout)
        analyzer_lines = [
            line
            for line in result.stdout.splitlines()
            if "asset analyze-iam-policy" in line
        ]
        self.assertEqual(len(analyzer_lines), 2)
        self.assertEqual(
            {line.split("--scope=", 1)[1].split()[0] for line in analyzer_lines},
            {r"\<resolved-after-ancestry-proof\>"},
        )
        self.assertEqual(result.stdout.count("run services update-traffic"), 2)
        self.assertIn("httpGet.path=/v1/ready", result.stdout)
        self.assertIn("verify-stable-release.py record", result.stdout)
        self.assertLess(
            result.stdout.index("curl"),
            result.stdout.index("run services update-traffic"),
        )

    def test_render_refuses_non_covering_project_scope(self) -> None:
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--render"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(
                EMILIA_IAM_ANALYZER_SCOPE="projects/other-project",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EMILIA_IAM_ANALYZER_SCOPE", result.stderr)
        self.assertNotIn("gcloud run deploy", result.stdout)

    def test_preprovisioned_standalone_project_bootstraps_and_signs_manifest(
        self,
    ) -> None:
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
        self.assertIsNone(value["services"]["actuator"]["vpc"])
        self.assertEqual(
            value["services"]["actuator"]["service_account"],
            "bootstrap-actuator@test-project.iam.gserviceaccount.com",
        )
        self.assertEqual(value["lineage"]["kind"], "bootstrap-genesis")
        self.assertEqual(
            value["lineage"]["provenance"]["digest"],
            PLACEHOLDER_IMAGE.rsplit("@", 1)[1],
        )

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
        self.assertTrue(all("--no-traffic" in call for call in deploys))
        self.assertTrue(all(not any("--network=" in arg for arg in call) for call in deploys))
        self.assertFalse(
            any(
                call[:3] == ["iam", "service-accounts", "create"]
                for call in calls
            )
        )
        self.assertTrue(
            any(call[:2] == ["projects", "get-ancestors"] for call in calls)
        )
        analyses = [
            call
            for call in calls
            if call[:2] == ["asset", "analyze-iam-policy"]
        ]
        self.assertEqual(len(analyses), 2)
        self.assertTrue(
            all("--scope=projects/test-project" in call for call in analyses)
        )
        traffic = [
            call
            for call in calls
            if call[:3] == ["run", "services", "update-traffic"]
        ]
        self.assertEqual(
            [call[3] for call in traffic],
            [ACTUATOR_SERVICE, DECISION_SERVICE],
        )

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
            json.dumps(
                {
                    "deployed": [ACTUATOR_SERVICE],
                    "service_accounts": [],
                    "promoted": [],
                }
            ),
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

    def test_unallowlisted_digest_is_refused_before_cloud_mutation(self) -> None:
        arguments = self.arguments()
        hostile_image = (
            "us-central1-docker.pkg.dev/test-project/runtime/bootstrap@sha256:"
            + "8" * 64
        )
        arguments[arguments.index(PLACEHOLDER_IMAGE)] = hostile_image
        result = subprocess.run(
            [str(BOOTSTRAP), *arguments, "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(DEPLOYMENT_APPROVED="true"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not explicitly allowlisted", result.stderr)
        self.assertFalse(self.log_path.exists())

    def test_hierarchy_requires_explicit_organization_scope(self) -> None:
        ancestry = json.dumps(
            [
                {"type": "project", "id": "test-project"},
                {"type": "folder", "id": "123456789"},
                {"type": "organization", "id": "987654321"},
            ]
        )
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(
                DEPLOYMENT_APPROVED="true",
                FAKE_ANCESTRY_JSON=ancestry,
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "EMILIA_IAM_ANALYZER_SCOPE=organizations/987654321",
            result.stderr,
        )
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(
            any(call[:2] == ["services", "enable"] for call in calls)
        )
        self.assertFalse(
            any(call[:2] == ["asset", "analyze-iam-policy"] for call in calls)
        )

    def test_hierarchy_refuses_scope_for_a_different_organization(self) -> None:
        ancestry = json.dumps(
            [
                {"type": "project", "id": "test-project"},
                {"type": "organization", "id": "987654321"},
            ]
        )
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(
                DEPLOYMENT_APPROVED="true",
                EMILIA_IAM_ANALYZER_SCOPE="organizations/111111111",
                FAKE_ANCESTRY_JSON=ancestry,
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match actual organization", result.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(
            any(call[:2] == ["services", "enable"] for call in calls)
        )

    def test_hierarchy_uses_covering_scope_for_both_bootstrap_identities(
        self,
    ) -> None:
        ancestry = json.dumps(
            [
                {"type": "project", "id": "test-project"},
                {"type": "folder", "id": "123456789"},
                {"type": "organization", "id": "987654321"},
            ]
        )
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(
                DEPLOYMENT_APPROVED="true",
                EMILIA_IAM_ANALYZER_SCOPE="organizations/987654321",
                FAKE_ANCESTRY_JSON=ancestry,
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        analyses = [
            call
            for call in calls
            if call[:2] == ["asset", "analyze-iam-policy"]
        ]
        self.assertEqual(len(analyses), 2)
        self.assertTrue(
            all("--scope=organizations/987654321" in call for call in analyses)
        )

    def test_ancestor_grant_is_refused_before_deploy(self) -> None:
        ancestry = json.dumps(
            [
                {"type": "project", "id": "test-project"},
                {"type": "organization", "id": "987654321"},
            ]
        )
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(
                DEPLOYMENT_APPROVED="true",
                EMILIA_IAM_ANALYZER_SCOPE="organizations/987654321",
                FAKE_ANCESTRY_JSON=ancestry,
                FAKE_EFFECTIVE_IAM="true",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not proven permissionless", result.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        analyses = [
            call
            for call in calls
            if call[:2] == ["asset", "analyze-iam-policy"]
        ]
        self.assertEqual(len(analyses), 1)
        self.assertIn("--scope=organizations/987654321", analyses[0])
        self.assertFalse(any(call[:2] == ["run", "deploy"] for call in calls))

    def test_permissioned_bootstrap_identity_is_refused_before_deploy(self) -> None:
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(
                DEPLOYMENT_APPROVED="true",
                FAKE_EFFECTIVE_IAM="true",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not proven permissionless", result.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(any(call[:2] == ["run", "deploy"] for call in calls))

    def test_incomplete_iam_analysis_cannot_claim_permissionless_identity(
        self,
    ) -> None:
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(
                DEPLOYMENT_APPROVED="true",
                FAKE_PARTIAL_IAM="true",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not proven permissionless", result.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(any(call[:2] == ["run", "deploy"] for call in calls))

    def test_incomplete_main_analysis_cannot_claim_permissionless_identity(
        self,
    ) -> None:
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(
                DEPLOYMENT_APPROVED="true",
                FAKE_INCOMPLETE_IAM="true",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not proven permissionless", result.stderr)
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(any(call[:2] == ["run", "deploy"] for call in calls))

    def test_missing_preprovisioned_identity_is_refused_without_creation(
        self,
    ) -> None:
        cases = (
            (["bootstrap-decision"], "bootstrap-actuator"),
            (["bootstrap-actuator"], "bootstrap-decision"),
        )
        for service_accounts, missing in cases:
            with self.subTest(missing=missing):
                self.state_path.write_text(
                    json.dumps(
                        {
                            "deployed": [],
                            "service_accounts": service_accounts,
                            "promoted": [],
                        }
                    ),
                    encoding="utf-8",
                )
                self.log_path.unlink(missing_ok=True)
                result = subprocess.run(
                    [str(BOOTSTRAP), *self.arguments(), "--apply"],
                    cwd=LANE,
                    check=False,
                    text=True,
                    capture_output=True,
                    env=self.environment(DEPLOYMENT_APPROVED="true"),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "must be pre-provisioned: "
                    f"{missing}@test-project.iam.gserviceaccount.com",
                    result.stderr,
                )
                calls = [
                    json.loads(line)
                    for line in self.log_path.read_text(
                        encoding="utf-8"
                    ).splitlines()
                ]
                self.assertFalse(
                    any(
                        call[:3] == ["iam", "service-accounts", "create"]
                        for call in calls
                    )
                )
                self.assertFalse(
                    any(
                        call[:2] == ["asset", "analyze-iam-policy"]
                        for call in calls
                    )
                )
                self.assertFalse(
                    any(call[:2] == ["run", "deploy"] for call in calls)
                )

    def test_failed_health_contract_keeps_both_revisions_at_zero_traffic(self) -> None:
        result = subprocess.run(
            [str(BOOTSTRAP), *self.arguments(), "--apply"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(
                DEPLOYMENT_APPROVED="true",
                FAKE_HEALTH_FAILURE="true",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 200", result.stderr)
        self.assertFalse(self.output.exists())
        calls = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            [
                call
                for call in calls
                if call[:3] == ["run", "services", "update-traffic"]
            ],
            [],
        )


if __name__ == "__main__":
    unittest.main()
