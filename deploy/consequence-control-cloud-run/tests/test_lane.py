from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

LANE = Path(__file__).resolve().parents[1]
CONFIG = LANE / "tests" / "fixture.env"


def run(
    *args: str,
    check: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=LANE,
        check=check,
        text=True,
        capture_output=True,
        env={**os.environ, "DEPLOYMENT_APPROVED": "", **(extra_env or {})},
    )


def load_config() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in CONFIG.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value
    return result


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = run(
            str(LANE / "deploy.sh"),
            "--config",
            str(CONFIG),
            "--render",
        ).stdout

    def test_two_digest_pinned_zero_traffic_services(self) -> None:
        self.assertEqual(self.plan.count("gcloud run deploy"), 2)
        self.assertEqual(self.plan.count("--no-traffic"), 2)
        self.assertIn(
            "--image=us-central1-docker.pkg.dev/test-project/runtime/"
            "actuator@sha256:" + "a" * 64,
            self.plan,
        )
        self.assertIn(
            "--image=us-central1-docker.pkg.dev/test-project/runtime/"
            "decision@sha256:" + "b" * 64,
            self.plan,
        )

    def test_distinct_service_accounts_and_internal_actuator(self) -> None:
        self.assertIn(
            "--service-account=emilia-actuator@test-project.iam.gserviceaccount.com",
            self.plan,
        )
        self.assertIn(
            "--service-account=emilia-decision@test-project.iam.gserviceaccount.com",
            self.plan,
        )
        actuator, decision = self.plan.split("# candidate decision:", 1)
        self.assertIn("--ingress=internal", actuator)
        self.assertIn("--network=runtime", actuator)
        self.assertIn("--vpc-egress=all-traffic", actuator)
        self.assertIn("--vpc-egress=all-traffic", decision)
        self.assertIn("--no-allow-unauthenticated", actuator)
        self.assertNotIn("--no-invoker-iam-check", actuator)
        self.assertIn("--no-invoker-iam-check", decision)
        self.assertNotIn("allUsers", self.plan)
        self.assertNotIn("allAuthenticatedUsers", self.plan)

    def test_resource_level_invoker_binding_names_only_decision_identity(self) -> None:
        self.assertIn(
            "gcloud run services get-iam-policy emilia-consequence-actuator",
            self.plan,
        )
        self.assertIn(
            "--member serviceAccount:emilia-decision"
            "@test-project.iam.gserviceaccount.com",
            self.plan,
        )
        self.assertIn("--role roles/run.invoker", self.plan)
        self.assertIn(
            "gcloud run services set-iam-policy emilia-consequence-actuator",
            self.plan,
        )
        self.assertNotIn("add-iam-policy-binding", self.plan)
        self.assertNotIn(
            "--member serviceAccount:emilia-actuator"
            "@test-project.iam.gserviceaccount.com --role roles/run.invoker",
            self.plan,
        )

    def test_secret_access_is_reconciled_instead_of_added(self) -> None:
        self.assertIn("gcloud secrets get-iam-policy actuator-token", self.plan)
        self.assertIn("gcloud secrets set-iam-policy actuator-token", self.plan)
        self.assertIn("roles/secretmanager.secretAccessor", self.plan)
        self.assertNotIn("secrets add-iam-policy-binding", self.plan)

    def test_effective_iam_is_verified_after_candidate_deployment(self) -> None:
        self.assertIn("emit-effective-iam-manifest.py", self.plan)
        self.assertIn("verify-effective-iam.py", self.plan)
        self.assertIn("--live", self.plan)
        self.assertLess(
            self.plan.index("# candidate decision:"),
            self.plan.index("# verify inherited"),
        )

    def test_credential_custody_is_split(self) -> None:
        deploy_lines = [
            line for line in self.plan.splitlines() if line.startswith("gcloud run deploy")
        ]
        self.assertEqual(len(deploy_lines), 2)
        actuator, decision = deploy_lines
        self.assertIn("EMILIA_ACTUATOR_GITHUB_PRIVATE_KEY=", actuator)
        self.assertIn("EMILIA_ACTUATOR_DATABASE_PRINCIPAL=", actuator)
        self.assertIn("EMILIA_ACTUATOR_ENVELOPE_PUBLIC_KEY=", actuator)
        self.assertIn("EMILIA_ACTUATOR_OBSERVATION_PRIVATE_KEY=", actuator)
        self.assertNotIn("EMILIA_ACTUATOR_GITHUB_", decision)
        self.assertNotIn("GITHUB_APP_ID", decision)
        self.assertNotIn("GITHUB_INSTALLATION_ID", decision)
        self.assertNotIn("GITHUB_PRIVATE_KEY", decision)
        self.assertIn("EMILIA_CONSEQUENCE_ACTUATOR_API_TOKEN=", decision)
        self.assertIn("EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_PRIVATE_KEY=", decision)
        self.assertIn("EMILIA_CONSEQUENCE_ACTUATOR_EVIDENCE_PUBLIC_KEY=", decision)

    def test_readiness_and_exact_candidate_origin_are_rendered(self) -> None:
        self.assertIn("startup-probe=tcpSocket.port=8080", self.plan)
        self.assertIn("readiness-probe=httpGet.path=/v1/ready", self.plan)
        self.assertIn("liveness-probe=httpGet.path=/v1/live", self.plan)
        self.assertIn(
            "EMILIA_CONSEQUENCE_ACTUATOR_ORIGIN=\\$\\{ACTUATOR_CANARY_URL\\}",
            self.plan,
        )
        self.assertIn(
            "EMILIA_CONSEQUENCE_ACTUATOR_AUDIENCE="
            "\\$\\{ACTUATOR_AUDIENCE\\}",
            self.plan,
        )
        self.assertIn(
            "ACTUATOR_AUDIENCE=<resolved-canonical-url-for-"
            "emilia-consequence-actuator>",
            self.plan,
        )
        self.assertIn("no production traffic is changed", self.plan)

    def test_secret_references_are_version_pinned(self) -> None:
        self.assertNotIn(":latest", self.plan)
        self.assertIn("EMILIA_ACTUATOR_API_TOKEN=actuator-token:2", self.plan)
        self.assertIn(
            "EMILIA_CONSEQUENCE_ACTUATOR_API_TOKEN=actuator-token:2", self.plan
        )

    def test_mutable_image_is_refused(self) -> None:
        source = CONFIG.read_text(encoding="utf-8").replace(
            load_config()["ACTUATOR_IMAGE"],
            "us-central1-docker.pkg.dev/test-project/runtime/actuator:latest",
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(source)
            handle.flush()
            result = run(
                str(LANE / "deploy.sh"),
                "--config",
                handle.name,
                "--render",
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pinned", result.stderr)


class TrafficTests(unittest.TestCase):
    def test_promotion_and_rollback_order(self) -> None:
        promote = run(
            str(LANE / "traffic.sh"),
            "--config",
            str(CONFIG),
            "--render-promote",
        ).stdout
        self.assertLess(
            promote.index("decision candidate 1%"),
            promote.index("actuator candidate 100%"),
        )
        self.assertIn(
            "emilia-consequence-control-r20260725b=1\\,"
            "emilia-consequence-control-r20260724a=99",
            promote,
        )
        rollback = run(
            str(LANE / "traffic.sh"),
            "--config",
            str(CONFIG),
            "--render-rollback",
        ).stdout
        self.assertLess(
            rollback.index("rollback actuator first"),
            rollback.index("rollback decision"),
        )

    def test_apply_is_approval_gated_before_gcloud(self) -> None:
        result = run(
            str(LANE / "traffic.sh"),
            "--config",
            str(CONFIG),
            "--apply-rollback",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DEPLOYMENT_APPROVED=true", result.stderr)


class CanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory(prefix="emilia-canary-tests-")
        cls.root = Path(cls.directory.name)
        cls.private_key = cls.root / "private.pem"
        cls.public_key = cls.root / "public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(cls.private_key),
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
                str(cls.private_key),
                "-pubout",
                "-out",
                str(cls.public_key),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        cls.config = cls.root / "config.env"
        cls.config.write_text(
            CONFIG.read_text(encoding="utf-8").replace(
                "/secure/test-canary-public.pem",
                str(cls.public_key),
            ),
            encoding="utf-8",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def evidence(self) -> dict:
        config = load_config()
        observed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        expires = observed + dt.timedelta(minutes=10)
        return {
            "@version": "EP-CONSEQUENCE-CANARY-EVIDENCE-v1",
            "project_id": config["PROJECT_ID"],
            "region": config["REGION"],
            "evidence_status": "observed",
            "observed_at": observed.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
            "nonce": "canary_nonce_0000000001",
            "actuator_revision": "emilia-consequence-actuator-r20260725b",
            "decision_revision": "emilia-consequence-control-r20260725b",
            "actuator_image": config["ACTUATOR_IMAGE"],
            "decision_image": config["DECISION_IMAGE"],
            "checks": {
                "exact_execution": {
                    "http_status": 200,
                    "outcome": "COMMITTED",
                    "action_digest": "sha256:" + "c" * 64,
                    "attempt_id": "attempt:canary-0001",
                    "provider_reference": "github:issue:example/canary#1",
                },
                "timeout": {
                    "http_status": 202,
                    "outcome": "INDETERMINATE",
                    "effect_boundary_entered": True,
                },
                "replay": {
                    "http_status": 409,
                    "reason": "envelope_replayed",
                    "provider_invocations": 1,
                },
                "reconciliation": {
                    "http_status": 200,
                    "valid": True,
                    "outcome": "ESCALATED",
                    "reason": "github_attempt_attribution_unavailable",
                    "reexecuted": False,
                },
            },
        }

    def sign(self, evidence: dict) -> dict:
        result = json.loads(json.dumps(evidence))
        result.pop("signature", None)
        payload = self.root / "payload.json"
        signature = self.root / "signature.bin"
        payload.write_text(
            json.dumps(
                result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.private_key),
                "-rawin",
                "-in",
                str(payload),
                "-out",
                str(signature),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        result["signature"] = {
            "algorithm": "Ed25519",
            "key_id": "canary-test-key",
            "value": base64.urlsafe_b64encode(signature.read_bytes())
            .decode("ascii")
            .rstrip("="),
        }
        return result

    def validate(
        self,
        evidence: dict,
        *,
        resign: bool = True,
        live: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        document = self.sign(evidence) if resign else evidence
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(document, handle)
            handle.flush()
            args = [
                str(LANE / "verify-canary.py"),
                "--config",
                str(self.config),
                "--evidence",
                handle.name,
            ]
            if live:
                args.append("--live")
            return run(
                *args,
                check=False,
                extra_env=extra_env,
            )

    def test_closed_canary_contract_is_accepted(self) -> None:
        result = self.validate(self.evidence())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("accepted", result.stdout)

    def test_replay_or_reexecution_drift_is_refused(self) -> None:
        evidence = self.evidence()
        evidence["checks"]["replay"]["provider_invocations"] = 2
        result = self.validate(evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provider_invocations", result.stderr)

    def test_canary_effect_target_must_match_the_deployment(self) -> None:
        evidence = self.evidence()
        evidence["checks"]["exact_execution"][
            "provider_reference"
        ] = "github:issue:attacker/decoy#999"
        result = self.validate(evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provider_reference", result.stderr)
        evidence = self.evidence()
        evidence["checks"]["reconciliation"]["reexecuted"] = True
        result = self.validate(evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reexecuted", result.stderr)

    def test_template_or_digest_mismatch_is_refused(self) -> None:
        evidence = self.evidence()
        evidence["evidence_status"] = "template-not-run"
        result = self.validate(evidence)
        self.assertNotEqual(result.returncode, 0)
        evidence = self.evidence()
        evidence["decision_image"] = evidence["decision_image"].replace("b", "c", 1)
        result = self.validate(evidence)
        self.assertNotEqual(result.returncode, 0)

    def test_unsigned_and_post_signature_tampering_are_refused(self) -> None:
        result = self.validate(self.evidence(), resign=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature", result.stderr)
        evidence = self.sign(self.evidence())
        evidence["checks"]["replay"]["provider_invocations"] = 2
        result = self.validate(evidence, resign=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature", result.stderr)

    def test_stale_signed_evidence_is_refused(self) -> None:
        evidence = self.evidence()
        observed = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
        evidence["observed_at"] = observed.isoformat().replace("+00:00", "Z")
        evidence["expires_at"] = (
            observed + dt.timedelta(minutes=10)
        ).isoformat().replace("+00:00", "Z")
        result = self.validate(evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr, r"expired|stale")

    def test_live_mode_rederives_revision_service_and_image(self) -> None:
        fake_bin = self.root / "bin"
        fake_bin.mkdir(exist_ok=True)
        gcloud = fake_bin / "gcloud"
        config = load_config()
        gcloud.write_text(
            """#!/usr/bin/env python3
import json
import sys
revision = sys.argv[4]
if revision == "emilia-consequence-actuator-r20260725b":
    service = "emilia-consequence-actuator"
    image = %r
elif revision == "emilia-consequence-control-r20260725b":
    service = "emilia-consequence-control"
    image = %r
else:
    raise SystemExit(2)
print(json.dumps({
    "metadata": {
        "name": revision,
        "labels": {"serving.knative.dev/service": service},
    },
    "spec": {"containers": [{"image": image}]},
}))
"""
            % (config["ACTUATOR_IMAGE"], config["DECISION_IMAGE"]),
            encoding="utf-8",
        )
        gcloud.chmod(0o755)
        result = self.validate(
            self.evidence(),
            live=True,
            extra_env={"PATH": f"{fake_bin}:{os.environ['PATH']}"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class IamPolicyTests(unittest.TestCase):
    def test_rewrite_removes_stale_role_members_and_preserves_other_roles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="emilia-iam-tests-") as directory:
            root = Path(directory)
            source = root / "source.json"
            target = root / "target.json"
            source.write_text(
                json.dumps(
                    {
                        "version": 3,
                        "etag": "etag",
                        "bindings": [
                            {
                                "role": "roles/run.invoker",
                                "members": [
                                    "allUsers",
                                    "serviceAccount:stale@example.test",
                                ],
                            },
                            {
                                "role": "roles/viewer",
                                "members": ["group:auditors@example.test"],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            member = "serviceAccount:decision@example.test"
            result = run(
                str(LANE / "reconcile-iam-policy.py"),
                "rewrite",
                "--input",
                str(source),
                "--output",
                str(target),
                "--role",
                "roles/run.invoker",
                "--member",
                member,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            policy = json.loads(target.read_text(encoding="utf-8"))
            self.assertIn(
                {
                    "role": "roles/viewer",
                    "members": ["group:auditors@example.test"],
                },
                policy["bindings"],
            )
            invoker = [
                binding
                for binding in policy["bindings"]
                if binding["role"] == "roles/run.invoker"
            ]
            self.assertEqual(invoker, [{"role": "roles/run.invoker", "members": [member]}])
            checked = run(
                str(LANE / "reconcile-iam-policy.py"),
                "check",
                "--input",
                str(target),
                "--role",
                "roles/run.invoker",
                "--member",
                member,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)


class StaticTests(unittest.TestCase):
    def test_source_contains_no_secret_payloads(self) -> None:
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in LANE.rglob("*")
            if path.is_file()
            and "tests" not in path.parts
            and "__pycache__" not in path.parts
        )
        self.assertNotIn("-----BEGIN PRIVATE KEY-----", text)
        self.assertNotIn("ghs_", text)
        self.assertNotIn(":latest", text)
        self.assertNotRegex(text, r"(?m)^(?:API_TOKEN|PRIVATE_KEY|DATABASE_URL)=")

    def test_canary_module_is_importable(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_canary", LANE / "verify-canary.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)

    def test_traffic_requires_live_canary_rederivation(self) -> None:
        traffic = (LANE / "traffic.sh").read_text(encoding="utf-8")
        self.assertIn("--live", traffic)


if __name__ == "__main__":
    unittest.main()
