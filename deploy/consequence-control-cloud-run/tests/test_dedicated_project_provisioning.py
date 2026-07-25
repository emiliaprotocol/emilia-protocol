from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


LANE_DIR = Path(__file__).resolve().parents[1]
SCRIPT = LANE_DIR / "provision-dedicated-project.sh"


def provision_config(**overrides: str) -> str:
    values = {
        "PROJECT_ID": "emilia-consequence-prod",
        "BILLING_ACCOUNT": "012345-6789AB-CDEF01",
        "REGION": "us-central1",
        "ACTUATOR_SERVICE_ACCOUNT": "emilia-actuator",
        "DECISION_SERVICE_ACCOUNT": "emilia-decision",
        "DEPLOYER_PRINCIPAL": (
            "serviceAccount:emilia-deployer@emilia-ops.iam.gserviceaccount.com"
        ),
        "RECOVERY_PRINCIPALS": (
            "user:recovery-one@example.com,user:recovery-two@example.com"
        ),
        "NETWORK": "emilia-runtime",
        "SUBNET": "emilia-runtime-us-central1",
        "SUBNET_CIDR": "10.42.0.0/26",
        "ARTIFACT_REPOSITORY": "runtime",
        "ROUTER": "emilia-egress-router",
        "NAT": "emilia-egress-nat",
    }
    values.update(overrides)
    return "".join(f"{key}={value}\n" for key, value in values.items())


class DedicatedProjectProvisioningTests(unittest.TestCase):
    def run_script(
        self,
        config: str,
        *arguments: str,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "provision.env"
            config_path.write_text(config, encoding="utf-8")
            return subprocess.run(
                [str(SCRIPT), "--config", str(config_path), *arguments],
                text=True,
                capture_output=True,
                check=False,
                env={**os.environ, **(env or {})},
            )

    def test_render_contains_dedicated_network_and_control_plane(self) -> None:
        result = self.run_script(provision_config(), "--render")

        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = result.stdout
        for api in (
            "run.googleapis.com",
            "compute.googleapis.com",
            "artifactregistry.googleapis.com",
            "secretmanager.googleapis.com",
            "iamcredentials.googleapis.com",
            "cloudasset.googleapis.com",
        ):
            self.assertIn(api, rendered)
        self.assertIn("--subnet-mode=custom", rendered)
        self.assertIn("--range=10.42.0.0/26", rendered)
        self.assertIn("--enable-private-ip-google-access", rendered)
        self.assertIn("compute routers create emilia-egress-router", rendered)
        self.assertIn("compute routers nats create emilia-egress-nat", rendered)
        self.assertIn("--nat-all-subnet-ip-ranges", rendered)
        self.assertIn("iam service-accounts create emilia-actuator", rendered)
        self.assertIn("iam service-accounts create emilia-decision", rendered)
        self.assertIn("artifacts repositories create runtime", rendered)
        self.assertIn("--immutable-tags", rendered)

    def test_rendered_steady_state_roles_exclude_data_plane_permissions(self) -> None:
        result = self.run_script(provision_config(), "--render")

        self.assertEqual(result.returncode, 0, result.stderr)
        for forbidden in (
            "run.routes.invoke",
            "secretmanager.versions.access",
            "iam.serviceAccounts.getAccessToken",
            "iam.serviceAccounts.getOpenIdToken",
            "iam.serviceAccounts.signBlob",
            "iam.serviceAccounts.signJwt",
            "iam.serviceAccounts.implicitDelegation",
            "iam.serviceAccounts.actAs",
            "roles/iam.serviceAccountUser",
        ):
            self.assertNotIn(forbidden, result.stdout)
        self.assertIn("emiliaConsequenceProvisioner", result.stdout)
        self.assertIn("emiliaConsequenceDeployer", result.stdout)
        deployer_section = result.stdout.split(
            "# create emiliaConsequenceDeployer", 1
        )[1].split("# establish explicit recovery owners", 1)[0]
        self.assertNotIn("run.services.setIamPolicy", deployer_section)
        self.assertNotIn("secretmanager.secrets.setIamPolicy", deployer_section)

    def test_default_editor_removal_is_ordered_after_recovery_verification(self) -> None:
        result = self.run_script(provision_config(), "--render")

        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = result.stdout
        recovery = rendered.index("# verify explicit recovery owners before cleanup")
        cleanup = rendered.index("# remove broad default Editor grants")
        self.assertLess(recovery, cleanup)
        self.assertIn("verify-recovery-owner", rendered)
        self.assertIn("roles/editor", rendered[cleanup:])

    def test_apply_refuses_without_two_explicit_confirmations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_gcloud = Path(directory) / "gcloud"
            marker = Path(directory) / "gcloud-called"
            fake_gcloud.write_text(
                f"#!/usr/bin/env bash\ntouch {marker!s}\nexit 0\n",
                encoding="utf-8",
            )
            fake_gcloud.chmod(0o755)
            result = self.run_script(
                provision_config(),
                "--apply",
                env={"PATH": f"{directory}:{os.environ['PATH']}"},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("PROVISIONING_APPROVED=true", result.stderr)
            self.assertFalse(marker.exists())

    def test_apply_refuses_project_confirmation_mismatch_before_gcloud(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_gcloud = Path(directory) / "gcloud"
            marker = Path(directory) / "gcloud-called"
            fake_gcloud.write_text(
                f"#!/usr/bin/env bash\ntouch {marker!s}\nexit 0\n",
                encoding="utf-8",
            )
            fake_gcloud.chmod(0o755)
            result = self.run_script(
                provision_config(),
                "--apply",
                env={
                    "PATH": f"{directory}:{os.environ['PATH']}",
                    "PROVISIONING_APPROVED": "true",
                    "PROVISIONING_CONFIRM_PROJECT": "wrong-project",
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must exactly equal PROJECT_ID", result.stderr)
            self.assertFalse(marker.exists())

    def test_config_cannot_embed_its_own_approval(self) -> None:
        result = self.run_script(
            provision_config(
                PROVISIONING_APPROVED="true",
                PROVISIONING_CONFIRM_PROJECT="emilia-consequence-prod",
            ),
            "--apply",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("approval controls must not be stored", result.stderr)

    def test_deployer_cannot_also_be_a_recovery_owner(self) -> None:
        result = self.run_script(
            provision_config(
                RECOVERY_PRINCIPALS=(
                    "serviceAccount:emilia-deployer@"
                    "emilia-ops.iam.gserviceaccount.com"
                )
            ),
            "--render",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not be a recovery owner", result.stderr)

    def test_rejects_subnet_that_is_not_an_ipv4_26(self) -> None:
        result = self.run_script(
            provision_config(SUBNET_CIDR="10.42.0.0/24"),
            "--render",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("IPv4 /26", result.stderr)

    def test_jit_actas_is_approval_gated_and_time_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_gcloud = Path(directory) / "gcloud"
            log = Path(directory) / "gcloud.log"
            fake_gcloud.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$*\" >> {log!s}\n",
                encoding="utf-8",
            )
            fake_gcloud.chmod(0o755)
            expiry = (
                datetime.now(timezone.utc) + timedelta(minutes=30)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            result = self.run_script(
                provision_config(),
                "--grant-jit-actas",
                env={
                    "PATH": f"{directory}:{os.environ['PATH']}",
                    "ROLLOUT_APPROVED": "true",
                    "ROLLOUT_CONFIRM_PROJECT": "emilia-consequence-prod",
                    "JIT_ACTAS_EXPIRES_AT": expiry,
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text(encoding="utf-8")
            self.assertEqual(calls.count("roles/iam.serviceAccountUser"), 2)
            self.assertEqual(calls.count("emilia-jit-actas"), 2)
            self.assertIn("request.time < timestamp", calls)
            self.assertIn(expiry, calls)
            self.assertIn("emilia-actuator@", calls)
            self.assertIn("emilia-decision@", calls)

    def test_jit_actas_refuses_missing_or_long_lived_expiry_before_gcloud(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_gcloud = Path(directory) / "gcloud"
            marker = Path(directory) / "gcloud-called"
            fake_gcloud.write_text(
                f"#!/usr/bin/env bash\ntouch {marker!s}\n",
                encoding="utf-8",
            )
            fake_gcloud.chmod(0o755)
            common_env = {
                "PATH": f"{directory}:{os.environ['PATH']}",
                "ROLLOUT_APPROVED": "true",
                "ROLLOUT_CONFIRM_PROJECT": "emilia-consequence-prod",
            }
            missing = self.run_script(
                provision_config(),
                "--grant-jit-actas",
                env=common_env,
            )
            long_lived = self.run_script(
                provision_config(),
                "--grant-jit-actas",
                env={
                    **common_env,
                    "JIT_ACTAS_EXPIRES_AT": (
                        datetime.now(timezone.utc) + timedelta(hours=2)
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
            )

            self.assertNotEqual(missing.returncode, 0)
            self.assertNotEqual(long_lived.returncode, 0)
            self.assertFalse(marker.exists())

    def test_shellcheck_accepts_provisioner(self) -> None:
        if not shutil_which("shellcheck"):
            self.skipTest("shellcheck is not installed")

        result = subprocess.run(
            ["shellcheck", str(SCRIPT)],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def shutil_which(command: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / command
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


if __name__ == "__main__":
    unittest.main()
