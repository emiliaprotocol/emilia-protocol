from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
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
        "STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT": "emilia-bootstrap-actuator",
        "STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT": "emilia-bootstrap-decision",
        "PROVISIONER_PRINCIPAL": (
            "serviceAccount:emilia-provisioner@"
            "emilia-ops.iam.gserviceaccount.com"
        ),
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
        self.assertIn(
            "iam service-accounts create emilia-bootstrap-actuator",
            rendered,
        )
        self.assertIn(
            "iam service-accounts create emilia-bootstrap-decision",
            rendered,
        )
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
        self.assertIn("emiliaConsequenceRecovery", result.stdout)
        deployer_section = result.stdout.split(
            "# create emiliaConsequenceDeployer", 1
        )[1].split("# create emiliaConsequenceRecovery", 1)[0]
        for permission in (
            "iam.serviceAccounts.setIamPolicy",
            "run.services.setIamPolicy",
            "secretmanager.secrets.setIamPolicy",
        ):
            self.assertIn(permission, deployer_section)
        provisioner_section = result.stdout.split(
            "# create emiliaConsequenceProvisioner", 1
        )[1].split("# create emiliaConsequenceDeployer", 1)[0]
        for forbidden in (
            "iam.serviceAccounts.actAs",
            "run.routes.invoke",
            "secretmanager.versions.access",
        ):
            self.assertNotIn(forbidden, provisioner_section)

    def test_recovery_role_is_custom_control_plane_only_and_replaces_owner(self) -> None:
        result = self.run_script(provision_config(), "--render")

        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = result.stdout
        recovery_section = rendered.split(
            "# create emiliaConsequenceRecovery", 1
        )[1].split("# establish break-glass recovery custodians", 1)[0]
        for permission in (
            "resourcemanager.projects.setIamPolicy",
            "iam.serviceAccounts.setIamPolicy",
            "run.services.setIamPolicy",
            "secretmanager.secrets.setIamPolicy",
        ):
            self.assertIn(permission, recovery_section)
        for forbidden in (
            "iam.serviceAccounts.actAs",
            "run.routes.invoke",
            "secretmanager.versions.access",
        ):
            self.assertNotIn(forbidden, recovery_section)
        self.assertEqual(
            rendered.count(
                "--role=projects/emilia-consequence-prod/roles/"
                "emiliaConsequenceRecovery"
            ),
            2,
        )
        self.assertNotIn("--role=roles/owner", rendered)
        self.assertIn(
            "--member=serviceAccount:emilia-provisioner@"
            "emilia-ops.iam.gserviceaccount.com "
            "--role=projects/emilia-consequence-prod/roles/"
            "emiliaConsequenceProvisioner",
            rendered,
        )

    def test_default_editor_removal_is_ordered_after_recovery_verification(self) -> None:
        result = self.run_script(provision_config(), "--render")

        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = result.stdout
        recovery = rendered.index(
            "# verify recovery and provisioner control before owner removal"
        )
        cleanup = rendered.index("# remove broad default Editor grants")
        self.assertLess(recovery, cleanup)
        self.assertIn("verify-control-plane-custody", rendered)
        self.assertIn("verify-control-plane-exact", rendered)
        self.assertIn("roles/editor", rendered[cleanup:])

    def test_apply_reconciles_exact_recovery_custody_and_creates_all_identities(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_gcloud = root / "gcloud"
            log = root / "gcloud.log"
            state_path = root / "state.json"
            recovery_role = (
                "projects/emilia-consequence-prod/roles/"
                "emiliaConsequenceRecovery"
            )
            initial_state = {
                "accounts": [],
                "policy": {
                    "version": 3,
                    "bindings": [
                        {
                            "role": "roles/owner",
                            "members": [
                                (
                                    "serviceAccount:emilia-provisioner@"
                                    "emilia-ops.iam.gserviceaccount.com"
                                ),
                                "user:recovery-one@example.com",
                                "user:recovery-two@example.com",
                                "user:unrelated-owner@example.com",
                            ],
                        },
                        {
                            "role": recovery_role,
                            "members": [
                                "user:stale-recovery@example.com"
                            ],
                        },
                    ],
                },
            }
            state_path.write_text(
                json.dumps(initial_state),
                encoding="utf-8",
            )
            fake_gcloud.write_text(
                """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
log = Path(os.environ["GCLOUD_LOG"])
state_path = Path(os.environ["GCLOUD_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\\n")

def save():
    state_path.write_text(json.dumps(state), encoding="utf-8")

def flag(prefix):
    return next(
        (argument.removeprefix(prefix) for argument in args
         if argument.startswith(prefix)),
        None,
    )

if args[:3] == ["config", "get-value", "account"]:
    print(
        os.environ.get(
            "ACTIVE_GCLOUD_ACCOUNT",
            "emilia-provisioner@emilia-ops.iam.gserviceaccount.com",
        )
    )
elif args[:2] == ["projects", "describe"]:
    if "--format=value(projectNumber)" in args:
        print("123456789")
elif args[:3] == ["iam", "service-accounts", "describe"]:
    if args[3] not in state["accounts"]:
        raise SystemExit(1)
elif args[:3] == ["iam", "service-accounts", "create"]:
    state["accounts"].append(
        args[3] + "@emilia-consequence-prod.iam.gserviceaccount.com"
    )
    save()
elif args[:3] == ["compute", "networks", "describe"]:
    if "--format=value(autoCreateSubnetworks)" in args:
        print("False")
elif args[:4] == ["compute", "networks", "subnets", "describe"]:
    if "--format=json" in args:
        print(
            json.dumps(
                {
                    "ipCidrRange": "10.42.0.0/26",
                    "network": (
                        "https://www.googleapis.com/compute/v1/projects/"
                        "emilia-consequence-prod/global/networks/emilia-runtime"
                    ),
                    "privateIpGoogleAccess": True,
                }
            )
        )
elif args[:2] == ["projects", "add-iam-policy-binding"]:
    role = flag("--role=")
    member = flag("--member=")
    binding = next(
        (
            item
            for item in state["policy"]["bindings"]
            if item.get("role") == role and not item.get("condition")
        ),
        None,
    )
    if binding is None:
        binding = {"role": role, "members": []}
        state["policy"]["bindings"].append(binding)
    if member not in binding["members"]:
        binding["members"].append(member)
    save()
elif args[:2] == ["projects", "get-iam-policy"]:
    print(json.dumps(state["policy"]))
elif args[:2] == ["projects", "set-iam-policy"]:
    desired = json.loads(
        Path(args[3]).read_text(encoding="utf-8")
    )
    if os.environ.get("PRESERVE_OWNER_AFTER_SET") == "true":
        desired["bindings"].append(
            {
                "role": "roles/owner",
                "members": [
                    (
                        "serviceAccount:emilia-provisioner@"
                        "emilia-ops.iam.gserviceaccount.com"
                    )
                ],
            }
        )
    state["policy"] = desired
    save()
""",
                encoding="utf-8",
            )
            fake_gcloud.chmod(0o755)
            result = self.run_script(
                provision_config(),
                "--apply",
                env={
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "GCLOUD_LOG": str(log),
                    "GCLOUD_STATE": str(state_path),
                    "PROVISIONING_APPROVED": "true",
                    "PROVISIONING_CONFIRM_PROJECT": (
                        "emilia-consequence-prod"
                    ),
                },
            )

            state = json.loads(state_path.read_text(encoding="utf-8"))
            calls = [
                json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()
            ]
            state_path.write_text(
                json.dumps(initial_state),
                encoding="utf-8",
            )
            log.write_text("", encoding="utf-8")
            sticky_owner = self.run_script(
                provision_config(),
                "--apply",
                env={
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "GCLOUD_LOG": str(log),
                    "GCLOUD_STATE": str(state_path),
                    "PROVISIONING_APPROVED": "true",
                    "PROVISIONING_CONFIRM_PROJECT": (
                        "emilia-consequence-prod"
                    ),
                    "PRESERVE_OWNER_AFTER_SET": "true",
                },
            )
            state_path.write_text(
                json.dumps(initial_state),
                encoding="utf-8",
            )
            log.write_text("", encoding="utf-8")
            wrong_identity = self.run_script(
                provision_config(),
                "--apply",
                env={
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "GCLOUD_LOG": str(log),
                    "GCLOUD_STATE": str(state_path),
                    "PROVISIONING_APPROVED": "true",
                    "PROVISIONING_CONFIRM_PROJECT": (
                        "emilia-consequence-prod"
                    ),
                    "ACTIVE_GCLOUD_ACCOUNT": "attacker@example.com",
                },
            )
            wrong_identity_calls = [
                json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()
            ]

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                set(state["accounts"]),
                {
                    (
                        "emilia-actuator@emilia-consequence-prod."
                        "iam.gserviceaccount.com"
                    ),
                    (
                        "emilia-decision@emilia-consequence-prod."
                        "iam.gserviceaccount.com"
                    ),
                    (
                        "emilia-bootstrap-actuator@emilia-consequence-prod."
                        "iam.gserviceaccount.com"
                    ),
                    (
                        "emilia-bootstrap-decision@emilia-consequence-prod."
                        "iam.gserviceaccount.com"
                    ),
                },
            )
            recovery_bindings = [
                binding
                for binding in state["policy"]["bindings"]
                if binding["role"] == recovery_role
            ]
            self.assertEqual(
                recovery_bindings,
                [
                    {
                        "role": recovery_role,
                        "members": [
                            "user:recovery-one@example.com",
                            "user:recovery-two@example.com",
                        ],
                    }
                ],
            )
            owner_members = {
                member
                for binding in state["policy"]["bindings"]
                if binding["role"] == "roles/owner"
                for member in binding["members"]
            }
            self.assertEqual(owner_members, set())
            self.assertFalse(
                any(
                    binding["role"] == "roles/owner"
                    for binding in state["policy"]["bindings"]
                )
            )
            exact_custom_bindings = {
                binding["role"]: binding["members"]
                for binding in state["policy"]["bindings"]
                if binding["role"].startswith(
                    "projects/emilia-consequence-prod/roles/"
                )
            }
            self.assertEqual(
                exact_custom_bindings[
                    (
                        "projects/emilia-consequence-prod/roles/"
                        "emiliaConsequenceProvisioner"
                    )
                ],
                [
                    (
                        "serviceAccount:emilia-provisioner@"
                        "emilia-ops.iam.gserviceaccount.com"
                    )
                ],
            )
            self.assertEqual(
                exact_custom_bindings[
                    (
                        "projects/emilia-consequence-prod/roles/"
                        "emiliaConsequenceDeployer"
                    )
                ],
                [
                    (
                        "serviceAccount:emilia-deployer@"
                        "emilia-ops.iam.gserviceaccount.com"
                    )
                ],
            )
            recovery_role_updates = [
                call
                for call in calls
                if call[:4]
                == ["iam", "roles", "update", "emiliaConsequenceRecovery"]
            ]
            self.assertEqual(len(recovery_role_updates), 1)
            permissions = next(
                argument
                for argument in recovery_role_updates[0]
                if argument.startswith("--permissions=")
            )
            for forbidden in (
                "iam.serviceAccounts.actAs",
                "run.routes.invoke",
                "secretmanager.versions.access",
            ):
                self.assertNotIn(forbidden, permissions)
            provisioner_binding = next(
                index
                for index, call in enumerate(calls)
                if call[:2] == ["projects", "add-iam-policy-binding"]
                and any(
                    argument.endswith(
                        "/roles/emiliaConsequenceProvisioner"
                    )
                    for argument in call
                )
            )
            first_identity_creation = next(
                index
                for index, call in enumerate(calls)
                if call[:3] == ["iam", "service-accounts", "create"]
            )
            self.assertTrue(
                any(
                    call[:2] == ["projects", "get-iam-policy"]
                    for call in calls[
                        provisioner_binding + 1:first_identity_creation
                    ]
                )
            )
            recovery_binding = max(
                index
                for index, call in enumerate(calls)
                if call[:2] == ["projects", "add-iam-policy-binding"]
                and any(
                    argument.endswith(
                        "/roles/emiliaConsequenceRecovery"
                    )
                    for argument in call
                )
            )
            owner_removal = next(
                index
                for index, call in enumerate(calls)
                if call[:2] == ["projects", "set-iam-policy"]
            )
            self.assertTrue(
                any(
                    call[:2] == ["projects", "get-iam-policy"]
                    for call in calls[recovery_binding + 1:owner_removal]
                )
            )
            self.assertNotEqual(sticky_owner.returncode, 0)
            self.assertIn("owner", sticky_owner.stderr)
            self.assertNotEqual(wrong_identity.returncode, 0)
            self.assertIn(
                "does not exactly match PROVISIONER_PRINCIPAL",
                wrong_identity.stderr,
            )
            self.assertEqual(
                wrong_identity_calls,
                [["config", "get-value", "account", "--quiet"]],
            )

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
        controls = {
            "DEPLOYMENT_APPROVED": "true",
            "PROVISIONING_APPROVED": "true",
            "PROVISIONING_CONFIRM_PROJECT": "emilia-consequence-prod",
            "ROLLOUT_APPROVED": "true",
            "ROLLOUT_CONFIRM_PROJECT": "emilia-consequence-prod",
            "JIT_ACTAS_EXPIRES_AT": "2099-01-01T00:00:00Z",
            "JIT_ACTIVE": "true",
            "JIT_MAX_TTL_SECONDS": "999999",
            "ATTACKER_APPROVED": "true",
            "ATTACKER_CONFIRM_PROJECT": "emilia-consequence-prod",
        }
        for name, value in controls.items():
            with self.subTest(name=name):
                result = self.run_script(
                    provision_config(**{name: value}),
                    "--render",
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "control variables must not be stored",
                    result.stderr,
                )

    def test_deployer_cannot_also_be_a_recovery_owner(self) -> None:
        result = self.run_script(
            provision_config(
                RECOVERY_PRINCIPALS=(
                    "serviceAccount:emilia-deployer@"
                    "emilia-ops.iam.gserviceaccount.com,"
                    "user:recovery-two@example.com"
                )
            ),
            "--render",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not be a recovery principal", result.stderr)

    def test_requires_two_distinct_recovery_principals(self) -> None:
        single = self.run_script(
            provision_config(
                RECOVERY_PRINCIPALS="user:recovery-one@example.com"
            ),
            "--render",
        )
        duplicate = self.run_script(
            provision_config(
                RECOVERY_PRINCIPALS=(
                    "user:recovery-one@example.com,"
                    "user:recovery-one@example.com"
                )
            ),
            "--render",
        )

        self.assertNotEqual(single.returncode, 0)
        self.assertIn(
            "at least two distinct RECOVERY_PRINCIPALS",
            single.stderr,
        )
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("duplicate recovery principal", duplicate.stderr)

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
                f"printf '%s\\n' \"$*\" >> {log!s}\n"
                "if [[ \"$1 $2 $3\" == "
                "\"config get-value account\" ]]; then\n"
                "  printf '%s\\n' "
                "'emilia-provisioner@emilia-ops.iam.gserviceaccount.com'\n"
                "fi\n",
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
