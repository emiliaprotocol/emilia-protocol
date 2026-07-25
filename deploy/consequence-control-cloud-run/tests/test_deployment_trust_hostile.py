from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


LANE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LANE / "tests"))
COMMON = LANE / "lib" / "common.sh"
DEPLOY = LANE / "deploy.sh"
TRAFFIC = LANE / "traffic.sh"
FIXTURE = LANE / "tests" / "fixture.env"
ROLLOUT = LANE / "verify-rollout-telemetry.py"
STABLE = LANE / "verify-stable-release.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ConfigBoundaryHostileTests(unittest.TestCase):
    def run_deploy(
        self,
        config: Path,
        *arguments: str,
        config_hash: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PROJECT_PARENT": "organizations/987654321",
        }
        if config_hash is not None:
            environment["DEPLOYMENT_CONFIG_SHA256"] = config_hash
        else:
            environment.pop("DEPLOYMENT_CONFIG_SHA256", None)
        return subprocess.run(
            [str(DEPLOY), "--config", str(config), *arguments],
            cwd=LANE,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def test_config_cannot_overwrite_path_action_thresholds_or_artifacts(
        self,
    ) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        hostile = {
            "PATH": "/attacker",
            "ACTION": "apply-actuator-100",
            "MAX_ERROR_RATE": "1",
            "ROLLOUT_POLL_ATTEMPTS": "1",
            "UPDATE_BODY": "/attacker/request.json",
            "AUTHORIZATION": "/attacker/authorization.json",
            "UNRELATED_SWITCH": "enabled",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for key, value in hostile.items():
                config = root / f"{key.lower()}.env"
                config.write_text(
                    f"{source}\n{key}={value}\n",
                    encoding="utf-8",
                )
                with self.subTest(key=key):
                    result = self.run_deploy(config, "--render")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("not allowed", result.stderr)

    def test_mutating_deploy_requires_protected_config_hash_before_cloud_use(
        self,
    ) -> None:
        result = self.run_deploy(FIXTURE, "--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "DEPLOYMENT_CONFIG_SHA256 must be injected by a protected source",
            result.stderr,
        )
        self.assertNotIn("GITHUB_ACTIONS", result.stderr)

    def test_every_mutating_entrypoint_requires_the_protected_config_hash(
        self,
    ) -> None:
        placeholder = (
            "us-central1-docker.pkg.dev/test-project/runtime/deny-all@sha256:"
            + "7" * 64
        )
        commands = (
            [
                str(LANE / "provision-dedicated-project.sh"),
                "--config",
                str(FIXTURE),
                "--apply",
            ],
            [
                str(LANE / "bootstrap-stable.sh"),
                "--config",
                str(FIXTURE),
                "--bootstrap-id",
                "bootstrap1",
                "--placeholder-image",
                placeholder,
                "--output",
                "/tmp/emilia-hostile-stable.json",
                "--apply",
            ],
            [
                str(TRAFFIC),
                "--config",
                str(FIXTURE),
                "--stable-manifest",
                "/tmp/emilia-hostile-stable.json",
                "--apply-rollback",
            ],
        )
        environment = {**os.environ}
        environment.pop("DEPLOYMENT_CONFIG_SHA256", None)
        for command in commands:
            with self.subTest(command=command[0]):
                result = subprocess.run(
                    command,
                    cwd=LANE,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "DEPLOYMENT_CONFIG_SHA256 must be injected",
                    result.stderr,
                )

    def test_config_is_single_open_no_follow_and_retained_as_private_bytes(
        self,
    ) -> None:
        source = COMMON.read_text(encoding="utf-8")
        for required in (
            "O_NOFOLLOW",
            "LANE_PINNED_CONFIG_BASE64",
            "LANE_PINNED_CONFIG",
            "lane_emit_pinned_config",
        ):
            self.assertIn(required, source)
        self.assertNotIn('done < "$LANE_PINNED_CONFIG"', source)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.env"
            config.write_text("PROJECT_ID=test-project\n", encoding="utf-8")
            link = root / "config-link.env"
            link.symlink_to(config)
            digest = hashlib.sha256(config.read_bytes()).hexdigest()
            command = (
                f"source {COMMON!s}; "
                "REQUIRE_DEPLOYMENT_CONFIG_PIN=true; "
                f"DEPLOYMENT_CONFIG_SHA256={digest}; "
                f"load_lane_config {link!s} PROJECT_ID"
            )
            result = subprocess.run(
                ["bash", "-c", command],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-symlink", result.stderr)

    def test_same_uid_path_replacement_cannot_change_retained_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.env"
            original = b"PROJECT_ID=test-project\n"
            config.write_bytes(original)
            digest = hashlib.sha256(original).hexdigest()
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    """
source "$1"
REQUIRE_DEPLOYMENT_CONFIG_PIN=true
DEPLOYMENT_CONFIG_SHA256=$3
load_lane_config "$2" PROJECT_ID
printf 'PROJECT_ID=attacker\\n' > "$2"
[[ "$PROJECT_ID" == test-project ]]
[[ "$(lane_emit_pinned_config)" == "PROJECT_ID=test-project" ]]
verify_lane_config_pin
""",
                    "bash",
                    str(COMMON),
                    str(config),
                    digest,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


class FileTrustHostileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rollout = load_module("hostile_rollout", ROLLOUT)
        self.stable = load_module("hostile_stable", STABLE)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def telemetry_config(self, path: Path) -> dict[str, str]:
        return {
            "ROLLOUT_TELEMETRY_KEY_ID": "telemetry-key",
            "ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE": str(path),
            "ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256": hashlib.sha256(
                path.read_bytes()
            ).hexdigest(),
        }

    def test_file_trust_rejects_symlinks_and_group_or_world_writable_keys(
        self,
    ) -> None:
        key = self.root / "telemetry.pem"
        key.write_bytes(b"trusted telemetry key bytes")
        link = self.root / "telemetry-link.pem"
        link.symlink_to(key)
        with self.assertRaisesRegex(self.rollout.TelemetryError, "non-symlink"):
            self.rollout.load_telemetry_trust(self.telemetry_config(link))

        key.chmod(0o666)
        with self.assertRaisesRegex(self.rollout.TelemetryError, "mode"):
            self.rollout.load_telemetry_trust(self.telemetry_config(key))

    def test_stable_file_trust_does_not_reopen_a_swapped_path(self) -> None:
        key = self.root / "stable.pem"
        original = b"original stable trust bytes"
        attacker = b"attacker replacement bytes"
        key.write_bytes(original)
        config = {
            "STABLE_RELEASE_KEY_ID": "stable-key",
            "STABLE_RELEASE_PUBLIC_KEY_FILE": str(key),
            "STABLE_RELEASE_PUBLIC_KEY_SHA256": hashlib.sha256(
                original
            ).hexdigest(),
        }
        validate = self.stable.validate_trust_config

        def swap_after_validation(value: dict[str, str]):
            trust = validate(value)
            key.unlink()
            key.write_bytes(attacker)
            return trust

        with mock.patch.object(
            self.stable,
            "validate_trust_config",
            side_effect=swap_after_validation,
        ):
            trusted, _ = self.stable.trusted_public_key(config, None)
        self.assertEqual(trusted, original)

    def test_authorization_and_telemetry_cannot_share_a_root(self) -> None:
        key = self.root / "shared.pem"
        key.write_bytes(b"one root is not two independent roots")
        digest = hashlib.sha256(key.read_bytes()).hexdigest()
        config = {
            "ROLLOUT_TELEMETRY_KEY_ID": "telemetry-key",
            "ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE": str(key),
            "ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256": digest,
            "ROLLOUT_AUTHORIZATION_KEY_ID": "authorization-key",
            "ROLLOUT_AUTHORIZATION_PUBLIC_KEY_FILE": str(key),
            "ROLLOUT_AUTHORIZATION_PUBLIC_KEY_SHA256": digest,
        }
        with self.assertRaisesRegex(
            self.rollout.TelemetryError,
            "must be distinct",
        ):
            self.rollout.load_rollout_trusts(config)

    def test_same_ed25519_key_in_pem_and_der_is_not_two_roots(self) -> None:
        private_key = self.root / "shared-private.pem"
        public_pem = self.root / "shared-public.pem"
        public_der = self.root / "shared-public.der"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_pem),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-in",
                str(public_pem),
                "-outform",
                "DER",
                "-out",
                str(public_der),
            ],
            check=True,
            capture_output=True,
        )
        self.assertNotEqual(public_pem.read_bytes(), public_der.read_bytes())
        config = {
            "ROLLOUT_TELEMETRY_KEY_ID": "telemetry-key",
            "ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE": str(public_pem),
            "ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256": hashlib.sha256(
                public_pem.read_bytes()
            ).hexdigest(),
            "ROLLOUT_AUTHORIZATION_KEY_ID": "authorization-key",
            "ROLLOUT_AUTHORIZATION_PUBLIC_KEY_FILE": str(public_der),
            "ROLLOUT_AUTHORIZATION_PUBLIC_KEY_SHA256": hashlib.sha256(
                public_der.read_bytes()
            ).hexdigest(),
        }
        with self.assertRaisesRegex(
            self.rollout.TelemetryError,
            "must be distinct",
        ):
            self.rollout.load_rollout_trusts(config)


class AuthorizationAndMutationHostileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rollout = load_module("hostile_authorization", ROLLOUT)

    @staticmethod
    def closed_context() -> dict:
        from test_rollout_telemetry import rollout_context

        context = rollout_context()
        context["deployment"] = {
            "config_sha256": "a" * 64,
            "deployer_principal": (
                "serviceAccount:emilia-deployer@"
                "test-project.iam.gserviceaccount.com"
            ),
            "workflow_ref": (
                "emiliaprotocol/emilia-protocol/.github/workflows/"
                "consequence-control-deploy.yml@refs/heads/main"
            ),
            "workflow_sha": "b" * 40,
            "wif_provider": (
                "projects/123456789/locations/global/"
                "workloadIdentityPools/emilia-prod/providers/github-prod"
            ),
        }
        context["request"] = {
            "service": "decision",
            "sha256": "c" * 64,
            "pre_resource_version": "rv-decision-7",
        }
        return context

    def test_authorization_binds_protected_identity_config_and_final_body(
        self,
    ) -> None:
        context = self.closed_context()
        self.assertEqual(
            self.rollout.validate_rollout_context(context),
            context,
        )
        for field in ("deployment", "request"):
            hostile = dict(context)
            hostile.pop(field)
            with self.subTest(field=field):
                with self.assertRaises(self.rollout.TelemetryError):
                    self.rollout.validate_rollout_context(hostile)

        config = {
            "PROJECT_ID": "test-project",
            "REGION": "us-central1",
            "RELEASE_ID": "r2",
            "DEPLOYER_PRINCIPAL": context["deployment"]["deployer_principal"],
            "ACTUATOR_SERVICE": "actuator",
            "DECISION_SERVICE": "decision",
            "ACTUATOR_IMAGE": context["candidate"]["actuator"]["image"],
            "DECISION_IMAGE": context["candidate"]["decision"]["image"],
            "ACTUATOR_STABLE_REVISION": "actuator-r1",
            "DECISION_STABLE_REVISION": "decision-r1",
        }
        wrong_deployer = deepcopy(context)
        wrong_deployer["deployment"]["deployer_principal"] = (
            "serviceAccount:attacker@test-project.iam.gserviceaccount.com"
        )
        with mock.patch.dict(
            os.environ,
            {"DEPLOYMENT_CONFIG_SHA256": "a" * 64},
            clear=False,
        ):
            with self.assertRaisesRegex(
                self.rollout.TelemetryError,
                "deployer_principal",
            ):
                self.rollout.validate_context_deployment(
                    wrong_deployer,
                    config,
                )

    def test_authorization_and_telemetry_have_distinct_roots_and_domains(
        self,
    ) -> None:
        unsigned_telemetry = {
            "schema": self.rollout.TELEMETRY_SCHEMA,
            "context": self.closed_context(),
            "authorization_sha256": "d" * 64,
            "window": {
                "started_at": "2026-07-25T12:00:00Z",
                "ended_at": "2026-07-25T12:10:00Z",
            },
            "services": {},
        }
        unsigned_authorization = {
            "schema": self.rollout.AUTHORIZATION_SCHEMA,
            "context": self.closed_context(),
            "consumption": {
                "state": "consumed",
                "consumed_at": "2026-07-25T12:00:00Z",
                "expires_at": "2026-07-25T12:15:00Z",
            },
        }
        telemetry_bytes = self.rollout.canonical_unsigned_telemetry(
            unsigned_telemetry
        )
        authorization_bytes = self.rollout.canonical_unsigned_authorization(
            unsigned_authorization
        )
        self.assertTrue(telemetry_bytes.startswith(b"EMILIA-ROLLOUT-TELEMETRY"))
        self.assertTrue(
            authorization_bytes.startswith(b"EMILIA-ROLLOUT-AUTHORIZATION")
        )
        self.assertNotEqual(
            telemetry_bytes.split(b"\x00", 1)[0],
            authorization_bytes.split(b"\x00", 1)[0],
        )
        source = ROLLOUT.read_text(encoding="utf-8")
        for required in (
            "ROLLOUT_AUTHORIZATION_KEY_ID",
            "ROLLOUT_AUTHORIZATION_PUBLIC_KEY_FILE",
            "ROLLOUT_AUTHORIZATION_PUBLIC_KEY_SHA256",
        ):
            self.assertIn(required, source)

    def test_attempt_claim_is_exact_one_time_and_precedes_request_send(
        self,
    ) -> None:
        context = self.closed_context()
        claim = self.rollout.build_attempt_claim(context)
        self.assertEqual(claim["authorization_id"], context["authorization_id"])
        self.assertEqual(claim["rollout_nonce"], context["rollout_nonce"])
        self.assertEqual(claim["request_sha256"], context["request"]["sha256"])
        self.assertEqual(
            claim["pre_resource_version"],
            context["request"]["pre_resource_version"],
        )
        traffic = TRAFFIC.read_text(encoding="utf-8")
        apply_body = traffic.split("apply_prepared_update() {", 1)[1].split(
            "\n}",
            1,
        )[0]
        self.assertLess(
            apply_body.index("claim_deployment_attempt"),
            apply_body.index("send_locked_update"),
        )
        self.assertIn("reconcile_ambiguous_update", traffic)

    def test_replayed_or_misbinding_attempt_store_responses_fail_closed(
        self,
    ) -> None:
        context = self.closed_context()
        claim = self.rollout.build_attempt_claim(context)
        for field, value in (
            ("authorization_id", "authorization:other"),
            ("rollout_nonce", "bm9uY2Utcm9sbG91dC01MC0wMDAy"),
        ):
            hostile = deepcopy(context)
            hostile[field] = value
            with self.subTest(field=field):
                self.assertNotEqual(
                    self.rollout.build_attempt_claim(hostile)["claim_sha256"],
                    claim["claim_sha256"],
                )
        hostile = deepcopy(context)
        hostile["request"]["sha256"] = "9" * 64
        self.assertNotEqual(
            self.rollout.build_attempt_claim(hostile)["claim_sha256"],
            claim["claim_sha256"],
        )
        hostile = deepcopy(context)
        hostile["request"]["pre_resource_version"] = "rv-decision-8"
        hostile["pre_state"]["decision"]["resource_version"] = "rv-decision-8"
        self.assertNotEqual(
            self.rollout.build_attempt_claim(hostile)["claim_sha256"],
            claim["claim_sha256"],
        )

        accepted = {
            "schema": self.rollout.ATTEMPT_STORE_RESPONSE_SCHEMA,
            "operation": "claim",
            "status": "claimed",
            "claim_sha256": claim["claim_sha256"],
            "final_resource_version": None,
        }
        self.assertEqual(
            self.rollout.validate_attempt_store_response(
                accepted,
                operation="claim",
                claim_sha256=claim["claim_sha256"],
                allowed_statuses={"claimed"},
            ),
            accepted,
        )
        attacks = (
            {**accepted, "status": "already-claimed"},
            {**accepted, "claim_sha256": "0" * 64},
            {**accepted, "operation": "complete"},
            {**accepted, "final_resource_version": "rv-attacker"},
        )
        for response in attacks:
            with self.subTest(response=response):
                with self.assertRaises(self.rollout.TelemetryError):
                    self.rollout.validate_attempt_store_response(
                        response,
                        operation="claim",
                        claim_sha256=claim["claim_sha256"],
                        allowed_statuses={"claimed"},
                    )

    def test_attempt_terminal_response_must_echo_exact_expected_post_version(
        self,
    ) -> None:
        claim = self.rollout.build_attempt_claim(self.closed_context())
        accepted = {
            "schema": self.rollout.ATTEMPT_STORE_RESPONSE_SCHEMA,
            "operation": "complete",
            "status": "completed",
            "claim_sha256": claim["claim_sha256"],
            "final_resource_version": "rv-decision-8",
        }
        self.assertEqual(
            self.rollout.validate_attempt_store_response(
                accepted,
                operation="complete",
                claim_sha256=claim["claim_sha256"],
                allowed_statuses={"completed"},
                expected_final_resource_version="rv-decision-8",
            ),
            accepted,
        )
        with self.assertRaisesRegex(
            self.rollout.TelemetryError,
            "resourceVersion",
        ):
            self.rollout.validate_attempt_store_response(
                {**accepted, "final_resource_version": "rv-attacker"},
                operation="complete",
                claim_sha256=claim["claim_sha256"],
                allowed_statuses={"completed"},
                expected_final_resource_version="rv-decision-8",
            )
        traffic = TRAFFIC.read_text(encoding="utf-8")
        self.assertIn(
            '--expected-final-resource-version "$expected_resource_version"',
            traffic,
        )

    def test_prepared_body_is_held_in_memory_and_streamed_without_path_reread(
        self,
    ) -> None:
        traffic = TRAFFIC.read_text(encoding="utf-8")
        self.assertIn("UPDATE_BODY_BASE64", traffic)
        self.assertIn("REQUEST_SHA256", traffic)
        self.assertNotIn('--data-binary "@$UPDATE_BODY"', traffic)
        self.assertIn("--data-binary @-", traffic)

        from test_rollout_telemetry import service_document

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "service.json"
            snapshot.write_text(
                json.dumps(
                    service_document(
                        "decision",
                        {"decision-r2": 10, "decision-r1": 90},
                        resource_version="rv-decision-7",
                    )
                ),
                encoding="utf-8",
            )
            prepared = subprocess.run(
                [
                    sys.executable,
                    str(ROLLOUT),
                    "prepare-update",
                    "--input",
                    str(snapshot),
                    "--service",
                    "decision",
                    "--expect-traffic",
                    "decision-r2:10,decision-r1:90",
                    "--target-traffic",
                    "decision-r2:50,decision-r1:50",
                    "--allowed-revision",
                    "decision-r1",
                    "--allowed-revision",
                    "decision-r2",
                    "--emit-base64",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        generation, resource_version, digest, encoded = (
            prepared.stdout.strip().split("\t")
        )
        body = base64.b64decode(encoded, validate=True)
        self.assertEqual(generation, "7")
        self.assertEqual(resource_version, "rv-decision-7")
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        self.assertEqual(
            json.loads(body)["metadata"]["resourceVersion"],
            "rv-decision-7",
        )

    def test_traffic_proves_protected_workflow_deployer_and_update_custody(
        self,
    ) -> None:
        traffic = TRAFFIC.read_text(encoding="utf-8")
        apply_body = traffic.split("apply_prepared_update() {", 1)[1].split(
            "\n}",
            1,
        )[0]
        for required in (
            "require_protected_traffic_identity",
            "verify_direct_traffic_custody",
            "run.services.update",
            "GITHUB_WORKFLOW_REF",
            "EMILIA_DEPLOY_WIF_PROVIDER",
        ):
            self.assertIn(required, traffic)
        self.assertLess(
            apply_body.index("verify_direct_traffic_custody"),
            apply_body.index("claim_deployment_attempt"),
        )

    def test_final_post_validation_is_locked_to_ack_resource_version(
        self,
    ) -> None:
        traffic = TRAFFIC.read_text(encoding="utf-8")
        poll = traffic.split("poll_exact_post_state() {", 1)[1].split(
            "\n}",
            1,
        )[0]
        final = traffic.split("verify_post_target_state() {", 1)[1].split(
            "\n}",
            1,
        )[0]
        for body in (poll, final):
            self.assertIn(
                '--resource-version-equals "$ACK_RESOURCE_VERSION"',
                body,
            )
            self.assertNotIn(
                '--resource-version-not "$LOCK_RESOURCE_VERSION"',
                body,
            )

        from test_rollout_telemetry import service_document

        changed = service_document(
            "decision",
            {"decision-r2": 50, "decision-r1": 50},
            generation=8,
            resource_version="rv-concurrent-write",
        )
        with self.assertRaisesRegex(
            self.rollout.TelemetryError,
            "resourceVersion",
        ):
            self.rollout.evaluate_service_state(
                changed,
                service="decision",
                expected_traffic={"decision-r2": 50, "decision-r1": 50},
                allowed_revisions={"decision-r1", "decision-r2"},
                generation_equals=8,
                resource_version_equals="rv-acknowledged",
            )


class CommandSpecificConfigHostileTests(unittest.TestCase):
    def config_keys(self, function: str) -> set[str]:
        result = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; "$2"',
                "bash",
                str(COMMON),
                function,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return set(result.stdout.splitlines())

    def test_each_mutating_command_has_a_distinct_closed_config_schema(
        self,
    ) -> None:
        deploy = self.config_keys("deploy_config_variables")
        traffic = self.config_keys("traffic_config_variables")
        bootstrap = self.config_keys("bootstrap_config_variables")
        provision = self.config_keys("provision_config_variables")
        self.assertNotEqual(deploy, traffic)
        self.assertNotEqual(deploy, bootstrap)
        self.assertNotEqual(deploy, provision)
        self.assertIn("ACTUATOR_STABLE_REVISION", traffic)
        self.assertNotIn("ACTUATOR_STABLE_REVISION", deploy)
        self.assertIn("STABLE_BOOTSTRAP_ALLOWED_DIGESTS", bootstrap)
        self.assertNotIn("STABLE_BOOTSTRAP_ALLOWED_DIGESTS", traffic)
        self.assertIn("BILLING_ACCOUNT", provision)
        self.assertNotIn("BILLING_ACCOUNT", deploy)

    def test_deploy_rejects_a_provision_only_config_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "deploy.env"
            config.write_text(
                FIXTURE.read_text(encoding="utf-8")
                + "\nBILLING_ACCOUNT=000000-000000-000000\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(DEPLOY), "--config", str(config), "--render"],
                cwd=LANE,
                text=True,
                capture_output=True,
                check=False,
                env={
                    **os.environ,
                    "PROJECT_PARENT": "organizations/987654321",
                },
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not allowed for this command", result.stderr)

    def test_workflow_pins_separate_deploy_bootstrap_and_traffic_profiles(
        self,
    ) -> None:
        workflow = (
            LANE.parent.parent
            / ".github"
            / "workflows"
            / "consequence-control-deploy.yml"
        ).read_text(encoding="utf-8")
        for required in (
            "CONSEQUENCE_CONTROL_DEPLOY_CONFIG",
            "CONSEQUENCE_CONTROL_DEPLOY_CONFIG_SHA256",
            "CONSEQUENCE_CONTROL_BOOTSTRAP_CONFIG",
            "CONSEQUENCE_CONTROL_BOOTSTRAP_CONFIG_SHA256",
            "CONSEQUENCE_CONTROL_TRAFFIC_CONFIG",
            "CONSEQUENCE_CONTROL_TRAFFIC_CONFIG_SHA256",
            "CONSEQUENCE_CONTROL_STABLE_MANIFEST",
            "CONSEQUENCE_CONTROL_ROLLOUT_AUTHORIZATION",
            "CONSEQUENCE_CONTROL_CANARY_EVIDENCE",
            "CONSEQUENCE_CONTROL_ROLLOUT_TELEMETRY",
        ):
            self.assertIn(required, workflow)
        self.assertNotIn(
            "secrets.CONSEQUENCE_CONTROL_CONFIG }}",
            workflow,
        )
        self.assertNotIn(
            "vars.CONSEQUENCE_CONTROL_CONFIG_SHA256 }}",
            workflow,
        )

    def test_protected_workflow_exposes_every_guarded_traffic_transition(
        self,
    ) -> None:
        workflow = (
            LANE.parent.parent
            / ".github"
            / "workflows"
            / "consequence-control-deploy.yml"
        ).read_text(encoding="utf-8")
        for operation in (
            "apply-decision-1",
            "apply-decision-10",
            "apply-decision-50",
            "apply-decision-100",
            "apply-actuator-100",
            "apply-rollback",
        ):
            self.assertIn(f"- {operation}", workflow)
        self.assertIn(
            "deploy/consequence-control-cloud-run/traffic.sh",
            workflow,
        )
        self.assertIn('case "$TRAFFIC_OPERATION" in', workflow)
        self.assertIn('"--$TRAFFIC_OPERATION"', workflow)
        self.assertIn("environment: consequence-control-production", workflow)


if __name__ == "__main__":
    unittest.main()
