# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for transactional stable bootstrap mutations."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest


LANE = Path(__file__).resolve().parents[1]
BOOTSTRAP = LANE / "bootstrap-stable.sh"
LEGACY_FIXTURE = Path(__file__).with_name("test_stable_bootstrap.py")
ACTUATOR_SERVICE = "emilia-consequence-actuator"
DECISION_SERVICE = "emilia-consequence-control"


def load_legacy_fixture() -> unittest.TestCase:
    spec = importlib.util.spec_from_file_location(
        "_bootstrap_transaction_fixture",
        LEGACY_FIXTURE,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("stable bootstrap fixture cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = module.StableBootstrapTests(methodName="runTest")
    fixture.setUp()
    return fixture


class BootstrapTransactionalityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = load_legacy_fixture()
        config_lines = self.fixture.config.read_text(encoding="utf-8").splitlines()
        deduplicated: dict[str, str] = {}
        order: list[str] = []
        for line in config_lines:
            key = line.split("=", 1)[0] if "=" in line else line
            if key not in deduplicated:
                order.append(key)
            deduplicated[key] = line
        self.fixture.config.write_text(
            "\n".join(deduplicated[key] for key in order)
            + "\nEMILIA_IAM_ANALYZER_SCOPE=organizations/987654321\n",
            encoding="utf-8",
        )
        self.adapter_state = self.fixture.root / "attempt-store.json"
        self.adapter_log = self.fixture.root / "attempt-store.log"
        self.adapter = self.fixture.root / "attempt-store"
        self.adapter_state.write_text(
            json.dumps({"claims": {}, "terminals": {}}),
            encoding="utf-8",
        )
        self._write_attempt_store()
        self._upgrade_fake_gcloud()
        self._upgrade_fake_curl()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _write_attempt_store(self) -> None:
        self.adapter.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

operation = sys.argv[1]
payload = json.load(sys.stdin)
state_path = pathlib.Path(os.environ["FAKE_ATTEMPT_STATE"])
state = json.loads(state_path.read_text())
claim = payload if operation == "claim" else payload["claim"]
digest = claim["claim_sha256"]

with pathlib.Path(os.environ["FAKE_ATTEMPT_LOG"]).open("a") as handle:
    handle.write(json.dumps({
        "operation": operation,
        "claim_sha256": digest,
        "authorization_id": claim["authorization_id"],
        "service": claim["service"],
        "request_sha256": claim["request_sha256"],
        "pre_resource_version": claim["pre_resource_version"],
        "outcome": payload.get("outcome") if isinstance(payload, dict) else None,
    }, sort_keys=True) + "\\n")

if operation == "claim":
    if digest in state["claims"]:
        print("duplicate claim", file=sys.stderr)
        raise SystemExit(9)
    state["claims"][digest] = claim
    state_path.write_text(json.dumps(state, sort_keys=True))
    response = {
        "schema": "emilia-deployment-attempt-store-response.v1",
        "operation": "claim",
        "status": "claimed",
        "claim_sha256": digest,
        "final_resource_version": None,
    }
else:
    if digest not in state["claims"] or digest in state["terminals"]:
        print("claim is not terminalizable", file=sys.stderr)
        raise SystemExit(9)
    if (
        os.environ.get("FAKE_TERMINAL_FAILURE_SERVICE") == claim["service"]
        and not os.environ.get("FAKE_TERMINAL_FAILURE_USED")
    ):
        print("injected terminal failure", file=sys.stderr)
        raise SystemExit(10)
    status = (
        "completed"
        if operation == "complete"
        else payload["outcome"]
    )
    state["terminals"][digest] = {
        "operation": operation,
        "status": status,
        "final_resource_version": payload["final_resource_version"],
    }
    state_path.write_text(json.dumps(state, sort_keys=True))
    response = {
        "schema": "emilia-deployment-attempt-store-response.v1",
        "operation": operation,
        "status": status,
        "claim_sha256": digest,
        "final_resource_version": payload["final_resource_version"],
    }
print(json.dumps(response, sort_keys=True, separators=(",", ":")))
""",
            encoding="utf-8",
        )
        self.adapter.chmod(0o700)

    def _upgrade_fake_gcloud(self) -> None:
        executable = self.fixture.bin / "gcloud"
        source = executable.read_text(encoding="utf-8")
        old_deploy = """if args[:2] == ["run", "deploy"]:
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
"""
        new_deploy = """if args[:2] == ["run", "deploy"]:
    service = args[2]
    if service in state["deployed"]:
        print("service already exists", file=sys.stderr)
        raise SystemExit(8)
    labels_arg = next(
        (value for value in args if value.startswith("--labels=")),
        "",
    )
    labels = dict(
        item.split("=", 1)
        for item in labels_arg.removeprefix("--labels=").split(",")
        if item
    )
    state["deployed"].append(service)
    state.setdefault("deploy_labels", {})[service] = labels
    state.setdefault("service_labels", {})[service] = dict(labels)
    state.setdefault("generations", {})[service] = 1
    state.setdefault("resource_versions", {})[service] = "rv-" + service + "-1"
    state_path.write_text(json.dumps(state))
    if os.environ.get("FAKE_DEPLOY_RESPONSE_LOSS_SERVICE") == service:
        raise SystemExit(17)
    raise SystemExit(0)
if args[:3] == ["run", "services", "update-traffic"]:
    print("unlocked traffic mutation is forbidden", file=sys.stderr)
    raise SystemExit(88)
"""
        self.assertIn(old_deploy, source)
        source = source.replace(old_deploy, new_deploy)

        old_revision_labels = '''            "labels": {
                "serving.knative.dev/service": service,
                "emilia-plane": "bootstrap",
                "emilia-deny-all": "true",
                "emilia-permissionless": "true",
            },'''
        new_revision_labels = '''            "labels": {
                "serving.knative.dev/service": service,
                **state.get("deploy_labels", {}).get(service, {}),
            },'''
        self.assertIn(old_revision_labels, source)
        source = source.replace(old_revision_labels, new_revision_labels)

        old_service = '''if args[:3] == ["run", "services", "describe"]:
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
'''
        new_service = '''if args[:3] == ["run", "services", "describe"]:
    service = args[3]
    if service not in state["deployed"]:
        raise SystemExit(4)
    if "--format=value(status.url)" in args:
        print("https://" + service + ".example.test")
        raise SystemExit(0)
    ingress = "internal" if service.endswith("actuator") else "all"
    revision = service + "-bootstrap1"
    promoted = service in state["promoted"]
    generation = state.get("generations", {}).get(service, 1)
    resource_version = state.get("resource_versions", {}).get(
        service, "rv-" + service + "-1"
    )
    tagged = {
        "revisionName": revision,
        "percent": 0,
        "tag": "stable-bootstrap-bootstrap1",
        "url": "https://" + revision + ".example.test",
    }
    traffic = [tagged]
    if promoted:
        traffic.append({"revisionName": revision, "percent": 100})
    print(json.dumps({
        "apiVersion": "serving.knative.dev/v1",
        "kind": "Service",
        "metadata": {
            "name": service,
            "namespace": "123456789012",
            "generation": generation,
            "resourceVersion": resource_version,
            "labels": state.get("service_labels", {}).get(service, {}),
            "annotations": {"run.googleapis.com/ingress": ingress},
        },
        "spec": {"traffic": traffic},
        "status": {
            "url": "https://" + service + ".example.test",
            "observedGeneration": generation,
            "conditions": [{
                "type": "Ready",
                "status": "True",
                "lastTransitionTime": "2026-07-25T12:00:00Z",
            }],
            "traffic": traffic,
        },
    }))
    raise SystemExit(0)
'''
        self.assertIn(old_service, source)
        source = source.replace(old_service, new_service)
        old_token = '''if args[:2] == ["auth", "print-identity-token"]:
    print("test-identity-token")
    raise SystemExit(0)
'''
        new_token = '''if args[:2] == ["auth", "print-identity-token"]:
    print("test-identity-token")
    raise SystemExit(0)
if args[:2] == ["auth", "print-access-token"]:
    print("test-access-token")
    raise SystemExit(0)
'''
        self.assertIn(old_token, source)
        executable.write_text(source.replace(old_token, new_token), encoding="utf-8")
        executable.chmod(0o755)

    def _upgrade_fake_curl(self) -> None:
        executable = self.fixture.bin / "curl"
        executable.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
if "--request" in args and args[args.index("--request") + 1] == "PUT":
    output = pathlib.Path(args[args.index("--output") + 1])
    service = args[-1].rsplit("/", 1)[1]
    state_path = pathlib.Path(os.environ["FAKE_STATE"])
    state = json.loads(state_path.read_text())
    body = json.load(sys.stdin)
    current = state["resource_versions"][service]
    if body["metadata"]["resourceVersion"] != current:
        output.write_text('{"error":"resourceVersion conflict"}')
        raise SystemExit(22)
    if os.environ.get("FAKE_PUT_FAIL_SERVICE") == service:
        output.write_text('{"error":"injected failure"}')
        raise SystemExit(22)
    generation = state["generations"][service] + 1
    resource_version = "rv-" + service + "-" + str(generation)
    state["generations"][service] = generation
    state["resource_versions"][service] = resource_version
    state.setdefault("service_labels", {})[service] = body["metadata"]["labels"]
    if service not in state["promoted"]:
        state["promoted"].append(service)
    state_path.write_text(json.dumps(state))
    response = {
        **body,
        "metadata": {
            **body["metadata"],
            "generation": generation,
            "resourceVersion": resource_version,
        },
        "status": {
            "observedGeneration": generation,
            "conditions": [{"type": "Ready", "status": "True"}],
            "traffic": body["spec"]["traffic"],
        },
    }
    output.write_text(json.dumps(response))
    if os.environ.get("FAKE_PUT_RESPONSE_LOSS_SERVICE") == service:
        output.unlink()
        raise SystemExit(56)
    raise SystemExit(0)

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
        adapter_hash = hashlib.sha256(self.adapter.read_bytes()).hexdigest()
        return self.fixture.environment(
            DEPLOYMENT_APPROVED="true",
            DEPLOYMENT_CONFIRM_PROJECT="test-project",
            EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER=str(self.adapter),
            EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER_SHA256=adapter_hash,
            FAKE_ATTEMPT_STATE=str(self.adapter_state),
            FAKE_ATTEMPT_LOG=str(self.adapter_log),
            **extra,
        )

    def run_bootstrap(
        self,
        *,
        arguments: list[str] | None = None,
        **environment: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(BOOTSTRAP),
                *(arguments or self.fixture.arguments()),
                "--apply",
            ],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(**environment),
        )

    def gcloud_calls(self) -> list[list[str]]:
        if not self.fixture.log_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.fixture.log_path.read_text(
                encoding="utf-8"
            ).splitlines()
        ]

    def attempt_events(self) -> list[dict[str, object]]:
        if not self.adapter_log.exists():
            return []
        return [
            json.loads(line)
            for line in self.adapter_log.read_text(
                encoding="utf-8"
            ).splitlines()
        ]

    def test_render_signs_and_claims_before_any_cloud_mutation(self) -> None:
        result = subprocess.run(
            [str(BOOTSTRAP), *self.fixture.arguments(), "--render"],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env=self.environment(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("authorize-bootstrap", result.stdout)
        self.assertIn("attempt-store", result.stdout)
        self.assertLess(
            result.stdout.index("authorize-bootstrap"),
            result.stdout.index("gcloud run deploy"),
        )
        self.assertNotIn("run services update-traffic", result.stdout)
        self.assertIn("resourceVersion-locked", result.stdout)

    def test_signing_failure_precedes_every_mutation(self) -> None:
        hostile_key = self.fixture.root / "hostile-private.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(hostile_key),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        hostile_key.chmod(0o600)
        arguments = self.fixture.arguments()
        arguments[arguments.index(str(self.fixture.private_key))] = str(hostile_key)
        result = self.run_bootstrap(arguments=arguments)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            any(call[:2] == ["run", "deploy"] for call in self.gcloud_calls())
        )
        self.assertEqual(self.attempt_events(), [])

    def test_response_loss_is_reconciled_without_reexecution(self) -> None:
        result = self.run_bootstrap(
            FAKE_PUT_RESPONSE_LOSS_SERVICE=ACTUATOR_SERVICE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.fixture.state_path.read_text(encoding="utf-8"))
        self.assertEqual(
            state["promoted"],
            [ACTUATOR_SERVICE, DECISION_SERVICE],
        )
        actuator_terminals = [
            event
            for event in self.attempt_events()
            if event["service"] == ACTUATOR_SERVICE
            and event["operation"] in {"complete", "reconcile"}
        ]
        self.assertTrue(
            any(
                event["operation"] == "reconcile"
                and event["outcome"] == "applied"
                for event in actuator_terminals
            )
        )
        self.assertFalse(
            any(
                call[:3] == ["run", "services", "update-traffic"]
                for call in self.gcloud_calls()
            )
        )

    def test_failure_between_planes_is_safe_to_retry(self) -> None:
        first = self.run_bootstrap(FAKE_PUT_FAIL_SERVICE=DECISION_SERVICE)
        self.assertNotEqual(first.returncode, 0)
        state = json.loads(self.fixture.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["promoted"], [ACTUATOR_SERVICE])
        self.assertFalse(self.fixture.output.exists())

        second = self.run_bootstrap()
        self.assertEqual(second.returncode, 0, second.stderr)
        state = json.loads(self.fixture.state_path.read_text(encoding="utf-8"))
        self.assertEqual(
            state["promoted"],
            [ACTUATOR_SERVICE, DECISION_SERVICE],
        )
        deploy_calls = [
            call for call in self.gcloud_calls() if call[:2] == ["run", "deploy"]
        ]
        self.assertEqual(len(deploy_calls), 2)
        actuator_reconciliations = [
            event
            for event in self.attempt_events()
            if event["service"] == ACTUATOR_SERVICE
            and event["operation"] == "reconcile"
            and event["outcome"] == "applied"
        ]
        self.assertTrue(actuator_reconciliations)
        self.assertTrue(self.fixture.output.is_file())


if __name__ == "__main__":
    unittest.main()
