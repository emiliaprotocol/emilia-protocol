from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


LANE = Path(__file__).resolve().parents[1]
DRIVER = LANE / "run-canary.py"
FIXTURE_CONFIG = LANE / "tests" / "fixture.env"
DIGEST = "sha256:" + "c" * 64
EXACT_ATTEMPT = {
    "tenant_id": "tenant:test",
    "provider_id": "github",
    "provider_account_id": "example",
    "environment": "production-smoke",
    "attempt_id": "attempt:exact-canary",
    "request_digest": "sha256:" + "d" * 64,
}
TIMEOUT_ATTEMPT = {
    **EXACT_ATTEMPT,
    "attempt_id": "attempt:timeout-canary",
    "request_digest": "sha256:" + "e" * 64,
}


def proposal(proposal_id: str, profile_id: str, attempt: dict) -> dict:
    return {
        "@version": "EMILIA-PROPOSAL-TO-EFFECT-v1",
        "proposal_id": proposal_id,
        "operation_id": proposal_id.replace("proposal:", "operation:"),
        "profile_id": profile_id,
        "action": {
            "action_type": "github.issue.update.1",
            "owner": "example",
            "repo": "canary",
            "issue_number": 1,
            "title": f"Canary {proposal_id}",
            "body": "Executable canary body",
        },
        "aeb_action_digest": DIGEST,
        "consequence": {
            key: attempt[key]
            for key in (
                "tenant_id",
                "provider_id",
                "provider_account_id",
                "environment",
                "request_digest",
            )
        },
    }


def scenario() -> dict:
    exact = proposal(
        "proposal:exact-canary",
        "github.issue.update.v1",
        EXACT_ATTEMPT,
    )
    timeout = proposal(
        "proposal:timeout-canary",
        "github.issue.update.indeterminate-smoke.v1",
        TIMEOUT_ATTEMPT,
    )
    return {
        "exact_execution": {
            "proposal_id": exact["proposal_id"],
            "request": {
                "proposal": exact,
                "receipt": {"@version": "EP-RECEIPT-v1"},
                "evaluation": {"verdict": "SATISFIED"},
                "evidence": {"artifacts": {}, "statuses": {}},
            },
        },
        "timeout": {
            "proposal_id": timeout["proposal_id"],
            "request": {
                "proposal": timeout,
                "receipt": {"@version": "EP-RECEIPT-v1"},
                "evaluation": {"verdict": "SATISFIED"},
                "evidence": {"artifacts": {}, "statuses": {}},
            },
        },
    }


class FakeDecision:
    def __init__(
        self,
        *,
        replay_reason: str = "envelope_replayed",
        reconciliation_reason: str = "github_attempt_attribution_unavailable",
    ) -> None:
        self.replay_reason = replay_reason
        self.reconciliation_reason = reconciliation_reason
        self.requests: list[dict] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def handler(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def send(self, status: int, body: dict) -> None:
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:
                length = int(self.headers.get("content-length", "0"))
                body = json.loads(self.rfile.read(length))
                fixture.requests.append(
                    {
                        "path": self.path,
                        "body": body,
                        "authorization": self.headers.get("authorization"),
                        "identity": self.headers.get("x-serverless-authorization"),
                    }
                )
                if self.path.endswith("/proposal:exact-canary/execute"):
                    self.send(
                        200,
                        {
                            "status": "completed",
                            "result": {
                                "ok": True,
                                "proposal": body["proposal"],
                                "consequence": {
                                    "state": "COMMITTED",
                                    "attempt": EXACT_ATTEMPT,
                                },
                                "effect": {
                                    "provider_status": 200,
                                    "provider_reference": "github:issue:example/canary#1",
                                    "actuator_observation": {
                                        "payload": {
                                            "outcome": "COMMITTED",
                                            "action_digest": DIGEST,
                                            "attempt_id": EXACT_ATTEMPT["attempt_id"],
                                            "provider_reference": (
                                                "github:issue:example/canary#1"
                                            ),
                                        }
                                    },
                                },
                            },
                        },
                    )
                    return
                if self.path.endswith("/proposal:timeout-canary/attempts/lookup"):
                    self.send(
                        200,
                        {
                            "status": "found",
                            "state": "INDETERMINATE",
                            "attempt": TIMEOUT_ATTEMPT,
                        },
                    )
                    return
                if self.path.endswith("/proposal:timeout-canary/reconcile"):
                    self.send(
                        200,
                        {
                            "status": "reconciled",
                            "result": {
                                "ok": True,
                                "state": "ESCALATED",
                                "outcome": "ESCALATED",
                                "reason": fixture.reconciliation_reason,
                                "reexecuted": False,
                                "consequence": {
                                    "state": "ESCALATED",
                                    "attempt": TIMEOUT_ATTEMPT,
                                },
                            },
                        },
                    )
                    return
                if self.path.endswith("/proposal:timeout-canary/execute"):
                    timeout_calls = sum(
                        request["path"].endswith(
                            "/proposal:timeout-canary/execute"
                        )
                        for request in fixture.requests
                    )
                    if timeout_calls == 1:
                        self.send(
                            202,
                            {
                                "status": "indeterminate",
                                "retry_allowed": False,
                                "attempt": {
                                    "tenant_id": TIMEOUT_ATTEMPT["tenant_id"],
                                    "attempt_id": TIMEOUT_ATTEMPT["attempt_id"],
                                },
                                "error": {
                                    "code": "provider_outcome_indeterminate"
                                },
                            },
                        )
                    else:
                        self.send(
                            409,
                            {
                                "status": "refused",
                                "result": {
                                    "ok": False,
                                    "reason": fixture.replay_reason,
                                    "invoked": False,
                                    "consequence": {
                                        "state": "INDETERMINATE",
                                        "attempt": TIMEOUT_ATTEMPT,
                                    },
                                },
                            },
                        )
                    return
                self.send(404, {"status": "refused", "error": {"code": "not_found"}})

        return Handler

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class CanaryDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="emilia-canary-driver-")
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.token = self.root / "application-token"
        self.token.write_text("decision-application-token\n", encoding="utf-8")
        self.token.chmod(0o600)
        self.private_key = self.root / "canary-private.pem"
        self.private_key.write_text("fake separately controlled key\n", encoding="utf-8")
        self.private_key.chmod(0o600)
        self.public_key = self.root / "canary-public.pem"
        self.public_key.write_text("fake public key\n", encoding="utf-8")
        self.scenario = self.root / "scenario.json"
        self.scenario.write_text(json.dumps(scenario()), encoding="utf-8")
        self.config = self.root / "config.env"
        self.config.write_text(
            FIXTURE_CONFIG.read_text(encoding="utf-8").replace(
                "/secure/test-canary-public.pem",
                str(self.public_key),
            ),
            encoding="utf-8",
        )
        self.output = self.root / "evidence.json"
        self.write_fake_openssl()
        self.write_fake_gcloud()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write_fake_openssl(self) -> None:
        executable = self.bin / "openssl"
        executable.write_text(
            """#!/usr/bin/env python3
import pathlib
import sys
if "-sign" in sys.argv:
    pathlib.Path(sys.argv[sys.argv.index("-out") + 1]).write_bytes(b"s" * 64)
elif len(sys.argv) > 1 and sys.argv[1] == "pkey":
    source = pathlib.Path(sys.argv[sys.argv.index("-in") + 1]).read_text()
    marker = "mismatched" if "mismatched" in source else "matched"
    if "-pubin" in sys.argv:
        marker = "matched"
    print("-----BEGIN PUBLIC KEY-----")
    print(marker)
    print("-----END PUBLIC KEY-----")
raise SystemExit(0)
""",
            encoding="utf-8",
        )
        executable.chmod(0o755)

    def write_fake_gcloud(self) -> None:
        executable = self.bin / "gcloud"
        executable.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
args = sys.argv[1:]
if args[:3] == ["auth", "print-identity-token", "--audiences=" + os.environ["FAKE_AUDIENCE"]]:
    print("eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJjYW5hcnkifQ.signature")
elif args[:3] == ["run", "services", "describe"]:
    print(json.dumps({
        "metadata": {"name": "emilia-consequence-control"},
        "status": {
            "url": os.environ["FAKE_AUDIENCE"],
            "traffic": [{
                "tag": "canary-r20260725b",
                "revisionName": "emilia-consequence-control-r20260725b",
                "url": os.environ["FAKE_DECISION_URL"],
            }],
        },
    }))
elif args[:3] == ["run", "revisions", "describe"]:
    revision = args[3]
    if revision == "emilia-consequence-actuator-r20260725b":
        service = "emilia-consequence-actuator"
        image = "us-central1-docker.pkg.dev/test-project/runtime/actuator@sha256:" + "a" * 64
    elif revision == "emilia-consequence-control-r20260725b":
        service = "emilia-consequence-control"
        image = "us-central1-docker.pkg.dev/test-project/runtime/decision@sha256:" + "b" * 64
    else:
        raise SystemExit(3)
    print(json.dumps({
        "metadata": {
            "name": revision,
            "labels": {"serving.knative.dev/service": service},
        },
        "spec": {"containers": [{"image": image}]},
    }))
else:
    print("unexpected gcloud arguments: " + repr(args), file=sys.stderr)
    raise SystemExit(2)
""",
            encoding="utf-8",
        )
        executable.chmod(0o755)

    def run_driver(
        self,
        origin: str,
        *,
        extra_args: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        audience = "https://emilia-consequence-control.example.run.app"
        return subprocess.run(
            [
                sys.executable,
                str(DRIVER),
                "--config",
                str(self.config),
                "--scenario",
                str(self.scenario),
                "--application-token-file",
                str(self.token),
                "--private-key-file",
                str(self.private_key),
                "--output",
                str(self.output),
                "--use-google-id-token",
                "--allow-insecure-loopback",
                *(extra_args or []),
            ],
            cwd=LANE,
            check=False,
            text=True,
            capture_output=True,
            env={
                **os.environ,
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "FAKE_DECISION_URL": origin,
                "FAKE_AUDIENCE": audience,
            },
        )

    def test_executes_live_workflow_and_writes_closed_signed_evidence(self) -> None:
        with FakeDecision() as server:
            result = self.run_driver(server.origin)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(
            set(evidence),
            {
                "@version",
                "project_id",
                "region",
                "evidence_status",
                "observed_at",
                "expires_at",
                "nonce",
                "actuator_revision",
                "decision_revision",
                "actuator_image",
                "decision_image",
                "checks",
                "signature",
            },
        )
        self.assertEqual(evidence["checks"]["exact_execution"]["outcome"], "COMMITTED")
        self.assertEqual(evidence["checks"]["timeout"]["outcome"], "INDETERMINATE")
        self.assertEqual(evidence["checks"]["replay"]["provider_invocations"], 1)
        self.assertEqual(evidence["checks"]["reconciliation"]["outcome"], "ESCALATED")
        self.assertEqual(evidence["signature"]["algorithm"], "Ed25519")
        self.assertEqual(evidence["signature"]["key_id"], "canary-test-key")
        self.assertTrue(all(
            request["authorization"] == "Bearer decision-application-token"
            for request in server.requests
        ))
        self.assertTrue(all(
            request["identity"]
            == "Bearer eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJjYW5hcnkifQ.signature"
            for request in server.requests
        ))
        reconcile = next(
            request for request in server.requests
            if request["path"].endswith("/reconcile")
        )
        self.assertEqual(
            reconcile["body"]["provider_evidence"],
            {"kind": "consequence-actuator-observation-v1"},
        )

    def test_replay_mismatch_fails_closed_without_evidence(self) -> None:
        with FakeDecision(replay_reason="aeb_consumption_conflict") as server:
            result = self.run_driver(server.origin)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("envelope_replayed", result.stderr)
        self.assertFalse(self.output.exists())
        self.assertFalse(any(
            request["path"].endswith("/reconcile") for request in server.requests
        ))

    def test_reconciliation_claim_must_come_from_response(self) -> None:
        with FakeDecision(reconciliation_reason="operator_asserted_success") as server:
            result = self.run_driver(server.origin)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("github_attempt_attribution_unavailable", result.stderr)
        self.assertFalse(self.output.exists())

    def test_scenario_refuses_operator_entered_outcome_fields(self) -> None:
        value = scenario()
        value["timeout"]["outcome"] = "INDETERMINATE"
        self.scenario.write_text(json.dumps(value), encoding="utf-8")
        with FakeDecision() as server:
            result = self.run_driver(server.origin)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("scenario.timeout", result.stderr)
        self.assertEqual(server.requests, [])
        self.assertFalse(self.output.exists())

    def test_scenario_target_must_match_the_pinned_deployment(self) -> None:
        value = scenario()
        value["exact_execution"]["request"]["proposal"]["action"]["owner"] = (
            "attacker"
        )
        self.scenario.write_text(json.dumps(value), encoding="utf-8")
        with FakeDecision() as server:
            result = self.run_driver(server.origin)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GITHUB_OWNER", result.stderr)
        self.assertEqual(server.requests, [])
        self.assertFalse(self.output.exists())

    def test_signing_key_must_match_the_pinned_public_key_before_effect(self) -> None:
        self.private_key.write_text("mismatched private key\n", encoding="utf-8")
        with FakeDecision() as server:
            result = self.run_driver(server.origin)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public key", result.stderr)
        self.assertEqual(server.requests, [])
        self.assertFalse(self.output.exists())

    def test_application_token_is_mandatory_and_not_accepted_on_command_line(self) -> None:
        self.token.unlink()
        with FakeDecision() as server:
            result = self.run_driver(server.origin)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("application token", result.stderr)
        self.assertEqual(server.requests, [])


if __name__ == "__main__":
    unittest.main()
