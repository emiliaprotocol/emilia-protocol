from __future__ import annotations

import hashlib
import importlib.util
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


LANE_DIR = Path(__file__).resolve().parents[1]
SCRIPT = LANE_DIR / "verify-rollout-telemetry.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_rollout_telemetry", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load rollout telemetry verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def good_telemetry() -> dict:
    samples = [
        {"observed_at": "2026-07-25T12:00:00Z", "ready": True},
        {"observed_at": "2026-07-25T12:05:00Z", "ready": True},
        {"observed_at": "2026-07-25T12:10:00Z", "ready": True},
    ]
    return {
        "schema": "emilia-rollout-telemetry.v1",
        "window": {
            "started_at": "2026-07-25T12:00:00Z",
            "ended_at": "2026-07-25T12:10:00Z",
        },
        "services": {
            "decision": {
                "traffic": [
                    {"revision": "decision-r2", "percent": 10},
                    {"revision": "decision-r1", "percent": 90},
                ],
                "requests": 1000,
                "errors": 2,
                "p95_latency_ms": 240,
                "indeterminate": 1,
                "readiness_samples": samples,
            },
            "actuator": {
                "traffic": [
                    {"revision": "actuator-r2", "percent": 10},
                    {"revision": "actuator-r1", "percent": 90},
                ],
                "requests": 500,
                "errors": 0,
                "p95_latency_ms": 180,
                "indeterminate": 0,
                "readiness_samples": samples,
            },
        },
    }


def current_good_telemetry() -> dict:
    ended_at = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=1)
    started_at = ended_at - timedelta(seconds=600)
    observed_at = [
        started_at,
        started_at + timedelta(seconds=300),
        ended_at,
    ]
    telemetry = good_telemetry()
    telemetry["window"] = {
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "ended_at": ended_at.isoformat().replace("+00:00", "Z"),
    }
    for service in telemetry["services"].values():
        service["readiness_samples"] = [
            {
                "observed_at": value.isoformat().replace("+00:00", "Z"),
                "ready": True,
            }
            for value in observed_at
        ]
    return telemetry


def service_document(
    service: str,
    traffic: dict[str, int],
    *,
    generation: int = 7,
    observed_generation: int | None = None,
    observed_traffic: dict[str, int] | None = None,
    resource_version: str = "rv-7",
    tagged_revision: str | None = None,
) -> dict:
    def records(value: dict[str, int], *, include_tag: bool) -> list[dict]:
        result = [
            {"revisionName": revision, "percent": percent}
            for revision, percent in value.items()
        ]
        if include_tag and tagged_revision is not None:
            result.append(
                {
                    "revisionName": tagged_revision,
                    "percent": 0,
                    "tag": "canary",
                }
            )
        return result

    return {
        "apiVersion": "serving.knative.dev/v1",
        "kind": "Service",
        "metadata": {
            "name": service,
            "namespace": "test-project",
            "generation": generation,
            "resourceVersion": resource_version,
            "labels": {"owner": "release"},
            "annotations": {"run.googleapis.com/ingress": "internal"},
        },
        "spec": {
            "template": {"spec": {"containers": [{"image": "example@sha256:abc"}]}},
            "traffic": records(traffic, include_tag=True),
        },
        "status": {
            "observedGeneration": (
                generation if observed_generation is None else observed_generation
            ),
            "conditions": [{"type": "Ready", "status": "True"}],
            "traffic": records(
                observed_traffic if observed_traffic is not None else traffic,
                include_tag=False,
            ),
        },
    }


class RolloutTelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.expectations = {
            "decision": {"decision-r2": 10, "decision-r1": 90},
            "actuator": {"actuator-r2": 10, "actuator-r1": 90},
        }
        self.thresholds = self.module.Thresholds(
            max_error_rate=0.01,
            max_p95_latency_ms=500,
            min_readiness_rate=0.99,
            max_indeterminate_rate=0.005,
            min_dwell_seconds=600,
            min_requests=100,
            min_readiness_samples=3,
            max_sample_gap_seconds=300,
        )

    def test_accepts_exact_traffic_and_healthy_dwell_evidence(self) -> None:
        result = self.module.evaluate_telemetry(
            good_telemetry(),
            self.expectations,
            self.thresholds,
        )

        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["dwell_seconds"], 600)
        self.assertEqual(set(result["services"]), {"decision", "actuator"})

    def test_rejects_traffic_drift_extra_revision_and_bad_total(self) -> None:
        mutations = []
        drift = good_telemetry()
        drift["services"]["decision"]["traffic"][0]["percent"] = 11
        drift["services"]["decision"]["traffic"][1]["percent"] = 89
        mutations.append(drift)
        extra = good_telemetry()
        extra["services"]["decision"]["traffic"].append(
            {"revision": "unknown", "percent": 0}
        )
        mutations.append(extra)
        bad_total = good_telemetry()
        bad_total["services"]["decision"]["traffic"][1]["percent"] = 80
        mutations.append(bad_total)

        for telemetry in mutations:
            with self.subTest(telemetry=telemetry["services"]["decision"]["traffic"]):
                with self.assertRaises(self.module.TelemetryError):
                    self.module.evaluate_telemetry(
                        telemetry,
                        self.expectations,
                        self.thresholds,
                    )

    def test_rejects_short_or_sparsely_sampled_dwell(self) -> None:
        short = good_telemetry()
        short["window"]["ended_at"] = "2026-07-25T12:09:59Z"
        sparse = good_telemetry()
        sparse["services"]["actuator"]["readiness_samples"] = [
            {"observed_at": "2026-07-25T12:00:00Z", "ready": True},
            {"observed_at": "2026-07-25T12:10:00Z", "ready": True},
        ]
        gap = good_telemetry()
        gap["services"]["decision"]["readiness_samples"][1]["observed_at"] = (
            "2026-07-25T12:04:59Z"
        )

        for telemetry in (short, sparse, gap):
            with self.assertRaises(self.module.TelemetryError):
                self.module.evaluate_telemetry(
                    telemetry,
                    self.expectations,
                    self.thresholds,
                )

    def test_rejects_non_utc_or_out_of_window_samples(self) -> None:
        non_utc = good_telemetry()
        non_utc["window"]["started_at"] = "2026-07-25T05:00:00-07:00"
        out_of_window = good_telemetry()
        out_of_window["services"]["decision"]["readiness_samples"][0][
            "observed_at"
        ] = "2026-07-25T11:59:59Z"

        for telemetry in (non_utc, out_of_window):
            with self.assertRaises(self.module.TelemetryError):
                self.module.evaluate_telemetry(
                    telemetry,
                    self.expectations,
                    self.thresholds,
                )

    def test_current_telemetry_window_rejects_stale_and_future_evidence(self) -> None:
        accepted = self.module.evaluate_telemetry(
            good_telemetry(),
            self.expectations,
            self.thresholds,
            now=datetime(2026, 7, 25, 12, 25, tzinfo=timezone.utc),
            max_age_seconds=900,
        )
        self.assertEqual(accepted["status"], "accepted")

        for evaluated_at in (
            datetime(2026, 7, 25, 12, 25, 1, tzinfo=timezone.utc),
            datetime(2026, 7, 25, 12, 9, 59, tzinfo=timezone.utc),
        ):
            with self.subTest(evaluated_at=evaluated_at):
                with self.assertRaises(self.module.TelemetryError):
                    self.module.evaluate_telemetry(
                        good_telemetry(),
                        self.expectations,
                        self.thresholds,
                        now=evaluated_at,
                        max_age_seconds=900,
                    )

    def test_rejects_each_operational_threshold_breach(self) -> None:
        cases = {
            "errors": 11,
            "p95_latency_ms": 501,
            "indeterminate": 6,
        }
        for field, value in cases.items():
            telemetry = good_telemetry()
            telemetry["services"]["decision"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(self.module.TelemetryError):
                    self.module.evaluate_telemetry(
                        telemetry,
                        self.expectations,
                        self.thresholds,
                    )

        readiness = good_telemetry()
        readiness["services"]["decision"]["readiness_samples"][1]["ready"] = False
        with self.assertRaises(self.module.TelemetryError):
            self.module.evaluate_telemetry(
                readiness,
                self.expectations,
                self.thresholds,
            )

    def test_rejects_impossible_counts_and_bools_disguised_as_integers(self) -> None:
        impossible = good_telemetry()
        impossible["services"]["decision"]["errors"] = 1001
        disguised = good_telemetry()
        disguised["services"]["decision"]["requests"] = True

        for telemetry in (impossible, disguised):
            with self.assertRaises(self.module.TelemetryError):
                self.module.evaluate_telemetry(
                    telemetry,
                    self.expectations,
                    self.thresholds,
                )

    def test_rejects_non_finite_metrics_and_thresholds(self) -> None:
        for value in (math.nan, math.inf, -math.inf):
            telemetry = good_telemetry()
            telemetry["services"]["decision"]["p95_latency_ms"] = value
            with self.subTest(metric=value):
                with self.assertRaises(self.module.TelemetryError):
                    self.module.evaluate_telemetry(
                        telemetry,
                        self.expectations,
                        self.thresholds,
                    )

        thresholds = self.module.Thresholds(
            **{
                **self.thresholds.__dict__,
                "max_error_rate": math.nan,
            }
        )
        with self.assertRaises(self.module.TelemetryError):
            self.module.evaluate_telemetry(
                good_telemetry(),
                self.expectations,
                thresholds,
            )

    def test_direct_call_revalidates_expected_traffic_contract(self) -> None:
        with self.assertRaises(self.module.TelemetryError):
            self.module.evaluate_telemetry(
                good_telemetry(),
                {
                    **self.expectations,
                    "decision": {"../candidate": 10, "decision-r1": 90},
                },
                self.thresholds,
            )

    def test_expectation_parser_requires_closed_exact_percentages(self) -> None:
        parsed = self.module.parse_expectation(
            "decision=decision-r2:10,decision-r1:90"
        )
        self.assertEqual(
            parsed,
            ("decision", {"decision-r2": 10, "decision-r1": 90}),
        )

        for value in (
            "decision=decision-r2:10",
            "decision=decision-r2:10,decision-r2:90",
            "decision=decision-r2:true,decision-r1:90",
            "decision=../revision:10,decision-r1:90",
        ):
            with self.subTest(value=value):
                with self.assertRaises(self.module.TelemetryError):
                    self.module.parse_expectation(value)

    def test_service_state_requires_exact_settled_generation_and_traffic(self) -> None:
        document = service_document(
            "decision",
            {"decision-r2": 10, "decision-r1": 90},
            tagged_revision="decision-r2",
        )

        state = self.module.evaluate_service_state(
            document,
            service="decision",
            expected_traffic={"decision-r2": 10, "decision-r1": 90},
            allowed_revisions={"decision-r1", "decision-r2"},
        )

        self.assertEqual(state.generation, 7)
        self.assertEqual(state.observed_generation, 7)
        self.assertEqual(state.resource_version, "rv-7")

        hostile = [
            {
                **document,
                "status": {**document["status"], "observedGeneration": 6},
            },
            {
                **document,
                "metadata": {**document["metadata"], "resourceVersion": ""},
            },
            service_document(
                "decision",
                {"decision-r2": 10, "decision-r1": 90},
                observed_traffic={"decision-r2": 11, "decision-r1": 89},
            ),
        ]
        latest = service_document(
            "decision",
            {"decision-r2": 10, "decision-r1": 90},
        )
        latest["spec"]["traffic"][0]["latestRevision"] = True
        hostile.append(latest)
        unknown_zero = service_document(
            "decision",
            {"decision-r2": 10, "decision-r1": 90},
        )
        unknown_zero["spec"]["traffic"].append(
            {"revisionName": "attacker-r1", "percent": 0, "tag": "backdoor"}
        )
        hostile.append(unknown_zero)

        for value in hostile:
            with self.subTest(value=value):
                with self.assertRaises(self.module.TelemetryError):
                    self.module.evaluate_service_state(
                        value,
                        service="decision",
                        expected_traffic={"decision-r2": 10, "decision-r1": 90},
                        allowed_revisions={"decision-r1", "decision-r2"},
                    )

    def test_post_state_allows_only_exact_reconciliation_from_pre_state(self) -> None:
        pending = service_document(
            "decision",
            {"decision-r2": 10, "decision-r1": 90},
            generation=8,
            observed_generation=7,
            observed_traffic={"decision-r2": 1, "decision-r1": 99},
            resource_version="rv-8",
        )
        with self.assertRaises(self.module.PendingReconciliation):
            self.module.evaluate_service_state(
                pending,
                service="decision",
                expected_traffic={"decision-r2": 10, "decision-r1": 90},
                pending_from_traffic={"decision-r2": 1, "decision-r1": 99},
                allowed_revisions={"decision-r1", "decision-r2"},
                generation_after=7,
                resource_version_not="rv-7",
            )

        failed = json.loads(json.dumps(pending))
        failed["status"]["conditions"] = [{"type": "Ready", "status": "False"}]
        with self.assertRaises(self.module.TelemetryError) as context:
            self.module.evaluate_service_state(
                failed,
                service="decision",
                expected_traffic={"decision-r2": 10, "decision-r1": 90},
                pending_from_traffic={"decision-r2": 1, "decision-r1": 99},
                allowed_revisions={"decision-r1", "decision-r2"},
                generation_after=7,
                resource_version_not="rv-7",
            )
        self.assertNotIsInstance(
            context.exception,
            self.module.PendingReconciliation,
        )

        pending["status"]["traffic"] = [
            {"revisionName": "decision-r2", "percent": 50},
            {"revisionName": "decision-r1", "percent": 50},
        ]
        with self.assertRaises(self.module.TelemetryError):
            self.module.evaluate_service_state(
                pending,
                service="decision",
                expected_traffic={"decision-r2": 10, "decision-r1": 90},
                pending_from_traffic={"decision-r2": 1, "decision-r1": 99},
                allowed_revisions={"decision-r1", "decision-r2"},
                generation_after=7,
                resource_version_not="rv-7",
            )

    def test_transition_contract_refuses_skips_and_actuator_before_decision(
        self,
    ) -> None:
        names = {
            "decision_service": "decision",
            "decision_stable": "decision-r1",
            "decision_candidate": "decision-r2",
            "actuator_service": "actuator",
            "actuator_stable": "actuator-r1",
            "actuator_candidate": "actuator-r2",
        }
        actions = (
            "apply-decision-1",
            "apply-decision-10",
            "apply-decision-50",
            "apply-decision-100",
            "apply-actuator-100",
        )
        for action in actions:
            contract = self.module.transition_contract(
                action,
                decision_stable=names["decision_stable"],
                decision_candidate=names["decision_candidate"],
                actuator_stable=names["actuator_stable"],
                actuator_candidate=names["actuator_candidate"],
            )
            transition, _, _ = self.module.evaluate_transition_pre_state(
                action,
                service_document("decision", contract.pre_decision),
                service_document("actuator", contract.pre_actuator),
                **names,
            )
            self.assertEqual(transition, contract)

        with self.assertRaises(self.module.TelemetryError):
            self.module.evaluate_transition_pre_state(
                "apply-decision-10",
                service_document("decision", {"decision-r1": 100}),
                service_document("actuator", {"actuator-r1": 100}),
                **names,
            )
        with self.assertRaises(self.module.TelemetryError):
            self.module.evaluate_transition_pre_state(
                "apply-actuator-100",
                service_document(
                    "decision", {"decision-r2": 50, "decision-r1": 50}
                ),
                service_document("actuator", {"actuator-r1": 100}),
                **names,
            )

    def test_rollback_classification_enforces_reverse_dependency_order(self) -> None:
        names = {
            "decision_service": "decision",
            "decision_stable": "decision-r1",
            "decision_candidate": "decision-r2",
            "actuator_service": "actuator",
            "actuator_stable": "actuator-r1",
            "actuator_candidate": "actuator-r2",
        }
        self.assertEqual(
            self.module.classify_rollback_pre_state(
                service_document("decision", {"decision-r2": 100}),
                service_document("actuator", {"actuator-r2": 100}),
                **names,
            ),
            "actuator:100",
        )
        self.assertEqual(
            self.module.classify_rollback_pre_state(
                service_document(
                    "decision", {"decision-r2": 50, "decision-r1": 50}
                ),
                service_document("actuator", {"actuator-r1": 100}),
                **names,
            ),
            "decision:50",
        )
        with self.assertRaises(self.module.TelemetryError):
            self.module.classify_rollback_pre_state(
                service_document(
                    "decision", {"decision-r2": 50, "decision-r1": 50}
                ),
                service_document("actuator", {"actuator-r2": 100}),
                **names,
            )

    def test_locked_update_binds_resource_version_and_preserves_only_safe_tags(
        self,
    ) -> None:
        document = service_document(
            "decision",
            {"decision-r2": 10, "decision-r1": 90},
            tagged_revision="decision-r2",
        )

        body, state = self.module.build_service_update(
            document,
            service="decision",
            expected_traffic={"decision-r2": 10, "decision-r1": 90},
            target_traffic={"decision-r2": 50, "decision-r1": 50},
            allowed_revisions={"decision-r1", "decision-r2"},
        )

        self.assertEqual(body["metadata"]["resourceVersion"], state.resource_version)
        self.assertNotIn("status", body)
        self.assertEqual(body["metadata"]["labels"], {"owner": "release"})
        self.assertIn(
            {"revisionName": "decision-r2", "percent": 0, "tag": "canary"},
            body["spec"]["traffic"],
        )
        self.assertIn(
            {"revisionName": "decision-r2", "percent": 50},
            body["spec"]["traffic"],
        )

    def test_cli_rejects_duplicate_service_json_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "service.json"
            path.write_text(
                '{"apiVersion":"serving.knative.dev/v1",'
                '"apiVersion":"serving.knative.dev/v1"}',
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "verify-service",
                    "--input",
                    str(path),
                    "--service",
                    "decision",
                    "--expect-traffic",
                    "decision-r1:100",
                    "--allowed-revision",
                    "decision-r1",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate JSON member", result.stderr)


class RolloutTelemetrySignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.private_key, self.public_key = self._generate_key_pair("rollout")
        self.config = self._write_config(
            "rollout-test-key",
            self.public_key,
        )
        self.unsigned = self.root / "unsigned.json"
        self.signed = self.root / "signed.json"
        self._write_json(self.unsigned, current_good_telemetry())

    def _generate_key_pair(self, stem: str) -> tuple[Path, Path]:
        private_key = self.root / f"{stem}-private.pem"
        public_key = self.root / f"{stem}-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        private_key.chmod(0o600)
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return private_key, public_key

    def _write_config(
        self,
        key_id: str,
        public_key: Path,
        *,
        expected_hash: str | None = None,
        name: str = "rollout.env",
    ) -> Path:
        digest = expected_hash or hashlib.sha256(public_key.read_bytes()).hexdigest()
        path = self.root / name
        path.write_text(
            "\n".join(
                [
                    f"ROLLOUT_TELEMETRY_KEY_ID={key_id}",
                    f"ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE={public_key}",
                    f"ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256={digest}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

    def _sign(
        self,
        *,
        config: Path | None = None,
        source: Path | None = None,
        output: Path | None = None,
        private_key: Path | None = None,
        force: bool = False,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(SCRIPT),
            "sign",
            "--config",
            str(config or self.config),
            "--input",
            str(source or self.unsigned),
            "--output",
            str(output or self.signed),
            "--private-key-file",
            str(private_key or self.private_key),
        ]
        if force:
            command.append("--force")
        return subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )

    def _verify(
        self,
        path: Path,
        *,
        config: Path | None = None,
        extra: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--config",
                str(config or self.config),
                "--input",
                str(path),
                "--expect-traffic",
                "decision=decision-r2:10,decision-r1:90",
                "--expect-traffic",
                "actuator=actuator-r2:10,actuator-r1:90",
                *(extra or []),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_cli_authenticates_before_accepting_metrics_and_rejects_unsigned(
        self,
    ) -> None:
        signed = self._sign()
        self.assertEqual(signed.returncode, 0, signed.stderr)
        self.assertEqual(stat.S_IMODE(self.signed.stat().st_mode), 0o600)

        verified = self._verify(self.signed)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout)["status"], "accepted")

        unsigned = self._verify(self.unsigned)
        self.assertNotEqual(unsigned.returncode, 0)
        self.assertIn("signed telemetry", unsigned.stderr)

    def test_traffic_promotion_passes_only_configured_telemetry_trust(self) -> None:
        traffic = (LANE_DIR / "traffic.sh").read_text(encoding="utf-8")
        self.assertIn('"$LANE_DIR/verify-rollout-telemetry.py"', traffic)
        self.assertIn('--config "$CONFIG"', traffic)
        for name in (
            "ROLLOUT_TELEMETRY_KEY_ID",
            "ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE",
            "ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256",
        ):
            self.assertIn(f"require_var {name}", traffic)

    def test_traffic_promotion_refuses_caller_selected_safety_thresholds(
        self,
    ) -> None:
        for option, value in (
            ("--max-error-rate", "1"),
            ("--max-p95-latency-ms", "999999"),
            ("--min-readiness-rate", "0"),
            ("--max-indeterminate-rate", "1"),
            ("--min-dwell-seconds", "1"),
            ("--min-requests", "1"),
            ("--min-readiness-samples", "1"),
            ("--max-sample-gap-seconds", "999999"),
            ("--max-telemetry-age-seconds", "999999"),
        ):
            with self.subTest(option=option):
                result = subprocess.run(
                    [
                        "bash",
                        str(LANE_DIR / "traffic.sh"),
                        "--config",
                        "/does/not/exist",
                        option,
                        value,
                        "--render-promote",
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"unknown argument: {option}", result.stderr)

    def test_rejects_post_signature_mutation_and_malformed_signature(self) -> None:
        self.assertEqual(self._sign().returncode, 0)
        signed = json.loads(self.signed.read_text(encoding="utf-8"))

        mutated = json.loads(json.dumps(signed))
        mutated["services"]["decision"]["errors"] = 1001
        mutated_path = self.root / "mutated.json"
        self._write_json(mutated_path, mutated)
        result = self._verify(mutated_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature is invalid", result.stderr)

        malformed_values = [
            "*",
            self.module.encode_base64url(b"x" * 63),
        ]
        for position, value in enumerate(malformed_values):
            malformed = json.loads(json.dumps(signed))
            malformed["signature"]["value"] = value
            malformed_path = self.root / f"malformed-{position}.json"
            self._write_json(malformed_path, malformed)
            with self.subTest(value=value):
                result = self._verify(malformed_path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("signature.value", result.stderr)

    def test_rejects_wrong_key_hash_key_id_and_caller_key_substitution(self) -> None:
        self.assertEqual(self._sign().returncode, 0)

        wrong_hash = self._write_config(
            "rollout-test-key",
            self.public_key,
            expected_hash="0" * 64,
            name="wrong-hash.env",
        )
        result = self._verify(self.signed, config=wrong_hash)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 differs", result.stderr)

        _, attacker_public = self._generate_key_pair("attacker")
        attacker_config = self._write_config(
            "rollout-test-key",
            attacker_public,
            name="attacker.env",
        )
        result = self._verify(self.signed, config=attacker_config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature is invalid", result.stderr)

        changed_id = json.loads(self.signed.read_text(encoding="utf-8"))
        changed_id["signature"]["key_id"] = "attacker-key"
        changed_id_path = self.root / "changed-key-id.json"
        self._write_json(changed_id_path, changed_id)
        result = self._verify(changed_id_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("key_id", result.stderr)

        result = self._verify(
            self.signed,
            extra=["--public-key-file", str(attacker_public)],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments", result.stderr)

    def test_rejects_duplicate_members_before_signature_verification(self) -> None:
        self.assertEqual(self._sign().returncode, 0)
        raw = self.signed.read_text(encoding="utf-8")
        duplicate = raw.replace(
            '"schema":"emilia-rollout-telemetry.v1"',
            '"schema":"attacker","schema":"emilia-rollout-telemetry.v1"',
            1,
        )
        duplicate_path = self.root / "duplicate.json"
        duplicate_path.write_text(duplicate, encoding="utf-8")

        result = self._verify(duplicate_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate JSON member", result.stderr)

    def test_signing_requires_closed_input_matching_private_key_and_safe_output(
        self,
    ) -> None:
        extra = current_good_telemetry()
        extra["caller_public_key"] = str(self.public_key)
        extra_path = self.root / "extra.json"
        self._write_json(extra_path, extra)
        result = self._sign(source=extra_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must contain exactly", result.stderr)

        attacker_private, _ = self._generate_key_pair("signer-attacker")
        result = self._sign(private_key=attacker_private)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match configured trust", result.stderr)

        self.private_key.chmod(0o644)
        result = self._sign()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("0600", result.stderr)
        self.private_key.chmod(0o600)

        result = self._sign(
            private_key=Path(self.private_key.name),
            cwd=self.root,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute", result.stderr)

        first = self._sign()
        self.assertEqual(first.returncode, 0, first.stderr)
        original = self.signed.read_bytes()
        refused = self._sign()
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("refusing to overwrite", refused.stderr)
        self.assertEqual(self.signed.read_bytes(), original)
        replaced = self._sign(force=True)
        self.assertEqual(replaced.returncode, 0, replaced.stderr)
        self.assertEqual(stat.S_IMODE(self.signed.stat().st_mode), 0o600)

        signed_input = self._sign(
            source=self.signed,
            output=self.root / "resigned.json",
        )
        self.assertNotEqual(signed_input.returncode, 0)
        self.assertIn("must contain exactly", signed_input.stderr)


if __name__ == "__main__":
    unittest.main()
