from __future__ import annotations

import importlib.util
import math
from pathlib import Path
import sys
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


if __name__ == "__main__":
    unittest.main()
