#!/usr/bin/env python3
"""Fail closed unless rollout traffic and dwell telemetry meet the contract."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
INTEGER_RE = re.compile(r"^(0|[1-9][0-9]*)$")
UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)


class TelemetryError(ValueError):
    """Raised when rollout evidence is incomplete, inconsistent, or unhealthy."""


@dataclass(frozen=True)
class Thresholds:
    max_error_rate: float
    max_p95_latency_ms: float
    min_readiness_rate: float
    max_indeterminate_rate: float
    min_dwell_seconds: int
    min_requests: int
    min_readiness_samples: int
    max_sample_gap_seconds: int


def _validate_thresholds(thresholds: Thresholds) -> None:
    for name in ("max_error_rate", "min_readiness_rate", "max_indeterminate_rate"):
        value = getattr(thresholds, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TelemetryError(f"{name} must be numeric")
        if not math.isfinite(float(value)) or not 0 <= float(value) <= 1:
            raise TelemetryError(f"{name} must be between 0 and 1")
    if (
        isinstance(thresholds.max_p95_latency_ms, bool)
        or not isinstance(thresholds.max_p95_latency_ms, (int, float))
        or not math.isfinite(float(thresholds.max_p95_latency_ms))
        or thresholds.max_p95_latency_ms < 0
    ):
        raise TelemetryError("max_p95_latency_ms must be non-negative")
    for name in (
        "min_dwell_seconds",
        "min_requests",
        "min_readiness_samples",
        "max_sample_gap_seconds",
    ):
        value = getattr(thresholds, name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise TelemetryError(f"{name} must be a positive integer")


def _parse_utc_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or UTC_TIMESTAMP_RE.fullmatch(value) is None:
        raise TelemetryError(f"{field} must be an RFC 3339 UTC timestamp ending Z")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise TelemetryError(f"{field} is not a valid timestamp") from error


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TelemetryError(f"{field} must be an integer >= {minimum}")
    return value


def _number(value: Any, field: str, *, minimum: float = 0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TelemetryError(f"{field} must be numeric")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < minimum:
        raise TelemetryError(f"{field} must be >= {minimum}")
    return numeric


def parse_expectation(value: str) -> tuple[str, dict[str, int]]:
    if value.count("=") != 1:
        raise TelemetryError(
            "traffic expectation must be SERVICE=REVISION:PERCENT,..."
        )
    service, raw_targets = value.split("=", 1)
    if NAME_RE.fullmatch(service) is None:
        raise TelemetryError(f"invalid service name in expectation: {service!r}")

    targets: dict[str, int] = {}
    for raw_target in raw_targets.split(","):
        if raw_target.count(":") != 1:
            raise TelemetryError(f"invalid traffic target: {raw_target!r}")
        revision, raw_percent = raw_target.split(":", 1)
        if NAME_RE.fullmatch(revision) is None:
            raise TelemetryError(f"invalid revision name: {revision!r}")
        if INTEGER_RE.fullmatch(raw_percent) is None:
            raise TelemetryError(f"invalid traffic percent: {raw_percent!r}")
        percent = int(raw_percent)
        if percent > 100:
            raise TelemetryError(f"traffic percent exceeds 100 for {revision}")
        if revision in targets:
            raise TelemetryError(f"duplicate expected revision: {revision}")
        targets[revision] = percent
    if not targets or sum(targets.values()) != 100:
        raise TelemetryError(f"expected traffic for {service} must total 100")
    return service, targets


def _actual_traffic(service: str, records: Any) -> dict[str, int]:
    if not isinstance(records, list) or not records:
        raise TelemetryError(f"{service}.traffic must be a non-empty array")
    targets: dict[str, int] = {}
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            raise TelemetryError(f"{service}.traffic[{position}] must be an object")
        revision = record.get("revision")
        if not isinstance(revision, str) or NAME_RE.fullmatch(revision) is None:
            raise TelemetryError(
                f"{service}.traffic[{position}].revision is invalid"
            )
        percent = _integer(
            record.get("percent"),
            f"{service}.traffic[{position}].percent",
        )
        if percent > 100:
            raise TelemetryError(f"{service} traffic percent exceeds 100")
        if revision in targets:
            raise TelemetryError(f"{service} has duplicate revision {revision}")
        targets[revision] = percent
    if sum(targets.values()) != 100:
        raise TelemetryError(f"{service} actual traffic must total 100")
    return targets


def _readiness_rate(
    service: str,
    samples: Any,
    *,
    started_at: datetime,
    ended_at: datetime,
    thresholds: Thresholds,
) -> tuple[float, int]:
    if not isinstance(samples, list):
        raise TelemetryError(f"{service}.readiness_samples must be an array")
    if len(samples) < thresholds.min_readiness_samples:
        raise TelemetryError(
            f"{service} has fewer than {thresholds.min_readiness_samples} "
            "readiness samples"
        )

    observations: list[tuple[datetime, bool]] = []
    for position, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise TelemetryError(
                f"{service}.readiness_samples[{position}] must be an object"
            )
        observed_at = _parse_utc_timestamp(
            sample.get("observed_at"),
            f"{service}.readiness_samples[{position}].observed_at",
        )
        ready = sample.get("ready")
        if not isinstance(ready, bool):
            raise TelemetryError(
                f"{service}.readiness_samples[{position}].ready must be boolean"
            )
        if observed_at < started_at or observed_at > ended_at:
            raise TelemetryError(f"{service} readiness sample is outside the window")
        observations.append((observed_at, ready))

    for left, right in zip(observations, observations[1:]):
        if right[0] <= left[0]:
            raise TelemetryError(
                f"{service} readiness samples must be strictly increasing"
            )

    gaps = [
        (observations[0][0] - started_at).total_seconds(),
        *[
            (right[0] - left[0]).total_seconds()
            for left, right in zip(observations, observations[1:])
        ],
        (ended_at - observations[-1][0]).total_seconds(),
    ]
    if max(gaps) > thresholds.max_sample_gap_seconds:
        raise TelemetryError(
            f"{service} readiness evidence has a gap larger than "
            f"{thresholds.max_sample_gap_seconds} seconds"
        )
    ready_count = sum(1 for _, ready in observations if ready)
    return ready_count / len(observations), len(observations)


def evaluate_telemetry(
    telemetry: Any,
    expectations: Mapping[str, Mapping[str, int]],
    thresholds: Thresholds,
) -> dict[str, Any]:
    _validate_thresholds(thresholds)
    for service, targets in expectations.items():
        if NAME_RE.fullmatch(service) is None:
            raise TelemetryError(f"invalid expected service name: {service!r}")
        if not targets:
            raise TelemetryError(f"expected traffic for {service} is empty")
        total = 0
        for revision, percent in targets.items():
            if NAME_RE.fullmatch(revision) is None:
                raise TelemetryError(f"invalid expected revision: {revision!r}")
            if (
                isinstance(percent, bool)
                or not isinstance(percent, int)
                or percent < 0
                or percent > 100
            ):
                raise TelemetryError(
                    f"invalid expected traffic percent for {revision}"
                )
            total += percent
        if total != 100:
            raise TelemetryError(f"expected traffic for {service} must total 100")
    if not isinstance(telemetry, dict):
        raise TelemetryError("telemetry must be an object")
    if telemetry.get("schema") != "emilia-rollout-telemetry.v1":
        raise TelemetryError("unsupported telemetry schema")

    window = telemetry.get("window")
    if not isinstance(window, dict):
        raise TelemetryError("window must be an object")
    started_at = _parse_utc_timestamp(window.get("started_at"), "window.started_at")
    ended_at = _parse_utc_timestamp(window.get("ended_at"), "window.ended_at")
    dwell_seconds = int((ended_at - started_at).total_seconds())
    if dwell_seconds < thresholds.min_dwell_seconds:
        raise TelemetryError(
            f"dwell window is shorter than {thresholds.min_dwell_seconds} seconds"
        )

    services = telemetry.get("services")
    if not isinstance(services, dict):
        raise TelemetryError("services must be an object")
    if set(services) != set(expectations):
        raise TelemetryError(
            "telemetry service set must exactly match traffic expectations"
        )

    accepted: dict[str, Any] = {}
    for service in sorted(expectations):
        record = services[service]
        if not isinstance(record, dict):
            raise TelemetryError(f"{service} telemetry must be an object")
        actual = _actual_traffic(service, record.get("traffic"))
        expected = dict(expectations[service])
        if actual != expected:
            raise TelemetryError(
                f"{service} actual traffic {actual} does not match expected {expected}"
            )

        requests = _integer(
            record.get("requests"),
            f"{service}.requests",
            minimum=thresholds.min_requests,
        )
        errors = _integer(record.get("errors"), f"{service}.errors")
        indeterminate = _integer(
            record.get("indeterminate"),
            f"{service}.indeterminate",
        )
        if errors > requests or indeterminate > requests:
            raise TelemetryError(f"{service} event counts exceed request count")
        p95_latency_ms = _number(
            record.get("p95_latency_ms"),
            f"{service}.p95_latency_ms",
        )
        error_rate = errors / requests
        indeterminate_rate = indeterminate / requests
        readiness_rate, readiness_samples = _readiness_rate(
            service,
            record.get("readiness_samples"),
            started_at=started_at,
            ended_at=ended_at,
            thresholds=thresholds,
        )

        if error_rate > thresholds.max_error_rate:
            raise TelemetryError(f"{service} error rate exceeds threshold")
        if p95_latency_ms > thresholds.max_p95_latency_ms:
            raise TelemetryError(f"{service} p95 latency exceeds threshold")
        if readiness_rate < thresholds.min_readiness_rate:
            raise TelemetryError(f"{service} readiness rate is below threshold")
        if indeterminate_rate > thresholds.max_indeterminate_rate:
            raise TelemetryError(f"{service} indeterminate rate exceeds threshold")

        accepted[service] = {
            "traffic": actual,
            "requests": requests,
            "error_rate": error_rate,
            "p95_latency_ms": p95_latency_ms,
            "readiness_rate": readiness_rate,
            "readiness_samples": readiness_samples,
            "indeterminate_rate": indeterminate_rate,
        }

    return {
        "schema": "emilia-rollout-telemetry-verification.v1",
        "status": "accepted",
        "dwell_seconds": dwell_seconds,
        "services": accepted,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify exact rollout traffic and structured dwell telemetry."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expect-traffic", action="append", required=True)
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--max-p95-latency-ms", type=float, default=500)
    parser.add_argument("--min-readiness-rate", type=float, default=0.99)
    parser.add_argument("--max-indeterminate-rate", type=float, default=0.005)
    parser.add_argument("--min-dwell-seconds", type=int, default=600)
    parser.add_argument("--min-requests", type=int, default=100)
    parser.add_argument("--min-readiness-samples", type=int, default=3)
    parser.add_argument("--max-sample-gap-seconds", type=int, default=300)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        expectations: dict[str, dict[str, int]] = {}
        for raw_expectation in args.expect_traffic:
            service, targets = parse_expectation(raw_expectation)
            if service in expectations:
                raise TelemetryError(f"duplicate service expectation: {service}")
            expectations[service] = targets
        try:
            telemetry = json.loads(args.input.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise TelemetryError(
                f"unable to load telemetry {args.input}: {error}"
            ) from error
        result = evaluate_telemetry(
            telemetry,
            expectations,
            Thresholds(
                max_error_rate=args.max_error_rate,
                max_p95_latency_ms=args.max_p95_latency_ms,
                min_readiness_rate=args.min_readiness_rate,
                max_indeterminate_rate=args.max_indeterminate_rate,
                min_dwell_seconds=args.min_dwell_seconds,
                min_requests=args.min_requests,
                min_readiness_samples=args.min_readiness_samples,
                max_sample_gap_seconds=args.max_sample_gap_seconds,
            ),
        )
    except TelemetryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
