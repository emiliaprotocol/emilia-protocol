#!/usr/bin/env python3
"""Fail closed unless rollout traffic and dwell telemetry meet the contract."""

from __future__ import annotations

import argparse
import base64
import binascii
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence


NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9:_.@-]{3,256}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
INTEGER_RE = re.compile(r"^(0|[1-9][0-9]*)$")
UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
UNSIGNED_TELEMETRY_KEYS = {
    "schema",
    "context",
    "authorization_sha256",
    "window",
    "services",
}
SIGNED_TELEMETRY_KEYS = {*UNSIGNED_TELEMETRY_KEYS, "signature"}
SIGNATURE_KEYS = {"algorithm", "key_id", "value"}
ROLLOUT_CONTEXT_KEYS = {
    "project_id",
    "region",
    "release_id",
    "transition",
    "authorization_id",
    "rollout_nonce",
    "candidate",
    "stable",
    "pre_state",
    "post_traffic",
    "thresholds",
}
PLANE_KEYS = {"actuator", "decision"}
REVISION_BINDING_KEYS = {"service", "revision", "image"}
SNAPSHOT_BINDING_KEYS = {
    "service",
    "generation",
    "observed_generation",
    "resource_version",
}
THRESHOLD_KEYS = {
    "max_error_rate",
    "max_p95_latency_ms",
    "min_readiness_rate",
    "max_indeterminate_rate",
    "min_dwell_seconds",
    "min_requests",
    "min_readiness_samples",
    "max_sample_gap_seconds",
    "max_age_seconds",
}
AUTHORIZATION_UNSIGNED_KEYS = {"schema", "context", "consumption"}
AUTHORIZATION_SIGNED_KEYS = {*AUTHORIZATION_UNSIGNED_KEYS, "signature"}
CONSUMPTION_KEYS = {"state", "consumed_at", "expires_at"}
ROLLOUT_TRANSITIONS = {
    "apply-decision-1",
    "apply-decision-10",
    "apply-decision-50",
    "apply-decision-100",
    "apply-actuator-100",
    "apply-rollback-actuator",
    "apply-rollback-decision",
}
TELEMETRY_SCHEMA = "emilia-rollout-telemetry.v2"
AUTHORIZATION_SCHEMA = "emilia-rollout-authorization.v1"


class TelemetryError(ValueError):
    """Raised when rollout evidence is incomplete, inconsistent, or unhealthy."""


class PendingReconciliation(TelemetryError):
    """Raised when desired traffic is correct but Cloud Run is still reconciling."""


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


@dataclass(frozen=True)
class ServiceState:
    service: str
    generation: int
    observed_generation: int
    resource_version: str
    traffic: dict[str, int]


@dataclass(frozen=True)
class Transition:
    service: str
    pre_decision: dict[str, int]
    pre_actuator: dict[str, int]
    post_traffic: dict[str, int]


@dataclass(frozen=True)
class TelemetryTrust:
    key_id: str
    public_key_file: Path
    public_key_sha256: str
    public_key: bytes


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TelemetryError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> Any:
    raise TelemetryError(f"non-finite JSON number is forbidden: {value}")


def exact_keys(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise TelemetryError(f"{name} must contain exactly {sorted(expected)}")
    return value


def parse_config(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise TelemetryError(f"invalid config line {number}")
        key, value = raw.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None:
            raise TelemetryError(f"invalid config key on line {number}")
        if key in {"DEPLOYMENT_CONFIG_SHA256", "REQUIRE_DEPLOYMENT_CONFIG_PIN"}:
            raise TelemetryError(
                f"protected config controls are forbidden in config: {key}"
            )
        if key in result:
            raise TelemetryError(f"duplicate config key on line {number}")
        result[key] = value
    return result


def load_config(path: Path) -> dict[str, str]:
    try:
        return parse_config(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise TelemetryError(f"unable to load config {path}: {error}") from error


def load_pinned_config(path: Path) -> dict[str, str]:
    expected = os.environ.get("DEPLOYMENT_CONFIG_SHA256", "")
    if SHA256_RE.fullmatch(expected) is None:
        raise TelemetryError(
            "DEPLOYMENT_CONFIG_SHA256 must be injected by a protected source"
        )
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise TelemetryError(f"unable to load config {path}: {error}") from error
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise TelemetryError("deployment config differs from protected SHA-256")
    try:
        return parse_config(raw.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise TelemetryError("deployment config is not UTF-8") from error


def load_telemetry_trust(config: Mapping[str, str]) -> TelemetryTrust:
    key_id = config.get("ROLLOUT_TELEMETRY_KEY_ID", "")
    if KEY_ID_RE.fullmatch(key_id) is None:
        raise TelemetryError("ROLLOUT_TELEMETRY_KEY_ID is required and invalid")
    public_key_file = Path(config.get("ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE", ""))
    if not public_key_file.is_absolute() or not public_key_file.is_file():
        raise TelemetryError(
            "configured rollout telemetry public-key file is unavailable"
        )
    expected_hash = config.get("ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256", "")
    if SHA256_RE.fullmatch(expected_hash) is None:
        raise TelemetryError("ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256 is invalid")
    try:
        public_key = public_key_file.read_bytes()
    except OSError as error:
        raise TelemetryError(
            "configured rollout telemetry public-key file is unavailable"
        ) from error
    actual_hash = hashlib.sha256(public_key).hexdigest()
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise TelemetryError("configured rollout telemetry public-key SHA-256 differs")
    return TelemetryTrust(
        key_id=key_id,
        public_key_file=public_key_file,
        public_key_sha256=expected_hash,
        public_key=public_key,
    )


def canonical_unsigned_telemetry(root: Mapping[str, Any]) -> bytes:
    unsigned = {key: value for key, value in root.items() if key != "signature"}
    try:
        return json.dumps(
            unsigned,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise TelemetryError("telemetry cannot be canonically encoded") from error


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_base64url(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise TelemetryError(f"{name} must be canonical unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise TelemetryError(
            f"{name} must be canonical unpadded base64url"
        ) from error
    if encode_base64url(decoded) != value:
        raise TelemetryError(f"{name} must be canonical unpadded base64url")
    return decoded


def canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise TelemetryError("artifact cannot be canonically encoded") from error


def _validate_traffic_mapping(value: Any, name: str) -> dict[str, int]:
    if not isinstance(value, dict) or not value:
        raise TelemetryError(f"{name} must be a non-empty object")
    result: dict[str, int] = {}
    for revision, percent in value.items():
        if not isinstance(revision, str) or NAME_RE.fullmatch(revision) is None:
            raise TelemetryError(f"{name} contains an invalid revision")
        if (
            isinstance(percent, bool)
            or not isinstance(percent, int)
            or percent < 0
            or percent > 100
        ):
            raise TelemetryError(f"{name}.{revision} has an invalid percentage")
        result[revision] = percent
    if sum(result.values()) != 100:
        raise TelemetryError(f"{name} traffic must total 100")
    return result


def validate_rollout_context(value: Any) -> dict[str, Any]:
    context = exact_keys(value, ROLLOUT_CONTEXT_KEYS, "context")
    for name in ("project_id", "region", "release_id"):
        raw = context[name]
        if not isinstance(raw, str) or NAME_RE.fullmatch(raw) is None:
            raise TelemetryError(f"context.{name} is invalid")
    if context["transition"] not in ROLLOUT_TRANSITIONS:
        raise TelemetryError("context.transition is unsupported")
    if (
        not isinstance(context["authorization_id"], str)
        or KEY_ID_RE.fullmatch(context["authorization_id"]) is None
    ):
        raise TelemetryError("context.authorization_id is invalid")
    if (
        not isinstance(context["rollout_nonce"], str)
        or NONCE_RE.fullmatch(context["rollout_nonce"]) is None
    ):
        raise TelemetryError("context.rollout_nonce is invalid")

    bindings: dict[str, dict[str, dict[str, str]]] = {}
    for stage in ("candidate", "stable"):
        planes = exact_keys(context[stage], PLANE_KEYS, f"context.{stage}")
        bindings[stage] = {}
        for plane in sorted(PLANE_KEYS):
            binding = exact_keys(
                planes[plane],
                REVISION_BINDING_KEYS,
                f"context.{stage}.{plane}",
            )
            service = binding["service"]
            revision = binding["revision"]
            image = binding["image"]
            if (
                not isinstance(service, str)
                or NAME_RE.fullmatch(service) is None
            ):
                raise TelemetryError(
                    f"context.{stage}.{plane}.service is invalid"
                )
            if (
                not isinstance(revision, str)
                or NAME_RE.fullmatch(revision) is None
                or not revision.startswith(f"{service}-")
            ):
                raise TelemetryError(
                    f"context.{stage}.{plane}.revision is invalid"
                )
            if not isinstance(image, str) or IMAGE_RE.fullmatch(image) is None:
                raise TelemetryError(
                    f"context.{stage}.{plane}.image is not digest pinned"
                )
            bindings[stage][plane] = {
                "service": service,
                "revision": revision,
                "image": image,
            }
    for plane in PLANE_KEYS:
        if bindings["candidate"][plane]["service"] != bindings["stable"][plane][
            "service"
        ]:
            raise TelemetryError(f"context {plane} service binding differs")
        if bindings["candidate"][plane]["revision"] == bindings["stable"][plane][
            "revision"
        ]:
            raise TelemetryError(
                f"context {plane} candidate and stable revisions must differ"
            )

    pre_state = exact_keys(
        context["pre_state"],
        PLANE_KEYS,
        "context.pre_state",
    )
    for plane in sorted(PLANE_KEYS):
        snapshot = exact_keys(
            pre_state[plane],
            SNAPSHOT_BINDING_KEYS,
            f"context.pre_state.{plane}",
        )
        if snapshot["service"] != bindings["candidate"][plane]["service"]:
            raise TelemetryError(
                f"context.pre_state.{plane}.service does not match binding"
            )
        _generation(
            snapshot["generation"],
            f"context.pre_state.{plane}.generation",
        )
        observed = _generation(
            snapshot["observed_generation"],
            f"context.pre_state.{plane}.observed_generation",
        )
        if observed != snapshot["generation"]:
            raise TelemetryError(
                f"context.pre_state.{plane} is not fully observed"
            )
        resource_version = snapshot["resource_version"]
        if (
            not isinstance(resource_version, str)
            or not resource_version
            or any(character.isspace() for character in resource_version)
        ):
            raise TelemetryError(
                f"context.pre_state.{plane}.resource_version is invalid"
            )

    post_traffic = exact_keys(
        context["post_traffic"],
        PLANE_KEYS,
        "context.post_traffic",
    )
    for plane in sorted(PLANE_KEYS):
        traffic = _validate_traffic_mapping(
            post_traffic[plane],
            f"context.post_traffic.{plane}",
        )
        allowed = {
            bindings["candidate"][plane]["revision"],
            bindings["stable"][plane]["revision"],
        }
        if not set(traffic).issubset(allowed):
            raise TelemetryError(
                f"context.post_traffic.{plane} contains an unbound revision"
            )

    raw_thresholds = exact_keys(
        context["thresholds"],
        THRESHOLD_KEYS,
        "context.thresholds",
    )
    thresholds = Thresholds(
        max_error_rate=raw_thresholds["max_error_rate"],
        max_p95_latency_ms=raw_thresholds["max_p95_latency_ms"],
        min_readiness_rate=raw_thresholds["min_readiness_rate"],
        max_indeterminate_rate=raw_thresholds["max_indeterminate_rate"],
        min_dwell_seconds=raw_thresholds["min_dwell_seconds"],
        min_requests=raw_thresholds["min_requests"],
        min_readiness_samples=raw_thresholds["min_readiness_samples"],
        max_sample_gap_seconds=raw_thresholds["max_sample_gap_seconds"],
    )
    _validate_thresholds(thresholds)
    _integer(
        raw_thresholds["max_age_seconds"],
        "context.thresholds.max_age_seconds",
        minimum=1,
    )
    return context


def validate_context_deployment(
    context: Mapping[str, Any],
    config: Mapping[str, str],
) -> None:
    expected = {
        "project_id": config.get("PROJECT_ID"),
        "region": config.get("REGION"),
        "release_id": config.get("RELEASE_ID"),
    }
    for name, value in expected.items():
        if context[name] != value:
            raise TelemetryError(
                f"context.{name} does not match pinned deployment config"
            )
    for plane, prefix in (("actuator", "ACTUATOR"), ("decision", "DECISION")):
        service = config.get(f"{prefix}_SERVICE")
        candidate = {
            "service": service,
            "revision": f"{service}-{config.get('RELEASE_ID')}",
            "image": config.get(f"{prefix}_IMAGE"),
        }
        if context["candidate"][plane] != candidate:
            raise TelemetryError(
                f"context.candidate.{plane} does not match pinned deployment config"
            )
        if context["stable"][plane]["service"] != service:
            raise TelemetryError(
                f"context.stable.{plane}.service does not match pinned config"
            )
        configured_stable = config.get(f"{prefix}_STABLE_REVISION")
        if configured_stable and (
            context["stable"][plane]["revision"] != configured_stable
        ):
            raise TelemetryError(
                f"context.stable.{plane}.revision does not match pinned config"
            )


def validate_unsigned_telemetry(root: Any) -> dict[str, Any]:
    telemetry = exact_keys(root, UNSIGNED_TELEMETRY_KEYS, "telemetry")
    if telemetry["schema"] != TELEMETRY_SCHEMA:
        raise TelemetryError("unsupported telemetry schema")
    validate_rollout_context(telemetry["context"])
    if (
        not isinstance(telemetry["authorization_sha256"], str)
        or SHA256_RE.fullmatch(telemetry["authorization_sha256"]) is None
    ):
        raise TelemetryError("authorization_sha256 is invalid")
    exact_keys(
        telemetry["window"],
        {"started_at", "ended_at"},
        "window",
    )
    if not isinstance(telemetry["services"], dict):
        raise TelemetryError("services must be an object")
    return telemetry


def validate_signed_telemetry(
    root: Any,
    trust: TelemetryTrust,
) -> tuple[dict[str, Any], bytes]:
    telemetry = exact_keys(root, SIGNED_TELEMETRY_KEYS, "signed telemetry")
    if telemetry["schema"] != TELEMETRY_SCHEMA:
        raise TelemetryError("unsupported telemetry schema")
    signature = exact_keys(telemetry["signature"], SIGNATURE_KEYS, "signature")
    if signature["algorithm"] != "Ed25519":
        raise TelemetryError("signature.algorithm must equal 'Ed25519'")
    if signature["key_id"] != trust.key_id:
        raise TelemetryError("signature.key_id does not match configured trust")
    signature_bytes = decode_base64url(signature["value"], "signature.value")
    if len(signature_bytes) != 64:
        raise TelemetryError("signature.value must be a 64-byte Ed25519 signature")
    unsigned = {
        key: value for key, value in telemetry.items() if key != "signature"
    }
    validate_unsigned_telemetry(unsigned)
    return unsigned, signature_bytes


def _run_openssl(command: list[str], failure: str) -> None:
    try:
        result = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise TelemetryError(f"{failure}: openssl is unavailable") from error
    if result.returncode != 0:
        raise TelemetryError(failure)


def verify_telemetry_signature(
    root: Any,
    trust: TelemetryTrust,
) -> dict[str, Any]:
    unsigned, signature_bytes = validate_signed_telemetry(root, trust)
    with tempfile.TemporaryDirectory(prefix="emilia-rollout-verify-") as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.bin"
        public_key_path = Path(directory) / "public.pem"
        payload_path.write_bytes(canonical_unsigned_telemetry(unsigned))
        signature_path.write_bytes(signature_bytes)
        public_key_path.write_bytes(trust.public_key)
        _run_openssl(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-rawin",
                "-in",
                str(payload_path),
                "-sigfile",
                str(signature_path),
            ],
            "rollout telemetry signature is invalid",
        )
    return unsigned


def canonical_unsigned_authorization(root: Mapping[str, Any]) -> bytes:
    return canonical_json(
        {key: value for key, value in root.items() if key != "signature"}
    )


def verify_rollout_authorization_signature(
    root: Any,
    trust: TelemetryTrust,
) -> dict[str, Any]:
    authorization = exact_keys(
        root,
        AUTHORIZATION_SIGNED_KEYS,
        "signed rollout authorization",
    )
    if authorization["schema"] != AUTHORIZATION_SCHEMA:
        raise TelemetryError("unsupported rollout authorization schema")
    validate_rollout_context(authorization["context"])
    exact_keys(
        authorization["consumption"],
        CONSUMPTION_KEYS,
        "authorization.consumption",
    )
    signature = exact_keys(
        authorization["signature"],
        SIGNATURE_KEYS,
        "authorization.signature",
    )
    if signature["algorithm"] != "Ed25519":
        raise TelemetryError(
            "authorization.signature.algorithm must equal 'Ed25519'"
        )
    if signature["key_id"] != trust.key_id:
        raise TelemetryError(
            "authorization.signature.key_id does not match configured trust"
        )
    signature_bytes = decode_base64url(
        signature["value"],
        "authorization.signature.value",
    )
    if len(signature_bytes) != 64:
        raise TelemetryError(
            "authorization.signature.value must be a 64-byte Ed25519 signature"
        )
    with tempfile.TemporaryDirectory(
        prefix="emilia-rollout-authorization-verify-"
    ) as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.bin"
        public_key_path = Path(directory) / "public.pem"
        payload_path.write_bytes(canonical_unsigned_authorization(authorization))
        signature_path.write_bytes(signature_bytes)
        public_key_path.write_bytes(trust.public_key)
        _run_openssl(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-rawin",
                "-in",
                str(payload_path),
                "-sigfile",
                str(signature_path),
            ],
            "rollout authorization signature is invalid",
        )
    return authorization


def validate_consumed_authorization(
    authorization: Mapping[str, Any],
    *,
    expected_context: Mapping[str, Any],
    max_age_seconds: int,
    now: datetime | None = None,
) -> str:
    if authorization["context"] != expected_context:
        raise TelemetryError(
            "rollout authorization context does not match this exact transition"
        )
    consumption = authorization["consumption"]
    if consumption["state"] != "consumed":
        raise TelemetryError("rollout authorization is not externally consumed")
    consumed_at = _parse_utc_timestamp(
        consumption["consumed_at"],
        "authorization.consumption.consumed_at",
    )
    expires_at = _parse_utc_timestamp(
        consumption["expires_at"],
        "authorization.consumption.expires_at",
    )
    if expires_at <= consumed_at:
        raise TelemetryError(
            "rollout authorization expiry must follow consumption"
        )
    if (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, int)
        or max_age_seconds <= 0
    ):
        raise TelemetryError(
            "rollout authorization max age must be a positive integer"
        )
    if (expires_at - consumed_at).total_seconds() > max_age_seconds:
        raise TelemetryError(
            "rollout authorization validity exceeds the immutable maximum"
        )
    current = now or datetime.now().astimezone()
    if current.tzinfo is None or current.utcoffset() is None:
        raise TelemetryError(
            "rollout authorization evaluation time must include a timezone"
        )
    if consumed_at > current:
        raise TelemetryError("rollout authorization is future-dated")
    if current > expires_at:
        raise TelemetryError("rollout authorization is expired")
    return hashlib.sha256(canonical_json(authorization)).hexdigest()


def _validate_private_key_file(private_key: Path) -> None:
    if not private_key.is_absolute():
        raise TelemetryError("private key path must be absolute")
    try:
        metadata = private_key.lstat()
    except OSError as error:
        raise TelemetryError("private key file is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise TelemetryError("private key path must name a regular non-symlink file")
    if metadata.st_uid != os.getuid():
        raise TelemetryError("private key file must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise TelemetryError("private key file mode must be exactly 0600")


def sign_telemetry(
    root: Any,
    *,
    config: Mapping[str, str],
    private_key: Path,
) -> dict[str, Any]:
    unsigned = validate_unsigned_telemetry(root)
    validate_context_deployment(unsigned["context"], config)
    trust = load_telemetry_trust(config)
    _validate_private_key_file(private_key)
    with tempfile.TemporaryDirectory(prefix="emilia-rollout-sign-") as directory:
        work = Path(directory)
        payload_path = work / "payload.json"
        signature_path = work / "signature.bin"
        configured_public_path = work / "configured-public.pem"
        configured_der_path = work / "configured-public.der"
        derived_der_path = work / "derived-public.der"
        payload_path.write_bytes(canonical_unsigned_telemetry(unsigned))
        configured_public_path.write_bytes(trust.public_key)
        _run_openssl(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-in",
                str(configured_public_path),
                "-outform",
                "DER",
                "-out",
                str(configured_der_path),
            ],
            "configured rollout telemetry public key is invalid",
        )
        _run_openssl(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(derived_der_path),
            ],
            "rollout telemetry private key is invalid",
        )
        if not hmac.compare_digest(
            derived_der_path.read_bytes(),
            configured_der_path.read_bytes(),
        ):
            raise TelemetryError(
                "rollout telemetry private key does not match configured trust"
            )
        _run_openssl(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key),
                "-rawin",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            "rollout telemetry signing failed",
        )
        signature_bytes = signature_path.read_bytes()
    if len(signature_bytes) != 64:
        raise TelemetryError("rollout telemetry signer did not produce Ed25519")
    signed = {
        **unsigned,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": trust.key_id,
            "value": encode_base64url(signature_bytes),
        },
    }
    verify_telemetry_signature(signed, trust)
    return signed


def write_atomic_private_json(
    output: Path,
    value: Mapping[str, Any],
    *,
    force: bool,
) -> None:
    try:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise TelemetryError("signed telemetry cannot be encoded") from error
    parent = output.parent
    if not parent.is_dir():
        raise TelemetryError(f"output directory is unavailable: {parent}")
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=str(parent),
            prefix=f".{output.name}.",
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary_name, output)
            temporary_name = ""
        else:
            try:
                os.link(temporary_name, output)
            except FileExistsError as error:
                raise TelemetryError(
                    f"refusing to overwrite existing output without --force: {output}"
                ) from error
            os.unlink(temporary_name)
            temporary_name = ""
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except TelemetryError:
        raise
    except OSError as error:
        raise TelemetryError(
            f"unable to write signed telemetry {output}: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


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


def parse_revision_percentages(value: str) -> dict[str, int]:
    _, targets = parse_expectation(f"service={value}")
    return targets


def _actual_traffic(service: str, records: Any) -> dict[str, int]:
    if not isinstance(records, list) or not records:
        raise TelemetryError(f"{service}.traffic must be a non-empty array")
    targets: dict[str, int] = {}
    for position, record in enumerate(records):
        record = exact_keys(
            record,
            {"revision", "percent"},
            f"{service}.traffic[{position}]",
        )
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
        sample = exact_keys(
            sample,
            {"observed_at", "ready"},
            f"{service}.readiness_samples[{position}]",
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
    *,
    now: datetime | None = None,
    max_age_seconds: int | None = None,
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
    telemetry = validate_unsigned_telemetry(telemetry)

    window = telemetry.get("window")
    if not isinstance(window, dict):
        raise TelemetryError("window must be an object")
    started_at = _parse_utc_timestamp(window.get("started_at"), "window.started_at")
    ended_at = _parse_utc_timestamp(window.get("ended_at"), "window.ended_at")
    if max_age_seconds is not None:
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or max_age_seconds <= 0
        ):
            raise TelemetryError("max_age_seconds must be a positive integer")
        evaluated_at = now or datetime.now().astimezone()
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise TelemetryError("telemetry evaluation time must include a timezone")
        age_seconds = (evaluated_at - ended_at).total_seconds()
        if age_seconds < 0:
            raise TelemetryError("telemetry window ends in the future")
        if age_seconds > max_age_seconds:
            raise TelemetryError(
                f"telemetry is older than {max_age_seconds} seconds"
            )
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
        record = exact_keys(
            services[service],
            {
                "traffic",
                "requests",
                "errors",
                "p95_latency_ms",
                "indeterminate",
                "readiness_samples",
            },
            f"{service} telemetry",
        )
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
        "schema": "emilia-rollout-telemetry-verification.v2",
        "status": "accepted",
        "dwell_seconds": dwell_seconds,
        "services": accepted,
    }


def _generation(value: Any, field: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        result = value
    elif isinstance(value, str) and INTEGER_RE.fullmatch(value) is not None:
        result = int(value)
    else:
        raise TelemetryError(f"{field} must be a positive canonical generation")
    if result <= 0:
        raise TelemetryError(f"{field} must be a positive canonical generation")
    return result


def _service_traffic(
    records: Any,
    field: str,
    *,
    allowed_revisions: set[str],
) -> dict[str, int]:
    if not isinstance(records, list) or not records:
        raise TelemetryError(f"{field} must be a non-empty array")
    totals: dict[str, int] = {}
    seen_tags: set[str] = set()
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            raise TelemetryError(f"{field}[{position}] must be an object")
        if record.get("latestRevision") is True or record.get("type") in {
            "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST",
            "LATEST",
        }:
            raise TelemetryError(f"{field}[{position}] must pin an exact revision")
        revision = record.get("revisionName", record.get("revision"))
        if not isinstance(revision, str) or NAME_RE.fullmatch(revision) is None:
            raise TelemetryError(f"{field}[{position}] revision is invalid")
        if revision not in allowed_revisions:
            raise TelemetryError(f"{field} contains unexpected revision {revision}")
        percent = _integer(record.get("percent"), f"{field}[{position}].percent")
        if percent > 100:
            raise TelemetryError(f"{field}[{position}].percent exceeds 100")
        tag = record.get("tag")
        if tag is not None:
            if not isinstance(tag, str) or NAME_RE.fullmatch(tag) is None:
                raise TelemetryError(f"{field}[{position}].tag is invalid")
            if tag in seen_tags:
                raise TelemetryError(f"{field} contains duplicate tag {tag}")
            seen_tags.add(tag)
        totals[revision] = totals.get(revision, 0) + percent
        if totals[revision] > 100:
            raise TelemetryError(f"{field} over-allocates revision {revision}")
    if sum(totals.values()) != 100:
        raise TelemetryError(f"{field} traffic must total 100")
    return {revision: percent for revision, percent in totals.items() if percent}


def _ready(service: Mapping[str, Any]) -> bool:
    status = service.get("status")
    if not isinstance(status, dict):
        return False
    conditions = status.get("conditions")
    if not isinstance(conditions, list):
        return False
    return any(
        isinstance(condition, dict)
        and condition.get("type") == "Ready"
        and condition.get("status") in (True, "True")
        for condition in conditions
    )


def _ready_failed(service: Mapping[str, Any]) -> bool:
    status = service.get("status")
    if not isinstance(status, dict):
        return True
    conditions = status.get("conditions")
    if not isinstance(conditions, list):
        return True
    return any(
        isinstance(condition, dict)
        and condition.get("type") == "Ready"
        and condition.get("status") in (False, "False")
        for condition in conditions
    )


def evaluate_service_state(
    document: Any,
    *,
    service: str,
    expected_traffic: Mapping[str, int],
    allowed_revisions: set[str],
    pending_from_traffic: Mapping[str, int] | None = None,
    generation_after: int | None = None,
    generation_equals: int | None = None,
    resource_version_not: str | None = None,
    resource_version_equals: str | None = None,
    allow_pending: bool = False,
) -> ServiceState:
    if NAME_RE.fullmatch(service) is None:
        raise TelemetryError("service name is invalid")
    if not isinstance(document, dict):
        raise TelemetryError("Cloud Run service must be an object")
    if document.get("apiVersion") != "serving.knative.dev/v1":
        raise TelemetryError(
            "Cloud Run service apiVersion must be serving.knative.dev/v1"
        )
    if document.get("kind") != "Service":
        raise TelemetryError("Cloud Run resource must be a Service")
    metadata = document.get("metadata")
    spec = document.get("spec")
    status = document.get("status")
    if not isinstance(metadata, dict):
        raise TelemetryError("Cloud Run service metadata is missing")
    if not isinstance(spec, dict):
        raise TelemetryError("Cloud Run service spec is missing")
    if not isinstance(status, dict):
        raise TelemetryError("Cloud Run service status is missing")
    if metadata.get("name") != service:
        raise TelemetryError("Cloud Run service name does not match")

    generation = _generation(metadata.get("generation"), "metadata.generation")
    observed_generation = _generation(
        status.get("observedGeneration"),
        "status.observedGeneration",
    )
    resource_version = metadata.get("resourceVersion")
    if (
        not isinstance(resource_version, str)
        or not resource_version
        or any(character.isspace() for character in resource_version)
    ):
        raise TelemetryError("metadata.resourceVersion is required for locking")
    if generation_after is not None and generation <= generation_after:
        raise TelemetryError("Cloud Run generation did not advance")
    if generation_equals is not None and generation != generation_equals:
        raise TelemetryError("Cloud Run generation differs from the exact lock")
    if resource_version_not is not None and resource_version == resource_version_not:
        raise TelemetryError("Cloud Run resourceVersion did not advance")
    if (
        resource_version_equals is not None
        and resource_version != resource_version_equals
    ):
        raise TelemetryError(
            "Cloud Run resourceVersion differs from the exact snapshot"
        )

    expected = dict(expected_traffic)
    if not expected or sum(expected.values()) != 100:
        raise TelemetryError("expected service traffic must total 100")
    if not set(expected).issubset(allowed_revisions):
        raise TelemetryError("expected traffic contains an unapproved revision")
    desired = _service_traffic(
        spec.get("traffic"),
        "spec.traffic",
        allowed_revisions=allowed_revisions,
    )
    if desired != expected:
        raise TelemetryError(
            f"{service} desired traffic {desired} does not match expected {expected}"
        )

    observed = _service_traffic(
        status.get("traffic"),
        "status.traffic",
        allowed_revisions=allowed_revisions,
    )
    if observed_generation == generation:
        if observed != expected:
            raise TelemetryError(
                f"{service} observed traffic {observed} does not match expected "
                f"{expected}"
            )
        if not _ready(document):
            raise TelemetryError(f"{service} is not Ready")
    else:
        if observed_generation > generation:
            raise TelemetryError("status.observedGeneration exceeds generation")
        if _ready_failed(document):
            raise TelemetryError(f"{service} reconciliation failed")
        pending = dict(pending_from_traffic or {})
        if not pending or observed != pending:
            raise TelemetryError(
                f"{service} has an unapproved generation/observedGeneration mismatch"
            )
        if not allow_pending:
            raise PendingReconciliation(f"{service} is still reconciling")

    return ServiceState(
        service=service,
        generation=generation,
        observed_generation=observed_generation,
        resource_version=resource_version,
        traffic=observed,
    )


def transition_contract(
    action: str,
    *,
    decision_stable: str,
    decision_candidate: str,
    actuator_stable: str,
    actuator_candidate: str,
) -> Transition:
    decision_stable_traffic = {decision_stable: 100}
    actuator_stable_traffic = {actuator_stable: 100}
    contracts = {
        "apply-decision-1": Transition(
            "decision",
            decision_stable_traffic,
            actuator_stable_traffic,
            {decision_candidate: 1, decision_stable: 99},
        ),
        "apply-decision-10": Transition(
            "decision",
            {decision_candidate: 1, decision_stable: 99},
            actuator_stable_traffic,
            {decision_candidate: 10, decision_stable: 90},
        ),
        "apply-decision-50": Transition(
            "decision",
            {decision_candidate: 10, decision_stable: 90},
            actuator_stable_traffic,
            {decision_candidate: 50, decision_stable: 50},
        ),
        "apply-decision-100": Transition(
            "decision",
            {decision_candidate: 50, decision_stable: 50},
            actuator_stable_traffic,
            {decision_candidate: 100},
        ),
        "apply-actuator-100": Transition(
            "actuator",
            {decision_candidate: 100},
            actuator_stable_traffic,
            {actuator_candidate: 100},
        ),
    }
    try:
        return contracts[action]
    except KeyError as error:
        raise TelemetryError(f"unsupported rollout transition: {action}") from error


def evaluate_transition_pre_state(
    action: str,
    decision_document: Any,
    actuator_document: Any,
    *,
    decision_service: str,
    decision_stable: str,
    decision_candidate: str,
    actuator_service: str,
    actuator_stable: str,
    actuator_candidate: str,
) -> tuple[Transition, ServiceState, ServiceState]:
    transition = transition_contract(
        action,
        decision_stable=decision_stable,
        decision_candidate=decision_candidate,
        actuator_stable=actuator_stable,
        actuator_candidate=actuator_candidate,
    )
    decision_state = evaluate_service_state(
        decision_document,
        service=decision_service,
        expected_traffic=transition.pre_decision,
        allowed_revisions={decision_stable, decision_candidate},
    )
    actuator_state = evaluate_service_state(
        actuator_document,
        service=actuator_service,
        expected_traffic=transition.pre_actuator,
        allowed_revisions={actuator_stable, actuator_candidate},
    )
    return transition, decision_state, actuator_state


def classify_rollback_pre_state(
    decision_document: Any,
    actuator_document: Any,
    *,
    decision_service: str,
    decision_stable: str,
    decision_candidate: str,
    actuator_service: str,
    actuator_stable: str,
    actuator_candidate: str,
) -> str:
    decision_stage: str | None = None
    for stage, traffic in (
        ("stable", {decision_stable: 100}),
        ("1", {decision_candidate: 1, decision_stable: 99}),
        ("10", {decision_candidate: 10, decision_stable: 90}),
        ("50", {decision_candidate: 50, decision_stable: 50}),
        ("100", {decision_candidate: 100}),
    ):
        try:
            evaluate_service_state(
                decision_document,
                service=decision_service,
                expected_traffic=traffic,
                allowed_revisions={decision_stable, decision_candidate},
            )
            decision_stage = stage
            break
        except TelemetryError:
            continue
    if decision_stage is None:
        raise TelemetryError("decision service is not in a rollback-safe rollout state")

    actuator_stage: str | None = None
    for stage, traffic in (
        ("stable", {actuator_stable: 100}),
        ("100", {actuator_candidate: 100}),
    ):
        try:
            evaluate_service_state(
                actuator_document,
                service=actuator_service,
                expected_traffic=traffic,
                allowed_revisions={actuator_stable, actuator_candidate},
            )
            actuator_stage = stage
            break
        except TelemetryError:
            continue
    if actuator_stage is None:
        raise TelemetryError("actuator service is not in a rollback-safe rollout state")
    if actuator_stage == "100" and decision_stage not in {"100", "stable"}:
        raise TelemetryError("actuator candidate cannot precede decision candidate 100")
    if actuator_stage == "100":
        return f"actuator:{decision_stage}"
    if decision_stage != "stable":
        return f"decision:{decision_stage}"
    return "stable"


def build_service_update(
    document: Any,
    *,
    service: str,
    expected_traffic: Mapping[str, int],
    target_traffic: Mapping[str, int],
    allowed_revisions: set[str],
) -> tuple[dict[str, Any], ServiceState]:
    state = evaluate_service_state(
        document,
        service=service,
        expected_traffic=expected_traffic,
        allowed_revisions=allowed_revisions,
    )
    metadata = document["metadata"]
    namespace = metadata.get("namespace")
    if not isinstance(namespace, str) or not namespace:
        raise TelemetryError("metadata.namespace is required for a locked update")
    target = dict(target_traffic)
    if not target or sum(target.values()) != 100:
        raise TelemetryError("target traffic must total 100")
    if not set(target).issubset(allowed_revisions):
        raise TelemetryError("target traffic contains an unapproved revision")

    tagged: list[dict[str, Any]] = []
    seen_tags: set[str] = set()
    for record in document["spec"]["traffic"]:
        tag = record.get("tag")
        if tag is None:
            continue
        if tag in seen_tags:
            raise TelemetryError(f"spec.traffic contains duplicate tag {tag}")
        seen_tags.add(tag)
        revision = record.get("revisionName", record.get("revision"))
        tagged.append({"revisionName": revision, "percent": 0, "tag": tag})
    traffic = tagged + [
        {"revisionName": revision, "percent": percent}
        for revision, percent in sorted(target.items())
        if percent
    ]
    body = {
        "apiVersion": "serving.knative.dev/v1",
        "kind": "Service",
        "metadata": {
            "name": service,
            "namespace": namespace,
            "resourceVersion": state.resource_version,
            **(
                {"labels": deepcopy(metadata["labels"])}
                if isinstance(metadata.get("labels"), dict)
                else {}
            ),
            **(
                {"annotations": deepcopy(metadata["annotations"])}
                if isinstance(metadata.get("annotations"), dict)
                else {}
            ),
        },
        "spec": deepcopy(document["spec"]),
    }
    body["spec"]["traffic"] = traffic
    return body, state


def thresholds_context(
    thresholds: Thresholds,
    *,
    max_age_seconds: int,
) -> dict[str, int | float]:
    _validate_thresholds(thresholds)
    _integer(max_age_seconds, "max_age_seconds", minimum=1)
    return {
        "max_error_rate": thresholds.max_error_rate,
        "max_p95_latency_ms": thresholds.max_p95_latency_ms,
        "min_readiness_rate": thresholds.min_readiness_rate,
        "max_indeterminate_rate": thresholds.max_indeterminate_rate,
        "min_dwell_seconds": thresholds.min_dwell_seconds,
        "min_requests": thresholds.min_requests,
        "min_readiness_samples": thresholds.min_readiness_samples,
        "max_sample_gap_seconds": thresholds.max_sample_gap_seconds,
        "max_age_seconds": max_age_seconds,
    }


def _parse_expectations(
    values: Sequence[str],
    *,
    name: str,
) -> dict[str, dict[str, int]]:
    expectations: dict[str, dict[str, int]] = {}
    for raw in values:
        service, targets = parse_expectation(raw)
        if service in expectations:
            raise TelemetryError(f"duplicate {name} service: {service}")
        expectations[service] = targets
    return expectations


def build_expected_rollout_context(
    *,
    config: Mapping[str, str],
    transition: str,
    authorization_context: Mapping[str, Any],
    expectations: Mapping[str, Mapping[str, int]],
    post_expectations: Mapping[str, Mapping[str, int]],
    actuator_stable_revision: str,
    actuator_stable_image: str,
    decision_stable_revision: str,
    decision_stable_image: str,
    actuator_snapshot: Any,
    decision_snapshot: Any,
    thresholds: Thresholds,
    max_age_seconds: int,
) -> dict[str, Any]:
    services = {
        "actuator": config.get("ACTUATOR_SERVICE", ""),
        "decision": config.get("DECISION_SERVICE", ""),
    }
    if set(expectations) != set(services.values()):
        raise TelemetryError(
            "pre-state expectations must exactly name both configured services"
        )
    if set(post_expectations) != set(services.values()):
        raise TelemetryError(
            "post-state expectations must exactly name both configured services"
        )
    stable = {
        "actuator": {
            "service": services["actuator"],
            "revision": actuator_stable_revision,
            "image": actuator_stable_image,
        },
        "decision": {
            "service": services["decision"],
            "revision": decision_stable_revision,
            "image": decision_stable_image,
        },
    }
    candidate = {
        plane: {
            "service": service,
            "revision": f"{service}-{config.get('RELEASE_ID', '')}",
            "image": config.get(f"{plane.upper()}_IMAGE", ""),
        }
        for plane, service in services.items()
    }
    if transition.startswith("apply-") and transition not in {
        "apply-rollback-actuator",
        "apply-rollback-decision",
    }:
        contract = transition_contract(
            transition,
            decision_stable=stable["decision"]["revision"],
            decision_candidate=candidate["decision"]["revision"],
            actuator_stable=stable["actuator"]["revision"],
            actuator_candidate=candidate["actuator"]["revision"],
        )
        canonical_pre = {
            services["decision"]: contract.pre_decision,
            services["actuator"]: contract.pre_actuator,
        }
        canonical_post = {
            services["decision"]: (
                contract.post_traffic
                if contract.service == "decision"
                else contract.pre_decision
            ),
            services["actuator"]: (
                contract.post_traffic
                if contract.service == "actuator"
                else contract.pre_actuator
            ),
        }
        if {
            service: dict(traffic)
            for service, traffic in expectations.items()
        } != canonical_pre:
            raise TelemetryError(
                "pre-state traffic does not match the named rollout transition"
            )
        if {
            service: dict(traffic)
            for service, traffic in post_expectations.items()
        } != canonical_post:
            raise TelemetryError(
                "post-state traffic does not match the named rollout transition"
            )
    elif transition == "apply-rollback-actuator":
        decision_pre = dict(expectations[services["decision"]])
        if decision_pre not in (
            {candidate["decision"]["revision"]: 100},
            {stable["decision"]["revision"]: 100},
        ):
            raise TelemetryError(
                "actuator rollback requires decision at candidate or stable 100"
            )
        if dict(expectations[services["actuator"]]) != {
            candidate["actuator"]["revision"]: 100
        }:
            raise TelemetryError(
                "actuator rollback pre-state must be candidate 100"
            )
        if dict(post_expectations[services["decision"]]) != decision_pre:
            raise TelemetryError(
                "actuator rollback must not change decision traffic"
            )
        if dict(post_expectations[services["actuator"]]) != {
            stable["actuator"]["revision"]: 100
        }:
            raise TelemetryError(
                "actuator rollback post-state must be stable 100"
            )
    else:
        decision_pre = dict(expectations[services["decision"]])
        allowed_decision_pre = (
            {candidate["decision"]["revision"]: 1, stable["decision"]["revision"]: 99},
            {candidate["decision"]["revision"]: 10, stable["decision"]["revision"]: 90},
            {candidate["decision"]["revision"]: 50, stable["decision"]["revision"]: 50},
            {candidate["decision"]["revision"]: 100},
        )
        if decision_pre not in allowed_decision_pre:
            raise TelemetryError(
                "decision rollback pre-state is not a governed rollout stage"
            )
        actuator_stable = {stable["actuator"]["revision"]: 100}
        if dict(expectations[services["actuator"]]) != actuator_stable:
            raise TelemetryError(
                "decision rollback requires actuator stable 100"
            )
        if dict(post_expectations[services["actuator"]]) != actuator_stable:
            raise TelemetryError(
                "decision rollback must not change actuator traffic"
            )
        if dict(post_expectations[services["decision"]]) != {
            stable["decision"]["revision"]: 100
        }:
            raise TelemetryError(
                "decision rollback post-state must be stable 100"
            )
    snapshots = {
        "actuator": actuator_snapshot,
        "decision": decision_snapshot,
    }
    pre_state: dict[str, dict[str, Any]] = {}
    post_traffic: dict[str, dict[str, int]] = {}
    for plane, service in services.items():
        state = evaluate_service_state(
            snapshots[plane],
            service=service,
            expected_traffic=expectations[service],
            allowed_revisions={
                stable[plane]["revision"],
                candidate[plane]["revision"],
            },
        )
        pre_state[plane] = {
            "service": service,
            "generation": state.generation,
            "observed_generation": state.observed_generation,
            "resource_version": state.resource_version,
        }
        post_traffic[plane] = dict(post_expectations[service])
    expected = {
        "project_id": config.get("PROJECT_ID"),
        "region": config.get("REGION"),
        "release_id": config.get("RELEASE_ID"),
        "transition": transition,
        "authorization_id": authorization_context.get("authorization_id"),
        "rollout_nonce": authorization_context.get("rollout_nonce"),
        "candidate": candidate,
        "stable": stable,
        "pre_state": pre_state,
        "post_traffic": post_traffic,
        "thresholds": thresholds_context(
            thresholds,
            max_age_seconds=max_age_seconds,
        ),
    }
    validate_rollout_context(expected)
    validate_context_deployment(expected, config)
    return expected


def _add_threshold_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--max-p95-latency-ms", type=float, default=500)
    parser.add_argument("--min-readiness-rate", type=float, default=0.99)
    parser.add_argument("--max-indeterminate-rate", type=float, default=0.005)
    parser.add_argument("--min-dwell-seconds", type=int, default=600)
    parser.add_argument("--min-requests", type=int, default=100)
    parser.add_argument("--min-readiness-samples", type=int, default=3)
    parser.add_argument("--max-sample-gap-seconds", type=int, default=300)
    parser.add_argument("--max-age-seconds", type=int, default=900)


def _add_rollout_context_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--transition", choices=sorted(ROLLOUT_TRANSITIONS), required=True)
    parser.add_argument("--expect-traffic", action="append", required=True)
    parser.add_argument("--post-traffic", action="append", required=True)
    parser.add_argument("--actuator-stable-revision", required=True)
    parser.add_argument("--actuator-stable-image", required=True)
    parser.add_argument("--decision-stable-revision", required=True)
    parser.add_argument("--decision-stable-image", required=True)
    parser.add_argument("--actuator-snapshot", type=Path, required=True)
    parser.add_argument("--decision-snapshot", type=Path, required=True)
    _add_threshold_arguments(parser)


def _thresholds_from_args(args: argparse.Namespace) -> Thresholds:
    return Thresholds(
        max_error_rate=args.max_error_rate,
        max_p95_latency_ms=args.max_p95_latency_ms,
        min_readiness_rate=args.min_readiness_rate,
        max_indeterminate_rate=args.max_indeterminate_rate,
        min_dwell_seconds=args.min_dwell_seconds,
        min_requests=args.min_requests,
        min_readiness_samples=args.min_readiness_samples,
        max_sample_gap_seconds=args.max_sample_gap_seconds,
    )


def verify_authorization_for_rollout(
    args: argparse.Namespace,
    *,
    config: Mapping[str, str],
    trust: TelemetryTrust,
) -> tuple[
    dict[str, Any],
    str,
    dict[str, dict[str, int]],
    dict[str, Any],
]:
    expectations = _parse_expectations(
        args.expect_traffic,
        name="pre-state expectation",
    )
    post_expectations = _parse_expectations(
        args.post_traffic,
        name="post-state expectation",
    )
    authorization = verify_rollout_authorization_signature(
        _load_json(args.authorization, "rollout authorization"),
        trust,
    )
    expected_context = build_expected_rollout_context(
        config=config,
        transition=args.transition,
        authorization_context=authorization["context"],
        expectations=expectations,
        post_expectations=post_expectations,
        actuator_stable_revision=args.actuator_stable_revision,
        actuator_stable_image=args.actuator_stable_image,
        decision_stable_revision=args.decision_stable_revision,
        decision_stable_image=args.decision_stable_image,
        actuator_snapshot=_load_json(args.actuator_snapshot, "actuator snapshot"),
        decision_snapshot=_load_json(args.decision_snapshot, "decision snapshot"),
        thresholds=_thresholds_from_args(args),
        max_age_seconds=args.max_age_seconds,
    )
    authorization_hash = validate_consumed_authorization(
        authorization,
        expected_context=expected_context,
        max_age_seconds=args.max_age_seconds,
    )
    return expected_context, authorization_hash, expectations, authorization


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Authenticate and verify exact rollout traffic and structured dwell "
            "telemetry."
        )
    )
    _add_rollout_context_arguments(parser)
    parser.add_argument("--input", type=Path, required=True)
    return parser


def _authorization_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify one externally consumed rollout authorization against exact "
            "deployment and Cloud Run pre-state bindings."
        )
    )
    _add_rollout_context_arguments(parser)
    return parser


def _sign_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sign closed rollout telemetry with configured Ed25519 trust."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    return parser


def _load_json(path: Path, name: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_json_constant,
        )
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        raise TelemetryError(f"unable to load {name} {path}: {error}") from error


def _state_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--expect-traffic", required=True)
    parser.add_argument("--allowed-revision", action="append", required=True)
    parser.add_argument("--pending-from-traffic")
    parser.add_argument("--generation-after", type=int)
    parser.add_argument("--generation-equals", type=int)
    parser.add_argument("--resource-version-not")
    parser.add_argument("--resource-version-equals")
    return parser


def _service_state_main(argv: Sequence[str]) -> int:
    parser = _state_parser("Verify one exact, settled Cloud Run service state.")
    args = parser.parse_args(argv)
    try:
        state = evaluate_service_state(
            _load_json(args.input, "service"),
            service=args.service,
            expected_traffic=parse_revision_percentages(args.expect_traffic),
            allowed_revisions=set(args.allowed_revision),
            pending_from_traffic=(
                parse_revision_percentages(args.pending_from_traffic)
                if args.pending_from_traffic
                else None
            ),
            generation_after=args.generation_after,
            generation_equals=args.generation_equals,
            resource_version_not=args.resource_version_not,
            resource_version_equals=args.resource_version_equals,
        )
    except PendingReconciliation as error:
        print(f"pending: {error}", file=sys.stderr)
        return 2
    except TelemetryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"{state.generation}\t{state.resource_version}")
    return 0


def _update_ack_main(argv: Sequence[str]) -> int:
    parser = _state_parser(
        "Verify an acknowledged resourceVersion-locked Cloud Run update."
    )
    args = parser.parse_args(argv)
    if args.pending_from_traffic is None:
        parser.error("--pending-from-traffic is required")
    if args.generation_after is None:
        parser.error("--generation-after is required")
    if args.resource_version_not is None:
        parser.error("--resource-version-not is required")
    try:
        state = evaluate_service_state(
            _load_json(args.input, "update response"),
            service=args.service,
            expected_traffic=parse_revision_percentages(args.expect_traffic),
            allowed_revisions=set(args.allowed_revision),
            pending_from_traffic=parse_revision_percentages(
                args.pending_from_traffic
            ),
            generation_after=args.generation_after,
            resource_version_not=args.resource_version_not,
            allow_pending=True,
        )
    except TelemetryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"{state.generation}\t{state.resource_version}")
    return 0


def _prepare_update_main(argv: Sequence[str]) -> int:
    parser = _state_parser("Prepare a resourceVersion-locked Cloud Run update.")
    parser.add_argument("--target-traffic", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        body, state = build_service_update(
            _load_json(args.input, "service"),
            service=args.service,
            expected_traffic=parse_revision_percentages(args.expect_traffic),
            target_traffic=parse_revision_percentages(args.target_traffic),
            allowed_revisions=set(args.allowed_revision),
        )
        args.output.write_text(
            json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    except (OSError, TelemetryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"{state.generation}\t{state.resource_version}")
    return 0


def _sign_main(argv: Sequence[str]) -> int:
    args = _sign_parser().parse_args(argv)
    try:
        signed = sign_telemetry(
            _load_json(args.input, "unsigned telemetry"),
            config=load_pinned_config(args.config),
            private_key=args.private_key_file,
        )
        write_atomic_private_json(args.output, signed, force=args.force)
    except TelemetryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"signed rollout telemetry written to {args.output}")
    return 0


def _authorization_main(argv: Sequence[str]) -> int:
    args = _authorization_parser().parse_args(argv)
    try:
        config = load_pinned_config(args.config)
        trust = load_telemetry_trust(config)
        _, authorization_hash, _, _ = verify_authorization_for_rollout(
            args,
            config=config,
            trust=trust,
        )
    except TelemetryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(authorization_hash)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv if argv is not None else sys.argv[1:])
    if arguments and arguments[0] == "verify-service":
        return _service_state_main(arguments[1:])
    if arguments and arguments[0] == "verify-update-ack":
        return _update_ack_main(arguments[1:])
    if arguments and arguments[0] == "prepare-update":
        return _prepare_update_main(arguments[1:])
    if arguments and arguments[0] == "sign":
        return _sign_main(arguments[1:])
    if arguments and arguments[0] == "verify-authorization":
        return _authorization_main(arguments[1:])
    args = _parser().parse_args(arguments)
    try:
        config = load_pinned_config(args.config)
        trust = load_telemetry_trust(config)
        (
            expected_context,
            authorization_hash,
            expectations,
            authorization,
        ) = verify_authorization_for_rollout(
            args,
            config=config,
            trust=trust,
        )
        telemetry = verify_telemetry_signature(
            _load_json(args.input, "signed telemetry"),
            trust,
        )
        if telemetry["context"] != expected_context:
            raise TelemetryError(
                "telemetry context does not match this exact rollout transition"
            )
        if telemetry["authorization_sha256"] != authorization_hash:
            raise TelemetryError(
                "telemetry does not bind the consumed rollout authorization"
            )
        consumed_at = _parse_utc_timestamp(
            authorization["consumption"]["consumed_at"],
            "authorization.consumption.consumed_at",
        )
        started_at = _parse_utc_timestamp(
            telemetry["window"]["started_at"],
            "window.started_at",
        )
        if consumed_at > started_at:
            raise TelemetryError(
                "telemetry window begins before authorization consumption"
            )
        result = evaluate_telemetry(
            telemetry,
            expectations,
            _thresholds_from_args(args),
            max_age_seconds=args.max_age_seconds,
        )
    except TelemetryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
