#!/usr/bin/env python3
"""Verify signed, fresh canary evidence and its live Cloud Run revisions."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
from decimal import Decimal, InvalidOperation
from pathlib import Path

DIGEST_IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.@-]{3,256}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = "EP-CONSEQUENCE-CANARY-EVIDENCE-v1"
MAX_CLOCK_SKEW_SECONDS = 30
CANARY_TAG_PREFIX = "canary-"
NETWORK_INTERFACES_ANNOTATION = "run.googleapis.com/network-interfaces"
VPC_EGRESS_ANNOTATION = "run.googleapis.com/vpc-access-egress"
INGRESS_ANNOTATION = "run.googleapis.com/ingress"
EXECUTION_ENVIRONMENT_ANNOTATION = "run.googleapis.com/execution-environment"
SESSION_AFFINITY_ANNOTATION = "run.googleapis.com/sessionAffinity"
MIN_SCALE_ANNOTATION = "autoscaling.knative.dev/minScale"
MAX_SCALE_ANNOTATION = "autoscaling.knative.dev/maxScale"
INVOKER_IAM_DISABLED_ANNOTATION = "run.googleapis.com/invoker-iam-disabled"

NON_BEHAVIOR_LABELS = {
    "cloud.googleapis.com/location",
    "run.googleapis.com/startupProbeType",
    "serving.knative.dev/configuration",
    "serving.knative.dev/configurationGeneration",
    "serving.knative.dev/route",
    "serving.knative.dev/serviceUid",
}

NON_BEHAVIOR_ANNOTATIONS = {
    "run.googleapis.com/client-name",
    "run.googleapis.com/client-version",
    "run.googleapis.com/operation-id",
    "run.googleapis.com/urls",
    "serving.knative.dev/creator",
    "serving.knative.dev/lastModifier",
}

ACTUATOR_SECRET_BINDINGS = {
    "EMILIA_ACTUATOR_DATABASE_URL": "ACTUATOR_DATABASE_URL_SECRET",
    "EMILIA_ACTUATOR_API_TOKEN": "ACTUATOR_API_TOKEN_SECRET",
    "EMILIA_ACTUATOR_ENVELOPE_PUBLIC_KEY": (
        "ACTUATOR_ENVELOPE_PUBLIC_KEY_SECRET"
    ),
    "EMILIA_ACTUATOR_OBSERVATION_PRIVATE_KEY": (
        "ACTUATOR_OBSERVATION_PRIVATE_KEY_SECRET"
    ),
    "EMILIA_ACTUATOR_GITHUB_APP_ID": "ACTUATOR_GITHUB_APP_ID_SECRET",
    "EMILIA_ACTUATOR_GITHUB_INSTALLATION_ID": (
        "ACTUATOR_GITHUB_INSTALLATION_ID_SECRET"
    ),
    "EMILIA_ACTUATOR_GITHUB_PRIVATE_KEY": (
        "ACTUATOR_GITHUB_PRIVATE_KEY_SECRET"
    ),
}

DECISION_SECRET_BINDINGS = {
    "EMILIA_CONSEQUENCE_EXECUTOR_DATABASE_URL": (
        "DECISION_EXECUTOR_DATABASE_URL_SECRET"
    ),
    "EMILIA_CONSEQUENCE_RECOVERY_DATABASE_URL": (
        "DECISION_RECOVERY_DATABASE_URL_SECRET"
    ),
    "EMILIA_CONSEQUENCE_API_TOKEN": "DECISION_API_TOKEN_SECRET",
    "EMILIA_CONSEQUENCE_RECOVERY_TOKEN": "DECISION_RECOVERY_TOKEN_SECRET",
    "EMILIA_CONSEQUENCE_PROPOSAL_HMAC_KEY": (
        "DECISION_PROPOSAL_HMAC_KEY_SECRET"
    ),
    "EMILIA_CONSEQUENCE_OWNER_HMAC_KEY": "DECISION_OWNER_HMAC_KEY_SECRET",
    "EMILIA_CONSEQUENCE_GATE_TRUST_JSON": "DECISION_GATE_TRUST_JSON_SECRET",
    "EMILIA_CONSEQUENCE_AEB_CONFIG_JSON": "DECISION_AEB_CONFIG_JSON_SECRET",
    "EMILIA_CONSEQUENCE_STATUS_CONFIG_JSON": (
        "DECISION_STATUS_CONFIG_JSON_SECRET"
    ),
    "EMILIA_CONSEQUENCE_APPROVAL_TOKEN": "DECISION_APPROVAL_TOKEN_SECRET",
    "EMILIA_CONSEQUENCE_ACTUATOR_API_TOKEN": "ACTUATOR_API_TOKEN_SECRET",
    "EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_PRIVATE_KEY": (
        "DECISION_ENVELOPE_PRIVATE_KEY_SECRET"
    ),
    "EMILIA_CONSEQUENCE_ACTUATOR_EVIDENCE_PUBLIC_KEY": (
        "DECISION_OBSERVATION_PUBLIC_KEY_SECRET"
    ),
}


def reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def parse_config(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw in enumerate(value.splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise ValueError(f"invalid config line {number}")
        key, value = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"invalid config key on line {number}")
        if key in {"DEPLOYMENT_CONFIG_SHA256", "REQUIRE_DEPLOYMENT_CONFIG_PIN"}:
            raise ValueError(
                f"protected config controls are forbidden in config: {key}"
            )
        if key in result:
            raise ValueError(f"duplicate config key on line {number}")
        result[key] = value
    return result


def load_config(path: Path) -> dict[str, str]:
    return parse_config(path.read_text(encoding="utf-8"))


def load_pinned_config(path: Path) -> dict[str, str]:
    expected = os.environ.get("DEPLOYMENT_CONFIG_SHA256", "")
    if SHA256.fullmatch(expected) is None:
        raise ValueError(
            "DEPLOYMENT_CONFIG_SHA256 must be injected by a protected source"
        )
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError("deployment config differs from protected SHA-256")
    try:
        return parse_config(raw.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ValueError("deployment config is not UTF-8") from error


def exact_keys(value: object, expected: set[str], name: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{name} must contain exactly {sorted(expected)}")
    return value


def require_equal(value: object, expected: object, name: str) -> None:
    if value != expected:
        raise ValueError(f"{name} must equal {expected!r}")


def parse_time(value: object, name: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an RFC 3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def canonical_unsigned_evidence(root: dict) -> bytes:
    unsigned = {key: value for key, value in root.items() if key != "signature"}
    return json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_base64url(value: object, name: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError(f"{name} must be unpadded base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise ValueError(f"{name} must be unpadded base64url") from error


def verify_signature(config: dict[str, str], root: dict) -> None:
    signature = exact_keys(
        root["signature"],
        {"algorithm", "key_id", "value"},
        "signature",
    )
    require_equal(signature["algorithm"], "Ed25519", "signature.algorithm")
    require_equal(
        signature["key_id"],
        config["CANARY_EVIDENCE_KEY_ID"],
        "signature.key_id",
    )
    signature_bytes = decode_base64url(signature["value"], "signature.value")
    if len(signature_bytes) != 64:
        raise ValueError("signature.value must be a 64-byte Ed25519 signature")
    public_key_path = Path(config["CANARY_EVIDENCE_PUBLIC_KEY_FILE"])
    if not public_key_path.is_absolute() or not public_key_path.is_file():
        raise ValueError("pinned canary public key file is unavailable")
    expected_hash = config.get("CANARY_EVIDENCE_PUBLIC_KEY_SHA256", "")
    if SHA256.fullmatch(expected_hash) is None:
        raise ValueError("CANARY_EVIDENCE_PUBLIC_KEY_SHA256 is invalid")
    public_key = public_key_path.read_bytes()
    actual_hash = hashlib.sha256(public_key).hexdigest()
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise ValueError("pinned canary public key SHA-256 differs")
    with tempfile.TemporaryDirectory(prefix="emilia-canary-verify-") as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.bin"
        public_key_path = Path(directory) / "public.pem"
        payload_path.write_bytes(canonical_unsigned_evidence(root))
        signature_path.write_bytes(signature_bytes)
        public_key_path.write_bytes(public_key)
        result = subprocess.run(
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
            check=False,
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        raise ValueError("canary evidence signature is invalid")


def validate_freshness(
    config: dict[str, str],
    root: dict,
    now: dt.datetime | None = None,
) -> None:
    observed_at = parse_time(root["observed_at"], "observed_at")
    expires_at = parse_time(root["expires_at"], "expires_at")
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    max_age = int(config["CANARY_MAX_AGE_SEC"])
    if max_age <= 0:
        raise ValueError("CANARY_MAX_AGE_SEC must be positive")
    if observed_at > current + dt.timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ValueError("canary evidence is future-dated")
    if current > expires_at:
        raise ValueError("canary evidence is expired")
    if expires_at <= observed_at:
        raise ValueError("canary evidence expiry must follow observation")
    if expires_at - observed_at > dt.timedelta(seconds=max_age):
        raise ValueError("canary evidence validity window exceeds the pinned maximum")
    if current - observed_at > dt.timedelta(seconds=max_age):
        raise ValueError("canary evidence is stale")


def validate_indeterminate_initial(value: object, name: str) -> None:
    initial = exact_keys(
        value,
        {"http_status", "outcome", "effect_boundary_entered"},
        name,
    )
    require_equal(initial["http_status"], 202, f"{name}.http_status")
    require_equal(initial["outcome"], "INDETERMINATE", f"{name}.outcome")
    require_equal(
        initial["effect_boundary_entered"],
        True,
        f"{name}.effect_boundary_entered",
    )


def validate_replay(value: object, name: str) -> None:
    replay = exact_keys(
        value,
        {"http_status", "reason", "provider_invocations"},
        name,
    )
    require_equal(replay["http_status"], 409, f"{name}.http_status")
    require_equal(replay["reason"], "envelope_replayed", f"{name}.reason")
    require_equal(
        replay["provider_invocations"],
        1,
        f"{name}.provider_invocations",
    )


def validate(config: dict[str, str], evidence: object) -> None:
    root = exact_keys(
        evidence,
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
        "evidence",
    )
    verify_signature(config, root)
    require_equal(root["@version"], VERSION, "@version")
    require_equal(root["project_id"], config["PROJECT_ID"], "project_id")
    require_equal(root["region"], config["REGION"], "region")
    require_equal(root["evidence_status"], "observed", "evidence_status")
    if not isinstance(root["nonce"], str) or not NONCE.fullmatch(root["nonce"]):
        raise ValueError("nonce is invalid")
    validate_freshness(config, root)

    expected_actuator_revision = (
        f"{config['ACTUATOR_SERVICE']}-{config['RELEASE_ID']}"
    )
    expected_decision_revision = (
        f"{config['DECISION_SERVICE']}-{config['RELEASE_ID']}"
    )
    require_equal(
        root["actuator_revision"],
        expected_actuator_revision,
        "actuator_revision",
    )
    require_equal(
        root["decision_revision"],
        expected_decision_revision,
        "decision_revision",
    )
    for key in ("ACTUATOR_IMAGE", "DECISION_IMAGE"):
        if not DIGEST_IMAGE.fullmatch(config[key]):
            raise ValueError(f"{key} is not digest pinned")
    require_equal(root["actuator_image"], config["ACTUATOR_IMAGE"], "actuator_image")
    require_equal(root["decision_image"], config["DECISION_IMAGE"], "decision_image")

    checks = exact_keys(
        root["checks"],
        {
            "exact_execution",
            "provider_response_loss",
            "actuator_response_loss",
        },
        "checks",
    )
    execution = exact_keys(
        checks["exact_execution"],
        {
            "http_status",
            "outcome",
            "action_digest",
            "attempt_id",
            "provider_reference",
        },
        "checks.exact_execution",
    )
    require_equal(execution["http_status"], 200, "exact_execution.http_status")
    require_equal(execution["outcome"], "COMMITTED", "exact_execution.outcome")
    if not isinstance(execution["action_digest"], str) or not DIGEST.fullmatch(
        execution["action_digest"]
    ):
        raise ValueError("exact_execution.action_digest must be sha256")
    if not isinstance(execution["attempt_id"], str) or not IDENTIFIER.fullmatch(
        execution["attempt_id"]
    ):
        raise ValueError("exact_execution.attempt_id is invalid")
    expected_provider_reference = (
        f"github:issue:{config['GITHUB_OWNER']}/"
        f"{config['GITHUB_REPO']}#{config['GITHUB_ISSUE_NUMBER']}"
    )
    require_equal(
        execution["provider_reference"],
        expected_provider_reference,
        "exact_execution.provider_reference",
    )

    provider_loss = exact_keys(
        checks["provider_response_loss"],
        {"initial", "replay", "reconciliation", "durable_state"},
        "checks.provider_response_loss",
    )
    validate_indeterminate_initial(
        provider_loss["initial"],
        "provider_response_loss.initial",
    )
    validate_replay(
        provider_loss["replay"],
        "provider_response_loss.replay",
    )
    provider_loss_reconciliation = exact_keys(
        provider_loss["reconciliation"],
        {
            "http_status",
            "valid",
            "outcome",
            "reason",
            "terminalized",
            "reexecuted",
        },
        "provider_response_loss.reconciliation",
    )
    require_equal(
        provider_loss_reconciliation["http_status"],
        503,
        "provider_response_loss.reconciliation.http_status",
    )
    require_equal(
        provider_loss_reconciliation["valid"],
        False,
        "provider_response_loss.reconciliation.valid",
    )
    require_equal(
        provider_loss_reconciliation["outcome"],
        "INDETERMINATE",
        "provider_response_loss.reconciliation.outcome",
    )
    require_equal(
        provider_loss_reconciliation["reason"],
        "provider_evidence_unavailable",
        "provider_response_loss.reconciliation.reason",
    )
    require_equal(
        provider_loss_reconciliation["terminalized"],
        False,
        "provider_response_loss.reconciliation.terminalized",
    )
    require_equal(
        provider_loss_reconciliation["reexecuted"],
        False,
        "provider_response_loss.reconciliation.reexecuted",
    )
    require_equal(
        provider_loss["durable_state"],
        "INDETERMINATE",
        "provider_response_loss.durable_state",
    )

    actuator_loss = exact_keys(
        checks["actuator_response_loss"],
        {"initial", "replay", "reconciliation", "durable_state"},
        "checks.actuator_response_loss",
    )
    validate_indeterminate_initial(
        actuator_loss["initial"],
        "actuator_response_loss.initial",
    )
    validate_replay(
        actuator_loss["replay"],
        "actuator_response_loss.replay",
    )
    actuator_loss_reconciliation = exact_keys(
        actuator_loss["reconciliation"],
        {
            "http_status",
            "valid",
            "outcome",
            "evidence_digest",
            "reexecuted",
        },
        "actuator_response_loss.reconciliation",
    )
    require_equal(
        actuator_loss_reconciliation["http_status"],
        200,
        "actuator_response_loss.reconciliation.http_status",
    )
    require_equal(
        actuator_loss_reconciliation["valid"],
        True,
        "actuator_response_loss.reconciliation.valid",
    )
    require_equal(
        actuator_loss_reconciliation["outcome"],
        "COMMITTED",
        "actuator_response_loss.reconciliation.outcome",
    )
    evidence_digest = actuator_loss_reconciliation["evidence_digest"]
    if not isinstance(evidence_digest, str) or not DIGEST.fullmatch(
        evidence_digest
    ):
        raise ValueError(
            "actuator_response_loss.reconciliation.evidence_digest "
            "must be sha256"
        )
    require_equal(
        actuator_loss_reconciliation["reexecuted"],
        False,
        "actuator_response_loss.reconciliation.reexecuted",
    )
    require_equal(
        actuator_loss["durable_state"],
        "COMMITTED",
        "actuator_response_loss.durable_state",
    )


def describe_live_resource(
    config: dict[str, str],
    resource_kind: str,
    resource: str,
) -> dict:
    result = subprocess.run(
        [
            "gcloud",
            "run",
            resource_kind,
            "describe",
            resource,
            f"--project={config['PROJECT_ID']}",
            f"--region={config['REGION']}",
            "--format=json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"live {resource_kind} lookup failed for {resource}")
    try:
        value = json.loads(result.stdout, object_pairs_hook=reject_duplicate_members)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"live {resource_kind} lookup was not JSON for {resource}"
        ) from error
    if not isinstance(value, dict):
        raise ValueError(f"live {resource_kind} lookup was malformed for {resource}")
    return value


def describe_live_revision(config: dict[str, str], revision: str) -> dict:
    return describe_live_resource(config, "revisions", revision)


def describe_live_service(config: dict[str, str], service: str) -> dict:
    return describe_live_resource(config, "services", service)


def require_dict(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def require_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    return value


def require_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def require_https_url(value: object, name: str) -> str:
    result = require_string(value, name)
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?", result):
        raise ValueError(f"{name} must be a canonical HTTPS origin")
    return result


def require_positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def require_nonnegative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def normalize_cpu(value: object, name: str) -> int:
    raw = require_string(value, name)
    try:
        if raw.endswith("m"):
            millicores = Decimal(raw[:-1])
        else:
            millicores = Decimal(raw) * 1000
    except InvalidOperation as error:
        raise ValueError(f"{name} must be a CPU quantity") from error
    if (
        not millicores.is_finite()
        or millicores <= 0
        or millicores != millicores.to_integral_value()
    ):
        raise ValueError(f"{name} must resolve to whole positive millicores")
    return int(millicores)


def behavior_metadata(
    value: object,
    name: str,
    ignored: set[str],
) -> dict[str, str]:
    source = require_dict(value, name)
    result: dict[str, str] = {}
    for key, raw in source.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"{name} keys must be non-empty strings")
        item = require_string(raw, f"{name}.{key}")
        if key not in ignored:
            result[key] = item
    return result


def expected_actuator_plain_environment(
    config: dict[str, str],
) -> dict[str, str]:
    return {
        "NODE_ENV": "production",
        "HOST": "0.0.0.0",
        "EMILIA_ACTUATOR_DATABASE_PRINCIPAL": config[
            "ACTUATOR_DATABASE_PRINCIPAL"
        ],
        "EMILIA_ACTUATOR_TENANT_ID": config["TENANT_ID"],
        "EMILIA_ACTUATOR_GITHUB_OWNER": config["GITHUB_OWNER"],
        "EMILIA_ACTUATOR_GITHUB_REPO": config["GITHUB_REPO"],
        "EMILIA_ACTUATOR_GITHUB_ISSUE_NUMBER": config["GITHUB_ISSUE_NUMBER"],
        "EMILIA_ACTUATOR_ENVELOPE_ISSUER_ID": config["ENVELOPE_ISSUER_ID"],
        "EMILIA_ACTUATOR_ENVELOPE_KEY_ID": config["ENVELOPE_KEY_ID"],
        "EMILIA_ACTUATOR_OBSERVATION_ISSUER_ID": config[
            "OBSERVATION_ISSUER_ID"
        ],
        "EMILIA_ACTUATOR_OBSERVATION_KEY_ID": config["OBSERVATION_KEY_ID"],
    }


def expected_decision_plain_environment(
    config: dict[str, str],
    actuator_origin: str,
    actuator_audience: str,
) -> dict[str, str]:
    return {
        "NODE_ENV": "production",
        "HOST": "0.0.0.0",
        "EMILIA_CONSEQUENCE_CONFIG": (
            "apps/consequence-control-service/src/production-config.js"
        ),
        "EMILIA_CONSEQUENCE_TENANT_ID": config["TENANT_ID"],
        "EMILIA_CONSEQUENCE_RELYING_PARTY_ID": config[
            "DECISION_RELYING_PARTY_ID"
        ],
        "EMILIA_CONSEQUENCE_EXECUTOR_ID": config["DECISION_EXECUTOR_ID"],
        "EMILIA_CONSEQUENCE_PRINCIPAL_ID": config["DECISION_PRINCIPAL_ID"],
        "EMILIA_CONSEQUENCE_APPROVAL_ENDPOINT": config[
            "DECISION_APPROVAL_ENDPOINT"
        ],
        "EMILIA_CONSEQUENCE_GITHUB_OWNER": config["GITHUB_OWNER"],
        "EMILIA_CONSEQUENCE_GITHUB_REPO": config["GITHUB_REPO"],
        "EMILIA_CONSEQUENCE_GITHUB_ISSUE_NUMBER": config[
            "GITHUB_ISSUE_NUMBER"
        ],
        "EMILIA_CONSEQUENCE_PROPOSAL_TTL_SEC": config[
            "DECISION_PROPOSAL_TTL_SEC"
        ],
        "EMILIA_CONSEQUENCE_ACTUATOR_ORIGIN": actuator_origin,
        "EMILIA_CONSEQUENCE_ACTUATOR_AUDIENCE": actuator_audience,
        "EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_ISSUER_ID": config[
            "ENVELOPE_ISSUER_ID"
        ],
        "EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_KEY_ID": config[
            "ENVELOPE_KEY_ID"
        ],
        "EMILIA_CONSEQUENCE_ACTUATOR_OBSERVATION_ISSUER_ID": config[
            "OBSERVATION_ISSUER_ID"
        ],
        "EMILIA_CONSEQUENCE_ACTUATOR_EVIDENCE_KEY_ID": config[
            "OBSERVATION_KEY_ID"
        ],
        "EMILIA_CONSEQUENCE_ACTUATOR_TIMEOUT_MS": config[
            "DECISION_ACTUATOR_TIMEOUT_MS"
        ],
        "EMILIA_CONSEQUENCE_AEB_REQUIREMENT_REF": config[
            "DECISION_AEB_REQUIREMENT_REF"
        ],
        "EMILIA_CONSEQUENCE_SHUTDOWN_GRACE_MS": config[
            "DECISION_SHUTDOWN_GRACE_MS"
        ],
    }


def parse_configured_secret(config: dict[str, str], variable: str) -> tuple[str, str]:
    value = config[variable]
    try:
        secret, version = value.rsplit(":", 1)
    except ValueError as error:
        raise ValueError(f"{variable} must use SECRET_ID:NUMERIC_VERSION") from error
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,254}", secret):
        raise ValueError(f"{variable} has an invalid secret ID")
    if not re.fullmatch(r"[1-9][0-9]*", version):
        raise ValueError(f"{variable} must use a numeric secret version")
    return secret, version


def expected_secret_environment(
    config: dict[str, str],
    bindings: dict[str, str],
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name, variable in bindings.items():
        secret, version = parse_configured_secret(config, variable)
        result[name] = {
            "secret": secret,
            "version": version,
        }
    return result


def normalize_environment(
    container: dict,
    revision: str,
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    environment = require_list(
        container.get("env"),
        f"live revision {revision} container environment",
    )
    plain: dict[str, str] = {}
    secret: dict[str, dict[str, str]] = {}
    for index, item in enumerate(environment):
        entry = require_dict(
            item,
            f"live revision {revision} environment[{index}]",
        )
        name = require_string(
            entry.get("name"),
            f"live revision {revision} environment[{index}].name",
        )
        if name in plain or name in secret:
            raise ValueError(
                f"live revision {revision} has duplicate environment member {name}"
            )
        if set(entry) == {"name", "value"}:
            plain[name] = require_string(
                entry["value"],
                f"live revision {revision} environment {name}.value",
            )
            continue
        if set(entry) != {"name", "valueFrom"}:
            raise ValueError(
                f"live revision {revision} environment {name} must be exactly "
                "plaintext or Secret Manager backed"
            )
        value_from = exact_keys(
            entry["valueFrom"],
            {"secretKeyRef"},
            f"live revision {revision} secret {name}.valueFrom",
        )
        reference = exact_keys(
            value_from["secretKeyRef"],
            {"key", "name"},
            f"live revision {revision} secret {name}.secretKeyRef",
        )
        secret[name] = {
            "secret": require_string(
                reference["name"],
                f"live revision {revision} secret {name} ID",
            ),
            "version": require_string(
                reference["key"],
                f"live revision {revision} secret {name} version",
            ),
        }
    return plain, secret


def normalize_network_interfaces(value: str, revision: str) -> list[dict]:
    try:
        interfaces = json.loads(
            value,
            object_pairs_hook=reject_duplicate_members,
        )
    except json.JSONDecodeError as error:
        raise ValueError(
            f"live revision {revision} network interfaces are not JSON"
        ) from error
    result = require_list(
        interfaces,
        f"live revision {revision} network interfaces",
    )
    for index, interface in enumerate(result):
        exact_keys(
            interface,
            {"network", "subnetwork"},
            f"live revision {revision} network interface[{index}]",
        )
    return result


def normalize_revision_annotations(
    metadata: dict,
    revision: str,
) -> tuple[dict[str, object], bool]:
    annotations = behavior_metadata(
        metadata.get("annotations"),
        f"live revision {revision}.metadata.annotations",
        NON_BEHAVIOR_ANNOTATIONS,
    )
    raw_session_affinity = annotations.pop(
        SESSION_AFFINITY_ANNOTATION,
        None,
    )
    if raw_session_affinity not in (None, "false", "true"):
        raise ValueError(
            f"live revision {revision} session affinity must be boolean"
        )
    if NETWORK_INTERFACES_ANNOTATION in annotations:
        annotations[NETWORK_INTERFACES_ANNOTATION] = normalize_network_interfaces(
            annotations[NETWORK_INTERFACES_ANNOTATION],
            revision,
        )
    return annotations, raw_session_affinity == "true"


def normalize_probe(value: object, name: str) -> dict[str, object]:
    probe = require_dict(value, name)
    action_names = {"grpc", "httpGet", "tcpSocket"}
    present_actions = action_names.intersection(probe)
    if len(present_actions) != 1:
        raise ValueError(f"{name} must contain exactly one probe action")
    action_name = present_actions.pop()
    allowed = {
        action_name,
        "failureThreshold",
        "initialDelaySeconds",
        "periodSeconds",
        "successThreshold",
        "timeoutSeconds",
    }
    if set(probe) - allowed:
        raise ValueError(f"{name} contains unexpected behavior fields")
    action = require_dict(probe[action_name], f"{name}.{action_name}")
    if action_name == "httpGet":
        if set(action) - {"httpHeaders", "path", "port"}:
            raise ValueError(f"{name}.httpGet contains unexpected fields")
        headers = require_list(
            action.get("httpHeaders", []),
            f"{name}.httpGet.httpHeaders",
        )
        normalized_headers: list[dict[str, str]] = []
        for index, item in enumerate(headers):
            header = exact_keys(
                item,
                {"name", "value"},
                f"{name}.httpGet.httpHeaders[{index}]",
            )
            normalized_headers.append(
                {
                    "name": require_string(
                        header["name"],
                        f"{name}.httpGet.httpHeaders[{index}].name",
                    ),
                    "value": require_string(
                        header["value"],
                        f"{name}.httpGet.httpHeaders[{index}].value",
                    ),
                }
            )
        normalized_action: dict[str, object] = {
            "httpHeaders": normalized_headers,
            "path": require_string(action.get("path", "/"), f"{name}.httpGet.path"),
            "port": require_positive_int(
                action.get("port"),
                f"{name}.httpGet.port",
            ),
        }
    elif action_name == "tcpSocket":
        socket = exact_keys(action, {"port"}, f"{name}.tcpSocket")
        normalized_action = {
            "port": require_positive_int(
                socket["port"],
                f"{name}.tcpSocket.port",
            )
        }
    else:
        if set(action) - {"port", "service"}:
            raise ValueError(f"{name}.grpc contains unexpected fields")
        normalized_action = {
            "port": require_positive_int(
                action.get("port"),
                f"{name}.grpc.port",
            ),
            "service": action.get("service", ""),
        }
        if not isinstance(normalized_action["service"], str):
            raise ValueError(f"{name}.grpc.service must be a string")
    return {
        "action": action_name,
        "configuration": normalized_action,
        "failureThreshold": require_positive_int(
            probe.get("failureThreshold", 3),
            f"{name}.failureThreshold",
        ),
        "initialDelaySeconds": require_nonnegative_int(
            probe.get("initialDelaySeconds", 0),
            f"{name}.initialDelaySeconds",
        ),
        "periodSeconds": require_positive_int(
            probe.get("periodSeconds", 10),
            f"{name}.periodSeconds",
        ),
        "successThreshold": require_positive_int(
            probe.get("successThreshold", 1),
            f"{name}.successThreshold",
        ),
        "timeoutSeconds": require_positive_int(
            probe.get("timeoutSeconds", 1),
            f"{name}.timeoutSeconds",
        ),
    }


def normalize_live_service(
    value: dict,
    service: str,
    tag: str,
) -> dict:
    metadata = require_dict(value.get("metadata"), f"live service {service}.metadata")
    require_equal(metadata.get("name"), service, f"live service {service} name")
    generation = require_positive_int(
        metadata.get("generation"),
        f"live service {service} generation",
    )
    status = require_dict(value.get("status"), f"live service {service}.status")
    observed_generation = require_positive_int(
        status.get("observedGeneration"),
        f"live service {service} observed generation",
    )
    require_equal(
        observed_generation,
        generation,
        f"live service {service} observed generation",
    )
    traffic = require_list(
        status.get("traffic"),
        f"live service {service}.status.traffic",
    )
    matches: list[dict] = []
    for index, item in enumerate(traffic):
        entry = require_dict(
            item,
            f"live service {service}.status.traffic[{index}]",
        )
        if entry.get("tag") == tag:
            matches.append(entry)
    if len(matches) != 1:
        raise ValueError(
            f"live service {service} must expose exactly one {tag!r} traffic tag"
        )
    tagged = exact_keys(
        matches[0],
        {"percent", "revisionName", "tag", "url"},
        f"live service {service} tagged traffic entry",
    )
    tagged_percent = require_nonnegative_int(
        tagged["percent"],
        f"live service {service} tagged traffic percent",
    )
    if tagged_percent > 100:
        raise ValueError(
            f"live service {service} tagged traffic percent must not exceed 100"
        )
    return {
        "name": service,
        "generation": generation,
        "observed_generation": observed_generation,
        "labels": behavior_metadata(
            metadata.get("labels"),
            f"live service {service}.metadata.labels",
            NON_BEHAVIOR_LABELS,
        ),
        "annotations": behavior_metadata(
            metadata.get("annotations"),
            f"live service {service}.metadata.annotations",
            NON_BEHAVIOR_ANNOTATIONS,
        ),
        "canonical_url": require_https_url(
            status.get("url"),
            f"live service {service} canonical URL",
        ),
        "tagged_traffic": {
            "percent": tagged_percent,
            "revision": require_string(
                tagged["revisionName"],
                f"live service {service} tagged traffic revision",
            ),
            "tag": require_string(
                tagged["tag"],
                f"live service {service} tagged traffic tag",
            ),
            "url": require_https_url(
                tagged["url"],
                f"live service {service} tagged URL",
            ),
        },
    }


def expected_service_projection(
    config: dict[str, str],
    plane: str,
    service: str,
    revision: str,
    tag: str,
    actual: dict,
) -> dict:
    annotations = {
        INGRESS_ANNOTATION: config[f"{plane.upper()}_INGRESS"],
    }
    if plane == "decision":
        annotations[INVOKER_IAM_DISABLED_ANNOTATION] = "true"
    return {
        "name": service,
        "generation": actual["generation"],
        "observed_generation": actual["generation"],
        "labels": {
            "emilia-plane": plane,
            "emilia-release": config["RELEASE_ID"],
        },
        "annotations": annotations,
        "canonical_url": actual["canonical_url"],
        "tagged_traffic": {
            "percent": 0,
            "revision": revision,
            "tag": tag,
            "url": actual["tagged_traffic"]["url"],
        },
    }


def expected_probe_projection(plane: str) -> dict[str, object]:
    if plane == "actuator":
        return {
            "startup": {
                "action": "tcpSocket",
                "configuration": {"port": 8080},
                "failureThreshold": 30,
                "initialDelaySeconds": 0,
                "periodSeconds": 2,
                "successThreshold": 1,
                "timeoutSeconds": 1,
            },
            "liveness": None,
            "readiness": None,
        }
    return {
        "startup": {
            "action": "httpGet",
            "configuration": {
                "httpHeaders": [],
                "path": "/v1/ready",
                "port": 8080,
            },
            "failureThreshold": 30,
            "initialDelaySeconds": 0,
            "periodSeconds": 2,
            "successThreshold": 1,
            "timeoutSeconds": 1,
        },
        "liveness": {
            "action": "httpGet",
            "configuration": {
                "httpHeaders": [],
                "path": "/v1/live",
                "port": 8080,
            },
            "failureThreshold": 3,
            "initialDelaySeconds": 10,
            "periodSeconds": 30,
            "successThreshold": 1,
            "timeoutSeconds": 2,
        },
        "readiness": {
            "action": "httpGet",
            "configuration": {
                "httpHeaders": [],
                "path": "/v1/ready",
                "port": 8080,
            },
            "failureThreshold": 3,
            "initialDelaySeconds": 0,
            "periodSeconds": 5,
            "successThreshold": 1,
            "timeoutSeconds": 2,
        },
    }


def normalize_live_revision(
    value: dict,
    revision: str,
    plane: str,
) -> dict:
    metadata = require_dict(
        value.get("metadata"),
        f"live revision {revision}.metadata",
    )
    require_equal(metadata.get("name"), revision, "live revision name")
    spec = exact_keys(
        value.get("spec"),
        {
            "containerConcurrency",
            "containers",
            "serviceAccountName",
            "timeoutSeconds",
        },
        f"live revision {revision}.spec",
    )
    containers = require_list(
        spec["containers"],
        f"live revision {revision}.spec.containers",
    )
    if len(containers) != 1:
        raise ValueError(f"live revision must have one container for {revision}")
    container_keys = {
        "env",
        "image",
        "ports",
        "resources",
        "startupProbe",
    }
    if plane == "decision":
        container_keys.update({"livenessProbe", "readinessProbe"})
    container = require_dict(
        containers[0],
        f"live revision {revision} container",
    )
    if not container_keys.issubset(container) or set(container) - (
        container_keys | {"name"}
    ):
        raise ValueError(
            f"live revision {revision} container must contain exactly the "
            "closed runtime fields"
        )
    if "name" in container:
        require_string(
            container["name"],
            f"live revision {revision} container name",
        )
    resources = exact_keys(
        container["resources"],
        {"limits"},
        f"live revision {revision} container resources",
    )
    limits = exact_keys(
        resources["limits"],
        {"cpu", "memory"},
        f"live revision {revision} container resource limits",
    )
    ports = require_list(
        container["ports"],
        f"live revision {revision} container ports",
    )
    if len(ports) != 1:
        raise ValueError(f"live revision {revision} must expose exactly one port")
    port = exact_keys(
        ports[0],
        {"containerPort", "name"},
        f"live revision {revision} container port",
    )
    container_port = require_positive_int(
        port["containerPort"],
        f"live revision {revision} container port number",
    )
    port_name = require_string(
        port["name"],
        f"live revision {revision} container port name",
    )
    plain_environment, secret_environment = normalize_environment(
        container,
        revision,
    )
    annotations, session_affinity = normalize_revision_annotations(
        metadata,
        revision,
    )
    return {
        "name": revision,
        "labels": behavior_metadata(
            metadata.get("labels"),
            f"live revision {revision}.metadata.labels",
            NON_BEHAVIOR_LABELS,
        ),
        "annotations": annotations,
        "session_affinity": session_affinity,
        "service_account": require_string(
            spec["serviceAccountName"],
            f"live revision {revision} service account",
        ),
        "image": require_string(
            container["image"],
            f"live revision {revision} image",
        ),
        "plain_environment": plain_environment,
        "secret_environment": secret_environment,
        "resources": {
            "cpu_millicores": normalize_cpu(
                limits["cpu"],
                f"live revision {revision} CPU",
            ),
            "memory": require_string(
                limits["memory"],
                f"live revision {revision} memory",
            ),
        },
        "scaling": {
            "minimum": annotations.get(MIN_SCALE_ANNOTATION),
            "maximum": annotations.get(MAX_SCALE_ANNOTATION),
        },
        "concurrency": require_positive_int(
            spec["containerConcurrency"],
            f"live revision {revision} concurrency",
        ),
        "timeout": require_positive_int(
            spec["timeoutSeconds"],
            f"live revision {revision} timeout",
        ),
        "ports": [
            {
                "containerPort": container_port,
                "name": port_name,
            }
        ],
        "probes": {
            "startup": normalize_probe(
                container["startupProbe"],
                f"live revision {revision} startup probe",
            ),
            "liveness": (
                normalize_probe(
                    container["livenessProbe"],
                    f"live revision {revision} liveness probe",
                )
                if "livenessProbe" in container
                else None
            ),
            "readiness": (
                normalize_probe(
                    container["readinessProbe"],
                    f"live revision {revision} readiness probe",
                )
                if "readinessProbe" in container
                else None
            ),
        },
    }


def expected_revision_projection(
    config: dict[str, str],
    plane: str,
    revision: str,
    service: str,
    actuator_origin: str,
    actuator_audience: str,
) -> dict:
    prefix = plane.upper()
    plain_environment = (
        expected_actuator_plain_environment(config)
        if plane == "actuator"
        else expected_decision_plain_environment(
            config,
            actuator_origin,
            actuator_audience,
        )
    )
    bindings = (
        ACTUATOR_SECRET_BINDINGS
        if plane == "actuator"
        else DECISION_SECRET_BINDINGS
    )
    timeout = 30 if plane == "actuator" else 60
    return {
        "name": revision,
        "labels": {
            "emilia-plane": plane,
            "emilia-release": config["RELEASE_ID"],
            "serving.knative.dev/service": service,
        },
        "annotations": {
            MIN_SCALE_ANNOTATION: config[f"{prefix}_MIN_INSTANCES"],
            MAX_SCALE_ANNOTATION: config[f"{prefix}_MAX_INSTANCES"],
            EXECUTION_ENVIRONMENT_ANNOTATION: "gen2",
            NETWORK_INTERFACES_ANNOTATION: [
                {
                    "network": config["NETWORK"],
                    "subnetwork": config["SUBNET"],
                }
            ],
            VPC_EGRESS_ANNOTATION: "all-traffic",
        },
        "session_affinity": False,
        "service_account": (
            f"{config[f'{prefix}_SERVICE_ACCOUNT']}@{config['PROJECT_ID']}"
            ".iam.gserviceaccount.com"
        ),
        "image": config[f"{prefix}_IMAGE"],
        "plain_environment": plain_environment,
        "secret_environment": expected_secret_environment(config, bindings),
        "resources": {
            "cpu_millicores": normalize_cpu(
                config[f"{prefix}_CPU"],
                f"{prefix}_CPU",
            ),
            "memory": config[f"{prefix}_MEMORY"],
        },
        "scaling": {
            "minimum": config[f"{prefix}_MIN_INSTANCES"],
            "maximum": config[f"{prefix}_MAX_INSTANCES"],
        },
        "concurrency": int(config[f"{prefix}_CONCURRENCY"]),
        "timeout": timeout,
        "ports": [
            {
                "containerPort": 8080,
                "name": "http1",
            }
        ],
        "probes": expected_probe_projection(plane),
    }


def validate_live(
    config: dict[str, str],
    evidence: dict,
    *,
    actuator_service_snapshot: dict | None = None,
    decision_service_snapshot: dict | None = None,
) -> None:
    actuator_revision = evidence["actuator_revision"]
    decision_revision = evidence["decision_revision"]
    tag = f"{CANARY_TAG_PREFIX}{config['RELEASE_ID']}"

    actuator_service = normalize_live_service(
        (
            actuator_service_snapshot
            if actuator_service_snapshot is not None
            else describe_live_service(config, config["ACTUATOR_SERVICE"])
        ),
        config["ACTUATOR_SERVICE"],
        tag,
    )
    decision_service = normalize_live_service(
        (
            decision_service_snapshot
            if decision_service_snapshot is not None
            else describe_live_service(config, config["DECISION_SERVICE"])
        ),
        config["DECISION_SERVICE"],
        tag,
    )
    require_equal(
        actuator_service,
        expected_service_projection(
            config,
            "actuator",
            config["ACTUATOR_SERVICE"],
            actuator_revision,
            tag,
            actuator_service,
        ),
        "live actuator service projection",
    )
    require_equal(
        decision_service,
        expected_service_projection(
            config,
            "decision",
            config["DECISION_SERVICE"],
            decision_revision,
            tag,
            decision_service,
        ),
        "live decision service projection",
    )
    actuator_tagged_url = actuator_service["tagged_traffic"]["url"]
    actuator_audience = actuator_service["canonical_url"]

    actuator_projection = normalize_live_revision(
        describe_live_revision(config, actuator_revision),
        actuator_revision,
        "actuator",
    )
    decision_projection = normalize_live_revision(
        describe_live_revision(config, decision_revision),
        decision_revision,
        "decision",
    )
    require_equal(
        actuator_projection,
        expected_revision_projection(
            config,
            "actuator",
            actuator_revision,
            config["ACTUATOR_SERVICE"],
            actuator_tagged_url,
            actuator_audience,
        ),
        "live actuator revision projection",
    )
    require_equal(
        decision_projection,
        expected_revision_projection(
            config,
            "decision",
            decision_revision,
            config["DECISION_SERVICE"],
            actuator_tagged_url,
            actuator_audience,
        ),
        "live decision revision projection",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument(
        "--live",
        action="store_true",
        help="also re-derive candidate revision and image bindings from Cloud Run",
    )
    parser.add_argument("--actuator-service-snapshot", type=Path)
    parser.add_argument("--decision-service-snapshot", type=Path)
    args = parser.parse_args()
    try:
        if bool(args.actuator_service_snapshot) != bool(
            args.decision_service_snapshot
        ):
            raise ValueError("both service snapshots must be supplied together")
        if (args.actuator_service_snapshot or args.decision_service_snapshot) and not (
            args.live
        ):
            raise ValueError("service snapshots require --live")
        config = load_pinned_config(args.config)
        evidence = json.loads(
            args.evidence.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_members,
        )
        validate(config, evidence)
        if args.live:
            service_snapshots = {}
            if args.actuator_service_snapshot is not None:
                service_snapshots = {
                    "actuator_service_snapshot": json.loads(
                        args.actuator_service_snapshot.read_text(encoding="utf-8"),
                        object_pairs_hook=reject_duplicate_members,
                    ),
                    "decision_service_snapshot": json.loads(
                        args.decision_service_snapshot.read_text(encoding="utf-8"),
                        object_pairs_hook=reject_duplicate_members,
                    ),
                }
            validate_live(config, evidence, **service_snapshots)
    except (
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        print(f"canary evidence refused: {error}", file=sys.stderr)
        return 1
    print("signed canary evidence accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
