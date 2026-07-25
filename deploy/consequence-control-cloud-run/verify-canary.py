#!/usr/bin/env python3
"""Verify signed, fresh canary evidence and its live Cloud Run revisions."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

DIGEST_IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.@-]{3,256}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
VERSION = "EP-CONSEQUENCE-CANARY-EVIDENCE-v1"
MAX_CLOCK_SKEW_SECONDS = 30
CANARY_TAG_PREFIX = "canary-"
NETWORK_INTERFACES_ANNOTATION = "run.googleapis.com/network-interfaces"
VPC_EGRESS_ANNOTATION = "run.googleapis.com/vpc-access-egress"
VPC_CONNECTOR_ANNOTATION = "run.googleapis.com/vpc-access-connector"
INGRESS_ANNOTATION = "run.googleapis.com/ingress"

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


def load_config(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise ValueError(f"invalid config line {number}")
        key, value = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"invalid config key on line {number}")
        if key in result:
            raise ValueError(f"duplicate config key on line {number}")
        result[key] = value
    return result


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
    public_key = Path(config["CANARY_EVIDENCE_PUBLIC_KEY_FILE"])
    if not public_key.is_absolute() or not public_key.is_file():
        raise ValueError("pinned canary public key file is unavailable")
    with tempfile.TemporaryDirectory(prefix="emilia-canary-verify-") as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.bin"
        payload_path.write_bytes(canonical_unsigned_evidence(root))
        signature_path.write_bytes(signature_bytes)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key),
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
        {"exact_execution", "timeout", "replay", "reconciliation"},
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

    timeout = exact_keys(
        checks["timeout"],
        {"http_status", "outcome", "effect_boundary_entered"},
        "checks.timeout",
    )
    require_equal(timeout["http_status"], 202, "timeout.http_status")
    require_equal(timeout["outcome"], "INDETERMINATE", "timeout.outcome")
    require_equal(
        timeout["effect_boundary_entered"],
        True,
        "timeout.effect_boundary_entered",
    )

    replay = exact_keys(
        checks["replay"],
        {"http_status", "reason", "provider_invocations"},
        "checks.replay",
    )
    require_equal(replay["http_status"], 409, "replay.http_status")
    require_equal(replay["reason"], "envelope_replayed", "replay.reason")
    require_equal(replay["provider_invocations"], 1, "replay.provider_invocations")

    reconciliation = exact_keys(
        checks["reconciliation"],
        {"http_status", "valid", "outcome", "reason", "reexecuted"},
        "checks.reconciliation",
    )
    require_equal(
        reconciliation["http_status"], 200, "reconciliation.http_status"
    )
    require_equal(reconciliation["valid"], True, "reconciliation.valid")
    require_equal(
        reconciliation["outcome"], "ESCALATED", "reconciliation.outcome"
    )
    require_equal(
        reconciliation["reason"],
        "github_attempt_attribution_unavailable",
        "reconciliation.reason",
    )
    require_equal(
        reconciliation["reexecuted"], False, "reconciliation.reexecuted"
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


def verify_live_service_tag(
    value: dict,
    service: str,
    tag: str,
    revision: str,
) -> str:
    metadata = require_dict(value.get("metadata"), f"live service {service}.metadata")
    require_equal(metadata.get("name"), service, f"live service {service} name")
    status = require_dict(value.get("status"), f"live service {service}.status")
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
    match = matches[0]
    require_equal(
        match.get("revisionName"),
        revision,
        f"live service {service} tag revision",
    )
    return require_https_url(
        match.get("url"),
        f"live service {service} tagged URL",
    )


def canonical_service_url(value: dict, service: str) -> str:
    status = require_dict(value.get("status"), f"live service {service}.status")
    return require_https_url(
        status.get("url"),
        f"live service {service} canonical URL",
    )


def revision_container(value: dict, revision: str) -> tuple[dict, dict, dict]:
    metadata = require_dict(
        value.get("metadata"),
        f"live revision {revision}.metadata",
    )
    spec = require_dict(value.get("spec"), f"live revision {revision}.spec")
    containers = require_list(
        spec.get("containers"),
        f"live revision {revision}.spec.containers",
    )
    if len(containers) != 1:
        raise ValueError(f"live revision must have one container for {revision}")
    container = require_dict(
        containers[0],
        f"live revision {revision}.spec.containers[0]",
    )
    return metadata, spec, container


def revision_environment(container: dict, revision: str) -> dict[str, dict]:
    environment = require_list(
        container.get("env"),
        f"live revision {revision} container environment",
    )
    result: dict[str, dict] = {}
    for index, item in enumerate(environment):
        entry = require_dict(
            item,
            f"live revision {revision} environment[{index}]",
        )
        name = require_string(
            entry.get("name"),
            f"live revision {revision} environment[{index}].name",
        )
        if name in result:
            raise ValueError(
                f"live revision {revision} has duplicate environment member {name}"
            )
        result[name] = entry
    return result


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


def verify_secret_bindings(
    config: dict[str, str],
    environment: dict[str, dict],
    expected: dict[str, str],
    revision: str,
) -> None:
    actual_names = {
        name for name, entry in environment.items() if "valueFrom" in entry
    }
    if actual_names != set(expected):
        raise ValueError(
            f"live revision {revision} secret environment must contain exactly "
            f"{sorted(expected)}"
        )
    for environment_name, config_variable in expected.items():
        entry = exact_keys(
            environment[environment_name],
            {"name", "valueFrom"},
            f"live revision {revision} secret {environment_name}",
        )
        require_equal(
            entry["name"],
            environment_name,
            f"live revision {revision} secret environment name",
        )
        value_from = exact_keys(
            entry["valueFrom"],
            {"secretKeyRef"},
            f"live revision {revision} secret {environment_name}.valueFrom",
        )
        reference = exact_keys(
            value_from["secretKeyRef"],
            {"key", "name"},
            f"live revision {revision} secret {environment_name}.secretKeyRef",
        )
        secret, version = parse_configured_secret(config, config_variable)
        require_equal(
            reference["name"],
            secret,
            f"live revision {revision} secret {environment_name} ID",
        )
        require_equal(
            reference["key"],
            version,
            f"live revision {revision} secret {environment_name} version",
        )


def require_plain_environment(
    environment: dict[str, dict],
    name: str,
    expected: str,
    revision: str,
) -> None:
    if name not in environment:
        raise ValueError(f"live revision {revision} is missing environment {name}")
    entry = exact_keys(
        environment[name],
        {"name", "value"},
        f"live revision {revision} environment {name}",
    )
    require_equal(entry["name"], name, f"live revision {revision} environment name")
    require_equal(
        entry["value"],
        expected,
        f"live revision {revision} environment {name}",
    )


def verify_revision_network(
    metadata: dict,
    config: dict[str, str],
    revision: str,
) -> None:
    annotations = require_dict(
        metadata.get("annotations"),
        f"live revision {revision}.metadata.annotations",
    )
    if VPC_CONNECTOR_ANNOTATION in annotations:
        raise ValueError(f"live revision {revision} must use Direct VPC egress")
    raw_interfaces = require_string(
        annotations.get(NETWORK_INTERFACES_ANNOTATION),
        f"live revision {revision} network interfaces",
    )
    try:
        interfaces = json.loads(
            raw_interfaces,
            object_pairs_hook=reject_duplicate_members,
        )
    except json.JSONDecodeError as error:
        raise ValueError(
            f"live revision {revision} network interfaces are not JSON"
        ) from error
    interfaces = require_list(
        interfaces,
        f"live revision {revision} network interfaces",
    )
    if len(interfaces) != 1:
        raise ValueError(
            f"live revision {revision} must have exactly one network interface"
        )
    interface = exact_keys(
        interfaces[0],
        {"network", "subnetwork"},
        f"live revision {revision} network interface",
    )
    require_equal(
        interface["network"],
        config["NETWORK"],
        f"live revision {revision} network",
    )
    require_equal(
        interface["subnetwork"],
        config["SUBNET"],
        f"live revision {revision} subnet",
    )
    require_equal(
        annotations.get(VPC_EGRESS_ANNOTATION),
        "all-traffic",
        f"live revision {revision} VPC egress",
    )


def verify_service_ingress(
    value: dict,
    service: str,
    expected: str,
) -> None:
    metadata = require_dict(value.get("metadata"), f"live service {service}.metadata")
    annotations = require_dict(
        metadata.get("annotations"),
        f"live service {service}.metadata.annotations",
    )
    require_equal(
        annotations.get(INGRESS_ANNOTATION),
        expected,
        f"live service {service} ingress",
    )


def verify_live_revision(
    config: dict[str, str],
    value: dict,
    revision: str,
    service: str,
    image: str,
) -> tuple[dict, dict[str, dict]]:
    metadata, spec, container = revision_container(value, revision)
    require_equal(metadata.get("name"), revision, "live revision name")
    labels = require_dict(
        metadata.get("labels"),
        f"live revision {revision}.metadata.labels",
    )
    require_equal(
        labels.get("serving.knative.dev/service"),
        service,
        "live revision service",
    )
    require_equal(container.get("image"), image, "live revision image")
    return spec, revision_environment(container, revision)


def validate_live(config: dict[str, str], evidence: dict) -> None:
    actuator_revision = evidence["actuator_revision"]
    decision_revision = evidence["decision_revision"]
    tag = f"{CANARY_TAG_PREFIX}{config['RELEASE_ID']}"

    actuator_service = describe_live_service(config, config["ACTUATOR_SERVICE"])
    decision_service = describe_live_service(config, config["DECISION_SERVICE"])
    actuator_tagged_url = verify_live_service_tag(
        actuator_service,
        config["ACTUATOR_SERVICE"],
        tag,
        actuator_revision,
    )
    verify_live_service_tag(
        decision_service,
        config["DECISION_SERVICE"],
        tag,
        decision_revision,
    )
    actuator_audience = canonical_service_url(
        actuator_service,
        config["ACTUATOR_SERVICE"],
    )

    actuator_value = describe_live_revision(config, actuator_revision)
    decision_value = describe_live_revision(config, decision_revision)
    actuator_spec, actuator_environment = verify_live_revision(
        config,
        actuator_value,
        actuator_revision,
        config["ACTUATOR_SERVICE"],
        config["ACTUATOR_IMAGE"],
    )
    decision_spec, decision_environment = verify_live_revision(
        config,
        decision_value,
        decision_revision,
        config["DECISION_SERVICE"],
        config["DECISION_IMAGE"],
    )
    require_equal(
        actuator_spec.get("serviceAccountName"),
        (
            f"{config['ACTUATOR_SERVICE_ACCOUNT']}@{config['PROJECT_ID']}"
            ".iam.gserviceaccount.com"
        ),
        "live actuator runtime service account",
    )
    require_equal(
        decision_spec.get("serviceAccountName"),
        (
            f"{config['DECISION_SERVICE_ACCOUNT']}@{config['PROJECT_ID']}"
            ".iam.gserviceaccount.com"
        ),
        "live decision runtime service account",
    )
    verify_service_ingress(
        actuator_service,
        config["ACTUATOR_SERVICE"],
        config["ACTUATOR_INGRESS"],
    )
    verify_service_ingress(
        decision_service,
        config["DECISION_SERVICE"],
        config["DECISION_INGRESS"],
    )
    verify_revision_network(
        require_dict(
            actuator_value.get("metadata"),
            f"live revision {actuator_revision}.metadata",
        ),
        config,
        actuator_revision,
    )
    verify_revision_network(
        require_dict(
            decision_value.get("metadata"),
            f"live revision {decision_revision}.metadata",
        ),
        config,
        decision_revision,
    )
    verify_secret_bindings(
        config,
        actuator_environment,
        ACTUATOR_SECRET_BINDINGS,
        actuator_revision,
    )
    verify_secret_bindings(
        config,
        decision_environment,
        DECISION_SECRET_BINDINGS,
        decision_revision,
    )
    require_plain_environment(
        decision_environment,
        "EMILIA_CONSEQUENCE_ACTUATOR_ORIGIN",
        actuator_tagged_url,
        decision_revision,
    )
    require_plain_environment(
        decision_environment,
        "EMILIA_CONSEQUENCE_ACTUATOR_AUDIENCE",
        actuator_audience,
        decision_revision,
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
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        evidence = json.loads(
            args.evidence.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_members,
        )
        validate(config, evidence)
        if args.live:
            validate_live(config, evidence)
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
