#!/usr/bin/env python3
"""Record and verify signed, configuration-complete Cloud Run rollback targets."""

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
from pathlib import Path

VERSION = "EP-CONSEQUENCE-STABLE-RELEASE-v2"
PROVENANCE_VERSION = "EP-CONSEQUENCE-BOOTSTRAP-PROVENANCE-v1"
IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.@-]{3,256}$")
SECRET = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,254}$")
SECRET_VERSION = re.compile(r"^[1-9][0-9]*$")
KMS_URI = re.compile(
    r"^gcp-kms://projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/"
    r"cryptoKeys/([^/]+)/cryptoKeyVersions/([1-9][0-9]*)$"
)


def reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def parse_config(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
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


def canonical_unsigned_manifest(root: dict) -> bytes:
    unsigned = dict(root)
    signature = dict(root["signature"])
    signature.pop("value", None)
    unsigned["signature"] = signature
    return json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_base64url(value: object, name: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError(f"{name} must be unpadded base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise ValueError(f"{name} must be unpadded base64url") from error


def run_json(command: list[str], name: str) -> dict:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"{name} lookup failed")
    try:
        value = json.loads(
            result.stdout,
            object_pairs_hook=reject_duplicate_members,
        )
    except json.JSONDecodeError as error:
        raise ValueError(f"{name} lookup was not JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{name} lookup was malformed")
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_time(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an RFC 3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def integer(value: object, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an integer") from error
    if result < 1:
        raise ValueError(f"{name} must be positive")
    return result


def normalize_json(value: object, name: str) -> object:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        raise ValueError(f"{name} must not contain floating-point values")
    if isinstance(value, list):
        return [
            normalize_json(item, f"{name}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise ValueError(f"{name} member name must be a string")
            result[key] = normalize_json(value[key], f"{name}.{key}")
        return result
    raise ValueError(f"{name} contains an unsupported JSON value")


def describe_revision(config: dict[str, str], revision: str) -> dict:
    return run_json(
        [
            "gcloud",
            "run",
            "revisions",
            "describe",
            revision,
            f"--project={config['PROJECT_ID']}",
            f"--region={config['REGION']}",
            "--format=json",
        ],
        f"revision {revision}",
    )


def describe_service(config: dict[str, str], service: str) -> dict:
    return run_json(
        [
            "gcloud",
            "run",
            "services",
            "describe",
            service,
            f"--project={config['PROJECT_ID']}",
            f"--region={config['REGION']}",
            "--format=json",
        ],
        f"service {service}",
    )


def describe_secret_version(
    config: dict[str, str],
    secret: str,
    version: str,
) -> dict:
    return run_json(
        [
            "gcloud",
            "secrets",
            "versions",
            "describe",
            version,
            f"--secret={secret}",
            f"--project={config['PROJECT_ID']}",
            "--format=json",
        ],
        f"secret {secret} version {version}",
    )


def annotations(value: dict, name: str) -> dict:
    metadata = value.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"{name} metadata is missing")
    result = metadata.get("annotations", {})
    if not isinstance(result, dict):
        raise ValueError(f"{name} annotations are malformed")
    return result


def normalize_ingress(value: object) -> str:
    aliases = {
        "all": "all",
        "internal": "internal",
        "internal-and-cloud-load-balancing": "internal-and-cloud-load-balancing",
        "INGRESS_TRAFFIC_ALL": "all",
        "INGRESS_TRAFFIC_INTERNAL_ONLY": "internal",
        "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER": (
            "internal-and-cloud-load-balancing"
        ),
    }
    if not isinstance(value, str) or value not in aliases:
        raise ValueError("service ingress is missing or unsupported")
    return aliases[value]


def extract_ingress(service: dict) -> str:
    service_annotations = annotations(service, "service")
    if "run.googleapis.com/ingress" in service_annotations:
        return normalize_ingress(service_annotations["run.googleapis.com/ingress"])
    spec = service.get("spec")
    if isinstance(spec, dict) and "ingress" in spec:
        return normalize_ingress(spec["ingress"])
    raise ValueError("service ingress is missing")


def extract_vpc(revision: dict) -> dict:
    revision_annotations = annotations(revision, "revision")
    raw_interfaces = revision_annotations.get("run.googleapis.com/network-interfaces")
    if not isinstance(raw_interfaces, str):
        raise ValueError("revision network interface annotation is missing")
    try:
        interfaces = json.loads(
            raw_interfaces,
            object_pairs_hook=reject_duplicate_members,
        )
    except json.JSONDecodeError as error:
        raise ValueError("revision network interface annotation is not JSON") from error
    if (
        not isinstance(interfaces, list)
        or len(interfaces) != 1
        or not isinstance(interfaces[0], dict)
    ):
        raise ValueError("revision must bind exactly one network interface")
    interface = exact_keys(
        interfaces[0],
        {"network", "subnetwork"},
        "revision network interface",
    )
    network = interface["network"]
    subnet = interface["subnetwork"]
    egress = revision_annotations.get("run.googleapis.com/vpc-access-egress")
    if not all(isinstance(item, str) and item for item in (network, subnet, egress)):
        raise ValueError("revision VPC binding is incomplete")
    return {
        "network": network.rsplit("/", 1)[-1],
        "subnet": subnet.rsplit("/", 1)[-1],
        "egress": egress,
    }


def extract_secret_bindings(
    config: dict[str, str],
    container: dict,
) -> list[dict[str, str]]:
    raw_environment = container.get("env", [])
    if not isinstance(raw_environment, list):
        raise ValueError("revision environment is malformed")
    bindings: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in raw_environment:
        if not isinstance(entry, dict):
            raise ValueError("revision environment member is malformed")
        env_name = entry.get("name")
        if not isinstance(env_name, str) or not env_name:
            raise ValueError("revision environment name is missing")
        if env_name in seen:
            raise ValueError(f"duplicate revision environment name: {env_name}")
        seen.add(env_name)
        secret_ref: object | None = None
        value_from = entry.get("valueFrom")
        if isinstance(value_from, dict):
            secret_ref = value_from.get("secretKeyRef")
        value_source = entry.get("valueSource")
        if secret_ref is None and isinstance(value_source, dict):
            secret_ref = value_source.get("secretKeyRef")
        if secret_ref is None:
            continue
        if not isinstance(secret_ref, dict):
            raise ValueError(f"secret binding for {env_name} is malformed")
        secret = secret_ref.get("name", secret_ref.get("secret"))
        version = secret_ref.get("key", secret_ref.get("version"))
        if not isinstance(secret, str) or not SECRET.fullmatch(secret):
            raise ValueError(f"secret binding for {env_name} has an invalid secret")
        if not isinstance(version, str) or not SECRET_VERSION.fullmatch(version):
            raise ValueError(
                f"secret binding for {env_name} must use a numeric version"
            )
        metadata = describe_secret_version(config, secret, version)
        expected_resource = (
            f"projects/{config['PROJECT_ID']}/secrets/{secret}/versions/{version}"
        )
        require_equal(
            metadata.get("name"),
            expected_resource,
            f"secret binding for {env_name} resource",
        )
        require_equal(
            metadata.get("state"),
            "ENABLED",
            f"secret binding for {env_name} state",
        )
        create_time = parse_time(
            metadata.get("createTime"),
            f"secret binding for {env_name} createTime",
        )
        bindings.append(
            {
                "env": env_name,
                "secret": secret,
                "version": version,
                "resource": expected_resource,
                "state": "ENABLED",
                "create_time": create_time,
            }
        )
    return sorted(bindings, key=lambda item: item["env"])


def extract_rollout_witness(
    service_value: dict,
    *,
    service: str,
    revision: str,
    require_revision_100: bool,
) -> dict:
    metadata = service_value.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"service {service} metadata is missing")
    require_equal(metadata.get("name"), service, f"service {service} name")
    generation = integer(metadata.get("generation"), f"service {service} generation")
    status = service_value.get("status")
    if not isinstance(status, dict):
        raise ValueError(f"service {service} status is missing")
    observed_generation = integer(
        status.get("observedGeneration"),
        f"service {service} observed generation",
    )
    require_equal(
        observed_generation,
        generation,
        f"service {service} observed generation",
    )
    conditions = status.get("conditions")
    if not isinstance(conditions, list):
        raise ValueError(f"service {service} conditions are missing")
    ready = [
        condition
        for condition in conditions
        if isinstance(condition, dict) and condition.get("type") == "Ready"
    ]
    if len(ready) != 1:
        raise ValueError(f"service {service} must have exactly one Ready condition")
    require_equal(ready[0].get("status"), "True", f"service {service} Ready")
    ready_at = parse_time(
        ready[0].get("lastTransitionTime"),
        f"service {service} Ready transition",
    )
    traffic = status.get("traffic")
    if not isinstance(traffic, list) or not traffic:
        raise ValueError(f"service {service} traffic is missing")
    normalized: list[dict[str, object]] = []
    selected_percent = 0
    total = 0
    for index, raw in enumerate(traffic):
        if not isinstance(raw, dict):
            raise ValueError(f"service {service} traffic[{index}] is malformed")
        target_revision = raw.get("revisionName")
        percent = raw.get("percent")
        if (
            not isinstance(target_revision, str)
            or not REVISION.fullmatch(target_revision)
            or isinstance(percent, bool)
            or not isinstance(percent, int)
            or percent < 0
            or percent > 100
        ):
            raise ValueError(f"service {service} traffic[{index}] is invalid")
        entry: dict[str, object] = {
            "revision": target_revision,
            "percent": percent,
        }
        for source, destination in (("tag", "tag"), ("url", "url")):
            optional = raw.get(source)
            if optional is not None:
                if not isinstance(optional, str) or not optional:
                    raise ValueError(
                        f"service {service} traffic[{index}].{source} is invalid"
                    )
                entry[destination] = optional
        normalized.append(entry)
        total += percent
        if target_revision == revision:
            selected_percent += percent
    require_equal(total, 100, f"service {service} total traffic")
    if require_revision_100:
        require_equal(
            selected_percent,
            100,
            f"service {service} stable revision traffic",
        )
    return {
        "generation": generation,
        "observed_generation": observed_generation,
        "ready_at": ready_at,
        "traffic": sorted(
            normalized,
            key=lambda entry: (
                str(entry["revision"]),
                str(entry.get("tag", "")),
                str(entry.get("url", "")),
            ),
        ),
    }


def extract_revision_configuration(
    config: dict[str, str],
    *,
    service: str,
    revision: str,
    require_serving: bool = True,
    service_value: dict | None = None,
) -> dict:
    revision_value = describe_revision(config, revision)
    if service_value is None:
        service_value = describe_service(config, service)
    metadata = revision_value.get("metadata")
    spec = revision_value.get("spec")
    if not isinstance(metadata, dict) or not isinstance(spec, dict):
        raise ValueError(f"revision metadata is missing for {revision}")
    require_equal(metadata.get("name"), revision, "live revision name")
    labels = metadata.get("labels")
    if not isinstance(labels, dict):
        raise ValueError(f"revision labels are missing for {revision}")
    require_equal(
        labels.get("serving.knative.dev/service"),
        service,
        "live revision service",
    )
    containers = spec.get("containers")
    if (
        not isinstance(containers, list)
        or len(containers) != 1
        or not isinstance(containers[0], dict)
    ):
        raise ValueError(f"revision must have one container for {revision}")
    image = containers[0].get("image")
    if not isinstance(image, str) or not IMAGE.fullmatch(image):
        raise ValueError(f"revision image is not digest pinned for {revision}")
    service_account = spec.get("serviceAccountName", spec.get("serviceAccount"))
    if not isinstance(service_account, str) or not service_account:
        raise ValueError(f"revision service account is missing for {revision}")
    bootstrap_accounts = {
        (
            f"{config.get('STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT', '')}"
            f"@{config['PROJECT_ID']}.iam.gserviceaccount.com"
        ),
        (
            f"{config.get('STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT', '')}"
            f"@{config['PROJECT_ID']}.iam.gserviceaccount.com"
        ),
    }
    if service_account in bootstrap_accounts:
        revision_annotations = annotations(revision_value, "revision")
        if (
            "run.googleapis.com/network-interfaces" in revision_annotations
            or "run.googleapis.com/vpc-access-connector" in revision_annotations
            or "run.googleapis.com/vpc-access-egress" in revision_annotations
        ):
            raise ValueError(f"bootstrap revision must not have VPC access: {revision}")
        require_equal(labels.get("emilia-plane"), "bootstrap", "bootstrap plane label")
        require_equal(
            labels.get("emilia-deny-all"),
            "true",
            "bootstrap deny-all label",
        )
        require_equal(
            labels.get("emilia-permissionless"),
            "true",
            "bootstrap permissionless label",
        )
        vpc = None
    else:
        vpc = extract_vpc(revision_value)
    revision_annotations = annotations(revision_value, "revision")
    configuration_annotations = {
        key: value
        for key, value in revision_annotations.items()
        if key.startswith("run.googleapis.com/")
        or key.startswith("autoscaling.knative.dev/")
    }
    return {
        "service": service,
        "revision": revision,
        "image": image,
        "service_account": service_account,
        "ingress": extract_ingress(service_value),
        "vpc": vpc,
        "secret_bindings": extract_secret_bindings(config, containers[0]),
        "configuration": {
            "revision_spec": normalize_json(spec, f"revision {revision} spec"),
            "revision_labels": normalize_json(
                labels,
                f"revision {revision} labels",
            ),
            "revision_annotations": normalize_json(
                configuration_annotations,
                f"revision {revision} configuration annotations",
            ),
        },
        "rollout": extract_rollout_witness(
            service_value,
            service=service,
            revision=revision,
            require_revision_100=require_serving,
        ),
    }


def validate_secret_bindings(value: object, name: str) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    result: list[dict] = []
    previous = ""
    for index, raw in enumerate(value):
        binding = exact_keys(
            raw,
            {
                "env",
                "secret",
                "version",
                "resource",
                "state",
                "create_time",
            },
            f"{name}[{index}]",
        )
        env = binding["env"]
        secret = binding["secret"]
        version = binding["version"]
        if not isinstance(env, str) or not env:
            raise ValueError(f"{name}[{index}].env is invalid")
        if env <= previous:
            raise ValueError(f"{name} must be uniquely sorted by env")
        if not isinstance(secret, str) or not SECRET.fullmatch(secret):
            raise ValueError(f"{name}[{index}].secret is invalid")
        if not isinstance(version, str) or not SECRET_VERSION.fullmatch(version):
            raise ValueError(f"{name}[{index}].version must be numeric")
        expected_suffix = f"/secrets/{secret}/versions/{version}"
        resource = binding["resource"]
        if not isinstance(resource, str) or not resource.endswith(expected_suffix):
            raise ValueError(f"{name}[{index}].resource is invalid")
        require_equal(binding["state"], "ENABLED", f"{name}[{index}].state")
        parse_time(binding["create_time"], f"{name}[{index}].create_time")
        previous = env
        result.append(binding)
    return result


def validate_service(
    config: dict[str, str],
    value: object,
    *,
    plane: str,
) -> dict:
    service = exact_keys(
        value,
        {
            "service",
            "revision",
            "image",
            "service_account",
            "ingress",
            "vpc",
            "secret_bindings",
            "configuration",
            "rollout",
        },
        f"services.{plane}",
    )
    expected_service = config[
        "ACTUATOR_SERVICE" if plane == "actuator" else "DECISION_SERVICE"
    ]
    runtime_account = (
        f"{config['ACTUATOR_SERVICE_ACCOUNT']}@{config['PROJECT_ID']}"
        ".iam.gserviceaccount.com"
        if plane == "actuator"
        else f"{config['DECISION_SERVICE_ACCOUNT']}@{config['PROJECT_ID']}"
        ".iam.gserviceaccount.com"
    )
    bootstrap_variable = (
        "STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT"
        if plane == "actuator"
        else "STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"
    )
    bootstrap_account = (
        f"{config.get(bootstrap_variable, '')}@{config['PROJECT_ID']}"
        ".iam.gserviceaccount.com"
    )
    expected_ingress = config[
        "ACTUATOR_INGRESS" if plane == "actuator" else "DECISION_INGRESS"
    ]
    require_equal(service["service"], expected_service, f"services.{plane}.service")
    revision = service["revision"]
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ValueError(f"services.{plane}.revision is invalid")
    if not revision.startswith(f"{expected_service}-"):
        raise ValueError(f"services.{plane}.revision belongs to another service")
    candidate = f"{expected_service}-{config['RELEASE_ID']}"
    if revision == candidate:
        raise ValueError(f"services.{plane}.revision must differ from the candidate")
    image = service["image"]
    if not isinstance(image, str) or not IMAGE.fullmatch(image):
        raise ValueError(f"services.{plane}.image is not digest pinned")
    if service["service_account"] not in {runtime_account, bootstrap_account}:
        raise ValueError(f"services.{plane}.service_account is not allowlisted")
    require_equal(
        service["ingress"],
        expected_ingress,
        f"services.{plane}.ingress",
    )
    if service["service_account"] == bootstrap_account:
        require_equal(service["vpc"], None, f"services.{plane}.vpc")
        require_equal(
            service["secret_bindings"],
            [],
            f"services.{plane}.secret_bindings",
        )
    else:
        vpc = exact_keys(
            service["vpc"],
            {"network", "subnet", "egress"},
            f"services.{plane}.vpc",
        )
        require_equal(
            vpc["network"],
            config["NETWORK"],
            f"services.{plane}.vpc.network",
        )
        require_equal(
            vpc["subnet"],
            config["SUBNET"],
            f"services.{plane}.vpc.subnet",
        )
        require_equal(
            vpc["egress"],
            "all-traffic",
            f"services.{plane}.vpc.egress",
        )
    validate_secret_bindings(
        service["secret_bindings"],
        f"services.{plane}.secret_bindings",
    )
    configuration = exact_keys(
        service["configuration"],
        {"revision_spec", "revision_labels", "revision_annotations"},
        f"services.{plane}.configuration",
    )
    if not isinstance(configuration["revision_spec"], dict):
        raise ValueError(f"services.{plane}.configuration.revision_spec is invalid")
    if not isinstance(configuration["revision_annotations"], dict):
        raise ValueError(
            f"services.{plane}.configuration.revision_annotations is invalid"
        )
    if not isinstance(configuration["revision_labels"], dict):
        raise ValueError(
            f"services.{plane}.configuration.revision_labels is invalid"
        )
    rollout = exact_keys(
        service["rollout"],
        {"generation", "observed_generation", "ready_at", "traffic"},
        f"services.{plane}.rollout",
    )
    require_equal(
        integer(rollout["observed_generation"], f"services.{plane}.rollout"),
        integer(rollout["generation"], f"services.{plane}.rollout"),
        f"services.{plane}.rollout observed generation",
    )
    parse_time(rollout["ready_at"], f"services.{plane}.rollout.ready_at")
    if not isinstance(rollout["traffic"], list):
        raise ValueError(f"services.{plane}.rollout.traffic is invalid")
    selected = sum(
        entry.get("percent", -1)
        for entry in rollout["traffic"]
        if isinstance(entry, dict) and entry.get("revision") == revision
    )
    require_equal(selected, 100, f"services.{plane}.rollout stable traffic")
    return service


def validate_trust_config(config: dict[str, str]) -> dict[str, str]:
    key_id = config.get("STABLE_RELEASE_KEY_ID")
    if not isinstance(key_id, str) or not IDENTIFIER.fullmatch(key_id):
        raise ValueError("STABLE_RELEASE_KEY_ID is required and invalid")
    file_values = {
        "path": config.get("STABLE_RELEASE_PUBLIC_KEY_FILE", ""),
        "sha256": config.get("STABLE_RELEASE_PUBLIC_KEY_SHA256", ""),
    }
    kms_uri = config.get("STABLE_RELEASE_KMS_KEY_URI", "")
    file_mode = any(file_values.values())
    kms_mode = bool(kms_uri)
    if file_mode == kms_mode:
        raise ValueError(
            "configure exactly one stable-release trust mode: "
            "public key file plus SHA-256, or KMS key URI"
        )
    if file_mode:
        path = Path(file_values["path"])
        if not path.is_absolute() or not path.is_file():
            raise ValueError(
                "configured stable-release public key file is unavailable"
            )
        if not SHA256.fullmatch(file_values["sha256"]):
            raise ValueError("STABLE_RELEASE_PUBLIC_KEY_SHA256 is invalid")
        public_key = path.read_bytes()
        require_equal(
            sha256_bytes(public_key),
            file_values["sha256"],
            "configured stable-release public key SHA-256",
        )
        return {
            "provider": "file",
            "key_id": key_id,
            "public_key_file": str(path),
            "public_key_sha256": file_values["sha256"],
        }
    if not KMS_URI.fullmatch(kms_uri):
        raise ValueError("STABLE_RELEASE_KMS_KEY_URI is invalid")
    return {
        "provider": "gcp-kms",
        "key_id": key_id,
        "kms_key_uri": kms_uri,
    }


def kms_arguments(uri: str) -> tuple[str, list[str]]:
    match = KMS_URI.fullmatch(uri)
    if match is None:
        raise ValueError("stable-release KMS key URI is invalid")
    project, location, keyring, key, version = match.groups()
    return project, [
        version,
        f"--key={key}",
        f"--keyring={keyring}",
        f"--location={location}",
        f"--project={project}",
    ]


def kms_public_key(trust: dict[str, str]) -> tuple[bytes, dict[str, str]]:
    uri = trust["kms_key_uri"]
    _, arguments = kms_arguments(uri)
    metadata = run_json(
        [
            "gcloud",
            "kms",
            "keys",
            "versions",
            "describe",
            *arguments,
            "--format=json",
        ],
        "stable-release KMS key",
    )
    require_equal(metadata.get("state"), "ENABLED", "stable-release KMS key state")
    require_equal(
        metadata.get("algorithm"),
        "EC_SIGN_ED25519",
        "stable-release KMS key algorithm",
    )
    protection_level = metadata.get("protectionLevel")
    if not isinstance(protection_level, str) or not protection_level:
        raise ValueError("stable-release KMS protection level is missing")
    result = subprocess.run(
        [
            "gcloud",
            "kms",
            "keys",
            "versions",
            "get-public-key",
            *arguments,
            "--public-key-format=pem",
        ],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0 or not result.stdout:
        raise ValueError("stable-release KMS public key lookup failed")
    return result.stdout, {
        "provider": "gcp-kms",
        "key_id": trust["key_id"],
        "kms_key_uri": uri,
        "algorithm": "EC_SIGN_ED25519",
        "protection_level": protection_level,
        "public_key_sha256": sha256_bytes(result.stdout),
    }


def trusted_public_key(
    config: dict[str, str],
    supplied_public_key: Path | None,
) -> tuple[bytes, dict[str, str]]:
    trust = validate_trust_config(config)
    if trust["provider"] == "file":
        configured = Path(trust["public_key_file"])
        if supplied_public_key is not None:
            if (
                not supplied_public_key.is_absolute()
                or supplied_public_key.resolve() != configured.resolve()
            ):
                raise ValueError(
                    "caller-supplied public key does not match configured trust"
                )
        return configured.read_bytes(), {
            "provider": "file",
            "key_id": trust["key_id"],
            "public_key_sha256": trust["public_key_sha256"],
        }
    if supplied_public_key is not None:
        raise ValueError("caller-supplied public key is forbidden for KMS trust")
    return kms_public_key(trust)


def validate_lineage(config: dict[str, str], value: object, services: dict) -> dict:
    if not isinstance(value, dict):
        raise ValueError("lineage must be an object")
    kind = value.get("kind")
    if kind == "configured-stable":
        lineage = exact_keys(
            value,
            {"kind", "actuator_revision", "decision_revision"},
            "lineage",
        )
        require_equal(
            lineage["actuator_revision"],
            config["ACTUATOR_STABLE_REVISION"],
            "lineage.actuator_revision",
        )
        require_equal(
            lineage["decision_revision"],
            config["DECISION_STABLE_REVISION"],
            "lineage.decision_revision",
        )
        expected_revisions = {
            "actuator": lineage["actuator_revision"],
            "decision": lineage["decision_revision"],
        }
        expected_accounts = {
            "actuator": config["ACTUATOR_SERVICE_ACCOUNT"],
            "decision": config["DECISION_SERVICE_ACCOUNT"],
        }
    elif kind == "bootstrap-genesis":
        lineage = exact_keys(
            value,
            {"kind", "bootstrap_id", "provenance"},
            "lineage",
        )
        bootstrap_id = lineage["bootstrap_id"]
        if not isinstance(bootstrap_id, str) or not REVISION.fullmatch(bootstrap_id):
            raise ValueError("lineage.bootstrap_id is invalid")
        provenance = lineage["provenance"]
        if not isinstance(provenance, dict):
            raise ValueError("lineage.provenance is invalid")
        expected_provenance = configured_bootstrap_provenance(
            config,
            services["actuator"]["image"],
            None,
        )
        require_equal(
            provenance,
            expected_provenance,
            "lineage.provenance",
        )
        expected_revisions = {
            "actuator": (
                f"{config['ACTUATOR_SERVICE']}-{lineage['bootstrap_id']}"
            ),
            "decision": (
                f"{config['DECISION_SERVICE']}-{lineage['bootstrap_id']}"
            ),
        }
        expected_accounts = {
            "actuator": config["STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT"],
            "decision": config["STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"],
        }
    else:
        raise ValueError("lineage.kind is invalid")
    for plane in ("actuator", "decision"):
        require_equal(
            services[plane]["revision"],
            expected_revisions[plane],
            f"lineage {plane} service",
        )
        require_equal(
            services[plane]["service_account"],
            (
                f"{expected_accounts[plane]}@{config['PROJECT_ID']}"
                ".iam.gserviceaccount.com"
            ),
            f"lineage {plane} service account",
        )
    return lineage


def validate_manifest(
    config: dict[str, str],
    manifest: object,
    expected_trust: dict[str, str],
) -> dict:
    root = exact_keys(
        manifest,
        {
            "@version",
            "project_id",
            "region",
            "recorded_at",
            "lineage",
            "services",
            "signature",
        },
        "manifest",
    )
    require_equal(root["@version"], VERSION, "@version")
    require_equal(root["project_id"], config["PROJECT_ID"], "project_id")
    require_equal(root["region"], config["REGION"], "region")
    parse_time(root["recorded_at"], "recorded_at")
    services = exact_keys(
        root["services"],
        {"actuator", "decision"},
        "services",
    )
    validate_service(config, services["actuator"], plane="actuator")
    validate_service(config, services["decision"], plane="decision")
    validate_lineage(config, root["lineage"], services)
    signature = exact_keys(
        root["signature"],
        {"algorithm", "key_id", "trust", "value"},
        "signature",
    )
    require_equal(signature["algorithm"], "Ed25519", "signature.algorithm")
    require_equal(signature["key_id"], expected_trust["key_id"], "signature.key_id")
    require_equal(signature["trust"], expected_trust, "signature.trust")
    return root


def verify_signature(root: dict, public_key: bytes) -> None:
    signature = root["signature"]
    key_id = signature["key_id"]
    if not isinstance(key_id, str) or not IDENTIFIER.fullmatch(key_id):
        raise ValueError("signature.key_id is invalid")
    signature_bytes = decode_base64url(signature["value"], "signature.value")
    if len(signature_bytes) != 64:
        raise ValueError("signature.value must be a 64-byte Ed25519 signature")
    with tempfile.TemporaryDirectory(prefix="emilia-stable-verify-") as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.bin"
        public_key_path = Path(directory) / "public.pem"
        payload_path.write_bytes(canonical_unsigned_manifest(root))
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
        raise ValueError("stable-release signature is invalid")


def verify_live(
    config: dict[str, str],
    root: dict,
    *,
    service_snapshots: dict[str, dict] | None = None,
) -> None:
    for plane in ("actuator", "decision"):
        expected = root["services"][plane]
        actual = extract_revision_configuration(
            config,
            service=expected["service"],
            revision=expected["revision"],
            require_serving=False,
            service_value=(
                service_snapshots[plane]
                if service_snapshots is not None
                else None
            ),
        )
        actual_without_rollout = {
            key: value for key, value in actual.items() if key != "rollout"
        }
        expected_without_rollout = {
            key: value for key, value in expected.items() if key != "rollout"
        }
        require_equal(
            actual_without_rollout,
            expected_without_rollout,
            f"live services.{plane}",
        )


def sign_manifest(
    root: dict,
    *,
    config: dict[str, str],
    private_key: Path | None,
    kms_key_uri: str | None,
    requested_key_id: str | None,
) -> dict:
    trust = validate_trust_config(config)
    if requested_key_id is not None:
        require_equal(
            requested_key_id,
            trust["key_id"],
            "requested stable-release key id",
        )
    public_key, signed_trust = trusted_public_key(config, None)
    unsigned_root = {
        **root,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": trust["key_id"],
            "trust": signed_trust,
        },
    }
    with tempfile.TemporaryDirectory(prefix="emilia-stable-sign-") as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.bin"
        payload_path.write_bytes(canonical_unsigned_manifest(unsigned_root))
        if trust["provider"] == "file":
            if (
                private_key is None
                or not private_key.is_absolute()
                or not private_key.is_file()
                or kms_key_uri is not None
            ):
                raise ValueError(
                    "file trust requires exactly one stable-release private key"
                )
            derived_path = Path(directory) / "derived-public.pem"
            derived = subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    str(private_key),
                    "-pubout",
                    "-out",
                    str(derived_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if derived.returncode != 0 or derived_path.read_bytes() != public_key:
                raise ValueError(
                    "stable-release private key does not match configured trust"
                )
            result = subprocess.run(
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
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise ValueError("stable-release signing failed")
            signature_bytes = signature_path.read_bytes()
        else:
            if private_key is not None or kms_key_uri != trust["kms_key_uri"]:
                raise ValueError(
                    "KMS trust requires the configured stable-release KMS key URI"
                )
            _, arguments = kms_arguments(trust["kms_key_uri"])
            encoded_signature = Path(directory) / "signature.base64"
            result = subprocess.run(
                [
                    "gcloud",
                    "kms",
                    "asymmetric-sign",
                    *arguments[1:],
                    f"--version={arguments[0]}",
                    f"--input-file={payload_path}",
                    f"--signature-file={encoded_signature}",
                    "--quiet",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise ValueError("stable-release KMS signing failed")
            try:
                signature_bytes = base64.b64decode(
                    encoded_signature.read_text(encoding="ascii"),
                    validate=True,
                )
            except (OSError, ValueError) as error:
                raise ValueError(
                    "stable-release KMS signature output is invalid"
                ) from error
    if len(signature_bytes) != 64:
        raise ValueError("stable-release signer did not produce Ed25519")
    return {
        **unsigned_root,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": trust["key_id"],
            "trust": signed_trust,
            "value": encode_base64url(signature_bytes),
        },
    }


def configured_bootstrap_provenance(
    config: dict[str, str],
    image: str,
    supplied_path: Path | None,
) -> dict:
    if not IMAGE.fullmatch(image):
        raise ValueError("bootstrap image is not digest pinned")
    digest = image.rsplit("@", 1)[1]
    allowed = config.get("STABLE_BOOTSTRAP_ALLOWED_DIGESTS", "").split(",")
    if not allowed or any(not DIGEST.fullmatch(item) for item in allowed):
        raise ValueError("STABLE_BOOTSTRAP_ALLOWED_DIGESTS is invalid")
    if digest not in set(allowed):
        raise ValueError("bootstrap image digest is not explicitly allowlisted")
    configured_path = Path(config.get("STABLE_BOOTSTRAP_PROVENANCE_FILE", ""))
    if not configured_path.is_absolute() or not configured_path.is_file():
        raise ValueError("configured bootstrap provenance file is unavailable")
    if supplied_path is not None and (
        not supplied_path.is_absolute()
        or supplied_path.resolve() != configured_path.resolve()
    ):
        raise ValueError(
            "caller-supplied bootstrap provenance does not match configured trust"
        )
    expected_hash = config.get("STABLE_BOOTSTRAP_PROVENANCE_SHA256", "")
    if not SHA256.fullmatch(expected_hash):
        raise ValueError("STABLE_BOOTSTRAP_PROVENANCE_SHA256 is invalid")
    raw = configured_path.read_bytes()
    require_equal(
        sha256_bytes(raw),
        expected_hash,
        "configured bootstrap provenance SHA-256",
    )
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicate_members,
    )
    evidence = exact_keys(
        value,
        {
            "@version",
            "image",
            "digest",
            "predicate_type",
            "builder_id",
            "source",
            "verification",
        },
        "bootstrap provenance",
    )
    require_equal(evidence["@version"], PROVENANCE_VERSION, "provenance @version")
    require_equal(evidence["image"], image, "provenance image")
    require_equal(evidence["digest"], digest, "provenance digest")
    for name in ("predicate_type", "builder_id"):
        if not isinstance(evidence[name], str) or not evidence[name]:
            raise ValueError(f"provenance {name} is invalid")
    source = exact_keys(
        evidence["source"],
        {"repository", "commit_sha"},
        "bootstrap provenance source",
    )
    if not isinstance(source["repository"], str) or not source["repository"]:
        raise ValueError("bootstrap provenance source repository is invalid")
    if not isinstance(source["commit_sha"], str) or not re.fullmatch(
        r"[0-9a-f]{40,64}",
        source["commit_sha"],
    ):
        raise ValueError("bootstrap provenance source commit is invalid")
    verification = exact_keys(
        evidence["verification"],
        {"result", "verifier", "key_id", "verified_at"},
        "bootstrap provenance verification",
    )
    require_equal(
        verification["result"],
        "VERIFIED",
        "bootstrap provenance verification result",
    )
    for name in ("verifier", "key_id"):
        if not isinstance(verification[name], str) or not verification[name]:
            raise ValueError(f"bootstrap provenance verification {name} is invalid")
    parse_time(
        verification["verified_at"],
        "bootstrap provenance verification verified_at",
    )
    return {
        "evidence_sha256": expected_hash,
        "image": image,
        "digest": digest,
        "predicate_type": evidence["predicate_type"],
        "builder_id": evidence["builder_id"],
        "source": source,
        "verification": verification,
    }


def stable_lineage(args: argparse.Namespace, config: dict[str, str]) -> dict:
    if args.bootstrap_id is not None:
        if args.bootstrap_image is None:
            raise ValueError("--bootstrap-id requires --bootstrap-image")
        provenance = configured_bootstrap_provenance(
            config,
            args.bootstrap_image,
            args.bootstrap_provenance,
        )
        for plane, revision in (
            ("actuator", args.actuator_revision),
            ("decision", args.decision_revision),
        ):
            service = config[
                "ACTUATOR_SERVICE" if plane == "actuator" else "DECISION_SERVICE"
            ]
            require_equal(
                revision,
                f"{service}-{args.bootstrap_id}",
                f"bootstrap {plane} revision",
            )
        return {
            "kind": "bootstrap-genesis",
            "bootstrap_id": args.bootstrap_id,
            "provenance": provenance,
        }
    if args.bootstrap_image is not None or args.bootstrap_provenance is not None:
        raise ValueError("bootstrap provenance requires --bootstrap-id")
    if args.actuator_revision == (
        f"{config['ACTUATOR_SERVICE']}-{config['RELEASE_ID']}"
    ) or args.decision_revision == (
        f"{config['DECISION_SERVICE']}-{config['RELEASE_ID']}"
    ):
        raise ValueError("current candidate revision cannot establish stable lineage")
    require_equal(
        args.actuator_revision,
        config["ACTUATOR_STABLE_REVISION"],
        "actuator stable lineage",
    )
    require_equal(
        args.decision_revision,
        config["DECISION_STABLE_REVISION"],
        "decision stable lineage",
    )
    return {
        "kind": "configured-stable",
        "actuator_revision": config["ACTUATOR_STABLE_REVISION"],
        "decision_revision": config["DECISION_STABLE_REVISION"],
    }


def record(args: argparse.Namespace) -> None:
    config = load_pinned_config(args.config)
    if args.output.exists():
        raise ValueError("stable-release output already exists")
    lineage = stable_lineage(args, config)
    root = {
        "@version": VERSION,
        "project_id": config["PROJECT_ID"],
        "region": config["REGION"],
        "recorded_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "lineage": lineage,
        "services": {
            "actuator": extract_revision_configuration(
                config,
                service=config["ACTUATOR_SERVICE"],
                revision=args.actuator_revision,
            ),
            "decision": extract_revision_configuration(
                config,
                service=config["DECISION_SERVICE"],
                revision=args.decision_revision,
            ),
        },
    }
    signed = sign_manifest(
        root,
        config=config,
        private_key=args.private_key,
        kms_key_uri=args.kms_key_uri,
        requested_key_id=args.key_id,
    )
    _, expected_trust = trusted_public_key(config, None)
    validate_manifest(config, signed, expected_trust)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=args.output.parent,
        prefix=f".{args.output.name}.",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        json.dump(signed, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
    temporary.replace(args.output)


def verify(args: argparse.Namespace) -> dict:
    config = load_pinned_config(args.config)
    public_key, expected_trust = trusted_public_key(config, args.public_key)
    manifest = json.loads(
        args.manifest.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_members,
    )
    root = validate_manifest(config, manifest, expected_trust)
    verify_signature(root, public_key)
    if args.live:
        snapshots = None
        if args.actuator_service_snapshot is not None:
            snapshots = {
                "actuator": json.loads(
                    args.actuator_service_snapshot.read_text(encoding="utf-8"),
                    object_pairs_hook=reject_duplicate_members,
                ),
                "decision": json.loads(
                    args.decision_service_snapshot.read_text(encoding="utf-8"),
                    object_pairs_hook=reject_duplicate_members,
                ),
            }
        verify_live(config, root, service_snapshots=snapshots)
    return root


def verify_bootstrap(args: argparse.Namespace) -> None:
    config = load_pinned_config(args.config)
    configured_bootstrap_provenance(config, args.image, args.provenance)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--config", required=True, type=Path)
    record_parser.add_argument("--actuator-revision", required=True)
    record_parser.add_argument("--decision-revision", required=True)
    record_parser.add_argument("--private-key", type=Path)
    record_parser.add_argument("--kms-key-uri")
    record_parser.add_argument("--key-id")
    record_parser.add_argument("--bootstrap-id")
    record_parser.add_argument("--bootstrap-image")
    record_parser.add_argument("--bootstrap-provenance", type=Path)
    record_parser.add_argument("--output", required=True, type=Path)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--config", required=True, type=Path)
    verify_parser.add_argument("--manifest", required=True, type=Path)
    verify_parser.add_argument("--public-key", type=Path)
    verify_parser.add_argument("--live", action="store_true")
    verify_parser.add_argument("--print-revisions", action="store_true")
    verify_parser.add_argument("--print-rollout-bindings", action="store_true")
    verify_parser.add_argument("--actuator-service-snapshot", type=Path)
    verify_parser.add_argument("--decision-service-snapshot", type=Path)

    bootstrap_parser = subparsers.add_parser("verify-bootstrap")
    bootstrap_parser.add_argument("--config", required=True, type=Path)
    bootstrap_parser.add_argument("--image", required=True)
    bootstrap_parser.add_argument("--provenance", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "verify":
            if bool(args.actuator_service_snapshot) != bool(
                args.decision_service_snapshot
            ):
                raise ValueError("both service snapshots must be supplied together")
            if (
                args.actuator_service_snapshot is not None
                and not args.live
            ):
                raise ValueError("service snapshots require --live")
            if args.print_revisions and args.print_rollout_bindings:
                raise ValueError("select at most one stable-release print mode")
        if args.command == "record":
            record(args)
            print(f"signed stable-release manifest written to {args.output}")
        elif args.command == "verify":
            root = verify(args)
            if args.print_rollout_bindings:
                print(
                    root["services"]["actuator"]["revision"],
                    root["services"]["actuator"]["image"],
                    root["services"]["decision"]["revision"],
                    root["services"]["decision"]["image"],
                    sep="\t",
                )
            elif args.print_revisions:
                print(
                    root["services"]["actuator"]["revision"],
                    root["services"]["decision"]["revision"],
                    sep="\t",
                )
            else:
                print("signed stable-release manifest accepted")
        else:
            verify_bootstrap(args)
            print("bootstrap image provenance accepted")
    except (
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        print(f"stable-release manifest refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
