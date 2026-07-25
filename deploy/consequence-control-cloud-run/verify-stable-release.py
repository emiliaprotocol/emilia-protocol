#!/usr/bin/env python3
"""Record and verify signed, configuration-complete Cloud Run rollback targets."""

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

VERSION = "EP-CONSEQUENCE-STABLE-RELEASE-v1"
IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
REVISION = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.@-]{3,256}$")
SECRET = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,254}$")
SECRET_VERSION = re.compile(r"^[1-9][0-9]*$")


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


def canonical_unsigned_manifest(root: dict) -> bytes:
    unsigned = {key: value for key, value in root.items() if key != "signature"}
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


def extract_secret_bindings(container: dict) -> list[dict[str, str]]:
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
        bindings.append(
            {"env": env_name, "secret": secret, "version": version}
        )
    return sorted(bindings, key=lambda item: item["env"])


def extract_revision_configuration(
    config: dict[str, str],
    *,
    service: str,
    revision: str,
) -> dict:
    revision_value = describe_revision(config, revision)
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
    return {
        "service": service,
        "revision": revision,
        "image": image,
        "service_account": service_account,
        "ingress": extract_ingress(service_value),
        "vpc": extract_vpc(revision_value),
        "secret_bindings": extract_secret_bindings(containers[0]),
    }


def validate_secret_bindings(value: object, name: str) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    result: list[dict] = []
    previous = ""
    for index, raw in enumerate(value):
        binding = exact_keys(
            raw,
            {"env", "secret", "version"},
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
        },
        f"services.{plane}",
    )
    expected_service = config[
        "ACTUATOR_SERVICE" if plane == "actuator" else "DECISION_SERVICE"
    ]
    expected_account = (
        f"{config['ACTUATOR_SERVICE_ACCOUNT']}@{config['PROJECT_ID']}"
        ".iam.gserviceaccount.com"
        if plane == "actuator"
        else f"{config['DECISION_SERVICE_ACCOUNT']}@{config['PROJECT_ID']}"
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
    require_equal(
        service["service_account"],
        expected_account,
        f"services.{plane}.service_account",
    )
    require_equal(
        service["ingress"],
        expected_ingress,
        f"services.{plane}.ingress",
    )
    vpc = exact_keys(
        service["vpc"],
        {"network", "subnet", "egress"},
        f"services.{plane}.vpc",
    )
    require_equal(vpc["network"], config["NETWORK"], f"services.{plane}.vpc.network")
    require_equal(vpc["subnet"], config["SUBNET"], f"services.{plane}.vpc.subnet")
    require_equal(
        vpc["egress"],
        "all-traffic",
        f"services.{plane}.vpc.egress",
    )
    validate_secret_bindings(
        service["secret_bindings"],
        f"services.{plane}.secret_bindings",
    )
    return service


def validate_manifest(config: dict[str, str], manifest: object) -> dict:
    root = exact_keys(
        manifest,
        {
            "@version",
            "project_id",
            "region",
            "recorded_at",
            "services",
            "signature",
        },
        "manifest",
    )
    require_equal(root["@version"], VERSION, "@version")
    require_equal(root["project_id"], config["PROJECT_ID"], "project_id")
    require_equal(root["region"], config["REGION"], "region")
    recorded_at = root["recorded_at"]
    if not isinstance(recorded_at, str):
        raise ValueError("recorded_at must be an RFC 3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(recorded_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("recorded_at must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("recorded_at must include a timezone")
    services = exact_keys(
        root["services"],
        {"actuator", "decision"},
        "services",
    )
    validate_service(config, services["actuator"], plane="actuator")
    validate_service(config, services["decision"], plane="decision")
    exact_keys(
        root["signature"],
        {"algorithm", "key_id", "value"},
        "signature",
    )
    return root


def verify_signature(root: dict, public_key: Path) -> None:
    signature = root["signature"]
    require_equal(signature["algorithm"], "Ed25519", "signature.algorithm")
    key_id = signature["key_id"]
    if not isinstance(key_id, str) or not IDENTIFIER.fullmatch(key_id):
        raise ValueError("signature.key_id is invalid")
    signature_bytes = decode_base64url(signature["value"], "signature.value")
    if len(signature_bytes) != 64:
        raise ValueError("signature.value must be a 64-byte Ed25519 signature")
    if not public_key.is_absolute() or not public_key.is_file():
        raise ValueError("pinned stable-release public key file is unavailable")
    with tempfile.TemporaryDirectory(prefix="emilia-stable-verify-") as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.bin"
        payload_path.write_bytes(canonical_unsigned_manifest(root))
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
        raise ValueError("stable-release signature is invalid")


def verify_live(config: dict[str, str], root: dict) -> None:
    for plane in ("actuator", "decision"):
        expected = root["services"][plane]
        actual = extract_revision_configuration(
            config,
            service=expected["service"],
            revision=expected["revision"],
        )
        require_equal(actual, expected, f"live services.{plane}")


def sign_manifest(root: dict, private_key: Path, key_id: str) -> dict:
    if not IDENTIFIER.fullmatch(key_id):
        raise ValueError("key id is invalid")
    if not private_key.is_absolute() or not private_key.is_file():
        raise ValueError("stable-release private key file is unavailable")
    with tempfile.TemporaryDirectory(prefix="emilia-stable-sign-") as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.bin"
        payload_path.write_bytes(canonical_unsigned_manifest(root))
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
    if len(signature_bytes) != 64:
        raise ValueError("stable-release signer did not produce Ed25519")
    return {
        **root,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value": encode_base64url(signature_bytes),
        },
    }


def record(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    if args.output.exists():
        raise ValueError("stable-release output already exists")
    root = {
        "@version": VERSION,
        "project_id": config["PROJECT_ID"],
        "region": config["REGION"],
        "recorded_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
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
    signed = sign_manifest(root, args.private_key, args.key_id)
    validate_manifest(config, signed)
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
    config = load_config(args.config)
    manifest = json.loads(
        args.manifest.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_members,
    )
    root = validate_manifest(config, manifest)
    verify_signature(root, args.public_key)
    if args.live:
        verify_live(config, root)
    return root


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--config", required=True, type=Path)
    record_parser.add_argument("--actuator-revision", required=True)
    record_parser.add_argument("--decision-revision", required=True)
    record_parser.add_argument("--private-key", required=True, type=Path)
    record_parser.add_argument("--key-id", required=True)
    record_parser.add_argument("--output", required=True, type=Path)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--config", required=True, type=Path)
    verify_parser.add_argument("--manifest", required=True, type=Path)
    verify_parser.add_argument("--public-key", required=True, type=Path)
    verify_parser.add_argument("--live", action="store_true")
    verify_parser.add_argument("--print-revisions", action="store_true")

    args = parser.parse_args()
    try:
        if args.command == "record":
            record(args)
            print(f"signed stable-release manifest written to {args.output}")
        else:
            root = verify(args)
            if args.print_revisions:
                print(
                    root["services"]["actuator"]["revision"],
                    root["services"]["decision"]["revision"],
                    sep="\t",
                )
            else:
                print("signed stable-release manifest accepted")
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
