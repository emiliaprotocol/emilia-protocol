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


def describe_live_revision(config: dict[str, str], revision: str) -> dict:
    result = subprocess.run(
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
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"live revision lookup failed for {revision}")
    try:
        value = json.loads(result.stdout, object_pairs_hook=reject_duplicate_members)
    except json.JSONDecodeError as error:
        raise ValueError(f"live revision lookup was not JSON for {revision}") from error
    if not isinstance(value, dict):
        raise ValueError(f"live revision lookup was malformed for {revision}")
    return value


def verify_live_revision(
    config: dict[str, str],
    revision: str,
    service: str,
    image: str,
) -> None:
    value = describe_live_revision(config, revision)
    metadata = value.get("metadata")
    spec = value.get("spec")
    if not isinstance(metadata, dict) or not isinstance(spec, dict):
        raise ValueError(f"live revision metadata is missing for {revision}")
    require_equal(metadata.get("name"), revision, "live revision name")
    labels = metadata.get("labels")
    if not isinstance(labels, dict):
        raise ValueError(f"live revision labels are missing for {revision}")
    require_equal(
        labels.get("serving.knative.dev/service"),
        service,
        "live revision service",
    )
    containers = spec.get("containers")
    if not isinstance(containers, list) or len(containers) != 1:
        raise ValueError(f"live revision must have one container for {revision}")
    if not isinstance(containers[0], dict):
        raise ValueError(f"live revision container is malformed for {revision}")
    require_equal(containers[0].get("image"), image, "live revision image")


def validate_live(config: dict[str, str], evidence: dict) -> None:
    verify_live_revision(
        config,
        evidence["actuator_revision"],
        config["ACTUATOR_SERVICE"],
        config["ACTUATOR_IMAGE"],
    )
    verify_live_revision(
        config,
        evidence["decision_revision"],
        config["DECISION_SERVICE"],
        config["DECISION_IMAGE"],
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
