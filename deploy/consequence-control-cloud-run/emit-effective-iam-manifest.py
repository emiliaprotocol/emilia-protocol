#!/usr/bin/env python3
"""Emit the closed effective-IAM manifest from deployment coordinates."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path


VERSION = "emilia-effective-iam/v1"
PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
PROJECT_NUMBER = re.compile(r"^[1-9][0-9]{5,29}$")
REGION = re.compile(r"^[a-z]+-[a-z]+[0-9]$")
SERVICE = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
SECRET = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,254}$")
SERVICE_ACCOUNT = re.compile(
    r"^serviceAccount:[a-z][a-z0-9-]{0,61}[a-z0-9]@"
    r"[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$"
)


class ManifestError(ValueError):
    """The deployment coordinates cannot produce a closed IAM manifest."""


def principal(value: str, name: str) -> str:
    if SERVICE_ACCOUNT.fullmatch(value) is None:
        raise ManifestError(f"{name} must be one concrete service account")
    return value


def managed_control_plane_principals(project_number: str) -> tuple[str, str]:
    """Return the project-derived control-plane principals accepted by this profile."""
    return (
        (
            "serviceAccount:"
            f"service-{project_number}@compute-system.iam.gserviceaccount.com"
        ),
        (
            "serviceAccount:"
            f"service-{project_number}@serverless-robot-prod.iam.gserviceaccount.com"
        ),
    )


def secret_spec(value: str) -> tuple[str, tuple[str, ...]]:
    if "=" not in value:
        raise ManifestError("--secret must be SECRET=PRINCIPAL[,PRINCIPAL]")
    name, encoded_principals = value.split("=", 1)
    if SECRET.fullmatch(name) is None:
        raise ManifestError(f"invalid secret name: {name!r}")
    principals = tuple(
        sorted(
            principal(entry, f"secret {name!r} principal")
            for entry in encoded_principals.split(",")
            if entry
        )
    )
    if not principals:
        raise ManifestError(f"secret {name!r} has no allowed principal")
    if len(principals) != len(set(principals)):
        raise ManifestError(f"secret {name!r} has a duplicate principal")
    return name, principals


def manifest(
    *,
    project: str,
    project_number: str,
    region: str,
    actuator_service: str,
    decision_principal: str,
    secrets: list[str],
) -> dict[str, object]:
    if PROJECT.fullmatch(project) is None:
        raise ManifestError("project is invalid")
    if PROJECT_NUMBER.fullmatch(project_number) is None:
        raise ManifestError("project number is invalid")
    if REGION.fullmatch(region) is None:
        raise ManifestError("region is invalid")
    if SERVICE.fullmatch(actuator_service) is None:
        raise ManifestError("actuator service is invalid")
    decision = principal(decision_principal, "decision principal")
    managed_principals = managed_control_plane_principals(project_number)
    parsed_secrets = [secret_spec(value) for value in secrets]
    names = [name for name, _principals in parsed_secrets]
    if not names:
        raise ManifestError("at least one secret is required")
    if len(names) != len(set(names)):
        raise ManifestError("secret specifications contain a duplicate")

    scope = f"projects/{project}"
    targets: list[dict[str, object]] = [
        {
            "name": "actuator",
            "kind": "actuator",
            "scope": scope,
            "resource": (
                f"//run.googleapis.com/projects/{project}/locations/{region}/"
                f"services/{actuator_service}"
            ),
            "allowedPrincipals": sorted((decision, *managed_principals)),
        }
    ]
    for name, principals in sorted(parsed_secrets):
        targets.append(
            {
                "name": f"secret:{name}",
                "kind": "secret",
                "scope": scope,
                "resource": (
                    f"//secretmanager.googleapis.com/projects/{project_number}/"
                    f"secrets/{name}"
                ),
                "allowedPrincipals": sorted(
                    set(principals) | set(managed_principals)
                ),
            }
        )
    return {
        "version": VERSION,
        "projectId": project,
        "projectNumber": project_number,
        "targets": targets,
    }


def write_atomic(path: Path, value: dict[str, object]) -> None:
    if not path.is_absolute():
        raise ManifestError("output must be an absolute path")
    if not path.parent.is_dir():
        raise ManifestError("output directory is unavailable")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Emit the consequence-control effective-IAM allowlist manifest."
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--project-number", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--actuator-service", required=True)
    parser.add_argument("--decision-principal", required=True)
    parser.add_argument("--secret", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        value = manifest(
            project=args.project,
            project_number=args.project_number,
            region=args.region,
            actuator_service=args.actuator_service,
            decision_principal=args.decision_principal,
            secrets=args.secret,
        )
        write_atomic(args.output, value)
    except (ManifestError, OSError) as error:
        print(f"effective IAM manifest refused: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
