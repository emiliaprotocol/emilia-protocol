#!/usr/bin/env python3
"""Emit the closed effective-IAM manifest from deployment coordinates."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from datetime import datetime, timezone
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
ANALYZER_SCOPE = re.compile(
    r"^(projects/[a-z][a-z0-9-]{4,28}[a-z0-9]|"
    r"organizations/[1-9][0-9]*)$"
)
CONCRETE_PRINCIPAL = re.compile(
    r"^(?:user|serviceAccount):[^@\s]+@[^@\s]+$|^principal://[^\s]+$"
)
CONDITION_TITLE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
JIT_MAX_LIFETIME_SECONDS = 900


class ManifestError(ValueError):
    """The deployment coordinates cannot produce a closed IAM manifest."""


def principal(value: str, name: str) -> str:
    if SERVICE_ACCOUNT.fullmatch(value) is None:
        raise ManifestError(f"{name} must be one concrete service account")
    return value


def concrete_principal(value: str, name: str) -> str:
    if CONCRETE_PRINCIPAL.fullmatch(value) is None:
        raise ManifestError(f"{name} must be one concrete IAM principal")
    return value


def utc_timestamp(value: str, name: str) -> datetime:
    if not value.endswith("Z"):
        raise ManifestError(f"{name} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ManifestError(f"{name} is not a valid timestamp") from error
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise ManifestError(f"{name} must use whole-second UTC precision")
    return parsed


def runtime_act_as_target(
    *,
    label: str,
    project: str,
    scope: str,
    runtime_principal: str,
    deployer: str,
    title_prefix: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, object]:
    account = runtime_principal.removeprefix("serviceAccount:")
    title = f"{title_prefix}-{label}"
    if CONDITION_TITLE.fullmatch(title) is None:
        raise ManifestError(
            f"JIT condition title for {label} must be unique and at most 100 characters"
        )
    description = (
        f"EMILIA {title_prefix.removeprefix('emilia-jit-actas-')} "
        f"{label} rollout; hard expiry {JIT_MAX_LIFETIME_SECONDS}s"
    )
    expression = f"request.time < timestamp('{expires_at}')"
    return {
        "name": f"runtime-actAs:{label}",
        "kind": "runtimeActAs",
        "scope": scope,
        "resource": (
            f"//iam.googleapis.com/projects/{project}/serviceAccounts/{account}"
        ),
        "allowedPrincipals": [],
        "jitGrant": {
            "principal": deployer,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "maxLifetimeSeconds": JIT_MAX_LIFETIME_SECONDS,
            "condition": {
                "title": title,
                "description": description,
                "expression": expression,
            },
        },
    }


def managed_control_plane_principals(project_number: str) -> tuple[str, str]:
    """Return exact project-derived control-plane principals accepted by the profile."""
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
    analyzer_scope: str | None = None,
    actuator_principal: str | None = None,
    deployer_principal: str | None = None,
    jit_condition_title_prefix: str | None = None,
    jit_issued_at: str | None = None,
    jit_expires_at: str | None = None,
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

    scope = analyzer_scope or f"projects/{project}"
    if ANALYZER_SCOPE.fullmatch(scope) is None:
        raise ManifestError(
            "analyzer scope must be the exact project or an ancestor organization"
        )
    if scope.startswith("projects/") and scope != f"projects/{project}":
        raise ManifestError(
            "project analyzer scope does not match the deployment project"
        )
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
    jit_coordinates = (
        actuator_principal,
        deployer_principal,
        jit_condition_title_prefix,
        jit_issued_at,
        jit_expires_at,
    )
    if any(value is not None for value in jit_coordinates):
        if not all(value is not None for value in jit_coordinates):
            raise ManifestError("all JIT coordinates must be provided together")
        actuator = principal(
            actuator_principal or "",
            "actuator principal",
        )
        deployer = concrete_principal(
            deployer_principal or "",
            "deployer principal",
        )
        title_prefix = jit_condition_title_prefix or ""
        if CONDITION_TITLE.fullmatch(title_prefix) is None:
            raise ManifestError("JIT condition title prefix is invalid")
        issued_text = jit_issued_at or ""
        expires_text = jit_expires_at or ""
        issued = utc_timestamp(issued_text, "JIT issued-at")
        expires = utc_timestamp(expires_text, "JIT expires-at")
        lifetime = int((expires - issued).total_seconds())
        if lifetime <= 0 or lifetime > JIT_MAX_LIFETIME_SECONDS:
            raise ManifestError(
                "JIT expiry must be after issue time and no more than "
                f"{JIT_MAX_LIFETIME_SECONDS} seconds later"
            )
        targets.extend(
            runtime_act_as_target(
                label=label,
                project=project,
                scope=scope,
                runtime_principal=runtime,
                deployer=deployer,
                title_prefix=title_prefix,
                issued_at=issued_text,
                expires_at=expires_text,
            )
            for label, runtime in (
                ("actuator", actuator),
                ("decision", decision),
            )
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
    parser.add_argument("--actuator-principal")
    parser.add_argument("--decision-principal", required=True)
    parser.add_argument("--deployer-principal")
    parser.add_argument("--jit-condition-title-prefix")
    parser.add_argument("--jit-issued-at")
    parser.add_argument("--jit-expires-at")
    parser.add_argument(
        "--analyzer-scope",
        default=os.environ.get("EMILIA_IAM_ANALYZER_SCOPE"),
        help=(
            "projects/PROJECT for a standalone project or the explicit "
            "organizations/NUMBER scope proven from project ancestry"
        ),
    )
    parser.add_argument("--secret", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        value = manifest(
            project=args.project,
            project_number=args.project_number,
            region=args.region,
            actuator_service=args.actuator_service,
            actuator_principal=args.actuator_principal,
            decision_principal=args.decision_principal,
            deployer_principal=args.deployer_principal,
            jit_condition_title_prefix=args.jit_condition_title_prefix,
            jit_issued_at=args.jit_issued_at,
            jit_expires_at=args.jit_expires_at,
            secrets=args.secret,
            analyzer_scope=args.analyzer_scope,
        )
        write_atomic(args.output, value)
    except (ManifestError, OSError) as error:
        print(f"effective IAM manifest refused: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
