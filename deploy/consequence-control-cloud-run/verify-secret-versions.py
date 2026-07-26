#!/usr/bin/env python3
"""Verify pinned Secret Manager version metadata without reading payloads."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Iterable, Sequence


SECRET_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,254}$")
VERSION_RE = re.compile(r"^[1-9][0-9]*$")
CONFIG_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
INVENTORY_FIELDS = {
    "secret",
    "version",
    "state",
    "destroyTime",
    "name",
    "createTime",
}
LIVE_NAME_RE = re.compile(
    r"^projects/[^/]+/secrets/(?P<secret>[A-Za-z][A-Za-z0-9_-]{0,254})/"
    r"versions/(?P<version>[1-9][0-9]*)$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(ValueError):
    """Raised when a secret reference or version state is unsafe."""


@dataclass(frozen=True, order=True)
class SecretReference:
    secret: str
    version: str

    @property
    def value(self) -> str:
        return f"{self.secret}:{self.version}"


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def parse_secret_reference(value: str) -> SecretReference:
    if value.count(":") != 1:
        raise VerificationError(f"invalid secret reference: {value!r}")
    secret, version = value.split(":", 1)
    if SECRET_ID_RE.fullmatch(secret) is None:
        raise VerificationError(f"invalid Secret Manager secret ID: {secret!r}")
    if VERSION_RE.fullmatch(version) is None:
        raise VerificationError(
            f"{secret} must use a positive canonical numeric version"
        )
    return SecretReference(secret, version)


def read_trusted_file(path: Path, name: str) -> bytes:
    if not path.is_absolute():
        raise VerificationError(f"{name} path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(
            f"{name} path must name a regular non-symlink file"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise VerificationError(
                f"{name} path must name a regular non-symlink file"
            )
        if metadata.st_uid not in {0, os.geteuid()}:
            raise VerificationError(f"{name} file ownership is unsafe")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise VerificationError(
                f"{name} file mode permits group or world writes"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        value = b"".join(chunks)
    finally:
        os.close(descriptor)
    if not value:
        raise VerificationError(f"{name} file is empty")
    return value


def parse_config_references(raw: bytes) -> list[SecretReference]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("deployment config is not UTF-8") from error

    references: list[SecretReference] = []
    seen: set[str] = set()
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise VerificationError(f"invalid config line {number}")
        key, value = line.split("=", 1)
        if CONFIG_KEY_RE.fullmatch(key) is None:
            raise VerificationError(f"invalid config key on line {number}")
        if key in seen:
            raise VerificationError(f"duplicate config key on line {number}")
        seen.add(key)
        if not key.endswith("_SECRET"):
            continue
        try:
            references.append(parse_secret_reference(value))
        except VerificationError as error:
            raise VerificationError(f"config line {number}: {error}") from error
    return normalize_references(references)


def load_config_references(path: Path) -> list[SecretReference]:
    return parse_config_references(
        read_trusted_file(path, "deployment config")
    )


def load_pinned_config_references(path: Path) -> list[SecretReference]:
    expected = os.environ.get("DEPLOYMENT_CONFIG_SHA256", "")
    if SHA256_RE.fullmatch(expected) is None:
        raise VerificationError(
            "DEPLOYMENT_CONFIG_SHA256 must be injected by a protected source"
        )
    if path == Path("-"):
        raw = sys.stdin.buffer.read()
        if not raw:
            raise VerificationError("deployment config stream is empty")
    else:
        raw = read_trusted_file(path, "deployment config")
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise VerificationError(
            "deployment config differs from protected SHA-256"
        )
    return parse_config_references(raw)


def normalize_references(
    references: Iterable[SecretReference],
) -> list[SecretReference]:
    return sorted(set(references))


def _inventory_index(inventory: Any) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(inventory, dict) or not isinstance(
        inventory.get("versions"), list
    ):
        raise VerificationError("inventory must contain a versions array")
    unsupported_root = sorted(set(inventory) - {"versions"})
    if unsupported_root:
        raise VerificationError(
            "inventory has unsupported fields: " + ", ".join(unsupported_root)
        )

    index: dict[tuple[str, str], dict[str, Any]] = {}
    for position, record in enumerate(inventory["versions"]):
        if not isinstance(record, dict):
            raise VerificationError(f"inventory record {position} must be an object")
        unsupported = sorted(set(record) - INVENTORY_FIELDS)
        if unsupported:
            raise VerificationError(
                f"inventory record {position} has unsupported fields: "
                + ", ".join(unsupported)
            )
        secret = record.get("secret")
        version = record.get("version")
        if not isinstance(secret, str) or not isinstance(version, str):
            raise VerificationError(
                f"inventory record {position} must identify secret and version"
            )
        reference = parse_secret_reference(f"{secret}:{version}")
        key = (reference.secret, reference.version)
        if key in index:
            raise VerificationError(
                f"duplicate inventory record for {reference.value}"
            )
        index[key] = record
    return index


def verify_inventory(
    references: Sequence[SecretReference],
    inventory: Any,
) -> dict[str, Any]:
    normalized = normalize_references(references)
    if not normalized:
        raise VerificationError("at least one secret reference is required")
    index = _inventory_index(inventory)
    failures: list[str] = []

    for reference in normalized:
        record = index.get((reference.secret, reference.version))
        if record is None:
            failures.append(f"{reference.value} is missing")
            continue
        state = record.get("state")
        if state != "ENABLED":
            failures.append(f"{reference.value} state is {state or 'UNKNOWN'}")
        if record.get("destroyTime") is not None:
            failures.append(f"{reference.value} has a destruction timestamp")

    if failures:
        raise VerificationError("; ".join(failures))
    return {
        "schema": "emilia-secret-version-verification.v1",
        "verified": len(normalized),
        "references": [reference.value for reference in normalized],
        "payloads_read": False,
    }


Runner = Callable[..., subprocess.CompletedProcess[str]]


def fetch_live_version(
    project: str,
    reference: SecretReference,
    *,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    command = [
        "gcloud",
        "secrets",
        "versions",
        "describe",
        reference.version,
        f"--secret={reference.secret}",
        f"--project={project}",
        "--format=json(name,state,destroyTime)",
    ]
    result = runner(
        command,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise VerificationError(
            f"metadata lookup failed for {reference.value}"
        )
    try:
        record = json.loads(
            result.stdout,
            object_pairs_hook=reject_duplicate_members,
        )
    except json.JSONDecodeError as error:
        raise VerificationError(
            f"metadata lookup returned invalid JSON for {reference.value}"
        ) from error
    if not isinstance(record, dict):
        raise VerificationError(
            f"metadata lookup returned invalid data for {reference.value}"
        )
    unsupported = sorted(set(record) - {"name", "state", "destroyTime"})
    if unsupported:
        raise VerificationError(
            f"metadata lookup returned unsupported fields for {reference.value}"
        )
    name = record.get("name")
    match = LIVE_NAME_RE.fullmatch(name) if isinstance(name, str) else None
    if (
        match is None
        or match.group("secret") != reference.secret
        or match.group("version") != reference.version
    ):
        raise VerificationError(
            f"metadata lookup identity mismatch for {reference.value}"
        )
    normalized = {
        "secret": reference.secret,
        "version": reference.version,
        "state": record.get("state"),
        "destroyTime": record.get("destroyTime"),
    }
    verify_inventory([reference], {"versions": [normalized]})
    return normalized


def _load_inventory(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_members,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"unable to load inventory {path}: {error}") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify numeric Secret Manager versions are present and ENABLED "
            "without accessing secret payloads."
        )
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--reference", action="append", default=[])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--inventory", type=Path)
    source.add_argument("--live", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        references = [parse_secret_reference(value) for value in args.reference]
        if args.config is not None:
            references.extend(load_pinned_config_references(args.config))
        references = normalize_references(references)
        if not references:
            raise VerificationError(
                "supply --config and/or at least one --reference"
            )

        if args.live:
            inventory = {
                "versions": [
                    fetch_live_version(args.project, reference)
                    for reference in references
                ]
            }
        else:
            inventory = _load_inventory(args.inventory)
        result = verify_inventory(references, inventory)
    except VerificationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
