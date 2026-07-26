#!/usr/bin/env python3
"""Build-time and deploy-time trust contract for consequence-control images.

The protected workflow creates a source manifest from the reviewed Git commit,
the governed assurance artifacts, and the exact npm tarballs copied into the
images.  OCI labels bind that manifest to each image.  A release manifest then
binds the source manifest to the immutable registry digests that may be
deployed.  Deployment configuration is deliberately not allowed to choose the
candidate image bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


SOURCE_VERSION = "EMILIA-CONSEQUENCE-IMAGE-SOURCE-v2"
RELEASE_VERSION = "EMILIA-CONSEQUENCE-IMAGE-RELEASE-v1"
BUNDLE_VERSION = "EMILIA-CONSEQUENCE-IMAGE-BUNDLE-v1"
REPOSITORY = "https://github.com/emiliaprotocol/emilia-protocol"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_RE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
REGION_RE = re.compile(r"^[a-z]+(?:-[a-z0-9]+)+[0-9]$")
RELEASE_RE = re.compile(r"^[a-z][a-z0-9-]{0,20}$")

GOVERNED_ARTIFACTS = (
    "security/security-case.json",
    "lib/proof-stats.json",
    "conformance/conformance-manifest.json",
)
BUILD_INPUTS = (
    "deploy/consequence-control-cloud-run/build-release-images.sh",
    "deploy/consequence-control-cloud-run/publish-release-images.py",
    "deploy/consequence-control-cloud-run/release-trust.py",
    "deploy/consequence-control-cloud-run/deploy.sh",
    "deploy/consequence-control-cloud-run/lib/common.sh",
    "deploy/consequence-control-cloud-run/Dockerfile.consequence-actuator.release",
    "Dockerfile.consequence-control",
    "Dockerfile.gate",
    "apps/consequence-actuator-service/package-lock.json",
    "apps/consequence-control-service/package-lock.json",
    "apps/gate-service/package-lock.json",
)
PACKAGE_ROOTS = {
    "gate": ("packages/gate", "@emilia-protocol/gate"),
    "require-receipt": (
        "packages/require-receipt",
        "@emilia-protocol/require-receipt",
    ),
    "verify": ("packages/verify", "@emilia-protocol/verify"),
}
PACK_RECIPE = {
    "archive": "git-archive",
    "lifecycle_scripts": False,
    "npm_arguments": ["pack", "--ignore-scripts", "--json"],
    "version": "EMILIA-NPM-PACK-GIT-BLOBS-v1",
}
BUILD_SOURCE_PATHS = (
    ".dockerignore",
    "Dockerfile.consequence-control",
    "Dockerfile.gate",
    "deploy/consequence-control-cloud-run/Dockerfile.consequence-actuator.release",
    "apps/consequence-actuator-service",
    "apps/consequence-control-service",
    "apps/gate-service",
    "caid",
    "packages/gate",
    "packages/require-receipt",
    "packages/verify",
)
DOCKER_CONTEXT_PATHS = BUILD_SOURCE_PATHS[:8]
LABEL_PATHS = {
    "io.emilia.governed.security-case.sha256": "security/security-case.json",
    "io.emilia.governed.proof-stats.sha256": "lib/proof-stats.json",
    "io.emilia.governed.conformance.sha256": "conformance/conformance-manifest.json",
}


class TrustError(ValueError):
    pass


def die(message: str) -> None:
    raise TrustError(message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    require_regular(path, "hashed input")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        raw = canonical_bytes(value)
        view = memoryview(raw)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_json(path: Path, label: str) -> Any:
    require_regular(path, label)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        die(f"{label} is not valid UTF-8 JSON: {error}")


def require_regular(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        die(f"{label} is unavailable: {path}")
    if path.is_symlink() or not path.is_file() or metadata.st_nlink != 1:
        die(f"{label} must be one regular non-symlink file: {path}")


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        die(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def git_bytes(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", *arguments], cwd=root, capture_output=True, check=False
    )
    if result.returncode != 0:
        die(
            f"git {' '.join(arguments)} failed: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout


def validate_commit(value: str, label: str = "commit") -> str:
    if COMMIT_RE.fullmatch(value) is None:
        die(f"{label} must be one lowercase 40-character Git SHA")
    return value


def ensure_reviewed_checkout(root: Path, expected_commit: str) -> str:
    expected_commit = validate_commit(expected_commit, "expected commit")
    actual = git(root, "rev-parse", "HEAD")
    if actual != expected_commit:
        die(f"checked-out commit {actual} does not match reviewed commit {expected_commit}")
    tree = git(root, "rev-parse", "HEAD^{tree}")
    validate_commit(tree, "Git tree")
    for arguments, label in (
        (("diff", "--quiet", "HEAD", "--"), "working tree"),
        (("diff", "--cached", "--quiet", "HEAD", "--"), "index"),
    ):
        result = subprocess.run(["git", *arguments], cwd=root, check=False)
        if result.returncode != 0:
            die(f"{label} differs from the reviewed commit")
    for ignored in (False, True):
        command = ["git", "ls-files", "--others", "-z"]
        if ignored:
            command.extend(["--ignored", "--exclude-standard"])
        else:
            command.append("--exclude-standard")
        command.extend(["--", *BUILD_SOURCE_PATHS])
        result = subprocess.run(command, cwd=root, capture_output=True, check=False)
        if result.returncode != 0:
            die("untracked build-input enumeration failed")
        names = [name for name in result.stdout.split(b"\0") if name]
        if names:
            display = names[0].decode("utf-8", "backslashreplace")
            die(f"untracked build input is forbidden: {display}")
    return tree


def checked_path(root: Path, relative: str, label: str) -> Path:
    candidate = root / relative
    require_regular(candidate, label)
    return candidate


def git_blob(root: Path, commit: str, relative: str) -> tuple[str, bytes]:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or str(pure) != relative:
        die(f"Git source path is unsafe: {relative}")
    record = git_bytes(root, "ls-tree", "-z", commit, "--", relative)
    entries = [entry for entry in record.split(b"\0") if entry]
    if len(entries) != 1:
        die(f"Git source path is not exactly one tracked blob: {relative}")
    try:
        header, encoded_path = entries[0].split(b"\t", 1)
        mode, kind, object_id = header.decode("ascii").split(" ")
        tracked_path = encoded_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        die(f"Git returned an invalid blob record for {relative}: {error}")
    if tracked_path != relative or kind != "blob" or mode not in {"100644", "100755"}:
        die(f"Git source path is not a regular tracked file: {relative}")
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id) is None:
        die(f"Git returned an invalid blob ID for {relative}")
    return object_id, git_bytes(root, "cat-file", "blob", object_id)


def git_file_sha256(root: Path, commit: str, relative: str) -> str:
    _, raw = git_blob(root, commit, relative)
    return sha256_bytes(raw)


def package_metadata(
    path: Path,
    expected_name: str,
    *,
    root: Path,
    expected_commit: str,
    package_root: str,
) -> dict[str, Any]:
    require_regular(path, f"{expected_name} tarball")
    if path.stat().st_size > 128 * 1024 * 1024:
        die(f"{expected_name} tarball is unexpectedly large")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) > 10_000:
                die(f"{expected_name} tarball has too many members")
            names: set[str] = set()
            bound_members: list[dict[str, Any]] = []
            for member in members:
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or ".." in pure.parts:
                    die(f"{expected_name} tarball has an unsafe member path")
                if member.name in names:
                    die(f"{expected_name} tarball repeats a member path")
                names.add(member.name)
                if member.isdir():
                    continue
                if not member.isfile():
                    die(f"{expected_name} tarball has a non-regular member")
                if not member.name.startswith("package/"):
                    die(f"{expected_name} tarball member is outside package/")
                relative = member.name.removeprefix("package/")
                if not relative:
                    die(f"{expected_name} tarball has an empty member path")
                source_path = f"{package_root}/{relative}"
                object_id, expected_raw = git_blob(root, expected_commit, source_path)
                handle = archive.extractfile(member)
                if handle is None:
                    die(f"{expected_name} tarball member is unreadable: {member.name}")
                raw_member = handle.read(128 * 1024 * 1024 + 1)
                if len(raw_member) > 128 * 1024 * 1024:
                    die(f"{expected_name} tarball member is unexpectedly large")
                if raw_member != expected_raw:
                    die(
                        f"{expected_name} tarball member differs from reviewed Git blob: "
                        f"{member.name}"
                    )
                bound_members.append(
                    {
                        "archive_path": member.name,
                        "git_blob": object_id,
                        "sha256": sha256_bytes(raw_member),
                        "size": len(raw_member),
                        "source_path": source_path,
                    }
                )
            package_json = [m for m in members if m.name == "package/package.json" and m.isfile()]
            if len(package_json) != 1:
                die(f"{expected_name} tarball must contain exactly one package/package.json")
            handle = archive.extractfile(package_json[0])
            if handle is None:
                die(f"{expected_name} package metadata is unreadable")
            raw = handle.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                die(f"{expected_name} package metadata is unexpectedly large")
    except (tarfile.TarError, OSError) as error:
        die(f"{expected_name} tarball is invalid: {error}")
    try:
        metadata = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        die(f"{expected_name} package metadata is invalid: {error}")
    if metadata.get("name") != expected_name:
        die(f"tarball package name does not match {expected_name}")
    version = metadata.get("version")
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        die(f"{expected_name} package version is invalid")
    return {
        "filename": path.name,
        "members": sorted(bound_members, key=lambda item: item["archive_path"]),
        "name": expected_name,
        "recipe": {**PACK_RECIPE, "package_root": package_root},
        "sha256": sha256_file(path),
        "version": version,
    }


def source_manifest(
    root: Path,
    expected_commit: str,
    verify_tarball: Path,
    gate_tarball: Path,
    require_receipt_tarball: Path,
) -> dict[str, Any]:
    tree = ensure_reviewed_checkout(root, expected_commit)
    governed: dict[str, str] = {}
    for relative in GOVERNED_ARTIFACTS:
        _, raw = git_blob(root, expected_commit, relative)
        try:
            json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            die(f"governed artifact {relative} is not valid JSON: {error}")
        governed[relative] = sha256_bytes(raw)
    inputs = {
        relative: git_file_sha256(root, expected_commit, relative)
        for relative in BUILD_INPUTS
    }
    return {
        "@version": SOURCE_VERSION,
        "build_inputs": inputs,
        "governed_artifacts": governed,
        "packages": {
            "gate": package_metadata(
                gate_tarball,
                "@emilia-protocol/gate",
                root=root,
                expected_commit=expected_commit,
                package_root=PACKAGE_ROOTS["gate"][0],
            ),
            "require-receipt": package_metadata(
                require_receipt_tarball,
                "@emilia-protocol/require-receipt",
                root=root,
                expected_commit=expected_commit,
                package_root=PACKAGE_ROOTS["require-receipt"][0],
            ),
            "verify": package_metadata(
                verify_tarball,
                "@emilia-protocol/verify",
                root=root,
                expected_commit=expected_commit,
                package_root=PACKAGE_ROOTS["verify"][0],
            ),
        },
        "source": {
            "commit": expected_commit,
            "repository": REPOSITORY,
            "tree": tree,
        },
    }


def validate_source_shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "@version", "build_inputs", "governed_artifacts", "packages", "source"
    }:
        die("source manifest shape is invalid")
    if value.get("@version") != SOURCE_VERSION:
        die("source manifest version is invalid")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {"commit", "repository", "tree"}:
        die("source manifest source binding is invalid")
    validate_commit(source.get("commit", ""), "source commit")
    validate_commit(source.get("tree", ""), "source tree")
    if source.get("repository") != REPOSITORY:
        die("source manifest repository is invalid")
    if set(value.get("governed_artifacts", {})) != set(GOVERNED_ARTIFACTS):
        die("source manifest governed-artifact set is incomplete")
    if set(value.get("build_inputs", {})) != set(BUILD_INPUTS):
        die("source manifest build-input set is incomplete")
    for group in (value["governed_artifacts"], value["build_inputs"]):
        if not isinstance(group, dict) or any(SHA256_RE.fullmatch(v or "") is None for v in group.values()):
            die("source manifest contains an invalid file digest")
    packages = value.get("packages")
    if not isinstance(packages, dict) or set(packages) != {
        "gate", "require-receipt", "verify"
    }:
        die("source manifest package set is invalid")
    for key, (package_root, expected_name) in PACKAGE_ROOTS.items():
        record = packages.get(key)
        if not isinstance(record, dict) or set(record) != {
            "filename", "members", "name", "recipe", "sha256", "version"
        }:
            die(f"source manifest {key} package record is invalid")
        if record.get("name") != expected_name:
            die(f"source manifest {key} package name is invalid")
        filename = record.get("filename")
        if not isinstance(filename, str) or PurePosixPath(filename).name != filename:
            die(f"source manifest {key} package filename is invalid")
        if SHA256_RE.fullmatch(record.get("sha256", "")) is None:
            die(f"source manifest {key} package digest is invalid")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", record.get("version", "")) is None:
            die(f"source manifest {key} package version is invalid")
        if record.get("recipe") != {**PACK_RECIPE, "package_root": package_root}:
            die(f"source manifest {key} package recipe is invalid")
        members = record.get("members")
        if not isinstance(members, list) or not members:
            die(f"source manifest {key} package member binding is empty")
        if members != sorted(members, key=lambda item: item.get("archive_path", "")):
            die(f"source manifest {key} package member binding is not canonical")
        names: set[str] = set()
        for member in members:
            if not isinstance(member, dict) or set(member) != {
                "archive_path", "git_blob", "sha256", "size", "source_path"
            }:
                die(f"source manifest {key} package member is invalid")
            archive_path = member.get("archive_path")
            source_path = member.get("source_path")
            if (
                not isinstance(archive_path, str)
                or not archive_path.startswith("package/")
                or archive_path in names
                or not isinstance(source_path, str)
                or source_path != f"{package_root}/{archive_path.removeprefix('package/')}"
                or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", member.get("git_blob", "")) is None
                or SHA256_RE.fullmatch(member.get("sha256", "")) is None
                or not isinstance(member.get("size"), int)
                or member["size"] < 0
            ):
                die(f"source manifest {key} package member binding is invalid")
            names.add(archive_path)
    return value


def verify_source(
    root: Path,
    manifest_path: Path,
    artifact_dir: Path,
    expected_commit: str,
) -> dict[str, Any]:
    value = validate_source_shape(read_json(manifest_path, "source manifest"))
    if value["source"]["commit"] != expected_commit:
        die("source manifest commit does not match the reviewed commit")
    tree = ensure_reviewed_checkout(root, expected_commit)
    if value["source"]["tree"] != tree:
        die("source manifest tree does not match the reviewed Git tree")
    for relative, expected in value["governed_artifacts"].items():
        if git_file_sha256(root, expected_commit, relative) != expected:
            die(f"governed artifact differs from source manifest: {relative}")
    for relative, expected in value["build_inputs"].items():
        if git_file_sha256(root, expected_commit, relative) != expected:
            die(f"build input differs from source manifest: {relative}")
    for key, (package_root, expected_name) in PACKAGE_ROOTS.items():
        record = value["packages"][key]
        filename = record.get("filename")
        actual = package_metadata(
            artifact_dir / filename,
            expected_name,
            root=root,
            expected_commit=expected_commit,
            package_root=package_root,
        )
        if actual != record:
            die(f"{key} tarball differs from source manifest")
    return value


def extract_git_archive(root: Path, commit: str, paths: list[str], output: Path) -> None:
    process = subprocess.Popen(
        ["git", "archive", "--format=tar", commit, "--", *paths],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or ".." in pure.parts:
                    die("Git archive contains an unsafe path")
                archive.extract(member, output, filter="data")
        _, stderr = process.communicate()
        if process.returncode != 0:
            die(f"Git archive failed: {stderr.decode('utf-8', 'replace').strip()}")
    except Exception:
        process.kill()
        process.wait()
        raise


def pack_git_package(
    root: Path,
    expected_commit: str,
    package_root: str,
    expected_name: str,
    output_dir: Path,
) -> Path:
    ensure_reviewed_checkout(root, expected_commit)
    output_dir = output_dir.resolve()
    if not output_dir.is_dir() or output_dir.is_symlink():
        die("package output directory must be one existing directory")
    with tempfile.TemporaryDirectory(prefix="emilia-git-pack-") as directory:
        snapshot = Path(directory)
        extract_git_archive(root, expected_commit, [package_root], snapshot)
        result = subprocess.run(
            [
                "npm",
                "pack",
                str(snapshot / package_root),
                "--ignore-scripts",
                "--json",
                "--pack-destination",
                str(output_dir),
            ],
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "npm_config_ignore_scripts": "true"},
        )
    if result.returncode != 0:
        die(f"lifecycle-disabled npm pack failed: {result.stderr.strip()[:500]}")
    try:
        packed = json.loads(result.stdout)
        if (
            not isinstance(packed, list)
            or len(packed) != 1
            or not isinstance(packed[0], dict)
            or not isinstance(packed[0].get("filename"), str)
        ):
            raise ValueError("npm pack returned an unexpected record")
        filename = PurePosixPath(packed[0]["filename"])
        if filename.name != str(filename):
            raise ValueError("npm pack returned an unsafe filename")
    except (json.JSONDecodeError, ValueError) as error:
        die(f"lifecycle-disabled npm pack output is invalid: {error}")
    path = output_dir / filename.name
    package_metadata(
        path,
        expected_name,
        root=root,
        expected_commit=expected_commit,
        package_root=package_root,
    )
    return path


def inspect_record(path: Path, component: str, source_path: Path) -> tuple[str, dict[str, Any]]:
    value = read_json(path, f"{component} image inspection")
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        die(f"{component} image inspection must contain exactly one image")
    image_id = value[0].get("Id")
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        die(f"{component} image inspection has an invalid image ID")
    args = argparse.Namespace(
        source_manifest=source_path,
        inspect=path,
        component=component,
    )
    command_verify_inspect(args)
    return image_id, value[0]


def verify_image_archive(
    path: Path, *, component: str, expected_tag: str, expected_id: str
) -> None:
    """Require one Docker-save image whose only tag and config match the seal."""
    require_regular(path, f"{component} image archive")
    files: dict[str, tarfile.TarInfo] = {}
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > 100_000:
                die(f"{component} image archive inventory is invalid")
            seen: set[str] = set()
            for member in members:
                name = member.name
                candidate = PurePosixPath(name)
                if (
                    not name
                    or candidate.is_absolute()
                    or "\\" in name
                    or any(part in ("", ".", "..") for part in candidate.parts)
                    or name in seen
                ):
                    die(f"{component} image archive has an unsafe or duplicate member")
                seen.add(name)
                if member.isfile():
                    files[name] = member
                elif not member.isdir():
                    die(f"{component} image archive contains a non-regular member")
            manifest_member = files.get("manifest.json")
            if manifest_member is None or manifest_member.size > 1024 * 1024:
                die(f"{component} image archive has no bounded manifest")
            manifest_handle = archive.extractfile(manifest_member)
            if manifest_handle is None:
                die(f"{component} image archive manifest is unavailable")
            manifest = json.loads(manifest_handle.read())
            if not isinstance(manifest, list) or len(manifest) != 1:
                die(f"{component} image archive must contain exactly one image")
            record = manifest[0]
            if not isinstance(record, dict):
                die(f"{component} image archive manifest record is invalid")
            config_name = record.get("Config")
            tags = record.get("RepoTags")
            layers = record.get("Layers")
            if (
                not isinstance(config_name, str)
                or config_name not in files
                or tags != [expected_tag]
                or not isinstance(layers, list)
                or not layers
                or len(layers) != len(set(layers))
                or any(not isinstance(layer, str) or layer not in files for layer in layers)
            ):
                die(
                    f"{component} image archive must contain exactly its sealed image and tag"
                )
            config_member = files[config_name]
            if config_member.size > 16 * 1024 * 1024:
                die(f"{component} image archive config is unbounded")
            config_handle = archive.extractfile(config_member)
            if config_handle is None:
                die(f"{component} image archive config is unavailable")
            config_digest = "sha256:" + hashlib.sha256(config_handle.read()).hexdigest()
            if config_digest != expected_id:
                die(f"{component} image archive config differs from its sealed image ID")
    except (tarfile.TarError, json.JSONDecodeError, UnicodeDecodeError) as error:
        die(f"{component} image archive is invalid: {error}")


def bundle_manifest(
    *,
    root: Path,
    bundle_dir: Path,
    source_path: Path,
    expected_commit: str,
    actuator_archive: Path,
    actuator_inspect: Path,
    actuator_tag: str,
    decision_archive: Path,
    decision_inspect: Path,
    decision_tag: str,
) -> dict[str, Any]:
    source = verify_source(root, source_path, bundle_dir, expected_commit)
    tag_pattern = re.compile(r"^emilia-[a-z0-9-]+:git-([0-9a-f]{40})$")
    artifacts: dict[str, dict[str, Any]] = {}
    images: dict[str, dict[str, str]] = {}
    inputs = {
        "actuator": (actuator_archive, actuator_inspect, actuator_tag),
        "decision": (decision_archive, decision_inspect, decision_tag),
    }
    files = [source_path]
    files.extend(bundle_dir / source["packages"][key]["filename"] for key in PACKAGE_ROOTS)
    for component, (archive, inspect, tag) in inputs.items():
        match = tag_pattern.fullmatch(tag)
        if match is None or match.group(1) != expected_commit:
            die(f"{component} bundle tag is not derived from the reviewed commit")
        image_id, _ = inspect_record(inspect, component, source_path)
        verify_image_archive(
            archive,
            component=component,
            expected_tag=tag,
            expected_id=image_id,
        )
        files.extend([archive, inspect])
        images[component] = {
            "archive": archive.name,
            "id": image_id,
            "inspect": inspect.name,
            "tag": tag,
        }
    for path in files:
        resolved = path.resolve()
        if resolved.parent != bundle_dir.resolve():
            die("bundle artifact must be a direct child of the bundle directory")
        require_regular(resolved, f"bundle artifact {resolved.name}")
        artifacts[resolved.name] = {
            "sha256": sha256_file(resolved),
            "size": resolved.stat().st_size,
        }
    if len(artifacts) != len(files):
        die("bundle artifact filenames are not unique")
    return {
        "@version": BUNDLE_VERSION,
        "artifacts": dict(sorted(artifacts.items())),
        "images": images,
        "source": {
            "commit": source["source"]["commit"],
            "manifest": source_path.name,
            "manifest_sha256": sha256_file(source_path),
            "tree": source["source"]["tree"],
        },
    }


def validate_bundle_shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"@version", "artifacts", "images", "source"}:
        die("bundle manifest shape is invalid")
    if value.get("@version") != BUNDLE_VERSION:
        die("bundle manifest version is invalid")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {
        "commit", "manifest", "manifest_sha256", "tree"
    }:
        die("bundle source binding is invalid")
    validate_commit(source.get("commit", ""), "bundle source commit")
    validate_commit(source.get("tree", ""), "bundle source tree")
    if (
        source.get("manifest") != "source-manifest.json"
        or SHA256_RE.fullmatch(source.get("manifest_sha256", "")) is None
    ):
        die("bundle source-manifest binding is invalid")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        die("bundle artifact set is invalid")
    for name, record in artifacts.items():
        if (
            not isinstance(name, str)
            or PurePosixPath(name).name != name
            or not isinstance(record, dict)
            or set(record) != {"sha256", "size"}
            or SHA256_RE.fullmatch(record.get("sha256", "")) is None
            or not isinstance(record.get("size"), int)
            or record["size"] < 0
        ):
            die("bundle artifact record is invalid")
    images = value.get("images")
    if not isinstance(images, dict) or set(images) != {"actuator", "decision"}:
        die("bundle image set is invalid")
    for component, record in images.items():
        if not isinstance(record, dict) or set(record) != {"archive", "id", "inspect", "tag"}:
            die(f"bundle {component} image record is invalid")
        if (
            record.get("archive") not in artifacts
            or record.get("inspect") not in artifacts
            or re.fullmatch(r"sha256:[0-9a-f]{64}", record.get("id", "")) is None
            or re.fullmatch(
                rf"emilia-[a-z0-9-]+:git-{source['commit']}", record.get("tag", "")
            ) is None
        ):
            die(f"bundle {component} image binding is invalid")
    if len({record["id"] for record in images.values()}) != 2:
        die("bundle actuator and decision image IDs must be distinct")
    if len({record["tag"] for record in images.values()}) != 2:
        die("bundle actuator and decision tags must be distinct")
    return value


def verify_bundle(
    root: Path, bundle_dir: Path, bundle_path: Path, expected_commit: str
) -> dict[str, Any]:
    bundle_dir = bundle_dir.resolve()
    if not bundle_dir.is_dir() or bundle_dir.is_symlink():
        die("bundle directory is unavailable")
    bundle = validate_bundle_shape(read_json(bundle_path, "bundle manifest"))
    if bundle["source"]["commit"] != expected_commit:
        die("bundle commit does not match the reviewed commit")
    expected_names = set(bundle["artifacts"]) | {bundle_path.name}
    actual_names = {path.name for path in bundle_dir.iterdir()}
    if actual_names != expected_names:
        die("bundle directory contains missing or unbound artifacts")
    for name, record in bundle["artifacts"].items():
        path = bundle_dir / name
        require_regular(path, f"bundle artifact {name}")
        if path.stat().st_size != record["size"] or sha256_file(path) != record["sha256"]:
            die(f"bundle artifact differs from manifest: {name}")
    source_path = bundle_dir / bundle["source"]["manifest"]
    if sha256_file(source_path) != bundle["source"]["manifest_sha256"]:
        die("bundle source manifest differs from its binding")
    source = verify_source(root, source_path, bundle_dir, expected_commit)
    if source["source"]["tree"] != bundle["source"]["tree"]:
        die("bundle Git tree differs from the accepted source manifest")
    for component, record in bundle["images"].items():
        image_id, _ = inspect_record(bundle_dir / record["inspect"], component, source_path)
        if image_id != record["id"]:
            die(f"bundle {component} image ID differs from its binding")
        verify_image_archive(
            bundle_dir / record["archive"],
            component=component,
            expected_tag=record["tag"],
            expected_id=record["id"],
        )
    return bundle


def expected_labels(value: dict[str, Any], manifest_path: Path) -> dict[str, str]:
    labels = {
        "org.opencontainers.image.revision": value["source"]["commit"],
        "org.opencontainers.image.source": REPOSITORY,
        "io.emilia.source.tree": value["source"]["tree"],
        "io.emilia.source.manifest.sha256": sha256_file(manifest_path),
        "io.emilia.package.verify.sha256": value["packages"]["verify"]["sha256"],
        "io.emilia.package.gate.sha256": value["packages"]["gate"]["sha256"],
        "io.emilia.package.require-receipt.sha256": value["packages"]["require-receipt"]["sha256"],
    }
    labels.update({key: value["governed_artifacts"][path] for key, path in LABEL_PATHS.items()})
    return labels


def parse_config(path: Path, *, forbid_images: bool) -> tuple[list[str], dict[str, str]]:
    require_regular(path, "deployment config")
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        die(f"deployment config is not UTF-8: {error}")
    if "\x00" in raw or "\r" in raw:
        die("deployment config contains a forbidden control byte")
    lines = raw.splitlines()
    values: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            die(f"deployment config line {number} is invalid")
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None:
            die(f"deployment config key on line {number} is invalid")
        if key in values:
            die(f"deployment config repeats {key}")
        values[key] = value
    if forbid_images and ({"ACTUATOR_IMAGE", "DECISION_IMAGE"} & values.keys()):
        die("candidate deployment config must not choose ACTUATOR_IMAGE or DECISION_IMAGE")
    return lines, values


def release_manifest(source_path: Path, actuator_image: str, decision_image: str) -> dict[str, Any]:
    source = validate_source_shape(read_json(source_path, "source manifest"))
    for label, image in (("actuator", actuator_image), ("decision", decision_image)):
        if IMAGE_RE.fullmatch(image) is None:
            die(f"{label} image is not pinned by a lowercase registry digest")
    if actuator_image == decision_image:
        die("actuator and decision images must be distinct")
    return {
        "@version": RELEASE_VERSION,
        "images": {"actuator": actuator_image, "decision": decision_image},
        "source": {
            "commit": source["source"]["commit"],
            "manifest_sha256": sha256_file(source_path),
            "tree": source["source"]["tree"],
        },
    }


def validate_release_shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"@version", "images", "source"}:
        die("release manifest shape is invalid")
    if value.get("@version") != RELEASE_VERSION:
        die("release manifest version is invalid")
    images = value.get("images")
    source = value.get("source")
    if not isinstance(images, dict) or set(images) != {"actuator", "decision"}:
        die("release manifest image set is invalid")
    if any(IMAGE_RE.fullmatch(v or "") is None for v in images.values()) or images["actuator"] == images["decision"]:
        die("release manifest image binding is invalid")
    if not isinstance(source, dict) or set(source) != {"commit", "manifest_sha256", "tree"}:
        die("release manifest source binding is invalid")
    validate_commit(source.get("commit", ""), "release source commit")
    validate_commit(source.get("tree", ""), "release source tree")
    if SHA256_RE.fullmatch(source.get("manifest_sha256", "")) is None:
        die("release source-manifest digest is invalid")
    return value


def verify_release(
    root: Path,
    source_path: Path,
    release_path: Path,
    artifact_dir: Path,
    expected_commit: str,
    config_path: Path | None,
) -> dict[str, Any]:
    source = verify_source(root, source_path, artifact_dir, expected_commit)
    release = validate_release_shape(read_json(release_path, "release manifest"))
    expected_source = {
        "commit": source["source"]["commit"],
        "manifest_sha256": sha256_file(source_path),
        "tree": source["source"]["tree"],
    }
    if release["source"] != expected_source:
        die("release manifest does not bind the accepted source manifest")
    if config_path is not None:
        _, values = parse_config(config_path, forbid_images=False)
        expected_images = {
            "actuator": values.get("ACTUATOR_IMAGE"),
            "decision": values.get("DECISION_IMAGE"),
        }
        if expected_images != release["images"]:
            die("deployment config images do not match the reviewed release manifest")
    return release


def command_source(args: argparse.Namespace) -> None:
    value = source_manifest(
        args.root.resolve(),
        args.expected_commit,
        args.verify_tarball.resolve(),
        args.gate_tarball.resolve(),
        args.require_receipt_tarball.resolve(),
    )
    write_json(args.output.resolve(), value)
    print(sha256_file(args.output.resolve()))


def command_pack_package(args: argparse.Namespace) -> None:
    package_root, expected_name = PACKAGE_ROOTS[args.package]
    path = pack_git_package(
        args.root.resolve(),
        args.expected_commit,
        package_root,
        expected_name,
        args.output_dir.resolve(),
    )
    print(path)


def command_context(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    ensure_reviewed_checkout(root, args.expected_commit)
    output = args.output.resolve()
    if output.exists():
        die(f"Docker context output already exists: {output}")
    tarballs = {
        "verify.tgz": args.verify_tarball.resolve(),
        "gate.tgz": args.gate_tarball.resolve(),
        "require-receipt.tgz": args.require_receipt_tarball.resolve(),
    }
    for name, source in tarballs.items():
        require_regular(source, f"Docker context {name}")
    output.mkdir(parents=True, mode=0o700)
    try:
        extract_git_archive(root, args.expected_commit, list(DOCKER_CONTEXT_PATHS), output)
        release_dir = output / "release-packages"
        release_dir.mkdir(mode=0o700)
        for name, source in tarballs.items():
            destination = release_dir / name
            with source.open("rb") as reader, destination.open("xb") as writer:
                shutil.copyfileobj(reader, writer)
            destination.chmod(0o400)
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise
    print(output)


def command_bundle(args: argparse.Namespace) -> None:
    value = bundle_manifest(
        root=args.root.resolve(),
        bundle_dir=args.bundle_dir.resolve(),
        source_path=args.source_manifest.resolve(),
        expected_commit=args.expected_commit,
        actuator_archive=args.actuator_archive.resolve(),
        actuator_inspect=args.actuator_inspect.resolve(),
        actuator_tag=args.actuator_tag,
        decision_archive=args.decision_archive.resolve(),
        decision_inspect=args.decision_inspect.resolve(),
        decision_tag=args.decision_tag,
    )
    write_json(args.output.resolve(), value)
    print(sha256_file(args.output.resolve()))


def command_verify_bundle(args: argparse.Namespace) -> None:
    verify_bundle(
        args.root.resolve(),
        args.bundle_dir.resolve(),
        args.bundle_manifest.resolve(),
        args.expected_commit,
    )
    print("release bundle accepted")


def command_load_bundle(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    bundle_dir = args.bundle_dir.resolve()
    manifest = args.bundle_manifest.resolve()
    bundle = verify_bundle(root, bundle_dir, manifest, args.expected_commit)
    docker = args.docker_bin.resolve()
    require_regular(docker, "Docker CLI")
    if not os.access(docker, os.X_OK):
        die("Docker CLI is not executable")
    for component in ("actuator", "decision"):
        record = bundle["images"][component]
        loaded = subprocess.run(
            [str(docker), "load", "--input", str(bundle_dir / record["archive"])],
            text=True,
            capture_output=True,
            check=False,
        )
        if loaded.returncode != 0:
            die(f"Docker refused the sealed {component} image archive")
        loaded_tags = []
        for line in (loaded.stdout + "\n" + loaded.stderr).splitlines():
            match = re.fullmatch(r"Loaded image: (.+)", line.strip())
            if match is not None:
                loaded_tags.append(match.group(1))
            elif line.strip().startswith("Loaded image ID:"):
                die(f"sealed {component} archive loaded an untagged image")
        if loaded_tags != [record["tag"]]:
            die(f"sealed {component} archive loaded an unexpected image or tag set")

    sealed_ids = {
        component: bundle["images"][component]["id"]
        for component in ("actuator", "decision")
    }
    current_ids: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="emilia-loaded-images-") as directory:
        for component in ("actuator", "decision"):
            record = bundle["images"][component]
            inspected = subprocess.run(
                [str(docker), "image", "inspect", record["tag"]],
                text=True,
                capture_output=True,
                check=False,
            )
            if inspected.returncode != 0:
                die(f"Docker could not inspect loaded {component} image")
            inspect_path = Path(directory) / f"{component}.json"
            inspect_path.write_text(inspected.stdout, encoding="utf-8")
            image_id, _ = inspect_record(
                inspect_path, component, bundle_dir / bundle["source"]["manifest"]
            )
            current_ids[component] = image_id
    if current_ids != sealed_ids:
        die("loaded actuator and decision image IDs differ from the sealed pair")
    print("sealed release images loaded and verified")


def command_labels(args: argparse.Namespace) -> None:
    value = validate_source_shape(read_json(args.source_manifest.resolve(), "source manifest"))
    for key, value in sorted(expected_labels(value, args.source_manifest.resolve()).items()):
        print(f"{key}={value}")


def command_verify_inspect(args: argparse.Namespace) -> None:
    source_path = args.source_manifest.resolve()
    source = validate_source_shape(read_json(source_path, "source manifest"))
    inspect = read_json(args.inspect.resolve(), "Docker inspect record")
    if not isinstance(inspect, list) or len(inspect) != 1 or not isinstance(inspect[0], dict):
        die("Docker inspect record must contain exactly one image")
    labels = inspect[0].get("Config", {}).get("Labels")
    if not isinstance(labels, dict):
        die("Docker image labels are unavailable")
    expected = expected_labels(source, source_path)
    for key, value in expected.items():
        if labels.get(key) != value:
            die(f"Docker image label mismatch: {key}")
    if labels.get("io.emilia.image.component") != args.component:
        die("Docker image component label does not match the requested component")
    print(f"accepted {args.component} image labels")


def command_release(args: argparse.Namespace) -> None:
    value = release_manifest(args.source_manifest.resolve(), args.actuator_image, args.decision_image)
    write_json(args.output.resolve(), value)
    print(sha256_file(args.output.resolve()))


def command_derive_config(args: argparse.Namespace) -> None:
    lines, _ = parse_config(args.config.resolve(), forbid_images=True)
    release = validate_release_shape(read_json(args.release_manifest.resolve(), "release manifest"))
    output = args.output.resolve()
    if output.exists():
        die(f"derived config output already exists: {output}")
    raw = "\n".join(lines)
    if raw and not raw.endswith("\n"):
        raw += "\n"
    raw += "# Images below are generated from the reviewed release manifest.\n"
    raw += f"ACTUATOR_IMAGE={release['images']['actuator']}\n"
    raw += f"DECISION_IMAGE={release['images']['decision']}\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o400)
    try:
        os.write(descriptor, raw.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(sha256_file(output))


def command_coordinates(args: argparse.Namespace) -> None:
    _, values = parse_config(args.config.resolve(), forbid_images=True)
    required = {"PROJECT_ID": PROJECT_RE, "REGION": REGION_RE, "RELEASE_ID": RELEASE_RE}
    for key, pattern in required.items():
        value = values.get(key, "")
        if pattern.fullmatch(value) is None:
            die(f"deployment config {key} is invalid")
        print(value)


def command_verify_release(args: argparse.Namespace) -> None:
    verify_release(
        args.root.resolve(),
        args.source_manifest.resolve(),
        args.release_manifest.resolve(),
        args.artifact_dir.resolve(),
        args.expected_commit,
        args.config.resolve() if args.config else None,
    )
    print("release trust chain accepted")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    source = commands.add_parser("source")
    source.add_argument("--root", type=Path, required=True)
    source.add_argument("--expected-commit", required=True)
    source.add_argument("--verify-tarball", type=Path, required=True)
    source.add_argument("--gate-tarball", type=Path, required=True)
    source.add_argument("--require-receipt-tarball", type=Path, required=True)
    source.add_argument("--output", type=Path, required=True)
    source.set_defaults(handler=command_source)

    pack = commands.add_parser("pack-package")
    pack.add_argument("--root", type=Path, required=True)
    pack.add_argument("--expected-commit", required=True)
    pack.add_argument("--package", choices=tuple(PACKAGE_ROOTS), required=True)
    pack.add_argument("--output-dir", type=Path, required=True)
    pack.set_defaults(handler=command_pack_package)

    context = commands.add_parser("context")
    context.add_argument("--root", type=Path, required=True)
    context.add_argument("--expected-commit", required=True)
    context.add_argument("--verify-tarball", type=Path, required=True)
    context.add_argument("--gate-tarball", type=Path, required=True)
    context.add_argument("--require-receipt-tarball", type=Path, required=True)
    context.add_argument("--output", type=Path, required=True)
    context.set_defaults(handler=command_context)

    bundle = commands.add_parser("bundle")
    bundle.add_argument("--root", type=Path, required=True)
    bundle.add_argument("--bundle-dir", type=Path, required=True)
    bundle.add_argument("--source-manifest", type=Path, required=True)
    bundle.add_argument("--expected-commit", required=True)
    bundle.add_argument("--actuator-archive", type=Path, required=True)
    bundle.add_argument("--actuator-inspect", type=Path, required=True)
    bundle.add_argument("--actuator-tag", required=True)
    bundle.add_argument("--decision-archive", type=Path, required=True)
    bundle.add_argument("--decision-inspect", type=Path, required=True)
    bundle.add_argument("--decision-tag", required=True)
    bundle.add_argument("--output", type=Path, required=True)
    bundle.set_defaults(handler=command_bundle)

    verify_bundle_parser = commands.add_parser("verify-bundle")
    verify_bundle_parser.add_argument("--root", type=Path, required=True)
    verify_bundle_parser.add_argument("--bundle-dir", type=Path, required=True)
    verify_bundle_parser.add_argument("--bundle-manifest", type=Path, required=True)
    verify_bundle_parser.add_argument("--expected-commit", required=True)
    verify_bundle_parser.set_defaults(handler=command_verify_bundle)

    load_bundle = commands.add_parser("load-bundle")
    load_bundle.add_argument("--root", type=Path, required=True)
    load_bundle.add_argument("--bundle-dir", type=Path, required=True)
    load_bundle.add_argument("--bundle-manifest", type=Path, required=True)
    load_bundle.add_argument("--expected-commit", required=True)
    load_bundle.add_argument("--docker-bin", type=Path, default=Path("/usr/bin/docker"))
    load_bundle.set_defaults(handler=command_load_bundle)

    labels = commands.add_parser("labels")
    labels.add_argument("--source-manifest", type=Path, required=True)
    labels.set_defaults(handler=command_labels)

    inspect = commands.add_parser("verify-inspect")
    inspect.add_argument("--source-manifest", type=Path, required=True)
    inspect.add_argument("--inspect", type=Path, required=True)
    inspect.add_argument("--component", choices=("actuator", "decision", "gate"), required=True)
    inspect.set_defaults(handler=command_verify_inspect)

    release = commands.add_parser("release")
    release.add_argument("--source-manifest", type=Path, required=True)
    release.add_argument("--actuator-image", required=True)
    release.add_argument("--decision-image", required=True)
    release.add_argument("--output", type=Path, required=True)
    release.set_defaults(handler=command_release)

    derived = commands.add_parser("derive-config")
    derived.add_argument("--config", type=Path, required=True)
    derived.add_argument("--release-manifest", type=Path, required=True)
    derived.add_argument("--output", type=Path, required=True)
    derived.set_defaults(handler=command_derive_config)

    coordinates = commands.add_parser("coordinates")
    coordinates.add_argument("--config", type=Path, required=True)
    coordinates.set_defaults(handler=command_coordinates)

    verify = commands.add_parser("verify-release")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--source-manifest", type=Path, required=True)
    verify.add_argument("--release-manifest", type=Path, required=True)
    verify.add_argument("--artifact-dir", type=Path, required=True)
    verify.add_argument("--expected-commit", required=True)
    verify.add_argument("--config", type=Path)
    verify.set_defaults(handler=command_verify_release)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.handler(args)
        return 0
    except TrustError as error:
        print(f"release trust refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
