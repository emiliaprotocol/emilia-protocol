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
from typing import Any


SOURCE_VERSION = "EMILIA-CONSEQUENCE-IMAGE-SOURCE-v1"
RELEASE_VERSION = "EMILIA-CONSEQUENCE-IMAGE-RELEASE-v1"
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
    "deploy/consequence-control-cloud-run/Dockerfile.consequence-actuator.release",
    "Dockerfile.consequence-control",
    "Dockerfile.gate",
    "apps/consequence-actuator-service/package-lock.json",
    "apps/consequence-control-service/package-lock.json",
    "apps/gate-service/package-lock.json",
)
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


def package_metadata(path: Path, expected_name: str) -> dict[str, str]:
    require_regular(path, f"{expected_name} tarball")
    if path.stat().st_size > 128 * 1024 * 1024:
        die(f"{expected_name} tarball is unexpectedly large")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or ".." in pure.parts:
                    die(f"{expected_name} tarball has an unsafe member path")
                if member.issym() or member.islnk() or member.isdev():
                    die(f"{expected_name} tarball has a link or device member")
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
        "name": expected_name,
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
        path = checked_path(root, relative, f"governed artifact {relative}")
        read_json(path, f"governed artifact {relative}")
        governed[relative] = sha256_file(path)
    inputs = {
        relative: sha256_file(checked_path(root, relative, f"build input {relative}"))
        for relative in BUILD_INPUTS
    }
    return {
        "@version": SOURCE_VERSION,
        "build_inputs": inputs,
        "governed_artifacts": governed,
        "packages": {
            "gate": package_metadata(gate_tarball, "@emilia-protocol/gate"),
            "require-receipt": package_metadata(
                require_receipt_tarball, "@emilia-protocol/require-receipt"
            ),
            "verify": package_metadata(verify_tarball, "@emilia-protocol/verify"),
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
        if sha256_file(checked_path(root, relative, relative)) != expected:
            die(f"governed artifact differs from source manifest: {relative}")
    for relative, expected in value["build_inputs"].items():
        if sha256_file(checked_path(root, relative, relative)) != expected:
            die(f"build input differs from source manifest: {relative}")
    expected_names = {
        "gate": "@emilia-protocol/gate",
        "require-receipt": "@emilia-protocol/require-receipt",
        "verify": "@emilia-protocol/verify",
    }
    for key, expected_name in expected_names.items():
        record = value["packages"][key]
        if not isinstance(record, dict) or set(record) != {"filename", "name", "sha256", "version"}:
            die(f"source manifest {key} package record is invalid")
        filename = record.get("filename")
        if not isinstance(filename, str) or PurePosixPath(filename).name != filename:
            die(f"source manifest {key} package filename is invalid")
        actual = package_metadata(artifact_dir / filename, expected_name)
        if actual != record:
            die(f"{key} tarball differs from source manifest")
    return value


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
        process = subprocess.Popen(
            ["git", "archive", "--format=tar", args.expected_commit, "--", *DOCKER_CONTEXT_PATHS],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or ".." in pure.parts:
                    die("Git archive contains an unsafe path")
                archive.extract(member, output, filter="data")
        _, stderr = process.communicate()
        if process.returncode != 0:
            die(f"Git archive failed: {stderr.decode('utf-8', 'replace').strip()}")
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

    context = commands.add_parser("context")
    context.add_argument("--root", type=Path, required=True)
    context.add_argument("--expected-commit", required=True)
    context.add_argument("--verify-tarball", type=Path, required=True)
    context.add_argument("--gate-tarball", type=Path, required=True)
    context.add_argument("--require-receipt-tarball", type=Path, required=True)
    context.add_argument("--output", type=Path, required=True)
    context.set_defaults(handler=command_context)

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
