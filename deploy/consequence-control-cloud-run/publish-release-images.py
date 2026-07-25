#!/usr/bin/env python3
"""Publish or safely reuse commit-derived consequence-control images."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = DIGEST_RE
TAG_RE = re.compile(
    r"^[a-z0-9.-]+/[a-z0-9._/-]+:git-([0-9a-f]{40})$"
)
REPOSITORY_RE = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
NOT_FOUND_RE = re.compile(r"not[_ ]found|not found|does not exist", re.IGNORECASE)


class PublishError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise PublishError(message)


def command(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, text=True, capture_output=True, check=False)


def require_tool(path: Path, label: str) -> str:
    resolved = path.resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        fail(f"{label} is not one executable file: {resolved}")
    return str(resolved)


def image_id(docker: str, reference: str) -> str:
    result = command([docker, "image", "inspect", reference, "--format", "{{.Id}}"])
    value = result.stdout.strip()
    if result.returncode != 0 or ID_RE.fullmatch(value) is None:
        fail(f"Docker could not prove one image ID for {reference}")
    return value


def digest_from_description(value: object) -> str:
    if not isinstance(value, dict):
        fail("registry description is not an object")
    candidates = [
        value.get("digest"),
        value.get("version"),
        (value.get("image_summary") or {}).get("digest")
        if isinstance(value.get("image_summary"), dict) else None,
        (value.get("imageSummary") or {}).get("digest")
        if isinstance(value.get("imageSummary"), dict) else None,
    ]
    digests = {candidate for candidate in candidates if isinstance(candidate, str)}
    if len(digests) != 1:
        fail("registry description does not contain exactly one digest")
    digest = digests.pop()
    if DIGEST_RE.fullmatch(digest) is None:
        fail("registry returned a noncanonical digest")
    return digest


def describe(gcloud: str, tag: str) -> str | None:
    result = command([gcloud, "artifacts", "docker", "images", "describe", tag, "--format=json"])
    if result.returncode != 0:
        if NOT_FOUND_RE.search(result.stderr):
            return None
        fail(f"registry lookup failed closed for {tag}: {result.stderr.strip()[:300]}")
    try:
        return digest_from_description(json.loads(result.stdout))
    except json.JSONDecodeError as error:
        fail(f"registry returned invalid JSON for {tag}: {error}")


def retry(function, attempts: int, delay: float, label: str):
    last_error: PublishError | None = None
    for attempt in range(attempts):
        try:
            value = function()
            if value is not None:
                return value
        except PublishError as error:
            last_error = error
        if attempt + 1 < attempts:
            time.sleep(delay)
    if last_error is not None:
        raise last_error
    fail(f"{label} did not converge after {attempts} attempts")


def verify_remote(
    *, docker: str, trust: Path, source_manifest: Path, component: str,
    tag: str, digest: str, local_id: str, attempts: int, delay: float,
) -> str:
    name = tag.rsplit(":", 1)[0]
    reference = f"{name}@{digest}"

    def pull() -> bool | None:
        result = command([docker, "pull", reference])
        return True if result.returncode == 0 else None

    retry(pull, attempts, delay, f"pull of {reference}")
    remote_id = image_id(docker, reference)
    if remote_id != local_id:
        fail(f"existing remote image content differs from reviewed local build: {tag}")
    with tempfile.TemporaryDirectory(prefix="emilia-remote-inspect-") as directory:
        inspect = command([docker, "image", "inspect", reference])
        if inspect.returncode != 0:
            fail(f"remote image inspection failed: {reference}")
        record = Path(directory) / "inspect.json"
        record.write_text(inspect.stdout, encoding="utf-8")
        verified = command([
            str(trust), "verify-inspect", "--source-manifest", str(source_manifest),
            "--inspect", str(record), "--component", component,
        ])
        if verified.returncode != 0:
            fail(f"remote image labels differ from governed manifest: {tag}: {verified.stderr.strip()}")
    return reference


def copy_regular(source: Path, destination: Path, label: str) -> None:
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
    )
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
        write_flags |= os.O_NOFOLLOW
    source_fd = os.open(source, read_flags)
    destination_fd = -1
    try:
        metadata = os.fstat(source_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"{label} must be one regular non-symlink file")
        destination_fd = os.open(destination, write_flags, 0o600)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)


def publish_component(
    args,
    docker: str,
    gcloud: str,
    trust: Path,
    component: str,
    source_tag: str,
    tag: str,
    source_manifest: Path,
) -> str:
    match = TAG_RE.fullmatch(tag)
    if match is None or match.group(1) != args.expected_commit:
        fail(f"{component} tag is not derived from the reviewed commit")
    local_id = image_id(docker, source_tag)
    tagged = command([docker, "tag", source_tag, tag])
    if tagged.returncode != 0 or image_id(docker, tag) != local_id:
        fail(f"Docker could not bind reviewed {component} image to immutable registry tag")
    digest = describe(gcloud, tag)
    if digest is None:
        pushed = command([docker, "push", tag])
        if pushed.returncode != 0:
            try:
                digest = retry(
                    lambda: describe(gcloud, tag),
                    args.retry_attempts,
                    args.retry_delay_seconds,
                    f"concurrent registry digest for {tag}",
                )
            except PublishError:
                fail(
                    f"Docker push failed and no immutable tag could be reconciled for "
                    f"{tag}: {pushed.stderr.strip()[:300]}"
                )
        else:
            digest = retry(
                lambda: describe(gcloud, tag),
                args.retry_attempts,
                args.retry_delay_seconds,
                f"registry digest for {tag}",
            )
    return verify_remote(
        docker=docker,
        trust=trust,
        source_manifest=source_manifest,
        component=component,
        tag=tag,
        digest=digest,
        local_id=local_id,
        attempts=args.retry_attempts,
        delay=args.retry_delay_seconds,
    )


def append_outputs(path: Path, values: dict[str, str]) -> None:
    if not path.is_file() or path.is_symlink():
        fail("GitHub output path must be one existing regular file")
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                fail(f"unsafe GitHub output value: {key}")
            handle.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--bundle-manifest", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--artifact-repository", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--docker-bin", type=Path, default=Path("/usr/bin/docker"))
    parser.add_argument("--gcloud-bin", type=Path, default=Path("/usr/bin/gcloud"))
    parser.add_argument("--retry-attempts", type=int, default=5)
    parser.add_argument("--retry-delay-seconds", type=float, default=2.0)
    args = parser.parse_args()
    try:
        if not 1 <= args.retry_attempts <= 10 or not 0 <= args.retry_delay_seconds <= 30:
            fail("retry bounds are invalid")
        docker = require_tool(args.docker_bin, "Docker CLI")
        gcloud = require_tool(args.gcloud_bin, "gcloud CLI")
        trust = Path(__file__).resolve().with_name("release-trust.py")
        if REPOSITORY_RE.fullmatch(args.artifact_repository) is None:
            fail("artifact repository is not a lowercase Google Cloud slug")
        bundle_dir = args.bundle_dir.resolve()
        bundle_manifest = args.bundle_manifest.resolve()
        verified_bundle = command([
            str(trust), "verify-bundle", "--root", str(args.root.resolve()),
            "--bundle-dir", str(bundle_dir), "--bundle-manifest", str(bundle_manifest),
            "--expected-commit", args.expected_commit,
        ])
        if verified_bundle.returncode != 0:
            fail(verified_bundle.stderr.strip())
        bundle = json.loads(bundle_manifest.read_text(encoding="utf-8"))
        source_manifest = bundle_dir / bundle["source"]["manifest"]
        coordinates = command([str(trust), "coordinates", "--config", str(args.config.resolve())])
        if coordinates.returncode != 0:
            fail(coordinates.stderr.strip())
        values = coordinates.stdout.splitlines()
        if len(values) != 3:
            fail("deployment coordinates are incomplete")
        project_id, region, _release_id = values
        registry_host = f"{region}-docker.pkg.dev"
        configured = command([gcloud, "auth", "configure-docker", registry_host, "--quiet"])
        if configured.returncode != 0:
            fail("gcloud could not configure Docker for the pinned registry")
        prefix = f"{registry_host}/{project_id}/{args.artifact_repository}"
        actuator_tag = f"{prefix}/consequence-actuator:git-{args.expected_commit}"
        decision_tag = f"{prefix}/consequence-control:git-{args.expected_commit}"
        actuator = publish_component(
            args,
            docker,
            gcloud,
            trust,
            "actuator",
            bundle["images"]["actuator"]["tag"],
            actuator_tag,
            source_manifest,
        )
        decision = publish_component(
            args,
            docker,
            gcloud,
            trust,
            "decision",
            bundle["images"]["decision"]["tag"],
            decision_tag,
            source_manifest,
        )
        reverified_bundle = command([
            str(trust), "verify-bundle", "--root", str(args.root.resolve()),
            "--bundle-dir", str(bundle_dir), "--bundle-manifest", str(bundle_manifest),
            "--expected-commit", args.expected_commit,
        ])
        if reverified_bundle.returncode != 0:
            fail("release bundle changed during protected publication")
        output = args.output_dir.resolve()
        output.mkdir(parents=True, mode=0o700, exist_ok=False)
        source = json.loads(source_manifest.read_text(encoding="utf-8"))
        bundled_source = output / "source-manifest.json"
        copy_regular(source_manifest, bundled_source, "source manifest")
        bundled_packages: dict[str, Path] = {}
        for key, label in (
            ("verify", "Verify package"),
            ("gate", "Gate package"),
            ("require-receipt", "require-receipt package"),
        ):
            filename = source["packages"][key]["filename"]
            package_source = bundle_dir / filename
            package_destination = output / filename
            copy_regular(package_source, package_destination, label)
            bundled_packages[key] = package_destination
        release = output / "release-manifest.json"
        derived = output / "deploy.env"
        created = command([
            str(trust), "release", "--source-manifest", str(bundled_source),
            "--actuator-image", actuator, "--decision-image", decision, "--output", str(release),
        ])
        if created.returncode != 0:
            fail(created.stderr.strip())
        derived_result = command([
            str(trust), "derive-config", "--config", str(args.config.resolve()),
            "--release-manifest", str(release), "--output", str(derived),
        ])
        if derived_result.returncode != 0:
            fail(derived_result.stderr.strip())
        verified = command([
            str(trust), "verify-release", "--root", str(args.root.resolve()),
            "--source-manifest", str(bundled_source),
            "--release-manifest", str(release), "--artifact-dir", str(output),
            "--expected-commit", args.expected_commit, "--config", str(derived),
        ])
        if verified.returncode != 0:
            fail(verified.stderr.strip())
        values = {
            "actuator_name": actuator.rsplit("@", 1)[0],
            "actuator_digest": actuator.rsplit("@", 1)[1],
            "actuator_image": actuator,
            "decision_name": decision.rsplit("@", 1)[0],
            "decision_digest": decision.rsplit("@", 1)[1],
            "decision_image": decision,
            "source_manifest": str(bundled_source),
            "release_manifest": str(release),
            "verify_tarball": str(bundled_packages["verify"]),
            "gate_tarball": str(bundled_packages["gate"]),
            "require_receipt_tarball": str(bundled_packages["require-receipt"]),
            "derived_config": str(derived),
            "derived_config_sha256": derived_result.stdout.strip(),
        }
        append_outputs(args.github_output.resolve(), values)
        print(json.dumps(values, sort_keys=True))
        return 0
    except (PublishError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release publish refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
