#!/usr/bin/env python3
"""Publish or safely reuse commit-derived consequence-control images."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = DIGEST_RE
TAG_RE = re.compile(
    r"^[a-z0-9.-]+/[a-z0-9._/-]+:git-([0-9a-f]{40})$"
)
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


def publish_component(args, docker: str, gcloud: str, trust: Path, component: str, tag: str) -> str:
    match = TAG_RE.fullmatch(tag)
    if match is None or match.group(1) != args.expected_commit:
        fail(f"{component} tag is not derived from the reviewed commit")
    local_id = image_id(docker, tag)
    digest = describe(gcloud, tag)
    if digest is None:
        pushed = command([docker, "push", tag])
        if pushed.returncode != 0:
            fail(f"Docker push failed for {tag}: {pushed.stderr.strip()[:300]}")
        digest = retry(
            lambda: describe(gcloud, tag),
            args.retry_attempts,
            args.retry_delay_seconds,
            f"registry digest for {tag}",
        )
    return verify_remote(
        docker=docker,
        trust=trust,
        source_manifest=args.source_manifest.resolve(),
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
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--actuator-tag", required=True)
    parser.add_argument("--decision-tag", required=True)
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
        actuator = publish_component(args, docker, gcloud, trust, "actuator", args.actuator_tag)
        decision = publish_component(args, docker, gcloud, trust, "decision", args.decision_tag)
        output = args.output_dir.resolve()
        output.mkdir(parents=True, mode=0o700, exist_ok=False)
        release = output / "release-manifest.json"
        derived = output / "deploy.env"
        created = command([
            str(trust), "release", "--source-manifest", str(args.source_manifest.resolve()),
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
            "--source-manifest", str(args.source_manifest.resolve()),
            "--release-manifest", str(release), "--artifact-dir", str(args.artifact_dir.resolve()),
            "--expected-commit", args.expected_commit, "--config", str(derived),
        ])
        if verified.returncode != 0:
            fail(verified.stderr.strip())
        source = json.loads(args.source_manifest.read_text(encoding="utf-8"))
        values = {
            "actuator_name": actuator.rsplit("@", 1)[0],
            "actuator_digest": actuator.rsplit("@", 1)[1],
            "actuator_image": actuator,
            "decision_name": decision.rsplit("@", 1)[0],
            "decision_digest": decision.rsplit("@", 1)[1],
            "decision_image": decision,
            "source_manifest": str(args.source_manifest.resolve()),
            "release_manifest": str(release),
            "verify_tarball": str(args.artifact_dir.resolve() / source["packages"]["verify"]["filename"]),
            "gate_tarball": str(args.artifact_dir.resolve() / source["packages"]["gate"]["filename"]),
            "require_receipt_tarball": str(args.artifact_dir.resolve() / source["packages"]["require-receipt"]["filename"]),
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
