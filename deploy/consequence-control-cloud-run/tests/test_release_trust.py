from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest


LANE = Path(__file__).resolve().parents[1]
ROOT = LANE.parents[1]
TRUST = LANE / "release-trust.py"
PUBLISH = LANE / "publish-release-images.py"
SCHEMA_RECONCILE = ROOT / "scripts" / "schema-pr-candidate-reconcile.mjs"

GOVERNED = (
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

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
path = pathlib.Path(os.environ["FAKE_RELEASE_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    target = args[2]
    record = state["local"].get(target)
    if record is None:
        for tag, remote in state["remote"].items():
            if target == tag.rsplit(":", 1)[0] + "@" + remote["digest"]:
                record = remote
                break
    if record is None:
        raise SystemExit(1)
    if "--format" in args:
        print(record["id"])
    else:
        print(json.dumps([{"Id": record["id"], "Config": {"Labels": record["labels"]}}]))
elif args and args[0] == "push":
    tag = args[1]
    state["push_count"] += 1
    if tag not in state["pushed"]:
        state["pushed"].append(tag)
    if tag in state.get("push_race", []):
        import hashlib
        local = state["local"][tag]
        state["remote"][tag] = {
            "digest": "sha256:" + hashlib.sha256(tag.encode()).hexdigest(),
            "id": local["id"],
            "labels": local["labels"],
        }
        path.write_text(json.dumps(state))
        print("tag was created concurrently", file=sys.stderr)
        raise SystemExit(1)
    path.write_text(json.dumps(state))
elif args and args[0] == "tag":
    source, target = args[1:3]
    state["local"][target] = dict(state["local"][source])
    path.write_text(json.dumps(state))
elif args and args[0] == "pull":
    if state["pull_failures"] > 0:
        state["pull_failures"] -= 1
        path.write_text(json.dumps(state))
        print("temporary pull failure", file=sys.stderr)
        raise SystemExit(1)
    print(args[1])
else:
    print("unsupported fake docker: " + repr(args), file=sys.stderr)
    raise SystemExit(2)
'''

FAKE_GCLOUD = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, sys
path = pathlib.Path(os.environ["FAKE_RELEASE_STATE"])
state = json.loads(path.read_text())
if sys.argv[1:3] == ["auth", "configure-docker"]:
    raise SystemExit(0)
tag = sys.argv[sys.argv.index("describe") + 1]
remote = state["remote"].get(tag)
if remote is None and tag in state["pushed"]:
    if state["describe_failures"] > 0:
        state["describe_failures"] -= 1
        path.write_text(json.dumps(state))
        print("NOT_FOUND", file=sys.stderr)
        raise SystemExit(1)
    digest = "sha256:" + hashlib.sha256(tag.encode()).hexdigest()
    local = state["local"][tag]
    remote = {"digest": digest, "id": local["id"], "labels": local["labels"]}
    state["remote"][tag] = remote
    path.write_text(json.dumps(state))
if remote is None:
    print("NOT_FOUND", file=sys.stderr)
    raise SystemExit(1)
print(json.dumps({"image_summary": {"digest": remote["digest"]}}))
'''


def run(
    *arguments: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def package_tarball(path: Path, raw: bytes) -> None:
    metadata = tarfile.TarInfo("package/package.json")
    metadata.size = len(raw)
    metadata.mode = 0o644
    metadata.mtime = 0
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(metadata, io.BytesIO(raw))


def docker_image_archive(
    path: Path, images: list[tuple[str, dict[str, str]]]
) -> dict[str, str]:
    manifest = []
    image_ids: dict[str, str] = {}
    members: list[tuple[str, bytes]] = []
    for index, (tag, labels) in enumerate(images):
        config = docker_config_bytes(tag, labels)
        image_id = sha256(config)
        config_name = f"{image_id}.json"
        layer_name = f"layers/{index}-{image_id}/layer.tar"
        members.extend(((config_name, config), (layer_name, b"fixture-layer")))
        manifest.append(
            {"Config": config_name, "Layers": [layer_name], "RepoTags": [tag]}
        )
        image_ids[tag] = "sha256:" + image_id
    members.append(
        (
            "manifest.json",
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
        )
    )
    with tarfile.open(path, "w") as archive:
        for name, raw in members:
            metadata = tarfile.TarInfo(name)
            metadata.size = len(raw)
            metadata.mode = 0o600
            metadata.mtime = 0
            archive.addfile(metadata, io.BytesIO(raw))
    return image_ids


def docker_config_bytes(tag: str, labels: dict[str, str]) -> bytes:
    return json.dumps(
        {"config": {"Labels": labels}, "fixture_tag": tag},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


class ReleaseTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        for relative in GOVERNED:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"path": relative}) + "\n", encoding="utf-8")
        for relative in BUILD_INPUTS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"pinned input {relative}\n", encoding="utf-8")
        package_fixtures = {
            "packages/verify": ("@emilia-protocol/verify", "3.15.0"),
            "packages/gate": ("@emilia-protocol/gate", "0.16.0"),
            "packages/require-receipt": (
                "@emilia-protocol/require-receipt",
                "0.7.0",
            ),
        }
        self.package_bytes: dict[str, bytes] = {}
        for package_root, (name, version) in package_fixtures.items():
            raw = json.dumps(
                {
                    "name": name,
                    "version": version,
                    "scripts": {
                        "prepack": "node -e \"require('fs').writeFileSync(process.env.HOSTILE_MARKER,'prepack')\"",
                        "postpack": "node -e \"require('fs').writeFileSync(process.env.HOSTILE_MARKER,'postpack')\"",
                    },
                }
            ).encode()
            package_json = self.root / package_root / "package.json"
            package_json.parent.mkdir(parents=True, exist_ok=True)
            package_json.write_bytes(raw)
            self.package_bytes[package_root] = raw
        (self.root / ".dockerignore").write_text(".git\n", encoding="utf-8")
        (self.root / "caid").mkdir()
        (self.root / "caid" / "README.md").write_text("fixture\n", encoding="utf-8")
        lane = self.root / "deploy" / "consequence-control-cloud-run"
        (lane / "lib").mkdir(parents=True, exist_ok=True)
        for relative in ("deploy.sh", "release-trust.py"):
            shutil.copy2(LANE / relative, lane / relative)
        shutil.copy2(LANE / "lib" / "common.sh", lane / "lib" / "common.sh")
        run("git", "init", "-q", cwd=self.root)
        run("git", "config", "user.name", "Release Test", cwd=self.root)
        run("git", "config", "user.email", "release@example.test", cwd=self.root)
        run("git", "add", ".", cwd=self.root)
        committed = run("git", "commit", "-qm", "fixture", cwd=self.root)
        self.assertEqual(committed.returncode, 0, committed.stderr)
        self.commit = run("git", "rev-parse", "HEAD", cwd=self.root).stdout.strip()
        self.artifacts = Path(self.temporary.name) / "artifacts"
        self.artifacts.mkdir()
        self.verify_tarball = self.artifacts / "emilia-protocol-verify-3.15.0.tgz"
        self.gate_tarball = self.artifacts / "emilia-protocol-gate-0.16.0.tgz"
        self.require_tarball = self.artifacts / "emilia-protocol-require-receipt-0.7.0.tgz"
        package_tarball(self.verify_tarball, self.package_bytes["packages/verify"])
        package_tarball(self.gate_tarball, self.package_bytes["packages/gate"])
        package_tarball(self.require_tarball, self.package_bytes["packages/require-receipt"])
        self.source = self.artifacts / "source-manifest.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_source(self) -> subprocess.CompletedProcess[str]:
        return run(
            str(TRUST),
            "source",
            "--root",
            str(self.root),
            "--expected-commit",
            self.commit,
            "--verify-tarball",
            str(self.verify_tarball),
            "--gate-tarball",
            str(self.gate_tarball),
            "--require-receipt-tarball",
            str(self.require_tarball),
            "--output",
            str(self.source),
        )

    def test_source_labels_release_and_derived_config_are_one_closed_chain(self) -> None:
        created = self.create_source()
        self.assertEqual(created.returncode, 0, created.stderr)
        labels_result = run(
            str(TRUST), "labels", "--source-manifest", str(self.source)
        )
        self.assertEqual(labels_result.returncode, 0, labels_result.stderr)
        labels = dict(line.split("=", 1) for line in labels_result.stdout.splitlines())
        self.assertEqual(labels["org.opencontainers.image.revision"], self.commit)
        self.assertEqual(
            labels["io.emilia.source.manifest.sha256"],
            sha256(self.source.read_bytes()),
        )

        inspect = self.artifacts / "inspect.json"
        inspect.write_text(
            json.dumps([{"Config": {"Labels": {**labels, "io.emilia.image.component": "decision"}}}]),
            encoding="utf-8",
        )
        inspected = run(
            str(TRUST),
            "verify-inspect",
            "--source-manifest",
            str(self.source),
            "--inspect",
            str(inspect),
            "--component",
            "decision",
        )
        self.assertEqual(inspected.returncode, 0, inspected.stderr)

        actuator = "us-central1-docker.pkg.dev/test-project/runtime/actuator@sha256:" + "a" * 64
        decision = "us-central1-docker.pkg.dev/test-project/runtime/decision@sha256:" + "b" * 64
        release = self.artifacts / "release-manifest.json"
        released = run(
            str(TRUST),
            "release",
            "--source-manifest",
            str(self.source),
            "--actuator-image",
            actuator,
            "--decision-image",
            decision,
            "--output",
            str(release),
        )
        self.assertEqual(released.returncode, 0, released.stderr)
        config = self.artifacts / "base.env"
        config.write_text(
            "PROJECT_ID=test-project\nREGION=us-central1\nRELEASE_ID=r1\n",
            encoding="utf-8",
        )
        derived = self.artifacts / "derived.env"
        derivation = run(
            str(TRUST),
            "derive-config",
            "--config",
            str(config),
            "--release-manifest",
            str(release),
            "--output",
            str(derived),
        )
        self.assertEqual(derivation.returncode, 0, derivation.stderr)
        accepted = run(
            str(TRUST),
            "verify-release",
            "--root",
            str(self.root),
            "--source-manifest",
            str(self.source),
            "--release-manifest",
            str(release),
            "--artifact-dir",
            str(self.artifacts),
            "--expected-commit",
            self.commit,
            "--config",
            str(derived),
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

    def test_dirty_reviewed_checkout_is_refused(self) -> None:
        (self.root / GOVERNED[0]).write_text("{}\n", encoding="utf-8")
        result = self.create_source()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("working tree differs", result.stderr)

    def test_nested_untracked_and_symlinked_build_inputs_are_refused(self) -> None:
        package_root = self.root / "packages" / "gate"
        package_root.mkdir(parents=True, exist_ok=True)
        for hostile in (package_root / "nested" / "payload.js", package_root / "escape.js"):
            with self.subTest(path=hostile.name):
                if hostile.name == "payload.js":
                    hostile.parent.mkdir(parents=True)
                    hostile.write_text("unreviewed\n", encoding="utf-8")
                else:
                    hostile.symlink_to("/tmp/unreviewed-release-input")
                result = self.create_source()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("untracked build input", result.stderr)
                if hostile.is_symlink():
                    hostile.unlink()
                else:
                    hostile.unlink()

    def test_docker_context_contains_tarballs_but_no_checkout_package_directories(self) -> None:
        context = Path(self.temporary.name) / "context"
        result = run(
            str(TRUST),
            "context",
            "--root",
            str(self.root),
            "--expected-commit",
            self.commit,
            "--verify-tarball",
            str(self.verify_tarball),
            "--gate-tarball",
            str(self.gate_tarball),
            "--require-receipt-tarball",
            str(self.require_tarball),
            "--output",
            str(context),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((context / "packages" / "gate").exists())
        self.assertFalse((context / "packages" / "verify").exists())
        self.assertFalse((context / "packages" / "require-receipt").exists())
        self.assertEqual(
            (context / "release-packages" / "gate.tgz").read_bytes(),
            self.gate_tarball.read_bytes(),
        )

    def test_package_substitution_is_refused_at_deploy_verification(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        package_tarball(
            self.verify_tarball,
            json.dumps({"name": "@emilia-protocol/verify", "version": "9.9.9"}).encode(),
        )
        result = run(
            str(TRUST),
            "verify-release",
            "--root",
            str(self.root),
            "--source-manifest",
            str(self.source),
            "--release-manifest",
            str(self.artifacts / "missing-release.json"),
            "--artifact-dir",
            str(self.artifacts),
            "--expected-commit",
            self.commit,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from reviewed Git blob", result.stderr)

    def test_git_archive_pack_disables_prepack_and_postpack_mutation(self) -> None:
        marker = self.artifacts / "lifecycle-hook-ran"
        output = self.artifacts / "packed"
        output.mkdir()
        original = (self.root / "packages/verify/package.json").read_bytes()
        result = run(
            str(TRUST),
            "pack-package",
            "--root",
            str(self.root),
            "--expected-commit",
            self.commit,
            "--package",
            "verify",
            "--output-dir",
            str(output),
            env={**os.environ, "HOSTILE_MARKER": str(marker)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists(), "prepack/postpack hooks must never execute")
        self.assertEqual(
            (self.root / "packages/verify/package.json").read_bytes(), original
        )
        self.assertIn("emilia-protocol-verify-3.15.0.tgz", result.stdout)

    def test_bundle_verification_refuses_package_and_image_artifact_swaps(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        labels_result = run(str(TRUST), "labels", "--source-manifest", str(self.source))
        labels = dict(line.split("=", 1) for line in labels_result.stdout.splitlines())
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-control:git-" + self.commit
        state = self.artifacts / "swap-state.json"
        state.write_text(json.dumps({
            "local": {
                actuator_tag: {"id": "sha256:" + "1" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                decision_tag: {"id": "sha256:" + "2" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
            },
            "remote": {}, "pushed": [], "push_count": 0,
            "describe_failures": 0, "pull_failures": 0,
        }))
        environment = {**os.environ, "FAKE_RELEASE_STATE": str(state)}
        for target in ("verify-package", "actuator-image"):
            with self.subTest(target=target):
                bundle = self._make_publish_bundle(
                    actuator_tag,
                    decision_tag,
                    self.artifacts / f"swap-{target}",
                    environment,
                )
                if target == "verify-package":
                    source = json.loads((bundle / "source-manifest.json").read_text())
                    path = bundle / source["packages"]["verify"]["filename"]
                else:
                    path = bundle / "actuator-image.tar"
                path.chmod(0o600)
                path.write_bytes(path.read_bytes() + b"hostile swap")
                refused = run(
                    str(TRUST), "verify-bundle", "--root", str(self.root),
                    "--bundle-dir", str(bundle),
                    "--bundle-manifest", str(bundle / "bundle-manifest.json"),
                    "--expected-commit", self.commit,
                )
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("differs from manifest", refused.stderr)

    def test_crafted_dual_image_archive_is_refused_even_when_resealed(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        labels_result = run(str(TRUST), "labels", "--source-manifest", str(self.source))
        labels = dict(line.split("=", 1) for line in labels_result.stdout.splitlines())
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-control:git-" + self.commit
        state = self.artifacts / "dual-archive-state.json"
        state.write_text(json.dumps({
            "local": {
                actuator_tag: {"id": "sha256:" + "1" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                decision_tag: {"id": "sha256:" + "2" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
            },
            "remote": {}, "pushed": [], "push_count": 0,
            "describe_failures": 0, "pull_failures": 0,
        }))
        environment = {**os.environ, "FAKE_RELEASE_STATE": str(state)}
        bundle = self._make_publish_bundle(
            actuator_tag, decision_tag, self.artifacts / "dual-image-bundle", environment
        )
        manifest_path = bundle / "bundle-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        actuator = manifest["images"]["actuator"]
        decision = manifest["images"]["decision"]
        docker_image_archive(
            bundle / decision["archive"],
            [
                (decision["tag"], {**labels, "io.emilia.image.component": "decision"}),
                (actuator["tag"], {**labels, "io.emilia.image.component": "actuator"}),
            ],
        )
        archive = bundle / decision["archive"]
        manifest["artifacts"][archive.name] = {
            "sha256": sha256(archive.read_bytes()),
            "size": archive.stat().st_size,
        }
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")

        refused = run(
            str(TRUST), "verify-bundle", "--root", str(self.root),
            "--bundle-dir", str(bundle), "--bundle-manifest", str(manifest_path),
            "--expected-commit", self.commit,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("exactly one image", refused.stderr)

    def test_loader_rechecks_both_sealed_ids_after_all_archives_load(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        labels_result = run(str(TRUST), "labels", "--source-manifest", str(self.source))
        labels = dict(line.split("=", 1) for line in labels_result.stdout.splitlines())
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-control:git-" + self.commit
        state = self.artifacts / "load-pair-state.json"
        state.write_text(json.dumps({
            "local": {
                actuator_tag: {"id": "sha256:" + "1" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                decision_tag: {"id": "sha256:" + "2" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
            },
            "remote": {}, "pushed": [], "push_count": 0,
            "describe_failures": 0, "pull_failures": 0,
        }))
        environment = {**os.environ, "FAKE_RELEASE_STATE": str(state)}
        bundle = self._make_publish_bundle(
            actuator_tag, decision_tag, self.artifacts / "load-pair-bundle", environment
        )
        manifest = json.loads((bundle / "bundle-manifest.json").read_text())
        load_state = self.artifacts / "hostile-load-state.json"
        load_state.write_text(json.dumps({
            "local": {},
            "actuator_tag": manifest["images"]["actuator"]["tag"],
            "decision_tag": manifest["images"]["decision"]["tag"],
            "images": {
                component: {
                    "id": manifest["images"][component]["id"],
                    "labels": {**labels, "io.emilia.image.component": component},
                }
                for component in ("actuator", "decision")
            },
        }))
        docker = self.artifacts / "hostile-load-docker.py"
        docker.write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, sys
path = pathlib.Path(os.environ["HOSTILE_LOAD_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
if args[:2] == ["load", "--input"]:
    component = "actuator" if pathlib.Path(args[2]).name.startswith("actuator") else "decision"
    tag = state[f"{component}_tag"]
    state["local"][tag] = dict(state["images"][component])
    if component == "decision":
        state["local"][state["actuator_tag"]] = {
            "id": state["images"]["decision"]["id"],
            "labels": state["images"]["actuator"]["labels"],
        }
    path.write_text(json.dumps(state))
    print("Loaded image: " + tag)
elif args[:2] == ["image", "inspect"]:
    record = state["local"].get(args[2])
    if record is None:
        raise SystemExit(1)
    print(json.dumps([{"Id": record["id"], "Config": {"Labels": record["labels"]}}]))
else:
    raise SystemExit(2)
''', encoding="utf-8")
        docker.chmod(0o755)
        refused = run(
            str(TRUST), "load-bundle", "--root", str(self.root),
            "--bundle-dir", str(bundle),
            "--bundle-manifest", str(bundle / "bundle-manifest.json"),
            "--expected-commit", self.commit, "--docker-bin", str(docker),
            env={**os.environ, "HOSTILE_LOAD_STATE": str(load_state)},
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("differ from the sealed pair", refused.stderr)

    def test_publisher_compares_both_loaded_ids_to_the_sealed_pair(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        labels_result = run(str(TRUST), "labels", "--source-manifest", str(self.source))
        labels = dict(line.split("=", 1) for line in labels_result.stdout.splitlines())
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-control:git-" + self.commit
        state = self.artifacts / "publisher-pair-state.json"
        state.write_text(json.dumps({
            "local": {
                actuator_tag: {"id": "sha256:" + "1" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                decision_tag: {"id": "sha256:" + "2" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
            },
            "remote": {}, "pushed": [], "push_count": 0,
            "describe_failures": 0, "pull_failures": 0,
        }))
        environment = {**os.environ, "FAKE_RELEASE_STATE": str(state)}
        bundle = self._make_publish_bundle(
            actuator_tag, decision_tag, self.artifacts / "publisher-pair-bundle", environment
        )
        manifest = json.loads((bundle / "bundle-manifest.json").read_text())
        current = json.loads(state.read_text())
        current["local"][manifest["images"]["actuator"]["tag"]]["id"] = "sha256:" + "9" * 64
        state.write_text(json.dumps(current))
        docker, gcloud = self._fake_registry_tools(state)
        config = self.artifacts / "publisher-pair.env"
        config.write_text("PROJECT_ID=test-project\nREGION=us-central1\nRELEASE_ID=r1\n")
        github_output = self.artifacts / "publisher-pair.outputs"
        github_output.write_text("")
        refused = run(
            str(PUBLISH), "--root", str(self.root), "--bundle-dir", str(bundle),
            "--bundle-manifest", str(bundle / "bundle-manifest.json"),
            "--expected-commit", self.commit, "--config", str(config),
            "--artifact-repository", "runtime", "--output-dir", str(self.artifacts / "publisher-pair-output"),
            "--github-output", str(github_output), "--docker-bin", str(docker),
            "--gcloud-bin", str(gcloud), "--retry-delay-seconds", "0", env=environment,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("differ from the sealed pair", refused.stderr)

    def test_secret_config_cannot_choose_candidate_images(self) -> None:
        config = self.artifacts / "hostile.env"
        config.write_text(
            "PROJECT_ID=test-project\nREGION=us-central1\nRELEASE_ID=r1\n"
            "ACTUATOR_IMAGE=us-central1-docker.pkg.dev/test/runtime/a@sha256:" + "a" * 64 + "\n",
            encoding="utf-8",
        )
        result = run(str(TRUST), "coordinates", "--config", str(config))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not choose", result.stderr)

    def test_publish_path_retries_then_reuses_only_exact_remote_images(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        labels_result = run(str(TRUST), "labels", "--source-manifest", str(self.source))
        labels = dict(line.split("=", 1) for line in labels_result.stdout.splitlines())
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-control:git-" + self.commit
        state = self.artifacts / "fake-state.json"
        state.write_text(
            json.dumps(
                {
                    "local": {
                        actuator_tag: {"id": "sha256:" + "1" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                        decision_tag: {"id": "sha256:" + "2" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
                    },
                    "remote": {},
                    "pushed": [],
                    "push_count": 0,
                    "describe_failures": 1,
                    "pull_failures": 1,
                }
            ),
            encoding="utf-8",
        )
        docker, gcloud = self._fake_registry_tools(state)
        config = self.artifacts / "candidate.env"
        config.write_text("PROJECT_ID=test-project\nREGION=us-central1\nRELEASE_ID=r1\n")
        environment = {**os.environ, "FAKE_RELEASE_STATE": str(state)}

        first = self._publish(
            actuator_tag, decision_tag, config, docker, gcloud, self.artifacts / "release-one", environment
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        first_state = json.loads(state.read_text())
        self.assertEqual(first_state["push_count"], 2)
        derived = (self.artifacts / "release-one" / "deploy.env").read_text()
        self.assertIn(
            "ACTUATOR_IMAGE=us-central1-docker.pkg.dev/test-project/runtime/"
            "consequence-actuator@sha256:",
            derived,
        )

        second = self._publish(
            actuator_tag, decision_tag, config, docker, gcloud, self.artifacts / "release-two", environment
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(state.read_text())["push_count"], 2)
        self.assertEqual(
            (self.artifacts / "release-one" / "release-manifest.json").read_bytes(),
            (self.artifacts / "release-two" / "release-manifest.json").read_bytes(),
        )

    def test_publish_path_refuses_existing_tag_with_different_content(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        labels_result = run(str(TRUST), "labels", "--source-manifest", str(self.source))
        labels = dict(line.split("=", 1) for line in labels_result.stdout.splitlines())
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-control:git-" + self.commit
        decision_digest = "sha256:" + "b" * 64
        source_decision_tag = "emilia-consequence-control:git-" + self.commit
        source_decision_id = "sha256:" + sha256(
            docker_config_bytes(
                source_decision_tag,
                {**labels, "io.emilia.image.component": "decision"},
            )
        )
        state = self.artifacts / "fake-state-mismatch.json"
        state.write_text(json.dumps({
            "local": {
                actuator_tag: {"id": "sha256:" + "1" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                decision_tag: {"id": "sha256:" + "2" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
            },
            "remote": {
                decision_tag: {
                    "digest": decision_digest,
                    "id": source_decision_id,
                    "labels": {**labels, "io.emilia.image.component": "actuator"},
                }
            },
            "pushed": [], "push_count": 0, "describe_failures": 0, "pull_failures": 0,
        }), encoding="utf-8")
        docker, gcloud = self._fake_registry_tools(state)
        config = self.artifacts / "candidate-mismatch.env"
        config.write_text("PROJECT_ID=test-project\nREGION=us-central1\nRELEASE_ID=r1\n")
        result = self._publish(
            actuator_tag,
            decision_tag,
            config,
            docker,
            gcloud,
            self.artifacts / "release-mismatch",
            {**os.environ, "FAKE_RELEASE_STATE": str(state)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("labels differ", result.stderr)

    def test_cold_rebuild_refuses_remote_with_different_image_content(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        labels_result = run(str(TRUST), "labels", "--source-manifest", str(self.source))
        labels = dict(line.split("=", 1) for line in labels_result.stdout.splitlines())
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-control:git-" + self.commit
        state = self.artifacts / "fake-state-cold-rebuild.json"
        state.write_text(json.dumps({
            "local": {
                actuator_tag: {"id": "sha256:" + "1" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                decision_tag: {"id": "sha256:" + "2" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
            },
            "remote": {
                actuator_tag: {"digest": "sha256:" + "a" * 64, "id": "sha256:" + "7" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                decision_tag: {"digest": "sha256:" + "b" * 64, "id": "sha256:" + "8" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
            },
            "pushed": [], "push_count": 0, "describe_failures": 0,
            "pull_failures": 0, "push_race": [],
        }), encoding="utf-8")
        docker, gcloud = self._fake_registry_tools(state)
        config = self.artifacts / "candidate-cold.env"
        config.write_text("PROJECT_ID=test-project\nREGION=us-central1\nRELEASE_ID=r1\n")
        result = self._publish(
            actuator_tag, decision_tag, config, docker, gcloud,
            self.artifacts / "release-cold",
            {**os.environ, "FAKE_RELEASE_STATE": str(state)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("content differs", result.stderr)
        self.assertEqual(json.loads(state.read_text())["push_count"], 0)

    def test_failed_push_accepts_only_exact_concurrently_created_tag(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        labels_result = run(str(TRUST), "labels", "--source-manifest", str(self.source))
        labels = dict(line.split("=", 1) for line in labels_result.stdout.splitlines())
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/consequence-control:git-" + self.commit
        state = self.artifacts / "fake-state-race.json"
        state.write_text(json.dumps({
            "local": {
                actuator_tag: {"id": "sha256:" + "1" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                decision_tag: {"id": "sha256:" + "2" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
            },
            "remote": {}, "pushed": [], "push_count": 0,
            "describe_failures": 0, "pull_failures": 0,
            "push_race": [actuator_tag],
        }), encoding="utf-8")
        docker, gcloud = self._fake_registry_tools(state)
        config = self.artifacts / "candidate-race.env"
        config.write_text("PROJECT_ID=test-project\nREGION=us-central1\nRELEASE_ID=r1\n")
        result = self._publish(
            actuator_tag, decision_tag, config, docker, gcloud,
            self.artifacts / "release-race",
            {**os.environ, "FAKE_RELEASE_STATE": str(state)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        final = json.loads(state.read_text())
        self.assertEqual(final["push_count"], 2)
        self.assertIn(actuator_tag, final["remote"])

    def test_protected_deploy_preflight_accepts_same_directory_chain_without_cloud(self) -> None:
        self.assertEqual(self.create_source().returncode, 0)
        actuator = "us-central1-docker.pkg.dev/test-project/runtime/actuator@sha256:" + "a" * 64
        decision = "us-central1-docker.pkg.dev/test-project/runtime/decision@sha256:" + "b" * 64
        release = self.artifacts / "release-manifest.json"
        released = run(
            str(TRUST), "release", "--source-manifest", str(self.source),
            "--actuator-image", actuator, "--decision-image", decision,
            "--output", str(release),
        )
        self.assertEqual(released.returncode, 0, released.stderr)
        base = self.artifacts / "base-deploy.env"
        fixture = (LANE / "tests" / "fixture.env").read_text(encoding="utf-8")
        base.write_text("\n".join(
            line for line in fixture.splitlines()
            if not line.startswith(("ACTUATOR_IMAGE=", "DECISION_IMAGE="))
        ) + "\n", encoding="utf-8")
        derived = self.artifacts / "deploy.env"
        derivation = run(
            str(TRUST), "derive-config", "--config", str(base),
            "--release-manifest", str(release), "--output", str(derived),
        )
        self.assertEqual(derivation.returncode, 0, derivation.stderr)
        marker = self.artifacts / "gcloud-called"
        fake_bin = self.artifacts / "bin"
        fake_bin.mkdir()
        gcloud = fake_bin / "gcloud"
        gcloud.write_text(
            "#!/usr/bin/env bash\nprintf called > \"$GCLOUD_MARKER\"\nexit 99\n",
            encoding="utf-8",
        )
        gcloud.chmod(0o755)
        environment = {
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "GCLOUD_MARKER": str(marker),
            "DEPLOYMENT_CONFIG_SHA256": sha256(derived.read_bytes()),
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "emiliaprotocol/emilia-protocol",
            "GITHUB_REPOSITORY_ID": "123",
            "GITHUB_REPOSITORY_OWNER_ID": "456",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": self.commit,
            "GITHUB_WORKFLOW_REF": "emiliaprotocol/emilia-protocol/.github/workflows/consequence-control-deploy.yml@refs/heads/main",
            "EMILIA_GITHUB_WORKFLOW_SHA": self.commit,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-token",
            "GOOGLE_GHA_CREDS_PATH": "/tmp/nonexistent-preflight-creds.json",
            "EMILIA_DEPLOY_ENVIRONMENT": "consequence-control-production",
            "EMILIA_DEPLOY_WIF_PROVIDER": "projects/123/locations/global/workloadIdentityPools/testpool/providers/testprovider",
        }
        result = run(
            str(self.root / "deploy" / "consequence-control-cloud-run" / "deploy.sh"),
            "--config", str(derived), "--verify-release-preflight",
            "--source-manifest", str(self.source),
            "--release-manifest", str(release), env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("release preflight accepted", result.stdout)
        self.assertFalse(marker.exists(), "preflight must exit before invoking gcloud")

    def _make_publish_bundle(self, actuator, decision, bundle, environment):
        bundle.mkdir()
        shutil.copy2(self.source, bundle / "source-manifest.json")
        source = json.loads(self.source.read_text())
        for record in source["packages"].values():
            shutil.copy2(self.artifacts / record["filename"], bundle / record["filename"])
        source_tags = {
            "actuator": "emilia-consequence-actuator:git-" + self.commit,
            "decision": "emilia-consequence-control:git-" + self.commit,
        }
        state_path = Path(environment["FAKE_RELEASE_STATE"])
        state = json.loads(state_path.read_text())
        for component, remote_tag in (("actuator", actuator), ("decision", decision)):
            labels = state["local"][remote_tag]["labels"]
            archive_ids = docker_image_archive(
                bundle / f"{component}-image.tar",
                [(source_tags[component], labels)],
            )
            record = {
                "id": archive_ids[source_tags[component]],
                "labels": labels,
            }
            state["local"][source_tags[component]] = record
            (bundle / f"inspect-{component}.json").write_text(
                json.dumps([{"Id": record["id"], "Config": {"Labels": record["labels"]}}]),
                encoding="utf-8",
            )
        state_path.write_text(json.dumps(state))
        bundled = run(
            str(TRUST), "bundle", "--root", str(self.root),
            "--bundle-dir", str(bundle),
            "--source-manifest", str(bundle / "source-manifest.json"),
            "--expected-commit", self.commit,
            "--actuator-archive", str(bundle / "actuator-image.tar"),
            "--actuator-inspect", str(bundle / "inspect-actuator.json"),
            "--actuator-tag", source_tags["actuator"],
            "--decision-archive", str(bundle / "decision-image.tar"),
            "--decision-inspect", str(bundle / "inspect-decision.json"),
            "--decision-tag", source_tags["decision"],
            "--output", str(bundle / "bundle-manifest.json"),
        )
        self.assertEqual(bundled.returncode, 0, bundled.stderr)
        return bundle

    def _publish(self, actuator, decision, config, docker, gcloud, output, environment):
        bundle = self._make_publish_bundle(
            actuator, decision, output.parent / (output.name + "-bundle"), environment
        )
        github_output = output.parent / (output.name + ".outputs")
        github_output.write_text("")
        return run(
            str(PUBLISH), "--root", str(self.root), "--bundle-dir", str(bundle),
            "--bundle-manifest", str(bundle / "bundle-manifest.json"),
            "--expected-commit", self.commit, "--config", str(config),
            "--artifact-repository", "runtime",
            "--output-dir", str(output), "--github-output", str(github_output),
            "--docker-bin", str(docker), "--gcloud-bin", str(gcloud),
            "--retry-delay-seconds", "0", env=environment,
        )

    def _fake_registry_tools(self, state: Path) -> tuple[Path, Path]:
        docker = self.artifacts / "fake-docker.py"
        gcloud = self.artifacts / "fake-gcloud.py"
        docker.write_text(FAKE_DOCKER, encoding="utf-8")
        gcloud.write_text(FAKE_GCLOUD, encoding="utf-8")
        docker.chmod(0o755)
        gcloud.chmod(0o755)
        return docker, gcloud


class SchemaCandidateReconciliationTests(unittest.TestCase):
    def migration(self, root: Path, name: str, raw: bytes) -> None:
        path = root / "supabase" / "migrations" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def ledger(
        self,
        root: Path,
        files: dict[str, bytes],
        pending: list[str],
        *,
        remote: list[str] | None = None,
        private_remote: list[str] | None = None,
        extra_public: dict[str, str] | None = None,
    ) -> None:
        remote = remote or ["001"]
        private_remote = private_remote or []
        path = root / "supabase" / "migration-history.v1.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        public_files = {name: sha256(raw) for name, raw in files.items()}
        public_files.update(extra_public or {})
        path.write_text(
            json.dumps(
                {
                    "schema_version": "EP-MIGRATION-HISTORY-v1",
                    "as_of": "2026-07-25",
                    "remote_head": remote[-1],
                    "remote_versions": remote,
                    "private_remote_versions": private_remote,
                    "retroactive_pending_versions": [],
                    "forward_pending_versions": pending,
                    "deployment_sequence": sorted(pending),
                    "requires_include_all": False,
                    "public_files": public_files,
                }
            ),
            encoding="utf-8",
        )
        archive = root / "supabase" / "migration-archive" / "2026-07-25-history-reconciliation"
        archive.mkdir(parents=True, exist_ok=True)
        (archive / "README.md").write_text("fixture\n", encoding="utf-8")
        (archive / "SHA256SUMS").write_text("", encoding="utf-8")

    def test_candidate_preserves_base_and_classifies_addition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "base"
            candidate = Path(directory) / "candidate"
            old = {"001_base.sql": b"select 1;\n"}
            new = {**old, "20260101000000_new.sql": b"select 2;\n"}
            for name, raw in old.items():
                self.migration(base, name, raw)
            for name, raw in new.items():
                self.migration(candidate, name, raw)
            self.ledger(candidate, new, ["20260101000000"])
            result = run(
                "node",
                str(SCHEMA_RECONCILE),
                "--base-root",
                str(base),
                "--candidate-root",
                str(candidate),
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 classified additions", result.stdout)

    def test_candidate_rewrite_and_unclassified_addition_are_refused(self) -> None:
        for rewrite, pending, expected in (
            (True, ["20260101000000"], "rewrites base migration"),
            (False, [], "not classified as pending"),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "base"
                candidate = Path(directory) / "candidate"
                old = {"001_base.sql": b"select 1;\n"}
                new = {
                    "001_base.sql": b"select 9;\n" if rewrite else old["001_base.sql"],
                    "20260101000000_new.sql": b"select 2;\n",
                }
                for name, raw in old.items():
                    self.migration(base, name, raw)
                for name, raw in new.items():
                    self.migration(candidate, name, raw)
                self.ledger(candidate, new, pending)
                result = run(
                    "node",
                    str(SCHEMA_RECONCILE),
                    "--base-root",
                    str(base),
                    "--candidate-root",
                    str(candidate),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)

    def test_candidate_rejects_ghost_pending_and_public_file_entries(self) -> None:
        cases = (
            ("ghost pending", ["20260101000000"], {}, None, "executable migration versions"),
            ("ghost public file", [], {}, {"999_ghost.sql": "0" * 64}, "public_files must cover"),
        )
        for label, pending, additions, extra_public, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "base"
                candidate = Path(directory) / "candidate"
                files = {"001_base.sql": b"select 1;\n", **additions}
                self.migration(base, "001_base.sql", files["001_base.sql"])
                for name, raw in files.items():
                    self.migration(candidate, name, raw)
                self.ledger(candidate, files, pending, extra_public=extra_public)
                result = run(
                    "node", str(SCHEMA_RECONCILE), "--base-root", str(base),
                    "--candidate-root", str(candidate),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)

    def test_candidate_rejects_incomplete_remote_private_history_relationships(self) -> None:
        cases = (
            ("remote without public SQL", ["001", "002"], [], "executable migration versions"),
            ("private absent from remote", ["001"], ["002"], "not journaled remotely"),
            ("pending overlaps remote", ["001", "20260101000000"], [], "already journaled remotely"),
        )
        for label, remote, private_remote, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "base"
                candidate = Path(directory) / "candidate"
                files = {"001_base.sql": b"select 1;\n"}
                pending = ["20260101000000"] if label == "pending overlaps remote" else []
                self.migration(base, "001_base.sql", files["001_base.sql"])
                self.migration(candidate, "001_base.sql", files["001_base.sql"])
                self.ledger(
                    candidate, files, pending, remote=remote,
                    private_remote=private_remote,
                )
                result = run(
                    "node", str(SCHEMA_RECONCILE), "--base-root", str(base),
                    "--candidate-root", str(candidate),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)


class WorkflowTrustContractTests(unittest.TestCase):
    def test_deploy_workflow_builds_and_attests_instead_of_accepting_image_secrets(self) -> None:
        workflow = (ROOT / ".github/workflows/consequence-control-deploy.yml").read_text()
        self.assertIn("build-release-images.sh", workflow)
        self.assertIn("--expected-commit \"$GITHUB_SHA\"", workflow)
        self.assertIn("Attest the exact approved trusted-executor request", workflow)
        self.assertIn("GCP_CONSEQUENCE_CONTROL_TRUSTED_EXECUTOR_IMAGE", workflow)
        self.assertIn("--bundle-manifest", workflow)
        self.assertNotIn("CONSEQUENCE_CONTROL_DEPLOY_CONFIG_SHA256", workflow)

    def test_candidate_build_has_no_production_credential_surface(self) -> None:
        workflow = (ROOT / ".github/workflows/consequence-control-deploy.yml").read_text()
        candidate = workflow.split("  candidate-release:", 1)[1].split("\n  release-approval:", 1)[0]
        self.assertIn("--bundle", candidate)
        self.assertIn("permissions:\n      contents: read", candidate)
        self.assertNotIn("environment:", candidate)
        self.assertNotIn("id-token: write", candidate)
        self.assertNotIn("secrets.", candidate)
        self.assertNotIn("google-github-actions/auth", candidate)
        self.assertNotIn("gcloud", candidate)

    def test_every_oidc_job_has_no_checkout_local_script_or_general_interpreter(self) -> None:
        workflow = (ROOT / ".github/workflows/consequence-control-deploy.yml").read_text()
        boundaries = list(re.finditer(r"(?m)^  ([a-z0-9-]+):\n", workflow))
        oidc_jobs: list[tuple[str, str]] = []
        for index, boundary in enumerate(boundaries):
            end = boundaries[index + 1].start() if index + 1 < len(boundaries) else len(workflow)
            block = workflow[boundary.start():end]
            if "id-token: write" in block:
                oidc_jobs.append((boundary.group(1), block))
        self.assertEqual([name for name, _ in oidc_jobs], ["deploy"])
        for name, block in oidc_jobs:
            self.assertNotIn("actions/checkout@", block, name)
            self.assertNotIn("GITHUB_WORKSPACE", block, name)
            self.assertNotRegex(block, r"deploy/consequence-control-cloud-run/", name)
            self.assertNotRegex(block, r"(?:^|[\s/])[^\s]+\.(?:py|sh|mjs|mts|js|ts)(?:\s|$)", name)
            self.assertNotRegex(
                block,
                r"\b(?:python3?|node|npm|npx|deno|ruby|perl|php|eval|exec|xargs)\b|"
                r"\b(?:bash|sh)\s+-c\b|\bdocker\s+(?:run|build)\b|\bfind\b[^\n]*-exec",
                name,
            )
            self.assertNotIn("secrets.", block, name)
            for action in re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", block):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$", name)
        protected = oidc_jobs[0][1]
        self.assertIn(
            "artifact-ids: ${{ needs.release-approval.outputs.artifact-id }}",
            protected,
        )
        self.assertIn("GCP_CONSEQUENCE_CONTROL_TRUSTED_EXECUTOR_IMAGE", protected)
        self.assertIn("gcloud builds submit", protected)
        self.assertNotIn("publish-release-images.py", protected)

    def test_unprivileged_approval_verifies_bundle_and_dual_image_load(self) -> None:
        workflow = (ROOT / ".github/workflows/consequence-control-deploy.yml").read_text()
        approval = workflow.split("\n  release-approval:", 1)[1].split("\n  deploy:", 1)[0]
        self.assertNotIn("environment:", approval)
        self.assertNotIn("id-token: write", approval)
        self.assertNotIn("secrets.", approval)
        self.assertIn("verify-bundle", approval)
        self.assertIn("load-bundle", approval)
        self.assertIn(
            "artifact-ids: ${{ needs.candidate-release.outputs.artifact-id }}",
            approval,
        )
        self.assertIn("artifact-digest", workflow)

    def test_schema_workflow_separates_candidate_data_from_trusted_live_code(self) -> None:
        workflow = (ROOT / ".github/workflows/schema-security.yml").read_text()
        self.assertIn("pull_request_target:", workflow)
        self.assertIn("candidate-reconciliation:", workflow)
        candidate_job = workflow.split("candidate-reconciliation:", 1)[1].split(
            "live-schema-contract:", 1
        )[0]
        self.assertIn("path: candidate-data", candidate_job)
        self.assertIn("path: trusted-base", candidate_job)
        self.assertNotIn("npm ci", candidate_job)
        self.assertNotIn("SCHEMA_GATE_DB_URL", candidate_job)
        self.assertIn("node trusted-base/scripts/schema-pr-candidate-reconcile.mjs", candidate_job)
        self.assertIn("schema-pr-candidate-reconcile.mjs", workflow)
        self.assertIn("working-directory: trusted", workflow)
        self.assertIn("supabase/migration-archive/2026-07-25-history-reconciliation", candidate_job)
        live_job = workflow.split("live-schema-contract:", 1)[1].split(
            "schema-contract:", 1
        )[0]
        self.assertNotIn("candidate-data", live_job)
        self.assertNotIn("MIGRATION_RECONCILE_REF: ${{ github.event.pull_request.base.sha }}", workflow)
        job_header = workflow.split("live-schema-contract:", 1)[1].split("steps:", 1)[0]
        self.assertNotIn("SCHEMA_GATE_DB_URL", job_header)
        aggregator = workflow.split("schema-contract:", 1)[1]
        self.assertIn("needs: [candidate-reconciliation, live-schema-contract]", aggregator)
        self.assertIn("if: always()", aggregator)
        self.assertIn("needs.candidate-reconciliation.result", aggregator)
        self.assertIn("needs.live-schema-contract.result", aggregator)
        self.assertIn('name: emilia-production-schema-contract-v2', workflow)
        self.assertIn('"emilia-production-schema-contract-v2" is satisfied.', workflow)

    def test_ci_uses_the_same_release_image_builder(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("build-release-images.sh", workflow)
        self.assertIn("--expected-commit \"$GITHUB_SHA\"", workflow)

    def test_ci_release_sealing_reuses_governed_evidence_only_after_dependencies_pass(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        gate_product = workflow.split("  gate-product:", 1)[1].split("\n  build:", 1)[0]
        self.assertIn("needs: [security-case, language-governance]", gate_product)
        self.assertIn("--governed-evidence-preverified", gate_product)

        language_governance = workflow.split("  language-governance:", 1)[1].split(
            "\n  license-headers:", 1
        )[0]
        self.assertIn("needs: [security-case]", language_governance)
        self.assertIn("SECURITY_CASE_PREVERIFIED_SHA: ${{ github.sha }}", language_governance)
        self.assertIn("npm run check:proof-stats -- --security-case-preverified", language_governance)

        builder = (
            ROOT / "deploy/consequence-control-cloud-run/build-release-images.sh"
        ).read_text()
        self.assertIn("--governed-evidence-preverified", builder)
        self.assertIn('[[ "$GITHUB_SHA" == "$EXPECTED_COMMIT" ]]', builder)
        self.assertIn('if [[ "$GOVERNED_EVIDENCE_PREVERIFIED" != 1 ]]', builder)

        proof_generator = (ROOT / "scripts/generate-proof-stats.mts").read_text()
        self.assertIn('"--security-case-preverified"', proof_generator)
        self.assertIn("SECURITY_CASE_PREVERIFIED_SHA", proof_generator)

    def test_release_builder_seals_before_removing_generated_ignored_state(self) -> None:
        builder = (
            ROOT / "deploy/consequence-control-cloud-run/build-release-images.sh"
        ).read_text()
        seal = builder.index('VERIFY_TARBALL=$("$TRUST" pack-package')
        assurance = builder.index("npm run check:security-case")
        cleanup = builder.index("git clean -fdX --")
        source_manifest = builder.index('SOURCE_MANIFEST="$WORK/source-manifest.json"')
        self.assertLess(seal, assurance)
        self.assertLess(assurance, cleanup)
        self.assertLess(cleanup, source_manifest)
        self.assertNotIn("git clean -fdx --", builder)

    def test_runtime_images_pin_fixed_openssl_and_actuator_carries_exact_caid(self) -> None:
        patched_openssl = (
            "apk add --no-cache --upgrade "
            "libcrypto3=3.5.8-r0 libssl3=3.5.8-r0"
        )
        for relative_path in (
            "Dockerfile",
            "Dockerfile.gate",
            "Dockerfile.consequence-control",
            "Dockerfile.consequence-actuator",
            "deploy/consequence-control-cloud-run/Dockerfile.consequence-actuator.release",
            "witness/Dockerfile",
        ):
            self.assertIn(
                patched_openssl,
                (ROOT / relative_path).read_text(),
                f"{relative_path} must install the fixed Alpine OpenSSL libraries",
            )

        for relative_path in ("Dockerfile", "witness/Dockerfile"):
            runtime_image = (ROOT / relative_path).read_text()
            for unused_runtime_tool in (
                "/usr/local/lib/node_modules/npm",
                "/usr/local/lib/node_modules/corepack",
                "/opt/yarn-v1.22.22",
                "/usr/local/bin/npm",
                "/usr/local/bin/npx",
                "/usr/local/bin/corepack",
                "/usr/local/bin/yarn",
                "/usr/local/bin/yarnpkg",
            ):
                self.assertIn(
                    unused_runtime_tool,
                    runtime_image,
                    f"{relative_path} must remove unused runtime tool {unused_runtime_tool}",
                )

        dockerfile = (
            ROOT
            / "deploy/consequence-control-cloud-run/Dockerfile.consequence-actuator.release"
        ).read_text()
        self.assertIn("COPY caid/impl/js/caid.mjs caid/impl/js/caid.mjs", dockerfile)
        self.assertIn(
            "COPY --from=build /opt/consequence-actuator/caid/impl/js/caid.mjs "
            "caid/impl/js/caid.mjs",
            dockerfile,
        )


if __name__ == "__main__":
    unittest.main()
