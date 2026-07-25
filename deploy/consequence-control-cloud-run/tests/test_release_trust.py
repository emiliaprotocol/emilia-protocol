from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
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


def package_tarball(path: Path, name: str, version: str) -> None:
    raw = json.dumps({"name": name, "version": version}).encode()
    metadata = tarfile.TarInfo("package/package.json")
    metadata.size = len(raw)
    metadata.mode = 0o644
    metadata.mtime = 0
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(metadata, io.BytesIO(raw))


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
        package_tarball(self.verify_tarball, "@emilia-protocol/verify", "3.15.0")
        package_tarball(self.gate_tarball, "@emilia-protocol/gate", "0.16.0")
        package_tarball(
            self.require_tarball, "@emilia-protocol/require-receipt", "0.7.0"
        )
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
        package_root.mkdir(parents=True)
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
        package_tarball(self.verify_tarball, "@emilia-protocol/verify", "9.9.9")
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
        self.assertIn("tarball differs", result.stderr)

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
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/decision:git-" + self.commit
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
        self.assertIn("ACTUATOR_IMAGE=" + actuator_tag.rsplit(":", 1)[0] + "@sha256:", derived)

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
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/decision:git-" + self.commit
        decision_digest = "sha256:" + "b" * 64
        state = self.artifacts / "fake-state-mismatch.json"
        state.write_text(json.dumps({
            "local": {
                actuator_tag: {"id": "sha256:" + "1" * 64, "labels": {**labels, "io.emilia.image.component": "actuator"}},
                decision_tag: {"id": "sha256:" + "2" * 64, "labels": {**labels, "io.emilia.image.component": "decision"}},
            },
            "remote": {
                decision_tag: {
                    "digest": decision_digest,
                    "id": "sha256:" + "2" * 64,
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
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/decision:git-" + self.commit
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
        actuator_tag = "us-central1-docker.pkg.dev/test-project/runtime/actuator:git-" + self.commit
        decision_tag = "us-central1-docker.pkg.dev/test-project/runtime/decision:git-" + self.commit
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

    def _publish(self, actuator, decision, config, docker, gcloud, output, environment):
        github_output = output.parent / (output.name + ".outputs")
        github_output.write_text("")
        return run(
            str(PUBLISH), "--root", str(self.root), "--source-manifest", str(self.source),
            "--artifact-dir", str(self.artifacts), "--expected-commit", self.commit,
            "--config", str(config), "--actuator-tag", actuator, "--decision-tag", decision,
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
                    "requires_include_all": True,
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
        self.assertIn("subject-digest: ${{ steps.release-images.outputs.actuator_digest }}", workflow)
        self.assertIn("subject-digest: ${{ steps.release-images.outputs.decision_digest }}", workflow)
        self.assertIn("--source-manifest", workflow)
        self.assertIn("--release-manifest", workflow)
        self.assertNotIn("CONSEQUENCE_CONTROL_DEPLOY_CONFIG_SHA256", workflow)

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
        self.assertIn('"schema-security / schema-contract"', workflow)

    def test_ci_uses_the_same_release_image_builder(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("build-release-images.sh", workflow)
        self.assertIn("--expected-commit \"$GITHUB_SHA\"", workflow)


if __name__ == "__main__":
    unittest.main()
