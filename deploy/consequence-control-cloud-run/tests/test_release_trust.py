from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


LANE = Path(__file__).resolve().parents[1]
ROOT = LANE.parents[1]
TRUST = LANE / "release-trust.py"
SCHEMA_RECONCILE = ROOT / "scripts" / "schema-pr-candidate-reconcile.mjs"

GOVERNED = (
    "security/security-case.json",
    "lib/proof-stats.json",
    "conformance/conformance-manifest.json",
)
BUILD_INPUTS = (
    "Dockerfile.consequence-actuator",
    "Dockerfile.consequence-control",
    "Dockerfile.gate",
    "apps/consequence-actuator-service/package-lock.json",
    "apps/consequence-control-service/package-lock.json",
    "apps/gate-service/package-lock.json",
)


def run(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
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
        package_tarball(self.verify_tarball, "@emilia-protocol/verify", "3.15.0")
        package_tarball(self.gate_tarball, "@emilia-protocol/gate", "0.16.0")
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


class SchemaCandidateReconciliationTests(unittest.TestCase):
    def migration(self, root: Path, name: str, raw: bytes) -> None:
        path = root / "supabase" / "migrations" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def ledger(self, root: Path, files: dict[str, bytes], pending: list[str]) -> None:
        path = root / "supabase" / "migration-history.v1.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "EP-MIGRATION-HISTORY-v1",
                    "retroactive_pending_versions": pending,
                    "forward_pending_versions": [],
                    "deployment_sequence": pending,
                    "public_files": {name: sha256(raw) for name, raw in files.items()},
                }
            ),
            encoding="utf-8",
        )

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
        self.assertIn("path: candidate", workflow)
        self.assertIn("path: trusted", workflow)
        self.assertIn("schema-pr-candidate-reconcile.mjs", workflow)
        self.assertIn("working-directory: trusted", workflow)
        self.assertNotIn("MIGRATION_RECONCILE_REF: ${{ github.event.pull_request.base.sha }}", workflow)
        job_header = workflow.split("schema-contract:", 1)[1].split("steps:", 1)[0]
        self.assertNotIn("SCHEMA_GATE_DB_URL", job_header)

    def test_ci_uses_the_same_release_image_builder(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("build-release-images.sh", workflow)
        self.assertIn("--expected-commit \"$GITHUB_SHA\"", workflow)


if __name__ == "__main__":
    unittest.main()
