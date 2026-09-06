"""Exercise the standalone Space inventory without building dependency wheels."""

import hashlib
import json
from pathlib import Path

import bundle_space
import pytest
import yaml

WHEEL_NAMES = {
    "python-verify": "emilia_verify-2.8.5-py3-none-any.whl",
    "crewai": "emilia_crewai-0.3.5-py3-none-any.whl",
    "smolagents": "emilia_smolagents-0.1.1-py3-none-any.whl",
}


@pytest.fixture
def stub_builds(monkeypatch):
    def build(command, *, check):
        assert check is True
        assert command[1:5] == ["-m", "pip", "wheel", "--no-deps"]
        destination = Path(command[command.index("--wheel-dir") + 1])
        package = Path(command[-1]).name
        (destination / WHEEL_NAMES[package]).write_bytes(
            f"standalone-wheel-fixture:{package}".encode()
        )

    def git(command, *, cwd, text):
        assert cwd == bundle_space.ROOT
        assert text is True
        return "a" * 40 + "\n" if command[1] == "rev-parse" else ""

    monkeypatch.setattr(bundle_space.subprocess, "run", build)
    monkeypatch.setattr(bundle_space.subprocess, "check_output", git)


def test_bundle_copies_docker_runtime_and_hashes_every_packaged_file(
    tmp_path, stub_builds
):
    output = bundle_space.bundle(tmp_path / "space")
    metadata = yaml.safe_load((output / "README.md").read_text().split("---", 2)[1])
    assert metadata["sdk"] == "docker"
    assert metadata["app_port"] == 7860
    assert "sdk_version" not in metadata
    assert (output / "Dockerfile").read_bytes() == (
        bundle_space.EXAMPLE / "Dockerfile"
    ).read_bytes()
    assert (output / "test_demo.py").read_bytes() == (
        bundle_space.EXAMPLE / "test_demo.py"
    ).read_bytes()

    checksums = {
        name: digest
        for digest, name in (
            line.split("  ", 1)
            for line in (output / "SHA256SUMS").read_text().splitlines()
        )
    }
    expected_files = {
        "Dockerfile",
        "app.py",
        "demo.py",
        "test_demo.py",
        "requirements.txt",
        "README.md",
        "ADAPTER.md",
        "LICENSE",
        "BUNDLE.json",
        *(f"wheels/{name}" for name in WHEEL_NAMES.values()),
    }
    assert set(checksums) == expected_files
    assert {
        str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()
    } == expected_files | {"SHA256SUMS"}
    for name, digest in checksums.items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest

    requirements = (output / "requirements.txt").read_text().splitlines()
    assert set(requirements) == {
        "gradio==6.26.0",
        "smolagents==1.26.0",
        *(f"./wheels/{name}" for name in WHEEL_NAMES.values()),
    }
    assert json.loads((output / "BUNDLE.json").read_text()) == {
        "source_commit": "a" * 40,
        "source_tree_dirty": False,
        "packages": list(bundle_space.PACKAGES),
    }


def test_bundle_refuses_to_overwrite_existing_files(tmp_path, stub_builds):
    output = tmp_path / "space"
    output.mkdir()
    marker = output / "README.md"
    marker.write_text("keep this existing bundle")
    with pytest.raises(FileExistsError):
        bundle_space.bundle(output)
    assert marker.read_text() == "keep this existing bundle"
    assert set(output.iterdir()) == {marker}


@pytest.mark.parametrize("source", (*bundle_space.PACKAGES, str(bundle_space.EXAMPLE)))
def test_bundle_refuses_source_directory_outputs(source):
    with pytest.raises(ValueError, match="outside the source"):
        bundle_space.bundle(bundle_space.ROOT / source / "nested-output")


def test_bundle_rejects_missing_local_wheels(tmp_path, monkeypatch, stub_builds):
    monkeypatch.setattr(bundle_space.subprocess, "run", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError, match="one wheel for each"):
        bundle_space.bundle(tmp_path / "incomplete-space")
