"""Build a self-contained Space folder from this checkout. Never uploads it."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = Path(__file__).resolve().parent
PACKAGES = ("packages/python-verify", "packages/crewai", "packages/smolagents")


def bundle(output):
    output = Path(output).resolve()
    if any(
        output.is_relative_to(ROOT / package) for package in PACKAGES
    ) or output.is_relative_to(EXAMPLE):
        raise ValueError(
            "Choose an output folder outside the source packages and example."
        )
    # Refuse to overwrite any existing directory, including a previous bundle.
    output.mkdir(parents=True, exist_ok=False)
    wheels = output / "wheels"
    wheels.mkdir()
    for package in PACKAGES:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--wheel-dir",
                str(wheels),
                str(ROOT / package),
            ],
            check=True,
        )
    artifacts = sorted(wheels.glob("*.whl"))
    if len(artifacts) != 3:
        raise RuntimeError(
            "Expected one wheel for each of the three local EMILIA packages."
        )
    requirements = [
        "gradio==6.26.0",
        "smolagents==1.26.0",
        *(f"./wheels/{wheel.name}" for wheel in artifacts),
    ]
    (output / "requirements.txt").write_text("\n".join(requirements) + "\n")
    for name in ("app.py", "demo.py", "test_demo.py"):
        shutil.copy2(EXAMPLE / name, output / name)
    shutil.copy2(ROOT / "LICENSE", output / "LICENSE")
    shutil.copy2(ROOT / "packages/smolagents/README.md", output / "ADAPTER.md")
    (output / "README.md").write_text(
        "---\ntitle: EMILIA Refund Tool Demo\nemoji: 🛂\ncolorFrom: green\ncolorTo: blue\n"
        "sdk: gradio\nsdk_version: 6.26.0\npython_version: '3.12'\napp_file: app.py\n"
        "pinned: false\nlicense: apache-2.0\ntags:\n- smolagents\n- agent-tools\n- authorization\n---\n\n"
        "# One approval, one exact refund\n\n"
        "Try an EMILIA-guarded smolagents tool with synthetic refunds. No model token, "
        "provider credentials, or real funds are used. Each run creates a fresh software issuer "
        "and in-memory store. This is not a verified human approval ceremony or a durable production Gate.\n\n"
        "The three included EMILIA wheels were built from the checkout recorded in BUNDLE.json. "
        "They include source fixes that may not yet be on PyPI; do not replace them with older registry versions. "
        "SHA256SUMS identifies the exact files in this bundle. This script did not upload the Space.\n\n"
        "See ADAPTER.md for local use, receipt transport, and production boundaries. The native wrapper "
        "is an EMILIA community integration, not a Hugging Face endorsement.\n"
    )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--", *PACKAGES, str(EXAMPLE)],
        cwd=ROOT,
        text=True,
    )
    manifest = {
        "source_commit": commit,
        "source_tree_dirty": bool(status.strip()),
        "packages": list(PACKAGES),
    }
    (output / "BUNDLE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    lines = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            lines.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(output)}"
            )
    (output / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="A new output folder, outside the source packages.",
    )
    print(bundle(parser.parse_args().output))
