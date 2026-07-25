from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


LANE = Path(__file__).resolve().parents[1]
COMMON = LANE / "lib" / "common.sh"


class ConfigDigestCompletenessTests(unittest.TestCase):
    def run_common(
        self,
        config: Path,
        script: str,
        *,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        config_hash = hashlib.sha256(config.read_bytes()).hexdigest()
        process_environment = {
            **os.environ,
            "DEPLOYMENT_CONFIG_SHA256": config_hash,
            "REQUIRE_DEPLOYMENT_CONFIG_PIN": "true",
        }
        if environment is not None:
            process_environment.update(environment)
        return subprocess.run(
            ["bash", "-c", script, "bash", str(COMMON), str(config)],
            cwd=LANE,
            text=True,
            capture_output=True,
            check=False,
            env=process_environment,
        )

    def test_ambient_allowlisted_values_cannot_fill_missing_config_keys(
        self,
    ) -> None:
        hostile_values = {
            "PROJECT_ID": "ambient-project",
            "ACTUATOR_IMAGE": (
                "us-central1-docker.pkg.dev/ambient/runtime/actuator@sha256:"
                + "a" * 64
            ),
            "CANARY_EVIDENCE_PUBLIC_KEY_FILE": "/ambient/canary.pem",
            "ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE": "/ambient/telemetry.pem",
            "ROLLOUT_AUTHORIZATION_PUBLIC_KEY_FILE": "/ambient/authz.pem",
            "STABLE_RELEASE_PUBLIC_KEY_FILE": "/ambient/stable.pem",
        }
        allowlist = " ".join(hostile_values)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.env"
            config.write_text(
                "# all allowlisted coordinates are intentionally absent\n",
                encoding="utf-8",
            )
            for name in hostile_values:
                with self.subTest(name=name):
                    result = self.run_common(
                        config,
                        (
                            'source "$1"\n'
                            f'load_lane_config "$2" {allowlist}\n'
                            f"require_var {name}\n"
                        ),
                        environment=hostile_values,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"{name} was not loaded from pinned config",
                        result.stderr,
                    )

    def test_loader_clears_allowlist_and_tracks_only_exact_loaded_keys(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.env"
            config.write_text("PROJECT_ID=pinned-project\n", encoding="utf-8")
            result = self.run_common(
                config,
                textwrap.dedent(
                    """\
                    source "$1"
                    load_lane_config "$2" \
                      PROJECT_ID ACTUATOR_IMAGE CANARY_EVIDENCE_PUBLIC_KEY_FILE
                    [[ "$PROJECT_ID" == pinned-project ]]
                    [[ -z "${ACTUATOR_IMAGE+x}" ]]
                    [[ -z "${CANARY_EVIDENCE_PUBLIC_KEY_FILE+x}" ]]
                    [[ "$LANE_ALLOWLISTED_CONFIG_KEYS" == \
                      :PROJECT_ID:ACTUATOR_IMAGE:CANARY_EVIDENCE_PUBLIC_KEY_FILE: ]]
                    [[ "$LANE_LOADED_CONFIG_KEYS" == :PROJECT_ID: ]]
                    require_var PROJECT_ID
                    """
                ),
                environment={
                    "PROJECT_ID": "ambient-project",
                    "ACTUATOR_IMAGE": "ambient-image",
                    "CANARY_EVIDENCE_PUBLIC_KEY_FILE": "/ambient/canary.pem",
                },
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_require_var_rejects_value_injected_after_config_load(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.env"
            config.write_text("# PROJECT_ID is missing\n", encoding="utf-8")
            result = self.run_common(
                config,
                textwrap.dedent(
                    """\
                    source "$1"
                    load_lane_config "$2" PROJECT_ID
                    PROJECT_ID=post-load-attacker
                    require_var PROJECT_ID
                    """
                ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "PROJECT_ID was not loaded from pinned config",
            result.stderr,
        )

    def test_source_replacement_after_single_open_cannot_change_loaded_bytes(
        self,
    ) -> None:
        real_python = shutil.which("python3")
        self.assertIsNotNone(real_python)
        original = b"PROJECT_ID=pinned-project\n"
        replacement = "PROJECT_ID=attacker-project\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.env"
            config.write_bytes(original)
            marker = root / "source-replaced"
            wrapper_directory = root / "bin"
            wrapper_directory.mkdir()
            wrapper = wrapper_directory / "python3"
            wrapper.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -euo pipefail
                    "$REAL_PYTHON" "$@"
                    status=$?
                    if [[ ! -e "$PIN_REPLACEMENT_MARKER" ]]; then
                      printf '%s' "$PIN_REPLACEMENT" > "$PIN_SOURCE"
                      : > "$PIN_REPLACEMENT_MARKER"
                    fi
                    exit "$status"
                    """
                ),
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            result = self.run_common(
                config,
                textwrap.dedent(
                    """\
                    source "$1"
                    load_lane_config "$2" PROJECT_ID
                    require_var PROJECT_ID
                    [[ "$PROJECT_ID" == pinned-project ]]
                    [[ "$(lane_emit_pinned_config)" == \
                      "PROJECT_ID=pinned-project" ]]
                    verify_lane_config_pin
                    """
                ),
                environment={
                    "PATH": f"{wrapper_directory}:{os.environ['PATH']}",
                    "REAL_PYTHON": real_python or "",
                    "PIN_SOURCE": str(config),
                    "PIN_REPLACEMENT": replacement,
                    "PIN_REPLACEMENT_MARKER": str(marker),
                },
            )
            replaced = config.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(replaced, replacement)


if __name__ == "__main__":
    unittest.main()
