"""Distribution-level checks; CI runs these from a wheel-only virtualenv."""

from __future__ import annotations

import importlib.util
import os
import unittest
from importlib import metadata
from pathlib import Path

import emilia_protocol


class TestInstalledWheel(unittest.TestCase):
    def test_distribution_metadata_matches_runtime(self) -> None:
        distribution = metadata.distribution("emilia-protocol")
        self.assertEqual(distribution.version, "0.11.0")
        self.assertEqual(emilia_protocol.__version__, "0.11.0")
        self.assertFalse(distribution.requires)

    def test_distribution_contains_only_canonical_namespace(self) -> None:
        distribution = metadata.distribution("emilia-protocol")
        files = {str(path) for path in (distribution.files or [])}
        self.assertIn("emilia_protocol/__init__.py", files)
        self.assertFalse(any(path == "ep" or path.startswith("ep/") for path in files))

    def test_clean_wheel_environment_has_no_ep_namespace(self) -> None:
        if os.environ.get("EMILIA_SDK_WHEEL_TEST") != "1":
            self.skipTest("strict import-origin assertion is for the wheel-only CI environment")
        self.assertIsNone(importlib.util.find_spec("ep"))
        module_path = Path(emilia_protocol.__file__).resolve()
        self.assertNotIn("/sdks/python/src/", str(module_path))


if __name__ == "__main__":
    unittest.main()
