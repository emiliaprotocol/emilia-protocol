"""Regression checks binding the SDK route manifest to specs and handlers."""

from __future__ import annotations

import inspect
import json
import re
import unittest
from pathlib import Path
from typing import Dict, Set

from emilia_protocol import EPClient, ROUTE_CONTRACT


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _yaml_paths(spec_path: Path) -> Dict[str, Set[str]]:
    """Extract only path/method keys without adding a YAML dependency."""
    paths: Dict[str, Set[str]] = {}
    current_path = None
    for line in spec_path.read_text(encoding="utf-8").splitlines():
        path_match = re.match(r"^  (/[^:]*):\s*$", line)
        if path_match:
            current_path = path_match.group(1)
            paths.setdefault(current_path, set())
            continue
        method_match = re.match(r"^    ([a-z]+):\s*$", line)
        if current_path and method_match and method_match.group(1) in HTTP_METHODS:
            paths[current_path].add(method_match.group(1).upper())
    return paths


def _runtime_route_path(template: str) -> Path:
    segments = []
    for segment in template.strip("/").split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            segment = "[{0}]".format(segment[1:-1])
        segments.append(segment)
    return REPOSITORY_ROOT.joinpath("app", *segments)


class TestRouteContract(unittest.TestCase):
    def test_public_manifest_matches_the_machine_readable_contract(self) -> None:
        contract = json.loads(
            (REPOSITORY_ROOT / "sdks/python/route-contract.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(contract["version"], 1)
        self.assertEqual(contract["routes"], list(ROUTE_CONTRACT))

    def test_every_manifest_route_is_in_its_named_openapi_document(self) -> None:
        parsed_specs: Dict[str, Dict[str, Set[str]]] = {}
        for route in ROUTE_CONTRACT:
            spec = route["spec"]
            if spec not in parsed_specs:
                parsed_specs[spec] = _yaml_paths(REPOSITORY_ROOT / spec)
            with self.subTest(method=route["method"], path=route["path"], spec=spec):
                self.assertIn(route["path"], parsed_specs[spec])
                self.assertIn(route["method"], parsed_specs[spec][route["path"]])

    def test_every_manifest_route_has_a_matching_runtime_handler(self) -> None:
        for route in ROUTE_CONTRACT:
            route_directory = _runtime_route_path(route["path"])
            candidates = sorted(route_directory.glob("route.*"))
            with self.subTest(method=route["method"], path=route["path"]):
                self.assertTrue(candidates, "missing runtime route: {0}".format(route_directory))
                source = "\n".join(
                    candidate.read_text(encoding="utf-8") for candidate in candidates
                )
                self.assertRegex(
                    source,
                    r"export\s+(?:async\s+)?function\s+{0}\b".format(route["method"]),
                )

    def test_public_client_surface_is_exactly_manifest_plus_orchestration(self) -> None:
        public_methods = {
            name
            for name, member in inspect.getmembers(EPClient, predicate=inspect.isfunction)
            if not name.startswith("_")
        }
        expected = {route["client_method"] for route in ROUTE_CONTRACT}
        expected.add("require_receipt")
        self.assertEqual(public_methods, expected)

    def test_lifecycle_is_in_canonical_and_focused_openapi(self) -> None:
        parsed_specs: Dict[str, Dict[str, Set[str]]] = {}
        focused_routes = [route for route in ROUTE_CONTRACT if "focused_spec" in route]
        self.assertTrue(focused_routes)
        for route in focused_routes:
            for key in ("spec", "focused_spec"):
                spec = route[key]
                if spec not in parsed_specs:
                    parsed_specs[spec] = _yaml_paths(REPOSITORY_ROOT / spec)
                with self.subTest(
                    method=route["method"],
                    path=route["path"],
                    spec=spec,
                ):
                    self.assertIn(route["path"], parsed_specs[spec])
                    self.assertIn(route["method"], parsed_specs[spec][route["path"]])


if __name__ == "__main__":
    unittest.main()
