#!/usr/bin/env python3
"""Hostile promotion-time Cloud Run configuration tests."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock

LANE = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).with_name("fixture.env")
SPEC = importlib.util.spec_from_file_location(
    "verify_canary_configuration",
    LANE / "verify-canary.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("verify-canary.py could not be imported")
verify_canary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_canary)


def secret_environment(
    config: dict[str, str],
    bindings: dict[str, str],
) -> list[dict]:
    result: list[dict] = []
    for environment_name, config_variable in bindings.items():
        secret, version = config[config_variable].rsplit(":", 1)
        result.append(
            {
                "name": environment_name,
                "valueFrom": {
                    "secretKeyRef": {
                        "key": version,
                        "name": secret,
                    }
                },
            }
        )
    return result


class LiveConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = verify_canary.load_config(FIXTURE)
        self.actuator_revision = (
            f"{self.config['ACTUATOR_SERVICE']}-{self.config['RELEASE_ID']}"
        )
        self.decision_revision = (
            f"{self.config['DECISION_SERVICE']}-{self.config['RELEASE_ID']}"
        )
        self.tag = f"canary-{self.config['RELEASE_ID']}"
        self.actuator_tagged_url = (
            "https://canary-actuator---emilia-consequence-actuator.example.run.app"
        )
        self.decision_tagged_url = (
            "https://canary-decision---emilia-consequence-control.example.run.app"
        )
        self.actuator_audience = (
            "https://emilia-consequence-actuator.example.run.app"
        )
        self.resources = self.valid_resources()

    def service(
        self,
        name: str,
        revision: str,
        tagged_url: str,
        canonical_url: str,
        ingress: str,
    ) -> dict:
        return {
            "metadata": {
                "name": name,
                "annotations": {
                    "run.googleapis.com/ingress": ingress,
                },
            },
            "status": {
                "url": canonical_url,
                "traffic": [
                    {
                        "percent": 0,
                        "revisionName": revision,
                        "tag": self.tag,
                        "url": tagged_url,
                    }
                ],
            },
        }

    def revision(
        self,
        name: str,
        service: str,
        image: str,
        account: str,
        environment: list[dict],
    ) -> dict:
        return {
            "metadata": {
                "name": name,
                "labels": {
                    "serving.knative.dev/service": service,
                },
                "annotations": {
                    "run.googleapis.com/network-interfaces": json.dumps(
                        [
                            {
                                "network": self.config["NETWORK"],
                                "subnetwork": self.config["SUBNET"],
                            }
                        ]
                    ),
                    "run.googleapis.com/vpc-access-egress": "all-traffic",
                },
            },
            "spec": {
                "serviceAccountName": account,
                "containers": [
                    {
                        "image": image,
                        "env": environment,
                    }
                ],
            },
        }

    def valid_resources(self) -> dict[tuple[str, str], dict]:
        actuator_service = self.config["ACTUATOR_SERVICE"]
        decision_service = self.config["DECISION_SERVICE"]
        actuator_environment = secret_environment(
            self.config,
            verify_canary.ACTUATOR_SECRET_BINDINGS,
        )
        decision_environment = secret_environment(
            self.config,
            verify_canary.DECISION_SECRET_BINDINGS,
        )
        decision_environment.extend(
            [
                {
                    "name": "EMILIA_CONSEQUENCE_ACTUATOR_ORIGIN",
                    "value": self.actuator_tagged_url,
                },
                {
                    "name": "EMILIA_CONSEQUENCE_ACTUATOR_AUDIENCE",
                    "value": self.actuator_audience,
                },
            ]
        )
        return {
            ("services", actuator_service): self.service(
                actuator_service,
                self.actuator_revision,
                self.actuator_tagged_url,
                self.actuator_audience,
                self.config["ACTUATOR_INGRESS"],
            ),
            ("services", decision_service): self.service(
                decision_service,
                self.decision_revision,
                self.decision_tagged_url,
                "https://emilia-consequence-control.example.run.app",
                self.config["DECISION_INGRESS"],
            ),
            ("revisions", self.actuator_revision): self.revision(
                self.actuator_revision,
                actuator_service,
                self.config["ACTUATOR_IMAGE"],
                (
                    f"{self.config['ACTUATOR_SERVICE_ACCOUNT']}@"
                    f"{self.config['PROJECT_ID']}.iam.gserviceaccount.com"
                ),
                actuator_environment,
            ),
            ("revisions", self.decision_revision): self.revision(
                self.decision_revision,
                decision_service,
                self.config["DECISION_IMAGE"],
                (
                    f"{self.config['DECISION_SERVICE_ACCOUNT']}@"
                    f"{self.config['PROJECT_ID']}.iam.gserviceaccount.com"
                ),
                decision_environment,
            ),
        }

    def runner(self, args: list[str], **_: object) -> subprocess.CompletedProcess:
        self.assertEqual(args[:2], ["gcloud", "run"])
        self.assertEqual(args[3], "describe")
        resource = self.resources.get((args[2], args[4]))
        if resource is None:
            return subprocess.CompletedProcess(args, 1, "", "not found")
        return subprocess.CompletedProcess(args, 0, json.dumps(resource), "")

    def verify(self) -> None:
        evidence = {
            "actuator_revision": self.actuator_revision,
            "decision_revision": self.decision_revision,
        }
        with mock.patch.object(
            verify_canary.subprocess,
            "run",
            side_effect=self.runner,
        ):
            verify_canary.validate_live(self.config, evidence)

    def test_exact_live_configuration_is_accepted(self) -> None:
        self.verify()

    def test_tag_repoint_is_refused(self) -> None:
        baseline = copy.deepcopy(self.resources)
        for plane, service_key in (
            ("actuator", "ACTUATOR_SERVICE"),
            ("decision", "DECISION_SERVICE"),
        ):
            with self.subTest(plane=plane):
                self.resources = copy.deepcopy(baseline)
                service = self.resources[
                    ("services", self.config[service_key])
                ]
                service["status"]["traffic"][0]["revisionName"] = (
                    f"{self.config[service_key]}-stable"
                )
                with self.assertRaisesRegex(ValueError, "tag revision"):
                    self.verify()

    def test_wrong_actuator_origin_or_audience_is_refused(self) -> None:
        cases = {
            "origin": (
                "EMILIA_CONSEQUENCE_ACTUATOR_ORIGIN",
                "https://wrong-origin.example.run.app",
            ),
            "audience": (
                "EMILIA_CONSEQUENCE_ACTUATOR_AUDIENCE",
                "https://wrong-audience.example.run.app",
            ),
        }
        baseline = copy.deepcopy(self.resources)
        for label, (name, value) in cases.items():
            with self.subTest(label=label):
                self.resources = copy.deepcopy(baseline)
                decision = self.resources[("revisions", self.decision_revision)]
                environment = decision["spec"]["containers"][0]["env"]
                next(item for item in environment if item["name"] == name)[
                    "value"
                ] = value
                with self.assertRaisesRegex(ValueError, name):
                    self.verify()

    def test_runtime_service_account_substitution_is_refused(self) -> None:
        decision = self.resources[("revisions", self.decision_revision)]
        decision["spec"]["serviceAccountName"] = (
            "substituted@test-project.iam.gserviceaccount.com"
        )
        with self.assertRaisesRegex(ValueError, "runtime service account"):
            self.verify()

    def test_mutable_or_missing_secret_version_is_refused(self) -> None:
        baseline = copy.deepcopy(self.resources)
        cases = ("mutable", "missing")
        for label in cases:
            with self.subTest(label=label):
                self.resources = copy.deepcopy(baseline)
                actuator = self.resources[("revisions", self.actuator_revision)]
                environment = actuator["spec"]["containers"][0]["env"]
                target = next(
                    item
                    for item in environment
                    if item["name"] == "EMILIA_ACTUATOR_API_TOKEN"
                )
                if label == "mutable":
                    target["valueFrom"]["secretKeyRef"]["key"] = "latest"
                else:
                    del target["valueFrom"]["secretKeyRef"]["key"]
                with self.assertRaisesRegex(ValueError, "secret"):
                    self.verify()

    def test_ingress_or_vpc_drift_is_refused(self) -> None:
        baseline = copy.deepcopy(self.resources)
        mutations = {
            "ingress": lambda resources: resources[
                ("services", self.config["ACTUATOR_SERVICE"])
            ]["metadata"]["annotations"].__setitem__(
                "run.googleapis.com/ingress",
                "all",
            ),
            "network": lambda resources: self.set_network_annotation(
                resources,
                network="wrong-network",
            ),
            "egress": lambda resources: resources[
                ("revisions", self.actuator_revision)
            ]["metadata"]["annotations"].__setitem__(
                "run.googleapis.com/vpc-access-egress",
                "private-ranges-only",
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.resources = copy.deepcopy(baseline)
                mutate(self.resources)
                with self.assertRaisesRegex(
                    ValueError,
                    "ingress|network|VPC egress",
                ):
                    self.verify()

    def set_network_annotation(
        self,
        resources: dict[tuple[str, str], dict],
        network: str,
    ) -> None:
        revision = resources[("revisions", self.actuator_revision)]
        revision["metadata"]["annotations"][
            "run.googleapis.com/network-interfaces"
        ] = json.dumps(
            [
                {
                    "network": network,
                    "subnetwork": self.config["SUBNET"],
                }
            ]
        )


if __name__ == "__main__":
    unittest.main()
