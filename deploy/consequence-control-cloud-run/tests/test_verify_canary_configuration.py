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


def plain_environment(values: dict[str, str]) -> list[dict]:
    return [{"name": name, "value": value} for name, value in values.items()]


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
        plane: str,
        revision: str,
        tagged_url: str,
        canonical_url: str,
        ingress: str,
    ) -> dict:
        annotations = {
            "run.googleapis.com/client-name": "gcloud",
            "run.googleapis.com/ingress": ingress,
        }
        if plane == "decision":
            annotations["run.googleapis.com/invoker-iam-disabled"] = "true"
        return {
            "metadata": {
                "name": name,
                "generation": 7,
                "labels": {
                    "cloud.googleapis.com/location": self.config["REGION"],
                    "emilia-plane": plane,
                    "emilia-release": self.config["RELEASE_ID"],
                },
                "annotations": annotations,
            },
            "status": {
                "observedGeneration": 7,
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
        plane: str,
        image: str,
        account: str,
        cpu: str,
        memory: str,
        minimum: str,
        maximum: str,
        concurrency: int,
        timeout: int,
        environment: list[dict],
    ) -> dict:
        container = {
            "image": image,
            "env": environment,
            "resources": {
                "limits": {
                    "cpu": f"{int(cpu) * 1000}m",
                    "memory": memory,
                },
            },
            "ports": [
                {
                    "containerPort": 8080,
                    "name": "http1",
                }
            ],
            "startupProbe": {
                "failureThreshold": 30,
                "initialDelaySeconds": 0,
                "periodSeconds": 2,
                "successThreshold": 1,
                "timeoutSeconds": 1,
                (
                    "tcpSocket" if plane == "actuator" else "httpGet"
                ): (
                    {"port": 8080}
                    if plane == "actuator"
                    else {"path": "/v1/ready", "port": 8080}
                ),
            },
        }
        if plane == "decision":
            container["livenessProbe"] = {
                "failureThreshold": 3,
                "httpGet": {
                    "path": "/v1/live",
                    "port": 8080,
                },
                "initialDelaySeconds": 10,
                "periodSeconds": 30,
                "successThreshold": 1,
                "timeoutSeconds": 2,
            }
            container["readinessProbe"] = {
                "failureThreshold": 3,
                "httpGet": {
                    "path": "/v1/ready",
                    "port": 8080,
                },
                "periodSeconds": 5,
                "successThreshold": 1,
                "timeoutSeconds": 2,
            }
        return {
            "metadata": {
                "name": name,
                "labels": {
                    "cloud.googleapis.com/location": self.config["REGION"],
                    "emilia-plane": plane,
                    "emilia-release": self.config["RELEASE_ID"],
                    "serving.knative.dev/service": service,
                },
                "annotations": {
                    "autoscaling.knative.dev/maxScale": maximum,
                    "autoscaling.knative.dev/minScale": minimum,
                    "run.googleapis.com/client-name": "gcloud",
                    "run.googleapis.com/execution-environment": "gen2",
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
                "containerConcurrency": concurrency,
                "timeoutSeconds": timeout,
                "serviceAccountName": account,
                "containers": [container],
            },
        }

    def actuator_plain_environment(self) -> dict[str, str]:
        return {
            "NODE_ENV": "production",
            "HOST": "0.0.0.0",
            "EMILIA_ACTUATOR_DATABASE_PRINCIPAL": self.config[
                "ACTUATOR_DATABASE_PRINCIPAL"
            ],
            "EMILIA_ACTUATOR_TENANT_ID": self.config["TENANT_ID"],
            "EMILIA_ACTUATOR_GITHUB_OWNER": self.config["GITHUB_OWNER"],
            "EMILIA_ACTUATOR_GITHUB_REPO": self.config["GITHUB_REPO"],
            "EMILIA_ACTUATOR_GITHUB_ISSUE_NUMBER": self.config[
                "GITHUB_ISSUE_NUMBER"
            ],
            "EMILIA_ACTUATOR_ENVELOPE_ISSUER_ID": self.config[
                "ENVELOPE_ISSUER_ID"
            ],
            "EMILIA_ACTUATOR_ENVELOPE_KEY_ID": self.config["ENVELOPE_KEY_ID"],
            "EMILIA_ACTUATOR_OBSERVATION_ISSUER_ID": self.config[
                "OBSERVATION_ISSUER_ID"
            ],
            "EMILIA_ACTUATOR_OBSERVATION_KEY_ID": self.config[
                "OBSERVATION_KEY_ID"
            ],
        }

    def decision_plain_environment(self) -> dict[str, str]:
        return {
            "NODE_ENV": "production",
            "HOST": "0.0.0.0",
            "EMILIA_CONSEQUENCE_CONFIG": (
                "apps/consequence-control-service/src/production-config.js"
            ),
            "EMILIA_CONSEQUENCE_TENANT_ID": self.config["TENANT_ID"],
            "EMILIA_CONSEQUENCE_RELYING_PARTY_ID": self.config[
                "DECISION_RELYING_PARTY_ID"
            ],
            "EMILIA_CONSEQUENCE_EXECUTOR_ID": self.config[
                "DECISION_EXECUTOR_ID"
            ],
            "EMILIA_CONSEQUENCE_PRINCIPAL_ID": self.config[
                "DECISION_PRINCIPAL_ID"
            ],
            "EMILIA_CONSEQUENCE_APPROVAL_ENDPOINT": self.config[
                "DECISION_APPROVAL_ENDPOINT"
            ],
            "EMILIA_CONSEQUENCE_GITHUB_OWNER": self.config["GITHUB_OWNER"],
            "EMILIA_CONSEQUENCE_GITHUB_REPO": self.config["GITHUB_REPO"],
            "EMILIA_CONSEQUENCE_GITHUB_ISSUE_NUMBER": self.config[
                "GITHUB_ISSUE_NUMBER"
            ],
            "EMILIA_CONSEQUENCE_PROPOSAL_TTL_SEC": self.config[
                "DECISION_PROPOSAL_TTL_SEC"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_ORIGIN": self.actuator_tagged_url,
            "EMILIA_CONSEQUENCE_ACTUATOR_AUDIENCE": self.actuator_audience,
            "EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_ISSUER_ID": self.config[
                "ENVELOPE_ISSUER_ID"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_KEY_ID": self.config[
                "ENVELOPE_KEY_ID"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_OBSERVATION_ISSUER_ID": self.config[
                "OBSERVATION_ISSUER_ID"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_EVIDENCE_KEY_ID": self.config[
                "OBSERVATION_KEY_ID"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_TIMEOUT_MS": self.config[
                "DECISION_ACTUATOR_TIMEOUT_MS"
            ],
            "EMILIA_CONSEQUENCE_AEB_REQUIREMENT_REF": self.config[
                "DECISION_AEB_REQUIREMENT_REF"
            ],
            "EMILIA_CONSEQUENCE_SHUTDOWN_GRACE_MS": self.config[
                "DECISION_SHUTDOWN_GRACE_MS"
            ],
        }

    def valid_resources(self) -> dict[tuple[str, str], dict]:
        actuator_service = self.config["ACTUATOR_SERVICE"]
        decision_service = self.config["DECISION_SERVICE"]
        actuator_environment = plain_environment(
            self.actuator_plain_environment()
        )
        actuator_environment.extend(
            secret_environment(
                self.config,
                verify_canary.ACTUATOR_SECRET_BINDINGS,
            )
        )
        decision_environment = plain_environment(
            self.decision_plain_environment()
        )
        decision_environment.extend(
            secret_environment(
                self.config,
                verify_canary.DECISION_SECRET_BINDINGS,
            )
        )
        return {
            ("services", actuator_service): self.service(
                actuator_service,
                "actuator",
                self.actuator_revision,
                self.actuator_tagged_url,
                self.actuator_audience,
                self.config["ACTUATOR_INGRESS"],
            ),
            ("services", decision_service): self.service(
                decision_service,
                "decision",
                self.decision_revision,
                self.decision_tagged_url,
                "https://emilia-consequence-control.example.run.app",
                self.config["DECISION_INGRESS"],
            ),
            ("revisions", self.actuator_revision): self.revision(
                self.actuator_revision,
                actuator_service,
                "actuator",
                self.config["ACTUATOR_IMAGE"],
                (
                    f"{self.config['ACTUATOR_SERVICE_ACCOUNT']}@"
                    f"{self.config['PROJECT_ID']}.iam.gserviceaccount.com"
                ),
                self.config["ACTUATOR_CPU"],
                self.config["ACTUATOR_MEMORY"],
                self.config["ACTUATOR_MIN_INSTANCES"],
                self.config["ACTUATOR_MAX_INSTANCES"],
                int(self.config["ACTUATOR_CONCURRENCY"]),
                30,
                actuator_environment,
            ),
            ("revisions", self.decision_revision): self.revision(
                self.decision_revision,
                decision_service,
                "decision",
                self.config["DECISION_IMAGE"],
                (
                    f"{self.config['DECISION_SERVICE_ACCOUNT']}@"
                    f"{self.config['PROJECT_ID']}.iam.gserviceaccount.com"
                ),
                self.config["DECISION_CPU"],
                self.config["DECISION_MEMORY"],
                self.config["DECISION_MIN_INSTANCES"],
                self.config["DECISION_MAX_INSTANCES"],
                int(self.config["DECISION_CONCURRENCY"]),
                60,
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

    def test_plaintext_environment_set_and_values_are_closed(self) -> None:
        baseline = copy.deepcopy(self.resources)
        cases = {
            "actuator-wrong-value": (
                self.actuator_revision,
                lambda environment: next(
                    item
                    for item in environment
                    if item["name"] == "EMILIA_ACTUATOR_TENANT_ID"
                ).__setitem__("value", "tenant:hostile"),
            ),
            "actuator-extra": (
                self.actuator_revision,
                lambda environment: environment.append(
                    {"name": "HOSTILE_ACTUATOR_FLAG", "value": "enabled"}
                ),
            ),
            "decision-missing": (
                self.decision_revision,
                lambda environment: environment.__setitem__(
                    slice(None),
                    [
                        item
                        for item in environment
                        if item["name"] != "EMILIA_CONSEQUENCE_CONFIG"
                    ],
                ),
            ),
            "decision-wrong-value": (
                self.decision_revision,
                lambda environment: next(
                    item
                    for item in environment
                    if item["name"] == "EMILIA_CONSEQUENCE_PROPOSAL_TTL_SEC"
                ).__setitem__("value", "1"),
            ),
        }
        for label, (revision, mutate) in cases.items():
            with self.subTest(label=label):
                self.resources = copy.deepcopy(baseline)
                environment = self.resources[
                    ("revisions", revision)
                ]["spec"]["containers"][0]["env"]
                mutate(environment)
                with self.assertRaisesRegex(ValueError, "environment|projection"):
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
                with self.assertRaisesRegex(
                    ValueError,
                    "tag revision|service projection",
                ):
                    self.verify()

    def test_canary_traffic_tag_percent_is_zero(self) -> None:
        baseline = copy.deepcopy(self.resources)
        for service_key in ("ACTUATOR_SERVICE", "DECISION_SERVICE"):
            with self.subTest(service=service_key):
                self.resources = copy.deepcopy(baseline)
                service = self.resources[
                    ("services", self.config[service_key])
                ]
                service["status"]["traffic"][0]["percent"] = 1
                with self.assertRaisesRegex(ValueError, "percent|projection"):
                    self.verify()

    def test_observed_generation_must_match_service_generation(self) -> None:
        baseline = copy.deepcopy(self.resources)
        for service_key in ("ACTUATOR_SERVICE", "DECISION_SERVICE"):
            with self.subTest(service=service_key):
                self.resources = copy.deepcopy(baseline)
                service = self.resources[
                    ("services", self.config[service_key])
                ]
                service["status"]["observedGeneration"] = 6
                with self.assertRaisesRegex(
                    ValueError,
                    "observed generation|projection",
                ):
                    self.verify()

    def test_image_and_runtime_service_account_are_closed(self) -> None:
        baseline = copy.deepcopy(self.resources)
        for revision in (self.actuator_revision, self.decision_revision):
            for field in ("image", "service-account"):
                with self.subTest(revision=revision, field=field):
                    self.resources = copy.deepcopy(baseline)
                    value = self.resources[("revisions", revision)]
                    if field == "image":
                        value["spec"]["containers"][0]["image"] = (
                            "us-central1-docker.pkg.dev/test-project/runtime/"
                            "hostile@sha256:"
                            + "c" * 64
                        )
                    else:
                        value["spec"]["serviceAccountName"] = (
                            "substituted@test-project.iam.gserviceaccount.com"
                        )
                    with self.assertRaisesRegex(
                        ValueError,
                        "image|service account|projection",
                    ):
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

    def test_secret_environment_set_is_closed(self) -> None:
        decision = self.resources[("revisions", self.decision_revision)]
        decision["spec"]["containers"][0]["env"].append(
            {
                "name": "HOSTILE_SECRET",
                "valueFrom": {
                    "secretKeyRef": {
                        "key": "1",
                        "name": "hostile-secret",
                    }
                },
            }
        )
        with self.assertRaisesRegex(ValueError, "secret environment|projection"):
            self.verify()

    def test_ingress_is_closed_for_both_services(self) -> None:
        baseline = copy.deepcopy(self.resources)
        for service_key in ("ACTUATOR_SERVICE", "DECISION_SERVICE"):
            with self.subTest(service=service_key):
                self.resources = copy.deepcopy(baseline)
                service = self.resources[
                    ("services", self.config[service_key])
                ]
                service["metadata"]["annotations"][
                    "run.googleapis.com/ingress"
                ] = "internal-and-cloud-load-balancing"
                with self.assertRaisesRegex(ValueError, "ingress|projection"):
                    self.verify()

    def test_direct_vpc_network_and_egress_are_closed(self) -> None:
        baseline = copy.deepcopy(self.resources)
        cases = {
            "wrong-network": lambda revision: revision["metadata"][
                "annotations"
            ].__setitem__(
                "run.googleapis.com/network-interfaces",
                json.dumps(
                    [
                        {
                            "network": "wrong-network",
                            "subnetwork": self.config["SUBNET"],
                        }
                    ]
                ),
            ),
            "network-tags": lambda revision: revision["metadata"][
                "annotations"
            ].__setitem__(
                "run.googleapis.com/network-interfaces",
                json.dumps(
                    [
                        {
                            "network": self.config["NETWORK"],
                            "subnetwork": self.config["SUBNET"],
                            "tags": ["hostile"],
                        }
                    ]
                ),
            ),
            "vpc-connector": lambda revision: revision["metadata"][
                "annotations"
            ].__setitem__(
                "run.googleapis.com/vpc-access-connector",
                "projects/test/locations/us-central1/connectors/hostile",
            ),
            "egress": lambda revision: revision["metadata"][
                "annotations"
            ].__setitem__(
                "run.googleapis.com/vpc-access-egress",
                "private-ranges-only",
            ),
        }
        for candidate in (self.actuator_revision, self.decision_revision):
            for label, mutate in cases.items():
                with self.subTest(revision=candidate, label=label):
                    self.resources = copy.deepcopy(baseline)
                    revision = self.resources[("revisions", candidate)]
                    mutate(revision)
                    with self.assertRaisesRegex(
                        ValueError,
                        "network|VPC|annotation|projection",
                    ):
                        self.verify()

    def test_cpu_memory_scaling_concurrency_and_timeout_are_closed(self) -> None:
        baseline = copy.deepcopy(self.resources)
        mutations = {
            "cpu": lambda revision: revision["spec"]["containers"][0][
                "resources"
            ]["limits"].__setitem__("cpu", "2"),
            "memory": lambda revision: revision["spec"]["containers"][0][
                "resources"
            ]["limits"].__setitem__("memory", "4Gi"),
            "minimum": lambda revision: revision["metadata"]["annotations"].__setitem__(
                "autoscaling.knative.dev/minScale",
                "0",
            ),
            "maximum": lambda revision: revision["metadata"]["annotations"].__setitem__(
                "autoscaling.knative.dev/maxScale",
                "99",
            ),
            "concurrency": lambda revision: revision["spec"].__setitem__(
                "containerConcurrency",
                1,
            ),
            "timeout": lambda revision: revision["spec"].__setitem__(
                "timeoutSeconds",
                900,
            ),
        }
        for candidate in (self.actuator_revision, self.decision_revision):
            for label, mutate in mutations.items():
                with self.subTest(revision=candidate, label=label):
                    self.resources = copy.deepcopy(baseline)
                    mutate(self.resources[("revisions", candidate)])
                    with self.assertRaisesRegex(ValueError, "projection"):
                        self.verify()

    def test_ports_are_closed(self) -> None:
        baseline = copy.deepcopy(self.resources)
        for candidate in (self.actuator_revision, self.decision_revision):
            with self.subTest(revision=candidate):
                self.resources = copy.deepcopy(baseline)
                container = self.resources[
                    ("revisions", candidate)
                ]["spec"]["containers"][0]
                container["ports"][0]["containerPort"] = 9090
                with self.assertRaisesRegex(
                    ValueError,
                    "projection|must contain exactly",
                ):
                    self.verify()

    def test_startup_liveness_and_readiness_probes_are_closed(self) -> None:
        baseline = copy.deepcopy(self.resources)
        cases = {
            "actuator-startup": (
                self.actuator_revision,
                lambda container: container["startupProbe"].__setitem__(
                    "failureThreshold",
                    1,
                ),
            ),
            "actuator-unexpected-liveness": (
                self.actuator_revision,
                lambda container: container.__setitem__(
                    "livenessProbe",
                    {
                        "failureThreshold": 1,
                        "httpGet": {"path": "/hostile", "port": 8080},
                        "periodSeconds": 1,
                        "timeoutSeconds": 1,
                    },
                ),
            ),
            "decision-startup": (
                self.decision_revision,
                lambda container: container["startupProbe"]["httpGet"].__setitem__(
                    "path",
                    "/hostile",
                ),
            ),
            "decision-liveness": (
                self.decision_revision,
                lambda container: container["livenessProbe"].__setitem__(
                    "periodSeconds",
                    1,
                ),
            ),
            "decision-readiness": (
                self.decision_revision,
                lambda container: container["readinessProbe"].__setitem__(
                    "failureThreshold",
                    99,
                ),
            ),
        }
        for label, (revision, mutate) in cases.items():
            with self.subTest(label=label):
                self.resources = copy.deepcopy(baseline)
                container = self.resources[
                    ("revisions", revision)
                ]["spec"]["containers"][0]
                mutate(container)
                with self.assertRaisesRegex(
                    ValueError,
                    "projection|must contain exactly",
                ):
                    self.verify()

    def test_execution_environment_and_session_affinity_are_closed(self) -> None:
        baseline = copy.deepcopy(self.resources)
        for candidate in (self.actuator_revision, self.decision_revision):
            for annotation, value in (
                ("run.googleapis.com/execution-environment", "gen1"),
                ("run.googleapis.com/sessionAffinity", "true"),
            ):
                with self.subTest(revision=candidate, annotation=annotation):
                    self.resources = copy.deepcopy(baseline)
                    revision = self.resources[("revisions", candidate)]
                    revision["metadata"]["annotations"][annotation] = value
                    with self.assertRaisesRegex(
                        ValueError,
                        "annotation|projection",
                    ):
                        self.verify()

    def test_behavior_affecting_labels_and_annotations_are_closed(self) -> None:
        baseline = copy.deepcopy(self.resources)
        cases = {
            "service-label": lambda resources: resources[
                ("services", self.config["ACTUATOR_SERVICE"])
            ]["metadata"]["labels"].__setitem__("hostile-mode", "enabled"),
            "revision-label": lambda resources: resources[
                ("revisions", self.actuator_revision)
            ]["metadata"]["labels"].__setitem__("hostile-mode", "enabled"),
            "service-annotation": lambda resources: resources[
                ("services", self.config["DECISION_SERVICE"])
            ]["metadata"]["annotations"].__setitem__(
                "run.googleapis.com/custom-audiences",
                '["https://hostile.example"]',
            ),
            "revision-annotation": lambda resources: resources[
                ("revisions", self.decision_revision)
            ]["metadata"]["annotations"].__setitem__(
                "run.googleapis.com/cloudsql-instances",
                "test-project:us-central1:hostile",
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                self.resources = copy.deepcopy(baseline)
                mutate(self.resources)
                with self.assertRaisesRegex(
                    ValueError,
                    "label|annotation|projection",
                ):
                    self.verify()

    def test_unexpected_behavior_fields_are_refused(self) -> None:
        baseline = copy.deepcopy(self.resources)
        cases = {
            "spec-volume": lambda revision: revision["spec"].__setitem__(
                "volumes",
                [{"name": "hostile", "emptyDir": {}}],
            ),
            "spec-accelerator": lambda revision: revision["spec"].__setitem__(
                "nodeSelector",
                {"run.googleapis.com/accelerator": "nvidia-l4"},
            ),
            "container-command": lambda revision: revision["spec"][
                "containers"
            ][0].__setitem__("command", ["/hostile"]),
            "resource-gpu": lambda revision: revision["spec"]["containers"][0][
                "resources"
            ]["limits"].__setitem__("nvidia.com/gpu", "1"),
            "probe-header": lambda revision: revision["spec"]["containers"][0][
                "startupProbe"
            ].setdefault("httpGet", {"path": "/", "port": 8080}).__setitem__(
                "httpHeaders",
                [{"name": "X-Hostile", "value": "true"}],
            ),
            "traffic-field": lambda revision: self.resources[
                ("services", self.config["ACTUATOR_SERVICE"])
            ]["status"]["traffic"][0].__setitem__("latestRevision", True),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                self.resources = copy.deepcopy(baseline)
                revision = self.resources[
                    ("revisions", self.actuator_revision)
                ]
                mutate(revision)
                with self.assertRaisesRegex(ValueError, "projection|exactly"):
                    self.verify()

if __name__ == "__main__":
    unittest.main()
