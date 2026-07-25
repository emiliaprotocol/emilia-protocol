"""Closed Cloud Run service/revision fixtures for promotion tests."""

from __future__ import annotations

import json


ACTUATOR_SECRET_BINDINGS = {
    "EMILIA_ACTUATOR_DATABASE_URL": "ACTUATOR_DATABASE_URL_SECRET",
    "EMILIA_ACTUATOR_API_TOKEN": "ACTUATOR_API_TOKEN_SECRET",
    "EMILIA_ACTUATOR_ENVELOPE_PUBLIC_KEY": (
        "ACTUATOR_ENVELOPE_PUBLIC_KEY_SECRET"
    ),
    "EMILIA_ACTUATOR_OBSERVATION_PRIVATE_KEY": (
        "ACTUATOR_OBSERVATION_PRIVATE_KEY_SECRET"
    ),
    "EMILIA_ACTUATOR_GITHUB_APP_ID": "ACTUATOR_GITHUB_APP_ID_SECRET",
    "EMILIA_ACTUATOR_GITHUB_INSTALLATION_ID": (
        "ACTUATOR_GITHUB_INSTALLATION_ID_SECRET"
    ),
    "EMILIA_ACTUATOR_GITHUB_PRIVATE_KEY": (
        "ACTUATOR_GITHUB_PRIVATE_KEY_SECRET"
    ),
}

DECISION_SECRET_BINDINGS = {
    "EMILIA_CONSEQUENCE_EXECUTOR_DATABASE_URL": (
        "DECISION_EXECUTOR_DATABASE_URL_SECRET"
    ),
    "EMILIA_CONSEQUENCE_RECOVERY_DATABASE_URL": (
        "DECISION_RECOVERY_DATABASE_URL_SECRET"
    ),
    "EMILIA_CONSEQUENCE_API_TOKEN": "DECISION_API_TOKEN_SECRET",
    "EMILIA_CONSEQUENCE_RECOVERY_TOKEN": "DECISION_RECOVERY_TOKEN_SECRET",
    "EMILIA_CONSEQUENCE_PROPOSAL_HMAC_KEY": (
        "DECISION_PROPOSAL_HMAC_KEY_SECRET"
    ),
    "EMILIA_CONSEQUENCE_OWNER_HMAC_KEY": "DECISION_OWNER_HMAC_KEY_SECRET",
    "EMILIA_CONSEQUENCE_GATE_TRUST_JSON": "DECISION_GATE_TRUST_JSON_SECRET",
    "EMILIA_CONSEQUENCE_AEB_CONFIG_JSON": "DECISION_AEB_CONFIG_JSON_SECRET",
    "EMILIA_CONSEQUENCE_STATUS_CONFIG_JSON": (
        "DECISION_STATUS_CONFIG_JSON_SECRET"
    ),
    "EMILIA_CONSEQUENCE_APPROVAL_TOKEN": "DECISION_APPROVAL_TOKEN_SECRET",
    "EMILIA_CONSEQUENCE_ACTUATOR_API_TOKEN": "ACTUATOR_API_TOKEN_SECRET",
    "EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_PRIVATE_KEY": (
        "DECISION_ENVELOPE_PRIVATE_KEY_SECRET"
    ),
    "EMILIA_CONSEQUENCE_ACTUATOR_EVIDENCE_PUBLIC_KEY": (
        "DECISION_OBSERVATION_PUBLIC_KEY_SECRET"
    ),
}


def load_env(path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        key, value = raw.split("=", 1)
        result[key] = value
    return result


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


def build_live_resources(
    config: dict[str, str],
    *,
    actuator_tagged_url: str = (
        "https://canary-actuator---emilia-consequence-actuator.example.run.app"
    ),
    decision_tagged_url: str = (
        "https://canary-decision---emilia-consequence-control.example.run.app"
    ),
) -> dict[str, dict]:
    actuator_service = config["ACTUATOR_SERVICE"]
    decision_service = config["DECISION_SERVICE"]
    actuator_revision = f"{actuator_service}-{config['RELEASE_ID']}"
    decision_revision = f"{decision_service}-{config['RELEASE_ID']}"
    tag = f"canary-{config['RELEASE_ID']}"
    actuator_audience = (
        f"https://{actuator_service}.{config['REGION']}.example.run.app"
    )
    decision_audience = (
        f"https://{decision_service}.{config['REGION']}.example.run.app"
    )

    def service(
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
                    "cloud.googleapis.com/location": config["REGION"],
                    "emilia-plane": plane,
                    "emilia-release": config["RELEASE_ID"],
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
                        "tag": tag,
                        "url": tagged_url,
                    }
                ],
            },
        }

    def revision(
        name: str,
        service_name: str,
        plane: str,
        image: str,
        service_account: str,
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
            "ports": [{"containerPort": 8080, "name": "http1"}],
            "startupProbe": {
                "failureThreshold": 30,
                "initialDelaySeconds": 0,
                "periodSeconds": 2,
                "successThreshold": 1,
                "timeoutSeconds": 1,
                ("tcpSocket" if plane == "actuator" else "httpGet"): (
                    {"port": 8080}
                    if plane == "actuator"
                    else {"path": "/v1/ready", "port": 8080}
                ),
            },
        }
        if plane == "decision":
            container["livenessProbe"] = {
                "failureThreshold": 3,
                "httpGet": {"path": "/v1/live", "port": 8080},
                "initialDelaySeconds": 10,
                "periodSeconds": 30,
                "successThreshold": 1,
                "timeoutSeconds": 2,
            }
            container["readinessProbe"] = {
                "failureThreshold": 3,
                "httpGet": {"path": "/v1/ready", "port": 8080},
                "periodSeconds": 5,
                "successThreshold": 1,
                "timeoutSeconds": 2,
            }
        return {
            "metadata": {
                "name": name,
                "labels": {
                    "cloud.googleapis.com/location": config["REGION"],
                    "emilia-plane": plane,
                    "emilia-release": config["RELEASE_ID"],
                    "serving.knative.dev/service": service_name,
                },
                "annotations": {
                    "autoscaling.knative.dev/maxScale": maximum,
                    "autoscaling.knative.dev/minScale": minimum,
                    "run.googleapis.com/client-name": "gcloud",
                    "run.googleapis.com/execution-environment": "gen2",
                    "run.googleapis.com/network-interfaces": json.dumps(
                        [
                            {
                                "network": config["NETWORK"],
                                "subnetwork": config["SUBNET"],
                            }
                        ]
                    ),
                    "run.googleapis.com/vpc-access-egress": "all-traffic",
                },
            },
            "spec": {
                "containerConcurrency": concurrency,
                "timeoutSeconds": timeout,
                "serviceAccountName": service_account,
                "containers": [container],
            },
        }

    actuator_environment = [
        {"name": name, "value": value}
        for name, value in {
            "NODE_ENV": "production",
            "HOST": "0.0.0.0",
            "EMILIA_ACTUATOR_DATABASE_PRINCIPAL": config[
                "ACTUATOR_DATABASE_PRINCIPAL"
            ],
            "EMILIA_ACTUATOR_TENANT_ID": config["TENANT_ID"],
            "EMILIA_ACTUATOR_GITHUB_OWNER": config["GITHUB_OWNER"],
            "EMILIA_ACTUATOR_GITHUB_REPO": config["GITHUB_REPO"],
            "EMILIA_ACTUATOR_GITHUB_ISSUE_NUMBER": config[
                "GITHUB_ISSUE_NUMBER"
            ],
            "EMILIA_ACTUATOR_ENVELOPE_ISSUER_ID": config[
                "ENVELOPE_ISSUER_ID"
            ],
            "EMILIA_ACTUATOR_ENVELOPE_KEY_ID": config["ENVELOPE_KEY_ID"],
            "EMILIA_ACTUATOR_OBSERVATION_ISSUER_ID": config[
                "OBSERVATION_ISSUER_ID"
            ],
            "EMILIA_ACTUATOR_OBSERVATION_KEY_ID": config[
                "OBSERVATION_KEY_ID"
            ],
        }.items()
    ]
    actuator_environment.extend(
        secret_environment(config, ACTUATOR_SECRET_BINDINGS)
    )
    decision_environment = [
        {"name": name, "value": value}
        for name, value in {
            "NODE_ENV": "production",
            "HOST": "0.0.0.0",
            "EMILIA_CONSEQUENCE_CONFIG": (
                "apps/consequence-control-service/src/production-config.js"
            ),
            "EMILIA_CONSEQUENCE_TENANT_ID": config["TENANT_ID"],
            "EMILIA_CONSEQUENCE_RELYING_PARTY_ID": config[
                "DECISION_RELYING_PARTY_ID"
            ],
            "EMILIA_CONSEQUENCE_EXECUTOR_ID": config[
                "DECISION_EXECUTOR_ID"
            ],
            "EMILIA_CONSEQUENCE_PRINCIPAL_ID": config[
                "DECISION_PRINCIPAL_ID"
            ],
            "EMILIA_CONSEQUENCE_APPROVAL_ENDPOINT": config[
                "DECISION_APPROVAL_ENDPOINT"
            ],
            "EMILIA_CONSEQUENCE_GITHUB_OWNER": config["GITHUB_OWNER"],
            "EMILIA_CONSEQUENCE_GITHUB_REPO": config["GITHUB_REPO"],
            "EMILIA_CONSEQUENCE_GITHUB_ISSUE_NUMBER": config[
                "GITHUB_ISSUE_NUMBER"
            ],
            "EMILIA_CONSEQUENCE_PROPOSAL_TTL_SEC": config[
                "DECISION_PROPOSAL_TTL_SEC"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_ORIGIN": actuator_tagged_url,
            "EMILIA_CONSEQUENCE_ACTUATOR_AUDIENCE": actuator_audience,
            "EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_ISSUER_ID": config[
                "ENVELOPE_ISSUER_ID"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_KEY_ID": config[
                "ENVELOPE_KEY_ID"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_OBSERVATION_ISSUER_ID": config[
                "OBSERVATION_ISSUER_ID"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_EVIDENCE_KEY_ID": config[
                "OBSERVATION_KEY_ID"
            ],
            "EMILIA_CONSEQUENCE_ACTUATOR_TIMEOUT_MS": config[
                "DECISION_ACTUATOR_TIMEOUT_MS"
            ],
            "EMILIA_CONSEQUENCE_AEB_REQUIREMENT_REF": config[
                "DECISION_AEB_REQUIREMENT_REF"
            ],
            "EMILIA_CONSEQUENCE_SHUTDOWN_GRACE_MS": config[
                "DECISION_SHUTDOWN_GRACE_MS"
            ],
        }.items()
    ]
    decision_environment.extend(
        secret_environment(config, DECISION_SECRET_BINDINGS)
    )
    return {
        f"services:{actuator_service}": service(
            actuator_service,
            "actuator",
            actuator_revision,
            actuator_tagged_url,
            actuator_audience,
            config["ACTUATOR_INGRESS"],
        ),
        f"services:{decision_service}": service(
            decision_service,
            "decision",
            decision_revision,
            decision_tagged_url,
            decision_audience,
            config["DECISION_INGRESS"],
        ),
        f"revisions:{actuator_revision}": revision(
            actuator_revision,
            actuator_service,
            "actuator",
            config["ACTUATOR_IMAGE"],
            (
                f"{config['ACTUATOR_SERVICE_ACCOUNT']}@"
                f"{config['PROJECT_ID']}.iam.gserviceaccount.com"
            ),
            config["ACTUATOR_CPU"],
            config["ACTUATOR_MEMORY"],
            config["ACTUATOR_MIN_INSTANCES"],
            config["ACTUATOR_MAX_INSTANCES"],
            int(config["ACTUATOR_CONCURRENCY"]),
            30,
            actuator_environment,
        ),
        f"revisions:{decision_revision}": revision(
            decision_revision,
            decision_service,
            "decision",
            config["DECISION_IMAGE"],
            (
                f"{config['DECISION_SERVICE_ACCOUNT']}@"
                f"{config['PROJECT_ID']}.iam.gserviceaccount.com"
            ),
            config["DECISION_CPU"],
            config["DECISION_MEMORY"],
            config["DECISION_MIN_INSTANCES"],
            config["DECISION_MAX_INSTANCES"],
            int(config["DECISION_CONCURRENCY"]),
            60,
            decision_environment,
        ),
    }
