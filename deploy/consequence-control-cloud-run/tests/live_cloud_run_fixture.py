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
        revision: str,
        tagged_url: str,
        canonical_url: str,
        ingress: str,
    ) -> dict:
        return {
            "metadata": {
                "name": name,
                "annotations": {"run.googleapis.com/ingress": ingress},
            },
            "status": {
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
        image: str,
        service_account: str,
        environment: list[dict],
    ) -> dict:
        return {
            "metadata": {
                "name": name,
                "labels": {"serving.knative.dev/service": service_name},
                "annotations": {
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
                "serviceAccountName": service_account,
                "containers": [{"image": image, "env": environment}],
            },
        }

    actuator_environment = secret_environment(
        config,
        ACTUATOR_SECRET_BINDINGS,
    )
    decision_environment = secret_environment(
        config,
        DECISION_SECRET_BINDINGS,
    )
    decision_environment.extend(
        [
            {
                "name": "EMILIA_CONSEQUENCE_ACTUATOR_ORIGIN",
                "value": actuator_tagged_url,
            },
            {
                "name": "EMILIA_CONSEQUENCE_ACTUATOR_AUDIENCE",
                "value": actuator_audience,
            },
        ]
    )
    return {
        f"services:{actuator_service}": service(
            actuator_service,
            actuator_revision,
            actuator_tagged_url,
            actuator_audience,
            config["ACTUATOR_INGRESS"],
        ),
        f"services:{decision_service}": service(
            decision_service,
            decision_revision,
            decision_tagged_url,
            decision_audience,
            config["DECISION_INGRESS"],
        ),
        f"revisions:{actuator_revision}": revision(
            actuator_revision,
            actuator_service,
            config["ACTUATOR_IMAGE"],
            (
                f"{config['ACTUATOR_SERVICE_ACCOUNT']}@"
                f"{config['PROJECT_ID']}.iam.gserviceaccount.com"
            ),
            actuator_environment,
        ),
        f"revisions:{decision_revision}": revision(
            decision_revision,
            decision_service,
            config["DECISION_IMAGE"],
            (
                f"{config['DECISION_SERVICE_ACCOUNT']}@"
                f"{config['PROJECT_ID']}.iam.gserviceaccount.com"
            ),
            decision_environment,
        ),
    }
