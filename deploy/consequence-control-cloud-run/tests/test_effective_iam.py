from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

LANE = Path(__file__).resolve().parents[1]
SCRIPT = LANE / "verify-effective-iam.py"
SPEC = importlib.util.spec_from_file_location("verify_effective_iam", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verify_effective_iam = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_effective_iam)

VERSION = "emilia-effective-iam/v1"
PROJECT_SCOPE = "projects/test-project"
ACTUATOR_RESOURCE = (
    "//run.googleapis.com/projects/test-project/locations/us-central1/"
    "services/emilia-consequence-actuator"
)
SECRET_RESOURCE = (
    "//secretmanager.googleapis.com/projects/123456789/secrets/actuator-token"
)
DECISION = "serviceAccount:emilia-decision@test-project.iam.gserviceaccount.com"
ACTUATOR = "serviceAccount:emilia-actuator@test-project.iam.gserviceaccount.com"
COMPUTE_AGENT = (
    "serviceAccount:service-123456789@compute-system.iam.gserviceaccount.com"
)
RUN_AGENT = (
    "serviceAccount:"
    "service-123456789@serverless-robot-prod.iam.gserviceaccount.com"
)
STANDALONE_ANCESTRY = [{"type": "project", "id": "test-project"}]
DEPLOYER = "user:deployer@example.com"
ACTUATOR_SA_RESOURCE = (
    "//iam.googleapis.com/projects/test-project/serviceAccounts/"
    "emilia-actuator@test-project.iam.gserviceaccount.com"
)
DECISION_SA_RESOURCE = (
    "//iam.googleapis.com/projects/test-project/serviceAccounts/"
    "emilia-decision@test-project.iam.gserviceaccount.com"
)
JIT_ISSUED_AT = "2026-07-25T18:00:00Z"
JIT_EXPIRES_AT = "2026-07-25T18:15:00Z"


def result(
    *,
    resource: str,
    permission: str,
    identities: list[str],
    role: str,
    attached_resource: str | None = None,
    members: list[str] | None = None,
    group_edges: list[dict[str, str]] | None = None,
) -> dict:
    identity_list: dict[str, object] = {
        "identities": [{"name": identity} for identity in identities],
    }
    if group_edges is not None:
        identity_list["groupEdges"] = group_edges
    return {
        "attachedResourceFullName": attached_resource or resource,
        "iamBinding": {
            "role": role,
            "members": members if members is not None else identities,
        },
        "accessControlLists": [
            {
                "resources": [{"fullResourceName": resource}],
                "accesses": [{"permission": permission}],
            }
        ],
        "identityList": identity_list,
        "fullyExplored": True,
    }


def response(
    *,
    resource: str,
    permission: str,
    identities: list[str],
    role: str,
    attached_resource: str | None = None,
    members: list[str] | None = None,
    group_edges: list[dict[str, str]] | None = None,
) -> dict:
    return {
        "mainAnalysis": {
            "analysisQuery": {
                "scope": PROJECT_SCOPE,
                "resourceSelector": {"fullResourceName": resource},
                "accessSelector": {"permissions": [permission]},
                "options": {
                    "expandGroups": True,
                    "outputGroupEdges": True,
                    "analyzeServiceAccountImpersonation": True,
                },
            },
            "analysisResults": [
                result(
                    resource=resource,
                    permission=permission,
                    identities=identities,
                    role=role,
                    attached_resource=attached_resource,
                    members=members,
                    group_edges=group_edges,
                )
            ],
            "fullyExplored": True,
        },
        "serviceAccountImpersonationAnalysis": [],
        "fullyExplored": True,
    }


def impersonation_analysis(
    service_account: str,
    identities: list[str],
    *,
    permission: str = "iam.serviceAccounts.actAs",
) -> dict:
    account = service_account.removeprefix("serviceAccount:")
    resource = (
        "//iam.googleapis.com/projects/test-project/serviceAccounts/" + account
    )
    return {
        "analysisQuery": {
            "scope": PROJECT_SCOPE,
            "resourceSelector": {"fullResourceName": resource},
            "accessSelector": {"permissions": [permission]},
            "options": {
                "expandGroups": True,
                "outputGroupEdges": True,
            },
        },
        "analysisResults": [
            result(
                resource=resource,
                permission=permission,
                identities=identities,
                role="roles/run.serviceAgent",
            )
        ],
        "fullyExplored": True,
    }


def set_scope(value: dict, scope: str) -> None:
    def update_analysis(analysis: dict) -> None:
        analysis["mainAnalysis"]["analysisQuery"]["scope"] = scope
        for impersonation in analysis.get(
            "serviceAccountImpersonationAnalysis", []
        ):
            impersonation["analysisQuery"]["scope"] = scope

    for target in value["targets"]:
        target["scope"] = scope
        analysis = target.get("analysis")
        if analysis is None:
            continue
        if target["kind"] == "runtimeActAs":
            for phase_analysis in analysis.values():
                update_analysis(phase_analysis)
        else:
            update_analysis(analysis)


def empty_response(*, resource: str, permission: str) -> dict:
    value = response(
        resource=resource,
        permission=permission,
        identities=[DEPLOYER],
        role="roles/iam.serviceAccountUser",
    )
    value["mainAnalysis"]["analysisResults"] = []
    return value


def jit_condition(label: str) -> dict[str, str]:
    return {
        "title": f"emilia-jit-actas-r20260725b-{label}",
        "description": (
            f"EMILIA r20260725b {label} rollout; hard expiry 900s"
        ),
        "expression": (
            "request.time < timestamp('2026-07-25T18:15:00Z')"
        ),
    }


def active_jit_response(*, resource: str, label: str) -> dict:
    value = response(
        resource=resource,
        permission="iam.serviceAccounts.actAs",
        identities=[DEPLOYER],
        role="roles/iam.serviceAccountUser",
    )
    query = value["mainAnalysis"]["analysisQuery"]
    query["conditionContext"] = {"accessTime": JIT_ISSUED_AT}
    binding = value["mainAnalysis"]["analysisResults"][0]["iamBinding"]
    binding["condition"] = jit_condition(label)
    acl = value["mainAnalysis"]["analysisResults"][0]["accessControlLists"][0]
    acl["conditionEvaluation"] = {"evaluationValue": "TRUE"}
    return value


def jit_manifest() -> dict:
    value = manifest()
    for label, resource in (
        ("actuator", ACTUATOR_SA_RESOURCE),
        ("decision", DECISION_SA_RESOURCE),
    ):
        value["targets"].append(
            {
                "name": f"runtime-actAs:{label}",
                "kind": "runtimeActAs",
                "scope": PROJECT_SCOPE,
                "resource": resource,
                "allowedPrincipals": [],
                "jitGrant": {
                    "principal": DEPLOYER,
                    "issuedAt": JIT_ISSUED_AT,
                    "expiresAt": JIT_EXPIRES_AT,
                    "maxLifetimeSeconds": 900,
                    "condition": jit_condition(label),
                },
                "analysis": {
                    "before": empty_response(
                        resource=resource,
                        permission="iam.serviceAccounts.actAs",
                    ),
                    "during": active_jit_response(
                        resource=resource,
                        label=label,
                    ),
                    "after": empty_response(
                        resource=resource,
                        permission="iam.serviceAccounts.actAs",
                    ),
                },
            }
        )
    return value


def manifest() -> dict:
    actuator_analysis = response(
        resource=ACTUATOR_RESOURCE,
        permission="run.routes.invoke",
        identities=[DECISION],
        role="roles/run.invoker",
    )
    actuator_analysis["serviceAccountImpersonationAnalysis"] = [
        impersonation_analysis(DECISION, [COMPUTE_AGENT, RUN_AGENT])
    ]
    secret_analysis = response(
        resource=SECRET_RESOURCE,
        permission="secretmanager.versions.access",
        identities=[ACTUATOR, DECISION],
        role="roles/secretmanager.secretAccessor",
    )
    secret_analysis["serviceAccountImpersonationAnalysis"] = [
        impersonation_analysis(ACTUATOR, [COMPUTE_AGENT, RUN_AGENT]),
        impersonation_analysis(DECISION, [COMPUTE_AGENT, RUN_AGENT]),
    ]
    return {
        "version": VERSION,
        "projectId": "test-project",
        "projectNumber": "123456789",
        "targets": [
            {
                "name": "actuator",
                "kind": "actuator",
                "scope": PROJECT_SCOPE,
                "resource": ACTUATOR_RESOURCE,
                "allowedPrincipals": [COMPUTE_AGENT, DECISION, RUN_AGENT],
                "analysis": actuator_analysis,
            },
            {
                "name": "secret:actuator-token",
                "kind": "secret",
                "scope": PROJECT_SCOPE,
                "resource": SECRET_RESOURCE,
                "allowedPrincipals": [
                    ACTUATOR,
                    COMPUTE_AGENT,
                    DECISION,
                    RUN_AGENT,
                ],
                "analysis": secret_analysis,
            },
        ],
    }


class EffectiveIamTests(unittest.TestCase):
    def assert_refused(self, value: dict, message: str) -> None:
        with self.assertRaisesRegex(verify_effective_iam.VerificationError, message):
            verify_effective_iam.verify_manifest(value)

    def test_exact_effective_allowlists_pass(self) -> None:
        verified = verify_effective_iam.verify_manifest(manifest())
        self.assertEqual(
            verified,
            {
                "actuator": tuple(
                    sorted((COMPUTE_AGENT, DECISION, RUN_AGENT))
                ),
                "secret:actuator-token": tuple(
                    sorted(
                        (ACTUATOR, COMPUTE_AGENT, DECISION, RUN_AGENT)
                    )
                ),
            },
        )

    def test_managed_service_agents_are_proven_through_impersonation_paths(
        self,
    ) -> None:
        verified = verify_effective_iam.verify_manifest(manifest())
        self.assertIn(COMPUTE_AGENT, verified["actuator"])
        self.assertIn(RUN_AGENT, verified["actuator"])
        self.assertIn(COMPUTE_AGENT, verified["secret:actuator-token"])
        self.assertIn(RUN_AGENT, verified["secret:actuator-token"])

    def test_inherited_admin_permission_is_refused(self) -> None:
        value = manifest()
        analysis = value["targets"][0]["analysis"]["mainAnalysis"]
        analysis["analysisResults"].append(
            result(
                resource=ACTUATOR_RESOURCE,
                permission="run.routes.invoke",
                identities=["user:project-admin@example.com"],
                role="roles/owner",
                attached_resource=(
                    "//cloudresourcemanager.googleapis.com/projects/test-project"
                ),
            )
        )
        self.assert_refused(value, "nonallowlisted effective principal")

    def test_inherited_folder_admin_permission_is_refused(self) -> None:
        value = manifest()
        analysis = value["targets"][1]["analysis"]["mainAnalysis"]
        analysis["analysisResults"].append(
            result(
                resource=SECRET_RESOURCE,
                permission="secretmanager.versions.access",
                identities=["user:folder-admin@example.com"],
                role="roles/secretmanager.admin",
                attached_resource=(
                    "//cloudresourcemanager.googleapis.com/folders/123456789"
                ),
            )
        )
        self.assert_refused(value, "nonallowlisted effective principal")

    def test_inherited_organization_owner_permission_is_refused(self) -> None:
        value = manifest()
        analysis = value["targets"][0]["analysis"]["mainAnalysis"]
        analysis["analysisResults"].append(
            result(
                resource=ACTUATOR_RESOURCE,
                permission="run.routes.invoke",
                identities=["user:organization-owner@example.com"],
                role="roles/owner",
                attached_resource=(
                    "//cloudresourcemanager.googleapis.com/organizations/987654321"
                ),
            )
        )
        self.assert_refused(value, "nonallowlisted effective principal")

    def test_expanded_group_members_are_checked_as_effective_principals(self) -> None:
        value = manifest()
        target = value["targets"][0]
        target["allowedPrincipals"] = ["user:operator@example.com"]
        target["analysis"] = response(
            resource=ACTUATOR_RESOURCE,
            permission="run.routes.invoke",
            identities=[
                "group:operators@example.com",
                "user:operator@example.com",
            ],
            role="roles/run.invoker",
            members=["group:operators@example.com"],
            group_edges=[
                {
                    "sourceNode": "group:operators@example.com",
                    "targetNode": "user:operator@example.com",
                }
            ],
        )
        verified = verify_effective_iam.verify_manifest(value)
        self.assertEqual(verified["actuator"], ("user:operator@example.com",))

    def test_unexpanded_group_is_refused(self) -> None:
        value = manifest()
        target = value["targets"][0]
        target["allowedPrincipals"] = ["user:operator@example.com"]
        target["analysis"] = response(
            resource=ACTUATOR_RESOURCE,
            permission="run.routes.invoke",
            identities=["group:operators@example.com"],
            role="roles/run.invoker",
            members=["group:operators@example.com"],
        )
        self.assert_refused(value, "group was not fully expanded")

    def test_nested_unexpanded_group_is_refused(self) -> None:
        value = manifest()
        target = value["targets"][0]
        target["allowedPrincipals"] = ["user:operator@example.com"]
        target["analysis"] = response(
            resource=ACTUATOR_RESOURCE,
            permission="run.routes.invoke",
            identities=[
                "group:operators@example.com",
                "group:nested@example.com",
            ],
            role="roles/run.invoker",
            members=["group:operators@example.com"],
            group_edges=[
                {
                    "sourceNode": "group:operators@example.com",
                    "targetNode": "group:nested@example.com",
                }
            ],
        )
        self.assert_refused(value, "group was not fully expanded")

    def test_public_principal_is_refused_even_if_allowlisted(self) -> None:
        value = manifest()
        target = value["targets"][0]
        target["allowedPrincipals"] = ["allAuthenticatedUsers"]
        target["analysis"] = response(
            resource=ACTUATOR_RESOURCE,
            permission="run.routes.invoke",
            identities=["allAuthenticatedUsers"],
            role="roles/run.invoker",
        )
        self.assert_refused(value, "public or aggregate principal")

    def test_domain_principal_is_refused_even_if_allowlisted(self) -> None:
        value = manifest()
        target = value["targets"][1]
        target["allowedPrincipals"] = ["domain:example.com"]
        target["analysis"] = response(
            resource=SECRET_RESOURCE,
            permission="secretmanager.versions.access",
            identities=["domain:example.com"],
            role="roles/secretmanager.secretAccessor",
        )
        self.assert_refused(value, "public or aggregate principal")

    def test_conditional_binding_is_refused(self) -> None:
        value = manifest()
        binding = value["targets"][0]["analysis"]["mainAnalysis"][
            "analysisResults"
        ][0]["iamBinding"]
        binding["condition"] = {
            "title": "temporary",
            "expression": "request.time < timestamp('2099-01-01T00:00:00Z')",
        }
        self.assert_refused(value, "conditional binding")

    def test_partial_top_level_analysis_is_refused(self) -> None:
        value = manifest()
        value["targets"][0]["analysis"]["fullyExplored"] = False
        self.assert_refused(value, "not fully explored")

    def test_partial_result_is_refused(self) -> None:
        value = manifest()
        result_value = value["targets"][1]["analysis"]["mainAnalysis"][
            "analysisResults"
        ][0]
        result_value["fullyExplored"] = False
        self.assert_refused(value, "not fully explored")

    def test_noncritical_analysis_error_is_refused(self) -> None:
        value = manifest()
        value["targets"][0]["analysis"]["mainAnalysis"]["nonCriticalErrors"] = [
            {"code": "PERMISSION_DENIED", "cause": "group expansion denied"}
        ]
        self.assert_refused(value, "non-critical errors")

    def test_identity_analysis_error_is_refused(self) -> None:
        value = manifest()
        identity = value["targets"][0]["analysis"]["mainAnalysis"][
            "analysisResults"
        ][0]["identityList"]["identities"][0]
        identity["analysisState"] = {
            "code": "PERMISSION_DENIED",
            "cause": "identity hidden",
        }
        self.assert_refused(value, "analysis state")

    def test_query_must_match_exact_resource_and_permission(self) -> None:
        value = manifest()
        query = value["targets"][0]["analysis"]["mainAnalysis"]["analysisQuery"]
        query["accessSelector"]["permissions"] = ["run.services.get"]
        self.assert_refused(value, "query does not match")

    def test_group_expansion_option_is_required(self) -> None:
        value = manifest()
        options = value["targets"][0]["analysis"]["mainAnalysis"][
            "analysisQuery"
        ]["options"]
        options["expandGroups"] = False
        self.assert_refused(value, "group expansion")

    def test_service_account_impersonation_analysis_is_required(self) -> None:
        value = manifest()
        options = value["targets"][0]["analysis"]["mainAnalysis"][
            "analysisQuery"
        ]["options"]
        options["analyzeServiceAccountImpersonation"] = False
        self.assert_refused(value, "impersonation analysis")

    def test_nonallowlisted_impersonator_is_refused(self) -> None:
        value = manifest()
        target = value["targets"][0]
        impersonation_query = {
            "scope": PROJECT_SCOPE,
            "resourceSelector": {
                "fullResourceName": (
                    "//iam.googleapis.com/projects/test-project/serviceAccounts/"
                    "emilia-decision@test-project.iam.gserviceaccount.com"
                )
            },
            "accessSelector": {
                "permissions": ["iam.serviceAccounts.getAccessToken"]
            },
            "options": {
                "expandGroups": True,
                "outputGroupEdges": True,
            },
        }
        impersonation_resource = impersonation_query["resourceSelector"][
            "fullResourceName"
        ]
        target["analysis"]["serviceAccountImpersonationAnalysis"] = [
            {
                "analysisQuery": impersonation_query,
                "analysisResults": [
                    result(
                        resource=impersonation_resource,
                        permission="iam.serviceAccounts.getAccessToken",
                        identities=["user:impersonator@example.com"],
                        role="roles/iam.serviceAccountTokenCreator",
                    )
                ],
                "fullyExplored": True,
            }
        ]
        self.assert_refused(value, "nonallowlisted effective principal")

    def test_jit_act_as_requires_only_the_exact_conditional_deployer(self) -> None:
        verified = verify_effective_iam.verify_manifest(
            jit_manifest(),
            jit_phase="during",
            now=datetime(2026, 7, 25, 18, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(
            verified,
            {
                "runtime-actAs:actuator": (DEPLOYER,),
                "runtime-actAs:decision": (DEPLOYER,),
            },
        )

    def test_inherited_group_custom_role_act_as_is_refused_during_jit(self) -> None:
        value = jit_manifest()
        target = value["targets"][2]
        target["analysis"]["during"]["mainAnalysis"]["analysisResults"].append(
            result(
                resource=ACTUATOR_SA_RESOURCE,
                permission="iam.serviceAccounts.actAs",
                identities=[
                    "group:platform-admins@example.com",
                    "user:hostile-admin@example.com",
                ],
                role="organizations/987654321/roles/hostileActAs",
                attached_resource=(
                    "//cloudresourcemanager.googleapis.com/"
                    "organizations/987654321"
                ),
                members=["group:platform-admins@example.com"],
                group_edges=[
                    {
                        "sourceNode": "group:platform-admins@example.com",
                        "targetNode": "user:hostile-admin@example.com",
                    }
                ],
            )
        )
        with self.assertRaisesRegex(
            verify_effective_iam.VerificationError,
            "nonallowlisted effective principal",
        ):
            verify_effective_iam.verify_manifest(
                value,
                jit_phase="during",
                now=datetime(2026, 7, 25, 18, 1, tzinfo=timezone.utc),
            )

    def test_jit_active_phase_refuses_expired_grant(self) -> None:
        with self.assertRaisesRegex(
            verify_effective_iam.VerificationError,
            "expired",
        ):
            verify_effective_iam.verify_manifest(
                jit_manifest(),
                jit_phase="during",
                now=datetime(2026, 7, 25, 18, 15, tzinfo=timezone.utc),
            )

    def test_jit_after_phase_requires_deployer_absent_on_both_accounts(
        self,
    ) -> None:
        value = jit_manifest()
        target = value["targets"][3]
        target["analysis"]["after"] = response(
            resource=DECISION_SA_RESOURCE,
            permission="iam.serviceAccounts.actAs",
            identities=[DEPLOYER],
            role="organizations/987654321/roles/hostileActAs",
        )
        with self.assertRaisesRegex(
            verify_effective_iam.VerificationError,
            "nonallowlisted effective principal",
        ):
            verify_effective_iam.verify_manifest(
                value,
                jit_phase="after",
                now=datetime(2026, 7, 25, 18, 2, tzinfo=timezone.utc),
            )

    def test_live_jit_queries_both_accounts_at_organization_scope(self) -> None:
        expected = jit_manifest()
        set_scope(expected, "organizations/987654321")
        value = copy.deepcopy(expected)
        for target in value["targets"]:
            if target["kind"] == "runtimeActAs":
                del target["analysis"]
        ancestry = [
            {"type": "project", "id": "test-project"},
            {"type": "folder", "id": "123456789"},
            {"type": "organization", "id": "987654321"},
        ]
        runtime_targets = [
            target
            for target in expected["targets"]
            if target["kind"] == "runtimeActAs"
        ]
        runner = mock.Mock(
            side_effect=[
                subprocess.CompletedProcess(
                    [], 0, stdout=json.dumps(ancestry), stderr=""
                ),
                *[
                    subprocess.CompletedProcess(
                        [],
                        0,
                        stdout=json.dumps(target["analysis"]["during"]),
                        stderr="",
                    )
                    for target in runtime_targets
                ],
            ]
        )
        verified = verify_effective_iam.verify_manifest(
            value,
            live=True,
            runner=runner,
            gcloud="test-gcloud",
            jit_phase="during",
            now=datetime(2026, 7, 25, 18, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(
            set(verified),
            {"runtime-actAs:actuator", "runtime-actAs:decision"},
        )
        self.assertEqual(runner.call_count, 3)
        for invocation in runner.call_args_list[1:]:
            command = invocation.args[0]
            self.assertIn("--organization=987654321", command)
            self.assertIn(
                "--permissions=iam.serviceAccounts.actAs",
                command,
            )
            self.assertIn("--expand-groups", command)
            self.assertIn("--output-group-edges", command)
            self.assertIn(f"--access-time={JIT_ISSUED_AT}", command)

    def test_unknown_manifest_or_policy_analyzer_fields_are_refused(self) -> None:
        value = manifest()
        value["targets"][0]["analysis"]["unexpected"] = True
        self.assert_refused(value, "unknown field")

    def test_non_string_query_permission_is_refused_cleanly(self) -> None:
        value = manifest()
        query = value["targets"][0]["analysis"]["mainAnalysis"]["analysisQuery"]
        query["accessSelector"]["permissions"] = [{"permission": "run.routes.invoke"}]
        self.assert_refused(value, "must be a non-empty single-line string")

    def test_duplicate_target_is_refused(self) -> None:
        value = manifest()
        value["targets"] = [copy.deepcopy(value["targets"][0])] * 2
        self.assert_refused(value, "duplicates a target")

    def test_live_query_uses_structured_policy_analyzer_json(self) -> None:
        value = manifest()
        for target in value["targets"]:
            del target["analysis"]
        outputs = [
            json.dumps(STANDALONE_ANCESTRY),
            json.dumps(manifest()["targets"][0]["analysis"]),
            json.dumps(manifest()["targets"][1]["analysis"]),
        ]
        runner = mock.Mock(
            side_effect=[
                subprocess.CompletedProcess([], 0, stdout=output, stderr="")
                for output in outputs
            ]
        )
        verified = verify_effective_iam.verify_manifest(
            value,
            live=True,
            runner=runner,
            gcloud="test-gcloud",
        )
        self.assertEqual(
            verified["actuator"],
            tuple(sorted((COMPUTE_AGENT, DECISION, RUN_AGENT))),
        )
        ancestry_command = runner.call_args_list[0].args[0]
        self.assertEqual(
            ancestry_command[:4],
            ["test-gcloud", "projects", "get-ancestors", "test-project"],
        )
        first_command = runner.call_args_list[1].args[0]
        self.assertEqual(
            first_command[:3],
            ["test-gcloud", "asset", "analyze-iam-policy"],
        )
        self.assertIn("--project=test-project", first_command)
        self.assertIn(f"--full-resource-name={ACTUATOR_RESOURCE}", first_command)
        self.assertIn("--permissions=run.routes.invoke", first_command)
        self.assertIn("--expand-groups", first_command)
        self.assertIn("--output-group-edges", first_command)
        self.assertIn("--analyze-service-account-impersonation", first_command)
        self.assertIn("--show-response", first_command)
        self.assertIn("--format=json", first_command)

    def test_live_organization_ancestry_requires_and_uses_organization_scope(
        self,
    ) -> None:
        expected = manifest()
        set_scope(expected, "organizations/987654321")
        value = copy.deepcopy(expected)
        for target in value["targets"]:
            del target["analysis"]
        ancestry = [
            {"type": "project", "id": "test-project"},
            {"type": "folder", "id": "123456789"},
            {"type": "organization", "id": "987654321"},
        ]
        runner = mock.Mock(
            side_effect=[
                subprocess.CompletedProcess(
                    [], 0, stdout=json.dumps(ancestry), stderr=""
                ),
                *[
                    subprocess.CompletedProcess(
                        [], 0, stdout=json.dumps(target["analysis"]), stderr=""
                    )
                    for target in expected["targets"]
                ],
            ]
        )
        verified = verify_effective_iam.verify_manifest(
            value,
            live=True,
            runner=runner,
            gcloud="test-gcloud",
        )
        self.assertIn(RUN_AGENT, verified["actuator"])
        analyzer_command = runner.call_args_list[1].args[0]
        self.assertIn("--organization=987654321", analyzer_command)
        self.assertNotIn("--project=test-project", analyzer_command)

    def test_live_organization_ancestry_refuses_project_scope(self) -> None:
        value = manifest()
        for target in value["targets"]:
            del target["analysis"]
        ancestry = [
            {"type": "project", "id": "test-project"},
            {"type": "organization", "id": "987654321"},
        ]
        runner = mock.Mock(
            return_value=subprocess.CompletedProcess(
                [], 0, stdout=json.dumps(ancestry), stderr=""
            )
        )
        with self.assertRaisesRegex(
            verify_effective_iam.VerificationError,
            "explicit organizations/987654321 analyzer scope is required",
        ):
            verify_effective_iam.verify_manifest(
                value,
                live=True,
                runner=runner,
                gcloud="test-gcloud",
            )
        self.assertEqual(runner.call_count, 1)

    def test_live_ancestry_lookup_failure_is_fail_closed(self) -> None:
        value = manifest()
        for target in value["targets"]:
            del target["analysis"]
        runner = mock.Mock(
            return_value=subprocess.CompletedProcess(
                [], 1, stdout="", stderr="permission denied"
            )
        )
        with self.assertRaisesRegex(
            verify_effective_iam.VerificationError,
            "ancestry lookup failed",
        ):
            verify_effective_iam.verify_manifest(
                value,
                live=True,
                runner=runner,
                gcloud="test-gcloud",
            )
        self.assertEqual(runner.call_count, 1)

    def test_live_mode_validates_all_targets_before_invoking_gcloud(self) -> None:
        value = manifest()
        value["targets"] = [value["targets"][0]]
        del value["targets"][0]["analysis"]
        runner = mock.Mock()
        with self.assertRaisesRegex(
            verify_effective_iam.VerificationError, "at least one named secret"
        ):
            verify_effective_iam.verify_manifest(value, live=True, runner=runner)
        runner.assert_not_called()

    def test_cli_reports_refusal_without_traceback(self) -> None:
        value = manifest()
        value["targets"][0]["analysis"]["fullyExplored"] = False
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            completed = subprocess.run(
                [str(SCRIPT), "--input", str(path)],
                cwd=LANE,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("effective IAM refused:", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
