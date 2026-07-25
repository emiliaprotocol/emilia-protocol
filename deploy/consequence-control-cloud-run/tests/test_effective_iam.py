from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
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


def manifest() -> dict:
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
                "allowedPrincipals": [DECISION],
                "analysis": response(
                    resource=ACTUATOR_RESOURCE,
                    permission="run.routes.invoke",
                    identities=[DECISION],
                    role="roles/run.invoker",
                ),
            },
            {
                "name": "secret:actuator-token",
                "kind": "secret",
                "scope": PROJECT_SCOPE,
                "resource": SECRET_RESOURCE,
                "allowedPrincipals": [ACTUATOR, DECISION],
                "analysis": response(
                    resource=SECRET_RESOURCE,
                    permission="secretmanager.versions.access",
                    identities=[ACTUATOR, DECISION],
                    role="roles/secretmanager.secretAccessor",
                ),
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
                "actuator": (DECISION,),
                "secret:actuator-token": tuple(sorted((ACTUATOR, DECISION))),
            },
        )

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
        self.assertEqual(verified["actuator"], (DECISION,))
        first_command = runner.call_args_list[0].args[0]
        self.assertEqual(first_command[:3], ["test-gcloud", "asset", "analyze-iam-policy"])
        self.assertIn("--project=test-project", first_command)
        self.assertIn(f"--full-resource-name={ACTUATOR_RESOURCE}", first_command)
        self.assertIn("--permissions=run.routes.invoke", first_command)
        self.assertIn("--expand-groups", first_command)
        self.assertIn("--output-group-edges", first_command)
        self.assertIn("--analyze-service-account-impersonation", first_command)
        self.assertIn("--show-response", first_command)
        self.assertIn("--format=json", first_command)

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
