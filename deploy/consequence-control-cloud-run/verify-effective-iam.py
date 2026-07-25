#!/usr/bin/env python3
"""Fail-closed verification of effective IAM from Policy Analyzer JSON."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

VERSION = "emilia-effective-iam/v1"
PERMISSIONS = {
    "actuator": "run.routes.invoke",
    "secret": "secretmanager.versions.access",
}
IMPERSONATION_PERMISSIONS = {
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.getOpenIdToken",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
}
PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}
AGGREGATE_PREFIXES = (
    "domain:",
    "principalSet:",
    "principalSet://",
    "projectOwner:",
    "projectEditor:",
    "projectViewer:",
)
CONCRETE_PRINCIPAL_PATTERNS = (
    re.compile(r"^user:[^@\s]+@[^@\s]+$"),
    re.compile(r"^serviceAccount:[^@\s]+@[^@\s]+$"),
    re.compile(r"^principal://[^\s]+$"),
)
GROUP_PATTERN = re.compile(r"^group:[^@\s]+@[^@\s]+$")
SCOPE_PATTERN = re.compile(r"^(projects|folders|organizations)/([^/]+)$")
ACTUATOR_PATTERN = re.compile(
    r"^//run\.googleapis\.com/projects/([^/]+)/locations/([^/]+)/services/([^/]+)$"
)
SECRET_PATTERN = re.compile(
    r"^//secretmanager\.googleapis\.com/projects/([^/]+)/secrets/([^/]+)$"
)
PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
PROJECT_NUMBER_PATTERN = re.compile(r"^[1-9][0-9]{5,29}$")
SERVICE_ACCOUNT_RESOURCE_PATTERN = re.compile(
    r"^//iam\.googleapis\.com/projects/[^/]+/serviceAccounts/[^/\s]+$"
)
ANCESTOR_RESOURCE_PATTERN = re.compile(
    r"^//cloudresourcemanager\.googleapis\.com/"
    r"(?:projects/[^/]+|folders/[0-9]+|organizations/[0-9]+)$"
)


class VerificationError(ValueError):
    """The evidence cannot prove the configured effective-IAM allowlist."""


def require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{path} must be an object")
    return value


def require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{path} must be an array")
    return value


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or any(
        character in value for character in "\r\n\0"
    ):
        raise VerificationError(f"{path} must be a non-empty single-line string")
    return value


def check_fields(
    value: dict[str, Any],
    path: str,
    required: set[str],
    optional: set[str] = frozenset(),
) -> None:
    missing = required - value.keys()
    if missing:
        raise VerificationError(
            f"{path} missing required field: {sorted(missing)[0]}"
        )
    unknown = value.keys() - required - optional
    if unknown:
        raise VerificationError(f"{path} has unknown field: {sorted(unknown)[0]}")


def require_true(value: Any, path: str) -> None:
    if value is not True:
        raise VerificationError(f"{path} is not fully explored")


def validate_state(value: Any, path: str) -> None:
    state = require_object(value, path)
    check_fields(state, path, {"code"}, {"cause"})
    if state["code"] != "OK":
        cause = state.get("cause", "unspecified")
        raise VerificationError(
            f"{path} has non-OK analysis state {state['code']!r}: {cause}"
        )
    if "cause" in state:
        require_string(state["cause"], f"{path}.cause")


def validate_principal(principal: Any, path: str) -> str:
    name = require_string(principal, path)
    if name in PUBLIC_PRINCIPALS or name.startswith(AGGREGATE_PREFIXES):
        raise VerificationError(f"{path} is a public or aggregate principal: {name}")
    if name.startswith("group:"):
        raise VerificationError(f"{path} is an unexpanded group: {name}")
    if not any(pattern.fullmatch(name) for pattern in CONCRETE_PRINCIPAL_PATTERNS):
        raise VerificationError(f"{path} is an unknown principal form: {name}")
    return name


def validate_group(group: Any, path: str) -> str:
    name = require_string(group, path)
    if GROUP_PATTERN.fullmatch(name) is None:
        raise VerificationError(f"{path} is an invalid group principal: {name}")
    return name


def validate_allowlist(value: Any, path: str) -> tuple[str, ...]:
    entries = require_list(value, path)
    if not entries:
        raise VerificationError(f"{path} must contain at least one principal")
    principals = tuple(
        sorted(
            validate_principal(entry, f"{path}[{index}]")
            for index, entry in enumerate(entries)
        )
    )
    if len(principals) != len(set(principals)):
        raise VerificationError(f"{path} contains a duplicate principal")
    return principals


def validate_edge(value: Any, path: str) -> tuple[str, str]:
    edge = require_object(value, path)
    check_fields(edge, path, {"sourceNode", "targetNode"})
    source = require_string(edge["sourceNode"], f"{path}.sourceNode")
    target = require_string(edge["targetNode"], f"{path}.targetNode")
    if not source.startswith("group:"):
        raise VerificationError(f"{path}.sourceNode is not a group")
    validate_group(source, f"{path}.sourceNode")
    if target.startswith("group:"):
        validate_group(target, f"{path}.targetNode")
    else:
        validate_principal(target, f"{path}.targetNode")
    return source, target


def collect_effective_identities(
    identity_list_value: Any,
    binding_members_value: Any,
    path: str,
) -> set[str]:
    identity_list = require_object(identity_list_value, f"{path}.identityList")
    check_fields(identity_list, f"{path}.identityList", {"identities"}, {"groupEdges"})

    identity_values = require_list(
        identity_list["identities"], f"{path}.identityList.identities"
    )
    identities: set[str] = set()
    for index, identity_value in enumerate(identity_values):
        identity_path = f"{path}.identityList.identities[{index}]"
        identity = require_object(identity_value, identity_path)
        check_fields(identity, identity_path, {"name"}, {"analysisState"})
        name = require_string(identity["name"], f"{identity_path}.name")
        if "analysisState" in identity:
            validate_state(identity["analysisState"], f"{identity_path}.analysisState")
        if name in identities:
            raise VerificationError(f"{path}.identityList has duplicate identity: {name}")
        identities.add(name)

    members = require_list(binding_members_value, f"{path}.iamBinding.members")
    if not members:
        raise VerificationError(f"{path}.iamBinding.members must not be empty")
    direct_principals: set[str] = set()
    root_groups: set[str] = set()
    for index, member_value in enumerate(members):
        member = require_string(
            member_value, f"{path}.iamBinding.members[{index}]"
        )
        if member.startswith("group:"):
            root_groups.add(
                validate_group(member, f"{path}.iamBinding.members[{index}]")
            )
        else:
            direct_principals.add(
                validate_principal(member, f"{path}.iamBinding.members[{index}]")
            )
    if len(direct_principals) + len(root_groups) != len(members):
        raise VerificationError(f"{path}.iamBinding.members contains a duplicate")

    edge_values = require_list(
        identity_list.get("groupEdges", []), f"{path}.identityList.groupEdges"
    )
    adjacency: dict[str, set[str]] = {}
    seen_edges: set[tuple[str, str]] = set()
    for index, edge_value in enumerate(edge_values):
        edge = validate_edge(edge_value, f"{path}.identityList.groupEdges[{index}]")
        if edge in seen_edges:
            raise VerificationError(f"{path}.identityList.groupEdges has a duplicate")
        seen_edges.add(edge)
        adjacency.setdefault(edge[0], set()).add(edge[1])

    if not root_groups:
        if edge_values or any(name.startswith("group:") for name in identities):
            raise VerificationError(
                f"{path}.identityList has group expansion without a group binding"
            )
        for identity in identities:
            validate_principal(identity, f"{path}.identityList identity")
        if identities != direct_principals:
            raise VerificationError(
                f"{path}.identityList does not match direct binding members"
            )
        return identities

    reachable_groups: set[str] = set()
    leaves: set[str] = set()
    active: set[str] = set()

    def visit(group: str) -> None:
        if group in active:
            raise VerificationError(f"{path}.identityList group expansion has a cycle")
        if group in reachable_groups:
            return
        children = adjacency.get(group)
        if not children:
            raise VerificationError(
                f"{path}.identityList group was not fully expanded: {group}"
            )
        active.add(group)
        reachable_groups.add(group)
        for child in children:
            if child.startswith("group:"):
                visit(child)
            else:
                leaves.add(child)
        active.remove(group)

    for group in root_groups:
        visit(group)

    if set(adjacency) - reachable_groups:
        raise VerificationError(
            f"{path}.identityList contains group edges unrelated to the binding"
        )
    listed_groups = {name for name in identities if name.startswith("group:")}
    for group in listed_groups:
        validate_group(group, f"{path}.identityList identity")
    if listed_groups - reachable_groups:
        raise VerificationError(
            f"{path}.identityList contains an unreachable group identity"
        )
    listed_principals = identities - listed_groups
    for identity in listed_principals:
        validate_principal(identity, f"{path}.identityList identity")
    effective = direct_principals | leaves
    if listed_principals != effective:
        raise VerificationError(
            f"{path}.identityList does not match fully expanded binding members"
        )
    return effective


def validate_resource(value: Any, expected: str, path: str) -> None:
    resource = require_object(value, path)
    check_fields(resource, path, {"fullResourceName"}, {"analysisState"})
    if resource["fullResourceName"] != expected:
        raise VerificationError(f"{path} does not match the queried resource")
    if "analysisState" in resource:
        validate_state(resource["analysisState"], f"{path}.analysisState")


def validate_access(value: Any, expected: set[str], path: str) -> str:
    access = require_object(value, path)
    check_fields(access, path, set(), {"permission", "role", "analysisState"})
    present = {"permission", "role"} & access.keys()
    if len(present) != 1:
        raise VerificationError(f"{path} must contain exactly one access specifier")
    if "analysisState" in access:
        validate_state(access["analysisState"], f"{path}.analysisState")
    if "permission" not in access:
        raise VerificationError(f"{path} contains a role instead of a queried permission")
    permission = require_string(access["permission"], f"{path}.permission")
    if permission not in expected:
        raise VerificationError(f"{path} does not match the queried permission")
    return permission


def verify_result(
    value: Any,
    resource: str,
    permissions: set[str],
    path: str,
) -> set[str]:
    result = require_object(value, path)
    check_fields(
        result,
        path,
        {
            "attachedResourceFullName",
            "iamBinding",
            "accessControlLists",
            "identityList",
            "fullyExplored",
        },
    )
    require_true(result["fullyExplored"], f"{path}.fullyExplored")
    attached_resource = require_string(
        result["attachedResourceFullName"], f"{path}.attachedResourceFullName"
    )
    if (
        attached_resource != resource
        and ANCESTOR_RESOURCE_PATTERN.fullmatch(attached_resource) is None
    ):
        raise VerificationError(
            f"{path}.attachedResourceFullName is not the target or an ancestor"
        )

    binding = require_object(result["iamBinding"], f"{path}.iamBinding")
    check_fields(binding, f"{path}.iamBinding", {"role", "members"}, {"condition"})
    require_string(binding["role"], f"{path}.iamBinding.role")
    if "condition" in binding:
        raise VerificationError(f"{path} contains a conditional binding")

    access_control_lists = require_list(
        result["accessControlLists"], f"{path}.accessControlLists"
    )
    if not access_control_lists:
        raise VerificationError(f"{path}.accessControlLists must not be empty")
    observed_permissions: set[str] = set()
    for acl_index, acl_value in enumerate(access_control_lists):
        acl_path = f"{path}.accessControlLists[{acl_index}]"
        acl = require_object(acl_value, acl_path)
        check_fields(
            acl,
            acl_path,
            {"resources", "accesses"},
            {"resourceEdges", "conditionEvaluation"},
        )
        if "conditionEvaluation" in acl:
            raise VerificationError(f"{acl_path} contains conditional analysis")
        if "resourceEdges" in acl:
            resource_edges = require_list(
                acl["resourceEdges"], f"{acl_path}.resourceEdges"
            )
            if resource_edges:
                raise VerificationError(
                    f"{acl_path} contains unexpected resource expansion"
                )
        resources = require_list(acl["resources"], f"{acl_path}.resources")
        accesses = require_list(acl["accesses"], f"{acl_path}.accesses")
        if not resources or not accesses:
            raise VerificationError(f"{acl_path} is empty")
        for resource_index, resource_value in enumerate(resources):
            validate_resource(
                resource_value,
                resource,
                f"{acl_path}.resources[{resource_index}]",
            )
        for access_index, access_value in enumerate(accesses):
            observed_permissions.add(
                validate_access(
                    access_value,
                    permissions,
                    f"{acl_path}.accesses[{access_index}]",
                )
            )
    if not observed_permissions:
        raise VerificationError(f"{path} has no queried permission")
    return collect_effective_identities(
        result["identityList"], binding["members"], path
    )


def validate_query_options(value: Any, path: str, *, impersonation: bool) -> None:
    options = require_object(value, path)
    check_fields(
        options,
        path,
        {"expandGroups", "outputGroupEdges"},
        {
            "expandRoles",
            "expandResources",
            "outputResourceEdges",
            "analyzeServiceAccountImpersonation",
        },
    )
    if options["expandGroups"] is not True or options["outputGroupEdges"] is not True:
        raise VerificationError(f"{path} does not require complete group expansion")
    for option in ("expandRoles", "expandResources", "outputResourceEdges"):
        if option in options and not isinstance(options[option], bool):
            raise VerificationError(f"{path}.{option} must be a boolean")
        if options.get(option) is True:
            raise VerificationError(f"{path}.{option} must be false")
    if (
        "analyzeServiceAccountImpersonation" in options
        and not isinstance(options["analyzeServiceAccountImpersonation"], bool)
    ):
        raise VerificationError(
            f"{path}.analyzeServiceAccountImpersonation must be a boolean"
        )
    if (
        not impersonation
        and options.get("analyzeServiceAccountImpersonation") is not True
    ):
        raise VerificationError(f"{path} does not require impersonation analysis")
    if impersonation and options.get("analyzeServiceAccountImpersonation") is True:
        raise VerificationError(f"{path} recursively requests impersonation analysis")


def validate_query(
    value: Any,
    *,
    scope: str,
    resource: str,
    permissions: set[str],
    path: str,
    impersonation: bool,
) -> None:
    query = require_object(value, path)
    check_fields(
        query,
        path,
        {"scope", "resourceSelector", "accessSelector", "options"},
        {"identitySelector", "conditionContext"},
    )
    if "identitySelector" in query or "conditionContext" in query:
        raise VerificationError(f"{path} contains an unsupported selector or condition")
    resource_selector = require_object(
        query["resourceSelector"], f"{path}.resourceSelector"
    )
    check_fields(
        resource_selector, f"{path}.resourceSelector", {"fullResourceName"}
    )
    access_selector = require_object(
        query["accessSelector"], f"{path}.accessSelector"
    )
    check_fields(
        access_selector, f"{path}.accessSelector", {"permissions"}, {"roles"}
    )
    permission_values = require_list(
        access_selector["permissions"], f"{path}.accessSelector.permissions"
    )
    queried_permissions = {
        require_string(
            permission_value,
            f"{path}.accessSelector.permissions[{index}]",
        )
        for index, permission_value in enumerate(permission_values)
    }
    roles = (
        require_list(access_selector["roles"], f"{path}.accessSelector.roles")
        if "roles" in access_selector
        else []
    )
    if (
        query["scope"] != scope
        or resource_selector["fullResourceName"] != resource
        or queried_permissions != permissions
        or len(permission_values) != len(permissions)
        or roles
    ):
        raise VerificationError(f"{path} query does not match configured target")
    validate_query_options(
        query["options"], f"{path}.options", impersonation=impersonation
    )


def verify_analysis(
    value: Any,
    *,
    scope: str,
    resource: str,
    permissions: set[str],
    path: str,
    impersonation: bool,
) -> set[str]:
    analysis = require_object(value, path)
    check_fields(
        analysis,
        path,
        {"analysisQuery", "analysisResults", "fullyExplored"},
        {"nonCriticalErrors"},
    )
    require_true(analysis["fullyExplored"], f"{path}.fullyExplored")
    errors = require_list(
        analysis.get("nonCriticalErrors", []), f"{path}.nonCriticalErrors"
    )
    if errors:
        raise VerificationError(f"{path} contains non-critical errors")
    validate_query(
        analysis["analysisQuery"],
        scope=scope,
        resource=resource,
        permissions=permissions,
        path=f"{path}.analysisQuery",
        impersonation=impersonation,
    )
    effective: set[str] = set()
    results = require_list(analysis["analysisResults"], f"{path}.analysisResults")
    for index, result_value in enumerate(results):
        effective.update(
            verify_result(
                result_value,
                resource,
                permissions,
                f"{path}.analysisResults[{index}]",
            )
        )
    return effective


def verify_response(
    value: Any,
    *,
    scope: str,
    resource: str,
    permission: str,
    path: str,
) -> set[str]:
    response = require_object(value, path)
    check_fields(
        response,
        path,
        {"mainAnalysis", "fullyExplored"},
        {"serviceAccountImpersonationAnalysis"},
    )
    require_true(response["fullyExplored"], f"{path}.fullyExplored")
    effective = verify_analysis(
        response["mainAnalysis"],
        scope=scope,
        resource=resource,
        permissions={permission},
        path=f"{path}.mainAnalysis",
        impersonation=False,
    )
    impersonation_analyses = require_list(
        response.get("serviceAccountImpersonationAnalysis", []),
        f"{path}.serviceAccountImpersonationAnalysis",
    )
    for index, analysis_value in enumerate(impersonation_analyses):
        analysis_path = f"{path}.serviceAccountImpersonationAnalysis[{index}]"
        analysis = require_object(analysis_value, analysis_path)
        query = require_object(analysis.get("analysisQuery"), f"{analysis_path}.analysisQuery")
        selector = require_object(
            query.get("resourceSelector"), f"{analysis_path}.analysisQuery.resourceSelector"
        )
        impersonated_resource = require_string(
            selector.get("fullResourceName"),
            f"{analysis_path}.analysisQuery.resourceSelector.fullResourceName",
        )
        if not SERVICE_ACCOUNT_RESOURCE_PATTERN.fullmatch(impersonated_resource):
            raise VerificationError(
                f"{analysis_path} does not target a service account"
            )
        access_selector = require_object(
            query.get("accessSelector"), f"{analysis_path}.analysisQuery.accessSelector"
        )
        permission_values = require_list(
            access_selector.get("permissions"),
            f"{analysis_path}.analysisQuery.accessSelector.permissions",
        )
        impersonation_permissions = {
            require_string(
                permission_value,
                (
                    f"{analysis_path}.analysisQuery.accessSelector."
                    f"permissions[{permission_index}]"
                ),
            )
            for permission_index, permission_value in enumerate(permission_values)
        }
        if (
            not impersonation_permissions
            or len(impersonation_permissions) != len(permission_values)
            or not impersonation_permissions <= IMPERSONATION_PERMISSIONS
        ):
            raise VerificationError(
                f"{analysis_path} has invalid impersonation permissions"
            )
        effective.update(
            verify_analysis(
                analysis,
                scope=scope,
                resource=impersonated_resource,
                permissions=impersonation_permissions,
                path=analysis_path,
                impersonation=True,
            )
        )
    return effective


def scope_argument(scope: str) -> str:
    match = SCOPE_PATTERN.fullmatch(scope)
    if match is None:
        raise VerificationError(f"invalid Policy Analyzer scope: {scope}")
    kind = {
        "projects": "project",
        "folders": "folder",
        "organizations": "organization",
    }[match.group(1)]
    return f"--{kind}={match.group(2)}"


def live_analysis(
    *,
    scope: str,
    resource: str,
    permission: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
    gcloud: str,
) -> Any:
    command = [
        gcloud,
        "asset",
        "analyze-iam-policy",
        scope_argument(scope),
        f"--full-resource-name={resource}",
        f"--permissions={permission}",
        "--expand-groups",
        "--output-group-edges",
        "--analyze-service-account-impersonation",
        "--show-response",
        "--format=json",
        "--quiet",
    ]
    try:
        completed = runner(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError(f"gcloud Policy Analyzer invocation failed: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "no diagnostic"
        raise VerificationError(
            f"gcloud Policy Analyzer invocation failed ({completed.returncode}): {detail}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(
            "gcloud Policy Analyzer did not return one JSON document"
        ) from error


def live_analyzer_scope(
    *,
    project_id: str,
    project_number: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
    gcloud: str,
) -> str:
    command = [
        gcloud,
        "projects",
        "get-ancestors",
        project_id,
        "--format=json",
        "--quiet",
    ]
    try:
        completed = runner(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError(f"gcloud ancestry lookup failed: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "no diagnostic"
        raise VerificationError(
            f"gcloud ancestry lookup failed ({completed.returncode}): {detail}"
        )
    try:
        entries = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(
            "gcloud ancestry lookup did not return one JSON document"
        ) from error
    if not isinstance(entries, list) or not entries:
        raise VerificationError("project ancestry is empty or unavailable")

    projects: set[str] = set()
    folders: set[str] = set()
    organizations: set[str] = set()
    for index, entry_value in enumerate(entries):
        path = f"project ancestry[{index}]"
        entry = require_object(entry_value, path)
        entry_type = require_string(entry.get("type"), f"{path}.type")
        entry_id = require_string(entry.get("id"), f"{path}.id")
        if entry_type == "project":
            projects.add(entry_id)
        elif entry_type == "folder":
            if not entry_id.isdigit() or entry_id.startswith("0"):
                raise VerificationError(f"{path}.id is not a numeric folder ID")
            folders.add(entry_id)
        elif entry_type == "organization":
            if not entry_id.isdigit() or entry_id.startswith("0"):
                raise VerificationError(
                    f"{path}.id is not a numeric organization ID"
                )
            organizations.add(entry_id)
        else:
            raise VerificationError(f"{path}.type is unknown: {entry_type}")

    if len(projects) != 1 or not projects <= {project_id, project_number}:
        raise VerificationError(
            "project ancestry does not identify the deployment project exactly once"
        )
    if not folders and not organizations:
        return f"projects/{project_id}"
    if len(organizations) != 1:
        raise VerificationError(
            "project ancestry exists but one covering organization is unavailable"
        )
    return f"organizations/{next(iter(organizations))}"


def validate_target_shape(target: dict[str, Any], path: str, live: bool) -> None:
    required = {"name", "kind", "scope", "resource", "allowedPrincipals"}
    optional = {"analysis"} if live else set()
    if not live:
        required.add("analysis")
    check_fields(target, path, required, optional)


def verify_manifest(
    value: Any,
    *,
    live: bool = False,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    gcloud: str = "gcloud",
) -> dict[str, tuple[str, ...]]:
    manifest = require_object(value, "manifest")
    check_fields(
        manifest,
        "manifest",
        {"version", "projectId", "projectNumber", "targets"},
    )
    if manifest["version"] != VERSION:
        raise VerificationError(f"manifest.version must be {VERSION!r}")
    project_id = require_string(manifest["projectId"], "manifest.projectId")
    project_number = require_string(
        manifest["projectNumber"], "manifest.projectNumber"
    )
    if PROJECT_ID_PATTERN.fullmatch(project_id) is None:
        raise VerificationError("manifest.projectId is invalid")
    if PROJECT_NUMBER_PATTERN.fullmatch(project_number) is None:
        raise VerificationError("manifest.projectNumber is invalid")
    targets = require_list(manifest["targets"], "manifest.targets")
    if not targets:
        raise VerificationError("manifest.targets must not be empty")

    prepared: list[
        tuple[str, str, str, str, tuple[str, ...], Any]
    ] = []
    names: set[str] = set()
    resources: set[str] = set()
    actuator_count = 0
    secret_count = 0

    for index, target_value in enumerate(targets):
        path = f"manifest.targets[{index}]"
        target = require_object(target_value, path)
        validate_target_shape(target, path, live)
        name = require_string(target["name"], f"{path}.name")
        kind = require_string(target["kind"], f"{path}.kind")
        scope = require_string(target["scope"], f"{path}.scope")
        resource = require_string(target["resource"], f"{path}.resource")
        scope_match = SCOPE_PATTERN.fullmatch(scope)
        if scope_match is None:
            raise VerificationError(f"{path}.scope is invalid")
        if kind not in PERMISSIONS:
            raise VerificationError(f"{path}.kind must be 'actuator' or 'secret'")
        if name in names or resource in resources:
            raise VerificationError(f"{path} duplicates a target name or resource")
        names.add(name)
        resources.add(resource)
        allowed = validate_allowlist(
            target["allowedPrincipals"], f"{path}.allowedPrincipals"
        )

        if kind == "actuator":
            actuator_count += 1
            if name != "actuator" or ACTUATOR_PATTERN.fullmatch(resource) is None:
                raise VerificationError(f"{path} is not the named actuator resource")
            resource_project = ACTUATOR_PATTERN.fullmatch(resource).group(1)
            if resource_project != project_id:
                raise VerificationError(
                    f"{path}.resource does not use manifest.projectId"
                )
        else:
            secret_count += 1
            match = SECRET_PATTERN.fullmatch(resource)
            if match is None or name != f"secret:{match.group(2)}":
                raise VerificationError(f"{path} is not a consistently named secret")
            resource_project = match.group(1)
            if resource_project != project_number:
                raise VerificationError(
                    f"{path}.resource does not use manifest.projectNumber"
                )
        if (
            scope_match.group(1) == "projects"
            and scope_match.group(2) != project_id
        ):
            raise VerificationError(
                f"{path}.scope does not use manifest.projectId"
            )
        if scope_match.group(1) == "folders":
            raise VerificationError(
                f"{path}.scope must cover the project or its organization"
            )

        analysis = target.get("analysis")
        prepared.append((name, kind, scope, resource, allowed, analysis))

    if actuator_count != 1:
        raise VerificationError("manifest must contain exactly one actuator")
    if secret_count < 1:
        raise VerificationError("manifest must contain at least one named secret")

    if live:
        expected_scope = live_analyzer_scope(
            project_id=project_id,
            project_number=project_number,
            runner=runner,
            gcloud=gcloud,
        )
        configured_scopes = {scope for _name, _kind, scope, *_rest in prepared}
        if configured_scopes != {expected_scope}:
            if expected_scope.startswith("organizations/"):
                raise VerificationError(
                    "project has organization or folder ancestry; an explicit "
                    f"{expected_scope} analyzer scope is required"
                )
            raise VerificationError(
                "standalone project must use its exact project analyzer scope"
            )

    verified: dict[str, tuple[str, ...]] = {}
    for index, (name, kind, scope, resource, allowed, analysis) in enumerate(prepared):
        if live:
            analysis = live_analysis(
                scope=scope,
                resource=resource,
                permission=PERMISSIONS[kind],
                runner=runner,
                gcloud=gcloud,
            )
        effective = tuple(
            sorted(
                verify_response(
                    analysis,
                    scope=scope,
                    resource=resource,
                    permission=PERMISSIONS[kind],
                    path=f"manifest.targets[{index}].analysis",
                )
            )
        )
        if effective != allowed:
            extra = sorted(set(effective) - set(allowed))
            missing = sorted(set(allowed) - set(effective))
            if extra:
                raise VerificationError(
                    f"{name} has nonallowlisted effective principal: {extra[0]}"
                )
            raise VerificationError(
                f"{name} is missing allowlisted effective principal: {missing[0]}"
            )
        verified[name] = effective
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify effective Cloud Run and Secret Manager IAM allowlists."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument(
        "--live",
        action="store_true",
        help="ignore embedded analyses and query gcloud Policy Analyzer read-only",
    )
    parser.add_argument("--gcloud", default="gcloud")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.input.read_text(encoding="utf-8"))
        verified = verify_manifest(
            manifest,
            live=args.live,
            gcloud=args.gcloud,
        )
    except (OSError, json.JSONDecodeError, VerificationError) as error:
        print(f"effective IAM refused: {error}", file=sys.stderr)
        return 1
    for name, principals in verified.items():
        print(f"effective IAM verified: {name}={','.join(principals)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
