#!/usr/bin/env bash
set -euo pipefail

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$LANE_DIR/lib/common.sh"

CONFIG=
MODE=render
ANALYZER_SCOPE=
while (($#)); do
  case "$1" in
    --config)
      (($# >= 2)) || lane_die "--config requires a path"
      CONFIG=$2
      shift 2
      ;;
    --render)
      MODE=render
      shift
      ;;
    --apply)
      MODE=apply
      shift
      ;;
    --verify-protected-identity)
      MODE=verify-identity
      shift
      ;;
    --analyzer-scope)
      (($# >= 2)) || lane_die "--analyzer-scope requires a value"
      ANALYZER_SCOPE=$2
      shift 2
      ;;
    *)
      lane_die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$CONFIG" ]] || lane_die "--config is required"
if [[ "$MODE" != render ]]; then
  export REQUIRE_DEPLOYMENT_CONFIG_PIN=true
fi
DEPLOY_CONFIG_KEYS=()
while IFS= read -r name; do
  DEPLOY_CONFIG_KEYS+=("$name")
done < <(deploy_config_variables)
load_lane_config "$CONFIG" "${DEPLOY_CONFIG_KEYS[@]}"
validate_lane_config
require_var PROJECT_PARENT
[[ "$PROJECT_PARENT" =~ ^organizations/[1-9][0-9]*$ ]] \
  || lane_die "production deployment requires PROJECT_PARENT=organizations/NUMBER"
if [[ -n "$ANALYZER_SCOPE" \
      && "$ANALYZER_SCOPE" != "$PROJECT_PARENT" ]]; then
  lane_die "--analyzer-scope must exactly equal PROJECT_PARENT=$PROJECT_PARENT"
fi

readonly EXPECTED_GITHUB_REPOSITORY="emiliaprotocol/emilia-protocol"
readonly EXPECTED_GITHUB_REF="refs/heads/main"
readonly EXPECTED_GITHUB_ENVIRONMENT="consequence-control-production"
readonly EXPECTED_GITHUB_WORKFLOW_REF="${EXPECTED_GITHUB_REPOSITORY}/.github/workflows/consequence-control-deploy.yml@${EXPECTED_GITHUB_REF}"
readonly DEPLOYER_ROLE_ID="emiliaConsequenceDeployer"

ACTUATOR_SA=$(runtime_service_account_email "$ACTUATOR_SERVICE_ACCOUNT")
DECISION_SA=$(runtime_service_account_email "$DECISION_SERVICE_ACCOUNT")
ACTUATOR_REVISION=$(candidate_revision "$ACTUATOR_SERVICE")
DECISION_REVISION=$(candidate_revision "$DECISION_SERVICE")
CANARY_TAG=$(candidate_tag)
DEPLOY_REQUIRED_APIS=(
  artifactregistry.googleapis.com
  cloudasset.googleapis.com
  cloudkms.googleapis.com
  cloudresourcemanager.googleapis.com
  compute.googleapis.com
  iam.googleapis.com
  orgpolicy.googleapis.com
  run.googleapis.com
  secretmanager.googleapis.com
  serviceusage.googleapis.com
)

actuator_env="NODE_ENV=production,HOST=0.0.0.0,EMILIA_ACTUATOR_DATABASE_PRINCIPAL=${ACTUATOR_DATABASE_PRINCIPAL},EMILIA_ACTUATOR_TENANT_ID=${TENANT_ID},EMILIA_ACTUATOR_GITHUB_OWNER=${GITHUB_OWNER},EMILIA_ACTUATOR_GITHUB_REPO=${GITHUB_REPO},EMILIA_ACTUATOR_GITHUB_ISSUE_NUMBER=${GITHUB_ISSUE_NUMBER},EMILIA_ACTUATOR_ENVELOPE_ISSUER_ID=${ENVELOPE_ISSUER_ID},EMILIA_ACTUATOR_ENVELOPE_KEY_ID=${ENVELOPE_KEY_ID},EMILIA_ACTUATOR_OBSERVATION_ISSUER_ID=${OBSERVATION_ISSUER_ID},EMILIA_ACTUATOR_OBSERVATION_KEY_ID=${OBSERVATION_KEY_ID}"
actuator_secrets="EMILIA_ACTUATOR_DATABASE_URL=${ACTUATOR_DATABASE_URL_SECRET},EMILIA_ACTUATOR_API_TOKEN=${ACTUATOR_API_TOKEN_SECRET},EMILIA_ACTUATOR_ENVELOPE_PUBLIC_KEY=${ACTUATOR_ENVELOPE_PUBLIC_KEY_SECRET},EMILIA_ACTUATOR_OBSERVATION_PRIVATE_KEY=${ACTUATOR_OBSERVATION_PRIVATE_KEY_SECRET},EMILIA_ACTUATOR_GITHUB_APP_ID=${ACTUATOR_GITHUB_APP_ID_SECRET},EMILIA_ACTUATOR_GITHUB_INSTALLATION_ID=${ACTUATOR_GITHUB_INSTALLATION_ID_SECRET},EMILIA_ACTUATOR_GITHUB_PRIVATE_KEY=${ACTUATOR_GITHUB_PRIVATE_KEY_SECRET}"

actuator_command=(
  gcloud run deploy "$ACTUATOR_SERVICE"
  "--project=$PROJECT_ID"
  "--region=$REGION"
  --platform=managed
  "--image=$ACTUATOR_IMAGE"
  "--revision-suffix=$RELEASE_ID"
  "--tag=$CANARY_TAG"
  --no-traffic
  "--service-account=$ACTUATOR_SA"
  "--ingress=$ACTUATOR_INGRESS"
  --no-invoker-iam-check
  "--network=$NETWORK"
  "--subnet=$SUBNET"
  --vpc-egress=all-traffic
  "--cpu=$ACTUATOR_CPU"
  "--memory=$ACTUATOR_MEMORY"
  "--min=$ACTUATOR_MIN_INSTANCES"
  "--max=$ACTUATOR_MAX_INSTANCES"
  "--concurrency=$ACTUATOR_CONCURRENCY"
  --timeout=30s
  --port=8080
  --execution-environment=gen2
  --no-session-affinity
  --deploy-health-check
  "--startup-probe=tcpSocket.port=8080,periodSeconds=2,timeoutSeconds=1,failureThreshold=30"
  "--set-env-vars=$actuator_env"
  "--set-secrets=$actuator_secrets"
  "--labels=emilia-plane=actuator,emilia-release=$RELEASE_ID"
  --quiet
)

decision_command() {
  local actuator_url=$1
  local actuator_audience=$2
  local decision_env decision_secrets
  decision_env="NODE_ENV=production,HOST=0.0.0.0,EMILIA_CONSEQUENCE_CONFIG=apps/consequence-control-service/src/production-config.js,EMILIA_CONSEQUENCE_TENANT_ID=${TENANT_ID},EMILIA_CONSEQUENCE_RELYING_PARTY_ID=${DECISION_RELYING_PARTY_ID},EMILIA_CONSEQUENCE_EXECUTOR_ID=${DECISION_EXECUTOR_ID},EMILIA_CONSEQUENCE_PRINCIPAL_ID=${DECISION_PRINCIPAL_ID},EMILIA_CONSEQUENCE_APPROVAL_ENDPOINT=${DECISION_APPROVAL_ENDPOINT},EMILIA_CONSEQUENCE_GITHUB_OWNER=${GITHUB_OWNER},EMILIA_CONSEQUENCE_GITHUB_REPO=${GITHUB_REPO},EMILIA_CONSEQUENCE_GITHUB_ISSUE_NUMBER=${GITHUB_ISSUE_NUMBER},EMILIA_CONSEQUENCE_PROPOSAL_TTL_SEC=${DECISION_PROPOSAL_TTL_SEC},EMILIA_CONSEQUENCE_ACTUATOR_ORIGIN=${actuator_url},EMILIA_CONSEQUENCE_ACTUATOR_AUDIENCE=${actuator_audience},EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_ISSUER_ID=${ENVELOPE_ISSUER_ID},EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_KEY_ID=${ENVELOPE_KEY_ID},EMILIA_CONSEQUENCE_ACTUATOR_OBSERVATION_ISSUER_ID=${OBSERVATION_ISSUER_ID},EMILIA_CONSEQUENCE_ACTUATOR_EVIDENCE_KEY_ID=${OBSERVATION_KEY_ID},EMILIA_CONSEQUENCE_ACTUATOR_TIMEOUT_MS=${DECISION_ACTUATOR_TIMEOUT_MS},EMILIA_CONSEQUENCE_AEB_REQUIREMENT_REF=${DECISION_AEB_REQUIREMENT_REF},EMILIA_CONSEQUENCE_SHUTDOWN_GRACE_MS=${DECISION_SHUTDOWN_GRACE_MS}"
  decision_secrets="EMILIA_CONSEQUENCE_EXECUTOR_DATABASE_URL=${DECISION_EXECUTOR_DATABASE_URL_SECRET},EMILIA_CONSEQUENCE_RECOVERY_DATABASE_URL=${DECISION_RECOVERY_DATABASE_URL_SECRET},EMILIA_CONSEQUENCE_API_TOKEN=${DECISION_API_TOKEN_SECRET},EMILIA_CONSEQUENCE_RECOVERY_TOKEN=${DECISION_RECOVERY_TOKEN_SECRET},EMILIA_CONSEQUENCE_PROPOSAL_HMAC_KEY=${DECISION_PROPOSAL_HMAC_KEY_SECRET},EMILIA_CONSEQUENCE_OWNER_HMAC_KEY=${DECISION_OWNER_HMAC_KEY_SECRET},EMILIA_CONSEQUENCE_GATE_TRUST_JSON=${DECISION_GATE_TRUST_JSON_SECRET},EMILIA_CONSEQUENCE_AEB_CONFIG_JSON=${DECISION_AEB_CONFIG_JSON_SECRET},EMILIA_CONSEQUENCE_STATUS_CONFIG_JSON=${DECISION_STATUS_CONFIG_JSON_SECRET},EMILIA_CONSEQUENCE_APPROVAL_TOKEN=${DECISION_APPROVAL_TOKEN_SECRET},EMILIA_CONSEQUENCE_ACTUATOR_API_TOKEN=${ACTUATOR_API_TOKEN_SECRET},EMILIA_CONSEQUENCE_ACTUATOR_ENVELOPE_PRIVATE_KEY=${DECISION_ENVELOPE_PRIVATE_KEY_SECRET},EMILIA_CONSEQUENCE_ACTUATOR_EVIDENCE_PUBLIC_KEY=${DECISION_OBSERVATION_PUBLIC_KEY_SECRET}"
  DECISION_COMMAND=(
    gcloud run deploy "$DECISION_SERVICE"
    "--project=$PROJECT_ID"
    "--region=$REGION"
    --platform=managed
    "--image=$DECISION_IMAGE"
    "--revision-suffix=$RELEASE_ID"
    "--tag=$CANARY_TAG"
    --no-traffic
    "--service-account=$DECISION_SA"
    "--ingress=$DECISION_INGRESS"
    --no-invoker-iam-check
    "--network=$NETWORK"
    "--subnet=$SUBNET"
    --vpc-egress=all-traffic
    "--cpu=$DECISION_CPU"
    "--memory=$DECISION_MEMORY"
    "--min=$DECISION_MIN_INSTANCES"
    "--max=$DECISION_MAX_INSTANCES"
    "--concurrency=$DECISION_CONCURRENCY"
    --timeout=60s
    --port=8080
    --execution-environment=gen2
    --no-session-affinity
    --deploy-health-check
    "--startup-probe=httpGet.path=/v1/ready,httpGet.port=8080,periodSeconds=2,timeoutSeconds=1,failureThreshold=30"
    "--liveness-probe=httpGet.path=/v1/live,httpGet.port=8080,initialDelaySeconds=10,periodSeconds=30,timeoutSeconds=2,failureThreshold=3"
    "--readiness-probe=httpGet.path=/v1/ready,httpGet.port=8080,periodSeconds=5,timeoutSeconds=2,failureThreshold=3,successThreshold=1"
    "--set-env-vars=$decision_env"
    "--set-secrets=$decision_secrets"
    "--labels=emilia-plane=decision,emilia-release=$RELEASE_ID"
    --quiet
  )
}

require_apply_approval() {
  [[ "${DEPLOYMENT_APPROVED:-}" == true ]] \
    || lane_die "apply requires DEPLOYMENT_APPROVED=true"
  [[ "${DEPLOYMENT_CONFIRM_PROJECT:-}" == "$PROJECT_ID" ]] \
    || lane_die "DEPLOYMENT_CONFIRM_PROJECT must exactly equal PROJECT_ID"
  command -v gcloud >/dev/null 2>&1 || lane_die "gcloud is required for apply"
}

expected_wif_subject() {
  printf '%s' \
    'repo:emiliaprotocol/emilia-protocol:environment:consequence-control-production'
}

require_protected_workflow_context() {
  local name
  for name in \
    GITHUB_ACTIONS GITHUB_REPOSITORY GITHUB_REPOSITORY_ID \
    GITHUB_REPOSITORY_OWNER_ID GITHUB_REF GITHUB_SHA GITHUB_WORKFLOW_REF \
    EMILIA_GITHUB_WORKFLOW_SHA GITHUB_EVENT_NAME ACTIONS_ID_TOKEN_REQUEST_URL \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN GOOGLE_GHA_CREDS_PATH \
    EMILIA_DEPLOY_ENVIRONMENT EMILIA_DEPLOY_WIF_PROVIDER; do
    [[ -n "${!name:-}" ]] || lane_die "$name is required for protected deployment"
  done
  [[ "$GITHUB_ACTIONS" == true ]] || lane_die "deployment requires GitHub Actions"
  [[ "$GITHUB_REPOSITORY" == "$EXPECTED_GITHUB_REPOSITORY" ]] \
    || lane_die "GitHub repository identity mismatch"
  [[ "$GITHUB_REPOSITORY_ID" =~ ^[1-9][0-9]*$ \
      && "$GITHUB_REPOSITORY_OWNER_ID" =~ ^[1-9][0-9]*$ ]] \
    || lane_die "immutable GitHub repository IDs are required"
  [[ "$GITHUB_REF" == "$EXPECTED_GITHUB_REF" ]] \
    || lane_die "protected deployment requires refs/heads/main"
  [[ "$GITHUB_WORKFLOW_REF" == "$EXPECTED_GITHUB_WORKFLOW_REF" ]] \
    || lane_die "protected deployment workflow identity mismatch"
  [[ "$EMILIA_GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" \
      && "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] \
    || lane_die "workflow SHA must exactly equal the deployed main-branch SHA"
  [[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]] \
    || lane_die "protected deployment requires workflow_dispatch"
  [[ "$EMILIA_DEPLOY_ENVIRONMENT" == "$EXPECTED_GITHUB_ENVIRONMENT" ]] \
    || lane_die "protected GitHub environment identity mismatch"
  [[ "$EMILIA_DEPLOY_WIF_PROVIDER" =~ ^projects/([1-9][0-9]*)/locations/global/workloadIdentityPools/([a-z][a-z0-9-]{3,31})/providers/([a-z][a-z0-9-]{3,31})$ ]] \
    || lane_die "EMILIA_DEPLOY_WIF_PROVIDER is not a canonical provider resource"
  WIF_PROJECT_NUMBER=${BASH_REMATCH[1]}
  WIF_POOL_ID=${BASH_REMATCH[2]}
  WIF_PROVIDER_ID=${BASH_REMATCH[3]}
}

resolve_active_deployer() {
  local account active_principal
  account=$(gcloud config get-value account --quiet)
  [[ -n "$account" && "$account" != "(unset)" \
      && "$account" != *[$'\r\n\t ']* ]] \
    || lane_die "active gcloud deployer account could not be resolved exactly"
  case "$account" in
    serviceAccount:*) active_principal=$account ;;
    *@*.gserviceaccount.com) active_principal="serviceAccount:$account" ;;
    *) lane_die "active gcloud deployer must be one service account" ;;
  esac
  [[ "$active_principal" == "$DEPLOYER_PRINCIPAL" ]] \
    || lane_die "active gcloud identity $active_principal does not exactly match DEPLOYER_PRINCIPAL $DEPLOYER_PRINCIPAL"
}

verify_keyless_wif_boundary() {
  local deployer_email=${DEPLOYER_PRINCIPAL#serviceAccount:}
  local deployer_project=${deployer_email#*@}
  deployer_project=${deployer_project%.iam.gserviceaccount.com}
  [[ "$deployer_project" == "$PROJECT_ID" ]] \
    || lane_die "protected deployer service account must belong to PROJECT_ID"
  local provider="$IAM_TMPDIR/wif-provider.json"
  local policy="$IAM_TMPDIR/deployer-service-account-policy.json"
  local key_creation_policy="$IAM_TMPDIR/disable-key-creation-policy.json"
  local key_upload_policy="$IAM_TMPDIR/disable-key-upload-policy.json"
  local account key_file key_files=()
  gcloud iam workload-identity-pools providers describe "$WIF_PROVIDER_ID" \
    "--workload-identity-pool=$WIF_POOL_ID" \
    "--project=$WIF_PROJECT_NUMBER" --location=global --format=json \
    > "$provider" || lane_die "protected WIF provider is unreadable"
  gcloud iam service-accounts get-iam-policy "$deployer_email" \
    "--project=$deployer_project" --format=json > "$policy" \
    || lane_die "deployer service-account trust policy is unreadable"
  gcloud resource-manager org-policies describe \
    constraints/iam.disableServiceAccountKeyCreation \
    "--project=$PROJECT_ID" --effective --format=json \
    > "$key_creation_policy" \
    || lane_die "effective service-account key-creation policy is unreadable"
  gcloud resource-manager org-policies describe \
    constraints/iam.disableServiceAccountKeyUpload \
    "--project=$PROJECT_ID" --effective --format=json \
    > "$key_upload_policy" \
    || lane_die "effective service-account key-upload policy is unreadable"
  for account in \
    "$deployer_email" "$ACTUATOR_SA" "$DECISION_SA" \
    "$(runtime_service_account_email "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT")" \
    "$(runtime_service_account_email "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT")"; do
    key_file="$IAM_TMPDIR/keys-${account%%@*}.json"
    gcloud iam service-accounts keys list \
      "--iam-account=$account" "--project=$PROJECT_ID" --format=json \
      > "$key_file" \
      || lane_die "service-account key inventory is unreadable: $account"
    key_files+=("$account=$key_file")
  done
  python3 - "$provider" "$policy" "$GOOGLE_GHA_CREDS_PATH" \
    "$EMILIA_DEPLOY_WIF_PROVIDER" "$WIF_PROJECT_NUMBER" "$WIF_POOL_ID" \
    "$(expected_wif_subject)" "$DEPLOYER_PRINCIPAL" \
    "$GITHUB_REPOSITORY_ID" "$GITHUB_REPOSITORY_OWNER_ID" \
    "$EXPECTED_GITHUB_WORKFLOW_REF" "$GITHUB_SHA" \
    "$key_creation_policy" "$key_upload_policy" "${key_files[@]}" <<'PY' || \
    lane_die "deployer is not bounded to the exact immutable protected workflow identity"
import json
from pathlib import Path
import sys

(
    provider_path,
    policy_path,
    credentials_path,
    provider_resource,
    project_number,
    pool_id,
    subject,
    deployer_principal,
    repository_id,
    owner_id,
    workflow_ref,
    workflow_sha,
    key_creation_policy_path,
    key_upload_policy_path,
    *key_inventory_specs,
) = sys.argv[1:]
provider = json.loads(Path(provider_path).read_text(encoding="utf-8"))
policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))
credentials = json.loads(Path(credentials_path).read_text(encoding="utf-8"))
for policy_path, constraint in (
    (
        key_creation_policy_path,
        "constraints/iam.disableServiceAccountKeyCreation",
    ),
    (
        key_upload_policy_path,
        "constraints/iam.disableServiceAccountKeyUpload",
    ),
):
    key_policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))
    if key_policy.get("constraint") != constraint:
        raise SystemExit(f"effective key policy mismatch: {constraint}")
    if key_policy.get("booleanPolicy", {}).get("enforced") is not True:
        raise SystemExit(f"effective key policy is not enforced: {constraint}")
for inventory_spec in key_inventory_specs:
    account, separator, inventory_path = inventory_spec.partition("=")
    if not separator or not account or not inventory_path:
        raise SystemExit("service-account key inventory descriptor is malformed")
    inventory = json.loads(Path(inventory_path).read_text(encoding="utf-8"))
    if not isinstance(inventory, list):
        raise SystemExit(f"service-account key inventory is malformed: {account}")
    for key in inventory:
        if not isinstance(key, dict):
            raise SystemExit(f"service-account key record is malformed: {account}")
        if key.get("keyType") == "USER_MANAGED" or key.get("keyOrigin") == "USER_PROVIDED":
            raise SystemExit(f"user-managed service-account key exists: {account}")
if provider.get("state") != "ACTIVE":
    raise SystemExit("WIF provider is not ACTIVE")
if provider.get("oidc", {}).get("issuerUri", "").rstrip("/") != (
    "https://token.actions.githubusercontent.com"
):
    raise SystemExit("WIF issuer mismatch")
mapping = provider.get("attributeMapping", {})
if mapping != {
    "google.subject": "assertion.sub",
    "attribute.repository_id": "assertion.repository_id",
    "attribute.repository_owner_id": "assertion.repository_owner_id",
    "attribute.ref": "assertion.ref",
    "attribute.workflow_ref": "assertion.workflow_ref",
    "attribute.workflow_sha": "assertion.workflow_sha",
}:
    raise SystemExit("WIF attribute mapping is not closed")
condition = provider.get("attributeCondition", "")
expected_condition = "&&".join(
    [
        f"assertion.sub=='{subject}'",
        f"attribute.repository_id=='{repository_id}'",
        f"attribute.repository_owner_id=='{owner_id}'",
        "attribute.ref=='refs/heads/main'",
        f"attribute.workflow_ref=='{workflow_ref}'",
        f"attribute.workflow_sha=='{workflow_sha}'",
    ]
)
if "".join(condition.split()) != expected_condition:
    raise SystemExit("WIF provider condition is not exact")
member = (
    "principal://iam.googleapis.com/projects/"
    f"{project_number}/locations/global/workloadIdentityPools/{pool_id}/"
    f"subject/{subject}"
)
bindings = policy.get("bindings", [])
if bindings != [
    {
        "role": "roles/iam.workloadIdentityUser",
        "members": [member],
    }
]:
    raise SystemExit("deployer service account is broadly impersonable")
if credentials.get("type") != "external_account":
    raise SystemExit("Google credentials are not external-account credentials")
if credentials.get("audience") != f"//iam.googleapis.com/{provider_resource}":
    raise SystemExit("credential audience does not match the pinned WIF provider")
deployer_email = deployer_principal.removeprefix("serviceAccount:")
if deployer_email not in credentials.get("service_account_impersonation_url", ""):
    raise SystemExit("credential impersonation target does not match deployer")
PY
}

verify_dedicated_project() {
  local project="$IAM_TMPDIR/project.json"
  local ancestry="$IAM_TMPDIR/ancestry.json"
  gcloud projects describe "$PROJECT_ID" --format=json > "$project"
  gcloud projects get-ancestors "$PROJECT_ID" --format=json --quiet > "$ancestry"
  python3 - "$project" "$ancestry" "$PROJECT_ID" \
    "${PROJECT_PARENT#organizations/}" <<'PY' || \
    lane_die "standalone, shared, relabeled, or wrong-parent project is forbidden"
import json
from pathlib import Path
import sys

project_path, ancestry_path, project_id, organization_id = sys.argv[1:]
project = json.loads(Path(project_path).read_text(encoding="utf-8"))
ancestry = json.loads(Path(ancestry_path).read_text(encoding="utf-8"))
if project.get("projectId") != project_id:
    raise SystemExit("project ID mismatch")
if project.get("labels") != {"emilia-purpose": "consequence-control"}:
    raise SystemExit("dedication label mismatch")
if project.get("parent") != {"type": "organization", "id": organization_id}:
    raise SystemExit("project parent mismatch")
actual = [(entry.get("type"), entry.get("id")) for entry in ancestry]
expected = [("project", project_id), ("organization", organization_id)]
if actual != expected:
    raise SystemExit("project ancestry mismatch")
PY
  RESOLVED_ANALYZER_SCOPE=$PROJECT_PARENT
}

verify_deployment_prerequisites() {
  local api state account ref secret version
  for api in "${DEPLOY_REQUIRED_APIS[@]}"; do
    state=$(gcloud services describe "$api" \
      "--project=$PROJECT_ID" '--format=value(state)' 2>/dev/null) \
      || lane_die "$api must already be ENABLED by provisioning"
    [[ "$state" == ENABLED ]] \
      || lane_die "$api must already be ENABLED by provisioning"
  done
  for account in "$ACTUATOR_SA" "$DECISION_SA"; do
    gcloud iam service-accounts describe "$account" \
      "--project=$PROJECT_ID" >/dev/null 2>&1 \
      || lane_die "runtime service account $account must already exist from provisioning"
  done
  while IFS= read -r ref; do
    secret=$(secret_name "$ref")
    version=$(secret_version "$ref")
    state=$(gcloud secrets versions describe "$version" \
      "--secret=$secret" "--project=$PROJECT_ID" \
      '--format=value(state)' 2>/dev/null) \
      || lane_die "secret version $ref must already be present and ENABLED"
    [[ "$state" == ENABLED ]] \
      || lane_die "secret version $ref must already be present and ENABLED"
  done < <(configured_secret_refs)
}

capture_direct_iam_snapshot() {
  local directory=$1 variable ref secret account
  mkdir -p "$directory"
  gcloud projects describe "$PROJECT_ID" \
    --format=json > "$directory/project-resource.json"
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --format=json > "$directory/project.json"
  gcloud iam roles describe "$DEPLOYER_ROLE_ID" \
    "--project=$PROJECT_ID" --format=json > "$directory/deployer-role.json"
  for account in "$ACTUATOR_SA" "$DECISION_SA"; do
    gcloud iam service-accounts get-iam-policy "$account" \
      "--project=$PROJECT_ID" --format=json \
      > "$directory/sa-${account%%@*}.json"
  done
  while IFS= read -r secret; do
    gcloud secrets get-iam-policy "$secret" \
      "--project=$PROJECT_ID" --format=json \
      > "$directory/secret-$secret.json"
  done < <(
    while IFS= read -r variable; do
      ref=${!variable}
      secret_name "$ref"
      printf '\n'
    done < <(all_secret_variables) | sort -u
  )
}

verify_direct_iam_snapshot() {
  local directory=$1
  python3 - "$directory" "$PROJECT_ID" "$PROVISIONER_PRINCIPAL" \
    "$DEPLOYER_PRINCIPAL" "$ACTUATOR_SA" "$DECISION_SA" \
    "$REGION" "$ACTUATOR_SERVICE" <<'PY' || \
    lane_die "direct current IAM policy proof failed"
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
project_id, provisioner, deployer, actuator_sa, decision_sa, region, service = sys.argv[2:]
role_name = f"projects/{project_id}/roles/emiliaConsequenceDeployer"
project = json.loads(
    (root / "project-resource.json").read_text(encoding="utf-8")
)
project_number = str(project.get("projectNumber", ""))
if not re.fullmatch(r"[1-9][0-9]{5,29}", project_number):
    raise SystemExit("project number is unavailable")
service_agent = re.compile(
    rf"^serviceAccount:(service-{project_number}@|{project_number}@cloudservices[.])"
)
role = json.loads((root / "deployer-role.json").read_text(encoding="utf-8"))
permissions = role.get("includedPermissions", [])
if not isinstance(permissions, list) or any(
    permission.endswith(".setIamPolicy") for permission in permissions
):
    raise SystemExit("deployer role retains an IAM policy writer")
if "run.services.update" not in permissions:
    raise SystemExit("deployer role is not the expected rollout role")
policy = json.loads((root / "project.json").read_text(encoding="utf-8"))
bindings = policy.get("bindings", [])
for binding in bindings:
    if provisioner in binding.get("members", []):
        raise SystemExit("provisioner still has direct project custody")
    if binding.get("role") in {"roles/owner", "roles/editor"}:
        raise SystemExit("broad project role remains")
    if binding.get("role") in {role_name, "roles/run.invoker"}:
        continue
    if (
        not str(binding.get("role", "")).endswith(".serviceAgent")
        or binding.get("condition")
        or not binding.get("members")
        or any(
            not service_agent.match(member)
            for member in binding.get("members", [])
        )
    ):
        raise SystemExit("unrelated direct project IAM binding remains")
deployer_bindings = [
    binding for binding in bindings
    if deployer in binding.get("members", [])
]
if deployer_bindings != [{"role": role_name, "members": [deployer]}]:
    raise SystemExit("deployer project binding is not exact")
invoker = [
    binding for binding in bindings
    if binding.get("role") == "roles/run.invoker"
]
expected_condition = {
    "title": "emilia-actuator-invoker",
    "description": "Decision workload may invoke only the actuator",
    "expression": (
        "resource.name == "
        f"'//run.googleapis.com/projects/{project_id}/locations/{region}/"
        f"services/{service}'"
    ),
}
if invoker != [{
    "role": "roles/run.invoker",
    "members": [f"serviceAccount:{decision_sa}"],
    "condition": expected_condition,
}]:
    raise SystemExit("project-level actuator invoker binding is not exact")
for account in (actuator_sa, decision_sa):
    value = json.loads(
        (root / f"sa-{account.split('@', 1)[0]}.json").read_text(encoding="utf-8")
    )
    if value.get("bindings") != [{
        "role": "roles/iam.serviceAccountUser",
        "members": [deployer],
    }]:
        raise SystemExit(f"runtime actAs policy is not exact: {account}")
for path in root.glob("secret-*.json"):
    value = json.loads(path.read_text(encoding="utf-8"))
    for binding in value.get("bindings", []):
        if binding.get("role") != "roles/secretmanager.secretAccessor":
            raise SystemExit(f"unrelated secret IAM binding: {path.name}")
        allowed = {
            f"serviceAccount:{actuator_sa}",
            f"serviceAccount:{decision_sa}",
        }
        if not set(binding.get("members", [])) <= allowed:
            raise SystemExit(f"unrelated secret IAM member: {path.name}")
PY
  local variable ref secret member
  local members=() member_args=()
  while IFS= read -r secret; do
    members=()
    member_args=()
    if secret_is_used_by "$secret" actuator_secret_variables; then
      members+=("serviceAccount:$ACTUATOR_SA")
    fi
    if secret_is_used_by "$secret" decision_secret_variables; then
      members+=("serviceAccount:$DECISION_SA")
    fi
    for member in "${members[@]}"; do member_args+=(--member "$member"); done
    python3 "$LANE_DIR/reconcile-iam-policy.py" check \
      --input "$directory/secret-$secret.json" \
      --role roles/secretmanager.secretAccessor "${member_args[@]}" \
      || lane_die "direct secret IAM policy is not exact: $secret"
  done < <(
    while IFS= read -r variable; do
      ref=${!variable}
      secret_name "$ref"
      printf '\n'
    done < <(all_secret_variables) | sort -u
  )
}

snapshot_digest() {
  python3 - "$1" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.glob("*.json")):
    value = json.loads(path.read_text(encoding="utf-8"))
    value.pop("etag", None)
    digest.update(path.name.encode())
    digest.update(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
print(digest.hexdigest())
PY
}

verify_service_policies_empty() {
  local service policy
  for service in "$ACTUATOR_SERVICE" "$DECISION_SERVICE"; do
    policy="$IAM_TMPDIR/run-policy-$service.json"
    gcloud run services get-iam-policy "$service" \
      "--project=$PROJECT_ID" "--region=$REGION" --format=json > "$policy"
    python3 - "$policy" <<'PY' || \
      lane_die "Cloud Run service IAM must remain empty; invoker access is project-scoped"
import json
from pathlib import Path
import sys
value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("bindings", []):
    raise SystemExit("resource IAM binding found")
PY
  done
}

verify_effective_iam_org_live() {
  local manifest="$IAM_TMPDIR/effective-iam.json" spec
  local arguments=(
    python3 "$LANE_DIR/emit-effective-iam-manifest.py"
    "--project=$PROJECT_ID"
    "--project-number=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["projectNumber"])' "$IAM_TMPDIR/project.json")"
    "--analyzer-scope=$RESOLVED_ANALYZER_SCOPE"
    "--region=$REGION"
    "--actuator-service=$ACTUATOR_SERVICE"
    "--decision-service=$DECISION_SERVICE"
    "--decision-principal=serviceAccount:$DECISION_SA"
    "--deployer-principal=$DEPLOYER_PRINCIPAL"
    "--output=$manifest"
  )
  while IFS= read -r spec; do arguments+=(--secret "$spec"); done \
    < <(effective_iam_secret_args)
  "${arguments[@]}" \
    || lane_die "organization-scoped effective IAM manifest generation failed"
  "$LANE_DIR/verify-effective-iam.py" --input "$manifest" --live \
    || lane_die "organization-scoped effective IAM is broader than the closed allowlist"
}

resolve_tag_url() {
  gcloud run services describe "$ACTUATOR_SERVICE" \
    "--project=$PROJECT_ID" "--region=$REGION" --format=json \
    | python3 -c '
import json, sys
tag = sys.argv[1]
data = json.load(sys.stdin)
for target in data.get("status", {}).get("traffic", []):
    if target.get("tag") == tag and target.get("url"):
        print(target["url"])
        raise SystemExit(0)
raise SystemExit("candidate actuator tag URL not found")
' "$CANARY_TAG"
}

resolve_service_url() {
  gcloud run services describe "$ACTUATOR_SERVICE" \
    "--project=$PROJECT_ID" "--region=$REGION" \
    --format='value(status.url)'
}

render_plan() {
  printf '# protected boundary: immutable repository IDs, exact main ref, protected environment, workflow ref, active service account, WIF provider, and SA trust policy\n'
  shell_join gcloud config get-value account --quiet
  shell_join gcloud iam workload-identity-pools providers describe \
    '<provider-id>' --workload-identity-pool='<pool-id>' \
    --project='<pool-project-number>' --location=global --format=json
  shell_join gcloud iam service-accounts get-iam-policy \
    "${DEPLOYER_PRINCIPAL#serviceAccount:}" --format=json
  shell_join gcloud resource-manager org-policies describe \
    constraints/iam.disableServiceAccountKeyCreation \
    "--project=$PROJECT_ID" --effective --format=json
  shell_join gcloud resource-manager org-policies describe \
    constraints/iam.disableServiceAccountKeyUpload \
    "--project=$PROJECT_ID" --effective --format=json
  shell_join gcloud iam service-accounts keys list \
    '--iam-account=<each protected service account>' \
    "--project=$PROJECT_ID" --format=json
  printf '# direct current project/custom-role/runtime-SA/secret IAM snapshots must be exact and quiescent\n'
  shell_join gcloud projects describe "$PROJECT_ID" --format=json
  shell_join gcloud projects get-ancestors "$PROJECT_ID" --format=json --quiet
  shell_join gcloud projects get-iam-policy "$PROJECT_ID" --format=json
  shell_join gcloud iam roles describe "$DEPLOYER_ROLE_ID" \
    "--project=$PROJECT_ID" --format=json
  shell_join gcloud iam service-accounts get-iam-policy "$ACTUATOR_SA" \
    "--project=$PROJECT_ID" --format=json
  shell_join gcloud iam service-accounts get-iam-policy "$DECISION_SA" \
    "--project=$PROJECT_ID" --format=json
  shell_join sleep 5
  printf '# candidate actuator: %s, zero traffic and no IAM mutation\n' "$ACTUATOR_REVISION"
  shell_join "${actuator_command[@]}"
  printf 'ACTUATOR_AUDIENCE=<resolved-canonical-url-for-%s>\n' "$ACTUATOR_SERVICE"
  printf 'ACTUATOR_CANARY_URL=<resolved-from-%s-tag-%s>\n' \
    "$ACTUATOR_SERVICE" "$CANARY_TAG"
  # shellcheck disable=SC2016
  decision_command '${ACTUATOR_CANARY_URL}' '${ACTUATOR_AUDIENCE}'
  printf '# candidate decision: %s, zero traffic and no IAM mutation\n' "$DECISION_REVISION"
  shell_join "${DECISION_COMMAND[@]}"
  printf '# read Cloud Run policies directly, compare pre/post IAM snapshots, then retain Policy Analyzer as inherited-access evidence\n'
  shell_join gcloud run services get-iam-policy "$ACTUATOR_SERVICE" \
    "--project=$PROJECT_ID" "--region=$REGION" --format=json
  shell_join gcloud run services get-iam-policy "$DECISION_SERVICE" \
    "--project=$PROJECT_ID" "--region=$REGION" --format=json
  shell_join "$LANE_DIR/verify-effective-iam.py" \
    --input '<effective-iam.json>' --live
  printf '# stop: no production traffic is changed by deploy.sh\n'
}

if [[ "$MODE" == render ]]; then
  render_plan
  exit 0
fi

IAM_TMPDIR=$(mktemp -d)
trap 'rm -rf "$IAM_TMPDIR"; lane_cleanup_pinned_config' EXIT
require_protected_workflow_context
resolve_active_deployer
verify_keyless_wif_boundary
verify_dedicated_project

if [[ "$MODE" == verify-identity ]]; then
  capture_direct_iam_snapshot "$IAM_TMPDIR/iam-identity-proof"
  verify_direct_iam_snapshot "$IAM_TMPDIR/iam-identity-proof"
  printf 'protected deployment identity and direct IAM boundary verified\n'
  exit 0
fi

require_apply_approval
verify_deployment_prerequisites

capture_direct_iam_snapshot "$IAM_TMPDIR/iam-before-a"
verify_direct_iam_snapshot "$IAM_TMPDIR/iam-before-a"
sleep 5
capture_direct_iam_snapshot "$IAM_TMPDIR/iam-before-b"
verify_direct_iam_snapshot "$IAM_TMPDIR/iam-before-b"
BEFORE_A=$(snapshot_digest "$IAM_TMPDIR/iam-before-a")
BEFORE_B=$(snapshot_digest "$IAM_TMPDIR/iam-before-b")
[[ "$BEFORE_A" == "$BEFORE_B" ]] \
  || lane_die "IAM was not quiescent before deployment"

"${actuator_command[@]}"
ACTUATOR_AUDIENCE=$(resolve_service_url)
ACTUATOR_CANARY_URL=$(resolve_tag_url)
[[ "$ACTUATOR_AUDIENCE" == https://* ]] \
  || lane_die "resolved actuator audience is not https"
[[ "$ACTUATOR_CANARY_URL" == https://* ]] \
  || lane_die "resolved actuator candidate URL is not https"
decision_command "$ACTUATOR_CANARY_URL" "$ACTUATOR_AUDIENCE"
"${DECISION_COMMAND[@]}"

verify_service_policies_empty
capture_direct_iam_snapshot "$IAM_TMPDIR/iam-after"
verify_direct_iam_snapshot "$IAM_TMPDIR/iam-after"
AFTER=$(snapshot_digest "$IAM_TMPDIR/iam-after")
[[ "$BEFORE_B" == "$AFTER" ]] \
  || lane_die "direct IAM changed during deployment"
verify_effective_iam_org_live

printf 'created zero-traffic candidates: %s and %s\n' \
  "$ACTUATOR_REVISION" "$DECISION_REVISION"
printf 'direct IAM remained exact/quiescent; no production traffic changed\n'
