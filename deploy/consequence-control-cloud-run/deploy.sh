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
load_lane_config "$CONFIG"
validate_lane_config
if [[ -n "$ANALYZER_SCOPE" \
      && "$ANALYZER_SCOPE" != "projects/$PROJECT_ID" \
      && ! "$ANALYZER_SCOPE" =~ ^organizations/[1-9][0-9]*$ ]]; then
  lane_die "--analyzer-scope must be projects/$PROJECT_ID or organizations/NUMBER"
fi

ACTUATOR_SA=$(runtime_service_account_email "$ACTUATOR_SERVICE_ACCOUNT")
DECISION_SA=$(runtime_service_account_email "$DECISION_SERVICE_ACCOUNT")
ACTUATOR_REVISION=$(candidate_revision "$ACTUATOR_SERVICE")
DECISION_REVISION=$(candidate_revision "$DECISION_SERVICE")
CANARY_TAG=$(candidate_tag)

actuator_env="NODE_ENV=production,HOST=0.0.0.0,EMILIA_ACTUATOR_DATABASE_PRINCIPAL=${ACTUATOR_DATABASE_PRINCIPAL},EMILIA_ACTUATOR_TENANT_ID=${TENANT_ID},EMILIA_ACTUATOR_GITHUB_OWNER=${GITHUB_OWNER},EMILIA_ACTUATOR_GITHUB_REPO=${GITHUB_REPO},EMILIA_ACTUATOR_GITHUB_ISSUE_NUMBER=${GITHUB_ISSUE_NUMBER},EMILIA_ACTUATOR_ENVELOPE_ISSUER_ID=${ENVELOPE_ISSUER_ID},EMILIA_ACTUATOR_ENVELOPE_KEY_ID=${ENVELOPE_KEY_ID},EMILIA_ACTUATOR_OBSERVATION_ISSUER_ID=${OBSERVATION_ISSUER_ID},EMILIA_ACTUATOR_OBSERVATION_KEY_ID=${OBSERVATION_KEY_ID}"
actuator_secrets="EMILIA_ACTUATOR_DATABASE_URL=${ACTUATOR_DATABASE_URL_SECRET},EMILIA_ACTUATOR_API_TOKEN=${ACTUATOR_API_TOKEN_SECRET},EMILIA_ACTUATOR_ENVELOPE_PUBLIC_KEY=${ACTUATOR_ENVELOPE_PUBLIC_KEY_SECRET},EMILIA_ACTUATOR_OBSERVATION_PRIVATE_KEY=${ACTUATOR_OBSERVATION_PRIVATE_KEY_SECRET},EMILIA_ACTUATOR_GITHUB_APP_ID=${ACTUATOR_GITHUB_APP_ID_SECRET},EMILIA_ACTUATOR_GITHUB_INSTALLATION_ID=${ACTUATOR_GITHUB_INSTALLATION_ID_SECRET},EMILIA_ACTUATOR_GITHUB_PRIVATE_KEY=${ACTUATOR_GITHUB_PRIVATE_KEY_SECRET}"

actuator_command=(
  gcloud run deploy "$ACTUATOR_SERVICE"
  "--project=$PROJECT_ID"
  "--region=$REGION"
  "--platform=managed"
  "--image=$ACTUATOR_IMAGE"
  "--revision-suffix=$RELEASE_ID"
  "--tag=$CANARY_TAG"
  --no-traffic
  "--service-account=$ACTUATOR_SA"
  "--ingress=$ACTUATOR_INGRESS"
  --no-allow-unauthenticated
  "--network=$NETWORK"
  "--subnet=$SUBNET"
  "--vpc-egress=all-traffic"
  "--cpu=$ACTUATOR_CPU"
  "--memory=$ACTUATOR_MEMORY"
  "--min=$ACTUATOR_MIN_INSTANCES"
  "--max=$ACTUATOR_MAX_INSTANCES"
  "--concurrency=$ACTUATOR_CONCURRENCY"
  "--timeout=30s"
  "--port=8080"
  "--execution-environment=gen2"
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
    "--platform=managed"
    "--image=$DECISION_IMAGE"
    "--revision-suffix=$RELEASE_ID"
    "--tag=$CANARY_TAG"
    --no-traffic
    "--service-account=$DECISION_SA"
    "--ingress=$DECISION_INGRESS"
    --no-invoker-iam-check
    "--network=$NETWORK"
    "--subnet=$SUBNET"
    "--vpc-egress=all-traffic"
    "--cpu=$DECISION_CPU"
    "--memory=$DECISION_MEMORY"
    "--min=$DECISION_MIN_INSTANCES"
    "--max=$DECISION_MAX_INSTANCES"
    "--concurrency=$DECISION_CONCURRENCY"
    "--timeout=60s"
    "--port=8080"
    "--execution-environment=gen2"
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

render_policy_reconciliation() {
  local resource_kind=$1 resource=$2 role=$3
  shift 3
  local members=("$@") member_args=() member
  for member in "${members[@]}"; do
    member_args+=(--member "$member")
  done
  printf '# close %s %s to the exact %s member allowlist\n' \
    "$resource_kind" "$resource" "$role"
  if [[ "$resource_kind" == run-service ]]; then
    shell_join gcloud run services get-iam-policy "$resource" \
      "--project=$PROJECT_ID" "--region=$REGION" --format=json
    shell_join python3 "$LANE_DIR/reconcile-iam-policy.py" rewrite \
      --input '<current-policy.json>' --output '<closed-policy.json>' \
      --role "$role" "${member_args[@]}"
    shell_join gcloud run services set-iam-policy "$resource" \
      '<closed-policy.json>' "--project=$PROJECT_ID" "--region=$REGION"
  else
    shell_join gcloud secrets get-iam-policy "$resource" \
      "--project=$PROJECT_ID" --format=json
    shell_join python3 "$LANE_DIR/reconcile-iam-policy.py" rewrite \
      --input '<current-policy.json>' --output '<closed-policy.json>' \
      --role "$role" "${member_args[@]}"
    shell_join gcloud secrets set-iam-policy "$resource" \
      '<closed-policy.json>' "--project=$PROJECT_ID"
  fi
}

render_prerequisites() {
  shell_join gcloud services enable \
    run.googleapis.com secretmanager.googleapis.com iam.googleapis.com \
    cloudasset.googleapis.com \
    "--project=$PROJECT_ID"
  shell_join gcloud iam service-accounts describe "$ACTUATOR_SA" \
    "--project=$PROJECT_ID"
  shell_join gcloud iam service-accounts describe "$DECISION_SA" \
    "--project=$PROJECT_ID"
  local variable ref secret members=()
  while IFS= read -r variable; do
    ref=${!variable}
    shell_join gcloud secrets describe "$(secret_name "$ref")" \
      "--project=$PROJECT_ID"
  done < <(all_secret_variables)
  while IFS= read -r secret; do
    members=()
    if secret_is_used_by "$secret" actuator_secret_variables; then
      members+=("serviceAccount:$ACTUATOR_SA")
    fi
    if secret_is_used_by "$secret" decision_secret_variables; then
      members+=("serviceAccount:$DECISION_SA")
    fi
    render_policy_reconciliation secret "$secret" \
      roles/secretmanager.secretAccessor "${members[@]}"
  done < <(
    while IFS= read -r variable; do
      ref=${!variable}
      secret_name "$ref"
      printf '\n'
    done < <(all_secret_variables) | sort -u
  )
}

resolve_tag_url() {
  gcloud run services describe "$ACTUATOR_SERVICE" \
    "--project=$PROJECT_ID" \
    "--region=$REGION" \
    --format=json \
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
    "--project=$PROJECT_ID" \
    "--region=$REGION" \
    --format='value(status.url)'
}

render_jit_act_as() {
  local action=$1 account
  for account in "$ACTUATOR_SA" "$DECISION_SA"; do
    shell_join gcloud iam service-accounts \
      "${action}-iam-policy-binding" "$account" \
      "--project=$PROJECT_ID" \
      --member '<resolved-active-deployer-principal>' \
      --role roles/iam.serviceAccountUser \
      --condition=None \
      --quiet
    shell_join gcloud iam service-accounts get-iam-policy "$account" \
      "--project=$PROJECT_ID" --format=json
  done
}

resolve_deployer_principal() {
  local account
  account=$(gcloud config get-value account --quiet)
  [[ -n "$account" && "$account" != "(unset)" \
      && "$account" != *[$'\r\n\t ']* ]] \
    || lane_die "active gcloud deployer account could not be resolved exactly"
  case "$account" in
    user:*|serviceAccount:*|principal://*)
      DEPLOYER_PRINCIPAL=$account
      ;;
    *@*.gserviceaccount.com)
      DEPLOYER_PRINCIPAL="serviceAccount:$account"
      ;;
    *@*)
      DEPLOYER_PRINCIPAL="user:$account"
      ;;
    *)
      lane_die "active gcloud deployer is not a concrete IAM principal"
      ;;
  esac
}

resolve_analyzer_scope() {
  local project_number ancestry
  project_number=$(gcloud projects describe "$PROJECT_ID" \
    "--project=$PROJECT_ID" --format='value(projectNumber)')
  [[ "$project_number" =~ ^[1-9][0-9]{5,29}$ ]] \
    || lane_die "Google Cloud project number could not be resolved"
  ancestry="$IAM_TMPDIR/project-ancestry.json"
  gcloud projects get-ancestors "$PROJECT_ID" \
    --format=json --quiet > "$ancestry" \
    || lane_die "project ancestry could not be queried"
  RESOLVED_ANALYZER_SCOPE=$(
    python3 - "$ancestry" "$PROJECT_ID" "$project_number" "$ANALYZER_SCOPE" <<'PY'
import json
import re
import sys

path, project_id, project_number, requested = sys.argv[1:]
try:
    entries = json.load(open(path, encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"project ancestry is unavailable: {error}")
if not isinstance(entries, list) or not entries:
    raise SystemExit("project ancestry is empty or unavailable")

projects = set()
folders = set()
organizations = set()
for index, entry in enumerate(entries):
    if not isinstance(entry, dict):
        raise SystemExit(f"project ancestry[{index}] is not an object")
    entry_type = entry.get("type")
    entry_id = entry.get("id")
    if not isinstance(entry_type, str) or not isinstance(entry_id, str):
        raise SystemExit(f"project ancestry[{index}] is incomplete")
    if entry_type == "project":
        projects.add(entry_id)
    elif entry_type == "folder":
        if re.fullmatch(r"[1-9][0-9]*", entry_id) is None:
            raise SystemExit(f"project ancestry[{index}] has an invalid folder ID")
        folders.add(entry_id)
    elif entry_type == "organization":
        if re.fullmatch(r"[1-9][0-9]*", entry_id) is None:
            raise SystemExit(
                f"project ancestry[{index}] has an invalid organization ID"
            )
        organizations.add(entry_id)
    else:
        raise SystemExit(f"project ancestry[{index}] has an unknown type")

if len(projects) != 1 or not projects <= {project_id, project_number}:
    raise SystemExit(
        "project ancestry does not identify the deployment project exactly once"
    )
if not folders and not organizations:
    expected = f"projects/{project_id}"
    if requested and requested != expected:
        raise SystemExit(
            f"standalone project requires analyzer scope {expected}, not {requested}"
        )
    print(expected)
    raise SystemExit(0)
if len(organizations) != 1:
    raise SystemExit(
        "project ancestry exists but one covering organization is unavailable"
    )
expected = f"organizations/{next(iter(organizations))}"
if requested != expected:
    raise SystemExit(
        f"project ancestry requires explicit --analyzer-scope {expected}"
    )
print(expected)
PY
  ) || lane_die "project ancestry did not produce a safe analyzer scope"
  printf 'project ancestry verified; Policy Analyzer scope=%s\n' \
    "$RESOLVED_ANALYZER_SCOPE"
}

verify_jit_member_state() {
  local account=$1 expected=$2
  local policy="$IAM_TMPDIR/service-account-policy-${account%%@*}.json"
  gcloud iam service-accounts get-iam-policy "$account" \
    "--project=$PROJECT_ID" --format=json > "$policy" \
    || return 1
  python3 - "$policy" "$DEPLOYER_PRINCIPAL" "$expected" <<'PY'
import json
import sys

path, principal, expected = sys.argv[1:]
try:
    policy = json.load(open(path, encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(policy, dict) or not isinstance(policy.get("bindings", []), list):
    raise SystemExit(1)
present = False
for binding in policy.get("bindings", []):
    if not isinstance(binding, dict):
        raise SystemExit(1)
    if binding.get("role") != "roles/iam.serviceAccountUser":
        continue
    members = binding.get("members")
    if not isinstance(members, list) or not all(
        isinstance(member, str) for member in members
    ):
        raise SystemExit(1)
    present = present or principal in members
if present != (expected == "present"):
    raise SystemExit(1)
PY
}

grant_jit_act_as() {
  local account
  for account in "$ACTUATOR_SA" "$DECISION_SA"; do
    verify_jit_member_state "$account" absent \
      || lane_die "deployer already has persistent actAs on $account"
    JIT_GRANTED_ACCOUNTS+=("$account")
    gcloud iam service-accounts add-iam-policy-binding "$account" \
      "--project=$PROJECT_ID" \
      "--member=$DEPLOYER_PRINCIPAL" \
      --role=roles/iam.serviceAccountUser \
      --condition=None \
      --quiet >/dev/null
    verify_jit_member_state "$account" present \
      || lane_die "temporary actAs grant was not visible on $account"
  done
}

revoke_jit_act_as() {
  local account failed=false
  for account in "${JIT_GRANTED_ACCOUNTS[@]}"; do
    if ! gcloud iam service-accounts remove-iam-policy-binding "$account" \
      "--project=$PROJECT_ID" \
      "--member=$DEPLOYER_PRINCIPAL" \
      --role=roles/iam.serviceAccountUser \
      --condition=None \
      --quiet >/dev/null; then
      printf 'failed to revoke temporary actAs from %s\n' "$account" >&2
      failed=true
    fi
  done
  for account in "$ACTUATOR_SA" "$DECISION_SA"; do
    if ! verify_jit_member_state "$account" absent; then
      printf 'temporary actAs revocation was not proven on %s\n' "$account" >&2
      failed=true
    fi
  done
  [[ "$failed" == false ]] || return 1
  JIT_GRANTED_ACCOUNTS=()
}

reconcile_policy() {
  local resource_kind=$1 resource=$2 role=$3
  shift 3
  local members=("$@") member_args=() member
  local current="$IAM_TMPDIR/current.json"
  local desired="$IAM_TMPDIR/desired.json"
  local verified="$IAM_TMPDIR/verified.json"
  for member in "${members[@]}"; do
    member_args+=(--member "$member")
  done

  if [[ "$resource_kind" == run-service ]]; then
    gcloud run services get-iam-policy "$resource" \
      "--project=$PROJECT_ID" "--region=$REGION" --format=json > "$current"
  else
    gcloud secrets get-iam-policy "$resource" \
      "--project=$PROJECT_ID" --format=json > "$current"
  fi
  python3 "$LANE_DIR/reconcile-iam-policy.py" rewrite \
    --input "$current" --output "$desired" --role "$role" "${member_args[@]}"
  if [[ "$resource_kind" == run-service ]]; then
    gcloud run services set-iam-policy "$resource" "$desired" \
      "--project=$PROJECT_ID" "--region=$REGION" --quiet >/dev/null
    gcloud run services get-iam-policy "$resource" \
      "--project=$PROJECT_ID" "--region=$REGION" --format=json > "$verified"
  else
    gcloud secrets set-iam-policy "$resource" "$desired" \
      "--project=$PROJECT_ID" --quiet >/dev/null
    gcloud secrets get-iam-policy "$resource" \
      "--project=$PROJECT_ID" --format=json > "$verified"
  fi
  python3 "$LANE_DIR/reconcile-iam-policy.py" check \
    --input "$verified" --role "$role" "${member_args[@]}"
}

reconcile_secret_accessors() {
  local variable ref secret members=()
  while IFS= read -r secret; do
    members=()
    if secret_is_used_by "$secret" actuator_secret_variables; then
      members+=("serviceAccount:$ACTUATOR_SA")
    fi
    if secret_is_used_by "$secret" decision_secret_variables; then
      members+=("serviceAccount:$DECISION_SA")
    fi
    reconcile_policy secret "$secret" roles/secretmanager.secretAccessor \
      "${members[@]}"
  done < <(
    while IFS= read -r variable; do
      ref=${!variable}
      secret_name "$ref"
      printf '\n'
    done < <(all_secret_variables) | sort -u
  )
}

if [[ "$MODE" == render ]]; then
  printf '# prerequisites: existing service accounts, secrets, and secret-level IAM\n'
  render_prerequisites
  printf '# query ancestry; standalone projects use project scope, while ancestry requires an explicit organization scope\n'
  shell_join gcloud projects get-ancestors "$PROJECT_ID" \
    --format=json --quiet
  printf '# temporarily grant the active deployer actAs on exactly the two runtime identities\n'
  render_jit_act_as add
  printf '# candidate actuator: %s, zero traffic\n' "$ACTUATOR_REVISION"
  shell_join "${actuator_command[@]}"
  printf '# close the resource-level invoker binding to the decision workload identity\n'
  render_policy_reconciliation run-service "$ACTUATOR_SERVICE" \
    roles/run.invoker "serviceAccount:$DECISION_SA"
  printf '# resolve the canonical service URL for the Google ID-token audience\n'
  printf 'ACTUATOR_AUDIENCE=<resolved-canonical-url-for-%s>\n' \
    "$ACTUATOR_SERVICE"
  printf '# resolve the exact tagged actuator revision URL after actuator creation\n'
  printf 'ACTUATOR_CANARY_URL=<resolved-from-%s-tag-%s>\n' \
    "$ACTUATOR_SERVICE" "$CANARY_TAG"
  # shellcheck disable=SC2016
  decision_command '${ACTUATOR_CANARY_URL}' '${ACTUATOR_AUDIENCE}'
  printf '# candidate decision: %s, zero traffic\n' "$DECISION_REVISION"
  shell_join "${DECISION_COMMAND[@]}"
  printf '# revoke temporary actAs and read back both runtime service-account policies\n'
  render_jit_act_as remove
  printf '# verify inherited, group-expanded, and impersonation-derived access against the closed allowlist\n'
  shell_join python3 "$LANE_DIR/emit-effective-iam-manifest.py" \
    "--project=$PROJECT_ID" --project-number '<resolved-project-number>' \
    --analyzer-scope "${ANALYZER_SCOPE:-<resolved-after-ancestry-proof>}" \
    "--region=$REGION" \
    "--actuator-service=$ACTUATOR_SERVICE" \
    "--decision-principal=serviceAccount:$DECISION_SA" \
    --secret '<SECRET=EXACT_RUNTIME_PRINCIPALS>' \
    --output '<effective-iam.json>'
  shell_join "$LANE_DIR/verify-effective-iam.py" \
    --input '<effective-iam.json>' --live
  printf '# stop: no production traffic is changed by deploy.sh\n'
  exit 0
fi

require_apply_approval
IAM_TMPDIR=$(mktemp -d)
JIT_GRANTED_ACCOUNTS=()
cleanup() {
  local status=$?
  trap - EXIT
  if ((${#JIT_GRANTED_ACCOUNTS[@]})); then
    if ! revoke_jit_act_as; then
      status=1
    fi
  fi
  rm -rf "$IAM_TMPDIR"
  exit "$status"
}
trap cleanup EXIT
gcloud services enable \
  run.googleapis.com secretmanager.googleapis.com iam.googleapis.com \
  cloudasset.googleapis.com \
  "--project=$PROJECT_ID" --quiet

for account in "$ACTUATOR_SERVICE_ACCOUNT" "$DECISION_SERVICE_ACCOUNT"; do
  email=$(runtime_service_account_email "$account")
  if ! gcloud iam service-accounts describe "$email" \
      "--project=$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$account" \
      "--project=$PROJECT_ID" \
      "--display-name=EMILIA consequence runtime $account" \
      --quiet
  fi
done

resolve_deployer_principal
resolve_analyzer_scope
while IFS= read -r variable; do
  ref=${!variable}
  gcloud secrets describe "$(secret_name "$ref")" \
    "--project=$PROJECT_ID" >/dev/null
done < <(all_secret_variables)

reconcile_secret_accessors

grant_jit_act_as
"${actuator_command[@]}"
reconcile_policy run-service "$ACTUATOR_SERVICE" roles/run.invoker \
  "serviceAccount:$DECISION_SA"
ACTUATOR_AUDIENCE=$(resolve_service_url)
ACTUATOR_CANARY_URL=$(resolve_tag_url)
[[ "$ACTUATOR_AUDIENCE" == https://* ]] \
  || lane_die "resolved actuator audience is not https"
[[ "$ACTUATOR_CANARY_URL" == https://* ]] \
  || lane_die "resolved actuator candidate URL is not https"
decision_command "$ACTUATOR_CANARY_URL" "$ACTUATOR_AUDIENCE"
"${DECISION_COMMAND[@]}"
revoke_jit_act_as \
  || lane_die "temporary actAs revocation or service-account policy readback failed"
export EMILIA_IAM_ANALYZER_SCOPE=$RESOLVED_ANALYZER_SCOPE
verify_effective_iam_live

printf 'created zero-traffic candidates: %s and %s\n' \
  "$ACTUATOR_REVISION" "$DECISION_REVISION"
printf 'no production traffic changed; run and verify the canary contract next\n'
