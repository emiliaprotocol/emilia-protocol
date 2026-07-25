#!/usr/bin/env bash
set -euo pipefail

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$LANE_DIR/lib/common.sh"

CONFIG=
MODE=render
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
    *)
      lane_die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$CONFIG" ]] || lane_die "--config is required"
load_lane_config "$CONFIG"
validate_lane_config

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

all_secret_variables() {
  {
    actuator_secret_variables
    decision_secret_variables
  } | awk '!seen[$0]++'
}

render_prerequisites() {
  shell_join gcloud services enable \
    run.googleapis.com secretmanager.googleapis.com iam.googleapis.com \
    "--project=$PROJECT_ID"
  shell_join gcloud iam service-accounts describe "$ACTUATOR_SA" \
    "--project=$PROJECT_ID"
  shell_join gcloud iam service-accounts describe "$DECISION_SA" \
    "--project=$PROJECT_ID"
  local variable ref account
  while IFS= read -r variable; do
    ref=${!variable}
    shell_join gcloud secrets describe "$(secret_name "$ref")" \
      "--project=$PROJECT_ID"
  done < <(all_secret_variables)
  while IFS= read -r variable; do
    ref=${!variable}
    account=$ACTUATOR_SA
    shell_join gcloud secrets add-iam-policy-binding "$(secret_name "$ref")" \
      "--project=$PROJECT_ID" \
      "--member=serviceAccount:$account" \
      "--role=roles/secretmanager.secretAccessor"
  done < <(actuator_secret_variables)
  while IFS= read -r variable; do
    ref=${!variable}
    account=$DECISION_SA
    shell_join gcloud secrets add-iam-policy-binding "$(secret_name "$ref")" \
      "--project=$PROJECT_ID" \
      "--member=serviceAccount:$account" \
      "--role=roles/secretmanager.secretAccessor"
  done < <(decision_secret_variables)
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

grant_actuator_invoker() {
  gcloud run services add-iam-policy-binding "$ACTUATOR_SERVICE" \
    "--project=$PROJECT_ID" \
    "--region=$REGION" \
    "--member=serviceAccount:$DECISION_SA" \
    "--role=roles/run.invoker" \
    --quiet
}

if [[ "$MODE" == render ]]; then
  printf '# prerequisites: existing service accounts, secrets, and secret-level IAM\n'
  render_prerequisites
  printf '# candidate actuator: %s, zero traffic\n' "$ACTUATOR_REVISION"
  shell_join "${actuator_command[@]}"
  printf '# only the decision workload identity may pass the actuator IAM gate\n'
  shell_join gcloud run services add-iam-policy-binding "$ACTUATOR_SERVICE" \
    "--project=$PROJECT_ID" \
    "--region=$REGION" \
    "--member=serviceAccount:$DECISION_SA" \
    "--role=roles/run.invoker"
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
  printf '# stop: no production traffic is changed by deploy.sh\n'
  exit 0
fi

require_apply_approval
gcloud services enable \
  run.googleapis.com secretmanager.googleapis.com iam.googleapis.com \
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

while IFS= read -r variable; do
  ref=${!variable}
  gcloud secrets describe "$(secret_name "$ref")" \
    "--project=$PROJECT_ID" >/dev/null
done < <(all_secret_variables)

while IFS= read -r variable; do
  ref=${!variable}
  gcloud secrets add-iam-policy-binding "$(secret_name "$ref")" \
    "--project=$PROJECT_ID" \
    "--member=serviceAccount:$ACTUATOR_SA" \
    "--role=roles/secretmanager.secretAccessor" \
    --quiet >/dev/null
done < <(actuator_secret_variables)

while IFS= read -r variable; do
  ref=${!variable}
  gcloud secrets add-iam-policy-binding "$(secret_name "$ref")" \
    "--project=$PROJECT_ID" \
    "--member=serviceAccount:$DECISION_SA" \
    "--role=roles/secretmanager.secretAccessor" \
    --quiet >/dev/null
done < <(decision_secret_variables)

"${actuator_command[@]}"
grant_actuator_invoker
ACTUATOR_AUDIENCE=$(resolve_service_url)
ACTUATOR_CANARY_URL=$(resolve_tag_url)
[[ "$ACTUATOR_AUDIENCE" == https://* ]] \
  || lane_die "resolved actuator audience is not https"
[[ "$ACTUATOR_CANARY_URL" == https://* ]] \
  || lane_die "resolved actuator candidate URL is not https"
decision_command "$ACTUATOR_CANARY_URL" "$ACTUATOR_AUDIENCE"
"${DECISION_COMMAND[@]}"

printf 'created zero-traffic candidates: %s and %s\n' \
  "$ACTUATOR_REVISION" "$DECISION_REVISION"
printf 'no production traffic changed; run and verify the canary contract next\n'
