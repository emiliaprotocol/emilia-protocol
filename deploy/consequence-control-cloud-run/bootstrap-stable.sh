#!/usr/bin/env bash
set -euo pipefail

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$LANE_DIR/lib/common.sh"

CONFIG=
BOOTSTRAP_ID=
PLACEHOLDER_IMAGE=
SIGNING_KEY_FILE=
VERIFY_KEY_FILE=
KMS_KEY_URI=
KEY_ID=
PROVENANCE_FILE=
OUTPUT=
MODE=render
while (($#)); do
  case "$1" in
    --config)
      (($# >= 2)) || lane_die "--config requires a value"
      CONFIG=$2
      shift 2
      ;;
    --bootstrap-id)
      (($# >= 2)) || lane_die "--bootstrap-id requires a value"
      BOOTSTRAP_ID=$2
      shift 2
      ;;
    --placeholder-image)
      (($# >= 2)) || lane_die "--placeholder-image requires a value"
      PLACEHOLDER_IMAGE=$2
      shift 2
      ;;
    --placeholder-repository)
      lane_die "--placeholder-repository is forbidden; use an allowlisted digest"
      ;;
    --private-key)
      (($# >= 2)) || lane_die "--private-key requires a value"
      SIGNING_KEY_FILE=$2
      shift 2
      ;;
    --public-key)
      (($# >= 2)) || lane_die "--public-key requires a value"
      VERIFY_KEY_FILE=$2
      shift 2
      ;;
    --kms-key-uri)
      (($# >= 2)) || lane_die "--kms-key-uri requires a value"
      KMS_KEY_URI=$2
      shift 2
      ;;
    --key-id)
      (($# >= 2)) || lane_die "--key-id requires a value"
      KEY_ID=$2
      shift 2
      ;;
    --provenance)
      (($# >= 2)) || lane_die "--provenance requires a value"
      PROVENANCE_FILE=$2
      shift 2
      ;;
    --output)
      (($# >= 2)) || lane_die "--output requires a value"
      OUTPUT=$2
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
[[ "$BOOTSTRAP_ID" =~ ^[a-z][a-z0-9-]{0,20}$ ]] \
  || lane_die "--bootstrap-id must be a short lowercase revision suffix"
[[ -n "$OUTPUT" ]] || lane_die "--output is required"
[[ "$OUTPUT" == /* ]] || lane_die "--output must be an absolute path"
[[ -n "$PLACEHOLDER_IMAGE" ]] || lane_die "--placeholder-image is required"

load_lane_config "$CONFIG"
validate_lane_config
require_var STABLE_RELEASE_KEY_ID
require_var STABLE_BOOTSTRAP_ALLOWED_DIGESTS
require_var STABLE_BOOTSTRAP_PROVENANCE_FILE
require_var STABLE_BOOTSTRAP_PROVENANCE_SHA256
require_var STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT
require_var STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT
validate_slug STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT
validate_slug STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT
[[ "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
    != "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT" ]] \
  || lane_die "bootstrap service accounts must be distinct"
[[ "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
    != "$ACTUATOR_SERVICE_ACCOUNT" \
    && "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
    != "$DECISION_SERVICE_ACCOUNT" \
    && "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT" \
    != "$ACTUATOR_SERVICE_ACCOUNT" \
    && "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT" \
    != "$DECISION_SERVICE_ACCOUNT" ]] \
  || lane_die "bootstrap service accounts must not reuse runtime identities"
[[ "$BOOTSTRAP_ID" != "$RELEASE_ID" ]] \
  || lane_die "bootstrap and candidate release ids must differ"

ACTUATOR_SA=$(
  runtime_service_account_email "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT"
)
DECISION_SA=$(
  runtime_service_account_email "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"
)
ACTUATOR_REVISION="$ACTUATOR_SERVICE-$BOOTSTRAP_ID"
DECISION_REVISION="$DECISION_SERVICE-$BOOTSTRAP_ID"
BOOTSTRAP_TAG="stable-bootstrap-$BOOTSTRAP_ID"

KEY_ID=${KEY_ID:-$STABLE_RELEASE_KEY_ID}
PROVENANCE_FILE=${PROVENANCE_FILE:-$STABLE_BOOTSTRAP_PROVENANCE_FILE}
[[ "$PROVENANCE_FILE" == /* ]] \
  || lane_die "--provenance must be an absolute path"
if [[ -n "${STABLE_RELEASE_KMS_KEY_URI:-}" ]]; then
  [[ -z "$SIGNING_KEY_FILE" ]] \
    || lane_die "--private-key is forbidden when KMS trust is configured"
  KMS_KEY_URI=${KMS_KEY_URI:-$STABLE_RELEASE_KMS_KEY_URI}
  [[ "$KMS_KEY_URI" == "$STABLE_RELEASE_KMS_KEY_URI" ]] \
    || lane_die "--kms-key-uri must equal configured stable-release trust"
else
  [[ -z "$KMS_KEY_URI" ]] \
    || lane_die "--kms-key-uri requires configured KMS trust"
  [[ -n "$SIGNING_KEY_FILE" && "$SIGNING_KEY_FILE" == /* ]] \
    || lane_die "--private-key must be an absolute path for file trust"
fi
if [[ -n "$VERIFY_KEY_FILE" ]]; then
  [[ "$VERIFY_KEY_FILE" == /* ]] \
    || lane_die "--public-key must be an absolute path"
fi
[[ "$KEY_ID" == "$STABLE_RELEASE_KEY_ID" ]] \
  || lane_die "--key-id must equal configured stable-release key id"

validate_placeholder_image() {
  local image=$1
  [[ "$image" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] \
    || lane_die "placeholder image must be pinned by lowercase sha256 digest"
}

validate_placeholder_image "$PLACEHOLDER_IMAGE"

placeholder_deploy_command() {
  local service=$1 account=$2 ingress=$3
  PLACEHOLDER_DEPLOY_COMMAND=(
    gcloud run deploy "$service"
    "--project=$PROJECT_ID"
    "--region=$REGION"
    --platform=managed
    "--image=$PLACEHOLDER_IMAGE"
    "--revision-suffix=$BOOTSTRAP_ID"
    "--tag=$BOOTSTRAP_TAG"
    --no-traffic
    "--service-account=$account"
    "--ingress=$ingress"
    --no-allow-unauthenticated
    --cpu=1
    --memory=256Mi
    --min=0
    --max=1
    --concurrency=1
    --timeout=5s
    --port=8080
    --execution-environment=gen2
    --no-session-affinity
    --deploy-health-check
    "--startup-probe=httpGet.path=/v1/ready,httpGet.port=8080,periodSeconds=2,timeoutSeconds=1,failureThreshold=30"
    "--liveness-probe=httpGet.path=/v1/live,httpGet.port=8080,periodSeconds=30,timeoutSeconds=2,failureThreshold=3"
    "--readiness-probe=httpGet.path=/v1/ready,httpGet.port=8080,periodSeconds=5,timeoutSeconds=2,failureThreshold=3,successThreshold=1"
    "--labels=emilia-plane=bootstrap,emilia-release=$BOOTSTRAP_ID,emilia-deny-all=true,emilia-permissionless=true"
    --quiet
  )
}

render_plan() {
  printf '# verify the configured digest allowlist and hash-pinned provenance\n'
  shell_join "$LANE_DIR/verify-stable-release.py" verify-bootstrap \
    --config "$CONFIG" \
    --image "$PLACEHOLDER_IMAGE" \
    --provenance "$PROVENANCE_FILE"
  printf '# refuse bootstrap if either Cloud Run service already exists\n'
  shell_join gcloud run services list \
    "--project=$PROJECT_ID" "--region=$REGION" \
    "--filter=metadata.name=($ACTUATOR_SERVICE OR $DECISION_SERVICE)" \
    --format='value(metadata.name)'
  printf '# create dedicated identities and prove they have no effective IAM access\n'
  for account in \
    "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
    "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"; do
    shell_join gcloud iam service-accounts create "$account" \
      "--project=$PROJECT_ID" \
      "--display-name=EMILIA permissionless stable bootstrap" \
      --quiet
    shell_join gcloud asset analyze-iam-policy \
      "--identity=serviceAccount:$(runtime_service_account_email "$account")" \
      "--scope=projects/$PROJECT_ID" \
      --format=json
  done
  printf '# create tagged actuator bootstrap revision with zero production traffic\n'
  placeholder_deploy_command \
    "$ACTUATOR_SERVICE" "$ACTUATOR_SA" "$ACTUATOR_INGRESS"
  shell_join "${PLACEHOLDER_DEPLOY_COMMAND[@]}"
  printf '# create tagged decision bootstrap revision with zero production traffic\n'
  placeholder_deploy_command \
    "$DECISION_SERVICE" "$DECISION_SA" "$DECISION_INGRESS"
  shell_join "${PLACEHOLDER_DEPLOY_COMMAND[@]}"
  printf '# authenticate health probes with the canonical audience; prove unauthenticated and negative routes fail\n'
  shell_join gcloud auth print-identity-token \
    --audiences='<canonical-service-url>'
  shell_join curl -fsS '<tagged-bootstrap-url>/v1/live' \
    -H 'Authorization: Bearer <identity-token>'
  shell_join curl -fsS '<tagged-bootstrap-url>/v1/ready' \
    -H 'Authorization: Bearer <identity-token>'
  shell_join curl -sS '<tagged-bootstrap-url>/v1/ready'
  shell_join curl -sS '<tagged-bootstrap-url>/not-health' \
    -H 'Authorization: Bearer <identity-token>'
  printf '# only after both test matrices pass, route each service to the witnessed pair\n'
  shell_join gcloud run services update-traffic "$ACTUATOR_SERVICE" \
    "--project=$PROJECT_ID" "--region=$REGION" \
    "--to-revisions=$ACTUATOR_REVISION=100" --quiet
  shell_join gcloud run services update-traffic "$DECISION_SERVICE" \
    "--project=$PROJECT_ID" "--region=$REGION" \
    "--to-revisions=$DECISION_REVISION=100" --quiet
  printf '# record the witnessed 100%% pair, complete config, and provenance; then sign\n'
  local record_render_command=(
    "$LANE_DIR/verify-stable-release.py" record
    --config "$CONFIG"
    --actuator-revision "$ACTUATOR_REVISION"
    --decision-revision "$DECISION_REVISION"
    --bootstrap-id "$BOOTSTRAP_ID"
    --bootstrap-image "$PLACEHOLDER_IMAGE"
    --bootstrap-provenance "$PROVENANCE_FILE"
    --key-id "$KEY_ID"
    --output "$OUTPUT"
  )
  if [[ -n "$SIGNING_KEY_FILE" ]]; then
    record_render_command+=(--private-key "$SIGNING_KEY_FILE")
  else
    record_render_command+=(--kms-key-uri "$KMS_KEY_URI")
  fi
  shell_join "${record_render_command[@]}"
  local verify_command=(
    "$LANE_DIR/verify-stable-release.py" verify
    --config "$CONFIG"
    --manifest "$OUTPUT"
    --live
  )
  if [[ -n "$VERIFY_KEY_FILE" ]]; then
    verify_command+=(--public-key "$VERIFY_KEY_FILE")
  fi
  shell_join "${verify_command[@]}"
}

if [[ "$MODE" == render ]]; then
  render_plan
  exit 0
fi

require_apply_approval
[[ ! -e "$OUTPUT" ]] \
  || lane_die "stable-release output already exists"
if [[ -n "$SIGNING_KEY_FILE" ]]; then
  [[ -f "$SIGNING_KEY_FILE" ]] \
    || lane_die "stable-release private key is unavailable"
  private_mode=$(stat -f '%Lp' "$SIGNING_KEY_FILE" 2>/dev/null \
    || stat -c '%a' "$SIGNING_KEY_FILE")
  (( (8#$private_mode & 8#077) == 0 )) \
    || lane_die "stable-release private key must not be group/world accessible"
fi
HTTP_TMPDIR=$(mktemp -d)
trap 'rm -rf "${HTTP_TMPDIR:-}"' EXIT

"$LANE_DIR/verify-stable-release.py" verify-bootstrap \
  --config "$CONFIG" \
  --image "$PLACEHOLDER_IMAGE" \
  --provenance "$PROVENANCE_FILE"

gcloud services enable \
  run.googleapis.com iam.googleapis.com cloudasset.googleapis.com \
  "--project=$PROJECT_ID" --quiet

existing_services=$(
  gcloud run services list \
    "--project=$PROJECT_ID" "--region=$REGION" \
    "--filter=metadata.name=($ACTUATOR_SERVICE OR $DECISION_SERVICE)" \
    --format='value(metadata.name)'
)
[[ -z "$existing_services" ]] \
  || lane_die "stable bootstrap requires both Cloud Run services to be absent"

ensure_bootstrap_service_account() {
  local account=$1 email analysis
  email=$(runtime_service_account_email "$account")
  if ! gcloud iam service-accounts describe "$email" \
      "--project=$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$account" \
      "--project=$PROJECT_ID" \
      "--display-name=EMILIA permissionless stable bootstrap" \
      --quiet
  fi
  analysis=$(
    gcloud asset analyze-iam-policy \
      "--identity=serviceAccount:$email" \
      "--scope=projects/$PROJECT_ID" \
      --format=json
  )
  python3 -c '
import json, sys
value = json.load(sys.stdin)
main = value.get("mainAnalysis")
if not isinstance(main, dict) or main.get("fullyExplored") is not True:
    raise SystemExit("IAM analysis was not complete")
results = main.get("analysisResults")
if not isinstance(results, list):
    raise SystemExit("IAM analysis results are malformed")
if results:
    raise SystemExit("bootstrap identity has effective IAM access")
' <<< "$analysis" \
    || lane_die "bootstrap service account is not proven permissionless: $email"
}

ensure_bootstrap_service_account "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT"
ensure_bootstrap_service_account "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"

placeholder_deploy_command \
  "$ACTUATOR_SERVICE" "$ACTUATOR_SA" "$ACTUATOR_INGRESS"
"${PLACEHOLDER_DEPLOY_COMMAND[@]}"
placeholder_deploy_command \
  "$DECISION_SERVICE" "$DECISION_SA" "$DECISION_INGRESS"
"${PLACEHOLDER_DEPLOY_COMMAND[@]}"

resolve_bootstrap_url() {
  local service=$1
  gcloud run services describe "$service" \
    "--project=$PROJECT_ID" "--region=$REGION" --format=json \
    | python3 -c '
import json, sys
tag = sys.argv[1]
value = json.load(sys.stdin)
matches = [
    target.get("url")
    for target in value.get("status", {}).get("traffic", [])
    if target.get("tag") == tag and target.get("url")
]
if len(matches) != 1 or not matches[0].startswith("https://"):
    raise SystemExit("tagged bootstrap URL not found")
print(matches[0])
' "$BOOTSTRAP_TAG"
}

resolve_bootstrap_audience() {
  local service=$1
  gcloud run services describe "$service" \
    "--project=$PROJECT_ID" "--region=$REGION" \
    --format='value(status.url)'
}

check_http() {
  local expected_status=$1 method=$2 url=$3 token=${4:-} body status
  body="$HTTP_TMPDIR/body.json"
  local curl_args=(-sS -o "$body" -w '%{http_code}' -X "$method")
  if [[ -n "$token" ]]; then
    curl_args+=(-H "Authorization: Bearer $token")
  fi
  status=$(curl "${curl_args[@]}" "$url")
  [[ "$status" == "$expected_status" ]] \
    || lane_die "$method $url returned $status, expected $expected_status"
  if [[ "$expected_status" == 200 ]]; then
    python3 -c '
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value != {"status": "healthy", "mode": "deny-all-bootstrap"}:
    raise SystemExit("bootstrap health response is not exact")
' "$body"
  fi
}

verify_health_only_revision() {
  local service=$1 url audience token route
  url=$(resolve_bootstrap_url "$service")
  audience=$(resolve_bootstrap_audience "$service")
  [[ "$audience" == https://* ]] \
    || lane_die "canonical bootstrap audience was not resolved for $service"
  token=$(gcloud auth print-identity-token --audiences="$audience")
  [[ -n "$token" ]] || lane_die "identity token was not issued for $service"
  for route in /v1/live /v1/ready; do
    check_http 200 GET "$url$route" "$token"
    check_http 403 GET "$url$route"
  done
  check_http 403 GET "$url/not-health" "$token"
  check_http 403 POST "$url/v1/execute" "$token"
  check_http 403 GET "$url/not-health"
  check_http 403 POST "$url/v1/execute"
}

verify_health_only_revision "$ACTUATOR_SERVICE"
verify_health_only_revision "$DECISION_SERVICE"

gcloud run services update-traffic "$ACTUATOR_SERVICE" \
  "--project=$PROJECT_ID" "--region=$REGION" \
  "--to-revisions=$ACTUATOR_REVISION=100" --quiet
gcloud run services update-traffic "$DECISION_SERVICE" \
  "--project=$PROJECT_ID" "--region=$REGION" \
  "--to-revisions=$DECISION_REVISION=100" --quiet

record_command=(
  "$LANE_DIR/verify-stable-release.py" record
  --config "$CONFIG"
  --actuator-revision "$ACTUATOR_REVISION"
  --decision-revision "$DECISION_REVISION"
  --bootstrap-id "$BOOTSTRAP_ID"
  --bootstrap-image "$PLACEHOLDER_IMAGE"
  --bootstrap-provenance "$PROVENANCE_FILE"
  --key-id "$KEY_ID"
  --output "$OUTPUT"
)
if [[ -n "$SIGNING_KEY_FILE" ]]; then
  record_command+=(--private-key "$SIGNING_KEY_FILE")
else
  record_command+=(--kms-key-uri "$KMS_KEY_URI")
fi
"${record_command[@]}"
verify_command=(
  "$LANE_DIR/verify-stable-release.py" verify
  --config "$CONFIG"
  --manifest "$OUTPUT"
  --live
)
if [[ -n "$VERIFY_KEY_FILE" ]]; then
  verify_command+=(--public-key "$VERIFY_KEY_FILE")
fi
"${verify_command[@]}"

printf 'bootstrapped deny-all stable revisions: %s and %s\n' \
  "$ACTUATOR_REVISION" "$DECISION_REVISION"
printf 'signed rollback manifest: %s\n' "$OUTPUT"
