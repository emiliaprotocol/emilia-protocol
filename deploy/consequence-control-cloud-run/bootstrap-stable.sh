#!/usr/bin/env bash
set -euo pipefail
umask 077

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

if [[ "$MODE" == apply ]]; then
  export REQUIRE_DEPLOYMENT_CONFIG_PIN=true
fi
BOOTSTRAP_CONFIG_KEYS=()
while IFS= read -r name; do
  BOOTSTRAP_CONFIG_KEYS+=("$name")
done < <(bootstrap_config_variables)
load_lane_config "$CONFIG" "${BOOTSTRAP_CONFIG_KEYS[@]}"
prepare_deploy_config_projection
validate_lane_config
require_var STABLE_RELEASE_KEY_ID
require_var STABLE_BOOTSTRAP_ALLOWED_DIGESTS
require_var STABLE_BOOTSTRAP_PROVENANCE_FILE
require_var STABLE_BOOTSTRAP_PROVENANCE_SHA256
require_var STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT
require_var STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT
REQUESTED_ANALYZER_SCOPE=${EMILIA_IAM_ANALYZER_SCOPE:-}
if [[ -n "$REQUESTED_ANALYZER_SCOPE" \
    && "$REQUESTED_ANALYZER_SCOPE" != "projects/$PROJECT_ID" \
    && ! "$REQUESTED_ANALYZER_SCOPE" =~ ^organizations/[1-9][0-9]*$ ]]; then
  lane_die \
    "EMILIA_IAM_ANALYZER_SCOPE must be projects/$PROJECT_ID or organizations/NUMBER"
fi
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

resolve_analyzer_scope() {
  local ancestry project_number
  project_number=$(
    gcloud projects describe "$PROJECT_ID" \
      "--project=$PROJECT_ID" --format='value(projectNumber)'
  )
  [[ "$project_number" =~ ^[1-9][0-9]{5,29}$ ]] \
    || lane_die "Google Cloud project number could not be resolved"
  ancestry="$HTTP_TMPDIR/project-ancestry.json"
  gcloud projects get-ancestors "$PROJECT_ID" \
    --format=json --quiet > "$ancestry" \
    || lane_die "project ancestry could not be queried"
  RESOLVED_ANALYZER_SCOPE=$(
    python3 - "$ancestry" "$PROJECT_ID" "$project_number" \
      "$REQUESTED_ANALYZER_SCOPE" <<'PY'
import json
import re
import sys

path, project_id, project_number, requested = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as handle:
        entries = json.load(handle)
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"project ancestry is unavailable: {error}")
if not isinstance(entries, list) or not entries:
    raise SystemExit("project ancestry is empty or unavailable")

projects = []
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
        projects.append(entry_id)
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

if len(projects) != 1 or projects[0] not in {project_id, project_number}:
    raise SystemExit(
        "project ancestry does not identify the deployment project exactly once"
    )
if not folders and not organizations:
    expected = f"projects/{project_id}"
    if requested and requested != expected:
        raise SystemExit(
            f"standalone project requires project analyzer scope {expected}"
        )
    print(expected)
    raise SystemExit(0)
if len(organizations) != 1:
    raise SystemExit(
        "project hierarchy exists but one covering organization is unavailable"
    )
expected = f"organizations/{next(iter(organizations))}"
if not requested:
    raise SystemExit(
        f"project hierarchy requires EMILIA_IAM_ANALYZER_SCOPE={expected}"
    )
if requested != expected:
    raise SystemExit(
        f"EMILIA_IAM_ANALYZER_SCOPE={requested} does not match "
        f"actual organization {expected}"
    )
print(expected)
PY
  ) || lane_die "project ancestry did not produce a safe analyzer scope"
}

placeholder_deploy_command() {
  local service=$1 account=$2 ingress=$3 authorization_id=${4:-}
  local labels
  labels="emilia-plane=bootstrap,emilia-release=$BOOTSTRAP_ID"
  labels+=",emilia-deny-all=true,emilia-permissionless=true"
  if [[ -n "$authorization_id" ]]; then
    labels+=",emilia-bootstrap-deploy-authorization=$authorization_id"
  fi
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
    "--labels=$labels"
    --quiet
  )
}

render_plan() {
  printf '# verify the configured digest allowlist and hash-pinned provenance\n'
  shell_join "$LANE_DIR/verify-stable-release.py" verify-bootstrap \
    --config "$CONFIG" \
    --image "$PLACEHOLDER_IMAGE" \
    --provenance "$PROVENANCE_FILE"
  printf '# authorize-bootstrap signs and verifies the exact two-plane intent before any mutation\n'
  shell_join "$LANE_DIR/verify-stable-release.py" authorize-bootstrap \
    --config "$CONFIG" --plan '<exact-deployment-plan.json>' \
    --provenance "$PROVENANCE_FILE" --output '<signed-deployment-authorization.json>'
  printf '# claim both signed deployment attempts in the protected durable attempt-store before either deployment\n'
  shell_join '<protected-attempt-store>' claim \
    '<signed-deployment-attempt-claim.json>'
  printf '# require the exact immutable protected GitHub workflow/WIF identity and direct current IAM proof\n'
  shell_join env \
    "DEPLOYMENT_CONFIG_SHA256=$DEPLOY_CONFIG_PROJECTION_SHA256" \
    "$LANE_DIR/deploy.sh" --config "$DEPLOY_CONFIG_PROJECTION" \
    --verify-protected-identity
  printf '# refuse bootstrap if either Cloud Run service already exists\n'
  shell_join gcloud run services list \
    "--project=$PROJECT_ID" "--region=$REGION" \
    "--filter=metadata.name=($ACTUATOR_SERVICE OR $DECISION_SERVICE)" \
    --format='value(metadata.name)'
  printf '# independently query project ancestry and resolve one covering analyzer scope\n'
  shell_join gcloud projects describe "$PROJECT_ID" \
    "--project=$PROJECT_ID" --format='value(projectNumber)'
  shell_join gcloud projects get-ancestors "$PROJECT_ID" \
    --format=json --quiet
  printf '# require both dedicated identities to be pre-provisioned\n'
  for account in \
    "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
    "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"; do
    shell_join gcloud iam service-accounts describe \
      "$(runtime_service_account_email "$account")" \
      "--project=$PROJECT_ID"
  done
  printf '# prove both identities have no effective IAM access in the covering scope\n'
  local render_analyzer_scope
  render_analyzer_scope=${REQUESTED_ANALYZER_SCOPE:-<resolved-after-ancestry-proof>}
  for account in \
    "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
    "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"; do
    shell_join gcloud asset analyze-iam-policy \
      "--identity=serviceAccount:$(runtime_service_account_email "$account")" \
      "--scope=$render_analyzer_scope" \
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
  printf '# sign and durably claim both exact resourceVersion-locked traffic requests before either send\n'
  shell_join "$LANE_DIR/verify-stable-release.py" authorize-bootstrap \
    --config "$CONFIG" --plan '<exact-traffic-plan.json>' \
    --provenance "$PROVENANCE_FILE" --output '<signed-traffic-authorization.json>'
  shell_join '<protected-attempt-store>' claim \
    '<signed-traffic-attempt-claim.json>'
  printf '# send each exact resourceVersion-locked body; read back and terminalize before advancing\n'
  shell_join curl --request PUT --data-binary \
    '@<resourceVersion-locked-actuator.json>' '<cloud-run-v1-service-url>'
  shell_join curl --request PUT --data-binary \
    '@<resourceVersion-locked-decision.json>' '<cloud-run-v1-service-url>'
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
if [[ -n "$SIGNING_KEY_FILE" ]]; then
  [[ -f "$SIGNING_KEY_FILE" ]] \
    || lane_die "stable-release private key is unavailable"
  private_mode=$(stat -f '%Lp' "$SIGNING_KEY_FILE" 2>/dev/null \
    || stat -c '%a' "$SIGNING_KEY_FILE")
  (( (8#$private_mode & 8#077) == 0 )) \
    || lane_die "stable-release private key must not be group/world accessible"
fi
HTTP_TMPDIR=$(mktemp -d)
trap 'rm -rf "${HTTP_TMPDIR:-}"; lane_cleanup_pinned_config' EXIT

"$LANE_DIR/verify-stable-release.py" verify-bootstrap \
  --config "$CONFIG" \
  --image "$PLACEHOLDER_IMAGE" \
  --provenance "$PROVENANCE_FILE"

DEPLOYMENT_CONFIG_SHA256="$DEPLOY_CONFIG_PROJECTION_SHA256" \
  "$LANE_DIR/deploy.sh" \
  --config "$DEPLOY_CONFIG_PROJECTION" \
  --verify-protected-identity
resolve_analyzer_scope

if [[ -e "$OUTPUT" ]]; then
  verify_existing_command=(
    "$LANE_DIR/verify-stable-release.py" verify
    --config "$CONFIG"
    --manifest "$OUTPUT"
    --live
  )
  if [[ -n "$VERIFY_KEY_FILE" ]]; then
    verify_existing_command+=(--public-key "$VERIFY_KEY_FILE")
  fi
  "${verify_existing_command[@]}" >/dev/null \
    || lane_die "existing stable-release output is not an exact live completion"
  printf 'stable bootstrap is already complete and live: %s\n' "$OUTPUT"
  exit 0
fi

for api in run.googleapis.com iam.googleapis.com cloudasset.googleapis.com; do
  state=$(gcloud services describe "$api" \
    "--project=$PROJECT_ID" '--format=value(state)' 2>/dev/null) \
    || lane_die "$api must already be ENABLED by provisioning"
  [[ "$state" == ENABLED ]] \
    || lane_die "$api must already be ENABLED by provisioning"
done

prepare_attempt_store_adapter() {
  [[ -n "${EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER:-}" \
      && "$EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER" == /* ]] \
    || lane_die "a protected absolute rollout attempt-store adapter is required"
  [[ "${EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
    || lane_die "rollout attempt-store adapter SHA-256 is required"
  ATTEMPT_STORE_ADAPTER="$HTTP_TMPDIR/attempt-store-adapter"
  python3 - "$EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER" \
    "$ATTEMPT_STORE_ADAPTER" \
    "$EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER_SHA256" <<'PY' \
    || lane_die "rollout attempt-store adapter trust check failed"
import errno
import hashlib
import os
import stat
import sys

source, destination, expected = sys.argv[1:]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
try:
    descriptor = os.open(source, flags)
except OSError as error:
    if error.errno in {errno.ELOOP, errno.EMLINK}:
        raise SystemExit("adapter must be a regular non-symlink file")
    raise
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SystemExit("adapter must be a regular non-symlink file")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise SystemExit("adapter ownership is unsafe")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise SystemExit("adapter permits group or world writes")
    chunks = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    raw = b"".join(chunks)
finally:
    os.close(descriptor)
if not raw or hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit("adapter bytes differ from protected SHA-256")
output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    output_flags |= os.O_NOFOLLOW
output = os.open(destination, output_flags, 0o500)
try:
    view = memoryview(raw)
    while view:
        written = os.write(output, view)
        view = view[written:]
    os.fsync(output)
finally:
    os.close(output)
PY
}

new_authorization_token() {
  python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
}

hash_command() {
  printf '%s\0' "$@" \
    | python3 -c \
      'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
}

hash_reconciliation() {
  python3 - "$@" <<'PY'
import hashlib
import json
import sys

value = {
    "schema": "emilia-bootstrap-reconciliation.v1",
    "phase": sys.argv[1],
    "plane": sys.argv[2],
    "service": sys.argv[3],
    "revision": sys.argv[4],
    "resource_version": sys.argv[5],
    "state": sys.argv[6],
    "prior_authorization_id": sys.argv[7],
}
print(hashlib.sha256(json.dumps(
    value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode()).hexdigest())
PY
}

write_authorization_plan() {
  local output=$1 phase=$2
  local actuator_mode=$3 actuator_authorization=$4 actuator_nonce=$5
  local actuator_request=$6 actuator_pre=$7
  local decision_mode=$8 decision_authorization=$9 decision_nonce=${10}
  local decision_request=${11} decision_pre=${12}
  python3 - "$output" "$phase" "$PROJECT_ID" "$REGION" "$BOOTSTRAP_ID" \
    "$PLACEHOLDER_IMAGE" "$STABLE_BOOTSTRAP_PROVENANCE_SHA256" \
    "$DEPLOYMENT_CONFIG_SHA256" "$DEPLOYER_PRINCIPAL" \
    "$GITHUB_WORKFLOW_REF" "$GITHUB_SHA" "$EMILIA_DEPLOY_WIF_PROVIDER" \
    "$actuator_mode" "$actuator_authorization" "$actuator_nonce" \
    "$actuator_request" "$actuator_pre" \
    "$decision_mode" "$decision_authorization" "$decision_nonce" \
    "$decision_request" "$decision_pre" <<'PY'
import json
import os
import sys

(
    output,
    phase,
    project_id,
    region,
    bootstrap_id,
    image,
    provenance_sha256,
    config_sha256,
    deployer_principal,
    workflow_ref,
    workflow_sha,
    wif_provider,
    actuator_mode,
    actuator_authorization,
    actuator_nonce,
    actuator_request,
    actuator_pre,
    decision_mode,
    decision_authorization,
    decision_nonce,
    decision_request,
    decision_pre,
) = sys.argv[1:]
services = {
    "actuator": os.environ["ACTUATOR_SERVICE"],
    "decision": os.environ["DECISION_SERVICE"],
}
mutations = []
for plane, mode, authorization_id, nonce, request_sha256, pre in (
    (
        "actuator",
        actuator_mode,
        actuator_authorization,
        actuator_nonce,
        actuator_request,
        actuator_pre,
    ),
    (
        "decision",
        decision_mode,
        decision_authorization,
        decision_nonce,
        decision_request,
        decision_pre,
    ),
):
    service = services[plane]
    mutations.append({
        "authorization_id": authorization_id,
        "rollout_nonce": nonce,
        "phase": phase,
        "plane": plane,
        "mode": mode,
        "service": service,
        "revision": f"{service}-{bootstrap_id}",
        "transition": (
            "apply-actuator-100"
            if plane == "actuator"
            else "apply-decision-100"
        ),
        "request_sha256": request_sha256,
        "pre_resource_version": pre,
        "expected_traffic_percent": 0 if phase == "deploy" else 100,
    })
value = {
    "@version": "EP-CONSEQUENCE-BOOTSTRAP-AUTHORIZATION-v1",
    "project_id": project_id,
    "region": region,
    "bootstrap_id": bootstrap_id,
    "image": image,
    "provenance_sha256": provenance_sha256,
    "deployment": {
        "config_sha256": config_sha256,
        "deployer_principal": deployer_principal,
        "workflow_ref": workflow_ref,
        "workflow_sha": workflow_sha,
        "wif_provider": wif_provider,
    },
    "mutations": mutations,
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(output, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY
}

authorize_plan() {
  local plan=$1 output=$2
  local command=(
    "$LANE_DIR/verify-stable-release.py" authorize-bootstrap
    --config "$CONFIG"
    --plan "$plan"
    --provenance "$PROVENANCE_FILE"
    --key-id "$KEY_ID"
    --output "$output"
  )
  if [[ -n "$SIGNING_KEY_FILE" ]]; then
    command+=(--private-key "$SIGNING_KEY_FILE")
  else
    command+=(--kms-key-uri "$KMS_KEY_URI")
  fi
  "${command[@]}" >/dev/null \
    || lane_die "exact bootstrap authorization signing failed"
}

extract_attempt_claim() {
  local authorization=$1 phase=$2 plane=$3 output=$4
  local command=(
    "$LANE_DIR/verify-stable-release.py" bootstrap-claim
    --config "$CONFIG"
    --authorization "$authorization"
    --phase "$phase"
    --plane "$plane"
    --output "$output"
  )
  if [[ -n "$VERIFY_KEY_FILE" ]]; then
    command+=(--public-key "$VERIFY_KEY_FILE")
  fi
  "${command[@]}"
}

attempt_store_call() {
  local operation=$1 payload=$2 claim_sha256=$3 allowed_status=$4
  local final_resource_version=${5:-} response response_file
  response_file="$HTTP_TMPDIR/attempt-response-$claim_sha256-$operation.json"
  "$ATTEMPT_STORE_ADAPTER" "$operation" < "$payload" > "$response_file" \
    || lane_die "durable attempt-store $operation failed; no further mutation permitted"
  local verification=(
    "$LANE_DIR/verify-rollout-telemetry.py" verify-attempt-response
    --input "$response_file"
    --operation "$operation"
    --claim-sha256 "$claim_sha256"
    --allow-status "$allowed_status"
  )
  if [[ "$operation" != claim ]]; then
    [[ -n "$final_resource_version" ]] \
      || lane_die "attempt terminal requires a final resourceVersion"
    verification+=(
      --expected-final-resource-version "$final_resource_version"
    )
  fi
  "${verification[@]}" >/dev/null \
    || lane_die "durable attempt-store $operation response is invalid"
}

claim_attempt() {
  attempt_store_call claim "$1" "$2" claimed
}

terminalize_attempt() {
  local claim=$1 claim_sha256=$2 operation=$3 outcome=$4
  local resource_version=$5 payload allowed
  payload="$HTTP_TMPDIR/attempt-terminal-$claim_sha256.json"
  python3 - "$claim" "$payload" "$operation" "$outcome" \
    "$resource_version" <<'PY'
import json
import os
import sys

claim_path, output, operation, outcome, resource_version = sys.argv[1:]
with open(claim_path, encoding="utf-8") as handle:
    claim = json.load(handle)
value = {
    "schema": "emilia-deployment-attempt-store-operation.v1",
    "operation": operation,
    "claim": claim,
    "outcome": outcome,
    "final_resource_version": resource_version,
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(output, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY
  if [[ "$operation" == complete ]]; then
    allowed=completed
  else
    allowed=$outcome
  fi
  attempt_store_call \
    "$operation" "$payload" "$claim_sha256" "$allowed" "$resource_version"
}

service_is_listed() {
  local service=$1 services
  services=$(
    gcloud run services list \
      "--project=$PROJECT_ID" "--region=$REGION" \
      "--filter=metadata.name=($ACTUATOR_SERVICE OR $DECISION_SERVICE)" \
      --format='value(metadata.name)'
  ) || lane_die "Cloud Run service inventory is unavailable"
  set +e
  python3 - "$service" "$ACTUATOR_SERVICE" "$DECISION_SERVICE" \
    "$services" <<'PY'
import sys

target, actuator, decision, raw = sys.argv[1:]
values = [line for line in raw.splitlines() if line]
if len(values) != len(set(values)) or not set(values).issubset({actuator, decision}):
    raise SystemExit(2)
raise SystemExit(0 if target in values else 1)
PY
  local status=$?
  set -e
  ((status <= 1)) || lane_die "Cloud Run service inventory is malformed"
  return "$status"
}

capture_plane() {
  local plane=$1 service revision service_snapshot revision_snapshot
  if [[ "$plane" == actuator ]]; then
    service=$ACTUATOR_SERVICE
    revision=$ACTUATOR_REVISION
    service_snapshot=$ACTUATOR_SERVICE_SNAPSHOT
    revision_snapshot=$ACTUATOR_REVISION_SNAPSHOT
  else
    service=$DECISION_SERVICE
    revision=$DECISION_REVISION
    service_snapshot=$DECISION_SERVICE_SNAPSHOT
    revision_snapshot=$DECISION_REVISION_SNAPSHOT
  fi
  gcloud run services describe "$service" \
    "--project=$PROJECT_ID" "--region=$REGION" --format=json \
    > "$service_snapshot" \
    || lane_die "unable to describe bootstrap service $service"
  gcloud run revisions describe "$revision" \
    "--project=$PROJECT_ID" "--region=$REGION" --format=json \
    > "$revision_snapshot" \
    || lane_die "unable to describe bootstrap revision $revision"
}

verify_plane_state() {
  local plane=$1 expected_state=${2:-}
  local expected_deploy=${3:-} expected_traffic=${4:-}
  local service_snapshot revision_snapshot
  if [[ "$plane" == actuator ]]; then
    service_snapshot=$ACTUATOR_SERVICE_SNAPSHOT
    revision_snapshot=$ACTUATOR_REVISION_SNAPSHOT
  else
    service_snapshot=$DECISION_SERVICE_SNAPSHOT
    revision_snapshot=$DECISION_REVISION_SNAPSHOT
  fi
  local command=(
    "$LANE_DIR/verify-stable-release.py" verify-bootstrap-state
    --config "$CONFIG"
    --service-snapshot "$service_snapshot"
    --revision-snapshot "$revision_snapshot"
    --plane "$plane"
    --bootstrap-id "$BOOTSTRAP_ID"
    --image "$PLACEHOLDER_IMAGE"
    --provenance "$PROVENANCE_FILE"
  )
  if [[ -n "$expected_state" ]]; then
    command+=(--expect-state "$expected_state")
  fi
  if [[ -n "$expected_deploy" ]]; then
    command+=(--expect-deploy-authorization "$expected_deploy")
  fi
  if [[ -n "$expected_traffic" ]]; then
    command+=(--expect-traffic-authorization "$expected_traffic")
  fi
  "${command[@]}"
}

observed_resource_version() {
  python3 - "$1" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        value = json.load(handle)
    resource_version = value.get("metadata", {}).get("resourceVersion")
    if (
        not isinstance(resource_version, str)
        or not resource_version
        or any(character.isspace() for character in resource_version)
    ):
        raise ValueError
except (OSError, ValueError, json.JSONDecodeError):
    print("unknown")
else:
    print(resource_version)
PY
}

prepare_attempt_store_adapter
ACTUATOR_SERVICE_SNAPSHOT="$HTTP_TMPDIR/actuator-service.json"
DECISION_SERVICE_SNAPSHOT="$HTTP_TMPDIR/decision-service.json"
ACTUATOR_REVISION_SNAPSHOT="$HTTP_TMPDIR/actuator-revision.json"
DECISION_REVISION_SNAPSHOT="$HTTP_TMPDIR/decision-revision.json"

require_bootstrap_service_account() {
  local account=$1 email
  email=$(runtime_service_account_email "$account")
  if ! gcloud iam service-accounts describe "$email" \
      "--project=$PROJECT_ID" >/dev/null 2>&1; then
    lane_die "bootstrap service account must be pre-provisioned: $email"
  fi
}

prove_bootstrap_service_account_permissionless() {
  local account=$1 email analysis
  email=$(runtime_service_account_email "$account")
  analysis=$(
    gcloud asset analyze-iam-policy \
      "--identity=serviceAccount:$email" \
      "--scope=$RESOLVED_ANALYZER_SCOPE" \
      --format=json
  )
  python3 -c '
import json, sys
value = json.load(sys.stdin)
if not isinstance(value, dict) or value.get("fullyExplored") is not True:
    raise SystemExit("IAM response was not fully explored")
main = value.get("mainAnalysis")
if not isinstance(main, dict) or main.get("fullyExplored") is not True:
    raise SystemExit("main IAM analysis was not fully explored")
errors = main.get("nonCriticalErrors", [])
if not isinstance(errors, list) or errors:
    raise SystemExit("main IAM analysis contains unresolved errors")
results = main.get("analysisResults")
if not isinstance(results, list):
    raise SystemExit("IAM analysis results are malformed")
if results:
    raise SystemExit("bootstrap identity has effective IAM access")
' <<< "$analysis" \
    || lane_die "bootstrap service account is not proven permissionless: $email"
}

for account in \
  "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
  "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"; do
  require_bootstrap_service_account "$account"
done
for account in \
  "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
  "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"; do
  prove_bootstrap_service_account_permissionless "$account"
done

inspect_deployment_state() {
  local plane=$1 service verification
  if [[ "$plane" == actuator ]]; then
    service=$ACTUATOR_SERVICE
  else
    service=$DECISION_SERVICE
  fi
  if service_is_listed "$service"; then
    capture_plane "$plane"
    verification=$(verify_plane_state "$plane") \
      || lane_die \
        "existing $plane bootstrap service is not an exact authorized partial effect"
    local state generation resource_version deploy_authorization
    local _traffic_authorization
    IFS=$'\t' read -r state generation resource_version \
      deploy_authorization _traffic_authorization <<< "$verification"
    [[ "$state" == zero || "$state" == post ]] \
      || lane_die "$plane bootstrap service state is not resumable"
    if [[ "$plane" == actuator ]]; then
      ACTUATOR_DEPLOY_MODE=reconcile
      ACTUATOR_DEPLOY_STATE=$state
      ACTUATOR_DEPLOY_PRE=$resource_version
      ACTUATOR_DEPLOY_PRIOR_AUTH=$deploy_authorization
    else
      DECISION_DEPLOY_MODE=reconcile
      DECISION_DEPLOY_STATE=$state
      DECISION_DEPLOY_PRE=$resource_version
      DECISION_DEPLOY_PRIOR_AUTH=$deploy_authorization
    fi
  else
    if [[ "$plane" == actuator ]]; then
      ACTUATOR_DEPLOY_MODE=apply
      ACTUATOR_DEPLOY_STATE=zero
      ACTUATOR_DEPLOY_PRE=absent
      ACTUATOR_DEPLOY_PRIOR_AUTH=absent
    else
      DECISION_DEPLOY_MODE=apply
      DECISION_DEPLOY_STATE=zero
      DECISION_DEPLOY_PRE=absent
      DECISION_DEPLOY_PRIOR_AUTH=absent
    fi
  fi
}

inspect_deployment_state actuator
inspect_deployment_state decision

ACTUATOR_DEPLOY_AUTHORIZATION=$(new_authorization_token)
ACTUATOR_DEPLOY_NONCE=$(new_authorization_token)
DECISION_DEPLOY_AUTHORIZATION=$(new_authorization_token)
DECISION_DEPLOY_NONCE=$(new_authorization_token)

if [[ "$ACTUATOR_DEPLOY_MODE" == apply ]]; then
  placeholder_deploy_command \
    "$ACTUATOR_SERVICE" "$ACTUATOR_SA" "$ACTUATOR_INGRESS" \
    "$ACTUATOR_DEPLOY_AUTHORIZATION"
  ACTUATOR_DEPLOY_REQUEST=$(
    hash_command "${PLACEHOLDER_DEPLOY_COMMAND[@]}"
  )
else
  ACTUATOR_DEPLOY_REQUEST=$(
    hash_reconciliation \
      deploy actuator "$ACTUATOR_SERVICE" "$ACTUATOR_REVISION" \
      "$ACTUATOR_DEPLOY_PRE" "$ACTUATOR_DEPLOY_STATE" \
      "$ACTUATOR_DEPLOY_PRIOR_AUTH"
  )
fi
if [[ "$DECISION_DEPLOY_MODE" == apply ]]; then
  placeholder_deploy_command \
    "$DECISION_SERVICE" "$DECISION_SA" "$DECISION_INGRESS" \
    "$DECISION_DEPLOY_AUTHORIZATION"
  DECISION_DEPLOY_REQUEST=$(
    hash_command "${PLACEHOLDER_DEPLOY_COMMAND[@]}"
  )
else
  DECISION_DEPLOY_REQUEST=$(
    hash_reconciliation \
      deploy decision "$DECISION_SERVICE" "$DECISION_REVISION" \
      "$DECISION_DEPLOY_PRE" "$DECISION_DEPLOY_STATE" \
      "$DECISION_DEPLOY_PRIOR_AUTH"
  )
fi

DEPLOY_PLAN="$HTTP_TMPDIR/deployment-plan.json"
DEPLOY_AUTHORIZATION="$HTTP_TMPDIR/deployment-authorization.json"
write_authorization_plan \
  "$DEPLOY_PLAN" deploy \
  "$ACTUATOR_DEPLOY_MODE" "$ACTUATOR_DEPLOY_AUTHORIZATION" \
  "$ACTUATOR_DEPLOY_NONCE" "$ACTUATOR_DEPLOY_REQUEST" \
  "$ACTUATOR_DEPLOY_PRE" \
  "$DECISION_DEPLOY_MODE" "$DECISION_DEPLOY_AUTHORIZATION" \
  "$DECISION_DEPLOY_NONCE" "$DECISION_DEPLOY_REQUEST" \
  "$DECISION_DEPLOY_PRE"
authorize_plan "$DEPLOY_PLAN" "$DEPLOY_AUTHORIZATION"

ACTUATOR_DEPLOY_CLAIM="$HTTP_TMPDIR/actuator-deploy-claim.json"
DECISION_DEPLOY_CLAIM="$HTTP_TMPDIR/decision-deploy-claim.json"
ACTUATOR_DEPLOY_CLAIM_SHA=$(
  extract_attempt_claim \
    "$DEPLOY_AUTHORIZATION" deploy actuator "$ACTUATOR_DEPLOY_CLAIM"
) || lane_die "signed actuator deployment claim is invalid"
DECISION_DEPLOY_CLAIM_SHA=$(
  extract_attempt_claim \
    "$DEPLOY_AUTHORIZATION" deploy decision "$DECISION_DEPLOY_CLAIM"
) || lane_die "signed decision deployment claim is invalid"
claim_attempt "$ACTUATOR_DEPLOY_CLAIM" "$ACTUATOR_DEPLOY_CLAIM_SHA"
claim_attempt "$DECISION_DEPLOY_CLAIM" "$DECISION_DEPLOY_CLAIM_SHA"

apply_or_reconcile_deployment() {
  local plane=$1 service account ingress mode expected_state pre
  local prior_authorization authorization claim claim_sha status verification
  local state generation resource_version deploy_authorization
  local _traffic_authorization
  if [[ "$plane" == actuator ]]; then
    service=$ACTUATOR_SERVICE
    account=$ACTUATOR_SA
    ingress=$ACTUATOR_INGRESS
    mode=$ACTUATOR_DEPLOY_MODE
    expected_state=$ACTUATOR_DEPLOY_STATE
    pre=$ACTUATOR_DEPLOY_PRE
    prior_authorization=$ACTUATOR_DEPLOY_PRIOR_AUTH
    authorization=$ACTUATOR_DEPLOY_AUTHORIZATION
    claim=$ACTUATOR_DEPLOY_CLAIM
    claim_sha=$ACTUATOR_DEPLOY_CLAIM_SHA
  else
    service=$DECISION_SERVICE
    account=$DECISION_SA
    ingress=$DECISION_INGRESS
    mode=$DECISION_DEPLOY_MODE
    expected_state=$DECISION_DEPLOY_STATE
    pre=$DECISION_DEPLOY_PRE
    prior_authorization=$DECISION_DEPLOY_PRIOR_AUTH
    authorization=$DECISION_DEPLOY_AUTHORIZATION
    claim=$DECISION_DEPLOY_CLAIM
    claim_sha=$DECISION_DEPLOY_CLAIM_SHA
  fi
  if [[ "$mode" == reconcile ]]; then
    capture_plane "$plane"
    verification=$(verify_plane_state "$plane" "$expected_state") \
      || lane_die "$plane deployment changed before durable reconciliation"
    IFS=$'\t' read -r state generation resource_version \
      deploy_authorization _traffic_authorization <<< "$verification"
    [[ "$resource_version" == "$pre" \
      && "$deploy_authorization" == "$prior_authorization" ]] \
      || lane_die "$plane deployment resourceVersion changed before reconciliation"
    terminalize_attempt \
      "$claim" "$claim_sha" reconcile applied "$resource_version"
    return
  fi
  if service_is_listed "$service"; then
    capture_plane "$plane"
    resource_version=$(observed_resource_version \
      "$([[ "$plane" == actuator ]] \
        && printf '%s' "$ACTUATOR_SERVICE_SNAPSHOT" \
        || printf '%s' "$DECISION_SERVICE_SNAPSHOT")")
    terminalize_attempt \
      "$claim" "$claim_sha" reconcile indeterminate "$resource_version"
    lane_die "$plane service appeared after the signed absent-state lock"
  fi
  placeholder_deploy_command "$service" "$account" "$ingress" "$authorization"
  set +e
  "${PLACEHOLDER_DEPLOY_COMMAND[@]}"
  status=$?
  set -e
  if service_is_listed "$service"; then
    capture_plane "$plane"
    set +e
    verification=$(verify_plane_state "$plane" zero "$authorization")
    local verify_status=$?
    set -e
    if ((verify_status == 0)); then
      IFS=$'\t' read -r state generation resource_version \
        deploy_authorization _traffic_authorization <<< "$verification"
      if ((status == 0)); then
        terminalize_attempt \
          "$claim" "$claim_sha" complete applied "$resource_version"
      else
        terminalize_attempt \
          "$claim" "$claim_sha" reconcile applied "$resource_version"
      fi
      return
    fi
    if [[ "$plane" == actuator ]]; then
      resource_version=$(observed_resource_version "$ACTUATOR_SERVICE_SNAPSHOT")
    else
      resource_version=$(observed_resource_version "$DECISION_SERVICE_SNAPSHOT")
    fi
    terminalize_attempt \
      "$claim" "$claim_sha" reconcile indeterminate "$resource_version"
    lane_die "$plane deployment response did not reconcile to the signed effect"
  fi
  terminalize_attempt "$claim" "$claim_sha" reconcile not-applied absent
  lane_die "$plane deployment was not applied"
}

apply_or_reconcile_deployment actuator
apply_or_reconcile_deployment decision

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

capture_plane actuator
capture_plane decision
ACTUATOR_TRAFFIC_VERIFICATION=$(verify_plane_state actuator) \
  || lane_die "actuator bootstrap traffic state is not safely resumable"
DECISION_TRAFFIC_VERIFICATION=$(verify_plane_state decision) \
  || lane_die "decision bootstrap traffic state is not safely resumable"
IFS=$'\t' read -r \
  ACTUATOR_TRAFFIC_STATE ACTUATOR_TRAFFIC_GENERATION ACTUATOR_TRAFFIC_PRE \
  _ACTUATOR_DEPLOY_EFFECT_AUTH ACTUATOR_PRIOR_TRAFFIC_AUTH \
  <<< "$ACTUATOR_TRAFFIC_VERIFICATION"
IFS=$'\t' read -r \
  DECISION_TRAFFIC_STATE DECISION_TRAFFIC_GENERATION DECISION_TRAFFIC_PRE \
  _DECISION_DEPLOY_EFFECT_AUTH DECISION_PRIOR_TRAFFIC_AUTH \
  <<< "$DECISION_TRAFFIC_VERIFICATION"
[[ "$ACTUATOR_TRAFFIC_STATE" == zero \
    || "$ACTUATOR_TRAFFIC_STATE" == post ]] \
  || lane_die "actuator bootstrap traffic state is invalid"
[[ "$DECISION_TRAFFIC_STATE" == zero \
    || "$DECISION_TRAFFIC_STATE" == post ]] \
  || lane_die "decision bootstrap traffic state is invalid"

ACTUATOR_TRAFFIC_AUTHORIZATION=$(new_authorization_token)
ACTUATOR_TRAFFIC_NONCE=$(new_authorization_token)
DECISION_TRAFFIC_AUTHORIZATION=$(new_authorization_token)
DECISION_TRAFFIC_NONCE=$(new_authorization_token)
ACTUATOR_TRAFFIC_BODY="$HTTP_TMPDIR/actuator-traffic-update.json"
DECISION_TRAFFIC_BODY="$HTTP_TMPDIR/decision-traffic-update.json"

prepare_traffic_request() {
  local plane=$1 state authorization output prepared
  if [[ "$plane" == actuator ]]; then
    state=$ACTUATOR_TRAFFIC_STATE
    authorization=$ACTUATOR_TRAFFIC_AUTHORIZATION
    output=$ACTUATOR_TRAFFIC_BODY
  else
    state=$DECISION_TRAFFIC_STATE
    authorization=$DECISION_TRAFFIC_AUTHORIZATION
    output=$DECISION_TRAFFIC_BODY
  fi
  if [[ "$state" == zero ]]; then
    local service_snapshot revision_snapshot
    if [[ "$plane" == actuator ]]; then
      service_snapshot=$ACTUATOR_SERVICE_SNAPSHOT
      revision_snapshot=$ACTUATOR_REVISION_SNAPSHOT
    else
      service_snapshot=$DECISION_SERVICE_SNAPSHOT
      revision_snapshot=$DECISION_REVISION_SNAPSHOT
    fi
    prepared=$(
      "$LANE_DIR/verify-stable-release.py" prepare-bootstrap-traffic \
        --config "$CONFIG" \
        --service-snapshot "$service_snapshot" \
        --revision-snapshot "$revision_snapshot" \
        --plane "$plane" \
        --bootstrap-id "$BOOTSTRAP_ID" \
        --image "$PLACEHOLDER_IMAGE" \
        --authorization-id "$authorization" \
        --output "$output"
    ) || lane_die "$plane resourceVersion-locked traffic request is invalid"
    local generation resource_version request_sha256
    IFS=$'\t' read -r generation resource_version request_sha256 <<< "$prepared"
    if [[ "$plane" == actuator ]]; then
      [[ "$generation" == "$ACTUATOR_TRAFFIC_GENERATION" \
        && "$resource_version" == "$ACTUATOR_TRAFFIC_PRE" ]] \
        || lane_die "actuator traffic request lock changed during preparation"
      ACTUATOR_TRAFFIC_MODE=apply
      ACTUATOR_TRAFFIC_REQUEST=$request_sha256
    else
      [[ "$generation" == "$DECISION_TRAFFIC_GENERATION" \
        && "$resource_version" == "$DECISION_TRAFFIC_PRE" ]] \
        || lane_die "decision traffic request lock changed during preparation"
      DECISION_TRAFFIC_MODE=apply
      DECISION_TRAFFIC_REQUEST=$request_sha256
    fi
  elif [[ "$plane" == actuator ]]; then
    ACTUATOR_TRAFFIC_MODE=reconcile
    ACTUATOR_TRAFFIC_REQUEST=$(
      hash_reconciliation \
        traffic actuator "$ACTUATOR_SERVICE" "$ACTUATOR_REVISION" \
        "$ACTUATOR_TRAFFIC_PRE" post "$ACTUATOR_PRIOR_TRAFFIC_AUTH"
    )
  else
    DECISION_TRAFFIC_MODE=reconcile
    DECISION_TRAFFIC_REQUEST=$(
      hash_reconciliation \
        traffic decision "$DECISION_SERVICE" "$DECISION_REVISION" \
        "$DECISION_TRAFFIC_PRE" post "$DECISION_PRIOR_TRAFFIC_AUTH"
    )
  fi
}

prepare_traffic_request actuator
prepare_traffic_request decision

TRAFFIC_PLAN="$HTTP_TMPDIR/traffic-plan.json"
TRAFFIC_AUTHORIZATION="$HTTP_TMPDIR/traffic-authorization.json"
write_authorization_plan \
  "$TRAFFIC_PLAN" traffic \
  "$ACTUATOR_TRAFFIC_MODE" "$ACTUATOR_TRAFFIC_AUTHORIZATION" \
  "$ACTUATOR_TRAFFIC_NONCE" "$ACTUATOR_TRAFFIC_REQUEST" \
  "$ACTUATOR_TRAFFIC_PRE" \
  "$DECISION_TRAFFIC_MODE" "$DECISION_TRAFFIC_AUTHORIZATION" \
  "$DECISION_TRAFFIC_NONCE" "$DECISION_TRAFFIC_REQUEST" \
  "$DECISION_TRAFFIC_PRE"
authorize_plan "$TRAFFIC_PLAN" "$TRAFFIC_AUTHORIZATION"

ACTUATOR_TRAFFIC_CLAIM="$HTTP_TMPDIR/actuator-traffic-claim.json"
DECISION_TRAFFIC_CLAIM="$HTTP_TMPDIR/decision-traffic-claim.json"
ACTUATOR_TRAFFIC_CLAIM_SHA=$(
  extract_attempt_claim \
    "$TRAFFIC_AUTHORIZATION" traffic actuator "$ACTUATOR_TRAFFIC_CLAIM"
) || lane_die "signed actuator traffic claim is invalid"
DECISION_TRAFFIC_CLAIM_SHA=$(
  extract_attempt_claim \
    "$TRAFFIC_AUTHORIZATION" traffic decision "$DECISION_TRAFFIC_CLAIM"
) || lane_die "signed decision traffic claim is invalid"
claim_attempt "$ACTUATOR_TRAFFIC_CLAIM" "$ACTUATOR_TRAFFIC_CLAIM_SHA"
claim_attempt "$DECISION_TRAFFIC_CLAIM" "$DECISION_TRAFFIC_CLAIM_SHA"

verify_plane_snapshot_state() {
  local plane=$1 service_snapshot=$2 expected_state=$3
  local expected_deploy=${4:-} expected_traffic=${5:-}
  local revision_snapshot
  if [[ "$plane" == actuator ]]; then
    revision_snapshot=$ACTUATOR_REVISION_SNAPSHOT
  else
    revision_snapshot=$DECISION_REVISION_SNAPSHOT
  fi
  local command=(
    "$LANE_DIR/verify-stable-release.py" verify-bootstrap-state
    --config "$CONFIG"
    --service-snapshot "$service_snapshot"
    --revision-snapshot "$revision_snapshot"
    --plane "$plane"
    --bootstrap-id "$BOOTSTRAP_ID"
    --image "$PLACEHOLDER_IMAGE"
    --provenance "$PROVENANCE_FILE"
    --expect-state "$expected_state"
  )
  if [[ -n "$expected_deploy" ]]; then
    command+=(--expect-deploy-authorization "$expected_deploy")
  fi
  if [[ -n "$expected_traffic" ]]; then
    command+=(--expect-traffic-authorization "$expected_traffic")
  fi
  "${command[@]}"
}

reconcile_traffic_send() {
  local plane=$1 claim=$2 claim_sha=$3 pre=$4 authorization=$5
  local service_snapshot verification state generation resource_version
  local deploy_authorization _traffic_authorization
  capture_plane "$plane"
  if [[ "$plane" == actuator ]]; then
    service_snapshot=$ACTUATOR_SERVICE_SNAPSHOT
  else
    service_snapshot=$DECISION_SERVICE_SNAPSHOT
  fi
  set +e
  verification=$(verify_plane_state "$plane" post "" "$authorization")
  local post_status=$?
  set -e
  if ((post_status == 0)); then
    IFS=$'\t' read -r state generation resource_version \
      deploy_authorization _traffic_authorization <<< "$verification"
    [[ "$resource_version" != "$pre" ]] \
      || lane_die "$plane traffic response did not advance resourceVersion"
    terminalize_attempt \
      "$claim" "$claim_sha" reconcile applied "$resource_version"
    return 0
  fi
  set +e
  verification=$(verify_plane_state "$plane" zero)
  local pre_status=$?
  set -e
  if ((pre_status == 0)); then
    IFS=$'\t' read -r state generation resource_version \
      deploy_authorization _traffic_authorization <<< "$verification"
    if [[ "$resource_version" == "$pre" ]]; then
      terminalize_attempt \
        "$claim" "$claim_sha" reconcile not-applied "$resource_version"
      lane_die "$plane traffic mutation was not applied"
    fi
  fi
  resource_version=$(observed_resource_version "$service_snapshot")
  terminalize_attempt \
    "$claim" "$claim_sha" reconcile indeterminate "$resource_version"
  lane_die "$plane traffic effect is indeterminate; no further mutation permitted"
}

apply_or_reconcile_traffic() {
  local plane=$1 mode service body claim claim_sha pre generation
  local prior_traffic authorization other_plane status response curl_config token
  if [[ "$plane" == actuator ]]; then
    mode=$ACTUATOR_TRAFFIC_MODE
    service=$ACTUATOR_SERVICE
    body=$ACTUATOR_TRAFFIC_BODY
    claim=$ACTUATOR_TRAFFIC_CLAIM
    claim_sha=$ACTUATOR_TRAFFIC_CLAIM_SHA
    pre=$ACTUATOR_TRAFFIC_PRE
    generation=$ACTUATOR_TRAFFIC_GENERATION
    prior_traffic=$ACTUATOR_PRIOR_TRAFFIC_AUTH
    authorization=$ACTUATOR_TRAFFIC_AUTHORIZATION
    other_plane=decision
  else
    mode=$DECISION_TRAFFIC_MODE
    service=$DECISION_SERVICE
    body=$DECISION_TRAFFIC_BODY
    claim=$DECISION_TRAFFIC_CLAIM
    claim_sha=$DECISION_TRAFFIC_CLAIM_SHA
    pre=$DECISION_TRAFFIC_PRE
    generation=$DECISION_TRAFFIC_GENERATION
    prior_traffic=$DECISION_PRIOR_TRAFFIC_AUTH
    authorization=$DECISION_TRAFFIC_AUTHORIZATION
    other_plane=actuator
  fi
  if [[ "$mode" == reconcile ]]; then
    capture_plane "$plane"
    local verification state observed_generation resource_version
    local deploy_authorization _traffic_authorization
    verification=$(verify_plane_state "$plane" post "" "$prior_traffic") \
      || lane_die "$plane authorized traffic effect changed before reconciliation"
    IFS=$'\t' read -r state observed_generation resource_version \
      deploy_authorization _traffic_authorization <<< "$verification"
    [[ "$resource_version" == "$pre" ]] \
      || lane_die "$plane traffic resourceVersion changed before reconciliation"
    terminalize_attempt \
      "$claim" "$claim_sha" reconcile applied "$resource_version"
    return
  fi
  capture_plane "$plane"
  local locked state observed_generation resource_version
  local deploy_authorization _traffic_authorization
  locked=$(verify_plane_state "$plane" zero) \
    || lane_die "$plane traffic pre-state changed after signed authorization"
  IFS=$'\t' read -r state observed_generation resource_version \
    deploy_authorization _traffic_authorization <<< "$locked"
  [[ "$resource_version" == "$pre" \
    && "$observed_generation" == "$generation" ]] \
    || lane_die "$plane traffic lock changed after signed authorization"
  capture_plane "$other_plane"
  if [[ "$plane" == decision ]]; then
    verify_plane_state actuator post >/dev/null \
      || lane_die "actuator bootstrap must be exact before decision traffic"
  else
    if [[ "$DECISION_TRAFFIC_STATE" == zero ]]; then
      verify_plane_state decision zero >/dev/null \
        || lane_die "decision bootstrap changed before actuator traffic"
    else
      verify_plane_state decision post >/dev/null \
        || lane_die "decision bootstrap changed before actuator traffic"
    fi
  fi
  [[ "$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$body")" \
      == "$([[ "$plane" == actuator ]] \
        && printf '%s' "$ACTUATOR_TRAFFIC_REQUEST" \
        || printf '%s' "$DECISION_TRAFFIC_REQUEST")" ]] \
    || lane_die "$plane traffic request bytes changed after authorization"
  token=$(gcloud auth print-access-token --quiet) \
    || lane_die "unable to obtain a Cloud Run API access token"
  [[ "$token" =~ ^[A-Za-z0-9._~-]+$ ]] \
    || lane_die "Cloud Run API access token is malformed"
  curl_config="$HTTP_TMPDIR/$plane-curl.conf"
  {
    printf 'header = "Authorization: Bearer %s"\n' "$token"
    printf 'header = "Content-Type: application/json"\n'
  } > "$curl_config"
  chmod 600 "$curl_config"
  response="$HTTP_TMPDIR/$plane-traffic-response.json"
  local url
  url="https://run.googleapis.com/apis/serving.knative.dev/v1/projects"
  url+="/$PROJECT_ID/locations/$REGION/services/$service"
  set +e
  curl \
    --silent \
    --show-error \
    --fail-with-body \
    --request PUT \
    --config "$curl_config" \
    --data-binary @- \
    --output "$response" \
    "$url" < "$body"
  status=$?
  set -e
  if ((status != 0)) || [[ ! -s "$response" ]]; then
    reconcile_traffic_send \
      "$plane" "$claim" "$claim_sha" "$pre" "$authorization"
    return
  fi
  local acknowledgement _ack_state ack_generation ack_resource_version
  local _ack_deploy_authorization _ack_traffic_authorization
  set +e
  acknowledgement=$(
    verify_plane_snapshot_state \
      "$plane" "$response" post "" "$authorization"
  )
  local ack_status=$?
  set -e
  if ((ack_status != 0)); then
    reconcile_traffic_send \
      "$plane" "$claim" "$claim_sha" "$pre" "$authorization"
    return
  fi
  IFS=$'\t' read -r _ack_state ack_generation ack_resource_version \
    _ack_deploy_authorization _ack_traffic_authorization <<< "$acknowledgement"
  [[ "$ack_generation" =~ ^[1-9][0-9]*$ \
    && "$ack_generation" -gt "$generation" \
    && "$ack_resource_version" != "$pre" ]] \
    || lane_die "$plane traffic acknowledgement did not advance the exact lock"
  local poll verification _poll_state poll_generation poll_resource_version
  local _poll_deploy_authorization _poll_traffic_authorization
  for ((poll = 1; poll <= 30; poll++)); do
    capture_plane "$plane"
    set +e
    verification=$(verify_plane_state "$plane" post "" "$authorization")
    status=$?
    set -e
    if ((status == 0)); then
      IFS=$'\t' read -r _poll_state poll_generation poll_resource_version \
        _poll_deploy_authorization _poll_traffic_authorization <<< "$verification"
      if [[ "$poll_generation" == "$ack_generation" \
        && "$poll_resource_version" == "$ack_resource_version" ]]; then
        terminalize_attempt \
          "$claim" "$claim_sha" complete applied "$ack_resource_version"
        return
      fi
      lane_die "$plane traffic read-back changed after acknowledgement"
    fi
    if ((poll < 30)); then
      sleep 2
    fi
  done
  lane_die "$plane traffic did not reconcile before the bounded deadline"
}

apply_or_reconcile_traffic actuator
apply_or_reconcile_traffic decision

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
