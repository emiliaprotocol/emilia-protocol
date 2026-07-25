#!/usr/bin/env bash
set -euo pipefail
umask 077

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$LANE_DIR/lib/common.sh"

CONFIG=
ACTION=
EVIDENCE=
TELEMETRY=
AUTHORIZATION=
STABLE_MANIFEST=
STABLE_PUBLIC_KEY=
readonly MAX_ERROR_RATE=0.01
readonly MAX_P95_LATENCY_MS=500
readonly MIN_READINESS_RATE=0.99
readonly MAX_INDETERMINATE_RATE=0.005
readonly MIN_DWELL_SECONDS=600
readonly MIN_REQUESTS=100
readonly MIN_READINESS_SAMPLES=3
readonly MAX_SAMPLE_GAP_SECONDS=300
readonly MAX_TELEMETRY_AGE_SECONDS=900
readonly ROLLOUT_POLL_ATTEMPTS=30
readonly ROLLOUT_POLL_INTERVAL_SEC=2
while (($#)); do
  case "$1" in
    --config)
      (($# >= 2)) || lane_die "--config requires a path"
      CONFIG=$2
      shift 2
      ;;
    --evidence)
      (($# >= 2)) || lane_die "--evidence requires a path"
      EVIDENCE=$2
      shift 2
      ;;
    --telemetry)
      (($# >= 2)) || lane_die "--telemetry requires a path"
      TELEMETRY=$2
      shift 2
      ;;
    --authorization)
      (($# >= 2)) || lane_die "--authorization requires a path"
      AUTHORIZATION=$2
      shift 2
      ;;
    --stable-manifest)
      (($# >= 2)) || lane_die "--stable-manifest requires a path"
      STABLE_MANIFEST=$2
      shift 2
      ;;
    --stable-public-key)
      (($# >= 2)) || lane_die "--stable-public-key requires a path"
      STABLE_PUBLIC_KEY=$2
      shift 2
      ;;
    --render-promote|--render-rollback|--apply-decision-1|--apply-decision-10|--apply-decision-50|--apply-decision-100|--apply-actuator-100|--apply-rollback)
      [[ -z "$ACTION" ]] || lane_die "select exactly one traffic action"
      ACTION=${1#--}
      shift
      ;;
    *)
      lane_die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$CONFIG" ]] || lane_die "--config is required"
[[ -n "$ACTION" ]] || lane_die "a traffic action is required"
if [[ "$ACTION" != render-promote && "$ACTION" != render-rollback ]]; then
  export REQUIRE_DEPLOYMENT_CONFIG_PIN=true
fi
TRAFFIC_CONFIG_KEYS=()
while IFS= read -r name; do
  TRAFFIC_CONFIG_KEYS+=("$name")
done < <(deployment_config_variables)
load_lane_config "$CONFIG" "${TRAFFIC_CONFIG_KEYS[@]}"
validate_lane_config

require_protected_traffic_identity() {
  local expected_workflow
  expected_workflow="emiliaprotocol/emilia-protocol/.github/workflows/"
  expected_workflow+="consequence-control-deploy.yml@refs/heads/main"
  [[ "${GITHUB_ACTIONS:-}" == true ]] \
    || lane_die "traffic mutation requires protected GitHub Actions"
  [[ "${GITHUB_REPOSITORY:-}" == emiliaprotocol/emilia-protocol \
      && "${GITHUB_REF:-}" == refs/heads/main \
      && "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] \
    || lane_die "traffic mutation requires the protected main workflow"
  [[ "${GITHUB_WORKFLOW_REF:-}" == "$expected_workflow" ]] \
    || lane_die "traffic mutation workflow identity mismatch"
  [[ "${EMILIA_GITHUB_WORKFLOW_SHA:-}" == "${GITHUB_SHA:-}" \
      && "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
    || lane_die "traffic mutation workflow SHA is not exact"
  [[ "${EMILIA_DEPLOY_ENVIRONMENT:-}" \
      == consequence-control-production ]] \
    || lane_die "traffic mutation environment identity mismatch"
  [[ "${EMILIA_DEPLOY_WIF_PROVIDER:-}" =~ ^projects/[1-9][0-9]*/locations/global/workloadIdentityPools/[a-z][a-z0-9-]{3,31}/providers/[a-z][a-z0-9-]{3,31}$ ]] \
    || lane_die "traffic mutation WIF provider is invalid"
  [[ "${DEPLOYMENT_CONFIRM_PROJECT:-}" == "$PROJECT_ID" ]] \
    || lane_die "DEPLOYMENT_CONFIRM_PROJECT must exactly equal PROJECT_ID"
}

verify_direct_traffic_custody() {
  # deploy.sh's read-only identity mode proves the exact WIF/workflow/deployer,
  # the sole direct custom-role binding containing run.services.update, empty
  # service IAM, and the closed effective-IAM allowlist.
  "$LANE_DIR/deploy.sh" \
    --config "$CONFIG" \
    --verify-protected-identity \
    >/dev/null \
    || lane_die "protected traffic deployer custody is not exact"
}

stable_trust_arguments() {
  if [[ -n "${STABLE_RELEASE_KMS_KEY_URI:-}" ]]; then
    [[ -z "$STABLE_PUBLIC_KEY" ]] \
      || lane_die "--stable-public-key is forbidden when KMS trust is configured"
    STABLE_TRUST_MODE="kms"
    return
  fi
  [[ -n "$STABLE_PUBLIC_KEY" ]] \
    || lane_die "file trust requires --stable-public-key"
  [[ "$STABLE_PUBLIC_KEY" == /* ]] \
    || lane_die "--stable-public-key must be an absolute path"
  STABLE_TRUST_MODE="file"
}

verify_stable_revisions() {
  local mode=${1:-offline}
  local command=(
    "$LANE_DIR/verify-stable-release.py" verify
    --config -
    --manifest "$STABLE_MANIFEST"
  )
  if [[ "$STABLE_TRUST_MODE" == file ]]; then
    command+=(--public-key "$STABLE_PUBLIC_KEY")
  fi
  if [[ "$mode" == live ]]; then
    command+=(
      --live
      --actuator-service-snapshot "$2"
      --decision-service-snapshot "$3"
    )
  elif [[ "$mode" != offline ]]; then
    lane_die "invalid stable-release verification mode"
  fi
  command+=(--print-rollout-bindings)
  lane_emit_pinned_config | "${command[@]}"
}

ACTUATOR_CANDIDATE=$(candidate_revision "$ACTUATOR_SERVICE")
DECISION_CANDIDATE=$(candidate_revision "$DECISION_SERVICE")

load_render_stable_revisions() {
  require_var ACTUATOR_STABLE_REVISION
  require_var DECISION_STABLE_REVISION
}

load_pinned_stable_revisions() {
  [[ -n "$STABLE_MANIFEST" ]] \
    || lane_die "traffic apply requires --stable-manifest"
  stable_trust_arguments
  local bindings
  bindings=$(verify_stable_revisions offline) \
    || lane_die "stable rollback target is invalid or has drifted"
  IFS=$'\t' read -r \
    ACTUATOR_STABLE_REVISION ACTUATOR_STABLE_IMAGE \
    DECISION_STABLE_REVISION DECISION_STABLE_IMAGE <<< "$bindings"
  [[ -n "$ACTUATOR_STABLE_REVISION" && -n "$ACTUATOR_STABLE_IMAGE" \
    && -n "$DECISION_STABLE_REVISION" && -n "$DECISION_STABLE_IMAGE" ]] \
    || lane_die "stable rollback bindings are incomplete"
}

if [[ "$ACTION" == render-promote || "$ACTION" == render-rollback ]]; then
  load_render_stable_revisions
else
  require_apply_approval
  load_pinned_stable_revisions
fi

[[ "$ACTUATOR_STABLE_REVISION" == "$ACTUATOR_SERVICE"-* ]] \
  || lane_die "ACTUATOR_STABLE_REVISION must belong to the actuator service"
[[ "$DECISION_STABLE_REVISION" == "$DECISION_SERVICE"-* ]] \
  || lane_die "DECISION_STABLE_REVISION must belong to the decision service"
[[ "$ACTUATOR_STABLE_REVISION" != "$ACTUATOR_CANDIDATE" ]] \
  || lane_die "actuator stable and candidate revisions must differ"
[[ "$DECISION_STABLE_REVISION" != "$DECISION_CANDIDATE" ]] \
  || lane_die "decision stable and candidate revisions must differ"

traffic_command() {
  local service=$1 split=$2
  TRAFFIC_COMMAND=(
    gcloud run services update-traffic "$service"
    "--project=$PROJECT_ID"
    "--region=$REGION"
    "--to-revisions=$split"
    --quiet
  )
}

render_stage() {
  local label=$1 service=$2 split=$3
  traffic_command "$service" "$split"
  printf '# %s\n' "$label"
  shell_join "${TRAFFIC_COMMAND[@]}"
}

render_promote() {
  render_stage "1. decision candidate 1%; observe before continuing" \
    "$DECISION_SERVICE" \
    "$DECISION_CANDIDATE=1,$DECISION_STABLE_REVISION=99"
  render_stage "2. decision candidate 10%; observe before continuing" \
    "$DECISION_SERVICE" \
    "$DECISION_CANDIDATE=10,$DECISION_STABLE_REVISION=90"
  render_stage "3. decision candidate 50%; observe before continuing" \
    "$DECISION_SERVICE" \
    "$DECISION_CANDIDATE=50,$DECISION_STABLE_REVISION=50"
  render_stage "4. decision candidate 100%; observe before continuing" \
    "$DECISION_SERVICE" \
    "$DECISION_CANDIDATE=100"
  render_stage "5. actuator candidate 100% after decision is stable" \
    "$ACTUATOR_SERVICE" \
    "$ACTUATOR_CANDIDATE=100"
}

render_rollback() {
  render_stage "1. rollback actuator first" \
    "$ACTUATOR_SERVICE" \
    "$ACTUATOR_STABLE_REVISION=100"
  render_stage "2. rollback decision after stable actuator restoration" \
    "$DECISION_SERVICE" \
    "$DECISION_STABLE_REVISION=100"
}

case "$ACTION" in
  render-promote)
    render_promote
    exit 0
    ;;
  render-rollback)
    render_rollback
    exit 0
    ;;
esac

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"; lane_cleanup_pinned_config' EXIT
DECISION_SNAPSHOT="$WORK_DIR/decision.json"
ACTUATOR_SNAPSHOT="$WORK_DIR/actuator.json"
UPDATE_RESPONSE="$WORK_DIR/update-response.json"
PRE_SEND_DECISION_SNAPSHOT="$WORK_DIR/pre-send-decision.json"
PRE_SEND_ACTUATOR_SNAPSHOT="$WORK_DIR/pre-send-actuator.json"
POST_DECISION_SNAPSHOT="$WORK_DIR/post-decision.json"
POST_ACTUATOR_SNAPSHOT="$WORK_DIR/post-actuator.json"
AMBIGUOUS_SNAPSHOT="$WORK_DIR/ambiguous-target.json"

describe_service() {
  local service=$1 output=$2
  gcloud run services describe "$service" \
    "--project=$PROJECT_ID" \
    "--region=$REGION" \
    --format=json > "$output" \
    || lane_die "unable to describe Cloud Run service $service"
}

capture_snapshots() {
  describe_service "$DECISION_SERVICE" "$DECISION_SNAPSHOT"
  describe_service "$ACTUATOR_SERVICE" "$ACTUATOR_SNAPSHOT"
  chmod 400 "$DECISION_SNAPSHOT" "$ACTUATOR_SNAPSHOT"
}

verify_current_signed_config() {
  local actuator_snapshot=$1 decision_snapshot=$2 bindings
  bindings=$(verify_stable_revisions \
    live "$actuator_snapshot" "$decision_snapshot") \
    || lane_die "signed stable-release configuration is no longer current"
  local actuator_revision actuator_image decision_revision decision_image
  IFS=$'\t' read -r \
    actuator_revision actuator_image decision_revision decision_image \
    <<< "$bindings"
  [[ "$actuator_revision" == "$ACTUATOR_STABLE_REVISION" \
    && "$actuator_image" == "$ACTUATOR_STABLE_IMAGE" \
    && "$decision_revision" == "$DECISION_STABLE_REVISION" \
    && "$decision_image" == "$DECISION_STABLE_IMAGE" ]] \
    || lane_die "signed stable-release bindings changed during rollout"
}

verify_secret_versions() {
  lane_emit_pinned_config | "$LANE_DIR/verify-secret-versions.py" \
    --project "$PROJECT_ID" \
    --config - \
    --live \
    || lane_die "a configured Secret Manager version is missing or not ENABLED"
}

rollout_context_arguments() {
  local transition=$1 decision_pre=$2 actuator_pre=$3
  local decision_post=$4 actuator_post=$5
  ROLLOUT_CONTEXT_ARGUMENTS=(
    --config -
    --authorization "$AUTHORIZATION"
    --transition "$transition"
    --expect-traffic "$DECISION_SERVICE=$decision_pre"
    --expect-traffic "$ACTUATOR_SERVICE=$actuator_pre"
    --post-traffic "$DECISION_SERVICE=$decision_post"
    --post-traffic "$ACTUATOR_SERVICE=$actuator_post"
    --actuator-stable-revision "$ACTUATOR_STABLE_REVISION"
    --actuator-stable-image "$ACTUATOR_STABLE_IMAGE"
    --decision-stable-revision "$DECISION_STABLE_REVISION"
    --decision-stable-image "$DECISION_STABLE_IMAGE"
    --actuator-snapshot "$ACTUATOR_SNAPSHOT"
    --decision-snapshot "$DECISION_SNAPSHOT"
    --max-error-rate "$MAX_ERROR_RATE"
    --max-p95-latency-ms "$MAX_P95_LATENCY_MS"
    --min-readiness-rate "$MIN_READINESS_RATE"
    --max-indeterminate-rate "$MAX_INDETERMINATE_RATE"
    --min-dwell-seconds "$MIN_DWELL_SECONDS"
    --min-requests "$MIN_REQUESTS"
    --min-readiness-samples "$MIN_READINESS_SAMPLES"
    --max-sample-gap-seconds "$MAX_SAMPLE_GAP_SECONDS"
    --max-age-seconds "$MAX_TELEMETRY_AGE_SECONDS"
    --deployment-config-sha256 "$DEPLOYMENT_CONFIG_SHA256"
    --deployer-principal "$DEPLOYER_PRINCIPAL"
    --workflow-ref "$GITHUB_WORKFLOW_REF"
    --workflow-sha "$GITHUB_SHA"
    --wif-provider "$EMILIA_DEPLOY_WIF_PROVIDER"
    --request-sha256 "$REQUEST_SHA256"
    --request-service "$TARGET_SERVICE"
    --pre-resource-version "$LOCK_RESOURCE_VERSION"
  )
}

verify_rollout_authorization() {
  local transition=$1 decision_pre=$2 actuator_pre=$3
  local decision_post=$4 actuator_post=$5
  [[ -n "$AUTHORIZATION" ]] \
    || lane_die "traffic mutation requires --authorization"
  rollout_context_arguments \
    "$transition" "$decision_pre" "$actuator_pre" \
    "$decision_post" "$actuator_post"
  local verification parsed
  verification=$(
    lane_emit_pinned_config \
      | "$LANE_DIR/verify-rollout-telemetry.py" verify-authorization \
      "${ROLLOUT_CONTEXT_ARGUMENTS[@]}"
  ) \
    || lane_die "rollout authorization is invalid, stale, or not consumed"
  parsed=$(
    python3 -c '
import base64
import json
import sys
value = json.load(sys.stdin)
attempt = value["attempt"]
print(attempt["claim_sha256"])
print(base64.b64encode(json.dumps(
    attempt,
    sort_keys=True,
    separators=(",", ":"),
).encode()).decode())
' <<< "$verification"
  ) || lane_die "rollout authorization attempt claim is malformed"
  ATTEMPT_CLAIM_SHA256=${parsed%%$'\n'*}
  ATTEMPT_CLAIM_BASE64=${parsed#*$'\n'}
  [[ "$ATTEMPT_CLAIM_SHA256" =~ ^[0-9a-f]{64}$ \
      && -n "$ATTEMPT_CLAIM_BASE64" ]] \
    || lane_die "rollout authorization attempt claim is incomplete"
}

verify_prior_stage_telemetry() {
  local decision_traffic=$1 actuator_traffic=$2
  rollout_context_arguments \
    "$ACTION" "$decision_traffic" "$actuator_traffic" \
    "$POST_DECISION" "$POST_ACTUATOR"
  lane_emit_pinned_config | "$LANE_DIR/verify-rollout-telemetry.py" \
    --input "$TELEMETRY" \
    "${ROLLOUT_CONTEXT_ARGUMENTS[@]}" \
    >/dev/null \
    || lane_die "prior rollout stage lacks acceptable telemetry and dwell"
}

set_promotion_transition() {
  case "$ACTION" in
    apply-decision-1)
      TARGET_PLANE=decision
      PRE_DECISION="$DECISION_STABLE_REVISION:100"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_DECISION="$DECISION_CANDIDATE:1,$DECISION_STABLE_REVISION:99"
      POST_ACTUATOR="$PRE_ACTUATOR"
      ;;
    apply-decision-10)
      TARGET_PLANE=decision
      PRE_DECISION="$DECISION_CANDIDATE:1,$DECISION_STABLE_REVISION:99"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_DECISION="$DECISION_CANDIDATE:10,$DECISION_STABLE_REVISION:90"
      POST_ACTUATOR="$PRE_ACTUATOR"
      ;;
    apply-decision-50)
      TARGET_PLANE=decision
      PRE_DECISION="$DECISION_CANDIDATE:10,$DECISION_STABLE_REVISION:90"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_DECISION="$DECISION_CANDIDATE:50,$DECISION_STABLE_REVISION:50"
      POST_ACTUATOR="$PRE_ACTUATOR"
      ;;
    apply-decision-100)
      TARGET_PLANE=decision
      PRE_DECISION="$DECISION_CANDIDATE:50,$DECISION_STABLE_REVISION:50"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_DECISION="$DECISION_CANDIDATE:100"
      POST_ACTUATOR="$PRE_ACTUATOR"
      ;;
    apply-actuator-100)
      TARGET_PLANE=actuator
      PRE_DECISION="$DECISION_CANDIDATE:100"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_DECISION="$PRE_DECISION"
      POST_ACTUATOR="$ACTUATOR_CANDIDATE:100"
      ;;
    *)
      lane_die "unsupported promotion action"
      ;;
  esac
  if [[ "$TARGET_PLANE" == decision ]]; then
    POST_TRAFFIC=$POST_DECISION
  else
    POST_TRAFFIC=$POST_ACTUATOR
  fi
}

verify_service_state() {
  local input=$1 service=$2 traffic=$3 stable=$4 candidate=$5
  "$LANE_DIR/verify-rollout-telemetry.py" verify-service \
    --input "$input" \
    --service "$service" \
    --expect-traffic "$traffic" \
    --allowed-revision "$stable" \
    --allowed-revision "$candidate"
}

verify_exact_service_state() {
  local input=$1 service=$2 traffic=$3 stable=$4 candidate=$5
  local generation=$6 resource_version=$7
  "$LANE_DIR/verify-rollout-telemetry.py" verify-service \
    --input "$input" \
    --service "$service" \
    --expect-traffic "$traffic" \
    --allowed-revision "$stable" \
    --allowed-revision "$candidate" \
    --generation-equals "$generation" \
    --resource-version-equals "$resource_version"
}

prepare_locked_update() {
  local target_plane=$1 pre_decision=$2 pre_actuator=$3 post_traffic=$4
  local lock other_lock
  if [[ "$target_plane" == decision ]]; then
    other_lock=$(verify_service_state \
      "$ACTUATOR_SNAPSHOT" "$ACTUATOR_SERVICE" "$pre_actuator" \
      "$ACTUATOR_STABLE_REVISION" "$ACTUATOR_CANDIDATE") \
      || lane_die "actuator pre-state forbids the requested decision transition"
    lock=$(
      "$LANE_DIR/verify-rollout-telemetry.py" prepare-update \
        --input "$DECISION_SNAPSHOT" \
        --service "$DECISION_SERVICE" \
        --expect-traffic "$pre_decision" \
        --target-traffic "$post_traffic" \
        --allowed-revision "$DECISION_STABLE_REVISION" \
        --allowed-revision "$DECISION_CANDIDATE" \
        --emit-base64
    ) || lane_die "decision pre-state forbids skipping rollout stages"
    TARGET_SERVICE=$DECISION_SERVICE
    OTHER_SERVICE=$ACTUATOR_SERVICE
    OTHER_EXPECTED=$pre_actuator
    TARGET_STABLE=$DECISION_STABLE_REVISION
    TARGET_CANDIDATE=$DECISION_CANDIDATE
    OTHER_STABLE=$ACTUATOR_STABLE_REVISION
    OTHER_CANDIDATE=$ACTUATOR_CANDIDATE
    TARGET_PRE=$pre_decision
    TARGET_POST_SNAPSHOT=$POST_DECISION_SNAPSHOT
    OTHER_POST_SNAPSHOT=$POST_ACTUATOR_SNAPSHOT
  else
    other_lock=$(verify_service_state \
      "$DECISION_SNAPSHOT" "$DECISION_SERVICE" "$pre_decision" \
      "$DECISION_STABLE_REVISION" "$DECISION_CANDIDATE") \
      || lane_die "decision must be at candidate 100 before actuator promotion"
    lock=$(
      "$LANE_DIR/verify-rollout-telemetry.py" prepare-update \
        --input "$ACTUATOR_SNAPSHOT" \
        --service "$ACTUATOR_SERVICE" \
        --expect-traffic "$pre_actuator" \
        --target-traffic "$post_traffic" \
        --allowed-revision "$ACTUATOR_STABLE_REVISION" \
        --allowed-revision "$ACTUATOR_CANDIDATE" \
        --emit-base64
    ) || lane_die "actuator pre-state forbids the requested transition"
    TARGET_SERVICE=$ACTUATOR_SERVICE
    OTHER_SERVICE=$DECISION_SERVICE
    OTHER_EXPECTED=$pre_decision
    TARGET_STABLE=$ACTUATOR_STABLE_REVISION
    TARGET_CANDIDATE=$ACTUATOR_CANDIDATE
    OTHER_STABLE=$DECISION_STABLE_REVISION
    OTHER_CANDIDATE=$DECISION_CANDIDATE
    TARGET_PRE=$pre_actuator
    TARGET_POST_SNAPSHOT=$POST_ACTUATOR_SNAPSHOT
    OTHER_POST_SNAPSHOT=$POST_DECISION_SNAPSHOT
  fi
  IFS=$'\t' read -r \
    LOCK_GENERATION LOCK_RESOURCE_VERSION REQUEST_SHA256 UPDATE_BODY_BASE64 \
    <<< "$lock"
  IFS=$'\t' read -r OTHER_GENERATION OTHER_RESOURCE_VERSION <<< "$other_lock"
  [[ "$LOCK_GENERATION" =~ ^[1-9][0-9]*$ \
    && -n "$LOCK_RESOURCE_VERSION" \
    && "$REQUEST_SHA256" =~ ^[0-9a-f]{64}$ \
    && -n "$UPDATE_BODY_BASE64" \
    && "$OTHER_GENERATION" =~ ^[1-9][0-9]*$ \
    && -n "$OTHER_RESOURCE_VERSION" ]] \
    || lane_die "Cloud Run lock metadata is malformed"
  TARGET_POST=$post_traffic
}

prepare_attempt_store_adapter() {
  [[ -n "${EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER:-}" \
      && "$EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER" == /* ]] \
    || lane_die "a protected absolute rollout attempt-store adapter is required"
  [[ "${EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
    || lane_die "rollout attempt-store adapter SHA-256 is required"
  ATTEMPT_STORE_ADAPTER="$WORK_DIR/attempt-store-adapter"
  python3 - "$EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER" \
    "$ATTEMPT_STORE_ADAPTER" \
    "$EMILIA_ROLLOUT_ATTEMPT_STORE_ADAPTER_SHA256" <<'PY' || \
    lane_die "rollout attempt-store adapter trust check failed"
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

attempt_store_call() {
  local operation=$1 payload_base64=$2 allowed_status=$3
  local response input_stream
  response=$(
    printf '%s' "$payload_base64" \
      | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read(), validate=True))' \
      | "$ATTEMPT_STORE_ADAPTER" "$operation"
  ) || lane_die "durable attempt-store $operation failed; no mutation permitted"
  input_stream=<(printf '%s' "$response")
  "$LANE_DIR/verify-rollout-telemetry.py" verify-attempt-response \
    --input "$input_stream" \
    --operation "$operation" \
    --claim-sha256 "$ATTEMPT_CLAIM_SHA256" \
    --allow-status "$allowed_status" \
    >/dev/null \
    || lane_die "durable attempt-store $operation response is invalid"
}

attempt_outcome_payload() {
  local operation=$1 outcome=$2 resource_version=$3
  printf '%s' "$ATTEMPT_CLAIM_BASE64" \
    | python3 -c '
import base64
import json
import sys
operation, outcome, resource_version = sys.argv[1:]
claim = json.loads(base64.b64decode(sys.stdin.buffer.read(), validate=True))
value = {
    "schema": "emilia-deployment-attempt-store-operation.v1",
    "operation": operation,
    "claim": claim,
    "outcome": outcome,
    "final_resource_version": resource_version,
}
print(base64.b64encode(json.dumps(
    value,
    sort_keys=True,
    separators=(",", ":"),
).encode()).decode())
' "$operation" "$outcome" "$resource_version"
}

claim_deployment_attempt() {
  prepare_attempt_store_adapter
  attempt_store_call claim "$ATTEMPT_CLAIM_BASE64" claimed
}

record_attempt_outcome() {
  local operation=$1 outcome=$2 resource_version=$3 allowed_status payload
  if [[ "$operation" == complete ]]; then
    allowed_status=completed
  else
    allowed_status=$outcome
  fi
  payload=$(attempt_outcome_payload \
    "$operation" "$outcome" "$resource_version") \
    || lane_die "unable to encode durable attempt outcome"
  attempt_store_call "$operation" "$payload" "$allowed_status"
}

reconcile_ambiguous_update() {
  local reason=$1 state observed_resource_version
  describe_service "$TARGET_SERVICE" "$AMBIGUOUS_SNAPSHOT"
  set +e
  state=$(
    "$LANE_DIR/verify-rollout-telemetry.py" verify-service \
      --input "$AMBIGUOUS_SNAPSHOT" \
      --service "$TARGET_SERVICE" \
      --expect-traffic "$TARGET_POST" \
      --pending-from-traffic "$TARGET_PRE" \
      --allowed-revision "$TARGET_STABLE" \
      --allowed-revision "$TARGET_CANDIDATE" \
      --generation-after "$LOCK_GENERATION" \
      --resource-version-not "$LOCK_RESOURCE_VERSION"
  )
  local post_status=$?
  set -e
  if ((post_status == 0)); then
    IFS=$'\t' read -r ACK_GENERATION ACK_RESOURCE_VERSION <<< "$state"
    describe_service "$OTHER_SERVICE" "$OTHER_POST_SNAPSHOT"
    verify_exact_service_state \
      "$OTHER_POST_SNAPSHOT" "$OTHER_SERVICE" "$OTHER_EXPECTED" \
      "$OTHER_STABLE" "$OTHER_CANDIDATE" \
      "$OTHER_GENERATION" "$OTHER_RESOURCE_VERSION" >/dev/null \
      || lane_die "ambiguous update coincided with non-target state drift"
    record_attempt_outcome reconcile applied "$ACK_RESOURCE_VERSION"
    ATTEMPT_RECONCILED=true
    printf 'reconciled ambiguous Cloud Run response as applied: %s\n' \
      "$reason" >&2
    return 0
  fi
  if verify_exact_service_state \
    "$AMBIGUOUS_SNAPSHOT" "$TARGET_SERVICE" "$TARGET_PRE" \
    "$TARGET_STABLE" "$TARGET_CANDIDATE" \
    "$LOCK_GENERATION" "$LOCK_RESOURCE_VERSION" >/dev/null 2>&1; then
    record_attempt_outcome reconcile not-applied "$LOCK_RESOURCE_VERSION"
    lane_die "Cloud Run update was not observed; authorization is durably burned and must not be replayed"
  fi
  observed_resource_version=$(
    python3 - "$AMBIGUOUS_SNAPSHOT" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
resource_version = value.get("metadata", {}).get("resourceVersion")
if not isinstance(resource_version, str) or not resource_version or any(
    character.isspace() for character in resource_version
):
    raise SystemExit(1)
print(resource_version)
PY
  ) || lane_die "ambiguous Cloud Run state is unreadable; attempt remains durably burned"
  record_attempt_outcome reconcile indeterminate "$observed_resource_version"
  lane_die "Cloud Run update is indeterminate after reconciliation; do not replay"
}

send_locked_update() {
  local token actual_request_sha256
  actual_request_sha256=$(
    printf '%s' "$UPDATE_BODY_BASE64" \
      | python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(sys.stdin.buffer.read(), validate=True)).hexdigest())'
  ) || lane_die "prepared Cloud Run request bytes are invalid"
  [[ "$actual_request_sha256" == "$REQUEST_SHA256" ]] \
    || lane_die "prepared Cloud Run request bytes changed after authorization"
  token=$(gcloud auth print-access-token --quiet) \
    || lane_die "unable to obtain a Cloud Run API access token"
  [[ "$token" =~ ^[A-Za-z0-9._~-]+$ ]] \
    || lane_die "Cloud Run API access token is malformed"
  local curl_config="$WORK_DIR/curl.conf"
  {
    printf 'header = "Authorization: Bearer %s"\n' "$token"
    printf 'header = "Content-Type: application/json"\n'
  } > "$curl_config"
  chmod 600 "$curl_config"
  local url
  url="https://run.googleapis.com/apis/serving.knative.dev/v1/projects"
  url+="/$PROJECT_ID/locations/$REGION/services/$TARGET_SERVICE"
  set +e
  printf '%s' "$UPDATE_BODY_BASE64" \
    | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read(), validate=True))' \
    | curl \
    --silent \
    --show-error \
    --fail-with-body \
    --request PUT \
    --config "$curl_config" \
    --data-binary @- \
    --output "$UPDATE_RESPONSE" \
    "$url"
  local update_status
  update_status=$?
  set -e
  if ((update_status != 0)); then
    reconcile_ambiguous_update "HTTP client status $update_status"
    return
  fi
  local ack ack_status
  set +e
  ack=$(
    "$LANE_DIR/verify-rollout-telemetry.py" verify-update-ack \
      --input "$UPDATE_RESPONSE" \
      --service "$TARGET_SERVICE" \
      --expect-traffic "$TARGET_POST" \
      --pending-from-traffic "$TARGET_PRE" \
      --allowed-revision "$TARGET_STABLE" \
      --allowed-revision "$TARGET_CANDIDATE" \
      --generation-after "$LOCK_GENERATION" \
      --resource-version-not "$LOCK_RESOURCE_VERSION"
  )
  ack_status=$?
  set -e
  if ((ack_status != 0)); then
    reconcile_ambiguous_update "unverifiable update acknowledgement"
    return
  fi
  IFS=$'\t' read -r ACK_GENERATION ACK_RESOURCE_VERSION <<< "$ack"
  [[ "$ACK_GENERATION" =~ ^[1-9][0-9]*$ \
    && -n "$ACK_RESOURCE_VERSION" ]] \
    || lane_die "Cloud Run update acknowledgement lock is malformed"
}

poll_exact_post_state() {
  local attempt status snapshot=$TARGET_POST_SNAPSHOT
  for ((attempt = 1; attempt <= ROLLOUT_POLL_ATTEMPTS; attempt++)); do
    describe_service "$TARGET_SERVICE" "$snapshot"
    set +e
    "$LANE_DIR/verify-rollout-telemetry.py" verify-service \
      --input "$snapshot" \
      --service "$TARGET_SERVICE" \
      --expect-traffic "$TARGET_POST" \
      --pending-from-traffic "$TARGET_PRE" \
      --allowed-revision "$TARGET_STABLE" \
      --allowed-revision "$TARGET_CANDIDATE" \
      --generation-equals "$ACK_GENERATION" \
      --resource-version-equals "$ACK_RESOURCE_VERSION" \
      >/dev/null 2>&1
    status=$?
    set -e
    if ((status == 0)); then
      describe_service "$OTHER_SERVICE" "$OTHER_POST_SNAPSHOT"
      verify_exact_service_state \
        "$OTHER_POST_SNAPSHOT" "$OTHER_SERVICE" "$OTHER_EXPECTED" \
        "$OTHER_STABLE" "$OTHER_CANDIDATE" \
        "$OTHER_GENERATION" "$OTHER_RESOURCE_VERSION" >/dev/null \
        || lane_die "non-target service snapshot lock changed during transition"
      return 0
    fi
    ((status == 2)) \
      || lane_die "Cloud Run read-back does not match the exact requested post-state"
    if ((attempt < ROLLOUT_POLL_ATTEMPTS)); then
      sleep "$ROLLOUT_POLL_INTERVAL_SEC"
    fi
  done
  lane_die "Cloud Run did not reconcile the exact post-state in time"
}

verify_pre_send_service_locks() {
  if [[ "$TARGET_SERVICE" == "$DECISION_SERVICE" ]]; then
    verify_exact_service_state \
      "$PRE_SEND_DECISION_SNAPSHOT" "$TARGET_SERVICE" "$TARGET_PRE" \
      "$TARGET_STABLE" "$TARGET_CANDIDATE" \
      "$LOCK_GENERATION" "$LOCK_RESOURCE_VERSION" >/dev/null \
      || lane_die "target service changed after its signed preflight snapshot"
    verify_exact_service_state \
      "$PRE_SEND_ACTUATOR_SNAPSHOT" "$OTHER_SERVICE" "$OTHER_EXPECTED" \
      "$OTHER_STABLE" "$OTHER_CANDIDATE" \
      "$OTHER_GENERATION" "$OTHER_RESOURCE_VERSION" >/dev/null \
      || lane_die "non-target service changed after preflight"
  else
    verify_exact_service_state \
      "$PRE_SEND_ACTUATOR_SNAPSHOT" "$TARGET_SERVICE" "$TARGET_PRE" \
      "$TARGET_STABLE" "$TARGET_CANDIDATE" \
      "$LOCK_GENERATION" "$LOCK_RESOURCE_VERSION" >/dev/null \
      || lane_die "target service changed after its signed preflight snapshot"
    verify_exact_service_state \
      "$PRE_SEND_DECISION_SNAPSHOT" "$OTHER_SERVICE" "$OTHER_EXPECTED" \
      "$OTHER_STABLE" "$OTHER_CANDIDATE" \
      "$OTHER_GENERATION" "$OTHER_RESOURCE_VERSION" >/dev/null \
      || lane_die "non-target service changed after preflight"
  fi
}

revalidate_before_send() {
  verify_lane_config_pin
  verify_secret_versions
  verify_effective_iam_live
  describe_service "$DECISION_SERVICE" "$PRE_SEND_DECISION_SNAPSHOT"
  describe_service "$ACTUATOR_SERVICE" "$PRE_SEND_ACTUATOR_SNAPSHOT"
  verify_current_signed_config \
    "$PRE_SEND_ACTUATOR_SNAPSHOT" "$PRE_SEND_DECISION_SNAPSHOT"
  verify_pre_send_service_locks
  verify_direct_traffic_custody
  verify_lane_config_pin
}

verify_post_target_state() {
  local snapshot
  if [[ "$TARGET_SERVICE" == "$DECISION_SERVICE" ]]; then
    snapshot=$POST_DECISION_SNAPSHOT
  else
    snapshot=$POST_ACTUATOR_SNAPSHOT
  fi
  "$LANE_DIR/verify-rollout-telemetry.py" verify-service \
    --input "$snapshot" \
    --service "$TARGET_SERVICE" \
    --expect-traffic "$TARGET_POST" \
    --allowed-revision "$TARGET_STABLE" \
    --allowed-revision "$TARGET_CANDIDATE" \
    --generation-equals "$ACK_GENERATION" \
    --resource-version-equals "$ACK_RESOURCE_VERSION" >/dev/null \
    || lane_die "target service changed after the acknowledged mutation"
}

verify_post_mutation_controls() {
  verify_lane_config_pin
  verify_current_signed_config \
    "$POST_ACTUATOR_SNAPSHOT" "$POST_DECISION_SNAPSHOT"
  verify_secret_versions
  verify_effective_iam_live
  describe_service "$DECISION_SERVICE" "$POST_DECISION_SNAPSHOT"
  describe_service "$ACTUATOR_SERVICE" "$POST_ACTUATOR_SNAPSHOT"
  verify_post_target_state
  verify_exact_service_state \
    "$OTHER_POST_SNAPSHOT" "$OTHER_SERVICE" "$OTHER_EXPECTED" \
    "$OTHER_STABLE" "$OTHER_CANDIDATE" \
    "$OTHER_GENERATION" "$OTHER_RESOURCE_VERSION" >/dev/null \
    || lane_die "non-target service changed after mutation read-back"
  verify_lane_config_pin
}

apply_prepared_update() {
  require_protected_traffic_identity
  verify_direct_traffic_custody
  revalidate_before_send
  claim_deployment_attempt
  ATTEMPT_RECONCILED=false
  send_locked_update
  poll_exact_post_state
  verify_post_mutation_controls
  if [[ "$ATTEMPT_RECONCILED" != true ]]; then
    record_attempt_outcome complete applied "$ACK_RESOURCE_VERSION"
  fi
}

promotion_preflight() {
  [[ -n "$EVIDENCE" ]] || lane_die "promotion requires --evidence"
  [[ -n "$TELEMETRY" ]] || lane_die "promotion requires --telemetry"
  [[ -n "$AUTHORIZATION" ]] \
    || lane_die "promotion requires --authorization"
  require_var ROLLOUT_TELEMETRY_KEY_ID
  require_var ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE
  require_var ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256
  require_var ROLLOUT_AUTHORIZATION_KEY_ID
  require_var ROLLOUT_AUTHORIZATION_PUBLIC_KEY_FILE
  require_var ROLLOUT_AUTHORIZATION_PUBLIC_KEY_SHA256
  verify_current_signed_config "$ACTUATOR_SNAPSHOT" "$DECISION_SNAPSHOT"
  verify_secret_versions
  verify_effective_iam_live
  "$LANE_DIR/verify-canary.py" \
    --config <(lane_emit_pinned_config) \
    --evidence "$EVIDENCE" \
    --live \
    --actuator-service-snapshot "$ACTUATOR_SNAPSHOT" \
    --decision-service-snapshot "$DECISION_SNAPSHOT" \
    >/dev/null \
    || lane_die "current signed canary/config verification failed"
}

matches_service_state() {
  verify_service_state "$1" "$2" "$3" "$4" "$5" >/dev/null 2>&1
}

decision_rollback_stage() {
  local stage traffic
  while IFS=$'\t' read -r stage traffic; do
    if matches_service_state \
      "$DECISION_SNAPSHOT" "$DECISION_SERVICE" "$traffic" \
      "$DECISION_STABLE_REVISION" "$DECISION_CANDIDATE"; then
      printf '%s\t%s\n' "$stage" "$traffic"
      return 0
    fi
  done <<EOF
stable	$DECISION_STABLE_REVISION:100
1	$DECISION_CANDIDATE:1,$DECISION_STABLE_REVISION:99
10	$DECISION_CANDIDATE:10,$DECISION_STABLE_REVISION:90
50	$DECISION_CANDIDATE:50,$DECISION_STABLE_REVISION:50
100	$DECISION_CANDIDATE:100
EOF
  return 1
}

apply_rollback() {
  capture_snapshots
  verify_current_signed_config "$ACTUATOR_SNAPSHOT" "$DECISION_SNAPSHOT"
  verify_secret_versions
  local decision_state decision_stage decision_traffic actuator_stage
  decision_state=$(decision_rollback_stage) \
    || lane_die "decision service is not in a rollback-safe rollout state"
  IFS=$'\t' read -r decision_stage decision_traffic <<< "$decision_state"
  if matches_service_state \
    "$ACTUATOR_SNAPSHOT" "$ACTUATOR_SERVICE" \
    "$ACTUATOR_CANDIDATE:100" \
    "$ACTUATOR_STABLE_REVISION" "$ACTUATOR_CANDIDATE"; then
    actuator_stage=candidate
  elif matches_service_state \
    "$ACTUATOR_SNAPSHOT" "$ACTUATOR_SERVICE" \
    "$ACTUATOR_STABLE_REVISION:100" \
    "$ACTUATOR_STABLE_REVISION" "$ACTUATOR_CANDIDATE"; then
    actuator_stage=stable
  else
    lane_die "actuator service is not in a rollback-safe rollout state"
  fi

  if [[ "$actuator_stage" == stable && "$decision_stage" == stable ]]; then
    printf 'rollback target is already serving 100%% on both services\n'
    return 0
  fi

  verify_effective_iam_live
  require_var ROLLOUT_TELEMETRY_KEY_ID
  require_var ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE
  require_var ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256
  require_var ROLLOUT_AUTHORIZATION_KEY_ID
  require_var ROLLOUT_AUTHORIZATION_PUBLIC_KEY_FILE
  require_var ROLLOUT_AUTHORIZATION_PUBLIC_KEY_SHA256

  if [[ "$actuator_stage" == candidate ]]; then
    [[ "$decision_stage" == 100 || "$decision_stage" == stable ]] \
      || lane_die "refusing actuator-before-decision rollout state"
    prepare_locked_update \
      actuator "$decision_traffic" "$ACTUATOR_CANDIDATE:100" \
      "$ACTUATOR_STABLE_REVISION:100"
    verify_rollout_authorization \
      apply-rollback-actuator \
      "$decision_traffic" "$ACTUATOR_CANDIDATE:100" \
      "$decision_traffic" "$ACTUATOR_STABLE_REVISION:100"
    apply_prepared_update
    if [[ "$decision_stage" != stable ]]; then
      printf '%s\n' \
        "actuator rollback complete; a new consumed authorization is required for decision rollback"
    fi
    return 0
  fi

  prepare_locked_update \
    decision "$decision_traffic" "$ACTUATOR_STABLE_REVISION:100" \
    "$DECISION_STABLE_REVISION:100"
  verify_rollout_authorization \
    apply-rollback-decision \
    "$decision_traffic" "$ACTUATOR_STABLE_REVISION:100" \
    "$DECISION_STABLE_REVISION:100" "$ACTUATOR_STABLE_REVISION:100"
  apply_prepared_update
}

if [[ "$ACTION" == apply-rollback ]]; then
  apply_rollback
else
  set_promotion_transition
  capture_snapshots
  promotion_preflight
  prepare_locked_update \
    "$TARGET_PLANE" "$PRE_DECISION" "$PRE_ACTUATOR" "$POST_TRAFFIC"
  verify_rollout_authorization \
    "$ACTION" "$PRE_DECISION" "$PRE_ACTUATOR" \
    "$POST_DECISION" "$POST_ACTUATOR"
  verify_prior_stage_telemetry "$PRE_DECISION" "$PRE_ACTUATOR"
  apply_prepared_update
fi
