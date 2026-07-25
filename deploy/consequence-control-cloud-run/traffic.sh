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
STABLE_MANIFEST=
STABLE_PUBLIC_KEY=
MAX_ERROR_RATE=0.01
MAX_P95_LATENCY_MS=500
MIN_READINESS_RATE=0.99
MAX_INDETERMINATE_RATE=0.005
MIN_DWELL_SECONDS=600
MIN_REQUESTS=100
MIN_READINESS_SAMPLES=3
MAX_SAMPLE_GAP_SECONDS=300
MAX_TELEMETRY_AGE_SECONDS=900
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
    --max-error-rate|--max-p95-latency-ms|--min-readiness-rate|--max-indeterminate-rate|--min-dwell-seconds|--min-requests|--min-readiness-samples|--max-sample-gap-seconds|--max-telemetry-age-seconds)
      (($# >= 2)) || lane_die "$1 requires a value"
      case "$1" in
        --max-error-rate) MAX_ERROR_RATE=$2 ;;
        --max-p95-latency-ms) MAX_P95_LATENCY_MS=$2 ;;
        --min-readiness-rate) MIN_READINESS_RATE=$2 ;;
        --max-indeterminate-rate) MAX_INDETERMINATE_RATE=$2 ;;
        --min-dwell-seconds) MIN_DWELL_SECONDS=$2 ;;
        --min-requests) MIN_REQUESTS=$2 ;;
        --min-readiness-samples) MIN_READINESS_SAMPLES=$2 ;;
        --max-sample-gap-seconds) MAX_SAMPLE_GAP_SECONDS=$2 ;;
        --max-telemetry-age-seconds) MAX_TELEMETRY_AGE_SECONDS=$2 ;;
      esac
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
load_lane_config "$CONFIG"
validate_lane_config

ACTUATOR_CANDIDATE=$(candidate_revision "$ACTUATOR_SERVICE")
DECISION_CANDIDATE=$(candidate_revision "$DECISION_SERVICE")

load_render_stable_revisions() {
  require_var ACTUATOR_STABLE_REVISION
  require_var DECISION_STABLE_REVISION
}

load_pinned_stable_revisions() {
  [[ -n "$STABLE_MANIFEST" ]] \
    || lane_die "traffic apply requires --stable-manifest"
  [[ -n "$STABLE_PUBLIC_KEY" ]] \
    || lane_die "traffic apply requires --stable-public-key"
  local revisions
  revisions=$(
    "$LANE_DIR/verify-stable-release.py" verify \
      --config "$CONFIG" \
      --manifest "$STABLE_MANIFEST" \
      --public-key "$STABLE_PUBLIC_KEY" \
      --live \
      --print-revisions
  ) || lane_die "stable rollback target is invalid or has drifted"
  IFS=$'\t' read -r ACTUATOR_STABLE_REVISION DECISION_STABLE_REVISION \
    <<< "$revisions"
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

ROLLOUT_POLL_ATTEMPTS=${ROLLOUT_POLL_ATTEMPTS:-30}
ROLLOUT_POLL_INTERVAL_SEC=${ROLLOUT_POLL_INTERVAL_SEC:-2}
[[ "$ROLLOUT_POLL_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] \
  || lane_die "ROLLOUT_POLL_ATTEMPTS must be a positive integer"
[[ "$ROLLOUT_POLL_INTERVAL_SEC" =~ ^[0-9]+$ ]] \
  || lane_die "ROLLOUT_POLL_INTERVAL_SEC must be a non-negative integer"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
DECISION_SNAPSHOT="$WORK_DIR/decision.json"
ACTUATOR_SNAPSHOT="$WORK_DIR/actuator.json"
UPDATE_BODY="$WORK_DIR/update.json"
UPDATE_RESPONSE="$WORK_DIR/update-response.json"

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
}

verify_current_signed_config() {
  local revisions
  revisions=$(
    "$LANE_DIR/verify-stable-release.py" verify \
      --config "$CONFIG" \
      --manifest "$STABLE_MANIFEST" \
      --public-key "$STABLE_PUBLIC_KEY" \
      --live \
      --print-revisions
  ) || lane_die "signed stable-release configuration is no longer current"
  local actuator decision
  IFS=$'\t' read -r actuator decision <<< "$revisions"
  [[ "$actuator" == "$ACTUATOR_STABLE_REVISION" \
    && "$decision" == "$DECISION_STABLE_REVISION" ]] \
    || lane_die "signed stable-release revisions changed during rollout"
}

verify_secret_versions() {
  "$LANE_DIR/verify-secret-versions.py" \
    --project "$PROJECT_ID" \
    --config "$CONFIG" \
    --live \
    || lane_die "a configured Secret Manager version is missing or not ENABLED"
}

verify_prior_stage_telemetry() {
  local decision_traffic=$1 actuator_traffic=$2
  "$LANE_DIR/verify-rollout-telemetry.py" \
    --input "$TELEMETRY" \
    --expect-traffic "$DECISION_SERVICE=$decision_traffic" \
    --expect-traffic "$ACTUATOR_SERVICE=$actuator_traffic" \
    --max-error-rate "$MAX_ERROR_RATE" \
    --max-p95-latency-ms "$MAX_P95_LATENCY_MS" \
    --min-readiness-rate "$MIN_READINESS_RATE" \
    --max-indeterminate-rate "$MAX_INDETERMINATE_RATE" \
    --min-dwell-seconds "$MIN_DWELL_SECONDS" \
    --min-requests "$MIN_REQUESTS" \
    --min-readiness-samples "$MIN_READINESS_SAMPLES" \
    --max-sample-gap-seconds "$MAX_SAMPLE_GAP_SECONDS" \
    --max-age-seconds "$MAX_TELEMETRY_AGE_SECONDS" \
    >/dev/null \
    || lane_die "prior rollout stage lacks acceptable telemetry and dwell"
}

set_promotion_transition() {
  case "$ACTION" in
    apply-decision-1)
      TARGET_PLANE=decision
      PRE_DECISION="$DECISION_STABLE_REVISION:100"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_TRAFFIC="$DECISION_CANDIDATE:1,$DECISION_STABLE_REVISION:99"
      ;;
    apply-decision-10)
      TARGET_PLANE=decision
      PRE_DECISION="$DECISION_CANDIDATE:1,$DECISION_STABLE_REVISION:99"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_TRAFFIC="$DECISION_CANDIDATE:10,$DECISION_STABLE_REVISION:90"
      ;;
    apply-decision-50)
      TARGET_PLANE=decision
      PRE_DECISION="$DECISION_CANDIDATE:10,$DECISION_STABLE_REVISION:90"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_TRAFFIC="$DECISION_CANDIDATE:50,$DECISION_STABLE_REVISION:50"
      ;;
    apply-decision-100)
      TARGET_PLANE=decision
      PRE_DECISION="$DECISION_CANDIDATE:50,$DECISION_STABLE_REVISION:50"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_TRAFFIC="$DECISION_CANDIDATE:100"
      ;;
    apply-actuator-100)
      TARGET_PLANE=actuator
      PRE_DECISION="$DECISION_CANDIDATE:100"
      PRE_ACTUATOR="$ACTUATOR_STABLE_REVISION:100"
      POST_TRAFFIC="$ACTUATOR_CANDIDATE:100"
      ;;
    *)
      lane_die "unsupported promotion action"
      ;;
  esac
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

prepare_locked_update() {
  local target_plane=$1 pre_decision=$2 pre_actuator=$3 post_traffic=$4
  local lock
  if [[ "$target_plane" == decision ]]; then
    verify_service_state \
      "$ACTUATOR_SNAPSHOT" "$ACTUATOR_SERVICE" "$pre_actuator" \
      "$ACTUATOR_STABLE_REVISION" "$ACTUATOR_CANDIDATE" >/dev/null \
      || lane_die "actuator pre-state forbids the requested decision transition"
    lock=$(
      "$LANE_DIR/verify-rollout-telemetry.py" prepare-update \
        --input "$DECISION_SNAPSHOT" \
        --service "$DECISION_SERVICE" \
        --expect-traffic "$pre_decision" \
        --target-traffic "$post_traffic" \
        --allowed-revision "$DECISION_STABLE_REVISION" \
        --allowed-revision "$DECISION_CANDIDATE" \
        --output "$UPDATE_BODY"
    ) || lane_die "decision pre-state forbids skipping rollout stages"
    TARGET_SERVICE=$DECISION_SERVICE
    OTHER_SERVICE=$ACTUATOR_SERVICE
    OTHER_SNAPSHOT=$ACTUATOR_SNAPSHOT
    OTHER_EXPECTED=$pre_actuator
    TARGET_STABLE=$DECISION_STABLE_REVISION
    TARGET_CANDIDATE=$DECISION_CANDIDATE
    OTHER_STABLE=$ACTUATOR_STABLE_REVISION
    OTHER_CANDIDATE=$ACTUATOR_CANDIDATE
    TARGET_PRE=$pre_decision
  else
    verify_service_state \
      "$DECISION_SNAPSHOT" "$DECISION_SERVICE" "$pre_decision" \
      "$DECISION_STABLE_REVISION" "$DECISION_CANDIDATE" >/dev/null \
      || lane_die "decision must be at candidate 100 before actuator promotion"
    lock=$(
      "$LANE_DIR/verify-rollout-telemetry.py" prepare-update \
        --input "$ACTUATOR_SNAPSHOT" \
        --service "$ACTUATOR_SERVICE" \
        --expect-traffic "$pre_actuator" \
        --target-traffic "$post_traffic" \
        --allowed-revision "$ACTUATOR_STABLE_REVISION" \
        --allowed-revision "$ACTUATOR_CANDIDATE" \
        --output "$UPDATE_BODY"
    ) || lane_die "actuator pre-state forbids the requested transition"
    TARGET_SERVICE=$ACTUATOR_SERVICE
    OTHER_SERVICE=$DECISION_SERVICE
    OTHER_SNAPSHOT=$DECISION_SNAPSHOT
    OTHER_EXPECTED=$pre_decision
    TARGET_STABLE=$ACTUATOR_STABLE_REVISION
    TARGET_CANDIDATE=$ACTUATOR_CANDIDATE
    OTHER_STABLE=$DECISION_STABLE_REVISION
    OTHER_CANDIDATE=$DECISION_CANDIDATE
    TARGET_PRE=$pre_actuator
  fi
  IFS=$'\t' read -r LOCK_GENERATION LOCK_RESOURCE_VERSION <<< "$lock"
  [[ "$LOCK_GENERATION" =~ ^[1-9][0-9]*$ \
    && -n "$LOCK_RESOURCE_VERSION" ]] \
    || lane_die "Cloud Run lock metadata is malformed"
  TARGET_POST=$post_traffic
}

send_locked_update() {
  local token
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
  curl \
    --silent \
    --show-error \
    --fail-with-body \
    --request PUT \
    --config "$curl_config" \
    --data-binary "@$UPDATE_BODY" \
    --output "$UPDATE_RESPONSE" \
    "$url"
}

poll_exact_post_state() {
  local attempt status snapshot="$WORK_DIR/post.json"
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
      --generation-after "$LOCK_GENERATION" \
      --resource-version-not "$LOCK_RESOURCE_VERSION" \
      >/dev/null 2>&1
    status=$?
    set -e
    if ((status == 0)); then
      describe_service "$OTHER_SERVICE" "$OTHER_SNAPSHOT"
      verify_service_state \
        "$OTHER_SNAPSHOT" "$OTHER_SERVICE" "$OTHER_EXPECTED" \
        "$OTHER_STABLE" "$OTHER_CANDIDATE" >/dev/null \
        || lane_die "non-target service changed during the rollout transition"
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

apply_prepared_update() {
  if ! send_locked_update; then
    # A lost response can follow an accepted mutation. Never replay it blindly;
    # the generation/resourceVersion-bound read-back below decides the outcome.
    :
  fi
  poll_exact_post_state
}

promotion_preflight() {
  [[ -n "$EVIDENCE" ]] || lane_die "promotion requires --evidence"
  [[ -n "$TELEMETRY" ]] || lane_die "promotion requires --telemetry"
  verify_current_signed_config
  verify_secret_versions
  verify_effective_iam_live
  "$LANE_DIR/verify-canary.py" \
    --config "$CONFIG" \
    --evidence "$EVIDENCE" \
    --live \
    >/dev/null \
    || lane_die "current signed canary/config verification failed"
  verify_prior_stage_telemetry "$PRE_DECISION" "$PRE_ACTUATOR"
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
  verify_current_signed_config
  verify_secret_versions
  capture_snapshots
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

  if [[ "$actuator_stage" == candidate ]]; then
    [[ "$decision_stage" == 100 || "$decision_stage" == stable ]] \
      || lane_die "refusing actuator-before-decision rollout state"
    prepare_locked_update \
      actuator "$decision_traffic" "$ACTUATOR_CANDIDATE:100" \
      "$ACTUATOR_STABLE_REVISION:100"
    apply_prepared_update
    if [[ "$decision_stage" == stable ]]; then
      return 0
    fi
    load_pinned_stable_revisions
    verify_current_signed_config
    verify_secret_versions
    capture_snapshots
  fi

  if [[ "$decision_stage" != stable ]]; then
    prepare_locked_update \
      decision "$decision_traffic" "$ACTUATOR_STABLE_REVISION:100" \
      "$DECISION_STABLE_REVISION:100"
    apply_prepared_update
  else
    printf 'rollback target is already serving 100%% on both services\n'
  fi
}

if [[ "$ACTION" == apply-rollback ]]; then
  apply_rollback
else
  set_promotion_transition
  promotion_preflight
  capture_snapshots
  prepare_locked_update \
    "$TARGET_PLANE" "$PRE_DECISION" "$PRE_ACTUATOR" "$POST_TRAFFIC"
  apply_prepared_update
fi
