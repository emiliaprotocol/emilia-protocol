#!/usr/bin/env bash
set -euo pipefail

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$LANE_DIR/lib/common.sh"

CONFIG=
ACTION=
EVIDENCE=
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
require_var ACTUATOR_STABLE_REVISION
require_var DECISION_STABLE_REVISION

ACTUATOR_CANDIDATE=$(candidate_revision "$ACTUATOR_SERVICE")
DECISION_CANDIDATE=$(candidate_revision "$DECISION_SERVICE")
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

require_apply_approval
if [[ "$ACTION" != apply-rollback ]]; then
  [[ -n "$EVIDENCE" ]] || lane_die "promotion requires --evidence"
  "$LANE_DIR/verify-canary.py" --config "$CONFIG" --evidence "$EVIDENCE"
fi

case "$ACTION" in
  apply-decision-1)
    traffic_command "$DECISION_SERVICE" \
      "$DECISION_CANDIDATE=1,$DECISION_STABLE_REVISION=99"
    "${TRAFFIC_COMMAND[@]}"
    ;;
  apply-decision-10)
    traffic_command "$DECISION_SERVICE" \
      "$DECISION_CANDIDATE=10,$DECISION_STABLE_REVISION=90"
    "${TRAFFIC_COMMAND[@]}"
    ;;
  apply-decision-50)
    traffic_command "$DECISION_SERVICE" \
      "$DECISION_CANDIDATE=50,$DECISION_STABLE_REVISION=50"
    "${TRAFFIC_COMMAND[@]}"
    ;;
  apply-decision-100)
    traffic_command "$DECISION_SERVICE" "$DECISION_CANDIDATE=100"
    "${TRAFFIC_COMMAND[@]}"
    ;;
  apply-actuator-100)
    traffic_command "$ACTUATOR_SERVICE" "$ACTUATOR_CANDIDATE=100"
    "${TRAFFIC_COMMAND[@]}"
    ;;
  apply-rollback)
    traffic_command "$ACTUATOR_SERVICE" "$ACTUATOR_STABLE_REVISION=100"
    "${TRAFFIC_COMMAND[@]}"
    traffic_command "$DECISION_SERVICE" "$DECISION_STABLE_REVISION=100"
    "${TRAFFIC_COMMAND[@]}"
    ;;
  *)
    lane_die "unsupported traffic action"
    ;;
esac
