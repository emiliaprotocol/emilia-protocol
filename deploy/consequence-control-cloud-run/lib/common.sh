#!/usr/bin/env bash
set -euo pipefail

lane_die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

is_invocation_control_variable() {
  case "$1" in
    PATH | ACTION | MODE | CONFIG | EVIDENCE | TELEMETRY | AUTHORIZATION | \
      STABLE_MANIFEST | STABLE_PUBLIC_KEY | UPDATE_* | *_SNAPSHOT | \
      MAX_* | MIN_* | ROLLOUT_POLL_* | \
      DEPLOYMENT_CONFIG_SHA256 | REQUIRE_DEPLOYMENT_CONFIG_PIN | \
      *_APPROVED | *_CONFIRM | *_CONFIRM_* | JIT_*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

verify_lane_config_pin() {
  local expected=${DEPLOYMENT_CONFIG_SHA256:-} actual
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] \
    || lane_die "DEPLOYMENT_CONFIG_SHA256 must be injected by a protected source"
  [[ -n "${LANE_PINNED_CONFIG_BASE64:-}" ]] \
    || lane_die "deployment config has not been pinned in memory"
  actual=$(
    printf '%s' "$LANE_PINNED_CONFIG_BASE64" \
      | python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(sys.stdin.buffer.read(), validate=True)).hexdigest())'
  ) || lane_die "unable to verify retained deployment config bytes"
  [[ "$actual" == "$expected" \
      && "$actual" == "${LANE_PINNED_CONFIG_SHA256:-}" ]] \
    || lane_die "deployment config differs from protected SHA-256"
}

lane_cleanup_pinned_config() {
  local temporary_parent=${TMPDIR:-/tmp}
  temporary_parent=${temporary_parent%/}
  if [[ -n "${LANE_PINNED_CONFIG_DIR:-}" \
      && "$LANE_PINNED_CONFIG_DIR" != / \
      && "$LANE_PINNED_CONFIG_DIR" == "$temporary_parent/"* ]]; then
    rm -rf -- "$LANE_PINNED_CONFIG_DIR"
  fi
}

lane_emit_pinned_config() {
  [[ -n "${LANE_PINNED_CONFIG_BASE64:-}" ]] \
    || lane_die "deployment config has not been retained"
  printf '%s' "$LANE_PINNED_CONFIG_BASE64" \
    | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read(), validate=True))'
}

lane_config_key_is_allowed() {
  local candidate=$1 allowed
  shift
  for allowed in "$@"; do
    [[ "$candidate" == "$allowed" ]] && return 0
  done
  return 1
}

load_lane_config() {
  local file=${1:-}
  shift
  (($# > 0)) || lane_die "a strict config-key allowlist is required"
  local allowed=("$@")
  local expected=${DEPLOYMENT_CONFIG_SHA256:-}
  local require_pin=${REQUIRE_DEPLOYMENT_CONFIG_PIN:-false}
  if [[ "$require_pin" == true ]]; then
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] \
      || lane_die "DEPLOYMENT_CONFIG_SHA256 must be injected by a protected source"
  elif [[ -n "$expected" && ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    lane_die "DEPLOYMENT_CONFIG_SHA256 must be lowercase SHA-256"
  fi

  lane_cleanup_pinned_config
  LANE_PINNED_CONFIG_DIR=$(mktemp -d)
  chmod 700 "$LANE_PINNED_CONFIG_DIR"
  LANE_PINNED_CONFIG="$LANE_PINNED_CONFIG_DIR/config.env"
  local metadata
  metadata=$(
    python3 - "$file" "$LANE_PINNED_CONFIG" "$expected" "$require_pin" <<'PY'
import base64
import errno
import hashlib
import os
import stat
import sys

source, destination, expected, require_pin = sys.argv[1:]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
try:
    descriptor = os.open(source, flags)
except OSError as error:
    if error.errno in {errno.ELOOP, errno.EMLINK}:
        raise SystemExit("config path must name a regular non-symlink file")
    raise SystemExit(f"config file is unavailable: {error}")
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit("config path must name a regular non-symlink file")
    if metadata.st_nlink != 1:
        raise SystemExit("config file must have exactly one filesystem link")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise SystemExit("config file ownership is unsafe")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise SystemExit("config file mode permits group or world writes")
    chunks = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    raw = b"".join(chunks)
finally:
    os.close(descriptor)
if b"\x00" in raw:
    raise SystemExit("config contains a NUL byte")
actual = hashlib.sha256(raw).hexdigest()
if require_pin == "true" and actual != expected:
    raise SystemExit("deployment config differs from protected SHA-256")
output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
if hasattr(os, "O_NOFOLLOW"):
    output_flags |= os.O_NOFOLLOW
output = os.open(destination, output_flags, 0o400)
try:
    view = memoryview(raw)
    while view:
        written = os.write(output, view)
        view = view[written:]
    os.fsync(output)
finally:
    os.close(output)
print(actual)
print(base64.b64encode(raw).decode("ascii"))
PY
  ) || {
    lane_cleanup_pinned_config
    lane_die "unable to create single-open pinned config snapshot"
  }
  LANE_PINNED_CONFIG_SHA256=${metadata%%$'\n'*}
  LANE_PINNED_CONFIG_BASE64=${metadata#*$'\n'}
  [[ "$LANE_PINNED_CONFIG_SHA256" =~ ^[0-9a-f]{64}$ \
      && -n "$LANE_PINNED_CONFIG_BASE64" ]] || {
    lane_cleanup_pinned_config
    lane_die "pinned config snapshot metadata is invalid"
  }
  trap 'lane_cleanup_pinned_config' EXIT

  local line key value number=0
  local seen=':'
  LANE_LOADED_CONFIG_KEYS=':'
  while IFS= read -r line || [[ -n "$line" ]]; do
    number=$((number + 1))
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || lane_die "invalid config line $number"
    key=${line%%=*}
    value=${line#*=}
    [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] \
      || lane_die "invalid config key on line $number"
    if is_invocation_control_variable "$key"; then
      lane_die "invocation control variables must not be stored in config; config key is not allowed: $key"
    fi
    lane_config_key_is_allowed "$key" "${allowed[@]}" \
      || lane_die "config key is not allowed for this command: $key"
    [[ "$seen" != *":$key:"* ]] \
      || lane_die "duplicate config key on line $number: $key"
    seen+="$key:"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] \
      || lane_die "invalid control character on line $number"
    printf -v "$key" '%s' "$value"
    export "${key?}"
    LANE_LOADED_CONFIG_KEYS+="$key:"
  done < <(lane_emit_pinned_config)
  # shellcheck disable=SC2034
  CONFIG=$LANE_PINNED_CONFIG
  if [[ "$require_pin" == true ]]; then
    verify_lane_config_pin
  fi
}

prepare_deploy_config_projection() {
  [[ -n "${LANE_PINNED_CONFIG_DIR:-}" \
      && -d "$LANE_PINNED_CONFIG_DIR" ]] \
    || lane_die "deployment config snapshot directory is unavailable"
  DEPLOY_CONFIG_PROJECTION="$LANE_PINNED_CONFIG_DIR/deploy.env"
  local projection projection_base64
  projection=$(
    local name
    while IFS= read -r name; do
      if [[ "${LANE_LOADED_CONFIG_KEYS:-:}" == *":$name:"* ]]; then
        printf '%s=%s\n' "$name" "${!name}"
      fi
    done < <(deploy_config_variables)
  ) || lane_die "unable to prepare deploy config projection"
  projection_base64=$(
    printf '%s\n' "$projection" \
      | python3 -c 'import base64,sys; print(base64.b64encode(sys.stdin.buffer.read()).decode("ascii"))'
  ) || lane_die "unable to encode deploy config projection"
  DEPLOY_CONFIG_PROJECTION_SHA256=$(
    python3 - "$DEPLOY_CONFIG_PROJECTION" "$projection_base64" <<'PY'
import base64
import hashlib
import os
import sys

destination = sys.argv[1]
raw = base64.b64decode(sys.argv[2], validate=True)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(destination, flags, 0o400)
try:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
print(hashlib.sha256(raw).hexdigest())
PY
  ) || lane_die "unable to retain deploy config projection"
  [[ "$DEPLOY_CONFIG_PROJECTION_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || lane_die "deploy config projection hash is invalid"
}

require_var() {
  local name=$1
  [[ -n "${!name:-}" ]] || lane_die "$name is required"
}

validate_slug() {
  local name=$1 value=${!1:-}
  [[ "$value" =~ ^[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]] \
    || lane_die "$name must be a lowercase Google Cloud slug"
}

validate_release() {
  [[ "${RELEASE_ID:-}" =~ ^[a-z][a-z0-9-]{0,20}$ ]] \
    || lane_die "RELEASE_ID must be a short lowercase revision suffix"
}

validate_positive_integer() {
  local name=$1 value=${!1:-}
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || lane_die "$name must be a positive integer"
}

validate_image_digest() {
  local name=$1 value=${!1:-}
  [[ "$value" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] \
    || lane_die "$name must be a registry image pinned by lowercase sha256 digest"
}

validate_secret_ref() {
  local name=$1 value=${!1:-}
  [[ "$value" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,254}:[1-9][0-9]*$ ]] \
    || lane_die "$name must be SECRET_ID:NUMERIC_VERSION"
}

secret_name() {
  printf '%s' "${1%%:*}"
}

secret_version() {
  printf '%s' "${1##*:}"
}

effective_iam_secret_args() {
  local variable ref secret members=()
  while IFS= read -r secret; do
    members=()
    if secret_is_used_by "$secret" actuator_secret_variables; then
      members+=("serviceAccount:$(runtime_service_account_email "$ACTUATOR_SERVICE_ACCOUNT")")
    fi
    if secret_is_used_by "$secret" decision_secret_variables; then
      members+=("serviceAccount:$(runtime_service_account_email "$DECISION_SERVICE_ACCOUNT")")
    fi
    local IFS=,
    printf '%s=%s\n' "$secret" "${members[*]}"
  done < <(
    while IFS= read -r variable; do
      ref=${!variable}
      secret_name "$ref"
      printf '\n'
    done < <(all_secret_variables) | sort -u
  )
}

emit_effective_iam_manifest() {
  local output=$1 spec
  local project_number
  project_number=$(gcloud projects describe "$PROJECT_ID" \
    "--project=$PROJECT_ID" --format='value(projectNumber)')
  [[ "$project_number" =~ ^[1-9][0-9]{5,29}$ ]] \
    || lane_die "Google Cloud project number could not be resolved"
  local arguments=(
    python3 "$LANE_DIR/emit-effective-iam-manifest.py"
    "--project=$PROJECT_ID"
    "--project-number=$project_number"
    "--region=$REGION"
    "--actuator-service=$ACTUATOR_SERVICE"
    "--decision-service=$DECISION_SERVICE"
    "--decision-principal=serviceAccount:$(runtime_service_account_email "$DECISION_SERVICE_ACCOUNT")"
    "--deployer-principal=$DEPLOYER_PRINCIPAL"
    "--output=$output"
  )
  while IFS= read -r spec; do
    arguments+=(--secret "$spec")
  done < <(effective_iam_secret_args)
  "${arguments[@]}"
}

verify_effective_iam_live() {
  local directory manifest
  directory=$(mktemp -d)
  manifest="$directory/effective-iam.json"
  if ! emit_effective_iam_manifest "$manifest"; then
    rm -rf "$directory"
    lane_die "effective IAM manifest generation failed"
  fi
  if ! "$LANE_DIR/verify-effective-iam.py" --input "$manifest" --live; then
    rm -rf "$directory"
    lane_die "effective IAM is broader than the closed deployment allowlist"
  fi
  rm -rf "$directory"
}

shell_join() {
  local rendered=() item
  for item in "$@"; do
    printf -v item '%q' "$item"
    rendered+=("$item")
  done
  local IFS=' '
  printf '%s\n' "${rendered[*]}"
}

runtime_service_account_email() {
  local account=$1
  printf '%s@%s.iam.gserviceaccount.com' "$account" "$PROJECT_ID"
}

candidate_revision() {
  local service=$1
  printf '%s-%s' "$service" "$RELEASE_ID"
}

candidate_tag() {
  printf 'canary-%s' "$RELEASE_ID"
}

actuator_secret_variables() {
  printf '%s\n' \
    ACTUATOR_DATABASE_URL_SECRET \
    ACTUATOR_API_TOKEN_SECRET \
    ACTUATOR_ENVELOPE_PUBLIC_KEY_SECRET \
    ACTUATOR_OBSERVATION_PRIVATE_KEY_SECRET \
    ACTUATOR_GITHUB_APP_ID_SECRET \
    ACTUATOR_GITHUB_INSTALLATION_ID_SECRET \
    ACTUATOR_GITHUB_PRIVATE_KEY_SECRET
}

decision_secret_variables() {
  printf '%s\n' \
    DECISION_EXECUTOR_DATABASE_URL_SECRET \
    DECISION_RECOVERY_DATABASE_URL_SECRET \
    DECISION_API_TOKEN_SECRET \
    DECISION_RECOVERY_TOKEN_SECRET \
    DECISION_PROPOSAL_HMAC_KEY_SECRET \
    DECISION_OWNER_HMAC_KEY_SECRET \
    DECISION_GATE_TRUST_JSON_SECRET \
    DECISION_AEB_CONFIG_JSON_SECRET \
    DECISION_STATUS_CONFIG_JSON_SECRET \
    DECISION_APPROVAL_TOKEN_SECRET \
    ACTUATOR_API_TOKEN_SECRET \
    DECISION_ENVELOPE_PRIVATE_KEY_SECRET \
    DECISION_OBSERVATION_PUBLIC_KEY_SECRET
}

all_secret_variables() {
  {
    actuator_secret_variables
    decision_secret_variables
  } | awk '!seen[$0]++'
}

runtime_config_variables() {
  printf '%s\n' \
    PROJECT_ID REGION RELEASE_ID DEPLOYER_PRINCIPAL \
    ACTUATOR_SERVICE DECISION_SERVICE \
    ACTUATOR_SERVICE_ACCOUNT DECISION_SERVICE_ACCOUNT \
    ACTUATOR_IMAGE DECISION_IMAGE \
    NETWORK SUBNET \
    ACTUATOR_INGRESS DECISION_INGRESS \
    ACTUATOR_CPU ACTUATOR_MEMORY ACTUATOR_MIN_INSTANCES \
    ACTUATOR_MAX_INSTANCES ACTUATOR_CONCURRENCY \
    DECISION_CPU DECISION_MEMORY DECISION_MIN_INSTANCES \
    DECISION_MAX_INSTANCES DECISION_CONCURRENCY \
    ACTUATOR_DATABASE_PRINCIPAL TENANT_ID GITHUB_OWNER GITHUB_REPO \
    GITHUB_ISSUE_NUMBER ENVELOPE_ISSUER_ID ENVELOPE_KEY_ID \
    OBSERVATION_ISSUER_ID OBSERVATION_KEY_ID \
    DECISION_RELYING_PARTY_ID DECISION_EXECUTOR_ID DECISION_PRINCIPAL_ID \
    DECISION_APPROVAL_ENDPOINT DECISION_PROPOSAL_TTL_SEC \
    DECISION_ACTUATOR_TIMEOUT_MS DECISION_AEB_REQUIREMENT_REF \
    DECISION_SHUTDOWN_GRACE_MS \
    CANARY_EVIDENCE_KEY_ID CANARY_EVIDENCE_PUBLIC_KEY_FILE \
    CANARY_EVIDENCE_PUBLIC_KEY_SHA256 CANARY_MAX_AGE_SEC
  all_secret_variables
}

deploy_config_variables() {
  {
    runtime_config_variables
    printf '%s\n' \
      PROJECT_PARENT PROVISIONER_PRINCIPAL EMILIA_IAM_ANALYZER_SCOPE
  } | awk '!seen[$0]++'
}

traffic_config_variables() {
  {
    deploy_config_variables
    printf '%s\n' \
    ROLLOUT_TELEMETRY_KEY_ID ROLLOUT_TELEMETRY_PUBLIC_KEY_FILE \
    ROLLOUT_TELEMETRY_PUBLIC_KEY_SHA256 \
    ROLLOUT_AUTHORIZATION_KEY_ID ROLLOUT_AUTHORIZATION_PUBLIC_KEY_FILE \
    ROLLOUT_AUTHORIZATION_PUBLIC_KEY_SHA256 \
    STABLE_RELEASE_KEY_ID STABLE_RELEASE_KMS_KEY_URI \
    STABLE_RELEASE_PUBLIC_KEY_FILE STABLE_RELEASE_PUBLIC_KEY_SHA256 \
    ACTUATOR_STABLE_REVISION DECISION_STABLE_REVISION
  } | awk '!seen[$0]++'
}

bootstrap_config_variables() {
  {
    deploy_config_variables
    printf '%s\n' \
    STABLE_RELEASE_KEY_ID STABLE_RELEASE_KMS_KEY_URI \
    STABLE_RELEASE_PUBLIC_KEY_FILE STABLE_RELEASE_PUBLIC_KEY_SHA256 \
    STABLE_BOOTSTRAP_ALLOWED_DIGESTS STABLE_BOOTSTRAP_PROVENANCE_FILE \
    STABLE_BOOTSTRAP_PROVENANCE_SHA256 \
    STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT \
    STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT
  } | awk '!seen[$0]++'
}

provision_config_variables() {
  {
    printf '%s\n' \
      PROJECT_ID PROJECT_NAME PROJECT_PARENT BILLING_ACCOUNT REGION \
      PROVISIONER_PRINCIPAL DEPLOYER_PRINCIPAL \
      RECOVERY_PRINCIPALS RECOVERY_PAM_ENTITLEMENT RECOVERY_PAM_ROLE \
      ACTUATOR_SERVICE DECISION_SERVICE \
      ACTUATOR_SERVICE_ACCOUNT DECISION_SERVICE_ACCOUNT \
      STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT \
      STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT \
      NETWORK SUBNET SUBNET_CIDR ARTIFACT_REPOSITORY ROUTER NAT
    all_secret_variables
  } | awk '!seen[$0]++'
}

configured_secret_refs() {
  local variable
  while IFS= read -r variable; do
    printf '%s\n' "${!variable}"
  done < <(all_secret_variables) | sort -u
}

secret_is_used_by() {
  local secret=$1 group=$2 variable ref
  while IFS= read -r variable; do
    ref=${!variable}
    if [[ "$(secret_name "$ref")" == "$secret" ]]; then
      return 0
    fi
  done < <("$group")
  return 1
}

validate_lane_config() {
  local required=(
    PROJECT_ID REGION RELEASE_ID DEPLOYER_PRINCIPAL
    ACTUATOR_SERVICE DECISION_SERVICE
    ACTUATOR_SERVICE_ACCOUNT DECISION_SERVICE_ACCOUNT
    ACTUATOR_IMAGE DECISION_IMAGE NETWORK SUBNET
    ACTUATOR_INGRESS DECISION_INGRESS
    ACTUATOR_CPU ACTUATOR_MEMORY ACTUATOR_MIN_INSTANCES
    ACTUATOR_MAX_INSTANCES ACTUATOR_CONCURRENCY
    DECISION_CPU DECISION_MEMORY DECISION_MIN_INSTANCES
    DECISION_MAX_INSTANCES DECISION_CONCURRENCY
    ACTUATOR_DATABASE_PRINCIPAL TENANT_ID GITHUB_OWNER GITHUB_REPO
    GITHUB_ISSUE_NUMBER ENVELOPE_ISSUER_ID ENVELOPE_KEY_ID
    OBSERVATION_ISSUER_ID OBSERVATION_KEY_ID
    DECISION_RELYING_PARTY_ID DECISION_EXECUTOR_ID DECISION_PRINCIPAL_ID
    DECISION_APPROVAL_ENDPOINT DECISION_PROPOSAL_TTL_SEC
    DECISION_ACTUATOR_TIMEOUT_MS DECISION_AEB_REQUIREMENT_REF
    DECISION_SHUTDOWN_GRACE_MS
    CANARY_EVIDENCE_KEY_ID CANARY_EVIDENCE_PUBLIC_KEY_FILE
    CANARY_EVIDENCE_PUBLIC_KEY_SHA256
    CANARY_MAX_AGE_SEC
  )
  local name
  while IFS= read -r name; do required+=("$name"); done < <(actuator_secret_variables)
  while IFS= read -r name; do required+=("$name"); done < <(decision_secret_variables)
  for name in "${required[@]}"; do require_var "$name"; done

  validate_slug ACTUATOR_SERVICE
  validate_slug DECISION_SERVICE
  validate_slug ACTUATOR_SERVICE_ACCOUNT
  validate_slug DECISION_SERVICE_ACCOUNT
  [[ "$ACTUATOR_SERVICE_ACCOUNT" != "$DECISION_SERVICE_ACCOUNT" ]] \
    || lane_die "runtime service accounts must be distinct"
  [[ "$DEPLOYER_PRINCIPAL" =~ ^serviceAccount:[^[:space:],@]+@[^[:space:],@]+\.iam\.gserviceaccount\.com$ ]] \
    || lane_die "DEPLOYER_PRINCIPAL must be an exact serviceAccount IAM principal"
  validate_release
  validate_image_digest ACTUATOR_IMAGE
  validate_image_digest DECISION_IMAGE
  [[ "$ACTUATOR_INGRESS" == internal ]] \
    || lane_die "ACTUATOR_INGRESS must be internal"
  [[ "$DECISION_INGRESS" == all || "$DECISION_INGRESS" == internal \
      || "$DECISION_INGRESS" == internal-and-cloud-load-balancing ]] \
    || lane_die "DECISION_INGRESS is invalid"
  [[ "$DECISION_APPROVAL_ENDPOINT" == https://* ]] \
    || lane_die "DECISION_APPROVAL_ENDPOINT must use https"
  [[ ${#CANARY_EVIDENCE_KEY_ID} -ge 3 \
      && ${#CANARY_EVIDENCE_KEY_ID} -le 256 \
      && "$CANARY_EVIDENCE_KEY_ID" =~ ^[A-Za-z0-9:_.@-]+$ ]] \
    || lane_die "CANARY_EVIDENCE_KEY_ID is invalid"
  [[ "$CANARY_EVIDENCE_PUBLIC_KEY_FILE" == /* ]] \
    || lane_die "CANARY_EVIDENCE_PUBLIC_KEY_FILE must be an absolute path"
  [[ "$CANARY_EVIDENCE_PUBLIC_KEY_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || lane_die "CANARY_EVIDENCE_PUBLIC_KEY_SHA256 must be lowercase SHA-256"

  for name in \
    GITHUB_ISSUE_NUMBER ACTUATOR_MIN_INSTANCES ACTUATOR_MAX_INSTANCES \
    ACTUATOR_CONCURRENCY DECISION_MIN_INSTANCES DECISION_MAX_INSTANCES \
    DECISION_CONCURRENCY DECISION_PROPOSAL_TTL_SEC \
    DECISION_ACTUATOR_TIMEOUT_MS DECISION_SHUTDOWN_GRACE_MS \
    CANARY_MAX_AGE_SEC; do
    validate_positive_integer "$name"
  done
  while IFS= read -r name; do validate_secret_ref "$name"; done \
    < <(actuator_secret_variables)
  while IFS= read -r name; do validate_secret_ref "$name"; done \
    < <(decision_secret_variables)
}

require_apply_approval() {
  [[ "${DEPLOYMENT_APPROVED:-}" == true ]] \
    || lane_die "apply requires DEPLOYMENT_APPROVED=true"
  command -v gcloud >/dev/null 2>&1 || lane_die "gcloud is required for apply"
}
