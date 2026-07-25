#!/usr/bin/env bash
set -euo pipefail

lane_die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

is_invocation_control_variable() {
  case "$1" in
    DEPLOYMENT_CONFIG_SHA256 | REQUIRE_DEPLOYMENT_CONFIG_PIN | *_APPROVED | *_CONFIRM | *_CONFIRM_* | JIT_*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

lane_sha256_file() {
  local file=$1 digest
  if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$file") || lane_die "unable to hash deployment config"
    printf '%s' "${digest%% *}"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    digest=$(shasum -a 256 "$file") || lane_die "unable to hash deployment config"
    printf '%s' "${digest%% *}"
    return
  fi
  command -v openssl >/dev/null 2>&1 \
    || lane_die "sha256sum, shasum, or openssl is required"
  digest=$(openssl dgst -sha256 -r "$file") \
    || lane_die "unable to hash deployment config"
  printf '%s' "${digest%% *}"
}

verify_lane_config_pin() {
  local file=$1 expected=${DEPLOYMENT_CONFIG_SHA256:-} actual
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] \
    || lane_die "DEPLOYMENT_CONFIG_SHA256 must be injected by a protected source"
  actual=$(lane_sha256_file "$file")
  [[ "$actual" == "$expected" ]] \
    || lane_die "deployment config differs from protected SHA-256"
}

load_lane_config() {
  local file=${1:-}
  [[ -f "$file" ]] || lane_die "config file not found: $file"
  if [[ "${REQUIRE_DEPLOYMENT_CONFIG_PIN:-false}" != true ]]; then
    local line key value number=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      number=$((number + 1))
      [[ -z "$line" || "$line" == \#* ]] && continue
      [[ "$line" == *=* ]] || lane_die "invalid config line $number"
      key=${line%%=*}
      value=${line#*=}
      [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] \
        || lane_die "invalid config key on line $number"
      if is_invocation_control_variable "$key"; then
        lane_die "invocation control variables must not be stored in config: $key"
      fi
      [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] \
        || lane_die "invalid control character on line $number"
      printf -v "$key" '%s' "$value"
      export "${key?}"
    done < "$file"
    return
  fi
  local pinned_copy
  pinned_copy=$(mktemp)
  chmod 600 "$pinned_copy"
  cp "$file" "$pinned_copy" || {
    rm -f "$pinned_copy"
    lane_die "unable to snapshot deployment config"
  }
  verify_lane_config_pin "$pinned_copy"
  local line key value number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    number=$((number + 1))
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || lane_die "invalid config line $number"
    key=${line%%=*}
    value=${line#*=}
    [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] \
      || lane_die "invalid config key on line $number"
    if is_invocation_control_variable "$key"; then
      lane_die "invocation control variables must not be stored in config: $key"
    fi
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] \
      || lane_die "invalid control character on line $number"
    printf -v "$key" '%s' "$value"
    export "${key?}"
  done < "$pinned_copy"
  rm -f "$pinned_copy"
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
    "--decision-principal=serviceAccount:$(runtime_service_account_email "$DECISION_SERVICE_ACCOUNT")"
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
