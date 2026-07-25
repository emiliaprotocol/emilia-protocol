#!/usr/bin/env bash
set -euo pipefail

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$LANE_DIR/lib/common.sh"

CONFIG=
MODE=render
ACTION=provision
while (($#)); do
  case "$1" in
    --config)
      (($# >= 2)) || lane_die "--config requires a path"
      CONFIG=$2
      shift 2
      ;;
    --render)
      MODE=render
      ACTION=provision
      shift
      ;;
    --apply)
      MODE=apply
      ACTION=provision
      shift
      ;;
    --grant-jit-actas)
      MODE=apply
      ACTION=grant-jit-actas
      shift
      ;;
    --revoke-jit-actas)
      MODE=apply
      ACTION=revoke-jit-actas
      shift
      ;;
    *)
      lane_die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$CONFIG" ]] || lane_die "--config is required"
load_lane_config "$CONFIG"

: "${PROJECT_NAME:=EMILIA consequence control}"
: "${ARTIFACT_REPOSITORY:=runtime}"
: "${ROUTER:=emilia-egress-router}"
: "${NAT:=emilia-egress-nat}"
: "${PROJECT_PARENT:=}"

PROVISIONER_ROLE_ID=emiliaConsequenceProvisioner
DEPLOYER_ROLE_ID=emiliaConsequenceDeployer
RECOVERY_ROLE_ID=emiliaConsequenceRecovery
PROVISIONER_PERMISSIONS=(
  artifactregistry.repositories.create
  artifactregistry.repositories.get
  artifactregistry.repositories.update
  compute.networks.create
  compute.networks.get
  compute.routers.create
  compute.routers.get
  compute.routers.update
  compute.routers.use
  compute.subnetworks.create
  compute.subnetworks.get
  compute.subnetworks.setPrivateIpGoogleAccess
  iam.roles.create
  iam.roles.get
  iam.roles.update
  iam.serviceAccounts.create
  iam.serviceAccounts.get
  iam.serviceAccounts.getIamPolicy
  iam.serviceAccounts.setIamPolicy
  orgpolicy.policies.create
  orgpolicy.policies.list
  orgpolicy.policies.update
  resourcemanager.projects.get
  resourcemanager.projects.getIamPolicy
  resourcemanager.projects.setIamPolicy
  resourcemanager.projects.update
  run.services.get
  run.services.getIamPolicy
  run.services.setIamPolicy
  secretmanager.secrets.get
  secretmanager.secrets.getIamPolicy
  secretmanager.secrets.setIamPolicy
  secretmanager.versions.get
  secretmanager.versions.list
  serviceusage.services.enable
  serviceusage.services.get
  serviceusage.services.list
  serviceusage.services.use
)
DEPLOYER_PERMISSIONS=(
  artifactregistry.repositories.downloadArtifacts
  artifactregistry.repositories.get
  cloudasset.assets.analyzeIamPolicy
  cloudasset.assets.searchAllIamPolicies
  cloudasset.assets.searchAllResources
  compute.networks.get
  compute.subnetworks.get
  compute.subnetworks.use
  iam.serviceAccounts.get
  iam.serviceAccounts.getIamPolicy
  iam.serviceAccounts.setIamPolicy
  logging.logEntries.list
  monitoring.timeSeries.list
  resourcemanager.projects.get
  run.operations.get
  run.revisions.get
  run.revisions.list
  run.services.create
  run.services.get
  run.services.getIamPolicy
  run.services.list
  run.services.setIamPolicy
  run.services.update
  secretmanager.secrets.get
  secretmanager.secrets.getIamPolicy
  secretmanager.secrets.setIamPolicy
  secretmanager.versions.get
  secretmanager.versions.list
  serviceusage.services.get
  serviceusage.services.list
  serviceusage.services.use
)
RECOVERY_PERMISSIONS=(
  iam.roles.get
  iam.roles.list
  iam.serviceAccounts.get
  iam.serviceAccounts.getIamPolicy
  iam.serviceAccounts.setIamPolicy
  resourcemanager.projects.get
  resourcemanager.projects.getIamPolicy
  resourcemanager.projects.setIamPolicy
  run.services.get
  run.services.getIamPolicy
  run.services.setIamPolicy
  secretmanager.secrets.get
  secretmanager.secrets.getIamPolicy
  secretmanager.secrets.setIamPolicy
  serviceusage.services.get
  serviceusage.services.list
)
REQUIRED_APIS=(
  artifactregistry.googleapis.com
  cloudasset.googleapis.com
  cloudbilling.googleapis.com
  cloudresourcemanager.googleapis.com
  compute.googleapis.com
  iam.googleapis.com
  iamcredentials.googleapis.com
  logging.googleapis.com
  monitoring.googleapis.com
  orgpolicy.googleapis.com
  run.googleapis.com
  secretmanager.googleapis.com
  serviceusage.googleapis.com
)

csv_join() {
  local IFS=,
  printf '%s' "$*"
}

validate_project_id() {
  [[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] \
    || lane_die "PROJECT_ID must be a lowercase 6-30 character Google project ID"
}

validate_account_id() {
  local name=$1 value=${!1:-}
  [[ "$value" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] \
    || lane_die "$name must be a lowercase 6-30 character service account ID"
}

validate_region() {
  [[ "$REGION" =~ ^[a-z]+-[a-z]+[0-9]$ ]] \
    || lane_die "REGION must be a Google Cloud region"
}

validate_principal() {
  local value=$1
  [[ "$value" =~ ^(user|group|serviceAccount):[^[:space:],]+$ ]] \
    || lane_die "invalid IAM principal: $value"
}

validate_subnet_cidr() {
  if ! python3 - "$SUBNET_CIDR" <<'PY'
import ipaddress
import sys

try:
    network = ipaddress.ip_network(sys.argv[1], strict=True)
except ValueError:
    raise SystemExit(1)
if network.version != 4 or network.prefixlen != 26:
    raise SystemExit(1)
PY
  then
    lane_die "SUBNET_CIDR must be a canonical IPv4 /26"
  fi
}

validate_provision_config() {
  local required=(
    PROJECT_ID BILLING_ACCOUNT REGION ACTUATOR_SERVICE_ACCOUNT
    DECISION_SERVICE_ACCOUNT STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT
    STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT PROVISIONER_PRINCIPAL
    DEPLOYER_PRINCIPAL RECOVERY_PRINCIPALS
    NETWORK SUBNET SUBNET_CIDR ARTIFACT_REPOSITORY ROUTER NAT
  )
  local name member left right
  local account_names=(
    ACTUATOR_SERVICE_ACCOUNT
    DECISION_SERVICE_ACCOUNT
    STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT
    STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT
  )
  local account_values=()
  for name in "${required[@]}"; do require_var "$name"; done
  account_values=(
    "$ACTUATOR_SERVICE_ACCOUNT"
    "$DECISION_SERVICE_ACCOUNT"
    "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT"
    "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"
  )
  validate_project_id
  [[ "$BILLING_ACCOUNT" =~ ^[A-Fa-f0-9]{6}-[A-Fa-f0-9]{6}-[A-Fa-f0-9]{6}$ ]] \
    || lane_die "BILLING_ACCOUNT must use the canonical XXXXXX-XXXXXX-XXXXXX form"
  validate_region
  for name in "${account_names[@]}"; do
    validate_account_id "$name"
  done
  for left in "${!account_values[@]}"; do
    for right in "${!account_values[@]}"; do
      ((right > left)) || continue
      [[ "${account_values[left]}" != "${account_values[right]}" ]] \
        || lane_die "runtime and stable bootstrap service accounts must all be distinct"
    done
  done
  [[ "$DEPLOYER_PRINCIPAL" == serviceAccount:* ]] \
    || lane_die "DEPLOYER_PRINCIPAL must be a serviceAccount principal"
  validate_principal "$DEPLOYER_PRINCIPAL"
  [[ "$DEPLOYER_PRINCIPAL" =~ ^serviceAccount:[^[:space:],@]+@[^[:space:],@]+\.iam\.gserviceaccount\.com$ ]] \
    || lane_die "DEPLOYER_PRINCIPAL must be an exact serviceAccount IAM principal"
  [[ "$PROVISIONER_PRINCIPAL" =~ ^(user:[^[:space:],@]+@[^[:space:],@]+|serviceAccount:[^[:space:],@]+@[^[:space:],@]+\.iam\.gserviceaccount\.com)$ ]] \
    || lane_die "PROVISIONER_PRINCIPAL must be an exact user or serviceAccount IAM principal"
  [[ "$PROVISIONER_PRINCIPAL" != "$DEPLOYER_PRINCIPAL" ]] \
    || lane_die "PROVISIONER_PRINCIPAL and DEPLOYER_PRINCIPAL must be distinct"
  validate_slug NETWORK
  validate_slug SUBNET
  validate_slug ARTIFACT_REPOSITORY
  validate_slug ROUTER
  validate_slug NAT
  validate_subnet_cidr
  if [[ -n "$PROJECT_PARENT" ]]; then
    [[ "$PROJECT_PARENT" =~ ^(organizations|folders)/[1-9][0-9]*$ ]] \
      || lane_die "PROJECT_PARENT must be organizations/NUMBER or folders/NUMBER"
  fi

  IFS=, read -r -a RECOVERY_MEMBERS <<< "$RECOVERY_PRINCIPALS"
  ((${#RECOVERY_MEMBERS[@]} >= 2)) \
    || lane_die "at least two distinct RECOVERY_PRINCIPALS members are required"
  for left in "${!RECOVERY_MEMBERS[@]}"; do
    member=${RECOVERY_MEMBERS[left]}
    validate_principal "$member"
    [[ "$member" != "$DEPLOYER_PRINCIPAL" ]] \
      || lane_die "DEPLOYER_PRINCIPAL must not be a recovery principal"
    [[ "$member" != "$PROVISIONER_PRINCIPAL" ]] \
      || lane_die "PROVISIONER_PRINCIPAL must not be a recovery principal"
    for ((right = 0; right < left; right++)); do
      [[ "$member" != "${RECOVERY_MEMBERS[right]}" ]] \
        || lane_die "duplicate recovery principal: $member"
    done
  done
}

require_active_provisioner() {
  local account active_principal
  account=$(gcloud config get-value account --quiet)
  [[ -n "$account" && "$account" != "(unset)" \
      && "$account" != *[$'\r\n\t ']* ]] \
    || lane_die "active gcloud provisioner account could not be resolved exactly"
  case "$account" in
    user:*|serviceAccount:*)
      active_principal=$account
      ;;
    *@*.gserviceaccount.com)
      active_principal="serviceAccount:$account"
      ;;
    *@*)
      active_principal="user:$account"
      ;;
    *)
      lane_die "active gcloud provisioner is not a concrete IAM principal"
      ;;
  esac
  [[ "$active_principal" == "$PROVISIONER_PRINCIPAL" ]] \
    || lane_die "active gcloud identity $active_principal does not exactly match PROVISIONER_PRINCIPAL $PROVISIONER_PRINCIPAL"
}

require_provision_approval() {
  [[ "${PROVISIONING_APPROVED:-}" == true ]] \
    || lane_die "apply requires PROVISIONING_APPROVED=true"
  [[ "${PROVISIONING_CONFIRM_PROJECT:-}" == "$PROJECT_ID" ]] \
    || lane_die "PROVISIONING_CONFIRM_PROJECT must exactly equal PROJECT_ID"
  command -v gcloud >/dev/null 2>&1 || lane_die "gcloud is required for apply"
}

validate_jit_expiry() {
  require_var JIT_ACTAS_EXPIRES_AT
  python3 - "$JIT_ACTAS_EXPIRES_AT" <<'PY' || \
    lane_die "JIT_ACTAS_EXPIRES_AT must be UTC, future, and no more than 60 minutes away"
from datetime import datetime, timezone
import re
import sys

value = sys.argv[1]
if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
    raise SystemExit(1)
expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
seconds = (expiry - datetime.now(timezone.utc)).total_seconds()
if seconds <= 0 or seconds > 3600:
    raise SystemExit(1)
PY
}

require_rollout_approval() {
  [[ "${ROLLOUT_APPROVED:-}" == true ]] \
    || lane_die "JIT actAs changes require ROLLOUT_APPROVED=true"
  [[ "${ROLLOUT_CONFIRM_PROJECT:-}" == "$PROJECT_ID" ]] \
    || lane_die "ROLLOUT_CONFIRM_PROJECT must exactly equal PROJECT_ID"
  command -v gcloud >/dev/null 2>&1 || lane_die "gcloud is required for rollout IAM"
  validate_jit_expiry
}

render_custom_role() {
  local role_id=$1 title=$2 description=$3
  shift 3
  local permissions
  permissions=$(csv_join "$@")
  printf '# create %s if absent, then reconcile its exact permission set\n' "$role_id"
  shell_join gcloud iam roles create "$role_id" \
    "--project=$PROJECT_ID" "--title=$title" "--description=$description" \
    "--permissions=$permissions" --stage=GA
  shell_join gcloud iam roles update "$role_id" \
    "--project=$PROJECT_ID" "--title=$title" "--description=$description" \
    "--permissions=$permissions" --stage=GA
}

render_plan() {
  local project_create=(
    gcloud projects create "$PROJECT_ID"
    "--name=$PROJECT_NAME"
    "--labels=emilia-purpose=consequence-control"
  )
  if [[ -n "$PROJECT_PARENT" ]]; then
    project_create+=("--folder=${PROJECT_PARENT#folders/}")
    if [[ "$PROJECT_PARENT" == organizations/* ]]; then
      project_create=(
        gcloud projects create "$PROJECT_ID"
        "--name=$PROJECT_NAME"
        "--labels=emilia-purpose=consequence-control"
        "--organization=${PROJECT_PARENT#organizations/}"
      )
    fi
  fi

  printf '# create the dedicated project if absent and link explicit billing\n'
  shell_join "${project_create[@]}"
  shell_join gcloud billing projects link "$PROJECT_ID" \
    "--billing-account=$BILLING_ACCOUNT"
  printf '# enable the complete runtime and assurance control plane\n'
  shell_join gcloud services enable "${REQUIRED_APIS[@]}" "--project=$PROJECT_ID"
  shell_join gcloud projects update "$PROJECT_ID" \
    "--update-labels=emilia-purpose=consequence-control"
  render_custom_role "$PROVISIONER_ROLE_ID" \
    "EMILIA consequence provisioner" \
    "JIT infrastructure and IAM reconciliation; never a runtime principal" \
    "${PROVISIONER_PERMISSIONS[@]}"
  printf '# bind and read back the exact active provisioner before completing infrastructure\n'
  shell_join gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=$PROVISIONER_PRINCIPAL" \
    "--role=projects/$PROJECT_ID/roles/$PROVISIONER_ROLE_ID" \
    --condition=None
  shell_join gcloud projects get-iam-policy "$PROJECT_ID" --format=json

  printf '# create isolated runtime and stable bootstrap identities without keys\n'
  shell_join gcloud iam service-accounts create "$ACTUATOR_SERVICE_ACCOUNT" \
    "--project=$PROJECT_ID" \
    "--display-name=EMILIA consequence actuator"
  shell_join gcloud iam service-accounts create "$DECISION_SERVICE_ACCOUNT" \
    "--project=$PROJECT_ID" \
    "--display-name=EMILIA consequence decision"
  shell_join gcloud iam service-accounts create \
    "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
    "--project=$PROJECT_ID" \
    "--display-name=EMILIA permissionless stable bootstrap actuator"
  shell_join gcloud iam service-accounts create \
    "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT" \
    "--project=$PROJECT_ID" \
    "--display-name=EMILIA permissionless stable bootstrap decision"

  printf '# create a digest-oriented Artifact Registry repository\n'
  shell_join gcloud artifacts repositories create "$ARTIFACT_REPOSITORY" \
    "--project=$PROJECT_ID" "--location=$REGION" \
    --repository-format=docker --immutable-tags \
    "--description=EMILIA consequence control runtime images"

  printf '# create a custom VPC, regional IPv4 /26, and Private Google Access\n'
  shell_join gcloud compute networks create "$NETWORK" \
    "--project=$PROJECT_ID" --subnet-mode=custom --bgp-routing-mode=regional
  shell_join gcloud compute networks subnets create "$SUBNET" \
    "--project=$PROJECT_ID" "--region=$REGION" "--network=$NETWORK" \
    "--range=$SUBNET_CIDR" --enable-private-ip-google-access
  printf '# create explicit all-subnet Cloud NAT egress with error logging\n'
  shell_join gcloud compute routers create "$ROUTER" \
    "--project=$PROJECT_ID" "--region=$REGION" "--network=$NETWORK"
  shell_join gcloud compute routers nats create "$NAT" \
    "--project=$PROJECT_ID" "--region=$REGION" "--router=$ROUTER" \
    --nat-all-subnet-ip-ranges --auto-allocate-nat-external-ips \
    --enable-logging --log-filter=ERRORS_ONLY

  render_custom_role "$DEPLOYER_ROLE_ID" \
    "EMILIA consequence deployer" \
    "Steady-state zero-secret-payload Cloud Run deployment and observation" \
    "${DEPLOYER_PERMISSIONS[@]}"
  render_custom_role "$RECOVERY_ROLE_ID" \
    "EMILIA consequence break-glass recovery" \
    "IAM control-plane restoration without runtime impersonation or data access" \
    "${RECOVERY_PERMISSIONS[@]}"
  shell_join gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=$DEPLOYER_PRINCIPAL" \
    "--role=projects/$PROJECT_ID/roles/$DEPLOYER_ROLE_ID" --condition=None

  printf '# establish break-glass recovery custodians\n'
  local member
  for member in "${RECOVERY_MEMBERS[@]}"; do
    shell_join gcloud projects add-iam-policy-binding "$PROJECT_ID" \
      "--member=$member" \
      "--role=projects/$PROJECT_ID/roles/$RECOVERY_ROLE_ID" \
      --condition=None
  done
  printf '# verify recovery and provisioner control before owner removal\n'
  printf '# verify-control-plane-custody: recovery, provisioner, and deployer custom bindings must be readable\n'
  shell_join gcloud projects get-iam-policy "$PROJECT_ID" --format=json
  printf '# reconcile exact custom-role custody and remove every project owner binding\n'
  shell_join python3 '<rewrite-control-plane-policy-exactly>' \
    '<current-project-policy.json>' '<closed-project-policy.json>'
  shell_join gcloud projects set-iam-policy "$PROJECT_ID" \
    '<closed-project-policy.json>'
  printf '# verify-control-plane-exact: no roles/owner and exact provisioner, deployer, and recovery bindings\n'
  shell_join gcloud projects get-iam-policy "$PROJECT_ID" --format=json
  printf '# prevent automatic broad grants before removing any existing defaults\n'
  shell_join gcloud resource-manager org-policies enable-enforce \
    constraints/iam.automaticIamGrantsForDefaultServiceAccounts \
    "--project=$PROJECT_ID"
  printf '# remove broad default Editor grants only after recovery verification\n'
  shell_join gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
    '--member=serviceAccount:<PROJECT_NUMBER>-compute@developer.gserviceaccount.com' \
    --role=roles/editor --condition=None
  shell_join gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
    "--member=serviceAccount:$PROJECT_ID@appspot.gserviceaccount.com" \
    --role=roles/editor --condition=None
  printf '# steady-state plan intentionally contains no service-account-user binding\n'
}

ensure_project() {
  if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
    local command=(
      gcloud projects create "$PROJECT_ID"
      "--name=$PROJECT_NAME"
      "--labels=emilia-purpose=consequence-control"
    )
    if [[ "$PROJECT_PARENT" == folders/* ]]; then
      command+=("--folder=${PROJECT_PARENT#folders/}")
    elif [[ "$PROJECT_PARENT" == organizations/* ]]; then
      command+=("--organization=${PROJECT_PARENT#organizations/}")
    fi
    "${command[@]}" --quiet
  fi
  gcloud billing projects link "$PROJECT_ID" \
    "--billing-account=$BILLING_ACCOUNT" --quiet
  gcloud projects update "$PROJECT_ID" \
    "--update-labels=emilia-purpose=consequence-control" --quiet
}

ensure_service_account() {
  local account=$1 display_name=$2
  local email="$account@$PROJECT_ID.iam.gserviceaccount.com"
  if ! gcloud iam service-accounts describe "$email" \
      "--project=$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$account" \
      "--project=$PROJECT_ID" "--display-name=$display_name" --quiet
  fi
}

ensure_artifact_repository() {
  if ! gcloud artifacts repositories describe "$ARTIFACT_REPOSITORY" \
      "--project=$PROJECT_ID" "--location=$REGION" >/dev/null 2>&1; then
    gcloud artifacts repositories create "$ARTIFACT_REPOSITORY" \
      "--project=$PROJECT_ID" "--location=$REGION" \
      --repository-format=docker --immutable-tags \
      "--description=EMILIA consequence control runtime images" --quiet
  else
    gcloud artifacts repositories update "$ARTIFACT_REPOSITORY" \
      "--project=$PROJECT_ID" "--location=$REGION" --immutable-tags --quiet
  fi
}

ensure_network() {
  if ! gcloud compute networks describe "$NETWORK" \
      "--project=$PROJECT_ID" >/dev/null 2>&1; then
    gcloud compute networks create "$NETWORK" \
      "--project=$PROJECT_ID" --subnet-mode=custom \
      --bgp-routing-mode=regional --quiet
  else
    local auto_subnets
    auto_subnets=$(gcloud compute networks describe "$NETWORK" \
      "--project=$PROJECT_ID" --format='value(autoCreateSubnetworks)')
    [[ "$auto_subnets" == False ]] \
      || lane_die "existing NETWORK is not a custom-mode VPC"
  fi
}

verify_subnet() {
  local data_file="$PROVISION_TMPDIR/subnet.json"
  gcloud compute networks subnets describe "$SUBNET" \
    "--project=$PROJECT_ID" "--region=$REGION" --format=json > "$data_file"
  python3 - "$data_file" "$SUBNET_CIDR" "$NETWORK" <<'PY' || \
    lane_die "existing subnet does not match CIDR, network, and Private Google Access"
import json
from pathlib import Path
import sys

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
network = str(data.get("network", "")).rsplit("/", 1)[-1]
if (
    data.get("ipCidrRange") != sys.argv[2]
    or network != sys.argv[3]
    or data.get("privateIpGoogleAccess") is not True
):
    raise SystemExit(1)
PY
}

ensure_subnet() {
  if ! gcloud compute networks subnets describe "$SUBNET" \
      "--project=$PROJECT_ID" "--region=$REGION" >/dev/null 2>&1; then
    gcloud compute networks subnets create "$SUBNET" \
      "--project=$PROJECT_ID" "--region=$REGION" "--network=$NETWORK" \
      "--range=$SUBNET_CIDR" --enable-private-ip-google-access --quiet
  else
    gcloud compute networks subnets update "$SUBNET" \
      "--project=$PROJECT_ID" "--region=$REGION" \
      --enable-private-ip-google-access --quiet
  fi
  verify_subnet
}

ensure_nat() {
  if ! gcloud compute routers describe "$ROUTER" \
      "--project=$PROJECT_ID" "--region=$REGION" >/dev/null 2>&1; then
    gcloud compute routers create "$ROUTER" \
      "--project=$PROJECT_ID" "--region=$REGION" \
      "--network=$NETWORK" --quiet
  fi
  if ! gcloud compute routers nats describe "$NAT" \
      "--project=$PROJECT_ID" "--region=$REGION" \
      "--router=$ROUTER" >/dev/null 2>&1; then
    gcloud compute routers nats create "$NAT" \
      "--project=$PROJECT_ID" "--region=$REGION" "--router=$ROUTER" \
      --nat-all-subnet-ip-ranges --auto-allocate-nat-external-ips \
      --enable-logging --log-filter=ERRORS_ONLY --quiet
  else
    gcloud compute routers nats update "$NAT" \
      "--project=$PROJECT_ID" "--region=$REGION" "--router=$ROUTER" \
      --nat-all-subnet-ip-ranges --auto-allocate-nat-external-ips \
      --enable-logging --log-filter=ERRORS_ONLY --quiet
  fi
}

ensure_custom_role() {
  local role_id=$1 title=$2 description=$3
  shift 3
  local permissions
  permissions=$(csv_join "$@")
  if gcloud iam roles describe "$role_id" \
      "--project=$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam roles update "$role_id" \
      "--project=$PROJECT_ID" "--title=$title" "--description=$description" \
      "--permissions=$permissions" --stage=GA --quiet
  else
    gcloud iam roles create "$role_id" \
      "--project=$PROJECT_ID" "--title=$title" "--description=$description" \
      "--permissions=$permissions" --stage=GA --quiet
  fi
}

verify_control_plane_policy() {
  local mode=$1
  local policy_file="$PROVISION_TMPDIR/project-policy.json"
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --format=json > "$policy_file"
  python3 - "$policy_file" \
    "$mode" \
    "projects/$PROJECT_ID/roles/$PROVISIONER_ROLE_ID" \
    "$PROVISIONER_PRINCIPAL" \
    "projects/$PROJECT_ID/roles/$DEPLOYER_ROLE_ID" \
    "$DEPLOYER_PRINCIPAL" \
    "projects/$PROJECT_ID/roles/$RECOVERY_ROLE_ID" \
    "${RECOVERY_MEMBERS[@]}" <<'PY' || \
    lane_die "control-plane IAM verification failed; refusing owner or default-role cleanup"
import json
from pathlib import Path
import sys

policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
(
    mode,
    provisioner_role,
    provisioner_principal,
    deployer_role,
    deployer_principal,
    recovery_role,
    *recovery_principals,
) = sys.argv[2:]

role_members = {
    provisioner_role: set(),
    deployer_role: set(),
    recovery_role: set(),
}
conditional_roles = set()
owner_bindings = []
for binding in policy.get("bindings", []):
    members = set(binding.get("members", []))
    role = binding.get("role")
    if role in role_members:
        if binding.get("condition"):
            conditional_roles.add(role)
        else:
            role_members[role].update(members)
    if role == "roles/owner":
        owner_bindings.append(binding)

if provisioner_principal not in role_members[provisioner_role]:
    raise SystemExit("provisioner custom role is not readable")
if mode == "provisioner":
    raise SystemExit(0)
if deployer_principal not in role_members[deployer_role]:
    raise SystemExit("deployer custom role is not readable")
missing_recovery = set(recovery_principals) - role_members[recovery_role]
if missing_recovery:
    raise SystemExit(
        "recovery custom role is missing: "
        + ", ".join(sorted(missing_recovery))
    )
if mode == "custody":
    raise SystemExit(0)
if mode != "exact":
    raise SystemExit("unknown recovery verification mode")
expected = {
    provisioner_role: {provisioner_principal},
    deployer_role: {deployer_principal},
    recovery_role: set(recovery_principals),
}
if role_members != expected or conditional_roles:
    raise SystemExit("custom control-plane role bindings are not exact")
if owner_bindings:
    raise SystemExit("roles/owner remains after control-plane reconciliation")
PY
}

reconcile_control_plane_policy() {
  local current="$PROVISION_TMPDIR/control-policy-current.json"
  local desired="$PROVISION_TMPDIR/control-policy-desired.json"
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --format=json > "$current"
  python3 - "$current" "$desired" \
    "projects/$PROJECT_ID/roles/$PROVISIONER_ROLE_ID" \
    "$PROVISIONER_PRINCIPAL" \
    "projects/$PROJECT_ID/roles/$DEPLOYER_ROLE_ID" \
    "$DEPLOYER_PRINCIPAL" \
    "projects/$PROJECT_ID/roles/$RECOVERY_ROLE_ID" \
    "${RECOVERY_MEMBERS[@]}" <<'PY' || \
    lane_die "control-plane policy reconciliation failed"
import json
import os
from pathlib import Path
import sys

(
    source,
    destination,
    provisioner_role,
    provisioner_principal,
    deployer_role,
    deployer_principal,
    recovery_role,
    *recovery_principals,
) = sys.argv[1:]
policy = json.loads(Path(source).read_text(encoding="utf-8"))
managed_roles = {provisioner_role, deployer_role, recovery_role}
bindings = []
for binding in policy.get("bindings", []):
    if binding.get("role") in managed_roles:
        continue
    if binding.get("role") == "roles/owner":
        continue
    bindings.append(binding)
bindings.extend(
    [
        {
            "role": provisioner_role,
            "members": [provisioner_principal],
        },
        {
            "role": deployer_role,
            "members": [deployer_principal],
        },
        {
            "role": recovery_role,
            "members": recovery_principals,
        },
    ]
)
policy["bindings"] = bindings
descriptor = os.open(
    destination,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    0o600,
)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(policy, handle, sort_keys=True)
    handle.write("\n")
PY
  gcloud projects set-iam-policy "$PROJECT_ID" "$desired" \
    --quiet >/dev/null
}

member_has_editor() {
  local policy_file=$1 member=$2
  python3 - "$policy_file" "$member" <<'PY'
import json
from pathlib import Path
import sys

policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for binding in policy.get("bindings", []):
    if (
        binding.get("role") == "roles/editor"
        and not binding.get("condition")
        and sys.argv[2] in binding.get("members", [])
    ):
        raise SystemExit(0)
raise SystemExit(1)
PY
}

remove_default_editors() {
  local project_number policy_file member
  project_number=$(gcloud projects describe "$PROJECT_ID" \
    --format='value(projectNumber)')
  [[ "$project_number" =~ ^[1-9][0-9]{5,29}$ ]] \
    || lane_die "unable to resolve project number"
  policy_file="$PROVISION_TMPDIR/project-policy-before-editor-cleanup.json"
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --format=json > "$policy_file"
  for member in \
    "serviceAccount:$project_number-compute@developer.gserviceaccount.com" \
    "serviceAccount:$PROJECT_ID@appspot.gserviceaccount.com"; do
    if member_has_editor "$policy_file" "$member"; then
      gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
        "--member=$member" --role=roles/editor --condition=None --quiet
    fi
  done
}

apply_provisioning() {
  ensure_project
  gcloud services enable "${REQUIRED_APIS[@]}" \
    "--project=$PROJECT_ID" --quiet
  ensure_custom_role "$PROVISIONER_ROLE_ID" \
    "EMILIA consequence provisioner" \
    "JIT infrastructure and IAM reconciliation; never a runtime principal" \
    "${PROVISIONER_PERMISSIONS[@]}"
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=$PROVISIONER_PRINCIPAL" \
    "--role=projects/$PROJECT_ID/roles/$PROVISIONER_ROLE_ID" \
    --condition=None --quiet
  verify_control_plane_policy provisioner
  ensure_service_account "$ACTUATOR_SERVICE_ACCOUNT" \
    "EMILIA consequence actuator"
  ensure_service_account "$DECISION_SERVICE_ACCOUNT" \
    "EMILIA consequence decision"
  ensure_service_account "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
    "EMILIA permissionless stable bootstrap actuator"
  ensure_service_account "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT" \
    "EMILIA permissionless stable bootstrap decision"
  ensure_artifact_repository
  ensure_network
  ensure_subnet
  ensure_nat
  ensure_custom_role "$DEPLOYER_ROLE_ID" \
    "EMILIA consequence deployer" \
    "Steady-state zero-secret-payload Cloud Run deployment and observation" \
    "${DEPLOYER_PERMISSIONS[@]}"
  ensure_custom_role "$RECOVERY_ROLE_ID" \
    "EMILIA consequence break-glass recovery" \
    "IAM control-plane restoration without runtime impersonation or data access" \
    "${RECOVERY_PERMISSIONS[@]}"
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=$DEPLOYER_PRINCIPAL" \
    "--role=projects/$PROJECT_ID/roles/$DEPLOYER_ROLE_ID" \
    --condition=None --quiet

  local member
  for member in "${RECOVERY_MEMBERS[@]}"; do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
      "--member=$member" \
      "--role=projects/$PROJECT_ID/roles/$RECOVERY_ROLE_ID" \
      --condition=None --quiet
  done
  verify_control_plane_policy custody
  reconcile_control_plane_policy
  verify_control_plane_policy exact
  gcloud resource-manager org-policies enable-enforce \
    constraints/iam.automaticIamGrantsForDefaultServiceAccounts \
    "--project=$PROJECT_ID" --quiet
  remove_default_editors
  verify_control_plane_policy exact
  printf 'dedicated consequence-control project provisioned: %s\n' "$PROJECT_ID"
  printf 'steady-state deployer has no secret payload, token minting, or persistent actAs grant\n'
}

jit_condition() {
  printf "expression=request.time < timestamp('%s'),title=emilia-jit-actas,description=Time-bounded Cloud Run rollout" \
    "$JIT_ACTAS_EXPIRES_AT"
}

change_jit_actas() {
  local operation=$1 account email condition
  condition=$(jit_condition)
  for account in "$ACTUATOR_SERVICE_ACCOUNT" "$DECISION_SERVICE_ACCOUNT"; do
    email="$account@$PROJECT_ID.iam.gserviceaccount.com"
    if [[ "$operation" == grant ]]; then
      gcloud iam service-accounts add-iam-policy-binding "$email" \
        "--project=$PROJECT_ID" "--member=$DEPLOYER_PRINCIPAL" \
        --role=roles/iam.serviceAccountUser "--condition=$condition" --quiet
    else
      gcloud iam service-accounts remove-iam-policy-binding "$email" \
        "--project=$PROJECT_ID" "--member=$DEPLOYER_PRINCIPAL" \
        --role=roles/iam.serviceAccountUser "--condition=$condition" --quiet
    fi
  done
  printf '%s time-bounded rollout actAs on both runtime identities\n' "$operation"
}

validate_provision_config
if [[ "$MODE" == render ]]; then
  render_plan
  exit 0
fi

if [[ "$ACTION" == provision ]]; then
  require_provision_approval
else
  require_rollout_approval
fi
require_active_provisioner

PROVISION_TMPDIR=$(mktemp -d)
trap 'rm -rf "$PROVISION_TMPDIR"' EXIT
case "$ACTION" in
  provision)
    apply_provisioning
    ;;
  grant-jit-actas)
    change_jit_actas grant
    ;;
  revoke-jit-actas)
    change_jit_actas revoke
    ;;
  *)
    lane_die "unsupported action: $ACTION"
    ;;
esac
