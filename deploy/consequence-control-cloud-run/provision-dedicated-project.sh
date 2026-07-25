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
if grep -Eq \
    '^(PROVISIONING_APPROVED|PROVISIONING_CONFIRM_PROJECT|ROLLOUT_APPROVED|ROLLOUT_CONFIRM_PROJECT)=' \
    "$CONFIG"; then
  lane_die "approval controls must not be stored in the provisioning config"
fi
load_lane_config "$CONFIG"

: "${PROJECT_NAME:=EMILIA consequence control}"
: "${ARTIFACT_REPOSITORY:=runtime}"
: "${ROUTER:=emilia-egress-router}"
: "${NAT:=emilia-egress-nat}"
: "${PROJECT_PARENT:=}"

PROVISIONER_ROLE_ID=emiliaConsequenceProvisioner
DEPLOYER_ROLE_ID=emiliaConsequenceDeployer
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
  run.services.update
  secretmanager.secrets.get
  secretmanager.secrets.getIamPolicy
  secretmanager.versions.get
  secretmanager.versions.list
  serviceusage.services.get
  serviceusage.services.list
  serviceusage.services.use
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
    DECISION_SERVICE_ACCOUNT DEPLOYER_PRINCIPAL RECOVERY_PRINCIPALS
    NETWORK SUBNET SUBNET_CIDR ARTIFACT_REPOSITORY ROUTER NAT
  )
  local name member
  for name in "${required[@]}"; do require_var "$name"; done
  validate_project_id
  [[ "$BILLING_ACCOUNT" =~ ^[A-Fa-f0-9]{6}-[A-Fa-f0-9]{6}-[A-Fa-f0-9]{6}$ ]] \
    || lane_die "BILLING_ACCOUNT must use the canonical XXXXXX-XXXXXX-XXXXXX form"
  validate_region
  validate_account_id ACTUATOR_SERVICE_ACCOUNT
  validate_account_id DECISION_SERVICE_ACCOUNT
  [[ "$ACTUATOR_SERVICE_ACCOUNT" != "$DECISION_SERVICE_ACCOUNT" ]] \
    || lane_die "runtime service accounts must be distinct"
  [[ "$DEPLOYER_PRINCIPAL" == serviceAccount:* ]] \
    || lane_die "DEPLOYER_PRINCIPAL must be a serviceAccount principal"
  validate_principal "$DEPLOYER_PRINCIPAL"
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
  ((${#RECOVERY_MEMBERS[@]} > 0)) \
    || lane_die "at least one RECOVERY_PRINCIPALS member is required"
  for member in "${RECOVERY_MEMBERS[@]}"; do
    validate_principal "$member"
    [[ "$member" != "$DEPLOYER_PRINCIPAL" ]] \
      || lane_die "DEPLOYER_PRINCIPAL must not be a recovery owner"
  done
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

  printf '# create isolated runtime identities without keys\n'
  shell_join gcloud iam service-accounts create "$ACTUATOR_SERVICE_ACCOUNT" \
    "--project=$PROJECT_ID" \
    "--display-name=EMILIA consequence actuator"
  shell_join gcloud iam service-accounts create "$DECISION_SERVICE_ACCOUNT" \
    "--project=$PROJECT_ID" \
    "--display-name=EMILIA consequence decision"

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

  render_custom_role "$PROVISIONER_ROLE_ID" \
    "EMILIA consequence provisioner" \
    "JIT infrastructure and IAM reconciliation; never a runtime principal" \
    "${PROVISIONER_PERMISSIONS[@]}"
  render_custom_role "$DEPLOYER_ROLE_ID" \
    "EMILIA consequence deployer" \
    "Steady-state zero-secret-payload Cloud Run deployment and observation" \
    "${DEPLOYER_PERMISSIONS[@]}"
  shell_join gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=$DEPLOYER_PRINCIPAL" \
    "--role=projects/$PROJECT_ID/roles/$DEPLOYER_ROLE_ID" --condition=None

  printf '# establish explicit recovery owners\n'
  local member
  for member in "${RECOVERY_MEMBERS[@]}"; do
    shell_join gcloud projects add-iam-policy-binding "$PROJECT_ID" \
      "--member=$member" --role=roles/owner --condition=None
  done
  printf '# verify explicit recovery owners before cleanup\n'
  printf '# verify-recovery-owner: each configured member must be an unconditional owner\n'
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

verify_recovery_owners() {
  local policy_file="$PROVISION_TMPDIR/project-policy.json"
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --format=json > "$policy_file"
  python3 - "$policy_file" "${RECOVERY_MEMBERS[@]}" <<'PY' || \
    lane_die "recovery owner verification failed; refusing default grant cleanup"
import json
from pathlib import Path
import sys

policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
owners = set()
for binding in policy.get("bindings", []):
    if binding.get("role") == "roles/owner" and not binding.get("condition"):
        owners.update(binding.get("members", []))
missing = [member for member in sys.argv[2:] if member not in owners]
if missing:
    print("missing unconditional recovery owners: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)
PY
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
  ensure_service_account "$ACTUATOR_SERVICE_ACCOUNT" \
    "EMILIA consequence actuator"
  ensure_service_account "$DECISION_SERVICE_ACCOUNT" \
    "EMILIA consequence decision"
  ensure_artifact_repository
  ensure_network
  ensure_subnet
  ensure_nat
  ensure_custom_role "$PROVISIONER_ROLE_ID" \
    "EMILIA consequence provisioner" \
    "JIT infrastructure and IAM reconciliation; never a runtime principal" \
    "${PROVISIONER_PERMISSIONS[@]}"
  ensure_custom_role "$DEPLOYER_ROLE_ID" \
    "EMILIA consequence deployer" \
    "Steady-state zero-secret-payload Cloud Run deployment and observation" \
    "${DEPLOYER_PERMISSIONS[@]}"
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=$DEPLOYER_PRINCIPAL" \
    "--role=projects/$PROJECT_ID/roles/$DEPLOYER_ROLE_ID" \
    --condition=None --quiet

  local member
  for member in "${RECOVERY_MEMBERS[@]}"; do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
      "--member=$member" --role=roles/owner --condition=None --quiet
  done
  verify_recovery_owners
  gcloud resource-manager org-policies enable-enforce \
    constraints/iam.automaticIamGrantsForDefaultServiceAccounts \
    "--project=$PROJECT_ID" --quiet
  remove_default_editors
  verify_recovery_owners
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
