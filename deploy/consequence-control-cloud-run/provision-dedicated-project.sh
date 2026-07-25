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
if [[ "$MODE" == apply ]]; then
  export REQUIRE_DEPLOYMENT_CONFIG_PIN=true
fi
PROVISION_CONFIG_KEYS=()
while IFS= read -r name; do
  PROVISION_CONFIG_KEYS+=("$name")
done < <(provision_config_variables)
load_lane_config "$CONFIG" "${PROVISION_CONFIG_KEYS[@]}"

: "${PROJECT_NAME:=EMILIA consequence control}"
: "${ARTIFACT_REPOSITORY:=runtime}"
: "${ROUTER:=emilia-egress-router}"
: "${NAT:=emilia-egress-nat}"
: "${PROJECT_PARENT:=}"

DEPLOYER_ROLE_ID=emiliaConsequenceDeployer
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
  cloudkms.googleapis.com
  cloudresourcemanager.googleapis.com
  compute.googleapis.com
  iam.googleapis.com
  iamcredentials.googleapis.com
  logging.googleapis.com
  monitoring.googleapis.com
  orgpolicy.googleapis.com
  privilegedaccessmanager.googleapis.com
  run.googleapis.com
  secretmanager.googleapis.com
  serviceusage.googleapis.com
)
KEYLESS_CONTROL_APIS=(
  cloudresourcemanager.googleapis.com
  iam.googleapis.com
  orgpolicy.googleapis.com
  serviceusage.googleapis.com
)
KEYLESS_ORG_CONSTRAINTS=(
  constraints/iam.automaticIamGrantsForDefaultServiceAccounts
  constraints/iam.disableServiceAccountKeyCreation
  constraints/iam.disableServiceAccountKeyUpload
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
    DEPLOYER_PRINCIPAL RECOVERY_PAM_ENTITLEMENT RECOVERY_PAM_ROLE
    ACTUATOR_SERVICE DECISION_SERVICE NETWORK SUBNET SUBNET_CIDR
    ARTIFACT_REPOSITORY ROUTER NAT
    STABLE_RELEASE_KMS_KEY_URI
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
  [[ "$DEPLOYER_PRINCIPAL" == \
      serviceAccount:*@"$PROJECT_ID".iam.gserviceaccount.com ]] \
    || lane_die "DEPLOYER_PRINCIPAL must belong to the dedicated PROJECT_ID"
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
  [[ "$PROJECT_PARENT" =~ ^organizations/[1-9][0-9]*$ ]] \
    || lane_die "production provisioning requires PROJECT_PARENT=organizations/NUMBER"
  [[ -z "${RECOVERY_PRINCIPALS:-}" ]] \
    || lane_die "RECOVERY_PRINCIPALS is forbidden; recovery must be an external multi-approval PAM entitlement"
  [[ "$RECOVERY_PAM_ENTITLEMENT" =~ ^[a-z][a-z0-9-]{3,62}$ ]] \
    || lane_die "RECOVERY_PAM_ENTITLEMENT must be an external PAM entitlement ID"
  [[ "$RECOVERY_PAM_ROLE" =~ ^organizations/${PROJECT_PARENT#organizations/}/roles/[A-Za-z][A-Za-z0-9_.]{2,63}$ ]] \
    || lane_die "RECOVERY_PAM_ROLE must be a custom role in the pinned organization"
  if [[ "$STABLE_RELEASE_KMS_KEY_URI" =~ ^gcp-kms://projects/([^/]+)/locations/([^/]+)/keyRings/([a-z][a-z0-9_-]{0,62})/cryptoKeys/([a-z][a-z0-9_-]{0,62})/cryptoKeyVersions/([1-9][0-9]*)$ ]]; then
    STABLE_KMS_PROJECT=${BASH_REMATCH[1]}
    STABLE_KMS_LOCATION=${BASH_REMATCH[2]}
    STABLE_KMS_KEYRING=${BASH_REMATCH[3]}
    STABLE_KMS_KEY=${BASH_REMATCH[4]}
    STABLE_KMS_VERSION=${BASH_REMATCH[5]}
  else
    lane_die "STABLE_RELEASE_KMS_KEY_URI must pin one versioned Cloud KMS key"
  fi
  [[ "$STABLE_KMS_PROJECT" == "$PROJECT_ID" \
      && "$STABLE_KMS_LOCATION" == "$REGION" \
      && "$STABLE_KMS_VERSION" == 1 ]] \
    || lane_die "stable-release KMS must be version 1 in the dedicated project and region"
  validate_slug ACTUATOR_SERVICE
  validate_slug DECISION_SERVICE
  local variable
  while IFS= read -r variable; do
    require_var "$variable"
    validate_secret_ref "$variable"
  done < <(all_secret_variables)
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
    "--organization=${PROJECT_PARENT#organizations/}"
  )

  printf '# refuse every existing project; create one organization-parented dedicated project\n'
  shell_join gcloud projects describe "$PROJECT_ID" --format=json
  shell_join "${project_create[@]}"
  shell_join gcloud billing projects link "$PROJECT_ID" \
    "--billing-account=$BILLING_ACCOUNT"
  printf '# prove exact parent, ancestry, and immutable dedication label before any resource creation\n'
  shell_join gcloud projects describe "$PROJECT_ID" --format=json
  shell_join gcloud projects get-ancestors "$PROJECT_ID" --format=json --quiet
  printf '# enable only the keyless-policy control plane first\n'
  shell_join gcloud services enable "${KEYLESS_CONTROL_APIS[@]}" \
    "--project=$PROJECT_ID"
  printf '# forbid default broad grants and every user-managed service-account key before enabling workload APIs\n'
  local constraint
  for constraint in "${KEYLESS_ORG_CONSTRAINTS[@]}"; do
    shell_join gcloud resource-manager org-policies enable-enforce \
      "$constraint" "--project=$PROJECT_ID"
    shell_join gcloud resource-manager org-policies describe \
      "$constraint" "--project=$PROJECT_ID" --effective --format=json
  done
  printf '# enable the complete runtime and assurance control plane\n'
  shell_join gcloud services enable "${REQUIRED_APIS[@]}" "--project=$PROJECT_ID"

  printf '# create the isolated deploy, runtime, and stable-bootstrap identities without keys\n'
  shell_join gcloud iam service-accounts create \
    "$(deployer_service_account_id)" \
    "--project=$PROJECT_ID" \
    "--display-name=EMILIA protected consequence deployer"
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
  shell_join gcloud iam service-accounts keys list \
    '--iam-account=<each protected service account>' \
    "--project=$PROJECT_ID" --format=json
  printf '# create and close the HSM-backed Ed25519 stable-release signer to the keyless deployer\n'
  shell_join gcloud kms keyrings create "$STABLE_KMS_KEYRING" \
    "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION"
  shell_join gcloud kms keys create "$STABLE_KMS_KEY" \
    "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" \
    "--keyring=$STABLE_KMS_KEYRING" --purpose=asymmetric-signing \
    --default-algorithm=ec-sign-ed25519 --protection-level=hsm
  shell_join gcloud kms keys versions describe "$STABLE_KMS_VERSION" \
    "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" \
    "--keyring=$STABLE_KMS_KEYRING" "--key=$STABLE_KMS_KEY" --format=json
  shell_join gcloud kms keys set-iam-policy "$STABLE_KMS_KEY" \
    '<closed-kms-policy.json>' "--project=$PROJECT_ID" \
    "--location=$STABLE_KMS_LOCATION" "--keyring=$STABLE_KMS_KEYRING"

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
    "Protected-workflow-only Cloud Run deployment and observation; no IAM writes" \
    "${DEPLOYER_PERMISSIONS[@]}"
  shell_join gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=$DEPLOYER_PRINCIPAL" \
    "--role=projects/$PROJECT_ID/roles/$DEPLOYER_ROLE_ID" --condition=None
  printf '# establish fixed runtime actAs and project-level actuator invocation for the protected deploy identity\n'
  shell_join gcloud iam service-accounts add-iam-policy-binding \
    "$ACTUATOR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com" \
    "--project=$PROJECT_ID" "--member=$DEPLOYER_PRINCIPAL" \
    --role=roles/iam.serviceAccountUser --condition=None
  shell_join gcloud iam service-accounts add-iam-policy-binding \
    "$DECISION_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com" \
    "--project=$PROJECT_ID" "--member=$DEPLOYER_PRINCIPAL" \
    --role=roles/iam.serviceAccountUser --condition=None
  shell_join gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=serviceAccount:$DECISION_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com" \
    --role=roles/run.invoker \
    "--condition=expression=resource.name == '//run.googleapis.com/projects/$PROJECT_ID/locations/$REGION/services/$ACTUATOR_SERVICE',title=emilia-actuator-invoker,description=Decision workload may invoke only the actuator"
  printf '# close every configured secret directly to its exact runtime identities during one-time provisioning\n'
  shell_join gcloud secrets get-iam-policy '<configured-secret>' \
    "--project=$PROJECT_ID" --format=json
  shell_join gcloud secrets set-iam-policy '<configured-secret>' \
    '<closed-secret-policy.json>' "--project=$PROJECT_ID"
  printf '# verify an organization-owned PAM entitlement with at least two approvals; no project recovery principal is created\n'
  shell_join gcloud pam entitlements describe "$RECOVERY_PAM_ENTITLEMENT" \
    --location=global "--organization=${PROJECT_PARENT#organizations/}" \
    --format=json
  printf '# remove broad default Editor grants before the final custody transition\n'
  shell_join gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
    '--member=serviceAccount:<PROJECT_NUMBER>-compute@developer.gserviceaccount.com' \
    --role=roles/editor --condition=None
  shell_join gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
    "--member=serviceAccount:$PROJECT_ID@appspot.gserviceaccount.com" \
    --role=roles/editor --condition=None
  printf '# final operation reconciles exact steady-state custody and removes every owner/editor/provisioner binding\n'
  shell_join python3 '<rewrite-control-plane-policy-exactly>' \
    '<current-project-policy.json>' '<closed-project-policy.json>'
  shell_join gcloud projects set-iam-policy "$PROJECT_ID" \
    '<closed-project-policy.json>'
}

create_project_once() {
  if gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
    lane_die "PROJECT_ID already exists; production provisioning is new-project-only and never relabels or adopts"
  fi
  gcloud projects create "$PROJECT_ID" \
    "--name=$PROJECT_NAME" \
    "--labels=emilia-purpose=consequence-control" \
    "--organization=${PROJECT_PARENT#organizations/}" --quiet
  gcloud billing projects link "$PROJECT_ID" \
    "--billing-account=$BILLING_ACCOUNT" --quiet
}

verify_dedicated_project_identity() {
  local project="$PROVISION_TMPDIR/project.json"
  local ancestry="$PROVISION_TMPDIR/ancestry.json"
  gcloud projects describe "$PROJECT_ID" --format=json > "$project"
  gcloud projects get-ancestors "$PROJECT_ID" --format=json --quiet > "$ancestry"
  python3 - "$project" "$ancestry" "$PROJECT_ID" \
    "${PROJECT_PARENT#organizations/}" <<'PY' || \
    lane_die "project parent, ancestry, or dedication label is not exact"
import json
from pathlib import Path
import sys

project_path, ancestry_path, project_id, organization_id = sys.argv[1:]
project = json.loads(Path(project_path).read_text(encoding="utf-8"))
ancestry = json.loads(Path(ancestry_path).read_text(encoding="utf-8"))
if project.get("projectId") != project_id:
    raise SystemExit("project ID mismatch")
if project.get("labels") != {"emilia-purpose": "consequence-control"}:
    raise SystemExit("dedication label is not exact")
parent = project.get("parent")
if parent != {"type": "organization", "id": organization_id}:
    raise SystemExit("project parent is not the pinned organization")
expected = {
    ("project", project_id),
    ("organization", organization_id),
}
actual = {
    (entry.get("type"), entry.get("id"))
    for entry in ancestry
    if isinstance(entry, dict)
}
if actual != expected or len(ancestry) != 2:
    raise SystemExit("project ancestry is not exactly project plus organization")
PY
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

deployer_service_account_id() {
  local email=${DEPLOYER_PRINCIPAL#serviceAccount:}
  printf '%s' "${email%%@*}"
}

enforce_keyless_org_policies() {
  local constraint policy_file
  for constraint in "${KEYLESS_ORG_CONSTRAINTS[@]}"; do
    gcloud resource-manager org-policies enable-enforce "$constraint" \
      "--project=$PROJECT_ID" --quiet
    policy_file="$PROVISION_TMPDIR/policy-${constraint##*/}.json"
    gcloud resource-manager org-policies describe "$constraint" \
      "--project=$PROJECT_ID" --effective --format=json > "$policy_file" \
      || lane_die "effective organization policy is unreadable: $constraint"
    python3 - "$policy_file" "$constraint" <<'PY' || \
      lane_die "effective organization policy is not enforced: $constraint"
import json
from pathlib import Path
import sys

policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if policy.get("constraint") != sys.argv[2]:
    raise SystemExit("constraint mismatch")
if policy.get("booleanPolicy", {}).get("enforced") is not True:
    raise SystemExit("boolean policy is not enforced")
PY
  done
}

verify_service_accounts_are_keyless() {
  local account email inventory
  local accounts=(
    "$(deployer_service_account_id)"
    "$ACTUATOR_SERVICE_ACCOUNT"
    "$DECISION_SERVICE_ACCOUNT"
    "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT"
    "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT"
  )
  for account in "${accounts[@]}"; do
    email="$account@$PROJECT_ID.iam.gserviceaccount.com"
    inventory="$PROVISION_TMPDIR/keys-$account.json"
    gcloud iam service-accounts keys list \
      "--iam-account=$email" "--project=$PROJECT_ID" --format=json \
      > "$inventory" \
      || lane_die "service-account key inventory is unreadable: $email"
    python3 - "$inventory" "$email" <<'PY' || \
      lane_die "user-managed service-account key is forbidden: $email"
import json
from pathlib import Path
import sys

inventory = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(inventory, list):
    raise SystemExit("key inventory is malformed")
for key in inventory:
    if not isinstance(key, dict):
        raise SystemExit("key record is malformed")
    if key.get("keyType") == "USER_MANAGED" or key.get("keyOrigin") == "USER_PROVIDED":
        raise SystemExit(f"user-managed key exists for {sys.argv[2]}")
PY
  done
}

ensure_stable_release_kms_key() {
  local metadata="$PROVISION_TMPDIR/stable-kms-version.json"
  local current="$PROVISION_TMPDIR/stable-kms-current-policy.json"
  local desired="$PROVISION_TMPDIR/stable-kms-desired-policy.json"
  local verified="$PROVISION_TMPDIR/stable-kms-verified-policy.json"
  if ! gcloud kms keyrings describe "$STABLE_KMS_KEYRING" \
      "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" \
      >/dev/null 2>&1; then
    gcloud kms keyrings create "$STABLE_KMS_KEYRING" \
      "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" --quiet
  fi
  if ! gcloud kms keys describe "$STABLE_KMS_KEY" \
      "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" \
      "--keyring=$STABLE_KMS_KEYRING" >/dev/null 2>&1; then
    gcloud kms keys create "$STABLE_KMS_KEY" \
      "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" \
      "--keyring=$STABLE_KMS_KEYRING" --purpose=asymmetric-signing \
      --default-algorithm=ec-sign-ed25519 --protection-level=hsm --quiet
  fi
  gcloud kms keys versions describe "$STABLE_KMS_VERSION" \
    "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" \
    "--keyring=$STABLE_KMS_KEYRING" "--key=$STABLE_KMS_KEY" \
    --format=json > "$metadata" \
    || lane_die "stable-release KMS version is unreadable"
  python3 - "$metadata" "$STABLE_RELEASE_KMS_KEY_URI" <<'PY' || \
    lane_die "stable-release KMS version is not the pinned HSM Ed25519 signer"
import json
from pathlib import Path
import sys

metadata = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_name = sys.argv[2].removeprefix("gcp-kms://")
if metadata.get("name") != expected_name:
    raise SystemExit("KMS version resource mismatch")
if metadata.get("state") != "ENABLED":
    raise SystemExit("KMS version is not enabled")
if metadata.get("algorithm") != "EC_SIGN_ED25519":
    raise SystemExit("KMS algorithm mismatch")
if metadata.get("protectionLevel") != "HSM":
    raise SystemExit("KMS signer is not HSM protected")
PY
  gcloud kms keys get-iam-policy "$STABLE_KMS_KEY" \
    "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" \
    "--keyring=$STABLE_KMS_KEYRING" --format=json > "$current"
  python3 "$LANE_DIR/reconcile-iam-policy.py" rewrite \
    --input "$current" --output "$desired" \
    --role roles/cloudkms.signerVerifier --member "$DEPLOYER_PRINCIPAL"
  gcloud kms keys set-iam-policy "$STABLE_KMS_KEY" "$desired" \
    "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" \
    "--keyring=$STABLE_KMS_KEYRING" --quiet >/dev/null
  gcloud kms keys get-iam-policy "$STABLE_KMS_KEY" \
    "--project=$PROJECT_ID" "--location=$STABLE_KMS_LOCATION" \
    "--keyring=$STABLE_KMS_KEYRING" --format=json > "$verified"
  python3 - "$verified" "$DEPLOYER_PRINCIPAL" <<'PY' || \
    lane_die "stable-release KMS IAM is not closed to the keyless deployer"
import json
from pathlib import Path
import sys

policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if policy.get("bindings") != [{
    "role": "roles/cloudkms.signerVerifier",
    "members": [sys.argv[2]],
}]:
    raise SystemExit("unexpected KMS IAM binding")
PY
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

verify_external_recovery_quorum() {
  local organization_id=${PROJECT_PARENT#organizations/}
  local entitlement="$PROVISION_TMPDIR/recovery-entitlement.json"
  local role="$PROVISION_TMPDIR/recovery-role.json"
  gcloud pam entitlements describe "$RECOVERY_PAM_ENTITLEMENT" \
    --location=global "--organization=$organization_id" \
    --format=json > "$entitlement" \
    || lane_die "external organization PAM recovery entitlement is unavailable"
  gcloud iam roles describe "${RECOVERY_PAM_ROLE##*/}" \
    "--organization=$organization_id" --format=json > "$role" \
    || lane_die "external organization PAM recovery role is unavailable"
  python3 - "$entitlement" "$role" "$PROJECT_ID" \
    "$RECOVERY_PAM_ROLE" "$PROVISIONER_PRINCIPAL" "$DEPLOYER_PRINCIPAL" <<'PY' \
    || lane_die "external recovery is not an organization-owned multi-approval PAM boundary"
import json
from pathlib import Path
import sys

entitlement_path, role_path, project_id, role_name, provisioner, deployer = sys.argv[1:]
entitlement = json.loads(Path(entitlement_path).read_text(encoding="utf-8"))
role = json.loads(Path(role_path).read_text(encoding="utf-8"))
access = entitlement.get("privilegedAccess", {}).get("gcpIamAccess", {})
if access.get("resourceType") != "cloudresourcemanager.googleapis.com/Project":
    raise SystemExit("PAM recovery resource type is not Project")
if access.get("resource") != f"//cloudresourcemanager.googleapis.com/projects/{project_id}":
    raise SystemExit("PAM recovery does not target the dedicated project exactly")
bindings = access.get("roleBindings")
if bindings != [{"role": role_name}]:
    raise SystemExit("PAM recovery must grant exactly the pinned recovery role")
manual = entitlement.get("approvalWorkflow", {}).get("manualApprovals", {})
if manual.get("requireApproverJustification") is not True:
    raise SystemExit("PAM recovery requires approver justification")
steps = manual.get("steps")
if not isinstance(steps, list) or len(steps) != 1:
    raise SystemExit("PAM recovery requires one exact approval step")
if steps[0].get("approvalsNeeded", 0) < 2:
    raise SystemExit("PAM recovery requires at least two approvals")
approvers = {
    principal
    for entry in steps[0].get("approvers", [])
    for principal in entry.get("principals", [])
}
if len(approvers) < 2:
    raise SystemExit("PAM recovery does not identify two external approvers")
eligible = {
    principal
    for entry in entitlement.get("eligibleUsers", [])
    for principal in entry.get("principals", [])
}
if not eligible or {provisioner, deployer} & (eligible | approvers):
    raise SystemExit("provisioner/deployer must not request or approve recovery")
if set(role.get("includedPermissions", [])) != {
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.setIamPolicy",
}:
    raise SystemExit("PAM recovery role is not the exact project-IAM-only role")
PY
}

reconcile_secret_accessors_once() {
  local variable ref secret members=() member_args=()
  while IFS= read -r secret; do
    members=()
    member_args=()
    if secret_is_used_by "$secret" actuator_secret_variables; then
      members+=("serviceAccount:$ACTUATOR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com")
    fi
    if secret_is_used_by "$secret" decision_secret_variables; then
      members+=("serviceAccount:$DECISION_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com")
    fi
    for member in "${members[@]}"; do member_args+=(--member "$member"); done
    local current="$PROVISION_TMPDIR/secret-$secret-current.json"
    local desired="$PROVISION_TMPDIR/secret-$secret-desired.json"
    local verified="$PROVISION_TMPDIR/secret-$secret-verified.json"
    if ! gcloud secrets describe "$secret" \
        "--project=$PROJECT_ID" >/dev/null 2>&1; then
      gcloud secrets create "$secret" \
        "--project=$PROJECT_ID" --replication-policy=automatic --quiet
    fi
    gcloud secrets get-iam-policy "$secret" \
      "--project=$PROJECT_ID" --format=json > "$current"
    python3 "$LANE_DIR/reconcile-iam-policy.py" rewrite \
      --input "$current" --output "$desired" \
      --role roles/secretmanager.secretAccessor "${member_args[@]}"
    gcloud secrets set-iam-policy "$secret" "$desired" \
      "--project=$PROJECT_ID" --quiet >/dev/null
    gcloud secrets get-iam-policy "$secret" \
      "--project=$PROJECT_ID" --format=json > "$verified"
    python3 "$LANE_DIR/reconcile-iam-policy.py" check \
      --input "$verified" --role roles/secretmanager.secretAccessor \
      "${member_args[@]}" \
      || lane_die "secret IAM readback is not exact: $secret"
  done < <(
    while IFS= read -r variable; do
      ref=${!variable}
      secret_name "$ref"
      printf '\n'
    done < <(all_secret_variables) | sort -u
  )
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

bind_fixed_deployment_access() {
  local account email
  for account in "$ACTUATOR_SERVICE_ACCOUNT" "$DECISION_SERVICE_ACCOUNT"; do
    email="$account@$PROJECT_ID.iam.gserviceaccount.com"
    gcloud iam service-accounts add-iam-policy-binding "$email" \
      "--project=$PROJECT_ID" "--member=$DEPLOYER_PRINCIPAL" \
      --role=roles/iam.serviceAccountUser --condition=None --quiet >/dev/null
  done
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=serviceAccount:$DECISION_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com" \
    --role=roles/run.invoker \
    "--condition=expression=resource.name == '//run.googleapis.com/projects/$PROJECT_ID/locations/$REGION/services/$ACTUATOR_SERVICE',title=emilia-actuator-invoker,description=Decision workload may invoke only the actuator" \
    --quiet >/dev/null
}

finalize_steady_state_policy() {
  local current="$PROVISION_TMPDIR/project-policy-current.json"
  local desired="$PROVISION_TMPDIR/project-policy-final.json"
  local response="$PROVISION_TMPDIR/project-policy-response.json"
  local project_number
  project_number=$(gcloud projects describe "$PROJECT_ID" \
    --format='value(projectNumber)')
  [[ "$project_number" =~ ^[1-9][0-9]{5,29}$ ]] \
    || lane_die "unable to resolve project number"
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --format=json > "$current"
  python3 - "$current" "$desired" "$PROJECT_ID" "$project_number" \
    "$PROVISIONER_PRINCIPAL" "$DEPLOYER_PRINCIPAL" \
    "projects/$PROJECT_ID/roles/$DEPLOYER_ROLE_ID" \
    "serviceAccount:$DECISION_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com" \
    "$REGION" "$ACTUATOR_SERVICE" <<'PY' || \
    lane_die "unrelated direct IAM binding found; refusing final custody transition"
import json
import os
from pathlib import Path
import re
import sys

(
    source,
    destination,
    project_id,
    project_number,
    provisioner,
    deployer,
    deployer_role,
    decision,
    region,
    actuator_service,
) = sys.argv[1:]
policy = json.loads(Path(source).read_text(encoding="utf-8"))
service_agent = re.compile(
    rf"^serviceAccount:(service-{project_number}@|{project_number}@cloudservices[.])"
)
preserved = []
for binding in policy.get("bindings", []):
    role = binding.get("role")
    members = binding.get("members", [])
    condition = binding.get("condition")
    if not isinstance(role, str) or not isinstance(members, list):
        raise SystemExit("malformed project IAM binding")
    if provisioner in members:
        members = [member for member in members if member != provisioner]
    if role == deployer_role:
        if members != [deployer] or condition:
            raise SystemExit("deployer custom role binding is not exact")
        continue
    if role == "roles/run.invoker":
        if members != [decision]:
            raise SystemExit("actuator invoker member is not exact")
        continue
    if role in {"roles/owner", "roles/editor"}:
        unexpected = [
            member for member in members
            if not service_agent.match(member)
        ]
        if unexpected:
            raise SystemExit(
                f"unrelated {role} members: {', '.join(unexpected)}"
            )
        continue
    if role.startswith(f"projects/{project_id}/roles/"):
        raise SystemExit(f"unrelated project custom role binding: {role}")
    if not role.endswith(".serviceAgent"):
        raise SystemExit(f"unrelated project role binding: {role}")
    if condition or not members or any(not service_agent.match(member) for member in members):
        raise SystemExit(f"service-agent binding is not exact: {role}")
    preserved.append(binding)

invoker_condition = {
    "title": "emilia-actuator-invoker",
    "description": "Decision workload may invoke only the actuator",
    "expression": (
        "resource.name == "
        f"'//run.googleapis.com/projects/{project_id}/locations/{region}/"
        f"services/{actuator_service}'"
    ),
}
preserved.extend(
    [
        {"role": deployer_role, "members": [deployer]},
        {
            "role": "roles/run.invoker",
            "members": [decision],
            "condition": invoker_condition,
        },
    ]
)
policy["version"] = 3
policy["bindings"] = sorted(preserved, key=lambda item: item["role"])
descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(policy, handle, sort_keys=True)
    handle.write("\n")
PY
  gcloud projects set-iam-policy "$PROJECT_ID" "$desired" \
    --format=json --quiet > "$response"
  python3 - "$desired" "$response" <<'PY' || \
    lane_die "final project IAM response did not match the closed steady-state policy"
import json
from pathlib import Path
import sys

desired = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
response = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
desired.pop("etag", None)
response.pop("etag", None)
if desired != response:
    raise SystemExit("final policy response mismatch")
PY
}

apply_provisioning() {
  create_project_once
  verify_dedicated_project_identity
  gcloud services enable "${KEYLESS_CONTROL_APIS[@]}" \
    "--project=$PROJECT_ID" --quiet
  enforce_keyless_org_policies
  gcloud services enable "${REQUIRED_APIS[@]}" \
    "--project=$PROJECT_ID" --quiet
  ensure_service_account "$(deployer_service_account_id)" \
    "EMILIA protected consequence deployer"
  ensure_service_account "$ACTUATOR_SERVICE_ACCOUNT" \
    "EMILIA consequence actuator"
  ensure_service_account "$DECISION_SERVICE_ACCOUNT" \
    "EMILIA consequence decision"
  ensure_service_account "$STABLE_BOOTSTRAP_ACTUATOR_SERVICE_ACCOUNT" \
    "EMILIA permissionless stable bootstrap actuator"
  ensure_service_account "$STABLE_BOOTSTRAP_DECISION_SERVICE_ACCOUNT" \
    "EMILIA permissionless stable bootstrap decision"
  verify_service_accounts_are_keyless
  ensure_stable_release_kms_key
  ensure_artifact_repository
  ensure_network
  ensure_subnet
  ensure_nat
  ensure_custom_role "$DEPLOYER_ROLE_ID" \
    "EMILIA consequence deployer" \
    "Protected-workflow-only Cloud Run deployment and observation; no IAM writes" \
    "${DEPLOYER_PERMISSIONS[@]}"
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    "--member=$DEPLOYER_PRINCIPAL" \
    "--role=projects/$PROJECT_ID/roles/$DEPLOYER_ROLE_ID" \
    --condition=None --quiet

  bind_fixed_deployment_access
  reconcile_secret_accessors_once
  verify_external_recovery_quorum
  enforce_keyless_org_policies
  verify_service_accounts_are_keyless
  remove_default_editors
  finalize_steady_state_policy
  printf 'dedicated consequence-control project provisioned: %s\n' "$PROJECT_ID"
  printf 'final project policy response removed direct provisioner custody\n'
  printf 'steady-state deployer has no IAM-policy writer and recovery is external PAM quorum only\n'
}

validate_provision_config
if [[ "$MODE" == render ]]; then
  render_plan
  exit 0
fi

require_provision_approval
require_active_provisioner

PROVISION_TMPDIR=$(mktemp -d)
trap 'rm -rf "$PROVISION_TMPDIR"; lane_cleanup_pinned_config' EXIT
apply_provisioning
