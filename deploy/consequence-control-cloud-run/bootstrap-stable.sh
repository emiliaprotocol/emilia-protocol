#!/usr/bin/env bash
set -euo pipefail

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$LANE_DIR/lib/common.sh"

CONFIG=
BOOTSTRAP_ID=
PLACEHOLDER_IMAGE=
PLACEHOLDER_REPOSITORY=
SIGNING_KEY_FILE=
VERIFY_KEY_FILE=
KEY_ID=
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
      (($# >= 2)) || lane_die "--placeholder-repository requires a value"
      PLACEHOLDER_REPOSITORY=$2
      shift 2
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
    --key-id)
      (($# >= 2)) || lane_die "--key-id requires a value"
      KEY_ID=$2
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
[[ -n "$SIGNING_KEY_FILE" && "$SIGNING_KEY_FILE" == /* ]] \
  || lane_die "--private-key must be an absolute path"
[[ -n "$VERIFY_KEY_FILE" && "$VERIFY_KEY_FILE" == /* ]] \
  || lane_die "--public-key must be an absolute path"
[[ -n "$KEY_ID" ]] || lane_die "--key-id is required"
if [[ -n "$PLACEHOLDER_IMAGE" && -n "$PLACEHOLDER_REPOSITORY" ]]; then
  lane_die "select either --placeholder-image or --placeholder-repository"
fi
if [[ -z "$PLACEHOLDER_IMAGE" && -z "$PLACEHOLDER_REPOSITORY" ]]; then
  lane_die "--placeholder-image or --placeholder-repository is required"
fi

load_lane_config "$CONFIG"
validate_lane_config
[[ "$BOOTSTRAP_ID" != "$RELEASE_ID" ]] \
  || lane_die "bootstrap and candidate release ids must differ"

ACTUATOR_SA=$(runtime_service_account_email "$ACTUATOR_SERVICE_ACCOUNT")
DECISION_SA=$(runtime_service_account_email "$DECISION_SERVICE_ACCOUNT")
ACTUATOR_REVISION="$ACTUATOR_SERVICE-$BOOTSTRAP_ID"
DECISION_REVISION="$DECISION_SERVICE-$BOOTSTRAP_ID"

validate_placeholder_image() {
  local image=$1
  [[ "$image" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] \
    || lane_die "placeholder image must be pinned by lowercase sha256 digest"
}

validate_placeholder_repository() {
  [[ "$PLACEHOLDER_REPOSITORY" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+$ ]] \
    || lane_die "placeholder repository must be an Artifact Registry image path"
}

if [[ -n "$PLACEHOLDER_IMAGE" ]]; then
  validate_placeholder_image "$PLACEHOLDER_IMAGE"
else
  validate_placeholder_repository
fi

placeholder_deploy_command() {
  local service=$1 account=$2 ingress=$3
  PLACEHOLDER_DEPLOY_COMMAND=(
    gcloud run deploy "$service"
    "--project=$PROJECT_ID"
    "--region=$REGION"
    --platform=managed
    "--image=$PLACEHOLDER_IMAGE"
    "--revision-suffix=$BOOTSTRAP_ID"
    "--service-account=$account"
    "--ingress=$ingress"
    --no-allow-unauthenticated
    "--network=$NETWORK"
    "--subnet=$SUBNET"
    --vpc-egress=all-traffic
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
    "--labels=emilia-plane=bootstrap,emilia-release=$BOOTSTRAP_ID,emilia-deny-all=true"
    --quiet
  )
}

render_build() {
  local tag="$PLACEHOLDER_REPOSITORY:bootstrap-$BOOTSTRAP_ID"
  printf '# build one health-only image; every non-health route returns 403\n'
  shell_join gcloud builds submit '<generated-health-only-context>' \
    "--project=$PROJECT_ID" "--tag=$tag" --quiet
  shell_join gcloud artifacts docker images describe "$tag" \
    "--project=$PROJECT_ID" --format='value(image_summary.digest)'
  printf 'PLACEHOLDER_IMAGE=%s@<resolved-sha256-digest>\n' \
    "$PLACEHOLDER_REPOSITORY"
}

create_build_context() {
  BUILD_CONTEXT=$(mktemp -d)
  cat > "$BUILD_CONTEXT/server.py" <<'PY'
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def reply(self, status, body):
        payload = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path in ("/v1/live", "/v1/ready"):
            self.reply(200, {"status": "healthy", "mode": "deny-all-bootstrap"})
        else:
            self.reply(403, {"status": "refused", "reason": "bootstrap_deny_all"})

    def do_POST(self):
        self.reply(403, {"status": "refused", "reason": "bootstrap_deny_all"})

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST

ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
PY
  cat > "$BUILD_CONTEXT/Dockerfile" <<'DOCKER'
FROM python:3.13-alpine
RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --chown=app:app server.py /app/server.py
USER app
ENTRYPOINT ["python3", "/app/server.py"]
DOCKER
}

build_placeholder_image() {
  local tag digest
  tag="$PLACEHOLDER_REPOSITORY:bootstrap-$BOOTSTRAP_ID"
  create_build_context
  gcloud builds submit "$BUILD_CONTEXT" \
    "--project=$PROJECT_ID" "--tag=$tag" --quiet
  digest=$(gcloud artifacts docker images describe "$tag" \
    "--project=$PROJECT_ID" --format='value(image_summary.digest)')
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || lane_die "built placeholder digest could not be resolved"
  PLACEHOLDER_IMAGE="$PLACEHOLDER_REPOSITORY@$digest"
  validate_placeholder_image "$PLACEHOLDER_IMAGE"
}

render_plan() {
  if [[ -n "$PLACEHOLDER_REPOSITORY" ]]; then
    render_build
    PLACEHOLDER_IMAGE="$PLACEHOLDER_REPOSITORY@sha256:$(printf '0%.0s' {1..64})"
  fi
  printf '# refuse bootstrap if either Cloud Run service already exists\n'
  shell_join gcloud run services list \
    "--project=$PROJECT_ID" "--region=$REGION" \
    "--filter=metadata.name=($ACTUATOR_SERVICE OR $DECISION_SERVICE)" \
    --format='value(metadata.name)'
  printf '# bootstrap actuator stable revision at 100%% deny-all traffic\n'
  placeholder_deploy_command \
    "$ACTUATOR_SERVICE" "$ACTUATOR_SA" "$ACTUATOR_INGRESS"
  shell_join "${PLACEHOLDER_DEPLOY_COMMAND[@]}"
  printf '# bootstrap decision stable revision at 100%% deny-all traffic\n'
  placeholder_deploy_command \
    "$DECISION_SERVICE" "$DECISION_SA" "$DECISION_INGRESS"
  shell_join "${PLACEHOLDER_DEPLOY_COMMAND[@]}"
  printf '# record exact live rollback configuration and sign it\n'
  shell_join "$LANE_DIR/verify-stable-release.py" record \
    --config "$CONFIG" \
    --actuator-revision "$ACTUATOR_REVISION" \
    --decision-revision "$DECISION_REVISION" \
    --private-key "$SIGNING_KEY_FILE" \
    --key-id "$KEY_ID" \
    --output "$OUTPUT"
  shell_join "$LANE_DIR/verify-stable-release.py" verify \
    --config "$CONFIG" \
    --manifest "$OUTPUT" \
    --public-key "$VERIFY_KEY_FILE" \
    --live
}

if [[ "$MODE" == render ]]; then
  render_plan
  exit 0
fi

require_apply_approval
[[ -f "$SIGNING_KEY_FILE" && -f "$VERIFY_KEY_FILE" ]] \
  || lane_die "stable-release signing key pair is unavailable"
[[ ! -e "$OUTPUT" ]] \
  || lane_die "stable-release output already exists"
private_mode=$(stat -f '%Lp' "$SIGNING_KEY_FILE" 2>/dev/null \
  || stat -c '%a' "$SIGNING_KEY_FILE")
(( (8#$private_mode & 8#077) == 0 )) \
  || lane_die "stable-release private key must not be group/world accessible"
KEY_CHECK_DIR=$(mktemp -d)
trap 'rm -rf "${BUILD_CONTEXT:-}" "${KEY_CHECK_DIR:-}"' EXIT
openssl pkey -in "$SIGNING_KEY_FILE" -pubout \
  -out "$KEY_CHECK_DIR/derived-public.pem"
cmp -s "$KEY_CHECK_DIR/derived-public.pem" "$VERIFY_KEY_FILE" \
  || lane_die "stable-release signing key does not match the pinned public key"

gcloud services enable \
  run.googleapis.com compute.googleapis.com artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  "--project=$PROJECT_ID" --quiet

existing_services=$(
  gcloud run services list \
    "--project=$PROJECT_ID" "--region=$REGION" \
    "--filter=metadata.name=($ACTUATOR_SERVICE OR $DECISION_SERVICE)" \
    --format='value(metadata.name)'
)
[[ -z "$existing_services" ]] \
  || lane_die "stable bootstrap requires both Cloud Run services to be absent"

if [[ -n "$PLACEHOLDER_REPOSITORY" ]]; then
  build_placeholder_image
fi

placeholder_deploy_command \
  "$ACTUATOR_SERVICE" "$ACTUATOR_SA" "$ACTUATOR_INGRESS"
"${PLACEHOLDER_DEPLOY_COMMAND[@]}"
placeholder_deploy_command \
  "$DECISION_SERVICE" "$DECISION_SA" "$DECISION_INGRESS"
"${PLACEHOLDER_DEPLOY_COMMAND[@]}"

"$LANE_DIR/verify-stable-release.py" record \
  --config "$CONFIG" \
  --actuator-revision "$ACTUATOR_REVISION" \
  --decision-revision "$DECISION_REVISION" \
  --private-key "$SIGNING_KEY_FILE" \
  --key-id "$KEY_ID" \
  --output "$OUTPUT"
"$LANE_DIR/verify-stable-release.py" verify \
  --config "$CONFIG" \
  --manifest "$OUTPUT" \
  --public-key "$VERIFY_KEY_FILE" \
  --live

printf 'bootstrapped deny-all stable revisions: %s and %s\n' \
  "$ACTUATOR_REVISION" "$DECISION_REVISION"
printf 'signed rollback manifest: %s\n' "$OUTPUT"
