#!/usr/bin/env bash
set -euo pipefail

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(CDPATH='' cd -- "$LANE_DIR/../.." && pwd)
TRUST="$LANE_DIR/release-trust.py"
PUBLISH="$LANE_DIR/publish-release-images.py"

MODE=
CONFIG=
ARTIFACT_REPOSITORY=
EXPECTED_COMMIT=
OUTPUT=
GITHUB_OUTPUT_FILE=
while (($#)); do
  case "$1" in
    --ci)
      MODE=ci
      shift
      ;;
    --push)
      MODE=push
      shift
      ;;
    --config)
      (($# >= 2)) || { printf 'error: --config requires a path\n' >&2; exit 2; }
      CONFIG=$2
      shift 2
      ;;
    --artifact-repository)
      (($# >= 2)) || { printf 'error: --artifact-repository requires a value\n' >&2; exit 2; }
      ARTIFACT_REPOSITORY=$2
      shift 2
      ;;
    --expected-commit)
      (($# >= 2)) || { printf 'error: --expected-commit requires a value\n' >&2; exit 2; }
      EXPECTED_COMMIT=$2
      shift 2
      ;;
    --output)
      (($# >= 2)) || { printf 'error: --output requires a path\n' >&2; exit 2; }
      OUTPUT=$2
      shift 2
      ;;
    --github-output)
      (($# >= 2)) || { printf 'error: --github-output requires a path\n' >&2; exit 2; }
      GITHUB_OUTPUT_FILE=$2
      shift 2
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

[[ "$MODE" == ci || "$MODE" == push ]] || { printf 'error: exactly one of --ci or --push is required\n' >&2; exit 2; }
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { printf 'error: --expected-commit must be a lowercase Git SHA\n' >&2; exit 2; }
[[ -n "$OUTPUT" && "$OUTPUT" == /* ]] || { printf 'error: --output must be absolute\n' >&2; exit 2; }
[[ ! -e "$OUTPUT" ]] || { printf 'error: output already exists: %s\n' "$OUTPUT" >&2; exit 2; }
if [[ "$MODE" == push ]]; then
  [[ -n "$CONFIG" && "$CONFIG" == /* ]] || { printf 'error: --push requires an absolute --config\n' >&2; exit 2; }
  [[ "$ARTIFACT_REPOSITORY" =~ ^[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]] \
    || { printf 'error: --artifact-repository must be a lowercase Google Cloud slug\n' >&2; exit 2; }
  [[ -n "$GITHUB_OUTPUT_FILE" && "$GITHUB_OUTPUT_FILE" == /* ]] \
    || { printf 'error: --push requires absolute --github-output\n' >&2; exit 2; }
fi

command -v docker >/dev/null
command -v node >/dev/null
command -v npm >/dev/null
command -v python3 >/dev/null
mkdir -m 700 "$OUTPUT"

cd "$ROOT"
[[ "$(git rev-parse HEAD)" == "$EXPECTED_COMMIT" ]] \
  || { printf 'error: checkout does not match expected commit\n' >&2; exit 1; }

npm run check:standalone-runtimes
npm run check:security-case
npm run conformance:manifest:check
npm run check:proof-stats
npm --prefix packages/verify run build
npm --prefix packages/gate run build
git diff --exit-code -- packages/verify/dist packages/gate/dist \
  security/security-case.json lib/proof-stats.json conformance/conformance-manifest.json

npm pack ./packages/verify --json --pack-destination "$OUTPUT" > "$OUTPUT/verify-pack.json"
npm pack ./packages/gate --json --pack-destination "$OUTPUT" > "$OUTPUT/gate-pack.json"
npm pack ./packages/require-receipt --json --pack-destination "$OUTPUT" > "$OUTPUT/require-receipt-pack.json"
VERIFY_TARBALL=$(python3 - "$OUTPUT/verify-pack.json" "$OUTPUT" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0].get("filename"), str):
    raise SystemExit("verify npm pack output is invalid")
print(pathlib.Path(sys.argv[2], pathlib.Path(value[0]["filename"]).name))
PY
)
GATE_TARBALL=$(python3 - "$OUTPUT/gate-pack.json" "$OUTPUT" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0].get("filename"), str):
    raise SystemExit("gate npm pack output is invalid")
print(pathlib.Path(sys.argv[2], pathlib.Path(value[0]["filename"]).name))
PY
)
REQUIRE_RECEIPT_TARBALL=$(python3 - "$OUTPUT/require-receipt-pack.json" "$OUTPUT" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0].get("filename"), str):
    raise SystemExit("require-receipt npm pack output is invalid")
print(pathlib.Path(sys.argv[2], pathlib.Path(value[0]["filename"]).name))
PY
)
SOURCE_MANIFEST="$OUTPUT/source-manifest.json"
"$TRUST" source \
  --root "$ROOT" \
  --expected-commit "$EXPECTED_COMMIT" \
  --verify-tarball "$VERIFY_TARBALL" \
  --gate-tarball "$GATE_TARBALL" \
  --require-receipt-tarball "$REQUIRE_RECEIPT_TARBALL" \
  --output "$SOURCE_MANIFEST"

DOCKER_CONTEXT="$OUTPUT/docker-context"
"$TRUST" context \
  --root "$ROOT" \
  --expected-commit "$EXPECTED_COMMIT" \
  --verify-tarball "$VERIFY_TARBALL" \
  --gate-tarball "$GATE_TARBALL" \
  --require-receipt-tarball "$REQUIRE_RECEIPT_TARBALL" \
  --output "$DOCKER_CONTEXT"

mapfile -t SOURCE_LABELS < <("$TRUST" labels --source-manifest "$SOURCE_MANIFEST")
BUILD_ARGS=()
for binding in "${SOURCE_LABELS[@]}"; do
  case "$binding" in
    org.opencontainers.image.revision=*) BUILD_ARGS+=(--build-arg "EMILIA_SOURCE_REVISION=${binding#*=}") ;;
    io.emilia.source.tree=*) BUILD_ARGS+=(--build-arg "EMILIA_SOURCE_TREE=${binding#*=}") ;;
    io.emilia.source.manifest.sha256=*) BUILD_ARGS+=(--build-arg "EMILIA_SOURCE_MANIFEST_SHA256=${binding#*=}") ;;
    io.emilia.package.verify.sha256=*) BUILD_ARGS+=(--build-arg "EMILIA_VERIFY_PACKAGE_SHA256=${binding#*=}") ;;
    io.emilia.package.gate.sha256=*) BUILD_ARGS+=(--build-arg "EMILIA_GATE_PACKAGE_SHA256=${binding#*=}") ;;
    io.emilia.package.require-receipt.sha256=*) BUILD_ARGS+=(--build-arg "EMILIA_REQUIRE_RECEIPT_PACKAGE_SHA256=${binding#*=}") ;;
    io.emilia.governed.security-case.sha256=*) BUILD_ARGS+=(--build-arg "EMILIA_SECURITY_CASE_SHA256=${binding#*=}") ;;
    io.emilia.governed.proof-stats.sha256=*) BUILD_ARGS+=(--build-arg "EMILIA_PROOF_STATS_SHA256=${binding#*=}") ;;
    io.emilia.governed.conformance.sha256=*) BUILD_ARGS+=(--build-arg "EMILIA_CONFORMANCE_MANIFEST_SHA256=${binding#*=}") ;;
  esac
done

if [[ "$MODE" == ci ]]; then
  ACTUATOR_TAG=emilia-consequence-actuator:ci
  DECISION_TAG=emilia-consequence-control:ci
  GATE_TAG=emilia-gate-service:ci
else
  mapfile -t COORDINATES < <("$TRUST" coordinates --config "$CONFIG")
  [[ ${#COORDINATES[@]} -eq 3 ]] || { printf 'error: deployment coordinates are incomplete\n' >&2; exit 1; }
  PROJECT_ID=${COORDINATES[0]}
  REGION=${COORDINATES[1]}
  REGISTRY_HOST="${REGION}-docker.pkg.dev"
  IMAGE_PREFIX="${REGISTRY_HOST}/${PROJECT_ID}/${ARTIFACT_REPOSITORY}"
  ACTUATOR_TAG="${IMAGE_PREFIX}/consequence-actuator:git-${EXPECTED_COMMIT}"
  DECISION_TAG="${IMAGE_PREFIX}/consequence-control:git-${EXPECTED_COMMIT}"
  GATE_TAG=
  gcloud auth configure-docker "$REGISTRY_HOST" --quiet
fi

docker build --file "$DOCKER_CONTEXT/deploy/consequence-control-cloud-run/Dockerfile.consequence-actuator.release" \
  --tag "$ACTUATOR_TAG" "${BUILD_ARGS[@]}" "$DOCKER_CONTEXT"
docker build --file "$DOCKER_CONTEXT/Dockerfile.consequence-control" --tag "$DECISION_TAG" \
  "${BUILD_ARGS[@]}" "$DOCKER_CONTEXT"
if [[ "$MODE" == ci ]]; then
  docker build --file "$DOCKER_CONTEXT/Dockerfile.gate" --tag "$GATE_TAG" \
    "${BUILD_ARGS[@]}" "$DOCKER_CONTEXT"
fi

verify_inspect() {
  local component=$1 tag=$2
  local record="$OUTPUT/inspect-$component.json"
  docker image inspect "$tag" > "$record"
  "$TRUST" verify-inspect \
    --source-manifest "$SOURCE_MANIFEST" \
    --inspect "$record" \
    --component "$component"
}
verify_inspect actuator "$ACTUATOR_TAG"
verify_inspect decision "$DECISION_TAG"
if [[ "$MODE" == ci ]]; then
  verify_inspect gate "$GATE_TAG"
  exit 0
fi

"$PUBLISH" \
  --root "$ROOT" \
  --source-manifest "$SOURCE_MANIFEST" \
  --artifact-dir "$OUTPUT" \
  --expected-commit "$EXPECTED_COMMIT" \
  --config "$CONFIG" \
  --actuator-tag "$ACTUATOR_TAG" \
  --decision-tag "$DECISION_TAG" \
  --output-dir "$OUTPUT/published-release" \
  --github-output "$GITHUB_OUTPUT_FILE" \
  --docker-bin "$(command -v docker)" \
  --gcloud-bin "$(command -v gcloud)"
