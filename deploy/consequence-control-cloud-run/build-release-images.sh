#!/usr/bin/env bash
set -euo pipefail

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(CDPATH='' cd -- "$LANE_DIR/../.." && pwd)
TRUST="$LANE_DIR/release-trust.py"

MODE=
EXPECTED_COMMIT=
OUTPUT=
GOVERNED_EVIDENCE_PREVERIFIED=0
while (($#)); do
  case "$1" in
    --ci)
      MODE=ci
      shift
      ;;
    --bundle)
      MODE=bundle
      shift
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
    --governed-evidence-preverified)
      GOVERNED_EVIDENCE_PREVERIFIED=1
      shift
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

[[ "$MODE" == ci || "$MODE" == bundle ]] || { printf 'error: exactly one of --ci or --bundle is required\n' >&2; exit 2; }
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { printf 'error: --expected-commit must be a lowercase Git SHA\n' >&2; exit 2; }
[[ -n "$OUTPUT" && "$OUTPUT" == /* ]] || { printf 'error: --output must be absolute\n' >&2; exit 2; }
[[ ! -e "$OUTPUT" ]] || { printf 'error: output already exists: %s\n' "$OUTPUT" >&2; exit 2; }
if [[ "$GOVERNED_EVIDENCE_PREVERIFIED" == 1 ]]; then
  [[ "$MODE" == ci ]] || { printf 'error: preverified governed evidence is CI-only\n' >&2; exit 2; }
  [[ "${GITHUB_ACTIONS:-}" == true ]] || { printf 'error: preverified governed evidence requires GitHub Actions\n' >&2; exit 2; }
  GITHUB_SHA=${GITHUB_SHA:-}
  [[ "$GITHUB_SHA" == "$EXPECTED_COMMIT" ]] \
    || { printf 'error: preverified governed evidence SHA mismatch\n' >&2; exit 2; }
fi
command -v docker >/dev/null
command -v node >/dev/null
command -v npm >/dev/null
command -v python3 >/dev/null
mkdir -m 700 "$OUTPUT"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/emilia-release-build.XXXXXX")
cleanup() {
  rm -rf -- "$WORK"
}
trap cleanup EXIT

cd "$ROOT"
[[ "$(git rev-parse HEAD)" == "$EXPECTED_COMMIT" ]] \
  || { printf 'error: checkout does not match expected commit\n' >&2; exit 1; }

VERIFY_TARBALL=$("$TRUST" pack-package --root "$ROOT" --expected-commit "$EXPECTED_COMMIT" --package verify --output-dir "$WORK")
GATE_TARBALL=$("$TRUST" pack-package --root "$ROOT" --expected-commit "$EXPECTED_COMMIT" --package gate --output-dir "$WORK")
REQUIRE_RECEIPT_TARBALL=$("$TRUST" pack-package --root "$ROOT" --expected-commit "$EXPECTED_COMMIT" --package require-receipt --output-dir "$WORK")

if [[ "$GOVERNED_EVIDENCE_PREVERIFIED" != 1 ]]; then
  npm run check:standalone-runtimes
  npm run check:security-case
  npm run conformance:manifest:check
  npm run check:proof-stats
else
  printf 'governed evidence already verified by SHA-bound CI dependencies: %s\n' "$EXPECTED_COMMIT"
fi
npm --prefix packages/verify run build
npm --prefix packages/gate run build
git diff --exit-code -- packages/verify/dist packages/gate/dist \
  security/security-case.json lib/proof-stats.json conformance/conformance-manifest.json
# The package seals above reject pre-existing ignored or untracked build inputs.
# Assurance execution may create only ignored caches or compiled test state;
# remove that post-seal state before the trust contract validates the checkout
# again and materializes the Docker context from reviewed Git objects.
git clean -fdX -- \
  apps/consequence-actuator-service \
  apps/consequence-control-service \
  apps/gate-service \
  caid \
  packages/gate \
  packages/require-receipt \
  packages/verify

SOURCE_MANIFEST="$WORK/source-manifest.json"
"$TRUST" source \
  --root "$ROOT" \
  --expected-commit "$EXPECTED_COMMIT" \
  --verify-tarball "$VERIFY_TARBALL" \
  --gate-tarball "$GATE_TARBALL" \
  --require-receipt-tarball "$REQUIRE_RECEIPT_TARBALL" \
  --output "$SOURCE_MANIFEST"

DOCKER_CONTEXT="$WORK/docker-context"
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
  ACTUATOR_TAG="emilia-consequence-actuator:git-${EXPECTED_COMMIT}"
  DECISION_TAG="emilia-consequence-control:git-${EXPECTED_COMMIT}"
  GATE_TAG=
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
  local record="$WORK/inspect-$component.json"
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

install -m 400 "$SOURCE_MANIFEST" "$OUTPUT/source-manifest.json"
install -m 400 "$VERIFY_TARBALL" "$OUTPUT/$(basename -- "$VERIFY_TARBALL")"
install -m 400 "$GATE_TARBALL" "$OUTPUT/$(basename -- "$GATE_TARBALL")"
install -m 400 "$REQUIRE_RECEIPT_TARBALL" "$OUTPUT/$(basename -- "$REQUIRE_RECEIPT_TARBALL")"
docker image inspect "$ACTUATOR_TAG" > "$OUTPUT/inspect-actuator.json"
docker image inspect "$DECISION_TAG" > "$OUTPUT/inspect-decision.json"
docker save --output "$OUTPUT/actuator-image.tar" "$ACTUATOR_TAG"
docker save --output "$OUTPUT/decision-image.tar" "$DECISION_TAG"
chmod 400 "$OUTPUT/inspect-actuator.json" "$OUTPUT/inspect-decision.json" \
  "$OUTPUT/actuator-image.tar" "$OUTPUT/decision-image.tar"
"$TRUST" bundle \
  --root "$ROOT" \
  --bundle-dir "$OUTPUT" \
  --source-manifest "$OUTPUT/source-manifest.json" \
  --expected-commit "$EXPECTED_COMMIT" \
  --actuator-archive "$OUTPUT/actuator-image.tar" \
  --actuator-inspect "$OUTPUT/inspect-actuator.json" \
  --actuator-tag "$ACTUATOR_TAG" \
  --decision-archive "$OUTPUT/decision-image.tar" \
  --decision-inspect "$OUTPUT/inspect-decision.json" \
  --decision-tag "$DECISION_TAG" \
  --output "$OUTPUT/bundle-manifest.json"
"$TRUST" verify-bundle \
  --root "$ROOT" \
  --bundle-dir "$OUTPUT" \
  --bundle-manifest "$OUTPUT/bundle-manifest.json" \
  --expected-commit "$EXPECTED_COMMIT"
