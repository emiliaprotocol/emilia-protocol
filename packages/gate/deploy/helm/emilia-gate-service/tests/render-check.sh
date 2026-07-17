#!/usr/bin/env bash
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helm_bin="${HELM_BIN:-helm}"

if ! command -v "$helm_bin" >/dev/null 2>&1; then
  echo "helm is required (or set HELM_BIN)" >&2
  exit 127
fi
if ! command -v node >/dev/null 2>&1; then
  echo "node is required to syntax-check the E2E operator config fixture" >&2
  exit 127
fi

digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
values=(
  --set-string image.repository=registry.example.test/security/emilia-gate-service
  --set-string image.digest="$digest"
  --set-string configuration.existingSecret=gate-configuration
  --set-string secrets.postgres.existingSecret=gate-postgres
  --set-string migrations.postgres.existingSecret=gate-postgres-migrate
  --set-string migrations.postgres.key=database-url
  --set-string secrets.apiToken.existingSecret=gate-api-token
  --set-string secrets.kms.existingSecret=gate-kms
  --set-string secrets.issuerRoots.existingSecret=gate-issuer-roots
  --set-string networkPolicy.egress.githubCidrs[0]=192.0.2.10/32
  --set-string networkPolicy.egress.siemCidrs[0]=198.51.100.20/32
)

"$helm_bin" lint --strict "$chart_dir" "${values[@]}"
rendered="$("$helm_bin" template render-check "$chart_dir" --namespace gate-system "${values[@]}")"

assert_rendered() {
  local expected="$1"
  if ! grep -Fq -- "$expected" <<<"$rendered"; then
    echo "render assertion failed: missing '$expected'" >&2
    exit 1
  fi
}

assert_rendered "kind: Deployment"
assert_rendered "kind: Job"
assert_rendered "kind: PodDisruptionBudget"
assert_rendered "kind: NetworkPolicy"
assert_rendered "replicas: 2"
assert_rendered "runAsNonRoot: true"
assert_rendered "readOnlyRootFilesystem: true"
assert_rendered "allowPrivilegeEscalation: false"
assert_rendered "automountServiceAccountToken: false"
assert_rendered "registry.example.test/security/emilia-gate-service@$digest"
assert_rendered "name: gate-postgres"
assert_rendered "name: gate-postgres-migrate"
assert_rendered "name: gate-api-token"
assert_rendered "name: gate-kms"
assert_rendered "name: gate-issuer-roots"
assert_rendered "secretName: gate-configuration"
assert_rendered "value: \"/app/config/gate.config.mjs\""
assert_rendered "path: /v1/live"
assert_rendered "path: /v1/ready"
assert_rendered "cidr: \"192.0.2.10/32\""
assert_rendered "cidr: \"198.51.100.20/32\""

if grep -Eq '^kind: Secret$' <<<"$rendered"; then
  echo "chart must reference existing Secrets, never render one" >&2
  exit 1
fi

if [[ "$(grep -Fc 'kind: NetworkPolicy' <<<"$rendered")" -ne 2 ]]; then
  echo "chart must render separate base and service-only NetworkPolicies" >&2
  exit 1
fi

if "$helm_bin" template missing-required "$chart_dir" >/dev/null 2>&1; then
  echo "chart unexpectedly rendered without BYOC image and Secret references" >&2
  exit 1
fi

if "$helm_bin" template mutable-image "$chart_dir" --namespace gate-system \
  --set-string image.repository=registry.example.test/security/emilia-gate-service \
  --set-string image.tag=latest \
  --set-string configuration.existingSecret=gate-configuration \
  --set-string secrets.postgres.existingSecret=gate-postgres \
  --set-string migrations.postgres.existingSecret=gate-postgres-migrate \
  --set-string migrations.postgres.key=database-url \
  --set-string secrets.apiToken.existingSecret=gate-api-token \
  --set-string secrets.issuerRoots.existingSecret=gate-issuer-roots >/dev/null 2>&1; then
  echo "chart unexpectedly accepted image.tag=latest" >&2
  exit 1
fi

if "$helm_bin" template missing-migration-secret "$chart_dir" --namespace gate-system \
  --set-string image.repository=registry.example.test/security/emilia-gate-service \
  --set-string image.digest="$digest" \
  --set-string configuration.existingSecret=gate-configuration \
  --set-string secrets.postgres.existingSecret=gate-postgres \
  --set-string secrets.apiToken.existingSecret=gate-api-token \
  --set-string secrets.issuerRoots.existingSecret=gate-issuer-roots >/dev/null 2>&1; then
  echo "chart unexpectedly reused the runtime Postgres Secret for migrations" >&2
  exit 1
fi

if "$helm_bin" template equal-migration-secret "$chart_dir" --namespace gate-system \
  --set-string image.repository=registry.example.test/security/emilia-gate-service \
  --set-string image.digest="$digest" \
  --set-string configuration.existingSecret=gate-configuration \
  --set-string secrets.postgres.existingSecret=gate-postgres \
  --set-string migrations.postgres.existingSecret=gate-postgres \
  --set-string migrations.postgres.key=database-url \
  --set-string secrets.apiToken.existingSecret=gate-api-token \
  --set-string secrets.issuerRoots.existingSecret=gate-issuer-roots >/dev/null 2>&1; then
  echo "chart unexpectedly accepted the runtime Postgres Secret for migrations" >&2
  exit 1
fi

migrations_disabled="$($helm_bin template migrations-disabled "$chart_dir" --namespace gate-system \
  --set-string image.repository=registry.example.test/security/emilia-gate-service \
  --set-string image.digest="$digest" \
  --set-string configuration.existingSecret=gate-configuration \
  --set-string secrets.postgres.existingSecret=gate-postgres \
  --set-string secrets.apiToken.existingSecret=gate-api-token \
  --set-string secrets.issuerRoots.existingSecret=gate-issuer-roots \
  --set migrations.enabled=false)"
if grep -Fq 'kind: Job' <<<"$migrations_disabled"; then
  echo "chart rendered a migration Job while migrations were disabled" >&2
  exit 1
fi

without_kms="$($helm_bin template no-kms "$chart_dir" --namespace gate-system \
  --set-string image.repository=registry.example.test/security/emilia-gate-service \
  --set-string image.digest="$digest" \
  --set-string configuration.existingSecret=gate-configuration \
  --set-string secrets.postgres.existingSecret=gate-postgres \
  --set-string migrations.postgres.existingSecret=gate-postgres-migrate \
  --set-string migrations.postgres.key=database-url \
  --set-string secrets.apiToken.existingSecret=gate-api-token \
  --set-string secrets.issuerRoots.existingSecret=gate-issuer-roots)"
if grep -Fq -- "EP_KMS_KEY_ID" <<<"$without_kms"; then
  echo "chart rendered a KMS dependency even though no KMS extension was configured" >&2
  exit 1
fi

node --check "$chart_dir/tests/fixtures/gate.config.mjs"

echo "Helm lint and render assertions passed"
