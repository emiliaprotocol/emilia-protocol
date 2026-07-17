#!/usr/bin/env bash
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helm_bin="${HELM_BIN:-helm}"
issuer_args=(
  --set-string issuerKeys.existingSecret=gate-issuer-keys
  --set-string image.repository=registry.example.test/security/emilia-gate
)

if ! command -v "$helm_bin" >/dev/null 2>&1; then
  echo "helm is required (or set HELM_BIN)" >&2
  exit 127
fi

"$helm_bin" lint --strict "$chart_dir" "${issuer_args[@]}"
rendered="$("$helm_bin" template legacy-safe "$chart_dir" "${issuer_args[@]}")"
if ! grep -Fq 'replicas: 1' <<<"$rendered"; then
  echo 'legacy chart must default to one replica' >&2
  exit 1
fi

if "$helm_bin" template legacy-unsafe "$chart_dir" "${issuer_args[@]}" \
  --set replicaCount=2 >/dev/null 2>&1; then
  echo 'legacy chart unexpectedly rendered multiple in-memory replicas' >&2
  exit 1
fi

shared_rendered="$("$helm_bin" template legacy-shared "$chart_dir" "${issuer_args[@]}" \
  --set replicaCount=2 \
  --set-string sharedState.consumption.envName=EP_GATE_CONSUMPTION_DATABASE_URL \
  --set-string sharedState.consumption.existingSecret=gate-consumption \
  --set-string sharedState.consumption.secretKey=database-url \
  --set-string sharedState.evidence.envName=EP_GATE_EVIDENCE_DATABASE_URL \
  --set-string sharedState.evidence.existingSecret=gate-evidence \
  --set-string sharedState.evidence.secretKey=database-url)"

for expected in \
  'replicas: 2' \
  'name: EP_GATE_CONSUMPTION_DATABASE_URL' \
  'name: gate-consumption' \
  'name: EP_GATE_EVIDENCE_DATABASE_URL' \
  'name: gate-evidence'; do
  if ! grep -Fq -- "$expected" <<<"$shared_rendered"; then
    echo "legacy shared-state render missing: $expected" >&2
    exit 1
  fi
done

if grep -Eq '^kind: Secret$' <<<"$shared_rendered"; then
  echo 'legacy chart must reference existing Secrets, never render one' >&2
  exit 1
fi

echo 'Legacy Helm scaling validation passed'
