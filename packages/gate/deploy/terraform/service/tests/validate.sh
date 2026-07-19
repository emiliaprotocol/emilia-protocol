#!/usr/bin/env bash
set -euo pipefail

module_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
terraform_bin="${TERRAFORM_BIN:-terraform}"

if ! command -v "$terraform_bin" >/dev/null 2>&1; then
  echo "terraform is required (or set TERRAFORM_BIN)" >&2
  exit 127
fi

"$terraform_bin" fmt -check -recursive "$module_dir"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
cp "$module_dir"/*.tf "$tmp_dir"/
cp -R "$module_dir/tests" "$tmp_dir/tests"

TF_DATA_DIR="$tmp_dir/.terraform" "$terraform_bin" -chdir="$tmp_dir" init \
  -backend=false -input=false >/dev/null
TF_DATA_DIR="$tmp_dir/.terraform" "$terraform_bin" -chdir="$tmp_dir" validate
TF_DATA_DIR="$tmp_dir/.terraform" "$terraform_bin" -chdir="$tmp_dir" test

echo "Terraform formatting, provider-schema, and validation-contract tests passed"
