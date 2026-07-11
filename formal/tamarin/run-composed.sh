#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

IMAGE='lmandrelli/tamarin-prover-and-batch@sha256:dff2af961e192e2b8eef3faa0484a0075c380b476bd0e79c160a5619b2519083'
MODEL='ep_reliance_composed.spthy'
OUT_DIR="${TAMARIN_OUT_DIR:-run-output}"

VERIFIED_LEMMAS='executable_composed_reliance
execution_requires_full_composition
caid_binds_family_and_material
initiator_cannot_self_approve
no_single_signer_fills_quorum
no_issuer_laundering
strict_registry_view_is_exact
no_cross_action_profile_or_audience_replay
execution_has_honest_approvals_or_prior_compromise
injective_execution_with_consumption'

FALSIFIED_LEMMAS='unchecked_composition_is_injective
unchecked_registry_view_is_current'

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/*.txt

run_lemma() {
  lemma="$1"
  expected="$2"
  output="$OUT_DIR/$lemma.txt"
  echo "Proving $lemma (expected: $expected)"
  docker run --rm \
    -v "$PWD:/work" -w /work \
    "$IMAGE" \
    tamarin-prover --derivcheck-timeout=300 --prove="$lemma" "$MODEL" \
    > "$output" 2>&1

  grep -Fq 'All wellformedness checks were successful.' "$output"
  if [ "$expected" = verified ]; then
    grep -Eq "^  $lemma \\([^)]*\\): verified" "$output"
  else
    grep -Eq "^  $lemma \\([^)]*\\): falsified - found trace" "$output"
  fi
  grep -E "^  $lemma \\(" "$output" | tail -n 1
}

for lemma in $VERIFIED_LEMMAS; do
  run_lemma "$lemma" verified
done

for lemma in $FALSIFIED_LEMMAS; do
  run_lemma "$lemma" falsified
done

echo 'All composed proof obligations passed.'
