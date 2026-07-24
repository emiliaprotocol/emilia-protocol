#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

IMAGE='lmandrelli/tamarin-prover-and-batch@sha256:dff2af961e192e2b8eef3faa0484a0075c380b476bd0e79c160a5619b2519083'
CORE_MODEL='ep_reliance_composed.spthy'
CLAIM_MODEL='ep_six_claim_composed.spthy'
OUT_DIR="${TAMARIN_OUT_DIR:-run-output}"

CORE_VERIFIED_LEMMAS='executable_composed_reliance
execution_requires_full_composition
caid_binds_family_and_material
initiator_cannot_self_approve
no_single_signer_fills_quorum
no_issuer_laundering
strict_registry_view_is_exact
no_cross_action_profile_or_audience_replay
execution_has_honest_approvals_or_prior_compromise
injective_execution_with_consumption'

CORE_FALSIFIED_LEMMAS='unchecked_composition_is_injective
unchecked_registry_view_is_current'

CLAIM_VERIFIED_LEMMAS='executable_six_claim_composition
signed_denial_remains_verifiable_evidence
class_a_downgrade_refused
signed_denial_cannot_authorize
scoped_authority_is_pinned
reliance_requires_pinned_profile
evidence_challenge_is_registered_and_consumed
fresh_challenge_registration_is_unique
aec_execution_is_action_keyed_and_fleet_fail_closed
action_reservation_failure_is_fail_closed'

CLAIM_FALSIFIED_LEMMAS='unchecked_presenter_class_is_pinned
unchecked_signed_denial_cannot_authorize
unchecked_authority_scope_is_pinned
unchecked_reliance_profile_is_pinned
unchecked_unregistered_challenge_is_registered
unchecked_presenter_execution_key_is_canonical'

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/*.txt

run_lemma() {
  model="$1"
  lemma="$2"
  expected="$3"
  output="$OUT_DIR/$lemma.txt"
  echo "Proving $lemma in $model (expected: $expected)"
  docker run --rm \
    -v "$PWD:/work" -w /work \
    "$IMAGE" \
    tamarin-prover --derivcheck-timeout=300 --prove="$lemma" "$model" \
    > "$output" 2>&1

  grep -Fq 'All wellformedness checks were successful.' "$output"
  if [ "$expected" = verified ]; then
    grep -Eq "^  $lemma \\([^)]*\\): verified" "$output"
  else
    grep -Eq "^  $lemma \\([^)]*\\): falsified - found trace" "$output"
  fi
  grep -E "^  $lemma \\(" "$output" | tail -n 1
}

for lemma in $CORE_VERIFIED_LEMMAS; do
  run_lemma "$CORE_MODEL" "$lemma" verified
done

for lemma in $CORE_FALSIFIED_LEMMAS; do
  run_lemma "$CORE_MODEL" "$lemma" falsified
done

for lemma in $CLAIM_VERIFIED_LEMMAS; do
  run_lemma "$CLAIM_MODEL" "$lemma" verified
done

for lemma in $CLAIM_FALSIFIED_LEMMAS; do
  run_lemma "$CLAIM_MODEL" "$lemma" falsified
done

echo 'All composed proof obligations passed.'
