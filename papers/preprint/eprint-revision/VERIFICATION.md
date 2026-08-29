# Verification receipt: ANA preprint v4

Date: 29 August 2026

This receipt identifies the exact manuscript, PDF, symbolic models, and runner
evidence checked for **Authorization Non-Amplification under Chosen-Context
Signer Harvesting**. It records local reproducibility, not IACR acceptance,
peer review, or security of a deployed system.

## Manuscript audit

The v4 security experiment and proof received an independent, full-source audit
after the final context fields and state interfaces were frozen. The audit found
no remaining theorem, game, reduction, adaptive-corruption, audience-binding,
or state-model blocker. Material repairs made before that verdict include:

- binding the enforcement domain and relying-party audience into the signed
  context and checking the audience against a trusted domain function;
- carrying the accepted evidence set in the provider-entry event;
- defining a fixed certified key-and-identity relation;
- distinguishing the cardinality clause from the exact witness clause;
- summing the EUF-CMA bound over the complete enrolled-key universe;
- defining the real-resource experiment and its registry and mediation failure
  events; and
- delimiting ANA to one issued instance, with semantic reissuance explicitly
  outside the theorem.

The novelty audit added anonymous counting tokens, Bellare–Neven
multisignatures, object-capability authority safety, and source-authority
non-amplification to the prior-work comparison.

## Build toolchain

The PDF was built twice with Tectonic and a fixed
`SOURCE_DATE_EPOCH=1786752000`. The outputs were byte-identical. Text extraction
and the focused artifact guard use Poppler `pdftotext` and Node.js. All 15
rendered pages were visually inspected.

The Tamarin runners pin:

```text
lmandrelli/tamarin-prover-and-batch@sha256:dff2af961e192e2b8eef3faa0484a0075c380b476bd0e79c160a5619b2519083
```

That image contains Tamarin 1.10.0 and Maude 3.4.

## Source digests

| Artifact | SHA-256 |
|---|---|
| `formal/tamarin/ep_receipt_core.spthy` | `99777fe702d58a731fcb35f3879459f867c8869e14113c810d3997172e4b2da1` |
| `formal/tamarin/ep_quorum_core.spthy` | `c71a116bd0bc1326876e569b893f2b197f736d9fbf76f787938e87137355cc20` |
| `formal/tamarin/ep_reliance_composed.spthy` | `7c6f623e6cec025a49054e42b2b384a16cbea98f4d1d0e05c6fd4c4ff077e968` |
| `formal/tamarin/ep_six_claim_composed.spthy` | `80c64c9b85eaa4781542d5cbf8f2f9e54ea62d3cbf2e8efa8723f1e41c847e3b` |
| `formal/tamarin/run-receipt-core.sh` | `b710f30b1ae4e62a2eeef39c00ef9b7322901e43185860c51bd930b2a5c63a26` |
| `formal/tamarin/run-quorum.sh` | `3dcaf37a0d1fa047bc655319ee35959b3f4ee6fc6afde358b7487eb5227691d7` |
| `formal/tamarin/run-composed.sh` | `c04a9471d29c3d8164c52b2f2e01b38275d1fdc47ccdd587561315e8835e640f` |

## Receipt-core rerun

Executed from the pinned container on 29 August 2026:

```text
executable_honest_receipt (exists-trace): verified (9 steps)
core_authenticity_uv_gated (all-traces): verified (11 steps)
acceptance_prefix_integrity_after_later_reveal (all-traces): verified (12 steps)
no_replay_across_actions (all-traces): verified (11 steps)
injective_acceptance_with_consumption (all-traces): verified (11 steps)
unchecked_acceptance_is_injective (all-traces): falsified - found trace (11 steps)
```

The final line is a required negative control: removing linear consumption lets
one genuine artifact reach acceptance twice.

## Quorum-core rerun

Executed from the pinned container on 29 August 2026:

```text
executable_quorum (exists-trace): verified (13 steps)
quorum_requires_two_distinct_uv_gated_signatures (all-traces): verified (27 steps)
initiator_cannot_self_approve (all-traces): verified (4 steps)
no_single_signer_fills_quorum (all-traces): verified (4 steps)
commit_requires_signature_over_that_action (all-traces): verified (8 steps)
```

## Composed models

The pinned composed runner was executed again on 29 August 2026 and exited
successfully with `All composed proof obligations passed.` It verified 20
positive obligations across the two theories and reproduced eight required
negative controls using the same source and runner digests above. Its positive claims include exact
action identity, current registry view, issuer and scope pinning, profile and
audience binding, registered challenge consumption, action-keyed entry, and
fail-closed reservation handling.

The negative controls are:

```text
unchecked_composition_is_injective (all-traces): falsified - found trace (31 steps)
unchecked_registry_view_is_current (all-traces): falsified - found trace (20 steps)
unchecked_presenter_class_is_pinned (all-traces): falsified
unchecked_signed_denial_cannot_authorize (all-traces): falsified
unchecked_authority_scope_is_pinned (all-traces): falsified
unchecked_reliance_profile_is_pinned (all-traces): falsified
unchecked_unregistered_challenge_is_registered (all-traces): falsified
unchecked_presenter_execution_key_is_canonical (all-traces): falsified
```

These symbolic results do not establish the computational theorem. The theories
idealize signatures and typed encodings and assume the linear state facts they
consume.

## PDF artifact

| Property | Value |
|---|---|
| File | `papers/preprint/eprint-revision/main.pdf` |
| Pages | 15 |
| Bytes | 152,612 |
| SHA-256 | `3f86f29129f0ed4b1b2d502b7b9a6e62a7a311b022d19ea3eed9e3462992990d` |

## Reproduction commands

```sh
cd formal/tamarin
TAMARIN_OUT_DIR=/tmp/emilia-abia-v4-receipt ./run-receipt-core.sh
TAMARIN_OUT_DIR=/tmp/emilia-abia-v4-quorum ./run-quorum.sh
TAMARIN_OUT_DIR=/tmp/emilia-abia-v4-composed ./run-composed.sh

cd ../../papers/preprint/eprint-revision
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build-a main.tex
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build-b main.tex
cmp build-a/main.pdf build-b/main.pdf
cp build-a/main.pdf main.pdf
node check.mjs
```

The rejected v3 PDF remains the published predecessor at
`10.5281/zenodo.21968577`. It was not relabeled as v4. The v4 ePrint and Zenodo
records remain unsubmitted and unpublished until their external interfaces
return confirmation identifiers.
