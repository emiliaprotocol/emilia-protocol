# Verification receipt

Date: 16 August 2026

This receipt identifies the exact source, model, proof, and PDF evidence reviewed for the focused authorization-protocol revision. It does not assert acceptance by a refereed or editorial venue.

## Toolchain

The Tamarin runs used the repository-pinned image:

```text
lmandrelli/tamarin-prover-and-batch@sha256:dff2af961e192e2b8eef3faa0484a0075c380b476bd0e79c160a5619b2519083
```

The PDF was built twice with Tectonic using `SOURCE_DATE_EPOCH=1786752000`. The two clean outputs were byte-identical. Text extraction and the focused artifact guard used Poppler `pdftotext` and Node.js. The version DOI `10.5281/zenodo.21968577` was reserved before the final build and is embedded in the PDF.

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

## Receipt-core results

```text
executable_honest_receipt (exists-trace): verified (9 steps)
core_authenticity_uv_gated (all-traces): verified (11 steps)
acceptance_prefix_integrity_after_later_reveal (all-traces): verified (12 steps)
no_replay_across_actions (all-traces): verified (11 steps)
injective_acceptance_with_consumption (all-traces): verified (11 steps)
unchecked_acceptance_is_injective (all-traces): falsified (11-step trace)
```

The later-reveal result is deliberately a trace-prefix authenticity property. The model also requires that no reveal occurred before acceptance. It does not claim forward-secure logging or offline anti-backdating after compromise.

## Quorum-core results

```text
executable_quorum (exists-trace): verified (13 steps)
quorum_requires_two_distinct_uv_gated_signatures (all-traces): verified (27 steps)
initiator_cannot_self_approve (all-traces): verified (4 steps)
no_single_signer_fills_quorum (all-traces): verified (4 steps)
commit_requires_signature_over_that_action (all-traces): verified (8 steps)
```

## Composed-model results

The composed run verified 20 positive obligations and reproduced eight deliberate falsifications. The verified obligations include full-composition admission, current registry view, scope and profile pinning, signed denial as evidence but never authority, fresh challenge uniqueness, action-keyed execution, and fail-closed reservation behavior.

The reproduced negative controls were:

```text
unchecked_composition_is_injective (all-traces): falsified (31-step trace)
unchecked_registry_view_is_current (all-traces): falsified (20-step trace)
unchecked_authority_scope_is_pinned (all-traces): falsified (16-step trace)
unchecked_presenter_class_is_pinned (all-traces): falsified (14-step trace)
unchecked_presenter_execution_key_is_canonical (all-traces): falsified (14-step trace)
unchecked_reliance_profile_is_pinned (all-traces): falsified (14-step trace)
unchecked_signed_denial_cannot_authorize (all-traces): falsified (14-step trace)
unchecked_unregistered_challenge_is_registered (all-traces): falsified (14-step trace)
```

## PDF artifact

| Property | Value |
|---|---|
| File | `papers/preprint/eprint-revision/main.pdf` |
| Pages | 19 |
| Bytes | 172,068 |
| SHA-256 | `f158dbcd36f8831cc8f39aa7d37cfd505679483b57b29bb33dc676a9af75867e` |

## Reproduction commands

```sh
cd formal/tamarin
TAMARIN_OUT_DIR=/tmp/emilia-tamarin-receipt ./run-receipt-core.sh
TAMARIN_OUT_DIR=/tmp/emilia-tamarin-quorum ./run-quorum.sh
TAMARIN_OUT_DIR=/tmp/emilia-tamarin-composed ./run-composed.sh

cd ../../papers/preprint/eprint-revision
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build-a main.tex
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build-b main.tex
cmp build-a/main.pdf build-b/main.pdf
cp build-a/main.pdf main.pdf
node check.mjs
```

The rejected PDF for temporary submission `xxxx/111097` remains separate and was not reused. This corrected paper records semantic contexts in the signing experiment and is packaged as Zenodo v3 rather than resubmitted to the same ePrint queue.
