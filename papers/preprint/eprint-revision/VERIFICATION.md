# Verification receipt: ANA preprint v5

Date: 30 August 2026

This receipt identifies the exact source, PDF, symbolic models, and runner
evidence checked for **Per-Issuance Authorization Non-Amplification under
Chosen-Context Signature Collection**. It records local reproducibility and an
adversarial proof review. It is not IACR acceptance, peer review, a mechanized
proof of the computational theorem, or verification of a deployed system.

## Proof-audit chronology

The first v5 audit found material defects rather than certifying the draft:

- issuance storage and the `Issued` witness were not one atomic event;
- the evidence map could change between validation and mediation;
- duplicate identical issuance was not charged by `RegistryBreak`;
- real issuance was not bound to trusted caller input;
- exact action bytes disappeared before the modeled provider boundary;
- distinct-key setup silently conditioned the key distribution;
- successful consume could return a token without an exact `Consumed` event;
  and
- the completeness lemma ignored the stated signature-correctness error.

The repaired source adds `ValidatedIssueInput`, atomic unique `Issued` and
`Consumed` events, exact action and evidence preservation through
`ValidatedEntryInput` and `Entry`, an explicit `KeyCollision` term, and a
correctness-conditioned completeness lemma. It separates exact-witness
authenticity, ideal non-amplification, and their composition. A final
adversarial pass found no remaining counterexample, false bound, game-index
error, or material theorem overclaim.

This is still an in-model theorem. A deployment must separately establish the
probabilities of `RegistryBreak` and `MediationBreak` and show that no provider
path bypasses the mediator.

## Exact manuscript and PDF

| Property | Value |
|---|---|
| Source | `papers/preprint/eprint-revision/main.tex` |
| Source SHA-256 | `ebc93f0a57af389c2b9eefaa910a74ed82c50f13ae3f3d80ec8eeb313d592864` |
| PDF | `papers/preprint/eprint-revision/main.pdf` |
| Delivery PDF | `output/pdf/authorization-non-amplification-v5.pdf` |
| Pages | 19 |
| Bytes | 173,254 |
| PDF SHA-256 | `1f0b9e220f2072f42724516b53aa169e866770bad909f9b7a4fef8e90886406b` |

Two clean Tectonic builds used `SOURCE_DATE_EPOCH=1786752000` and were
byte-identical. The log contained no TeX warnings, overfull boxes, underfull
boxes, undefined references, or errors. Poppler reported PDF 1.5 and 19 pages.
All rendered pages were inspected after the build recorded below.

## Symbolic evidence boundary

The Tamarin artifacts were not changed by v5. They remain pinned to repository
commit `c3e5da51d656f56470c2d568cd6295cb842893cf` and provide bounded case
studies only. They do not prove the computational theorem or the real-resource
refinement.

The pinned container is:

```text
lmandrelli/tamarin-prover-and-batch@sha256:dff2af961e192e2b8eef3faa0484a0075c380b476bd0e79c160a5619b2519083
```

It contains Tamarin 1.10.0 and Maude 3.4.

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

## Recorded Tamarin reruns

The focused and composed runners completed on 29 August 2026. The receipt and
quorum models reported:

```text
executable_honest_receipt (exists-trace): verified (9 steps)
core_authenticity_uv_gated (all-traces): verified (11 steps)
acceptance_prefix_integrity_after_later_reveal (all-traces): verified (12 steps)
no_replay_across_actions (all-traces): verified (11 steps)
injective_acceptance_with_consumption (all-traces): verified (11 steps)
unchecked_acceptance_is_injective (all-traces): falsified - found trace (11 steps)

executable_quorum (exists-trace): verified (13 steps)
quorum_requires_two_distinct_uv_gated_signatures (all-traces): verified (27 steps)
initiator_cannot_self_approve (all-traces): verified (4 steps)
no_single_signer_fills_quorum (all-traces): verified (4 steps)
commit_requires_signature_over_that_action (all-traces): verified (8 steps)
```

The composed runner verified 20 positive obligations and reproduced eight
required negative controls. The committed result summary is
`formal/tamarin/results/ep_reliance_composed.summary.txt`.

## Reproduction commands

```sh
cd formal/tamarin
TAMARIN_OUT_DIR=/tmp/emilia-ana-v5-receipt ./run-receipt-core.sh
TAMARIN_OUT_DIR=/tmp/emilia-ana-v5-quorum ./run-quorum.sh
TAMARIN_OUT_DIR=/tmp/emilia-ana-v5-composed ./run-composed.sh

cd ../../papers/preprint/eprint-revision
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build-a main.tex
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build-b main.tex
cmp build-a/main.pdf build-b/main.pdf
cp build-a/main.pdf main.pdf
node check.mjs
```

The v3 predecessor is published at `10.5281/zenodo.21968577`. Version 5 was
submitted and email-confirmed as temporary IACR ePrint submission
`xxxx/111420` on 30 August 2026. It was rejected at editor screening on 1 September 2026; the ePrint
archive is closed as a venue for this paper (see IACR-SUBMISSION.md).
