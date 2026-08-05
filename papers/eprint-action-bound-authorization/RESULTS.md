# Symbolic analysis results

Checked on 2026-08-05 with Tamarin Prover 1.10.0 and Maude 3.4 from:

`lmandrelli/tamarin-prover-and-batch@sha256:dff2af961e192e2b8eef3faa0484a0075c380b476bd0e79c160a5619b2519083`

## Core model

Model: `../../formal/tamarin/ep_receipt_core.spthy`

SHA-256: `de5eee9b40790baadb22d42cdfff921c5fb2edf10ac6e041d3f8a786f0f0343e`

Results:

- `executable_honest_receipt`: verified, 8 steps
- `core_authenticity_uv_gated`: verified, 12 steps
- `no_replay_across_actions`: verified, 12 steps
- `injective_acceptance_with_consumption`: verified, 6 steps
- `unchecked_acceptance_is_injective`: falsified, 10 steps

The falsified lemma is a retained negative control. It demonstrates same-action replay when the verifier does not consume the receipt.

## Split-domain model

Model: `ep_receipt_split_domains.spthy`

SHA-256: `f4aad9f68c4d97fbbaed5292c2f5e24ef35cc77a9f50808efffd12f27d95c8ed`

Results:

- `executable_honest_receipt`: verified, 8 steps
- `action_binding_survives_local_consumption`: verified, 6 steps
- `acceptance_is_injective_within_one_domain`: verified, 2 steps
- `acceptance_is_globally_injective_across_domains`: falsified, 8 steps

The final lemma is another retained negative control. Tamarin finds two acceptances of one honest receipt in two isolated consumption domains. The trace contains no signing-key reveal.

## Rerun

From the repository root:

```sh
docker run --rm \
  -v "$PWD/formal/tamarin:/work" \
  -w /work \
  lmandrelli/tamarin-prover-and-batch@sha256:dff2af961e192e2b8eef3faa0484a0075c380b476bd0e79c160a5619b2519083 \
  tamarin-prover --prove ep_receipt_core.spthy

docker run --rm \
  -v "$PWD/papers/eprint-action-bound-authorization:/work" \
  -w /work \
  lmandrelli/tamarin-prover-and-batch@sha256:dff2af961e192e2b8eef3faa0484a0075c380b476bd0e79c160a5619b2519083 \
  tamarin-prover --prove ep_receipt_split_domains.spthy
```
