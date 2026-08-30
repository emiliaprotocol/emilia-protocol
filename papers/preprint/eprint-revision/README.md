# Per-Issuance Authorization Non-Amplification, preprint v5

This directory contains the cryptology manuscript rebuilt after temporary IACR
ePrint submission `xxxx/111404` was declined under the archive's clarity,
readability, self-containment, novelty, and proof screen.

Version 5 asks one narrow question: when an untrusted collector can obtain
genuine signatures on adaptively chosen authorization contexts, what prevents
one issued authorization from accounting for two provider entries? The paper
answers with:

- a finite multi-user chosen-context experiment;
- an exact witness joining validated issuance input, one immutable issuance,
  pinned slot signatures, exact action bytes, one-time consumption, and provider
  entry;
- separations from EUF-CMA and signer-to-collector injective agreement;
- a reduction to duplicate-key setup risk, collision resistance, and per-key
  EUF-CMA security under explicit ideal state resources;
- a real-resource corollary that charges registry and mediation failures rather
  than treating them as cryptographic facts; and
- bounded Tamarin case studies whose claims remain separate from the
  computational theorem and deployment correctness.

The editorial structure was checked against the five newest ePrint reports
available on 30 August 2026. The comparison and links are recorded in
[`IACR-RESUBMISSION-EDITORIAL-MEMO.md`](IACR-RESUBMISSION-EDITORIAL-MEMO.md).
An ePrint posting is an archive-screening outcome, not peer review.

## Current state

- Manuscript: v5 proof repair complete; final adversarial audit passed
- Tamarin evidence: unchanged, pinned to repository commit
  `c3e5da51d656f56470c2d568cd6295cb842893cf`
- IACR ePrint: not yet resubmitted
- Peer review: not submitted
- Zenodo v5: metadata staged, not published

Local compilation, a green checker, or an ePrint posting would not constitute
peer review or deployment verification.

## Build

Prerequisites: Tectonic, Node.js, and Poppler.

```sh
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build-a main.tex
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build-b main.tex
cmp build-a/main.pdf build-b/main.pdf
cp build-a/main.pdf main.pdf
node check.mjs
```

## Symbolic evidence

The manuscript cites these committed theories and pinned runners:

- `formal/tamarin/ep_receipt_core.spthy`
- `formal/tamarin/ep_quorum_core.spthy`
- `formal/tamarin/ep_reliance_composed.spthy`
- `formal/tamarin/ep_six_claim_composed.spthy`
- `formal/tamarin/run-receipt-core.sh`
- `formal/tamarin/run-quorum.sh`
- `formal/tamarin/run-composed.sh`

Their digests, recorded verdicts, assumptions, and reproduction commands are in
[`VERIFICATION.md`](VERIFICATION.md). The models do not prove the paper's
computational theorem, a concrete database, complete mediation in a deployment,
or exactly-once physical effects.

## Submission files

- [`IACR-SUBMISSION.md`](IACR-SUBMISSION.md): ePrint form copy and submission state
- [`IACR-RESUBMISSION-EDITORIAL-MEMO.md`](IACR-RESUBMISSION-EDITORIAL-MEMO.md): five-report comparison
- [`CSF-2027-SUBMISSION-PLAN.md`](CSF-2027-SUBMISSION-PLAN.md): peer-review plan
- [`ZENODO.md`](ZENODO.md): staged v5 archive metadata

## Final artifact

Two byte-identical clean builds produced a 19-page, 173,254-byte PDF. All 19
rendered pages were visually inspected.

`SHA-256: 1f0b9e220f2072f42724516b53aa169e866770bad909f9b7a4fef8e90886406b`

The v3 predecessor remains archived at
[`10.5281/zenodo.21968577`](https://doi.org/10.5281/zenodo.21968577). Version 5
has not yet received a Zenodo DOI or an IACR ePrint identifier.
