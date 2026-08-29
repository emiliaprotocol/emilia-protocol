# Authorization Non-Amplification, preprint v4

This directory contains the rebuilt cryptology manuscript prepared after the
IACR ePrint editors rejected temporary submissions `xxxx/111011`,
`xxxx/111097`, and the jointly reconsidered `xxxx/111261` for an insufficiently
clear contribution to cryptology and an incomplete security argument.

Version 4 is not a prose revision of the rejected paper. It replaces the ABIA
formulation with **authorization non-amplification (ANA)**: a finite,
multi-user chosen-context experiment that counts provider entries attributed to
one issued authorization instance. The paper gives:

- an exact issuance, signing, reveal, admission, consumption, and entry game;
- separations from EUF-CMA security, nonce freshness, byte-level authenticity,
  and signer-to-collector injective agreement;
- a compiler from EUF-CMA signatures, collision resistance, injective typed
  encoding, exact issue-and-consume state, and complete mediation;
- a reduction over every enrolled challenge key, rather than a policy chosen
  after the adversary wins;
- a real-resource corollary that charges registry and mediation failures
  explicitly; and
- four bounded Tamarin case studies, presented as symbolic evidence rather than
  as a computational or deployment proof.

The closest predecessors are discussed directly. Anonymous counting tokens
limit token issuance per client and message; multisignatures authenticate a
common document under several certified keys; object-capability and agent-memory
work use other non-amplification properties; and CapLease addresses semantic
reissuance above a single token. ANA's bounded delta is the multi-signer
issuance-to-provider-entry witness under a chosen-context collector.

## Current state

- Manuscript: rebuilt and independently audited
- Two deterministic PDF builds: byte-identical
- Focused receipt and quorum Tamarin reruns: green on 29 August 2026
- Composed Tamarin rerun: 20 positive obligations and eight required negative
  controls passed on 29 August 2026
- IACR ePrint: upload-ready, not submitted
- Peer review: planned for IEEE CSF 2027, not submitted
- Zenodo v4: metadata prepared, not published

Neither a local green build nor an ePrint posting would constitute peer review.

## Build

Prerequisites: Tectonic, Node.js, and Poppler's `pdftotext`.

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

The exact model and runner digests, machine verdicts, scope, and reproduction
commands are pinned in [`VERIFICATION.md`](VERIFICATION.md). The models assume
the linear state transitions they represent. They do not prove the paper's
computational theorem, a concrete database, or exactly-once physical effects.

## Submission files

- [`IACR-SUBMISSION.md`](IACR-SUBMISSION.md): exact ePrint form copy and state
- [`CSF-2027-SUBMISSION-PLAN.md`](CSF-2027-SUBMISSION-PLAN.md): peer-review plan
- [`ZENODO.md`](ZENODO.md): staged v4 archive metadata

## Final artifact

The final v4 PDF is 15 pages and 152,612 bytes. Two clean builds were
byte-identical.

`SHA-256: 3f86f29129f0ed4b1b2d502b7b9a6e62a7a311b022d19ea3eed9e3462992990d`

The v3 predecessor remains archived at
[`10.5281/zenodo.21968577`](https://doi.org/10.5281/zenodo.21968577). Version 4
has not yet received a Zenodo DOI or an IACR ePrint identifier.
