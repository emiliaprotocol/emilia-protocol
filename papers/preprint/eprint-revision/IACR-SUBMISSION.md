# IACR ePrint submission packet: v5

## State

Closed. The IACR Cryptology ePrint Archive is no longer a distribution target for this paper.

Version 5 was Submitted and email-confirmed on 30 August 2026 as temporary Cryptology ePrint
submission `xxxx/111420` and was rejected at editor screening on 1 September 2026 with the
archive's acceptance-criteria note. It was the sixth and last temporary submission of this
line of work:

| Temporary id | Manuscript | Submitted | Rejected | Editor note |
|---|---|---|---|---|
| `xxxx/110966` | ABIA long | 2026-08-06 | 2026-08-10 | lacks security proofs or convincing arguments |
| `xxxx/111011` | ABIA long | 2026-08-10 | 2026-08-15 | acceptance-criteria template |
| `xxxx/111097` | ABIA lean | 2026-08-15 | 2026-08-16 | unclear or insufficient contribution to cryptology |
| `xxxx/111261` | ABIA lean | 2026-08-22 | 2026-08-22 | same; appeal of 2026-08-24 jointly reconsidered and reaffirmed 2026-08-29 |
| `xxxx/111404` | ANA v4 | 2026-08-29 | 2026-08-30 | acceptance-criteria template |
| `xxxx/111420` | ANA v5 | 2026-08-30 | 2026-09-01 | acceptance-criteria template |

None received a permanent ePrint number. No further ePrint submission will be made under any title.
The editors stated on 2026-08-29 that they cannot provide feedback beyond the criteria at
https://eprint.iacr.org/operations.html.

Posting on ePrint would not have been peer review, IACR endorsement, or validation of a deployed
system. Public distribution of this manuscript is the Zenodo record under concept DOI
`10.5281/zenodo.21520972` (see `ZENODO.md`) and the source and PDF in this directory. The
peer-reviewed venue plan is in [`CSF-2027-SUBMISSION-PLAN.md`](CSF-2027-SUBMISSION-PLAN.md).

The fields below are retained as the record of what was submitted as v5. They are not a plan for
another submission.

## Authorized public fields

- Author: Iman Schrock
- Affiliation: EMILIA Protocol, Inc.
- ORCID: `0009-0004-0290-5433`
- Contact: `team@emiliaprotocol.ai`
- Category: Cryptographic protocols
- License: Creative Commons Attribution 4.0 International (CC BY 4.0)

## Title

Per-Issuance Authorization Non-Amplification under Chosen-Context Signature Collection

## Keywords

authorization non-amplification; chosen-context signature collection; digital
signatures; replay; injective agreement; stateful authorization; multi-user
security; formal verification; Tamarin

## Prior-publication disclosure

- Selection: Published elsewhere
- Venue: Zenodo preprint v3
- DOI: `10.5281/zenodo.21968577`
- Difference: Major differences (more than 25% of the material)

Version 5 replaces the security experiment, construction, proof, systems
refinement, closest-work comparison, and limitations. The Zenodo record is
disclosed as the predecessor; it has no IACR ePrint identifier.

## Abstract

A valid signature proves that a key signed a message. It does not say how many
actions an executor may perform with that message. This gap matters when an
untrusted collector can ask honest signers to approve adaptively chosen
requests, retain the resulting artifacts, and present them concurrently to
several executors. Replaying one genuine approval can then cause two provider
entries without forging any signature.

We formalize this gap as *authorization non-amplification* (ANA). In a finite
multi-user experiment, the adversary wins if a provider entry lacks a prior
issuance record or, for any required key unrevealed before entry, lacks an
earlier signing event for the accepted context and slot. The adversary also
wins if one issued instance witnesses more than one provider entry. We show
that neither EUF-CMA security nor signer-to-collector injective agreement
implies ANA.

Our construction combines EUF-CMA signatures, a collision-resistant hash,
injective typed encodings, an ideal exact issue-and-consume resource, and a
one-use provider mediator. Except for setup-key collision, an entry without the
required witness yields either a signature forgery or a hash collision; the
state resources rule out duplicate entry. A separate bound names the registry
and mediation failures that a real implementation must control. Four Tamarin
models illustrate the correspondence, while nine weakened variants produce the
expected attacks. The result concerns provider entry only; it does not establish
human identity, display fidelity, policy correctness, or exactly-once physical
effect.

## Note to the archive editor

Version 5 begins with the minimal no-forgery failure and states one research
question. It then gives the full adversary interface, win conditions, typed
encoding, construction, and dependency ladder in the report itself. The main
result separates three claims that the previous version blurred:

1. exact-witness authenticity reduces to duplicate-key setup risk, hash
   collision, and per-key EUF-CMA security;
2. one-entry cardinality follows from explicit linear issue-and-consume and
   mediation resources; and
3. the deployment corollary charges concrete registry and mediation failures.

The resubmission audit produced material repairs. Validated caller input,
unique atomic issuance, exact action bytes, the exact evidence map, and one
matching consume event are now preserved through provider entry. The proof no
longer conditions key generation by resampling. The closest-work section states
the contribution relationally, and the limitations sit next to the claims they
qualify.

This is a substantive replacement for declined temporary submission
`xxxx/111404` and a major revision of the v3 Zenodo preprint at
`10.5281/zenodo.21968577`.

## Public additional note

Major revision of the v3 Zenodo preprint. Version 5 rebuilds the security
experiment, construction, proof, real-resource refinement, closest-work
comparison, and limitations.

## Contribution to cryptology

EUF-CMA limits forgery of signed messages. It does not count how many provider
entries an authentic artifact may unlock. ANA defines that missing quantity in
a finite multi-user chosen-context experiment and gives a reduction-based
treatment that joins certified multi-key evidence to exact issuance, adaptive
reveal, one-time consumption, and provider entry.

The paper does not claim that replay prevention, single-use state, or the term
non-amplification is new. Its bounded contribution is the exact cross-role
correspondence and the separation of cryptographic authenticity from the state
and mediation obligations needed when the conclusion concerns actions rather
than signed bytes.

## Five-report editorial calibration

The structure was compared end to end with ePrint reports 2026/1833,
2026/1832, 2026/1831, 2026/1830, and 2026/1829. The comparison is recorded in
`IACR-RESUBMISSION-EDITORIAL-MEMO.md`. These reports were approved into the
archive; that status is not peer review.

## Exact upload artifact

- Filename: `authorization-non-amplification-v5.pdf`
- Pages: `19`
- Bytes: `173,254`
- SHA-256: `1f0b9e220f2072f42724516b53aa169e866770bad909f9b7a4fef8e90886406b`
- Temporary ePrint submission: `xxxx/111420`
- Archive state: email-confirmed; awaiting editor screening

## Preflight checklist

- [x] Exact public identity, category, and CC BY license recorded.
- [x] Title and abstract match `main.tex`.
- [x] Complete experiment, construction, definitions, theorem, proof, and limitations are in the PDF.
- [x] Final adversarial proof audit passed after repairing the discovered defects.
- [x] Two clean fixed-epoch builds are byte-identical.
- [x] PDF has no TeX warnings or undefined references.
- [x] Tamarin claims match the committed proof records and remain bounded as case studies.
- [x] Final PDF filename, pages, bytes, and digest are pinned.
- [x] Every rendered page has been visually inspected.
- [x] Repository checker passes against v5.
- [x] Exact local upload artifact was selected and the portal returned
  temporary submission `xxxx/111420`.
- [x] Author-email ownership was confirmed and the portal reported that the
  paper was received for editor review.
