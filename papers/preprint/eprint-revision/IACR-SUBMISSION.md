# IACR ePrint submission packet: v4

## State

Closed. The IACR Cryptology ePrint Archive is no longer a distribution target for this paper.

Record of temporary ePrint submissions, all rejected at editor screening:

| Temporary id | Manuscript | Submitted | Rejected | Editor note |
|---|---|---|---|---|
| `xxxx/110966` | ABIA long | 2026-08-06 | 2026-08-10 | lacks security proofs or convincing arguments |
| `xxxx/111011` | ABIA long | 2026-08-10 | 2026-08-15 | acceptance-criteria template |
| `xxxx/111097` | ABIA lean | 2026-08-15 | 2026-08-16 | unclear or insufficient contribution to cryptology |
| `xxxx/111261` | ABIA lean | 2026-08-22 | 2026-08-22 | same; appeal of 2026-08-24 jointly reconsidered and reaffirmed 2026-08-29 |
| `xxxx/111404` | ANA v4 | 2026-08-29 | 2026-08-30 | acceptance-criteria template |
| `xxxx/111420` | ANA v5 | 2026-08-30 | 2026-09-01 | acceptance-criteria template |

None received a permanent ePrint number. No further ePrint submission will be made under any title. The editors stated on 2026-08-29 that they cannot provide feedback beyond the criteria at https://eprint.iacr.org/operations.html.

Posting on ePrint would not have been peer review, acceptance by IACR, or validation of the paper's claims. Public distribution of the paper is the Zenodo record `10.5281/zenodo.21968577` (v3) and a planned arXiv cs.CR posting of v5. The peer-reviewed venue plan is in [`CSF-2027-SUBMISSION-PLAN.md`](CSF-2027-SUBMISSION-PLAN.md).

The form fields, editor note, and preflight checklist below are retained as the record of what was submitted as v4. They are not a plan for another submission.

## Form fields

### Title

Authorization Non-Amplification under Chosen-Context Signer Harvesting

### Author

Iman Schrock

- Affiliation: EMILIA Protocol, Inc.
- ORCID: `0009-0004-0290-5433`
- Contact: `team@emiliaprotocol.ai`

### Primary area

Cryptographic protocols

### Keywords

authorization non-amplification; chosen-context signer harvesting; digital signatures; replay; injective agreement; stateful authorization; formal verification; Tamarin

### Abstract

A signature limits who could have produced a message. It does not limit how many consequential actions that message can unlock. This distinction is easy to miss in authorization systems whose collector may solicit genuine signatures on adaptively chosen requests, retain the resulting artifacts, and present them to multiple executors.

We study *authorization non-amplification* (ANA), a per-issued-instance trace property connecting cryptographic approval events to provider-entry cardinality. An entry must map to one exact issued context and, for every required key not yet revealed, to a prior signature on that context's exact slot message. No issued instance may map to more than one entry. ANA is not implied by EUF-CMA security or by signer-to-collector Lowe-style injective agreement: replaying one valid artifact preserves both while violating ANA with probability one.

We define a finite multi-user chosen-context experiment and give a compiler from an EUF-CMA signature scheme, a collision-resistant hash, an injective typed encoding, and ideal issue-and-consume and mediation resources. An unwitnessed entry yields a signature forgery or hash collision; duplicate entry is excluded by the linear resources. A real-resource refinement bound exposes registry and mediation failures as separate trace events rather than cryptographic advantages. Four Tamarin models provide symbolic case studies and nine deliberately weakened comparisons. The result concerns admission, not human identity, display fidelity, policy wisdom, or exactly-once physical effects.

## Note to the archive editor

Version 4 replaces the earlier security target with a finite multi-user chosen-context experiment whose winning events are an unwitnessed provider entry and reuse of one issued instance for two entries. It proves a compiler from standard signatures and hashing in an explicit ideal issue-and-consume/mediation model, then gives a real-resource refinement bound with separate registry and mediation failure events. The claims stop at provider entry and do not include human identity, display fidelity, policy correctness, or exactly-once physical execution.

## What is new in v4

Version 4 contains these substantive changes:

1. **A precise security target.** ANA requires an exact issuance-and-signature witness for every provider entry and an injective map from entries to issued authorization instances.
2. **A complete experiment.** The game fixes the enrolled-key universe and gives explicit issuance, chosen-context signing, reveal, admission, consumption, and entry events with finite query budgets.
3. **Separations from existing notions.** The paper shows that EUF-CMA, a signed fresh nonce, byte-level unforgeability under noninjective encoding, and Lowe-style injective agreement do not supply the provider-entry bound.
4. **A standard-primitive compiler.** The construction uses EUF-CMA signatures, collision resistance, injective typed encoding, exact issue-and-consume state, and complete provider mediation. It does not present state correctness as a consequence of signature security.
5. **An honest multi-user bound.** The reduction sums over all enrolled challenge keys fixed before play. It does not select only the keys in a winning policy after the fact.
6. **A real-resource refinement.** Registry and mediation failures are named trace events whose probabilities must come from a refinement proof, transactional argument, or fault model.
7. **Machine-checked case studies with bounded claims.** The Tamarin models support concrete separations. They are not presented as a computational proof or a deployment verification.

## Contribution to cryptology

The paper identifies a gap between message authenticity and action cardinality. EUF-CMA asks whether an adversary produced a valid signature on a message it did not obtain from the signing oracle. A collector can stay entirely inside that boundary, replay authentic approval artifacts, and still cause more consequential entries than the issuer authorized. ANA makes the missing quantity explicit and gives it a reduction-based treatment.

The manuscript does not claim priority over every use of “non-amplification” or single use. It distinguishes anonymous counting tokens, multisignatures, object-capability authority safety, source-authority preservation in agent memory, single-use delegation, and durable semantic-replay state. Its bounded contribution is the finite multi-user chosen-context experiment and reduction that join certified multi-key evidence, exact issuance, adaptive reveal, and provider-entry cardinality.

The result is not that signatures are deficient. It is that a cryptographic authorization theorem needs an executor event and a state transition if its conclusion is about actions rather than signed bytes. The paper formalizes that endpoint, proves the separations, and states which remaining obligations are operational rather than cryptographic.

## Files to upload

- Final v4 PDF generated from `main.tex`
- Optional public artifact bundle containing the four cited Tamarin theories, pinned runners, proof-status records, and this submission metadata

Do not upload the old `main.pdf` unless its digest has first been confirmed to be the new v4 artifact. The final upload record should contain the exact filename, page count, byte count, and SHA-256 digest.

## Preflight checklist

- [x] The title, abstract, theorem statement, conclusion, and metadata all use **Authorization Non-Amplification**, not the superseded ABIA framing.
- [x] The final source compiles from the dedicated clean-base worktree.
- [x] Two clean builds are byte-identical.
- [x] The PDF has been rendered to images and visually inspected page by page.
- [x] Every new bibliography entry was checked against a primary publication record.
- [x] The Tamarin result counts and deliberate falsifications match the committed proof-status files.
- [x] The repository checker passes against the v4 claims.
- [x] The final PDF filename, page count, byte count, and SHA-256 digest are recorded here before upload.
- [ ] The uploaded PDF is reopened from the ePrint submission interface and compared to the local digest when the interface permits download.
- [ ] The confirmation email or archive identifier is saved before calling the paper submitted.

## Final artifact record

Fill only after the final build:

- Filename: `authorization-non-amplification-v4.pdf`
- Pages: `15`
- Bytes: `152,612`
- SHA-256: `3f86f29129f0ed4b1b2d502b7b9a6e62a7a311b022d19ea3eed9e3462992990d`
- ePrint identifier: `xxxx/111404` (temporary; rejected 2026-08-30). v5 was `xxxx/111420` (temporary; rejected 2026-09-01).
