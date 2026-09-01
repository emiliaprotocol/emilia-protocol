# Zenodo v5 upload metadata

Status: prepared, not uploaded or published.

## Record lineage

- New version DOI: not assigned
- Previous version DOI: `10.5281/zenodo.21968577`
- All-versions concept DOI: `10.5281/zenodo.21520972`
- Resource type: Publication / Preprint
- Version: `v5`
- Publication date: set to the actual Zenodo publication date at upload
- License: Creative Commons Attribution 4.0 International
- Copyright: Copyright (C) 2026 Iman Schrock / EMILIA Protocol, Inc.

## Title

Per-Issuance Authorization Non-Amplification under Chosen-Context Signature Collection

## Creator

Schrock, Iman; EMILIA Protocol, Inc.; ORCID `0009-0004-0290-5433`

## Description

A valid signature proves that a key signed a message. It does not say how many actions an executor may perform with that message. This gap matters when an untrusted collector can ask honest signers to approve adaptively chosen requests, retain the resulting artifacts, and present them concurrently to several executors. Replaying one genuine approval can then cause two provider entries without forging any signature. We formalize this gap as authorization non-amplification (ANA). In a finite multi-user experiment, the adversary wins if a provider entry lacks a prior issuance record or, for any required key unrevealed before entry, lacks an earlier signing event for the accepted context and slot. The adversary also wins if one issued instance witnesses more than one provider entry. We show that neither EUF-CMA security nor signer-to-collector injective agreement implies ANA. Our construction combines EUF-CMA signatures, a collision-resistant hash, injective typed encod- ings, an ideal exact issue-and-consume resource, and a one-use provider mediator. Except for setup-key collision, an entry without the required witness yields either a signature forgery or a hash collision; the state resources rule out duplicate entry. A separate bound names the registry and mediation failures that a real implementation must control. Four Tamarin models illustrate the correspondence, while nine weakened variants produce the expected attacks. The result concerns provider entry only; it does not establish human identity, display fidelity, policy correctness, or exactly-once physical eﬀect.

This is an unrefereed technical preprint. Version 5 supersedes v4 and the ABIA versions. It is not posted on the IACR ePrint Archive; see IACR-SUBMISSION.md for that record.

## Keywords

authorization non-amplification; chosen-context signer harvesting; digital
signatures; replay; injective agreement; stateful authorization; Tamarin; formal
verification; multi-user security; complete mediation

## Files

- `authorization-non-amplification-v5.pdf` (19 pages, 173254 bytes, SHA-256 1f0b9e220f2072f42724516b53aa169e866770bad909f9b7a4fef8e90886406b)
- optional `authorization-non-amplification-v5-artifacts.zip`
- `ZENODO.md`

## Exact PDF

- Pages: 15
- Bytes: 152,612
- SHA-256: `3f86f29129f0ed4b1b2d502b7b9a6e62a7a311b022d19ea3eed9e3462992990d`

## Upload boundary

Reopen the uploaded PDF and compare its digest before publishing the record.
Do not add a DOI or mark this record published until Zenodo returns and resolves
the final identifier.
