# Zenodo v5 upload metadata

Status: prepared, not uploaded or published. Zenodo does not block the IACR
ePrint submission.

## Record lineage

- New version DOI: not assigned
- Previous version DOI: `10.5281/zenodo.21968577`
- All-versions concept DOI: `10.5281/zenodo.21520972`
- Resource type: Publication / Preprint
- Version: `v5`
- Publication date: use the actual Zenodo publication date
- License: Creative Commons Attribution 4.0 International
- Copyright: Copyright (C) 2026 Iman Schrock / EMILIA Protocol, Inc.

## Title

Per-Issuance Authorization Non-Amplification under Chosen-Context Signature Collection

## Creator

Schrock, Iman; EMILIA Protocol, Inc.; ORCID `0009-0004-0290-5433`

## Description

This preprint studies authorization non-amplification (ANA), a
per-issued-instance trace property for an untrusted collector that may obtain
genuine signatures on adaptively chosen authorization contexts. Every provider
entry must have an exact issuance-and-signature witness, and one issued instance
may account for at most one entry.

The paper separates ANA from EUF-CMA and signer-to-collector injective
agreement. It gives a finite multi-user experiment and a construction using
EUF-CMA signatures, collision resistance, injective typed encodings, exact
issue-and-consume state, and a one-use mediator. The proof charges duplicate-key
setup risk, hash collision, and per-key forgery separately. A real-resource
corollary exposes registry and mediation failures rather than treating them as
cryptographic facts.

Four Tamarin theories provide bounded case studies and deliberately weakened
comparisons. They are not a computational proof or deployment verification.
The result concerns provider entry, not human identity, display fidelity,
policy wisdom, semantic replay across fresh issuances, or exactly-once physical
effects. This is an unrefereed technical preprint.

## Keywords

authorization non-amplification; chosen-context signature collection; digital
signatures; replay; injective agreement; stateful authorization; multi-user
security; Tamarin; formal verification; complete mediation

## Files

- `authorization-non-amplification-v5.pdf`
- optional `authorization-non-amplification-v5-artifacts.zip`
- `ZENODO.md`

## Exact PDF

- Pages: 19
- Bytes: 173,254
- SHA-256: `1f0b9e220f2072f42724516b53aa169e866770bad909f9b7a4fef8e90886406b`

## Upload boundary

Reopen the uploaded PDF and compare its digest before publishing. Do not add a
DOI or mark this record published until Zenodo returns and resolves the final
identifier.
