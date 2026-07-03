# EMILIA Protocol: Crypto-Agility and Post-Quantum Profile
## draft-schrock-ep-pqc-00

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               28 June 2026
Expires: 30 December 2026
```

> STATUS (repo): staged I-D. Render to .xml/.txt via xml2rfc and file with the EP cluster batch.
> Derived from PIP-015. Profile + roadmap; the hybrid signing path is reference-implementation
> follow-on (do not hand-roll PQC — use a vetted ML-DSA library).

## Abstract

This document defines a crypto-agility framework and post-quantum (PQC) signature profile for
EMILIA Protocol (EP) authorization receipts ([I-D.draft-schrock-ep-authorization-receipts]). EP
receipts are long-lived (multi-year regulatory retention), so the signature and digest algorithms
MUST be explicitly identified and migratable. This profile specifies an algorithm registry, a hybrid
(classical + PQC) signature mode for a no-flag-day migration, and a fail-closed verifier
accepted-algorithm policy. It composes with EP-EVIDENCE-RECORD, which already renews digests across
algorithm aging.

## 1. Algorithm registry

Receipts and signoffs carry an explicit algorithm identifier. Defined classes: Ed25519 (EdDSA) and
ECDSA P-256 (ES256) for classical/device signatures; **ML-DSA (FIPS 204)** and **SLH-DSA (FIPS 205)**
for post-quantum signatures; SHA-256 → SHA-384/512 (FIPS 180-4) for digest agility. (ML-KEM / FIPS 203
is key encapsulation, not signatures, and is out of scope for the authorization signature.)

## 2. Hybrid mode (the migration path)

A hybrid signature carries both a classical (Ed25519) and a PQC (ML-DSA) signature over the same
JCS-canonical payload; under hybrid policy a receipt verifies only if BOTH verify. This gives
backward verifiability (classical-only verifiers still check), forward security (the PQC part carries
weight once "harvest-now-decrypt-later" matters), and no flag day (issuers add the PQC signature;
verifiers upgrade independently).

```
signature: { algorithm: "hybrid-ed25519+ml-dsa-65",
             classical: { algorithm: "Ed25519", value: "<b64u>" },
             pqc:       { algorithm: "ML-DSA-65", value: "<b64u>" } }
```

## 3. Verifier policy

A verifier declares `classical-only` (today), `hybrid-required` (transition), or `pqc-required`
(post-migration). Fail-closed: an algorithm not in policy is a rejection, never a silent downgrade.

## 4. Relationship to other work

Composes with EP-EVIDENCE-RECORD (long-term receipts re-anchored under stronger algorithms as they
age). National-algorithm jurisdictions (e.g. SM2/SM3 and PQC adaptations) register in the same
algorithm registry — same agility mechanism, different identifiers. Aligns in direction with NIST PQC
standards and the NSA CNSA 2.0 migration timeline.

## 5. Security Considerations

Algorithm-downgrade is the dominant risk; the verifier accepted-algorithm policy is fail-closed by
design. Hybrid mode ensures a single broken family does not invalidate a receipt. PQC signing MUST
use a vetted implementation; EP does not specify a novel scheme.

## 6. IANA Considerations

No IANA actions; algorithm identifiers register in the EP profile registry (PIP-012).
