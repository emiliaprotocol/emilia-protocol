# Plan — EMILIA Protocol Clean-Room Verifier

## Objective
Implement independent, native Node.js verifiers for all 16 conformance suites to achieve 158/158 passing vector count, without relying on the reference `packages/verify/` library. The implementation must only use native Node.js `crypto` modules (no external cryptographic dependencies), and output results in the plugfest-contract format so that `sign-statement.mjs` can generate a cryptographically valid Verification Statement.

## Milestones

### Milestone 1: Core Primitives and Receipts/Signoffs
- **Scope**:
  - JCS Canonicalization (`canonicalize` and `isCanonicalizable`)
  - Basic SPKI DER public key parsing & Ed25519 signature checks
  - WebAuthn signoff validation (user presence/verification, challenge binding, RP ID hash, and ECDSA signature checks)
  - Merkle v2 leaf and branch hashing, and Merkle anchor validation (including legacy v1 and v2 options)
- **Vectors Covered**: `receipts.v1.json` (13), `signoffs.v1.json` (9), `boundary.v1.json` (3), `canonicalization.v1.json` (35)
- **Verification**: Run unit tests on Core Primitives.

### Milestone 2: Quorum Policy & Ordered Chains
- **Scope**:
  - Quorum verification (`verifyQuorum`)
  - Separation of duties (distinct human/key checks)
  - Role eligibility verification
  - Ordered mode validation (time monotonicity, sequence matching)
  - Ordered chain validation (cryptographic prev_context_hash linking)
- **Vectors Covered**: `quorum.v1.json` (11)
- **Verification**: Run quorum tests.

### Milestone 3: Revocation & Time Attestation
- **Scope**:
  - Revocation verification (`verifyRevocation`)
  - Target binding (target type, ID, action hash matching)
  - Key validation and pinning (revoker ID key match)
  - Validity time check and freshness window
  - Time Attestation verification (`verifyTimeAttestation`)
  - TSA key pinning, time format check, and hash binding
- **Vectors Covered**: `revocation.exec.v1.json` (6), `time-attestation.v1.json` (6)
- **Verification**: Run revocation and time-attestation tests.

### Milestone 4: Trust Receipt Verification
- **Scope**:
  - Full Section 6.3 Trust Receipt verification (`verifyTrustReceipt`)
  - Context commitments (action hash validation, policy hash consistency)
  - Signoff signatures (WebAuthn Class-A and Ed25519 Class-B over context digests)
  - Separation of duties (pairwise distinct approvers, initiator exclusion, threshold checks)
  - Merkle v2 inclusion paths & empty-path single-leaf exception
  - Log checkpoints verification (log signature check, SPKI key check)
  - Checkpoint consistency check (`verifyCheckpointConsistency`)
- **Vectors Covered**: `trust-receipt.exec.v1.json` (10), `trust-receipt.timestamp-forms.v1.json` (6)
- **Verification**: Run trust-receipt tests.

### Milestone 5: Provenance Chains & Evidence Records
- **Scope**:
  - Provenance chains verification (`verifyProvenanceOffline`)
  - Delegation chain verification (inter-hop binding, expiration, signature check, scope containment)
  - Constraints monotonicity validation ( tighten-only constraints matching)
  - Evidence Record verification (`verifyEvidenceRecord`)
  - Hash-linkage between renewals (RFC 4998 renewal chain)
  - Monotonic time check
- **Vectors Covered**: `provenance.exec.v1.json` (6), `evidence-record.v1.json` (5)
- **Verification**: Run provenance and evidence-record tests.

### Milestone 6: Currency, SMT Consumption, Witness, & RFC 3161 Timestamp
- **Scope**:
  - Currency evaluation (`evaluateCurrency`)
  - SMT Consumption Proof verification (`verifyConsumptionProof`)
  - Witness Quorum verification (`requireWitnessQuorum`)
  - RFC 3161 Timestamp Proof verification (`verifyTimestampProof`) with pure-Node DER/CMS parsing
- **Vectors Covered**: `currency.v1.json` (12), `consumption-proof.v1.json` (6), `witness.v1.json` (6), `timestamp-proof.v1.json` (13), `initiator-attestation.v1.json` (11)
- **Verification**: Run all primitive/profile tests.

### Milestone 7: Integration & End-to-End Conformance Verification
- **Scope**:
  - Package all verifiers in a single self-contained JS script runner (`examples/external-verification/out/run-independent.mjs`)
  - Process all 16 JSON vector suites and output `.results.json` files for each
  - Run the official `sign-statement.mjs` against the generated results
  - Assert that a 161/161 verified `statement.json` is generated successfully
- **Verification**: Execute `self-test` or verify final `statement.json` output.
