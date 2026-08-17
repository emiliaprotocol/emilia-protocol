# Project: EMILIA Protocol Clean-Room Verifier

## Architecture
- Self-contained, native Node.js verifier runner at `examples/external-verification/out/run-independent.mjs`
- Custom JCS canonicalization and DER/CMS parsers inside the runner.
- Standard Node.js `crypto` for SPKI DER public key importing, Ed25519, and ECDSA P-256 signature verification.

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Core Primitives | canonicalize, verifyReceipt, verifyWebAuthnSignoff, verifyMerkleAnchor | none | DONE |
| 2 | Quorum Policy & Ordered Chains | verifyQuorum | M1 | DONE |
| 3 | Revocation & Time Attestation | verifyRevocation, verifyTimeAttestation | M1 | DONE |
| 4 | Trust Receipt Verification | verifyTrustReceipt, verifyCheckpointConsistency | M1, M2, M3 | DONE |
| 5 | Provenance & Evidence Record | verifyProvenanceOffline, verifyEvidenceRecord | M3, M4 | DONE |
| 6 | Primitive/Profile Verifiers | evaluateCurrency, verifyConsumptionProof, requireWitnessQuorum, verifyTimestampProof (RFC 3161) | M1, M3, M4 | DONE |
| 7 | End-to-End Verification | Integrate all verifiers into the runner, run over 161 vectors, generate statements | M1-M6 | DONE |

## Interface Contracts
- Each verifier method matches the signature of the corresponding function in `packages/verify`.
- The runner accepts a path to a vector JSON suite file and prints a JSON array of `[{"id": "...", "valid": boolean}]` to stdout.
