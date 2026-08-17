# EMILIA Protocol Cleanroom Rust Verifier — End-to-End Test Infrastructure

This document outlines the End-to-End (E2E) Test Infrastructure for the EMILIA Protocol Cleanroom Rust Verifier. It details the 15 core features of the EMILIA Protocol, their mapping to a 4-tier testing structure, and the exact vector inventory of 161 vectors across 16 conformance files.

---

## 1. Core Verification Features

The Cleanroom Rust Verifier is designed to verify the following 15 core features of the EMILIA Protocol:

1. **JCS JSON Canonicalization (`EP-CANONICALIZATION-v1`)**
   Enforces RFC 8785 (JSON Canonicalization Scheme) and I-JSON rules, including sorting object keys by UTF-16 code units, depth limits ($\le 64$), and rejection of duplicate keys or unpaired UTF-16 surrogates.
   
2. **Offline-Verifiable Authorization Receipts (`EP-RECEIPT-v1`)**
   Cryptographic verification of Ed25519 signatures over recursive canonical JSON structures, verifying action digests, issuer, subject, nonce, and expiration.

3. **Device-Bound Human Signoffs (`EP-SIGNOFF-v1`)**
   Validation of WebAuthn ECDSA P-256 signatures, checking UV/UP flags, Relying Party ID binding, and ceremony constraints.

4. **Multi-Party Quorum (`EP-QUORUM-v1`)**
   M-of-N threshold logic, pairwise distinct human approver verification (Separation of Duties), monotonic chronological sequence enforcement, and bounded approval windows.

5. **Transparency Log Commitments (`EP-TRUST-RECEIPT-v1`)**
   Integration of WebAuthn signoffs, Merkle inclusion proof paths, and log checkpoint signature verification.

6. **Trusted-Time Attestation (`EP-TIME-ATTESTATION-v1`)**
   Verification of trusted-time assertions from trusted Time Stamp Authorities (TSAs) to establish commit times.

7. **RFC 3161 Timestamp Proofs (`EP-TIMESTAMP-PROOF-v1`)**
   CMS SignedData parsing and signature verification over receipt digests using pinned TSA public keys.

8. **Delegated Provenance Chains (`EP-PROVENANCE-CHAIN-v1`)**
   Authority chain validation verifying scope narrowing (e.g. max value caps) from root signoffs down to the executing agent.

9. **Crypto-Agile Evidence Records (`EP-EVIDENCE-RECORD-v1`)**
   RFC 4998-compliant evidence records supporting algorithm transitions (e.g. SHA-256 to SHA-384) over historical time chains.

10. **Continuous Posture Signals (`EP-EYE-SET-v1`)**
    Validation of signed Security Event Tokens (SETs) containing posture advisories (e.g. "never the sole gate" marker, audience checking, expirations).

11. **Authorization/Attribution Boundary (`EP-BOUNDARY-v1` / `EP-ATTRIBUTION-v1`)**
    Enforces distinct operational boundaries, ensuring post-execution attribution receipts cannot be used in pre-execution authorization slots.

12. **Offline Currency (`EP-CURRENCY-v1`)**
    Verifies relative stale thresholds and log commit states to evaluate currency status (`fresh`, `stale`, or `unknown`).

13. **Neutralized Hostile Text (`EP-INITIATOR-ATTESTATION-v1`)**
    Field validation and neutralization of bidi controls, confusable homoglyphs, and C0/C1 control characters in model/agent inputs.

14. **Double-Spend Prevention (`EP-SMT-CONSUME-v1`)**
    Sparse Merkle Tree (SMT) non-inclusion/inclusion transition verification for one-time nonce consumption.

15. **Checkpoint Witnessing (`EP-WITNESS-v1`)**
    Verification of $k$-of-$n$ distinct witness cosignatures over the head of log checkpoints.

---

## 2. 4-Tier Testing Structure Mapping

The E2E Test Suite organizes features and boundaries into a 4-tier testing hierarchy:

```
+------------------------------------------------------------------------------------+
| Tier 4: Real-World & E2E Integration (System Lifecycle)                             |
| - Stateful nonce double-spend, live multi-party ceremonies, dynamic posture webhooks|
+------------------------------------------------------------------------------------+
                                         ▲
                                         │
+------------------------------------------------------------------------------------+
| Tier 3: Cross-Feature Interaction & Composition Integration                        |
| - Quorum composed with revoked keys, evidence record renewal under algorithm changes |
+------------------------------------------------------------------------------------+
                                         ▲
                                         │
+------------------------------------------------------------------------------------+
| Tier 2: Boundary & Security Validation (Negative & Parser Limits)                  |
| - JCS nesting boundary (depth > 64), duplicate keys, hostile text, float drift     |
+------------------------------------------------------------------------------------+
                                         ▲
                                         │
+------------------------------------------------------------------------------------+
| Tier 1: Feature Coverage (Unit & Functional)                                       |
| - Ed25519 signatures, WebAuthn assertion math, basic quorum math, TSA key checks   |
+------------------------------------------------------------------------------------+
```

*   **Tier 1: Feature Coverage**  
    Exercises the verifier on basic, happy-path scenarios, verifying that valid signatures, credentials, and constraints are correctly recognized.
*   **Tier 2: Boundary & Security Validation**  
    Enforces negative tests, checking that the verifier fails closed when parsing malformed JSON, duplicate keys, deeply nested objects, or when executing against tampered signatures, wrong keys, and expired timestamps.
*   **Tier 3: Cross-Feature Interaction**  
    Tests composition of features, such as validating a quorum of WebAuthn signoffs within a trust receipt or verifying evidence records that contain time attestations.
*   **Tier 4: Real-World & E2E Integration**  
    Tests the end-to-end lifecycle, including double-spend prevention through active database/SMT verification and live webhook integrations.

---

## 3. Conformance Vectors Inventory

The verifier conformance is validated against **161 vectors** across **16 JSON files** from `conformance/vectors/`.

| File Name | Target Feature / Profile | Accept | Reject | Total Vectors |
| :--- | :--- | :---: | :---: | :---: |
| `receipts.v1.json` | `EP-RECEIPT-v1` (Core Receipts) | 5 | 8 | **13** |
| `signoffs.v1.json` | `EP-SIGNOFF-v1` (WebAuthn Signoffs) | 1 | 8 | **9** |
| `quorum.v1.json` | `EP-QUORUM-v1` (Multi-Party Quorum) | 5 | 8 | **13** |
| `revocation.exec.v1.json` | `EP-REVOCATION-v1` (Revocation Statements) | 1 | 5 | **6** |
| `time-attestation.v1.json` | `EP-TIME-ATTESTATION-v1` (Time Attestation) | 1 | 5 | **6** |
| `trust-receipt.exec.v1.json` | `EP-TRUST-RECEIPT-v1` (Trust Receipts) | 3 | 8 | **11** |
| `trust-receipt.timestamp-forms.v1.json` | `EP-TRUST-RECEIPT-v1` (Timestamp Formats) | 1 | 5 | **6** |
| `provenance.exec.v1.json` | `EP-PROVENANCE-CHAIN-v1` (Provenance) | 2 | 4 | **6** |
| `evidence-record.v1.json` | `EP-EVIDENCE-RECORD-v1` (Evidence Records) | 2 | 3 | **5** |
| `canonicalization.v1.json` | `EP-CANONICALIZATION-v1` (JCS Parsing) | 6 | 29 | **35** |
| `boundary.v1.json` | `EP-BOUNDARY-v1` (Attribution Boundary) | 1 | 2 | **3** |
| `currency.v1.json` | `EP-CURRENCY-v1` (Currency Evaluation) | 12 | 0 | **12** |
| `initiator-attestation.v1.json` | `EP-INITIATOR-ATTESTATION-v1` (Neutralization) | 1 | 10 | **11** |
| `consumption-proof.v1.json` | `EP-SMT-CONSUME-v1` (SMT Double-Spend) | 2 | 4 | **6** |
| `witness.v1.json` | `EP-WITNESS-v1` (Witness Cosignatures) | 1 | 5 | **6** |
| `timestamp-proof.v1.json` | `EP-TIMESTAMP-PROOF-v1` (RFC 3161) | 1 | 12 | **13** |
| **Total Vectors** | | **45** | **116** | **161** |

---

## 4. Execution & Verification Method

The conformance suite is driven by a central Python test runner (`run_tests.py`) which:
1. Locates and compiles the Rust CLI conformance runner via `cargo build --manifest-path cleanroom-rust-verifier/Cargo.toml --bin conformance`.
2. Locates the compiled binary under the Cargo output targets.
3. Feeds each of the 16 JSON vector files to the CLI binary.
4. Asserts that the output matches the expected outcomes (`expect.valid` boolean) for every vector.
