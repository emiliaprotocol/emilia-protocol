# Project: EMILIA Protocol Cleanroom Rust Verifier

## Architecture
The EMILIA Cleanroom Rust Verifier is a pure, zero-reference-read implementation of the EMILIA Protocol verification specifications. It will be built as a Rust library (`emilia-rust-verifier`) with an accompanying CLI runner for conformance testing.

```
                  ┌──────────────────────────────────────────┐
                  │                 CLI Run                  │
                  └─────────────────────┬────────────────────┘
                                        │
                                        ▼
                  ┌──────────────────────────────────────────┐
                  │          Verification API Lib            │
                  └─────────────────────┬────────────────────┘
                                        │
      ┌───────────────────────┬─────────┼───────────┬────────────────────────┐
      ▼                       ▼         ▼           ▼                        ▼
┌───────────┐           ┌───────────┐ ┌───┐   ┌───────────┐            ┌───────────┐
│ Canonical │           │Signature /│ │SMT│   │ WebAuthn  │            │ RFC 3161  │
│    JCS    │           │  Merkle   │ │   │   │  Signoff  │            │ Timestamp │
└───────────┘           └───────────┘ └───┘   └───────────┘            └───────────┘
```

## Code Layout
- `Cargo.toml` — Cargo package manifest
- `src/lib.rs` — Library entrypoint and high-level verify APIs
- `src/canonical.rs` — RFC 8785 JSON Canonicalization Scheme & profile validation
- `src/merkle.rs` — Merkle inclusion verification
- `src/signoff.rs` — WebAuthn assertion (EP-SIGNOFF-v1) parsing and verification
- `src/timestamp.rs` — RFC 3161 DER/CMS parser & timestamp verification
- `src/provenance.rs` — Provenance delegation chain check
- `src/currency.rs` — Currency evaluation
- `src/initiator.rs` — Initiator attestation & text normalization
- `src/error.rs` — Standard error definitions
- `src/bin/conformance.rs` — Conformance runner CLI matching the cross-language format

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|---|---|---|---|
| 1 | Setup & Canonicalization | Setup Cargo workspace, enforce parse boundary (depth, duplicate keys, surrogates), and implement/verify RFC 8785 JCS canonicalization. | None | IN_PROGRESS |
| 2 | Core Receipts & Cryptography | Implement Ed25519 signature verify, Merkle inclusion checks, WebAuthn assertion parsing/verification, and Witness Quorum checks. | M1 | PLANNED |
| 3 | Advanced Time & Proofs | Implement RFC 3161 DER/CMS parsing and signature verification, Time Attestation check, and Evidence Record validation. | M2 | PLANNED |
| 4 | Quorum, Trust Receipts & Provenance | Implement Multi-party ordered quorum validation, Trust Receipts (signoff + checkpoint), and Provenance Delegation chain verification. | M3 | PLANNED |
| 5 | Profile Predicates | Implement Currency status evaluation, SMT consumption proof, and Initiator Attestation text-neutralization checks. | M4 | PLANNED |
| 6 | Integration & Conformance Run | Finalize CLI conformance runner, integrate with `conformance/run.mjs`, and verify all 161 conformance vectors. | M5 | ✅ DONE (161/161) |

## Interface Contracts
The Rust library exposes a clean, fail-closed verification API:

```rust
pub fn verify_receipt(document: &str, public_key_b64: &str) -> Result<bool, Error>;
pub fn verify_webauthn_signoff(signoff_json: &str, approver_pk_b64: &str, rp_id: Option<&str>) -> Result<bool, Error>;
pub fn verify_quorum(quorum_json: &str, rp_id: &str) -> Result<bool, Error>;
pub fn verify_revocation(target_json: &str, revocation_json: &str, revoker_keys: &[String], max_age_secs: Option<u64>, now: u64) -> Result<bool, Error>;
pub fn verify_time_attestation(time_attestation_json: &str, tsa_keys: &[String], expected_hash: &str, not_before: u64, not_after: u64) -> Result<bool, Error>;
pub fn verify_trust_receipt(trust_receipt_json: &str, approver_keys: &[String], log_public_key: &str, verify_opts: Option<VerifyOpts>) -> Result<bool, Error>;
pub fn verify_provenance_offline(provenance_chain_json: &str, delegation_keys: &[String], now_ms: u64) -> Result<bool, Error>;
pub fn verify_evidence_record(evidence_record_json: &str, tsa_keys: &[String], protected_hash: &str) -> Result<bool, Error>;
pub fn canonicalize(val: &serde_json::Value) -> Result<String, Error>;
pub fn is_canonicalizable(val: &serde_json::Value) -> bool;
pub fn evaluate_currency(args_json: &str) -> Result<CurrencyResult, Error>;
pub fn validate_initiator_attestation(attestation_json: &str) -> Result<bool, Error>;
pub fn verify_consumption_proof(proof_json: &str) -> Result<bool, Error>;
pub fn require_witness_quorum(checkpoint_json: &str, cosignatures: &[Cosignature], pinned: &[String], k: usize) -> Result<bool, Error>;
pub fn verify_timestamp_proof(proof_json: &str, expected_digest: Option<&str>, pinned_tsa_keys: Option<&[String]>) -> Result<bool, Error>;
```
