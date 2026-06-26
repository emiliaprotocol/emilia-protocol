# PIP-015 — Crypto-Agility & Post-Quantum Profile

**Status:** Draft (flag-plant; profile + roadmap, reference implementation follow-on)
**Builds on:** `draft-schrock-ep-authorization-receipts`, EP-EVIDENCE-RECORD (existing algorithm-aging
renewal), PIP-012 (registry).
**Scope note:** This profile stakes EP's crypto-agility and post-quantum posture. The hybrid signing
path is specified here and is reference-implementation follow-on; today's receipts are Ed25519 over
RFC 8785 (JCS), and EP-EVIDENCE-RECORD already renews digests across algorithm aging (e.g.
SHA-256 → SHA-384). This is a forward claim made honestly: a profile and roadmap, not a shipped PQC
verifier.

## 1. Why

High-assurance and government deployments are moving toward post-quantum readiness (NIST PQC
standards; NSA CNSA 2.0 migration timeline; EU cyber-resilience direction). An authorization-receipt
layer that signs records meant to be verifiable for *years* (multi-year regulatory retention) must be
crypto-agile and have a credible PQC path, or it is excluded from high-assurance procurement. EP's
long-lived receipts make this non-optional over the standardization horizon.

## 2. Algorithm registry

Receipts and signoffs carry an explicit algorithm identifier so verifiers select the right path.

| Class | Algorithm | NIST ref | Use |
|---|---|---|---|
| Classical (today) | Ed25519 (EdDSA) | — | Default receipt/signoff signature |
| Classical (device) | ECDSA P-256 (ES256) | — | WebAuthn / Class-A device signoff |
| PQC signature | **ML-DSA** (Dilithium) | **FIPS 204** | Post-quantum receipt/signoff signature |
| PQC signature (hash-based) | **SLH-DSA** (SPHINCS+) | **FIPS 205** | Conservative/stateless-hash high-assurance option |
| Digest agility | SHA-256 → SHA-384 / SHA-512 | FIPS 180-4 | Action-digest + Merkle (already in EP-EVIDENCE-RECORD) |

(ML-KEM / FIPS 203 is key-encapsulation, not signatures, and is out of scope for the authorization
signature; noted only to disambiguate.)

## 3. Hybrid mode (the migration path)

A **hybrid signature** carries *both* a classical (Ed25519) and a PQC (ML-DSA) signature over the
same JCS-canonical payload. A receipt verifies under hybrid policy only if **both** verify. This gives:

- **Backward verifiability** — classical-only verifiers still check the Ed25519 part.
- **Forward security** — once "harvest-now-decrypt-later" matters, the ML-DSA part carries the weight.
- **No flag day** — issuers add the PQC signature; verifiers upgrade independently.

```
signature: {
  algorithm: "hybrid-ed25519+ml-dsa-65",
  classical: { algorithm: "Ed25519", value: "<b64u>" },
  pqc:       { algorithm: "ML-DSA-65", value: "<b64u>" }
}
```

## 4. Verifier policy

A verifier declares an accepted-algorithm policy: `classical-only` (today), `hybrid-required`
(transition), or `pqc-required` (post-migration). Fail-closed: an algorithm not in policy is a
rejection, not a downgrade.

## 5. Crosswalk

- Composes with EP-EVIDENCE-RECORD: long-term receipts are re-anchored under stronger algorithms as
  they age, so a receipt issued today stays verifiable after the PQC transition.
- China-market note: SM2/SM3 (and PQC adaptations) can register in the same algorithm registry for
  jurisdictions that require national algorithms — same agility mechanism, different identifiers.

## 6. Built vs. to build (honest)

| Piece | Status |
|---|---|
| Explicit algorithm identifiers in receipts/signoffs | partially present (algorithm field) |
| Digest agility (SHA-256→384) across renewal | **shipped** (EP-EVIDENCE-RECORD) |
| Hybrid Ed25519+ML-DSA signing/verify in the verifiers | to build (needs a vetted ML-DSA lib; do not hand-roll) |
| Accepted-algorithm verifier policy | to build |
| Conformance vectors (hybrid + pqc-required) | to build |
