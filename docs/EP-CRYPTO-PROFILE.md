<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-CRYPTO-PROFILE — declared, fail-closed crypto boundary

A deployment **declares** which cryptographic algorithms it is allowed to use, and
the system **fails closed** if asked to operate outside that boundary. This is the
policy seam a FIPS-140 buyer needs: not "EP happens to use Ed25519," but "this
deployment refuses to sign or accept an algorithm outside its validated set."

- Module: [`lib/crypto/profile.js`](../lib/crypto/profile.js) — registry + fail-closed selector.
- Config: `EP_CRYPTO_PROFILE` (default `default`). An unrecognized value throws (`unknown_crypto_profile`) — no silent fallback.
- Gov gate: `scripts/gov-readiness-check.mjs` asserts a declared profile is *satisfiable* before a deployment is called ready.

## Profiles

| id | signing algorithms | FIPS boundary | requires custody |
|----|--------------------|---------------|------------------|
| `default` | Ed25519 (issuer/receipt) + ES256 (WebAuthn Class-A signoff) | no | no |
| `fips` | ES256 (ECDSA P-256) only | yes | yes (KMS/HSM) |

`fips` excludes Ed25519 **by default** because FIPS-140 validated *modules*
broadly cover ECDSA P-256/P-384 and RSA, while validated **EdDSA** coverage is
still thin (EdDSA is in FIPS 186-5, but certificates lag). A deployment whose
validated module *does* cover EdDSA can widen the set explicitly.

## What `fips` does — and does not — do

**Does (shipped, tested):**
- Fail-closed algorithm gate: `assertAlgAllowed(alg)` throws (`alg_outside_crypto_profile`) for anything outside the profile's set. A `fips` deployment cannot silently sign with Ed25519.
- Satisfiability gate: `assertProfileSatisfied({ custodyMode })` — a `fips` profile is **not ready** unless signing occurs in a validated module (`EP_KEY_CUSTODY_MODE=kms` or `hsm`, see [`EP key custody`](../lib/key-custody.js)). Wired into `gov:check`.
- Honest, declared boundary an auditor can inspect and test.

**Does NOT (the seam, tracked, not shipped):**
- Make EP FIPS-*validated*. Full end-to-end FIPS operation ALSO requires:
  1. Signing inside a FIPS 140-validated module — provided by a KMS/HSM custody signer (`registerCustodySigner`, already wired into commit signing at `lib/commit.js`); and
  2. The **verifier accepting P-256 issuer signatures** — an additive, conformance-gated change to the frozen `packages/verify` core, tracked in `draft-schrock-ep-pqc` and the assurance-classes work. Until that lands, `fips` is a policy + custody boundary, not a shipped P-256 receipt path.

This document is deliberately explicit about (2) so "profile set to fips" is never
mistaken for "FIPS validated." The profile boundary is real and enforced today;
the P-256 issuer-verify path is the remaining, conformance-gated step.

## Relationship to the algorithm-agility / PQC work
`EP-CRYPTO-PROFILE` is the *runtime selector*; `draft-schrock-ep-pqc` is the
*protocol-level* algorithm registry and hybrid (Ed25519 + ML-DSA/SLH-DSA)
migration path. The profile's `fips` set and the PQC draft's registry are the same
idea at two layers — a deployment picks a profile; the draft defines what the
verifier will accept. Widening the frozen verifier to a new algorithm (P-256,
ML-DSA) is the conformance-gated step both share.
