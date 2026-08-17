# EP-RECEIPT-HYBRID-v1 conformance vectors

Deterministic vectors for ISSUED hybrid receipts: one canonical byte string
signed under BOTH Ed25519 and ML-DSA-65 (FIPS 204), carried in a receipt whose
signed material commits to the full required algorithm set, so neither leg can
be stripped and the remainder replayed as an ordinary receipt.

This is the issuance-side companion to `conformance/pq-agility`. That suite
proves the SAME canonical payload bytes can be signed and verified under either
algorithm. This suite proves a Gate or issuer can MINT a receipt carrying both
at once, and that every way of taking one leg away is refused with a named
reason.

## Files

- `vectors.json` -- the vector set, plus the two captured EP-RECEIPT-v1
  verifier results.
- `generate.mts` -- regenerates `vectors.json` from fixed seed labels.
  `node conformance/hybrid-receipts/generate.mjs --check` proves the checked-in
  file is still exactly what the generator produces.
- `run.test.mts` -- executes every vector against
  `packages/issue/src/hybrid-issuance.ts`, re-derives the recorded v1-verifier
  results by running `verifyReceipt` from `packages/verify`, and re-runs the
  generator in `--check` mode. Run:
  `npx vitest run conformance/hybrid-receipts/run.test.mts`.

## What the profile signs

The bytes both legs sign are NOT `canonicalize(payload)`. They are:

```
signed_material = {
  "@version":            "EP-RECEIPT-HYBRID-v1",
  "payload":             <the receipt payload>,
  "required_algorithms": ["Ed25519", "ML-DSA-65"]
}
message_bytes   = UTF8(canonicalize(signed_material))
```

The required algorithm set is INSIDE the signed bytes. That is the
anti-stripping property, and it holds in two independent ways:

1. Remove the ML-DSA leg and narrow `required_algorithms` to `["Ed25519"]` so
   the receipt looks complete: the surviving Ed25519 signature no longer
   verifies, because the bytes changed. Vector
   `ml-dsa-leg-stripped-and-set-narrowed` refuses at the structural check, and
   `packages/issue/hybrid-issuance.test.ts` proves the cryptographic half
   separately by verifying the surviving leg against the narrowed bytes.
2. Leave the set intact and the missing leg is a structural refusal,
   `hybrid_leg_missing`.

## Why a distinct `@version`

EP-RECEIPT-v1 verifiers pin `SUPPORTED_VERSIONS = ['EP-RECEIPT-v1']` and read a
single `signature` object. A hybrid receipt carries a signature SET. Reusing the
v1 marker would have forced every deployed verifier to either refuse a valid
receipt or accept it on the strength of the one leg it understood. Accepting one
leg of two is exactly the silent downgrade this profile exists to prevent, so
hybrid receipts take their own marker and old verifiers refuse cleanly with an
unknown version.

Both refusals below are CAPTURED OUTPUT from running `verifyReceipt()` in
`packages/verify`, recorded in `vectors.json` under `v1_verifier_behaviour` and
re-derived by the test suite on every run.

An EP-RECEIPT-v1 verifier handed the hybrid receipt unchanged:

```json
{
  "valid": false,
  "checks": { "version": false, "signature": false, "anchor": null },
  "error": "Unsupported version: EP-RECEIPT-HYBRID-v1"
}
```

The hybrid receipt's Ed25519 leg lifted into an EP-RECEIPT-v1 envelope over the
same payload. The version check now passes and the signature check fails,
because that leg signed bytes naming the profile and the full algorithm set:

```json
{
  "valid": false,
  "checks": { "version": true, "signature": false, "anchor": null }
}
```

## Vector semantics

| id | expectation |
| --- | --- |
| `hybrid-valid` | verifies |
| `ed25519-leg-stripped` | refusal, `hybrid_leg_missing` (Ed25519) |
| `ml-dsa-leg-stripped` | refusal, `hybrid_leg_missing` (ML-DSA-65) |
| `ml-dsa-leg-stripped-and-set-narrowed` | refusal, `algorithm_set_mismatch` |
| `legs-over-different-bytes` | refusal, `signature_invalid` (ML-DSA-65) |
| `classical-leg-over-different-bytes` | refusal, `signature_invalid` (Ed25519) |
| `payload-tampered` | refusal, `signature_invalid` |
| `duplicate-classical-leg` | refusal, `duplicate_algorithm` |
| `algorithm-outside-committed-set` | refusal, `unexpected_algorithm` |
| `hybrid-relabelled-as-classical` | refusal, `unknown_profile` |

## Determinism and key provenance (TEST KEYS ONLY)

Every byte in `vectors.json` is reproducible from fixed public seed labels.
Never use these keys or seeds for anything real.

- Canonicalization: the EP JCS-style `canonicalize()` shared by
  `@emilia-protocol/issue` and `@emilia-protocol/verify`.
- Ed25519: private key seed = `SHA-256("EP-RECEIPT-HYBRID-v1/vectors/ed25519/1")`,
  wrapped in the RFC 8410 PKCS#8 prefix `302e020100300506032b657004220420`.
  Ed25519 signatures are deterministic per RFC 8032.
- ML-DSA-65: keygen seed = `SHA-256("EP-RECEIPT-HYBRID-v1/vectors/ml-dsa-65/1")`,
  expanded by ML-DSA.KeyGen (FIPS 204). Signing uses the FIPS 204 deterministic
  variant (`extraEntropy = false`), so the 3309-byte signature is fixed by seed
  plus message.
- Implementation used to generate and check: `@noble/post-quantum` 0.6.1, a
  pure-JS FIPS 204 implementation.

## Claim boundary

Read this before describing any of it outside the repository.

- This is an OPT-IN PROFILE. `EP-RECEIPT-v1` remains the default receipt
  format. Nothing in this repository issues hybrid receipts unless an operator
  sets `hybrid_issuance` to `enabled` or `required`
  (`packages/gate/src/hybrid-receipt-profile.ts`), and no shipped deployment
  sets it.
- NOT FIPS VALIDATED. `@noble/post-quantum` is, per its own README, not
  independently audited and not a FIPS-validated module. These vectors
  demonstrate format-level and protocol-level behaviour, not a certification.
- NOT DEPLOYED. No production Gate, no pilot, and no external party is issuing
  or consuming these receipts today. This is running code with executed
  vectors, which is a different and smaller claim than adoption.
- NOT A REGISTERED CONFORMANCE SUITE. This vector set is not in
  `conformance/suites.mjs` and does not change the published suite or vector
  totals, exactly as `conformance/pq-agility` does not.
- The property proven here is ANTI-STRIPPING AND CLEAN REFUSAL, not
  post-quantum security of the EP system as a whole. Receipts already issued
  under Ed25519 alone are not retroactively protected by this profile; that
  needs re-attestation while the classical algorithm is still unbroken
  (EP-EVIDENCE-REATTESTATION-v1, `packages/verify/src/evidence-record.ts`).

The honest sentence this work supports: post-quantum receipts, available as an opt-in hybrid profile.
