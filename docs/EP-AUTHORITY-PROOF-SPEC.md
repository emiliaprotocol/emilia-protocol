<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-AUTHORITY-PROOF-v1

**A portable, offline-verifiable snapshot of one scoped-authority grant.**

## Why a proof, not a lookup

[EP-AUTHORITY-REGISTRY-v1](EP-AUTHORITY-REGISTRY-SPEC.md) resolves a verdict, but
a verdict on its own forces the relying party to trust EP's live database at
verification time — the exact anti-pattern the admissibility doctrine forbids
("Verified is not accepted; accepted requires pinned policy"). An authority proof
is a signed, self-contained statement of what the registry held for a subject at
authorization time. The registry signs it under an issuer key; a relying party
accepts it **only** by pinning that issuer key out of band. No pin, no acceptance.

## Shape

```json
{
  "@type": "EP-AUTHORITY-PROOF-v1",
  "authority_id": "auth_cfo",
  "subject": "ada",
  "organization_id": "org1",
  "role": "cfo",
  "scope": ["large_payment_release"],
  "limits": { "max_amount_usd": 50000, "currency": "USD" },
  "validity": { "from": "2026-01-01T00:00:00.000Z", "to": "2027-01-01T00:00:00.000Z" },
  "revocation": { "status": "not_revoked", "checked_at": "2026-07-07T00:00:00.000Z" },
  "registry_head": "sha256:…",
  "registry_epoch": 17,
  "issued_at": "2026-07-07T00:00:00.000Z",
  "limitations": [ "…honest non-claims…" ],
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "ep:authority-registry-key:sha256:…",
    "public_key": "…base64url SPKI…",
    "proof_digest": "sha256:…",
    "signature_b64u": "…"
  }
}
```

## Signing and verification

The construction is deliberately identical to
`EP-EXTERNAL-VERIFICATION-STATEMENT-v1` (`packages/gate/reports/external-verification.js`):

- **Domain-separated Ed25519** over canonical bytes: `sign("EP-AUTHORITY-PROOF-v1\0" + JCS(body))`.
- **`key_id` is always re-derived** from the carried public key. The envelope
  `key_id` sits outside the signed bytes and is attacker-malleable; a present but
  divergent one is a refusal (`key_id_mismatch`).
- **Two-field result** `{ verified, accepted }`, never collapsed. `verified` = the
  signature and digest hold. `accepted` = verified **and** the issuer key is
  pinned (and any head/epoch pins are satisfied).

`verifyAuthorityProof(proof, opts)` (`lib/authority/proof.js`) refuses, with a
stable reason, on every failure mode:

| `reason` | Cause |
|---|---|
| `unsupported_version` | not `EP-AUTHORITY-PROOF-v1` |
| `signature_missing_or_malformed` | no/!Ed25519/missing public key or signature |
| `proof_digest_missing_or_malformed` | digest absent or not `sha256:<64hex>` |
| `proof_digest_mismatch` | body was altered after signing |
| `key_id_mismatch` | envelope `key_id` ≠ derived key id |
| `registry_head_mismatch` | `opts.expectRegistryHead` set and the proof's head differs (equivocation) |
| `stale_registry` | `opts.expectMinEpoch` set and the proof's epoch is lower |
| `registry_key_not_pinned` | the carried key is not in `opts.pinnedRegistryKeys` |
| `pin_mismatched_issuer` | key matched a pin, but not for the vouched issuer identity |
| `signature_invalid` | the Ed25519 check fails |

## Acceptance semantics

- **VERIFIED** = the signature is valid and the digest matches — provable on
  general infrastructure with no trust.
- **ACCEPTED** = verified **and** the registry issuer key was pinned by the
  relying party out of band, **and** the relying party's `expectMinEpoch` /
  `expectRegistryHead` freshness pins (if any) are satisfied.

## What it is not

The `limitations` array is mandatory and honest: the proof records what the
registry held at issuance; it is a **snapshot** (revocation is as of
`checked_at`, and a later revocation is not reflected); and it does **not**
itself authorize the action — acceptance requires the out-of-band pin.

## Conformance

`conformance/vectors/authority.v1.json` proof vectors cover accept-when-pinned
plus every refusal: unpinned key, tampered body, head mismatch, stale epoch, and
a forged envelope `key_id`. Signatures are reproduced at test time from a fixed
seed. Driven by `tests/authority-registry.test.ts`.
