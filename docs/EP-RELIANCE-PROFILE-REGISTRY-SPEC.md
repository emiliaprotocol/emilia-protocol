<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-RELIANCE-PROFILE-REGISTRY-v1

**The clearinghouse layer: signed, pinnable, certified reliance profiles for regulated flows.**

The reliance kernel ([EP-RELIANCE-KERNEL-SPEC.md](EP-RELIANCE-KERNEL-SPEC.md))
lets a relying party pin its OWN rule. The profile registry is the layer above:
a registrar publishes and signs a named `EP-RELIANCE-PROFILE-v1` for a regulated
flow, so every payer, PBM, pharmacy, agency, bank, or model platform pins ONE
registrar key plus a `profile_id` and epoch and computes the **same** reliance
verdict over the **same** automated action. That is the commercial control
point: which evidence is admissible before anyone acts.

## The entry

```json
{
  "@type": "EP-RELIANCE-PROFILE-REGISTRY-v1",
  "profile_id": "ncpdp.specialty-pa.v1",
  "registry_epoch": 3,
  "profile": { "@type": "EP-RELIANCE-PROFILE-v1", "...": "..." },
  "profile_hash": "sha256:…",
  "issued_at": "2026-07-07T00:00:00.000Z",
  "signature": {
    "algorithm": "Ed25519",
    "public_key": "…base64url SPKI…",
    "key_id": "ep:reliance-registry-key:sha256:…",
    "entry_digest": "sha256:…",
    "signature_b64u": "…"
  }
}
```

`profile_hash` binds the inner profile, so a lying hash cannot substitute a
different profile under the same signature. `entry_digest` covers the whole
signed body (domain-separated: `EP-RELIANCE-PROFILE-REGISTRY-v1\0` + canonical
JSON), so any post-signing mutation of the entry is caught before the signature
is even checked.

## Fixed vs. overlaid

A published profile fixes the **regulatory requirements** (assurance floor,
whether scoped authority is required, revocation-freshness bound, required
evidence). The **trust anchors are the relying party's own**: it overlays
`accepted_registry_keys`, `accepted_issuer_keys`, and `accepted_policy_hashes`
onto the resolved profile before calling `evaluateReliance`. The published key
arrays are empty by construction. The regulator (or registrar) fixes the bar;
the relying party fixes whom it trusts.

## Verified vs. accepted

`verifyRelianceProfileEntry(entry, { pinnedRegistryKeys, expectProfileId, expectMinEpoch })`
keeps the two separate:

- **VERIFIED** = the Ed25519 signature, the entry digest, and the inner profile
  hash all hold, and the inner profile is a well-formed `EP-RELIANCE-PROFILE-v1`.
- **ACCEPTED** = verified AND the registrar key was pinned out of band by the
  relying party AND the `profile_id` / `registry_epoch` freshness pins are
  satisfied.

A signed entry under an unpinned key is `verified: true, accepted: false` with
reason `registry_key_not_pinned`: the profile is surfaced for inspection but is
not trusted. Fail-closed throughout: unsupported version, malformed or invalid
signature, digest or hash mismatch, an ill-formed inner profile, a `profile_id`
mismatch, or a stale epoch each refuse.

## Seed profiles

`public/schemas/reliance-profiles/` ships `ncpdp.specialty-pa.v1` and
`cms.prior-auth.v1`. These are individual, versioned artifacts. They are not a
regulatory endorsement.

## Conformance

`conformance/vectors/reliance-profile-registry.v1.json` +
`tests/reliance-profile-registry.test.js`: a pinned accept, a verified-but-
unpinned case, and a reject for tampered body, tampered hash, invalid signature,
`profile_id` mismatch, and stale epoch.
