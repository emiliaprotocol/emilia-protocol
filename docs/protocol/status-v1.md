# EP-STATUS-v1

`EP-STATUS-v1` is a closed, signed current-status artifact for a receipt,
commit, or delegation. It closes one narrow gap: the absence of a revocation
record is not evidence that an authorization remains usable.

The relying party pins an authority domain, authority identifier, Ed25519 root
key identifier, and public key. That root signs an
`EP-REVOKER-AUTHORITY-v1` certificate delegating one status key for an explicit
set of target types and usages. The delegated key signs the exact target,
state, sequence, predecessor digest, issue time, and next-update time.

The verifier has three outcomes:

- `current_not_revoked`: the artifact, delegation, target, scope, signature,
  sequence, predecessor, and freshness window all verify;
- `revoked`: an effective signed revocation verifies and is terminal; or
- `indeterminate`: anything is missing, stale, malformed, untrusted,
  rollback-prone, outside scope, or unverifiable.

An affirmative status is valid only while `issued_at <= now < next_update` and
within the delegated authority certificate. A revocation has no
`next_update`; once accepted, no later `not_revoked` artifact may resurrect the
target. Sequence numbers and the relying-party-held predecessor digest prevent
a presenter from rolling status back to an older signed head.

All signed object boundaries reject unknown fields. Signing uses RFC 8785 JSON
Canonicalization Scheme bytes with explicit domain separation and Ed25519.
Key, authority, target, scope, and time inputs are relying-party policy; the
presenter cannot select them.

This artifact proves only the signed status statement within the authority and
completeness boundary the relying party chose. It does not prove that the
authority observed every possible revocation source. Deployments must pin the
authority whose status domain they are willing to rely on.

Reference verification is exported from
`@emilia-protocol/verify/status`. Issuance uses an external signer interface so
production deployments can keep the status root and delegated key in KMS or
HSM custody.
