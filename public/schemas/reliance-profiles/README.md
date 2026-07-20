# Regulated reliance profiles (EP-RELIANCE-PROFILE-REGISTRY-v1)

Certified `EP-RELIANCE-PROFILE-v1` bodies for regulated flows. A registrar signs
each into an `EP-RELIANCE-PROFILE-REGISTRY-v1` entry (see
`packages/verify/reliance-profile-registry.js` and
`docs/EP-RELIANCE-PROFILE-REGISTRY-SPEC.md`). A relying party pins ONE registrar
key plus a `profile_id` and `registry_epoch`, then computes the SAME reliance
verdict over the same automated action as every other party pinning that profile.

## What is fixed vs. overlaid

The published body fixes the **regulatory requirements**: the assurance floor,
whether scoped authority is required, the revocation-freshness bound, and the
required evidence legs. The **trust anchors are the relying party's own**: it
overlays organization-scoped `accepted_registry_keys` (including minimum epoch
and exact head), `accepted_issuer_keys`, and
`accepted_policy_hashes` (the specific keys and policy hashes it trusts) onto the
resolved profile before evaluation. The published arrays are therefore empty.

VERIFIED (the entry signature holds) is never ACCEPTED (the registrar key is
pinned by the relying party). Both are separate fields on the verifier result.

| profile_id | flow | assurance | revocation freshness |
|---|---|---|---|
| `ncpdp.specialty-pa.v1` | NCPDP specialty medication prior auth | class_a | 3600s |
| `cms.prior-auth.v1` | CMS prior authorization (medical) | class_a | 900s |
| `medi-cal.hospice-integrity.v1` | Synthetic Medi-Cal hospice authorization and claim-payment integrity | class_a | 900s |

These are seed profiles. They are individual, versioned artifacts, not a
regulatory endorsement of any kind.
