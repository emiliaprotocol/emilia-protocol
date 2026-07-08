<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-RELIANCE-PROFILE-v1

**The relying party's pinned rule for what evidence it will act on.**

A reliance profile is the thing a bank, insurer, auditor, marketplace, or model
platform pins *out of band* to say: "these are my conditions for relying on an
EMILIA evidence packet." The kernel ([EP-RELIANCE-KERNEL-SPEC.md](EP-RELIANCE-KERNEL-SPEC.md))
evaluates a packet against this profile and returns a closed verdict. EMILIA
never authors the bar; the relying party does.

## Shape

```json
{
  "@type": "EP-RELIANCE-PROFILE-v1",
  "required_assurance": "quorum",
  "required_authority": true,
  "max_revocation_staleness_sec": 300,
  "accepted_registry_keys": [{ "issuer_id": "auth_cfo", "public_key": "…base64url SPKI…" }],
  "accepted_issuer_keys": ["…base64url SPKI transparency-log key…"],
  "accepted_policy_hashes": ["sha256:…"],
  "required_evidence": [
    "receipt",
    "class_a_or_quorum",
    "authority_proof",
    "revocation_freshness",
    "consumption_proof"
  ]
}
```

## Fields

| Field | Meaning |
|---|---|
| `required_assurance` | The ceremony floor: `signed` (a valid receipt), `class_a` (a device-bound named-human signoff), or `quorum` (a satisfied M-of-N bound to the action). |
| `required_authority` | When true, a valid, accepted `EP-AUTHORITY-PROOF-v1` is required and its scope/limit/validity/revocation are judged against the action. |
| `max_revocation_staleness_sec` | The freshness bound on the revocation check (when `revocation_freshness` is required). |
| `accepted_registry_keys` | The authority-registry issuer keys the relying party pins. An authority proof signed by any other key yields `do_not_rely_registry_unavailable`. |
| `accepted_issuer_keys` | The transparency-log / checkpoint keys the relying party trusts. A checkpoint signed by any other key yields `do_not_rely_untrusted_issuer`. |
| `accepted_policy_hashes` | The policy hashes the relying party will act under. An action outside the list yields `do_not_rely_policy_mismatch`. |
| `required_evidence` | Which legs must be present: `receipt`, `class_a_or_quorum`, `authority_proof`, `revocation_freshness`, `consumption_proof`. A required-but-absent leg fails closed to the leg's verdict. |

## Why this is the standards flag

Every evidence format in the agent-action space specifies *verification* and
leaves *acceptance* to "pinned out of band." `EP-RELIANCE-PROFILE-v1` makes
acceptance itself a **portable, mechanical, replayable object**: two relying
parties with the same profile and the same packet compute the same verdict, and
a relying party can hand its profile to an auditor to show exactly what it
required before it acted. That is the difference between "trust our receipt" and
"pin your own rule and decide."

## Design rules

- **Fail-closed.** A required-but-absent or malformed leg is a refusal, never a
  pass. An unset/unknown `required_assurance` defaults to `signed`.
- **The relying party pins every root.** EMILIA is never in the trust path; it
  supplies the evidence and the mechanical evaluator, not the bar.
- **Verified ≠ accepted.** A packet can verify (all crypto checks out) and still
  be `do_not_rely` because it does not meet *this* profile.
