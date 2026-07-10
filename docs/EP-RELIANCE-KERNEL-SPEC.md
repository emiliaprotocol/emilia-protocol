<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-RELIANCE-KERNEL-v1

**EMILIA is not a receipt protocol. EMILIA is a reliance kernel for agentic action.**

## The primitive

A receipt proves a named human authorized an action. **Reliance** proves the
whole evidence packet is good enough for *someone else* to act on — to release
money, execute an irreversible action, underwrite a control, accept an audit
exhibit, or settle a liability. That is the commercial control point:

- banks rely before releasing money,
- insurers rely before underwriting control quality,
- auditors rely before accepting evidence,
- marketplaces rely before settling agent transactions,
- tool/model platforms rely before allowing an irreversible action.

The kernel composes the legs the rest of the stack proves separately:

```
identity
+ device-bound ceremony
+ scoped authority
+ policy match
+ freshness / revocation
+ one-time consumption
+ evidence completeness
= reliance verdict
```

## The key upgrade: authority is an input, not an internal check

The kernel does not emit `authorized: true`. It emits a **closed, portable
reliance verdict**, and it treats authority as one admissibility *input*. The
relying party pins its OWN profile (`EP-RELIANCE-PROFILE-v1`, see
[EP-RELIANCE-PROFILE-SPEC.md](EP-RELIANCE-PROFILE-SPEC.md)) and the kernel
mechanically decides whether the evidence is admissible under *that* rule:

> We do not ask you to trust our receipt. We let you pin your own reliance rule
> and mechanically decide whether the evidence is admissible.

## The closed verdict set

`evaluateReliance(...)` (`packages/verify/reliance.js`) returns exactly one of a
fixed set. `rely` is the only success; every other verdict is a fail-closed
refusal:

| Verdict | Cause |
|---|---|
| `rely` | Every pinned requirement is satisfied. |
| `do_not_rely_no_profile` | No pinned EP-RELIANCE-PROFILE-v1 was supplied. Verification can pass; reliance cannot without a rule. |
| `do_not_rely_unsigned` | The receipt did not cryptographically verify (or does not attest this action). |
| `do_not_rely_untrusted_issuer` | The transparency checkpoint was not signed by a pinned issuer key. |
| `do_not_rely_no_class_a` | Profile requires Class-A and no valid device-bound signoff is present. |
| `do_not_rely_quorum_unsatisfied` | Profile requires quorum and no satisfied EP-QUORUM-v1 bound to the action is present. |
| `do_not_rely_authority_missing` | Authority required, but no (or an unverifiable) EP-AUTHORITY-PROOF-v1. |
| `do_not_rely_authority_subject_mismatch` | The authority proof belongs to a subject who is not the verified approver of this action. |
| `do_not_rely_authority_organization_mismatch` | The signed action, authority proof, and organization-scoped registry pin do not name the same organization. |
| `do_not_rely_authority_revoked` | The authority proof (or a bound revocation statement) shows revoked. |
| `do_not_rely_authority_expired` | The authority is outside its validity window at reliance time. |
| `do_not_rely_scope_mismatch` | The action is not within the authority's scope. |
| `do_not_rely_amount_exceeded` | The amount exceeds the authority ceiling (or is in an unprovable currency). |
| `do_not_rely_policy_mismatch` | The action policy hash is not on the accepted list (or the authority pins a different policy). |
| `do_not_rely_stale_revocation` | The revocation check is older than the pinned freshness bound. |
| `do_not_rely_already_consumed` | The one-time authorization has already been consumed. |
| `do_not_rely_registry_unavailable` | The authority registry key is not pinned / the registry head is stale or equivocates. |

## Two invariants the composition enforces

**No pinned profile, no reliance.** The kernel never returns `rely` without a
relying-party-pinned `EP-RELIANCE-PROFILE-v1`. A packet can VERIFY (all crypto
checks out) with no profile; it can never be RELIED ON without a rule. An absent
or unrecognized profile is `do_not_rely_no_profile`, evaluated before anything
else.

**Authority is bound to the human who actually approved.** Proving "a valid
Class-A ceremony happened" and "a valid authority proof exists" is not enough if
they belong to two different people. The kernel joins them: the authority proof
`subject` MUST be the verified approver of THIS action. Under `class_a` the
subject must be the Class-A signer; under `quorum` it must be a verified quorum
member; under `signed` it must be a verified approver on the receipt. Otherwise
Alice's signoff plus Bob-CFO's authority proof would compose to `rely` though
Bob never approved. That is `do_not_rely_authority_subject_mismatch`.

**Authority is evaluated against signed action material.** Action type, amount,
currency, organization, and policy are extracted from the verified receipt and its signed
contexts. A caller may repeat those fields as a convenience, but a mismatch is
`do_not_rely_unsigned`; the caller's summary is never an authority input. This
prevents a receipt for a high-value action from being tested against a lower
caller-supplied amount, or an accepted authority and policy from being composed
over a receipt signed under another policy.

**Authority is organization-bound three ways.** The organization in the signed
action, the organization in the signed authority proof, and the organization on
the relying party's pinned registry-key entry MUST match. A registry key pin
without `organization_id` is structurally invalid. This prevents a valid grant
from one tenant or legal entity being composed over another entity's action.

**Registry state is pinned, not merely signed.** The matching organization key
pin also supplies `min_epoch` and the exact `registry_head`. The authority-proof
verifier enforces both, so an authentic but stale snapshot or a different head at
the expected trust point is `do_not_rely_registry_unavailable`.

## Composition (deterministic, fail-closed)

The kernel introduces **no new cryptography**. Every leg is delegated to a frozen
offline verifier and the results are composed into one verdict:

- receipt + Class-A + consumption/currency → `verifyTrustReceipt`
- quorum → `verifyQuorum`
- revocation statements → `verifyRevocation`
- positive consumption evidence → `verifyConsumptionProof`
- scoped authority → `verifyAuthorityProof` (the offline port in `packages/verify/authority-proof.js`, byte-identical to the reference `lib/authority/proof.js`)

Revocation freshness is accepted only from an already verified, pinned
authority proof carrying `not_revoked` and `checked_at`, or from a complete
signed revocation artifact verified under a pinned revoker. A presenter-supplied
bare timestamp is not evidence.

An unconsumed claim is inherently relying-party state, not portable presenter
evidence. When a profile requires `consumption_proof`, the kernel requires a
synchronous `isConsumed({ receipt_id, action_hash })` callback owned by the
relying party. Missing, throwing, asynchronous, or indeterminate lookups refuse.
A presenter can prove that a receipt *was* consumed; it cannot prove the
negative by sending `{ consumed: false }`.

All cryptographic verification remains offline. The decision core has no
network client and follows a fixed precedence, but profiles that require
one-time-use necessarily inject the relying party's local consumption-state
lookup. That trust boundary is explicit rather than hidden in the packet.

## Runtime enforcement

`packages/gate/reliance-kernel.js` (`createRelianceKernel`) is the deny-by-default
runtime point: it binds one relying-party profile, evaluates a packet, appends
the decision to a tamper-evident evidence log, and — on anything other than
`rely` — returns a machine-readable refusal (HTTP 428, the same Receipt-Required
status the Gate uses) naming the closed verdict and the required evidence. It
never re-derives a verdict; it enforces the one the pure verifier computed. A
strict evidence-log failure denies.

## Verified vs. accepted

Registered as `evidence-admissible-under-pinned-reliance-profile` in the
[Admissibility Invariant Registry](ADMISSIBILITY-INVARIANT-REGISTRY.md):

- **VERIFIED** = every composed leg checks out under the offline verifiers.
- **ACCEPTED (`rely`)** = those results additionally satisfy the relying party's
  own pinned profile. A packet that verifies but does not meet the pinned
  profile is `do_not_rely`, not `rely`. **Reliance is the relying party's
  decision, never EMILIA's.**

## Conformance

`conformance/vectors/reliance.v1.json` carries a positive `rely` and a reject
vector for every `do_not_rely_*` verdict; `tests/reliance-kernel.test.js`
assembles a fully-valid packet with live signatures and breaks exactly one leg
per vector. Unit invariants additionally pin the joins between signed action
material, authority policy, the ceremony that achieved assurance, and the
checkpoint issuer key.
