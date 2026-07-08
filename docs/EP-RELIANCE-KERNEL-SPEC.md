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

## Composition (pure, offline, fail-closed)

The kernel introduces **no new cryptography**. Every leg is delegated to a frozen
offline verifier and the results are composed into one verdict:

- receipt + Class-A + consumption/currency → `verifyTrustReceipt`
- quorum → `verifyQuorum`
- revocation → `verifyRevocation`
- one-time consumption evidence → `verifyConsumptionProof`
- scoped authority → `verifyAuthorityProof` (the offline port in `packages/verify/authority-proof.js`, byte-identical to the reference `lib/authority/proof.js`)

No database, no network, no operator trust. Evaluation follows a fixed
precedence and returns the first failing gate, so the verdict is deterministic
across implementations.

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
per vector.
