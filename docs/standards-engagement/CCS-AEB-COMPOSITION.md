<!-- SPDX-License-Identifier: Apache-2.0 -->

# Candidate CCS to AEB composition profile

## Ownership boundary

CCS owns the native tool-invocation policy decision. Its native verifier owns
the meaning of `allow`, `deny`, and `escalate`, its rule evaluation, and the
integrity of its receipt.

AEB does not reinterpret those states. It accepts a natively verified CCS
`allow` only as one `machine-policy-decision` evidence leg, maps the protected
tool and parameters to the executor's independently constructed CAID, evaluates
the relying party's complete AEC requirement, makes a separate local
authorization decision, and reserves every replay identity before provider
entry.

## Current runnable profile

The runnable adapter is source-locked to the PyPI distribution labeled
`ccs-verifier==1.1.0` whose installed runtime reports version `0.4.1`. It
verifies the HMAC bytes emitted by that package. Because this is a shared-key
artifact, the key is pinned to one relying party and one audience. The profile
does not claim portable or independent public-key verification.

The adapter maps only integrity-covered material:

```text
CCS command.tool    -> observed_action.parameters.tool
CCS command.params  -> observed_action.parameters.arguments
```

The executor constructs the observed action. It never trusts the CCS `action`
string as a CAID and never infers execution authority from a CCS verdict.
The unsigned CCS `agent_id` is not action material in this profile and does not
establish initiator identity; the AEB executor authenticates and records its
initiator separately.

## Replay and authority are separate

The CCS result identity fences replay of one native CCS decision. It does not
identify or consume the authority that permits provider entry. A complete AEB
deployment therefore reserves the CCS replay identity together with every
other required native replay identity, including the execution-authority leg.

The hostile suite proves the distinction by producing a second, valid CCS
receipt for the same exact action after an indeterminate attempt. The CCS
receipt is fresh, but the execution authority is still reserved, so the second
provider admission is refused.

## Post-effect evidence is not pre-action policy evidence

The CCS drafts describe `response_hash` and `outcome_status` concepts. The
current PyPI runtime does not emit those fields. This profile rejects unknown
fields and does not map any CCS label to AEB's provider/effect lifecycle.
Provider execution, failure, and indeterminate outcome remain separate,
authenticated observations after provider entry.

## Publication and reference boundary

This is an experimental same-team composition profile plus synthetic hostile
cases. It is not an independent CCS implementation, CCS author review, an
interoperability result, or a reason to change either draft's reference class.

If implementing CCS requires an AEB profile after the source author reproduces
the composition, the CCS authors can classify that dependency according to
their document's actual requirements. If CCS remains independently
implementable, an informative reference is correct.
