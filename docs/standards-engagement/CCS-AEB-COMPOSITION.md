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

## Current runnable profiles

The current public-key profile is source-locked to
`ccs-verifier==1.1.19`, upstream tag object
`bdd79fa8257b764cffa5bceb458330ce01bc41ce`, and commit
`4c5e6c7a9670be0a417414f8b8f41ff4d5df0aa6`. It verifies an explicitly labeled
EMILIA-derived Ed25519 L1 receipt regenerated from that exact source lock and
the upstream public deterministic seed under a
relying-party-pinned issuer key and checks its audience, expiry, rule version,
action, and tool. AEB reconstructs the exact imminent action at the executor
and compares the signed full `args_digest` before deriving the CAID.

The 1.1.19 source archive still bundles a stale vector whose package and rule
versions are 1.1.14. The profile preserves and hash-checks the exact upstream
bytes without relabeling them; the EMILIA-derived fixture and stale-upstream
boundary are separately hash-pinned and reproducible from a checked-in
generator.

Run its eight pinned and hostile cases with:

```bash
npm run conformance:composition:ccs-l1-aeb
```

The older local-HMAC profile below remains source-locked for historical
reproduction and for the existing CCS + OASNT two-leg runner. It is not
silently relabeled as 1.1.19.

The legacy runnable adapter is source-locked to the PyPI distribution labeled
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

When CCS is composed with another native evidence format, the adapter can use
the stricter shared `native_action` projection:

```text
CCS command.tool    -> observed_action.native_action.type
CCS command.params  -> observed_action.native_action.parameters
```

The legacy runnable
[`CCS + OASNT to AEB composition`](../../conformance/composition/ccs-oasnt-aeb-v1/README.md)
proves that the CCS machine-policy leg and an independently verified OASNT
human-authorization leg map to the same CAID and action digest before AEB
evaluates the relying party's two-role requirement. It also exercises
action substitution, indeterminate outcome, and replay after indeterminate.

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

These are experimental EMILIA reference profiles plus synthetic hostile
cases. They are not an independent CCS implementation, CCS author review, an
interoperability result, or by themselves a reason to change either draft's
reference class.

An external author can run the same kit and obtain a digest-bound report plus
paste-ready Implementation Status text. That proves external reproduction of
the EMILIA reference composition, not independent implementation. The report
keeps the pinned CCS-native checks separate from AEB composition checks and can
be signed with a runner-controlled Ed25519 key.

If implementing CCS requires an AEB profile after the source author reproduces
the composition, the CCS authors can classify that dependency according to
their document's actual requirements. If CCS remains independently
implementable, an informative reference is correct.
