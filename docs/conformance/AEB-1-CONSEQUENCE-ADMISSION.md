<!-- SPDX-License-Identifier: Apache-2.0 -->

# AEB-1 Consequence Admission Conformance

`AEB-1` is an open, format-neutral self-assessment for a consequence boundary.
It tests whether an implementation can take evidence already verified under its
native protocol, join every accepted leg to one exact material action,
determine whether the relying party's evidence requirement is satisfied,
reserve that authority before dispatch, and keep an unknown provider outcome
locked until authenticated reconciliation.

The profile implements the conformance requirements in
[`draft-schrock-action-evidence-boundary-00`](https://datatracker.ietf.org/doc/draft-schrock-action-evidence-boundary/).
It does not define another receipt, token, credential, policy language, or
identity system.

## The decision boundary

An AEB-1 implementation keeps these decisions separate:

1. `VERIFIED`: each artifact passed its native verifier under relying-party
   trust inputs.
2. `ACCEPTED`: the relying party accepts that result under pinned roots,
   status, adapters, and mapping profiles.
3. `MATCH`: every accepted leg denotes the same exact material action under the
   pinned CAID definition and normalized-action projection.
4. `SATISFIED`: the accepted and matched legs fill the relying party's complete
   evidence requirement.
5. `AUTHORIZED`: local policy permits this exact consequence.
6. `RESERVED`: the operation and every native replay identity are atomically
   fenced before dispatch.
7. `INVOKING`: custody has transferred after reservation; this state is never
   eligible for blind retry.
8. Provider outcome: `COMMITTED`, `PROVEN_NOT_COMMITTED`, or `INDETERMINATE`.
9. Observed-effect relation: `OBSERVED_AS_REQUESTED`, `DIVERGED`, or
   `INDETERMINATE`.

`INDETERMINATE` is a custody state. The reservation remains held. A blind retry
is refused. Only authenticated evidence that the effect did or did not occur
can reconcile the operation.

## Run the reference pack

From the repository:

```sh
npm run conformance:aeb-1
```

From the published verifier package:

```sh
npx @emilia-protocol/verify aeb-conformance --reference
```

To validate a saved self-assessment report:

```sh
npx @emilia-protocol/verify aeb-conformance --submission report.json
```

The command is offline and deterministic. A passing result means the submitted
report conforms to the closed `AEB-CONSEQUENCE-CONFORMANCE-REPORT-v1`
contract and contains a passing result for every required vector in the pinned
suite. It does not establish that an untested deployment uses the same code.

## Required hostile behaviors

The suite includes positive and fail-closed cases for:

- native-verification failure;
- rejected or unavailable relying-party status;
- CAID or normalized-action substitution;
- missing evidence roles and failed distinct-human quorum;
- initiator or executor self-approval;
- unavailable atomic reservation;
- same-operation replay;
- native evidence rewrapped under a new operation;
- provider timeout producing an `INDETERMINATE` provider outcome and effect
  relation;
- provider commitment with a divergent observed effect;
- authenticated proof that the provider did not commit;
- blind retry while an outcome is unknown;
- unauthenticated reconciliation; and
- authenticated reconciliation to the observed terminal outcome.

The vectors are in
[`conformance/vectors/aeb-consequence-conformance.v1.json`](../../conformance/vectors/aeb-consequence-conformance.v1.json).
The reference implementation is exported by
`@emilia-protocol/verify/aeb-consequence-conformance`.

## Claim boundary

A passing AEB-1 report is a **self-attested conformance result**. A
`local_atomic` result applies only inside the consequence owner's demonstrated
transaction domain; it cannot be projected across a remote or federated
boundary. The report is not:

- an independent audit or certification;
- evidence of production deployment, complete mediation, or commercial
  adoption;
- proof that a native protocol, identity, policy, credential, or payment rail
  is secure;
- proof that an action was legal, safe, beneficial, or correctly settled; or
- permission to execute an action.

Independent operators can publish signed or otherwise provenance-bound reports
around the same deterministic result, but the base profile deliberately does
not appoint EMILIA as a certification authority.

## Why this profile exists

A frozen review of 441 agent-protocol records credited only seven records with
both one-time control and explicit indeterminate-effect handling. Five were
EMILIA-authored, and none had corpus-verified cross-vendor production
interoperability. That finding identifies an open implementation and
interoperation seam; it does not prove the absence of private systems or confer
market ownership.

The standards position is therefore narrow: one open effect-boundary profile,
hostile vectors, and reproducible results that other evidence systems can plug
into without surrendering their native semantics.
