<!-- SPDX-License-Identifier: Apache-2.0 -->
# Recovery Admission Profile v1

The Recovery Admission profile classifies how an already-authorized exact
consequential action may enter execution. It does not promise that every action
is reversible. The current code is an experimental evaluator, a local
PostgreSQL execution scaffold, and a separately admitted remedy bridge; it is
not yet a production credential-release integration.

`EP-RECOVERY-CAPABILITY-v1` is a closed, signed relying-party artifact. It binds
one exact Admission Store snapshot, action, CAID, tenant, audience, operation, provider, provider account,
environment, resource set, policy snapshot, trust/configuration epochs, validity
window, and recovery class. The relying party pins the issuer, derives the
expected class from local policy, and resolves current status. A presenter,
adapter, or recovery worker cannot select or downgrade any of them.

## Policy-derived classes

### `LOCAL_ATOMIC`

The action may run only inside one controlled transaction domain that can
commit or roll back the protected mutation as one unit. The capability binds:

- the state-domain digest;
- the adapter identifier and implementation digest; and
- a maximum transaction duration.

The reference PostgreSQL scaffold requires a durable ordinary Admission Store,
consumes its exact reservation, starts a `SERIALIZABLE` transaction, invokes the
relying party's pinned callback, validates the result, rechecks current status
immediately before `COMMIT`, and attempts one commit. A validation failure may
return `PROVEN_NOT_COMMITTED` only when rollback acknowledgement and bound
evidence are both available. A callback failure without evidence, lost commit
acknowledgement, or failed rollback is `INDETERMINATE`; it is never called rolled
back or safe to retry.

This mode applies only when every protected effect is inside that transaction.
Calling a payment rail, sending a message, invoking another cloud, or performing
any other external effect inside the callback violates the profile. The
reference callback interface does not sandbox JavaScript; an enforceable
deployment boundary must establish this property.

### `RESERVED_COMPENSATION`

The original action may run only while a separately authorized compensating
action is current and durably reserved. The capability binds the remedy's CAID
and action digest, the reservation and authority digests, the destination,
typed amount, and availability deadline.

Compensation is a new action. It never rewrites history or proves that the
original effect was undone. A failed or uncertain original invocation keeps the
reservation frozen for authenticated reconciliation; it is not released for a
blind retry. A compensation reservation proves reserved capacity only. It does
not prove that compensation ran, restored prior state, or eliminated loss.

### `IRREVERSIBLE`

No rollback or reserved compensation is represented. This is an action-risk
classification, not a recovery outcome. Gate routes the action to the relying
party's existing authority policy, including any required human or quorum
approval. Entered authority remains consumed permanently, and automatic retry
is prohibited. The recovery artifact never upgrades evidence into authorization.

## Admission decision

The reference evaluator returns one of four closed decisions:

- `LOCAL_ATOMIC`: use the bound local transaction executor;
- `RESERVED_COMPENSATION`: reservation evidence is current, but the original
  action integration must re-evaluate it immediately before provider entry;
- `AUTHORITY_REQUIRED`: apply the ordinary Gate authority policy; or
- `REFUSED`: do not enter the provider.

Admission requires a valid signature from a pinned issuer, exact equality with
the relying party-supplied trusted policy snapshot, an unexpired capability,
affirmative current status, and all class-specific checks. Missing, stale,
revoked, malformed, downgraded, or uncheckable state fails closed. Reserved
compensation also requires the relying-party reservation verifier to confirm
the exact reservation and authority digests as current.

Evaluation is not execution. The selected executor MUST recheck currentness and
any reservation immediately before provider entry or commit. A successful
evaluation cannot be cached across that boundary. The repository-local
experimental remedy bridge requires the current claim secret and reserves a
fresh remedy, but it does not invoke the original action, so it is not a
compensation-aware original-action executor and is not yet in a published
package.

## Outcome discipline

The profile uses the following meanings:

- `COMMITTED`: the selected transaction acknowledged `COMMIT` and the callback
  supplied a bound evidence digest. It does not prove the intended mutation or
  an external effect;
- `PROVEN_NOT_COMMITTED`: rollback was acknowledged and bound callback evidence
  supports non-commit inside the selected transaction. It says nothing about
  any out-of-transaction effect;
- `INDETERMINATE`: the effect may have happened and the system must not retry
  without authenticated reconciliation.

`INDETERMINATE` is a first-class terminal-for-retry state, not a temporary
network error. Remedy and reconciliation create new attributable records; they
do not edit the original outcome.

Only a still-reserved operation that provably never crossed provider entry may
be released. Once execution authority is consumed, no negative lookup, timeout,
recovery process, or remedy may restore it. Any subsequent attempt requires a
fresh admission.

## Claim boundary

A valid recovery capability proves that a pinned issuer classified one exact
action under one recovery policy and that the relying party accepted current
supporting status at admission time. It does not prove:

- that the action was wise, legal, correct, or safe;
- that an external system will honor a compensating request;
- that a saga is atomic;
- that a supplied reservation is sufficient after its deadline;
- that every effect bypass path is mediated by Gate; or
- that an observed provider response is physical truth.

Complete mediation remains a deployment property. Credentials and provider
entry paths must be held behind the enforcing Gate for the profile to control
the action.

## Reference implementation

- `@emilia-protocol/gate/recovery-admission`
- `@emilia-protocol/gate/recovery-admission-postgres`
- `@emilia-protocol/gate/recovery-admission-remedy`
- `packages/gate/src/recovery-admission.ts`
- `packages/gate/src/recovery-admission-postgres.ts`
- `packages/gate/src/recovery-admission-remedy.ts`
- `packages/gate/recovery-admission.test.ts`
- `packages/gate/recovery-admission-postgres.test.ts`
- `packages/gate/recovery-admission-remedy.test.ts`
- `examples/recovery-admission/demo.mts`

The PostgreSQL scaffold currently has mock-backed transaction-control tests; it
is not evidence of database mutation, crash durability, or process confinement.
Before this profile is
proposed as an Internet-Draft, the repository requires an independent second
adapter, one end-to-end original-action integration for reserved compensation,
and deployment evidence that local-effect confinement is enforced rather than
self-declared.
