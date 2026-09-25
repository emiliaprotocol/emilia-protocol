# Consequence admission

This guide describes the consequence-admission lifecycle of AEB-06 and its
reference implementation. AEB-06 was posted on 2026-09-24 as an individual
Internet-Draft; it is not adopted by any working group. It makes CAID
conditional on a cross-format join and AEC conditional on a multi-leg evidence
requirement. The published AEB-05 required both. The signed gateway handoff and
the same-action fence described below are repository implementation profiles;
AEB-06 does not specify them.

Authorization answers whether an operation may proceed. Consequence admission
handles the narrower problem that begins after that answer: admitting one
provider attempt, surviving crashes and retries, and preserving an honest result
when the provider outcome is unknown.

EMILIA does not replace OAuth, AuthZEN, COAZ, AP2, or a local policy engine.
Those systems remain authoritative for their own credentials, mappings, and
decisions. AIMS (`draft-ietf-wimse-aims`) is an Informational WIMSE
working-group document that profiles existing standards such as WIMSE and
OAuth; it does not itself issue credentials or decisions, so a deployment that
follows it keeps the decisions of those underlying systems. AEB applies the
relying party's native decision at the protected provider boundary.

```text
native identity, mandate, or permit
                |
                v
final receiver-observed operation
                |
                v
      [ AEB consequence admission ]
      exact-action check when needed
      stable native replay identity
      exact-action in-flight fence
      durable reserve before entry
                |
                v
           provider entry
                |
        +-------+--------+
        |       |        |
    executed  failed  indeterminate
                         |
                         v
             authenticated reconciliation
             (never a blind redispatch)
```

## Who owns what

| Layer | Responsibility |
| --- | --- |
| Native authorization system | Defines and verifies its credential or decision. With AuthZEN and COAZ, this includes mapping the operation into SARC, obtaining a decision, and enforcing the decision at the PEP. |
| CAID mapping profile | Compares material action meaning when independently encoded native representations must be joined. It is optional when the same PEP derives and enforces a current decision over the final operation without a cross-format join. |
| AEC requirement | Composes multiple evidence legs only when the relying party's policy requires them. A current native permit does not need a second policy engine merely to enter AEB. |
| AEB | Derives stable replay identity from the relying-party-pinned authority namespace, issuer, and native authorization ID (never from labels such as system or profile), reserves it and an exact-action in-flight fence in durable state, owns provider-entry custody, refuses blind retry after an uncertain result, and accepts only authenticated reconciliation bound to the same operation, action, and provider. |
| Provider | Performs the external effect and supplies whatever outcome or reconciliation evidence its native interface supports. AEB does not prove a physical effect from a local record alone. |

A COAZ permit covers only the operation inputs that the selected COAZ mapping
projects into the AuthZEN request. The direct native path therefore does not
treat a permit as covering the whole provider action. The gateway signs the
digest of the exact final action, and Gate admits only when that digest equals
the digest of the action it is about to execute. Whether the gateway may attest
a field that the permit did not cover is the gateway operator's decision; Gate
does not make it.

## When this profile is useful

Use consequence admission when an operation can create an external or
non-idempotent effect and at least one of these conditions applies:

- a transport retry could repeat the effect;
- more than one executor can race to dispatch the same authority;
- the provider can accept an operation before the caller receives a response;
- a crash can occur between reservation, provider entry, and outcome recording;
- the authorization and executable operation use different representations; or
- the relying party requires several independently verified evidence legs.

If one consequence-owning PEP obtains a current decision over the final
operation and the provider already offers sufficient atomic idempotency and
outcome recovery, AEB must not be presented as a mandatory second authorization
layer.

## Required lifecycle

1. Verify the native authorization under the native system's rules.
2. Bind it to the final operation. Use CAID only when a cross-format comparison
   is required; refuse or return `INDETERMINATE` when material meaning is lost.
3. Apply the relying party's local authorization decision. AEB records this
   result but does not make a universal policy decision.
4. Derive replay identity from the pinned authority namespace, the issuer, and
   the native authorization ID, not from a fresh wrapper, a transport nonce, or
   the system and profile labels.
5. Reserve the operation, every native replay identity, and the same-action
   fence in a shared durable state domain. The fence is keyed by relying party,
   effecting target, and action digest.
6. Record provider entry before treating the attempt as dispatchable elsewhere.
7. Record a terminal authenticated outcome, or keep the attempt
   `INDETERMINATE` and refuse redispatch.
8. Reconcile only with authenticated provider evidence bound to the same
   provider, operation, and material action. An attempt that never entered the
   provider (still `RESERVED`, or `RELEASED` without terminal evidence) is not
   reconcilable, and an outcome that conflicts with an existing terminal record
   is refused as `reconciliation_outcome_conflict`.

## Same-action fence

A fresh native permit does not make an uncertain attempt safe to repeat. A
stateless PDP can issue a new permit, with a new `authorization_id`, for a
retry of the same action, and the retry can carry a new operation identifier.
The direct native path therefore fences the action itself, not only the
authority and the operation record.

- Once an attempt for an action is `RESERVED`, `INVOKING`, or
  `INDETERMINATE`, a new attempt with the same relying party, effecting target,
  and `action_digest` is refused with reason `native_action_in_flight`, even
  when it carries a fresh native `authorization_id` and a fresh operation
  identifier. The effecting target is the one defined by the pinned profile,
  or otherwise the provider and account that the boundary invokes. Gate uses
  its configured provider coordinates: tenant, provider, provider account, and
  environment.
- The fence is released only by an authenticated terminal `FAILED` outcome,
  returned directly or reached through authenticated reconciliation, or by a
  proven pre-entry release. `EXECUTED` keeps the fence closed for that action
  instance, and a later attempt is refused with `native_action_already_executed`.
- The fence lives in the durable consumption store and survives a restart. It
  is not in-process memory.
- Two intentional actions that look identical must differ in a
  profile-declared instance field, such as a caller-chosen payment instance
  identifier. That field is part of the canonical action and therefore of
  `action_digest`. Without such a field, identical actions are the same
  action.
- Gate computes `action_digest` over the action object the caller passes. A
  field that varies between retries, such as a memo or a timestamp, would
  give the same action a new digest and bypass the fence. Put only material
  fields, plus any instance field, in that object.

## Native replay identity

The replay identity that Gate fences, its replay key, and the provider
idempotency key are derived from the relying-party-pinned authority namespace,
the issuer, and the native `authorization_id`. Wire labels such as `system`
and `profile` are not inputs, so presenting one grant under a second label
cannot make it spendable twice. A pin may declare an `authority_namespace`; by
default the namespace is the issuer. Pins that accept one issuer under several
labels share one namespace unless each pin explicitly declares a distinct
namespace, and a pin set that mixes declared and default namespaces for one
issuer is refused.

## Reference implementation

The current reference implementation is the
[`consequence-boundary`](../../packages/gate/src/consequence-boundary.ts)
module. The open [AEB-1 conformance pack](../conformance/AEB-1-CONSEQUENCE-ADMISSION.md)
tests the boundary as a self-run profile. A passing self-test is not proof of a
production deployment, complete mediation, independent interoperability, or a
provider effect.

The stable package entry points keep the native verifier and provider boundary
separate:

```js
import {
  verifyAebNativeAuthorizationHandoff,
} from '@emilia-protocol/verify/aeb';
import {
  createNativeConsequenceBoundary,
} from '@emilia-protocol/gate/aeb';
```

`createNativeConsequenceBoundary()` requires a consumption store that is
durable, ownership-fenced, permanent, atomically replay-fenced, and exposes a
durable `state()` read; construction fails with
`native_consequence_boundary_configuration_invalid` otherwise. The PostgreSQL
AEB store, `createPostgresAebDurableConsumptionStore()`, provides that read
through the executor-only `ep_aeb_private.operation_state` function. Its commit
and release are fenced to the reserving store instance, so after a restart
`reconcile()` claims the operation reservation and the action-fence holder
through `claimReservation()` with the caller's `recovery_authorization`. The
store's `authorizeRecoveryClaim` must accept that authorization for both keys
(`nativeConsequenceBoundaryReservationKey()` and
`nativeConsequenceBoundaryActionFenceHolderKey()`). Gate 0.26.0 shipped the
PostgreSQL store without `state()`, so it could not back the native boundary
there.

See the
[`AEB-NATIVE-AUTHORIZATION-HANDOFF-v1`](aeb-native-authorization-handoff-v1.md)
profile for the direct path. `createConsequenceBoundary()` remains the composed
path when the deployment needs CAID or AEC.
