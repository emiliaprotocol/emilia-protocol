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
| AEB | Derives stable replay identity from the relying-party-pinned authority namespace (the issuer unless the pin declares one) and the native authorization ID (never from labels such as system or profile), reserves it and an exact-action in-flight fence in durable state, owns provider-entry custody, refuses blind retry after an uncertain result, and accepts only authenticated reconciliation bound to the same operation, action, and provider. |
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
4. Derive replay identity from the pinned authority namespace and the native
   authorization ID, not from a fresh wrapper, a transport nonce, or the system
   and profile labels. The namespace is the issuer unless the pin declares one.
5. Reserve the operation, every native replay identity, and the same-action
   fence in a shared durable state domain. The fence is keyed by relying party,
   effecting target, and canonical action digest.
6. Record provider entry before treating the attempt as dispatchable elsewhere.
7. Record a terminal authenticated outcome, or keep the attempt
   `INDETERMINATE` and refuse redispatch.
8. Reconcile only with authenticated provider evidence bound to the same
   provider, operation, and material action. An outcome that conflicts with an
   existing terminal record is refused as `reconciliation_outcome_conflict`.
   An attempt that never entered the provider is never reconciled to
   `EXECUTED` or `FAILED`; it is closed only through the proven pre-entry
   recovery described below.

## Same-action fence

A fresh native permit does not make an uncertain attempt safe to repeat. A
stateless PDP can issue a new permit, with a new `authorization_id`, for a
retry of the same action, and the retry can carry a new operation identifier.
Both Gate boundaries therefore fence the action itself, not only the authority
and the operation record: `createNativeConsequenceBoundary()` on the direct
native path and `createConsequenceBoundary()` on the composed CAID/AEC path.

- The fence key is the relying party ID (`pins.relying_party_id` on the
  native boundary, `aeb.config.relying_party_id` on the composed one), the
  effecting target, and the canonical action digest
  (`digestAebNativeAuthorizationAction(action)`). Gate uses its configured
  provider coordinates (tenant, provider, provider account, and environment)
  as the effecting target.
- While an attempt for that key is `RESERVED`, `INVOKING`, or
  `INDETERMINATE`, a new attempt is refused before provider entry with
  `native_action_in_flight`, even when it carries fresh authority and a fresh
  operation identifier. A refused attempt does not consume its authority. Both
  boundaries derive the same fence key, so they also fence each other when
  they share a consumption store and relying party ID. On the composed
  boundary the refusals it already had (for example a reused evaluation) take
  precedence over the fence refusal.
- The fence opens only on a terminal `FAILED` outcome the boundary accepts,
  returned by the provider call or reached through authorized reconciliation
  (the native boundary also requires it to pass `provider_outcomes.verify`),
  or on a pre-entry stop that the boundary proves from its own durable attempt
  record (below). `EXECUTED` keeps it closed for that action
  instance, and a later attempt is refused with
  `native_action_already_executed`.
- The fence lives in the durable consumption store and survives a restart. It
  is not in-process memory.
- A call releases or closes only reservations that it created. The native
  boundary writes three reservations per attempt, in refusal order: the
  operation identity (`consumption_conflict`), the native replay key
  (`native_replay_conflict`), and the action fence (`native_action_in_flight`
  or `native_action_already_executed`). Each row key includes the attempt ID
  (`nativeConsequenceBoundaryAttemptReservationKeys()`), which no other
  attempt can produce, so a failed write for one attempt cannot release
  another attempt's reservation even when both carry the same caller-chosen
  operation ID. The composed boundary keys its fence holder by attempt ID
  (`consequenceBoundaryActionFenceHolderKey()`) and never releases its
  evaluation reservation after a reserve error. If Gate cannot confirm a
  release through a durable read, it returns `INDETERMINATE` with a reason and
  the key stays held until an authorized recovery settles it.

### Attempts that stopped before provider entry

An attempt can stop before it reaches the provider. The process can crash
while the attempt is `RESERVED`, the acknowledgement of the `RESERVED` to
`INVOKING` write can be lost, or a store error can interrupt the release that
follows a pre-entry refusal. Such an attempt still holds the fence and its
other reservations. A timeout, a caller retry, and fresh authority do not
release them. Gate writes the durable attempt record before any reservation
that fences the action, so every attempt that holds the fence has a record
that `reconcile()` can find.

Recovery releases them only with proof that no provider entry occurred. The
operator calls `reconcile()` for the attempt with a `recovery_authorization`
that the attempt store's `recover()` accepts for that exact attempt, and the
provider's answer: a `FAILED` ("not found") from a provider lookup, or
`INDETERMINATE` when the provider offers no lookup. On the native boundary a
`FAILED` answer must pass `provider_outcomes.verify`. Gate calls the provider
only after the attempt record reaches `INVOKING`, and it records `RELEASED`
without provider evidence only when it stops before the provider callback. A
durable record that is still `RESERVED`, or `RELEASED` without terminal
evidence, therefore proves that this attempt never entered. Only then does
Gate move a `RESERVED` record to `RELEASED`, release the attempt's
reservations, confirm each release through a durable read, and return
`REFUSED` with `attempt_never_entered_provider`. On the native boundary those
are the fence holder, native authority, and operation reservations. On the
composed boundary they are the fence holder and the evaluation reservation,
which is closed as `RELEASED_NOT_ENTERED` when the store supports terminal
release (otherwise it stays reserved), so a retry needs a fresh evaluation. A
claim of `EXECUTED` contradicts the record and is refused as
`reconciliation_outcome_conflict` without releasing anything. If a release
cannot be confirmed, the result is `INDETERMINATE` with
`native_pre_entry_release_unconfirmed`, and repeating the call is safe. If the
record is `INVOKING` or `INDETERMINATE`, only a terminal provider outcome can
close it. An attempt is never released silently, and it is never reconciled
to `EXECUTED` or `FAILED` as a pre-entry stop.

The composed boundary needs a durable `state()` read on its attempt store to
prove a pre-entry stop. Without one, an attempt that stopped before entry
keeps the fence closed until the attempt store provides that read.

### Canonical action identity

The fence, like every Gate key built from them, compares the canonical action
digest and the provider coordinates exactly as configured. Gate implements no
material-field inventory and no equivalence between spellings of one value.
Its canonical JSON fixes member order and integer spelling, but it compares
strings exactly: `"500"` and `"500.00"`, `"USD"` and `"usd"`, a trailing
space, or the NFC and NFD forms of one name are different actions to Gate,
and each would reach the provider again while the first attempt is
uncertain. Two boundary instances configured with `account:one` and
`Account:One` for one real provider account do not share a fence. Callers and
profiles must therefore:

- canonicalize amounts, currency codes, case, whitespace, and Unicode
  normalization before they build the action;
- put only material fields, plus any profile-declared instance field, in the
  action object, because a memo, a timestamp, or a retry identifier would give
  the same action a new digest; and
- configure identical provider coordinates on every boundary instance that
  can reach one provider account.

Two intentional actions that look identical must differ in a
profile-declared instance field, such as a payment instance identifier fixed
when the action is authorized. That field is part of the canonical action and
therefore of the action digest. Without such a field, identical actions are
the same action.

## Native replay identity

The replay key that Gate reserves and the provider idempotency key are derived
from the relying-party-pinned authority namespace and the native
`authorization_id`. The namespace is the issuer unless the pin declares an
`authority_namespace`. When it does, the issuer string is not an input, so
pins that spell one issuer two ways (`https://a.example` and
`https://a.example/`) and declare the same namespace share one key. Wire labels
such as `system` and `profile` are never inputs, so presenting one grant under
a second label cannot make it spendable twice.

Pins that accept the same issuer string share the issuer as their namespace
unless every one of them declares an `authority_namespace`; a mix of declared
and default namespaces for one issuer is refused. Pins whose issuers are
different spellings of one URL (scheme or host case, a default port, a
trailing slash) are refused unless all of them declare the same
`authority_namespace`. `verifyAebNativeAuthorizationPins()` reports these
refusals as `native_pins_namespace_declaration_mixed` and
`native_pins_issuer_alias_without_shared_namespace`;
`createNativeConsequenceBoundary()` refuses such a pin set at construction,
and the handoff verifier refuses it as `native_handoff_schema_invalid`. The
URL comparison lower-cases the scheme and host, drops a default port, and
drops trailing slashes from the path; it is used only to detect aliases and is
never hashed. Declaring distinct namespaces for one issuer asserts that its
authorization identifiers under those pins denote distinct grants; if that is
wrong, one grant can be spent once per namespace.

Changing a pin's `authority_namespace`, or the issuer spelling of a pin that
uses the default namespace, rotates the replay key: a grant consumed or in
flight under the old key could be admitted again under the new one. Before
rotating, drain or reconcile in-flight attempts and wait until every grant
consumed under the old namespace has expired or been revoked.

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
`reconcile()` claims the attempt's reservations through `claimReservation()`
with the caller's `recovery_authorization`: the operation, native-authority,
and action-fence-holder rows on the native boundary, and the evaluation
reservation and the holder on the composed boundary. Each claim passes
`authorizeRecoveryClaim` a `scope` (`AebRecoveryClaimScope`):
`{ attemptId, operationId, recoveryOperationKey, reservation }`, where
`recoveryOperationKey` is the native `nativeConsequenceBoundaryReservationKey()`
value or the composed evaluation reservation key, and `reservation` is
`operation`, `native-authority`, or `action-fence-holder`. Gate builds the
scope from attempt custody it has already authenticated. An authorizer that
binds one credential to `scope.attemptId` or `scope.recoveryOperationKey`,
not to the row key, therefore accepts every reservation the attempt holds,
and restart reconciliation to `FAILED` or `EXECUTED` completes in one call.
Gate 0.26.0 shipped the PostgreSQL store without `state()`, so it could not
back the native boundary there.

See the
[`AEB-NATIVE-AUTHORIZATION-HANDOFF-v1`](aeb-native-authorization-handoff-v1.md)
profile for the direct path. `createConsequenceBoundary()` remains the composed
path when the deployment needs CAID or AEC; it holds the same durable
same-action fence and follows the same release rules, with the recovery
differences described above.
