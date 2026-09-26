# Direct native authorization at the consequence boundary

`AEB-NATIVE-AUTHORIZATION-HANDOFF-v1` is the short path from a native
authorization system to EMILIA Gate. Use it when the native result already
identifies the final action exactly. It does not require CAID or AEC.

This is a repository implementation profile for the direct native path that
AEB-07 describes. AEB-07 was posted on 2026-09-25 as an individual
Internet-Draft and is not adopted by any working group. Its Section 5.8
specifies what a native authorization handoff binds and how the boundary
verifies it, but defines no encoding; AEB-07 cites this profile, at a pinned
commit, as one informative reference encoding. AEB-06 did not specify the
handoff, and it was not part of AEB-05.

The native system still owns the authorization decision. A
relying-party-pinned gateway signs a closed handoff that records:

- the native system, profile, issuer, and stable authorization identifier;
- one `PERMIT` decision and one exact canonical action digest;
- the relying party, audience, executor, tenant, provider, account, and
  environment;
- the validity window and revocation identifier; and
- a `replay_unit` digest over the native system, profile, issuer, and
  authorization identifier, computed exactly as verify 4.1.0 computes it.
  Wrapper IDs and operation IDs are not inputs. The verifier checks this
  value as part of the signed wire format, but Gate does not use it as the
  replay key (see below).

Gate verifies the gateway statement under pinned Ed25519 gateway keys and
accepted source profiles. Gate does not re-verify the native permit or native
artifact. The supported source labels are `aims`, `authzen`, `coaz`, `ap2`,
`oauth`, and `local`. Those labels do not establish conformance with AIMS,
AuthZEN, COAZ, AP2, OAuth, or any other source protocol. AIMS is an
Informational WIMSE working-group document that profiles existing standards and
issues no permit itself; the `aims` label names a deployment that follows that
profile. The relying party must pin the exact gateway, profile, and issuer it
accepts.

## Execution order

1. Gate receives the final action and the signed handoff.
2. Gate checks the signature, source pin, action, relying party, audience,
   executor, and provider before it calls any status service. An invalid
   handoff cannot choose or trigger a lookup.
3. Gate obtains current status from its configured `resolve_status` callback.
   Caller-supplied status is not trusted. The resolver receives the already
   verified handoff and must use an operator-pinned registry or authenticated
   status service. The status result is bound to the gateway, full native
   source identity, and replay unit.
4. Gate checks the time window and revocation status, then runs its separate
   `local_authorize` callback. This callback may narrow admission but must not
   claim to reproduce the native policy decision. The operator supplies a
   digest for this local program. Gate records that digest, the decision time,
   and a digest of the exact local decision.
5. Gate allocates an attempt ID, writes the durable attempt record, and only
   then reserves, each atomically in its durable consumption store, three
   rows keyed by that attempt ID: the operation identity, the native
   authority (which fences the label-free replay identity key and the verify
   4.1.0 replay key), and the exact-action fence. The fence is keyed by
   relying party, provider coordinates as configured, and canonical action
   digest. Because every row key includes this attempt's ID, no other attempt
   can release it. A conflict on the operation identity is refused as
   `consumption_conflict` and one on either replay key as
   `native_replay_conflict`. If an earlier attempt for the same action is
   still `RESERVED`, `INVOKING`, or `INDETERMINATE`, the fence reservation
   conflicts and Gate refuses with `native_action_in_flight` (or
   `native_action_already_executed` once the action has executed). On any of
   these refusals Gate marks the attempt `RELEASED`, releases the rows this
   attempt created, confirms each release through a durable read, and does
   not enter the provider. This holds even when the new handoff carries a
   fresh `authorization_id` and a fresh operation ID. A refused run therefore
   leaves a `RELEASED` attempt record. The attempt record binds the exact
   trust snapshot, local-program digest, local-decision digest, and
   provider-outcome verifier digest.
6. Immediately before provider entry, Gate resolves status again and repeats
   the current-time and revocation checks. If they fail, Gate closes the
   not-entered attempt without calling the provider.
7. A terminal provider result is accepted only through the operator-pinned
   `provider_outcomes.verify` callback. That callback receives the exact
   provider, operation, action, native replay unit, attempt, outcome, the
   verifier-program digest recorded for that attempt, the attempt's provider
   idempotency key, and a `purpose`: `provider_outcome` for a terminal
   result, or `pre_entry_lookup` for the lookup presented in pre-entry
   recovery. The only answer Gate accepts is `{ verified: true, purpose,
   attempt_id, provider_idempotency_key }` restating what it was asked; any
   other answer, including a bare `true`, is "not verified". An entered
   attempt closes only on an affirmation of `provider_outcome` for that
   attempt, and a "not found" lookup is valid only as `pre_entry_lookup` in
   pre-entry mode.
   Evidence presented to reconciliation carries its kind in Gate's input
   (`evidence_kind`: `provider_outcome` or `pre_entry_lookup`), and Gate
   refuses a missing kind (`evidence_kind_required`) or a kind that does not
   match the mode (`evidence_kind_mismatch`) before it calls the verifier. Gate cannot detect a lookup
   presented as `provider_outcome` together with a verifier that affirms a
   purpose it did not evaluate; the operator labels evidence by what it is,
   and the verifier checks the evidence against the purpose. During reconciliation,
   the callback must resolve the verifier identified by that recorded digest,
   not silently reinterpret old evidence under a newer verifier.
8. A missing, malformed, or unauthenticated provider result becomes
   `INDETERMINATE`. The replay and action fences stay in place until separately
   authorized reconciliation closes the recorded attempt. An attempt that never
   entered the provider is never reconciled to `EXECUTED` or `FAILED`; its
   reservations are released only through the proven pre-entry recovery
   below.

## Replay identity

The replay identity is derived locally from the relying-party-pinned authority
namespace and the native `authorization_id`. The namespace is the issuer
unless the matched pin declares an `authority_namespace`; when it does, the
issuer string is not an input, so pins that spell one issuer two ways
(`https://a.example` and `https://a.example/`) and declare the same namespace
share one identity. The `system` and `profile` labels are never inputs, so the
same grant presented under a second label is the same authority. Changing a
wrapper, label, or Gate operation ID does not create fresh authority. The
verifier reports the identity as `native_replay_identity` and its
relying-party-scoped key as `replay_identity_key`, and returns null for both
unless the source is pinned and the pin set passes
`verifyAebNativeAuthorizationPins()`. The provider idempotency key is derived
from the identity.

Gate reserves `replay_identity_key`, which makes a relabelled grant one
spend, and, beside it, the verify 4.1.0 `replay_key` for every `system` and
`profile` label, with its issuer spelling, that the pin set accepts under the
grant's authority namespace. A grant that gate 0.26.0 consumed under one
label is therefore refused under any other label still pinned in that
namespace after an upgrade. The 4.1.0 keys cover the labels, so they are
never used alone, and they cover only the labels and spellings pinned now:
keep every label and spelling that 0.26.0 accepted pinned until the grants
consumed under it have expired or been revoked. Do not run gate 0.26.0 and a
newer Gate against one store: 0.26.0 has no same-action fence and does not
reserve the identity key, so a mixed fleet can execute one action twice.
Stop every 0.26.0 boundary and drain or reconcile its in-flight attempts on
0.26.0, including any pre-entry stop whose rows it did not release (0.26.0
wrote those records without the not-entered marker, so the newer Gate
reports them `attempt_record_unproven`), with the provider-outcome verifier
that 0.26.0 already uses, before
deploying the new verifier, the upgraded attempt stores, and the newer Gate
together. A 0.26.0 native boundary counts only a verifier answer of exactly
`true`, so the new verifier must never be deployed while 0.26.0 serves. The
executed-action fence is not retroactive: an action that 0.26.0 executed
has no fence row, so the newer Gate admits fresh authority for it.

One issuer has one namespace in a pin set. Pins whose issuer strings are
identical, or are spellings the verifier normalizes as equal (URI scheme case,
URL host case, a trailing dot on the host, a default port, trailing slashes,
dot segments in the path, an http or https URL written without `//`, IPv4
host spellings such as `127.1` or `0x7f.0.0.1`, an empty port, URN
namespace-identifier case, DID method-name case, `did:web` host case and
trailing dots, SPIFFE trust-domain case and trailing dots),
must either all omit `authority_namespace` and use one identical issuer
string, or all declare the same `authority_namespace`. Normalization cannot
find every alias; two issuer strings that denote one authority but do not
normalize equal need one explicitly shared namespace.
`verifyAebNativeAuthorizationPins()` refuses a pin set that mixes declared and
default namespaces for one issuer (`native_pins_namespace_declaration_mixed`),
declares two different namespaces for one exact issuer
(`native_pins_issuer_namespace_conflict`), or spells one issuer two ways
without one shared declared namespace
(`native_pins_issuer_alias_without_shared_namespace`), and
`createNativeConsequenceBoundary()` refuses such a pin set at construction.
The handoff verifier refuses it as `native_handoff_schema_invalid`, except
that a pin set declaring no namespace is accepted as verify 4.1.0 accepted it;
when such a set aliases an issuer, the verifier derives no replay identity for
it.

Changing a pin's namespace, or the issuer spelling of a pin that uses the
default namespace, changes the replay identity of every grant under it. The
4.1.0 keys do not depend on the namespace, so the same grant is still refused
while a label and issuer spelling whose 4.1.0 key was reserved when it was
consumed stays pinned in its namespace, but not when it is presented only
under labels and spellings outside that set. Drain or reconcile in-flight attempts, and wait until every grant
consumed under the old namespace has expired or been revoked, before
rotating.

The signed `AEB-NATIVE-AUTHORIZATION-HANDOFF-v1` wire is unchanged from
verify 4.1.0. A handoff issued by 4.1.0 verifies under this version, and a
handoff issued by this version verifies under 4.1.0. The carried
`replay_unit` keeps its 4.1.0 derivation under
`AEB-NATIVE-AUTHORIZATION-REPLAY-v1`, and `replay_key` keeps its 4.1.0 value
under `AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v1`. The replay identity is a
local derivation under `AEB-NATIVE-AUTHORIZATION-REPLAY-IDENTITY-v1`, keyed
under `AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2`, and is not carried on the
wire.

## Same-action fence

The same-action fence is keyed by the relying party, the provider coordinates
exactly as configured, and the canonical action digest. It is released only by
an authenticated terminal `FAILED` outcome (one that
`provider_outcomes.verify` affirms as `provider_outcome` for the attempt),
returned directly or reached through authorized reconciliation, or by a
pre-entry stop that Gate proves from the explicit not-entered marker in its
own durable attempt record. `EXECUTED` keeps it closed for that action instance.

An attempt that stopped before provider entry, for example after a crash while
`RESERVED`, a lost acknowledgement of the move to `INVOKING`, or a store error
during a pre-entry release, keeps the fence and its other reservations.
Pre-entry recovery is a separate mode of `reconcile()` (`mode: 'pre_entry'`);
terminal reconciliation (`mode: 'terminal'`, the default) returns
`INDETERMINATE` with `pre_entry_recovery_required` for a record that never
reached `INVOKING`, and neither mode falls through into the other. Pre-entry
recovery needs a `recovery_authorization` that the attempt store's `recover()`
accepts for that exact attempt, and the provider's answer: an authenticated
"not found" lookup result as `FAILED`, presented with `evidence_kind:
'pre_entry_lookup'`, which must pass `provider_outcomes.verify` with
`purpose: 'pre_entry_lookup'`, or
`INDETERMINATE` when the provider offers no lookup. A verification program
should accept a "not found" only for that purpose, never for `purpose:
'provider_outcome'`. Recovery treats the attempt as not entered only when a
durable read confirms its own atomic transition of the durable record from
`RESERVED` to `RELEASED`, which writes an explicit not-entered marker bound
to the attempt, or when the record is already `RELEASED` with that marker,
which Gate also writes when a run stops itself before the provider callback.
A `RELEASED` record without the marker or provider evidence is never read as
not entered: both reconciliation modes return `INDETERMINATE` with
`attempt_record_unproven` and release nothing. The attempt store must declare
`notEnteredMarker: true` and return the stored evidence from `state()`.
That transition is the linearization point: afterwards the original
run cannot move the record to `INVOKING` and does not call the provider. Only
after it does Gate release the attempt's reservations; after each release is
confirmed by a durable read the result is `REFUSED` with
`attempt_never_entered_provider`, and otherwise it is `INDETERMINATE` with
`native_pre_entry_release_unconfirmed`. A row that a failed claim finds
already `AVAILABLE` counts as released. If the record is already `INVOKING` or
later, recovery returns `INDETERMINATE` with `recovery_lost_to_live_attempt`,
releases nothing, and never uses its lookup result as terminal evidence; that
attempt needs terminal reconciliation with a provider outcome observed after
entry. A claim of `EXECUTED` is refused as `reconciliation_outcome_conflict`
and releases nothing.

Terminal reconciliation verifies the outcome, freezes an `INVOKING` record
as `INDETERMINATE`, and writes the terminal record before it consumes the
native authority and operation reservations and releases or keeps closed the
fence. If the move from `RESERVED` to `INVOKING` throws or answers anything
but `true`, the run releases nothing on that basis and reads the durable
record: `INVOKING` means the write landed and the run proceeds as its owner;
`RESERVED` is closed as not entered before anything is released
(`attempt_start_conflict`); `RELEASED` with the not-entered marker means a
pre-entry recovery linearized first, so the run releases what it holds
(`attempt_released_by_recovery`); anything else holds everything as
`INDETERMINATE` with `attempt_start_unconfirmed`. A run that has sent any
write that could record its attempt as not entered, including one whose
acknowledgement was lost, never calls the provider afterwards, whatever a
later read shows.
An unreadable record is read again; a read that shows `INVOKING` lets the
run proceed as the owner, and if the record stays unreadable the run sends
no not-entered write, holds everything, does not call the provider, and
returns `INDETERMINATE` with `attempt_start_unconfirmed`. A record that
then says `INVOKING` although the provider was never called is closable
only by terminal reconciliation with provider evidence that forecloses any
execution, now or later, under the attempt's provider idempotency key, as
the verifier decides; otherwise the action stays fenced, by design. A
point-in-time "not found", even from an authenticated provider lookup, does
not foreclose execution: a run that is still alive can deliver its call
after the lookup. A
reserve answer that is neither exactly `true` or `'RESERVED'` nor a defined
conflict, or a reserve call that throws, is resolved by a durable read and
is otherwise `INDETERMINATE` with `consumption_reservation_unconfirmed`,
never a clean refusal. The native boundary decides
every attempt-store transition and every consumption-store commit, release,
and close by a durable read, never by the store's answer, so a truthy answer
such as `{ ok: false }` never counts; a recovery claim counts only when the
store answers exactly `true`.

Gate compares the canonical action digest and provider coordinates exactly. It
implements no material-field inventory and no equivalence between spellings,
so `"500"` and `"500.00"`, `"USD"` and `"usd"`, trailing whitespace, and NFC
versus NFD strings are different actions, and a field that varies between
retries, such as a memo or a timestamp, would bypass the fence. The gateway or
caller must canonicalize amounts, case, whitespace, and Unicode normalization,
pass only material fields and any instance field, and configure identical
provider coordinates on every boundary instance that can reach one provider
account. A profile that must allow two intentional, otherwise identical
actions declares an instance field, such as a payment instance ID fixed when
the action is authorized, as part of the canonical action and therefore of
the action digest.

## JavaScript surface

Verification is exported from `@emilia-protocol/verify/aeb`:

```js
import {
  issueAebNativeAuthorizationHandoff,
  verifyAebNativeAuthorizationHandoff,
} from '@emilia-protocol/verify/aeb';
```

The Gate path is exported from `@emilia-protocol/gate/aeb`:

```js
import { createNativeConsequenceBoundary } from '@emilia-protocol/gate/aeb';
```

`issueAebNativeAuthorizationHandoff` is an integration helper for a trusted
gateway. It is not a policy engine. `verifyAebNativeAuthorizationHandoff`
accepts an explicit status object for offline verification. The Gate factory
does not; it calls the operator-configured status resolver itself. Production
stores must expose durable state reads so a lost write acknowledgement can be
distinguished from a write that never happened. The PostgreSQL AEB store
provides `state()` through the executor-only `ep_aeb_private.operation_state`
function; after a restart, reconciliation claims the attempt's operation,
native-authority, and action-fence-holder reservations through its recovery
path with the caller's `recovery_authorization`, passing a scope that names
the boundary kind (`boundary: 'native'`), the boundary's configured
`boundary_id`, and the attempt, so one credential covers all three.
The credential is bound to that one attempt (the `attemptIdentity` the
authorizer receives, `native:<boundaryId>:<attemptId>`, with the relying
party and tenant), never to `scope.recoveryOperationKey` or an operation
ID, which attempts that reuse one operation ID for the same action share,
and a claim succeeds only for a row key derived from the scope's own
boundary and attempt. `scope.operationId` is caller-asserted: the store
does not check it against the claimed row, so an authorizer must not rely
on it. A claim without a scope is refused before the authorizer runs
(`recovery_claim_scope_required`). Gate 0.26.0 shipped that store
without `state()`, so there it could not back
`createNativeConsequenceBoundary()`.

Each deployment gives its pins a stable `trust_snapshot_id` and retains the
corresponding snapshot. Reconciliation asks `resolve_historical_pins` for that
exact ID and verifies its digest before checking the old handoff. Rotating a
gateway key or source pin therefore does not reinterpret or strand an attempt
that was admitted under an earlier snapshot.

## What this path does not establish

A valid handoff does not prove that the native system made a wise or lawful
decision, that a human approved the action, or that the provider completed the
effect. It proves only that a pinned gateway signed the stated native `PERMIT`
and execution bindings. Gate then enforces its own admission and custody
lifecycle on the configured provider path.
