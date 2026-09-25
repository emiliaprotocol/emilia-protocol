# Direct native authorization at the consequence boundary

`AEB-NATIVE-AUTHORIZATION-HANDOFF-v1` is the short path from a native
authorization system to EMILIA Gate. Use it when the native result already
identifies the final action exactly. It does not require CAID or AEC.

This is a repository implementation profile for the direct native path that
AEB-06 describes. AEB-06 was posted on 2026-09-24 as an individual
Internet-Draft and is not adopted by any working group. The draft does not
specify this gateway handoff, and the handoff was not part of AEB-05.

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
   rows keyed by that attempt ID: the operation identity, the label-free
   native replay key, and the exact-action fence. The fence is keyed by
   relying party, provider coordinates as configured, and canonical action
   digest. Because every row key includes this attempt's ID, no other attempt
   can release it. A conflict on the operation identity is refused as
   `consumption_conflict` and one on the replay key as
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
   provider, operation, action, native replay unit, attempt, outcome, and the
   verifier-program digest recorded for that attempt. During reconciliation,
   the callback must resolve the verifier identified by that recorded digest,
   not silently reinterpret old evidence under a newer verifier.
8. A missing, malformed, or unauthenticated provider result becomes
   `INDETERMINATE`. The replay and action fences stay in place until separately
   authorized reconciliation closes the recorded attempt. An attempt that never
   entered the provider is never reconciled to `EXECUTED` or `FAILED`; its
   reservations are released only through the proven pre-entry recovery
   below.

## Replay identity

The replay key that Gate reserves and the provider idempotency key are
derived locally from the relying-party-pinned authority namespace and the
native `authorization_id`. The namespace is the issuer unless the matched pin
declares an `authority_namespace`; when it does, the issuer string is not an
input, so pins that spell one issuer two ways (`https://a.example` and
`https://a.example/`) and declare the same namespace share one key. The
`system` and `profile` labels are never inputs, so the same grant presented
under a second label is the same authority. Changing a wrapper, label, or Gate
operation ID does not create fresh authority. The verifier derives
`native_replay_unit` and `replay_key` under the matched pin's namespace and
returns null for both when the source is not pinned.

Pins that accept the same issuer string share the issuer as their namespace
unless every one of them declares an `authority_namespace`; a mix of declared
and default namespaces for one issuer is refused. Pins whose issuers are
different spellings of one URL (scheme or host case, a default port, a
trailing slash) are refused unless all of them declare the same
`authority_namespace`. `verifyAebNativeAuthorizationPins()` reports these
refusals (`native_pins_namespace_declaration_mixed`,
`native_pins_issuer_alias_without_shared_namespace`) before a pin set is used;
`createNativeConsequenceBoundary()` refuses such a pin set at construction, and
the handoff verifier refuses it as `native_handoff_schema_invalid`.

Changing a pin's namespace, or the issuer spelling of a pin that uses the
default namespace, rotates its replay keys: a grant consumed or in flight
under the old key could be admitted again. Drain or reconcile in-flight
attempts, and wait until every grant consumed under the old namespace has
expired or been revoked, before rotating.

The signed `AEB-NATIVE-AUTHORIZATION-HANDOFF-v1` wire is unchanged from
verify 4.1.0. A handoff issued by 4.1.0 verifies under this version, and a
handoff issued by this version verifies under 4.1.0. The carried
`replay_unit` keeps its 4.1.0 derivation under
`AEB-NATIVE-AUTHORIZATION-REPLAY-v1`. The enforcement identity is a local
derivation under `AEB-NATIVE-AUTHORIZATION-REPLAY-IDENTITY-v1`, keyed under
`AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2`, and is not carried on the wire, so
replay keys differ from those that verify 4.1.0 and gate 0.26.0 derived.
Drain stores keyed by the 4.1.0 replay keys before upgrading.

## Same-action fence

The same-action fence is keyed by the relying party, the provider coordinates
exactly as configured, and the canonical action digest. It is released only by
an authenticated terminal `FAILED` outcome (one that passes
`provider_outcomes.verify`), returned directly or reached through authorized
reconciliation, or by a pre-entry stop that Gate proves from its own durable
attempt record. `EXECUTED` keeps it closed for that action instance.

An attempt that stopped before provider entry, for example after a crash while
`RESERVED`, a lost acknowledgement of the move to `INVOKING`, or a store error
during a pre-entry release, keeps the fence and its other reservations.
`reconcile()` releases them when called with a `recovery_authorization` that
the attempt store's `recover()` accepts for that exact attempt, and the
provider's answer: an authenticated "not found" `FAILED` from a lookup, or
`INDETERMINATE` when the provider offers no lookup. It does so only when the
durable attempt record is still `RESERVED` (reconcile moves it to `RELEASED`)
or is `RELEASED` without provider evidence, which Gate records only for a stop
before the provider callback. After each release is confirmed by a durable
read the result is `REFUSED` with `attempt_never_entered_provider`; otherwise
it is `INDETERMINATE` with `native_pre_entry_release_unconfirmed`. A claim of
`EXECUTED` is refused as `reconciliation_outcome_conflict` and releases
nothing. A record that reached `INVOKING` or `INDETERMINATE` still needs a
terminal provider outcome.

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
the attempt so one credential covers all three. Gate 0.26.0 shipped that store without `state()`, so
there it could not back `createNativeConsequenceBoundary()`.

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
