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
- a replay unit derived from the issuer and the native authorization
  identifier only, under the default authority namespace (the issuer). The
  system and profile labels, wrapper IDs, and operation IDs are not inputs.

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
5. Gate atomically reserves the operation key together with the stable
   native replay key in its durable consumption store. It then atomically
   reserves the exact-action fence, keyed by relying party, provider
   coordinates, and action digest, through a second reservation owned by this
   operation. If an earlier attempt for the same action is still `RESERVED`,
   `INVOKING`, or `INDETERMINATE`, the fence reservation conflicts: Gate
   releases its own operation reservation without entering the provider and
   refuses with `native_action_in_flight` (or `native_action_already_executed`
   once the action has executed). This holds even when the new handoff carries
   a fresh `authorization_id` and a fresh operation ID. Gate then records an
   attempt. The attempt binds the exact trust snapshot, local-program digest,
   local-decision digest, and provider-outcome verifier digest.
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
   entered the provider cannot be reconciled.

The replay identity that Gate fences and the provider idempotency key are
derived from the relying-party-pinned authority namespace, the issuer, and the
native `authorization_id`. The `system` and `profile` labels are not inputs,
so the same grant presented under a second label is the same authority. A pin
may declare an `authority_namespace`; by default the namespace is the issuer,
and pins that accept one issuer under several labels share one namespace
unless each declares a distinct one. A pin set that mixes declared and default
namespaces for one issuer is refused. Changing a wrapper, label, or Gate
operation ID does not create fresh authority. The verifier derives
`native_replay_unit` and `replay_key` under the matched pin's namespace and
returns null for both when the source is not pinned.

The replay derivations use the domains `AEB-NATIVE-AUTHORIZATION-REPLAY-v2`
and `AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2`. Verify 4.1.0 hashed the labels
into the signed `replay_unit`, so a handoff issued by 4.1.0 is refused as
`native_handoff_schema_invalid` by later verifiers and must be reissued.

The same-action fence is released only by an authenticated terminal `FAILED`
outcome, returned directly or reached through authenticated reconciliation, or
by a proven pre-entry release. `EXECUTED` keeps it closed for that action
instance. A profile that must allow two intentional, otherwise identical
actions declares an instance field, such as a caller-chosen payment instance
ID, as part of the canonical action and therefore of the action digest. Gate
digests the action object the caller passes, so a field that varies between
retries, such as a memo or a timestamp, would bypass the fence; pass only
material fields and any instance field.

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
function; after a restart, reconciliation claims the operation and
action-fence reservations through its recovery path with the caller's
`recovery_authorization`. Gate 0.26.0 shipped that store without `state()`, so
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
