# Direct native authorization at the consequence boundary

`AEB-NATIVE-AUTHORIZATION-HANDOFF-v1` is the short path from a native
authorization system to EMILIA Gate. Use it when the native result already
identifies the final action exactly. It does not require CAID or AEC.

This is the reference path staged for AEB-06. It is not part of the published
AEB-05 draft.

The native system still owns the authorization decision. A
relying-party-pinned gateway signs a closed handoff that records:

- the native system, profile, issuer, and stable authorization identifier;
- one `PERMIT` decision and one exact canonical action digest;
- the relying party, audience, executor, tenant, provider, account, and
  environment;
- the validity window and revocation identifier; and
- a replay unit derived from the native authorization identity, not from a
  wrapper or operation ID.

Gate verifies the gateway statement under pinned Ed25519 gateway keys and
accepted source profiles. Gate does not re-verify the native permit or native
artifact. The supported source labels are `aims`, `authzen`, `coaz`, `ap2`,
`oauth`, and `local`. Those labels do not establish conformance with AIMS,
AuthZEN, COAZ, AP2, OAuth, or any other source protocol. The relying party must
pin the exact gateway, profile, and issuer it accepts.

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
5. Gate atomically reserves the operation key and stable native replay key in
   its durable consumption store, then records an attempt. The attempt binds
   the exact trust snapshot, local-program digest, local-decision digest, and
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
   `INDETERMINATE`. The replay fence stays in place until separately authorized
   reconciliation closes the recorded attempt.

The provider idempotency key is derived from the provider coordinates, exact
action digest, and stable native replay unit. Changing a wrapper or Gate
operation ID does not create fresh authority.

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
distinguished from a write that never happened.

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
