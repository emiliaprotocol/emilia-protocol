# GRACE Mobile, COSA, and Action State Composition

Status: runnable reference composition, July 2026. No physical grid deployment is claimed.

## What exists

GRACE now carries one canonical `grid.curtailment` action through five independently
checkable boundaries:

```mermaid
flowchart LR
  A["Bounded grid.curtailment action"] --> B["Two Class-A mobile ceremonies"]
  B --> C["Fail-closed execution reservation"]
  C --> D["COSA actuator adapter"]
  D --> E["Independent signed meter statement"]
  E --> F["Action State signed statement"]
  F --> G["One-time entitlement redemption"]
```

The action bytes, mobile presentation, relying-party policy, dispatch request,
actuator acknowledgment, meter statement, Action State capsule, and entitlement redemption
entitlement are joined by cryptographic digests. The reference implementation adds
no new cryptographic primitive: mobile approvals use the existing Class-A WebAuthn
path, while adapter records use Ed25519 over canonical bytes.

## Run it

```bash
node examples/grace/live-control-room.mjs
npx vitest run tests/grace-mobile-grid.test.ts
```

The public web experience is `/grace/live`. It calls the same reference scenario
exercised by the hostile tests.

## Boundary contracts

### Mobile authorization

`verifyGraceMobileAuthorization` requires a relying-party-pinned roster and checks:

- exact action, display, policy, profile, app, platform, credential, and device-key binding;
- a signed `approved` decision under the existing Class-A WebAuthn verifier;
- signed approver index bound to the pinned roster position;
- distinct humans and device keys, initiator exclusion, admitted roles, and threshold;
- challenge and quorum windows bounded by the action lifetime.

The production API creates all ceremonies for an action atomically. It derives the
display and policy on the server. For cuts at or above the configured hard-cut floor,
one-person authorization is refused.

### Execution and COSA

`executeGraceCurtailment` checks `Order subset-of Envelope`, action activity, and the
mobile quorum before reserving execution. The reference COSA adapter is idempotent and
returns a signed acknowledgment bound to the exact request digest.

There is no claimed production COSA actuator API in the pinned upstream repository.
`lib/grace/reference-adapters.js` is therefore a reference port, explicitly labeled
`simulation: true`; a physical integration must implement the same dispatch and
verification interface under deployment-owned keys.

If dispatch may have occurred and the acknowledgment is lost, the execution is
reported indeterminate and the reservation is burned. The system never retries the
physical effect automatically.

### Measurement and entitlement redemption

The meter has a separate pinned key. It reports readings only; a meter statement that
tries to inject `baseline_method_hash` is refused. The program-selected baseline method
stays in the authorized action, and compliance is computed outside the meter.

Redemption uses an entitlement key over the envelope, event, and signed meter digest.
The entitlement is consumed once. Storage failure or concurrent replay cannot create a
second redemption in the reference state machine; production depends on the durable
store preserving the documented ownership and atomicity contract.

### Action State

After measurement, GRACE emits an
`application/agent-action-capsule+json` COSE Signed Statement using
`draft-mih-scitt-agent-action-capsule-02`, format version `2`. A capsule is never marked
with a confirmed effect unless the signed meter digest is present. The outer JSON
capsule must byte-match the COSE payload, preventing wrapper substitution.

The generated statement was cross-checked against the upstream Python parser and
verifier at commit `8e3895d1b2afb1f794a43b679b986048805c9d3f`: capsule ID agreement and signature
verification passed. This is a time-pinned interoperability check, not endorsement,
registration, or a SCITT transparency-service anchor.

## Honest guarantees

The composition proves that the configured verifier accepted two pinned mobile
ceremonies for one exact action, that one adapter acknowledged one dispatch request,
that a separately keyed meter signed the readings used for compliance, and that the
resulting entitlement was consumed once.

It does not prove that a person understood the display, that the policy was wise, that
the meter measured physical truth, that the baseline method is economically correct,
or that no execution path bypassed the gate. Those are deployment, governance, and
hardware trust questions and must remain explicit.

## Production integrations still required

- Apple App Attest and Google Play Integrity production credentials and provider verification;
- a deployment-owned COSA or scheduler actuator and pinned acknowledgment key;
- a physically independent meter or PDU and pinned measurement key;
- a durable database with the mobile migration applied and its contract suite run;
- a value-transfer system adapter and program-owned baseline methodology;
- optional SCITT registration or transparency anchoring for Action State statements.
