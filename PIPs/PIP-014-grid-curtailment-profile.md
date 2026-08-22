# PIP-014: `grid.curtailment` Action Profile and GRACE Evidence Bundle

**Status:** Implemented reference profile; coauthored individual Internet-Draft -00 published

**Profile:** `EP-GRACE-PROOF-OF-CURTAILMENT-v1`

**Action:** `EP-GRACE-CURTAILMENT-ACTION-v1` / `grid.curtailment`

**Reference path:** `lib/grace/`, `examples/grace/`, and `conformance/vectors/grace-mobile-grid.v1.json`

## 1. Claim boundary

GRACE binds one exact curtailment action to a finite participation envelope, distinct Class-A human
approvals, one-attempt executor admission, a signed actuator acknowledgment, a separately keyed
meter statement, source-routed Outcome Observations, an Action State Signed Statement, and
single-use admission to a settlement adapter.

GRACE verifies signed inputs and deterministic computation. It does not establish physical meter
truth, baseline correctness, tariff eligibility, actual payment, complete mediation, a production
COSA integration, utility adoption, or a physical grid deployment. Its reference actuator and meter
are explicitly simulated.

## 2. Current composition

```text
EP-FLEX-ENVELOPE-v2
        |
EP-GRACE-CURTAILMENT-ACTION-v1
        |
two distinct Class-A mobile approvals
        |
durable reserve-before-dispatch
        |
signed actuator acknowledgment
        |
separately keyed meter statement
        |
executor + independent-observer Outcome Binding
        |
Action State v2 COSE_Sign1 statement
        |
EP-GRACE-SETTLE-v1 one-time settlement admission
        |
EP-GRACE-PROOF-OF-CURTAILMENT-v1
```

The action, presentation, policy, dispatch request, acknowledgment, meter statement, Outcome
Binding result, Action State statement, and settlement entitlement are joined by canonical digests.

## 3. Closed action object

The action has exactly these members:

```json
{
  "@version": "EP-GRACE-CURTAILMENT-ACTION-v1",
  "action_id": "grace:event:...",
  "action_type": "grid.curtailment",
  "effect_class": "power_reduction",
  "facility": "facility:...",
  "target_delta_kw": "18000",
  "window": {
    "not_before": "2026-07-15T20:15:00.000Z",
    "not_after": "2026-07-15T21:45:00.000Z"
  },
  "issued_at": "2026-07-15T20:00:00.000Z",
  "expires_at": "2026-07-15T21:45:00.000Z",
  "baseline_method_hash": "sha256:...",
  "control_mode": "human_on_the_loop",
  "envelope_id": "grace:envelope:...",
  "requested_by": "ep:agent:grid-coordinator"
}
```

Unknown, missing, duplicated, or non-canonicalizable members refuse. `expires_at` equals
`window.not_after`. `issued_at` precedes `window.not_before`. The controlled-action projection is
used to derive the action digest and CAID and to build the human presentation.

## 4. Envelope containment

`EP-FLEX-ENVELOPE-v2` contains positive bounds for:

- `max_event_mw`
- `max_period_mwh`
- `max_events`
- `max_event_hours`
- `min_notice_minutes`
- the participation window

The Gate compares power with power, energy with energy, counts with counts, and hours with hours.
A required bound or present spent-accounting value that is missing, negative, or unparseable
refuses. Omitted spent values mean zero only when the deployment can make that assertion.

## 5. Human authorization

The current reference profile requires two distinct Class-A WebAuthn approvals from a
relying-party-pinned roster. Each approval binds:

- the controlled action, presentation, and policy digests;
- initiator, approver, roster index, and threshold;
- decision and ceremony window;
- relying-party profile, platform, app, credential, and device key.

The verifier requires user verification, the pinned RP ID and origins, distinct people and devices,
initiator exclusion, admitted roles, exact roster indices, and the two-person threshold.

## 6. Executor admission and uncertainty

Before invocation, the Gate validates the action, active window, envelope containment, signed
outcome-policy digest, human authorization, and all deployment-pinned adapters and stores. It then
atomically reserves `grace:{action_id}:{action_hash}` in durable, ownership-fenced state.

Pre-invocation failures are mechanism-named refusals. Concurrent reservation is `refuse_replay`.
If dispatch may have occurred but its result is lost or invalid, the state is
`execution_indeterminate`, `retry_safe` is false, and the action is not blindly retried. A later
measurement or outcome failure is `effect_unconfirmed`, also with no retry authority.

## 7. Measurement and Outcome Binding

The meter statement contains measurement data only. It binds the meter, event, action digest, exact
window, baseline MW, timestamped intervals, measurement class, observation time, and signing key.
It must not contain `baseline_method_hash`. The program-selected rule remains in the authorized
action and relying-party policy.

The compliance calculation uses the accepted meter intervals. The result says what follows from
those signed inputs. It does not prove the baseline was correct or the readings were physically
true.

The actuator and meter each produce an Outcome Observation. The meter uses a distinct pinned key,
source class, and relying-party-declared control domain. That declaration is policy input, not proof
of organizational independence. Missing or insufficient source evidence remains unconfirmed.

## 8. Action State

After reconciliation, GRACE emits a COSE_Sign1 Signed Statement using
`draft-mih-scitt-agent-action-capsule-02`, format version 2. The statement binds the authorization,
dispatch request, meter statement, constraints, disposition, and confirmed-effect claim. The
capsule identifier, protected headers, COSE payload, JSON wrapper, and statement digest
cross-check.

The current output is an `unregistered_signed_statement`. It is not a SCITT transparency-service
registration or proof of ledger inclusion.

## 9. Single-use settlement admission

`EP-GRACE-SETTLE-v1` derives an injective entitlement key from:

```json
["envelope_id", "event_id", "meter_payload_digest"]
```

Only a compliant computation and an in-bounds reconciled outcome may reach the settlement adapter.
The entitlement is atomically reserved before invocation. A duplicate is
`settlement_already_consumed`. An exception after invocation burns or preserves the reservation and
cannot authorize a second attempt.

This is at-most-one admission to the configured settlement effect in one authoritative state
domain. It is not exactly-once physical payment or global double-spend prevention.

## 10. Artifact signatures

The baseline artifact envelope uses Ed25519. The optional
`EP-GRACE-ARTIFACT-SIGNATURE-v2` profile requires both Ed25519 and ML-DSA-65. The required algorithm
list is covered by the signing bytes, and verification refuses missing legs, a narrowed list,
substituted keys, malformed signatures, or an unavailable ML-DSA backend.

The optional hybrid path is implemented and tested. It is not the default reference-circuit output,
and the repository does not claim hardware custody, FIPS validation, or production deployment for
its test keys.

## 11. Current implementation status

| Piece | Current status |
|---|---|
| Exact action, presentation, and CAID derivation | Implemented and tested |
| Dimensioned envelope containment | Implemented and tested |
| Two distinct Class-A mobile approvals | Implemented and tested |
| Durable one-attempt dispatch | Implemented and tested against the store contract |
| Signed COSA-labeled actuator acknowledgment | Simulated reference adapter |
| Separately keyed signed meter statement | Simulated reference adapter |
| Outcome Binding and Action State v2 Signed Statement | Implemented and tested |
| One-time settlement admission | Implemented and tested against the store contract |
| Ed25519 plus ML-DSA-65 hybrid artifact envelope | Optional path implemented and tested |
| Physical actuator, revenue meter, production store, and payment rail | Not supplied or claimed |
| Utility, ISO, tariff, or external implementer validation | Not established |

The targeted current receipt is 80 passing tests across:

```bash
npx vitest run \
  tests/grace-curtailment.test.ts \
  tests/grace-mobile-grid.test.ts \
  lib/grace/mobile-grid-v2.test.ts \
  tests/mobile-production-routes.test.ts
```

## 12. Publication status

The previous June 2026 document in `standards/archive/` was never filed and is superseded as a
technical description by the source in `standards/profiles/NEXT-GRID-CURTAILMENT-00/`.
`draft-schrock-kintzele-grid-curtailment-00` was posted on the IETF Datatracker on August 22, 2026,
after a separately recorded one-time governance override and coauthor approval. The retained XML
and TXT match the immutable IETF archive byte-for-byte. This is an active individual
Internet-Draft, not an RFC, adopted working-group item, implementation or deployment result, or
IETF endorsement. The publication does not satisfy or claim the standing named-external-gap
exception.
