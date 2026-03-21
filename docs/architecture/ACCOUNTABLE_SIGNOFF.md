# EMILIA Protocol -- Accountable Signoff

## What Accountable Signoff Is

Accountable Signoff is a policy-driven mechanism through which a named human assumes personal responsibility for a specific high-risk action that has been prepared and verified by machine systems.

It is the point at which machine trust verification ends and human accountability begins. The machine has done its work: identity is bound, authority is checked, policy is satisfied, the handshake is verified. But policy says this action class requires more. It requires a human who will own the outcome.

### What Signoff Is NOT

**Not MFA.** MFA proves you are who you claim to be. Signoff proves you have seen a specific action, understood its consequences, and accepted responsibility for its execution. MFA is an identity assertion. Signoff is an accountability assertion. A system that conflates the two will authenticate actors who have no idea what they are approving.

**Not generic human-in-the-loop.** Human-in-the-loop patterns present a decision to a person. Accountable Signoff presents a decision *with its full action context, risk class, policy basis, and consequences* to a *named person with matching authority*. The human does not approve a vague request. They approve a cryptographically bound action description that they can read, understand, and be held accountable for.

**Not manual approval theater.** Systems that route every action through a human approval step create fatigue without accountability. If every action requires approval, no approval is meaningful. Accountable Signoff is triggered only when policy defines a specific action class as requiring human ownership. The default path does not involve signoff. The signoff path exists because the action's consequences demand it.

**Not a ceremony.** Signoff is not a UI pattern. It is a protocol object with a defined lifecycle, cryptographic binding, and append-only audit trail. The presentation layer may vary (secure app, passkey prompt, out-of-band confirmation), but the protocol object is invariant.

### The Distinction

Handshake handles machine-side trust. It binds identity, authority, and policy to an action and verifies that all machine-checkable requirements are satisfied before execution.

Signoff handles human accountability. It ensures that for action classes where machines should not be the final authority, a named human has seen the exact action, authenticated at the required assurance level, and made a deliberate decision to approve, deny, or escalate.

The two are complementary and sequential. Handshake is necessary but not sufficient for signoff-required actions. Signoff without a verified handshake has no trust basis. Handshake without signoff (where policy requires it) has no human owner.

## Why It Exists

### The Accountability Gap

As agent systems move from advisory to executive roles, a structural gap emerges: the system can verify trust requirements, but nobody owns the verification. A handshake proves that identity, authority, and policy were satisfied at the moment of verification. It does not prove that any human understood or accepted responsibility for the downstream action.

For many action classes, this is fine. Routine transactions, low-value operations, and reversible actions do not require human ownership at the point of execution. Machine trust verification is sufficient.

For others, it is not. When an agent changes a payment destination, redirects government benefits, executes a destructive operation on production infrastructure, or commits an organization to a financial obligation above a threshold, institutions need a record that a specific human saw the specific action and said yes.

### What Institutions Need

The requirement is not philosophical. It is operational and legal:

1. **Named ownership.** Not "someone approved this" but "Jane Chen (authority class: treasury_officer) approved this specific payment redirect at 2026-03-18T14:23:07Z after viewing the exact before/after state."
2. **Action specificity.** The approval must bind to the exact action. Blanket approvals ("I approve all actions from this agent today") are not signoff. They are delegation, which is a different mechanism with different rules.
3. **Auditability.** The approval, the action it approved, the policy that required the approval, and the authentication method used must all be recoverable from the append-only event log.
4. **Non-replayability.** A signoff attestation is consumed exactly once. It cannot be reused for a different action or a repeated execution of the same action.

## The Flow

The complete flow for a signoff-required action:

```
1. Handshake initiated
     |
2. Presentations added, handshake verified
     |  (machine-side trust established)
     |
3. Policy evaluated: signoff_required = true
     |  (policy identifies action class, required authority, assurance level)
     |
4. Signoff Challenge issued
     |  challenge_id generated
     |  binding_hash carried from handshake
     |  challenge delivered to accountable actor via policy-defined channel
     |
5. Human views challenge
     |  Exact action displayed:
     |    - action_type, resource_ref
     |    - before/after diff (if applicable)
     |    - risk_class
     |    - policy_key, policy_version
     |    - consequences summary
     |    - challenge expiry
     |
6. Human authenticates
     |  Authentication method must meet policy-required assurance level
     |  (passkey, biometric, out-of-band, dual signoff)
     |
7. Human decides: approve / deny / escalate
     |
8. Signoff Attestation created (if approved)
     |  attestation_id generated
     |  binding_hash must match challenge binding_hash
     |  authentication_method recorded
     |  actor_entity_ref recorded
     |  decision_timestamp recorded
     |
9. Execution gate
     |  Requires ALL of:
     |    - Verified handshake (not expired, not revoked)
     |    - Valid signoff attestation (not expired, not revoked, not consumed)
     |    - binding_hash match across handshake, challenge, and attestation
     |    - Atomic consumption of attestation
```

If any component is missing, expired, or mismatched, execution does not proceed.

## State Machine

### Challenge Lifecycle

```
challenge_issued --> challenge_viewed --> approved
                                     \-> denied
                                     \-> escalated
                 \---------------------> expired
```

### Attestation Lifecycle

```
approved --> consumed
         \-> expired
         \-> revoked
```

### Terminal States

| Terminal State | Reached From | Meaning |
|---|---|---|
| `denied` | `challenge_viewed` | Human explicitly rejected the action. No attestation created. |
| `consumed` | `approved` | Attestation was used exactly once for execution. Normal completion. |
| `expired` (challenge) | `challenge_issued` | Challenge TTL exceeded before human response. |
| `expired` (attestation) | `approved` | Attestation TTL exceeded before consumption. Action was approved but not executed in time. |
| `revoked` | `approved` | Attestation explicitly revoked by signoff actor, escalation authority, or system. |
| `escalated` | `challenge_viewed` | Human declined personal authority; routed to higher authority class. |

### State Transition Rules

1. Only `challenge_issued` may transition to `challenge_viewed`. The transition is triggered by the accountable actor's client confirming receipt and display of the challenge.
2. Only `challenge_viewed` may transition to `approved`, `denied`, or `escalated`. The human must have seen the action before deciding.
3. Only `approved` may transition to `consumed`, `expired`, or `revoked`. An attestation that was never created (denied/escalated) cannot reach these states.
4. `consumed` is absolutely terminal. No transitions out.
5. `denied` is absolutely terminal. A denied action requires a new handshake and new challenge.
6. `escalated` creates a new challenge at a higher authority class. The original challenge enters terminal state.

Every state transition emits a mandatory `signoff_events` record before the state change is materialized, following the event-first ordering principle established in the Event Model.

## Object Models

### Signoff Challenge

The challenge is the object delivered to the accountable actor. It contains everything the human needs to make an informed decision.

| Field | Type | Description |
|---|---|---|
| `challenge_id` | UUID | Unique identifier for this challenge |
| `handshake_id` | UUID | The verified handshake that triggered this signoff requirement |
| `binding_hash` | string | SHA-256 binding hash, carried from the handshake binding |
| `action_type` | string | The action being authorized (matches handshake action_type) |
| `resource_ref` | string | The resource the action targets (matches handshake resource_ref) |
| `action_diff` | JSON | Before/after state diff for the action, if applicable |
| `risk_class` | string | Policy-assigned risk classification |
| `policy_key` | string | The policy that requires signoff |
| `policy_version` | integer | Pinned policy version |
| `policy_hash` | string | SHA-256 of policy rules at challenge creation |
| `consequences_summary` | string | Human-readable description of action consequences |
| `signoff_actor_ref` | string | Entity reference of the human required to sign off |
| `authority_class` | string | Required authority class for the signoff actor |
| `required_assurance` | enum | Minimum authentication assurance: `substantial`, `high` |
| `channel` | string | Delivery channel for the challenge (secure_app, out_of_band, etc.) |
| `dual_signoff_required` | boolean | Whether a second independent signoff is required |
| `status` | enum | `challenge_issued`, `challenge_viewed`, `approved`, `denied`, `escalated`, `expired` |
| `expires_at` | ISO 8601 | Challenge expiry deadline |
| `created_at` | ISO 8601 | Challenge creation timestamp |
| `viewed_at` | ISO 8601 | Timestamp when accountable actor confirmed viewing (null until viewed) |
| `decided_at` | ISO 8601 | Timestamp of approve/deny/escalate decision (null until decided) |

### Signoff Attestation

The attestation is the protocol object that records a human's approval. It is the artifact consumed at execution time.

| Field | Type | Description |
|---|---|---|
| `attestation_id` | UUID | Unique identifier for this attestation |
| `challenge_id` | UUID | The challenge this attestation responds to |
| `handshake_id` | UUID | The handshake this attestation is bound to |
| `binding_hash` | string | Must exactly match the challenge and handshake binding_hash |
| `signoff_actor_ref` | string | Entity reference of the human who approved |
| `authority_class` | string | Authority class of the signoff actor at time of approval |
| `authentication_method` | string | Method used: `passkey`, `platform_biometric`, `secure_app`, `out_of_band`, `sms_transitional` |
| `authentication_assurance` | enum | Achieved assurance level: `low`, `medium`, `substantial`, `high` |
| `decision` | enum | `approved` (only value that creates an attestation) |
| `decision_context` | JSON | Optional structured context the actor provided with approval |
| `status` | enum | `active`, `consumed`, `expired`, `revoked` |
| `consumed_at` | ISO 8601 | Timestamp of consumption (null until consumed) |
| `consumed_by` | string | Entity reference that consumed the attestation |
| `expires_at` | ISO 8601 | Attestation expiry deadline (shorter than or equal to challenge expiry) |
| `revoked_at` | ISO 8601 | Timestamp of revocation (null unless revoked) |
| `revoked_by` | string | Entity reference that revoked (null unless revoked) |
| `created_at` | ISO 8601 | Attestation creation timestamp |

### Signoff Consumption

The consumption record proves that a specific attestation was used for a specific execution. It is the final link in the chain: handshake -> challenge -> attestation -> consumption.

| Field | Type | Description |
|---|---|---|
| `consumption_id` | UUID | Unique identifier for this consumption |
| `attestation_id` | UUID | The attestation being consumed |
| `challenge_id` | UUID | The challenge that produced the attestation |
| `handshake_id` | UUID | The handshake that produced the challenge |
| `binding_hash` | string | Must match across all three upstream objects |
| `action_type` | string | The action that was executed |
| `resource_ref` | string | The resource the action targeted |
| `execution_ref` | string | Reference to the downstream execution record |
| `consumed_by` | string | Entity reference of the system that consumed the attestation |
| `consumed_at` | ISO 8601 | Timestamp of consumption |
| `binding_verified` | boolean | Whether binding_hash was verified across all objects at consumption time |

Consumption is atomic. The attestation's `consumed_at` field and the consumption record are written in the same transaction. The `consumed_at IS NULL` filter on the attestation update ensures exactly-once consumption, following the same pattern established for handshake binding consumption.

## Policy Model

### Signoff Policy Controls

Signoff requirements are expressed as rules within the handshake policy object. When a handshake is verified and its policy contains signoff rules, the signoff gate activates.

Policy controls:

| Control | Type | Description |
|---|---|---|
| `signoff_required` | boolean | Whether this action class requires human signoff |
| `signoff_authority_class` | string | Required authority class for the signoff actor |
| `signoff_assurance_minimum` | enum | Minimum authentication assurance level |
| `signoff_channel` | string | Required delivery channel |
| `signoff_challenge_ttl` | integer | Challenge expiry in seconds (clamped to [120s, 3600s]) |
| `signoff_attestation_ttl` | integer | Attestation expiry in seconds (clamped to [60s, 1800s]) |
| `dual_signoff_threshold` | number | Value or risk threshold above which dual signoff is required |
| `dual_signoff_authority_classes` | array | Authority classes for dual signoff (must be distinct actors) |
| `out_of_band_required` | boolean | Whether the challenge must be delivered out-of-band |
| `escalation_authority_class` | string | Authority class for escalation target |

### Policy Examples

**Payment destination change.** An agent modifies the bank account associated with a payee. Policy requires signoff from an actor with `treasury_officer` authority class, `high` assurance authentication via passkey or platform biometric, delivered through the secure app channel. If the payment amount exceeds the dual signoff threshold, a second signoff from a `treasury_senior` authority class is required.

**Government benefits redirect.** An agent changes the routing of benefit payments. Policy requires signoff from an actor with `benefits_administrator` authority class, `high` assurance, out-of-band delivery (separate from the channel the agent uses), and mandatory dual signoff regardless of amount.

**Agent destructive action.** An agent requests deletion of production data or revocation of credentials. Policy requires signoff from an actor with `platform_admin` authority class, `substantial` assurance, with the challenge displaying the exact resources to be destroyed and the irreversibility statement.

### Policy Resolution

Signoff policy is resolved at handshake verification time as part of the standard policy resolution pipeline. The signoff rules are included in the policy hash. If the policy changes between handshake initiation and signoff challenge creation, the policy hash mismatch will cause the signoff gate to reject the challenge.

## Signoff Methods

### Allowed Methods

| Method | Assurance Level | Description |
|---|---|---|
| Secure app | `high` | Dedicated application with device binding and push-based challenge delivery |
| Passkey / WebAuthn | `high` | FIDO2-based authentication with hardware-bound credential |
| Platform authenticator with biometric | `substantial` | Device-native biometric (Face ID, Touch ID, Windows Hello) |
| Out-of-band confirmation | `high` | Challenge delivered on a separate channel from the requesting system |
| Dual signoff | `high` | Two independent actors each complete signoff. Neither actor alone is sufficient. |

### Transitional Methods

| Method | Assurance Level | Constraint |
|---|---|---|
| SMS OTP | `medium` | Permitted only for action classes with risk_class `moderate` or below. Not permitted for `high` or `critical` risk classes. Subject to deprecation timeline defined in deployment policy. |

### Prohibited

EP never stores raw biometric data. Biometric verification is performed by the platform authenticator (device-level) and the result is attested, not the biometric itself. An implementation that transmits or stores raw biometric templates is non-conformant.

## Integration with Handshake

### Consumption Gate

For signoff-required actions, the execution gate requires both artifacts:

```
Execution requires:
  1. Verified handshake (status = verified, not expired, not revoked)
  2. Valid signoff attestation (status = active, not expired, not revoked, not consumed)
  3. binding_hash match:
       handshake.binding_hash == challenge.binding_hash
       challenge.binding_hash == attestation.binding_hash
       attestation.binding_hash == consumption.binding_hash
  4. Atomic consumption of BOTH handshake binding AND signoff attestation
```

If the handshake expires or is revoked between signoff approval and consumption, the attestation is orphaned. A new handshake must be created, which will generate a new binding_hash, requiring a new challenge and new signoff.

### Binding Hash Continuity

The `binding_hash` is the cryptographic thread that connects the entire chain. It is computed once at handshake initiation from the canonical binding fields and carried unchanged through every subsequent object:

```
Handshake binding
    binding_hash = SHA-256(canonical_binding_material)
        |
Signoff Challenge
    binding_hash = (copied from handshake)
        |
Signoff Attestation
    binding_hash = (copied from challenge, verified against handshake)
        |
Signoff Consumption
    binding_hash = (verified against attestation, challenge, and handshake)
```

At consumption time, the binding_hash is verified across all four objects. Any mismatch causes rejection with `SIGNOFF_BINDING_MISMATCH`. This prevents an attestation issued for one action from being consumed for a different action, even if both actions share the same handshake.

### Sequencing

Signoff is always sequenced after handshake verification and before execution:

```
Handshake lifecycle:    initiated -> verified -> (consumed at execution)
Signoff lifecycle:      challenge_issued -> approved -> (consumed at execution)
Execution:              requires both consumed in same transaction
```

A signoff challenge cannot be issued for an unverified handshake. A signoff attestation cannot be consumed without a verified handshake. The handshake's `consumed_at` and the attestation's `consumed_at` are set in the same atomic operation.

## Threat Model Additions

### Approval Laundering

**Threat.** An attacker routes a signoff challenge to a human who has valid authentication credentials but lacks the authority class required by policy. The human authenticates successfully, and the system treats the signoff as valid because identity was proven.

**Mitigation.** The signoff actor's `authority_class` is verified at attestation creation time against the challenge's `authority_class` requirement. The authority class is resolved from the actor's current authority registry entry, not from the actor's claim. If the actor's authority class does not match or exceed the required class, attestation creation fails with `SIGNOFF_AUTHORITY_MISMATCH`. Authority class is re-verified at consumption time. If the actor's authority was revoked between attestation and consumption, consumption fails with `SIGNOFF_AUTHORITY_REVOKED`.

### Signoff Fatigue

**Threat.** If signoff is required for too many action classes, humans will develop approval fatigue and rubber-stamp challenges without reading them. This degrades signoff from an accountability mechanism to a click-through ritual.

**Mitigation.** Signoff is not a universal gate. It is triggered only for action classes that policy explicitly marks as `signoff_required`. The policy model is designed to be selective: signoff is reserved for high-risk action classes where human ownership is institutionally required. Implementations SHOULD monitor signoff approval rates and latencies. An approval rate above 98% or an average decision time below 3 seconds for a given actor is a signal that signoff fatigue may be occurring. Implementations MAY flag such patterns for policy review.

The adaptive principle: if everything requires signoff, nothing gets signed off meaningfully. Policy authors bear responsibility for limiting signoff requirements to action classes where the consequences genuinely warrant human ownership.

### Signoff Social Engineering

**Threat.** An attacker manipulates the signoff actor into approving a malicious action by presenting a misleading description of what the action does, obscuring the before/after diff, or creating urgency that bypasses careful review.

**Mitigation.** The challenge object contains the exact action description derived from the handshake binding material, not a human-authored summary that could be manipulated. The `action_type`, `resource_ref`, `action_diff`, `risk_class`, `policy_key`, `consequences_summary`, and `expires_at` are all populated from protocol objects, not from the requesting agent's description. The challenge display is rendered by the signoff channel's trusted application, not by the agent requesting the action.

Implementations MUST display the full action context. Implementations MUST NOT allow the requesting agent to customize the challenge display. The human sees what the protocol sees, not what the agent wants them to see.

### Replay of Expired Attestations

**Threat.** An attacker captures an expired attestation and attempts to present it for consumption, hoping the expiry check is performed inconsistently.

**Mitigation.** Attestation expiry is checked at consumption time against the server's clock. The `expires_at` field is set at attestation creation and cannot be modified (append-only event log, no UPDATE on attestation records). The consumption gate rejects attestations where `expires_at < now` with `SIGNOFF_ATTESTATION_EXPIRED`. The attestation TTL is clamped by policy to a maximum of 1800 seconds, limiting the window of validity.

### Dual Signoff Collusion

**Threat.** In a dual signoff configuration, both signoff actors collude to approve a malicious action.

**Mitigation.** Dual signoff does not eliminate collusion risk. It raises the cost. The two actors must have distinct `entity_ref` values, distinct `authority_class` values (as defined by the dual_signoff_authority_classes policy control), and must authenticate independently. Both attestations are recorded in the append-only log with full actor identity, authentication method, and timestamp. Post-hoc audit can detect patterns of coordinated approval across actor pairs. Dual signoff is a deterrence and audit mechanism, not a cryptographic guarantee against collusion.

## Event Model Integration

Signoff lifecycle events follow the event-first ordering principle: every state transition emits a mandatory event record before the state change is materialized.

### Signoff Event Types

```
signoff_challenge_created      -- challenge issued to accountable actor
signoff_challenge_viewed       -- accountable actor confirmed viewing
signoff_challenge_approved     -- human approved; attestation created
signoff_challenge_denied       -- human denied; terminal
signoff_challenge_escalated    -- human escalated; new challenge at higher authority
signoff_challenge_expired      -- challenge TTL exceeded; terminal
signoff_attestation_consumed   -- attestation used for execution; terminal
signoff_attestation_expired    -- attestation TTL exceeded without consumption; terminal
signoff_attestation_revoked    -- attestation explicitly revoked; terminal
```

All signoff events are written to the `signoff_events` table, which is append-only with the same UPDATE/DELETE trigger protection as `protocol_events` and `handshake_events`.

Each signoff event records: `event_id`, `challenge_id`, `attestation_id` (if applicable), `handshake_id`, `event_type`, `actor_entity_ref`, `detail` (JSON), `created_at`.

The signoff event log, combined with the handshake event log and protocol event log, provides a complete reconstruction of the trust decision chain from handshake initiation through human signoff through execution.
