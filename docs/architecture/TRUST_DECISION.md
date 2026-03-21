# EMILIA Protocol -- Trust Decision Specification

## Definition

A Trust Decision is a policy-evaluated, evidence-backed determination about whether a specific action should proceed. It is the primary output object of EP's trust evaluation pipeline. Every decision surface -- `/api/trust/evaluate`, `/api/trust/gate`, handshake verification -- MUST return a Trust Decision in the canonical shape defined by `buildTrustDecision()` in `lib/trust-decision.js`.

Formally: `TrustDecision = (decision, entity_id, policy_used, confidence, reasons, warnings, appeal_path, context_used, profile_summary, extensions)`.

## What a Trust Decision Is NOT

- **Not a score.** A Trust Decision is a categorical outcome (`allow`, `deny`, `review`), not a number. The legacy `compat_score` field exists for backward compatibility but MUST NOT be used for trust-critical logic.
- **Not a credential.** A Trust Decision is not carried or presented by the entity. It is computed server-side and returned to the requesting system.
- **Not permanent.** Decisions are point-in-time evaluations. The same entity may receive `allow` today and `deny` tomorrow if its evidence profile changes.
- **Not a handshake.** A handshake binds identity and authority before an action. A Trust Decision is the output of evaluating that evidence against a policy. The handshake produces the evidence; the decision consumes it.

## Required Fields

| Field | Type | Description |
|---|---|---|
| `decision` | enum | `allow`, `deny`, or `review` |
| `entity_id` | string | The entity this decision is about |
| `policy_used` | string | Which policy produced this decision (e.g., `standard`, `strict`) |
| `confidence` | string | Evidence confidence: `confident`, `emerging`, `provisional`, `insufficient`, `pending` |
| `reasons` | string[] | Why the decision was reached (non-empty on `deny`) |
| `warnings` | string[] | Non-blocking concerns (present on `allow` when edge cases exist) |
| `appeal_path` | string | URL path for disputes/appeals (default: `/api/disputes/report`) |
| `context_used` | object\|null | Context keys that influenced the decision |
| `profile_summary` | object\|null | `{ confidence, evidence_level, dispute_rate }` |

Extensions are spread into the top-level object for backward compatibility. The canonical shape is enforced by `buildTrustDecision()`.

## Decision Outcomes

| Outcome | Condition | Semantics |
|---|---|---|
| `allow` | Policy passes, zero blocking reasons | Action may proceed. On `/api/trust/gate`, a commit is issued. |
| `deny` | One or more policy conditions failed | Action must not proceed. `reasons[]` describes failures. |
| `review` | Policy cannot be evaluated (null pass result) | Insufficient evidence to decide. Manual review required. |

The `review` outcome exists because EP is fail-closed: if the system cannot determine trust, it does not default to `allow`. The entity is directed to provide additional evidence.

### Gate-Specific Outcomes

When a Trust Decision is produced by `/api/trust/gate`, two additional behaviors occur:

1. **Commit issuance**: On `allow`, a commit is minted via `protocolWrite(ISSUE_COMMIT)` and its `commit_ref` is included in the response. This commit serves as the pre-authorization token for the downstream action.
2. **Handshake consumption**: If a `handshake_id` was provided and verified, the handshake binding is consumed (`consumed_at` set, `consumed_for` set to `commit:{commit_ref}`). The binding cannot be reused.

## How Trust Decisions Are Produced

### From `/api/trust/evaluate`

The evaluate endpoint is the general-purpose decision surface. It runs the entity through `canonicalEvaluate()` and maps the result:

```
canonicalEvaluate(entity_id, { policy, context })
  -> policyResult = { pass: bool|null, failures[], warnings[] }
  -> decision = pass === null ? 'review' : pass ? 'allow' : 'deny'
  -> buildTrustDecision(decision, reasons: failures, warnings, ...)
```

### From `/api/trust/gate`

The gate endpoint is the pre-action trust checkpoint. It evaluates the entity, optionally verifies a delegation and/or handshake, and applies policy thresholds:

```
1. canonicalEvaluate(entity_id)
2. Apply GATE_POLICIES[policy] thresholds:
   - min_ee (effective evidence floor)
   - max_dispute_rate
   - require_established (long-term history)
3. If delegation_id provided: verifyDelegation(delegation_id, action)
4. If handshake_id provided: verify handshake status, action binding, binding consumption
5. Collect reasons (any threshold violation = deny)
6. If allow: protocolWrite(ISSUE_COMMIT) -> commit_ref
7. buildTrustDecision(decision, reasons, ...)
```

### From Handshake Verification

When `verifyHandshake()` completes, its result contains reason codes that map to a decision:

| Verification Outcome | Trust Decision Equivalent |
|---|---|
| `accepted` (zero reason codes) | `allow` |
| `partial` (assurance-related codes only) | `review` |
| `expired` (binding_expired code) | `deny` |
| `rejected` (any other failure code) | `deny` |

The handshake verification result is not itself a Trust Decision object. The consuming system (typically `/api/trust/gate`) materializes the verification outcome into a Trust Decision.

## Relationship to Handshake

A handshake produces the evidence that a Trust Decision consumes:

```
Handshake (identity + authority + policy binding)
  -> Verification (check all invariants)
  -> Trust Decision (policy-evaluated outcome)
  -> Commit (pre-authorization token)
  -> Action (downstream execution)
```

The handshake answers "are the parties who they claim to be, under a specific policy?" The Trust Decision answers "given that evidence, should this action proceed?"

## Relationship to Trust Profile

The Trust Profile (`/api/trust/profile/{entityId}`) is the canonical read surface for an entity's accumulated trust evidence. The Trust Decision consumes the profile as input:

- `profile.behavioral.dispute_rate` informs the `max_dispute_rate` policy check
- `effectiveEvidence` informs the `min_ee` threshold
- `confidence` state informs whether the decision is `allow`, `deny`, or `review`
- `establishment.established` informs `require_established` policy checks

The profile provides evidence. The decision provides outcome.

## Reason Codes

Reason codes are human-readable strings describing why a decision was reached. They appear in the `reasons[]` array on `deny` outcomes.

### Gate Policy Reasons

| Reason Pattern | Trigger |
|---|---|
| `Insufficient evidence: {ee} (required: {min})` | Effective evidence below policy floor |
| `Entity has not established long-term trust history` | `require_established` check failed |
| `Dispute rate {rate}% exceeds policy max {max}%` | Dispute rate above policy ceiling |
| `High-value transaction ($X) requires strict policy threshold` | Value escalation to strict policy |
| `Entity not found in EP registry` | Entity does not exist |

### Delegation Reasons

| Reason Pattern | Trigger |
|---|---|
| `Delegation has been revoked` | Delegation status is `revoked` |
| `Delegation has expired` | Delegation past `expires_at` |
| `Action "{type}" is not in delegation scope` | Action not in scope array |
| `Could not verify delegation` | Delegation verification threw |

### Handshake Reasons

| Reason Pattern | Trigger |
|---|---|
| `Handshake not found` | No handshake with provided ID |
| `Handshake status is '{status}', expected 'verified'` | Handshake not in verified state |
| `Handshake action_type mismatch` | Bound action differs from requested |
| `Handshake resource_ref mismatch` | Bound resource differs from requested |
| `Handshake action_hash mismatch -- action intent tampered` | Re-computed action hash differs |
| `Handshake binding already consumed` | Binding has `consumed_at` set |
| `Handshake binding expired` | Binding past `expires_at` |

## Evidence Chain

Every Trust Decision is traceable to the evidence that informed it:

1. **Entity evidence**: Receipts, disputes, behavioral rates, establishment history -- all stored in `receipts`, `disputes`, and derived from `canonicalEvaluate()`.
2. **Handshake evidence**: Presentations, issuer trust status, delegation chains -- stored in `handshake_presentations`, `handshake_results`.
3. **Policy evidence**: The specific policy version and rules that were applied -- pinned by `policy_hash` at handshake initiation, re-verified at verification time.
4. **Delegation evidence**: The delegation record linking principal to agent -- stored in `delegations`, verified by `verifyDelegation()`.

The `context_used` field in the Trust Decision records which evidence keys contributed to the outcome. The `profile_summary` provides a snapshot of the entity's trust state at decision time.

## Immutability

Trust Decisions are point-in-time outputs. They are not stored as first-class objects in the database. Instead, their effects are materialized as:

- **Commits** (on `allow` from gate): stored in `commits` table, append-only lifecycle.
- **Protocol events**: every `protocolWrite()` that produces a decision also writes to `protocol_events`.
- **Handshake results**: stored in `handshake_results`, recording the verification outcome.

Commits, the durable form of an `allow` decision, are append-only. Their status can only move forward: `active` -> `fulfilled` (receipt bound) or `active` -> `revoked`. A fulfilled or revoked commit cannot be un-fulfilled or un-revoked.

## Connection to the Canonical Write Path

Trust Decisions do not bypass `protocolWrite()`. When a gate decision results in `allow`:

```
POST /api/trust/gate
  -> canonicalEvaluate()  (read path -- no protocolWrite)
  -> decision = 'allow'
  -> protocolWrite(ISSUE_COMMIT)  (write path -- full pipeline)
  -> commit minted, protocol_event appended
  -> response includes commit_ref
```

The Trust Decision itself is a read-path computation. Its side effects (commit issuance, binding consumption) flow through the canonical write path. No trust-changing state transition occurs outside `protocolWrite()`.
