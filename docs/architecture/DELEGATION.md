# EMILIA Protocol -- Delegation Specification

## Definition

A Delegation is a signed authority chain extension: a principal (human, organization, or entity) grants an agent the right to act on their behalf within a bounded scope. Delegations create an auditable link between the human who authorized an action and the agent that executed it.

Formally: `Delegation = (principal_id, agent_entity_id, scope, max_value_usd, expires_at, constraints, status)`.

Delegations are implemented in `lib/delegation.js` (lifecycle management) and `lib/attribution.js` (outcome attribution up the delegation chain).

## What Delegation Is NOT

- **Not impersonation.** The delegate does not become the principal. Both identities are preserved in the audit trail. The delegate's actions are recorded under the delegate's `entity_id`, with the principal linked via `delegation_id`.
- **Not unrestricted.** Delegations are always scoped to a set of action types and optionally capped by value. A delegate cannot perform actions outside their granted scope.
- **Not permanent.** Every delegation has an `expires_at` (default: 24 hours). Expired delegations are automatically invalidated.
- **Not a key pair.** Delegations do not involve key transfer. The principal retains their own authentication; the delegate authenticates independently and references the delegation at action time.

## Delegation Model

```
Principal (human/org)
    |
    | grants delegation with:
    |   - scope: [action_type, ...]
    |   - max_value_usd: cap
    |   - expires_at: TTL
    |   - constraints: additional bounds
    |
    v
Agent (entity)
    |
    | acts within scope
    | references delegation_id in action
    |
    v
Action (commit, handshake, receipt)
    |
    | attribution chain:
    |   - agent: full weight (1.0)
    |   - principal: judgment signal (0.15)
    v
Protocol Event + Audit Trail
```

## Delegation Record

Stored in the `delegations` table.

| Field | Type | Description |
|---|---|---|
| `delegation_id` | string | Unique ID, prefixed `ep_dlg_` |
| `principal_id` | string | The granting entity |
| `agent_entity_id` | string | The authorized agent |
| `scope` | string[] | Permitted action types (e.g., `['install', 'connect']`). Wildcard `'*'` grants all actions. |
| `max_value_usd` | number\|null | Optional transaction value cap |
| `expires_at` | ISO8601 | Delegation expiry (default: 24 hours from creation) |
| `constraints` | object\|null | Additional constraints (future extensibility) |
| `status` | enum | `active`, `revoked`, `expired` |
| `created_at` | ISO8601 | Creation timestamp |
| `revoked_at` | ISO8601\|null | Revocation timestamp (set on revoke) |

## Key Invariants

### S10: Delegate Cannot Exceed Principal's Authority

A delegate's effective authority is bounded by the principal's authority. If the principal has scope `S`, the delegate can receive at most scope `S` -- never more.

From the TLA+ specification (`formal/ep_handshake.tla`):

```
DelegateCannotExceedPrincipal ==
    \A d \in DOMAIN delegations :
        \A del \in delegations[d] :
            del.scope \subseteq authority[del.principal]
```

**Enforcement**: At delegation creation (`createDelegation()` in `lib/delegation.js`), the scope is stored as-is. At verification time (`verifyDelegation()`), the action is checked against the delegation's scope array. The principal's own authority is enforced at the point where the principal authenticates (route-level auth check in `/api/delegations/create`).

### S11: Delegation Chains Are Acyclic

No circular delegation chains. If A delegates to B, B cannot (directly or transitively) delegate back to A.

From the TLA+ specification:

```
DelegationAcyclicity ==
    \A a \in Entities :
        a \notin {d.delegate : d \in delegations[a]}
```

**Enforcement**: The `GrantDelegation` operation in the TLA+ spec includes preconditions: `principal # delegate` (no self-delegation) and acyclicity checks. In the implementation, `createDelegation()` validates that `principalId` and `agentEntityId` are different entities.

### Transitive Scope Is Intersection, Not Union

When delegation chains are extended (A delegates to B, B delegates to C), C's effective scope is the intersection of A->B scope and B->C scope. C cannot gain broader scope by being delegated to by multiple principals.

This is a consequence of S10: each link in the chain can only narrow scope, never widen it. The effective scope at any point in the chain is `scope(A->B) INTERSECT scope(B->C)`.

## Delegation Lifecycle

```
grant --> active --> revoke
                 \-> expired (automatic)
```

### States

| State | Description | Transitions From | Transitions To |
|---|---|---|---|
| `active` | Delegation is valid and can be used | (creation) | `revoked`, `expired` |
| `revoked` | Explicitly revoked by the principal. Terminal. | `active` | (none) |
| `expired` | Past `expires_at`. Auto-detected at verification time. Terminal. | `active` | (none) |

### Grant

`POST /api/delegations/create` -> `createDelegation()` in `lib/delegation.js`.

Preconditions:
- `principal_id` must match the authenticated entity (no forgery -- enforced in route handler).
- `agent_entity_id` must reference an existing entity in the `entities` table.
- `scope` must be a non-empty array of action type strings.
- Default expiry: 24 hours from creation.

The delegation is inserted into the `delegations` table with status `active`.

### Verify

`GET /api/delegations/{delegationId}/verify` -> `verifyDelegation()` in `lib/delegation.js`.

Verification checks, in order:
1. Load delegation by `delegation_id`.
2. If `status === 'revoked'`: return `valid: false`, reason: `Delegation has been revoked`.
3. If `now > expires_at`: auto-expire (update status to `expired`), return `valid: false`, reason: `Delegation has expired`.
4. If `actionType` provided: check `scope.includes(actionType) || scope.includes('*')`. If not in scope: return `valid: true, action_permitted: false`.
5. Otherwise: return `valid: true`.

Verification is fail-closed: unknown delegations return `valid: false, status: 'not_found'`. If the `delegations` table does not exist (pre-migration), the same fail-closed response is returned.

### Revoke

`revokeDelegation(delegationId, principalId)` in `lib/delegation.js`.

Preconditions:
- `principal_id` on the revocation must match the delegation's `principal_id`. Only the granting principal can revoke.
- Revocation is immediate and terminal. The delegation cannot be un-revoked.

## How Delegation Connects to Handshake Verification

In delegated handshake mode, the presenter must match either the declared party or a valid delegate:

1. At handshake initiation, parties include a `delegate` role with `entity_ref` pointing to the agent and `delegation_chain` containing scope and expiry.
2. At presentation time, the authenticated entity adding a presentation for the `delegate` role must match the delegate's `entity_ref` (enforced by `DELEGATE_BINDING_VIOLATION` in `_handleAddPresentation()`).
3. At verification time, delegation-specific checks are applied:
   - Delegation expiry validation
   - Delegation scope validation (action must be in scope)
   - These are steps 9 in the verification pipeline (see HANDSHAKE.md)

If delegation verification fails, the handshake is rejected with delegation-specific reason codes.

## How Delegation Connects to Accountable Signoff

When a commit is issued under delegation, the signoff actor must have matching authority class through the delegation chain:

1. The commit carries `delegation_id` linking it to the delegation record.
2. `authorizeCommitIssuance()` in `lib/commit-auth.js` checks that the authenticated entity either owns the `entity_id` directly or holds a verified delegation for the requested `action_type`.
3. Only the principal or a delegate with scope covering the action can issue, revoke, or view the commit.

## Attribution Chain

When an agent acts under delegation, the outcome is not theirs alone. The principal's judgment -- "did they authorize a well-behaved agent?" -- belongs in the ledger.

`lib/attribution.js` computes the attribution chain:

| Role | Entity | Weight | Purpose |
|---|---|---|---|
| `agent` | Agent entity | 1.0 | Full weight: the agent performed the action |
| `principal` | Principal entity | 0.15 | Weak signal: delegation authority quality |

The 0.15 weight is deliberately weak. A single delegation gone wrong should not destroy a principal's trust profile. But a pattern of authorizing misbehaving agents should be legible to the system.

### Attribution Mechanics

After a receipt is written for a delegated action:

1. `buildAttributionChain(receipt)` constructs the chain from `receipt.delegation_id` and `receipt.context.principal_id`.
2. `applyAttributionChain(receipt, chain)` writes the agent attribution via the main receipt path and the principal attribution as a lightweight signal to `principal_delegation_signals`.
3. Both `delegation_id` AND `principal_id` must be present for principal attribution. A bare `principal_id` without a delegation record is not sufficient -- the delegation record is the proof.

### Delegation Judgment Score

`getDelegationJudgmentScore(principalId)` in `lib/attribution.js` answers: "Does this principal consistently authorize well-behaved agents?"

The score is computed as:
- Weighted fraction of delegations producing positive outcomes
- Agents with zero delegations: `judgment_score: null` (no judgment yet)
- Returned fields: `judgment_score`, `agents_authorized`, `good_outcome_rate`, `total_signals`, `positive_signals`, `negative_signals`

This score feeds into the principal's trust profile, creating a feedback loop: principals who consistently delegate to good agents build trust; principals who delegate to bad agents erode it.

## Connection to the Canonical Write Path

Delegation creation does not currently flow through `protocolWrite()`. It uses direct database insertion via `getServiceClient()` in `lib/delegation.js`. This is because delegation is not yet classified as a trust-changing write in the same sense as receipts, commits, or disputes.

However, delegation verification is consumed by `protocolWrite()` flows:
- `ISSUE_COMMIT` checks delegation validity via `authorizeCommitIssuance()`
- `VERIFY_HANDSHAKE` checks delegation scope in delegated mode
- `/api/trust/gate` calls `verifyDelegation()` when `delegation_id` is provided

Delegation creation and revocation do not emit `protocol_events`. This is a known gap; delegation events may be added in a future protocol version.

## Implementation References

| Component | File | Purpose |
|---|---|---|
| Delegation lifecycle | `lib/delegation.js` | `createDelegation()`, `verifyDelegation()`, `revokeDelegation()` |
| Attribution chain | `lib/attribution.js` | `buildAttributionChain()`, `applyAttributionChain()`, `getDelegationJudgmentScore()` |
| Create route | `app/api/delegations/create/route.js` | Principal auth enforcement, rate limiting |
| Verify route | `app/api/delegations/[delegationId]/verify/route.js` | Public verification endpoint |
| Commit authorization | `lib/commit-auth.js` | `authorizeCommitIssuance()` -- delegation-aware |
| TLA+ specification | `formal/ep_handshake.tla` | Theorems S10, S11; `GrantDelegation` operation |
