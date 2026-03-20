# EP for Financial Infrastructure

## Executive Summary

Payment fraud and unauthorized transaction modification occur predominantly inside approved workflows -- authenticated users, valid sessions, legitimate system access. The failure is not at the perimeter but at the transaction level: approved flows lack proper constraints on what specific action is authorized, for what specific parameters, and for how many uses. EMILIA Protocol (EP) provides pre-action authorization hardening that binds every trust-changing operation to a specific actor, authority chain, policy version, transaction context, and one-time consumption guarantee.

EP is not an identity provider, fraud scoring engine, or transaction monitoring system. It is control-strengthening infrastructure that sits between authorization decision and action execution, ensuring that approved actions are exactly scoped, cryptographically bound, and consumed once.

---

## Target Workflows

### Vendor Remittance Changes

Modification of payment routing (bank account, routing number, intermediary bank) for an existing vendor relationship. This is the highest-value single-action fraud vector in financial operations. EP binds the change authorization to the specific vendor, specific old and new routing details, and specific approver authority chain. The binding hash changes if any parameter is modified.

### Beneficiary Changes

Updates to the designated recipient of payments, benefits, or distributions -- including changes to disbursement method, address of record, or representative payee. EP ensures the operator's authority covers this beneficiary and change type, and that the approval is consumed exactly once upon execution.

### Payout Instructions

Instructions that direct funds movement: wire transfers, ACH originations, check issuances, or settlement instructions. EP captures the full instruction context (amount, destination, purpose code, reference) in the binding material. The instruction cannot be replayed or modified after approval without producing a binding hash mismatch.

### Treasury Approvals

Multi-level approval workflows for treasury operations: investment instructions, FX trades, collateral movements, or credit facility draws. EP enforces that each approval step is bound to the specific transaction parameters and that approval artifacts are not reusable across transactions.

### Operator-Assisted Servicing

Call center or back-office operations where staff make changes on behalf of customers: account closures, limit increases, fee waivers, address changes. EP captures the operator identity, delegation authority, customer context, and specific change in a single handshake binding. The operator cannot claim post-hoc that they were authorized for a different action.

---

## Key Controls

### Actor Identity

EP derives actor identity from the authentication layer, never from request payloads (Invariant 2). The `resolveAuthority()` function in `lib/protocol-write.js` normalizes the actor from the authenticated session. Handshake initiation enforces that the authenticated entity matches the initiator party's `entity_ref` (`INITIATOR_BINDING_VIOLATION` on mismatch). Presentation submission enforces the same binding (`ROLE_SPOOFING` on mismatch).

This means the identity attached to every trust decision is the identity that was authenticated, not the identity that was claimed.

### Authority Resolution

Issuer trust is resolved from a registered authority table, never from credentials embedded in the request (Invariants 3 and 4). The `_handleAddPresentation()` function in `lib/handshake/present.js` queries the `authorities` table by `key_id`. Unknown issuers default to untrusted (fail-closed). Revoked, expired, and not-yet-valid authorities are tracked with explicit status codes (`authority_revoked`, `authority_expired`, `authority_not_yet_valid`).

CI enforcement (`scripts/check-protocol-discipline.js`, `checkEmbeddedIssuerKeys()`) prevents any code path that trusts keys from the presentation payload.

### Transaction Binding

Every handshake produces a canonical binding hash: `SHA-256` over action type, resource reference, policy ID, policy version, policy hash, interaction ID, party set hash, payload hash, context hash, nonce, expiry, and binding material version (Invariant 10). The `CANONICAL_BINDING_FIELDS` list in `lib/handshake/invariants.js` defines the exact field set. Missing or extra fields throw `BINDING_INVARIANT_VIOLATION`.

At verification, the binding hash is recomputed. Mismatches on any component (action, policy, payload, nonce) produce explicit rejection reason codes.

### Policy Evaluation

Policy is resolved by `resolvePolicy()` in `lib/handshake/policy.js` and hash-pinned at initiation. At verification, the policy is re-loaded and re-hashed. Hash mismatch (policy drift) results in rejection with `policy_hash_mismatch`. Policy load failure results in rejection with `policy_load_failed` or `policy_not_found` (Invariant 7).

There is no fallback to a default or permissive policy. Resolution is fail-closed.

### Immutable Events

Every trust-changing state transition emits a durable event before the state change is materialized (Invariant 9). `appendProtocolEvent()` in `lib/protocol-write.js` records events for all 17 command types. `requireHandshakeEvent()` in `lib/handshake/events.js` records handshake lifecycle events. Both throw on failure, preventing the state change from proceeding.

Event tables (`protocol_events`, `handshake_events`) are append-only with database triggers preventing UPDATE and DELETE.

### One-Time Consumption

Accepted handshake bindings are consumed exactly once (Invariant 8). The `_handleVerifyHandshake()` function in `lib/handshake/verify.js` has a hard gate that rejects already-consumed bindings before any processing. The consumption update uses `.is('consumed_at', null)` as a conditional filter, ensuring that concurrent requests cannot both succeed. A unique constraint on `handshake_consumptions` prevents duplicate records at the database level.

---

## Risk Committee Positioning

### Control-Strengthening Infrastructure

EP does not replace existing controls. It strengthens them by adding a pre-action verification layer:

| Existing Control | EP Strengthening |
|---|---|
| User authentication (SSO, MFA) | Action-level authorization binding (handshake) |
| Role-based access control | Policy-bound authority verification with scope constraints |
| Transaction monitoring (post-hoc) | Pre-action binding with one-time consumption |
| Approval workflows (UI-level) | Cryptographic binding of approval to specific transaction parameters |
| Audit logging (application-level) | Append-only protocol events with database-enforced immutability |
| Delegation management (directory-based) | Scoped, time-bound delegation with explicit chain recording |

### Pre-Action Authorization Hardening

For risk committees evaluating EP, the core value proposition is:

1. **Actions are bound to approvals, not sessions.** A user's session authorizes access; a handshake authorizes a specific action with specific parameters. Changing the parameters requires a new handshake.
2. **Approvals are consumed, not referenced.** Each approval artifact can authorize exactly one action execution. There is no "re-use the same approval" path.
3. **Policy is pinned, not dynamic.** The policy that governs a transaction is the policy that was in effect when the handshake was initiated, verified by hash. Policy changes cannot retroactively weaken requirements.
4. **Authority is registry-resolved, not self-asserted.** Issuer trust comes from a managed registry, not from credentials in the request.
5. **Events precede state changes.** The audit record exists before the action takes effect. If the event cannot be written, the action does not execute.

---

## Outcomes

### Reduced Fraud Risk

EP narrows the attack surface from "any action within a valid session" to "only actions that match a cryptographically bound, policy-pinned, one-time-use approval." Specific fraud vectors addressed:

- **Payment redirection**: Binding hash includes destination details; changing the destination invalidates the approval.
- **Approval replay**: One-time consumption prevents reuse; nonce and expiry prevent replay.
- **Delegation abuse**: Scoped, time-bound delegation with explicit chain recording and verification.
- **Policy circumvention**: Hash-pinned policy with fail-closed resolution.

### Lower Approval Ambiguity

Every approval artifact records exactly what was approved: the action type, resource reference, parameters, policy version, and actor authority chain. Post-hoc disputes about what was authorized are resolvable from the binding material and event log.

### Stronger Investigation Readiness

EP produces investigation-ready evidence by default:

- **Protocol events**: Every trust-changing transition across all aggregate types, with actor, authority, command type, payload hash, and parent event hash.
- **Handshake events**: Full lifecycle (initiated, presentation added, verified/rejected, consumed) with actor entity references and detailed outcome data.
- **Binding material**: Complete action context that can be recomputed and verified against stored hashes.
- **Consumption records**: Timestamped, actor-attributed proof of one-time use.

All event data is append-only with database-enforced immutability, satisfying chain-of-custody requirements for forensic investigation.
