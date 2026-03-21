# EP for Government Fraud Prevention

## Executive Summary

Government fraud often succeeds inside authorized systems, through authenticated users and approved-looking workflows. The missing control is not simple identity verification. It is action-level trust enforcement: proving that this specific actor, under this specific authority chain, is allowed to perform this specific high-risk action under this specific policy, exactly once.

EMILIA Protocol (EP) provides that control layer. It sits downstream of identity and upstream of execution, binding high-risk actions to policy, authority, transaction context, replay resistance, and durable event traceability before they take effect.

---

## Problem Statement

### Weak Delegated Authority

Government operations rely heavily on delegation -- supervisors authorizing staff, contracting officers delegating to representatives, system operators acting on behalf of program offices. Current systems authenticate the delegate's identity but rarely verify that:

- The delegation is still active (not expired or revoked)
- The delegate is acting within scope (the right policy, the right transaction type)
- The delegation chain is auditable after the fact

EP's delegation model (`lib/handshake/bind.js`, `checkDelegation()`) enforces explicit scope constraints (policy ID list or wildcard) and expiry. Out-of-scope or expired delegations produce `delegation_expired` or `delegation_out_of_scope` rejection codes. The delegation chain is recorded in the handshake record and preserved in the event log.

### Poor Transaction Binding

Most government authorization is session-level: a user is authenticated, and all actions within that session are implicitly authorized. This means a payment amount change, a beneficiary redirect, or an address modification requires no additional proof that the specific action was reviewed and approved. The action is not cryptographically bound to the approval.

EP binds every authorization to a specific action context through a canonical binding hash (`SHA-256` over action type, resource reference, policy version, party set, payload, nonce, and expiry). The hash is computed at initiation and verified at execution. Any modification to any field produces a different hash and triggers rejection (`action_hash_mismatch`, `payload_hash_mismatch`). See `lib/handshake/invariants.js` for canonical binding field definitions.

### Replay Risk

Government transactions are high-value, low-frequency, and often involve approval chains with significant latency. This creates replay windows: a previously valid approval is re-presented to authorize a different or duplicate action. Current systems rely on application-level dedup logic, which is inconsistently implemented.

EP provides three-layer replay resistance: 32-byte random nonce per binding, configurable TTL clamped to [60s, 1800s], and one-time consumption enforced by database-level conditional update (`consumed_at IS NULL` filter) and unique constraint on the `handshake_consumptions` table. See Threat Model entries 4 (Artifact Replay) and 5 (Approval Reuse).

---

## Best-Fit Use Cases

### Payment Instruction Changes

A staff member modifies a vendor's banking details (routing number, account number) for an existing payment stream. EP handshake binds the change request to the specific vendor, the specific payment stream, and the specific new banking details. The approval cannot be replayed for a different vendor or different details.

### Benefits Redirection

An operator changes the disbursement destination for a benefits recipient (direct deposit routing, address change, representative payee assignment). EP enforces that the operator's authority covers this recipient and this change type, that the policy governing the change was the policy in effect when the approval was granted, and that the approval is consumed exactly once.

### Delegated Approvals

A contracting officer's representative (COR) approves an invoice on behalf of the contracting officer (CO). EP's delegation model verifies that the COR's delegation is current, scoped to the relevant contract, and that the specific invoice amount and line items match the binding material. The delegation chain is preserved in the handshake event log for post-audit.

### Operator Overrides

A system administrator overrides an automated control (fraud hold release, account unlock, access level change). EP captures the override as a handshake with the operator's identity, the override justification (in the payload), and the specific system state being overridden. The override is policy-bound and cannot be reused.

### Procurement Changes

A modification to a contract (scope change, period of performance extension, funding adjustment) moves through an approval workflow. EP binds each approval step to the specific modification details, ensuring that what was approved is what executes.

---

## EP Solution Mapping

| Government Problem | EP Mechanism | Code Reference |
|---|---|---|
| Who authorized this action? | Actor identity derived from auth, never request body (Invariant 2) | `lib/protocol-write.js` (`resolveAuthority()`) |
| Was their authority valid? | Authority resolution from trusted registry, fail-closed on unknown issuers (Invariants 3, 4) | `lib/handshake/present.js`, `lib/handshake/invariants.js` (`checkIssuerTrusted()`) |
| Was the action bound to the approval? | Canonical binding hash over all action context fields (Invariant 10) | `lib/handshake/create.js`, `lib/handshake/invariants.js` |
| Was the right policy applied? | Policy hash pinned at initiation, re-verified at execution. Mismatch = rejection (Invariant 7) | `lib/handshake/policy.js`, `lib/handshake/verify.js` |
| Could this approval be reused? | One-time consumption with database-level enforcement (Invariant 8) | `lib/handshake/verify.js`, `lib/handshake/consume.js` |
| Could this approval be replayed? | Nonce + expiry + consumption triple (Threat Model entry 4) | `lib/handshake/bind.js`, `lib/handshake/invariants.js` |
| Is there a durable audit trail? | Append-only `protocol_events` and `handshake_events` with database triggers preventing UPDATE/DELETE (Invariant 9) | `lib/protocol-write.js`, `lib/handshake/events.js` |
| Can the write path be bypassed? | Three-layer write discipline: runtime proxy, CI import guard, CI pattern guard (Invariant 1) | `lib/write-guard.js`, `scripts/check-write-discipline.js`, `scripts/check-protocol-discipline.js` |

---

## Pilot Scope Recommendation

A government pilot should target a single, well-defined workflow with the following characteristics:

1. **High-consequence writes**: Payment instruction changes, beneficiary modifications, or procurement approvals where unauthorized changes have direct financial impact.
2. **Existing delegation patterns**: Workflows where staff regularly act on behalf of others, making delegation scope enforcement immediately valuable.
3. **Existing audit requirements**: Workflows already subject to IG or GAO review, where EP's event log directly satisfies existing reporting obligations.

Recommended starting point: **vendor banking detail changes** in a payment system. The workflow is narrow (single action type), high-consequence (direct fraud vector), delegation-heavy (staff act on behalf of contracting officers), and already audited.

Pilot deliverables:
- EP handshake integration for the change workflow (initiate, present, verify, consume)
- Policy definition for the change type (required assurance level, delegation scope constraints)
- Authority registry population for the relevant organizational hierarchy
- Event export pipeline for existing audit tools
- Conformance test execution (47 invariant tests, 24 adversarial tests)

---

## Why EP Is Differentiated

Most government security infrastructure focuses on identity: who is this person, what credentials do they hold, what role are they assigned. EP does not compete with identity systems. It addresses the gap between identity and action:

- **Identity systems** answer: "Is this person who they claim to be?"
- **Access control systems** answer: "Is this person allowed to access this resource?"
- **EP** answers: "Is this specific action, by this specific actor, under this specific policy, with these specific parameters, authorized for exactly one execution?"

This distinction matters because government fraud rarely involves unauthorized access. It involves authorized users performing unauthorized actions within their access scope. EP enforces constraints at the action level, not the session level, closing the gap that identity and access control systems leave open.
