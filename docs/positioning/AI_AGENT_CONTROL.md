# EP for AI Agent Control

## Executive Summary

As AI agents move from suggestion to execution -- initiating payments, modifying accounts, approving procurement, configuring systems -- trust cannot remain informal. Current agent governance focuses on model quality (alignment, guardrails, prompt engineering) but neglects action control: ensuring that an agent's actions are authorized by specific policy, bound to specific parameters, consumed exactly once, and durably logged. EMILIA Protocol (EP) provides the trust-control layer between AI intent and operational execution.

EP does not evaluate whether an agent's decision is correct. It enforces that the agent's action is authorized, scoped, bound, and auditable -- regardless of the model, framework, or orchestration layer that produced the decision.

---

## The Governance Gap: Action Control, Not Just Model Quality

Current AI governance addresses:

- **Model safety**: Alignment techniques, RLHF, constitutional AI, guardrails
- **Prompt security**: Injection prevention, output filtering, content moderation
- **Access control**: API keys, rate limits, role-based permissions

What current governance does not address:

- **Action-level authorization**: Is this specific action (not just this API call) authorized under the current policy?
- **Parameter binding**: Is the action executing with the exact parameters that were approved, or have they been modified?
- **One-time execution**: Can this approval be reused to authorize additional actions?
- **Authority chain**: Is the agent acting within its delegated scope, and is that delegation still valid?
- **Policy pinning**: Is the policy governing this action the same policy that was in effect when authorization was granted?
- **Audit completeness**: Can every action be reconstructed from its authorization chain to its execution, with no gaps?

This is the governance gap. An agent with valid API credentials and appropriate role-based access can still execute unauthorized actions if there is no mechanism to bind authorization to specific action parameters, enforce one-time consumption, and log the complete decision chain.

---

## Use Cases

### Account Changes

An AI agent processes a customer request to change account details (address, beneficiary, payment method). EP handshake binds the change to the specific account, specific field, specific old and new values, and specific policy governing the change type. The agent cannot modify different fields or different accounts using the same authorization.

### Procurement

An AI agent generates purchase orders, evaluates bids, or processes invoices. EP enforces that each procurement action is authorized under the applicable policy, bound to specific contract/vendor/amount parameters, and consumed once upon execution. The agent's delegation chain (which human authority delegated procurement power to this agent, with what scope and expiry) is recorded in the handshake.

### System Configuration

An AI agent modifies infrastructure or application configuration (scaling parameters, feature flags, access rules, security settings). EP captures the specific configuration change in the binding material, enforces that the agent's authority covers this configuration domain, and ensures the change approval is consumed exactly once.

### Customer Service

An AI agent performs account servicing actions on behalf of customers: issuing refunds, waiving fees, adjusting balances, escalating disputes. EP binds each action to the specific customer, specific action type, and specific parameters (amount, reason code). The agent's authority constraints (maximum refund amount, allowed action types) are enforced through policy rules evaluated at verification time.

### Approval Orchestration

An AI agent orchestrates multi-step approval workflows, collecting human approvals and executing the final action. EP ensures that each human approval is bound to the specific action context, that approvals cannot be mixed across workflows, and that the final execution consumes all required approvals exactly once.

---

## What EP Provides for Agents

### Identity Anchoring

Every agent action passes through `protocolWrite()` in `lib/protocol-write.js`, which derives actor identity from the authentication layer (Invariant 2). The agent's identity is its authenticated entity reference, not a self-declared identifier in the request payload. `resolveAuthority()` normalizes the actor, and handshake initiation enforces that the authenticated entity matches the initiator party (`INITIATOR_BINDING_VIOLATION` on mismatch).

This means an agent cannot impersonate a different agent or a human user. The identity on every trust decision is the identity that was authenticated.

### Authority Constraints

Agent authority is resolved from the authority registry (`lib/handshake/present.js`, `_handleAddPresentation()`), not from the agent's own claims. An agent presents credentials whose issuer is verified against the `authorities` table by `key_id`. Unknown, revoked, expired, or not-yet-valid issuers are tracked with explicit status codes (Invariants 3, 4, 5).

For delegated agent actions, `checkDelegation()` in `lib/handshake/bind.js` enforces scope (list of allowed policy IDs or wildcard) and expiry. An agent acting outside its delegated scope receives `delegation_out_of_scope`; an agent with an expired delegation receives `delegation_expired`.

### Policy-Bound Verification

The policy governing an agent's action is resolved by `resolvePolicy()` in `lib/handshake/policy.js` and hash-pinned at handshake initiation. At verification time, the policy is re-loaded and re-hashed. If the policy has changed (`policy_hash_mismatch`), cannot be loaded (`policy_load_failed`), or does not exist (`policy_not_found`), the handshake is rejected (Invariant 7).

This prevents an agent from benefiting from policy relaxation between authorization and execution. The policy that governs is the policy that was in effect at authorization time.

### Transaction Binding

Every agent action is bound to a canonical binding hash computed over all action context fields: action type, resource reference, policy, parties, payload, nonce, and expiry (Invariant 10). The `CANONICAL_BINDING_FIELDS` in `lib/handshake/invariants.js` define the exact field set. The hash is computed at initiation and verified at execution.

If an agent modifies any action parameter after authorization (different amount, different account, different configuration value), the binding hash will not match and the action is rejected with explicit reason codes (`action_hash_mismatch`, `payload_hash_mismatch`).

### One-Time Consumption

Each authorization artifact can be used exactly once (Invariant 8). The `_handleVerifyHandshake()` function in `lib/handshake/verify.js` enforces this through a hard gate on `consumed_at`, a conditional database update with `IS NULL` filter, and a unique constraint on the `handshake_consumptions` table.

An agent cannot reuse a single approval to authorize multiple actions. Each action requires its own handshake, its own binding, and its own consumption.

### Event Traceability

Every trust-changing action by an agent is recorded in append-only event logs before the action takes effect (Invariant 9). `appendProtocolEvent()` records command-level events; `requireHandshakeEvent()` records handshake lifecycle events. Both throw on failure, preventing the action from proceeding without a log entry.

The event record includes: actor entity reference, authority ID, command type, aggregate type and ID, payload hash, parent event hash, and idempotency key. Database triggers prevent UPDATE and DELETE on event tables.

This provides complete reconstruction capability: every agent action can be traced from intent (handshake initiation) through authorization (verification) to execution (consumption), with cryptographic binding at each step.

---

## Positioning

**EP is the trust-control layer between AI intent and operational execution.**

It answers the question that model governance cannot: not "did the agent make a good decision?" but "was the agent's action authorized, scoped, bound to the right parameters, consumed once, and logged before it took effect?"

| Governance Layer | What It Controls | What It Cannot Control |
|---|---|---|
| Model alignment | Decision quality | Action authorization |
| Prompt engineering | Input/output behavior | Parameter binding |
| API access control | Endpoint access | Transaction-level scope |
| **EP** | **Action authorization, parameter binding, one-time consumption, delegation scope, policy enforcement, audit completeness** | Decision quality, model behavior |

EP is complementary to model governance. It does not compete with alignment, guardrails, or prompt security. It addresses the enforcement gap that these mechanisms leave open when agents move from suggesting to executing.
