# EP AI Agent Vertical Reference

**Status: Canonical**
**Last updated: March 2026**
**Owner: Core team**

This document maps the 5 core EP handshake endpoints to AI agent high-value transaction authorization. The same endpoints serve every vertical -- only the policy content and party configuration change.

---

## Use Case: Agent-Initiated High-Value Transaction

An AI agent -- operating within an orchestration framework (LangChain, CrewAI, AutoGen, custom) -- needs to execute a high-value action: a wire transfer, a procurement approval, a configuration change, a refund above threshold. The agent must prove its authority, bind the action to specific parameters, and consume the authorization exactly once before the action executes.

---

## The 5 Core Endpoints

| # | Endpoint | Purpose |
|---|---|---|
| 1 | `POST /api/handshake` | Initiate a handshake binding the agent's intended action |
| 2 | `GET /api/handshake/{id}` | Query handshake status (used by orchestrator for async workflows) |
| 3 | `POST /api/handshake/{id}/present` | Submit agent authority credentials (delegation proof) |
| 4 | `POST /api/handshake/{id}/verify` | Verify all invariants and consume the binding |
| 5 | `POST /api/handshake/{id}/revoke` | Revoke (human override, safety trigger, scope violation detected) |

---

## Policy Example

```json
{
  "policy_id": "ai-agent-high-value-action-v1",
  "policy_version": 1,
  "rules": {
    "required_assurance_level": "substantial",
    "required_roles": {
      "initiator": {
        "min_assurance": "substantial",
        "required_claims": [
          "agent_id",
          "principal_entity_ref",
          "delegation_scope",
          "max_transaction_value"
        ]
      }
    },
    "action_constraints": {
      "action_type": "high_value_transaction",
      "max_ttl_seconds": 120,
      "delegation_allowed": true,
      "delegation_scope": [
        "ai-agent-high-value-action-v1",
        "ai-agent-refund-v1",
        "ai-agent-procurement-v1"
      ]
    }
  }
}
```

**Key policy properties:**
- `required_claims` include `principal_entity_ref` -- the agent must declare which human principal delegated authority. This creates the Principal-to-Agent attribution chain.
- `max_transaction_value` is a required claim -- the agent must declare its spending limit. The orchestrator or policy engine validates this against the action parameters.
- `max_ttl_seconds: 120` -- 2-minute window. Agent actions should be immediate; long-lived approvals are a risk.
- `delegation_scope` lists the specific policies the agent may act under. An agent delegated for refunds cannot use that delegation for procurement.

---

## Handshake Flow

### Step 1: Initiate (Agent Orchestrator)

The agent's orchestration layer calls `POST /api/handshake` before executing the high-value action.

```
POST /api/handshake
{
  "mode": "delegated",
  "policy_id": "ai-agent-high-value-action-v1",
  "action_type": "high_value_transaction",
  "resource_ref": "account:CUST-88291:wire-transfer",
  "parties": [
    {
      "party_role": "initiator",
      "entity_ref": "principal:ops-manager@company.com",
      "assurance_level": "substantial"
    },
    {
      "party_role": "delegate",
      "entity_ref": "agent:treasury-bot-7a3f",
      "assurance_level": "substantial",
      "delegation_chain": {
        "delegator": "principal:ops-manager@company.com",
        "scope": ["ai-agent-high-value-action-v1"],
        "expires_at": "2026-03-20T18:00:00Z",
        "chain": [
          {
            "from": "principal:ops-manager@company.com",
            "to": "agent:treasury-bot-7a3f",
            "granted_at": "2026-03-20T08:00:00Z"
          }
        ]
      }
    }
  ],
  "payload": {
    "transaction_type": "wire_transfer",
    "amount": 75000,
    "currency": "USD",
    "destination_hash": "SHA256-OF-BENEFICIARY-DETAILS",
    "purpose_code": "vendor_payment",
    "reference": "INV-2026-44102"
  }
}
```

**What EP does:**
- Verifies the authenticated caller matches the **delegate** `entity_ref` (the agent is the one making the call). Mismatch = `DELEGATE_BINDING_VIOLATION`.
- Validates the delegation chain: scope includes `ai-agent-high-value-action-v1`, delegation has not expired.
- Resolves policy, computes binding hash over all fields including the $75,000 amount and destination hash.
- Sets 120-second TTL.
- Emits `handshake_initiated` event with full delegation chain recorded.

**Why `delegated` mode:** The agent acts on behalf of a human principal. The `delegated` mode enforces that the agent's delegation is current, scoped, and that the delegation chain is recorded in the handshake for attribution.

### Step 2: Present (Agent's Delegation Proof)

The agent presents its authority credential -- the delegation proof from its principal.

```
POST /api/handshake/{id}/present
{
  "party_role": "delegate",
  "presentation_type": "delegation_credential",
  "issuer_ref": "company-agent-authority-2026",
  "presentation_hash": "SHA256-OF-DELEGATION-PROOF",
  "normalized_claims": {
    "agent_id": "treasury-bot-7a3f",
    "principal_entity_ref": "principal:ops-manager@company.com",
    "delegation_scope": ["ai-agent-high-value-action-v1"],
    "max_transaction_value": 100000,
    "agent_framework": "custom-orchestrator-v3",
    "model_version": "claude-opus-4-20250514"
  }
}
```

**What EP does:**
- Actor-party binding: authenticated agent must match delegate `entity_ref`. Mismatch = `ROLE_SPOOFING`.
- Issuer resolution: `company-agent-authority-2026` looked up in `authorities` table. If the authority has been revoked (e.g., the agent's deployment was decommissioned), the handshake cannot proceed.
- Delegation scope check (`checkDelegation()`): the agent's declared scope must include the handshake policy. Scope mismatch = `delegation_out_of_scope`.
- Delegation expiry check: if `expires_at` has passed, `delegation_expired`.
- Claims stored: `principal_entity_ref` creates the attribution link from agent action to human principal.

### Step 3: Verify and Consume

```
POST /api/handshake/{id}/verify
{
  "action_hash": "EXPECTED-BINDING-HASH",
  "policy_hash": "EXPECTED-POLICY-HASH"
}
```

**Verification pipeline:**
1. Consumption gate: reject if already consumed.
2. State gate: must be `pending_verification`.
3. Hash checks: action hash and policy hash must match.
4. Binding checks: 120-second TTL, nonce, payload hash (including $75,000 amount).
5. Delegation checks: scope valid, delegation not expired.
6. Issuer checks: agent authority must be valid.
7. Claims checks: `agent_id`, `principal_entity_ref`, `delegation_scope`, `max_transaction_value` all present.
8. Outcome: zero reason codes = `accepted`.

**On acceptance:** Binding consumed. The orchestrator executes the wire transfer with the exact parameters from the binding. `handshake_verified` event emitted.

**On rejection:** The wire transfer does not execute. The orchestrator receives explicit reason codes and can surface them to the human principal or escalate.

### Agent-Specific Failure Modes

| Failure | Reason Code | What Happened |
|---|---|---|
| Agent tries to transfer $200,000 | `payload_hash_mismatch` | Amount differs from what was bound |
| Agent's delegation expired | `delegation_expired` | Principal's delegation grant has lapsed |
| Agent uses refund delegation for wire transfer | `delegation_out_of_scope` | Policy not in delegation scope |
| Agent authority revoked (decommissioned) | `authority_revoked` | Agent's deployment authority was revoked |
| Agent replays a previous approval | `already_consumed` | Binding was already consumed |
| Agent modifies destination after approval | `payload_hash_mismatch` | Destination hash changed |
| Policy relaxed between initiation and verify | `policy_hash_mismatch` | Policy rules changed, hash differs |

---

## Consumption Semantics

- **One-time**: Each agent action requires its own handshake. An approval for one wire transfer cannot authorize a second.
- **Parameter-locked**: The binding hash includes the amount, destination, purpose code, and reference. Any change requires a new handshake.
- **Time-bounded**: 120-second TTL. The agent must complete the handshake lifecycle within 2 minutes.
- **Delegation-scoped**: The agent can only act under policies listed in its delegation scope. Expanding scope requires a new delegation from the principal.

---

## Evidence Trail

| Record | Contains | Governance Relevance |
|---|---|---|
| Handshake events | Full lifecycle: initiated, presentation, verified/rejected, consumed | EU AI Act Art. 12 record-keeping for high-risk AI systems |
| Delegation chain | Principal identity, delegation scope, expiry, grant timestamp | NIST AI RMF: human accountability for delegated agent actions |
| Binding material | Action type, amount, destination, policy, nonce, expiry | SOX: authorization bound to specific transaction parameters |
| Agent presentation | Agent ID, principal ref, delegation scope, max value, model version | Audit: which agent, under whose authority, with what constraints |
| Consumption record | Consumed_at, consumed_by, consumed_for | Proof of one-time execution |

### What This Proves to an Auditor

1. **Principal accountability** -- which human delegated authority to this agent, with what scope and expiry.
2. **Agent identity** -- the authenticated agent identity, not a self-declared identifier.
3. **Action binding** -- the exact transaction parameters ($75,000, specific destination, specific purpose) bound by hash.
4. **Scope compliance** -- the agent acted within its delegated scope (policy list match).
5. **Temporal compliance** -- the action was authorized and consumed within the 120-second window.
6. **Non-reuse** -- the approval was consumed exactly once.
7. **Model attribution** -- the `model_version` claim records which model version produced the decision (useful for incident investigation and model-specific audits).

---

## Agent Integration Pattern

```
Agent Decision Loop:
  1. Agent determines action is needed (model inference)
  2. Orchestrator calls POST /api/handshake (bind action)
  3. Orchestrator calls POST /api/handshake/{id}/present (prove authority)
  4. Orchestrator calls POST /api/handshake/{id}/verify (authorize + consume)
  5. If accepted: execute action with bound parameters
  6. If rejected: surface reason codes, escalate to principal
```

The agent does not interact with EP directly. The orchestration layer wraps EP calls around the action execution. From the agent's perspective, the handshake is invisible -- it is infrastructure, like TLS.

---

## Integration Checklist

- [ ] Register agent authority in the `authorities` table (one per agent deployment)
- [ ] Define high-value action policy with agent-specific claims and delegation scope
- [ ] Configure principal delegation grants (scope, expiry) in the delegation system
- [ ] Add handshake initiation to agent orchestration layer (pre-action)
- [ ] Add presentation submission with agent delegation proof
- [ ] Add verification call as authorization gate before action execution
- [ ] Implement rejection handling: surface reason codes, escalation to principal
- [ ] Configure event export for AI governance dashboard
- [ ] Run conformance tests (47 invariant tests, 24 adversarial tests)

**Estimated integration time**: 3--5 days for an agent orchestration layer with existing action execution hooks.

---

*EMILIA Protocol -- emiliaprotocol.ai -- github.com/emiliaprotocol/emilia-protocol -- Apache 2.0*
