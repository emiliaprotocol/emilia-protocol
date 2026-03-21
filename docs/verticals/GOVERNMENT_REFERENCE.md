# EP Government Vertical Reference

**Status: Canonical**
**Last updated: March 2026**
**Owner: Core team**

This document maps the 5 core EP handshake endpoints to government payment destination change approval. The same endpoints serve every vertical -- only the policy content and party configuration change.

---

## Use Case: Payment Destination Change Approval

A benefits program operator changes the direct deposit routing for a recipient. The change must be authorized by the operator's authenticated identity, bound to the specific recipient and new bank details, verified against the governing policy, consumed exactly once, and durably logged for Inspector General and GAO audit.

---

## The 5 Core Endpoints

| # | Endpoint | Purpose |
|---|---|---|
| 1 | `POST /api/handshake` | Initiate a handshake binding the change request |
| 2 | `GET /api/handshake/{id}` | Query handshake status at any point in the lifecycle |
| 3 | `POST /api/handshake/{id}/present` | Submit operator authority credentials |
| 4 | `POST /api/handshake/{id}/verify` | Verify all invariants and consume the binding |
| 5 | `POST /api/handshake/{id}/revoke` | Revoke a handshake (supervisor override, fraud hold) |

---

## Policy Example

The policy defines what claims, assurance levels, and constraints are required for this action type. Policies are registered in EP and hash-pinned at handshake initiation.

```json
{
  "policy_id": "gov-benefits-payment-redirect-v1",
  "policy_version": 1,
  "rules": {
    "required_assurance_level": "substantial",
    "required_roles": {
      "initiator": {
        "min_assurance": "substantial",
        "required_claims": ["employee_id", "program_office", "authorization_level"]
      }
    },
    "action_constraints": {
      "action_type": "payment_destination_change",
      "max_ttl_seconds": 300,
      "delegation_allowed": true,
      "delegation_scope": ["gov-benefits-payment-redirect-v1"]
    }
  }
}
```

**Key policy properties:**
- `required_assurance_level: substantial` -- the operator must present credentials at the "substantial" level (not "low" or "medium").
- `required_claims` -- the operator must prove `employee_id`, `program_office`, and `authorization_level`. Missing claims trigger rejection.
- `max_ttl_seconds: 300` -- the binding expires after 5 minutes. Stale approvals cannot be used.
- `delegation_scope` -- if delegated, the delegate may only act under this specific policy. Cross-policy delegation is rejected.

---

## Handshake Flow

### Step 1: Initiate (Operator's System)

The benefits processing system calls `POST /api/handshake` when an operator submits a payment destination change.

```
POST /api/handshake
{
  "mode": "basic",
  "policy_id": "gov-benefits-payment-redirect-v1",
  "action_type": "payment_destination_change",
  "resource_ref": "recipient:SSN-HASH-4a7b:payment-stream:2026-Q1",
  "parties": [
    {
      "party_role": "initiator",
      "entity_ref": "operator:jsmith@agency.gov",
      "assurance_level": "substantial"
    }
  ],
  "payload": {
    "recipient_id": "SSN-HASH-4a7b",
    "old_routing": "HASH-OF-OLD-ROUTING",
    "new_routing": "HASH-OF-NEW-ROUTING",
    "change_reason": "recipient_request",
    "ticket_ref": "SR-2026-44891"
  }
}
```

**What EP does:**
- Verifies the authenticated caller matches the initiator `entity_ref` (Invariant 2). Mismatch = `INITIATOR_BINDING_VIOLATION`.
- Resolves the policy and computes `policy_hash` from `policy.rules`.
- Generates a 32-byte random nonce and computes the canonical binding hash over all `CANONICAL_BINDING_FIELDS`.
- Sets binding expiry (TTL clamped to policy `max_ttl_seconds`).
- Emits `handshake_initiated` event to `handshake_events`.
- Returns the handshake ID, binding hash, and nonce.

### Step 2: Present (Operator's Credentials)

The system submits the operator's authority credential.

```
POST /api/handshake/{id}/present
{
  "party_role": "initiator",
  "presentation_type": "piv_credential",
  "issuer_ref": "agency-ca-root-2024",
  "presentation_hash": "SHA256-OF-PIV-CERT-DATA",
  "normalized_claims": {
    "employee_id": "JS-44891",
    "program_office": "Office of Benefits Administration",
    "authorization_level": "payment_modifier",
    "clearance": "public_trust"
  }
}
```

**What EP does:**
- Verifies the authenticated caller matches the party's `entity_ref`. Mismatch = `ROLE_SPOOFING`.
- Looks up `agency-ca-root-2024` in the `authorities` table by `key_id`.
- If not found: `authority_not_found`, `verified = false`. Handshake cannot proceed.
- If revoked/expired: explicit status code, `verified = false`.
- If valid: `authority_valid`, `verified = true`. Claims are stored.
- Transitions handshake to `pending_verification`.
- Emits `presentation_added` event.

### Step 3: Verify and Consume

The system requests verification. This is the authorization gate -- either the action proceeds or it does not.

```
POST /api/handshake/{id}/verify
{
  "action_hash": "EXPECTED-BINDING-HASH",
  "policy_hash": "EXPECTED-POLICY-HASH"
}
```

**What EP does (verification pipeline):**
1. **Consumption gate**: Reject if binding already consumed.
2. **State gate**: Reject if handshake is not in `initiated` or `pending_verification`.
3. **Action hash check**: Provided hash must match stored binding hash.
4. **Policy hash check**: Policy is re-loaded and re-hashed. Must match stored hash. Mismatch = `policy_hash_mismatch`.
5. **Binding checks**: Expiry, nonce presence, payload hash match.
6. **Party presentation checks**: All required roles must have presentations.
7. **Assurance level checks**: Operator's credentials must meet `substantial`.
8. **Issuer trust checks**: Revoked/unverified presentations are flagged.
9. **Policy claims checks**: `employee_id`, `program_office`, `authorization_level` must be present.
10. **Outcome determination**: Zero reason codes = `accepted`. Any failure = `rejected` with explicit codes.

**On acceptance:**
- Binding is consumed: `consumed_at` set, `consumed_by` set to actor. Database conditional update (`consumed_at IS NULL`) ensures exactly-once.
- The benefits system receives `accepted` and executes the payment destination change.
- `handshake_verified` event emitted.

**On rejection:**
- The benefits system receives `rejected` with reason codes. The payment destination change does not execute.
- `handshake_rejected` event emitted with all reason codes.

---

## Consumption Semantics

- **One-time**: Each binding is consumed exactly once. The same approval cannot authorize a second change.
- **Database-enforced**: Conditional update with `consumed_at IS NULL` filter + unique constraint on `handshake_consumptions`.
- **Concurrent-safe**: Two simultaneous verification requests for the same binding -- only one succeeds.
- **Irrevocable**: Once consumed, the binding cannot be unconsumed. A new change requires a new handshake.

---

## Evidence Trail

Every handshake produces the following auditable records:

| Record | Table | Contains | Integrity |
|---|---|---|---|
| Handshake lifecycle events | `handshake_events` | State transitions (initiated, presentation added, verified/rejected, consumed), actor entity refs, timestamps | Append-only, DB triggers prevent UPDATE/DELETE |
| Protocol events | `protocol_events` | Command type, aggregate ID, actor authority, payload hash, parent event hash, idempotency key | Append-only, DB triggers prevent UPDATE/DELETE |
| Binding material | `handshake_bindings` | Full canonical binding fields, nonce, expiry, binding hash, consumption timestamp and actor | Immutable after creation |
| Presentation records | `handshake_presentations` | Issuer ref, claims, claims hash, authority resolution status, verification result | Immutable after creation |
| Consumption record | `handshake_consumptions` | Handshake ID, consumed_at, consumed_by, consumed_for | Unique constraint, immutable |

### What This Proves to an Auditor

1. **Who** -- the authenticated identity of the operator (derived from auth, never from request body).
2. **What** -- the exact action parameters (recipient, old routing, new routing) bound by hash.
3. **Under what authority** -- the credential presented, issuer verification result, and authority registry status.
4. **Under what policy** -- the policy ID, version, and hash-pinned rules that governed the decision.
5. **When** -- timestamps for initiation, presentation, verification, and consumption.
6. **How many times** -- exactly once (consumption record with unique constraint).
7. **What happened next** -- accepted or rejected, with explicit reason codes for rejection.

This evidence is produced automatically during normal protocol operation. No additional instrumentation, no post-hoc log collection, no manual evidence assembly.

---

## Integration Checklist

- [ ] Register operator authorities in the `authorities` table
- [ ] Define and register the payment change policy
- [ ] Add handshake initiation call to the payment change workflow
- [ ] Add presentation submission for operator credentials
- [ ] Add verification call as the authorization gate before executing the change
- [ ] Configure event export pipeline to existing audit/SIEM tools
- [ ] Run conformance tests (47 invariant tests, 24 adversarial tests)

**Estimated integration time**: 1--2 weeks for a team with access to the benefits processing system's approval workflow.

---

*EMILIA Protocol -- emiliaprotocol.ai -- github.com/emiliaprotocol/emilia-protocol -- Apache 2.0*
