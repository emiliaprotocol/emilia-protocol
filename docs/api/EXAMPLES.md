# EMILIA Protocol -- Worked API Examples

Three complete flows showing the EP trust lifecycle from initiation to outcome. Each example shows request payloads, response bodies, and the event trail produced.

All requests include `Authorization: Bearer ep_live_test_...` unless marked public.

---

## Example 1: Basic Handshake Flow

**Scenario**: Entity `acme-tools` wants to install a tool. The tool's trust must be evaluated before installation proceeds.

### Step 1: Discover Policy

```
GET /api/policies
```

Response (200):

```json
{
  "protocol_version": "EP/1.1",
  "policies": [
    {
      "name": "standard",
      "description": "Normal transactions. Balanced requirements for confidence and evidence.",
      "min_score": 40,
      "min_confidence": "emerging",
      "min_receipts": 3,
      "max_dispute_rate": 0.05,
      "software_requirements": null,
      "family": "commerce"
    }
  ],
  "families": ["commerce", "software", "marketplace", "custom"]
}
```

### Step 2: Initiate Handshake

```
POST /api/handshake
```

```json
{
  "mode": "basic",
  "policy_id": "standard",
  "parties": [
    { "role": "initiator", "entity_ref": "acme-tools" },
    { "role": "verifier", "entity_ref": "ep-system" }
  ],
  "action_type": "install",
  "resource_ref": "npm:acme-widget@1.2.0"
}
```

Response (201):

```json
{
  "handshake_id": "hs_a1b2c3d4",
  "status": "initiated",
  "mode": "basic",
  "policy_id": "standard",
  "policy_hash": "sha256:e3b0c44298fc...",
  "action_type": "install",
  "resource_ref": "npm:acme-widget@1.2.0",
  "binding": {
    "nonce": "a8f2e1c9...",
    "expires_at": "2025-01-01T00:30:00.000Z",
    "binding_hash": "sha256:9f86d081884c..."
  },
  "parties": [
    { "role": "initiator", "entity_ref": "acme-tools", "verified_status": "pending" },
    { "role": "verifier", "entity_ref": "ep-system", "verified_status": "pending" }
  ]
}
```

**Event trail**: `handshake_events` row with `event_type: "initiated"`.

### Step 3: Add Presentation

```
POST /api/handshake/hs_a1b2c3d4/present
```

```json
{
  "party_role": "initiator",
  "presentation_type": "self_asserted",
  "claims": {
    "entity_id": "acme-tools",
    "action": "install",
    "resource": "npm:acme-widget@1.2.0"
  },
  "disclosure_mode": "full"
}
```

Response (201):

```json
{
  "presentation_id": "pres_x1y2z3",
  "handshake_id": "hs_a1b2c3d4",
  "party_role": "initiator",
  "presentation_type": "self_asserted",
  "presentation_hash": "sha256:7c222fb2927d...",
  "issuer_status": "self_asserted",
  "verified": true,
  "normalized_claims": {
    "entity_id": "acme-tools",
    "action": "install",
    "resource": "npm:acme-widget@1.2.0"
  }
}
```

**Event trail**: `handshake_events` row with `event_type: "presentation_added"`.

### Step 4: Verify Handshake

```
POST /api/handshake/hs_a1b2c3d4/verify
```

```json
{}
```

Response (200):

```json
{
  "handshake_id": "hs_a1b2c3d4",
  "outcome": "accepted",
  "reason_codes": [],
  "binding_consumed": true,
  "consumed_at": "2025-01-01T00:01:30.000Z",
  "consumed_by": "acme-tools",
  "consumed_for": "handshake_verified:hs_a1b2c3d4"
}
```

**Event trail**: `handshake_events` row with `event_type: "verified"`. `protocol_events` row with `command_type: "verify_handshake"`. Binding `consumed_at` set.

### Step 5: Trust Gate

```
POST /api/trust/gate
```

```json
{
  "entity_id": "acme-tools",
  "action": "install",
  "policy": "standard",
  "handshake_id": "hs_a1b2c3d4",
  "resource_ref": "npm:acme-widget@1.2.0"
}
```

Response (200):

```json
{
  "decision": "allow",
  "entity_id": "acme-tools",
  "policy_used": "standard",
  "confidence": "confident",
  "reasons": [],
  "warnings": [],
  "appeal_path": "https://emiliaprotocol.ai/appeal",
  "profile_summary": {
    "confidence": "confident",
    "evidence_level": 45.2,
    "dispute_rate": 0
  },
  "action": "install",
  "display_name": "Acme Tools",
  "handshake_verified": true,
  "commit_ref": "ep_commit_f4e5d6c7"
}
```

**Event trail**: `protocol_events` row with `command_type: "issue_commit"`. `handshake_bindings` row updated with `consumed_for: "commit:ep_commit_f4e5d6c7"`.

---

## Example 2: Handshake with Accountable Signoff

**Scenario**: Entity `vendor-corp` connects to `buyer-inc` for a $5,000 transaction. Mutual handshake with commit lifecycle through to receipt binding and dispute.

### Step 1: Initiate Mutual Handshake

```
POST /api/handshake
```

```json
{
  "mode": "mutual",
  "policy_id": "standard",
  "parties": [
    { "role": "initiator", "entity_ref": "vendor-corp" },
    { "role": "responder", "entity_ref": "buyer-inc" }
  ],
  "action_type": "transact",
  "resource_ref": "order:PO-2025-001"
}
```

Response (201): Handshake record with `handshake_id: "hs_m1m2m3m4"`, status `initiated`.

**Event trail**: `handshake_events` -- `initiated`.

### Step 2: Initiator Presents

```
POST /api/handshake/hs_m1m2m3m4/present
```

```json
{
  "party_role": "initiator",
  "presentation_type": "verifiable_credential",
  "claims": {
    "entity_id": "vendor-corp",
    "business_registration": "US-DE-12345",
    "verified_since": "2023-06-01"
  },
  "issuer_ref": "authority_key_us_commerce",
  "disclosure_mode": "full"
}
```

Response (201): Presentation with `issuer_status: "authority_valid"`, `verified: true`.

**Event trail**: `handshake_events` -- `presentation_added`.

### Step 3: Responder Presents

(Authenticated as `buyer-inc`)

```
POST /api/handshake/hs_m1m2m3m4/present
```

```json
{
  "party_role": "responder",
  "presentation_type": "verifiable_credential",
  "claims": {
    "entity_id": "buyer-inc",
    "purchasing_authority": true,
    "department": "procurement"
  },
  "issuer_ref": "authority_key_buyer_org",
  "disclosure_mode": "full"
}
```

Response (201): Presentation with `issuer_status: "authority_valid"`, `verified: true`.

**Event trail**: `handshake_events` -- `presentation_added`.

### Step 4: Verify Handshake

```
POST /api/handshake/hs_m1m2m3m4/verify
```

Response (200): `outcome: "accepted"`, binding consumed.

**Event trail**: `handshake_events` -- `verified`. `protocol_events` -- `verify_handshake`.

### Step 5: Trust Gate with Value

```
POST /api/trust/gate
```

```json
{
  "entity_id": "vendor-corp",
  "action": "transact",
  "policy": "standard",
  "value_usd": 5000,
  "handshake_id": "hs_m1m2m3m4",
  "resource_ref": "order:PO-2025-001"
}
```

Response (200):

```json
{
  "decision": "allow",
  "entity_id": "vendor-corp",
  "policy_used": "standard",
  "confidence": "confident",
  "reasons": [],
  "warnings": [],
  "profile_summary": { "confidence": "confident", "evidence_level": 52, "dispute_rate": 0 },
  "action": "transact",
  "handshake_verified": true,
  "commit_ref": "ep_commit_t1t2t3t4",
  "value_threshold": { "value_usd": 5000, "escalated_to_strict": false }
}
```

**Event trail**: `protocol_events` -- `issue_commit`.

### Step 6: Bind Receipt to Commit (Fulfillment)

After the transaction completes, the vendor binds the receipt:

```
POST /api/commit/ep_commit_t1t2t3t4/receipt
```

```json
{
  "receipt_id": "rcpt_a1b2c3d4"
}
```

Response (200):

```json
{
  "commit_id": "ep_commit_t1t2t3t4",
  "status": "fulfilled",
  "receipt_id": "rcpt_a1b2c3d4"
}
```

**Event trail**: Commit status transitions from `active` to `fulfilled`.

### Step 7: Dispute the Outcome (Signoff Challenge)

If the buyer disputes the transaction:

```
POST /api/commit/ep_commit_t1t2t3t4/dispute
```

```json
{
  "reason": "context_mismatch",
  "description": "Delivered quantity did not match purchase order",
  "evidence": {
    "expected_quantity": 100,
    "received_quantity": 75
  }
}
```

Response (201):

```json
{
  "dispute_id": "dsp_x1y2z3",
  "receipt_id": "rcpt_a1b2c3d4",
  "status": "filed",
  "commit_id": "ep_commit_t1t2t3t4",
  "_message": "Dispute filed from commit. The receipt submitter has 7 days to respond."
}
```

**Event trail**: `protocol_events` -- `file_dispute`.

---

## Example 3: Delegated Authority Handshake

**Scenario**: Human principal `alice` delegates to agent `alice-bot` to perform installations on her behalf. The agent then executes a handshake and gate flow under delegation.

### Step 1: Create Delegation

(Authenticated as `alice`)

```
POST /api/delegations/create
```

```json
{
  "agent_entity_id": "alice-bot",
  "scope": ["install", "connect"],
  "max_value_usd": 1000,
  "expires_at": "2025-01-02T00:00:00.000Z"
}
```

Response (201):

```json
{
  "delegation_id": "ep_dlg_a1b2c3d4e5f6",
  "principal_id": "alice",
  "agent_entity_id": "alice-bot",
  "scope": ["install", "connect"],
  "max_value_usd": 1000,
  "expires_at": "2025-01-02T00:00:00.000Z",
  "constraints": null,
  "status": "active",
  "created_at": "2025-01-01T00:00:00.000Z"
}
```

### Step 2: Initiate Delegated Handshake

(Authenticated as `alice-bot`)

```
POST /api/handshake
```

```json
{
  "mode": "delegated",
  "policy_id": "standard",
  "parties": [
    { "role": "initiator", "entity_ref": "alice" },
    { "role": "delegate", "entity_ref": "alice-bot" }
  ],
  "action_type": "install",
  "resource_ref": "npm:some-package@2.0.0"
}
```

Response (201): Handshake with `handshake_id: "hs_d1d2d3d4"`, mode `delegated`.

**Event trail**: `handshake_events` -- `initiated`.

### Step 3: Delegate Presents with Delegation Proof

(Authenticated as `alice-bot`)

```
POST /api/handshake/hs_d1d2d3d4/present
```

```json
{
  "party_role": "delegate",
  "presentation_type": "delegation_proof",
  "claims": {
    "delegation_id": "ep_dlg_a1b2c3d4e5f6",
    "principal_id": "alice",
    "agent_entity_id": "alice-bot",
    "scope": ["install", "connect"],
    "action": "install"
  },
  "disclosure_mode": "full"
}
```

Response (201): Presentation with delegation claims verified.

**Event trail**: `handshake_events` -- `presentation_added`.

### Step 4: Verify Delegated Handshake

```
POST /api/handshake/hs_d1d2d3d4/verify
```

Response (200): `outcome: "accepted"`. Delegation scope and expiry validated as part of the verification pipeline (step 9 in HANDSHAKE.md).

**Event trail**: `handshake_events` -- `verified`. `protocol_events` -- `verify_handshake`.

### Step 5: Trust Gate with Delegation

```
POST /api/trust/gate
```

```json
{
  "entity_id": "alice",
  "action": "install",
  "policy": "standard",
  "delegation_id": "ep_dlg_a1b2c3d4e5f6",
  "handshake_id": "hs_d1d2d3d4",
  "resource_ref": "npm:some-package@2.0.0"
}
```

Response (200):

```json
{
  "decision": "allow",
  "entity_id": "alice",
  "policy_used": "standard",
  "confidence": "confident",
  "reasons": [],
  "warnings": [],
  "profile_summary": { "confidence": "confident", "evidence_level": 38, "dispute_rate": 0 },
  "action": "install",
  "delegation_verified": true,
  "handshake_verified": true,
  "commit_ref": "ep_commit_d5d6d7d8"
}
```

**Event trail**: `protocol_events` -- `issue_commit`. Delegation verified as valid with `install` in scope.

### Step 6: Issue Commit Under Delegation

(Authenticated as `alice-bot`)

```
POST /api/commit/issue
```

```json
{
  "entity_id": "alice",
  "action_type": "install",
  "delegation_id": "ep_dlg_a1b2c3d4e5f6",
  "principal_id": "alice",
  "scope": {
    "resource_ref": "npm:some-package@2.0.0"
  },
  "context": {
    "delegated": true,
    "agent": "alice-bot"
  }
}
```

Response (201):

```json
{
  "decision": "allow",
  "commit": {
    "commit_id": "ep_commit_e9f0a1b2",
    "entity_id": "alice",
    "action_type": "install",
    "decision": "allow",
    "status": "active",
    "delegation_id": "ep_dlg_a1b2c3d4e5f6"
  }
}
```

**Event trail**: `protocol_events` -- `issue_commit`. The commit records both `entity_id: "alice"` (principal) and `delegation_id` (proof of authority chain).

When a receipt is later submitted for this action, the attribution chain will write:
- Agent `alice-bot`: weight 1.0 (primary attribution)
- Principal `alice`: weight 0.15 (delegation judgment signal to `principal_delegation_signals`)
