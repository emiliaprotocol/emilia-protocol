# EP Quick Start: Protect Your First Workflow in 30 Minutes

> This guide walks through the core EP trust loop: register a policy,
> initiate a handshake, present credentials, verify, and gate an action.
> By the end, you will have a working trust-protected workflow.

## Prerequisites

- An EP API key (starts with `ep_live_` or `ep_test_`)
- Two registered entities (your agent and a counterparty)
- `curl` or any HTTP client

All examples use `https://emiliaprotocol.ai` as the base URL. Replace with
`http://localhost:3000` for local development.

Set your API key once:

```bash
export EP_KEY="ep_live_your_key_here"
export EP_BASE="https://emiliaprotocol.ai"
```

---

## Step 1: Browse Available Policies

Before initiating a handshake, understand what trust policies are available.
Policies define the thresholds for trust decisions.

```bash
curl "$EP_BASE/api/policies"
```

**Response:**

```json
{
  "protocol_version": "EP/1.1",
  "policies": [
    {
      "name": "standard",
      "description": "Normal transactions. Balanced requirements for confidence and evidence.",
      "min_score": 40,
      "min_confidence": "provisional",
      "min_receipts": 3,
      "max_dispute_rate": 5,
      "family": "commerce"
    },
    {
      "name": "strict",
      "description": "High-value transactions. Requires established confidence, low dispute rate, minimum receipt history.",
      "min_score": 70,
      "min_confidence": "confident",
      "min_receipts": 10,
      "max_dispute_rate": 2,
      "family": "commerce"
    }
  ],
  "families": ["commerce", "software", "marketplace", "custom"]
}
```

Pick a policy that matches your risk level. For this guide, we use `"standard"`.

---

## Step 2: Initiate a Handshake

A handshake is a structured identity exchange between two parties before a
trust decision is made. You declare who is involved, which policy governs,
and what mode of exchange to use.

```bash
curl -X POST "$EP_BASE/api/handshake" \
  -H "Authorization: Bearer $EP_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "mutual",
    "policy_id": "standard",
    "parties": [
      { "entity_ref": "your-agent-entity-id", "role": "initiator" },
      { "entity_ref": "counterparty-entity-id", "role": "responder" }
    ]
  }'
```

**Response (201 Created):**

```json
{
  "handshake_id": "hs_abc123def456",
  "status": "pending",
  "mode": "mutual",
  "policy_id": "standard",
  "parties": [
    { "entity_ref": "your-agent-entity-id", "role": "initiator" },
    { "entity_ref": "counterparty-entity-id", "role": "responder" }
  ],
  "created_at": "2026-03-20T10:00:00Z"
}
```

Save the `handshake_id`. You will use it in every subsequent step.

```bash
export HS_ID="hs_abc123def456"
```

**Error cases:**
- `400` -- Missing or invalid fields (e.g., fewer than 2 parties, missing policy_id)
- `401` -- Missing or invalid API key
- `403` -- Initiator `entity_ref` does not match the authenticated entity

---

## Step 3: Present Credentials

Each party presents identity claims for evaluation. The initiator presents first.

```bash
curl -X POST "$EP_BASE/api/handshake/$HS_ID/present" \
  -H "Authorization: Bearer $EP_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "party_role": "initiator",
    "presentation_type": "ep_trust_profile",
    "claims": {
      "entity_id": "your-agent-entity-id",
      "entity_type": "agent",
      "display_name": "My Agent"
    },
    "disclosure_mode": "full"
  }'
```

**Response (201 Created):**

```json
{
  "handshake_id": "hs_abc123def456",
  "presentation_id": "pres_789xyz",
  "party_role": "initiator",
  "presentation_type": "ep_trust_profile",
  "status": "received",
  "created_at": "2026-03-20T10:01:00Z"
}
```

The responder does the same with `"party_role": "responder"`.

**Supported presentation types:**
- `ep_trust_profile` -- Present your EP trust profile
- `verifiable_credential` -- Present a W3C Verifiable Credential
- `attestation` -- Present a third-party attestation

**Disclosure modes:**
- `full` -- All claims visible to the counterparty
- `selective` -- Only specified claims disclosed
- `zk` -- Zero-knowledge proof of claims

**Error cases:**
- `400` -- Missing required fields (`party_role`, `presentation_type`, `claims`)
- `401` -- Missing or invalid API key
- `404` -- Handshake not found

---

## Step 4: Verify the Handshake

Once all parties have presented, evaluate the handshake against the governing
policy. This is the trust decision.

```bash
curl -X POST "$EP_BASE/api/handshake/$HS_ID/verify" \
  -H "Authorization: Bearer $EP_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Response (200 OK) -- Accepted:**

```json
{
  "handshake_id": "hs_abc123def456",
  "result": "accepted",
  "reason_codes": [],
  "evaluated_at": "2026-03-20T10:02:00Z"
}
```

**Response (200 OK) -- Rejected:**

```json
{
  "handshake_id": "hs_abc123def456",
  "result": "rejected",
  "reason_codes": [
    "insufficient_confidence",
    "dispute_rate_exceeds_policy"
  ],
  "evaluated_at": "2026-03-20T10:02:00Z"
}
```

**Response (200 OK) -- Partial (awaiting more presentations):**

```json
{
  "handshake_id": "hs_abc123def456",
  "result": "partial",
  "reason_codes": ["awaiting_responder_presentation"],
  "evaluated_at": "2026-03-20T10:02:00Z"
}
```

**Error cases:**
- `401` -- Missing or invalid API key
- `404` -- Handshake not found

---

## Step 5: Gate the Action

After a successful handshake, use the trust gate to authorize a specific
action. The gate evaluates the entity, checks the handshake binding, and
issues a commit (a signed pre-authorization token).

```bash
curl -X POST "$EP_BASE/api/trust/gate" \
  -H "Authorization: Bearer $EP_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "counterparty-entity-id",
    "action": "transact",
    "policy": "standard",
    "handshake_id": "hs_abc123def456",
    "value_usd": 500
  }'
```

**Response (200 OK) -- Allowed:**

```json
{
  "decision": "allow",
  "entity_id": "counterparty-entity-id",
  "policy_used": "standard",
  "confidence": "emerging",
  "reasons": [],
  "warnings": [],
  "appeal_path": "https://emiliaprotocol.ai/appeal",
  "extensions": {
    "action": "transact",
    "handshake_verified": true,
    "commit_ref": "cmt_abc123"
  }
}
```

The `commit_ref` is your proof that EP authorized this action. Store it.

**Response (200 OK) -- Denied:**

```json
{
  "decision": "deny",
  "entity_id": "counterparty-entity-id",
  "policy_used": "standard",
  "confidence": "insufficient",
  "reasons": [
    "Insufficient evidence: 8.0 (required: 15)",
    "Dispute rate 12% exceeds policy max 5%"
  ],
  "warnings": [],
  "appeal_path": "https://emiliaprotocol.ai/appeal",
  "extensions": {
    "action": "transact",
    "_note": "Trust must never be more powerful than appeal."
  }
}
```

Every denial includes an `appeal_path`. This is a constitutional guarantee:
trust must never be more powerful than appeal.

**Error cases:**
- `400` -- Missing `entity_id` or `action`
- `401` -- Missing or invalid API key

---

## The Complete Flow

```
  You                          EP                      Counterparty
   |                           |                           |
   |-- POST /api/handshake --->|                           |
   |<-- 201 handshake_id ------|                           |
   |                           |                           |
   |-- POST /present --------->|                           |
   |<-- 201 received ----------|                           |
   |                           |                           |
   |                           |<-- POST /present ---------|
   |                           |-- 201 received ---------->|
   |                           |                           |
   |-- POST /verify ---------->|                           |
   |<-- 200 accepted ----------|                           |
   |                           |                           |
   |-- POST /trust/gate ------>|                           |
   |<-- 200 allow + commit ----|                           |
   |                           |                           |
   |========= ACTION PROCEEDS (with commit_ref) ==========|
```

---

## What Comes Next

- **Submit a receipt** after the action completes: `POST /api/receipts/submit`
- **Revoke a handshake** if something goes wrong: `POST /api/handshake/{id}/revoke`
- **File a dispute** if the counterparty misbehaves: `POST /api/disputes/file`
- **Check trust profile** of any entity: `GET /api/trust/profile/{entityId}`

---

## Quick Reference

| Step | Endpoint | Method | Auth |
|------|----------|--------|------|
| Browse policies | `/api/policies` | GET | No |
| Initiate handshake | `/api/handshake` | POST | Yes |
| Present credentials | `/api/handshake/{id}/present` | POST | Yes |
| Verify handshake | `/api/handshake/{id}/verify` | POST | Yes |
| Gate action | `/api/trust/gate` | POST | Yes |
| Get trust profile | `/api/trust/profile/{entityId}` | GET | No |
