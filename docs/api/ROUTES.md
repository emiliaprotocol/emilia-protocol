# EMILIA Protocol -- API Route Map

> This document covers the 17 protocol-essential endpoints classified in
> `docs/architecture/API_SURFACE_CLASSIFICATION.md`. These form the trust
> substrate that any conforming EP implementation must provide.

## Authentication

All authenticated endpoints require:

```
Authorization: Bearer ep_live_...
```

The token is hashed with SHA-256 and looked up in the `api_keys` table. Public endpoints (marked below) do not require authentication.

## Error Format

All errors use RFC 7807 Problem Details:

```json
{
  "type": "https://emiliaprotocol.ai/errors/{code}",
  "title": "Human Readable Code",
  "status": 400,
  "detail": "Specific description of what went wrong"
}
```

See `docs/api/ERRORS.md` for the full error code reference.

---

## 1. Policy

### GET /api/policies

List all available trust policies.

**Auth**: None (public)

**Parameters**: None

**Response** (200):

```json
{
  "protocol_version": "EP/1.1",
  "policies": [
    {
      "name": "strict",
      "description": "High-value transactions...",
      "min_score": 70,
      "min_confidence": "confident",
      "min_receipts": 5,
      "max_dispute_rate": 0.02,
      "software_requirements": null,
      "family": "commerce"
    }
  ],
  "families": ["commerce", "software", "marketplace", "custom"]
}
```

**Error codes**: `policy_list_failed` (500)

---

## 2. Handshake

### POST /api/handshake

Initiate a new handshake.

**Auth**: Required. Initiator `entity_ref` must match authenticated entity.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `mode` | string | Yes | `basic`, `mutual`, `selective`, `delegated` |
| `policy_id` | string | Yes | Policy governing this handshake |
| `parties` | array | Yes | At least 2 party objects (see below) |
| `payload` | object | No | Canonical payload to bind |
| `interaction_id` | string | No | Reference to subject interaction |
| `action_type` | string | No | `install`, `connect`, `delegate`, `transact` |
| `resource_ref` | string | No | Target resource reference |
| `intent_ref` | string | No | Intent reference |
| `binding_ttl_ms` | number | No | Binding TTL in ms (clamped to 60s--1800s) |
| `idempotency_key` | string | No | Client-provided dedup key |

**Party object**:

| Field | Type | Required |
|---|---|---|
| `role` | string | Yes (`initiator`, `responder`, `verifier`, `delegate`) |
| `entity_ref` | string | Yes |

**Response** (201): Handshake record with binding details, parties, and binding hash.

**Error codes**: `bad_request` (400), `unauthorized` (401), `unauthorized_handshake_access` (403), `handshake_initiation_failed` (500)

---

### GET /api/handshake

List handshakes for the authenticated entity.

**Auth**: Required. Results are scoped to the authenticated entity (forced filter).

**Query parameters**:

| Param | Type | Description |
|---|---|---|
| `status` | string | Filter by handshake status |
| `mode` | string | Filter by handshake mode |

**Response** (200): Array of handshake records.

**Error codes**: `unauthorized` (401), `handshake_list_failed` (500)

---

### GET /api/handshake/{handshakeId}

Get full handshake state including parties, presentations, binding, and result.

**Auth**: Required. Only parties to the handshake may view it.

**Response** (200): Full handshake record with nested parties, presentations, binding, and result objects.

**Error codes**: `unauthorized` (401), `not_party` (403), `handshake_not_found` (404)

---

### POST /api/handshake/{handshakeId}/present

Add an identity presentation to a handshake.

**Auth**: Required. Authenticated entity must match the party's `entity_ref`.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `party_role` | string | Yes | `initiator`, `responder`, `verifier`, `delegate` |
| `presentation_type` | string | Yes | `self_asserted`, `verifiable_credential`, `certificate`, `attestation`, `delegation_proof` |
| `claims` | object | Yes | Identity claims (non-array object) |
| `issuer_ref` | string | No | Issuing authority's `key_id` |
| `disclosure_mode` | string | No | `full`, `selective`, `commitment` (default: `full`) |

**Response** (201): Presentation record with `presentation_hash`, `issuer_status`, `verified`, and `normalized_claims`.

**Error codes**: `bad_request` (400), `unauthorized` (401), `presentation_failed` (500)

---

### POST /api/handshake/{handshakeId}/verify

Evaluate presentations against the policy and consume the binding.

**Auth**: Required.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `payload_hash` | string | No | Hash to match against binding's payload hash |
| `nonce` | string | No | Nonce to match against binding's nonce |

**Response** (200): Verification result with `outcome` (`accepted`, `rejected`, `partial`, `expired`), `reason_codes[]`, and consumption details.

**Error codes**: `unauthorized` (401), `handshake_verification_failed` (500)

---

### POST /api/handshake/{handshakeId}/revoke

Revoke an active handshake.

**Auth**: Required. Only parties to the handshake may revoke it.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `reason` | string | Yes | Reason for revocation |

**Response** (200): Revocation result with updated status.

**Error codes**: `bad_request` (400), `unauthorized` (401), `not_party` (403), `handshake_revocation_failed` (500)

---

## 3. Commit

### POST /api/commit/issue

Issue a signed pre-action authorization token.

**Auth**: Required. Caller must own `entity_id` or hold a verified delegation.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `entity_id` | string | Yes | Issuing entity |
| `action_type` | string | Yes | `install`, `connect`, `delegate`, `transact` |
| `principal_id` | string | No | Principal entity (for delegated commits) |
| `counterparty_entity_id` | string | No | Counterparty entity |
| `delegation_id` | string | No | Delegation reference |
| `scope` | object | No | Additional scope constraints |
| `max_value_usd` | number | No | Transaction value cap |
| `context` | object | No | Additional context |
| `policy` | string | No | Policy name |
| `gate_ref` | string | Conditional | Required for `transact` and `connect` actions -- must reference a prior gate `allow` commit |

**Response** (201):

```json
{
  "decision": "allow",
  "commit": {
    "commit_id": "...",
    "entity_id": "...",
    "action_type": "install",
    "decision": "allow",
    "status": "active",
    "scope": {},
    "expires_at": "..."
  }
}
```

**Error codes**: `missing_action_type` (400), `invalid_action_type` (400), `missing_entity_id` (400), `unauthorized` (401), `not_authorized` (403), `gate_required` (403), `invalid_gate_ref` (403), `gate_denied` (403), `gate_entity_mismatch` (403), `gate_action_mismatch` (403)

---

### POST /api/commit/verify

Verify a commit's validity. Public endpoint.

**Auth**: None (public)

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `commit_id` | string | Yes | Commit to verify |

**Response** (200):

```json
{
  "valid": true,
  "status": "active",
  "decision": "allow",
  "expires_at": "2025-01-01T00:00:00.000Z",
  "reasons": []
}
```

Minimum disclosure: verification does not expose the full commit payload (no scope, entity_id, action_type, or context).

**Error codes**: `missing_commit_id` (400)

---

### GET /api/commit/{commitId}

Get full commit status and metadata.

**Auth**: Required. Only the issuing entity or principal may view.

**Response** (200):

```json
{
  "commit": {
    "commit_id": "...",
    "entity_id": "...",
    "action_type": "...",
    "decision": "allow",
    "status": "active",
    "scope": {},
    "context": {},
    "created_at": "...",
    "expires_at": "..."
  }
}
```

**Error codes**: `unauthorized` (401), `not_authorized` (403), `commit_not_found` (404)

---

### POST /api/commit/{commitId}/revoke

Revoke an active commit.

**Auth**: Required. Only the issuing entity or principal may revoke.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `reason` | string | Yes | Reason for revocation |

**Response** (200):

```json
{
  "commit_id": "...",
  "status": "revoked",
  "revoked_at": "2025-01-01T00:00:00.000Z"
}
```

**Error codes**: `missing_reason` (400), `unauthorized` (401), `not_authorized` (403), `commit_not_found` (404)

---

### POST /api/commit/{commitId}/receipt

Bind a receipt to a commit and mark it as fulfilled.

**Auth**: Required. Only the issuing entity may bind a receipt.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `receipt_id` | string | Yes | Receipt to bind |

**Response** (200):

```json
{
  "commit_id": "...",
  "status": "fulfilled",
  "receipt_id": "..."
}
```

**Error codes**: `missing_receipt_id` (400), `unauthorized` (401), `not_authorized` (403), `commit_not_found` (404)

---

### POST /api/commit/{commitId}/dispute

File a dispute against a commit's bound receipt.

**Auth**: Required.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `reason` | string | No | Dispute reason (default: `context_mismatch`) |
| `description` | string | No | Dispute description |
| `evidence` | object | No | Supporting evidence |

**Response** (201): Dispute record with `dispute_id`, `commit_id`, and message.

**Error codes**: `unauthorized` (401), `commit_not_found` (404), `no_receipt_bound` (409), `dispute_filing_failed` (500)

---

## 4. Trust Evaluation

### POST /api/trust/evaluate

Evaluate an entity against a trust policy.

**Auth**: None (public)

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `entity_id` | string | Yes | Entity to evaluate |
| `policy` | string | No | Policy name (default: `standard`) |
| `context` | object | No | Additional evaluation context |

**Response** (200): Trust Decision (see `docs/architecture/TRUST_DECISION.md`):

```json
{
  "decision": "allow",
  "entity_id": "...",
  "policy_used": "standard",
  "confidence": "confident",
  "reasons": [],
  "warnings": [],
  "appeal_path": "/api/disputes/report",
  "profile_summary": {
    "confidence": "confident",
    "evidence_level": 45.2,
    "dispute_rate": 0
  },
  "pass": true,
  "display_name": "...",
  "score": 82,
  "_protocol_version": "EP/1.1-v2"
}
```

**Error codes**: `bad_request` (400), `not_found` (404)

---

### POST /api/trust/gate

Pre-action trust gate. Returns allow/deny with optional commit issuance.

**Auth**: Required.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `entity_id` | string | Yes | Entity requesting action |
| `action` | string | Yes | Action type |
| `policy` | string | No | `strict`, `standard`, `permissive` (default: `standard`) |
| `value_usd` | number | No | Transaction value (triggers escalation above $10,000) |
| `delegation_id` | string | No | Delegation to verify |
| `handshake_id` | string | No | Handshake to verify and consume |
| `resource_ref` | string | No | Resource reference for handshake binding check |
| `intent_ref` | string | No | Intent reference for action hash check |

**Response** (200): Trust Decision with extensions:

```json
{
  "decision": "allow",
  "entity_id": "...",
  "policy_used": "standard",
  "confidence": "confident",
  "reasons": [],
  "warnings": [],
  "appeal_path": "https://emiliaprotocol.ai/appeal",
  "profile_summary": { "confidence": "confident", "evidence_level": 45, "dispute_rate": 0 },
  "action": "install",
  "display_name": "...",
  "commit_ref": "ep_commit_...",
  "delegation_verified": true,
  "handshake_verified": true
}
```

On `allow`: a commit is issued via `protocolWrite(ISSUE_COMMIT)` and its ID returned as `commit_ref`. If `handshake_id` was provided and verified, the binding is consumed.

**Error codes**: `bad_request` (400), `unauthorized` (401)

---

### GET /api/trust/profile/{entityId}

Canonical read surface for an entity's trust data.

**Auth**: None (public)

**Response** (200):

```json
{
  "entity_id": "...",
  "display_name": "...",
  "entity_type": "...",
  "description": "...",
  "category": "...",
  "capabilities": [],
  "trust_profile": { "behavioral": {}, "volume": {}, "quality": {} },
  "anomaly": {},
  "current_confidence": "confident",
  "effective_evidence_current": 45.2,
  "quality_gated_evidence_current": 42.1,
  "historical_establishment": true,
  "effective_evidence_historical": 40,
  "unique_submitters": 12,
  "receipt_count": 85,
  "disputes": [],
  "disputesDampened": 0,
  "compat_score": 82,
  "member_since": "2024-01-01T00:00:00.000Z",
  "_protocol_version": "EP/1.1-v2"
}
```

**Error codes**: `not_found` (404)

---

## 5. Delegation

### POST /api/delegations/create

Create a principal-agent delegation.

**Auth**: Required. `principal_id` must match authenticated entity.

**Request body**:

| Field | Type | Required | Description |
|---|---|---|---|
| `principal_id` | string | No | Defaults to authenticated entity |
| `agent_entity_id` | string | Yes | Agent to authorize |
| `scope` | string[] | Yes | Permitted action types |
| `max_value_usd` | number | No | Transaction value cap |
| `expires_at` | ISO8601 | No | Delegation expiry (default: 24h) |
| `constraints` | object | No | Additional constraints |

**Response** (201):

```json
{
  "delegation_id": "ep_dlg_...",
  "principal_id": "...",
  "agent_entity_id": "...",
  "scope": ["install", "connect"],
  "max_value_usd": null,
  "expires_at": "...",
  "constraints": null,
  "status": "active",
  "created_at": "..."
}
```

**Error codes**: `validation_error` (400), `unauthorized` (401), `not_authorized` (403), `entity_not_found` (404), `rate_limited` (429), `delegation_store_unavailable` (503)

---

## 6. Cloud Control Plane (authenticated)

> All cloud routes require an EP Cloud API key:
> `Authorization: Bearer ep_cloud_...`

### POST /api/cloud/signoff/escalate

Escalate a pending signoff for review.

**Auth**: EP Cloud API key required.

---

### POST /api/cloud/signoff/notify

Send a signoff notification to the relevant parties.

**Auth**: EP Cloud API key required.

---

### GET /api/cloud/signoff/pending

List all pending signoffs.

**Auth**: EP Cloud API key required.

**Response** (200): Array of pending signoff records.

---

### GET /api/cloud/signoff/queue

Retrieve the signoff processing queue.

**Auth**: EP Cloud API key required.

**Response** (200): Ordered queue of signoff items awaiting action.

---

### GET /api/cloud/signoff/dashboard

Dashboard statistics for signoff operations.

**Auth**: EP Cloud API key required.

**Response** (200): Aggregated signoff metrics (counts, latency, status breakdown).

---

### GET /api/cloud/signoff/analytics

Analytics time series for signoff activity.

**Auth**: EP Cloud API key required.

**Response** (200): Time-bucketed signoff analytics data.

---

### GET /api/cloud/events/search

Search protocol events with filters.

**Auth**: EP Cloud API key required.

**Query parameters**: Supports filtering by event type, entity, date range, and free-text search.

**Response** (200): Array of matching event records.

---

### GET /api/cloud/events/timeline/{handshakeId}

Retrieve the full event timeline for a specific handshake.

**Auth**: EP Cloud API key required.

**Response** (200): Chronological array of events associated with the handshake.

---

### GET /api/cloud/audit/export

Export an evidence package for compliance or review.

**Auth**: EP Cloud API key required.

**Response** (200): Downloadable evidence bundle (events, commits, handshakes).

---

### GET /api/cloud/audit/report

Generate a compliance report.

**Auth**: EP Cloud API key required.

**Response** (200): Structured compliance report with policy adherence summary.

---

### GET /api/cloud/audit/integrity

Check event integrity across the audit trail.

**Auth**: EP Cloud API key required.

**Response** (200): Integrity check result with hash verification status.

---

### POST /api/cloud/policies/{policyId}/simulate

Simulate a policy against historical or hypothetical data.

**Auth**: EP Cloud API key required.

**Request body**: Simulation parameters (entity set, time range, threshold overrides).

**Response** (200): Simulation results showing projected allow/deny outcomes.

---

### POST /api/cloud/policies/{policyId}/rollout

Initiate a staged rollout of a policy version.

**Auth**: EP Cloud API key required.

**Request body**: Rollout configuration (percentage, target groups, schedule).

**Response** (200): Rollout plan with stages and rollback criteria.

---

### GET /api/cloud/policies/{policyId}/versions

List version history for a policy.

**Auth**: EP Cloud API key required.

**Response** (200): Array of policy versions with timestamps and change summaries.

---

### GET /api/cloud/policies/{policyId}/diff

Compare two versions of a policy.

**Auth**: EP Cloud API key required.

**Query parameters**: `from` and `to` version identifiers.

**Response** (200): Structured diff of policy parameters between versions.

---

## Lifecycle Summary

```
Policy           GET /api/policies                        (discover policies)
                   |
Handshake        POST /api/handshake                      (initiate)
                   |
Present          POST /api/handshake/{id}/present         (add identity proof)
                   |
Verify           POST /api/handshake/{id}/verify          (evaluate + consume binding)
                   |
Evaluate/Gate    POST /api/trust/evaluate                 (policy evaluation)
                 POST /api/trust/gate                     (pre-action gate + commit)
                   |
Commit           POST /api/commit/issue                   (issue pre-authorization)
                 POST /api/commit/verify                  (verify commit validity)
                 GET  /api/commit/{id}                    (get commit state)
                   |
Consume          POST /api/commit/{id}/receipt            (bind receipt, mark fulfilled)
                   |
Signoff          POST /api/commit/{id}/revoke             (revoke pre-authorization)
                 POST /api/commit/{id}/dispute            (challenge the outcome)
```
