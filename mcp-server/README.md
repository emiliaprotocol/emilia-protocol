# @emilia-protocol/mcp-server

[![npm version](https://img.shields.io/npm/v/@emilia-protocol/mcp-server)](https://www.npmjs.com/package/@emilia-protocol/mcp-server)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![MCP](https://img.shields.io/badge/protocol-MCP-5a5aff)](https://modelcontextprotocol.io)

**Trust enforcement for high-risk actions via MCP. Pre-action binding, policy-bound verification, one-time consumption, and accountable human signoff.**

---

## What This Is

EMILIA Protocol enforces trust before high-risk action. EP verifies whether a specific high-risk action should proceed under a specific authority context, governing policy, and transaction binding. This MCP server gives any Claude conversation or agent pipeline direct access to EP's trust-decision surfaces: 34 tools covering trust profiles, policy evaluation, handshake verification, signoff orchestration, and pre-action binding. Add it to Claude Desktop in 60 seconds. No self-hosted EP backend required.

---

## Installation

Add the following to your MCP client config. No local install required — `npx` handles it.

### Claude Desktop

Config file: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "emilia-protocol": {
      "command": "npx",
      "args": ["-y", "@emilia-protocol/mcp-server"],
      "env": {
        "EP_API_KEY": "ep_live_your_key_here",
        "EP_BASE_URL": "https://emiliaprotocol.ai"
      }
    }
  }
}
```

### Cursor

Config file: `.cursor/mcp.json`

```json
{
  "mcpServers": {
    "emilia-protocol": {
      "command": "npx",
      "args": ["-y", "@emilia-protocol/mcp-server"],
      "env": {
        "EP_API_KEY": "ep_live_your_key_here",
        "EP_BASE_URL": "https://emiliaprotocol.ai"
      }
    }
  }
}
```

### npx (zero install, test immediately)

```bash
EP_API_KEY=ep_live_your_key_here npx @emilia-protocol/mcp-server
```

Use EP Commit when a relying system wants proof that a high-stakes action was evaluated before it proceeded.

---

## Quick Start

Five scenarios you can try immediately after connecting.

### 1. Check if you should transact with a counterparty

```
"Check if I can trust acme-logistics for a $5,000 freight booking"
```

EP runs the gate check, then retrieves the full behavioral profile:

```
ep_trust_gate(entity_id="acme-logistics", action="purchase", value_usd=5000, policy="standard")
ep_trust_profile(entity_id="acme-logistics")
```

**Trust gate response:**
```
Trust Gate: purchase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Entity: acme-logistics
Decision: ✓ ALLOW
Policy: standard
Confidence: confident

Reasons:
  ✓ Confidence meets standard threshold
  ✓ Completion rate 94% (above 85% floor)
  ✓ Dispute rate 1.2% (below 5% ceiling)
```

**Trust profile response:**
```
Trust Profile: Acme Logistics (acme-logistics)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Confidence: confident
Established: Yes
Evidence: 47 (current) / 112 (historical)
Receipts: 112 from 23 submitters

Behavioral:
  Completion rate: 94%
  Retry rate:      4%
  Abandon rate:    1%
  Dispute rate:    1.2%

Signals:
  Delivery:  91
  Product:   88
  Price:     96
  Returns:   82
  Consistency: 0.91

Provenance: bilateral: 71%, self_attested: 29%
  Bilateral rate: 71%
```

---

### 2. Submit a receipt after a completed task

```
"Record that freight-agent-7 completed my delivery order on time"
```

```
ep_submit_receipt(
  entity_id="freight-agent-7",
  transaction_ref="FRT-20241218-001",
  transaction_type="delivery",
  agent_behavior="completed",
  delivery_accuracy=96,
  price_integrity=100,
  claims={"delivered": true, "on_time": true, "price_honored": true}
)
```

**Response:**
```
Receipt submitted.
ID: ep_rcpt_a8f3c2d1e9b4
Hash: sha256:7f3a9c1b2e8d4f6a...
Entity trust profile updated. Query with ep_trust_profile for current state.
```

Receipts are append-only and cryptographically chain-linked. They cannot be deleted — only disputed.

---

### 3. Check if a plugin is safe to install

```
"Should I install the code-helper GitHub App in my private repo?"
```

```
ep_install_preflight(
  entity_id="github_app:acme/code-helper",
  policy="github_private_repo_safe_v1",
  context={"host": "github", "data_sensitivity": "private_repo", "permission_class": "read_write"}
)
```

**Response:**
```
Install Preflight: Acme Code Helper (github_app:acme/code-helper)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Decision: ⚠ REVIEW
Policy: github_private_repo_safe_v1
Confidence: provisional

Reasons:
  Publisher not verified against GitHub profile
  Permission class (read_write) exceeds policy floor for private repos
  Provenance not verified (no signed release artifacts)

Software:
  Publisher verified: false
  Provenance verified: false
  Permission class: read_write
```

---

### 4. Create a delegation

```
"Authorize my scheduling agent to book meetings on my behalf for the next 8 hours"
```

```
ep_create_delegation(
  principal_id="ep_principal_usr_abc123",
  agent_entity_id="my-scheduler",
  scope=["book_meeting", "send_invite"],
  max_value_usd=0,
  expires_at="2024-12-18T20:00:00Z"
)
```

**Response:**
```
Delegation created.
ID: ep_dlg_x7y2z9w1
Principal: ep_principal_usr_abc123
Agent: my-scheduler
Scope: book_meeting, send_invite
Expires: 2024-12-18T20:00:00Z
Status: active
```

Any action the agent takes can now reference this delegation ID, creating a complete, auditable authorization chain.

---

### 5. File a dispute

```
"That receipt for acme-co was wrong — they abandoned my order, not completed it"
```

```
ep_dispute_file(
  receipt_id="ep_rcpt_a8f3c2d1e9b4",
  reason="inaccurate_signals",
  description="Receipt records agent_behavior=completed but the order was abandoned after 3 days with no communication. Order ref FRT-20241218-001.",
  evidence={"order_status_screenshot": "url", "support_ticket": "TKT-9921"}
)
```

**Response:**
```
Dispute filed.
Dispute ID: ep_disp_3f7a1c9b
Receipt: ep_rcpt_a8f3c2d1e9b4
Status: open
Response deadline: 2024-12-25T12:00:00Z
The submitter has 7 days to respond. Trust is suspended pending resolution.
```

---

## Tool Reference

### Summary

| Tool | Description | Auth Required |
|------|-------------|:---:|
| `ep_trust_profile` | Full trust profile — the canonical read surface | No |
| `ep_trust_evaluate` | Policy evaluation with Trust Decision (allow/review/deny) and failure reasons | No |
| `ep_trust_gate` | Pre-action trust check — call before irreversible actions | No |
| `ep_submit_receipt` | Record a behavioral outcome to the EP ledger | Yes |
| `ep_batch_submit` | Submit up to 50 receipts atomically | Yes |
| `ep_domain_score` | Per-domain trust scores (financial, code, comms, etc.) | No |
| `ep_search_entities` | Find entities by name, type, or capability | No |
| `ep_register_entity` | Register a new entity — returns first API key | No |
| `ep_leaderboard` | Top entities ranked by trust confidence | No |
| `ep_verify_receipt` | Verify a receipt against its Merkle proof | No |
| `ep_install_preflight` | Software trust check before installing plugins/packages | No |
| `ep_dispute_file` | Challenge an inaccurate or fraudulent receipt | Yes |
| `ep_dispute_status` | Check the status of a dispute | No |
| `ep_appeal_dispute` | Appeal a dispute resolution | Yes |
| `ep_report_trust_issue` | Human-accessible trust report (no auth required) | No |
| `ep_create_delegation` | Authorize an agent to act on a principal's behalf | Yes |
| `ep_verify_delegation` | Check that a delegation is valid for a specific action | No |
| `ep_principal_lookup` | Look up the enduring principal behind entities | No |
| `ep_lineage` | Entity lineage, predecessors, continuity, whitewashing flags | No |
| `ep_delegation_judgment` | Score a principal's track record of choosing and overseeing agents | No |
| `ep_configure_auto_receipt` | Configure automatic receipt generation from MCP tool call events (opt-in) | Yes |
| `ep_generate_zk_proof` | Generate a commitment proof for a score claim | No |
| `ep_verify_zk_proof` | Verify a commitment proof | No |
| `ep_list_policies` | List all available trust policies | No |
| `ep_issue_commit` | Issue a signed EP Commit before a high-stakes action | Yes |
| `ep_verify_commit` | Verify a commit's signature, status, and validity | No |
| `ep_get_commit_status` | Get current state of a commit | Yes |
| `ep_revoke_commit` | Revoke an active commit | Yes |
| `ep_bind_receipt_to_commit` | Bind a post-action receipt to a commit | Yes |
| `ep_initiate_handshake` | Initiate a structured identity exchange between parties | Yes |
| `ep_add_presentation` | Add an identity presentation (proof) to a handshake | Yes |
| `ep_verify_handshake` | Evaluate handshake presentations against policy | Yes |
| `ep_get_handshake` | Get full handshake state | Yes |
| `ep_revoke_handshake` | Revoke an active handshake | Yes |

---

### ep_trust_profile

Get an entity's full trust profile. This is the canonical read surface in EP — use it before transacting with any counterparty or installing any software.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `entity_id` | string | Yes | Entity slug (e.g. `acme-logistics`) or UUID |

**Example:**
```
ep_trust_profile(entity_id="stripe-payments")
```

**Returns:** Confidence level, behavioral rates (completion/retry/abandon/dispute), signal scores (delivery/product/price/returns), provenance composition, consistency score, dispute summary, and anomaly alerts. The compatibility score field exists for legacy sorting use cases — use the trust profile for decisions.

---

### ep_trust_evaluate

Evaluate an entity against a named trust policy. Returns a Trust Decision (allow/review/deny) with specific failure reasons — designed to be consumed programmatically by routing logic.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `entity_id` | string | Yes | Entity to evaluate |
| `policy` | string | No | `strict`, `standard`, `permissive`, `discovery` (default: `standard`) |
| `context` | object | No | Context key: `{ task_type, category, geo, modality, value_band }` |

**Example:**
```
ep_trust_evaluate(
  entity_id="acme-logistics",
  policy="strict",
  context={"value_band": "high", "category": "freight"}
)
```

**Response:**
```
Trust Evaluation: Acme Logistics (acme-logistics)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Policy: strict
Decision: ✗ DENY
Confidence: provisional
Context: {"value_band": "high", "category": "freight"}

Reasons:
  ✗ Insufficient evidence for strict policy (need: high, have: moderate)
  ✗ Dispute rate 1.2% exceeds strict ceiling of 0.5%
```

---

### ep_trust_gate

The canonical pre-action check. Call this before payments, installs, sending messages on behalf of users, or any irreversible action. Combines trust evaluation with optional delegation verification in a single call.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `entity_id` | string | Yes | Entity requesting to perform the action |
| `action` | string | Yes | Action being requested (e.g. `process_payment`, `send_email`, `install_package`) |
| `policy` | string | No | Policy to enforce (default: `standard`) |
| `value_usd` | number | No | Transaction value for risk calibration |
| `delegation_id` | string | No | If agent is acting on behalf of a human, the delegation ID |

**Example:**
```
ep_trust_gate(
  entity_id="payment-processor-x",
  action="process_payment",
  policy="strict",
  value_usd=12500
)
```

**Response:**
```
Trust Gate: process_payment
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Entity: payment-processor-x
Decision: ✓ ALLOW
Policy: strict
Confidence: confident

Reasons:
  ✓ Confidence meets strict threshold
  ✓ Completion rate 98% exceeds strict floor
  ✓ Dispute rate 0.3% below strict ceiling
```

When a gate blocks, the response includes an `appeal_path` — because trust must never be more powerful than appeal.

---

### ep_submit_receipt

Submit a transaction receipt to the EP ledger. Receipts are append-only, cryptographically hashed, and chain-linked. `agent_behavior` is the strongest behavioral signal and should always be set.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `entity_id` | string | Yes | Entity the receipt describes |
| `transaction_ref` | string | Yes | Your external transaction reference |
| `transaction_type` | string | Yes | `purchase`, `service`, `task_completion`, `delivery`, `return` |
| `agent_behavior` | string | No | `completed`, `retried_same`, `retried_different`, `abandoned`, `disputed` |
| `delivery_accuracy` | number | No | 0–100 |
| `product_accuracy` | number | No | 0–100 |
| `price_integrity` | number | No | 0–100 |
| `return_processing` | number | No | 0–100 |
| `claims` | object | No | `{ delivered, on_time, price_honored, as_described }` |
| `evidence` | object | No | Supporting evidence references |
| `context` | object | No | `{ task_type, category, geo, modality, value_band, risk_class }` |

**Example:**
```
ep_submit_receipt(
  entity_id="saas-vendor-y",
  transaction_ref="INV-2024-08871",
  transaction_type="service",
  agent_behavior="completed",
  delivery_accuracy=95,
  price_integrity=100,
  claims={"delivered": true, "price_honored": true}
)
```

---

### ep_batch_submit

Submit up to 50 receipts atomically. All receipts share the same API key as submitter. Returns per-receipt success or failure without aborting the batch — useful for bulk reconciliation or recording a full session of agent-entity interactions.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `receipts` | array | Yes | Array of receipt objects (same schema as `ep_submit_receipt`, max 50) |

**Example:**
```
ep_batch_submit(receipts=[
  {
    "entity_id": "vendor-a",
    "transaction_ref": "TXN-001",
    "transaction_type": "service",
    "agent_behavior": "completed"
  },
  {
    "entity_id": "vendor-b",
    "transaction_ref": "TXN-002",
    "transaction_type": "purchase",
    "agent_behavior": "abandoned"
  }
])
```

**Response:**
```
Batch submission: 1 succeeded, 1 failed
  ✓ vendor-a — ep_rcpt_f4a2b1c9
  ✗ vendor-b — Entity not found
```

---

### ep_domain_score

Trust is not a scalar. An agent excellent at financial transactions may be unreliable at creative tasks. `ep_domain_score` returns per-domain confidence and behavioral rates so you can make task-appropriate trust decisions.

**Domains:** `financial`, `code_execution`, `communication`, `delegation`, `infrastructure`, `content_creation`, `data_access`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `entity_id` | string | Yes | Entity to query |
| `domains` | array | No | Specific domains to query (omit for all) |

**Example:**
```
ep_domain_score(entity_id="dev-agent-42", domains=["code_execution", "data_access"])
```

**Response:**
```
Domain Scores: dev-agent-42
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

code_execution:
  Confidence: confident
  Evidence: 38 receipts
  Completion: 97%
  Dispute rate: 0.8%

data_access:
  Confidence: provisional
  Evidence: 6 receipts
  Completion: 83%
  Dispute rate: 5.1%
```

---

### ep_search_entities

Search for entities by name, capability, or category.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `query` | string | Yes | Search query |
| `entity_type` | string | No | Filter by type (see entity types below) |

**Entity types:** `agent`, `merchant`, `service_provider`, `github_app`, `github_action`, `mcp_server`, `npm_package`, `chrome_extension`, `shopify_app`, `marketplace_plugin`, `agent_tool`

**Example:**
```
ep_search_entities(query="freight logistics", entity_type="service_provider")
```

---

### ep_register_entity

Register a new entity on EP. This is a public operation — no API key required. Returns the first API key immediately. Save it: it is shown only once.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `entity_id` | string | Yes | Slug: lowercase, hyphens only (e.g. `my-agent-v2`) |
| `display_name` | string | Yes | Human-readable name |
| `entity_type` | string | Yes | One of the entity types listed above |
| `description` | string | Yes | What this entity does |
| `capabilities` | array | No | List of capability strings |

**Example:**
```
ep_register_entity(
  entity_id="my-scheduling-agent",
  display_name="My Scheduling Agent",
  entity_type="agent",
  description="Books meetings and sends calendar invites on behalf of users.",
  capabilities=["book_meeting", "send_invite", "check_availability"]
)
```

**Response:**
```
Registered: my-scheduling-agent
API Key: ep_live_xxxxxxxxxxxxxxxxxxxxxxxx
⚠ Save this key — it won't be shown again.
```

---

### ep_leaderboard

Get entities ranked by trust confidence, optionally filtered by type.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `limit` | number | No | Max results (default: 10, max: 50) |
| `entity_type` | string | No | Filter by entity type |

**Example:**
```
ep_leaderboard(entity_type="mcp_server", limit=5)
```

---

### ep_verify_receipt

Verify a receipt's integrity against its Merkle proof. Use when you need cryptographic assurance that a receipt has not been tampered with after submission.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `receipt_id` | string | Yes | Receipt ID (`ep_rcpt_...`) |

**Example:**
```
ep_verify_receipt(receipt_id="ep_rcpt_a8f3c2d1e9b4")
```

**Response:**
```
Receipt: ep_rcpt_a8f3c2d1e9b4
Hash: sha256:7f3a9c1b2e8d4f6a...
Anchored: Yes
Verified: YES
```

---

### ep_install_preflight

EP-SX: Should I install this plugin, app, package, or extension? Evaluates a software entity against a context-aware policy covering publisher verification, permission class, provenance, and behavioral history. Returns `allow`, `review`, or `deny` with specific reasons.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `entity_id` | string | Yes | Software entity ID (e.g. `github_app:acme/code-helper`, `npm:left-pad`) |
| `policy` | string | No | Software-specific or standard policy (see trust policies section) |
| `context` | object | No | `{ host, install_scope, permission_class, data_sensitivity, execution_mode }` |

**Software policies:** `github_private_repo_safe_v1`, `npm_buildtime_safe_v1`, `browser_extension_safe_v1`, `mcp_server_safe_v1`

**Example:**
```
ep_install_preflight(
  entity_id="mcp_server:some-org/data-extractor",
  policy="mcp_server_safe_v1",
  context={
    "host": "mcp",
    "data_sensitivity": "private_workspace",
    "execution_mode": "persistent"
  }
)
```

---

### ep_dispute_file

Challenge an inaccurate or fraudulent receipt. Any affected party can file. The submitter has 7 days to respond. The receipt remains on the ledger — nothing is deleted — but trust is suspended pending resolution.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `receipt_id` | string | Yes | Receipt to dispute (`ep_rcpt_...`) |
| `reason` | string | Yes | `fraudulent_receipt`, `inaccurate_signals`, `identity_dispute`, `context_mismatch`, `duplicate_transaction`, `coerced_receipt`, `other` |
| `description` | string | No | Explanation of the dispute |
| `evidence` | object | No | Supporting evidence |

**Example:**
```
ep_dispute_file(
  receipt_id="ep_rcpt_a8f3c2d1e9b4",
  reason="inaccurate_signals",
  description="Agent behavior recorded as 'completed' but order was abandoned after 72 hours. No communication received.",
  evidence={"support_ticket_url": "https://...", "order_status": "abandoned"}
)
```

---

### ep_dispute_status

Check the status of a dispute. Public — transparency is a protocol value.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `dispute_id` | string | Yes | Dispute ID (`ep_disp_...`) |

**Example:**
```
ep_dispute_status(dispute_id="ep_disp_3f7a1c9b")
```

---

### ep_appeal_dispute

Appeal a dispute resolution. Only dispute participants can appeal. The dispute must be in `upheld`, `reversed`, or `dismissed` state. The protocol guarantees this path exists — trust must never be more powerful than appeal.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `dispute_id` | string | Yes | Dispute to appeal (`ep_disp_...`) |
| `reason` | string | Yes | Why the resolution should be reconsidered (minimum 10 characters) |
| `evidence` | object | No | Additional supporting evidence |

**Example:**
```
ep_appeal_dispute(
  dispute_id="ep_disp_3f7a1c9b",
  reason="Resolution relied on incomplete evidence. I now have courier tracking data confirming non-delivery.",
  evidence={"tracking_data": "https://...", "courier_confirmation": "CNF-4821"}
)
```

---

### ep_report_trust_issue

File a human trust report. No authentication required. Use when someone has been wrongly downgraded, harmed by a trusted entity, or witnesses fraud. EP must never make trust more powerful than appeal — this tool is the human escape hatch.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `entity_id` | string | Yes | Entity the report concerns |
| `report_type` | string | Yes | `wrongly_downgraded`, `harmed_by_trusted_entity`, `fraudulent_entity`, `inaccurate_profile`, `other` |
| `description` | string | Yes | What happened |
| `contact_email` | string | No | Email for follow-up |

**Example:**
```
ep_report_trust_issue(
  entity_id="some-merchant",
  report_type="harmed_by_trusted_entity",
  description="Entity shows high trust but charged my card without authorization.",
  contact_email="user@example.com"
)
```

---

### ep_create_delegation

Record that a principal (human or organization) authorizes an agent to act on their behalf. The delegation is stored in the EP ledger with an explicit scope, expiry, and optional constraints. Every delegated action can reference this ID to prove authorization.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `principal_id` | string | Yes | The principal granting authorization (`ep_principal_...`) |
| `agent_entity_id` | string | Yes | The agent entity being authorized |
| `scope` | array | Yes | Permitted action types (e.g. `["purchase", "book_meeting", "send_email"]`) |
| `max_value_usd` | number | No | Maximum transaction value this delegation authorizes |
| `expires_at` | string | No | ISO 8601 expiry (default: 24 hours from creation) |
| `constraints` | object | No | Additional constraints: `{ geo, merchant_category, ... }` |

**Example:**
```
ep_create_delegation(
  principal_id="ep_principal_usr_abc123",
  agent_entity_id="travel-agent-v2",
  scope=["book_flight", "book_hotel", "purchase"],
  max_value_usd=2000,
  expires_at="2024-12-20T00:00:00Z",
  constraints={"merchant_category": ["airline", "hotel"]}
)
```

---

### ep_verify_delegation

Verify that an agent holds a currently valid delegation for a specific action. Call this before accepting a task from an agent claiming to act on behalf of a human.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `delegation_id` | string | Yes | Delegation to verify (`ep_dlg_...`) |
| `action_type` | string | No | Specific action to check against the delegation scope |

**Example:**
```
ep_verify_delegation(
  delegation_id="ep_dlg_x7y2z9w1",
  action_type="book_flight"
)
```

**Response:**
```
Delegation: ep_dlg_x7y2z9w1
Status: ✓ VALID
Principal: ep_principal_usr_abc123
Agent: travel-agent-v2
Scope: book_flight, book_hotel, purchase
Expires: 2024-12-20T00:00:00Z
Action "book_flight": ✓ Permitted
```

---

### ep_principal_lookup

Look up a principal — the enduring actor behind one or more entities. Returns identity bindings, controlled entities, and continuity history. A principal persists across entity re-registrations, making whitewashing detectable.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `principal_id` | string | Yes | Principal ID (`ep_principal_...`) |

**Example:**
```
ep_principal_lookup(principal_id="ep_principal_usr_abc123")
```

---

### ep_lineage

View an entity's lineage: predecessors, successors, and continuity decisions. Use this to detect whitewashing — where an entity attempts to shed a bad trust history by re-registering under a new ID.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `entity_id` | string | Yes | Entity to check lineage for |

**Example:**
```
ep_lineage(entity_id="new-vendor-rebranded")
```

**Response:**
```
Lineage: new-vendor-rebranded

Predecessors:
  <- old-vendor-ltd (rebranding) [approved] transfer: partial

No successors.
```

---

### ep_delegation_judgment

Score a principal's track record of choosing and overseeing agents. This is the inverse of `ep_trust_profile` — instead of asking "can I trust this agent?", it asks "can I trust the human who authorized it?" A principal with a poor delegation judgment score has a history of authorizing misbehaving agents, even if those individual agents no longer appear active.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|:--------:|-------------|
| `principal_id` | string | Yes | Principal ID (`ep_principal_...`) |

**Example:**
```
ep_delegation_judgment(principal_id="ep_principal_usr_abc123")
```

**Response:**
```
Delegation Judgment: ep_principal_usr_abc123
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Score:             0.94  (excellent)
Agents authorized: 6
Active agents:     2
Good outcome rate: 94%
Avg agent confidence: 0.82

Interpretation:
  Consistently authorizes high-confidence agents with excellent outcomes (47 receipts, 94% positive).

Recent signals:
  ✓ travel-agent-v2   — positive
  ✓ data-fetcher-x    — positive
  ✗ old-scheduler     — negative
  ...
```

**Grade thresholds:**

| Grade | Score range |
|-------|-------------|
| `excellent` | 0.85 – 1.0 |
| `good` | 0.70 – 0.84 |
| `fair` | 0.50 – 0.69 |
| `poor` | < 0.50 |

Delegation judgment scores are computed from `principal_delegation_signals` — lightweight attribution rows written each time a delegated agent's receipt is processed. The score is the weighted fraction of those signals that recorded a positive outcome. A principal with no delegation history returns `judgmentScore: null` and `grade: null`.

---

### ep_list_policies

List all available trust policies with their requirements, families, and minimum confidence thresholds.

**Parameters:** None

**Example:**
```
ep_list_policies()
```

Use the returned policy names with `ep_trust_evaluate`, `ep_trust_gate`, and `ep_install_preflight`.

---

## MCP Resources

In addition to tools, the server exposes four URI-addressable resources that can be read directly by MCP clients that support resource access.

| URI | Description |
|-----|-------------|
| `entity://acme-logistics` | Full trust profile JSON — identical to `ep_trust_profile` |
| `score://acme-logistics` | Condensed confidence snapshot: entity_id, confidence, evidence, established |
| `receipt://ep_rcpt_abc123` | Receipt with hash, provenance, and verification status |
| `delegation://ep_dlg_xyz789` | Delegation details: principal, agent, scope, expiry, status |

Resources are useful when you want to pass a trust profile into a prompt context directly rather than calling a tool. In Claude, you can attach them as context documents before making a routing decision.

---

## MCP Prompts

Three structured prompts orchestrate multi-step trust workflows. Invoke them from any MCP client that supports prompts.

### `trust_decision`

Orchestrates a full trust evaluation workflow. Instructs the model to call `ep_trust_gate`, retrieve the full trust profile, and synthesize a clear ALLOW, REVIEW, or DENY recommendation with the key behavioral signals that drove the decision — plus what the entity would need to do to qualify if denied.

**Arguments:** `entity_id` (required), `action` (required), `value_usd` (optional)

---

### `receipt_quality_check`

Guides accurate receipt submission. Checks the entity's current trust state first, then walks through each signal field interactively before submitting. Warns when signals appear inconsistent with the declared `agent_behavior` — for example, `delivery_accuracy=95` paired with `agent_behavior=abandoned`.

**Arguments:** `entity_id` (required), `transaction_ref` (required)

---

### `install_decision`

Full software trust review before installing any plugin, package, or extension. Calls `ep_install_preflight`, checks lineage for suspicious continuity gaps, retrieves the full trust profile, and produces a clear INSTALL / REVIEW / DENY recommendation. If not INSTALL, lists specific questions to investigate before proceeding.

**Arguments:** `entity_id` (required), `install_context` (optional, e.g. `private_repo`, `production_server`)

---

## Trust Policies

EP ships four built-in behavioral policies. Software-specific policies apply the same framework with domain-appropriate thresholds.

### Built-in Policies

| Policy | Use Case | Min Evidence | Max Dispute Rate |
|--------|----------|:------------:|:----------------:|
| `strict` | High-value transactions, critical infrastructure | high | 2% |
| `standard` | Normal operations, typical counterparties | moderate | 5% |
| `permissive` | Low-risk discovery, early relationships | low | 15% |
| `discovery` | Allow unevaluated entities for exploration | none | any |

### Software-Specific Policies

| Policy | Target |
|--------|--------|
| `github_private_repo_safe_v1` | GitHub Apps installed in private repositories |
| `npm_buildtime_safe_v1` | npm packages running in build pipelines |
| `browser_extension_safe_v1` | Browser extensions with broad page access |
| `mcp_server_safe_v1` | MCP servers connecting to agent workspaces |

Use `ep_list_policies` to see the full set of currently available policies.

---

## Environment Variables

| Variable | Description | Required |
|----------|-------------|:--------:|
| `EP_API_KEY` | Your API key (`ep_live_...`). Required for write operations: submitting receipts, filing disputes, creating delegations, filing appeals. | For writes |
| `EP_BASE_URL` | API endpoint. Defaults to `https://emiliaprotocol.ai` | No |

Read-only operations — trust profiles, policy evaluation, trust gates, install preflight, search, leaderboard, dispute status, lineage — work without an API key.

---

## Get an API Key

Registration is public and takes one tool call. No account creation, no email verification, no dashboard:

```
ep_register_entity(
  entity_id="your-agent-or-service",
  display_name="Your Agent or Service",
  entity_type="agent",
  description="What your entity does"
)
```

The response includes your first API key (`ep_live_...`). Save it immediately — EP does not store it in recoverable form. Add it to your MCP server config as `EP_API_KEY` and you have full read/write access.

---

## Philosophy

Trust must never be more powerful than appeal. Every negative trust effect in EP — a downgraded confidence level, a blocked gate, a disputed receipt — must be explainable, challengeable, and reversible. This is why `ep_report_trust_issue` requires no authentication: a person harmed by a trust system should not need credentials to report the harm. It is why blocked trust gates include an `appeal_path`. It is why receipts are never deleted, only disputed — because erasing a record is not the same as correcting it.

This is not a product. It is infrastructure — the same way TCP/IP is not a product but a protocol that products run on. EP is open source (Apache-2.0) and designed to be a neutral standard: no lock-in, no platform dependency, no private moat. Agents, merchants, service providers, and software components should be able to build and maintain trust reputations that are portable, verifiable, and not owned by any single platform. The MCP server is the first interface layer. The protocol is the point.

---

## Links

- Homepage: [emiliaprotocol.ai](https://emiliaprotocol.ai)
- GitHub: [github.com/emiliaprotocol/emilia-protocol](https://github.com/emiliaprotocol/emilia-protocol)
- npm: [@emilia-protocol/mcp-server](https://www.npmjs.com/package/@emilia-protocol/mcp-server)
- License: Apache-2.0
