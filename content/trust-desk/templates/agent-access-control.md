# AI Agent Access Control Policy

**Vendor:** {{COMPANY}}
**Product:** {{PRODUCT_NAME}}
**Document version:** 1.0
**Effective date:** {{EFFECTIVE_DATE}}
**Next review:** quarterly
**Owner:** {{SECURITY_LEAD_NAME}} ({{SECURITY_LEAD_EMAIL}})

---

## 1. Scope

This policy governs what actions AI agents within {{PRODUCT_NAME}} may take, on whose authority, and under what controls. It applies to every tool call, API invocation, data write, and external side-effect initiated by any model-driven agent in the product.

It specifically covers the buyer's most common AI-agent risk questions:

- What tools can the agent access?
- What data can the agent read?
- What writes or payments can the agent execute?
- How is authorization enforced?
- What does the agent do on behalf of a user vs. autonomously?
- How are tool-call errors handled?

---

## 2. Principle: the agent proposes, the authorization service disposes

{{COMPANY}} architects agent capability such that **no action an agent attempts to take bypasses the same authorization controls that a human user's action would pass through**. The model produces a tool-call proposal; the authorization service independently evaluates whether the session is allowed to perform that action; the tool is invoked only if authorization succeeds.

This is enforced as a code-path invariant: the authorization service does not read the model's justification text, does not accept instructions from the prompt, and does not elevate based on the model's assessment of intent. It evaluates only:

- The authenticated session's identity.
- The session's granted scopes.
- The action class being attempted.
- The resource being acted on.
- Applicable policy at evaluation time (not at session-start time).

---

## 3. Capability tiers

Agent tool calls are classified into four tiers. Each tier has distinct authorization, logging, and human-in-the-loop requirements.

### Tier 0 — Read-only, tenant-scoped

Examples: read a customer's own documents, query their own transaction history, summarize their own data.

- Authorization: session must have `read:tenant-data` scope.
- Logging: standard access log.
- Human approval: not required.
- Rate limits: {{TIER_0_RATE_LIMIT}} per user per minute.

### Tier 1 — Non-destructive writes, tenant-scoped

Examples: create a draft document, add a comment, schedule a calendar item, send an internal notification.

- Authorization: session must have `write:tenant-data` scope + the specific tool scope.
- Logging: standard audit log + tool-call metadata.
- Human approval: not required.
- Rate limits: {{TIER_1_RATE_LIMIT}} per user per minute.

### Tier 2 — Destructive or externally visible actions

Examples: delete a document, send an external email, post publicly, invoke a third-party API on the customer's behalf.

- Authorization: session must hold the specific tool scope AND pass a policy check (e.g., not after-hours if policy restricts).
- Logging: elevated audit log including full parameter payload.
- **Human approval: required by default.** A confirmation UI surfaces the proposed action with parameters; the human clicks "Approve" or "Reject." Agent cannot bypass.
- Rate limits: {{TIER_2_RATE_LIMIT}} per user per hour.
- Kill switch: configurable per tool.

### Tier 3 — Money-movement, data-deletion, or policy-changing actions

Examples: initiate a payment, move funds between accounts, change user permissions, publish a signed record, delete a dataset.

- Authorization: session must hold the specific tool scope AND pass an elevated policy check AND the user must have completed re-authentication within the last {{REAUTH_WINDOW}} minutes.
- Logging: cryptographically signed audit record with full parameter payload, user identity, agent decision path, and policy version.
- **Human approval: required, unskippable.** Approval must be from a named human with the appropriate role; the system records who approved, when, from what device/session, and over what channel.
- Rate limits: {{TIER_3_RATE_LIMIT}} per user per day; per-tenant absolute limits configurable.
- **Irreversibility warning**: user is shown estimated reversibility before approval.
- Tested monthly under {{COMPANY}}'s adversarial test suite.

---

## 4. Per-tool specifications

For each tool available to agents, {{COMPANY}} maintains a record containing:

- Tool name and version.
- Tier (0–3) and rationale.
- Parameter schema (JSON schema).
- Pre-call validation logic.
- Post-call side-effect record.
- Kill-switch configuration.

The current tool catalog:

| Tool | Tier | Side effects | Approval | Rate limit |
|---|---|---|---|---|
| {{TOOL_1_NAME}} | {{T}} | {{EFFECTS}} | {{APPROVAL}} | {{RATE}} |
| {{TOOL_2_NAME}} | {{T}} | {{EFFECTS}} | {{APPROVAL}} | {{RATE}} |
| {{TOOL_3_NAME}} | {{T}} | {{EFFECTS}} | {{APPROVAL}} | {{RATE}} |

Complete the table per actual catalog. Buyers will ask for the full list; don't abbreviate.

---

## 5. Session scoping

Every AI session begins with a scoping step that determines:

- The authenticated user and their granted permissions.
- The tenant (customer workspace) the session operates within.
- The allowed tool set for this session (intersection of user permissions and any session-scoped overrides).
- The approval policy for Tier 2+ actions (default: ask; configurable per tenant).

Scoping is **immutable for the session duration**. The model cannot request expanded scope mid-session; if a needed tool is outside scope, the request is rejected and the user is prompted (in the UI, not via the agent) to request elevated access.

---

## 6. Cross-tenant isolation

Agents are tenant-scoped by architectural invariant:

- Retrieval operations are filtered by tenant ID at the data layer, not at the model layer.
- Tool calls include the session's tenant ID as a required parameter; tools validate the target resource belongs to that tenant before acting.
- Embeddings, logs, and audit records are namespaced by tenant.
- No configuration option allows a session to operate across tenants.

A cross-tenant breach would require a bypass of the authorization service itself, not of the agent.

---

## 7. Delegation and on-behalf-of

When a user delegates an action to an agent (e.g., "handle these 12 invoices"), the delegation:

- Is recorded in the audit log with explicit user authorization.
- Expires after {{DELEGATION_TTL}} or on task completion, whichever is earlier.
- Does not survive across sessions or user logins.
- Cannot elevate privileges above the user's own scope.

Autonomous multi-step execution within a delegation is permitted at Tier 0–1. Each Tier 2+ step within a delegation triggers a fresh human approval unless the user explicitly grants batch approval (with a maximum batch size of {{BATCH_APPROVAL_LIMIT}}).

---

## 8. Error handling and kill switches

### 8.1. Tool-call errors

- **Authorization failure**: request rejected, logged, session-visible error. Model can propose an alternative but not retry the same call.
- **Parameter validation failure**: request rejected, logged. Model is shown the validation error and may retry with corrected parameters, up to {{RETRY_LIMIT}} attempts per session.
- **Rate limit hit**: request rejected, logged with rate-limit reason. Model is informed; user is notified.
- **Downstream tool failure**: error surfaced to model with sanitized message; user notified with clear error UI.

### 8.2. Kill switches

- **Per-tool kill switch**: feature flag to disable any specific tool globally. Propagates to all active sessions within {{KILL_SWITCH_SLA}}.
- **Per-tier kill switch**: disable all Tier 2 or Tier 3 tools globally.
- **Tenant-level kill switch**: a customer can disable agent actions for their tenant with immediate effect.

### 8.3. Anomaly triggers

Automatic throttling engages on:

- Unusual volume of tool-call rejections from a single session.
- Unusual geographic origin relative to session history.
- Pattern match against known adversarial sequences.

Triggered sessions are forced to re-authenticate; persistent anomalies page on-call.

---

## 9. Logging and audit

Every tool call produces an audit record containing:

- Session ID, user ID, tenant ID.
- Timestamp, tool name, tool version.
- Full parameter payload.
- Authorization decision (allow / deny + reason).
- Human approval record (for Tier 2+).
- Side-effect confirmation.
- Latency and downstream response code.

Audit records are retained for {{AGENT_AUDIT_RETENTION}} days and available for customer export. Tier 3 records are additionally hash-chained for tamper evidence.

---

## 10. Incident response

Agent-action incidents are triaged by tier:

- **Tier 3 unauthorized execution**: immediate kill switch, customer notification within {{TIER_3_INCIDENT_SLA}} hours, regulatory notification where required.
- **Tier 2 unauthorized execution**: kill switch for affected tool, customer notification within {{TIER_2_INCIDENT_SLA}} hours.
- **Tier 0/1 unauthorized read**: customer notification within {{TIER_01_INCIDENT_SLA}} hours.

Detailed procedure in the AI Incident Response Runbook.

---

## 11. Verification and attestation

The signed hash of this policy is published on {{COMPANY}}'s AI Trust Page:

> **{{TRUST_PAGE_URL}}**

Canonical SHA-256:

> `{{DOCUMENT_SHA256_HASH}}`

Document attested and timestamped by AI Trust Desk on behalf of {{COMPANY}}.

---

## Signatures

**Prepared by:** {{AUTHOR_NAME}}, {{AUTHOR_TITLE}}
**Reviewed by:** {{SECURITY_LEAD_NAME}}, {{SECURITY_LEAD_TITLE}}
**Approved by:** {{CTO_NAME}}, CTO
