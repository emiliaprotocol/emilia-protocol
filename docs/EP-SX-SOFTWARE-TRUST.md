# EP-SX — Software Trust Extension

**Version:** 0.1-draft
**Status:** Proposal
**Extends:** EP Core RFC v1.1
**License:** Apache-2.0

---

## 1. Purpose

EP Core answers: "Should you trust this merchant/agent?"
EP-SX answers: "Should you install this plugin/app/package/extension/MCP server?"

Every ecosystem has fragments of trust — permissions, publisher verification, download counts, marketplace reviews. None provide a portable, policy-evaluable trust profile across ecosystems.

EP-SX extends EP to third-party software: GitHub Apps, npm packages, Chrome extensions, Shopify apps, MCP servers, and marketplace plugins.

**The canonical question is not "is this safe?" but:**

> Is this safe enough for this host, this permission scope, this data sensitivity, and this policy?

---

## 2. Entity Types

EP-SX adds software-specific entity types:

| Entity Type | Example |
|------------|---------|
| `github_app` | `github_app:acme/code-helper` |
| `github_action` | `github_action:actions/checkout` |
| `mcp_server` | `mcp_server:acme/repo-tools` |
| `npm_package` | `npm_package:@acme/auth-sdk` |
| `chrome_extension` | `chrome_extension:abcdef123456` |
| `shopify_app` | `shopify_app:acme-inventory` |
| `marketplace_plugin` | `marketplace_plugin:vendor/widget` |
| `agent_tool` | `agent_tool:acme/search-tool` |

All existing EP entity types (agent, merchant, service_provider) continue to work.

---

## 3. Context Key for Software

For software trust, context is everything. The same plugin can be safe in one context and dangerous in another.

```json
{
  "host": "github",
  "install_scope": "selected_repos",
  "permission_class": "read_only",
  "data_sensitivity": "private_code",
  "execution_mode": "hosted",
  "org_tier": "enterprise"
}
```

Standard context fields for EP-SX:

| Field | Values (examples) | What it captures |
|-------|------------------|-----------------|
| `host` | github, npm, chrome, shopify, mcp | Which ecosystem |
| `install_scope` | all_repos, selected_repos, single_repo | How much access |
| `permission_class` | read_only, read_write, admin, code_execution | What it can do |
| `data_sensitivity` | public, internal, private_code, pii, financial | What it can see |
| `execution_mode` | hosted, local, sandboxed, privileged | Where it runs |
| `org_tier` | personal, team, enterprise | Who is using it |

---

## 4. Trust Dimensions for Software

A software trust profile has six dimensions:

### 4.1 Publisher Trust
Who built this, and is that identity meaningful?

Signals: publisher_verified, org_verified, maintainer_count, account_age, prior_entity_trust

### 4.2 Permission Risk
What can this thing actually do?

Signals: declared_permissions, permission_class, scope_breadth, escalation_history

### 4.3 Provenance Trust
Can we verify how it was built and published?

Signals: trusted_publishing, provenance_verified, signature_verified, build_transparency, source_available

### 4.4 Runtime Trust
How has it behaved over time?

Signals: execution_success_rate, incident_rate, revoke_rate, uninstall_rate, anomaly_state

### 4.5 Responsiveness
How fast does the maintainer respond?

Signals: median_response_hours, dispute_resolution_time, advisory_response_time

### 4.6 Human-Contested Trust
Can affected users report harm? Can the system correct?

Signals: active_disputes, reversed_receipts, human_reports, appeal_outcomes

---

## 5. Receipt Types for Software

### Identity and Listing
- `publisher_verified`
- `listing_review_passed`
- `listing_removed`
- `policy_violation_recorded`

### Install and Scope
- `install_granted`
- `install_restricted`
- `install_revoked`
- `permission_scope_selected`
- `permission_escalation_requested`
- `permission_escalation_approved`
- `permission_escalation_denied`

### Provenance
- `artifact_published`
- `provenance_verified`
- `trusted_publishing_verified`
- `signature_verified`
- `publisher_identity_mismatch`

### Runtime
- `execution_succeeded`
- `execution_failed`
- `unsafe_behavior_reported`
- `incident_opened`
- `incident_resolved`

### Human Layer
- `human_report_filed`
- `maintainer_response_submitted`
- `operator_adjudication_upheld`
- `operator_adjudication_reversed`

---

## 6. Policy Templates

### GitHub Private Repo Safe
```json
{
  "policy_id": "github_private_repo_safe_v1",
  "host": "github",
  "requirements": {
    "publisher_verified": true,
    "max_permission_class": "read_only",
    "install_scope": "selected_repos",
    "max_active_disputes": 0,
    "min_provenance_score": 80,
    "reject_severe_anomaly": true
  }
}
```

### npm Build-Time Safe
```json
{
  "policy_id": "npm_buildtime_safe_v1",
  "host": "npm",
  "requirements": {
    "trusted_publishing": true,
    "provenance_verified": true,
    "max_active_disputes": 0,
    "max_recent_incidents": 0,
    "min_runtime_score": 75
  }
}
```

### Browser Extension Safe
```json
{
  "policy_id": "browser_extension_safe_v1",
  "host": "chrome",
  "requirements": {
    "listing_review_passed": true,
    "max_permission_class": "limited_content_read",
    "max_site_scope": "declared_sites_only",
    "max_active_disputes": 0,
    "reject_severe_anomaly": true
  }
}
```

### MCP Server Safe
```json
{
  "policy_id": "mcp_server_safe_v1",
  "host": "mcp",
  "requirements": {
    "registry_listed": true,
    "server_card_present": true,
    "publisher_verified": true,
    "max_permission_class": "bounded_external_access",
    "max_active_disputes": 0,
    "min_provenance_score": 70
  }
}
```

---

## 7. Install Preflight Flow

The canonical EP-SX flow for "should I install this?"

**Step 1: Discover** — Find the entity via registry, marketplace, or well-known URL.

**Step 2: Normalize** — Map to EP entity + structured context key.

**Step 3: Evaluate** — Call `POST /api/trust/evaluate` with context and policy.

**Step 4: Decide** — Return pass/review/fail with specific reasons.

```json
POST /api/trust/evaluate
{
  "entity_id": "github_app:acme/code-helper",
  "policy": "github_private_repo_safe_v1",
  "context": {
    "host": "github",
    "install_scope": "selected_repos",
    "permission_class": "read_only",
    "data_sensitivity": "private_code"
  }
}

Response:
{
  "pass": true,
  "decision": "allow",
  "reasons": [
    "publisher verified",
    "selected repository scope",
    "permission class acceptable",
    "no active disputes",
    "provenance score 92 exceeds minimum 80"
  ],
  "confidence": "emerging",
  "context_used": { "host": "github", ... }
}
```

---

## 8. Human Layer Rules

**Constitutional rule: Humans may trigger review, but they do not directly write trust truth.**

| Tier | Action | Trust Impact |
|------|--------|-------------|
| Report | Creates a case | No direct impact |
| Dispute | Structured challenge against a receipt | Provisional flag, not final downgrade |
| Adjudication | Operator/reviewer resolves | Can reverse, uphold, or dismiss |

This prevents mob dynamics while preserving procedural justice.

---

## 9. Evidence Visibility Tiers

| Tier | Visible to | Content |
|------|-----------|---------|
| Public | Everyone | Safe summary ("incident resolved", "publisher verified") |
| Redacted | Everyone | Partial evidence with sensitive data masked |
| Restricted | Operator, affected parties | Full evidence including screenshots, URLs, code refs |

---

## 10. Discovery

Software entities should be discoverable via:

```
GET /.well-known/ep-trust.json
```

Extended for EP-SX:
```json
{
  "ep_extension": "software_trust_v1",
  "supported_hosts": ["github", "npm", "chrome", "mcp", "shopify"],
  "install_preflight_url": "https://emiliaprotocol.ai/api/trust/evaluate",
  "software_report_url": "https://emiliaprotocol.ai/api/disputes/report"
}
```

---

## 11. Mission

> Portable trust evaluation and appeals for counterparties, software, and machine actors.

EP-SX extends this mission to every ecosystem where humans and agents install, authorize, or rely on third-party software. Commerce is the first vertical. Software trust is the broader application.

---

*EP-SX — Software Trust Extension v0.1-draft*
*Trust profiles for plugins, packages, apps, extensions, and agent tools.*
*Not "is this safe?" but "is this safe enough for this context and this policy?"*
