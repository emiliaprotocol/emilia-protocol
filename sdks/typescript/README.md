# @emilia-protocol/sdk

**Portable trust for machine counterparties.**

The official TypeScript SDK for the [EMILIA Protocol](https://emiliaprotocol.ai) — the trust infrastructure for the age of AI agents, autonomous software, and machine-to-machine commerce.

EMILIA maps to six design pillars: **E**vidence, **M**ediation, **I**dentity, **L**ineage, **I**nvocation, **A**ppeals.

> Constitutional principle: **trust must never be more powerful than appeal.**

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Core Concepts](#core-concepts)
- [API Reference](#api-reference)
  - [Trust Profile](#trust-profile)
  - [Trust Evaluation](#trust-evaluation)
  - [Trust Gate](#trust-gate)
  - [Domain Scores](#domain-scores)
  - [Install Preflight](#install-preflight)
  - [Entities](#entities)
  - [Receipts](#receipts)
  - [Disputes & Due Process](#disputes--due-process)
  - [Delegation](#delegation)
  - [Identity Continuity](#identity-continuity)
  - [Policies](#policies)
  - [System](#system)
- [Error Handling](#error-handling)
- [TypeScript Usage](#typescript-usage)
- [Links](#links)
- [License](#license)

---

## Installation

```bash
npm install @emilia-protocol/sdk
```

Requires Node.js 18 or later (native `fetch` is used).

---

## Quick Start

```typescript
import { EPClient } from '@emilia-protocol/sdk';

const ep = new EPClient({ apiKey: process.env.EP_API_KEY });

const profile = await ep.trustProfile('merchant-xyz');
console.log(profile.current_confidence);           // "confident"
console.log(profile.trust_profile?.behavioral?.completion_rate); // 97.2

const evaluation = await ep.trustEvaluate('merchant-xyz', 'strict');
if (!evaluation.pass) throw new Error(`Trust check failed: ${evaluation.failures?.join(', ')}`);
```

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `EP_API_KEY` | Your EP API key (`ep_live_...`). Required for write operations. | — |
| `EP_BASE_URL` | Override the API base URL (useful for local dev). | `https://emiliaprotocol.ai` |

You can also pass these directly to the constructor:

```typescript
const ep = new EPClient({
  apiKey: 'ep_live_...',
  baseUrl: 'http://localhost:3000', // local dev
  timeout: 10_000,                  // 10 seconds (default: 30s)
});
```

---

## Core Concepts

### Trust Profile

The trust profile is the canonical EP read surface. It aggregates behavioral rates, signal scores, provenance breakdown, consistency, anomaly detection, and dispute history into a single structured object. Always start here.

```
profile.current_confidence  → "pending" | "insufficient" | "provisional" | "emerging" | "confident"
profile.trust_profile.behavioral.completion_rate  → float (0-100)
profile.trust_profile.signals.delivery_accuracy   → float (0-100)
profile.trust_profile.provenance.bilateral_rate   → float (0-100)
profile.anomaly                                   → present only when anomaly detected
```

### Receipts

Receipts are the atomic unit of evidence in EP. Every interaction between principals generates a receipt. Receipts are:

- **Append-only** — cannot be edited or deleted
- **Cryptographically hashed** — SHA-256 of the canonical payload
- **Chain-linked** — each receipt references the previous hash for the entity
- **Anchored** — periodically committed to a Merkle root for external verification

The `agent_behavior` field is the strongest Phase 1 signal. Always set it.

### Policy Evaluation

Policies define trust thresholds. EP ships 8 named policies:

| Policy | Family | Use case |
|---|---|---|
| `strict` | core | High-value transactions, sensitive data |
| `standard` | core | Normal commerce, default |
| `permissive` | core | Low-risk interactions |
| `discovery` | core | Allow unevaluated entities to participate |
| `mcp_server_safe_v1` | software | MCP server installation |
| `npm_buildtime_safe_v1` | software | npm package installation in CI |
| `browser_extension_safe_v1` | software | Browser extension installation |
| `github_private_repo_safe_v1` | software | GitHub App with private repo access |

### Trust Gate

The trust gate is a pre-action decision surface that combines trust evaluation with delegation verification. Call it before any high-stakes autonomous action. It returns `allow | block | review | deny` with appeal paths for non-allow decisions.

### Due Process

EP enforces a mandatory due process pipeline for every negative trust event:

1. **Dispute** — any affected party can challenge a receipt
2. **Response** — the receipt submitter has 7 days to respond
3. **Resolution** — EP resolves with rationale (`upheld | reversed | dismissed`)
4. **Appeal** — participants can appeal the resolution
5. **Human Report** — no auth required; any human can report trust issues

---

## API Reference

### Trust Profile

#### `ep.trustProfile(entityId)`

Get an entity's full trust profile. This is the canonical EP read surface.

```typescript
const profile = await ep.trustProfile('merchant-xyz');

console.log(profile.entity_id);                              // "merchant-xyz"
console.log(profile.display_name);                           // "Merchant XYZ"
console.log(profile.current_confidence);                     // "confident"
console.log(profile.historical_establishment);               // true
console.log(profile.effective_evidence_current);             // 42
console.log(profile.receipt_count);                          // 57
console.log(profile.unique_submitters);                      // 12

// Behavioral rates
const b = profile.trust_profile?.behavioral;
console.log(b?.completion_rate);   // 97.2
console.log(b?.retry_rate);        // 1.8
console.log(b?.abandon_rate);      // 0.5
console.log(b?.dispute_rate);      // 0.5

// Signal scores
const s = profile.trust_profile?.signals;
console.log(s?.delivery_accuracy); // 96.1
console.log(s?.product_accuracy);  // 94.8
console.log(s?.price_integrity);   // 99.2
console.log(s?.return_processing); // 88.0

// Provenance
const prov = profile.trust_profile?.provenance;
console.log(prov?.breakdown);        // { bilateral: 0.6, self_attested: 0.4 }
console.log(prov?.bilateral_rate);   // 60

// Disputes
console.log(profile.disputes?.total);    // 2
console.log(profile.disputes?.active);   // 0
console.log(profile.disputes?.reversed); // 1

// Anomaly detection (only present when triggered)
if (profile.anomaly) {
  console.warn(profile.anomaly.alert); // "Sudden drop: 23 points in 7 days"
}

// Legacy score (fallback only — prefer trust_profile for decisions)
console.log(profile.compat_score); // 91
```

---

### Trust Evaluation

#### `ep.trustEvaluate(entityId, policy?, context?)`

Evaluate an entity against a named trust policy.

```typescript
// Basic evaluation
const result = await ep.trustEvaluate('merchant-xyz', 'standard');
console.log(result.pass);       // true
console.log(result.confidence); // "confident"

// With context for context-aware evaluation
const strict = await ep.trustEvaluate('merchant-xyz', 'strict', {
  category: 'furniture',
  geo: 'US-CA',
  value_band: 'high',
});

if (!strict.pass) {
  console.error('Failures:', strict.failures);
  // e.g. ["insufficient_evidence_current", "dispute_rate_too_high"]
  console.warn('Warnings:', strict.warnings);
}

// Check which policy was applied (useful when policies cascade)
console.log(strict.policy_used); // "strict"
```

---

### Trust Gate

#### `ep.trustGate(options)`

Pre-action trust check. Combines trust evaluation with delegation verification.

```typescript
const gate = await ep.trustGate({
  entityId: 'payment-agent-v2',
  action: 'execute_payment',
  policy: 'strict',
  valueUsd: 750,
});

// gate.decision: "allow" | "review" | "deny"
if (gate.decision === 'allow') {
  // Proceed with action
} else {
  console.error('Gate denied:', gate.reasons);
  console.log('Appeal path:', gate.appeal_path);
}

// With delegation verification
const gateWithDelegation = await ep.trustGate({
  entityId: 'acme-payment-agent',
  action: 'purchase',
  policy: 'standard',
  valueUsd: 200,
  delegationId: 'ep_del_abc123',
});
console.log(gateWithDelegation.delegation_verified); // true
```

---

### Domain Scores

#### `ep.domainScore(entityId, domains?)`

Get trust scores broken down by domain. Useful when you need trust context scoped to a specific action category.

```typescript
// All domains
const all = await ep.domainScore('agent-v2');
console.log(all.domains.financial?.confidence);    // "confident"
console.log(all.domains.code_execution?.confidence); // "provisional"

// Filtered to specific domains
const relevant = await ep.domainScore('agent-v2', ['financial', 'delegation']);
console.log(relevant.domains.financial?.completion_rate); // 98.1
console.log(relevant.domains.delegation?.dispute_rate);   // 0.2
```

---

### Install Preflight

#### `ep.installPreflight(entityId, policy?, context?)`

EP-SX: Software install preflight check. Use before installing any plugin, package, extension, MCP server, or marketplace app.

```typescript
// MCP server
const mcp = await ep.installPreflight(
  'mcp-server-acme-v1',
  'mcp_server_safe_v1',
  { host: 'claude-desktop', permission_class: 'bounded_external_access' },
);

console.log(mcp.decision);    // "allow" | "review" | "deny"
console.log(mcp.confidence);  // "confident"
console.log(mcp.reasons);     // present for review/deny
console.log(mcp.software_meta?.publisher_verified);  // true
console.log(mcp.software_meta?.permission_class);    // "bounded_external_access"

if (mcp.decision === 'deny') throw new Error('Installation blocked by EP trust policy');
if (mcp.decision === 'review') console.warn('Manual review recommended before installing');

// npm package
const pkg = await ep.installPreflight(
  'npm:acme-build-plugin',
  'npm_buildtime_safe_v1',
  { execution_mode: 'build_only' },
);

// Browser extension
const ext = await ep.installPreflight(
  'chrome_extension:acme-helper',
  'browser_extension_safe_v1',
  { data_sensitivity: 'low' },
);

// GitHub App
const app = await ep.installPreflight(
  'github_app:acme/code-review',
  'github_private_repo_safe_v1',
  { install_scope: 'private_repos' },
);
```

---

### Entities

#### `ep.registerEntity(options)`

Register a new entity. Public endpoint — no API key required. Save the returned `api_key` securely; it will not be shown again.

```typescript
const { entity, api_key } = await ep.registerEntity({
  entityId: 'acme-payment-agent',
  displayName: 'Acme Payment Agent',
  entityType: 'agent',
  description: 'Handles autonomous payment flows for Acme Corp.',
  capabilities: ['payment', 'refund', 'dispute_resolution'],
});

console.log(entity.entity_id); // "acme-payment-agent"
console.log(api_key);          // "ep_live_..." — store this securely!
```

#### `ep.searchEntities(query, entityType?, minConfidence?)`

Search for entities by name, capability, or category.

```typescript
const { entities } = await ep.searchEntities('payment', 'agent', 'confident');

for (const e of entities) {
  console.log(`${e.display_name} (${e.entity_id}): ${e.confidence}`);
}
```

#### `ep.leaderboard(limit?, entityType?)`

Get the leaderboard of top-trusted entities.

```typescript
// Top 5 merchants
const { leaderboard } = await ep.leaderboard(5, 'merchant');
leaderboard.forEach(e => console.log(`#${e.rank} ${e.display_name} — ${e.confidence}`));
```

---

### Receipts

#### `ep.submitReceipt(input)`

Submit a single transaction receipt. Requires an API key.

```typescript
const { receipt } = await ep.submitReceipt({
  entity_id: 'merchant-xyz',
  transaction_ref: 'order-8821',        // Required — must be unique per entity
  transaction_type: 'purchase',
  agent_behavior: 'completed',          // Strongest signal — always set this
  delivery_accuracy: 98,
  product_accuracy: 95,
  price_integrity: 100,
  return_processing: 88,
  claims: {
    delivered: true,
    on_time: true,
    price_honored: true,
    as_described: true,
  },
  context: {
    category: 'electronics',
    geo: 'US-NY',
    value_band: 'medium',
  },
});

console.log(receipt.receipt_id);   // "ep_rcpt_..."
console.log(receipt.receipt_hash); // SHA-256 hash
```

#### `ep.batchSubmit(receipts)`

Submit up to 50 receipts in a single atomic call. Partial success is possible.

```typescript
const result = await ep.batchSubmit([
  {
    entity_id: 'merchant-a',
    transaction_ref: 'tx-001',
    transaction_type: 'purchase',
    agent_behavior: 'completed',
  },
  {
    entity_id: 'merchant-b',
    transaction_ref: 'tx-002',
    transaction_type: 'service',
    agent_behavior: 'completed',
  },
]);

result.results.forEach(r => {
  if (r.success) console.log(`${r.entity_id}: receipt ${r.receipt_id}`);
  else console.error(`${r.entity_id}: ${r.error}`);
});
```

#### `ep.confirmReceipt(receiptId, confirm)`

Bilateral confirmation — counterparty confirms or rejects a receipt within 48 hours. Confirmed receipts receive a higher provenance tier.

```typescript
// Confirm as the counterparty
await ep.confirmReceipt('ep_rcpt_abc123', true);

// Reject (triggers dispute-like flow)
await ep.confirmReceipt('ep_rcpt_abc123', false);
```

#### `ep.verifyReceipt(receiptId)`

Verify receipt hash integrity and Merkle root anchoring.

```typescript
const { verified, anchored, receipt_hash } = await ep.verifyReceipt('ep_rcpt_abc123');

if (!verified) console.error('Receipt integrity check FAILED — possible tampering');
if (!anchored) console.log('Receipt not yet anchored — check back after next anchor cycle');
```

---

### Disputes & Due Process

#### `ep.fileDispute(options)`

File a dispute against a receipt. Any affected party can challenge.

```typescript
const dispute = await ep.fileDispute({
  receiptId: 'ep_rcpt_abc123',
  reason: 'inaccurate_signals',           // See DisputeReason type for all options
  description: 'Delivery accuracy was reported as 98 but item arrived damaged.',
  evidence: { photo_url: 'https://cdn.example.com/damage-photo.jpg' },
});

console.log('Dispute ID:', dispute.dispute_id);
console.log('Respond by:', dispute.response_deadline); // 7-day window
```

Valid `reason` values: `fraudulent_receipt` | `inaccurate_signals` | `identity_dispute` | `context_mismatch` | `duplicate_transaction` | `coerced_receipt` | `other`

#### `ep.disputeStatus(disputeId)`

Check dispute status. Public — transparency is a protocol value.

```typescript
const dispute = await ep.disputeStatus('ep_disp_xyz789');

console.log(dispute.status);              // "pending" | "responded" | "upheld" | "reversed" | "dismissed"
console.log(dispute.reason);             // "inaccurate_signals"
console.log(dispute.entity?.entity_id);  // "merchant-xyz"
console.log(dispute.response);           // submitter's response (if provided)
console.log(dispute.resolution);         // resolution decision (if resolved)
console.log(dispute.resolution_rationale);
```

#### `ep.respondToDispute(options)`

Respond to a dispute filed against one of your receipts.

```typescript
await ep.respondToDispute({
  disputeId: 'ep_disp_xyz789',
  response: 'The accuracy score reflects carrier handoff state, confirmed by tracking log.',
  evidence: { tracking_log: 'https://carrier.example.com/track/8821' },
});
```

#### `ep.withdrawDispute(disputeId)`

Withdraw an open dispute before resolution.

```typescript
await ep.withdrawDispute('ep_disp_xyz789');
```

#### `ep.appealDispute(options)`

Appeal a dispute resolution. Only dispute participants may appeal. The dispute must be in `upheld`, `reversed`, or `dismissed` state. Appeal decisions are final.

```typescript
await ep.appealDispute({
  disputeId: 'ep_disp_xyz789',
  reason: 'The carrier log submitted in the response was from a different shipment.',
  evidence: { corrected_manifest: 'https://...' },
});
```

#### `ep.reportTrustIssue(options)`

Human appeal channel. No authentication required.

```typescript
// No API key needed
const report = await ep.reportTrustIssue({
  entityId: 'merchant-xyz',
  reportType: 'harmed_by_trusted_entity',
  description: 'Paid for an item marked delivered but never received. Order #8821.',
  contactEmail: 'jane@example.com',   // Optional — for EP follow-up
});

console.log(report.report_id);  // "ep_report_..."
console.log(report._principle); // "Trust must never be more powerful than appeal."
```

Valid `reportType` values: `wrongly_downgraded` | `harmed_by_trusted_entity` | `fraudulent_entity` | `inaccurate_profile` | `fake_receipts` | `unsafe_software` | `misleading_identity` | `terms_violation` | `demo_challenge` | `other`

---

### Delegation

#### `ep.createDelegation(options)`

Create a delegation record authorizing an agent to act on behalf of a principal.

```typescript
const delegation = await ep.createDelegation({
  principalId: 'ep_principal_acme',
  agentEntityId: 'acme-payment-agent',
  scope: ['purchase', 'refund'],
  maxValueUsd: 1000,
  expiresAt: '2026-12-31T23:59:59Z',
  constraints: { require_confirmation_above_usd: 500 },
});

console.log('Delegation ID:', delegation.delegation_id);
console.log('Status:', delegation.status);  // "active"
```

#### `ep.verifyDelegation(delegationId, actionType?)`

Verify a delegation is valid and covers a specific action.

```typescript
const result = await ep.verifyDelegation('ep_del_abc123', 'purchase');

console.log(result.valid);            // true
console.log(result.action_permitted); // true
console.log(result.status);           // "active"
console.log(result.expires_at);       // "2026-12-31T23:59:59Z"

if (!result.valid) throw new Error(`Delegation invalid: ${result.reason}`);
```

---

### Identity Continuity

#### `ep.principalLookup(principalId)`

Look up a principal — the enduring actor behind one or more entities.

```typescript
const result = await ep.principalLookup('ep_principal_acme');

console.log(result.principal.display_name);       // "Acme Corp"
console.log(result.principal.principal_type);     // "organization"
console.log(result.principal.bootstrap_verified); // true

// Controlled entities
result.entities?.forEach(e => {
  console.log(`${e.display_name} (${e.entity_type}): ${e.entity_id}`);
});

// Identity bindings (e.g. domain, GitHub org)
result.bindings?.forEach(b => {
  console.log(`${b.binding_type}: ${b.binding_target} [${b.status}]`);
});

// Continuity history
result.continuity_claims?.forEach(c => {
  console.log(`${c.old_entity_id} → ${c.new_entity_id} (${c.reason}) [${c.status}]`);
});
```

#### `ep.lineage(entityId)`

View entity lineage — predecessors and successors. Use to detect reputation laundering.

```typescript
const lineage = await ep.lineage('merchant-xyz');

// Check for suspicious predecessor gaps
if (lineage.predecessors?.some(p => p.status === 'disputed')) {
  console.warn('Entity has disputed predecessor — investigate before transacting');
}

lineage.predecessors?.forEach(p => {
  console.log(`← ${p.from} (${p.reason}) [${p.status}] transfer: ${p.transfer_policy}`);
});

lineage.successors?.forEach(s => {
  console.log(`→ ${s.to} (${s.reason}) [${s.status}]`);
});
```

---

### Policies

#### `ep.listPolicies()`

List all available trust policies.

```typescript
const { policies } = await ep.listPolicies();

policies.forEach(p => {
  console.log(`${p.name} [${p.family}]`);
  console.log(`  ${p.description}`);
  if (p.min_confidence) console.log(`  min confidence: ${p.min_confidence}`);
});
```

---

### System

#### `ep.stats()`

Public proof metrics.

```typescript
const stats = await ep.stats();
console.log(`${stats.total_entities} entities`);
console.log(`${stats.trust_policies} trust policies`);
console.log(`${stats.mcp_tools} MCP tools`);
```

#### `ep.health()`

Health check.

```typescript
const health = await ep.health();
console.log(health.status); // "ok"
```

#### `ep.legacyScore(entityId)` (deprecated)

Returns the 0-100 legacy compatibility score. Prefer `trustProfile()` for all new code.

```typescript
const { score } = await ep.legacyScore('merchant-xyz');
console.log(score); // 91
```

---

## Error Handling

All methods throw `EPError` on failure. `EPError` extends `Error` with `status` (HTTP status code) and `code` (API error code).

```typescript
import { EPClient, EPError } from '@emilia-protocol/sdk';

const ep = new EPClient({ apiKey: process.env.EP_API_KEY });

try {
  const profile = await ep.trustProfile('unknown-entity');
} catch (err) {
  if (err instanceof EPError) {
    console.error(`EP error ${err.status}: ${err.message}`);
    // err.status === 404 → entity not found
    // err.status === 401 → missing or invalid API key
    // err.status === 429 → rate limited
    // err.code === 'timeout' → request timed out
    // err.code === 'network_error' → network failure
  } else {
    throw err; // unexpected error — re-throw
  }
}
```

### Common status codes

| Status | Meaning |
|---|---|
| `401` | Missing or invalid API key |
| `403` | Insufficient permissions for this operation |
| `404` | Entity, receipt, or dispute not found |
| `409` | Conflict (e.g. duplicate transaction_ref) |
| `422` | Validation error — check request body |
| `429` | Rate limited |

---

## TypeScript Usage

The SDK is fully typed. All types are exported from the package root.

```typescript
import {
  EPClient,
  EPError,
  // Enumerations
  type EntityType,
  type TrustPolicy,
  type AgentBehavior,
  type TransactionType,
  type DisputeReason,
  type TrustDomain,
  type ConfidenceTier,
  // Response types
  type EntityTrustProfile,
  type TrustEvaluation,
  type TrustGateResult,
  type InstallPreflightResult,
  type Receipt,
  type Dispute,
  type DelegationRecord,
  // Input types
  type SubmitReceiptInput,
  type TrustContext,
  type EPClientOptions,
} from '@emilia-protocol/sdk';

// Type-safe client construction
const options: EPClientOptions = {
  apiKey: process.env.EP_API_KEY,
  timeout: 15_000,
};
const ep = new EPClient(options);

// Type-safe receipt submission
const input: SubmitReceiptInput = {
  entity_id: 'merchant-xyz',
  transaction_ref: `order-${Date.now()}`,
  transaction_type: 'purchase',
  agent_behavior: 'completed',
  delivery_accuracy: 98,
};
const { receipt } = await ep.submitReceipt(input);

// Type-safe context
const context: TrustContext = {
  category: 'electronics',
  geo: 'US-CA',
  value_band: 'high',
};
const evaluation = await ep.trustEvaluate('merchant-xyz', 'strict', context);

// Narrowing on confidence tier
function isHighConfidence(confidence: ConfidenceTier): boolean {
  return confidence === 'confident' || confidence === 'emerging';
}
```

### Using with custom fetch (e.g. for testing)

```typescript
import { EPClient } from '@emilia-protocol/sdk';

const mockFetch: typeof fetch = async (url, init) => {
  // Return mock responses for testing
  return new Response(JSON.stringify({ entity_id: 'test', current_confidence: 'confident' }));
};

const ep = new EPClient({ fetchImpl: mockFetch });
```

---

## Links

- [emiliaprotocol.ai](https://emiliaprotocol.ai)
- [EP Core RFC](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CORE-RFC.md)
- [OpenAPI Specification](https://github.com/emiliaprotocol/emilia-protocol/blob/main/openapi.yaml)
- [MCP Server](https://github.com/emiliaprotocol/emilia-protocol/tree/main/mcp-server)
- [Conformance Vectors](https://github.com/emiliaprotocol/emilia-protocol/tree/main/conformance)
- [Issues](https://github.com/emiliaprotocol/emilia-protocol/issues)

---

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
