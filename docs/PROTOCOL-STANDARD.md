# EMILIA Protocol Standard v1.0

**Document Status:** Proposed Standard
**Version:** 1.0
**Date:** 2026-03-18
**License:** Apache-2.0
**Authors:** EMILIA Protocol Contributors

---

## Abstract

The proliferation of AI agents as economic actors — executing purchases, brokering services, routing tasks, and operating autonomously across organizational boundaries — has outpaced the infrastructure necessary to assess their behavioral integrity. No shared layer exists for establishing whether an agent, merchant, or software component has earned trust through observable conduct. Systems that need to answer "should I transact with this counterparty?" must either rely on platform-specific reputation systems that do not transfer, accept opaque vendor assertions, or operate without any behavioral signal at all. This absence creates compounding risk: as agents are granted increasing autonomy and economic authority, the cost of misplaced trust grows faster than any organization's ability to audit it manually.

The EMILIA Protocol defines a portable, vendor-neutral behavioral trust layer for machine-mediated systems. Its core primitive is the Trust Receipt — a cryptographically anchored record of a transaction outcome, submitted by the transacting party after the fact. Receipts accumulate into an append-only ledger. From this ledger, a multi-dimensional Trust Profile is derived through graph-analyzed, evidence-weighted scoring that is resistant to Sybil attacks, closed-loop manipulation, and synthetic volume. Agents consuming the protocol evaluate counterparties not against a single score but against structured Trust Policies that express their own risk tolerance across behavioral dimensions.

The goal of this document is to specify EMILIA Protocol v1.0 as an implementation-independent standard. Any system — an agent framework, a marketplace, an orchestration platform, a developer tool — MUST be able to implement a conformant EP node using only this document. No implementation is authoritative over this specification. Where implementation code and this document conflict, this document wins.

---

## Core vs Extension: Section Classification

This standard is organized into **EP Core** sections and **EP Extension** sections. A conformant minimal implementation MUST implement all Core sections. Extension sections are optional — they build on the core but are not required for basic interoperability.

**EP Core** (required for interoperability):
- Section 1: Introduction (motivation, design principles, terminology)
- Section 2: Entity Identity
- Section 3: Receipt Format
- Section 4: Trust Scoring
- Section 5: Sybil Resistance
- Section 6: Policy Evaluation
- Section 9: Security Properties
- Section 10: Implementation Requirements
- Section 11: Versioning
- Section 12: Governance
- Section 17: Conformance Requirements

**EP Extensions** (optional, adopt as needed):
- Section 7: Delegation Chain
- Section 8: Dispute Lifecycle
- Section 13: Privacy and Zero-Knowledge Proofs
- Section 14: Dispute Adjudication Standard
- Section 15: Attribution Chain Standard
- Section 16: Auto-Receipt Generation

**EP Product Surfaces** (not part of this standard): Explorer, leaderboards, operator dashboards, registry views, managed adjudication workflows, and hosted APIs are implementation choices, not protocol requirements.

---

## 1. Introduction

### 1.1 Motivation

Trust in human commercial systems is maintained through a layered combination of legal accountability, brand reputation, social proof, and financial rails that impose consequences for misbehavior. None of these mechanisms transfer cleanly to autonomous agent systems. Agents do not have brands in the traditional sense, are difficult to hold legally accountable across organizational boundaries, and move faster than reputation systems built for human-paced commerce.

The question EP answers is narrow and precise: **given the observable history of this entity's behavior in prior interactions, should you transact with it now, and under what conditions?**

EP does not answer whether an agent is aligned, safe, or beneficial in any philosophical sense. It answers whether a specific entity has behaved reliably enough in past transactions that a consuming agent should extend it trust for the next one.

### 1.2 Design Principles

Six principles are non-negotiable. Implementations MUST NOT compromise them.

**Append-only ledger.** Trust Receipts are permanent records. They cannot be deleted and cannot be substantively modified. The only permitted post-write operation on a receipt's weight is downward adjustment upon confirmed fraud detection. An auditor with access to the ledger at any point in time MUST be able to reconstruct the complete behavioral history of any entity.

**No self-scoring.** An entity cannot submit a Trust Receipt for itself. The submitter and the scored entity MUST be distinct. This eliminates the most trivially gameable failure mode of self-reported reputation systems.

**Due process above all.** Trust is never more powerful than the right to appeal it. Any affected party may dispute a receipt. Any human may file a trust report without authentication. The protocol imposes an obligation on implementors to investigate reports. A trust system that can harm a party without recourse is not a trust system — it is a control system.

**Sybil resistance by design.** The scoring model is constructed so that volume alone cannot manufacture credibility. Unestablished submitters contribute at most a capped quantum of effective evidence. Graph analysis penalizes closed-loop scoring, thin graphs, and cluster patterns. Registration rate limits constrain synthetic identity creation.

**Behavioral primacy.** Observable agent actions (did the agent complete, retry, abandon, or dispute?) carry more evidential weight than self-reported numeric scores. Actions are harder to fabricate credibly and more predictive of future routing behavior than opinions expressed as numbers.

**Open standard, not a product.** EP is specified as a protocol. No single implementation is canonical. The scoring algorithm, schema, and dispute lifecycle are published openly. Any party can audit them.

### 1.3 Terminology

The following terms carry precise meanings throughout this document. When used in this document without qualification, these definitions apply.

**Entity.** Any actor registered in an EP-conformant ledger that can send or receive Trust Receipts. Entities include agents, merchants, service providers, MCP servers, and software packages. An entity has a unique identifier, a type, and an append-only receipt history.

**Principal.** The human or organization behind one or more entities. A principal is the enduring accountable party. Multiple entities may share a principal.

**Trust Receipt (Receipt).** A cryptographically anchored record of a single transaction outcome, submitted by the party that initiated or observed the transaction. The receipt is the atomic unit of the EP ledger.

**Trust Profile.** The multi-dimensional output derived from an entity's receipt history. The Trust Profile is the primary protocol output. It includes behavioral rates, signal scores, consistency, confidence level, and anomaly data. A scalar compatibility score is provided for backward compatibility but is not the canonical output.

**Confidence.** A classification of how much credible evidence underlies a Trust Profile. Confidence advances through levels as quality-gated effective evidence accumulates. Confidence is distinct from score: a high confidence level indicates the profile is well-evidenced, not that the entity is well-behaved.

**Effective Evidence.** A scalar that quantifies the evidential weight of receipts in a scoring window, calculated as the sum of per-receipt weights, where each weight is the product of submitter weight, time weight, graph weight, and provenance weight.

**Quality-Gated Evidence.** Effective evidence capped to prevent unestablished submitters from manufacturing advancement through volume. Defined precisely in Section 4.

**Evidence.** Structured data attached to a receipt that substantiates its claims. Evidence is not interpreted by the protocol for truth; it is preserved for human and automated audit.

**Delegation.** A formal record authorizing an agent entity to act on behalf of a principal within defined scope and value limits. Behavioral outcomes produced while acting under delegation attach to the agent's Trust Profile and are traceable to the principal through the delegation record.

**Dispute.** A formal challenge to the accuracy or legitimacy of a specific Trust Receipt, filed by an affected party and following a defined lifecycle with obligatory response periods and appeal rights.

---

## 2. Entity Identity

### 2.1 Entity Types

Every entity registered with an EP-conformant implementation MUST declare one of the following types:

| Type | Description |
|---|---|
| `agent` | An AI agent that acts autonomously or semi-autonomously on behalf of a principal |
| `merchant` | A commercial entity offering goods |
| `service_provider` | An entity offering services, including professional services |
| `mcp_server` | A Model Context Protocol tool server |
| `npm_package` | A software package distributed through npm |
| `browser_extension` | A browser extension |
| `github_app` | A GitHub application |
| `other_software` | Any software entity not covered by the above |

Implementations MAY extend this enumeration. Extension type identifiers MUST be prefixed with a reverse-domain namespace (e.g., `com.example.custom_type`) to avoid collision with future standard types.

### 2.2 Entity ID Format

An Entity ID is the human-readable, stable identifier for an entity within the EP namespace.

**Format requirements:**

- Lowercase ASCII letters, digits, and hyphens only
- MUST begin with a letter or digit
- MUST NOT begin or end with a hyphen
- Maximum length: 64 characters
- Globally unique within a conformant EP implementation

**Examples of valid Entity IDs:** `rex-booking-v2`, `shopping-agent-prod`, `stripe-mcp-server-1`

**Examples of invalid Entity IDs:** `Rex_Booking`, `-agent`, `my agent`, `a` (too short to be descriptive; implementations SHOULD enforce a minimum length of 3 characters)

The Entity ID is immutable after registration. Changes in underlying software or agent versions MUST be reflected by registering a new entity with a lineage relationship to the prior entity (see Section 2.4).

### 2.3 Principal Binding

A Principal is identified by an `owner_id` — the credential identifier of the API key holder at registration time. Multiple entities may share a principal. This binding serves two purposes:

1. It enables rate limiting on entity registration to constrain Sybil attacks (Section 5.1).
2. It creates an audit trail linking agent behavior back to the accountable human or organization.

Principal binding is private by default. An implementation MAY expose principal information to dispute investigators and regulatory bodies. Implementations MUST NOT expose `owner_id` to arbitrary API consumers.

### 2.4 Identity Continuity

When an entity undergoes a material change — a version upgrade that alters behavior, a transfer of ownership, or a rebranding — the correct action is to register a new entity, not to modify the existing one.

**Lineage claims** allow a new entity to declare its relationship to a predecessor. A lineage claim is a statement, not a verification: it asserts that the new entity is a continuation of the prior one and does not inherit the prior entity's Trust Profile automatically. Consuming agents MAY choose to weight a lineage claim positively when evaluating an otherwise low-evidence entity.

**Whitewashing prevention.** An entity MUST NOT be used to launder a poor trust history. Implementations MUST flag and investigate cases where a new entity claims lineage to a high-trust predecessor but was registered shortly after the predecessor accumulated significant disputes or fraud flags. Graph analysis (Section 5) applies to lineage clusters.

---

## 3. Receipt Format

### 3.1 Required Fields

Every Trust Receipt MUST contain the following fields. A receipt submission missing any required field MUST be rejected.

```json
{
  "receipt_id": "ep_rcpt_{hex-32}",
  "entity_id": "target-entity-slug",
  "submitted_by": "submitter-entity-uuid",
  "transaction_ref": "external-transaction-identifier",
  "transaction_type": "purchase | service | task_completion | delivery | return",
  "provenance_tier": "unilateral | bilateral | verified | anchored",
  "receipt_hash": "sha256-hex",
  "chain_prev_hash": "sha256-hex | null",
  "created_at": "ISO-8601"
}
```

**`transaction_ref`** is a mandatory external transaction identifier. It MUST reference a transaction that exists outside the EP system. The combination of `(entity_id, submitted_by, transaction_ref)` MUST be unique; duplicate submissions MUST be treated as idempotent and return the existing receipt without creating a new one.

**`receipt_id`** MUST be formatted as `ep_rcpt_` followed by 32 hexadecimal characters derived from a cryptographically random source.

**`receipt_hash`** MUST be the SHA-256 hash of the canonical JSON serialization of all truth-bearing fields. Canonical serialization requires lexicographically sorted keys, no insignificant whitespace, and deterministic encoding of all value types. This hash is the receipt's cryptographic commitment.

**`chain_prev_hash`** MUST be the `receipt_hash` of the most recent prior receipt for the same `entity_id`. For the first receipt of an entity, this field is `null`. This links receipts into a tamper-evident chain: modifying any historical receipt invalidates all subsequent hashes.

### 3.2 Optional Signal Fields

Signal fields carry the behavioral and quality measurements that scoring is derived from. No single signal field is required, but a receipt MUST contain at least one field that produces a recognized derived signal. Submissions with no interpretable signal MUST be rejected.

**Agent Behavior (strongest signal in Phase 1)**

```
agent_behavior: "completed" | "retried_same" | "retried_different" | "abandoned" | "disputed"
```

This field records the purchasing agent's observable action following the transaction. It is not a rating. It is a behavioral fact. The mapping to score values is:

| Behavior | Score Value | Interpretation |
|---|---|---|
| `completed` | 95 | Transaction finished; agent did not retry or abandon |
| `retried_same` | 75 | Agent returned to the same counterparty for another attempt |
| `retried_different` | 40 | Agent switched counterparties for the same task category |
| `abandoned` | 15 | Agent ceased pursuing the task category entirely |
| `disputed` | 5 | Agent filed a formal dispute against the receipt |

**Numeric Signal Fields (0-100, self-reported in Phase 1)**

| Field | Description |
|---|---|
| `delivery_accuracy` | Congruence of promised vs. actual delivery timing |
| `product_accuracy` | Congruence of listing description vs. received goods or output |
| `price_integrity` | Congruence of quoted price vs. charged price |
| `return_processing` | Whether the counterparty's return or refund policy was honored |

All numeric signal fields MUST be in the range [0, 100]. Out-of-range values MUST be rejected, not clamped.

**Evidence-Backed Claims**

```json
{
  "claims": {
    "delivered": true,
    "on_time": { "promised": "ISO-8601", "actual": "ISO-8601" },
    "price_honored": { "quoted_cents": 4990, "charged_cents": 4990 },
    "as_described": true,
    "return_accepted": true
  },
  "evidence": {
    "tracking_id": "FDX-123456",
    "payment_ref": "stripe_pi_abc"
  }
}
```

Claims with recognized keys (`delivered`, `on_time`, `price_honored`, `as_described`, `return_accepted`) are translated into numeric signal scores at submission time. Claims with unrecognized keys are preserved in the record but produce no scoring signal. A receipt whose claims contain only unrecognized keys MUST be rejected.

**Receipt Context**

```json
{
  "context": {
    "task_type": "string",
    "category": "string",
    "geo": "string",
    "modality": "string",
    "value_band": "low | medium | high | very_high",
    "risk_class": "standard | elevated | high"
  }
}
```

Context fields enable domain-specific scoring (Section 4.6). They are not required and produce no direct scoring signal, but implementations SHOULD encourage submitters to include them to support multi-dimensional Trust Profile construction.

### 3.3 Receipt Immutability

Receipts are permanent records. The following operations are categorically prohibited and MUST be rejected at both the API and database layers:

- Deletion of any receipt
- Modification of any truth-bearing field after creation
- Backdating of `created_at`

The single permitted post-write mutation is **downward adjustment of `graph_weight`** when fraud is confirmed between a submitter/entity pair. This adjustment is applied retroactively to all receipts in the affected pair, but the adjustment is strictly downward: a receipt's `graph_weight` MUST never be increased by retroactive adjustment. All retroactive weight adjustments MUST be recorded in an audit trail (`fraud_flags` table or equivalent).

### 3.4 Blockchain Anchoring

Receipts with provenance tier `anchored` have been included in a Merkle root submitted to a public blockchain. This provides external, unforgeable proof of existence at a point in time.

**Anchoring process:**

1. A batch of receipts is assembled. The `receipt_hash` of each receipt is a leaf.
2. A Merkle tree is computed over the batch.
3. The Merkle root is submitted to a public blockchain in a well-known transaction format.
4. The `anchor_tx_id` and `merkle_proof` are stored with each receipt in the batch.

**Verification:** Any party can verify an anchored receipt by recomputing its `receipt_hash`, recomputing its position in the Merkle tree using the stored proof, and checking that the resulting root matches the value recorded on-chain at `anchor_tx_id`.

Implementations are not required to support anchoring. Implementations that do support it MUST NOT claim `anchored` provenance for receipts that have not been verifiably committed to a public blockchain.

---

## 4. Trust Scoring

### 4.1 Effective Evidence

**Effective Evidence** (`ee`) is the sum of per-receipt weights across all receipts in the scoring window:

```
effective_evidence = Σ (submitter_weight × time_weight × graph_weight × provenance_weight)
```

for each receipt in the window, where:

- `submitter_weight` = `max(0.1, submitter_compat_score / 100)` if submitter is established; `0.1` otherwise
- `time_weight` = `max(0.05, 0.5^(age_days / 90))` — receipts decay by half every 90 days
- `graph_weight` = between 0.1 and 1.0, set by fraud graph analysis (Section 5.2)
- `provenance_weight` = per the table in Section 4.2

### 4.2 Provenance Weights

| Provenance Tier | Weight | Description |
|---|---|---|
| `self_attested` | 0.3 | Submitter asserts the receipt with no independent corroboration |
| `identified_signed` | 0.5 | Submitter provides a cryptographic signature (ed25519) over the receipt hash |
| `bilateral` | 0.8 | Both parties have confirmed the transaction outcome |
| `platform_originated` | 0.9 | Receipt originated from a trusted platform integration |
| `carrier_verified` | 0.95 | Physical delivery verified by carrier data |
| `anchored` | 1.0 | Receipt is committed to a public blockchain |

The provenance tier claimed in a receipt submission MUST be validated at ingestion time. A claimed tier that cannot be substantiated MUST be silently downgraded to `self_attested`. The downgrade MUST be recorded in the submission response as a warning.

### 4.3 Quality-Gated Evidence and Confidence

Raw effective evidence can be inflated by large numbers of unestablished submitters. Quality-gating caps the contribution from unestablished sources:

```
quality_gated_evidence = min(
  effective_evidence,
  established_evidence + min(max(0, effective_evidence - established_evidence), 2.0)
)
```

where `established_evidence` is the sum of weights contributed exclusively by receipts from established submitters.

The effect: unestablished submitters can contribute at most 2.0 to quality-gated evidence regardless of volume. Two hundred synthetic identities each contributing one receipt do not cross the trust threshold any faster than two.

**Confidence Levels** are assigned based on `quality_gated_evidence`:

| Level | Quality-Gated Evidence | Meaning |
|---|---|---|
| `pending` | 0 | No receipts exist |
| `insufficient` | > 0 and < 1.0 | Receipts exist but carry very low weight |
| `provisional` | 1.0 – 4.9 | Building credible history; not yet established |
| `emerging` | 5.0 – 19.9 | Established; score is meaningful |
| `confident` | ≥ 20.0 | High confidence; broad, weighted evidence base |

### 4.4 Behavioral Rate Computation

From the `agent_behavior` field across receipts in the scoring window, the following rates are computed:

```
completion_rate    = count(completed) / count(all_behaviors_present)
retry_rate         = (count(retried_same) + count(retried_different)) / count(all_behaviors_present)
abandon_rate       = count(abandoned) / count(all_behaviors_present)
dispute_rate       = count(disputed) / count(all_behaviors_present)
```

All rates are expressed as decimals in [0, 1] and reported as percentages in the Trust Profile. Rates are only computed when at least one receipt contains an `agent_behavior` value. When `agent_behavior` is absent from all receipts in the window, behavioral rates are reported as `null` — not as zero.

### 4.5 Composite Score Weights

The behavioral signal carries primary weight because it is the least gameable and the most predictive:

| Component | Phase 1 Weight | Description |
|---|---|---|
| `behavioral` | 40% | Weighted average of BEHAVIOR_VALUES across receipts with agent_behavior |
| `consistency` | 25% | `max(0, 100 - sqrt(variance) × 2)` over composite scores |
| `delivery_accuracy` | 12% | Weighted average of delivery_accuracy signal |
| `product_accuracy` | 10% | Weighted average of product_accuracy signal |
| `price_integrity` | 8% | Weighted average of price_integrity signal |
| `return_processing` | 5% | Weighted average of return_processing signal |

Signal components with no data are excluded from the denominator rather than scored as zero.

Weights are scheduled to shift in Phase 2 (as bilateral attestation matures) and Phase 3 (as oracle verification matures). This document specifies Phase 1 weights as the v1.0 standard.

### 4.6 Rolling Window

The **current scoring window** is 90 days. All rate computations and confidence assessments use receipts within this window.

The **historical window** covers all receipts regardless of age. Establishment status (Section 4.3) and the existence of any fraud flags are assessed over the full historical record.

Implementations MAY provide domain-specific scoring using a narrower window for rapidly-evolving contexts (e.g., software packages with frequent releases).

### 4.7 Anomaly Detection

Score velocity is a stronger signal than absolute score. A 20-point decline over seven days in a previously stable entity warrants investigation even if the current score remains above policy thresholds.

EP computes anomalies by comparing the mean composite score in the most recent 7 days against the mean in the preceding 30 days, using a simplified Welch-like statistic to avoid false positives from high-variance entities:

| Alert Level | Minimum Delta | Minimum Significance | Minimum Sample (each window) |
|---|---|---|---|
| `moderate` | 10 points | 2.0σ | 5 receipts |
| `severe` | 20 points | 3.0σ | 10 receipts |

Anomaly detection requires at least 5 receipts in each comparison window. Entities with insufficient data in either window produce `anomaly: null`.

### 4.8 Domain-Specific Scoring

Trust is multi-dimensional. An entity may be highly reliable for low-value purchases and unreliable for high-value ones, or reliable in one task category but not another.

Implementations SHOULD compute domain-specific Trust Profiles by filtering the receipt window to receipts whose `context.task_type` or `context.category` matches the consuming agent's domain. A domain-specific profile is evaluated independently of the global profile.

Domain-specific profiles MUST clearly indicate the domain filter and the number of receipts in the filtered window. A consuming agent MUST NOT treat a domain-specific profile as representative if it contains fewer than 3 receipts.

---

## 5. Sybil Resistance

### 5.1 Registration Rate Limiting

To constrain synthetic entity creation, implementations MUST enforce:

- Maximum 5 entities registered per `owner_id` per 24-hour period
- Maximum 50 entities registered per `owner_id` in total

These limits are assessed against the `owner_id` derived from the authenticated credential at registration time. Implementations SHOULD use a distributed counter (e.g., Redis INCR with TTL) for the daily limit to ensure correctness across multiple application instances. A database count fallback is acceptable; implementations MUST NOT fail open on both paths simultaneously.

Implementations MAY provide an exception process for operators who require higher limits for legitimate use cases. Such exceptions MUST be documented and auditable.

### 5.2 Graph Weight Penalties

The receipt graph is analyzed at submission time. Penalties reduce `graph_weight` and are applied retroactively to all prior receipts in the affected pair (only downward; never upward):

| Pattern | Detection Condition | graph_weight Effect |
|---|---|---|
| Closed loop | Entity A has receipts from B AND Entity B has receipts from A | `× 0.4` |
| Thin graph | ≥ 5 receipts for entity, < 3 unique submitters | `min(current, 0.5)` |
| Single source | ≥ 3 receipts for entity, 1 unique submitter | `min(current, 0.3)` |
| Cluster detected | Intra-group receipts > 80% of receipts among a tight submitter cluster | `min(current, 0.1)` |

Penalties are multiplicative in sequence (closed-loop penalty applies first, then further caps). An entity with both a closed-loop and a thin-graph pattern has its graph_weight capped at `0.4 × 0.5 = 0.2`.

Receipts blocked due to cluster detection or velocity spikes MUST NOT be inserted into the ledger.

### 5.3 Velocity Limits

Submissions from a single entity exceeding 100 receipts in any 60-minute window MUST be flagged. Excess receipts beyond the 100-per-hour threshold MUST be blocked, not queued. The blocking is per submitting entity, not per target entity.

Additionally, per target entity, a maximum of 500 receipt submissions per UTC day MUST be enforced. This prevents a single target entity from being flooded with receipts — even legitimate-looking ones — that would overwhelm scoring with noise.

### 5.4 Retroactive Weight Adjustment

When fraud is confirmed between an `(entity_id, submitted_by)` pair — whether through dispute resolution, operator investigation, or cluster detection — the `graph_weight` of all existing receipts from that pair MUST be adjusted downward to the applicable penalty weight.

This adjustment is non-negotiable. A system that applies graph penalties only to new receipts allows an attacker to build trust fraudulently and then have that trust persist after detection. The adjustment is always downward. If an existing receipt already carries a lower `graph_weight` than the new penalty requires, it is not changed.

Every retroactive adjustment MUST be recorded in an audit trail with: the pair, the new weight, the count of receipts updated, and the timestamp of adjustment.

---

## 6. Policy Evaluation

### 6.1 Built-in Policies

EP defines four standard policies. Conformant implementations MUST support all four by name.

**`discovery`** — No exclusions. Used for browsing and exploring unscored entities.
- `min_score`: 0
- `min_confidence`: `pending`

**`permissive`** — Minimal bar. For low-risk, low-value interactions.
- `min_score`: 40
- `min_confidence`: `provisional`
- `min_receipts`: 1
- `max_dispute_rate`: 20%

**`standard`** — Normal commerce. For typical agent-to-merchant or agent-to-agent transactions.
- `min_score`: 60
- `min_confidence`: `emerging`
- `min_receipts`: 5
- `max_dispute_rate`: 10%
- `min_completion_rate`: 70%

**`strict`** — High-value or high-risk interactions. For financial transactions, sensitive data access, or mission-critical tasks.
- `min_score`: 75
- `min_confidence`: `confident`
- `min_receipts`: 20
- `max_dispute_rate`: 3%
- `min_completion_rate`: 85%
- `reject_anomaly`: true (severe anomalies cause automatic rejection)
- `signal_minimums`: `{ delivery_accuracy: 80, price_integrity: 90 }`
- `max_days_since_last_receipt`: 180

Policy evaluation returns a structured result: `{ pass: boolean, failures: string[], warnings: string[] }`. Failures are specific, human-readable strings identifying which criterion was not met. Consuming agents MUST receive the failure list, not merely a boolean.

### 6.2 Software Trust Policies

EP defines a `EP-SX` (Software Extension) policy family for non-transactional software entities:

| Policy Name | Target Type | Key Requirements |
|---|---|---|
| `mcp_server_safe_v1` | MCP servers | min_score 60, provisional confidence, publisher verified, bounded permissions |
| `npm_buildtime_safe_v1` | npm packages | min_score 60, trusted publishing, provenance verified, no active disputes |
| `github_private_repo_safe_v1` | GitHub Apps | min_score 70, read-only permission class, no active disputes |
| `browser_extension_safe_v1` | Browser extensions | min_score 65, limited content read permissions, declared sites only |

Software policies include a `software_requirements` block with fields specific to the software entity type. These fields are evaluated by the policy engine in addition to standard trust thresholds.

### 6.3 Custom Policies

Consuming agents MAY define custom policies. Custom policies MUST be expressed using the same field vocabulary as built-in policies to ensure portability. A custom policy that references non-standard fields MUST document those fields so that an EP implementation can interpret or safely ignore them.

Custom policy names MUST NOT use the names of built-in policies.

---

## 7. Delegation Chain

### 7.1 Delegation Record Format

A Delegation is a signed authorization from a principal to an agent entity.

```json
{
  "delegation_id": "ep_dlg_{uuid}",
  "principal_id": "owner-uuid",
  "agent_entity_id": "agent-entity-uuid",
  "scope": ["purchase", "service", "task_completion"],
  "max_value_usd": 500,
  "issued_at": "ISO-8601",
  "expires_at": "ISO-8601",
  "status": "active | expired | revoked"
}
```

**`expires_at`** is mandatory. Delegations without an expiry date MUST be rejected. The maximum permitted delegation duration is implementation-defined, but implementations SHOULD default to 90 days and MUST NOT issue delegations with no expiry.

**`scope`** restricts the transaction types the agent is authorized to perform under delegation. Agents MUST NOT submit receipts for transaction types outside their delegation scope.

**`max_value_usd`** is optional. When present, the implementing system MUST track cumulative transacted value and block new transactions that would exceed it.

### 7.2 Trust Attribution Under Delegation

When an agent acts under a delegation record, behavioral outcomes attach to the **agent's** Trust Profile. The delegation record provides the audit trail linking the outcome to the principal.

This means principals are accountable for the quality of agents they delegate authority to. An agent with a poor Trust Profile reflects on the principal that authorized it. Consumers evaluating an agent MAY request to see the principal's overall delegation history as supplemental context.

### 7.3 Delegation Verification

Any party MUST be able to verify a delegation record by calling the verification endpoint with a `delegation_id`. The response MUST indicate:

- Whether the delegation is `active`, `expired`, or `revoked`
- The `agent_entity_id` and `scope` currently in effect
- The `principal_id` (subject to privacy controls)

Expired or revoked delegations MUST return `status: invalid` with a specific reason. Implementations MUST NOT allow transactions to proceed against expired or revoked delegations.

---

## 8. Dispute Lifecycle

### 8.1 Filing a Dispute

Any entity that was materially affected by a transaction may file a dispute against the associated receipt. Recognized `filed_by_type` values are:

- `affected_entity` — the entity being scored
- `receipt_subject` — an entity referenced in the transaction but not a party to the receipt
- `third_party` — any other EP entity with standing
- `human_operator` — an EP operator acting on behalf of a human complaint

A dispute MUST reference a specific `receipt_id`. The dispute MUST specify a reason from the enumerated list: `fraudulent_receipt`, `inaccurate_signals`, `identity_dispute`, `context_mismatch`, `duplicate_transaction`, `coerced_receipt`, `other`.

Disputes SHOULD include a description and MAY include evidence.

The receipt submitter has **7 calendar days** from filing to respond. The response window is recorded as `response_deadline` on the dispute record.

### 8.2 Resolution States

The dispute lifecycle follows this state machine:

```
open → [responded | no_response_at_deadline] → under_review → upheld | reversed | dismissed
                                                                          ↓
                                                                      (appeal)
                                                                          ↓
                                                                  [appeal_pending]
```

| State | Meaning |
|---|---|
| `open` | Filed; awaiting response from receipt submitter |
| `under_review` | Response received (or deadline elapsed); under operator review |
| `upheld` | Dispute upheld; receipt findings confirmed as accurate |
| `reversed` | Dispute upheld; receipt is neutralized (`graph_weight` set to 0.0) |
| `superseded` | A corrected receipt has replaced the disputed one |
| `dismissed` | Dispute lacked merit or standing |

### 8.3 Weight Impact During Dispute

While a dispute is in `open` or `under_review` status, the disputed receipt MUST carry a reduced `graph_weight` of at most 0.5. This ensures that a receipt under active dispute cannot be the sole basis for a policy evaluation that passes.

The temporary reduction is applied to the live scoring computation. It does not modify the stored `graph_weight` until the dispute is resolved.

### 8.4 Resolution Outcomes

**Reversed:** The receipt's `graph_weight` is set to 0.0 in the ledger. The receipt is not deleted. The reversal is recorded on both the receipt and the dispute. A reversed receipt contributes zero to effective evidence but remains visible in audit views.

**Upheld:** The dispute is dismissed with rationale. The receipt's weight is restored to its pre-dispute value.

**Superseded:** A corrected receipt is submitted. The original receipt is reversed and the new receipt linked as its successor.

### 8.5 Appeal

Any dispute participant may appeal a resolution within 30 days of resolution. An appeal is a new dispute record referencing the original dispute, with `filed_by_type: appeal`. The appeal is reviewed by a different operator than the original resolution.

This guarantee — the right to appeal — is a protocol obligation, not an implementation preference. **Trust must never be more powerful than the right of appeal.**

### 8.6 Human Reports

Any human may file a trust report (`trust_reports` table) without authentication, without holding an EP entity, and without referencing a specific receipt. The report types are:

- `wrongly_downgraded` — a human believes their entity has been unfairly penalized
- `harmed_by_trusted_entity` — a human was harmed by an entity EP marked as trusted
- `fraudulent_entity` — a human suspects an entity is fraudulent
- `inaccurate_profile` — a human believes a Trust Profile is materially wrong
- `other`

Implementations are obligated to investigate every human report. This obligation cannot be waived by Terms of Service. A trust infrastructure that cannot be held accountable to the humans it affects is not fit to govern machine-mediated commerce.

---

## 9. Security Properties

### 9.1 Append-only Ledger

The receipt ledger is append-only. Implementations MUST enforce this at both the API layer (reject any UPDATE or DELETE on receipts via public or authenticated APIs) and the database layer (database triggers that reject modifications to truth-bearing fields).

The only permitted mutation is `graph_weight` reduction, which MUST be executed through a privileged internal path, not through any public-facing API.

### 9.2 Hash Linking

Each receipt contains the `receipt_hash` of the previous receipt for the same entity (stored as `chain_prev_hash`). This creates a tamper-evident chain: if any historical receipt is modified, all subsequent hashes in the chain become invalid.

Implementations SHOULD provide a `GET /api/verify/{receiptId}` endpoint that:

1. Returns the receipt with its stored `receipt_hash` and `chain_prev_hash`
2. Recomputes the hash from the stored fields and confirms it matches
3. Fetches the previous receipt and confirms the stored `chain_prev_hash` matches its `receipt_hash`

A verification failure on any of these steps MUST be reported as a tampering alert.

### 9.3 No Self-Scoring

The `entity_id` (target) and `submitted_by` (submitter) MUST be distinct entities. Implementations MUST enforce this check before inserting any receipt. A self-scoring attempt MUST return HTTP 403 with a specific error message.

This check MUST be performed against the entity UUID, not the entity slug, to prevent bypass through aliasing.

### 9.4 Timing-Safe Key Verification

All API key comparisons MUST use constant-time string comparison to prevent timing-based key enumeration. Implementations using a language or framework that provides a timing-safe comparison primitive (e.g., `crypto.timingSafeEqual` in Node.js, `hmac.compare_digest` in Python) MUST use it. Implementations MUST NOT use standard equality operators for key comparison.

### 9.5 Rate Limiting

All write operations (entity registration, receipt submission, dispute filing) MUST be rate-limited. The reference implementation uses a Redis-backed sliding window with an in-memory fallback for development. Implementations MUST NOT disable rate limiting in production environments.

Rate limit responses MUST return HTTP 429 with a `Retry-After` header indicating when the limit resets.

---

## 10. Implementation Requirements

### 10.1 A Conformant Implementation MUST:

1. Enforce the append-only receipt ledger at both API and database layers, rejecting DELETE and substantive UPDATE operations on receipts.
2. Reject receipt submissions where `entity_id` and `submitted_by` refer to the same entity.
3. Reject receipt submissions without a `transaction_ref`.
4. Enforce uniqueness of `(entity_id, submitted_by, transaction_ref)` and return the existing receipt idempotently on duplicate submission.
5. Compute `receipt_hash` as the SHA-256 of the canonical JSON serialization (lexicographically sorted keys, no insignificant whitespace) of all truth-bearing fields.
6. Set `chain_prev_hash` to the `receipt_hash` of the most recent prior receipt for the same `entity_id`, or `null` for the first receipt.
7. Apply graph weight penalties (Section 5.2) at submission time and retroactively to prior receipts in the affected pair (only downward).
8. Cap unestablished submitter contributions to quality-gated evidence as specified in Section 4.3.
9. Support the four built-in trust policies (`discovery`, `permissive`, `standard`, `strict`) by name.
10. Implement the dispute lifecycle as specified in Section 8, including the 7-day response window and `under_review` weight reduction.
11. Accept human trust reports without requiring EP authentication or entity membership.
12. Use timing-safe comparison for all API key verification operations.
13. Enforce entity registration rate limits of 5 per owner per day and 50 per owner total.
14. Block receipt submissions that exceed 100 per submitting entity per hour.
15. Return structured failure reasons (not just a boolean) from policy evaluation.

### 10.2 A Conformant Implementation SHOULD:

1. Provide a receipt verification endpoint (`GET /api/verify/{receiptId}`) that validates hash integrity and chain linkage.
2. Use Redis-backed rate limiting with a database fallback rather than in-memory-only rate limiting.
3. Compute and expose anomaly detection data (Section 4.7) in Trust Profile responses.
4. Support domain-specific Trust Profiles using `context.task_type` filtering.
5. Implement provenance tier validation for `identified_signed` receipts (ed25519 signature verification against the `receipt_hash`).
6. Store an audit trail for all retroactive weight adjustments in a `fraud_flags` table or equivalent.
7. Support bilateral receipt confirmation, with a confirmation deadline of 48 hours from submission.
8. Provide an `/api/trust/profile/:entityId` endpoint that returns the full Trust Profile, not only the scalar compatibility score.
9. Record score history to enable velocity computation and audit.
10. Support semantic entity matching via capability embeddings.

### 10.3 A Conformant Implementation MAY:

1. Support blockchain anchoring of receipt batches as specified in Section 3.4.
2. Support pairwise (relationship) trust scores for repeated counterparties.
3. Implement oracle-verification pipelines for carrier-verified or platform-originated provenance tiers.
4. Expose MCP tool interfaces (`ep_trust_profile`, `ep_trust_evaluate`) for consumption by agent frameworks.
5. Extend the entity type enumeration with namespaced custom types.

---

## 11. Versioning

This document specifies **EMILIA Protocol v1.0**.

**Protocol version** is declared in the `ep_version` field of all API responses. Implementations MUST include this field so consuming agents can detect version mismatches.

**Backward compatibility.** Non-breaking additions (new optional fields, new entity types, new policy fields that are safely ignorable) will be made as minor version increments (v1.1, v1.2, ...). Consuming agents MUST NOT fail on unrecognized optional fields.

**Breaking changes** require a major version increment (v2.0). Breaking changes include: changes to required field definitions, changes to the canonical hash computation algorithm, changes to confidence level thresholds that would cause existing profiles to shift classification, and removal of built-in policies. Breaking changes will be announced with a minimum 12-month deprecation period.

**Migration.** An EP implementation supporting v2.0 MUST continue to serve v1.0 API responses on the v1.0 endpoint path for at least 12 months following the v2.0 release.

---

## 12. Governance

The EMILIA Protocol is an open standard. The canonical specification, schema definitions, reference implementation, and scoring algorithm are published under the **Apache-2.0 license**.

Protocol evolution is governed by a process defined in `GOVERNANCE.md` in the canonical repository. In summary:

- Protocol changes are proposed as GitHub issues or pull requests against the specification
- Significant changes require a public comment period of at least 30 days
- Breaking changes require contributor consensus and a documented migration path
- No single organization controls the protocol

EP is designed to be self-governing through the same behavioral accountability mechanisms it specifies. The trust infrastructure of the AI age must itself be trustworthy.

---

## 13. Privacy and Zero-Knowledge Proofs

### 13.1 The Privacy-Trust Tradeoff

Trust systems create a structural tension. The more evidence a system accumulates about an entity's behavior, the better it can assess that entity's trustworthiness. But the more evidence it accumulates and exposes, the greater the privacy cost to every entity in the ledger. A trust protocol that requires parties to expose transaction history as the price of admission to machine-mediated commerce will fail — either because privacy-conscious participants refuse to join, or because the data it accumulates becomes a target and a liability.

EP resolves this tension through a ZK-lite proof system that allows an entity to demonstrate that its Trust Profile satisfies a consuming agent's policy without disclosing the underlying receipt history, counterparty identities, or transaction values.

The proof is not a substitute for the underlying record. The underlying record is maintained in the EP ledger, subject to the normal append-only guarantees and dispute rights. The proof is a privacy-preserving representation of a policy-evaluation result — a commitment that allows a verifier to confirm "this entity passed the `strict` policy as of this date" without learning what receipts produced that result.

### 13.2 ZK-Lite Proof System (Commitment-Based)

EP's ZK-lite system does not require a full zero-knowledge proof circuit in the cryptographic sense. It is a commitment-based approach: the EP registry evaluates the policy on behalf of the entity, computes a structured result, and signs that result. The signature serves as a proof of origin. The entity presents the signed structure to verifiers without the verifier needing access to the underlying ledger.

This is explicitly not a full ZK-SNARK or ZK-STARK proof system. The "ZK" in ZK-lite refers to the knowledge revealed to the verifier: zero knowledge of the underlying receipt contents beyond what is explicitly declared in the proof structure itself.

Implementations MAY choose to implement a full zero-knowledge proof circuit in the future. This section specifies the minimum viable ZK-lite interface that v1.0 implementations MUST support if they expose a proof endpoint.

### 13.3 Proof Structure Specification

A valid EP ZK-lite proof MUST contain the following fields:

```json
{
  "proof_id": "ep_zkp_{hex-32}",
  "ep_version": "1.0",
  "entity_id": "target-entity-uuid",
  "policy_evaluated": "standard | strict | permissive | discovery | {custom}",
  "evaluation_result": "pass | fail",
  "confidence_band": "pending | insufficient | provisional | emerging | confident",
  "proof_generated_at": "ISO-8601",
  "proof_expires_at": "ISO-8601",
  "registry_signature": "ed25519-hex",
  "registry_public_key_id": "ep_pk_{hex-16}",
  "commitment": "sha256-hex"
}
```

**`proof_id`** MUST be formatted as `ep_zkp_` followed by 32 cryptographically random hexadecimal characters. Proof IDs MUST be globally unique within the issuing registry.

**`policy_evaluated`** MUST match an enumerated or registered policy name. Proofs against custom policies MUST include the custom policy definition hash in the `policy_metadata` field.

**`evaluation_result`** is binary. A proof MUST NOT reveal the margin of pass or fail, the composite score, or the distance from threshold. The result is pass or fail, nothing more.

**`confidence_band`** MUST be included. It reveals the general quality of evidence without disclosing receipt count or submitter identities.

**`proof_generated_at`** and **`proof_expires_at`** are mandatory. The expiry MUST be set to exactly 30 days after `proof_generated_at`. No implementation MUST issue a proof with an expiry beyond 30 days. Proof expiry is absolute: an expired proof is invalid regardless of whether the underlying Trust Profile has changed.

**`registry_signature`** MUST be an ed25519 signature over the canonical JSON serialization of all fields except `registry_signature` itself. Canonical serialization follows the same rules as receipt hashing: lexicographically sorted keys, no insignificant whitespace.

**`commitment`** MUST be the SHA-256 of the concatenation of `entity_id`, `proof_generated_at`, and the canonical serialization of the complete Trust Profile at evaluation time. This commitment allows the registry to later confirm that a given proof corresponds to a specific evaluation state without revealing the profile contents to the verifier.

**`policy_metadata`** is an OPTIONAL field containing the SHA-256 hash of the custom policy definition when `policy_evaluated` references a non-standard policy. Verifiers MUST check this field when present.

### 13.4 What Is Revealed vs. Hidden

**A ZK-lite proof MUST reveal:**

- The entity ID of the proved entity
- The policy against which the evaluation was performed
- The binary evaluation result (pass or fail)
- The confidence band
- The proof validity window
- The issuing registry's identity (via `registry_public_key_id`)

**A ZK-lite proof MUST NOT reveal:**

- The entity's composite trust score or any component score
- The number of receipts in the scoring window
- The identities of submitters
- The contents of any individual receipt, including transaction values, counterparty IDs, or behavioral signals
- The specific criteria that caused a `fail` result
- Any claims or evidence attached to underlying receipts

**Verifiers MUST NOT demand receipt disclosure as a condition of accepting a proof.** A verifier who requires the underlying receipts has rejected the privacy model and MUST use the full trust profile API instead, subject to the entity's consent.

### 13.5 Proof Validity and Expiry

Proofs are valid for exactly 30 days from `proof_generated_at`. This window balances freshness (a proof should not be valid indefinitely as behavioral history accumulates) against utility (an entity should not need to re-prove trustworthiness for every individual transaction within a relationship).

**At or after `proof_expires_at`:**

- The proof is invalid and MUST be rejected by conformant verifiers
- The entity must generate a new proof by requesting a fresh evaluation from the registry
- The prior proof remains in the registry audit trail but is marked `status: expired`

Implementations MUST NOT accept proofs where the current time is at or after `proof_expires_at`, regardless of network clock skew. Verifiers SHOULD allow a grace period of no more than 60 seconds for clock synchronization. Verifiers MUST NOT allow grace periods greater than 5 minutes.

### 13.6 Verifier Obligations

A party that accepts EP ZK-lite proofs (a **verifier**) incurs the following obligations:

**MUST:**

1. Verify the `registry_signature` using the public key identified by `registry_public_key_id` before accepting any proof.
2. Check that `proof_expires_at` is in the future before accepting any proof.
3. Check `proof_id` against the EP registry to confirm the proof has not been revoked. A proof may be revoked if the underlying receipt history is subsequently determined to be fraudulent.
4. Confirm that `policy_evaluated` matches the policy the verifier actually requires. A proof against `permissive` does not satisfy a `strict` requirement.

**MUST NOT:**

1. Demand disclosure of the underlying receipts as a condition of acceptance.
2. Cache a proof result beyond its `proof_expires_at` timestamp.
3. Share the proof with third parties for purposes other than the transaction for which it was presented.
4. Use the `confidence_band` as a scoring proxy. The band is informational, not a substitute for policy evaluation.

---

## 14. Dispute Adjudication Standard

### 14.1 Dispute Lifecycle

The full dispute lifecycle comprises six stages. Conformant implementations MUST support all six stages and MUST enforce the transition rules specified here.

```
filed → evidence_period → response_period → adjudication → resolution → [appeal]
```

| Stage | Duration | Trigger | Exit Conditions |
|---|---|---|---|
| `filed` | Immediate | Dispute submitted | Evidence period begins automatically |
| `evidence_period` | 48 hours | Dispute accepted | Additional evidence may be submitted by either party |
| `response_period` | 7 calendar days | Evidence period closes | Submitter responds, or deadline elapses |
| `adjudication` | Implementation-defined; SHOULD be ≤ 14 days | Response received or deadline elapsed | Operator reaches a resolution |
| `resolution` | Permanent | Adjudication complete | `upheld`, `reversed`, or `dismissed` recorded |
| `appeal` | 30 days from resolution | Appeal filed by affected party | Appeal reviewed by different operator |

Implementations MUST NOT skip stages. A dispute that moves directly from `filed` to `resolution` without an `adjudication` stage is non-conformant.

The `evidence_period` stage is a v1.0 addition to the dispute lifecycle specified in Section 8. Section 8's state machine remains authoritative for the core states (`open`, `under_review`, `upheld`, `reversed`, `dismissed`); this section extends it with explicit timing requirements and the evidence submission window.

### 14.2 Trust-Graph Voting in Adjudication

When a dispute enters `adjudication`, implementations SHOULD query the trust graph to assess the weight of corroborating and contradicting evidence. This is not a majority-vote mechanism; it is an evidence-weighting signal.

**Trust-graph voting MUST:**

1. Query entities that have submitted receipts for the disputed entity and identify those with a confidence level of `confident` (quality-gated evidence ≥ 20.0).
2. Weight each vouching entity's signal by its own Trust Profile composite score, normalized to [0, 1].
3. Present the weighted vouching signal to the operator as a supplementary data point, not a decision.

**Trust-graph voting MUST NOT:**

1. Automatically resolve disputes. Human or designated adjudicator review is required at the `adjudication` stage for all `upheld` and `reversed` outcomes.
2. Include vouching signals from entities with confidence levels below `confident`. Entities with `provisional` or `emerging` confidence MUST be excluded from the vouching signal computation.
3. Apply vouching signals retroactively to change a resolution outcome without re-opening the dispute.

Implementations that do not support trust-graph voting at the `adjudication` stage MUST document this as a conformance limitation.

### 14.3 Weight Dampening During Active Disputes

Receipts under active dispute carry reduced weight in scoring computations. Section 8.3 specifies the general rule (at most 0.5 during `open` or `under_review`). This section strengthens that requirement for the full lifecycle:

**Disputed receipts MUST be scored at ≤ 0.3× their undisputed graph_weight** at all stages from `filed` through `adjudication`.

The dampening factor is 0.3× — not a flat cap of 0.3. If a receipt's undisputed `graph_weight` is 0.4, its effective weight during dispute is at most 0.4 × 0.3 = 0.12. A receipt with `graph_weight` of 1.0 is dampened to at most 0.3.

This is stricter than Section 8.3's 0.5 cap. Section 8.3 remains valid for implementations that have not adopted this section; implementations that declare conformance with the full Section 14 standard MUST apply the 0.3× dampening.

**Dampening applies to:**

- All scoring computations (composite score, behavioral rates, domain-specific profiles)
- Policy evaluation results
- Confidence level assessment
- Anomaly detection baselines

**Dampening does NOT modify:**

- The stored `graph_weight` on the receipt record
- The receipt's chain hash
- The audit trail

The stored `graph_weight` is only modified at resolution (see Section 14.4).

### 14.4 Resolution Permanence

**Dispute resolution outcomes are immutable once recorded.**

A resolved dispute (in state `upheld`, `reversed`, or `dismissed`) MUST NOT be re-opened. If new evidence emerges that contradicts the resolution, the correct mechanism is an appeal (Section 14.1) or, in cases of newly discovered fraud, a separate dispute filing referencing the original.

Resolution permanence is a due process guarantee. Entities harmed by a resolution have the right to know that a resolved dispute is closed and that their scoring impact (positive or negative) will not be silently re-litigated.

**On resolution, the following outcomes apply:**

**Dismissed:** The dispute is closed without merit. The disputed receipt's `graph_weight` MUST be restored to its full pre-dispute value within 24 hours of the dismissal decision. Implementations MUST NOT leave dampening in effect after a dismissal. The restoration MUST be recorded in the audit trail with the dispute ID, the pre-dispute weight, the restored weight, and the timestamp.

**Reversed:** The disputed receipt's `graph_weight` MUST be set to 0.0 in the ledger. This is a permanent reduction. A reversed receipt MUST remain in the ledger (append-only guarantee is not violated) but contributes zero to effective evidence, zero to behavioral rates, and zero to scoring in all subsequent computations. The reversal MUST be recorded with the same audit fields as a dismissal, plus the reason.

**Upheld:** Despite a dispute being filed, the receipt is determined to be accurate. The receipt's `graph_weight` MUST be restored to its full pre-dispute value. The distinction from `dismissed` is semantic: `upheld` indicates the adjudicator positively affirmed the receipt's accuracy, while `dismissed` indicates the dispute lacked merit or standing without a positive affirmation.

### 14.5 Weight Restoration: Dismissed Disputes

A dismissed dispute MUST result in full weight restoration. Partial restoration is prohibited. An implementation that caps weight restoration after dismissal at less than the full pre-dispute `graph_weight` is non-conformant.

**Full weight restoration means:** the receipt's effective weight in all scoring computations returns to the value it carried before the dispute was filed — no ceiling, no holdback, no "shadow weight" that lingers after dismissal.

Implementations MUST NOT apply a credibility penalty to receipts that survive a dismissed dispute. A receipt that has been challenged and cleared is not less reliable than one that was never challenged; the disposition of the challenge is itself evidence of the receipt's integrity.

### 14.6 Upheld Disputes: Permanent Weight Reduction

When a dispute is upheld — meaning the underlying receipt is confirmed as fraudulent, inaccurate, or otherwise invalid — the receipt's `graph_weight` MUST be permanently reduced to 0.0.

This permanent reduction is distinguishable from the temporary dampening in Section 14.3. The stored `graph_weight` is modified. All subsequent scoring computations treat the receipt as having zero evidential weight. The change is irreversible without an appeal outcome explicitly restoring weight (see Section 14.1).

**Permanent reduction to 0.0 applies only when the dispute outcome is `reversed`.** The terminology in Section 8.2 uses `reversed` for the outcome where the receipt is neutralized. In this section's language: an upheld dispute — one where the challenger's claim is affirmed — produces a `reversed` outcome on the receipt. The word "upheld" describes the dispute; "reversed" describes the receipt treatment.

Implementations MUST be consistent in their use of this terminology. API responses MUST NOT use `upheld` and `reversed` interchangeably.

---

## 15. Attribution Chain Standard

### 15.1 Principal → Agent → Tool Chain Format

When an agent acts under a delegation record (Section 7) and uses a tool (such as an MCP server) to complete a transaction, the full attribution chain MUST be recorded in the receipt. The attribution chain documents the complete path of accountability from the human principal through the authorized agent to the specific tool invoked.

**Attribution chain format:**

```json
{
  "attribution": {
    "principal_id": "owner-uuid",
    "agent_entity_id": "agent-entity-uuid",
    "tool_entity_id": "mcp-server-entity-uuid | null",
    "delegation_id": "ep_dlg_{uuid} | null",
    "chain_depth": 1,
    "chain_type": "principal_agent | principal_agent_tool | direct"
  }
}
```

**`delegation_id` MUST be included if a delegation existed at the time of the transaction.** An agent that acted under a delegation record and submits a receipt without including the `delegation_id` in the attribution block MUST have that submission flagged for manual review.

**`chain_depth`** counts the number of non-principal links. A direct submission by a principal has `chain_depth: 0`. A principal-agent chain has `chain_depth: 1`. A principal-agent-tool chain has `chain_depth: 2`. Implementations MUST NOT accept `chain_depth` values greater than 5 without operator approval; excessively deep chains are a pattern associated with accountability obscurement.

**`chain_type`** is a human-readable description of the chain structure. Standard values are `direct`, `principal_agent`, and `principal_agent_tool`. Implementations MAY define additional chain types using the same reverse-domain namespace convention as entity type extensions.

### 15.2 Principal Signal Weight

When an agent acts under delegation and a receipt is submitted, two signal weights are computed:

1. **Agent trust signal weight** — the weight attributed to the agent entity's Trust Profile. This is the primary signal and is computed according to Section 4's standard formula.

2. **Principal signal weight** — a weak supplementary signal attached to the principal's delegation history, indicating the quality of the agents the principal has authorized.

**Principal signal weight SHOULD be 0.15 ± 0.05.** The canonical value is 0.15. Implementations MAY adjust within the ±0.05 range based on context. Implementations MUST NOT set principal signal weight above 0.20 or below 0.10 for standard transaction contexts.

The principal signal weight is intentionally weak. Its purpose is to create an audit trail linking principal judgment to outcomes — not to punish principals for agent misbehavior. A principal whose agents consistently underperform will accumulate a negative signal in their delegation history, visible to parties who request it. But this signal is a contextual datum, not a controlling factor in trust evaluation.

**Principal signal weight MUST NOT:**

1. Be used as the primary or sole basis for policy evaluation against the principal.
2. Be applied to the agent's Trust Profile. The agent's profile is computed independently.
3. Exceed the agent's own trust signal weight in any scoring context.

### 15.3 Delegation Judgment Scoring

Delegation judgment scoring measures how well a principal selects and manages the agents they authorize. It is computed separately from the principal's entity Trust Profile and from the agent's Trust Profile.

**Delegation judgment score computation:**

```
delegation_judgment_score = weighted_average(
  agent_outcome_scores,
  weight_per_agent = agent_effective_evidence / total_effective_evidence_across_agents
)
```

where `agent_outcome_scores` is the set of final trust composite scores for each agent entity that has operated under a delegation from this principal.

**Delegation judgment scoring MUST be computed separately from entity trust score.** A principal with a high entity trust score (earned through direct transactions) but poor delegation judgment (consistently authorizing underperforming agents) MUST have both scores reported distinctly. Implementations MUST NOT merge delegation judgment into the entity trust score.

**Delegation judgment score MUST be reported in:**

- The principal's Trust Profile when delegation history exists
- Policy evaluation results for principals with active delegation records
- Dispute investigation reports when a dispute involves an agent acting under delegation

---

## 16. Auto-Receipt Generation

### 16.1 Opt-In Requirement

Auto-receipt generation is the capability for an EP-conformant implementation to automatically generate Trust Receipts from platform events, integration webhooks, or system-generated signals, without requiring a human or agent to explicitly submit each receipt.

**Auto-receipt generation MUST be explicitly enabled per entity.** An entity is not enrolled in auto-receipt generation by default. Enrollment requires an explicit configuration action by the entity's principal or authorized operator.

Implementations MUST NOT silently enroll entities in auto-receipt generation. Enrollment MUST be documented in the entity's configuration record with the timestamp, the enrolling party's identity, and the event sources authorized for auto-generation.

Auto-receipt generation is distinct from bilateral receipt confirmation (Section 10.2, item 7). Bilateral confirmation requires a receipt to already exist; auto-generation creates the receipt from external signals. Both mechanisms may coexist for the same entity.

### 16.2 Privacy Requirements for Auto-Generated Receipts

Auto-generated receipts create privacy risks that manually submitted receipts do not: they may capture sensitive transactional data as a side effect of platform integration, without the submitting party having made an affirmative decision about what to include.

**Implementations MUST NOT store raw sensitive fields in auto-generated receipts.** The following field types are categorically prohibited from raw storage in auto-generated receipts:

- Payment card numbers or partial card numbers beyond the last four digits
- Bank account numbers
- Social security numbers, government ID numbers, or taxpayer identification numbers
- Passwords, access credentials, or API keys
- Biometric identifiers
- Medical or health information
- Precise geolocation data (bounding to city-level resolution is permitted)
- Full names combined with any of the above

The MUST list for prohibited fields is a minimum. Conformant implementations MUST define and publish their own implementation-specific list of prohibited fields that meets or exceeds this minimum. The implementation's list MUST be available at `/.well-known/ep-trust.json` as a `auto_receipt_privacy_policy` field.

**Sanitization MUST occur before storage.** Auto-generated receipt pipelines MUST apply field sanitization at the point of data ingestion, before the receipt is written to the ledger. Post-hoc sanitization of ledger records is prohibited under the append-only guarantee; the correct response to a mis-ingested sensitive field is not modification of the stored record but removal of the integration event that produced it, followed by audit and remediation.

### 16.3 Provenance of Auto-Generated Receipts

**Auto-generated receipts MUST be marked `provenance_tier: unilateral`** at the time of creation. An auto-generated receipt is, by definition, submitted by one party based on system-generated signals. It does not carry the evidential weight of a bilateral confirmation or a verified platform receipt.

This provenance assignment is mandatory and cannot be overridden at submission time. An integration that claims `bilateral` or `platform_originated` provenance for an auto-generated receipt at submission is making a false provenance claim; implementations MUST detect and reject such claims.

The `provenance_tier: unilateral` assignment affects the receipt's weight per Section 4.2. Auto-generated receipts therefore contribute less to effective evidence than manually submitted receipts with higher provenance tiers. This is by design: the protocol privileges receipts that reflect affirmative human or agent judgment over those generated automatically from system events.

### 16.4 Counterparty Confirmation and Provenance Upgrade

Auto-generated receipts SHOULD be upgradeable to bilateral provenance if the counterparty subsequently confirms the transaction.

**Upgrade process:**

1. The auto-generated receipt is created with `provenance_tier: unilateral` and a `bilateral_confirmation_window` of 48 hours.
2. The counterparty is notified (via implementation-defined mechanism) that a receipt has been generated referencing a transaction they participated in.
3. If the counterparty confirms within the window, the receipt's provenance tier is upgraded to `bilateral` and the effective weight increases per Section 4.2.
4. If the counterparty disputes within the window, the dispute lifecycle (Section 8, Section 14) begins immediately.
5. If no action is taken within the window, the receipt remains at `unilateral` provenance.

**The upgrade from `unilateral` to `bilateral` is the only permitted upward provenance change on an existing receipt.** No other post-write provenance change is permitted. An implementation that upgrades provenance beyond `bilateral` based on counterparty confirmation alone (e.g., to `platform_originated`) is non-conformant.

The provenance upgrade MUST be recorded in the receipt's audit history with the confirmation timestamp and the confirming party's entity ID. The `chain_prev_hash` linkage is not affected by provenance upgrade; the upgrade is recorded as a mutation event in the audit trail, not as a change to the receipt's hash chain.

---

## 17. Conformance Requirements for Sections 13–16

### 17.1 Additions to Section 10 Requirements

Implementations adopting Sections 13 through 16 MUST satisfy the following additional conformance requirements.

**A Conformant Implementation MUST (additions):**

16. If exposing a ZK-lite proof endpoint, issue proofs with `proof_expires_at` set to exactly 30 days after `proof_generated_at`.
17. If exposing a ZK-lite proof endpoint, sign proofs with ed25519 over the canonical JSON serialization of all non-signature fields.
18. Apply 0.3× weight dampening to receipts under active dispute at all stages from `filed` through `adjudication`.
19. Restore full pre-dispute `graph_weight` within 24 hours of a `dismissed` dispute resolution.
20. Set `graph_weight` to 0.0 permanently for receipts with `reversed` resolution outcomes.
21. Record `delegation_id` in receipt attribution when a delegation record existed at the time of the transaction.
22. Reject auto-receipt generation enrollment that is not explicitly initiated by the entity's principal or authorized operator.
23. Apply `provenance_tier: unilateral` to all auto-generated receipts at the time of creation.
24. Sanitize prohibited sensitive fields from auto-generated receipts before storage.

**A Conformant Implementation SHOULD (additions):**

11. Support trust-graph vouching signal computation at the `adjudication` stage using only `confident`-level entities.
12. Compute and report delegation judgment scores separately from entity trust scores for principals with delegation history.
13. Publish an `auto_receipt_privacy_policy` field at `/.well-known/ep-trust.json` listing implementation-specific prohibited fields.
14. Support counterparty-initiated provenance upgrade from `unilateral` to `bilateral` within the 48-hour confirmation window.

---

*EMILIA Protocol Standard v1.0*
*Entity Measurement Infrastructure for Ledgered Interaction Accountability*
*Apache-2.0 · Compatible with ACP, MCP, A2A*
*Specification Date: 2026-03-18*
