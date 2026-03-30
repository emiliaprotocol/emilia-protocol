# EMILIA Protocol -- Scoring Rationale

Version: 2.0 (aligned with `lib/scoring-v2.js`)
Status: Living document. See amendment process at end.

This document explains *why* each weight, threshold, and penalty exists in the EP scoring algorithm. Every claim references the actual code path.

---

## 1. Behavioral Weights (v2)

**Code path:** `lib/scoring-v2.js` -- `EP_WEIGHTS_V2` and `BEHAVIOR_VALUES`

### 1.1 Behavioral Score (40%)

**What it measures:** Whether the purchasing agent came back, switched providers, abandoned the task, or filed a dispute. Encoded as `agent_behavior` on each receipt, mapped to numeric values via `BEHAVIOR_VALUES`:

| Behavior | Value | Meaning |
|---|---|---|
| `completed` | 95 | Transaction completed without retry |
| `retried_same` | 75 | Agent retried with the same counterparty (minor issue resolved) |
| `retried_different` | 40 | Agent switched to a different counterparty |
| `abandoned` | 15 | Agent abandoned the transaction entirely |
| `disputed` | 5 | Agent filed a formal dispute |

**Why 40% weight:** Behavioral signals are the hardest to fake credibly. An agent that lies about completing (to inflate a merchant's score) will route back to that merchant and get burned. The signal is self-enforcing: you rate what you eat. In Phase 1, where most numeric signals are self-reported, behavioral data is the strongest indicator of real-world outcomes.

**What informed this:** The design analogy is FICO: credit scores do not ask borrowers to rate their lenders -- they watch whether borrowers pay. EP does not ask agents to rate merchants -- it watches whether agents come back. The 40% weight reflects the principle that observed actions dominate stated preferences.

**Edge cases and limitations:**
- Behavioral signals are still self-reported by the submitting agent. A colluding agent could report `completed` for a merchant that never delivered.
- Short-lived agents may not generate enough behavioral data to be meaningful.
- The `retried_same` vs `retried_different` distinction relies on the agent correctly reporting which counterparty was involved.

### 1.2 Consistency Score (25%)

**What it measures:** The variance in an entity's composite scores over the receipt window. Low variance = reliable. Computed as `max(0, 100 - sqrt(variance) * 2)`.

**Code path:** `lib/scoring-v2.js`, lines 238-247.

**Why 25% weight:** Consistency is mathematical, not self-reported. A merchant with 200 receipts averaging 80 but with a standard deviation of 15 is objectively less reliable than one averaging 75 with a standard deviation of 3. This is the second-hardest signal to game because it requires sustained performance, not a single inflated receipt.

**What informed this:** Increased from 5% (v1 `EMILIA_WEIGHTS.consistency`) to 25% in v2 because Phase 1 lacks verified signals -- mathematical consistency partially compensates for the absence of oracle verification.

**Edge cases and limitations:**
- An entity with very few receipts (< 2) defaults to a consistency score of 50, which is neutral rather than penalizing.
- A consistently bad entity gets a high consistency score (low variance). This is by design -- the signal dimensions are independent. Consistency tells you *reliability*, not *quality*.

### 1.3 Delivery Accuracy (12%)

**What it measures:** Whether goods/services arrived when promised. In v1 receipts, a 0-100 numeric signal. In v2 receipts, computed from structured claims (`claims.delivered`, `claims.on_time`) via `computeScoresFromClaims()` in `lib/scoring.js`.

**Why 12% weight:** The most commercially consequential signal for e-commerce, but in Phase 1 it is self-reported and therefore placed in Tier 2. Weight will increase as Phase 2 evidence (carrier APIs, delivery confirmations) backs the claims.

### 1.4 Product Accuracy (10%)

**What it measures:** Whether the listing matched reality. Computed from `claims.as_described` in v2 receipts (100 if true, 20 if false).

**Why 10% weight:** Slightly less weight than delivery because product accuracy is harder to objectively measure and more subjective. A "not as described" claim is harder to verify than a delivery timestamp.

### 1.5 Price Integrity (8%)

**What it measures:** Whether the quoted price was honored. Computed from `claims.price_honored` with graduated scoring based on overcharge percentage (0% overcharge = 100, >10% overcharge = 10).

**Why 8% weight:** Price manipulation is a serious trust violation but occurs less frequently than delivery or product issues. The graduated scoring (via `computeScoresFromClaims`) means small discrepancies (< 2%) are tolerated.

### 1.6 Return Processing (5%)

**What it measures:** Whether the return policy was followed. Binary in v2 (`claims.return_accepted`: 95 if true, 15 if false).

**Why 5% weight:** Return processing only applies to a subset of transactions. Many transactions (services, digital goods) have no return flow. The low weight prevents this signal from dominating when it is the only one present.

### 1.7 Weight Evolution Plan

The code documents a planned weight migration as verification improves:

| Phase | Behavioral | Consistency | Claims/Verified | Self-reported/Oracle |
|---|---|---|---|---|
| Phase 1 (current) | 40% | 25% | 35% (self-reported) | -- |
| Phase 2 | 30% | 20% | 40% (claims-backed) | 10% |
| Phase 3 | 20% | 20% | 50% (verified) | 10% (oracle) |

---

## 2. Agent Satisfaction (v1 only)

**Code path:** `lib/scoring.js` -- `EMILIA_WEIGHTS.agent_satisfaction: 0.10`

**Current status in v2:** Agent satisfaction does **not** appear in `EP_WEIGHTS_V2` in `lib/scoring-v2.js`. It has been superseded by the behavioral score. The behavioral signal (`agent_behavior` -> `behaviorToSatisfaction()` in `lib/scoring.js`) converts observed actions into a satisfaction proxy, removing the need for a separate self-reported satisfaction field.

**In v1 scoring:** `agent_satisfaction` carried 10% weight and was a self-reported 0-100 value submitted on each receipt. This created a gameable signal with no verification mechanism. See `docs/AGENT_SATISFACTION_GOVERNANCE.md` for the governance policy.

**In receipt creation:** `lib/create-receipt.js` still accepts `agent_satisfaction` as a signal and stores it on receipts. If `agent_behavior` is provided, the behavior-derived satisfaction value overwrites any manually submitted `agent_satisfaction` value (line 349-351 of `create-receipt.js`).

---

## 3. Time Decay

**Code path:** `lib/scoring.js` -- `computeTimeDecay()`, `lib/scoring-v2.js` line 200.

**Formula:** `weight = max(0.05, 0.5^(ageDays / 90))`

### 3.1 Why a 90-Day Half-Life

- **Recovery window:** A merchant who was terrible 6 months ago but has been perfect since will see approximately 75% of the old bad receipts' weight decay away. This allows meaningful recovery without erasing history.
- **Staleness detection:** A merchant with no recent receipts has all evidence at reduced weight, pulling their score toward the 50 default. This is intentional: stale data should not sustain high trust.
- **Practical commerce cycles:** 90 days approximates one business quarter, which is a natural cadence for evaluating vendor reliability.

### 3.2 Why a 0.05 Floor

Very old receipts never fully disappear. A catastrophic fraud event from 2 years ago still contributes 5% of its original weight. This prevents the "wait it out" strategy where a bad actor simply goes dormant until old evidence decays to zero.

**Decay schedule:**

| Age | Weight |
|---|---|
| 0 days | 1.00 |
| 90 days | 0.50 |
| 180 days | 0.25 |
| 1 year | ~0.06 |
| 2 years | 0.05 (floor) |

---

## 4. Sybil Quality Gates

**Code path:** `lib/scoring-v2.js` lines 196-198, 263-269; `lib/scoring.js` lines 213-220.

### 4.1 Unestablished Submitter Weight: 0.1x

**What it measures:** Receipts from submitters who have not themselves achieved "established" status (5+ effective evidence from 3+ unique submitters) carry only 10% of their nominal weight.

**Formula:** `submitterWeight = submitter_established ? max(0.1, submitter_score / 100) : 0.1`

**Why 0.1x:** This is the Sybil killer. Creating 100 fake entities to boost a score is useless -- each fake entity is unestablished, so their receipts carry 0.1x weight. To get meaningful weight, each fake entity would need 5+ receipts from 3+ other established entities. The cost of a Sybil attack spirals exponentially because each layer of the attack requires legitimate established entities that are themselves expensive to create.

**Why not 0x:** Zero weight would make bootstrapping impossible. New legitimate entities must be able to build trust gradually. The 0.1x weight means unestablished submitters can contribute, but 50 of them would only produce 5.0 effective evidence -- barely reaching the establishment threshold.

### 4.2 Quality-Gated Evidence Cap

**Code path:** `lib/scoring-v2.js` lines 263-269.

**Formula:** `qualityGatedEvidence = min(effectiveEvidence, establishedEvidence + min(max(0, effectiveEvidence - establishedEvidence), 2.0))`

**What this does:** Unestablished evidence is capped at a maximum contribution of 2.0, regardless of volume. Even 200 fake identities each contributing 0.1 effective evidence (= 20.0 raw) are capped at 2.0 from unestablished sources. This prevents pure Sybil volume from crossing the 5.0 evidence threshold needed for establishment.

### 4.3 Evidence Dampening

**Code path:** `lib/scoring-v2.js` lines 270-272.

**Formula:** If `qualityGatedEvidence < 5.0`: `score = 50 + (score - 50) * (qualityGatedEvidence / 5.0)`

Entities below the establishment threshold are damped toward the neutral score of 50. An entity with 2.5 quality-gated evidence can only move halfway from 50 toward its computed score.

---

## 5. Graph Analysis Penalties

**Code path:** `lib/sybil.js` -- `runReceiptFraudChecks()`, lines 287-297.

Graph analysis assigns `graph_weight` to each receipt. This weight is one of the four factors in the receipt weight calculation: `submitterWeight * timeWeight * graphWeight * provenanceWeight`.

### 5.1 Closed-Loop Penalty: 0.4x

**What it detects:** Bidirectional scoring -- entity A has submitted receipts about entity B, AND entity B is now submitting a receipt about entity A.

**Why 0.4x:** Closed loops are suspicious but not always fraudulent. Two businesses that legitimately trade with each other (e.g., a restaurant buying supplies from a wholesaler who also eats at the restaurant) will create closed loops. The 0.4x weight reduces the influence without eliminating it. Combined with other factors (time decay, submitter weight), legitimate mutual scoring still contributes meaningfully.

**Retroactive application:** When a closed loop is detected, `retroactivelyApplyGraphWeight()` reduces the weight on all existing receipts between the pair. Historical trust cannot persist at full weight after fraud detection.

### 5.2 Thin-Graph Penalty: 0.5x

**What it detects:** An entity with 5+ total receipts but fewer than 3 unique submitters. Also triggers for "single source" (3+ receipts, 1 unique submitter).

**Why 0.5x:** A thin graph means the entity's reputation rests on too few independent sources. Even if those sources are legitimate, the score is statistically unreliable. The 0.5x weight is moderate because a thin graph may simply indicate a new or niche entity, not fraud.

**Single source gets 0.3x:** All receipts from one submitter is more severe than few submitters. An entity whose entire reputation comes from a single source is barely more trustworthy than an unscored entity.

### 5.3 Cluster Penalty: 0.1x

**What it detects:** A small group of entities (2-3 submitters, 20+ receipts) where most intra-group receipts (>80%) are between members of the group. This is the hallmark of a coordinated Sybil ring.

**Why 0.1x:** Cluster detection is the strongest fraud signal. Unlike thin graphs (which may be legitimate), a cluster pattern with >80% intra-group receipts has almost no innocent explanation. The 0.1x weight makes the cluster's contributions nearly negligible without requiring proof of intent.

**Blocking behavior:** Cluster detection (along with velocity spikes) blocks the receipt entirely (`allowed: false`). The receipt is rejected, not just down-weighted.

### 5.4 Velocity Spike: Blocked

**What it detects:** More than 100 receipts submitted per hour by a single entity.

**Behavior:** Receipt is blocked entirely. No graph weight is assigned because the receipt is not accepted.

---

## 6. Provenance Tiers

**Code path:** `lib/scoring-v2.js` lines 183-191 -- `PROVENANCE_WEIGHTS`.

Provenance indicates how the receipt was created and what level of verification it carries.

| Tier | Weight | Description |
|---|---|---|
| `self_attested` | 0.3x | Submitter claims the transaction occurred. No external verification. |
| `identified_signed` | 0.5x | Receipt is cryptographically signed by an identified submitter. |
| `bilateral` | 0.8x | Both counterparties have confirmed the transaction. |
| `platform_originated` | 0.9x | Receipt originated from a platform API (e.g., Shopify order webhook). |
| `carrier_verified` | 0.95x | External carrier or logistics provider confirmed delivery. |
| `oracle_verified` | 1.0x | Independent oracle has verified all claims. Full weight. |

**Why these weights:**

- **Self-attested at 0.3x:** In Phase 1, most receipts are self-attested. The low weight means a large volume of unverified receipts is needed to move a score, creating a natural cost floor for manipulation.
- **Bilateral at 0.8x:** When both parties confirm, the receipt is significantly more trustworthy, but bilateral confirmation can still be faked by colluding parties. The 20% discount reflects residual collusion risk.
- **Platform-originated at 0.9x:** Platform APIs (Shopify, Stripe) are harder to forge than bilateral attestations because they require actual platform access. The 10% discount accounts for the possibility of fraudulent platform integrations.
- **Oracle-verified at 1.0x:** The target state. When an independent oracle verifies all claims, the receipt carries full weight.

---

## 7. Confidence Levels

**Code path:** `lib/scoring-v2.js` lines 283-289.

Confidence levels communicate how much trust to place in the score itself, based on quality-gated evidence.

| Level | Quality-Gated Evidence | Established | Meaning |
|---|---|---|---|
| `pending` | 0 | No | No receipts. Score is the 50 default. |
| `insufficient` | < 1.0 | No | Some data exists but too little to compute a meaningful score. |
| `provisional` | >= 1.0 | No | Enough data for a directional signal, but not yet established. |
| `emerging` | >= 5.0 | Yes | Established entity with growing evidence base. |
| `confident` | >= 20.0 | Yes | Substantial evidence. Score is statistically reliable. |

**Why quality-gated:** Confidence uses `qualityGatedEvidence`, not raw `effectiveEvidence`. This prevents a Sybil army of unestablished submitters from advancing an entity's confidence level through sheer volume. The 2.0 cap on unestablished evidence means unestablished sources alone can never push past `provisional`.

**Establishment requirement:** The `established` flag requires both `qualityGatedEvidence >= 5.0` AND `uniqueSubmitters >= 3`. This dual requirement ensures that establishment cannot be achieved through a single high-quality submitter alone.

---

## 8. Anomaly Detection

**Code path:** `lib/scoring-v2.js` -- `detectScoreAnomaly()`, lines 362-431.

**What it measures:** Score velocity -- the rate of change in composite scores between the last 7 days and the preceding 23 days (7d vs 30d window).

**Statistical method:** A simplified Welch t-statistic. The delta between window means must clear both a magnitude threshold (10 points) and a statistical significance threshold (2.0 pooled standard errors).

**Alert levels:**
- `moderate`: delta >= 10 points AND significance >= 2.0
- `severe`: delta >= 20 points AND significance >= 3.0 AND min sample size >= 10

**Why significance testing:** Without it, high-variance entities would generate false positives from normal fluctuation. A merchant whose scores naturally range from 60-90 would trigger alerts constantly. The pooled standard error accounts for this variance.

**Why minimum sample sizes (5 per window, 10 for severe):** Small samples are inherently noisy. A single bad receipt out of 2 looks like a 50% crash. Requiring 5+ receipts per window (10+ for severe alerts) ensures the signal is real.

---

## 9. Dispute Dampening

**Code path:** `lib/scoring-v2.js` lines 36-60, 207-210.

**Mechanism:** Receipts under active dispute carry 30% weight (`DISPUTE_DAMPENING_FACTOR = 0.3`). Resolved disputes either restore full weight (dismissed, 1.0x) or exclude the receipt entirely (upheld, 0.0x).

**Why 30%:** A balance between two attack vectors:
1. Filing false disputes to tank a competitor's score (mitigated by reducing disputed receipt weight rather than zeroing it)
2. Legitimate disputes that should reduce trust while under review (mitigated by not ignoring them entirely)

The dampening is symmetric: the dispute filer's own dispute rate also affects their trust profile.

---

## Amendment Process

1. **Propose:** Open a GitHub issue with the label `scoring-weights`. Include:
   - Which weight or threshold you propose changing
   - The proposed new value
   - Data, simulation results, or reasoning supporting the change
   - Analysis of how the change affects the formal verification properties (Sybil resistance, convergence, monotonicity)

2. **Review:** Changes require review against:
   - Sybil resistance properties (does the change make manipulation cheaper?)
   - Convergence properties (does the score still converge with sufficient evidence?)
   - Monotonicity properties (does better behavior still produce better scores?)
   - Edge case analysis (bootstrapping, dormant entities, cross-border commerce)

3. **Version:** All weight changes are versioned. The `receipt_version` field in `computeReceiptHash()` increments when scoring semantics change. Historical receipts retain their original version and are scored under the rules that existed at submission time.

4. **Document:** This file is updated with each weight change. Each change includes:
   - Date and version number
   - Previous and new values
   - Rationale for the change
   - Link to the GitHub issue or PR
