# Adaptive Scoring -- Design Architecture

Version: 1.0
Status: Design (not yet implemented)
Depends on: `docs/SCORING_RATIONALE.md`, `docs/AGENT_SATISFACTION_GOVERNANCE.md`

---

## 1. Problem

EP's scoring weights are currently static constants in `lib/scoring-v2.js`. Every operator sees the same formula: behavioral 40%, consistency 25%, delivery 12%, product 10%, price 8%, returns 5%. These weights were chosen based on first-principles reasoning (see `SCORING_RATIONALE.md`), but they encode assumptions about which signals best predict real-world trust across all verticals, geographies, and risk profiles.

These assumptions will be wrong in specific contexts:

- **Government procurement** cares more about price integrity and delivery accuracy than behavioral signals (agents don't "come back" to a sole-source vendor).
- **High-frequency API marketplaces** generate thousands of receipts per day. Consistency dominates because individual receipt signals are noise at that volume.
- **Cross-border e-commerce** has structurally higher delivery variance. Penalizing delivery accuracy at 12% weight may be too aggressive for international routes.

Static weights create a fork incentive: operators who disagree with the defaults will fork the scoring code rather than deploy EP as-is. Forking fragments the trust signal -- an entity's score means different things under different weight sets, destroying cross-ecosystem comparability.

---

## 2. Design Principles

### 2.1 The protocol defines the formula. The policy defines the weights.

The scoring *algorithm* (time decay, Sybil gates, graph penalties, provenance tiers, anomaly detection) is protocol-level. It does not change per operator. The *weights within the algorithm* are policy-level. They travel with the policy, are versioned, and are auditable.

This is already how EP works for other policy parameters (signoff thresholds, challenge TTLs, delegation scopes). Scoring weights are the last major parameter set that is still hardcoded.

### 2.2 Transparency is non-negotiable.

An entity must be able to reconstruct its own score from its own receipts plus the active policy. If the weights are opaque or change silently, entities cannot contest scores -- which defeats EP's entire dispute mechanism.

Adaptive scoring must therefore be:
- **Versioned**: every weight set has a policy version hash
- **Published**: the active weight set is readable via `GET /api/trust/profile/{entityId}` (already returns `scoring_version`)
- **Deterministic**: the same receipts + the same weight set = the same score, always

### 2.3 Recommendations, not automation.

The system produces weight *recommendations*. The operator decides whether to adopt them via EP Cloud's policy rollout pipeline (diff, simulate, signoff, deploy). There is no path where weights change without human authorization.

This is Level 2 adaptive scoring (outcome-informed adjustment), not Level 3 (fully adaptive). Level 3 is explicitly out of scope because it creates opacity, gaming vectors, and a black-box trust score.

---

## 3. Architecture

### 3.1 Three-Layer Model

```
Layer 1: Protocol (immutable per version)
  - Scoring algorithm structure
  - Sybil quality gates
  - Graph analysis penalties
  - Anomaly detection thresholds
  - Time decay formula
  - Provenance tier structure

Layer 2: Policy (operator-configurable, versioned)
  - Signal weights (behavioral, consistency, delivery, product, price, returns)
  - Provenance weights (self_attested, bilateral, platform_originated, etc.)
  - Evidence thresholds (establishment, confidence levels)
  - Dispute dampening factor
  - Time decay half-life

Layer 3: Recommendations (EP Cloud analytics)
  - Outcome-informed weight suggestions
  - Vertical-specific calibration data
  - Dispute correlation analysis
  - Cross-operator benchmark comparisons
```

### 3.2 Data Flow

```
                  Dispute outcomes
                        |
                        v
  +-----------------------------------------+
  |  EP Cloud Analytics Engine              |
  |                                         |
  |  1. Collect dispute resolution data     |
  |  2. Correlate with pre-dispute scores   |
  |  3. Identify weight miscalibrations     |
  |  4. Generate weight recommendations     |
  +-----------------------------------------+
                        |
                        v
              Weight recommendation
              (proposed policy diff)
                        |
                        v
  +-----------------------------------------+
  |  EP Cloud Policy Pipeline               |
  |                                         |
  |  1. POST /api/cloud/policies/*/simulate |
  |  2. Operator reviews simulation results |
  |  3. POST /api/cloud/policies/*/rollout  |
  |  4. Accountable Signoff on rollout      |
  +-----------------------------------------+
                        |
                        v
              New policy version
              (weights updated)
                        |
                        v
  +-----------------------------------------+
  |  EP Scoring Engine                      |
  |                                         |
  |  computeTrustProfile() reads weights    |
  |  from active policy, not constants      |
  +-----------------------------------------+
```

---

## 4. Outcome-Informed Weight Calibration

### 4.1 Core Insight

Disputes are labeled ground truth. When a dispute is resolved (upheld, dismissed, or settled), the resolution tells us whether the pre-dispute score was accurate:

- **Dispute upheld** (entity was at fault): the entity's score *should have been lower* before the dispute. The signals that predicted high trust were overweighted or the signals that predicted low trust were underweighted.
- **Dispute dismissed** (entity was not at fault): the entity's score was roughly correct or the dispute was frivolous. No weight adjustment signal.
- **Dispute settled** (partial fault): weak signal. Useful in aggregate but not individually.

### 4.2 Calibration Algorithm

For each operator's entity population, over a rolling window (default: 90 days):

```
1. Collect all resolved disputes where resolution = 'upheld'

2. For each upheld dispute:
   a. Retrieve the entity's trust profile at dispute filing time
      (score, confidence, per-signal breakdown)
   b. Identify which signal dimensions were strongest
      (highest weighted contribution to the composite score)
   c. Record: { entity_id, filing_date, upheld_date,
                 pre_dispute_score, signal_breakdown,
                 dispute_category }

3. Aggregate across all upheld disputes:
   a. For each signal dimension, compute:
      - mean_contribution: average contribution to pre-dispute scores
        of entities that were later found at fault
      - baseline_contribution: average contribution across all entities
      - overweight_ratio: mean_contribution / baseline_contribution
   b. Signals with overweight_ratio > 1.3 are candidates for
      weight reduction
   c. Signals with overweight_ratio < 0.7 are candidates for
      weight increase

4. Generate recommendation:
   a. Proposed new weights (normalized to sum to 1.0)
   b. Confidence interval based on sample size
   c. Expected score impact across entity population
   d. Backtested dispute prediction accuracy
      (would the new weights have flagged the disputed entities earlier?)
```

### 4.3 Constraints on Recommendations

The calibration engine enforces hard bounds:

| Signal | Min Weight | Max Weight | Rationale |
|--------|-----------|-----------|-----------|
| Behavioral | 20% | 50% | Must remain dominant (hardest to fake) |
| Consistency | 10% | 35% | Mathematical signal, always valuable |
| Delivery | 5% | 25% | Varies by vertical but never irrelevant |
| Product | 3% | 20% | Subjective, limited weight ceiling |
| Price | 3% | 20% | Critical in some verticals, minor in others |
| Returns | 2% | 15% | Only applies to subset of transactions |

These bounds prevent degenerate configurations:
- No single signal can exceed 50% (avoids single-axis gaming)
- Behavioral + consistency must be >= 35% (hard-to-fake signals must dominate)
- No signal can drop below its minimum (prevents gaming via signal omission)

### 4.4 Minimum Sample Size

Recommendations are not generated until the operator has:
- 50+ resolved disputes (upheld or dismissed)
- 500+ total receipts in the scoring window
- 20+ unique entities involved in disputes

Below these thresholds, the protocol defaults apply. The system reports "insufficient data for calibration" rather than producing noisy recommendations.

---

## 5. Vertical Packs

EP Cloud's vertical packs (Government, Financial, Agent Governance) ship with pre-calibrated weight sets based on sector-specific risk profiles. These are starting points, not mandates.

### 5.1 Government Pack (Proposed)

```javascript
EP_WEIGHTS_GOV = {
  behavioral:    0.25,  // Agents don't "come back" in sole-source procurement
  consistency:   0.30,  // Reliability is paramount for government contracts
  delivery:      0.20,  // Delivery timeliness is audited and consequential
  product:       0.10,  // Spec compliance matters
  price:         0.12,  // Price integrity is legally required
  returns:       0.03,  // Returns are rare in government procurement
};
```

**Rationale**: Government procurement has structural differences from commercial e-commerce. Behavioral signals are weaker because vendors are often sole-source or competitively awarded. Consistency and delivery are higher because government contracts have explicit SLAs. Price integrity is elevated because overcharging the government is a federal offense.

### 5.2 Financial Services Pack (Proposed)

```javascript
EP_WEIGHTS_FIN = {
  behavioral:    0.35,  // Repeat business is strong signal in financial services
  consistency:   0.30,  // Reliability is the core product
  delivery:      0.10,  // "Delivery" is usually instant (digital)
  product:       0.08,  // Service accuracy matters
  price:         0.15,  // Fee transparency is a compliance requirement
  returns:       0.02,  // Returns don't apply to most financial products
};
```

### 5.3 Agent Governance Pack (Proposed)

```javascript
EP_WEIGHTS_AGENT = {
  behavioral:    0.45,  // Agent routing decisions are the purest signal
  consistency:   0.25,  // Consistency is critical for autonomous agents
  delivery:      0.10,  // Varies by agent task type
  product:       0.08,  // Output quality
  price:         0.07,  // Cost efficiency
  returns:       0.05,  // Retry/rollback rates
};
```

---

## 6. Score Comparability

### 6.1 The Problem

If operator A uses default weights and operator B uses the government pack, the same entity may score 78 under A and 65 under B. This breaks cross-ecosystem trust decisions.

### 6.2 The Solution: Canonical Score + Policy Score

Every trust profile returns two scores:

```json
{
  "canonical_score": 73,
  "canonical_confidence": "confident",
  "canonical_weights_version": "ep-v2-default",

  "policy_score": 68,
  "policy_confidence": "confident",
  "policy_weights_version": "gov-v1.2",
  "policy_hash": "sha256:a1b2c3..."
}
```

- **`canonical_score`**: computed with protocol default weights. Always comparable across the ecosystem. This is what entities see on their public profile.
- **`policy_score`**: computed with the operator's active policy weights. This is what the operator uses for trust decisions within their deployment.

The canonical score is the "lingua franca" of the EP ecosystem. The policy score is the operator's private risk assessment. Both are derived from the same receipt data and the same algorithm -- only the weights differ.

### 6.3 Fork Prevention

This dual-score design removes the fork incentive. Operators who want different weights don't need to fork the scoring code -- they configure a policy. The canonical score remains comparable. The protocol's value (shared trust signal) is preserved while operators get the flexibility they need.

---

## 7. Implementation Plan

### Phase 1: Policy-Configurable Weights (Near-term)

**Goal**: Move weights from `lib/scoring-v2.js` constants into the policy object.

1. Define `scoring_weights` schema in the policy format:
   ```json
   {
     "scoring_weights": {
       "behavioral": 0.40,
       "consistency": 0.25,
       "delivery": 0.12,
       "product": 0.10,
       "price": 0.08,
       "returns": 0.05
     },
     "scoring_weights_version": "ep-v2-default"
   }
   ```

2. Modify `computeTrustProfile()` to accept weights as a parameter (default to `EP_WEIGHTS_V2` when no policy weights are provided -- backward compatible).

3. Add `canonical_score` alongside `policy_score` in trust profile responses.

4. Update `GET /api/trust/profile/{entityId}` to return both scores.

5. Add policy weight validation (enforce min/max bounds from section 4.3).

**Code changes**: `lib/scoring-v2.js`, `lib/trust-profile.js`, `app/api/trust/profile/[entityId]/route.js`, policy schema validation.

### Phase 2: EP Cloud Calibration Engine (Medium-term)

**Goal**: Build the dispute-to-recommendation pipeline.

1. Create `lib/cloud/calibration.js`:
   - `collectCalibrationData(operatorId, windowDays)`: queries disputes + pre-dispute profiles
   - `computeWeightRecommendation(calibrationData)`: runs the algorithm from section 4.2
   - `validateRecommendation(recommendation)`: enforces bounds from section 4.3

2. Create `GET /api/cloud/scoring/recommendations`:
   - Returns current weight recommendation for the operator
   - Includes confidence intervals, sample sizes, backtested accuracy

3. Integrate with existing policy pipeline:
   - Recommendation feeds into `POST /api/cloud/policies/*/simulate`
   - Operator reviews simulation results
   - Rollout via `POST /api/cloud/policies/*/rollout` with Accountable Signoff

### Phase 3: Vertical Packs (Medium-term)

**Goal**: Ship pre-calibrated weight sets for government, financial, and agent governance verticals.

1. Create vertical pack definitions in `lib/cloud/verticals/`
2. Expose via EP Cloud onboarding (operator selects vertical during setup)
3. Vertical pack weights serve as starting defaults; operator can customize further
4. Calibration engine uses vertical pack as the baseline for recommendations

### Phase 4: Cross-Operator Benchmarking (Long-term)

**Goal**: Aggregate anonymized calibration data across operators to improve vertical pack defaults.

1. Operators opt-in to anonymous benchmark sharing
2. EP Cloud aggregates dispute-resolution patterns across operators in the same vertical
3. Vertical pack defaults are updated based on cross-operator evidence
4. No individual operator's data is identifiable in the aggregate

---

## 8. Security Considerations

### 8.1 Weight Manipulation Attacks

**Threat**: An attacker files frivolous disputes to skew the calibration data, causing the recommendation engine to suggest weights that benefit their position.

**Mitigation**: The calibration engine only uses *upheld* disputes (where the entity was found at fault after adjudication). Frivolous disputes are dismissed and do not influence recommendations. Additionally, the minimum sample size requirements (50+ resolved disputes) make it expensive to generate enough upheld disputes to move the calibration needle.

### 8.2 Policy Rollout Attacks

**Threat**: An attacker with operator access deploys degenerate weights to inflate specific entities.

**Mitigation**: Hard bounds on all weights (section 4.3) prevent degenerate configurations. Policy rollouts require Accountable Signoff (human authorization). The canonical score is unaffected by operator policy changes -- only the policy score changes. All weight changes are versioned and auditable.

### 8.3 Canonical Score Anchoring

**Threat**: Operators ignore the policy score and only use the canonical score, defeating the purpose of vertical customization.

**Mitigation**: This is acceptable behavior, not a threat. The canonical score exists precisely as a fallback for operators who don't want to customize. The system degrades gracefully to static weights.

---

## 9. Relationship to Formal Verification

The TLA+ model (`tla/EP.tla`) verifies safety properties against the scoring algorithm structure, not specific weight values. The key properties that must hold regardless of weight configuration:

1. **Sybil resistance**: Unestablished submitter weight (0.1x) and quality-gated evidence cap (2.0) are protocol-level, not policy-level. No weight configuration can bypass these gates.

2. **Monotonicity**: Better behavior produces equal or better scores. This holds for any non-negative weight vector that sums to 1.0.

3. **Convergence**: With sufficient evidence, scores converge. This depends on the time decay formula and evidence thresholds, not signal weights.

4. **Dispute integrity**: Dispute dampening factor (0.3x) and resolution weight effects (0.0x for upheld, 1.0x for dismissed) are protocol-level.

The weight bounds in section 4.3 are conservative enough that all formal verification properties hold for any configuration within bounds. This should be re-verified when bounds are finalized.

---

## 10. FAQ

**Q: Why not let operators set arbitrary weights?**
A: Unconstrained weights create degenerate configurations. An operator could set behavioral to 0% and returns to 100%, creating a score that is trivially gameable. The bounds in section 4.3 ensure all configurations maintain minimum Sybil resistance and signal diversity.

**Q: Why not make the calibration fully automatic?**
A: Fully automatic weight adjustment (Level 3) creates a black-box score that entities cannot predict or contest. EP's dispute mechanism requires that entities can reconstruct their own score. If the weights change without notice, an entity's dispute about "my score is wrong" becomes unfalsifiable -- neither side can agree on what the score *should* be. The recommendation model preserves human judgment in the loop.

**Q: What if an operator's calibration data is too small?**
A: The system falls back to protocol defaults (or vertical pack defaults). No recommendation is generated below the minimum sample thresholds. This is the correct behavior -- small-sample recommendations are worse than informed defaults.

**Q: Can entities see which weight set was used to compute their score?**
A: Yes. The trust profile response includes `policy_weights_version` and `policy_hash`. Entities can query the operator's published policy to see the exact weights. This is a transparency requirement, not an option.

**Q: What happens to historical scores when weights change?**
A: Scores are recomputed on read (not stored). When an operator rolls out new weights, all trust profile queries immediately reflect the new weights applied to existing receipt data. Historical trust decisions (handshake verifications, signoff attestations) are not retroactively invalidated -- they were correct under the policy that was active at decision time.
