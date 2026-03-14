# EMILIA Protocol — The Irrefutable Trust Layer

## Why Every Trust System Has Failed

Every trust system in history has been corrupted for exactly one of three reasons:

1. **The scorer has incentive to lie** — Amazon reviews, Yelp ratings
2. **The platform has incentive to manipulate** — Yelp sells "enhanced profiles," Google ranks by ad spend
3. **The algorithm is opaque** — FICO won't tell you the formula, so you can't verify fairness

EMILIA Protocol eliminates all three failure modes simultaneously:

1. **The scorer IS the buyer.** Lying hurts them — their own agent will route back to a bad merchant and get burned. Incentive alignment is structural, not enforced.
2. **EP has no platform.** It's an open-source protocol. There is no company selling "premium reputation" or suppressing bad scores. The code is the authority.
3. **The algorithm is published.** Every weight, every threshold, every line of scoring logic is open source under Apache 2.0. Anyone can verify. Anyone can fork.

This is not incrementally better than existing trust systems. It is architecturally different.

---

## The Three Phases of Truth

### Phase 1: Behavioral Truth (LIVE NOW)

**How it works:** The buying agent submits a receipt after each transaction. The receipt contains what happened — not an opinion.

**Why it works even with self-reporting:** The key insight is that the BUYING agent has no incentive to inflate the SELLER's score. If a buyer's agent scores a bad merchant highly, the buyer's agent will route back to that merchant and get burned. The scorer and the consumer of the score are the same entity. This creates natural incentive alignment that no review system has ever achieved.

**The behavioral signal is the breakthrough:** Agent satisfaction isn't a rating. It's an observable action:

| Agent Behavior | Score | What It Means |
|---|---|---|
| Completed without retry | 95 | Transaction worked perfectly |
| Retried same entity | 75 | Minor issue, still trusted |
| Switched to different entity | 40 | Lost trust, went elsewhere |
| Abandoned entirely | 15 | Complete failure |
| Filed dispute | 5 | Adversarial outcome |

FICO doesn't ask borrowers to rate their lender. It watches whether they pay. EP doesn't ask agents to rate merchants. It watches whether they come back.

**What's live:**
- 15 API endpoints
- Receipt submission with SHA-256 chaining
- 6-signal scoring engine (open source)
- Sybil resistance (3 layers)
- Merkle root anchoring on Base L2
- MCP server, TypeScript SDK, Python SDK

### Phase 2: Evidence-Backed Truth (IN DEVELOPMENT)

**The upgrade:** Instead of asking agents to submit scores (0-100), ask them to submit CLAIMS + EVIDENCE. The scoring engine computes the number from verifiable data.

**Receipt v2 format:**

```json
{
  "entity_id": "sofaco-123",
  "transaction_type": "purchase",
  "outcome": "completed",

  "claims": {
    "delivered": true,
    "on_time": {
      "promised": "2026-03-15T00:00:00Z",
      "actual": "2026-03-14T18:00:00Z"
    },
    "price_honored": {
      "quoted_cents": 49900,
      "charged_cents": 49900
    },
    "as_described": false,
    "return_accepted": true
  },

  "evidence": {
    "tracking_id": "FDX-123456789",
    "payment_ref": "stripe_pi_abc123",
    "listing_hash": "sha256:a1b2c3...",
    "photo_hashes": ["sha256:d4e5f6..."]
  },

  "agent_behavior": "retried_different"
}
```

**How the scoring engine computes from claims:**

| Claim | True | False | Computation |
|---|---|---|---|
| `delivered` | 80 base | 0 | Binary |
| `on_time` | +20 (total 100) | Scaled by delay | `delivery_accuracy` |
| `price_honored` | 100 | Scaled by overcharge % | `price_integrity` |
| `as_described` | 100 | 20 | `product_accuracy` |
| `return_accepted` | 100 | 0 | `return_processing` |

**The shift:** From ASKING agents to rate, to ASKING agents to report and COMPUTING the rating. The agent doesn't decide "delivery was 87/100." The agent reports "it arrived 3 days late" and the engine computes the score.

**Backward compatible:** v1 receipts (manual 0-100 scores) continue to work. v2 receipts (claims + evidence) are computed. Both feed into the same scoring engine.

**Submitter-weighted scoring:** A receipt from a high-scoring entity carries more weight than one from a new, unproven entity.

```
receipt_weight = submitter_score / 100
```

An established score-90 entity's receipt counts 0.9x. But an **unestablished** entity — regardless of score — counts only **0.1x**. To become established, an entity needs 5+ receipts from 3+ unique submitters. This makes Sybil attacks exponentially harder — creating 100 throwaway entities is useless because each carries 0.1x weight, and to become established each would need its own network of real counterparties.

### Phase 3: Protocol-Observed Truth (ROADMAP)

**The endgame:** EP doesn't ask agents to submit anything. It LISTENS to protocol events and auto-generates receipts.

```
MCP tool call completes  →  EP observes outcome  →  Receipt auto-generated
A2A task delegation      →  EP observes completion →  Receipt auto-generated
UCP checkout             →  EP observes delivery   →  Receipt auto-generated
```

**Verification Oracles:** Specialized high-reputation entities that verify specific claims:

| Oracle | Verifies | Data Source |
|---|---|---|
| DeliveryOracle | Shipping times | FedEx/UPS/USPS APIs |
| PaymentOracle | Price integrity | Stripe/AP2 settlement data |
| ListingOracle | Product accuracy | IPFS-pinned listing snapshots |
| ComplianceOracle | Regulatory adherence | TCPA/HIPAA audit logs |

Oracles have their own EP scores. A bad oracle gets scored down by the agents it serves. Trust is recursive all the way down.

**Zero-knowledge proofs:** Entities can prove their score without revealing their receipt history. "I have a score above 80 with 50+ receipts" — cryptographically provable, without exposing transaction details. Privacy-preserving trust.

---

## The Entity Taxonomy: Who Gets Scored?

The broken sofa question: Does Amazon get scored, or the seller?

**Rule: EP scores the direct economic counterparty — whoever took the money and made the promise.**

| Entity | Gets EP Score? | Why |
|---|---|---|
| Amazon.com (platform) | Aggregate only | Too large, shifts blame |
| Amazon Seller "SofaCo-123" | ✅ Individual score | Took the money, made the product promise |
| Amazon Logistics / FedEx | ✅ Separate score | Made the delivery promise |
| FBA (Fulfilled by Amazon) | ✅ Amazon's score | Amazon handles logistics, Amazon gets scored |
| Your buying agent "Clara" | ✅ Yes | Other agents can check if Clara is a reliable counterparty |

**Separate signals for separate entities.** When a sofa arrives broken:

- **SofaCo-123** gets: `as_described: false` (product was damaged)
- **FedEx** gets: `delivered: true, on_time: true` (they delivered on time, damage may be handling)
- **Clara** (buying agent) submits both receipts — her score reflects her diligence as a buyer

This granularity is unique to EP. Yelp gives the restaurant one star even if the food was great but the delivery driver was late. EP separates the signals.

---

## The Dispute Model

**Phase 1 (Live):** No formal disputes. Receipts are one-directional (buyer → seller). The seller cannot modify a receipt, but the receipt is weighted by the submitter's own score. A bad-faith buyer with a low score can barely dent a high-scoring seller.

**Phase 2 (In Development):** Counter-receipts. The seller can submit a counter-receipt within 48 hours. If no counter-receipt, the original is accepted as uncontested. Conflicting receipts are flagged and both are stored — transparency over arbitration.

**Phase 3 (Roadmap):** Automated arbitration. When claims + evidence conflict, evidence is checked against oracles. If FedEx tracking says "delivered on time" but the buyer claims "late," the oracle resolves it. No human jury needed — just math against external data.

---

## Why EP Cannot Be Corrupted

| Attack | Defense | Why It Works |
|---|---|---|
| Fake entities submitting good receipts | Sybil resistance: rate limiting, thin-graph detection, cluster analysis | Unestablished entities' receipts carry only 0.1x weight — creating throwaway entities is useless |
| Seller inflating own score | No self-scoring + closed-loop detection | Protocol enforces separation |
| Buyer filing false bad reviews | Buyer's own score degrades if they file many negatives | Incentive alignment: bad-faith scoring is observable |
| Buying own products to generate good receipts | Thin-graph flagging: 5 receipts from 1 submitter = flagged | Diversity requirement: 3+ unique submitters to establish |
| Bribing the platform | No platform. Open source. Fork it if you disagree. | Architectural impossibility |
| Changing the algorithm secretly | Algorithm is on GitHub. Changes are public commits. | Transparency by design |
| Deleting bad history | Append-only ledger + blockchain anchoring | Receipts are permanent |
| Permanent bad score trapping good entities | Time-decay: 90-day half-life on receipt weight | Recovery through sustained improvement |

**The economic argument:** To meaningfully inflate a score, an attacker must create multiple fake entities (rate-limited), register API keys for each, submit 5+ receipts per entity from 3+ unique submitters to escape dampening, maintain consistent scoring across 200+ receipts, avoid triggering velocity monitoring, and do all of this while leaving a permanent, auditable, on-chain-anchored trail.

The cost of faking exceeds the cost of being good.

---

## Time-Decay: Recovery Is Possible

Permanent black marks are unjust. EP uses exponential time-decay so entities can recover from bad periods through sustained improvement.

**Half-life: 90 days.**

| Receipt Age | Weight | Meaning |
|---|---|---|
| Today | 1.0x | Full weight |
| 90 days | 0.5x | Half weight |
| 180 days | 0.25x | Quarter weight |
| 1 year | ~0.06x | Nearly gone |
| 2 years | ~0.004x | Effectively zero |

**Floor: 0.05x.** Very old receipts never fully disappear — catastrophic fraud leaves a permanent trace, just a faint one.

Combined with the 200-receipt rolling window, this means: no entity is permanently condemned, but recovery requires sustained good performance across many transactions. You can't recover with a single PR stunt — you recover by being good for months.

This is how FICO works too. A bankruptcy stays on your credit report for 7-10 years, but its impact fades as you build new positive history.

---

## Conflict Receipts (Phase 2)

---

## Score Confidence States

---

## Establishment vs Scoring: Deliberate Windowing Distinction

`is_entity_established()` uses ALL receipts. `compute_emilia_score()` uses a rolling 200-receipt window.

These are deliberately different:

- **Establishment is historical:** "Has this entity ever built enough credible history to be considered real?" Once established, the entity retains that status. This prevents an attacker from de-establishing a legitimate entity by flooding it with low-weight receipts.
- **Scoring is current:** "How is this entity performing right now?" Only recent receipts (200 window + time decay) affect the score. Old good behavior doesn't excuse current poor performance.

An entity can be established (from past history) but have a low current score (recent performance is poor). The confidence state system communicates this: an established entity with a declining score shows "ESTABLISHED" status but the score itself drops. The anomaly detector flags the velocity of change.

This is analogous to how FICO works: you can have a long credit history (established) but a currently declining score (missed recent payments). The length of history and the current performance are different dimensions.

---

Not all scores are equally trustworthy. EP communicates this transparently through confidence states — visible in the API response and on entity profile pages.

| State | Condition | Display | Meaning |
|---|---|---|---|
| **Pending** | 0 receipts | "Score pending" | No data at all |
| **Insufficient** | Score ≤55, receipts ≤10 | "Low confidence" with progress bar | All receipts from unestablished submitters — effectively no credible data |
| **Provisional** | <5 receipts or <3 unique submitters | "Provisional" with progress bar | Building history, not yet established |
| **Emerging** | 5+ receipts, established | Score + breakdown shown | Meaningful but still building |
| **Confident** | 20+ receipts, multiple submitters | Full score + breakdown | High confidence, reliable signal |

**Key design decisions:**

- Breakdown bars (delivery accuracy, product accuracy, etc.) are only shown at Emerging or Confident. Showing detailed breakdowns for 3 receipts from unestablished submitters would be misleading.
- A progress bar shows "X/20 receipts from established submitters needed" for low-confidence states. This turns the vulnerability into progressive disclosure — users see the path to credibility.
- The API response includes `confidence` and `confidence_message` fields so consuming agents can make automated trust decisions: "only transact with Confident-level entities."

**Why this matters:** After the Sybil resistance fix (unestablished submitters = 0.1x weight), an entity with 5 receipts from throwaway accounts scores ~54.9 — barely above default. The confidence state makes this explicit: "Low confidence — receipts from unestablished submitters." No one is misled.

---

When two parties submit conflicting claims about the same transaction:

1. **Both receipts enter "disputed" state** — neither is immediately applied to scores
2. **48-hour evidence window** — both parties can submit supporting evidence (tracking IDs, photos, payment confirmations, communication logs)
3. **Evidence comparison** — if an oracle can verify a claim (e.g., FedEx API confirms delivery time), the oracle's verification overrides the disputed claim
4. **Resolution** — if no oracle resolution, both receipts are stored with a `disputed` flag. Both contribute to scores but at 0.5x weight. Transparency over arbitration.
5. **Dispute rate tracking** — entities that frequently trigger disputes accumulate a `dispute_rate` signal. High dispute rates are a trust signal in themselves.

The principle: **don't try to determine truth between conflicting parties.** Instead, record both versions, flag the conflict, and let the dispute rate become its own signal. An entity that is constantly in disputes is inherently less trustworthy, regardless of who's "right."

---

## The Competitive Moat

### Who could build this?

| Threat | Likelihood | EP's Defense |
|---|---|---|
| Amazon builds internal reputation | High | Only works on Amazon. EP is cross-platform. |
| Shopify builds internal reputation | High | Only works on Shopify. EP is cross-platform. |
| UCP adds native reputation layer | Medium | EP is protocol-neutral — UCP may prefer a neutral third party |
| A2A builds scoring | Medium | Same — neutral layer preferred over self-scoring |
| FICO builds "FICO for agents" | High | FICO is closed-source, proprietary. EP wins on openness. |
| New startup with $50M funding | High | EP is open source with first-mover advantage. You can't buy a protocol moat with money — you earn it with adoption. |

### Why closed systems lose

The agent economy is fundamentally cross-platform. A Shopify seller's Claude agent buying from an Amazon seller's Gemini agent — that transaction crosses three ecosystems. No single platform's reputation system covers it.

| System | Scope | Limitation |
|---|---|---|
| Amazon internal score | Amazon only | Doesn't travel to Shopify, Stripe, or independent agents |
| Shopify internal score | Shopify only | Doesn't cover Amazon, eBay, or direct sales |
| FICO | US credit only | No international, no agent-to-agent |
| **EP** | **Cross-platform** | **Works everywhere: UCP, A2A, MCP, ACP, AP2** |

**The bet:** The agent economy is more cross-platform than the human economy. If true, EP wins. If false, EP becomes a niche tool. The evidence so far: MCP (Anthropic), A2A (Google), UCP (Google+Shopify), ACP (OpenAI+Stripe) — four competing companies all building open agent protocols. Cross-platform is the direction.

---

## The Protocol Stack Position

```
┌─────────────────────────────────────────────────────────────┐
│                    LLM PROVIDERS                             │
│        Anthropic · Google · OpenAI · Meta · Mistral          │
├─────────────────────────────────────────────────────────────┤
│                   AGENT PROTOCOLS                            │
│     MCP (Tools) · A2A (Comms) · UCP (Commerce) · ACP (Pay)  │
├─────────────────────────────────────────────────────────────┤
│               ══════════════════════════                      │
│               ║   EMILIA PROTOCOL    ║                       │
│               ║   The Trust Layer    ║                       │
│               ══════════════════════                         │
│          Receipts → Scores → Verification                    │
│          Open Source · Blockchain-Anchored                    │
├─────────────────────────────────────────────────────────────┤
│                    ENTERPRISES                               │
│    Shopify · Stripe · Walmart · Visa · Coinbase · +more      │
├─────────────────────────────────────────────────────────────┤
│                   BASE L2 (COINBASE)                         │
│            Merkle Root Anchoring · $0.60/mo                  │
└─────────────────────────────────────────────────────────────┘
```

EP sits between the protocols and the enterprises. Every protocol handles mechanics — connecting, communicating, transacting, paying. None of them answer: **should you trust this entity?**

That's EP. The missing layer.

---

## Analogies That Land

| Protocol | Internet Analogy | What It Does |
|---|---|---|
| MCP | USB-C | Plugs agents into tools |
| A2A | TCP/IP | Agents talk to each other |
| UCP | HTTP | Agents do commerce |
| ACP/AP2 | Credit card rails | Agents pay each other |
| **EP** | **SSL + FICO** | **Agents trust each other** |

SSL certificates don't handle the transaction. They tell your browser: "this server is who it claims to be." FICO doesn't handle the loan. It tells the lender: "this borrower will probably repay."

EP doesn't handle the commerce. It tells the agent: "this counterparty has a verified history of keeping promises."

---

## The Roadmap

### NOW (v1.0 — Live)
- [x] 15 API endpoints
- [x] 6-signal scoring engine
- [x] Submitter-weighted scoring (unestablished = 0.1x, established = score/100)
- [x] Time-decay scoring (90-day half-life — entities can recover)
- [x] Score confidence states (pending → insufficient → provisional → emerging → confident)
- [x] Sybil resistance (4 layers including submitter credibility)
- [x] SHA-256 receipt chaining
- [x] Base L2 Merkle anchoring
- [x] MCP server (6 tools)
- [x] TypeScript + Python SDKs
- [x] Entity profile pages with confidence display
- [x] Rate limiting middleware
- [x] Protocol specification (EP-SPEC v1.0)

### Q2 2026 (v1.5 — Evidence-Backed)
- [ ] Claims + evidence receipt format (v2 receipts)
- [ ] Score computation from binary claims
- [ ] Counter-receipts (48hr window)
- [ ] Conflict receipts (disputed state + evidence window)
- [ ] Entity taxonomy documentation
- [ ] RexRuby.ai integration (first live receipts)
- [ ] NIST ITL concept paper submission

### Q3 2026 (v2.0 — Verified)
- [ ] Decentralized verification oracle framework (oracles have their own EP scores)
- [ ] DeliveryOracle (carrier API integration)
- [ ] PaymentOracle (Stripe/AP2 settlement)
- [ ] Evidence validation engine (JSON Schema per transaction_type)
- [ ] Oracle-resolved disputes (conflicting claims checked against external data)
- [ ] Webhook notifications (score change alerts)
- [ ] Admin dashboard (entity management, fraud review)
- [ ] UCP extension proposal

### Q4 2026 (v3.0 — Protocol-Native)
- [ ] Protocol-level listeners (MCP/A2A/UCP event observation)
- [ ] Auto-generated receipts from protocol events
- [ ] Zero-knowledge score proofs
- [ ] Cross-chain anchoring (Ethereum L1, Arbitrum)
- [ ] Governance framework
- [ ] Dispute arbitration via oracle consensus

---

## The Tagline

**Receipts, not reviews. The first reputation system where lying hurts the liar.**

Every review system fails because the scorer doesn't consume the score. Yelp reviewers don't eat at the restaurant every day. Amazon reviewers don't rebuy the product. The person writing the review bears no cost for being wrong.

EP fixes this. The buying agent submits receipts — and if they lie about a bad seller, their own agent routes back to that seller and gets burned. The scorer and the consumer of the score are the same entity. This is evolutionary game theory applied to reputation. Self-enforcing honesty.

No other trust system has achieved this structural alignment.

---

*EMILIA Protocol — The Trust Layer for the Agent Economy*
*Apache 2.0 · emiliaprotocol.ai · github.com/emiliaprotocol/emilia-protocol*
